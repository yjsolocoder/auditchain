import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AnchoredContinuationChain,
    AuditLog,
    ContinuationChainReport,
    RotatedChain,
    SignedAuthAuditContinuation,
    SignedRoot,
    encode_rotated_anchor,
    encode_rotation,
    inspect_rotated_anchor_set,
    inspect_rotated_anchors,
    verify_rotated_chain,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(3, 35))
_SEED_E = bytes(range(5, 37))
_SEED_F = bytes(range(7, 39))
_KEY = b"super-secret-verifier-key"

_OK = ContinuationChainReport(True, None, None)


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(n=15, key=_KEY, hash_name="sha256", prefix="record"):
    # Each continuation / rotation consumes the log holder's one-shot
    # verifier export, so every artifact is minted from a fresh log over
    # identical content.
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _segment(old_size, new_size, seed, **kwargs):
    return _log(**kwargs).signed_auth_audit_continuation(
        old_size, (), seed, size=new_size
    )


def _rotation(old_seed, new_seed, size, **kwargs):
    return _log(**kwargs).rotate_signer(old_seed, new_seed, size)


def _package(receipts, rotations):
    return RotatedChain(
        receipts,
        rotations,
        receipts[0].consistency.old,
        receipts[-1].consistency.new,
    )


def _replace(checkpoint, **changes):
    fields = {
        "version": checkpoint.version,
        "hash_name": checkpoint.hash_name,
        "size": checkpoint.size,
        "root": checkpoint.root,
        "head": checkpoint.head,
        "signature": checkpoint.signature,
    }
    fields.update(changes)
    return SignedRoot(**fields)


class InspectRotatedAnchorSetTest(unittest.TestCase):
    def setUp(self):
        # One continuous cross-signer chain landed in three packages, two
        # segments per package: s0 (0,3) under A, rotation A->B at 3,
        # s1 (3,6) under B || bridge B->C at 6 || s2 (6,8) under C,
        # rotation C->D at 8, s3 (8,11) under D || bridge D->E at 11 ||
        # s4 (11,13) under E, rotation E->F at 13, s5 (13,15) under F.
        # Global receipt positions: s0..s5 are 0..5.
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.b0 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.r2 = _rotation(_SEED_C, _SEED_D, 8)
        self.s3 = _segment(8, 11, _SEED_D)
        self.b1 = _rotation(_SEED_D, _SEED_E, 11)
        self.s4 = _segment(11, 13, _SEED_E)
        self.r4 = _rotation(_SEED_E, _SEED_F, 13)
        self.s5 = _segment(13, 15, _SEED_F)
        self.p0 = _package((self.s0, self.s1), (self.r0,))
        self.p1 = _package((self.s2, self.s3), (self.r2,))
        self.p2 = _package((self.s4, self.s5), (self.r4,))
        self.items = (self.p0, self.p1, self.p2)
        self.bridges = (self.b0, self.b1)
        self.key_a = _public_key(_SEED_A)
        self.key_d = _public_key(_SEED_D)

    # --- success -----------------------------------------------------

    def test_success_report_shape(self):
        report = inspect_rotated_anchor_set(
            self.items, self.bridges, self.key_a
        )
        self.assertEqual(report, _OK)
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)
        self.assertEqual((report.ok, report.index, report.code), (True, None, None))

    def test_single_package_empty_bridges_reports_ok(self):
        self.assertEqual(
            inspect_rotated_anchor_set((self.p0,), (), self.key_a),
            _OK,
        )

    def test_single_package_matches_inspect_rotated_anchors(self):
        self.assertEqual(
            inspect_rotated_anchor_set((self.p0,), (), self.key_a),
            inspect_rotated_anchors(self.p0, self.key_a),
        )

    def test_two_packages_one_bridge_reports_ok(self):
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (self.b0,), self.key_a
            ),
            _OK,
        )

    def test_success_agrees_with_flattened_bool_verifier(self):
        receipts = (
            self.s0,
            self.s1,
            self.s2,
            self.s3,
            self.s4,
            self.s5,
        )
        rotations = (
            self.r0,
            self.b0,
            self.r2,
            self.b1,
            self.r4,
        )
        self.assertTrue(
            verify_rotated_chain(receipts, rotations, self.key_a)
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                self.items, self.bridges, self.key_a
            ),
            _OK,
        )

    # --- per-package failure codes, globally re-based ----------------

    def test_first_package_verify_failure_at_zero(self):
        s0_other = _segment(0, 3, _SEED_D)
        # Its start anchor differs too, but the internal verify failure is
        # diagnosed before the anchors; the (genuine) bridge is never seen.
        broken = _package((s0_other, self.s1), (self.r0,))
        self.assertEqual(
            inspect_rotated_anchor_set(
                (broken, self.p1), (self.b0,), self.key_a
            ),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_later_package_verify_failure_rebased(self):
        # Genuine bridge B->C, but p1's second segment carries a bundle
        # signed by F over a C-signed consistency: the seam joins, yet the
        # segment does not verify under the bridge's learned new_key C;
        # local position 1 becomes global position 3.
        foreign_bundle = _segment(8, 11, _SEED_F).bundle
        swapped = SignedAuthAuditContinuation(
            foreign_bundle, self.s3.consistency
        )
        p1 = _package((self.s2, swapped), (self.r2,))
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, p1), (self.b0,), self.key_a
            ),
            ContinuationChainReport(False, 3, "verify"),
        )

    def test_later_package_growth_failure_rebased(self):
        # A zero-length second segment in p1 (8 -> 8 under D) passes its
        # boundary rotation, then fails growth at local 1 / global 3.
        equal = _segment(8, 8, _SEED_D)
        p1 = _package((self.s2, equal), (self.r2,))
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, p1), (self.b0,), self.key_a
            ),
            ContinuationChainReport(False, 3, "growth"),
        )

    def test_third_package_failure_accumulates_both_prior_counts(self):
        # p2's first segment signed by D instead of E behind a genuine
        # D->E bridge: the bridge joins on both anchors, then "verify" is
        # reported at global position 4.
        foreign_bundle = _segment(11, 13, _SEED_D).bundle
        swapped = SignedAuthAuditContinuation(
            foreign_bundle, self.s4.consistency
        )
        p2 = _package((swapped, self.s5), (self.r4,))
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1, p2), self.bridges, self.key_a
            ),
            ContinuationChainReport(False, 4, "verify"),
        )

    def test_start_failure_in_first_package_at_zero(self):
        shifted = RotatedChain(
            (self.s0, self.s1),
            (self.r0,),
            _replace(self.s0.consistency.old, size=2),
            self.s1.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchor_set((shifted,), (), self.key_a),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_end_failure_in_first_package_at_last_receipt(self):
        shifted = RotatedChain(
            (self.s0, self.s1),
            (self.r0,),
            self.s0.consistency.old,
            _replace(self.s1.consistency.new, signature=b"\x00" * 64),
        )
        self.assertEqual(
            inspect_rotated_anchor_set((shifted,), (), self.key_a),
            ContinuationChainReport(False, 1, "end"),
        )

    def test_end_failure_in_later_package_rebased(self):
        shifted = RotatedChain(
            (self.s2, self.s3),
            (self.r2,),
            self.s2.consistency.old,
            _replace(self.s3.consistency.new, signature=b"\x00" * 64),
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, shifted), (self.b0,), self.key_a
            ),
            ContinuationChainReport(False, 3, "end"),
        )

    def test_start_failure_in_later_package_rebased(self):
        # p1's own receipts live over a different history at the same
        # sizes, so its start anchor (the genuine "record" size-6
        # checkpoint, equal to the bridge's new checkpoint) does not equal
        # its first receipt's "other" size-6 checkpoint: the bridge still
        # joins on both anchors, then the package reports "start" at its
        # first global position.
        s2_other = _segment(6, 8, _SEED_C, prefix="other")
        r2_other = _rotation(_SEED_C, _SEED_D, 8, prefix="other")
        s3_other = _segment(8, 11, _SEED_D, prefix="other")
        shifted = RotatedChain(
            (s2_other, s3_other),
            (r2_other,),
            self.s2.consistency.old,
            s3_other.consistency.new,
        )
        self.assertEqual(self.b0[2], shifted.start)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, shifted), (self.b0,), self.key_a
            ),
            ContinuationChainReport(False, 2, "start"),
        )

    def test_first_package_failure_masks_bridge(self):
        s0_other = _segment(0, 3, _SEED_D)
        broken = _package((s0_other, self.s1), (self.r0,))
        forged_auth = (
            self.b0[0],
            self.b0[1],
            self.b0[2],
            b"\x00" * 64,
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                (broken, self.p1), (forged_auth,), self.key_a
            ),
            ContinuationChainReport(False, 0, "verify"),
        )

    # --- bridge: rotation_duplicate ----------------------------------

    def test_duplicate_bridge_reports_at_later_package_first_receipt(self):
        # b0 repeated as the second bridge; p1 genuinely passes under C,
        # and the repeat is caught before that boundary's seam is
        # inspected, at global position 4.
        self.assertEqual(
            inspect_rotated_anchor_set(
                self.items, (self.b0, self.b0), self.key_a
            ),
            ContinuationChainReport(False, 4, "rotation_duplicate"),
        )

    def test_bridge_equal_to_intra_package_rotation_is_not_duplicate(self):
        # Repetition is tracked only across bridges: the boundary bridge
        # happens to be tuple-equal to p0's own r0. Trust after p0 rests on
        # B, under which r0 does not verify, so this is "rotation", never
        # "rotation_duplicate".
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (self.r0,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    # --- bridge: rotation --------------------------------------------

    def test_reordered_bridge_reports_rotation_at_next_package(self):
        # b1 (D->E at size 11) cannot verify against B at the first
        # boundary, even though its checkpoints would not join either.
        self.assertEqual(
            inspect_rotated_anchor_set(
                self.items, (self.b1, self.b0), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_forged_bridge_auth_reports_rotation(self):
        old, new_key, new, _auth = self.b0
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (forged,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_bridge_wrong_new_key_reports_rotation(self):
        old, _new_key, new, auth = self.b0
        claimed = (old, self.key_d, new, auth)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (claimed,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_bad_bridge_at_second_boundary_indexed_at_four(self):
        old, new_key, new, _auth = self.b1
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotated_anchor_set(
                self.items, (self.b0, forged), self.key_a
            ),
            ContinuationChainReport(False, 4, "rotation"),
        )

    # --- bridge: rotation_link ---------------------------------------

    def test_bridge_at_wrong_size_reports_rotation_link(self):
        # A genuine B->C rotation over the size-5 snapshot, not the size-6
        # seam where the packages meet.
        other = _rotation(_SEED_B, _SEED_C, 5)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (other,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_link"),
        )

    def test_bridge_old_mismatch_reports_rotation_link(self):
        # Genuine under B but over another history at the same size:
        # version/hash/size agree, root/head/signature do not.
        other = _rotation(_SEED_B, _SEED_C, 6, prefix="other")
        self.assertEqual(other[0].size, self.p0.end.size)
        self.assertNotEqual(other[0], self.p0.end)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (other,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_link"),
        )

    def test_rotation_link_at_second_boundary_indexed_at_four(self):
        other = _rotation(_SEED_D, _SEED_E, 10)
        self.assertEqual(
            inspect_rotated_anchor_set(
                self.items, (self.b0, other), self.key_a
            ),
            ContinuationChainReport(False, 4, "rotation_link"),
        )

    def test_bridge_failure_precedes_package_failure(self):
        # The bridge genuinely verifies under B but joins neither side,
        # and p1's first segment is also signed by an unauthorized key:
        # the seam must be reported, not the segment.
        other = _rotation(_SEED_B, _SEED_C, 5)
        s2_other = _segment(6, 8, _SEED_D)
        p1 = _package((s2_other, self.s3), (self.r2,))
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, p1), (other,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_link"),
        )

    def test_bridge_new_mismatch_reports_rotation_link(self):
        # The genuine bridge passes verify_rotation and joins p0's end, but
        # the later package's persisted start anchor attests another
        # history at the same boundary size: bridge[2] != item.start even
        # though version, hash_name and size all agree.
        other_start = _segment(
            6, 8, _SEED_C, prefix="other"
        ).consistency.old
        shifted = RotatedChain(
            (self.s2, self.s3),
            (self.r2,),
            other_start,
            self.s3.consistency.new,
        )
        self.assertEqual(other_start.size, self.b0[2].size)
        self.assertNotEqual(other_start, self.b0[2])
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, shifted), (self.b0,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_link"),
        )

    def test_rotation_link_requires_all_six_fields_equal(self):
        # The later package's start anchor differs from the bridge's new
        # checkpoint in the Ed25519 signature alone (same snapshot in
        # version, hash_name, size, root and head): the seam must already
        # fail, and it is diagnosed before the package itself.
        forged_start = _replace(self.s2.consistency.old, signature=b"\x01" * 64)
        shifted = RotatedChain(
            (self.s2, self.s3),
            (self.r2,),
            forged_start,
            self.s3.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, shifted), (self.b0,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_link"),
        )

    # --- input validation --------------------------------------------

    def test_empty_items_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set((), (), self.key_a)

    def test_bridge_count_must_be_packages_minus_one(self):
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (), self.key_a
            )
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set(
                (self.p0,), (self.b0,), self.key_a
            )
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set(
                self.items, (self.b0,), self.key_a
            )
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set(
                self.items,
                (self.b0, self.b1, self.b0),
                self.key_a,
            )

    def test_non_tuple_items_raises_type_error(self):
        for bad in (
            [self.p0],
            {self.p0},
            None,
            self.p0,
            "items",
            1,
        ):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set(bad, (), self.key_a)

    def test_non_tuple_bridges_raises_type_error(self):
        for bad in ([], None, "bridges", 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set(
                        (self.p0,), bad, self.key_a
                    )

    def test_generator_arguments_raise_type_error(self):
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set(
                (p for p in self.items), self.bridges, self.key_a
            )
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set(
                (self.p0,), (b for b in ()), self.key_a
            )

    def test_wrong_item_element_type_raises_type_error(self):
        anchored = AnchoredContinuationChain(
            self.p0.receipts, self.p0.start, self.p0.end
        )
        for bad in (b"bytes", "package", None, 1, self.s0, anchored):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set(
                        (bad,), (), self.key_a
                    )
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set(
                        (self.p0, bad), (self.b0,), self.key_a
                    )

    def test_wrong_bridge_element_type_raises_type_error(self):
        for bad in (b"bytes", "bridge", None, 1, object(), [self.b0]):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set(
                        (self.p0, self.p1), (bad,), self.key_a
                    )

    def test_inner_three_tuple_bridge_raises_value_error(self):
        # A bridge tuple of the wrong arity is verify_rotation's nested
        # ValueError and must propagate unchanged.
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (self.b0[:3],), self.key_a
            )

    def test_nested_package_structural_error_propagates(self):
        # A package whose first receipt has its bundle slot bypassed to a
        # non-bundle: isinstance checks still pass, but the nested
        # verify_signed_auth_audit_continuation TypeError propagates
        # unchanged rather than becoming a "verify" report.
        bypassed_receipt = object.__new__(SignedAuthAuditContinuation)
        object.__setattr__(bypassed_receipt, "bundle", "not-a-bundle")
        object.__setattr__(
            bypassed_receipt, "consistency", self.s0.consistency
        )
        bypassed = object.__new__(RotatedChain)
        object.__setattr__(
            bypassed, "receipts", (bypassed_receipt, self.s1)
        )
        object.__setattr__(bypassed, "rotations", (self.r0,))
        object.__setattr__(bypassed, "start", self.p0.start)
        object.__setattr__(bypassed, "end", self.p0.end)
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set((bypassed,), (), self.key_a)

    def test_key_type_raises_type_error(self):
        for bad in ("k", bytearray(self.key_a), None, 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set(
                        (self.p0,), (), bad
                    )

    def test_key_length_raises_value_error(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    inspect_rotated_anchor_set(
                        (self.p0,), (), bad
                    )

    def test_arguments_have_no_defaults(self):
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set(  # type: ignore[call-arg]
                self.items, self.bridges
            )
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set(self.items)  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set()  # type: ignore[call-arg]

    # --- read-only ----------------------------------------------------

    def test_call_is_read_only(self):
        package_bytes_before = tuple(
            encode_rotated_anchor(p) for p in self.items
        )
        bridge_bytes_before = tuple(
            encode_rotation(b) for b in self.bridges
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                self.items, self.bridges, self.key_a
            ),
            _OK,
        )
        self.assertEqual(
            tuple(encode_rotated_anchor(p) for p in self.items),
            package_bytes_before,
        )
        self.assertEqual(
            tuple(encode_rotation(b) for b in self.bridges),
            bridge_bytes_before,
        )

    def test_failed_diagnosis_is_read_only(self):
        other = _rotation(_SEED_B, _SEED_C, 5)
        bridges = (other,)
        package_bytes_before = tuple(
            encode_rotated_anchor(p) for p in (self.p0, self.p1)
        )
        bridge_bytes_before = tuple(encode_rotation(b) for b in bridges)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), bridges, self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_link"),
        )
        self.assertEqual(
            tuple(
                encode_rotated_anchor(p) for p in (self.p0, self.p1)
            ),
            package_bytes_before,
        )
        self.assertEqual(
            tuple(encode_rotation(b) for b in bridges),
            bridge_bytes_before,
        )


if __name__ == "__main__":
    unittest.main()
