import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    ContinuationChainReport,
    RotatedChain,
    encode_rotation,
    encode_rotated_anchor,
    encode_signed_auth_audit_continuation,
    inspect_rotated_anchor_set,
    inspect_rotated_anchors,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(3, 35))
_SEED_E = bytes(range(5, 37))
_KEY = b"super-secret-verifier-key"

_OK = ContinuationChainReport(True, None, None)


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(n=12, key=_KEY, hash_name="sha256", prefix="record"):
    # Every artifact is minted from a fresh log over identical content.
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


class InspectRotatedAnchorSetTest(unittest.TestCase):
    def setUp(self):
        # Package 0: (0,3) under A, A->B at 3, (3,6) under B.
        self.s0 = _segment(0, 3, _SEED_A)
        self.r_ab = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.p0 = RotatedChain(
            (self.s0, self.s1),
            (self.r_ab,),
            self.s0.consistency.old,
            self.s1.consistency.new,
        )
        # Bridge B->C at the size-6 seam.
        self.b_bc = _rotation(_SEED_B, _SEED_C, 6)
        # Package 1: (6,8) under C, C->D at 8, (8,11) under D.
        self.s2 = _segment(6, 8, _SEED_C)
        self.r_cd = _rotation(_SEED_C, _SEED_D, 8)
        self.s3 = _segment(8, 11, _SEED_D)
        self.p1 = RotatedChain(
            (self.s2, self.s3),
            (self.r_cd,),
            self.s2.consistency.old,
            self.s3.consistency.new,
        )
        # A third package beyond another seam: D->E at 11, (11,12) under E,
        # E->A at 12, (12,14) under A.
        self.b_de = _rotation(_SEED_D, _SEED_E, 11)
        self.s4 = _segment(11, 12, _SEED_E, n=14)
        self.r_ea = _rotation(_SEED_E, _SEED_A, 12)
        self.s5 = _segment(12, 14, _SEED_A, n=14)
        self.p2 = RotatedChain(
            (self.s4, self.s5),
            (self.r_ea,),
            self.s4.consistency.old,
            self.s5.consistency.new,
        )
        self.key_a = _public_key(_SEED_A)
        self.key_c = _public_key(_SEED_C)
        self.key_d = _public_key(_SEED_D)
        self.key_e = _public_key(_SEED_E)

    # --- success -----------------------------------------------------

    def test_success_report_shape(self):
        report = inspect_rotated_anchor_set(
            (self.p0, self.p1), (self.b_bc,), self.key_a
        )
        self.assertEqual(report, _OK)
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertEqual((report.ok, report.index, report.code), (True, None, None))

    def test_single_package_empty_bridges_reports_ok(self):
        self.assertEqual(
            inspect_rotated_anchor_set((self.p0,), (), self.key_a), _OK
        )

    def test_three_packages_report_ok_with_only_first_key(self):
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1, self.p2),
                (self.b_bc, self.b_de),
                self.key_a,
            ),
            _OK,
        )

    def test_restored_packages_report_ok(self):
        # The cross-process flow: each package encoded and decoded on its
        # own, each bridge encoded and decoded on its own, then diagnosed.
        from auditchain import decode_rotation, decode_rotated_anchor

        restored_packages = tuple(
            decode_rotated_anchor(encode_rotated_anchor(p))
            for p in (self.p0, self.p1)
        )
        restored_bridges = tuple(
            decode_rotation(encode_rotation(b)) for b in (self.b_bc,)
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                restored_packages, restored_bridges, self.key_a
            ),
            _OK,
        )

    def test_agrees_with_inspect_rotated_anchors_per_package(self):
        self.assertEqual(
            inspect_rotated_anchors(self.p0, self.key_a), _OK
        )
        self.assertEqual(
            inspect_rotated_anchors(self.p1, self.key_c), _OK
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (self.b_bc,), self.key_a
            ),
            _OK,
        )

    # --- inter-package bridge codes ----------------------------------

    def test_bridge_verify_failure_reports_rotation_at_later_package(self):
        old, new_key, new, _auth = self.b_bc
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (forged,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_bridge_wrong_new_key_reports_rotation(self):
        old, _new_key, new, auth = self.b_bc
        claimed = (old, self.key_e, new, auth)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (claimed,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_bridge_under_wrong_current_key_reports_rotation(self):
        # b_de (D->E) at the B|C boundary cannot verify under B.
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (self.b_de,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_bridge_at_other_size_reports_rotation_link(self):
        other = _rotation(_SEED_B, _SEED_C, 5)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (other,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_link"),
        )

    def test_rotation_link_requires_all_six_fields(self):
        # A genuine B->C rotation at size 6 over a different history:
        # version, hash_name and size agree at the seam, but root, head and
        # signature all differ from the preceding package's end.
        other = _rotation(_SEED_B, _SEED_C, 6, prefix="other")
        self.assertEqual(other[0].size, self.p0.end.size)
        self.assertNotEqual(other[0], self.p0.end)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (other,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_link"),
        )

    def test_bridge_codes_index_later_package_first_receipt(self):
        # p0 contributes two receipts, so every code at its boundary is at
        # global position 2; the second boundary lands at position 4.
        old, new_key, new, _auth = self.b_de
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1, self.p2),
                (self.b_bc, forged),
                self.key_a,
            ),
            ContinuationChainReport(False, 4, "rotation"),
        )
        other = _rotation(_SEED_D, _SEED_E, 10)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1, self.p2),
                (self.b_bc, other),
                self.key_a,
            ),
            ContinuationChainReport(False, 4, "rotation_link"),
        )

    def test_duplicate_bridge_reports_rotation_duplicate(self):
        # The first bridge repeated at the second boundary: the later
        # package's first receipt is at global position 4.
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1, self.p2),
                (self.b_bc, self.b_bc),
                self.key_a,
            ),
            ContinuationChainReport(False, 4, "rotation_duplicate"),
        )

    def test_duplicate_bridge_check_compares_all_fields(self):
        # A bridge equal in old/new/new_key but carrying another auth is a
        # different tuple: it is not a duplicate, it fails verify_rotation.
        old, new_key, new, _auth = self.b_bc
        altered = (old, new_key, new, b"\x00" * 64)
        self.assertNotEqual(altered, self.b_bc)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1, self.p2),
                (self.b_bc, altered),
                self.key_a,
            ),
            ContinuationChainReport(False, 4, "rotation"),
        )

    def test_only_first_broken_boundary_is_reported(self):
        old, new_key, new, _auth = self.b_bc
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1, self.p2),
                (forged, self.b_de),
                self.key_a,
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_boundary_is_diagnosed_before_later_package(self):
        # The bridge is forged and the later package would also fail under
        # the key the hop claims to teach; the boundary is reported first.
        old, new_key, new, _auth = self.b_bc
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (forged,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_bridge_old_must_equal_previous_package_end(self):
        # A seam over a different history at the same boundary size: the
        # genuine B->C signatures verify, but neither checkpoint joins the
        # actual seam, so rotation_link is reported.
        other = _rotation(_SEED_B, _SEED_C, 6, prefix="other")
        self.assertEqual(other[0].size, self.p0.end.size)
        self.assertNotEqual(other[0], self.p0.end)
        self.assertNotEqual(other[2], self.p1.start)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (other,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_link"),
        )

    # --- trust hopping -----------------------------------------------

    def test_current_key_tracks_last_internal_rotation(self):
        # p0 ends under B: without the matching B->C bridge the next
        # package, internally starting under C, cannot be reached. A
        # genuine C->D rotation at the seam cannot verify under B.
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (self.r_cd,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_wrong_initial_key_fails_first_package_at_zero(self):
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (self.b_bc,), self.key_e
            ),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_bridge_new_key_authorizes_following_package(self):
        # Swap the bridge to teach E instead of C; p1 starts under C, so
        # the bridge verifies but its new checkpoint/key pair does not join
        # p1 (reported as rotation_link, never a misattributed verify).
        swapped = _rotation(_SEED_B, _SEED_E, 6)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (swapped,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_link"),
        )

    # --- package-internal failures, re-based -------------------------

    def test_internal_rotation_failure_rebased(self):
        # p1 with the genuine C->D rotation reordered to a D->C one fails
        # inside the package at its local index 1 — global position 3.
        reordered = RotatedChain(
            (self.s2, self.s3),
            (self.r_ea,),
            self.s2.consistency.old,
            self.s3.consistency.new,
        )
        report = inspect_rotated_anchor_set(
            (self.p0, reordered), (self.b_bc,), self.key_a
        )
        self.assertEqual(report.index, 3)
        self.assertEqual(report.code, "rotation")

    def test_internal_verify_failure_rebased(self):
        # p1's last segment signed by E instead of D: the internal seam
        # fails first (rotation_link at local 1, global 3).
        s3_other = _segment(8, 11, _SEED_E)
        broken = RotatedChain(
            (self.s2, s3_other),
            (self.r_cd,),
            self.s2.consistency.old,
            s3_other.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, broken), (self.b_bc,), self.key_a
            ),
            ContinuationChainReport(False, 3, "rotation_link"),
        )

    def test_internal_end_failure_rebased(self):
        # Internally continuous p1 anchored against the wrong end: only
        # its "end" check fails, at local 1 — global 3.
        broken = RotatedChain(
            (self.s2, self.s3),
            (self.r_cd,),
            self.s2.consistency.old,
            self.s2.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, broken), (self.b_bc,), self.key_a
            ),
            ContinuationChainReport(False, 3, "end"),
        )

    def test_internal_verify_failure_with_sound_seam_rebased(self):
        # The later package's first receipt keeps s2's genuine consistency
        # (so the inter-package bridge and the package's start anchor all
        # join) but carries a bundle signed by E: verify fails against the
        # bridge-taught key C, at the package's first global position 2.
        from auditchain import SignedAuthAuditContinuation

        foreign = _segment(6, 8, _SEED_E)
        merged_first = SignedAuthAuditContinuation(
            foreign.bundle, self.s2.consistency
        )
        broken = RotatedChain(
            (merged_first, self.s3),
            (self.r_cd,),
            self.s2.consistency.old,
            self.s3.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, broken), (self.b_bc,), self.key_a
            ),
            ContinuationChainReport(False, 2, "verify"),
        )

    def test_internal_growth_failure_rebased(self):
        # A zero-length second segment inside the later package: its seams
        # join and it verifies under D, but 8 >= 8 reports growth at its
        # local index 1 — global position 3.
        equal = _segment(8, 8, _SEED_D, n=10)
        broken = RotatedChain(
            (self.s2, equal),
            (self.r_cd,),
            self.s2.consistency.old,
            equal.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, broken), (self.b_bc,), self.key_a
            ),
            ContinuationChainReport(False, 3, "growth"),
        )

    def test_first_package_failure_reported_at_zero(self):
        broken = RotatedChain(
            (self.s0, self.s1),
            (self.r_ab,),
            self.s0.consistency.old,
            self.s2.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                (broken, self.p1), (self.b_bc,), self.key_a
            ),
            ContinuationChainReport(False, 1, "end"),
        )

    def test_internal_failure_masks_broken_boundary(self):
        # The bridge also fails, but p0 itself is broken and diagnosed
        # first; later bridges are never examined.
        broken0 = RotatedChain(
            (self.s0, self.s1),
            (self.r_ab,),
            self.s0.consistency.old,
            self.s2.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                (broken0, self.p1), (self.b_bc,), self.key_a
            ),
            ContinuationChainReport(False, 1, "end"),
        )

    # --- input validation --------------------------------------------

    def test_empty_items_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set((), (), self.key_a)

    def test_bridge_count_must_be_packages_minus_one(self):
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set((self.p0,), (self.b_bc,), self.key_a)
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set((self.p0, self.p1), (), self.key_a)
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set(
                (self.p0, self.p1),
                (self.b_bc, self.b_de),
                self.key_a,
            )

    def test_non_tuple_items_raises_type_error(self):
        for bad in ([self.p0], {self.p0}, None, self.p0, "p", 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set(bad, (), self.key_a)

    def test_non_tuple_bridges_raises_type_error(self):
        for bad in ([], None, "bridges", 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set((self.p0,), bad, self.key_a)

    def test_generator_arguments_raise_type_error(self):
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set(
                (p for p in (self.p0,)), (), self.key_a
            )
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set(
                (self.p0,), (b for b in ()), self.key_a
            )

    def test_wrong_item_element_type_raises_type_error(self):
        for bad in (b"bytes", "package", None, 1, self.s0, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set((bad,), (), self.key_a)
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set(
                        (self.p0, bad), (self.b_bc,), self.key_a
                    )

    def test_wrong_bridge_element_type_raises_type_error(self):
        for bad in (b"bytes", "bridge", None, 1, object(), [self.b_bc]):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set(
                        (self.p0, self.p1), (bad,), self.key_a
                    )

    def test_inner_three_tuple_bridge_propagates_value_error(self):
        with self.assertRaises(ValueError):
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (self.b_bc[:3],), self.key_a
            )

    def test_key_type_raises_type_error(self):
        for bad in ("key", bytearray(self.key_a), None, 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchor_set(
                        (self.p0, self.p1), (self.b_bc,), bad
                    )

    def test_key_length_raises_value_error(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    inspect_rotated_anchor_set(
                        (self.p0, self.p1), (self.b_bc,), bad
                    )

    # --- read-only ----------------------------------------------------

    def test_call_is_read_only(self):
        package_bytes_before = tuple(
            encode_rotated_anchor(p) for p in (self.p0, self.p1, self.p2)
        )
        bridge_bytes_before = tuple(
            encode_rotation(b) for b in (self.b_bc, self.b_de)
        )
        receipt_bytes_before = tuple(
            encode_signed_auth_audit_continuation(r)
            for p in (self.p0, self.p1, self.p2)
            for r in p.receipts
        )
        inspect_rotated_anchor_set(
            (self.p0, self.p1, self.p2),
            (self.b_bc, self.b_de),
            self.key_a,
        )
        self.assertEqual(
            tuple(encode_rotated_anchor(p) for p in (self.p0, self.p1, self.p2)),
            package_bytes_before,
        )
        self.assertEqual(
            tuple(encode_rotation(b) for b in (self.b_bc, self.b_de)),
            bridge_bytes_before,
        )
        self.assertEqual(
            tuple(
                encode_signed_auth_audit_continuation(r)
                for p in (self.p0, self.p1, self.p2)
                for r in p.receipts
            ),
            receipt_bytes_before,
        )

    def test_failed_diagnosis_is_read_only(self):
        before = (
            encode_rotated_anchor(self.p0),
            encode_rotated_anchor(self.p1),
            encode_rotation(self.b_bc),
        )
        old, new_key, new, _auth = self.b_bc
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotated_anchor_set(
                (self.p0, self.p1), (forged,), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )
        self.assertEqual(
            (
                encode_rotated_anchor(self.p0),
                encode_rotated_anchor(self.p1),
                encode_rotation(self.b_bc),
            ),
            before,
        )

    def test_arguments_have_no_defaults(self):
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set(  # type: ignore[call-arg]
                (self.p0, self.p1), self.key_a
            )
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set((self.p0,), ())  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            inspect_rotated_anchor_set()  # type: ignore[call-arg]


if __name__ == "__main__":
    unittest.main()
