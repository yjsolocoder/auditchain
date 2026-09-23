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
    SignedAuthAuditContinuation,
    SignedConsistency,
    SignedRoot,
    decode_continuations,
    decode_rotated_anchor,
    decode_rotations,
    encode_continuations,
    encode_rotation,
    encode_rotated_anchor,
    encode_rotations,
    encode_signed_auth_audit_continuation,
    encode_signed_root,
    inspect_rotated_anchors,
    inspect_rotated_chain,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(3, 35))
_KEY = b"super-secret-verifier-key"
_MAGIC = b"auditchain/ra/v1\0"

_OK = ContinuationChainReport(True, None, None)


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(n=8, key=_KEY, hash_name="sha256", prefix="record"):
    # Each continuation consumes the log holder's one-shot verifier export,
    # so every artifact is minted from a fresh log over identical content.
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


def _u64(value):
    return value.to_bytes(8, "big")


def _blob(material):
    return _u64(len(material)) + material


class RotatedChainBundleTest(unittest.TestCase):
    def setUp(self):
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.r1 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.start = self.s0.consistency.old
        self.end = self.s2.consistency.new

    def _bundle(self, receipts=None, rotations=None, start=None, end=None):
        return RotatedChain(
            (self.s0, self.s1, self.s2) if receipts is None else receipts,
            (self.r0, self.r1) if rotations is None else rotations,
            self.start if start is None else start,
            self.end if end is None else end,
        )

    def test_positional_construction_and_equality(self):
        bundle = self._bundle()
        again = RotatedChain(
            (self.s0, self.s1, self.s2),
            (self.r0, self.r1),
            self.start,
            self.end,
        )
        self.assertEqual(bundle, again)
        self.assertEqual(hash(bundle), hash(again))
        self.assertEqual(
            (bundle.receipts, bundle.rotations, bundle.start, bundle.end),
            (again.receipts, again.rotations, again.start, again.end),
        )

    def test_keyword_construction(self):
        bundle = self._bundle()
        self.assertEqual(
            RotatedChain(
                receipts=(self.s0, self.s1, self.s2),
                rotations=(self.r0, self.r1),
                start=self.start,
                end=self.end,
            ),
            bundle,
        )

    def test_two_segments_one_rotation_is_enough(self):
        bundle = RotatedChain(
            (self.s0, self.s1), (self.r0,), self.start, self.s1.consistency.new
        )
        self.assertEqual(len(bundle.receipts), 2)
        self.assertEqual(len(bundle.rotations), 1)

    def test_inequality_by_each_field(self):
        bundle = self._bundle()
        other_s1 = _segment(3, 6, _SEED_B, prefix="other")
        self.assertNotEqual(
            bundle,
            RotatedChain(
                (self.s0, other_s1, self.s2),
                (self.r0, self.r1),
                self.start,
                self.end,
            ),
        )
        r_other = _rotation(_SEED_A, _SEED_B, 3, prefix="other")
        self.assertNotEqual(
            bundle,
            RotatedChain(
                (self.s0, self.s1, self.s2),
                (r_other, self.r1),
                self.start,
                self.end,
            ),
        )
        shifted_start = self.s1.consistency.old
        self.assertNotEqual(
            bundle,
            RotatedChain(
                (self.s0, self.s1, self.s2),
                (self.r0, self.r1),
                shifted_start,
                self.end,
            ),
        )
        shifted_end = self.s1.consistency.new
        self.assertNotEqual(
            bundle,
            RotatedChain(
                (self.s0, self.s1, self.s2),
                (self.r0, self.r1),
                self.start,
                shifted_end,
            ),
        )

    def test_frozen(self):
        bundle = self._bundle()
        with self.assertRaises(Exception):
            bundle.start = self.end
        with self.assertRaises(Exception):
            bundle.rotations = ()

    def test_single_segment_rejected(self):
        # A rotated chain crosses at least one signer boundary.
        with self.assertRaises(ValueError):
            RotatedChain((self.s0,), (), self.start, self.s0.consistency.new)

    def test_empty_receipts_tuple_rejected(self):
        with self.assertRaises(ValueError):
            RotatedChain((), (), self.start, self.end)

    def test_rotation_count_must_be_segments_minus_one(self):
        with self.assertRaises(ValueError):
            RotatedChain(
                (self.s0, self.s1), (), self.start, self.s1.consistency.new
            )
        with self.assertRaises(ValueError):
            RotatedChain(
                (self.s0, self.s1, self.s2),
                (self.r0,),
                self.start,
                self.end,
            )
        with self.assertRaises(ValueError):
            RotatedChain(
                (self.s0, self.s1, self.s2),
                (self.r0, self.r1, self.r0),
                self.start,
                self.end,
            )

    def test_non_tuple_receipts_raise_type_error(self):
        for bad in ([self.s0, self.s1], self.s0, None, "receipts", 1):
            with self.assertRaises(TypeError, msg=bad):
                RotatedChain(bad, (self.r0,), self.start, self.end)

    def test_non_tuple_rotations_raise_type_error(self):
        for bad in ([self.r0], None, "rotations", 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                RotatedChain((self.s0, self.s1), bad, self.start, self.end)

    def test_wrong_receipt_element_type_raises_type_error(self):
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                RotatedChain(
                    (bad, self.s1), (self.r0,), self.start, self.end
                )

    def test_wrong_rotation_element_type_raises_type_error(self):
        for bad in (b"bytes", "rotation", None, 1, object(), [self.r0]):
            with self.assertRaises(TypeError, msg=bad):
                RotatedChain(
                    (self.s0, self.s1), (bad,), self.start, self.end
                )

    def test_non_signed_root_anchors_raise_type_error(self):
        for bad in (b"bytes", "anchor", None, 1, (self.start,), object()):
            with self.assertRaises(TypeError, msg=bad):
                RotatedChain(
                    (self.s0, self.s1), (self.r0,), bad, self.end
                )
            with self.assertRaises(TypeError, msg=bad):
                RotatedChain(
                    (self.s0, self.s1), (self.r0,), self.start, bad
                )

    def test_inner_rotation_arity_not_validated_here(self):
        # Only the rotation container type is checked; arity is left to
        # verify_rotation, exactly as inspect_rotated_chain treats it.
        bundle = RotatedChain(
            (self.s0, self.s1),
            (self.r0[:3],),
            self.start,
            self.s1.consistency.new,
        )
        self.assertEqual(len(bundle.rotations[0]), 3)


class EncodeRotatedAnchorTest(unittest.TestCase):
    def setUp(self):
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.r1 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.bundle = RotatedChain(
            (self.s0, self.s1, self.s2),
            (self.r0, self.r1),
            self.s0.consistency.old,
            self.s2.consistency.new,
        )

    def test_canonical_stream_layout(self):
        expected = b"".join((
            _MAGIC,
            _u64(1),
            _blob(encode_continuations(self.bundle.receipts)),
            _blob(encode_rotations(self.bundle.rotations)),
            _blob(encode_signed_root(self.bundle.start)),
            _blob(encode_signed_root(self.bundle.end)),
        ))
        self.assertEqual(encode_rotated_anchor(self.bundle), expected)

    def test_four_blobs_reuse_existing_encodings(self):
        data = encode_rotated_anchor(self.bundle)
        offset = len(_MAGIC) + 8

        def take_blob():
            nonlocal offset
            length = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            blob = data[offset:offset + length]
            offset += length
            return blob

        chain_blob = take_blob()
        rotation_blob = take_blob()
        start_blob = take_blob()
        end_blob = take_blob()
        self.assertEqual(offset, len(data))
        self.assertEqual(
            chain_blob, encode_continuations(self.bundle.receipts)
        )
        self.assertEqual(decode_continuations(chain_blob), self.bundle.receipts)
        self.assertEqual(
            rotation_blob, encode_rotations(self.bundle.rotations)
        )
        self.assertEqual(
            decode_rotations(rotation_blob), self.bundle.rotations
        )
        self.assertEqual(start_blob, encode_signed_root(self.bundle.start))
        self.assertEqual(end_blob, encode_signed_root(self.bundle.end))

    def test_non_bundle_raises_type_error(self):
        for bad in (
            self.bundle.receipts,
            (self.bundle.receipts, self.bundle.rotations),
            b"bytes",
            "bundle",
            None,
            1,
            object(),
        ):
            with self.assertRaises(TypeError, msg=bad):
                encode_rotated_anchor(bad)

    def test_nested_encode_exception_propagates(self):
        corrupt = SignedRoot(
            self.bundle.start.version,
            self.bundle.start.hash_name,
            self.bundle.start.size,
            self.bundle.start.root,
            self.bundle.start.head,
            self.bundle.start.signature,
        )
        object.__setattr__(corrupt, "signature", b"\x00" * 63)
        object.__setattr__(self.bundle, "end", corrupt)
        with self.assertRaises(ValueError):
            encode_rotated_anchor(self.bundle)

    def test_call_is_read_only(self):
        receipts_before = tuple(
            encode_signed_auth_audit_continuation(r)
            for r in self.bundle.receipts
        )
        rotations_before = tuple(
            encode_rotation(r) for r in self.bundle.rotations
        )
        encode_rotated_anchor(self.bundle)
        self.assertEqual(
            tuple(
                encode_signed_auth_audit_continuation(r)
                for r in self.bundle.receipts
            ),
            receipts_before,
        )
        self.assertEqual(
            tuple(encode_rotation(r) for r in self.bundle.rotations),
            rotations_before,
        )


class DecodeRotatedAnchorTest(unittest.TestCase):
    def setUp(self):
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.r1 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.bundle = RotatedChain(
            (self.s0, self.s1, self.s2),
            (self.r0, self.r1),
            self.s0.consistency.old,
            self.s2.consistency.new,
        )

    def test_round_trip_restores_frozen_equal_bundle(self):
        data = encode_rotated_anchor(self.bundle)
        restored = decode_rotated_anchor(data)
        self.assertIsInstance(restored, RotatedChain)
        self.assertEqual(restored, self.bundle)
        self.assertEqual(
            (restored.receipts, restored.rotations),
            (self.bundle.receipts, self.bundle.rotations),
        )
        self.assertEqual(encode_rotated_anchor(restored), data)
        with self.assertRaises(Exception):
            restored.end = self.bundle.start

    def test_two_segment_round_trip_preserves_order(self):
        bundle = RotatedChain(
            (self.s0, self.s2),
            (self.r1,),
            self.s0.consistency.old,
            self.s2.consistency.new,
        )
        restored = decode_rotated_anchor(encode_rotated_anchor(bundle))
        self.assertEqual(restored, bundle)
        self.assertEqual(restored.receipts, (self.s0, self.s2))
        self.assertEqual(restored.rotations, (self.r1,))

    def test_non_bytes_raises_type_error(self):
        data = encode_rotated_anchor(self.bundle)
        for bad in (bytearray(data), memoryview(data), "data", None, 1):
            with self.assertRaises(TypeError, msg=bad):
                decode_rotated_anchor(bad)

    def test_bad_magic_raises_value_error(self):
        data = encode_rotated_anchor(self.bundle)
        for bad in (
            b"",
            b"auditchain/ra/v2\0" + data[len(_MAGIC):],
            b"\x00" + data[1:],
            b"auditchain/anchor/v1\0" + data[len(_MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=bad[:8]):
                decode_rotated_anchor(bad)

    def test_bad_version_raises_value_error(self):
        data = encode_rotated_anchor(self.bundle)
        for version in (0, 2, (1 << 64) - 1):
            broken = _MAGIC + _u64(version) + data[len(_MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_rotated_anchor(broken)

    def test_truncation_raises_value_error(self):
        data = encode_rotated_anchor(self.bundle)
        for cut in (
            len(_MAGIC),
            len(_MAGIC) + 4,
            len(_MAGIC) + 8,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_rotated_anchor(data[:cut])

    def test_trailing_bytes_raise_value_error(self):
        data = encode_rotated_anchor(self.bundle)
        with self.assertRaises(ValueError):
            decode_rotated_anchor(data + b"\x00")

    def test_oversized_blob_length_raises_value_error(self):
        data = encode_rotated_anchor(self.bundle)
        broken = _MAGIC + _u64(1) + _u64(len(data)) + data[len(_MAGIC) + 16:]
        with self.assertRaises(ValueError):
            decode_rotated_anchor(broken)

    def test_nested_chain_exception_propagates(self):
        data = b"".join((
            _MAGIC,
            _u64(1),
            _blob(b"not a continuation chain"),
            _blob(encode_rotations(self.bundle.rotations)),
            _blob(encode_signed_root(self.bundle.start)),
            _blob(encode_signed_root(self.bundle.end)),
        ))
        with self.assertRaises(ValueError):
            decode_rotated_anchor(data)

    def test_nested_rotation_exception_propagates(self):
        data = b"".join((
            _MAGIC,
            _u64(1),
            _blob(encode_continuations(self.bundle.receipts)),
            _blob(b"not a rotation chain"),
            _blob(encode_signed_root(self.bundle.start)),
            _blob(encode_signed_root(self.bundle.end)),
        ))
        with self.assertRaises(ValueError):
            decode_rotated_anchor(data)

    def test_nested_anchor_exception_propagates(self):
        for position in ("start", "end"):
            anchors = {
                "start": encode_signed_root(self.bundle.start),
                "end": encode_signed_root(self.bundle.end),
            }
            anchors[position] = b"not a signed root"
            data = b"".join((
                _MAGIC,
                _u64(1),
                _blob(encode_continuations(self.bundle.receipts)),
                _blob(encode_rotations(self.bundle.rotations)),
                _blob(anchors["start"]),
                _blob(anchors["end"]),
            ))
            with self.assertRaises(ValueError, msg=position):
                decode_rotated_anchor(data)

    def test_shape_mismatch_between_nested_blobs_rejected(self):
        # A single-segment continuation blob alongside one rotation: both
        # nested encodings are legal on their own, but the rotated-chain
        # relationship (rotations == receipts - 1) does not hold.
        one_receipt = encode_continuations((self.s0,))
        data = b"".join((
            _MAGIC,
            _u64(1),
            _blob(one_receipt),
            _blob(encode_rotations((self.r0,))),
            _blob(encode_signed_root(self.bundle.start)),
            _blob(encode_signed_root(self.bundle.end)),
        ))
        with self.assertRaises(ValueError):
            decode_rotated_anchor(data)


class InspectRotatedAnchorsTest(unittest.TestCase):
    def setUp(self):
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.r1 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.receipts = (self.s0, self.s1, self.s2)
        self.rotations = (self.r0, self.r1)
        self.start = self.s0.consistency.old
        self.end = self.s2.consistency.new
        self.key_a = _public_key(_SEED_A)
        self.key_d = _public_key(_SEED_D)

    def _bundle(self, receipts=None, rotations=None, start=None, end=None):
        return RotatedChain(
            self.receipts if receipts is None else receipts,
            self.rotations if rotations is None else rotations,
            self.start if start is None else start,
            self.end if end is None else end,
        )

    # --- success -----------------------------------------------------

    def test_success_report_shape(self):
        report = inspect_rotated_anchors(self._bundle(), self.key_a)
        self.assertEqual(report, _OK)
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)

    def test_two_segment_chain_reports_ok(self):
        bundle = RotatedChain(
            (self.s0, self.s1),
            (self.r0,),
            self.start,
            self.s1.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a), _OK
        )

    def test_restored_bundle_reports_ok(self):
        # The cross-process flow: encode, decode, diagnose — no log held.
        restored = decode_rotated_anchor(
            encode_rotated_anchor(self._bundle())
        )
        self.assertEqual(
            inspect_rotated_anchors(restored, self.key_a), _OK
        )

    def test_agrees_with_inspect_rotated_chain_when_anchors_match(self):
        bundle = self._bundle()
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a),
            inspect_rotated_chain(
                bundle.receipts, bundle.rotations, self.key_a
            ),
        )

    # --- anchor codes ------------------------------------------------

    def test_wrong_start_reports_start_at_zero(self):
        bundle = self._bundle(start=self.s1.consistency.old)
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_wrong_end_reports_end_at_last_index(self):
        bundle = self._bundle(end=self.s1.consistency.new)
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a),
            ContinuationChainReport(False, 2, "end"),
        )

    def test_start_mismatch_takes_priority_over_end(self):
        bundle = self._bundle(
            start=self.s1.consistency.old, end=self.s1.consistency.new
        )
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_anchor_compared_by_all_six_signed_root_fields(self):
        old = self.start
        forged = type(old)(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        # The forged anchor also makes the chain unverifiable only if it
        # appeared in a receipt; as a standalone expected anchor it must be
        # reported as "start", not "verify".
        bundle = self._bundle(start=forged)
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a),
            ContinuationChainReport(False, 0, "start"),
        )

    # --- internal failure codes pass through -------------------------

    def test_verify_passes_through(self):
        bundle = self._bundle()
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_d),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_rotation_codes_pass_through(self):
        duplicate = self._bundle(rotations=(self.r0, self.r0))
        self.assertEqual(
            inspect_rotated_anchors(duplicate, self.key_a),
            ContinuationChainReport(False, 2, "rotation_duplicate"),
        )
        reordered = self._bundle(rotations=(self.r1, self.r0))
        self.assertEqual(
            inspect_rotated_anchors(reordered, self.key_a),
            ContinuationChainReport(False, 1, "rotation"),
        )
        other = _rotation(_SEED_A, _SEED_B, 2)
        bad_link = self._bundle(rotations=(other, self.r1))
        self.assertEqual(
            inspect_rotated_anchors(bad_link, self.key_a),
            ContinuationChainReport(False, 1, "rotation_link"),
        )

    def test_growth_passes_through(self):
        equal = _segment(6, 6, _SEED_C)
        bundle = RotatedChain(
            (self.s0, self.s1, equal),
            (self.r0, self.r1),
            self.start,
            equal.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a),
            ContinuationChainReport(False, 2, "growth"),
        )

    def test_internal_failure_precedes_anchor_mismatch(self):
        # Both the chain and the start anchor are wrong; the internal
        # diagnosis must win, exactly as inspect_anchors behaves.
        bundle = self._bundle(
            rotations=(self.r1, self.r0), start=self.s1.consistency.old
        )
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_tampered_segment_signature_reports_verify(self):
        old = self.s1.consistency.old
        forged_old = type(old)(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        forged_consistency = SignedConsistency(
            forged_old,
            self.s1.consistency.new,
            self.s1.consistency.proof,
        )
        forged = SignedAuthAuditContinuation(
            self.s1.bundle, forged_consistency
        )
        bundle = RotatedChain(
            (self.s0, forged, self.s2),
            (self.r0, self.r1),
            self.start,
            self.end,
        )
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a),
            ContinuationChainReport(False, 1, "rotation_link"),
        )

    # --- input validation --------------------------------------------

    def test_non_bundle_raises_type_error(self):
        for bad in (
            self.receipts,
            (self.receipts, self.rotations, self.start, self.end),
            b"bytes",
            "bundle",
            None,
            1,
            object(),
        ):
            with self.assertRaises(TypeError, msg=bad):
                inspect_rotated_anchors(bad, self.key_a)

    def test_key_validation_propagates(self):
        bundle = self._bundle()
        for bad in ("key", bytearray(self.key_a), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_rotated_anchors(bundle, bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_rotated_anchors(bundle, bad)

    def test_no_default_arguments(self):
        with self.assertRaises(TypeError):
            inspect_rotated_anchors(self._bundle())  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            inspect_rotated_anchors()  # type: ignore[call-arg]

    # --- read-only ----------------------------------------------------

    def test_call_is_read_only(self):
        bundle = self._bundle()
        before = encode_rotated_anchor(bundle)
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a), _OK
        )
        self.assertEqual(encode_rotated_anchor(bundle), before)

    def test_failed_diagnosis_is_read_only(self):
        other = _rotation(_SEED_A, _SEED_B, 2)
        bundle = self._bundle(rotations=(other, self.r1))
        before = tuple(encode_rotation(r) for r in bundle.rotations)
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a),
            ContinuationChainReport(False, 1, "rotation_link"),
        )
        self.assertEqual(
            tuple(encode_rotation(r) for r in bundle.rotations), before
        )


if __name__ == "__main__":
    unittest.main()
