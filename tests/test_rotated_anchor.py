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
    SignedRoot,
    decode_continuations,
    decode_rotated_anchor,
    decode_rotations,
    encode_continuations,
    encode_rotated_anchor,
    encode_rotation,
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


class RotatedChainTest(unittest.TestCase):
    def setUp(self):
        # segment (0,3) under A, rotation A->B at size 3, segment (3,6)
        # under B, rotation B->C at size 6, segment (6,8) under C.
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.r1 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.receipts = (self.s0, self.s1, self.s2)
        self.rotations = (self.r0, self.r1)
        self.start = self.s0.consistency.old
        self.end = self.s2.consistency.new

    def _bundle(self, **kwargs):
        fields = dict(
            receipts=self.receipts,
            rotations=self.rotations,
            start=self.start,
            end=self.end,
        )
        fields.update(kwargs)
        return RotatedChain(**fields)

    def test_positional_construction_and_equality(self):
        bundle = RotatedChain(
            self.receipts, self.rotations, self.start, self.end
        )
        again = RotatedChain(
            self.receipts, self.rotations, self.start, self.end
        )
        self.assertEqual(bundle, again)
        self.assertEqual(hash(bundle), hash(again))
        self.assertEqual(
            (bundle.receipts, bundle.rotations, bundle.start, bundle.end),
            (again.receipts, again.rotations, again.start, again.end),
        )

    def test_keyword_construction(self):
        self.assertEqual(
            self._bundle(),
            RotatedChain(
                self.receipts, self.rotations, self.start, self.end
            ),
        )

    def test_two_segments_one_rotation_is_the_minimum(self):
        bundle = RotatedChain(
            (self.s0, self.s1), (self.r0,), self.start,
            self.s1.consistency.new,
        )
        self.assertEqual(len(bundle.receipts), 2)
        self.assertEqual(len(bundle.rotations), 1)

    def test_inequality_by_each_field(self):
        bundle = self._bundle()
        other = _segment(6, 8, _SEED_D)
        self.assertNotEqual(
            bundle,
            RotatedChain(
                (self.s0, self.s1, other), self.rotations,
                self.start, self.end,
            ),
        )
        self.assertNotEqual(
            bundle,
            RotatedChain(
                self.receipts, (self.r1, self.r0), self.start, self.end
            ),
        )
        self.assertNotEqual(
            bundle,
            RotatedChain(
                self.receipts, self.rotations, self.s1.consistency.old,
                self.end,
            ),
        )
        self.assertNotEqual(
            bundle,
            RotatedChain(
                self.receipts, self.rotations, self.start,
                self.s1.consistency.new,
            ),
        )

    def test_frozen(self):
        bundle = self._bundle()
        with self.assertRaises(Exception):
            bundle.end = self.start

    def test_non_tuple_receipts_raise_type_error(self):
        for bad in (
            list(self.receipts),
            self.s0,
            {self.s0, self.s1},
            None,
            "receipts",
            1,
        ):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedChain(bad, self.rotations, self.start, self.end)

    def test_non_tuple_rotations_raise_type_error(self):
        for bad in (
            list(self.rotations),
            {self.r0},
            None,
            "rotations",
            1,
            object(),
        ):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedChain(
                        self.receipts, bad, self.start, self.end
                    )

    def test_fewer_than_two_receipts_raises_value_error(self):
        with self.assertRaises(ValueError):
            RotatedChain((), (), self.start, self.end)
        with self.assertRaises(ValueError):
            RotatedChain((self.s0,), (), self.start, self.s0.consistency.new)

    def test_rotation_count_must_be_receipts_minus_one(self):
        with self.assertRaises(ValueError):
            RotatedChain(
                (self.s0, self.s1), (), self.start, self.s1.consistency.new
            )
        with self.assertRaises(ValueError):
            RotatedChain(
                self.receipts, (self.r0,), self.start, self.end
            )
        with self.assertRaises(ValueError):
            RotatedChain(
                self.receipts,
                (self.r0, self.r1, self.r0),
                self.start,
                self.end,
            )

    def test_wrong_receipt_element_type_raises_type_error(self):
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedChain(
                        (bad, self.s1), (self.r0,), self.start,
                        self.s1.consistency.new,
                    )

    def test_wrong_rotation_element_type_raises_type_error(self):
        for bad in (b"bytes", "rotation", None, 1, object(), [self.r0]):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedChain(
                        (self.s0, self.s1), (bad,), self.start,
                        self.s1.consistency.new,
                    )

    def test_non_signed_root_anchors_raise_type_error(self):
        for bad in (b"bytes", "anchor", None, 1, (self.start,), object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedChain(
                        self.receipts, self.rotations, bad, self.end
                    )
                with self.assertRaises(TypeError):
                    RotatedChain(
                        self.receipts, self.rotations, self.start, bad
                    )


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
        self.bundle = RotatedChain(
            self.receipts, self.rotations, self.start, self.end
        )
        self.key_a = _public_key(_SEED_A)
        self.key_d = _public_key(_SEED_D)

    def test_success_report_shape(self):
        report = inspect_rotated_anchors(self.bundle, self.key_a)
        self.assertEqual(report, _OK)
        self.assertIsInstance(report, ContinuationChainReport)

    def test_two_segment_bundle_reports_ok(self):
        bundle = RotatedChain(
            (self.s0, self.s1), (self.r0,), self.start,
            self.s1.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchors(bundle, self.key_a), _OK
        )

    def test_restored_bundle_reports_ok(self):
        # The cross-process flow: encode, decode, diagnose — no log held.
        restored = decode_rotated_anchor(
            encode_rotated_anchor(self.bundle)
        )
        self.assertEqual(
            inspect_rotated_anchors(restored, self.key_a), _OK
        )

    def test_agrees_with_inspect_rotated_chain(self):
        for key in (self.key_a, self.key_d):
            self.assertEqual(
                inspect_rotated_anchors(self.bundle, key),
                inspect_rotated_chain(
                    self.bundle.receipts, self.bundle.rotations, key
                ),
            )

    def test_internal_failure_codes_pass_through(self):
        # Wrong initial key: the internal rotated-chain diagnosis fails at
        # segment 0 and is returned unchanged, never re-diagnosed as an
        # anchor mismatch.
        self.assertEqual(
            inspect_rotated_anchors(self.bundle, self.key_d),
            ContinuationChainReport(False, 0, "verify"),
        )
        # A reordered boundary rotation fails at the later segment.
        reordered = RotatedChain(
            self.receipts, (self.r1, self.r0), self.start, self.end
        )
        self.assertEqual(
            inspect_rotated_anchors(reordered, self.key_a),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_start_mismatch_reports_start_at_zero(self):
        broken = RotatedChain(
            self.receipts, self.rotations, self.s1.consistency.old,
            self.end,
        )
        self.assertEqual(
            inspect_rotated_anchors(broken, self.key_a),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_end_mismatch_reports_end_at_last_segment(self):
        broken = RotatedChain(
            self.receipts, self.rotations, self.start,
            self.s1.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchors(broken, self.key_a),
            ContinuationChainReport(False, 2, "end"),
        )

    def test_start_is_checked_before_end(self):
        # Both anchors wrong: only "start" at index 0 is reported.
        broken = RotatedChain(
            self.receipts, self.rotations, self.s1.consistency.old,
            self.s1.consistency.new,
        )
        self.assertEqual(
            inspect_rotated_anchors(broken, self.key_a),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_anchor_equality_is_all_six_fields(self):
        # Same version/hash/size/root/head as the genuine start but another
        # signature: five fields matching must not be accepted as equal.
        forged = SignedRoot(
            self.start.version,
            self.start.hash_name,
            self.start.size,
            self.start.root,
            self.start.head,
            b"\x00" * 64,
        )
        self.assertEqual(forged.size, self.start.size)
        self.assertNotEqual(forged, self.start)
        broken = RotatedChain(
            self.receipts, self.rotations, forged, self.end
        )
        self.assertEqual(
            inspect_rotated_anchors(broken, self.key_a),
            ContinuationChainReport(False, 0, "start"),
        )

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
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchors(bad, self.key_a)

    def test_key_validation_propagates(self):
        for bad in ("key", bytearray(self.key_a), None, 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_anchors(self.bundle, bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    inspect_rotated_anchors(self.bundle, bad)

    def test_call_is_read_only(self):
        receipt_bytes_before = tuple(
            encode_signed_auth_audit_continuation(r)
            for r in self.receipts
        )
        rotation_bytes_before = tuple(
            encode_rotation(r) for r in self.rotations
        )
        start_bytes = encode_signed_root(self.start)
        end_bytes = encode_signed_root(self.end)
        self.assertEqual(
            inspect_rotated_anchors(self.bundle, self.key_a), _OK
        )
        self.assertEqual(
            tuple(
                encode_signed_auth_audit_continuation(r)
                for r in self.receipts
            ),
            receipt_bytes_before,
        )
        self.assertEqual(
            tuple(encode_rotation(r) for r in self.rotations),
            rotation_bytes_before,
        )
        self.assertEqual(encode_signed_root(self.start), start_bytes)
        self.assertEqual(encode_signed_root(self.end), end_bytes)


class EncodeRotatedAnchorTest(unittest.TestCase):
    def setUp(self):
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.r1 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.receipts = (self.s0, self.s1, self.s2)
        self.rotations = (self.r0, self.r1)
        self.bundle = RotatedChain(
            self.receipts,
            self.rotations,
            self.s0.consistency.old,
            self.s2.consistency.new,
        )

    def test_canonical_stream_layout(self):
        expected = b"".join((
            _MAGIC,
            _u64(1),
            _blob(encode_continuations(self.receipts)),
            _blob(encode_rotations(self.rotations)),
            _blob(encode_signed_root(self.bundle.start)),
            _blob(encode_signed_root(self.bundle.end)),
        ))
        self.assertEqual(encode_rotated_anchor(self.bundle), expected)

    def test_inner_blobs_reuse_existing_encodings(self):
        data = encode_rotated_anchor(self.bundle)
        offset = len(_MAGIC) + 8

        def take_blob():
            nonlocal offset
            length = int.from_bytes(data[offset:offset + 8], "big")
            blob = data[offset + 8:offset + 8 + length]
            offset += 8 + length
            return blob

        chain_blob = take_blob()
        rotation_blob = take_blob()
        self.assertEqual(chain_blob, encode_continuations(self.receipts))
        self.assertEqual(decode_continuations(chain_blob), self.receipts)
        self.assertEqual(rotation_blob, encode_rotations(self.rotations))
        self.assertEqual(decode_rotations(rotation_blob), self.rotations)

    def test_non_bundle_raises_type_error(self):
        for bad in (
            self.receipts,
            self.rotations,
            (self.receipts, self.rotations, self.bundle.start, self.bundle.end),
            b"bytes",
            "bundle",
            None,
            1,
            object(),
        ):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
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
        object.__setattr__(self.bundle, "start", corrupt)
        with self.assertRaises(ValueError):
            encode_rotated_anchor(self.bundle)

    def test_call_is_read_only(self):
        before = tuple(
            encode_signed_auth_audit_continuation(r)
            for r in self.receipts
        )
        encode_rotated_anchor(self.bundle)
        self.assertEqual(
            tuple(
                encode_signed_auth_audit_continuation(r)
                for r in self.receipts
            ),
            before,
        )


class DecodeRotatedAnchorTest(unittest.TestCase):
    def setUp(self):
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.r1 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.receipts = (self.s0, self.s1, self.s2)
        self.rotations = (self.r0, self.r1)
        self.bundle = RotatedChain(
            self.receipts,
            self.rotations,
            self.s0.consistency.old,
            self.s2.consistency.new,
        )
        self.key_a = _public_key(_SEED_A)

    def test_round_trip_restores_frozen_equal_bundle(self):
        data = encode_rotated_anchor(self.bundle)
        restored = decode_rotated_anchor(data)
        self.assertIsInstance(restored, RotatedChain)
        self.assertEqual(restored, self.bundle)
        self.assertEqual(encode_rotated_anchor(restored), data)
        with self.assertRaises(Exception):
            restored.end = restored.start

    def test_two_segment_round_trip_preserves_order(self):
        bundle = RotatedChain(
            (self.s0, self.s1), (self.r0,),
            self.s0.consistency.old, self.s1.consistency.new,
        )
        restored = decode_rotated_anchor(encode_rotated_anchor(bundle))
        self.assertEqual(restored, bundle)
        self.assertEqual(restored.receipts, (self.s0, self.s1))
        self.assertEqual(restored.rotations, (self.r0,))

    def test_non_bytes_raises_type_error(self):
        data = encode_rotated_anchor(self.bundle)
        for bad in (bytearray(data), memoryview(data), "data", None, 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    decode_rotated_anchor(bad)

    def test_bad_magic_raises_value_error(self):
        data = encode_rotated_anchor(self.bundle)
        for bad in (
            b"",
            b"auditchain/ra/v2\0" + data[len(_MAGIC):],
            b"\x00" + data[1:],
        ):
            with self.subTest(bad=bad[:8]):
                with self.assertRaises(ValueError):
                    decode_rotated_anchor(bad)

    def test_bad_version_raises_value_error(self):
        data = encode_rotated_anchor(self.bundle)
        for version in (0, 2, (1 << 64) - 1):
            broken = _MAGIC + _u64(version) + data[len(_MAGIC) + 8:]
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
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
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    decode_rotated_anchor(data[:cut])

    def test_trailing_bytes_raise_value_error(self):
        data = encode_rotated_anchor(self.bundle)
        with self.assertRaises(ValueError):
            decode_rotated_anchor(data + b"\x00")

    def test_oversized_blob_length_raises_value_error(self):
        data = encode_rotated_anchor(self.bundle)
        broken = (
            _MAGIC + _u64(1) + _u64(len(data))
            + data[len(_MAGIC) + 16:]
        )
        with self.assertRaises(ValueError):
            decode_rotated_anchor(broken)

    def test_nested_chain_exception_propagates(self):
        data = b"".join((
            _MAGIC,
            _u64(1),
            _blob(b"not a continuation chain"),
            _blob(encode_rotations(self.rotations)),
            _blob(encode_signed_root(self.bundle.start)),
            _blob(encode_signed_root(self.bundle.end)),
        ))
        with self.assertRaises(ValueError):
            decode_rotated_anchor(data)

    def test_nested_rotation_exception_propagates(self):
        data = b"".join((
            _MAGIC,
            _u64(1),
            _blob(encode_continuations(self.receipts)),
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
                _blob(encode_continuations(self.receipts)),
                _blob(encode_rotations(self.rotations)),
                _blob(anchors["start"]),
                _blob(anchors["end"]),
            ))
            with self.subTest(position=position):
                with self.assertRaises(ValueError):
                    decode_rotated_anchor(data)

    def test_restored_shape_mismatch_raises_value_error(self):
        # One receipt but one rotation: both nested encodings are sound, yet
        # the restored object violates the rotations = segments - 1 shape.
        data = b"".join((
            _MAGIC,
            _u64(1),
            _blob(encode_continuations((self.s0,))),
            _blob(encode_rotations((self.r0,))),
            _blob(encode_signed_root(self.bundle.start)),
            _blob(encode_signed_root(self.bundle.end)),
        ))
        with self.assertRaises(ValueError):
            decode_rotated_anchor(data)

    def test_decoded_bundle_is_verified_via_inspect_entry_point(self):
        restored = decode_rotated_anchor(
            encode_rotated_anchor(self.bundle)
        )
        self.assertEqual(
            inspect_rotated_anchors(restored, self.key_a), _OK
        )


if __name__ == "__main__":
    unittest.main()
