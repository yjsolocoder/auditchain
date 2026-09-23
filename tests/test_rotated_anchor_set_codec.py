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
    RotatedAnchorSet,
    RotatedChain,
    decode_rotated_anchor,
    decode_rotated_anchor_set,
    decode_rotation,
    encode_rotated_anchor,
    encode_rotated_anchor_set,
    encode_rotation,
    inspect_rotated_anchor_set,
    merge_rotated_anchor_set,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(3, 35))
_SEED_E = bytes(range(5, 37))
_SEED_F = bytes(range(7, 39))
_KEY = b"super-secret-verifier-key"
_MAGIC = b"auditchain/rotated-anchor-set/v1\0"

_OK = ContinuationChainReport(True, None, None)


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(n=15, key=_KEY, hash_name="sha256", prefix="record"):
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


def _package(receipts, rotations):
    return RotatedChain(
        receipts,
        rotations,
        receipts[0].consistency.old,
        receipts[-1].consistency.new,
    )


def _u64(value):
    return value.to_bytes(8, "big")


def _blob(material):
    return _u64(len(material)) + material


class RotatedAnchorSetTest(unittest.TestCase):
    def setUp(self):
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

    def test_positional_construction_and_equality(self):
        bundle = RotatedAnchorSet(self.items, self.bridges)
        self.assertEqual(bundle.items, self.items)
        self.assertEqual(bundle.bridges, self.bridges)
        self.assertEqual(
            bundle, RotatedAnchorSet(bridges=self.bridges, items=self.items)
        )
        self.assertNotEqual(bundle, RotatedAnchorSet((self.p0,), ()))
        self.assertNotEqual(
            bundle, RotatedAnchorSet((self.p0, self.p1), (self.b0,))
        )
        self.assertEqual(bundle, RotatedAnchorSet(self.items, self.bridges))

    def test_single_package_empty_bridges_is_the_minimum(self):
        bundle = RotatedAnchorSet((self.p0,), ())
        self.assertEqual(bundle.bridges, ())

    def test_frozen(self):
        bundle = RotatedAnchorSet(self.items, self.bridges)
        with self.assertRaises(Exception):
            bundle.items = (self.p0,)
        with self.assertRaises(Exception):
            bundle.bridges = ()

    def test_non_tuple_items_raises_type_error(self):
        for bad in ([self.p0], {self.p0}, None, self.p0, "items", 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedAnchorSet(bad, ())

    def test_non_tuple_bridges_raises_type_error(self):
        for bad in ([], None, "bridges", 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedAnchorSet((self.p0,), bad)

    def test_empty_items_raises_value_error(self):
        with self.assertRaises(ValueError):
            RotatedAnchorSet((), ())

    def test_wrong_item_element_type_raises_type_error(self):
        anchored = AnchoredContinuationChain(
            self.p0.receipts, self.p0.start, self.p0.end
        )
        for bad in (b"bytes", "package", None, 1, self.s0, anchored):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedAnchorSet((bad,), ())
                with self.assertRaises(TypeError):
                    RotatedAnchorSet((self.p0, bad), (self.b0,))

    def test_bridge_count_must_be_packages_minus_one(self):
        with self.assertRaises(ValueError):
            RotatedAnchorSet(self.items, ())
        with self.assertRaises(ValueError):
            RotatedAnchorSet((self.p0,), (self.b0,))
        with self.assertRaises(ValueError):
            RotatedAnchorSet(self.items, (self.b0, self.b1, self.b0))

    def test_wrong_bridge_element_type_is_not_shape_checked(self):
        # The container only validates item types and counts; a bridge of
        # the wrong element type is left to encode_rotation / verification.
        bundle = RotatedAnchorSet((self.p0, self.p1), ("bridge",))
        self.assertEqual(bundle.bridges, ("bridge",))


class EncodeRotatedAnchorSetTest(unittest.TestCase):
    def setUp(self):
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
        self.bundle = RotatedAnchorSet(self.items, self.bridges)

    def test_canonical_stream_layout(self):
        expected = b"".join((
            _MAGIC,
            _u64(1),
            _u64(3),
            _blob(encode_rotated_anchor(self.p0)),
            _blob(encode_rotated_anchor(self.p1)),
            _blob(encode_rotated_anchor(self.p2)),
            _u64(2),
            _blob(encode_rotation(self.b0)),
            _blob(encode_rotation(self.b1)),
        ))
        self.assertEqual(
            encode_rotated_anchor_set(self.bundle), expected
        )

    def test_single_package_empty_bridges_writes_zero_length_blob_section(self):
        bundle = RotatedAnchorSet((self.p0,), ())
        expected = b"".join((
            _MAGIC,
            _u64(1),
            _u64(1),
            _blob(encode_rotated_anchor(self.p0)),
            _u64(0),
        ))
        self.assertEqual(encode_rotated_anchor_set(bundle), expected)

    def test_inner_blobs_reuse_existing_encodings_in_order(self):
        data = encode_rotated_anchor_set(self.bundle)
        offset = len(_MAGIC) + 8
        self.assertEqual(
            int.from_bytes(data[offset:offset + 8], "big"), 3
        )
        offset += 8

        def take_blob():
            nonlocal offset
            length = int.from_bytes(data[offset:offset + 8], "big")
            blob = data[offset + 8:offset + 8 + length]
            offset += 8 + length
            return blob

        for index, item in enumerate(self.items):
            blob = take_blob()
            self.assertEqual(blob, encode_rotated_anchor(item))
            self.assertEqual(decode_rotated_anchor(blob), item)
        self.assertEqual(
            int.from_bytes(data[offset:offset + 8], "big"), 2
        )
        offset += 8
        for index, bridge in enumerate(self.bridges):
            blob = take_blob()
            self.assertEqual(blob, encode_rotation(bridge))
            self.assertEqual(decode_rotation(blob), bridge)
        self.assertEqual(offset, len(data))

    def test_non_bundle_raises_type_error(self):
        for bad in (
            self.items,
            self.bridges,
            (self.items, self.bridges),
            self.p0,
            b"bytes",
            "bundle",
            None,
            1,
            object(),
        ):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    encode_rotated_anchor_set(bad)

    def test_nested_encode_exception_propagates(self):
        # A bridge slot carrying a non-tuple passes the RotatedAnchorSet
        # shape checks but is rejected by encode_rotation with TypeError.
        bundle = RotatedAnchorSet((self.p0, self.p1), ("bridge",))
        with self.assertRaises(TypeError):
            encode_rotated_anchor_set(bundle)

    def test_call_is_read_only(self):
        items_before = tuple(encode_rotated_anchor(p) for p in self.items)
        bridges_before = tuple(encode_rotation(b) for b in self.bridges)
        encode_rotated_anchor_set(self.bundle)
        self.assertEqual(
            tuple(encode_rotated_anchor(p) for p in self.items), items_before
        )
        self.assertEqual(
            tuple(encode_rotation(b) for b in self.bridges), bridges_before
        )


class DecodeRotatedAnchorSetTest(unittest.TestCase):
    def setUp(self):
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
        self.bundle = RotatedAnchorSet(self.items, self.bridges)
        self.key_a = _public_key(_SEED_A)

    def test_round_trip_restores_frozen_equal_bundle(self):
        data = encode_rotated_anchor_set(self.bundle)
        restored = decode_rotated_anchor_set(data)
        self.assertIsInstance(restored, RotatedAnchorSet)
        self.assertEqual(restored, self.bundle)
        self.assertEqual(restored.items, self.items)
        self.assertEqual(restored.bridges, self.bridges)
        self.assertEqual(encode_rotated_anchor_set(restored), data)
        with self.assertRaises(Exception):
            restored.items = ()

    def test_single_package_round_trip(self):
        bundle = RotatedAnchorSet((self.p0,), ())
        restored = decode_rotated_anchor_set(
            encode_rotated_anchor_set(bundle)
        )
        self.assertEqual(restored, bundle)
        self.assertEqual(restored.bridges, ())

    def test_restored_set_can_continue_diagnosis_and_merge(self):
        restored = decode_rotated_anchor_set(
            encode_rotated_anchor_set(self.bundle)
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                restored.items, restored.bridges, self.key_a
            ),
            _OK,
        )
        merged = merge_rotated_anchor_set(
            restored.items, restored.bridges, self.key_a
        )
        self.assertEqual(merged.start, self.p0.start)
        self.assertEqual(merged.end, self.p2.end)
        self.assertEqual(len(merged.receipts), 6)
        self.assertEqual(len(merged.rotations), 5)

    def test_non_bytes_raises_type_error(self):
        data = encode_rotated_anchor_set(self.bundle)
        for bad in (bytearray(data), memoryview(data), "data", None, 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    decode_rotated_anchor_set(bad)

    def test_bad_magic_raises_value_error(self):
        data = encode_rotated_anchor_set(self.bundle)
        for bad in (
            b"",
            b"auditchain/rotated-anchor-set/v2\0" + data[len(_MAGIC):],
            b"\x00" + data[1:],
        ):
            with self.subTest(bad=bad[:8]):
                with self.assertRaises(ValueError):
                    decode_rotated_anchor_set(bad)

    def test_bad_version_raises_value_error(self):
        data = encode_rotated_anchor_set(self.bundle)
        for version in (0, 2, (1 << 64) - 1):
            broken = _MAGIC + _u64(version) + data[len(_MAGIC) + 8:]
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    decode_rotated_anchor_set(broken)

    def test_zero_package_count_raises_value_error(self):
        # n == 0 is canonical framing, m must then be u64(0): still
        # rejected — an anchor set must be non-empty.
        empty = _MAGIC + _u64(1) + _u64(0) + _u64(0)
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(empty)

    def test_bridge_count_mismatch_raises_value_error(self):
        good = encode_rotated_anchor_set(self.bundle)
        # Rewrite the bridge-count u64 (the 8 bytes immediately after the
        # three package blobs): 1 instead of 2 leaves a trailing bridge.
        offset = len(_MAGIC) + 8 + 8
        for _ in range(3):
            length = int.from_bytes(good[offset:offset + 8], "big")
            offset += 8 + length
        broken = good[:offset] + _u64(1) + good[offset + 8:]
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(broken)
        # Claiming an extra bridge with none framed truncates instead.
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(good[:offset] + _u64(3))

    def test_truncation_raises_value_error(self):
        data = encode_rotated_anchor_set(self.bundle)
        for cut in (
            len(_MAGIC),
            len(_MAGIC) + 4,
            len(_MAGIC) + 8,
            len(_MAGIC) + 16,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    decode_rotated_anchor_set(data[:cut])

    def test_trailing_bytes_raise_value_error(self):
        data = encode_rotated_anchor_set(self.bundle)
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(data + b"\x00")

    def test_oversized_blob_length_raises_value_error(self):
        data = encode_rotated_anchor_set(self.bundle)
        broken = (
            _MAGIC + _u64(1) + _u64(1) + _u64(len(data))
            + data[len(_MAGIC) + 24:]
        )
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(broken)

    def test_nested_package_exception_propagates(self):
        data = b"".join((
            _MAGIC,
            _u64(1),
            _u64(1),
            _blob(b"not a rotated anchor"),
            _u64(0),
        ))
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(data)

    def test_nested_bridge_exception_propagates(self):
        data = b"".join((
            _MAGIC,
            _u64(1),
            _u64(1),
            _blob(encode_rotated_anchor(self.p0)),
            _u64(0),
        ))
        self.assertEqual(
            decode_rotated_anchor_set(data),
            RotatedAnchorSet((self.p0,), ()),
        )
        bad = b"".join((
            _MAGIC,
            _u64(1),
            _u64(2),
            _blob(encode_rotated_anchor(self.p0)),
            _blob(encode_rotated_anchor(self.p1)),
            _u64(1),
            _blob(b"not a rotation record"),
        ))
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(bad)

    def test_forged_but_structurally_sound_set_still_decodes(self):
        # decode performs no verification: a forged bridge signature
        # decodes, and inspection of the restored artifact reports it.
        old, new_key, new, _auth = self.b0
        forged = (old, new_key, new, b"\x00" * 64)
        bundle = RotatedAnchorSet(
            (self.p0, self.p1), (forged,)
        )
        restored = decode_rotated_anchor_set(
            encode_rotated_anchor_set(bundle)
        )
        self.assertEqual(restored, bundle)
        self.assertEqual(
            inspect_rotated_anchor_set(
                restored.items, restored.bridges, self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )


if __name__ == "__main__":
    unittest.main()
