import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    decode_rotation,
    decode_rotations,
    encode_rotation,
    encode_rotations,
    verify_rotation,
    verify_rotation_chain,
)

CHAIN_MAGIC = b"auditchain/rotation-chain/v1\0"
RECORD_MAGIC = b"auditchain/signer-rotation-record/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(97, 129))


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


class RotationChainTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_a = _public_key(_SEED_A)
        self.public_b = _public_key(_SEED_B)
        self.public_c = _public_key(_SEED_C)
        self.item_ab = self.log.rotate_signer(_SEED_A, _SEED_B, 3)
        self.item_bc = self.log.rotate_signer(_SEED_B, _SEED_C, 4)
        self.item_cd = self.log.rotate_signer(_SEED_C, _SEED_D)
        self.chain = (self.item_ab, self.item_bc, self.item_cd)

    def test_single_hop_matches_verify_rotation(self):
        self.assertTrue(verify_rotation_chain((self.item_ab,), self.public_a))
        self.assertFalse(verify_rotation_chain((self.item_ab,), self.public_b))

    def test_multi_hop_trust_transfer(self):
        self.assertTrue(verify_rotation_chain(self.chain, self.public_a))
        # Every intermediate key only verifies its own suffix.
        self.assertTrue(
            verify_rotation_chain((self.item_bc, self.item_cd), self.public_b)
        )
        self.assertTrue(
            verify_rotation_chain((self.item_cd,), self.public_c)
        )
        # A key from the middle cannot authorize an earlier record.
        self.assertFalse(verify_rotation_chain(self.chain, self.public_b))
        self.assertFalse(verify_rotation_chain(self.chain, self.public_c))

    def test_first_record_uses_initial_key(self):
        # Dropping the first record and still claiming the initial key fails.
        self.assertFalse(
            verify_rotation_chain(
                (self.item_bc, self.item_cd), self.public_a
            )
        )

    def test_no_reordering(self):
        self.assertFalse(
            verify_rotation_chain(
                (self.item_ab, self.item_cd, self.item_bc), self.public_a
            )
        )
        self.assertFalse(
            verify_rotation_chain(
                (self.item_bc, self.item_ab, self.item_cd), self.public_a
            )
        )

    def test_no_skipping(self):
        self.assertFalse(
            verify_rotation_chain((self.item_ab, self.item_cd), self.public_a)
        )

    def test_duplicate_records_return_false(self):
        self.assertFalse(
            verify_rotation_chain(
                (self.item_ab, self.item_ab), self.public_a
            )
        )
        # Non-adjacent duplicates are rejected too.
        self.assertFalse(
            verify_rotation_chain(
                (self.item_ab, self.item_bc, self.item_ab), self.public_a
            )
        )

    def test_tampered_record_returns_false(self):
        old, new_key, new, auth = self.item_bc
        forged_auth = (old, new_key, new, b"\x00" * 64)
        self.assertFalse(
            verify_rotation_chain(
                (self.item_ab, forged_auth, self.item_cd), self.public_a
            )
        )

    def test_same_seed_rotation_chain(self):
        # Rotating a key onto itself is a genuine hop for verify_rotation.
        item_aa = self.log.rotate_signer(_SEED_A, _SEED_A)
        item_ab = self.log.rotate_signer(_SEED_A, _SEED_B)
        self.assertTrue(
            verify_rotation_chain((item_aa, item_ab), self.public_a)
        )

    def test_non_tuple_raises_type_error(self):
        for bad in (
            None,
            [self.item_ab],
            (record for record in (self.item_ab,)),
            b"bytes",
            self.item_ab,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_rotation_chain(bad, self.public_a)

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_rotation_chain((), self.public_a)

    def test_key_type_and_width(self):
        with self.assertRaises(TypeError):
            verify_rotation_chain((self.item_ab,), None)
        with self.assertRaises(TypeError):
            verify_rotation_chain((self.item_ab,), bytearray(self.public_a))
        with self.assertRaises(ValueError):
            verify_rotation_chain((self.item_ab,), self.public_a[:-1])
        with self.assertRaises(ValueError):
            verify_rotation_chain((self.item_ab,), self.public_a + b"\x00")

    def test_nested_type_errors_propagate(self):
        with self.assertRaises(TypeError):
            verify_rotation_chain(("not-a-record",), self.public_a)
        with self.assertRaises(ValueError):
            verify_rotation_chain((self.item_ab[:3],), self.public_a)

    def test_call_is_read_only(self):
        self.assertTrue(verify_rotation_chain(self.chain, self.public_a))
        self.assertTrue(verify_rotation_chain(self.chain, self.public_a))
        self.assertEqual(
            self.chain,
            (self.item_ab, self.item_bc, self.item_cd),
        )


class EncodeRotationsTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_a = _public_key(_SEED_A)
        self.item_ab = self.log.rotate_signer(_SEED_A, _SEED_B, 2)
        self.item_bc = self.log.rotate_signer(_SEED_B, _SEED_C)
        self.chain = (self.item_ab, self.item_bc)

    def test_canonical_layout(self):
        data = encode_rotations(self.chain)
        offset = 0
        self.assertTrue(data.startswith(CHAIN_MAGIC))
        offset = len(CHAIN_MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(2))  # count
        offset += 8
        for item in self.chain:
            record = encode_rotation(item)
            self.assertEqual(data[offset:offset + 8], u64(len(record)))
            offset += 8
            self.assertEqual(data[offset:offset + len(record)], record)
            offset += len(record)
        self.assertEqual(offset, len(data))

    def test_expected_canonical_bytes(self):
        expected = (
            CHAIN_MAGIC
            + u64(1)
            + u64(2)
            + blob(encode_rotation(self.item_ab))
            + blob(encode_rotation(self.item_bc))
        )
        self.assertEqual(encode_rotations(self.chain), expected)

    def test_blobs_are_exact_rotation_encodings(self):
        data = encode_rotations(self.chain)
        offset = len(CHAIN_MAGIC) + 16
        records = []
        for _ in range(2):
            length = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            records.append(data[offset:offset + length])
            offset += length
        self.assertEqual(offset, len(data))
        self.assertEqual(records[0], encode_rotation(self.item_ab))
        self.assertEqual(records[1], encode_rotation(self.item_bc))
        self.assertTrue(records[0].startswith(RECORD_MAGIC))
        # Each blob is independently consumable by the existing record codec.
        self.assertEqual(decode_rotation(records[0]), self.item_ab)
        self.assertEqual(decode_rotation(records[1]), self.item_bc)

    def test_single_record(self):
        data = encode_rotations((self.item_ab,))
        self.assertEqual(
            data,
            CHAIN_MAGIC + u64(1) + u64(1) + blob(encode_rotation(self.item_ab)),
        )

    def test_deterministic(self):
        self.assertEqual(
            encode_rotations(self.chain), encode_rotations(self.chain)
        )

    def test_only_tuple_accepted(self):
        for bad in (None, [], [self.item_ab], b"x", self.item_ab, 1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_rotations(bad)

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            encode_rotations(())

    def test_nested_errors_propagate(self):
        with self.assertRaises(TypeError):
            encode_rotations((self.item_ab, "not-a-record"))
        with self.assertRaises(ValueError):
            encode_rotations((self.item_ab, self.item_ab[:3]))

    def test_call_is_read_only(self):
        before = encode_rotations(self.chain)
        encode_rotations(self.chain)
        self.assertEqual(encode_rotations(self.chain), before)


class DecodeRotationsTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_a = _public_key(_SEED_A)
        self.records = (
            self.log.rotate_signer(_SEED_A, _SEED_B, 0),
            self.log.rotate_signer(_SEED_B, _SEED_C, 3),
            self.log.rotate_signer(_SEED_C, _SEED_D),
        )
        self.data = encode_rotations(self.records)

    def roundtrip(self, records, key):
        data = encode_rotations(records)
        decoded = decode_rotations(data)
        self.assertIsInstance(decoded, tuple)
        self.assertEqual(len(decoded), len(records))
        self.assertEqual(decoded, records)
        self.assertEqual(encode_rotations(decoded), data)
        self.assertTrue(verify_rotation_chain(decoded, key))
        return decoded

    def test_roundtrip_multi_hop(self):
        self.roundtrip(self.records, self.public_a)

    def test_roundtrip_single_and_empty_snapshot(self):
        self.roundtrip((self.records[0],), self.public_a)

    def test_order_preserved(self):
        decoded = decode_rotations(self.data)
        for position, record in enumerate(self.records):
            self.assertEqual(decoded[position], record)

    def test_persistence_across_process_boundary(self):
        restored = decode_rotations(bytes(self.data))
        self.assertEqual(restored, self.records)
        self.assertTrue(verify_rotation_chain(restored, self.public_a))

    def test_only_bytes_accepted(self):
        for bad in (
            bytearray(self.data),
            memoryview(self.data),
            None,
            (),
            [],
            "text",
            1,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_rotations(bad)

    def test_bad_magic(self):
        for bad in (
            b"",
            b"x" + self.data[1:],
            CHAIN_MAGIC[:-1],
            RECORD_MAGIC + self.data[len(CHAIN_MAGIC):],
            b"auditchain/cont-chain/v1\0" + self.data[len(CHAIN_MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:40])):
                decode_rotations(bad)

    def test_bad_version(self):
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = CHAIN_MAGIC + u64(version) + self.data[len(CHAIN_MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_rotations(bad)

    def test_zero_count(self):
        bad = CHAIN_MAGIC + u64(1) + u64(0)
        with self.assertRaises(ValueError):
            decode_rotations(bad)

    def test_oversized_count(self):
        with self.assertRaises(ValueError):
            decode_rotations(CHAIN_MAGIC + u64(1) + u64(4))
        with self.assertRaises(ValueError):
            decode_rotations(CHAIN_MAGIC + u64(1) + u64(1 << 63))

    def test_truncation(self):
        for cut in (
            len(CHAIN_MAGIC),
            len(CHAIN_MAGIC) + 3,
            len(CHAIN_MAGIC) + 15,
            len(self.data) - 1,
            len(self.data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_rotations(self.data[:cut])
        # Count promises three records but only two are present.
        two_blobs = (
            blob(encode_rotation(self.records[0]))
            + blob(encode_rotation(self.records[1]))
        )
        bad = CHAIN_MAGIC + u64(1) + u64(3) + two_blobs
        with self.assertRaises(ValueError):
            decode_rotations(bad)

    def test_oversized_blob_length(self):
        bad = CHAIN_MAGIC + u64(1) + u64(1) + u64(1 << 63) + b"x"
        with self.assertRaises(ValueError):
            decode_rotations(bad)

    def test_trailing_bytes(self):
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_rotations(self.data + extra)

    def test_nested_garbage_blob_rejected(self):
        bad = (
            CHAIN_MAGIC
            + u64(1)
            + u64(1)
            + blob(b"garbage")
        )
        with self.assertRaises(ValueError):
            decode_rotations(bad)

    def test_nested_framing_error_rejected(self):
        record = encode_rotation(self.records[0])
        tampered = b"x" + record[1:]
        bad = CHAIN_MAGIC + u64(1) + u64(1) + blob(tampered)
        with self.assertRaises(ValueError):
            decode_rotations(bad)

    def test_count_mismatch_with_blobs(self):
        # One blob framed, header claims two: truncated.
        body = u64(1) + blob(encode_rotation(self.records[0]))
        with self.assertRaises(ValueError):
            decode_rotations(CHAIN_MAGIC + body)
        # Two blobs framed, header claims one: trailing bytes.
        framed = (
            CHAIN_MAGIC
            + u64(1)
            + u64(1)
            + blob(encode_rotation(self.records[0]))
            + blob(encode_rotation(self.records[1]))
        )
        with self.assertRaises(ValueError):
            decode_rotations(framed)

    def test_structurally_valid_but_unverifiable_chain_decodes(self):
        # A chain framed with the wrong initial record still decodes; only the
        # verifier reports False.
        reordered = (self.records[1], self.records[0])
        decoded = decode_rotations(encode_rotations(reordered))
        self.assertEqual(decoded, reordered)
        self.assertFalse(verify_rotation_chain(decoded, self.public_a))

    def test_call_is_read_only(self):
        self.assertEqual(decode_rotations(self.data), self.records)
        decode_rotations(self.data)
        self.assertEqual(decode_rotations(self.data), self.records)


if __name__ == "__main__":
    unittest.main()
