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
    verify_signed_root,
)

MAGIC = b"auditchain/rotation-chain/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(2, 34))
_SEED_E = bytes(range(3, 35))


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


def _log():
    log = AuditLog()
    for record in ("a", "b", "c", "d", "e"):
        log.append(record)
    return log


class VerifyRotationChainTest(unittest.TestCase):
    def setUp(self):
        self.log = _log()
        # Three hops over distinct prefixes: A->B, B->C, C->D.
        self.r1 = self.log.rotate_signer(_SEED_A, _SEED_B, 2)
        self.r2 = self.log.rotate_signer(_SEED_B, _SEED_C, 3)
        self.r3 = self.log.rotate_signer(_SEED_C, _SEED_D, 5)
        self.items = (self.r1, self.r2, self.r3)
        self.initial_key = _public_key(_SEED_A)

    def test_single_record_verifies(self):
        self.assertTrue(verify_rotation_chain((self.r1,), self.initial_key))

    def test_multi_hop_chain_verifies(self):
        self.assertTrue(verify_rotation_chain(self.items, self.initial_key))

    def test_trust_lands_on_final_new_key(self):
        # With only the pre-set initial key, the chain lets an offline
        # verifier trust the final signer's checkpoint.
        self.assertTrue(verify_rotation_chain(self.items, self.initial_key))
        final_key = self.r3[1]
        self.assertEqual(final_key, _public_key(_SEED_D))
        self.assertTrue(verify_signed_root(self.r3[2], final_key))

    def test_empty_prefix_first_hop_verifies(self):
        first = AuditLog().rotate_signer(_SEED_A, _SEED_B)
        items = (first, self.r2, self.r3)
        self.assertTrue(verify_rotation_chain(items, self.initial_key))

    def test_wrong_initial_key_returns_false(self):
        self.assertFalse(verify_rotation_chain(self.items, _public_key(_SEED_E)))

    def test_reordered_records_return_false(self):
        # The second hop is presented first and cannot verify against A.
        self.assertFalse(
            verify_rotation_chain((self.r2, self.r1, self.r3), self.initial_key)
        )
        self.assertFalse(
            verify_rotation_chain((self.r3, self.r2, self.r1), self.initial_key)
        )

    def test_skipping_a_hop_returns_false(self):
        # r3 is C->D; without the B->C hop it is presented against B.
        self.assertFalse(
            verify_rotation_chain((self.r1, self.r3), self.initial_key)
        )

    def test_repeated_record_returns_false(self):
        self.assertFalse(
            verify_rotation_chain((self.r1, self.r1), self.initial_key)
        )
        self.assertFalse(
            verify_rotation_chain(
                (self.r1, self.r2, self.r1), self.initial_key
            )
        )
        self.assertFalse(
            verify_rotation_chain(
                (self.r1, self.r2, self.r3, self.r2), self.initial_key
            )
        )

    def test_tampered_first_auth_returns_false(self):
        old, new_key, new, _ = self.r1
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertFalse(
            verify_rotation_chain((forged, self.r2, self.r3), self.initial_key)
        )

    def test_tampered_later_record_returns_false(self):
        old, new_key, new, _ = self.r2
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertFalse(
            verify_rotation_chain((self.r1, forged, self.r3), self.initial_key)
        )

    def test_non_tuple_raises_type_error(self):
        for bad in ([], None, "x", object(), [self.r1]):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    verify_rotation_chain(bad, self.initial_key)

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_rotation_chain((), self.initial_key)

    def test_key_validation(self):
        with self.assertRaises(TypeError):
            verify_rotation_chain(self.items, "0" * 32)
        with self.assertRaises(TypeError):
            verify_rotation_chain(self.items, bytearray(self.initial_key))
        with self.assertRaises(ValueError):
            verify_rotation_chain(self.items, self.initial_key[:-1])
        with self.assertRaises(ValueError):
            verify_rotation_chain(self.items, self.initial_key + b"\x00")

    def test_nested_shape_errors_propagate(self):
        # A non-four-tuple element is verify_rotation's ValueError.
        with self.assertRaises(ValueError):
            verify_rotation_chain((self.r1[:3],), self.initial_key)
        # A wrong-typed element is verify_rotation's TypeError.
        with self.assertRaises(TypeError):
            verify_rotation_chain(("x",), self.initial_key)

    def test_call_is_read_only(self):
        before = encode_rotations(self.items)
        self.assertTrue(verify_rotation_chain(self.items, self.initial_key))
        self.assertTrue(verify_rotation_chain(self.items, self.initial_key))
        self.assertEqual(encode_rotations(self.items), before)
        self.assertEqual(self.items, (self.r1, self.r2, self.r3))


class EncodeRotationsTest(unittest.TestCase):
    def setUp(self):
        self.log = _log()
        self.r1 = self.log.rotate_signer(_SEED_A, _SEED_B, 2)
        self.r2 = self.log.rotate_signer(_SEED_B, _SEED_C, 3)
        self.r3 = self.log.rotate_signer(_SEED_C, _SEED_D, 5)
        self.items = (self.r1, self.r2, self.r3)

    def test_magic_and_field_layout(self):
        data = encode_rotations(self.items)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(3))  # count
        offset += 8
        for item in self.items:
            record = encode_rotation(item)
            self.assertEqual(data[offset:offset + 8], u64(len(record)))
            offset += 8
            self.assertEqual(data[offset:offset + len(record)], record)
            offset += len(record)
        self.assertEqual(offset, len(data))

    def test_expected_canonical_bytes(self):
        expected = (
            MAGIC
            + u64(1)
            + u64(len(self.items))
            + b"".join(blob(encode_rotation(item)) for item in self.items)
        )
        self.assertEqual(encode_rotations(self.items), expected)

    def test_single_record_layout(self):
        data = encode_rotations((self.r1,))
        self.assertEqual(
            data,
            MAGIC + u64(1) + u64(1) + blob(encode_rotation(self.r1)),
        )

    def test_encode_is_deterministic(self):
        self.assertEqual(
            encode_rotations(self.items), encode_rotations(self.items)
        )

    def test_only_non_empty_tuple_accepted(self):
        for bad in (None, 1, "items", b"bytes", [], [self.r1], object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    encode_rotations(bad)
        with self.assertRaises(ValueError):
            encode_rotations(())

    def test_nested_record_errors_propagate(self):
        with self.assertRaises(ValueError):
            encode_rotations((self.r1[:3],))
        with self.assertRaises(TypeError):
            encode_rotations(("x",))
        old, new_key, new, auth = self.r1
        with self.assertRaises(ValueError):
            encode_rotations(((old, new_key[:-1], new, auth),))

    def test_call_is_read_only(self):
        before = encode_rotations(self.items)
        encode_rotations(self.items)
        self.assertEqual(encode_rotations(self.items), before)


class DecodeRotationsTest(unittest.TestCase):
    def setUp(self):
        self.log = _log()
        self.initial_key = _public_key(_SEED_A)
        self.r1 = self.log.rotate_signer(_SEED_A, _SEED_B, 0)
        self.r2 = self.log.rotate_signer(_SEED_B, _SEED_C, 3)
        self.r3 = self.log.rotate_signer(_SEED_C, _SEED_D, 5)
        self.items = (self.r1, self.r2, self.r3)

    def roundtrip(self, items):
        data = encode_rotations(items)
        decoded = decode_rotations(data)
        self.assertIsInstance(decoded, tuple)
        self.assertEqual(len(decoded), len(items))
        self.assertEqual(decoded, items)
        self.assertEqual(encode_rotations(decoded), data)
        return decoded

    def test_roundtrip_preserves_order(self):
        decoded = self.roundtrip(self.items)
        self.assertTrue(verify_rotation_chain(decoded, self.initial_key))
        # Order is preserved verbatim, never sorted or deduplicated.
        self.roundtrip((self.r3, self.r1, self.r2))

    def test_roundtrip_single_record(self):
        self.roundtrip((self.r1,))

    def test_each_blob_decodes_with_existing_codec(self):
        data = encode_rotations(self.items)
        offset = len(MAGIC) + 16
        for item in self.items:
            length = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            self.assertEqual(decode_rotation(data[offset:offset + length]), item)
            offset += length
        self.assertEqual(offset, len(data))

    def test_persistence_across_process_boundary(self):
        data = bytes(encode_rotations(self.items))
        restored = decode_rotations(data)
        self.assertEqual(restored, self.items)
        self.assertTrue(verify_rotation_chain(restored, self.initial_key))

    def test_only_bytes_accepted(self):
        data = encode_rotations(self.items)
        for bad in (bytearray(data), memoryview(data), "text", None, 1, (), []):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    decode_rotations(bad)

    def test_bad_magic(self):
        data = encode_rotations(self.items)
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/cont-chain/v1\0" + data[len(MAGIC):],
            # The single-record envelope is a distinct lookalike.
            b"auditchain/signer-rotation-record/v1\0" + data[len(MAGIC):],
        ):
            with self.subTest(bad=repr(bad[:40])):
                with self.assertRaises(ValueError):
                    decode_rotations(bad)

    def test_bad_version(self):
        data = encode_rotations(self.items)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    decode_rotations(bad)

    def test_zero_count(self):
        with self.assertRaises(ValueError):
            decode_rotations(MAGIC + u64(1) + u64(0))

    def test_truncation(self):
        data = encode_rotations(self.items)
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(MAGIC) + 8,
            len(MAGIC) + 15,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    decode_rotations(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_rotations(data[:cut])

    def test_trailing_bytes(self):
        data = encode_rotations(self.items)
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    decode_rotations(data + extra)

    def test_oversized_blob_length(self):
        r1_blob = encode_rotation(self.r1)
        for bad in (
            MAGIC + u64(1) + u64(1) + u64(1 << 63),
            MAGIC + u64(1) + u64(1) + u64(len(r1_blob) + 1) + r1_blob,
            MAGIC
            + u64(1)
            + u64(2)
            + blob(r1_blob)
            + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_rotations(bad)

    def test_count_mismatch(self):
        r1_blob = encode_rotation(self.r1)
        r2_blob = encode_rotation(self.r2)
        # Count says 2 but only one blob follows.
        with self.assertRaises(ValueError):
            decode_rotations(MAGIC + u64(1) + u64(2) + blob(r1_blob))
        # Count says 1 but two blobs follow; the second is trailing junk.
        with self.assertRaises(ValueError):
            decode_rotations(
                MAGIC + u64(1) + u64(1) + blob(r1_blob) + blob(r2_blob)
            )

    def test_nested_garbage_rejected(self):
        with self.assertRaises(ValueError):
            decode_rotations(MAGIC + u64(1) + u64(1) + blob(b"hello"))
        # An empty record blob fails the nested magic check.
        with self.assertRaises(ValueError):
            decode_rotations(MAGIC + u64(1) + u64(1) + blob(b""))

    def test_nested_framing_error_rejected(self):
        record = encode_rotation(self.r1)
        tampered = b"x" + record[1:]
        with self.assertRaises(ValueError):
            decode_rotations(MAGIC + u64(1) + u64(1) + blob(tampered))

    def test_second_blob_nested_error_rejected(self):
        good = encode_rotation(self.r1)
        with self.assertRaises(ValueError):
            decode_rotations(
                MAGIC + u64(1) + u64(2) + blob(good) + blob(b"hello")
            )

    def test_bad_signature_still_decodes_but_chain_verifies_false(self):
        old, new_key, new, _ = self.r2
        forged = (old, new_key, new, b"\x00" * 64)
        decoded = decode_rotations(encode_rotations((self.r1, forged)))
        self.assertEqual(decoded, (self.r1, forged))
        self.assertFalse(verify_rotation_chain(decoded, self.initial_key))

    def test_broken_link_still_decodes_but_chain_verifies_false(self):
        # Skipping r2 stays structurally decodable; only chain verification
        # notices the missing hop.
        decoded = decode_rotations(encode_rotations((self.r1, self.r3)))
        self.assertEqual(decoded, (self.r1, self.r3))
        self.assertFalse(verify_rotation_chain(decoded, self.initial_key))

    def test_duplicate_records_decode_but_verify_false(self):
        decoded = decode_rotations(encode_rotations((self.r1, self.r1)))
        self.assertEqual(decoded, (self.r1, self.r1))
        self.assertFalse(verify_rotation_chain(decoded, self.initial_key))

    def test_call_is_read_only(self):
        data = encode_rotations(self.items)
        self.assertEqual(decode_rotations(data), self.items)
        decode_rotations(data)
        self.assertEqual(decode_rotations(data), self.items)


if __name__ == "__main__":
    unittest.main()
