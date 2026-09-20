import unittest

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    SignedRoot,
    decode_signed_root,
    encode_signed_root,
    verify_signed_root,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAGIC = b"auditchain/signed-root/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


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


class EncodeSignedRootTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        receipt = self.log.sign_root(_SEED_A, 4)
        data = encode_signed_root(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(4))  # size
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(32))  # root length
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.root)
        offset += 32
        self.assertEqual(data[offset:offset + 8], u64(32))  # head length
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.head)
        offset += 32
        self.assertEqual(data[offset:offset + 8], u64(64))  # signature length
        offset += 8
        self.assertEqual(data[offset:offset + 64], receipt.signature)
        offset += 64
        self.assertEqual(offset, len(data))

    def test_empty_prefix_head_is_zero_blob(self):
        receipt = self.log.sign_root(_SEED_A, 0)
        data = encode_signed_root(receipt)
        # root is the canonical empty root, head is the digest-width zero
        # value; both are framed with a u64(32) length.
        decoded = decode_signed_root(data)
        self.assertEqual(decoded.head, GENESIS_HASH)
        self.assertEqual(decoded.root, self.log.merkle_root(0))

    def test_encode_is_deterministic(self):
        receipt = self.log.sign_root(_SEED_A)
        self.assertEqual(encode_signed_root(receipt), encode_signed_root(receipt))

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                encode_signed_root(bad)

    def test_bypassed_wrong_field_types_raise_type_error(self):
        receipt = self.log.sign_root(_SEED_A)
        for field, value in (
            ("version", "1"),
            ("hash_name", 1),
            ("size", "5"),
            ("root", bytearray(receipt.root)),
            ("head", memoryview(receipt.head)),
            ("signature", bytearray(receipt.signature)),
        ):
            forged = SignedRoot.__new__(SignedRoot)
            for name in (
                "version", "hash_name", "size", "root", "head", "signature"
            ):
                object.__setattr__(forged, name, getattr(receipt, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_signed_root(forged)

    def test_bypassed_bad_structure_raises_value_error(self):
        receipt = self.log.sign_root(_SEED_A)
        for field, value in (
            ("version", 2),
            ("hash_name", "not-a-hash"),
            ("size", -1),
            ("size", 1 << 64),
            ("root", b"\x00" * 31),
            ("head", b"\x00" * 33),
            ("signature", b"\x00" * 63),
        ):
            forged = SignedRoot.__new__(SignedRoot)
            for name in (
                "version", "hash_name", "size", "root", "head", "signature"
            ):
                object.__setattr__(forged, name, getattr(receipt, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(ValueError, msg=field):
                encode_signed_root(forged)

    def test_call_is_read_only(self):
        receipt = self.log.sign_root(_SEED_A)
        before = encode_signed_root(receipt)
        encode_signed_root(receipt)
        self.assertEqual(encode_signed_root(receipt), before)
        self.assertTrue(verify_signed_root(receipt, self.public_key))


class DecodeSignedRootTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, receipt):
        data = encode_signed_root(receipt)
        decoded = decode_signed_root(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.hash_name, receipt.hash_name)
        self.assertEqual(decoded.size, receipt.size)
        self.assertEqual(decoded.root, receipt.root)
        self.assertEqual(decoded.head, receipt.head)
        self.assertEqual(decoded.signature, receipt.signature)
        self.assertIsInstance(decoded.root, bytes)
        self.assertIsInstance(decoded.head, bytes)
        self.assertIsInstance(decoded.signature, bytes)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_signed_root(decoded), data)
        self.assertTrue(verify_signed_root(decoded, self.public_key))
        return decoded

    def test_roundtrip_variants(self):
        for size in (None, 0, 1, 3, 5):
            self.roundtrip(self.log.sign_root(_SEED_A, size))

    def test_roundtrip_empty_log(self):
        self.roundtrip(AuditLog().sign_root(_SEED_A))

    def test_roundtrip_after_prune(self):
        self.log.prune(3, self.log.seal(3))
        self.roundtrip(self.log.sign_root(_SEED_A, 4))
        self.roundtrip(self.log.sign_root(_SEED_A, 0))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            for record in ("a", "b", "c"):
                log.append(record)
            self.roundtrip(log.sign_root(_SEED_A))

    def test_persistence_across_process_boundary(self):
        data = encode_signed_root(self.log.sign_root(_SEED_A, 3))
        # A fresh byte sequence (as read back from disk or a socket) decodes
        # into a receipt that still verifies against the pre-trusted key.
        restored = decode_signed_root(bytes(data))
        self.assertEqual(restored, self.log.sign_root(_SEED_A, 3))
        self.assertTrue(verify_signed_root(restored, self.public_key))

    def test_only_bytes_accepted(self):
        data = encode_signed_root(self.log.sign_root(_SEED_A))
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_signed_root(bad)

    def test_bad_magic(self):
        data = encode_signed_root(self.log.sign_root(_SEED_A))
        with self.assertRaises(ValueError):
            decode_signed_root(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_signed_root(b"")
        with self.assertRaises(ValueError):
            decode_signed_root(MAGIC[:-1])
        with self.assertRaises(ValueError):
            decode_signed_root(b"auditchain/audit-receipt/v1\0" + data[len(MAGIC):])

    def test_bad_version(self):
        receipt = self.log.sign_root(_SEED_A)
        data = MAGIC + u64(2) + encode_signed_root(receipt)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_signed_root(data)

    def test_unknown_hash_algorithm(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"not-a-hash")
            + u64(0)
            + blob(b"")
            + blob(b"")
            + blob(b"\x00" * 64)
        )
        with self.assertRaises(ValueError):
            decode_signed_root(data)

    def test_invalid_utf8_hash_name(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"\xff\xfe")
            + u64(0)
            + blob(b"")
            + blob(b"")
            + blob(b"\x00" * 64)
        )
        with self.assertRaises(ValueError):
            decode_signed_root(data)

    def test_truncation(self):
        data = encode_signed_root(self.log.sign_root(_SEED_A))
        for cut in (
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError):
                decode_signed_root(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_signed_root(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_root(self.log.sign_root(_SEED_A))
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_signed_root(data + extra)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_signed_root(data)

    def test_max_u64_size_is_structurally_acceptable(self):
        # SignedRoot only bounds size to the u64 range; framing cannot carry
        # 2**64, and the log length is irrelevant to offline verification.
        receipt = self.log.sign_root(_SEED_A)
        forged = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64((1 << 64) - 1)
            + blob(receipt.root)
            + blob(receipt.head)
            + blob(b"\x00" * 64)
        )
        decoded = decode_signed_root(forged)
        self.assertEqual(decoded.size, (1 << 64) - 1)
        self.assertFalse(verify_signed_root(decoded, self.public_key))

    def test_digest_widths_checked(self):
        receipt = self.log.sign_root(_SEED_A)
        base = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(receipt.size)
        )
        # Root one byte short / long.
        with self.assertRaises(ValueError):
            decode_signed_root(
                base + blob(b"\x00" * 31) + blob(receipt.head)
                + blob(receipt.signature)
            )
        with self.assertRaises(ValueError):
            decode_signed_root(
                base + blob(b"\x00" * 33) + blob(receipt.head)
                + blob(receipt.signature)
            )
        # Head of the wrong width.
        with self.assertRaises(ValueError):
            decode_signed_root(
                base + blob(receipt.root) + blob(b"\x00" * 16)
                + blob(receipt.signature)
            )

    def test_signature_width_checked(self):
        receipt = self.log.sign_root(_SEED_A)
        base = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(receipt.size)
            + blob(receipt.root)
            + blob(receipt.head)
        )
        with self.assertRaises(ValueError):
            decode_signed_root(base + blob(b"\x00" * 63))
        with self.assertRaises(ValueError):
            decode_signed_root(base + blob(b"\x00" * 65))

    def test_wrong_signature_decodes_but_verifies_false(self):
        receipt = self.log.sign_root(_SEED_A)
        forged = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(receipt.size)
            + blob(receipt.root)
            + blob(receipt.head)
            + blob(b"\x00" * 64)
        )
        decoded = decode_signed_root(forged)
        self.assertEqual(decoded.signature, b"\x00" * 64)
        self.assertFalse(verify_signed_root(decoded, self.public_key))

    def test_wrong_key_roundtrip_verifies_false(self):
        data = encode_signed_root(self.log.sign_root(_SEED_B))
        decoded = decode_signed_root(data)
        self.assertFalse(verify_signed_root(decoded, self.public_key))
        self.assertTrue(verify_signed_root(decoded, self.other_public_key))

    def test_call_is_read_only(self):
        receipt = self.log.sign_root(_SEED_A)
        data = encode_signed_root(receipt)
        decode_signed_root(data)
        self.assertEqual(
            decode_signed_root(data), self.log.sign_root(_SEED_A)
        )


if __name__ == "__main__":
    unittest.main()
