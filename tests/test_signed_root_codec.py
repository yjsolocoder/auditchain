import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedRoot,
    decode_signed_root,
    encode_signed_root,
    verify_signed_root,
)

MAGIC = b"auditchain/signed-root/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


class EncodeSignedRootTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.receipt = self.log.sign_root(_SEED_A)

    def test_magic_and_field_layout(self):
        data = encode_signed_root(self.receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(5))  # size
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(32))  # root length
        offset += 8
        self.assertEqual(data[offset:offset + 32], self.receipt.root)
        offset += 32
        self.assertEqual(data[offset:offset + 8], u64(32))  # head length
        offset += 8
        self.assertEqual(data[offset:offset + 32], self.receipt.head)
        offset += 32
        self.assertEqual(data[offset:offset + 8], u64(64))  # signature length
        offset += 8
        self.assertEqual(data[offset:offset + 64], self.receipt.signature)
        offset += 64
        self.assertEqual(offset, len(data))

    def test_encode_is_deterministic(self):
        self.assertEqual(
            encode_signed_root(self.receipt), encode_signed_root(self.receipt)
        )

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2)):
            with self.assertRaises(TypeError):
                encode_signed_root(bad)

    def test_bypassed_field_types_raise(self):
        forged = SignedRoot.__new__(SignedRoot)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", self.receipt.size),
            ("root", bytearray(self.receipt.root)),
            ("head", self.receipt.head),
            ("signature", self.receipt.signature),
        ):
            object.__setattr__(forged, name, value)
        with self.assertRaises(TypeError):
            encode_signed_root(forged)

    def test_call_is_read_only(self):
        head = self.log.head
        data = encode_signed_root(self.receipt)
        self.assertEqual(self.receipt, self.log.sign_root(_SEED_A))
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 5)
        self.assertEqual(encode_signed_root(self.receipt), data)


class DecodeSignedRootTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, receipt, public_key=None):
        data = encode_signed_root(receipt)
        decoded = decode_signed_root(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.hash_name, receipt.hash_name)
        self.assertEqual(decoded.size, receipt.size)
        self.assertEqual(decoded.root, receipt.root)
        self.assertEqual(decoded.head, receipt.head)
        self.assertEqual(decoded.signature, receipt.signature)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_signed_root(decoded), data)
        self.assertTrue(
            verify_signed_root(decoded, public_key or self.public_key)
        )
        return decoded

    def test_roundtrip_variants(self):
        for size in (None, 0, 1, 3, 5):
            self.roundtrip(self.log.sign_root(_SEED_A, size))

    def test_roundtrip_empty_log(self):
        self.roundtrip(AuditLog().sign_root(_SEED_A))

    def test_roundtrip_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.sign_root(_SEED_A, 4))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        self.roundtrip(log.sign_root(_SEED_A))

    def test_roundtrip_other_key(self):
        self.roundtrip(self.log.sign_root(_SEED_B), self.other_public_key)

    def test_only_bytes_accepted(self):
        data = encode_signed_root(self.log.sign_root(_SEED_A))
        for bad in (bytearray(data), memoryview(data), "text", None, 1):
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

    def test_bad_version(self):
        data = encode_signed_root(self.log.sign_root(_SEED_A))
        data = MAGIC + u64(2) + data[len(MAGIC) + 8:]
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
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_signed_root(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_root(self.log.sign_root(_SEED_A))
        with self.assertRaises(ValueError):
            decode_signed_root(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_signed_root(data)

    def test_digest_width_checked(self):
        receipt = self.log.sign_root(_SEED_A)
        for bad_root in (b"\x00" * 31, b"\x00" * 33):
            data = (
                MAGIC
                + u64(1)
                + blob(b"sha256")
                + u64(5)
                + blob(bad_root)
                + blob(receipt.head)
                + blob(receipt.signature)
            )
            with self.assertRaises(ValueError):
                decode_signed_root(data)

    def test_signature_width_checked(self):
        receipt = self.log.sign_root(_SEED_A)
        for bad_signature in (b"\x00" * 63, b"\x00" * 65):
            data = (
                MAGIC
                + u64(1)
                + blob(b"sha256")
                + u64(5)
                + blob(receipt.root)
                + blob(receipt.head)
                + blob(bad_signature)
            )
            with self.assertRaises(ValueError):
                decode_signed_root(data)

    def test_structurally_valid_but_forged_decodes_and_fails_verification(self):
        receipt = self.log.sign_root(_SEED_A)
        forged = SignedRoot(
            1, "sha256", receipt.size, receipt.root, receipt.head, b"\x00" * 64
        )
        decoded = decode_signed_root(encode_signed_root(forged))
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_signed_root(decoded, self.public_key))

    def test_tampered_encoding_fails_verification(self):
        data = bytearray(encode_signed_root(self.log.sign_root(_SEED_A)))
        # Flip one bit inside the root blob.
        data[len(MAGIC) + 8 + 8 + 6 + 8 + 8] ^= 0x01
        decoded = decode_signed_root(bytes(data))
        self.assertFalse(verify_signed_root(decoded, self.public_key))


if __name__ == "__main__":
    unittest.main()
