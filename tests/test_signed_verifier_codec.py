import unittest

from auditchain import (
    AuditLog,
    SignedVerifier,
    Verifier,
    decode_signed_verifier,
    encode_signed_verifier,
    verify_auth,
    verify_signed_verifier,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAGIC = b"auditchain/signed-verifier/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"


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


def _receipt(seed=_SEED_A, key=_KEY, hash_name="sha256", records=("a", "b", "c")):
    # export_signed_verifier shares a one-shot export eligibility with
    # export_verifier, so every receipt needs a fresh stage-0 log.
    log = AuditLog(key=key, hash_name=hash_name)
    for record in records:
        log.append(record)
    return log.export_signed_verifier(seed)


class EncodeSignedVerifierTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        receipt = _receipt()
        data = encode_signed_verifier(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(len(_KEY)))  # key length
        offset += 8
        self.assertEqual(data[offset:offset + len(_KEY)], _KEY)
        offset += len(_KEY)
        self.assertEqual(data[offset:offset + 8], u64(64))  # signature length
        offset += 8
        self.assertEqual(data[offset:offset + 64], receipt.signature)
        offset += 64
        self.assertEqual(offset, len(data))

    def test_encode_is_deterministic(self):
        receipt = _receipt()
        self.assertEqual(
            encode_signed_verifier(receipt), encode_signed_verifier(receipt)
        )

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                encode_signed_verifier(bad)

    def test_bypassed_wrong_field_types_raise_type_error(self):
        receipt = _receipt()
        for field, value in (
            ("version", "1"),
            ("verifier", "not-a-verifier"),
            ("signature", bytearray(receipt.signature)),
        ):
            forged = SignedVerifier.__new__(SignedVerifier)
            for name in ("version", "verifier", "signature"):
                object.__setattr__(forged, name, getattr(receipt, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_signed_verifier(forged)

    def test_bypassed_wrong_nested_field_types_raise_type_error(self):
        receipt = _receipt()
        for field, value in (
            ("key", bytearray(receipt.verifier.key)),
            ("hash_name", 1),
        ):
            verifier = Verifier.__new__(Verifier)
            object.__setattr__(verifier, "key", receipt.verifier.key)
            object.__setattr__(verifier, "hash_name", receipt.verifier.hash_name)
            object.__setattr__(verifier, field, value)
            forged = SignedVerifier.__new__(SignedVerifier)
            object.__setattr__(forged, "version", receipt.version)
            object.__setattr__(forged, "verifier", verifier)
            object.__setattr__(forged, "signature", receipt.signature)
            with self.assertRaises(TypeError, msg=field):
                encode_signed_verifier(forged)

    def test_bypassed_bad_structure_raises_value_error(self):
        receipt = _receipt()
        for field, value in (
            ("version", 2),
            ("signature", b"\x00" * 63),
            ("signature", b"\x00" * 65),
        ):
            forged = SignedVerifier.__new__(SignedVerifier)
            for name in ("version", "verifier", "signature"):
                object.__setattr__(forged, name, getattr(receipt, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(ValueError, msg=field):
                encode_signed_verifier(forged)

    def test_bypassed_bad_nested_structure_raises_value_error(self):
        receipt = _receipt()
        for field, value in (
            ("key", b""),
            ("hash_name", "not-a-hash"),
        ):
            verifier = Verifier.__new__(Verifier)
            object.__setattr__(verifier, "key", receipt.verifier.key)
            object.__setattr__(verifier, "hash_name", receipt.verifier.hash_name)
            object.__setattr__(verifier, field, value)
            forged = SignedVerifier.__new__(SignedVerifier)
            object.__setattr__(forged, "version", receipt.version)
            object.__setattr__(forged, "verifier", verifier)
            object.__setattr__(forged, "signature", receipt.signature)
            with self.assertRaises(ValueError, msg=field):
                encode_signed_verifier(forged)

    def test_call_is_read_only(self):
        receipt = _receipt()
        before = encode_signed_verifier(receipt)
        encode_signed_verifier(receipt)
        self.assertEqual(encode_signed_verifier(receipt), before)
        self.assertTrue(verify_signed_verifier(receipt, self.public_key))


class DecodeSignedVerifierTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, receipt):
        data = encode_signed_verifier(receipt)
        decoded = decode_signed_verifier(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.verifier, receipt.verifier)
        self.assertEqual(decoded.verifier.key, receipt.verifier.key)
        self.assertEqual(decoded.verifier.hash_name, receipt.verifier.hash_name)
        self.assertEqual(decoded.signature, receipt.signature)
        self.assertIsInstance(decoded.verifier.key, bytes)
        self.assertIsInstance(decoded.signature, bytes)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_signed_verifier(decoded), data)
        self.assertTrue(verify_signed_verifier(decoded, self.public_key))
        return decoded

    def test_roundtrip(self):
        self.roundtrip(_receipt())

    def test_roundtrip_empty_log(self):
        self.roundtrip(_receipt(records=()))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            self.roundtrip(_receipt(hash_name=hash_name))

    def test_roundtrip_other_key_material(self):
        self.roundtrip(_receipt(key=b"k"))
        self.roundtrip(_receipt(key=bytes(range(256))))

    def test_persistence_across_process_boundary(self):
        data = encode_signed_verifier(_receipt())
        # A fresh byte sequence (as read back from disk or a socket) decodes
        # into a receipt that still verifies against the pre-trusted key and
        # whose verifier still authenticates tags offline.
        restored = decode_signed_verifier(bytes(data))
        self.assertEqual(restored, _receipt())
        self.assertTrue(verify_signed_verifier(restored, self.public_key))
        log = AuditLog(key=_KEY)
        log.append("agent started")
        tag = log.auth(0)
        self.assertTrue(verify_auth(log.entry(0), tag, restored.verifier))

    def test_only_bytes_accepted(self):
        data = encode_signed_verifier(_receipt())
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_signed_verifier(bad)

    def test_bad_magic(self):
        data = encode_signed_verifier(_receipt())
        with self.assertRaises(ValueError):
            decode_signed_verifier(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_signed_verifier(b"")
        with self.assertRaises(ValueError):
            decode_signed_verifier(MAGIC[:-1])
        with self.assertRaises(ValueError):
            decode_signed_verifier(
                b"auditchain/signed-root/v1\0" + data[len(MAGIC):]
            )

    def test_bad_version(self):
        receipt = _receipt()
        data = MAGIC + u64(2) + encode_signed_verifier(receipt)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_signed_verifier(data)

    def test_unknown_hash_algorithm(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"not-a-hash")
            + blob(_KEY)
            + blob(b"\x00" * 64)
        )
        with self.assertRaises(ValueError):
            decode_signed_verifier(data)

    def test_invalid_utf8_hash_name(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"\xff\xfe")
            + blob(_KEY)
            + blob(b"\x00" * 64)
        )
        with self.assertRaises(ValueError):
            decode_signed_verifier(data)

    def test_truncation(self):
        data = encode_signed_verifier(_receipt())
        for cut in (
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError):
                decode_signed_verifier(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_signed_verifier(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_verifier(_receipt())
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_signed_verifier(data + extra)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_signed_verifier(data)

    def test_empty_key_rejected(self):
        data = MAGIC + u64(1) + blob(b"sha256") + blob(b"") + blob(b"\x00" * 64)
        with self.assertRaises(ValueError):
            decode_signed_verifier(data)

    def test_signature_width_checked(self):
        base = MAGIC + u64(1) + blob(b"sha256") + blob(_KEY)
        with self.assertRaises(ValueError):
            decode_signed_verifier(base + blob(b"\x00" * 63))
        with self.assertRaises(ValueError):
            decode_signed_verifier(base + blob(b"\x00" * 65))

    def test_wrong_signature_decodes_but_verifies_false(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + blob(_KEY)
            + blob(b"\x00" * 64)
        )
        decoded = decode_signed_verifier(data)
        self.assertEqual(decoded.signature, b"\x00" * 64)
        self.assertFalse(verify_signed_verifier(decoded, self.public_key))

    def test_wrong_key_roundtrip_verifies_false(self):
        data = encode_signed_verifier(_receipt(seed=_SEED_B))
        decoded = decode_signed_verifier(data)
        self.assertFalse(verify_signed_verifier(decoded, self.public_key))
        self.assertTrue(verify_signed_verifier(decoded, self.other_public_key))

    def test_call_is_read_only(self):
        receipt = _receipt()
        data = encode_signed_verifier(receipt)
        decode_signed_verifier(data)
        self.assertEqual(decode_signed_verifier(data), receipt)


if __name__ == "__main__":
    unittest.main()
