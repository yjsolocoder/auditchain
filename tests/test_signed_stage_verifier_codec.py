import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedStageVerifier,
    StageVerifier,
    decode_signed_stage_verifier,
    encode_signed_stage_verifier,
    verify_signed_stage_verifier,
)

MAGIC = b"auditchain/signed-stage/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-stage-key"


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


def delivered_receipt(stage, seed=_SEED_A, hash_name="sha256"):
    """A log evolved to ``stage`` and its signed stage verifier."""
    log = AuditLog(key=_KEY, hash_name=hash_name)
    for record in ("a", "b", "c"):
        log.append(record)
    for index in range(stage):
        log.auth(index % 3)
    return log, log.export_signed_stage_verifier(seed)


class EncodeSignedStageVerifierTest(unittest.TestCase):
    def test_magic_and_field_layout(self):
        _, receipt = delivered_receipt(3)
        data = encode_signed_stage_verifier(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(3))  # stage
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(32))  # key length
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.verifier.key)
        offset += 32
        self.assertEqual(data[offset:offset + 8], u64(64))  # signature length
        offset += 8
        self.assertEqual(data[offset:offset + 64], receipt.signature)
        offset += 64
        self.assertEqual(offset, len(data))

    def test_encode_is_deterministic(self):
        _, receipt = delivered_receipt(2)
        self.assertEqual(
            encode_signed_stage_verifier(receipt),
            encode_signed_stage_verifier(receipt),
        )

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                encode_signed_stage_verifier(bad)

    def test_bypassed_wrong_field_types_raise_type_error(self):
        _, receipt = delivered_receipt(1)
        for field, value in (
            ("version", "1"),
            ("verifier", "not-a-verifier"),
            ("signature", bytearray(receipt.signature)),
        ):
            forged = SignedStageVerifier.__new__(SignedStageVerifier)
            for name in ("version", "verifier", "signature"):
                object.__setattr__(forged, name, getattr(receipt, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_signed_stage_verifier(forged)

    def test_bypassed_bad_structure_raises_value_error(self):
        _, receipt = delivered_receipt(1)
        for field, value in (
            ("version", 2),
            ("signature", b"\x00" * 63),
            ("signature", b"\x00" * 65),
        ):
            forged = SignedStageVerifier.__new__(SignedStageVerifier)
            for name in ("version", "verifier", "signature"):
                object.__setattr__(forged, name, getattr(receipt, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(ValueError, msg=f"{field}={value!r}"):
                encode_signed_stage_verifier(forged)

    def test_bypassed_nested_verifier_corruption_raises(self):
        _, receipt = delivered_receipt(1)
        verifier = StageVerifier.__new__(StageVerifier)
        object.__setattr__(verifier, "stage", -1)
        object.__setattr__(verifier, "key", receipt.verifier.key)
        object.__setattr__(verifier, "hash_name", receipt.verifier.hash_name)
        forged = SignedStageVerifier.__new__(SignedStageVerifier)
        object.__setattr__(forged, "version", 1)
        object.__setattr__(forged, "verifier", verifier)
        object.__setattr__(forged, "signature", receipt.signature)
        with self.assertRaises(ValueError):
            encode_signed_stage_verifier(forged)

    def test_call_is_read_only(self):
        _, receipt = delivered_receipt(1)
        before = encode_signed_stage_verifier(receipt)
        encode_signed_stage_verifier(receipt)
        self.assertEqual(encode_signed_stage_verifier(receipt), before)
        self.assertTrue(
            verify_signed_stage_verifier(receipt, _public_key(_SEED_A))
        )


class DecodeSignedStageVerifierTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, receipt):
        data = encode_signed_stage_verifier(receipt)
        decoded = decode_signed_stage_verifier(data)
        self.assertEqual(decoded, receipt)
        self.assertIsNot(decoded, receipt)
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.verifier, receipt.verifier)
        self.assertEqual(decoded.signature, receipt.signature)
        self.assertIsInstance(decoded.verifier.key, bytes)
        self.assertIsInstance(decoded.signature, bytes)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_signed_stage_verifier(decoded), data)
        self.assertTrue(verify_signed_stage_verifier(decoded, self.public_key))
        return decoded

    def test_roundtrip_variants(self):
        for stage in (1, 2, 5):
            _, receipt = delivered_receipt(stage)
            self.roundtrip(receipt)

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            _, receipt = delivered_receipt(2, hash_name=hash_name)
            self.roundtrip(receipt)

    def test_decoded_is_frozen(self):
        _, receipt = delivered_receipt(1)
        decoded = self.roundtrip(receipt)
        with self.assertRaises(FrozenInstanceError):
            decoded.signature = b"\x00" * 64

    def test_persistence_across_process_boundary(self):
        _, receipt = delivered_receipt(2)
        data = encode_signed_stage_verifier(receipt)
        # A fresh byte sequence (as read back from disk or a socket) decodes
        # into a receipt that still verifies against the pre-trusted key.
        restored = decode_signed_stage_verifier(bytes(data))
        self.assertEqual(restored, receipt)
        self.assertTrue(verify_signed_stage_verifier(restored, self.public_key))

    def test_only_bytes_accepted(self):
        _, receipt = delivered_receipt(1)
        data = encode_signed_stage_verifier(receipt)
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_signed_stage_verifier(bad)

    def test_bad_magic(self):
        _, receipt = delivered_receipt(1)
        data = encode_signed_stage_verifier(receipt)
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(b"")
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(MAGIC[:-1])
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(
                b"auditchain/stage-verifier/v1\0" + data[len(MAGIC):]
            )

    def test_bad_version(self):
        _, receipt = delivered_receipt(1)
        data = (
            MAGIC + u64(2) + encode_signed_stage_verifier(receipt)[len(MAGIC) + 8:]
        )
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(data)

    def test_unknown_hash_algorithm(self):
        data = (
            MAGIC
            + u64(1)
            + u64(1)
            + blob(b"not-a-hash")
            + blob(b"\x00" * 32)
            + blob(b"\x00" * 64)
        )
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(data)

    def test_invalid_utf8_hash_name(self):
        data = (
            MAGIC
            + u64(1)
            + u64(1)
            + blob(b"\xff\xfe")
            + blob(b"\x00" * 32)
            + blob(b"\x00" * 64)
        )
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(data)

    def test_truncation(self):
        _, receipt = delivered_receipt(1)
        data = encode_signed_stage_verifier(receipt)
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_signed_stage_verifier(data[:cut])

    def test_trailing_bytes(self):
        _, receipt = delivered_receipt(1)
        data = encode_signed_stage_verifier(receipt)
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_signed_stage_verifier(data + extra)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(data)

    def test_empty_key_rejected(self):
        data = (
            MAGIC
            + u64(1)
            + u64(0)
            + blob(b"sha256")
            + blob(b"")
            + blob(b"\x00" * 64)
        )
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(data)

    def test_positive_stage_key_width_checked(self):
        base = MAGIC + u64(1) + u64(1) + blob(b"sha256")
        for key in (b"short", b"\x00" * 33):
            with self.assertRaises(ValueError):
                decode_signed_stage_verifier(
                    base + blob(key) + blob(b"\x00" * 64)
                )

    def test_signature_width_checked(self):
        _, receipt = delivered_receipt(1)
        base = (
            MAGIC
            + u64(1)
            + u64(receipt.verifier.stage)
            + blob(b"sha256")
            + blob(receipt.verifier.key)
        )
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(base + blob(b"\x00" * 63))
        with self.assertRaises(ValueError):
            decode_signed_stage_verifier(base + blob(b"\x00" * 65))

    def test_wrong_signature_decodes_but_verifies_false(self):
        _, receipt = delivered_receipt(1)
        forged = (
            MAGIC
            + u64(1)
            + u64(receipt.verifier.stage)
            + blob(b"sha256")
            + blob(receipt.verifier.key)
            + blob(b"\x00" * 64)
        )
        decoded = decode_signed_stage_verifier(forged)
        self.assertEqual(decoded.signature, b"\x00" * 64)
        self.assertFalse(verify_signed_stage_verifier(decoded, self.public_key))

    def test_wrong_key_roundtrip_verifies_false(self):
        _, receipt = delivered_receipt(1, seed=_SEED_B)
        data = encode_signed_stage_verifier(receipt)
        decoded = decode_signed_stage_verifier(data)
        self.assertFalse(verify_signed_stage_verifier(decoded, self.public_key))
        self.assertTrue(
            verify_signed_stage_verifier(decoded, self.other_public_key)
        )

    def test_call_is_read_only(self):
        _, receipt = delivered_receipt(1)
        data = encode_signed_stage_verifier(receipt)
        decode_signed_stage_verifier(data)
        self.assertEqual(decode_signed_stage_verifier(data), receipt)


if __name__ == "__main__":
    unittest.main()
