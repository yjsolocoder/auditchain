import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    AuditReceipt,
    SignedAuditReceipt,
    SignedRoot,
    decode_audit_receipt,
    decode_signed_audit_receipt,
    decode_signed_root,
    encode_audit_receipt,
    encode_signed_audit_receipt,
    encode_signed_root,
    verify_signed_audit_receipt,
)

MAGIC = b"auditchain/signed-audit-receipt/v1\0"

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


def _parse_blobs(data):
    """Split an envelope into (version, receipt_blob, checkpoint_blob)."""
    assert data.startswith(MAGIC)
    offset = len(MAGIC)
    version = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    length = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    receipt_blob = data[offset:offset + length]
    offset += length
    length = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    checkpoint_blob = data[offset:offset + length]
    offset += length
    assert offset == len(data)
    return version, receipt_blob, checkpoint_blob


class EncodeSignedAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        data = encode_signed_audit_receipt(bundle)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # receipt blob: u64 length then the complete encode_audit_receipt bytes.
        receipt_bytes = encode_audit_receipt(bundle.receipt)
        self.assertEqual(data[offset:offset + 8], u64(len(receipt_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(receipt_bytes)], receipt_bytes)
        offset += len(receipt_bytes)
        # checkpoint blob: u64 length then encode_signed_root bytes.
        checkpoint_bytes = encode_signed_root(bundle.checkpoint)
        self.assertEqual(data[offset:offset + 8], u64(len(checkpoint_bytes)))
        offset += 8
        self.assertEqual(
            data[offset:offset + len(checkpoint_bytes)], checkpoint_bytes
        )
        offset += len(checkpoint_bytes)
        self.assertEqual(offset, len(data))

    def test_blobs_are_exact_existing_encodings(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        _, receipt_blob, checkpoint_blob = _parse_blobs(
            encode_signed_audit_receipt(bundle)
        )
        self.assertEqual(receipt_blob, encode_audit_receipt(bundle.receipt))
        self.assertEqual(
            checkpoint_blob, encode_signed_root(bundle.checkpoint)
        )
        # The inner blobs are independently decodable by the existing codecs.
        self.assertEqual(decode_audit_receipt(receipt_blob), bundle.receipt)
        self.assertEqual(
            decode_signed_root(checkpoint_blob), bundle.checkpoint
        )

    def test_encode_is_deterministic(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        self.assertEqual(
            encode_signed_audit_receipt(bundle),
            encode_signed_audit_receipt(bundle),
        )

    def test_no_new_signing_message(self):
        # The checkpoint rides along verbatim; its bytes are exactly
        # sign_root's. Encoding introduces no signature of its own.
        bundle = self.log.signed_audit_receipt([0, 2], _SEED_A, 4)
        _, _, checkpoint_blob = _parse_blobs(
            encode_signed_audit_receipt(bundle)
        )
        self.assertEqual(
            checkpoint_blob,
            encode_signed_root(self.log.sign_root(_SEED_A, 4)),
        )

    def test_only_signed_audit_receipt_accepted(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        for bad in (
            None,
            1,
            "receipt",
            b"bytes",
            (),
            bundle.receipt,
            (bundle.receipt, bundle.checkpoint),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_audit_receipt(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        for field, value in (
            ("receipt", (bundle.receipt,)),
            ("receipt", None),
            ("checkpoint", None),
            ("checkpoint", bundle.receipt),
        ):
            forged = SignedAuditReceipt.__new__(SignedAuditReceipt)
            object.__setattr__(
                forged,
                "receipt",
                bundle.receipt if field == "checkpoint" else value,
            )
            object.__setattr__(
                forged,
                "checkpoint",
                bundle.checkpoint if field == "receipt" else value,
            )
            with self.assertRaises(TypeError, msg=field):
                encode_signed_audit_receipt(forged)

    def test_nested_receipt_type_error_propagates(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        receipt = AuditReceipt.__new__(AuditReceipt)
        for name in ("version", "hash_name", "size", "root", "items"):
            object.__setattr__(receipt, name, getattr(bundle.receipt, name))
        object.__setattr__(receipt, "size", "5")
        forged = SignedAuditReceipt.__new__(SignedAuditReceipt)
        object.__setattr__(forged, "receipt", receipt)
        object.__setattr__(forged, "checkpoint", bundle.checkpoint)
        with self.assertRaises(TypeError):
            encode_signed_audit_receipt(forged)

    def test_nested_receipt_value_error_propagates(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        receipt = AuditReceipt.__new__(AuditReceipt)
        for name in ("version", "hash_name", "size", "root", "items"):
            object.__setattr__(receipt, name, getattr(bundle.receipt, name))
        # A non-empty snapshot receipt without its last entry is illegal.
        object.__setattr__(receipt, "items", ())
        forged = SignedAuditReceipt.__new__(SignedAuditReceipt)
        object.__setattr__(forged, "receipt", receipt)
        object.__setattr__(forged, "checkpoint", bundle.checkpoint)
        with self.assertRaises(ValueError):
            encode_signed_audit_receipt(forged)

    def test_nested_checkpoint_type_error_propagates(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(
                checkpoint, name, getattr(bundle.checkpoint, name)
            )
        object.__setattr__(checkpoint, "version", "1")
        forged = SignedAuditReceipt.__new__(SignedAuditReceipt)
        object.__setattr__(forged, "receipt", bundle.receipt)
        object.__setattr__(forged, "checkpoint", checkpoint)
        with self.assertRaises(TypeError):
            encode_signed_audit_receipt(forged)

    def test_call_is_read_only(self):
        bundle = self.log.signed_audit_receipt([1, 2], _SEED_A)
        before = encode_signed_audit_receipt(bundle)
        encode_signed_audit_receipt(bundle)
        self.assertEqual(encode_signed_audit_receipt(bundle), before)
        self.assertTrue(
            verify_signed_audit_receipt(bundle, self.public_key)
        )


class DecodeSignedAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, bundle):
        data = encode_signed_audit_receipt(bundle)
        decoded = decode_signed_audit_receipt(data)
        self.assertIsInstance(decoded, SignedAuditReceipt)
        self.assertEqual(decoded, bundle)
        self.assertEqual(decoded.receipt, bundle.receipt)
        self.assertEqual(decoded.checkpoint, bundle.checkpoint)
        self.assertIs(type(decoded.receipt.items), tuple)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(encode_signed_audit_receipt(decoded), data)
        self.assertTrue(
            verify_signed_audit_receipt(decoded, self.public_key)
        )
        return decoded

    def test_roundtrip_variants(self):
        for chosen, size in (
            ([0], None),
            ([1, 3], None),
            ([3], 4),
            ([], None),
            ([], 3),
            ([0, 6], None),
            (range(7), None),
            ((), 0),
        ):
            self.roundtrip(
                self.log.signed_audit_receipt(chosen, _SEED_A, size)
            )

    def test_roundtrip_empty_log(self):
        self.roundtrip(AuditLog().signed_audit_receipt((), _SEED_A))

    def test_roundtrip_after_prune(self):
        twin = AuditLog()
        for i in range(6):
            record = f"r{i}"
            self.log.append(record)
            twin.append(record)
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.signed_audit_receipt([2, 4], _SEED_A))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            for record in ("a", "b", "c"):
                log.append(record)
            self.roundtrip(log.signed_audit_receipt([0, 2], _SEED_A))

    def test_frozen(self):
        data = encode_signed_audit_receipt(
            self.log.signed_audit_receipt([1], _SEED_A)
        )
        decoded = decode_signed_audit_receipt(data)
        with self.assertRaises(FrozenInstanceError):
            decoded.receipt = None
        with self.assertRaises(FrozenInstanceError):
            decoded.checkpoint = decoded.checkpoint

    def test_persistence_across_process_boundary(self):
        data = encode_signed_audit_receipt(
            self.log.signed_audit_receipt([1, 3], _SEED_A)
        )
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_signed_audit_receipt(bytes(data))
        self.assertEqual(
            restored, self.log.signed_audit_receipt([1, 3], _SEED_A)
        )
        self.assertTrue(
            verify_signed_audit_receipt(restored, self.public_key)
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_audit_receipt(
            self.log.signed_audit_receipt([1], _SEED_A)
        )
        for bad in (
            bytearray(data),
            memoryview(data),
            "text",
            None,
            1,
            (),
            [],
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_signed_audit_receipt(bad)

    def test_bad_magic(self):
        data = encode_signed_audit_receipt(
            self.log.signed_audit_receipt([1], _SEED_A)
        )
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/signed-root/v1\0" + data[len(MAGIC):],
            b"auditchain/audit-receipt/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-audit-batch/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:32])):
                decode_signed_audit_receipt(bad)

    def test_bad_version(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        data = encode_signed_audit_receipt(bundle)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_audit_receipt(bad)

    def test_truncation(self):
        data = encode_signed_audit_receipt(
            self.log.signed_audit_receipt([1], _SEED_A)
        )
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_audit_receipt(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_audit_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_audit_receipt(
            self.log.signed_audit_receipt([1], _SEED_A)
        )
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_audit_receipt(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_audit_receipt(bad)

    def test_missing_second_blob(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        data = encode_signed_audit_receipt(bundle)
        _, receipt_blob, _ = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_audit_receipt(
                MAGIC + u64(1) + blob(receipt_blob)
            )

    def test_swapped_blob_order_rejected(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        data = encode_signed_audit_receipt(bundle)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        swapped = (
            MAGIC
            + u64(1)
            + blob(checkpoint_blob)
            + blob(receipt_blob)
        )
        with self.assertRaises(ValueError):
            decode_signed_audit_receipt(swapped)

    def test_garbage_receipt_blob_rejected(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        data = encode_signed_audit_receipt(bundle)
        _, _, checkpoint_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_audit_receipt(
                MAGIC + u64(1) + blob(b"hello") + blob(checkpoint_blob)
            )

    def test_trailing_bytes_inside_blob_rejected(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        data = encode_signed_audit_receipt(bundle)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_audit_receipt(
                MAGIC
                + u64(1)
                + blob(receipt_blob + b"\x00")
                + blob(checkpoint_blob)
            )

    def test_nested_receipt_framing_error_rejected(self):
        # A receipt blob whose own magic is wrong must surface ValueError.
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        data = encode_signed_audit_receipt(bundle)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        tampered = b"x" + receipt_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_audit_receipt(
                MAGIC + u64(1) + blob(tampered) + blob(checkpoint_blob)
            )

    def test_nested_checkpoint_framing_error_rejected(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        data = encode_signed_audit_receipt(bundle)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        tampered = b"x" + checkpoint_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_audit_receipt(
                MAGIC + u64(1) + blob(receipt_blob) + blob(tampered)
            )

    def test_bad_signature_still_decodes_but_verifies_false(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        checkpoint = bundle.checkpoint
        bogus = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = SignedAuditReceipt(bundle.receipt, bogus)
        decoded = decode_signed_audit_receipt(
            encode_signed_audit_receipt(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_audit_receipt(decoded, self.public_key)
        )

    def test_wrong_key_decodes_but_verifies_false(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_B)
        decoded = decode_signed_audit_receipt(
            encode_signed_audit_receipt(bundle)
        )
        self.assertFalse(
            verify_signed_audit_receipt(decoded, self.public_key)
        )
        self.assertTrue(
            verify_signed_audit_receipt(decoded, self.other_public_key)
        )

    def test_call_is_read_only(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        data = encode_signed_audit_receipt(bundle)
        decode_signed_audit_receipt(data)
        self.assertEqual(
            decode_signed_audit_receipt(data),
            self.log.signed_audit_receipt([1], _SEED_A),
        )


if __name__ == "__main__":
    unittest.main()
