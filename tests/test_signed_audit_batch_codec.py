import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedAuditBatch,
    SignedRoot,
    decode_audit_batch,
    decode_signed_audit_batch,
    decode_signed_root,
    encode_audit_batch,
    encode_signed_audit_batch,
    encode_signed_root,
    verify_signed_audit_batch,
)

MAGIC = b"auditchain/signed-audit-batch/v1\0"

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
    """Split an envelope into (version, batch_blob, checkpoint_blob)."""
    assert data.startswith(MAGIC)
    offset = len(MAGIC)
    version = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    length = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    batch_blob = data[offset:offset + length]
    offset += length
    length = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    checkpoint_blob = data[offset:offset + length]
    offset += length
    assert offset == len(data)
    return version, batch_blob, checkpoint_blob


class EncodeSignedAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # batch blob: u64 length then the complete encode_audit_batch bytes.
        batch_bytes = encode_audit_batch(receipt.batch)
        self.assertEqual(data[offset:offset + 8], u64(len(batch_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(batch_bytes)], batch_bytes)
        offset += len(batch_bytes)
        # checkpoint blob: u64 length then encode_signed_root bytes.
        checkpoint_bytes = encode_signed_root(receipt.checkpoint)
        self.assertEqual(data[offset:offset + 8], u64(len(checkpoint_bytes)))
        offset += 8
        self.assertEqual(
            data[offset:offset + len(checkpoint_bytes)], checkpoint_bytes
        )
        offset += len(checkpoint_bytes)
        self.assertEqual(offset, len(data))

    def test_blobs_are_exact_existing_encodings(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        _, batch_blob, checkpoint_blob = _parse_blobs(
            encode_signed_audit_batch(receipt)
        )
        self.assertEqual(batch_blob, encode_audit_batch(receipt.batch))
        self.assertEqual(
            checkpoint_blob, encode_signed_root(receipt.checkpoint)
        )
        # The inner blobs are independently decodable by the existing codecs.
        self.assertEqual(decode_audit_batch(batch_blob), receipt.batch)
        self.assertEqual(
            decode_signed_root(checkpoint_blob), receipt.checkpoint
        )

    def test_encode_is_deterministic(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        self.assertEqual(
            encode_signed_audit_batch(receipt),
            encode_signed_audit_batch(receipt),
        )

    def test_no_new_signing_message(self):
        # The checkpoint rides along verbatim; its bytes are exactly
        # sign_root's. Encoding introduces no signature of its own.
        receipt = self.log.signed_audit_batch([0, 2], _SEED_A, 4)
        _, _, checkpoint_blob = _parse_blobs(
            encode_signed_audit_batch(receipt)
        )
        self.assertEqual(
            checkpoint_blob,
            encode_signed_root(self.log.sign_root(_SEED_A, 4)),
        )

    def test_only_signed_audit_batch_accepted(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        for bad in (
            None,
            1,
            "receipt",
            b"bytes",
            (),
            receipt.batch,
            (receipt.batch, receipt.checkpoint),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_audit_batch(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        for field, value in (
            ("batch", ["not-a-tuple"]),
            ("batch", None),
            ("checkpoint", None),
            ("checkpoint", receipt.batch),
        ):
            forged = SignedAuditBatch.__new__(SignedAuditBatch)
            object.__setattr__(
                forged,
                "batch",
                receipt.batch if field == "checkpoint" else value,
            )
            object.__setattr__(
                forged,
                "checkpoint",
                receipt.checkpoint if field == "batch" else value,
            )
            with self.assertRaises(TypeError, msg=field):
                encode_signed_audit_batch(forged)

    def test_nested_batch_type_error_propagates(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        forged = SignedAuditBatch.__new__(SignedAuditBatch)
        object.__setattr__(
            forged, "batch", (1,) + receipt.batch[1:]
        )
        object.__setattr__(forged, "checkpoint", receipt.checkpoint)
        with self.assertRaises(TypeError):
            encode_signed_audit_batch(forged)

    def test_nested_batch_value_error_propagates(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        forged = SignedAuditBatch.__new__(SignedAuditBatch)
        object.__setattr__(
            forged, "batch", ("not-a-hash",) + receipt.batch[1:]
        )
        object.__setattr__(forged, "checkpoint", receipt.checkpoint)
        with self.assertRaises(ValueError):
            encode_signed_audit_batch(forged)

    def test_nested_checkpoint_type_error_propagates(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(
                checkpoint, name, getattr(receipt.checkpoint, name)
            )
        object.__setattr__(checkpoint, "version", "1")
        forged = SignedAuditBatch.__new__(SignedAuditBatch)
        object.__setattr__(forged, "batch", receipt.batch)
        object.__setattr__(forged, "checkpoint", checkpoint)
        with self.assertRaises(TypeError):
            encode_signed_audit_batch(forged)

    def test_call_is_read_only(self):
        receipt = self.log.signed_audit_batch([1, 2], _SEED_A)
        before = encode_signed_audit_batch(receipt)
        encode_signed_audit_batch(receipt)
        self.assertEqual(encode_signed_audit_batch(receipt), before)
        self.assertTrue(
            verify_signed_audit_batch(receipt, self.public_key)
        )


class DecodeSignedAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, receipt):
        data = encode_signed_audit_batch(receipt)
        decoded = decode_signed_audit_batch(data)
        self.assertIsInstance(decoded, SignedAuditBatch)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.batch, receipt.batch)
        self.assertEqual(decoded.checkpoint, receipt.checkpoint)
        self.assertIs(type(decoded.batch), tuple)
        self.assertIs(type(decoded.batch[3]), tuple)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(encode_signed_audit_batch(decoded), data)
        self.assertTrue(
            verify_signed_audit_batch(decoded, self.public_key)
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
                self.log.signed_audit_batch(chosen, _SEED_A, size)
            )

    def test_roundtrip_empty_log(self):
        self.roundtrip(AuditLog().signed_audit_batch((), _SEED_A))

    def test_roundtrip_after_prune(self):
        twin = AuditLog()
        for i in range(6):
            record = f"r{i}"
            self.log.append(record)
            twin.append(record)
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.signed_audit_batch([2, 4], _SEED_A))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            for record in ("a", "b", "c"):
                log.append(record)
            self.roundtrip(log.signed_audit_batch([0, 2], _SEED_A))

    def test_frozen(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1], _SEED_A)
        )
        decoded = decode_signed_audit_batch(data)
        with self.assertRaises(FrozenInstanceError):
            decoded.batch = ()
        with self.assertRaises(FrozenInstanceError):
            decoded.checkpoint = decoded.checkpoint

    def test_persistence_across_process_boundary(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1, 3], _SEED_A)
        )
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_signed_audit_batch(bytes(data))
        self.assertEqual(
            restored, self.log.signed_audit_batch([1, 3], _SEED_A)
        )
        self.assertTrue(
            verify_signed_audit_batch(restored, self.public_key)
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1], _SEED_A)
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
                decode_signed_audit_batch(bad)

    def test_bad_magic(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1], _SEED_A)
        )
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/signed-root/v1\0" + data[len(MAGIC):],
            b"auditchain/batch/v1\0" + data[len(MAGIC):],
            b"auditchain/audit-receipt/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:32])):
                decode_signed_audit_batch(bad)

    def test_bad_version(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_audit_batch(bad)

    def test_truncation(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1], _SEED_A)
        )
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_audit_batch(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_audit_batch(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1], _SEED_A)
        )
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_audit_batch(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_audit_batch(bad)

    def test_missing_second_blob(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        _, batch_blob, _ = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(
                MAGIC + u64(1) + blob(batch_blob)
            )

    def test_swapped_blob_order_rejected(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        _, batch_blob, checkpoint_blob = _parse_blobs(data)
        swapped = (
            MAGIC
            + u64(1)
            + blob(checkpoint_blob)
            + blob(batch_blob)
        )
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(swapped)

    def test_garbage_batch_blob_rejected(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        _, _, checkpoint_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(
                MAGIC + u64(1) + blob(b"hello") + blob(checkpoint_blob)
            )

    def test_trailing_bytes_inside_blob_rejected(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        _, batch_blob, checkpoint_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(
                MAGIC
                + u64(1)
                + blob(batch_blob + b"\x00")
                + blob(checkpoint_blob)
            )

    def test_nested_batch_framing_error_rejected(self):
        # A batch blob whose own magic is wrong must surface ValueError.
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        _, batch_blob, checkpoint_blob = _parse_blobs(data)
        tampered = b"x" + batch_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(
                MAGIC + u64(1) + blob(tampered) + blob(checkpoint_blob)
            )

    def test_nested_checkpoint_framing_error_rejected(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        _, batch_blob, checkpoint_blob = _parse_blobs(data)
        tampered = b"x" + checkpoint_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(
                MAGIC + u64(1) + blob(batch_blob) + blob(tampered)
            )

    def test_bad_signature_still_decodes_but_verifies_false(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        checkpoint = receipt.checkpoint
        bogus = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = SignedAuditBatch(receipt.batch, bogus)
        decoded = decode_signed_audit_batch(
            encode_signed_audit_batch(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_audit_batch(decoded, self.public_key)
        )

    def test_wrong_key_decodes_but_verifies_false(self):
        receipt = self.log.signed_audit_batch([1], _SEED_B)
        decoded = decode_signed_audit_batch(
            encode_signed_audit_batch(receipt)
        )
        self.assertFalse(
            verify_signed_audit_batch(decoded, self.public_key)
        )
        self.assertTrue(
            verify_signed_audit_batch(decoded, self.other_public_key)
        )

    def test_call_is_read_only(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        decode_signed_audit_batch(data)
        self.assertEqual(
            decode_signed_audit_batch(data),
            self.log.signed_audit_batch([1], _SEED_A),
        )


if __name__ == "__main__":
    unittest.main()
