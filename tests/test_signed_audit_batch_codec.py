import unittest

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


def build(version, batch_blob, checkpoint_blob):
    """Hand-build a signed-audit-batch envelope with arbitrary content."""
    return (
        MAGIC
        + u64(version)
        + blob(batch_blob)
        + blob(checkpoint_blob)
    )


class EncodeSignedAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A, 4)
        batch_blob = encode_audit_batch(receipt.batch)
        checkpoint_blob = encode_signed_root(receipt.checkpoint)
        data = encode_signed_audit_batch(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(len(batch_blob)))
        offset += 8
        self.assertEqual(data[offset:offset + len(batch_blob)], batch_blob)
        self.assertTrue(batch_blob.startswith(b"auditchain/batch/v1\0"))
        offset += len(batch_blob)
        self.assertEqual(data[offset:offset + 8], u64(len(checkpoint_blob)))
        offset += 8
        self.assertEqual(data[offset:offset + len(checkpoint_blob)], checkpoint_blob)
        self.assertTrue(checkpoint_blob.startswith(b"auditchain/signed-root/v1\0"))
        offset += len(checkpoint_blob)
        self.assertEqual(offset, len(data))

    def test_empty_snapshot_layout(self):
        receipt = AuditLog().signed_audit_batch((), _SEED_A, 0)
        data = encode_signed_audit_batch(receipt)
        offset = len(MAGIC) + 8
        batch_blob = encode_audit_batch(receipt.batch)
        checkpoint_blob = encode_signed_root(receipt.checkpoint)
        self.assertEqual(data[offset:offset + 8], u64(len(batch_blob)))
        offset += 8 + len(batch_blob)
        self.assertEqual(data[offset:offset + 8], u64(len(checkpoint_blob)))
        offset += 8 + len(checkpoint_blob)
        self.assertEqual(offset, len(data))

    def test_embedded_blobs_are_verbatim_canonical_bytes(self):
        receipt = self.log.signed_audit_batch([0, 2], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        prefix = MAGIC + u64(1)
        self.assertEqual(
            data,
            prefix
            + blob(encode_audit_batch(receipt.batch))
            + blob(encode_signed_root(receipt.checkpoint)),
        )

    def test_encode_is_deterministic(self):
        receipt = self.log.signed_audit_batch([0, 4], _SEED_A)
        self.assertEqual(
            encode_signed_audit_batch(receipt),
            encode_signed_audit_batch(receipt),
        )

    def test_only_signed_audit_batch_accepted(self):
        batch = self.log.audit_batch([1])
        checkpoint = self.log.sign_root(_SEED_A)
        for bad in (
            None,
            "receipt",
            b"bytes",
            1,
            (batch, checkpoint),
            checkpoint,
            object(),
        ):
            with self.assertRaises(TypeError):
                encode_signed_audit_batch(bad)

    def test_bypassed_wrong_container_field_types_raise_type_error(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        for field, value in (
            ("batch", [receipt.batch]),
            ("batch", list(receipt.batch)),
            ("checkpoint", receipt.checkpoint.signature),
            ("checkpoint", None),
        ):
            forged = SignedAuditBatch.__new__(SignedAuditBatch)
            object.__setattr__(forged, "batch", receipt.batch)
            object.__setattr__(forged, "checkpoint", receipt.checkpoint)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_signed_audit_batch(forged)

    def test_nested_errors_propagate_from_existing_encoders(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        # A batch five-tuple that is not structurally encodable: a checkpoint
        # that is a valid SignedRoot keeps the failure isolated to the batch
        # encoder. A non-tuple batch is a container TypeError; a tuple with a
        # broken field raises like encode_audit_batch would.
        bad_batch = ("sha256", -1, receipt.batch[2], (), ())
        forged = SignedAuditBatch.__new__(SignedAuditBatch)
        object.__setattr__(forged, "batch", bad_batch)
        object.__setattr__(forged, "checkpoint", receipt.checkpoint)
        with self.assertRaises(ValueError):
            encode_signed_audit_batch(forged)
        with self.assertRaises(ValueError):
            encode_audit_batch(bad_batch)

        # A structurally broken checkpoint (signature of wrong width) raises
        # ValueError from encode_signed_root.
        bad_checkpoint = SignedRoot.__new__(SignedRoot)
        for name in ("version", "hash_name", "size", "root", "head", "signature"):
            object.__setattr__(
                bad_checkpoint, name, getattr(receipt.checkpoint, name)
            )
        object.__setattr__(bad_checkpoint, "signature", b"\x00" * 63)
        forged_root = SignedAuditBatch.__new__(SignedAuditBatch)
        object.__setattr__(forged_root, "batch", receipt.batch)
        object.__setattr__(forged_root, "checkpoint", bad_checkpoint)
        with self.assertRaises(ValueError):
            encode_signed_audit_batch(forged_root)

    def test_call_is_read_only(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        before = encode_signed_audit_batch(receipt)
        encode_signed_audit_batch(receipt)
        self.assertEqual(encode_signed_audit_batch(receipt), before)
        self.assertTrue(verify_signed_audit_batch(receipt, self.public_key))


class DecodeSignedAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
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
        # The batch five-tuple decodes through decode_audit_batch exactly.
        self.assertEqual(
            decoded.batch,
            decode_audit_batch(encode_audit_batch(receipt.batch)),
        )
        # The checkpoint decodes through decode_signed_root exactly.
        self.assertEqual(
            decoded.checkpoint,
            decode_signed_root(encode_signed_root(receipt.checkpoint)),
        )
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(encode_signed_audit_batch(decoded), data)
        self.assertTrue(verify_signed_audit_batch(decoded, self.public_key))
        return decoded

    def test_roundtrip_variants(self):
        self.roundtrip(AuditLog().signed_audit_batch((), _SEED_A, 0))
        for size, indices in (
            (1, [0]),
            (3, [0, 2]),
            (5, [0, 2]),
        ):
            self.roundtrip(self.log.signed_audit_batch(indices, _SEED_A, size))
        self.roundtrip(self.log.signed_audit_batch([0, 2], _SEED_A))

    def test_roundtrip_empty_log(self):
        self.roundtrip(AuditLog().signed_audit_batch((), _SEED_A))

    def test_roundtrip_empty_selection(self):
        self.roundtrip(self.log.signed_audit_batch((), _SEED_A, 4))

    def test_roundtrip_after_prune(self):
        self.log.prune(3, self.log.seal(3))
        self.roundtrip(self.log.signed_audit_batch([3], _SEED_A, 4))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            for record in ("a", "b", "c"):
                log.append(record)
            self.roundtrip(log.signed_audit_batch([0, 2], _SEED_A))

    def test_persistence_across_process_boundary(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1, 3], _SEED_A, 4)
        )
        # A fresh byte sequence (as read back from disk or a socket) decodes
        # into a frozen receipt that still verifies against the pre-trusted key.
        restored = decode_signed_audit_batch(bytes(data))
        self.assertEqual(
            restored, self.log.signed_audit_batch([1, 3], _SEED_A, 4)
        )
        self.assertTrue(verify_signed_audit_batch(restored, self.public_key))
        with self.assertRaises(Exception):
            restored.batch = ()
        with self.assertRaises(Exception):
            restored.checkpoint = None

    def test_only_bytes_accepted(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1], _SEED_A)
        )
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_signed_audit_batch(bad)

    def test_bad_magic(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1], _SEED_A)
        )
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(b"")
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(MAGIC[:-1])
        # The inner magics must not be accepted at the outer layer.
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(
                b"auditchain/batch/v1\0" + data[len(MAGIC):]
            )
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(
                b"auditchain/signed-root/v1\0" + data[len(MAGIC):]
            )

    def test_bad_version(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        data = build(
            2,
            encode_audit_batch(receipt.batch),
            encode_signed_root(receipt.checkpoint),
        )
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(data)

    def test_truncation(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_audit_batch(data[:cut])
        # Every prefix of a valid encoding is truncated, never valid.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_signed_audit_batch(data[:cut])

    def test_trailing_bytes(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        data = encode_signed_audit_batch(receipt)
        for extra in (b"\x00", b"trailing", u64(0)):
            with self.assertRaises(ValueError):
                decode_signed_audit_batch(data + extra)

    def test_oversized_blob_length(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        batch_blob = encode_audit_batch(receipt.batch)
        checkpoint_blob = encode_signed_root(receipt.checkpoint)
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(
                MAGIC + u64(1) + u64(1 << 63) + batch_blob
            )
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(
                MAGIC + u64(1) + blob(batch_blob) + u64(1 << 63)
                + checkpoint_blob
            )

    def test_nested_batch_format_errors_raise_value_error(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        checkpoint_blob = encode_signed_root(receipt.checkpoint)
        # A batch blob whose own magic is wrong is an illegal nested format.
        bad_batch = b"x" + encode_audit_batch(receipt.batch)[1:]
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(build(1, bad_batch, checkpoint_blob))
        # A batch blob with trailing bytes inside its length prefix.
        bad_batch = encode_audit_batch(receipt.batch) + b"\x00"
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(build(1, bad_batch, checkpoint_blob))
        # A batch blob truncated within its own framing.
        bad_batch = encode_audit_batch(receipt.batch)[:-1]
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(build(1, bad_batch, checkpoint_blob))

    def test_nested_checkpoint_format_errors_raise_value_error(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        batch_blob = encode_audit_batch(receipt.batch)
        # A checkpoint blob whose own magic is wrong.
        bad_checkpoint = b"x" + encode_signed_root(receipt.checkpoint)[1:]
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(build(1, batch_blob, bad_checkpoint))
        # A checkpoint blob with trailing bytes inside its length prefix.
        bad_checkpoint = encode_signed_root(receipt.checkpoint) + b"\x00"
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(build(1, batch_blob, bad_checkpoint))
        # A checkpoint blob truncated within its own framing.
        bad_checkpoint = encode_signed_root(receipt.checkpoint)[:-1]
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(build(1, batch_blob, bad_checkpoint))

    def test_swapped_blob_order_rejected(self):
        # Checkpoint bytes where the batch blob is expected fail the batch
        # decoder's magic check.
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        swapped = build(
            1,
            encode_signed_root(receipt.checkpoint),
            encode_audit_batch(receipt.batch),
        )
        with self.assertRaises(ValueError):
            decode_signed_audit_batch(swapped)

    def test_wrong_signature_decodes_but_verifies_false(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        forged_checkpoint = SignedRoot(
            receipt.checkpoint.version,
            receipt.checkpoint.hash_name,
            receipt.checkpoint.size,
            receipt.checkpoint.root,
            receipt.checkpoint.head,
            b"\x00" * 64,
        )
        forged = SignedAuditBatch(receipt.batch, forged_checkpoint)
        data = encode_signed_audit_batch(forged)
        decoded = decode_signed_audit_batch(data)
        self.assertEqual(decoded, forged)
        self.assertEqual(encode_signed_audit_batch(decoded), data)
        self.assertFalse(verify_signed_audit_batch(decoded, self.public_key))

    def test_wrong_key_roundtrip_verifies_false(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1], _SEED_B)
        )
        decoded = decode_signed_audit_batch(data)
        self.assertFalse(verify_signed_audit_batch(decoded, self.public_key))
        self.assertTrue(
            verify_signed_audit_batch(decoded, self.other_public_key)
        )

    def test_mismatched_parts_decode_but_verify_false(self):
        # Structurally legal blobs describing different snapshots: the
        # envelope decoder does no cross-field consistency checking, so this
        # decodes; verify_signed_audit_batch returns False.
        batch = self.log.audit_batch([0, 2], 4)
        checkpoint = self.log.sign_root(_SEED_A, 3)
        bundled = SignedAuditBatch(batch, checkpoint)
        data = encode_signed_audit_batch(bundled)
        decoded = decode_signed_audit_batch(data)
        self.assertEqual(decoded, bundled)
        self.assertFalse(verify_signed_audit_batch(decoded, self.public_key))

    def test_call_is_read_only(self):
        data = encode_signed_audit_batch(
            self.log.signed_audit_batch([1, 3], _SEED_A)
        )
        decode_signed_audit_batch(data)
        self.assertEqual(
            encode_signed_audit_batch(decode_signed_audit_batch(data)), data
        )


if __name__ == "__main__":
    unittest.main()
