import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    PruneReceipt,
    SignedPrune,
    SignedRoot,
    decode_prune_receipt,
    decode_signed_prune,
    decode_signed_root,
    encode_prune_receipt,
    encode_signed_prune,
    encode_signed_root,
    verify_signed_prune,
)

MAGIC = b"auditchain/signed-prune/v1\0"

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


def _split_envelope(data):
    """Split an envelope into (version, receipt_blob, checkpoint_blob)."""
    assert data.startswith(MAGIC)
    offset = len(MAGIC)
    version = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8

    def take():
        nonlocal offset
        length = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        part = data[offset:offset + length]
        offset += length
        return part

    receipt_blob = take()
    checkpoint_blob = take()
    assert offset == len(data)
    return version, receipt_blob, checkpoint_blob


class EncodeSignedPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_exact_field_layout(self):
        item = self.log.sign_prune(_SEED_A, 3)
        data = encode_signed_prune(item)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # receipt blob: u64 length then the complete encode_prune_receipt bytes.
        receipt_bytes = encode_prune_receipt(item.receipt)
        self.assertEqual(data[offset:offset + 8], u64(len(receipt_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(receipt_bytes)], receipt_bytes)
        offset += len(receipt_bytes)
        # checkpoint blob likewise.
        checkpoint_bytes = encode_signed_root(item.checkpoint)
        self.assertEqual(data[offset:offset + 8], u64(len(checkpoint_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(checkpoint_bytes)], checkpoint_bytes)
        offset += len(checkpoint_bytes)
        self.assertEqual(offset, len(data))

    def test_blobs_are_exact_existing_encodings(self):
        item = self.log.sign_prune(_SEED_A, 4)
        version, receipt_blob, checkpoint_blob = _split_envelope(
            encode_signed_prune(item)
        )
        self.assertEqual(version, 1)
        self.assertEqual(receipt_blob, encode_prune_receipt(item.receipt))
        self.assertEqual(checkpoint_blob, encode_signed_root(item.checkpoint))
        self.assertEqual(decode_prune_receipt(receipt_blob), item.receipt)
        self.assertEqual(decode_signed_root(checkpoint_blob), item.checkpoint)

    def test_encode_is_deterministic(self):
        item = self.log.sign_prune(_SEED_A)
        self.assertEqual(encode_signed_prune(item), encode_signed_prune(item))

    def test_no_new_signing_message(self):
        # The checkpoint rides along verbatim; its bytes are exactly
        # sign_root's. Encoding introduces no signature of its own.
        item = self.log.sign_prune(_SEED_A, 4)
        _, _, checkpoint_blob = _split_envelope(encode_signed_prune(item))
        self.assertEqual(
            checkpoint_blob, encode_signed_root(self.log.sign_root(_SEED_A, 4))
        )

    def test_only_signed_prune_accepted(self):
        item = self.log.sign_prune(_SEED_A)
        for bad in (
            None,
            1,
            "item",
            b"bytes",
            (),
            (item.receipt, item.checkpoint),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_prune(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        item = self.log.sign_prune(_SEED_A)
        forged = SignedPrune.__new__(SignedPrune)
        object.__setattr__(forged, "receipt", None)
        object.__setattr__(forged, "checkpoint", item.checkpoint)
        with self.assertRaises(TypeError):
            encode_signed_prune(forged)
        forged = SignedPrune.__new__(SignedPrune)
        object.__setattr__(forged, "receipt", item.receipt)
        object.__setattr__(forged, "checkpoint", "not-a-checkpoint")
        with self.assertRaises(TypeError):
            encode_signed_prune(forged)

    def test_nested_receipt_type_error_propagates(self):
        item = self.log.sign_prune(_SEED_A)
        receipt = PruneReceipt.__new__(PruneReceipt)
        for name in ("hash_name", "size", "merkle_root", "chain_hash"):
            object.__setattr__(receipt, name, getattr(item.receipt, name))
        object.__setattr__(receipt, "hash_name", 123)
        forged = SignedPrune.__new__(SignedPrune)
        object.__setattr__(forged, "receipt", receipt)
        object.__setattr__(forged, "checkpoint", item.checkpoint)
        with self.assertRaises(TypeError):
            encode_signed_prune(forged)

    def test_nested_checkpoint_value_error_propagates(self):
        item = self.log.sign_prune(_SEED_A)
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(
                checkpoint, name, getattr(item.checkpoint, name)
            )
        object.__setattr__(checkpoint, "version", 2)
        forged = SignedPrune.__new__(SignedPrune)
        object.__setattr__(forged, "receipt", item.receipt)
        object.__setattr__(forged, "checkpoint", checkpoint)
        with self.assertRaises(ValueError):
            encode_signed_prune(forged)

    def test_mismatched_pair_still_encodes(self):
        # Linkage between receipt and checkpoint is verification's job: a
        # structurally valid mismatched pair encodes just fine.
        item = self.log.sign_prune(_SEED_A, 3)
        other = self.log.sign_prune(_SEED_A, 2)
        forged = SignedPrune(other.receipt, item.checkpoint)
        data = encode_signed_prune(forged)
        _, receipt_blob, checkpoint_blob = _split_envelope(data)
        self.assertEqual(decode_prune_receipt(receipt_blob), other.receipt)
        self.assertEqual(decode_signed_root(checkpoint_blob), item.checkpoint)
        self.assertFalse(verify_signed_prune(forged, self.public_key))

    def test_call_is_read_only(self):
        item = self.log.sign_prune(_SEED_A, 4)
        before = encode_signed_prune(item)
        encode_signed_prune(item)
        self.assertEqual(encode_signed_prune(item), before)
        self.assertTrue(verify_signed_prune(item, self.public_key))


class DecodeSignedPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, item):
        data = encode_signed_prune(item)
        decoded = decode_signed_prune(data)
        self.assertIsInstance(decoded, SignedPrune)
        self.assertEqual(decoded, item)
        self.assertEqual(decoded.receipt, item.receipt)
        self.assertEqual(decoded.checkpoint, item.checkpoint)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(encode_signed_prune(decoded), data)
        self.assertTrue(verify_signed_prune(decoded, self.public_key))
        return decoded

    def test_roundtrip_variants(self):
        for size in (None, 0, 1, 3, 7):
            self.roundtrip(self.log.sign_prune(_SEED_A, size))

    def test_roundtrip_empty_log(self):
        self.roundtrip(AuditLog().sign_prune(_SEED_A))

    def test_roundtrip_after_prune(self):
        twin = AuditLog()
        for i in range(6):
            record = f"r{i}"
            self.log.append(record)
            twin.append(record)
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.sign_prune(_SEED_A, 4))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            for record in ("a", "b", "c", "d"):
                log.append(record)
            self.roundtrip(log.sign_prune(_SEED_A, 4))

    def test_frozen(self):
        data = encode_signed_prune(self.log.sign_prune(_SEED_A))
        decoded = decode_signed_prune(data)
        with self.assertRaises(FrozenInstanceError):
            decoded.receipt = decoded.receipt
        with self.assertRaises(FrozenInstanceError):
            decoded.checkpoint = decoded.checkpoint

    def test_persistence_across_process_boundary(self):
        item = self.log.sign_prune(_SEED_A, 6)
        data = encode_signed_prune(item)
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_signed_prune(bytes(data))
        self.assertEqual(restored, item)
        self.assertTrue(verify_signed_prune(restored, self.public_key))

    def test_only_bytes_accepted(self):
        data = encode_signed_prune(self.log.sign_prune(_SEED_A))
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
                decode_signed_prune(bad)

    def test_bad_magic(self):
        data = encode_signed_prune(self.log.sign_prune(_SEED_A))
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/signed-root/v1\0" + data[len(MAGIC):],
            b"auditchain/prune-receipt/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:32])):
                decode_signed_prune(bad)

    def test_bad_version(self):
        item = self.log.sign_prune(_SEED_A)
        data = encode_signed_prune(item)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_prune(bad)

    def test_truncation(self):
        data = encode_signed_prune(self.log.sign_prune(_SEED_A))
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_prune(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_prune(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_prune(self.log.sign_prune(_SEED_A))
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_prune(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_prune(bad)

    def test_missing_checkpoint_blob(self):
        item = self.log.sign_prune(_SEED_A)
        _, receipt_blob, _ = _split_envelope(encode_signed_prune(item))
        with self.assertRaises(ValueError):
            decode_signed_prune(MAGIC + u64(1) + blob(receipt_blob))

    def test_swapped_blob_order(self):
        item = self.log.sign_prune(_SEED_A, 6)
        other = self.log.sign_prune(_SEED_A, 3)
        _, receipt_blob, _ = _split_envelope(encode_signed_prune(item))
        _, other_receipt_blob, checkpoint_blob = _split_envelope(
            encode_signed_prune(other)
        )
        swapped = (
            MAGIC
            + u64(1)
            + blob(other_receipt_blob)
            + blob(checkpoint_blob)
        )
        # Swapped blobs decode positionally: the receipt is the other one.
        decoded = decode_signed_prune(swapped)
        self.assertNotEqual(decoded, item)
        self.assertEqual(decoded.checkpoint, other.checkpoint)
        self.assertEqual(decoded.receipt, other.receipt)
        # A checkpoint blob placed where the receipt blob must be is rejected
        # by the nested prune-receipt decoder.
        evil = MAGIC + u64(1) + blob(checkpoint_blob) + blob(receipt_blob)
        with self.assertRaises(ValueError):
            decode_signed_prune(evil)

    def test_garbage_receipt_blob_rejected(self):
        item = self.log.sign_prune(_SEED_A)
        _, _, checkpoint_blob = _split_envelope(encode_signed_prune(item))
        with self.assertRaises(ValueError):
            decode_signed_prune(
                MAGIC + u64(1) + blob(b"hello") + blob(checkpoint_blob)
            )

    def test_garbage_checkpoint_blob_rejected(self):
        item = self.log.sign_prune(_SEED_A)
        _, receipt_blob, _ = _split_envelope(encode_signed_prune(item))
        with self.assertRaises(ValueError):
            decode_signed_prune(
                MAGIC + u64(1) + blob(receipt_blob) + blob(b"hello")
            )

    def test_nested_framing_error_rejected(self):
        item = self.log.sign_prune(_SEED_A)
        _, receipt_blob, checkpoint_blob = _split_envelope(
            encode_signed_prune(item)
        )
        tampered = b"x" + receipt_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_prune(
                MAGIC + u64(1) + blob(tampered) + blob(checkpoint_blob)
            )

    def test_pair_linkage_not_validated_on_decode(self):
        # The receipt and checkpoint need not describe the same prefix: that
        # is verify_signed_prune's job. A genuine size-2 receipt paired with
        # a genuine size-3 checkpoint decodes but never verifies.
        item = self.log.sign_prune(_SEED_A, 3)
        other = self.log.sign_prune(_SEED_A, 2)
        forged = SignedPrune(other.receipt, item.checkpoint)
        decoded = decode_signed_prune(encode_signed_prune(forged))
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_signed_prune(decoded, self.public_key))

    def test_bad_signature_still_decodes_but_verifies_false(self):
        item = self.log.sign_prune(_SEED_A)
        checkpoint = item.checkpoint
        bogus = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = SignedPrune(item.receipt, bogus)
        decoded = decode_signed_prune(encode_signed_prune(forged))
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_signed_prune(decoded, self.public_key))

    def test_wrong_key_decodes_but_verifies_false(self):
        item = self.log.sign_prune(_SEED_B)
        decoded = decode_signed_prune(encode_signed_prune(item))
        self.assertFalse(verify_signed_prune(decoded, self.public_key))
        self.assertTrue(
            verify_signed_prune(decoded, self.other_public_key)
        )

    def test_call_is_read_only(self):
        item = self.log.sign_prune(_SEED_A, 6)
        data = encode_signed_prune(item)
        decode_signed_prune(data)
        self.assertEqual(decode_signed_prune(data), item)


if __name__ == "__main__":
    unittest.main()
