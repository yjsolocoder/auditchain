import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SearchReceipt,
    SignedRoot,
    SignedSearchReceipt,
    decode_search_receipt,
    decode_signed_root,
    decode_signed_search_receipt,
    encode_search_receipt,
    encode_signed_root,
    encode_signed_search_receipt,
    verify_signed_search_receipt,
)

MAGIC = b"auditchain/signed-search-receipt/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))

RECORDS = ("a", "b", "a", "c", "a", "b", "a")


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


def make_log(records=RECORDS, **kwargs):
    log = AuditLog(**kwargs)
    for record in records:
        log.append(record)
    return log


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


class EncodeSignedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1, as a single u64: U(1).
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # receipt blob: u64 length then the complete encode_search_receipt
        # bytes: B(R).
        receipt_bytes = encode_search_receipt(package.receipt)
        self.assertEqual(data[offset:offset + 8], u64(len(receipt_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(receipt_bytes)], receipt_bytes)
        offset += len(receipt_bytes)
        # checkpoint blob: u64 length then encode_signed_root bytes: B(C).
        checkpoint_bytes = encode_signed_root(package.checkpoint)
        self.assertEqual(data[offset:offset + 8], u64(len(checkpoint_bytes)))
        offset += 8
        self.assertEqual(
            data[offset:offset + len(checkpoint_bytes)], checkpoint_bytes
        )
        offset += len(checkpoint_bytes)
        self.assertEqual(offset, len(data))

    def test_layout_is_u1_br_bc(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        receipt_bytes = encode_search_receipt(package.receipt)
        checkpoint_bytes = encode_signed_root(package.checkpoint)
        self.assertEqual(
            encode_signed_search_receipt(package),
            MAGIC
            + u64(1)
            + blob(receipt_bytes)
            + blob(checkpoint_bytes),
        )

    def test_magic_includes_nul_terminator(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        self.assertEqual(data[: len(MAGIC)], MAGIC)
        self.assertEqual(data[len(MAGIC) - 1], 0)

    def test_blobs_are_exact_existing_encodings(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        _, receipt_blob, checkpoint_blob = _parse_blobs(
            encode_signed_search_receipt(package)
        )
        self.assertEqual(receipt_blob, encode_search_receipt(package.receipt))
        self.assertEqual(
            checkpoint_blob, encode_signed_root(package.checkpoint)
        )
        # The inner blobs are independently decodable by the existing codecs.
        self.assertEqual(decode_search_receipt(receipt_blob), package.receipt)
        self.assertEqual(
            decode_signed_root(checkpoint_blob), package.checkpoint
        )

    def test_encode_is_deterministic(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        self.assertEqual(
            encode_signed_search_receipt(package),
            encode_signed_search_receipt(package),
        )

    def test_no_new_signing_message(self):
        # The checkpoint rides along verbatim; its bytes are exactly
        # sign_root's. Encoding introduces no signature of its own.
        package = self.log.signed_search_receipt("a", _SEED_A, size=4)
        _, _, checkpoint_blob = _parse_blobs(
            encode_signed_search_receipt(package)
        )
        self.assertEqual(
            checkpoint_blob,
            encode_signed_root(self.log.sign_root(_SEED_A, 4)),
        )

    def test_only_signed_search_receipt_accepted(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        for bad in (
            None,
            1,
            "receipt",
            b"bytes",
            (),
            package.receipt,
            (package.receipt, package.checkpoint),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_search_receipt(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        for field, value in (
            ("receipt", ["not-a-receipt"]),
            ("receipt", None),
            ("checkpoint", None),
            ("checkpoint", package.receipt),
        ):
            forged = SignedSearchReceipt.__new__(SignedSearchReceipt)
            object.__setattr__(
                forged,
                "receipt",
                package.receipt if field == "checkpoint" else value,
            )
            object.__setattr__(
                forged,
                "checkpoint",
                package.checkpoint if field == "receipt" else value,
            )
            with self.assertRaises(TypeError, msg=field):
                encode_signed_search_receipt(forged)

    def test_bypassed_mismatched_snapshots_raise_value_error(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        other_checkpoint = self.log.sign_root(_SEED_A, 3)
        forged = SignedSearchReceipt.__new__(SignedSearchReceipt)
        object.__setattr__(forged, "receipt", package.receipt)
        object.__setattr__(forged, "checkpoint", other_checkpoint)
        with self.assertRaises(ValueError):
            encode_signed_search_receipt(forged)

    def test_nested_receipt_type_error_propagates(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        forged_receipt = SearchReceipt.__new__(SearchReceipt)
        for name in (
            "version", "hash_name", "size", "root", "query",
            "start", "stop", "items",
        ):
            object.__setattr__(
                forged_receipt, name, getattr(package.receipt, name)
            )
        object.__setattr__(forged_receipt, "query", 123)
        forged = SignedSearchReceipt.__new__(SignedSearchReceipt)
        object.__setattr__(forged, "receipt", forged_receipt)
        object.__setattr__(forged, "checkpoint", package.checkpoint)
        with self.assertRaises(TypeError):
            encode_signed_search_receipt(forged)

    def test_nested_checkpoint_type_error_propagates(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(
                checkpoint, name, getattr(package.checkpoint, name)
            )
        object.__setattr__(checkpoint, "version", "1")
        forged = SignedSearchReceipt.__new__(SignedSearchReceipt)
        object.__setattr__(forged, "receipt", package.receipt)
        object.__setattr__(forged, "checkpoint", checkpoint)
        with self.assertRaises(TypeError):
            encode_signed_search_receipt(forged)

    def test_call_is_read_only(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        before = encode_signed_search_receipt(package)
        encode_signed_search_receipt(package)
        self.assertEqual(encode_signed_search_receipt(package), before)
        self.assertTrue(
            verify_signed_search_receipt(package, self.public_key)
        )


class DecodeSignedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, package, *, verify=True):
        data = encode_signed_search_receipt(package)
        decoded = decode_signed_search_receipt(data)
        self.assertIsInstance(decoded, SignedSearchReceipt)
        self.assertEqual(decoded, package)
        self.assertEqual(decoded.receipt, package.receipt)
        self.assertEqual(decoded.checkpoint, package.checkpoint)
        self.assertIs(type(decoded.receipt), SearchReceipt)
        self.assertIs(type(decoded.checkpoint), SignedRoot)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(encode_signed_search_receipt(decoded), data)
        if verify:
            self.assertTrue(
                verify_signed_search_receipt(decoded, self.public_key)
            )
        return decoded

    def test_roundtrip_variants(self):
        for query, start, stop, size in (
            ("a", None, None, None),
            ("missing", None, None, None),
            ("a", 1, 4, 4),
            ("a", 0, 3, 3),
            ("a", 2, 2, 5),
            ("a", None, None, 0),
        ):
            self.roundtrip(
                self.log.signed_search_receipt(
                    query, _SEED_A, start, stop, size=size
                )
            )

    def test_roundtrip_empty_log(self):
        self.roundtrip(AuditLog().signed_search_receipt("a", _SEED_A))

    def test_roundtrip_after_prune(self):
        log = make_log()
        log.prune(2, log.seal(2))
        self.roundtrip(log.signed_search_receipt("a", _SEED_A))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            log = make_log(hash_name=hash_name)
            self.roundtrip(log.signed_search_receipt("a", _SEED_A))

    def test_frozen(self):
        data = encode_signed_search_receipt(
            self.log.signed_search_receipt("a", _SEED_A)
        )
        decoded = decode_signed_search_receipt(data)
        with self.assertRaises(FrozenInstanceError):
            decoded.receipt = decoded.receipt
        with self.assertRaises(FrozenInstanceError):
            decoded.checkpoint = decoded.checkpoint

    def test_persistence_across_process_boundary(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_signed_search_receipt(bytes(data))
        self.assertEqual(restored, package)
        self.assertTrue(
            verify_signed_search_receipt(restored, self.public_key)
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_search_receipt(
            self.log.signed_search_receipt("a", _SEED_A)
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
                decode_signed_search_receipt(bad)

    def test_bad_magic(self):
        data = encode_signed_search_receipt(
            self.log.signed_search_receipt("a", _SEED_A)
        )
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/signed-root/v1\0" + data[len(MAGIC):],
            b"auditchain/search-receipt/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-audit-receipt/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:32])):
                decode_signed_search_receipt(bad)

    def test_bad_version(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_search_receipt(bad)

    def test_truncation(self):
        data = encode_signed_search_receipt(
            self.log.signed_search_receipt("a", _SEED_A)
        )
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_search_receipt(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_search_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_search_receipt(
            self.log.signed_search_receipt("a", _SEED_A)
        )
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_search_receipt(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_search_receipt(bad)

    def test_missing_second_blob(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        _, receipt_blob, _ = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_search_receipt(
                MAGIC + u64(1) + blob(receipt_blob)
            )

    def test_swapped_blob_order_rejected(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        swapped = (
            MAGIC
            + u64(1)
            + blob(checkpoint_blob)
            + blob(receipt_blob)
        )
        with self.assertRaises(ValueError):
            decode_signed_search_receipt(swapped)

    def test_garbage_receipt_blob_rejected(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        _, _, checkpoint_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_search_receipt(
                MAGIC + u64(1) + blob(b"hello") + blob(checkpoint_blob)
            )

    def test_trailing_bytes_inside_blob_rejected(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_search_receipt(
                MAGIC
                + u64(1)
                + blob(receipt_blob + b"\x00")
                + blob(checkpoint_blob)
            )

    def test_nested_receipt_framing_error_rejected(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        tampered = b"x" + receipt_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_search_receipt(
                MAGIC + u64(1) + blob(tampered) + blob(checkpoint_blob)
            )

    def test_nested_checkpoint_framing_error_rejected(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        tampered = b"x" + checkpoint_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_search_receipt(
                MAGIC + u64(1) + blob(receipt_blob) + blob(tampered)
            )

    def _bypass(self, package, *, receipt=None, checkpoint=None):
        forged = SignedSearchReceipt.__new__(SignedSearchReceipt)
        object.__setattr__(
            forged,
            "receipt",
            package.receipt if receipt is None else receipt,
        )
        object.__setattr__(
            forged,
            "checkpoint",
            package.checkpoint if checkpoint is None else checkpoint,
        )
        return forged

    def test_nested_snapshot_mismatch_rejected(self):
        # Both nested encodings are individually well-formed, but they
        # describe different snapshots: the envelope decoder rejects the pair.
        package = self.log.signed_search_receipt("a", _SEED_A)
        other = self.log.signed_search_receipt("a", _SEED_A, size=4)
        forged = self._bypass(package, checkpoint=other.checkpoint)
        # The encoder rejects the mismatched pair, so assemble its bytes
        # directly from the two valid nested encodings.
        framed = (
            MAGIC
            + u64(1)
            + blob(encode_search_receipt(forged.receipt))
            + blob(encode_signed_root(forged.checkpoint))
        )
        with self.assertRaises(ValueError):
            decode_signed_search_receipt(framed)

    def test_bad_signature_still_decodes_but_verifies_false(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        checkpoint = package.checkpoint
        bogus = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = SignedSearchReceipt(package.receipt, bogus)
        decoded = decode_signed_search_receipt(
            encode_signed_search_receipt(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_search_receipt(decoded, self.public_key)
        )

    def test_wrong_key_decodes_but_verifies_false(self):
        package = self.log.signed_search_receipt("a", _SEED_B)
        decoded = decode_signed_search_receipt(
            encode_signed_search_receipt(package)
        )
        self.assertFalse(
            verify_signed_search_receipt(decoded, self.public_key)
        )
        self.assertTrue(
            verify_signed_search_receipt(decoded, self.other_public_key)
        )

    def test_verdict_is_preserved_across_roundtrip(self):
        # Whatever the pre-roundtrip verdict is, the restored package gives
        # the same verdict for the trusted and the untrusted key.
        for seed, key in (
            (_SEED_A, self.public_key),
            (_SEED_B, self.public_key),
        ):
            package = self.log.signed_search_receipt("a", seed)
            before = verify_signed_search_receipt(package, key)
            restored = decode_signed_search_receipt(
                encode_signed_search_receipt(package)
            )
            self.assertEqual(
                verify_signed_search_receipt(restored, key), before
            )

    def test_call_is_read_only(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        data = encode_signed_search_receipt(package)
        decode_signed_search_receipt(data)
        self.assertEqual(
            decode_signed_search_receipt(data), package
        )


if __name__ == "__main__":
    unittest.main()
