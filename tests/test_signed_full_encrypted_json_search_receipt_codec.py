import json
import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    FullEncryptedJsonSearchReceipt,
    SignedFullEncryptedJsonSearchReceipt,
    SignedRoot,
    decode_full_encrypted_json_search_receipt,
    decode_signed_full_encrypted_json_search_receipt,
    decode_signed_root,
    encode_full_encrypted_json_search_receipt,
    encode_signed_full_encrypted_json_search_receipt,
    encode_signed_root,
    verify_signed_full_encrypted_json_search_receipt,
)

MAGIC = b"auditchain/signed-full-encrypted-json-search/v1\0"

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


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


def make_log():
    log = AuditLog()
    log.encrypt(j({"a": 1, "b": "x"}), KEY, nonce=b"0" * 12)
    log.encrypt(j({"a": 1.0, "b": "y"}), KEY, nonce=b"1" * 12)
    log.encrypt(j({"a": "1"}), KEY, nonce=b"2" * 12)
    log.encrypt(j({"a": True}), KEY, nonce=b"3" * 12)
    log.encrypt(j({"a": [1]}), KEY, nonce=b"4" * 12)
    log.append(j({"a": 1}))
    log.encrypt(j({"a": 1}), OTHER_KEY, nonce=b"6" * 12)
    log.encrypt(b"{not json", KEY, nonce=b"7" * 12)
    log.encrypt(b'{"a": 1, "a": 2}', KEY, nonce=b"8" * 12)
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


class EncodeSignedFullEncryptedJsonSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1, as a single u64: U(1).
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # receipt blob: u64 length then the complete
        # encode_full_encrypted_json_search_receipt bytes: B(R).
        receipt_bytes = encode_full_encrypted_json_search_receipt(
            bundle.receipt
        )
        self.assertEqual(data[offset:offset + 8], u64(len(receipt_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(receipt_bytes)], receipt_bytes)
        offset += len(receipt_bytes)
        # checkpoint blob: u64 length then encode_signed_root bytes: B(C).
        checkpoint_bytes = encode_signed_root(bundle.checkpoint)
        self.assertEqual(data[offset:offset + 8], u64(len(checkpoint_bytes)))
        offset += 8
        self.assertEqual(
            data[offset:offset + len(checkpoint_bytes)], checkpoint_bytes
        )
        offset += len(checkpoint_bytes)
        self.assertEqual(offset, len(data))

    def test_layout_is_u1_br_bc(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        receipt_bytes = encode_full_encrypted_json_search_receipt(
            bundle.receipt
        )
        checkpoint_bytes = encode_signed_root(bundle.checkpoint)
        self.assertEqual(
            encode_signed_full_encrypted_json_search_receipt(bundle),
            MAGIC
            + u64(1)
            + blob(receipt_bytes)
            + blob(checkpoint_bytes),
        )

    def test_blobs_are_exact_existing_encodings(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        _, receipt_blob, checkpoint_blob = _parse_blobs(
            encode_signed_full_encrypted_json_search_receipt(bundle)
        )
        self.assertEqual(
            receipt_blob,
            encode_full_encrypted_json_search_receipt(bundle.receipt),
        )
        self.assertEqual(
            checkpoint_blob, encode_signed_root(bundle.checkpoint)
        )
        # The inner blobs are independently decodable by the existing codecs.
        self.assertEqual(
            decode_full_encrypted_json_search_receipt(receipt_blob),
            bundle.receipt,
        )
        self.assertEqual(
            decode_signed_root(checkpoint_blob), bundle.checkpoint
        )

    def test_encode_is_deterministic(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        self.assertEqual(
            encode_signed_full_encrypted_json_search_receipt(bundle),
            encode_signed_full_encrypted_json_search_receipt(bundle),
        )

    def test_no_new_signing_message(self):
        # The checkpoint rides along verbatim; its bytes are exactly
        # sign_root's. Encoding introduces no signature of its own.
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, size=4
        )
        _, _, checkpoint_blob = _parse_blobs(
            encode_signed_full_encrypted_json_search_receipt(bundle)
        )
        self.assertEqual(
            checkpoint_blob,
            encode_signed_root(self.log.sign_root(_SEED_A, 4)),
        )

    def test_only_signed_full_encrypted_json_search_receipt_accepted(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
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
                encode_signed_full_encrypted_json_search_receipt(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        for field, value in (
            ("receipt", ["not-a-receipt"]),
            ("receipt", None),
            ("checkpoint", None),
            ("checkpoint", bundle.receipt),
        ):
            forged = SignedFullEncryptedJsonSearchReceipt.__new__(
                SignedFullEncryptedJsonSearchReceipt
            )
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
                encode_signed_full_encrypted_json_search_receipt(forged)

    def test_bypassed_mismatched_snapshots_raise_value_error(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        other_checkpoint = self.log.sign_root(_SEED_A, 3)
        forged = SignedFullEncryptedJsonSearchReceipt.__new__(
            SignedFullEncryptedJsonSearchReceipt
        )
        object.__setattr__(forged, "receipt", bundle.receipt)
        object.__setattr__(forged, "checkpoint", other_checkpoint)
        with self.assertRaises(ValueError):
            encode_signed_full_encrypted_json_search_receipt(forged)

    def test_nested_receipt_type_error_propagates(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        forged_receipt = FullEncryptedJsonSearchReceipt.__new__(
            FullEncryptedJsonSearchReceipt
        )
        for name in (
            "version", "hash_name", "size", "root", "pointer", "value",
            "start", "stop", "items", "proof", "hits", "confirmation",
        ):
            object.__setattr__(
                forged_receipt, name, getattr(bundle.receipt, name)
            )
        object.__setattr__(forged_receipt, "version", "1")
        forged = SignedFullEncryptedJsonSearchReceipt.__new__(
            SignedFullEncryptedJsonSearchReceipt
        )
        object.__setattr__(forged, "receipt", forged_receipt)
        object.__setattr__(forged, "checkpoint", bundle.checkpoint)
        with self.assertRaises(TypeError):
            encode_signed_full_encrypted_json_search_receipt(forged)

    def test_nested_checkpoint_type_error_propagates(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(
                checkpoint, name, getattr(bundle.checkpoint, name)
            )
        object.__setattr__(checkpoint, "version", "1")
        forged = SignedFullEncryptedJsonSearchReceipt.__new__(
            SignedFullEncryptedJsonSearchReceipt
        )
        object.__setattr__(forged, "receipt", bundle.receipt)
        object.__setattr__(forged, "checkpoint", checkpoint)
        with self.assertRaises(TypeError):
            encode_signed_full_encrypted_json_search_receipt(forged)

    def test_nested_receipt_value_error_propagates(self):
        # A bypassed nested receipt with a wrong proof-node count must be
        # re-checked even though the container itself looks fine. A
        # sub-range receipt carries a non-empty shared proof; dropping it
        # violates the node-count rule.
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, 1, 7, size=7
        )
        self.assertTrue(bundle.receipt.proof)
        forged_receipt = FullEncryptedJsonSearchReceipt.__new__(
            FullEncryptedJsonSearchReceipt
        )
        for name in (
            "version", "hash_name", "size", "root", "pointer", "value",
            "start", "stop", "items", "proof", "hits", "confirmation",
        ):
            object.__setattr__(
                forged_receipt, name, getattr(bundle.receipt, name)
            )
        object.__setattr__(forged_receipt, "proof", ())
        forged = SignedFullEncryptedJsonSearchReceipt.__new__(
            SignedFullEncryptedJsonSearchReceipt
        )
        object.__setattr__(forged, "receipt", forged_receipt)
        object.__setattr__(forged, "checkpoint", bundle.checkpoint)
        with self.assertRaises(ValueError):
            encode_signed_full_encrypted_json_search_receipt(forged)

    def test_call_is_read_only(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        before = encode_signed_full_encrypted_json_search_receipt(bundle)
        encode_signed_full_encrypted_json_search_receipt(bundle)
        self.assertEqual(
            encode_signed_full_encrypted_json_search_receipt(bundle), before
        )
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                bundle, KEY, self.public_key
            )
        )


class DecodeSignedFullEncryptedJsonSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, bundle, key=KEY):
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        decoded = decode_signed_full_encrypted_json_search_receipt(data)
        self.assertIsInstance(
            decoded, SignedFullEncryptedJsonSearchReceipt
        )
        self.assertEqual(decoded, bundle)
        self.assertEqual(decoded.receipt, bundle.receipt)
        self.assertEqual(decoded.checkpoint, bundle.checkpoint)
        self.assertIs(type(decoded.receipt), FullEncryptedJsonSearchReceipt)
        self.assertIs(type(decoded.checkpoint), SignedRoot)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(
            encode_signed_full_encrypted_json_search_receipt(decoded), data
        )
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                decoded, key, self.public_key
            )
        )
        return decoded

    def test_roundtrip_variants(self):
        for pointer, value, start, stop, size in (
            ("/a", 1, None, None, None),
            ("/a", 1.0, None, None, None),
            ("/a", "1", None, None, None),
            ("/a", True, None, None, None),
            ("/a", None, None, None, None),
            ("/b", "x", None, None, None),
            ("/a", 1, 1, 7, 7),
            ("/a", 1, None, None, 4),
            ("/a", 42, None, None, None),
            ("/a", 1, 2, 2, None),
        ):
            self.roundtrip(
                self.log.signed_full_encrypted_json_search_receipt(
                    pointer, value, KEY, _SEED_A, start, stop, size
                )
            )

    def test_roundtrip_empty_snapshot(self):
        # Empty snapshot: canonical root, zero head, empty proof still
        # rebuilds and round-trips.
        self.roundtrip(
            AuditLog().signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A
            )
        )

    def test_roundtrip_empty_range(self):
        self.roundtrip(
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A, 2, 2
            )
        )

    def test_roundtrip_zero_hits(self):
        self.roundtrip(
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 42, KEY, _SEED_A
            )
        )

    def test_roundtrip_historical_snapshot(self):
        # A still-rebuildable historical snapshot (size smaller than the
        # current log length, range inside the retained segment).
        self.roundtrip(
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A, 0, 4, size=4
            )
        )

    def test_roundtrip_after_prune(self):
        twin = AuditLog()
        for index in range(6):
            payload = j({"a": index})
            nonce = bytes([index]) * 12
            self.log.encrypt(payload, KEY, nonce=nonce)
            twin.encrypt(payload, KEY, nonce=nonce)
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 4, KEY, _SEED_A
            )
        )

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            log.encrypt(j({"a": 1}), KEY, nonce=b"0" * 12)
            log.encrypt(j({"a": 2}), KEY, nonce=b"1" * 12)
            self.roundtrip(
                log.signed_full_encrypted_json_search_receipt(
                    "/a", 1, KEY, _SEED_A
                )
            )

    def test_frozen(self):
        data = encode_signed_full_encrypted_json_search_receipt(
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A
            )
        )
        decoded = decode_signed_full_encrypted_json_search_receipt(data)
        with self.assertRaises(FrozenInstanceError):
            decoded.receipt = decoded.receipt
        with self.assertRaises(FrozenInstanceError):
            decoded.checkpoint = decoded.checkpoint

    def test_persistence_across_process_boundary(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_signed_full_encrypted_json_search_receipt(bytes(data))
        self.assertEqual(restored, bundle)
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                restored, KEY, self.public_key
            )
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_full_encrypted_json_search_receipt(
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A
            )
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
                decode_signed_full_encrypted_json_search_receipt(bad)

    def test_bad_magic(self):
        data = encode_signed_full_encrypted_json_search_receipt(
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A
            )
        )
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/signed-root/v1\0" + data[len(MAGIC):],
            b"auditchain/full-encrypted-json-search/v1\0"
            + data[len(MAGIC):],
            b"auditchain/signed-full-encrypted-search/v1\0"
            + data[len(MAGIC):],
            b"auditchain/signed-full-search/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:40])):
                decode_signed_full_encrypted_json_search_receipt(bad)

    def test_bad_version(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_full_encrypted_json_search_receipt(bad)

    def test_truncation(self):
        data = encode_signed_full_encrypted_json_search_receipt(
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A
            )
        )
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_full_encrypted_json_search_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_full_encrypted_json_search_receipt(
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A
            )
        )
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_full_encrypted_json_search_receipt(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_full_encrypted_json_search_receipt(bad)

    def test_missing_second_blob(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        _, receipt_blob, _ = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_full_encrypted_json_search_receipt(
                MAGIC + u64(1) + blob(receipt_blob)
            )

    def test_swapped_blob_order_rejected(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        swapped = (
            MAGIC
            + u64(1)
            + blob(checkpoint_blob)
            + blob(receipt_blob)
        )
        with self.assertRaises(ValueError):
            decode_signed_full_encrypted_json_search_receipt(swapped)

    def test_garbage_receipt_blob_rejected(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        _, _, checkpoint_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_full_encrypted_json_search_receipt(
                MAGIC + u64(1) + blob(b"hello") + blob(checkpoint_blob)
            )

    def test_trailing_bytes_inside_blob_rejected(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_full_encrypted_json_search_receipt(
                MAGIC
                + u64(1)
                + blob(receipt_blob + b"\x00")
                + blob(checkpoint_blob)
            )

    def test_nested_receipt_framing_error_rejected(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        tampered = b"x" + receipt_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_full_encrypted_json_search_receipt(
                MAGIC + u64(1) + blob(tampered) + blob(checkpoint_blob)
            )

    def test_nested_checkpoint_framing_error_rejected(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        _, receipt_blob, checkpoint_blob = _parse_blobs(data)
        tampered = b"x" + checkpoint_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_full_encrypted_json_search_receipt(
                MAGIC + u64(1) + blob(receipt_blob) + blob(tampered)
            )

    def _bypass(self, bundle, *, receipt=None, checkpoint=None):
        forged = SignedFullEncryptedJsonSearchReceipt.__new__(
            SignedFullEncryptedJsonSearchReceipt
        )
        object.__setattr__(
            forged,
            "receipt",
            bundle.receipt if receipt is None else receipt,
        )
        object.__setattr__(
            forged,
            "checkpoint",
            bundle.checkpoint if checkpoint is None else checkpoint,
        )
        return forged

    def test_nested_snapshot_mismatch_rejected(self):
        # Both nested encodings are individually well-formed, but they
        # describe different snapshots: the envelope decoder rejects the pair.
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        other = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, size=4
        )
        forged = self._bypass(bundle, checkpoint=other.checkpoint)
        # The encoder rejects the mismatched pair, so assemble its bytes
        # directly from the two valid nested encodings.
        framed = (
            MAGIC
            + u64(1)
            + blob(
                encode_full_encrypted_json_search_receipt(forged.receipt)
            )
            + blob(encode_signed_root(forged.checkpoint))
        )
        with self.assertRaises(ValueError):
            decode_signed_full_encrypted_json_search_receipt(framed)

    def test_nested_snapshot_hash_name_mismatch_rejected(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        other_log = AuditLog(hash_name="sha512")
        other_log.encrypt(j({"a": 1}), KEY, nonce=b"0" * 12)
        other_checkpoint = other_log.sign_root(_SEED_A)
        forged = self._bypass(bundle, checkpoint=other_checkpoint)
        framed = (
            MAGIC
            + u64(1)
            + blob(
                encode_full_encrypted_json_search_receipt(forged.receipt)
            )
            + blob(encode_signed_root(forged.checkpoint))
        )
        with self.assertRaises(ValueError):
            decode_signed_full_encrypted_json_search_receipt(framed)

    def test_bad_signature_still_decodes_but_verifies_false(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        checkpoint = bundle.checkpoint
        bogus = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = SignedFullEncryptedJsonSearchReceipt(
            bundle.receipt, bogus
        )
        decoded = decode_signed_full_encrypted_json_search_receipt(
            encode_signed_full_encrypted_json_search_receipt(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                decoded, KEY, self.public_key
            )
        )

    def test_wrong_key_signature_still_roundtrips_but_verifies_false(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_B
        )
        decoded = decode_signed_full_encrypted_json_search_receipt(
            encode_signed_full_encrypted_json_search_receipt(bundle)
        )
        self.assertEqual(decoded, bundle)
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                decoded, KEY, self.public_key
            )
        )
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                decoded, KEY, self.other_public_key
            )
        )

    def test_wrong_query_key_still_roundtrips_but_verifies_false(self):
        # A wrong but length-valid 32-byte query key: the encoding neither
        # sees nor needs the key, and the existing verifier reports False.
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        decoded = decode_signed_full_encrypted_json_search_receipt(
            encode_signed_full_encrypted_json_search_receipt(bundle)
        )
        self.assertEqual(decoded, bundle)
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                decoded, bytes(range(1, 33)), self.public_key
            )
        )

    def test_wrong_query_key_zero_hits_still_returns_false(self):
        # Even with an empty recorded hit set the confirmation cannot be
        # reproduced with a wrong (but length-valid) query key.
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 42, KEY, _SEED_A
        )
        self.assertEqual(bundle.receipt.hits, ())
        decoded = decode_signed_full_encrypted_json_search_receipt(
            encode_signed_full_encrypted_json_search_receipt(bundle)
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                decoded, bytes(range(1, 33)), self.public_key
            )
        )

    def _rebuild_receipt(self, receipt, **overrides):
        fields = dict(
            version=receipt.version,
            hash_name=receipt.hash_name,
            size=receipt.size,
            root=receipt.root,
            pointer=receipt.pointer,
            value=receipt.value,
            start=receipt.start,
            stop=receipt.stop,
            items=receipt.items,
            proof=receipt.proof,
            hits=receipt.hits,
            confirmation=receipt.confirmation,
        )
        fields.update(overrides)
        return FullEncryptedJsonSearchReceipt(**fields)

    def _roundtrip_forged(self, forged):
        decoded = decode_signed_full_encrypted_json_search_receipt(
            encode_signed_full_encrypted_json_search_receipt(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                decoded, KEY, self.public_key
            )
        )
        return decoded

    def test_concealed_hits_roundtrip_but_verify_false(self):
        # Structurally valid (ascending hits) but the recorded hit set is
        # incomplete: it round-trips and verifies False, never raising.
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        trimmed = self._rebuild_receipt(bundle.receipt, hits=(0,))
        self._roundtrip_forged(
            SignedFullEncryptedJsonSearchReceipt(trimmed, bundle.checkpoint)
        )

    def test_tampered_confirmation_roundtrip_but_verify_false(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        width = len(bundle.receipt.confirmation)
        flipped = bytes([bundle.receipt.confirmation[0] ^ 0x01]) + (
            bundle.receipt.confirmation[1:]
        )
        self.assertEqual(len(flipped), width)
        tampered = self._rebuild_receipt(bundle.receipt, confirmation=flipped)
        self._roundtrip_forged(
            SignedFullEncryptedJsonSearchReceipt(tampered, bundle.checkpoint)
        )

    def test_tampered_pointer_roundtrip_but_verify_false(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        tampered = self._rebuild_receipt(bundle.receipt, pointer="/b")
        self._roundtrip_forged(
            SignedFullEncryptedJsonSearchReceipt(tampered, bundle.checkpoint)
        )

    def test_tampered_query_value_roundtrip_but_verify_false(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        tampered = self._rebuild_receipt(bundle.receipt, value=2)
        self._roundtrip_forged(
            SignedFullEncryptedJsonSearchReceipt(tampered, bundle.checkpoint)
        )

    def test_tampered_ciphertext_roundtrip_but_verify_false(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        items = list(bundle.receipt.items)
        entry = items[0]
        payload = entry.payload
        tampered_entry = type(entry)(
            entry.index,
            bytes([payload[0] ^ 0x01]) + payload[1:],
            entry.previous_hash,
            entry.entry_hash,
        )
        items[0] = tampered_entry
        tampered = self._rebuild_receipt(
            bundle.receipt, items=tuple(items)
        )
        self._roundtrip_forged(
            SignedFullEncryptedJsonSearchReceipt(tampered, bundle.checkpoint)
        )

    def test_tampered_proof_roundtrip_but_verify_false(self):
        # A sub-range receipt carries a non-empty shared proof; a proof node
        # of the right width with one flipped byte round-trips and only
        # fails verification.
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, 1, 7, size=7
        )
        proof = bundle.receipt.proof
        self.assertTrue(proof)
        tampered_proof = (
            bytes([proof[0][0] ^ 0x01]) + proof[0][1:],
        ) + proof[1:]
        tampered = self._rebuild_receipt(
            bundle.receipt, proof=tampered_proof
        )
        self._roundtrip_forged(
            SignedFullEncryptedJsonSearchReceipt(tampered, bundle.checkpoint)
        )

    def test_wrong_public_key_roundtrip_but_verify_false(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        decoded = decode_signed_full_encrypted_json_search_receipt(
            encode_signed_full_encrypted_json_search_receipt(bundle)
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                decoded, KEY, self.other_public_key
            )
        )

    def test_call_is_read_only(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        data = encode_signed_full_encrypted_json_search_receipt(bundle)
        decode_signed_full_encrypted_json_search_receipt(data)
        self.assertEqual(
            decode_signed_full_encrypted_json_search_receipt(data), bundle
        )


if __name__ == "__main__":
    unittest.main()
