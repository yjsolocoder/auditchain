import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedAuthAuditBundle,
    SignedAuthAuditContinuation,
    SignedConsistency,
    decode_signed_auth_audit_bundle,
    decode_signed_auth_audit_continuation,
    decode_signed_consistency,
    encode_signed_auth_audit_bundle,
    encode_signed_auth_audit_continuation,
    encode_signed_consistency,
    verify_signed_auth_audit_continuation,
)

MAGIC = b"auditchain/auth-audit-continuation/v1\0"
BUNDLE_MAGIC = b"auditchain/auth-audit/v1\0"
CONSISTENCY_MAGIC = b"auditchain/signed-consistency/v1\0"

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


def _log(n=6, key=_KEY, hash_name="sha256", prefix="record"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _issue(old_size=2, indices=(0, 2, 4), seed=_SEED_A, size=5, n=6, **kwargs):
    return _log(n, **kwargs).signed_auth_audit_continuation(
        old_size, indices, seed, size
    )


def _split_envelope(data):
    """Split an envelope into (version, bundle_blob, consistency_blob)."""
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

    bundle_blob = take()
    consistency_blob = take()
    assert offset == len(data)
    return version, bundle_blob, consistency_blob


class EncodeSignedAuthAuditContinuationTest(unittest.TestCase):
    def setUp(self):
        self.receipt = _issue()

    def test_magic_and_field_layout(self):
        data = encode_signed_auth_audit_continuation(self.receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # bundle blob: u64 length then the complete encode_signed_auth_audit_bundle bytes.
        bundle_bytes = encode_signed_auth_audit_bundle(self.receipt.bundle)
        self.assertEqual(data[offset:offset + 8], u64(len(bundle_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(bundle_bytes)], bundle_bytes)
        offset += len(bundle_bytes)
        # consistency blob likewise, and it is the last field.
        consistency_bytes = encode_signed_consistency(self.receipt.consistency)
        self.assertEqual(data[offset:offset + 8], u64(len(consistency_bytes)))
        offset += 8
        self.assertEqual(
            data[offset:offset + len(consistency_bytes)], consistency_bytes
        )
        offset += len(consistency_bytes)
        self.assertEqual(offset, len(data))

    def test_blobs_are_exact_existing_encodings(self):
        _, bundle_blob, consistency_blob = _split_envelope(
            encode_signed_auth_audit_continuation(self.receipt)
        )
        self.assertEqual(
            bundle_blob,
            encode_signed_auth_audit_bundle(self.receipt.bundle),
        )
        self.assertEqual(
            consistency_blob,
            encode_signed_consistency(self.receipt.consistency),
        )
        # Both blobs are independently decodable by their existing codecs.
        self.assertEqual(
            decode_signed_auth_audit_bundle(bundle_blob), self.receipt.bundle
        )
        self.assertEqual(
            decode_signed_consistency(consistency_blob),
            self.receipt.consistency,
        )

    def test_encode_is_deterministic(self):
        data = encode_signed_auth_audit_continuation(self.receipt)
        self.assertEqual(
            data, encode_signed_auth_audit_continuation(self.receipt)
        )

    def test_no_new_signing_domain(self):
        # Only framing is added; the nested bytes are the two existing
        # canonical packages, re-encoded verbatim.
        _, bundle_blob, consistency_blob = _split_envelope(
            encode_signed_auth_audit_continuation(self.receipt)
        )
        self.assertTrue(bundle_blob.startswith(BUNDLE_MAGIC))
        self.assertTrue(consistency_blob.startswith(CONSISTENCY_MAGIC))

    def test_only_continuation_accepted(self):
        for bad in (
            None,
            1,
            "receipt",
            b"bytes",
            (),
            (self.receipt.bundle, self.receipt.consistency),
            self.receipt.bundle,
            self.receipt.consistency,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_auth_audit_continuation(bad)

    def test_bypassed_container_fields_raise_type_error(self):
        for field, value in (
            ("bundle", None),
            ("bundle", "not-a-bundle"),
            ("bundle", self.receipt.consistency),
            ("consistency", None),
            ("consistency", "not-a-consistency"),
            ("consistency", self.receipt.bundle),
        ):
            forged = SignedAuthAuditContinuation.__new__(
                SignedAuthAuditContinuation
            )
            object.__setattr__(
                forged,
                "bundle",
                self.receipt.bundle if field != "bundle" else value,
            )
            object.__setattr__(
                forged,
                "consistency",
                self.receipt.consistency if field != "consistency" else value,
            )
            with self.assertRaises(TypeError, msg=field):
                encode_signed_auth_audit_continuation(forged)

    def test_nested_bundle_type_error_propagates(self):
        # A bundle whose own container field was bypassed survives the outer
        # isinstance checks (it is still a SignedAuthAuditBundle instance);
        # the TypeError raised inside encode_signed_auth_audit_bundle must
        # surface from the continuation encoder verbatim.
        bundle = SignedAuthAuditBundle.__new__(SignedAuthAuditBundle)
        object.__setattr__(bundle, "auth", "not-an-auth-bundle")
        object.__setattr__(bundle, "audit", self.receipt.bundle.audit)
        forged = SignedAuthAuditContinuation(
            bundle, self.receipt.consistency
        )
        with self.assertRaises(TypeError):
            encode_signed_auth_audit_continuation(forged)

    def test_nested_consistency_value_error_propagates(self):
        # A proof node of the wrong width is a ValueError in
        # encode_signed_consistency and must surface verbatim here.
        consistency = self.receipt.consistency
        self.assertTrue(consistency.proof)
        bad_consistency = SignedConsistency(
            consistency.old,
            consistency.new,
            (b"\x00" * 31,) + consistency.proof[1:],
        )
        forged = SignedAuthAuditContinuation(
            self.receipt.bundle, bad_consistency
        )
        with self.assertRaises(ValueError):
            encode_signed_auth_audit_continuation(forged)

    def test_call_is_read_only(self):
        before = (
            encode_signed_auth_audit_bundle(self.receipt.bundle),
            encode_signed_consistency(self.receipt.consistency),
        )
        encode_signed_auth_audit_continuation(self.receipt)
        after = (
            encode_signed_auth_audit_bundle(self.receipt.bundle),
            encode_signed_consistency(self.receipt.consistency),
        )
        self.assertEqual(after, before)


class DecodeSignedAuthAuditContinuationTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, receipt):
        data = encode_signed_auth_audit_continuation(receipt)
        decoded = decode_signed_auth_audit_continuation(data)
        self.assertIsInstance(decoded, SignedAuthAuditContinuation)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.bundle, receipt.bundle)
        self.assertEqual(decoded.consistency, receipt.consistency)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(
            encode_signed_auth_audit_continuation(decoded), data
        )
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                decoded, self.public_key
            )
        )
        return decoded

    def test_roundtrip_variants(self):
        for old_size, size in ((2, 5), (0, 5), (3, 3), (0, 0), (4, 5)):
            self.roundtrip(
                _issue(
                    old_size=old_size,
                    indices=(0,) if size else (),
                    size=size,
                    n=5,
                )
            )

    def test_roundtrip_empty_selection(self):
        self.roundtrip(_issue(indices=()))

    def test_roundtrip_after_prune(self):
        log = _log(6)
        log.prune(2, log.seal(2))
        receipt = log.signed_auth_audit_continuation(
            2, (2, 5), _SEED_A
        )
        self.roundtrip(receipt)

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            self.roundtrip(
                _issue(
                    old_size=1,
                    indices=(0, 2),
                    size=3,
                    n=3,
                    hash_name=hash_name,
                )
            )

    def test_frozen(self):
        decoded = decode_signed_auth_audit_continuation(
            encode_signed_auth_audit_continuation(_issue())
        )
        with self.assertRaises(FrozenInstanceError):
            decoded.bundle = decoded.bundle
        with self.assertRaises(FrozenInstanceError):
            decoded.consistency = decoded.consistency

    def test_persistence_across_process_boundary(self):
        receipt = _issue()
        data = encode_signed_auth_audit_continuation(receipt)
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_signed_auth_audit_continuation(bytes(data))
        self.assertEqual(restored, receipt)
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                restored, self.public_key
            )
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_auth_audit_continuation(_issue())
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
                decode_signed_auth_audit_continuation(bad)

    def test_bad_magic(self):
        data = encode_signed_auth_audit_continuation(_issue())
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/auth-audit/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-consistency/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-audit-batch/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:40])):
                decode_signed_auth_audit_continuation(bad)

    def test_bad_version(self):
        receipt = _issue()
        data = encode_signed_auth_audit_continuation(receipt)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_auth_audit_continuation(bad)

    def test_truncation(self):
        data = encode_signed_auth_audit_continuation(_issue())
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_auth_audit_continuation(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_auth_audit_continuation(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_auth_audit_continuation(_issue())
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_auth_audit_continuation(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC
            + u64(1)
            + blob(encode_signed_auth_audit_bundle(_issue().bundle))
            + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_auth_audit_continuation(bad)

    def test_missing_consistency_blob(self):
        receipt = _issue()
        _, bundle_blob, _ = _split_envelope(
            encode_signed_auth_audit_continuation(receipt)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC + u64(1) + blob(bundle_blob)
            )

    def test_missing_bundle_blob(self):
        receipt = _issue()
        _, _, consistency_blob = _split_envelope(
            encode_signed_auth_audit_continuation(receipt)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC + u64(1) + blob(consistency_blob)
            )

    def test_swapped_blob_order_rejected(self):
        receipt = _issue()
        _, bundle_blob, consistency_blob = _split_envelope(
            encode_signed_auth_audit_continuation(receipt)
        )
        swapped = (
            MAGIC
            + u64(1)
            + blob(consistency_blob)
            + blob(bundle_blob)
        )
        # The first blob no longer starts with the auth-audit magic, so the
        # nested decoder rejects it: fields are never silently swapped.
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(swapped)

    def test_garbage_bundle_blob_rejected(self):
        receipt = _issue()
        _, _, consistency_blob = _split_envelope(
            encode_signed_auth_audit_continuation(receipt)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC
                + u64(1)
                + blob(b"hello")
                + blob(consistency_blob)
            )

    def test_garbage_consistency_blob_rejected(self):
        receipt = _issue()
        _, bundle_blob, _ = _split_envelope(
            encode_signed_auth_audit_continuation(receipt)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC
                + u64(1)
                + blob(bundle_blob)
                + blob(b"hello")
            )

    def test_nested_bundle_framing_error_rejected(self):
        receipt = _issue()
        _, bundle_blob, consistency_blob = _split_envelope(
            encode_signed_auth_audit_continuation(receipt)
        )
        tampered = b"x" + bundle_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC
                + u64(1)
                + blob(tampered)
                + blob(consistency_blob)
            )

    def test_nested_consistency_framing_error_rejected(self):
        receipt = _issue()
        _, bundle_blob, consistency_blob = _split_envelope(
            encode_signed_auth_audit_continuation(receipt)
        )
        tampered = b"x" + consistency_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC
                + u64(1)
                + blob(bundle_blob)
                + blob(tampered)
            )

    def test_bundle_consistency_disagreement_still_decodes(self):
        # Both halves individually genuine and structurally sound, but the
        # consistency extends a different snapshot than the audit attests.
        # The decoder must not judge the linkage: it decodes, and only
        # verification returns False.
        bundle = _log(5).signed_auth_audit_bundle(
            (0,), _SEED_A, size=4
        )
        consistency = _log(5, prefix="other").signed_consistency(
            1, _SEED_A, new_size=5
        )
        receipt = SignedAuthAuditContinuation(bundle, consistency)
        decoded = decode_signed_auth_audit_continuation(
            encode_signed_auth_audit_continuation(receipt)
        )
        self.assertEqual(decoded, receipt)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                decoded, self.public_key
            )
        )

    def test_wrong_key_decodes_but_verifies_false(self):
        receipt = _issue(seed=_SEED_B)
        decoded = decode_signed_auth_audit_continuation(
            encode_signed_auth_audit_continuation(receipt)
        )
        self.assertEqual(decoded, receipt)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                decoded, self.public_key
            )
        )
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                decoded, self.other_public_key
            )
        )

    def test_halves_signed_by_different_keys_still_decode(self):
        # Each half is individually genuine but under a different key; the
        # nested encodings are both structurally valid, so the continuation
        # decodes while continuation verification returns False.
        bundle = _log(5).signed_auth_audit_bundle(
            (0, 2), _SEED_A, size=4
        )
        consistency = _log(5).signed_consistency(2, _SEED_B, new_size=4)
        receipt = SignedAuthAuditContinuation(bundle, consistency)
        decoded = decode_signed_auth_audit_continuation(
            encode_signed_auth_audit_continuation(receipt)
        )
        self.assertEqual(decoded, receipt)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                decoded, self.public_key
            )
        )

    def test_algorithm_mismatch_between_halves_still_decodes(self):
        # The bundle decoder only pins the algorithms *inside* the bundle;
        # the consistency naming a different hash than the bundle is a
        # verification matter, not a decoding one.
        bundle = _log(3, hash_name="sha256").signed_auth_audit_bundle(
            (0,), _SEED_A, size=3
        )
        other = _log(3, hash_name="sha512")
        consistency = other.signed_consistency(1, _SEED_A, new_size=3)
        receipt = SignedAuthAuditContinuation(bundle, consistency)
        decoded = decode_signed_auth_audit_continuation(
            encode_signed_auth_audit_continuation(receipt)
        )
        self.assertEqual(decoded, receipt)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                decoded, self.public_key
            )
        )

    def test_call_is_read_only(self):
        receipt = _issue()
        data = encode_signed_auth_audit_continuation(receipt)
        decode_signed_auth_audit_continuation(data)
        self.assertEqual(
            decode_signed_auth_audit_continuation(data), receipt
        )


if __name__ == "__main__":
    unittest.main()
