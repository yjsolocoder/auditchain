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
    SignedStageAuthAuditBundle,
    SignedStageAuthBundle,
    SignedStageVerifier,
    decode_signed_audit_batch,
    decode_signed_stage_auth_audit_bundle,
    decode_signed_stage_auth_bundle,
    encode_signed_audit_batch,
    encode_signed_stage_auth_audit_bundle,
    encode_signed_stage_auth_bundle,
    verify_signed_stage_auth_audit_bundle,
)

MAGIC = b"auditchain/signed-stage-auth-audit/v1\0"
STAGE_AUTH_MAGIC = b"auditchain/signed-stage-auth-bundle/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-stage-audit-bundle-key"


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


def _log(records=5, key=_KEY, hash_name="sha256", evolve=1, prefix="record"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(records):
        log.append(f"{prefix}-{record}")
    for _ in range(evolve):
        log.rotate_key()
    return log


def _issue(indices=(0, 2, 4), seed=_SEED_A, size=None, records=5, **kwargs):
    return _log(records=records, **kwargs).signed_stage_auth_audit_bundle(
        indices, seed, size
    )


def _parse_blobs(data):
    """Split an envelope into (version, auth_blob, audit_blob)."""
    assert data.startswith(MAGIC)
    offset = len(MAGIC)
    version = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    length = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    auth_blob = data[offset:offset + length]
    offset += length
    length = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    audit_blob = data[offset:offset + length]
    offset += length
    assert offset == len(data)
    return version, auth_blob, audit_blob


class EncodeSignedStageAuthAuditBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        bundle = _issue()
        data = encode_signed_stage_auth_audit_bundle(bundle)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        auth_bytes = encode_signed_stage_auth_bundle(bundle.auth)
        self.assertEqual(data[offset:offset + 8], u64(len(auth_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(auth_bytes)], auth_bytes)
        offset += len(auth_bytes)
        audit_bytes = encode_signed_audit_batch(bundle.audit)
        self.assertEqual(data[offset:offset + 8], u64(len(audit_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(audit_bytes)], audit_bytes)
        offset += len(audit_bytes)
        self.assertEqual(offset, len(data))

    def test_layout_matches_blob_framing(self):
        bundle = _issue(indices=(1, 3), hash_name="sha3_256")
        expected = (
            MAGIC
            + u64(1)
            + blob(encode_signed_stage_auth_bundle(bundle.auth))
            + blob(encode_signed_audit_batch(bundle.audit))
        )
        self.assertEqual(
            encode_signed_stage_auth_audit_bundle(bundle), expected
        )

    def test_blobs_are_exact_existing_encodings(self):
        bundle = _issue(indices=(0, 2, 4))
        _, auth_blob, audit_blob = _parse_blobs(
            encode_signed_stage_auth_audit_bundle(bundle)
        )
        self.assertEqual(
            auth_blob, encode_signed_stage_auth_bundle(bundle.auth)
        )
        self.assertEqual(audit_blob, encode_signed_audit_batch(bundle.audit))
        # The inner blobs are independently decodable by the existing codecs.
        self.assertEqual(
            decode_signed_stage_auth_bundle(auth_blob), bundle.auth
        )
        self.assertEqual(decode_signed_audit_batch(audit_blob), bundle.audit)

    def test_empty_selection_layout(self):
        bundle = _issue(indices=())
        data = encode_signed_stage_auth_audit_bundle(bundle)
        _, auth_blob, audit_blob = _parse_blobs(data)
        self.assertEqual(
            auth_blob, encode_signed_stage_auth_bundle(bundle.auth)
        )
        # Zero items never omit the nested framing: the empty auth batch and
        # the audit still carrying the last entry ride along in full.
        self.assertEqual(audit_blob, encode_signed_audit_batch(bundle.audit))
        self.assertEqual(bundle.auth.items, ())

    def test_empty_snapshot_layout(self):
        bundle = _issue(indices=(), size=0, records=3)
        data = encode_signed_stage_auth_audit_bundle(bundle)
        _, auth_blob, audit_blob = _parse_blobs(data)
        self.assertEqual(
            auth_blob, encode_signed_stage_auth_bundle(bundle.auth)
        )
        self.assertEqual(audit_blob, encode_signed_audit_batch(bundle.audit))
        self.assertEqual(bundle.auth.items, ())
        self.assertEqual(bundle.audit.batch[1], 0)
        self.assertEqual(bundle.audit.batch[3], ())

    def test_encode_is_deterministic_and_read_only(self):
        bundle = _issue()
        encoded = encode_signed_stage_auth_audit_bundle(bundle)
        self.assertEqual(
            encoded, encode_signed_stage_auth_audit_bundle(bundle)
        )
        snapshot = (bundle.auth, bundle.audit)
        encode_signed_stage_auth_audit_bundle(bundle)
        self.assertEqual((bundle.auth, bundle.audit), snapshot)
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(bundle, self.public_key)
        )

    def test_only_signed_stage_auth_audit_bundle_accepted(self):
        bundle = _issue()
        for bad in (
            None,
            1,
            "bundle",
            b"bytes",
            (),
            bundle.auth,
            bundle.audit,
            (bundle.auth, bundle.audit),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_stage_auth_audit_bundle(bad)

    def test_bypassed_container_fields_raise_type_error(self):
        bundle = _issue()
        for field, value in (
            ("auth", "not-a-bundle"),
            ("audit", "not-a-batch"),
        ):
            forged = SignedStageAuthAuditBundle.__new__(
                SignedStageAuthAuditBundle
            )
            object.__setattr__(forged, "auth", bundle.auth)
            object.__setattr__(forged, "audit", bundle.audit)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_signed_stage_auth_audit_bundle(forged)

    def test_nested_errors_propagate(self):
        # A 63-byte signature inside the signed stage verifier is rejected by
        # the existing encoder with ValueError, verbatim through the envelope.
        bundle = _issue()
        bad_verifier = SignedStageVerifier.__new__(SignedStageVerifier)
        object.__setattr__(
            bad_verifier, "version", bundle.auth.verifier.version
        )
        object.__setattr__(
            bad_verifier, "verifier", bundle.auth.verifier.verifier
        )
        object.__setattr__(
            bad_verifier, "signature", bundle.auth.verifier.signature[:-1]
        )
        bad_auth = SignedStageAuthBundle(
            bad_verifier, bundle.auth.hash_name, bundle.auth.items
        )
        with self.assertRaises(ValueError):
            encode_signed_stage_auth_audit_bundle(
                SignedStageAuthAuditBundle(bad_auth, bundle.audit)
            )

    def test_algorithm_mismatch_raises_value_error(self):
        # Two individually legal halves minted under different hash
        # algorithms never describe one delivery.
        sha256 = _issue(indices=(0,), records=3, hash_name="sha256")
        other = AuditLog(key=_KEY, hash_name="sha512")
        other.append("record-0")
        other.rotate_key()
        sha512_audit = other.signed_audit_batch((0,), _SEED_A)
        forged = SignedStageAuthAuditBundle(sha256.auth, sha512_audit)
        with self.assertRaises(ValueError):
            encode_signed_stage_auth_audit_bundle(forged)

    def test_no_new_signing_message(self):
        # Both nested halves ride along verbatim; the envelope adds no
        # signature of its own.
        bundle = _issue(indices=(1, 3))
        _, auth_blob, audit_blob = _parse_blobs(
            encode_signed_stage_auth_audit_bundle(bundle)
        )
        self.assertEqual(
            auth_blob, encode_signed_stage_auth_bundle(bundle.auth)
        )
        self.assertEqual(audit_blob, encode_signed_audit_batch(bundle.audit))


class DecodeSignedStageAuthAuditBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, bundle):
        data = encode_signed_stage_auth_audit_bundle(bundle)
        decoded = decode_signed_stage_auth_audit_bundle(data)
        self.assertIsInstance(decoded, SignedStageAuthAuditBundle)
        self.assertEqual(decoded, bundle)
        self.assertEqual(decoded.auth, bundle.auth)
        self.assertEqual(decoded.audit, bundle.audit)
        self.assertIs(type(decoded.auth), SignedStageAuthBundle)
        self.assertIs(type(decoded.audit), SignedAuditBatch)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(
            encode_signed_stage_auth_audit_bundle(decoded), data
        )
        # Verification verdicts survive the round trip.
        self.assertEqual(
            verify_signed_stage_auth_audit_bundle(decoded, self.public_key),
            verify_signed_stage_auth_audit_bundle(bundle, self.public_key),
        )
        return decoded

    def test_roundtrip(self):
        decoded = self.roundtrip(_issue(indices=(0, 2, 4)))
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(decoded, self.public_key)
        )

    def test_roundtrip_single_item(self):
        self.roundtrip(_issue(indices=(3,)))

    def test_roundtrip_empty_selection(self):
        decoded = self.roundtrip(_issue(indices=()))
        self.assertEqual(decoded.auth.items, ())
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(decoded, self.public_key)
        )

    def test_roundtrip_empty_snapshot(self):
        decoded = self.roundtrip(_issue(indices=(), size=0, records=3))
        self.assertEqual(decoded.auth.items, ())
        self.assertEqual(decoded.audit.batch[1], 0)
        self.assertEqual(decoded.audit.batch[3], ())
        # An empty selection still verifies True: the signed stage material
        # is checked explicitly and the audit covers the empty snapshot.
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(decoded, self.public_key)
        )

    def test_roundtrip_explicit_size(self):
        self.roundtrip(_issue(indices=(1, 2), size=4, records=6))

    def test_roundtrip_later_stages_and_alternate_hash(self):
        self.roundtrip(_issue(evolve=3))
        for hash_name in ("sha512", "sha3_256"):
            decoded = self.roundtrip(
                _issue(indices=(0, 2), records=3, hash_name=hash_name)
            )
            self.assertEqual(decoded.auth.hash_name, hash_name)
            self.assertEqual(decoded.audit.batch[0], hash_name)

    def test_roundtrip_after_prune(self):
        log = _log(records=6, evolve=1)
        log.prune(2, log.seal(2))
        bundle = log.signed_stage_auth_audit_bundle((5, 2), _SEED_A)
        self.roundtrip(bundle)

    def test_frozen(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
        decoded = decode_signed_stage_auth_audit_bundle(data)
        with self.assertRaises(FrozenInstanceError):
            decoded.auth = decoded.auth
        with self.assertRaises(FrozenInstanceError):
            decoded.audit = decoded.audit

    def test_persistence_across_process_boundary(self):
        bundle = _issue(indices=(1, 3))
        data = bytes(encode_signed_stage_auth_audit_bundle(bundle))
        restored = decode_signed_stage_auth_audit_bundle(data)
        self.assertEqual(restored, bundle)
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(
                restored, self.public_key
            )
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
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
                decode_signed_stage_auth_audit_bundle(bad)

    def test_bad_magic(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            STAGE_AUTH_MAGIC + data[len(MAGIC):],
            b"auditchain/auth-audit/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:40])):
                decode_signed_stage_auth_audit_bundle(bad)

    def test_bad_version(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_stage_auth_audit_bundle(bad)

    def test_truncation(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_stage_auth_audit_bundle(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_stage_auth_audit_bundle(data[:cut])

    def test_truncated_empty_selection(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=()))
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_stage_auth_audit_bundle(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_stage_auth_audit_bundle(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_stage_auth_audit_bundle(bad)

    def test_missing_second_blob(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
        _, auth_blob, _ = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                MAGIC + u64(1) + blob(auth_blob)
            )

    def test_extra_third_blob_rejected(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
        _, auth_blob, audit_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                MAGIC
                + u64(1)
                + blob(auth_blob)
                + blob(audit_blob)
                + blob(b"extra")
            )

    def test_swapped_blob_order_rejected(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
        _, auth_blob, audit_blob = _parse_blobs(data)
        swapped = (
            MAGIC + u64(1) + blob(audit_blob) + blob(auth_blob)
        )
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(swapped)

    def test_garbage_nested_blobs_rejected(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
        _, auth_blob, audit_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                MAGIC + u64(1) + blob(b"garbage") + blob(audit_blob)
            )
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                MAGIC + u64(1) + blob(auth_blob) + blob(b"garbage")
            )

    def test_trailing_bytes_inside_blob_rejected(self):
        data = encode_signed_stage_auth_audit_bundle(_issue(indices=(1,)))
        _, auth_blob, audit_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                MAGIC
                + u64(1)
                + blob(auth_blob + b"\x00")
                + blob(audit_blob)
            )
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                MAGIC
                + u64(1)
                + blob(auth_blob)
                + blob(audit_blob + b"\x00")
            )

    def test_algorithm_mismatch_between_blobs_rejected(self):
        # Two genuinely encoded halves under different algorithms: each
        # nested blob is legal on its own, but they do not describe one
        # delivery.
        sha256 = _issue(indices=(0,), records=3, hash_name="sha256")
        other = AuditLog(key=_KEY, hash_name="sha512")
        other.append("record-0")
        other.rotate_key()
        sha512_audit = other.signed_audit_batch((0,), _SEED_A)
        auth_blob = encode_signed_stage_auth_bundle(sha256.auth)
        audit_blob = encode_signed_audit_batch(sha512_audit)
        forged = MAGIC + u64(1) + blob(auth_blob) + blob(audit_blob)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(forged)

    def test_wrong_signature_decodes_but_verifies_false(self):
        bundle = _issue(indices=(0,), records=3, seed=_SEED_B)
        decoded = decode_signed_stage_auth_audit_bundle(
            encode_signed_stage_auth_audit_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(decoded, self.public_key)
        )
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(
                decoded, self.other_public_key
            )
        )

    def test_tampered_checkpoint_decodes_but_verifies_false(self):
        bundle = _issue(indices=(0,), records=3)
        checkpoint = bundle.audit.checkpoint
        forged_checkpoint = type(checkpoint)(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged_audit = SignedAuditBatch(
            bundle.audit.batch, forged_checkpoint
        )
        forged = SignedStageAuthAuditBundle(bundle.auth, forged_audit)
        decoded = decode_signed_stage_auth_audit_bundle(
            encode_signed_stage_auth_audit_bundle(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(decoded, self.public_key)
        )

    def test_empty_selection_wrong_key_roundtrip_and_false_verdict(self):
        bundle = _issue(indices=(), seed=_SEED_B)
        decoded = decode_signed_stage_auth_audit_bundle(
            encode_signed_stage_auth_audit_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(decoded, self.public_key)
        )
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(
                decoded, self.other_public_key
            )
        )

    def test_nested_decoders_match_existing_codecs(self):
        bundle = _issue(indices=(1, 3))
        decoded = decode_signed_stage_auth_audit_bundle(
            encode_signed_stage_auth_audit_bundle(bundle)
        )
        self.assertEqual(
            decoded.auth,
            decode_signed_stage_auth_bundle(
                encode_signed_stage_auth_bundle(bundle.auth)
            ),
        )
        self.assertEqual(
            decoded.audit,
            decode_signed_audit_batch(
                encode_signed_audit_batch(bundle.audit)
            ),
        )

    def test_decode_is_read_only(self):
        bundle = _issue(indices=(1, 2))
        data = encode_signed_stage_auth_audit_bundle(bundle)
        decode_signed_stage_auth_audit_bundle(data)
        self.assertEqual(
            decode_signed_stage_auth_audit_bundle(data), bundle
        )


if __name__ == "__main__":
    unittest.main()
