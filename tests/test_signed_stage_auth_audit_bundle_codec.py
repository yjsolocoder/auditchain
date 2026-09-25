import unittest

from auditchain import (
    AuditLog,
    SignedAuditBatch,
    SignedStageAuthAuditBundle,
    SignedStageAuthBundle,
    decode_signed_audit_batch,
    decode_signed_stage_auth_audit_bundle,
    decode_signed_stage_auth_bundle,
    encode_signed_audit_batch,
    encode_signed_stage_auth_audit_bundle,
    encode_signed_stage_auth_bundle,
    verify_signed_stage_auth_audit_bundle,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAGIC = b"auditchain/signed-stage-auth-audit/v1\0"

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


class EncodeSignedStageAuthAuditBundleTest(unittest.TestCase):
    def test_byte_layout(self):
        bundle = _issue()
        expected = (
            MAGIC
            + u64(1)
            + blob(encode_signed_stage_auth_bundle(bundle.auth))
            + blob(encode_signed_audit_batch(bundle.audit))
        )
        self.assertEqual(
            encode_signed_stage_auth_audit_bundle(bundle), expected
        )

    def test_starts_with_declared_magic(self):
        self.assertTrue(
            encode_signed_stage_auth_audit_bundle(_issue()).startswith(
                b"auditchain/signed-stage-auth-audit/v1\0"
            )
        )

    def test_distinct_from_stage_auth_bundle_magic(self):
        self.assertNotEqual(
            MAGIC, b"auditchain/signed-stage-auth-bundle/v1\0"
        )

    def test_deterministic_and_read_only(self):
        bundle = _issue()
        encoded = encode_signed_stage_auth_audit_bundle(bundle)
        self.assertEqual(
            encoded, encode_signed_stage_auth_audit_bundle(bundle)
        )

    def test_empty_selection_still_writes_both_blobs(self):
        bundle = _issue(indices=())
        data = encode_signed_stage_auth_audit_bundle(bundle)
        self.assertTrue(data.startswith(MAGIC + u64(1)))
        # The stage auth blob is present (non-zero length: it carries the
        # signed stage material even with no tagged items), and the audit
        # blob carries the snapshot's last entry.
        self.assertGreater(
            len(data), len(MAGIC) + 8 + 8 + 8
        )

    def test_empty_snapshot_roundtrip_layout(self):
        bundle = _issue(indices=(), size=0, records=3)
        data = encode_signed_stage_auth_audit_bundle(bundle)
        decoded = decode_signed_stage_auth_audit_bundle(data)
        self.assertEqual(decoded, bundle)
        self.assertEqual(encode_signed_stage_auth_audit_bundle(decoded), data)

    def test_type_errors(self):
        for bad in (None, "bundle", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
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

    def test_algorithm_mismatch_between_packages_raises_value_error(self):
        auth = _log(3, hash_name="sha256").signed_stage_auth_bundle(
            (0,), _SEED_A
        )
        other = AuditLog(key=_KEY, hash_name="sha512")
        other.append("record-0")
        other.rotate_key()
        audit = other.signed_audit_batch((0,), _SEED_A)
        bundle = SignedStageAuthAuditBundle(auth, audit)
        with self.assertRaises(ValueError):
            encode_signed_stage_auth_audit_bundle(bundle)


class DecodeSignedStageAuthAuditBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, bundle):
        data = encode_signed_stage_auth_audit_bundle(bundle)
        decoded = decode_signed_stage_auth_audit_bundle(data)
        self.assertEqual(decoded, bundle)
        self.assertEqual(decoded.auth, bundle.auth)
        self.assertEqual(decoded.audit, bundle.audit)
        self.assertIsInstance(decoded, SignedStageAuthAuditBundle)
        self.assertEqual(encode_signed_stage_auth_audit_bundle(decoded), data)
        return decoded

    def test_roundtrip(self):
        decoded = self.roundtrip(_issue())
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(decoded, self.public_key)
        )

    def test_roundtrip_empty_selection(self):
        decoded = self.roundtrip(_issue(indices=()))
        self.assertEqual(decoded.auth.items, ())

    def test_roundtrip_empty_snapshot(self):
        decoded = self.roundtrip(_issue(indices=(), size=0, records=3))
        self.assertEqual(decoded.audit.batch[1], 0)
        # Zero items omit no structure: verification still returns True.
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(decoded, self.public_key)
        )

    def test_roundtrip_explicit_size(self):
        self.roundtrip(_issue(indices=(1, 2), size=4, records=6))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            decoded = self.roundtrip(
                _issue(indices=(0, 2), records=3, hash_name=hash_name)
            )
            self.assertEqual(decoded.auth.hash_name, hash_name)
            self.assertTrue(
                verify_signed_stage_auth_audit_bundle(
                    decoded, self.public_key
                )
            )

    def test_persistence_across_process_boundary(self):
        data = bytes(encode_signed_stage_auth_audit_bundle(_issue()))
        restored = decode_signed_stage_auth_audit_bundle(data)
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(restored, self.public_key)
        )

    def test_verification_conclusion_is_preserved(self):
        for conclusion, seed in ((True, _SEED_A), (False, _SEED_B)):
            bundle = _issue(seed=seed)
            restored = decode_signed_stage_auth_audit_bundle(
                encode_signed_stage_auth_audit_bundle(bundle)
            )
            self.assertEqual(
                verify_signed_stage_auth_audit_bundle(
                    bundle, self.public_key
                ),
                conclusion,
            )
            self.assertEqual(
                verify_signed_stage_auth_audit_bundle(
                    restored, self.public_key
                ),
                conclusion,
            )

    def test_only_bytes_accepted(self):
        data = encode_signed_stage_auth_audit_bundle(_issue())
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_signed_stage_auth_audit_bundle(bad)

    def test_bad_magic(self):
        data = encode_signed_stage_auth_audit_bundle(_issue())
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(b"")
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(MAGIC[:-1])
        # The stage-auth-bundle magic must not be accepted here.
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                b"auditchain/signed-stage-auth-bundle/v1\0"
                + data[len(MAGIC):]
            )
        # Nor the stage-0 auth-audit magic.
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                b"auditchain/auth-audit/v1\0" + data[len(MAGIC):]
            )

    def test_bad_version(self):
        bundle = _issue()
        data = (
            MAGIC
            + u64(2)
            + encode_signed_stage_auth_audit_bundle(bundle)[
                len(MAGIC) + 8:
            ]
        )
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(data)
        data = (
            MAGIC
            + u64(0)
            + encode_signed_stage_auth_audit_bundle(bundle)[
                len(MAGIC) + 8:
            ]
        )
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(data)

    def test_truncation(self):
        data = encode_signed_stage_auth_audit_bundle(_issue())
        for cut in (
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError):
                decode_signed_stage_auth_audit_bundle(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_signed_stage_auth_audit_bundle(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_stage_auth_audit_bundle(_issue())
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_signed_stage_auth_audit_bundle(data + extra)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"x" * 16
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(data)

    def test_illegal_nested_encodings(self):
        bundle = _issue()
        auth_blob = encode_signed_stage_auth_bundle(bundle.auth)
        audit_blob = encode_signed_audit_batch(bundle.audit)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                MAGIC + u64(1) + blob(b"garbage") + blob(audit_blob)
            )
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                MAGIC + u64(1) + blob(auth_blob) + blob(b"garbage")
            )
        # The two blobs swapped.
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(
                MAGIC + u64(1) + blob(audit_blob) + blob(auth_blob)
            )

    def test_nested_hash_algorithm_mismatch(self):
        bundle = _issue(indices=(0,), records=3, hash_name="sha256")
        auth_blob = encode_signed_stage_auth_bundle(bundle.auth)
        other = AuditLog(key=_KEY, hash_name="sha512")
        other.append("record-0")
        other.rotate_key()
        other_audit = other.signed_audit_batch((0,), _SEED_A)
        audit_blob = encode_signed_audit_batch(other_audit)
        data = MAGIC + u64(1) + blob(auth_blob) + blob(audit_blob)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_audit_bundle(data)

    def test_wrong_signature_decodes_but_verifies_false(self):
        bundle = _issue(indices=(0,), records=3, seed=_SEED_B)
        decoded = decode_signed_stage_auth_audit_bundle(
            encode_signed_stage_auth_audit_bundle(bundle)
        )
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(decoded, self.public_key)
        )
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(
                decoded, self.other_public_key
            )
        )

    def test_tampered_tag_decodes_but_verifies_false(self):
        from auditchain import AuthTag

        bundle = _issue(indices=(0, 2))
        entry, tag = bundle.auth.items[1]
        bad_tag = type(tag)(
            tag.stage, bytes([tag.tag[0] ^ 1]) + tag.tag[1:]
        )
        items = (
            bundle.auth.items[:1]
            + ((entry, bad_tag),)
            + bundle.auth.items[2:]
        )
        forged_auth = SignedStageAuthBundle(
            bundle.auth.verifier, bundle.auth.hash_name, items
        )
        forged = SignedStageAuthAuditBundle(forged_auth, bundle.audit)
        # The tag is not covered by the codec's structural checks ...
        restored = decode_signed_stage_auth_audit_bundle(
            encode_signed_stage_auth_audit_bundle(forged)
        )
        self.assertEqual(restored, forged)
        # ... but verification must report False rather than raise.
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(restored, self.public_key)
        )

    def test_tampered_checkpoint_decodes_but_verifies_false(self):
        bundle = _issue()
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
        restored = decode_signed_stage_auth_audit_bundle(
            encode_signed_stage_auth_audit_bundle(forged)
        )
        self.assertEqual(restored, forged)
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(restored, self.public_key)
        )

    def test_decode_is_read_only(self):
        bundle = _issue()
        data = encode_signed_stage_auth_audit_bundle(bundle)
        decode_signed_stage_auth_audit_bundle(data)
        self.assertEqual(encode_signed_stage_auth_audit_bundle(bundle), data)

    def test_nested_decoders_match_existing_codecs(self):
        bundle = _issue()
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


if __name__ == "__main__":
    unittest.main()
