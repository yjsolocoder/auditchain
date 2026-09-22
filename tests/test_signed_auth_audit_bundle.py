import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    SignedAuditBatch,
    SignedAuthAuditBundle,
    SignedAuthBundle,
    SignedVerifier,
    decode_signed_audit_batch,
    decode_signed_auth_audit_bundle,
    decode_signed_auth_bundle,
    encode_signed_audit_batch,
    encode_signed_auth_audit_bundle,
    encode_signed_auth_bundle,
    verify_signed_audit_batch,
    verify_signed_auth_audit_bundle,
    verify_signed_auth_bundle,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAGIC = b"auditchain/auth-audit/v1\0"

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


def _log(n=5, key=_KEY, hash_name="sha256", prefix="record"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _issue(indices=(0, 2, 4), seed=_SEED_A, size=None, n=5, **kwargs):
    return _log(n, **kwargs).signed_auth_audit_bundle(indices, seed, size)


class SignedAuthAuditBundleConstructionTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        bundle = _issue()
        again = SignedAuthAuditBundle(bundle.auth, bundle.audit)
        self.assertEqual(bundle, again)
        self.assertIsInstance(bundle.auth, SignedAuthBundle)
        self.assertIsInstance(bundle.audit, SignedAuditBatch)
        self.assertNotEqual(bundle, _issue(indices=(1,)))

    def test_frozen(self):
        bundle = _issue()
        for field in ("auth", "audit"):
            with self.assertRaises(Exception):
                setattr(bundle, field, None)

    def test_container_type_errors(self):
        bundle = _issue()
        with self.assertRaises(TypeError):
            SignedAuthAuditBundle("not-a-bundle", bundle.audit)
        with self.assertRaises(TypeError):
            SignedAuthAuditBundle(bundle.auth, "not-a-batch")


class SignedAuthAuditBundleIssuanceTest(unittest.TestCase):
    def _snapshot(self, log):
        return (
            log.stage,
            log._key,
            dict(log._tags),
            log.head,
            len(log),
            log._verifier_exported,
        )

    def test_bundle_fields_and_audit_auto_includes_last_entry(self):
        log = _log(5)
        bundle = log.signed_auth_audit_bundle((4, 0), _SEED_A)
        self.assertIsInstance(bundle, SignedAuthAuditBundle)
        # The auth half tags exactly the selected, deduplicated indices.
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [0, 4]
        )
        self.assertEqual(bundle.auth.hash_name, "sha256")
        # The audit half carries the selected entries plus the snapshot's
        # last entry (index size - 1) automatically.
        _, audit_size, _, audit_entries, _ = bundle.audit.batch
        self.assertEqual(audit_size, 5)
        self.assertEqual([entry.index for entry in audit_entries], [0, 4])
        self.assertEqual(bundle.audit.checkpoint.size, 5)
        # Index 4 was both selected and the last entry: no duplicate.
        self.assertEqual(len(audit_entries), 2)

    def test_audit_appends_unselected_last_entry_without_auth_domain(self):
        bundle = _issue(indices=(1,), n=5)
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [1]
        )
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [1, 4]
        )
        # The appended last entry carries no auth tag/signing domain.
        self.assertEqual(len(bundle.auth.items), 1)

    def test_equals_two_step_issuance(self):
        log = _log(5)
        bundle = log.signed_auth_audit_bundle((4, 0, 2), _SEED_A)
        twin = _log(5)
        auth = twin.signed_auth_bundle((4, 0, 2), _SEED_A)
        audit = twin.signed_audit_batch((4, 0, 2), _SEED_A)
        self.assertEqual(bundle.auth, auth)
        self.assertEqual(bundle.audit, audit)
        self.assertEqual(bundle, SignedAuthAuditBundle(auth, audit))

    def test_tags_run_from_stage_zero_and_commit(self):
        log = _log(5)
        bundle = log.signed_auth_audit_bundle((4, 0, 2), _SEED_A)
        self.assertEqual([tag.stage for _, tag in bundle.auth.items], [0, 1, 2])
        self.assertEqual(log.stage, 3)
        self.assertEqual(sorted(log._tags), [0, 2, 4])

    def test_accepts_generator_and_sorts_ascending(self):
        bundle = _log(5).signed_auth_audit_bundle(
            (i for i in (4, 0)), _SEED_A
        )
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [0, 4]
        )
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [0, 4]
        )

    def test_explicit_size_smaller_than_length(self):
        log = _log(6)
        bundle = log.signed_auth_audit_bundle((1,), _SEED_A, size=3)
        self.assertEqual(bundle.audit.checkpoint.size, 3)
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [1, 2]
        )
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [1]
        )

    def test_size_defaults_to_current_length(self):
        bundle = _issue(indices=(1,), n=5)
        self.assertEqual(bundle.audit.batch[1], 5)
        self.assertEqual(bundle.audit.checkpoint.size, 5)

    def test_empty_selection_non_empty_snapshot(self):
        log = _log(5)
        bundle = log.signed_auth_audit_bundle((), _SEED_A)
        self.assertEqual(bundle.auth.items, ())
        # The audit still carries the last snapshot entry.
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [4]
        )
        # No tags minted: stage stays 0, but the export is consumed.
        self.assertEqual(log.stage, 0)
        self.assertTrue(log._verifier_exported)
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )

    def test_empty_snapshot(self):
        log = _log(3)
        bundle = log.signed_auth_audit_bundle((), _SEED_A, size=0)
        self.assertEqual(bundle.auth.items, ())
        hash_name, size, root, entries, proof = bundle.audit.batch
        self.assertEqual(size, 0)
        self.assertEqual(entries, ())
        self.assertEqual(proof, ())
        self.assertEqual(bundle.audit.checkpoint.size, 0)
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )
        # No index is eligible inside an empty snapshot.
        with self.assertRaises(IndexError):
            log.signed_auth_audit_bundle((0,), _SEED_A, size=0)

    def test_success_consumes_one_shot_eligibility(self):
        log = _log(5)
        log.signed_auth_audit_bundle((1,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((2,), _SEED_A)
        with self.assertRaises(ValueError):
            log.export_verifier()
        with self.assertRaises(ValueError):
            log.export_signed_verifier(_SEED_A)

    def test_prior_export_or_evolution_disqualifies(self):
        log = _log(5)
        log.export_signed_verifier(_SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((0,), _SEED_A)
        log = _log(5)
        log.auth(0)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((1,), _SEED_A)

    def test_keyless_mode_raises_value_error(self):
        log = AuditLog()
        for record in range(3):
            log.append(f"record-{record}")
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((), _SEED_A)

    def test_private_key_type_errors(self):
        log = _log(5)
        for bad in ("0" * 32, bytearray(_SEED_A), memoryview(_SEED_A), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                log.signed_auth_audit_bundle((0,), bad)

    def test_private_key_length_raises_value_error(self):
        log = _log(5)
        for bad in (b"", _SEED_A[:-1], _SEED_A + b"\x00"):
            with self.assertRaises(ValueError):
                log.signed_auth_audit_bundle((0,), bad)

    def test_indices_type_errors(self):
        log = _log(5)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_bundle(5, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_bundle(None, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_bundle(["0"], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_bundle([1.0], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_bundle([True], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_bundle([0, False], _SEED_A)

    def test_size_type_error(self):
        log = _log(5)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_bundle((0,), _SEED_A, size=True)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_bundle((0,), _SEED_A, size=1.0)

    def test_duplicate_index_raises_value_error(self):
        with self.assertRaises(ValueError):
            _log(5).signed_auth_audit_bundle([1, 2, 1], _SEED_A)

    def test_size_out_of_range_raises_value_error(self):
        log = _log(5)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((0,), _SEED_A, size=6)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((0,), _SEED_A, size=-1)

    def test_out_of_range_index_raises_index_error(self):
        log = _log(5)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_bundle([5], _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_bundle([-1], _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_bundle([3], _SEED_A, size=3)
        log.prune(2, log.seal(2))
        with self.assertRaises(IndexError):
            log.signed_auth_audit_bundle([1, 3], _SEED_A)

    def test_pruned_log_selection(self):
        log = _log(6)
        log.prune(2, log.seal(2))
        bundle = log.signed_auth_audit_bundle((5, 2), _SEED_A)
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [2, 5]
        )
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )

    def test_failure_is_atomic_and_preserves_eligibility(self):
        for call, error in (
            (lambda log: log.signed_auth_audit_bundle(["0"], _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_bundle([True], _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_bundle(5, _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_bundle([0, 0], _SEED_A), ValueError),
            (lambda log: log.signed_auth_audit_bundle([9], _SEED_A), IndexError),
            (lambda log: log.signed_auth_audit_bundle([-1], _SEED_A), IndexError),
            (lambda log: log.signed_auth_audit_bundle([3], _SEED_A, size=3), IndexError),
            (lambda log: log.signed_auth_audit_bundle([0], "0" * 32), TypeError),
            (lambda log: log.signed_auth_audit_bundle([0], b"short"), ValueError),
            (lambda log: log.signed_auth_audit_bundle([0], _SEED_A, size=6), ValueError),
        ):
            log = _log(5)
            before = self._snapshot(log)
            with self.assertRaises(error):
                call(log)
            self.assertEqual(self._snapshot(log), before)
            bundle = log.signed_auth_audit_bundle((0, 2, 4), _SEED_A)
            self.assertEqual(
                [tag.stage for _, tag in bundle.auth.items], [0, 1, 2]
            )
            self.assertTrue(
                verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
            )

    def test_success_and_failure_leave_chain_state_untouched(self):
        log = _log(5)
        head, root, entries = log.head, log.merkle_root(), log.entries()
        with self.assertRaises(IndexError):
            log.signed_auth_audit_bundle([9], _SEED_A)
        log.signed_auth_audit_bundle((0, 2), _SEED_A)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(len(log), 5)
        self.assertTrue(log.verify())

    def test_alternate_hash_algorithm(self):
        bundle = _issue(indices=(2, 0), n=3, hash_name="sha512")
        self.assertEqual(bundle.auth.hash_name, "sha512")
        self.assertEqual(bundle.audit.batch[0], "sha512")
        self.assertEqual(
            bundle.auth.verifier.verifier.hash_name, "sha512"
        )
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )


class VerifySignedAuthAuditBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_genuine_bundle_verifies(self):
        bundle = _issue()
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, self.public_key)
        )

    def test_empty_selection_still_checks_the_verifier_signature(self):
        # No per-item results can pass vacuously: the signed stage-0
        # material itself must verify.
        bundle = _issue(indices=())
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, self.public_key)
        )
        twin = _log(5).signed_auth_audit_bundle((), _SEED_B)
        self.assertFalse(
            verify_signed_auth_audit_bundle(twin, self.public_key)
        )

    def test_empty_snapshot_verifies(self):
        bundle = _issue(indices=(), size=0, n=3)
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, self.public_key)
        )

    def test_untrusted_key_returns_false(self):
        bundle = _issue()
        self.assertFalse(
            verify_signed_auth_audit_bundle(bundle, self.other_public_key)
        )

    def test_tampered_tag_returns_false(self):
        bundle = _issue()
        entry, tag = bundle.auth.items[1]
        bad_tag = AuthTag(tag.stage, bytes([tag.tag[0] ^ 1]) + tag.tag[1:])
        items = bundle.auth.items[:1] + ((entry, bad_tag),) + bundle.auth.items[2:]
        forged_auth = SignedAuthBundle(
            bundle.auth.verifier, bundle.auth.hash_name, items
        )
        forged = SignedAuthAuditBundle(forged_auth, bundle.audit)
        self.assertFalse(
            verify_signed_auth_audit_bundle(forged, self.public_key)
        )

    def test_tampered_verifier_signature_returns_false(self):
        bundle = _issue()
        forged_verifier = SignedVerifier(
            1, bundle.auth.verifier.verifier, b"\x00" * 64
        )
        forged_auth = SignedAuthBundle(
            forged_verifier, bundle.auth.hash_name, bundle.auth.items
        )
        forged = SignedAuthAuditBundle(forged_auth, bundle.audit)
        self.assertFalse(
            verify_signed_auth_audit_bundle(forged, self.public_key)
        )

    def test_tampered_audit_checkpoint_returns_false(self):
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
        forged_audit = SignedAuditBatch(bundle.audit.batch, forged_checkpoint)
        forged = SignedAuthAuditBundle(bundle.auth, forged_audit)
        self.assertFalse(
            verify_signed_auth_audit_bundle(forged, self.public_key)
        )

    def test_packages_individually_valid_but_entries_differ(self):
        # Same signing key and algorithm on both sides, but the two logs
        # hold different payloads, so the entry the auth package tags at
        # index 0 is not the entry the audit package carries there.
        auth = _log(5, prefix="record").signed_auth_bundle((0, 2), _SEED_A)
        other = _log(5, prefix="other")
        audit = other.signed_audit_batch((0, 2), _SEED_A)
        # Both halves verify on their own ...
        self.assertEqual(
            verify_signed_auth_bundle(auth, self.public_key), (True, True)
        )
        self.assertTrue(verify_signed_audit_batch(audit, self.public_key))
        # ... yet the combined bundle must not.
        bundle = SignedAuthAuditBundle(auth, audit)
        self.assertFalse(
            verify_signed_auth_audit_bundle(bundle, self.public_key)
        )

    def test_authenticated_index_missing_from_audit_returns_false(self):
        auth = _log(5).signed_auth_bundle((2,), _SEED_A)
        wider = _log(6)
        audit = wider.signed_audit_batch((0,), _SEED_A)  # carries 0 and 5
        self.assertTrue(verify_signed_audit_batch(audit, self.public_key))
        self.assertFalse(
            verify_signed_auth_audit_bundle(
                SignedAuthAuditBundle(auth, audit), self.public_key
            )
        )

    def test_algorithm_mismatch_between_packages_returns_false(self):
        auth = _log(3, hash_name="sha256").signed_auth_bundle((0,), _SEED_A)
        other = AuditLog(hash_name="sha512")
        other.append("record-0")
        audit = other.signed_audit_batch((0,), _SEED_A)
        self.assertTrue(verify_signed_audit_batch(audit, self.public_key))
        self.assertFalse(
            verify_signed_auth_audit_bundle(
                SignedAuthAuditBundle(auth, audit), self.public_key
            )
        )

    def test_type_errors(self):
        for bad in (None, "bundle", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                verify_signed_auth_audit_bundle(bad, self.public_key)
        bundle = _issue()
        for bad_key in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError):
                verify_signed_auth_audit_bundle(bundle, bad_key)

    def test_public_key_length_raises_value_error(self):
        bundle = _issue()
        for bad_key in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                verify_signed_auth_audit_bundle(bundle, bad_key)

    def test_bypassed_container_fields_raise_type_error(self):
        bundle = _issue()
        for field, value in (
            ("auth", "not-a-bundle"),
            ("audit", "not-a-batch"),
        ):
            forged = SignedAuthAuditBundle.__new__(SignedAuthAuditBundle)
            object.__setattr__(forged, "auth", bundle.auth)
            object.__setattr__(forged, "audit", bundle.audit)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                verify_signed_auth_audit_bundle(forged, self.public_key)

    def test_call_is_read_only(self):
        bundle = _issue()
        before = encode_signed_auth_audit_bundle(bundle)
        verify_signed_auth_audit_bundle(bundle, self.public_key)
        self.assertEqual(encode_signed_auth_audit_bundle(bundle), before)


class EncodeSignedAuthAuditBundleTest(unittest.TestCase):
    def test_byte_layout(self):
        bundle = _issue()
        expected = (
            MAGIC
            + u64(1)
            + blob(encode_signed_auth_bundle(bundle.auth))
            + blob(encode_signed_audit_batch(bundle.audit))
        )
        self.assertEqual(encode_signed_auth_audit_bundle(bundle), expected)

    def test_starts_with_declared_magic(self):
        self.assertTrue(
            encode_signed_auth_audit_bundle(_issue()).startswith(
                b"auditchain/auth-audit/v1\0"
            )
        )

    def test_deterministic_and_read_only(self):
        bundle = _issue()
        encoded = encode_signed_auth_audit_bundle(bundle)
        self.assertEqual(encoded, encode_signed_auth_audit_bundle(bundle))

    def test_type_errors(self):
        for bad in (None, "bundle", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                encode_signed_auth_audit_bundle(bad)

    def test_bypassed_container_fields_raise_type_error(self):
        bundle = _issue()
        for field, value in (
            ("auth", "not-a-bundle"),
            ("audit", "not-a-batch"),
        ):
            forged = SignedAuthAuditBundle.__new__(SignedAuthAuditBundle)
            object.__setattr__(forged, "auth", bundle.auth)
            object.__setattr__(forged, "audit", bundle.audit)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_signed_auth_audit_bundle(forged)


class DecodeSignedAuthAuditBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, bundle):
        data = encode_signed_auth_audit_bundle(bundle)
        decoded = decode_signed_auth_audit_bundle(data)
        self.assertEqual(decoded, bundle)
        self.assertEqual(decoded.auth, bundle.auth)
        self.assertEqual(decoded.audit, bundle.audit)
        self.assertIsInstance(decoded, SignedAuthAuditBundle)
        self.assertEqual(encode_signed_auth_audit_bundle(decoded), data)
        return decoded

    def test_roundtrip(self):
        decoded = self.roundtrip(_issue())
        self.assertTrue(
            verify_signed_auth_audit_bundle(decoded, self.public_key)
        )

    def test_roundtrip_empty_selection(self):
        decoded = self.roundtrip(_issue(indices=()))
        self.assertEqual(decoded.auth.items, ())

    def test_roundtrip_empty_snapshot(self):
        decoded = self.roundtrip(_issue(indices=(), size=0, n=3))
        self.assertEqual(decoded.audit.batch[1], 0)

    def test_roundtrip_explicit_size(self):
        self.roundtrip(_issue(indices=(1, 2), size=4, n=6))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            decoded = self.roundtrip(_issue(indices=(0, 2), n=3, hash_name=hash_name))
            self.assertEqual(decoded.auth.hash_name, hash_name)
            self.assertTrue(
                verify_signed_auth_audit_bundle(decoded, self.public_key)
            )

    def test_persistence_across_process_boundary(self):
        data = bytes(encode_signed_auth_audit_bundle(_issue()))
        restored = decode_signed_auth_audit_bundle(data)
        self.assertTrue(
            verify_signed_auth_audit_bundle(restored, self.public_key)
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_auth_audit_bundle(_issue())
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_signed_auth_audit_bundle(bad)

    def test_bad_magic(self):
        data = encode_signed_auth_audit_bundle(_issue())
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(b"")
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(MAGIC[:-1])
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(
                b"auditchain/signed-auth-bundle/v1\0" + data[len(MAGIC):]
            )

    def test_bad_version(self):
        bundle = _issue()
        data = MAGIC + u64(2) + encode_signed_auth_audit_bundle(bundle)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(data)

    def test_truncation(self):
        data = encode_signed_auth_audit_bundle(_issue())
        for cut in (
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError):
                decode_signed_auth_audit_bundle(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_signed_auth_audit_bundle(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_auth_audit_bundle(_issue())
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_signed_auth_audit_bundle(data + extra)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"x" * 16
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(data)

    def test_illegal_nested_encodings(self):
        bundle = _issue()
        auth_blob = encode_signed_auth_bundle(bundle.auth)
        audit_blob = encode_signed_audit_batch(bundle.audit)
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(
                MAGIC + u64(1) + blob(b"garbage") + blob(audit_blob)
            )
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(
                MAGIC + u64(1) + blob(auth_blob) + blob(b"garbage")
            )
        # The two blobs swapped.
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(
                MAGIC + u64(1) + blob(audit_blob) + blob(auth_blob)
            )

    def test_nested_hash_algorithm_mismatch(self):
        bundle = _issue(indices=(0,), n=3, hash_name="sha256")
        auth_blob = encode_signed_auth_bundle(bundle.auth)
        other = AuditLog(hash_name="sha512")
        other.append("record-0")
        other_audit = other.signed_audit_batch((0,), _SEED_A)
        audit_blob = encode_signed_audit_batch(other_audit)
        data = MAGIC + u64(1) + blob(auth_blob) + blob(audit_blob)
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(data)

    def test_wrong_signature_decodes_but_verifies_false(self):
        bundle = _issue(indices=(0,), n=3, seed=_SEED_B)
        decoded = decode_signed_auth_audit_bundle(
            encode_signed_auth_audit_bundle(bundle)
        )
        self.assertFalse(
            verify_signed_auth_audit_bundle(decoded, self.public_key)
        )
        self.assertTrue(
            verify_signed_auth_audit_bundle(decoded, self.other_public_key)
        )

    def test_decode_is_read_only(self):
        bundle = _issue()
        data = encode_signed_auth_audit_bundle(bundle)
        decode_signed_auth_audit_bundle(data)
        self.assertEqual(encode_signed_auth_audit_bundle(bundle), data)

    def test_nested_decoders_match_existing_codecs(self):
        bundle = _issue()
        decoded = decode_signed_auth_audit_bundle(
            encode_signed_auth_audit_bundle(bundle)
        )
        self.assertEqual(
            decoded.auth, decode_signed_auth_bundle(encode_signed_auth_bundle(bundle.auth))
        )
        self.assertEqual(
            decoded.audit,
            decode_signed_audit_batch(encode_signed_audit_batch(bundle.audit)),
        )


if __name__ == "__main__":
    unittest.main()
