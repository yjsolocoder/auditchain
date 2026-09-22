import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    Entry,
    SignedAuditBatch,
    SignedAuthAuditBundle,
    SignedAuthBundle,
    SignedVerifier,
    decode_signed_auth_audit_bundle,
    encode_signed_auth_audit_bundle,
    encode_signed_audit_batch,
    encode_signed_auth_bundle,
    verify_signed_auth_audit_bundle,
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


def _fresh(n=5, key=_KEY, hash_name="sha256"):
    # The one-shot verifier export is consumed on every issuance, so every
    # bundle needs a fresh stage-0 log with identical contents.
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"record-{record}")
    return log


def _bundle(seed=_SEED_A, key=_KEY, hash_name="sha256",
            indices=(0, 2, 4), records=5, size=None):
    log = _fresh(records, key, hash_name)
    return log.signed_auth_audit_bundle(indices, seed, size)


class SignedAuthAuditBundleTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        bundle = _bundle()
        again = SignedAuthAuditBundle(bundle.auth, bundle.audit)
        self.assertEqual(bundle, again)
        self.assertEqual(bundle.auth, again.auth)
        self.assertEqual(bundle.audit, again.audit)
        self.assertIsInstance(bundle.auth, SignedAuthBundle)
        self.assertIsInstance(bundle.audit, SignedAuditBatch)
        self.assertNotEqual(bundle, _bundle(indices=(1,)))

    def test_frozen(self):
        bundle = _bundle()
        for field in ("auth", "audit"):
            with self.assertRaises(Exception):
                setattr(bundle, field, None)

    def test_container_type_errors(self):
        bundle = _bundle()
        with self.assertRaises(TypeError):
            SignedAuthAuditBundle("not-an-auth-bundle", bundle.audit)
        with self.assertRaises(TypeError):
            SignedAuthAuditBundle(bundle.auth, "not-an-audit-batch")


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

    def test_returns_frozen_bundle_of_the_two_packages(self):
        bundle = _fresh().signed_auth_audit_bundle((4, 0, 2), _SEED_A)
        self.assertIsInstance(bundle, SignedAuthAuditBundle)
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [0, 2, 4]
        )
        # The audit half carries the selection plus the snapshot's last
        # entry (index size - 1), in ascending order.
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [0, 2, 4]
        )

    def test_equals_two_step_issuance(self):
        combo = _fresh(5).signed_auth_audit_bundle((0, 2, 4), _SEED_A)
        # The auth half is byte-for-byte what signed_auth_bundle produces on
        # an equivalent fresh log, and the audit half what
        # signed_audit_batch produces on another equivalent fresh log.
        self.assertEqual(
            combo.auth,
            _fresh(5).signed_auth_bundle((0, 2, 4), _SEED_A),
        )
        self.assertEqual(
            combo.audit,
            _fresh(5).signed_audit_batch((0, 2, 4), _SEED_A),
        )

    def test_audit_automatically_appends_last_snapshot_entry(self):
        # Selecting a strict subset still audits the last entry; selecting
        # it explicitly does not duplicate it.
        bundle = _fresh(5).signed_auth_audit_bundle((1,), _SEED_A)
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [1, 4]
        )
        bundle = _fresh(5).signed_auth_audit_bundle((1, 4), _SEED_A)
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [1, 4]
        )

    def test_empty_selection_audits_last_entry_without_advancing_stage(self):
        log = _fresh(3)
        bundle = log.signed_auth_audit_bundle((), _SEED_A)
        self.assertEqual(bundle.auth.items, ())
        self.assertEqual(log.stage, 0)
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [2]
        )
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )

    def test_size_parameter_selects_the_snapshot(self):
        log = _fresh(6)
        bundle = log.signed_auth_audit_bundle((0, 1), _SEED_A, size=4)
        self.assertEqual(bundle.audit.batch[1], 4)
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [0, 1, 3]
        )
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )

    def test_size_defaults_to_current_length(self):
        log = _fresh(5)
        bundle = log.signed_auth_audit_bundle((0,), _SEED_A)
        self.assertEqual(bundle.audit.batch[1], 5)
        self.assertEqual(bundle.audit.checkpoint.size, 5)

    def test_empty_snapshot(self):
        log = _fresh(2)
        bundle = log.signed_auth_audit_bundle((), _SEED_A, size=0)
        self.assertEqual(bundle.audit.batch[1], 0)
        self.assertEqual(bundle.audit.batch[3], ())
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )

    def test_indices_must_lie_inside_the_selected_snapshot(self):
        log = _fresh(5)
        # size=3: index 3 is retained in the log but outside the snapshot.
        with self.assertRaises(IndexError):
            log.signed_auth_audit_bundle((0, 3), _SEED_A, size=3)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_bundle((5,), _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_bundle((-1,), _SEED_A)

    def test_stages_and_tags_match_consecutive_auth(self):
        log = _fresh(5)
        bundle = log.signed_auth_audit_bundle((4, 0, 2), _SEED_A)
        self.assertEqual(
            [tag.stage for _, tag in bundle.auth.items], [0, 1, 2]
        )
        reference = _fresh(5)
        reference.export_signed_verifier(_SEED_A)
        expected = tuple(
            (reference.entry(i), reference.auth(i)) for i in (0, 2, 4)
        )
        self.assertEqual(bundle.auth.items, expected)
        self.assertEqual(log.stage, 3)
        self.assertEqual(sorted(log._tags), [0, 2, 4])

    def test_success_consumes_the_shared_one_shot_eligibility(self):
        log = _fresh(5)
        log.signed_auth_audit_bundle((1,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((2,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_bundle((2,), _SEED_A)
        with self.assertRaises(ValueError):
            log.export_verifier()
        with self.assertRaises(ValueError):
            log.export_signed_verifier(_SEED_A)

    def test_prior_export_or_evolution_disqualifies(self):
        log = _fresh(3)
        log.export_verifier()
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((0,), _SEED_A)
        log = _fresh(3)
        log.export_signed_verifier(_SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((0,), _SEED_A)
        log = _fresh(3)
        log.auth(0)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((1,), _SEED_A)
        log = _fresh(3)
        log.rotate_key()
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((0,), _SEED_A)

    def test_keyless_mode_raises_value_error(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((), _SEED_A)

    def test_private_key_errors(self):
        log = _fresh(3)
        for bad in ("0" * 32, bytearray(_SEED_A), memoryview(_SEED_A), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                log.signed_auth_audit_bundle((0,), bad)
        for bad in (b"", _SEED_A[:-1], _SEED_A + b"\x00"):
            with self.assertRaises(ValueError):
                log.signed_auth_audit_bundle((0,), bad)

    def test_indices_type_errors(self):
        log = _fresh(3)
        for bad in (5, None, ["0"], [1.0], [True], [0, False]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                log.signed_auth_audit_bundle(bad, _SEED_A)

    def test_size_type_errors(self):
        log = _fresh(3)
        for bad in (1.0, True, "3"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                log.signed_auth_audit_bundle((0,), _SEED_A, bad)

    def test_duplicate_and_out_of_range_size_raise_value_error(self):
        log = _fresh(3)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle([1, 2, 1], _SEED_A)
        for bad in (-1, 4):
            with self.assertRaises(ValueError):
                log.signed_auth_audit_bundle((0,), _SEED_A, bad)

    def test_pruned_snapshot_raises_value_error(self):
        log = _fresh(6)
        log.prune(2, log.seal(2))
        # A pruned-away snapshot is only reachable with an empty selection:
        # every index in [retain_from, size) would be out of range first.
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((), _SEED_A, size=1)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_bundle((1,), _SEED_A, size=1)
        # A retained snapshot on the pruned log works and starts at stage 0.
        bundle = log.signed_auth_audit_bundle((2, 5), _SEED_A)
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [2, 5]
        )
        self.assertEqual(
            [tag.stage for _, tag in bundle.auth.items], [0, 1]
        )
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )

    def test_stage_capacity_raises_value_error(self):
        log = _fresh(3)
        log._stage = (1 << 64) - 1
        with self.assertRaises(ValueError):
            log.signed_auth_audit_bundle((0,), _SEED_A)

    def test_failure_is_atomic(self):
        for call, error in (
            (lambda log: log.signed_auth_audit_bundle(["0"], _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_bundle([True], _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_bundle(5, _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_bundle([0, 0], _SEED_A), ValueError),
            (lambda log: log.signed_auth_audit_bundle([9], _SEED_A), IndexError),
            (lambda log: log.signed_auth_audit_bundle([-1], _SEED_A), IndexError),
            (lambda log: log.signed_auth_audit_bundle([0], "0" * 32), TypeError),
            (lambda log: log.signed_auth_audit_bundle([0], b"short"), ValueError),
            (lambda log: log.signed_auth_audit_bundle([0], _SEED_A, 9), ValueError),
        ):
            log = _fresh(5)
            before = self._snapshot(log)
            with self.assertRaises(error):
                call(log)
            self.assertEqual(self._snapshot(log), before)
            # Retry with the same selection works from a pristine stage 0.
            bundle = log.signed_auth_audit_bundle((0, 2, 4), _SEED_A)
            self.assertEqual(
                [tag.stage for _, tag in bundle.auth.items], [0, 1, 2]
            )
            self.assertTrue(
                verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
            )

    def test_failure_does_not_touch_chain_state(self):
        log = _fresh(5)
        head, root, entries = log.head, log.merkle_root(), log.entries()
        for call, error in (
            (lambda: log.signed_auth_audit_bundle([9], _SEED_A), IndexError),
            (lambda: log.signed_auth_audit_bundle([0, 0], _SEED_A), ValueError),
            (lambda: log.signed_auth_audit_bundle([0], b"bad"), ValueError),
        ):
            with self.assertRaises(error):
                call()
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertTrue(log.verify())

    def test_success_does_not_change_chain_state(self):
        log = _fresh(5)
        head, root, entries = log.head, log.merkle_root(), log.entries()
        log.signed_auth_audit_bundle((0, 2, 4), _SEED_A)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertTrue(log.verify())

    def test_alternate_hash_algorithm(self):
        bundle = _bundle(hash_name="sha512", indices=(1, 2), records=3)
        self.assertEqual(bundle.auth.hash_name, "sha512")
        self.assertEqual(bundle.auth.verifier.verifier.hash_name, "sha512")
        self.assertEqual(bundle.audit.batch[0], "sha512")
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )


class VerifySignedAuthAuditBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_genuine_bundle_verifies(self):
        bundle = _bundle()
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, self.public_key)
        )

    def test_empty_selection_still_requires_the_trusted_signature(self):
        bundle = _bundle(indices=())
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, self.public_key)
        )
        bundle_b = _bundle(seed=_SEED_B, indices=())
        self.assertFalse(
            verify_signed_auth_audit_bundle(bundle_b, self.public_key)
        )

    def test_untrusted_key_fails(self):
        bundle = _bundle(seed=_SEED_B)
        self.assertFalse(
            verify_signed_auth_audit_bundle(bundle, self.public_key)
        )
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, self.other_public_key)
        )

    def _with_audit_batch(self, bundle, batch):
        return SignedAuthAuditBundle(
            bundle.auth, SignedAuditBatch(batch, bundle.audit.checkpoint)
        )

    def test_tampered_audit_entry_at_auth_index_fails(self):
        bundle = _bundle()
        hash_name, size, root, entries, proof = bundle.audit.batch
        entry = entries[0]
        forged_entry = Entry(
            entry.index, b"forged", entry.previous_hash, entry.entry_hash
        )
        tampered = self._with_audit_batch(
            bundle, (hash_name, size, root, (forged_entry,) + entries[1:], proof)
        )
        self.assertFalse(
            verify_signed_auth_audit_bundle(tampered, self.public_key)
        )

    def test_tampered_unauthenticated_extra_audit_entry_fails(self):
        # The appended last entry carries no auth tag, but altering it still
        # breaks the audit batch's proof/head chain.
        bundle = _bundle(indices=(0, 2))
        hash_name, size, root, entries, proof = bundle.audit.batch
        self.assertEqual(entries[-1].index, 4)
        last = entries[-1]
        forged_last = Entry(
            last.index, b"forged", last.previous_hash, last.entry_hash
        )
        tampered = self._with_audit_batch(
            bundle, (hash_name, size, root, entries[:-1] + (forged_last,), proof)
        )
        self.assertFalse(
            verify_signed_auth_audit_bundle(tampered, self.public_key)
        )

    def test_tampered_auth_tag_fails(self):
        bundle = _bundle()
        entry, tag = bundle.auth.items[1]
        bad_tag = AuthTag(tag.stage, bytes([tag.tag[0] ^ 1]) + tag.tag[1:])
        auth = SignedAuthBundle(
            bundle.auth.verifier,
            bundle.auth.hash_name,
            bundle.auth.items[:1] + ((entry, bad_tag),) + bundle.auth.items[2:],
        )
        tampered = SignedAuthAuditBundle(auth, bundle.audit)
        self.assertFalse(
            verify_signed_auth_audit_bundle(tampered, self.public_key)
        )

    def test_tampered_verifier_signature_fails(self):
        bundle = _bundle()
        forged_verifier = SignedVerifier(
            1, bundle.auth.verifier.verifier, b"\x00" * 64
        )
        auth = SignedAuthBundle(
            forged_verifier, bundle.auth.hash_name, bundle.auth.items
        )
        tampered = SignedAuthAuditBundle(auth, bundle.audit)
        self.assertFalse(
            verify_signed_auth_audit_bundle(tampered, self.public_key)
        )

    def test_packages_signed_by_different_keys_fail(self):
        bundle_a = _bundle(seed=_SEED_A)
        bundle_b = _bundle(seed=_SEED_B)
        self.assertFalse(
            verify_signed_auth_audit_bundle(
                SignedAuthAuditBundle(bundle_b.auth, bundle_a.audit),
                self.public_key,
            )
        )
        self.assertFalse(
            verify_signed_auth_audit_bundle(
                SignedAuthAuditBundle(bundle_a.auth, bundle_b.audit),
                self.public_key,
            )
        )

    def test_algorithm_conflict_fails(self):
        bundle = _bundle(hash_name="sha256")
        other_audit = _fresh(3, hash_name="sha512").signed_audit_batch(
            (0,), _SEED_A
        )
        mixed = SignedAuthAuditBundle(bundle.auth, other_audit)
        self.assertFalse(
            verify_signed_auth_audit_bundle(mixed, self.public_key)
        )

    def test_verifier_auth_algorithm_conflict_fails_even_when_empty(self):
        # A hand-built pair (decode rejects this combination) whose auth
        # bundle names a different algorithm than its signed verifier must
        # fail even with no items, where verify_signed_auth_bundle returns
        # () on its own.
        bundle = _bundle(hash_name="sha256", indices=())
        verifier = SignedVerifier(
            bundle.auth.verifier.version,
            bundle.auth.verifier.verifier,
            bundle.auth.verifier.signature,
        )
        auth = SignedAuthBundle(verifier, "sha512", ())
        mixed = SignedAuthAuditBundle(auth, bundle.audit)
        self.assertFalse(
            verify_signed_auth_audit_bundle(mixed, self.public_key)
        )

    def test_type_errors(self):
        bundle = _bundle()
        for bad in (None, "bundle", b"bytes", 1, (1, 2), object(), bundle.auth):
            with self.assertRaises(TypeError):
                verify_signed_auth_audit_bundle(bad, self.public_key)
        for bad_key in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError):
                verify_signed_auth_audit_bundle(bundle, bad_key)

    def test_public_key_length_raises_value_error(self):
        bundle = _bundle()
        for bad_key in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                verify_signed_auth_audit_bundle(bundle, bad_key)

    def test_bypassed_container_fields_raise_type_error(self):
        bundle = _bundle()
        for field, value in (
            ("auth", "not-an-auth-bundle"),
            ("audit", "not-an-audit-batch"),
        ):
            forged = SignedAuthAuditBundle.__new__(SignedAuthAuditBundle)
            object.__setattr__(forged, "auth", bundle.auth)
            object.__setattr__(forged, "audit", bundle.audit)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                verify_signed_auth_audit_bundle(forged, self.public_key)

    def test_call_is_read_only(self):
        bundle = _bundle()
        before = encode_signed_auth_audit_bundle(bundle)
        verify_signed_auth_audit_bundle(bundle, self.public_key)
        self.assertEqual(encode_signed_auth_audit_bundle(bundle), before)


class EncodeSignedAuthAuditBundleTest(unittest.TestCase):
    def test_byte_layout(self):
        bundle = _bundle()
        expected = (
            MAGIC
            + u64(1)
            + blob(encode_signed_auth_bundle(bundle.auth))
            + blob(encode_signed_audit_batch(bundle.audit))
        )
        self.assertEqual(encode_signed_auth_audit_bundle(bundle), expected)

    def test_encode_is_deterministic(self):
        bundle = _bundle()
        self.assertEqual(
            encode_signed_auth_audit_bundle(bundle),
            encode_signed_auth_audit_bundle(bundle),
        )

    def test_type_errors(self):
        bundle = _bundle()
        for bad in (None, "bundle", b"bytes", 1, (), bundle.auth, bundle.audit):
            with self.assertRaises(TypeError):
                encode_signed_auth_audit_bundle(bad)

    def test_bypassed_container_fields_raise_type_error(self):
        bundle = _bundle()
        for field, value in (
            ("auth", "not-an-auth-bundle"),
            ("audit", "not-an-audit-batch"),
        ):
            forged = SignedAuthAuditBundle.__new__(SignedAuthAuditBundle)
            object.__setattr__(forged, "auth", bundle.auth)
            object.__setattr__(forged, "audit", bundle.audit)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_signed_auth_audit_bundle(forged)

    def test_call_is_read_only(self):
        bundle = _bundle()
        before = encode_signed_auth_audit_bundle(bundle)
        encode_signed_auth_audit_bundle(bundle)
        self.assertEqual(encode_signed_auth_audit_bundle(bundle), before)


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
        bundle = self.roundtrip(_bundle())
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, self.public_key)
        )

    def test_roundtrip_empty_selection(self):
        bundle = self.roundtrip(_bundle(indices=()))
        self.assertEqual(bundle.auth.items, ())
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, self.public_key)
        )

    def test_roundtrip_explicit_size_and_alternate_hash(self):
        bundle = self.roundtrip(_bundle(indices=(0, 1), records=6, size=4))
        self.assertEqual(bundle.audit.batch[1], 4)
        for hash_name in ("sha512", "sha3_256"):
            bundle = self.roundtrip(
                _bundle(hash_name=hash_name, indices=(0,), records=3)
            )
            self.assertEqual(bundle.auth.hash_name, hash_name)
            self.assertTrue(
                verify_signed_auth_audit_bundle(bundle, self.public_key)
            )

    def test_persistence_across_process_boundary(self):
        data = encode_signed_auth_audit_bundle(_bundle())
        restored = decode_signed_auth_audit_bundle(bytes(data))
        self.assertEqual(restored, _bundle())
        self.assertTrue(
            verify_signed_auth_audit_bundle(restored, self.public_key)
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_auth_audit_bundle(_bundle())
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_signed_auth_audit_bundle(bad)

    def test_bad_magic(self):
        data = encode_signed_auth_audit_bundle(_bundle())
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
        data = encode_signed_auth_audit_bundle(_bundle())
        bad = MAGIC + u64(2) + data[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(bad)

    def test_truncation(self):
        data = encode_signed_auth_audit_bundle(_bundle())
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_signed_auth_audit_bundle(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_auth_audit_bundle(_bundle())
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_signed_auth_audit_bundle(data + extra)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"x" * 16
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(data)

    def test_illegal_nested_encodings(self):
        bundle = _bundle()
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

    def test_nested_algorithm_conflict_raises_value_error(self):
        bundle = _bundle(hash_name="sha256")
        auth_blob = encode_signed_auth_bundle(bundle.auth)
        other_audit = _fresh(3, hash_name="sha512").signed_audit_batch(
            (0,), _SEED_A
        )
        audit_blob = encode_signed_audit_batch(other_audit)
        data = MAGIC + u64(1) + blob(auth_blob) + blob(audit_blob)
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_bundle(data)

    def test_wrong_signature_decodes_but_verifies_false(self):
        bundle = _bundle(seed=_SEED_B)
        decoded = self.roundtrip(bundle)
        self.assertFalse(
            verify_signed_auth_audit_bundle(decoded, self.public_key)
        )
        self.assertTrue(
            verify_signed_auth_audit_bundle(decoded, self.other_public_key)
        )

    def test_call_is_read_only(self):
        bundle = _bundle()
        data = encode_signed_auth_audit_bundle(bundle)
        decode_signed_auth_audit_bundle(data)
        self.assertEqual(encode_signed_auth_audit_bundle(bundle), data)


if __name__ == "__main__":
    unittest.main()
