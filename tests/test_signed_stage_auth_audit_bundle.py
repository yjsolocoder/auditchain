import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    SignedAuditBatch,
    SignedStageAuthAuditBundle,
    SignedStageAuthBundle,
    SignedStageVerifier,
    verify_signed_audit_batch,
    verify_signed_stage_auth_audit_bundle,
    verify_signed_stage_auth_bundle,
    verify_signed_stage_verifier,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"


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


class SignedStageAuthAuditBundleConstructionTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        bundle = _issue()
        again = SignedStageAuthAuditBundle(bundle.auth, bundle.audit)
        self.assertEqual(bundle, again)
        self.assertIsInstance(bundle.auth, SignedStageAuthBundle)
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
            SignedStageAuthAuditBundle("not-a-bundle", bundle.audit)
        with self.assertRaises(TypeError):
            SignedStageAuthAuditBundle(bundle.auth, "not-a-batch")


class SignedStageAuthAuditBundleIssuanceTest(unittest.TestCase):
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
        bundle = log.signed_stage_auth_audit_bundle((4, 0), _SEED_A)
        self.assertIsInstance(bundle, SignedStageAuthAuditBundle)
        self.assertIsInstance(bundle.auth, SignedStageAuthBundle)
        # The auth half tags exactly the selected, deduplicated indices.
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [0, 4]
        )
        self.assertEqual(bundle.auth.hash_name, "sha256")
        self.assertIsInstance(bundle.auth.verifier, SignedStageVerifier)
        self.assertEqual(bundle.auth.verifier.verifier.stage, 1)
        # The audit half carries the selected entries plus the snapshot's
        # last entry (index size - 1) automatically.
        _, audit_size, _, audit_entries, _ = bundle.audit.batch
        self.assertEqual(audit_size, 5)
        self.assertEqual([entry.index for entry in audit_entries], [0, 4])
        self.assertEqual(bundle.audit.checkpoint.size, 5)
        # Index 4 was both selected and the last entry: no duplicate.
        self.assertEqual(len(audit_entries), 2)

    def test_audit_appends_unselected_last_entry_without_auth_domain(self):
        bundle = _issue(indices=(1,), records=5)
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [1]
        )
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [1, 4]
        )
        # The appended last entry carries no auth tag/signing domain.
        self.assertEqual(len(bundle.auth.items), 1)

    def test_auth_half_is_byte_for_byte_stage_batch_issuance(self):
        log = _log(5)
        bundle = log.signed_stage_auth_audit_bundle((4, 0, 2), _SEED_A)
        twin = _log(5)
        auth = twin.signed_stage_auth_bundle((4, 0, 2), _SEED_A)
        audit = twin.signed_audit_batch((4, 0, 2), _SEED_A)
        self.assertEqual(bundle.auth, auth)
        self.assertEqual(bundle.audit, audit)
        self.assertEqual(bundle, SignedStageAuthAuditBundle(auth, audit))

    def test_first_tag_at_delivery_stage_and_commit(self):
        log = _log(5, evolve=2)
        delivery_stage = log.stage
        bundle = log.signed_stage_auth_audit_bundle((4, 0, 2), _SEED_A)
        self.assertEqual(
            [tag.stage for _, tag in bundle.auth.items],
            [delivery_stage, delivery_stage + 1, delivery_stage + 2],
        )
        self.assertEqual(log.stage, delivery_stage + 3)
        self.assertEqual(sorted(log._tags), [0, 2, 4])

    def test_items_match_consecutive_auth_from_same_state(self):
        log = _log(5, evolve=2)
        bundle = log.signed_stage_auth_audit_bundle((4, 0, 2), _SEED_A)
        reference = _log(5, evolve=2)
        reference.export_signed_stage_verifier(_SEED_A)
        expected = tuple(
            (reference.entry(i), reference.auth(i)) for i in (0, 2, 4)
        )
        self.assertEqual(bundle.auth.items, expected)

    def test_accepts_generator_and_sorts_ascending(self):
        bundle = _log(5).signed_stage_auth_audit_bundle(
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
        bundle = log.signed_stage_auth_audit_bundle((1,), _SEED_A, size=3)
        self.assertEqual(bundle.audit.checkpoint.size, 3)
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [1, 2]
        )
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [1]
        )

    def test_size_defaults_to_current_length(self):
        bundle = _issue(indices=(1,), records=5)
        self.assertEqual(bundle.audit.batch[1], 5)
        self.assertEqual(bundle.audit.checkpoint.size, 5)

    def test_empty_selection_delivers_material_stage_unmoved(self):
        log = _log(5)
        stage = log.stage
        bundle = log.signed_stage_auth_audit_bundle((), _SEED_A)
        self.assertEqual(bundle.auth.items, ())
        # The audit still carries the last snapshot entry.
        self.assertEqual(
            [entry.index for entry in bundle.audit.batch[3]], [4]
        )
        # No tags minted: the stage does not advance.
        self.assertEqual(log.stage, stage)
        # The signed stage material is still delivered.
        self.assertEqual(bundle.auth.verifier.verifier.stage, stage)
        self.assertTrue(
            verify_signed_stage_verifier(bundle.auth.verifier, _public_key(_SEED_A))
        )
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )

    def test_empty_selection_consumes_no_one_shot_eligibility(self):
        log = _log(5)
        log.signed_stage_auth_audit_bundle((), _SEED_A)
        self.assertFalse(log._verifier_exported)
        # Repeated issuance still works from the same delivery stage.
        again = log.signed_stage_auth_audit_bundle((), _SEED_A)
        self.assertEqual(again.auth.verifier.verifier.stage, 1)

    def test_empty_snapshot(self):
        log = _log(3)
        bundle = log.signed_stage_auth_audit_bundle((), _SEED_A, size=0)
        self.assertEqual(bundle.auth.items, ())
        hash_name, size, root, entries, proof = bundle.audit.batch
        self.assertEqual(size, 0)
        self.assertEqual(entries, ())
        self.assertEqual(proof, ())
        self.assertEqual(bundle.audit.checkpoint.size, 0)
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )
        # No index is eligible inside an empty snapshot.
        with self.assertRaises(IndexError):
            log.signed_stage_auth_audit_bundle((0,), _SEED_A, size=0)

    def test_issuance_is_repeatable_and_consumes_no_eligibility(self):
        log = _log(5)
        first = log.signed_stage_auth_audit_bundle((1,), _SEED_A)
        second = log.signed_stage_auth_audit_bundle((2,), _SEED_A)
        self.assertEqual(first.auth.verifier.verifier.stage, 1)
        self.assertEqual(second.auth.verifier.verifier.stage, 2)
        self.assertEqual(second.auth.items[0][1].stage, 2)
        self.assertEqual(log.stage, 3)
        self.assertFalse(log._verifier_exported)
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(second, _public_key(_SEED_A))
        )

    def test_initial_stage_raises_value_error(self):
        log = _log(5, evolve=0)
        before = self._snapshot(log)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_audit_bundle((0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_audit_bundle((), _SEED_A)
        self.assertEqual(self._snapshot(log), before)

    def test_keyless_mode_raises_value_error(self):
        log = AuditLog()
        for record in range(3):
            log.append(f"record-{record}")
        with self.assertRaises(ValueError):
            log.signed_stage_auth_audit_bundle((0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_audit_bundle((), _SEED_A)

    def test_private_key_type_errors(self):
        log = _log(5)
        for bad in ("0" * 32, bytearray(_SEED_A), memoryview(_SEED_A), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                log.signed_stage_auth_audit_bundle((0,), bad)

    def test_private_key_length_raises_value_error(self):
        log = _log(5)
        for bad in (b"", _SEED_A[:-1], _SEED_A + b"\x00"):
            with self.assertRaises(ValueError):
                log.signed_stage_auth_audit_bundle((0,), bad)

    def test_indices_type_errors(self):
        log = _log(5)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_audit_bundle(5, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_audit_bundle(None, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_audit_bundle(["0"], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_audit_bundle([1.0], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_audit_bundle([True], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_audit_bundle([0, False], _SEED_A)

    def test_size_type_error(self):
        log = _log(5)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_audit_bundle((0,), _SEED_A, size=True)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_audit_bundle((0,), _SEED_A, size=1.0)

    def test_duplicate_index_raises_value_error(self):
        with self.assertRaises(ValueError):
            _log(5).signed_stage_auth_audit_bundle([1, 2, 1], _SEED_A)

    def test_size_out_of_range_raises_value_error(self):
        log = _log(5)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_audit_bundle((0,), _SEED_A, size=6)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_audit_bundle((0,), _SEED_A, size=-1)

    def test_out_of_range_index_raises_index_error(self):
        log = _log(5)
        with self.assertRaises(IndexError):
            log.signed_stage_auth_audit_bundle([5], _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_stage_auth_audit_bundle([-1], _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_stage_auth_audit_bundle([3], _SEED_A, size=3)
        log.prune(2, log.seal(2))
        with self.assertRaises(IndexError):
            log.signed_stage_auth_audit_bundle([1, 3], _SEED_A)

    def test_unrebuildable_snapshot_raises_value_error(self):
        log = _log(6)
        log.prune(2, log.seal(2))
        # An empty selection reaches the rebuildability check.
        with self.assertRaises(ValueError):
            log.signed_stage_auth_audit_bundle((), _SEED_A, size=1)

    def test_pruned_log_selection(self):
        log = _log(6)
        log.prune(2, log.seal(2))
        bundle = log.signed_stage_auth_audit_bundle((5, 2), _SEED_A)
        self.assertEqual(
            [entry.index for entry, _ in bundle.auth.items], [2, 5]
        )
        self.assertEqual([tag.stage for _, tag in bundle.auth.items], [1, 2])
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )

    def test_stage_capacity_checked_before_signing(self):
        log = _log(3)
        log._stage = (1 << 64) - 1
        with self.assertRaises(ValueError):
            log.signed_stage_auth_audit_bundle((0,), _SEED_A)

    def test_failure_is_atomic(self):
        for call, error in (
            (lambda log: log.signed_stage_auth_audit_bundle(["0"], _SEED_A), TypeError),
            (lambda log: log.signed_stage_auth_audit_bundle([True], _SEED_A), TypeError),
            (lambda log: log.signed_stage_auth_audit_bundle(5, _SEED_A), TypeError),
            (lambda log: log.signed_stage_auth_audit_bundle([0, 0], _SEED_A), ValueError),
            (lambda log: log.signed_stage_auth_audit_bundle([9], _SEED_A), IndexError),
            (lambda log: log.signed_stage_auth_audit_bundle([-1], _SEED_A), IndexError),
            (lambda log: log.signed_stage_auth_audit_bundle([3], _SEED_A, size=3), IndexError),
            (lambda log: log.signed_stage_auth_audit_bundle([0], "0" * 32), TypeError),
            (lambda log: log.signed_stage_auth_audit_bundle([0], b"short"), ValueError),
            (lambda log: log.signed_stage_auth_audit_bundle([0], _SEED_A, size=6), ValueError),
            (lambda log: log.signed_stage_auth_audit_bundle((), _SEED_A, size=6), ValueError),
        ):
            log = _log(5)
            before = self._snapshot(log)
            with self.assertRaises(error):
                call(log)
            self.assertEqual(self._snapshot(log), before)
            # No key evolution happened: the retry delivers a bundle
            # starting at the same delivery stage.
            bundle = log.signed_stage_auth_audit_bundle((0, 2, 4), _SEED_A)
            self.assertEqual([tag.stage for _, tag in bundle.auth.items], [1, 2, 3])
            self.assertTrue(
                verify_signed_stage_auth_audit_bundle(bundle, _public_key(_SEED_A))
            )

    def test_failure_does_not_touch_chain_state(self):
        log = _log(5)
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        for call, error in (
            (lambda: log.signed_stage_auth_audit_bundle([9], _SEED_A), IndexError),
            (lambda: log.signed_stage_auth_audit_bundle([0, 0], _SEED_A), ValueError),
            (lambda: log.signed_stage_auth_audit_bundle([0], b"bad"), ValueError),
        ):
            with self.assertRaises(error):
                call()
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(len(log), 5)
        self.assertTrue(log.verify())

    def test_success_does_not_change_chain_state(self):
        log = _log(5)
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        log.signed_stage_auth_audit_bundle((0, 2, 4), _SEED_A)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(len(log), 5)
        self.assertTrue(log.verify())

    def test_same_state_same_seed_is_byte_for_byte_deterministic(self):
        first = _log(5).signed_stage_auth_audit_bundle((4, 0, 2), _SEED_A)
        second = _log(5).signed_stage_auth_audit_bundle((4, 0, 2), _SEED_A)
        self.assertEqual(first, second)
        self.assertEqual(first.auth, second.auth)
        self.assertEqual(first.audit, second.audit)

    def test_alternate_hash_algorithm(self):
        bundle = _issue(indices=(2, 0), records=3, hash_name="sha512")
        self.assertEqual(bundle.auth.hash_name, "sha512")
        self.assertEqual(bundle.audit.batch[0], "sha512")
        self.assertEqual(
            bundle.auth.verifier.verifier.hash_name, "sha512"
        )
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(bundle, _public_key(_SEED_A))
        )


class VerifySignedStageAuthAuditBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_genuine_bundle_verifies(self):
        bundle = _issue()
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(bundle, self.public_key)
        )

    def test_both_halves_verify_individually(self):
        bundle = _issue()
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle.auth, self.public_key),
            (True, True, True),
        )
        self.assertTrue(
            verify_signed_audit_batch(bundle.audit, self.public_key)
        )

    def test_empty_selection_still_checks_the_stage_signature(self):
        # No per-item results can pass vacuously: the signed stage
        # material itself must verify.
        bundle = _issue(indices=())
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(bundle, self.public_key)
        )
        twin = _log(5).signed_stage_auth_audit_bundle((), _SEED_B)
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(twin, self.public_key)
        )

    def test_empty_snapshot_verifies(self):
        bundle = _issue(indices=(), size=0, records=3)
        self.assertTrue(
            verify_signed_stage_auth_audit_bundle(bundle, self.public_key)
        )

    def test_untrusted_key_returns_false(self):
        bundle = _issue()
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(bundle, self.other_public_key)
        )

    def test_tampered_tag_returns_false(self):
        bundle = _issue()
        entry, tag = bundle.auth.items[1]
        bad_tag = AuthTag(tag.stage, bytes([tag.tag[0] ^ 1]) + tag.tag[1:])
        items = bundle.auth.items[:1] + ((entry, bad_tag),) + bundle.auth.items[2:]
        forged_auth = SignedStageAuthBundle(
            bundle.auth.verifier, bundle.auth.hash_name, items
        )
        forged = SignedStageAuthAuditBundle(forged_auth, bundle.audit)
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(forged, self.public_key)
        )

    def test_tampered_stage_verifier_signature_returns_false(self):
        bundle = _issue()
        forged_verifier = SignedStageVerifier(
            1, bundle.auth.verifier.verifier, b"\x00" * 64
        )
        forged_auth = SignedStageAuthBundle(
            forged_verifier, bundle.auth.hash_name, bundle.auth.items
        )
        forged = SignedStageAuthAuditBundle(forged_auth, bundle.audit)
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(forged, self.public_key)
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
        forged = SignedStageAuthAuditBundle(bundle.auth, forged_audit)
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(forged, self.public_key)
        )

    def test_tampered_proof_returns_false(self):
        bundle = _issue()
        hash_name, size, root, entries, proof = bundle.audit.batch
        if not proof:
            self.skipTest("batch proof unexpectedly empty")
        bad_node = bytes([proof[0][0] ^ 1]) + proof[0][1:]
        bad_proof = (bad_node,) + proof[1:]
        forged_audit = SignedAuditBatch(
            (hash_name, size, root, entries, bad_proof),
            bundle.audit.checkpoint,
        )
        forged = SignedStageAuthAuditBundle(bundle.auth, forged_audit)
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(forged, self.public_key)
        )

    def test_packages_individually_valid_but_entries_differ(self):
        # Same signing key and algorithm on both sides, but the two logs
        # hold different payloads, so the entry the auth package tags at
        # index 0 is not the entry the audit package carries there.
        auth = _log(5, prefix="record").signed_stage_auth_bundle((0, 2), _SEED_A)
        audit = _log(5, prefix="other").signed_audit_batch((0, 2), _SEED_A)
        # Both halves verify on their own ...
        self.assertEqual(
            verify_signed_stage_auth_bundle(auth, self.public_key), (True, True)
        )
        self.assertTrue(verify_signed_audit_batch(audit, self.public_key))
        # ... yet the combined bundle must not.
        bundle = SignedStageAuthAuditBundle(auth, audit)
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(bundle, self.public_key)
        )

    def test_authenticated_index_missing_from_audit_returns_false(self):
        auth = _log(6).signed_stage_auth_bundle((2,), _SEED_A)
        audit = _log(6).signed_audit_batch((0,), _SEED_A)  # carries 0 and 5
        self.assertTrue(verify_signed_audit_batch(audit, self.public_key))
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(
                SignedStageAuthAuditBundle(auth, audit), self.public_key
            )
        )

    def test_algorithm_mismatch_between_packages_returns_false(self):
        auth = _log(3, hash_name="sha256").signed_stage_auth_bundle(
            (0,), _SEED_A
        )
        other = AuditLog(key=_KEY, hash_name="sha512")
        other.append("record-0")
        other.rotate_key()
        audit = other.signed_audit_batch((0,), _SEED_A)
        self.assertTrue(verify_signed_audit_batch(audit, self.public_key))
        self.assertFalse(
            verify_signed_stage_auth_audit_bundle(
                SignedStageAuthAuditBundle(auth, audit), self.public_key
            )
        )

    def test_type_errors(self):
        for bad in (None, "bundle", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                verify_signed_stage_auth_audit_bundle(bad, self.public_key)
        bundle = _issue()
        for bad_key in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError):
                verify_signed_stage_auth_audit_bundle(bundle, bad_key)

    def test_public_key_length_raises_value_error(self):
        bundle = _issue()
        for bad_key in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                verify_signed_stage_auth_audit_bundle(bundle, bad_key)

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
                verify_signed_stage_auth_audit_bundle(forged, self.public_key)

    def test_call_is_read_only(self):
        bundle = _issue()
        snapshot = (bundle.auth, bundle.audit)
        verify_signed_stage_auth_audit_bundle(bundle, self.public_key)
        self.assertEqual((bundle.auth, bundle.audit), snapshot)


if __name__ == "__main__":
    unittest.main()
