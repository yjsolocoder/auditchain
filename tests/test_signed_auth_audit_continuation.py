import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    SignedAuditBatch,
    SignedAuthAuditBundle,
    SignedAuthAuditContinuation,
    SignedAuthBundle,
    SignedConsistency,
    SignedVerifier,
    encode_signed_auth_audit_bundle,
    encode_signed_consistency,
    verify_signed_auth_audit_bundle,
    verify_signed_auth_audit_continuation,
    verify_signed_consistency,
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


def _log(n=5, key=_KEY, hash_name="sha256", prefix="record"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _issue(old_size=2, indices=(0, 2), seed=_SEED_A, size=4, n=5, **kwargs):
    return _log(n, **kwargs).signed_auth_audit_continuation(
        old_size, indices, seed, size
    )


class SignedAuthAuditContinuationConstructionTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        receipt = _issue()
        again = SignedAuthAuditContinuation(receipt.bundle, receipt.consistency)
        self.assertEqual(receipt, again)
        self.assertIsInstance(receipt.bundle, SignedAuthAuditBundle)
        self.assertIsInstance(receipt.consistency, SignedConsistency)
        self.assertNotEqual(
            receipt, _issue(indices=(1,))
        )

    def test_frozen(self):
        receipt = _issue()
        for field in ("bundle", "consistency"):
            with self.assertRaises(Exception):
                setattr(receipt, field, None)

    def test_container_type_errors(self):
        receipt = _issue()
        with self.assertRaises(TypeError):
            SignedAuthAuditContinuation("not-a-bundle", receipt.consistency)
        with self.assertRaises(TypeError):
            SignedAuthAuditContinuation(receipt.bundle, "not-a-consistency")


class SignedAuthAuditContinuationIssuanceTest(unittest.TestCase):
    def _snapshot(self, log):
        return (
            log.stage,
            log._key,
            dict(log._tags),
            log.head,
            len(log),
            log._verifier_exported,
        )

    def test_bundle_fields_and_new_checkpoint_link(self):
        log = _log(6)
        receipt = log.signed_auth_audit_continuation(2, (4, 0), _SEED_A, size=5)
        # The bundle half is an ordinary SignedAuthAuditBundle at size 5.
        self.assertEqual(
            [entry.index for entry, _ in receipt.bundle.auth.items], [0, 4]
        )
        self.assertEqual(
            [entry.index for entry in receipt.bundle.audit.batch[3]], [0, 4]
        )
        self.assertEqual(receipt.bundle.audit.checkpoint.size, 5)
        # The consistency links old_size=2 to the new size=5 snapshot.
        self.assertEqual(receipt.consistency.old.size, 2)
        self.assertEqual(receipt.consistency.new.size, 5)
        # The decisive link: the consistency's new checkpoint is the audit
        # checkpoint itself, every field (including the signature) equal.
        self.assertEqual(
            receipt.consistency.new, receipt.bundle.audit.checkpoint
        )

    def test_audit_appends_unselected_last_entry_without_auth_domain(self):
        receipt = _issue(old_size=1, indices=(1,), size=5, n=5)
        self.assertEqual(
            [entry.index for entry, _ in receipt.bundle.auth.items], [1]
        )
        self.assertEqual(
            [entry.index for entry in receipt.bundle.audit.batch[3]], [1, 4]
        )
        # The continuation's new checkpoint matches that size-5 audit.
        self.assertEqual(receipt.consistency.new.size, 5)

    def test_equals_two_step_issuance(self):
        log = _log(6)
        receipt = log.signed_auth_audit_continuation(2, (4, 0, 2), _SEED_A, size=5)
        twin = _log(6)
        bundle = twin.signed_auth_audit_bundle((4, 0, 2), _SEED_A, size=5)
        consistency = twin.signed_consistency(2, _SEED_A, new_size=5)
        self.assertEqual(receipt.bundle, bundle)
        self.assertEqual(receipt.consistency, consistency)
        self.assertEqual(
            receipt, SignedAuthAuditContinuation(bundle, consistency)
        )

    def test_tags_run_from_stage_zero_and_commit(self):
        log = _log(6)
        receipt = log.signed_auth_audit_continuation(1, (4, 0, 2), _SEED_A, size=5)
        self.assertEqual(
            [tag.stage for _, tag in receipt.bundle.auth.items], [0, 1, 2]
        )
        self.assertEqual(log.stage, 3)
        self.assertEqual(sorted(log._tags), [0, 2, 4])

    def test_accepts_generator_and_sorts_ascending(self):
        receipt = _log(5).signed_auth_audit_continuation(
            1, (i for i in (4, 0)), _SEED_A, size=5
        )
        self.assertEqual(
            [entry.index for entry, _ in receipt.bundle.auth.items], [0, 4]
        )
        self.assertEqual(
            [entry.index for entry in receipt.bundle.audit.batch[3]], [0, 4]
        )

    def test_explicit_size_smaller_than_length(self):
        log = _log(6)
        receipt = log.signed_auth_audit_continuation(1, (1,), _SEED_A, size=3)
        self.assertEqual(receipt.bundle.audit.checkpoint.size, 3)
        self.assertEqual(receipt.consistency.new.size, 3)
        self.assertEqual(receipt.consistency.old.size, 1)
        self.assertEqual(
            [entry.index for entry in receipt.bundle.audit.batch[3]], [1, 2]
        )
        self.assertEqual(
            [entry.index for entry, _ in receipt.bundle.auth.items], [1]
        )

    def test_size_defaults_to_current_length(self):
        log = _log(6)
        receipt = log.signed_auth_audit_continuation(2, (1,), _SEED_A)
        self.assertEqual(receipt.bundle.audit.batch[1], 6)
        self.assertEqual(receipt.bundle.audit.checkpoint.size, 6)
        self.assertEqual(receipt.consistency.new.size, 6)

    def test_empty_selection_non_empty_snapshot(self):
        log = _log(5)
        receipt = log.signed_auth_audit_continuation(1, (), _SEED_A)
        self.assertEqual(receipt.bundle.auth.items, ())
        self.assertEqual(
            [entry.index for entry in receipt.bundle.audit.batch[3]], [4]
        )
        self.assertEqual(log.stage, 0)
        self.assertTrue(log._verifier_exported)
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                receipt, _public_key(_SEED_A)
            )
        )

    def test_empty_snapshot_genesis(self):
        log = _log(3)
        receipt = log.signed_auth_audit_continuation(0, (), _SEED_A, size=0)
        self.assertEqual(receipt.bundle.auth.items, ())
        hash_name, size, root, entries, proof = receipt.bundle.audit.batch
        self.assertEqual(size, 0)
        self.assertEqual(entries, ())
        self.assertEqual(proof, ())
        self.assertEqual(receipt.bundle.audit.checkpoint.size, 0)
        self.assertEqual(receipt.consistency.old.size, 0)
        self.assertEqual(receipt.consistency.new.size, 0)
        # Equal sizes carry an empty consistency proof.
        self.assertEqual(receipt.consistency.proof, ())
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                receipt, _public_key(_SEED_A)
            )
        )
        # No index is eligible inside an empty snapshot.
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(0, (0,), _SEED_A, size=0)

    def test_old_size_zero_from_non_empty_log(self):
        log = _log(5)
        receipt = log.signed_auth_audit_continuation(0, (0, 2), _SEED_A)
        # old_size 0 carries no proof nodes; the old root is the canonical
        # empty-tree root and the old head the digest-width zero value.
        self.assertEqual(receipt.consistency.proof, ())
        self.assertEqual(receipt.consistency.old.size, 0)
        self.assertEqual(receipt.consistency.old.head, bytes(32))
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                receipt, _public_key(_SEED_A)
            )
        )

    def test_equal_sizes_carry_empty_proof(self):
        log = _log(5)
        receipt = log.signed_auth_audit_continuation(3, (1,), _SEED_A, size=3)
        self.assertEqual(receipt.consistency.proof, ())
        self.assertEqual(receipt.consistency.old, receipt.consistency.new)
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                receipt, _public_key(_SEED_A)
            )
        )

    def test_proof_matches_consistency_proof(self):
        log = _log(6)
        receipt = log.signed_auth_audit_continuation(2, (0,), _SEED_A, size=5)
        self.assertEqual(
            receipt.consistency.proof, log.consistency_proof(2, 5)
        )

    def test_success_consumes_one_shot_eligibility(self):
        log = _log(5)
        log.signed_auth_audit_continuation(1, (1,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(1, (2,), _SEED_A)
        with self.assertRaises(ValueError):
            log.export_verifier()
        with self.assertRaises(ValueError):
            log.export_signed_verifier(_SEED_A)

    def test_prior_export_or_evolution_disqualifies(self):
        log = _log(5)
        log.export_signed_verifier(_SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(1, (0,), _SEED_A)
        log = _log(5)
        log.auth(0)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(1, (1,), _SEED_A)

    def test_keyless_mode_raises_value_error(self):
        log = AuditLog()
        for record in range(3):
            log.append(f"record-{record}")
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(0, (0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(0, (), _SEED_A)

    def test_pruned_old_snapshot_raises_value_error(self):
        log = _log(6)
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(1, (2,), _SEED_A)

    def test_pruned_retain_point_is_valid_old_size(self):
        log = _log(6)
        log.prune(2, log.seal(2))
        receipt = log.signed_auth_audit_continuation(2, (5, 2), _SEED_A)
        self.assertEqual(
            [entry.index for entry, _ in receipt.bundle.auth.items], [2, 5]
        )
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                receipt, _public_key(_SEED_A)
            )
        )

    def test_private_key_type_errors(self):
        log = _log(5)
        for bad in ("0" * 32, bytearray(_SEED_A), memoryview(_SEED_A), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                log.signed_auth_audit_continuation(1, (0,), bad)

    def test_private_key_length_raises_value_error(self):
        log = _log(5)
        for bad in (b"", _SEED_A[:-1], _SEED_A + b"\x00"):
            with self.assertRaises(ValueError):
                log.signed_auth_audit_continuation(1, (0,), bad)

    def test_indices_type_errors(self):
        log = _log(5)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(1, 5, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(1, None, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(1, ["0"], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(1, [1.0], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(1, [True], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(1, [0, False], _SEED_A)

    def test_size_type_errors(self):
        log = _log(5)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(1, (0,), _SEED_A, size=True)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(1, (0,), _SEED_A, size=1.0)

    def test_old_size_type_errors(self):
        log = _log(5)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(True, (0,), _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(1.0, (0,), _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation("1", (0,), _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(None, (0,), _SEED_A)

    def test_duplicate_index_raises_value_error(self):
        with self.assertRaises(ValueError):
            _log(5).signed_auth_audit_continuation(1, [1, 2, 1], _SEED_A)

    def test_size_chain_raises_value_error(self):
        log = _log(5)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(-1, (0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(6, (), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(1, (), _SEED_A, size=6)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(1, (), _SEED_A, size=-1)

    def test_out_of_range_index_raises_index_error(self):
        log = _log(5)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(1, [5], _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(1, [-1], _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(1, [3], _SEED_A, size=3)
        log.prune(2, log.seal(2))
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(2, [1, 3], _SEED_A)

    def test_failure_is_atomic_and_preserves_eligibility(self):
        for call, error in (
            (lambda log: log.signed_auth_audit_continuation(1, ["0"], _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_continuation(1, [True], _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_continuation(1, 5, _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_continuation(True, (), _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_continuation(1.0, (), _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_continuation(1, [0, 0], _SEED_A), ValueError),
            (lambda log: log.signed_auth_audit_continuation(1, [9], _SEED_A), IndexError),
            (lambda log: log.signed_auth_audit_continuation(1, [-1], _SEED_A), IndexError),
            (lambda log: log.signed_auth_audit_continuation(1, [3], _SEED_A, size=3), IndexError),
            (lambda log: log.signed_auth_audit_continuation(9, (), _SEED_A), ValueError),
            (lambda log: log.signed_auth_audit_continuation(1, [0], "0" * 32), TypeError),
            (lambda log: log.signed_auth_audit_continuation(1, [0], b"short"), ValueError),
            (lambda log: log.signed_auth_audit_continuation(1, [0], _SEED_A, size=6), ValueError),
        ):
            log = _log(5)
            before = self._snapshot(log)
            with self.assertRaises(error):
                call(log)
            self.assertEqual(self._snapshot(log), before)
            receipt = log.signed_auth_audit_continuation(
                1, (0, 2, 4), _SEED_A, size=5
            )
            self.assertEqual(
                [tag.stage for _, tag in receipt.bundle.auth.items], [0, 1, 2]
            )
            self.assertTrue(
                verify_signed_auth_audit_continuation(
                    receipt, _public_key(_SEED_A)
                )
            )

    def test_success_and_failure_leave_chain_state_untouched(self):
        log = _log(5)
        head, root, entries = log.head, log.merkle_root(), log.entries()
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(1, [9], _SEED_A)
        log.signed_auth_audit_continuation(1, (0, 2), _SEED_A, size=5)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(len(log), 5)
        self.assertTrue(log.verify())

    def test_alternate_hash_algorithm(self):
        receipt = _issue(
            old_size=1, indices=(2, 0), size=3, n=3, hash_name="sha512"
        )
        self.assertEqual(receipt.bundle.auth.hash_name, "sha512")
        self.assertEqual(receipt.bundle.audit.batch[0], "sha512")
        self.assertEqual(receipt.consistency.new.hash_name, "sha512")
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                receipt, _public_key(_SEED_A)
            )
        )


class VerifySignedAuthAuditContinuationTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_genuine_continuation_verifies(self):
        receipt = _issue()
        self.assertTrue(
            verify_signed_auth_audit_continuation(receipt, self.public_key)
        )

    def test_empty_selection_still_checks_the_verifier_signature(self):
        receipt = _issue(indices=())
        self.assertTrue(
            verify_signed_auth_audit_continuation(receipt, self.public_key)
        )
        twin = _log(5).signed_auth_audit_continuation(
            2, (), _SEED_B, size=4
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(twin, self.public_key)
        )

    def test_empty_snapshot_verifies(self):
        receipt = _issue(old_size=0, indices=(), size=0, n=3)
        self.assertTrue(
            verify_signed_auth_audit_continuation(receipt, self.public_key)
        )

    def test_untrusted_key_returns_false(self):
        receipt = _issue()
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                receipt, self.other_public_key
            )
        )

    def test_both_packages_verify_individually(self):
        receipt = _issue()
        self.assertTrue(
            verify_signed_auth_audit_bundle(receipt.bundle, self.public_key)
        )
        self.assertTrue(
            verify_signed_consistency(receipt.consistency, self.public_key)
        )

    def test_tampered_tag_returns_false(self):
        receipt = _issue()
        entry, tag = receipt.bundle.auth.items[1]
        bad_tag = AuthTag(tag.stage, bytes([tag.tag[0] ^ 1]) + tag.tag[1:])
        items = (
            receipt.bundle.auth.items[:1]
            + ((entry, bad_tag),)
            + receipt.bundle.auth.items[2:]
        )
        forged_auth = SignedAuthBundle(
            receipt.bundle.auth.verifier,
            receipt.bundle.auth.hash_name,
            items,
        )
        forged_bundle = SignedAuthAuditBundle(
            forged_auth, receipt.bundle.audit
        )
        forged = SignedAuthAuditContinuation(
            forged_bundle, receipt.consistency
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(forged, self.public_key)
        )

    def test_tampered_verifier_signature_returns_false(self):
        receipt = _issue()
        forged_verifier = SignedVerifier(
            1,
            receipt.bundle.auth.verifier.verifier,
            b"\x00" * 64,
        )
        forged_auth = SignedAuthBundle(
            forged_verifier,
            receipt.bundle.auth.hash_name,
            receipt.bundle.auth.items,
        )
        forged_bundle = SignedAuthAuditBundle(
            forged_auth, receipt.bundle.audit
        )
        forged = SignedAuthAuditContinuation(
            forged_bundle, receipt.consistency
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(forged, self.public_key)
        )

    def test_tampered_audit_checkpoint_returns_false(self):
        receipt = _issue()
        checkpoint = receipt.bundle.audit.checkpoint
        forged_checkpoint = type(checkpoint)(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged_audit = SignedAuditBatch(
            receipt.bundle.audit.batch, forged_checkpoint
        )
        forged_bundle = SignedAuthAuditBundle(
            receipt.bundle.auth, forged_audit
        )
        forged = SignedAuthAuditContinuation(
            forged_bundle, receipt.consistency
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(forged, self.public_key)
        )

    def test_tampered_old_checkpoint_returns_false(self):
        receipt = _issue()
        old = receipt.consistency.old
        forged_old = type(old)(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        forged_consistency = SignedConsistency(
            forged_old, receipt.consistency.new, receipt.consistency.proof
        )
        forged = SignedAuthAuditContinuation(
            receipt.bundle, forged_consistency
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(forged, self.public_key)
        )

    def test_bundles_individually_valid_but_signed_by_other_key(self):
        # The bundle is genuine from A; the consistency is genuine from B
        # but links the same sizes. Each package verifies under its own key,
        # yet the continuation must not verify under A's key.
        bundle = _log(5).signed_auth_audit_bundle((0, 2), _SEED_A, size=4)
        consistency = _log(5).signed_consistency(2, _SEED_B, new_size=4)
        receipt = SignedAuthAuditContinuation(bundle, consistency)
        self.assertTrue(
            verify_signed_auth_audit_bundle(bundle, self.public_key)
        )
        self.assertTrue(
            verify_signed_consistency(
                consistency, self.other_public_key
            )
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(receipt, self.public_key)
        )

    def test_new_checkpoint_size_differs_from_audit_returns_false(self):
        # Both halves genuine from A, but the consistency extends to a
        # different snapshot than the audit attests.
        bundle = _log(5).signed_auth_audit_bundle((0,), _SEED_A, size=4)
        consistency = _log(5).signed_consistency(1, _SEED_A, new_size=5)
        receipt = SignedAuthAuditContinuation(bundle, consistency)
        self.assertTrue(
            verify_signed_consistency(consistency, self.public_key)
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(receipt, self.public_key)
        )

    def test_same_sizes_but_different_roots_returns_false(self):
        # Same signing key and matching sizes on both sides, but the two
        # logs hold different payloads, so the consistency's new root is not
        # the audit checkpoint's root.
        bundle = _log(5, prefix="record").signed_auth_audit_bundle(
            (0,), _SEED_A, size=5
        )
        consistency = _log(5, prefix="other").signed_consistency(
            1, _SEED_A, new_size=5
        )
        receipt = SignedAuthAuditContinuation(bundle, consistency)
        self.assertTrue(
            verify_signed_consistency(consistency, self.public_key)
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(receipt, self.public_key)
        )

    def test_algorithm_mismatch_between_packages_returns_false(self):
        bundle = _log(3, hash_name="sha256").signed_auth_audit_bundle(
            (0,), _SEED_A, size=3
        )
        other = _log(3, hash_name="sha512")
        consistency = other.signed_consistency(1, _SEED_A, new_size=3)
        receipt = SignedAuthAuditContinuation(bundle, consistency)
        self.assertFalse(
            verify_signed_auth_audit_continuation(receipt, self.public_key)
        )

    def test_authenticated_index_missing_from_audit_returns_false(self):
        auth = _log(5).signed_auth_bundle((2,), _SEED_A)
        wider = _log(6)
        audit = wider.signed_audit_batch((0,), _SEED_A)
        bundle = SignedAuthAuditBundle(auth, audit)
        consistency = wider.signed_consistency(2, _SEED_A)
        receipt = SignedAuthAuditContinuation(bundle, consistency)
        self.assertFalse(
            verify_signed_auth_audit_continuation(receipt, self.public_key)
        )

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                verify_signed_auth_audit_continuation(bad, self.public_key)
        receipt = _issue()
        for bad_key in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError):
                verify_signed_auth_audit_continuation(receipt, bad_key)

    def test_public_key_length_raises_value_error(self):
        receipt = _issue()
        for bad_key in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                verify_signed_auth_audit_continuation(receipt, bad_key)

    def test_bypassed_container_fields_raise_type_error(self):
        receipt = _issue()
        for field, value in (
            ("bundle", "not-a-bundle"),
            ("consistency", "not-a-consistency"),
        ):
            forged = SignedAuthAuditContinuation.__new__(
                SignedAuthAuditContinuation
            )
            object.__setattr__(forged, "bundle", receipt.bundle)
            object.__setattr__(forged, "consistency", receipt.consistency)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                verify_signed_auth_audit_continuation(
                    forged, self.public_key
                )

    def test_call_is_read_only(self):
        receipt = _issue()
        before = (
            encode_signed_auth_audit_bundle(receipt.bundle),
            encode_signed_consistency(receipt.consistency),
        )
        verify_signed_auth_audit_continuation(receipt, self.public_key)
        after = (
            encode_signed_auth_audit_bundle(receipt.bundle),
            encode_signed_consistency(receipt.consistency),
        )
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
