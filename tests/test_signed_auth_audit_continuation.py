import unittest

from auditchain import (
    AuditLog,
    SignedAuthAuditBundle,
    SignedAuthAuditContinuation,
    SignedConsistency,
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


def _issue(old_size=2, indices=(0, 2, 4), seed=_SEED_A, size=None, n=5, **kwargs):
    return _log(n, **kwargs).signed_auth_audit_continuation(
        old_size, indices, seed, size
    )


class SignedAuthAuditContinuationConstructionTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        continuation = _issue()
        again = SignedAuthAuditContinuation(
            continuation.bundle, continuation.consistency
        )
        self.assertEqual(continuation, again)
        self.assertIsInstance(continuation.bundle, SignedAuthAuditBundle)
        self.assertIsInstance(continuation.consistency, SignedConsistency)
        self.assertNotEqual(continuation, _issue(indices=(1,)))

    def test_keyword_construction(self):
        continuation = _issue()
        twin = SignedAuthAuditContinuation(
            bundle=continuation.bundle, consistency=continuation.consistency
        )
        self.assertEqual(continuation, twin)

    def test_frozen(self):
        continuation = _issue()
        for field in ("bundle", "consistency"):
            with self.assertRaises(Exception):
                setattr(continuation, field, None)

    def test_container_type_errors(self):
        continuation = _issue()
        with self.assertRaises(TypeError):
            SignedAuthAuditContinuation(
                "not-a-bundle", continuation.consistency
            )
        with self.assertRaises(TypeError):
            SignedAuthAuditContinuation(
                continuation.bundle, "not-a-consistency"
            )


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

    def test_continuation_fields(self):
        continuation = _issue(old_size=2, indices=(4, 0), n=5)
        self.assertEqual(
            [entry.index for entry, _ in continuation.bundle.auth.items],
            [0, 4],
        )
        self.assertEqual(continuation.bundle.audit.checkpoint.size, 5)
        consistency = continuation.consistency
        self.assertEqual(consistency.old.size, 2)
        self.assertEqual(consistency.new.size, 5)
        # The consistency chain lands exactly on the audited snapshot.
        self.assertEqual(consistency.new, continuation.bundle.audit.checkpoint)

    def test_equals_two_step_issuance(self):
        log = _log(5)
        continuation = log.signed_auth_audit_continuation(
            2, (4, 0, 2), _SEED_A
        )
        twin = _log(5)
        bundle = twin.signed_auth_audit_bundle((4, 0, 2), _SEED_A)
        consistency = twin.signed_consistency(2, _SEED_A)
        self.assertEqual(continuation.bundle, bundle)
        self.assertEqual(continuation.consistency, consistency)
        self.assertEqual(
            continuation, SignedAuthAuditContinuation(bundle, consistency)
        )

    def test_size_defaults_to_current_length(self):
        continuation = _issue(old_size=1, indices=(1,), n=5)
        self.assertEqual(continuation.bundle.audit.batch[1], 5)
        self.assertEqual(continuation.consistency.new.size, 5)

    def test_explicit_size_smaller_than_length(self):
        log = _log(6)
        continuation = log.signed_auth_audit_continuation(
            2, (1,), _SEED_A, size=4
        )
        self.assertEqual(continuation.bundle.audit.checkpoint.size, 4)
        self.assertEqual(continuation.consistency.old.size, 2)
        self.assertEqual(continuation.consistency.new.size, 4)
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                continuation, _public_key(_SEED_A)
            )
        )

    def test_old_size_equal_to_size(self):
        continuation = _issue(old_size=5, indices=(1,), n=5)
        self.assertEqual(continuation.consistency.proof, ())
        self.assertEqual(
            continuation.consistency.old, continuation.consistency.new
        )
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                continuation, _public_key(_SEED_A)
            )
        )

    def test_old_size_zero(self):
        continuation = _issue(old_size=0, indices=(1,), n=5)
        self.assertEqual(continuation.consistency.old.size, 0)
        self.assertEqual(continuation.consistency.proof, ())
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                continuation, _public_key(_SEED_A)
            )
        )

    def test_empty_selection(self):
        log = _log(5)
        continuation = log.signed_auth_audit_continuation(2, (), _SEED_A)
        self.assertEqual(continuation.bundle.auth.items, ())
        # The audit still carries the last snapshot entry.
        self.assertEqual(
            [entry.index for entry in continuation.bundle.audit.batch[3]],
            [4],
        )
        self.assertEqual(log.stage, 0)
        self.assertTrue(log._verifier_exported)
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                continuation, _public_key(_SEED_A)
            )
        )

    def test_empty_snapshot(self):
        log = _log(3)
        continuation = log.signed_auth_audit_continuation(
            0, (), _SEED_A, size=0
        )
        self.assertEqual(continuation.bundle.audit.batch[1], 0)
        self.assertEqual(continuation.consistency.old.size, 0)
        self.assertEqual(continuation.consistency.new.size, 0)
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                continuation, _public_key(_SEED_A)
            )
        )

    def test_tags_run_from_stage_zero_and_commit(self):
        log = _log(5)
        continuation = log.signed_auth_audit_continuation(
            2, (4, 0, 2), _SEED_A
        )
        self.assertEqual(
            [tag.stage for _, tag in continuation.bundle.auth.items],
            [0, 1, 2],
        )
        self.assertEqual(log.stage, 3)
        self.assertEqual(sorted(log._tags), [0, 2, 4])

    def test_success_consumes_one_shot_eligibility(self):
        log = _log(5)
        log.signed_auth_audit_continuation(2, (1,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(2, (2,), _SEED_A)
        with self.assertRaises(ValueError):
            log.export_signed_verifier(_SEED_A)

    def test_prior_export_or_evolution_disqualifies(self):
        log = _log(5)
        log.export_signed_verifier(_SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(2, (0,), _SEED_A)
        log = _log(5)
        log.auth(0)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(2, (1,), _SEED_A)

    def test_keyless_mode_raises_value_error(self):
        log = AuditLog()
        for record in range(3):
            log.append(f"record-{record}")
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(1, (0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(1, (), _SEED_A)

    def test_private_key_type_errors(self):
        log = _log(5)
        for bad in ("0" * 32, bytearray(_SEED_A), memoryview(_SEED_A), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                log.signed_auth_audit_continuation(2, (0,), bad)

    def test_private_key_length_raises_value_error(self):
        log = _log(5)
        for bad in (b"", _SEED_A[:-1], _SEED_A + b"\x00"):
            with self.assertRaises(ValueError):
                log.signed_auth_audit_continuation(2, (0,), bad)

    def test_indices_type_errors(self):
        log = _log(5)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(2, 5, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(2, None, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(2, ["0"], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(2, [1.0], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(2, [True], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(2, [0, False], _SEED_A)

    def test_size_type_errors(self):
        log = _log(5)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(2, (0,), _SEED_A, size=True)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(2, (0,), _SEED_A, size=1.0)
        with self.assertRaises(TypeError):
            log.signed_auth_audit_continuation(2, (0,), _SEED_A, size="5")

    def test_old_size_type_errors(self):
        log = _log(5)
        for bad in (True, 1.0, "2", None):
            with self.assertRaises(TypeError, msg=bad):
                log.signed_auth_audit_continuation(bad, (0,), _SEED_A)

    def test_old_size_out_of_range_raises_value_error(self):
        log = _log(5)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(-1, (0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(6, (0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(4, (0,), _SEED_A, size=3)

    def test_size_out_of_range_raises_value_error(self):
        log = _log(5)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(2, (0,), _SEED_A, size=6)
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(2, (0,), _SEED_A, size=-1)

    def test_duplicate_index_raises_value_error(self):
        with self.assertRaises(ValueError):
            _log(5).signed_auth_audit_continuation(2, [1, 2, 1], _SEED_A)

    def test_out_of_range_index_raises_index_error(self):
        log = _log(5)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(2, [5], _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(2, [-1], _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(2, [3], _SEED_A, size=3)
        log.prune(2, log.seal(2))
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(2, [1, 3], _SEED_A)

    def test_pruned_snapshot_raises_value_error(self):
        log = _log(6)
        log.prune(2, log.seal(2))
        # The old prefix was released and cannot be rebuilt.
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(1, (2,), _SEED_A)
        # A size inside the released prefix cannot be rebuilt either.
        with self.assertRaises(ValueError):
            log.signed_auth_audit_continuation(0, (), _SEED_A, size=1)

    def test_pruned_log_continuation(self):
        log = _log(6)
        log.prune(2, log.seal(2))
        continuation = log.signed_auth_audit_continuation(2, (5, 2), _SEED_A)
        self.assertEqual(
            [entry.index for entry, _ in continuation.bundle.auth.items],
            [2, 5],
        )
        self.assertEqual(continuation.consistency.old.size, 2)
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                continuation, _public_key(_SEED_A)
            )
        )

    def test_failure_is_atomic_and_preserves_eligibility(self):
        for call, error in (
            (lambda log: log.signed_auth_audit_continuation(2, ["0"], _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_continuation(2, [True], _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_continuation(2, 5, _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_continuation(2, [0, 0], _SEED_A), ValueError),
            (lambda log: log.signed_auth_audit_continuation(2, [9], _SEED_A), IndexError),
            (lambda log: log.signed_auth_audit_continuation(2, [-1], _SEED_A), IndexError),
            (lambda log: log.signed_auth_audit_continuation(2, [3], _SEED_A, size=3), IndexError),
            (lambda log: log.signed_auth_audit_continuation(2, [0], "0" * 32), TypeError),
            (lambda log: log.signed_auth_audit_continuation(2, [0], b"short"), ValueError),
            (lambda log: log.signed_auth_audit_continuation(2, [0], _SEED_A, size=6), ValueError),
            (lambda log: log.signed_auth_audit_continuation(-1, [0], _SEED_A), ValueError),
            (lambda log: log.signed_auth_audit_continuation(6, [0], _SEED_A), ValueError),
            (lambda log: log.signed_auth_audit_continuation(True, [0], _SEED_A), TypeError),
            (lambda log: log.signed_auth_audit_continuation(2, [0], _SEED_A, size=True), TypeError),
        ):
            log = _log(5)
            before = self._snapshot(log)
            with self.assertRaises(error):
                call(log)
            self.assertEqual(self._snapshot(log), before)
            continuation = log.signed_auth_audit_continuation(
                2, (0, 2, 4), _SEED_A
            )
            self.assertEqual(
                [tag.stage for _, tag in continuation.bundle.auth.items],
                [0, 1, 2],
            )
            self.assertTrue(
                verify_signed_auth_audit_continuation(
                    continuation, _public_key(_SEED_A)
                )
            )

    def test_success_and_failure_leave_chain_state_untouched(self):
        log = _log(5)
        head, root, entries = log.head, log.merkle_root(), log.entries()
        with self.assertRaises(IndexError):
            log.signed_auth_audit_continuation(2, [9], _SEED_A)
        log.signed_auth_audit_continuation(2, (0, 2), _SEED_A)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(len(log), 5)
        self.assertTrue(log.verify())

    def test_alternate_hash_algorithm(self):
        continuation = _issue(old_size=1, indices=(2, 0), n=3, hash_name="sha512")
        self.assertEqual(continuation.bundle.auth.hash_name, "sha512")
        self.assertEqual(continuation.consistency.new.hash_name, "sha512")
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                continuation, _public_key(_SEED_A)
            )
        )


class VerifySignedAuthAuditContinuationTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_genuine_continuation_verifies(self):
        self.assertTrue(
            verify_signed_auth_audit_continuation(_issue(), self.public_key)
        )

    def test_empty_selection_verifies(self):
        continuation = _issue(old_size=2, indices=())
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                continuation, self.public_key
            )
        )

    def test_empty_snapshot_verifies(self):
        continuation = _issue(old_size=0, indices=(), size=0, n=3)
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                continuation, self.public_key
            )
        )

    def test_untrusted_key_returns_false(self):
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                _issue(), self.other_public_key
            )
        )

    def test_tampered_bundle_returns_false(self):
        continuation = _issue()
        checkpoint = continuation.bundle.audit.checkpoint
        forged_checkpoint = type(checkpoint)(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged_audit = type(continuation.bundle.audit)(
            continuation.bundle.audit.batch, forged_checkpoint
        )
        forged_bundle = SignedAuthAuditBundle(
            continuation.bundle.auth, forged_audit
        )
        forged = SignedAuthAuditContinuation(
            forged_bundle, continuation.consistency
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(forged, self.public_key)
        )

    def test_tampered_consistency_returns_false(self):
        continuation = _issue()
        old = continuation.consistency.old
        forged_old = type(old)(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        forged_consistency = SignedConsistency(
            forged_old,
            continuation.consistency.new,
            continuation.consistency.proof,
        )
        forged = SignedAuthAuditContinuation(
            continuation.bundle, forged_consistency
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(forged, self.public_key)
        )

    def test_packages_individually_valid_but_checkpoints_differ(self):
        # Same signing key and algorithm on both sides, but the consistency
        # chain lands on a different snapshot than the audit package
        # attests.
        bundle = _log(5).signed_auth_audit_bundle((0, 2), _SEED_A)
        consistency = _log(5).signed_consistency(2, _SEED_A, 3)
        self.assertTrue(verify_signed_auth_audit_bundle(bundle, self.public_key))
        self.assertTrue(
            verify_signed_consistency(consistency, self.public_key)
        )
        continuation = SignedAuthAuditContinuation(bundle, consistency)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                continuation, self.public_key
            )
        )

    def test_packages_from_different_logs_return_false(self):
        bundle = _log(5, prefix="record").signed_auth_audit_bundle(
            (0, 2), _SEED_A
        )
        consistency = _log(5, prefix="other").signed_consistency(2, _SEED_A)
        continuation = SignedAuthAuditContinuation(bundle, consistency)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                continuation, self.public_key
            )
        )

    def test_algorithm_mismatch_between_packages_returns_false(self):
        bundle = _log(3, hash_name="sha256").signed_auth_audit_bundle(
            (0,), _SEED_A
        )
        other = AuditLog(hash_name="sha512")
        for record in range(3):
            other.append(f"record-{record}")
        consistency = other.signed_consistency(1, _SEED_A)
        self.assertTrue(
            verify_signed_consistency(consistency, self.public_key)
        )
        continuation = SignedAuthAuditContinuation(bundle, consistency)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                continuation, self.public_key
            )
        )

    def test_type_errors(self):
        for bad in (None, "continuation", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                verify_signed_auth_audit_continuation(bad, self.public_key)
        continuation = _issue()
        for bad_key in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError):
                verify_signed_auth_audit_continuation(continuation, bad_key)

    def test_public_key_length_raises_value_error(self):
        continuation = _issue()
        for bad_key in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                verify_signed_auth_audit_continuation(continuation, bad_key)

    def test_bypassed_container_fields_raise_type_error(self):
        continuation = _issue()
        for field, value in (
            ("bundle", "not-a-bundle"),
            ("consistency", "not-a-consistency"),
        ):
            forged = SignedAuthAuditContinuation.__new__(
                SignedAuthAuditContinuation
            )
            object.__setattr__(forged, "bundle", continuation.bundle)
            object.__setattr__(
                forged, "consistency", continuation.consistency
            )
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                verify_signed_auth_audit_continuation(forged, self.public_key)

    def test_call_is_read_only(self):
        continuation = _issue()
        before = repr(continuation)
        verify_signed_auth_audit_continuation(continuation, self.public_key)
        self.assertEqual(repr(continuation), before)


if __name__ == "__main__":
    unittest.main()
