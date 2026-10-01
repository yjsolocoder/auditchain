import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    PruneReceipt,
    RetentionTransition,
    SignedConsistency,
    SignedPrune,
    SignedRoot,
    verify_retention_chain,
    verify_signed_consistency,
    verify_signed_prune,
    verify_signed_root,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_APPEND_KEY = b"k" * 32
_NONCE = b"n" * 12


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _fresh_log(count: int = 0, *, key=None, hash_name: str = "sha256") -> AuditLog:
    log = AuditLog(key=key, hash_name=hash_name)
    for i in range(count):
        log.append(f"r{i}")
    return log


class PruneWithRetentionTransitionTest(unittest.TestCase):
    def setUp(self):
        self.log = _fresh_log(10)
        self.public_key = _public_key(_SEED_A)

    def test_first_step_binds_three_credentials_and_prunes(self):
        initial = self.log.sign_root(_SEED_A, 0)
        transition = self.log.prune_with_retention_transition(
            initial, 3, _SEED_A
        )
        self.assertIsInstance(transition, RetentionTransition)
        self.assertEqual(transition.before, initial)
        # The prune authorization and the two-snapshot consistency are
        # byte-for-byte what the existing read-only issuers mint.
        self.assertEqual(transition.prune, self.log.sign_prune(_SEED_A, 3))
        self.assertEqual(
            transition.consistency,
            SignedConsistency(
                old=initial,
                new=transition.prune.checkpoint,
                proof=(),
            ),
        )
        self.assertEqual(transition.consistency.old, initial)
        self.assertEqual(
            transition.consistency.new, transition.prune.checkpoint
        )
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual([e.index for e in self.log], [3, 4, 5, 6, 7, 8, 9])
        self.assertTrue(self.log.verify())
        self.assertTrue(
            self.log.seal(3).matches(self.log.entry(3))
        )

    def test_step_is_seal_prune_equivalent(self):
        twin = _fresh_log(10)
        initial = self.log.sign_root(_SEED_A, 0)
        transition = self.log.prune_with_retention_transition(
            initial, 4, _SEED_A
        )
        receipt = twin.seal(4)
        twin.prune(4, receipt)
        self.assertEqual(transition.prune.receipt, receipt)
        self.assertEqual([e for e in self.log], [e for e in twin])
        self.assertEqual(self.log.head, twin.head)
        self.assertEqual(self.log.merkle_root(), twin.merkle_root())

    def test_chain_of_steps_with_appends_between(self):
        initial = self.log.sign_root(_SEED_A, 0)
        t1 = self.log.prune_with_retention_transition(initial, 3, _SEED_A)
        self.assertEqual(self.log.retain_from, 3)
        self.log.append("r10")
        self.log.append("r11")
        t2 = self.log.prune_with_retention_transition(
            t1.prune.checkpoint, 7, _SEED_A
        )
        self.assertEqual(t2.before, t1.prune.checkpoint)
        self.assertEqual(self.log.retain_from, 7)
        self.log.append("r12")
        t3 = self.log.prune_with_retention_transition(
            t2.prune.checkpoint, 13, _SEED_A
        )
        self.assertTrue(
            verify_retention_chain(initial, (t1, t2, t3), self.public_key)
        )

    def test_step_may_release_everything_then_append_and_step_again(self):
        initial = self.log.sign_root(_SEED_A, 0)
        t1 = self.log.prune_with_retention_transition(
            initial, 10, _SEED_A
        )
        self.assertEqual(self.log.retain_from, 10)
        self.assertEqual(self.log.entries(), [])
        self.log.append("after")
        t2 = self.log.prune_with_retention_transition(
            t1.prune.checkpoint, 11, _SEED_A
        )
        self.assertTrue(
            verify_retention_chain(initial, (t1, t2), self.public_key)
        )

    def test_nonempty_consistency_proof_for_nonempty_boundary(self):
        twin = _fresh_log(11)
        initial = self.log.sign_root(_SEED_A, 0)
        t1 = self.log.prune_with_retention_transition(initial, 3, _SEED_A)
        self.log.append("r10")
        t2 = self.log.prune_with_retention_transition(
            t1.prune.checkpoint, 11, _SEED_A
        )
        # old_size=3, new_size=11 has a non-empty RFC 6962 SUBPROOF; compare
        # against the unpruned twin that still holds the whole history.
        self.assertTrue(len(t2.consistency.proof) > 0)
        self.assertEqual(
            t2.consistency.proof, twin.consistency_proof(3, 11)
        )
        self.assertTrue(
            verify_signed_consistency(t2.consistency, self.public_key)
        )

    def test_each_credential_individually_verifies(self):
        initial = self.log.sign_root(_SEED_A, 0)
        transition = self.log.prune_with_retention_transition(
            initial, 3, _SEED_A
        )
        self.assertTrue(
            verify_signed_root(transition.before, self.public_key)
        )
        self.assertTrue(
            verify_signed_prune(transition.prune, self.public_key)
        )
        self.assertTrue(
            verify_signed_consistency(
                transition.consistency, self.public_key
            )
        )

    def test_alternate_hash_algorithms(self):
        for hash_name in ("sha3-256", "sha512", "blake2b"):
            log = _fresh_log(6, hash_name=hash_name)
            initial = log.sign_root(_SEED_A, 0)
            t1 = log.prune_with_retention_transition(initial, 2, _SEED_A)
            log.append("more")
            t2 = log.prune_with_retention_transition(
                t1.prune.checkpoint, 7, _SEED_A
            )
            self.assertTrue(
                verify_retention_chain(
                    initial, (t1, t2), self.public_key
                ),
                hash_name,
            )
            self.assertEqual(log.retain_from, 7)

    def test_frozen(self):
        initial = self.log.sign_root(_SEED_A, 0)
        transition = self.log.prune_with_retention_transition(
            initial, 3, _SEED_A
        )
        with self.assertRaises(FrozenInstanceError):
            transition.before = transition.before
        with self.assertRaises(FrozenInstanceError):
            transition.prune = transition.prune
        with self.assertRaises(FrozenInstanceError):
            transition.consistency = transition.consistency

    def test_constructor_field_types(self):
        initial = self.log.sign_root(_SEED_A, 0)
        transition = self.log.prune_with_retention_transition(
            initial, 3, _SEED_A
        )
        for field, value in (
            ("before", None),
            ("before", transition.prune),
            ("before", "x"),
            ("prune", None),
            ("prune", initial),
            ("prune", "x"),
            ("consistency", None),
            ("consistency", transition.prune),
            ("consistency", "x"),
        ):
            fields = {
                "before": transition.before,
                "prune": transition.prune,
                "consistency": transition.consistency,
            }
            fields[field] = value
            with self.assertRaises(TypeError, msg=field):
                RetentionTransition(**fields)


class PruneWithRetentionTransitionErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = _fresh_log(10)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.initial = self.log.sign_root(_SEED_A, 0)

    def _state(self):
        return (
            self.log.retain_from,
            self.log.head,
            tuple(self.log.entries()),
            self.log.merkle_root(),
            self.log.stage,
            self.log._key,
            frozenset(self.log._tags),
            frozenset(self.log._used_nonces),
            self.log._checkpoint_head,
            tuple(sorted(self.log._frontier)),
        )

    def _assert_unchanged(self, before):
        self.assertEqual(self._state(), before)
        # The boundary and later snapshots are still rebuildable.
        self.assertTrue(self.log.verify())

    def test_before_wrong_type_is_type_error(self):
        for bad in (None, 1, b"bytes", object(), ()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.log.prune_with_retention_transition(bad, 3, _SEED_A)

    def test_retain_from_wrong_type_is_type_error(self):
        for bad in (True, False, 1.5, "3", None, [3]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.log.prune_with_retention_transition(
                    self.initial, bad, _SEED_A
                )

    def test_private_key_wrong_type_is_type_error(self):
        for bad in (None, 1, bytearray(_SEED_A), memoryview(_SEED_A), "seed"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.log.prune_with_retention_transition(
                    self.initial, 3, bad
                )

    def test_private_key_wrong_length_is_value_error(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                self.log.prune_with_retention_transition(
                    self.initial, 3, bad
                )

    def test_target_equal_to_boundary_is_value_error(self):
        # Strictly greater: a zero-width release is not a transition.
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(
                self.initial, 0, _SEED_A
            )
        first = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(
                first.prune.checkpoint, 3, _SEED_A
            )

    def test_target_behind_boundary_is_value_error(self):
        first = self.log.prune_with_retention_transition(
            self.initial, 5, _SEED_A
        )
        self.log.append("r10")
        for bad in (4, 0):
            with self.assertRaises(ValueError, msg=bad):
                self.log.prune_with_retention_transition(
                    first.prune.checkpoint, bad, _SEED_A
                )

    def test_target_past_log_end_is_value_error(self):
        for bad in (11, 100):
            with self.assertRaises(ValueError, msg=bad):
                self.log.prune_with_retention_transition(
                    self.initial, bad, _SEED_A
                )

    def test_before_size_not_current_boundary_is_value_error(self):
        # A genuine checkpoint of a non-boundary snapshot cannot be "before".
        ahead = self.log.sign_root(_SEED_A, 3)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(ahead, 5, _SEED_A)
        # After a prune the empty-prefix checkpoint is a stale boundary.
        first = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(
                self.initial, 5, _SEED_A
            )
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(first.before, self.initial)

    def test_before_signed_by_other_key_is_value_error(self):
        # A checkpoint from another signer does not authorize this prune.
        foreign = self.log.sign_root(_SEED_B, 0)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(foreign, 3, _SEED_A)

    def test_before_may_carry_a_different_trust_anchor_on_first_step(self):
        # The empty boundary is content-free: choosing seed B for the very
        # first step legitimately starts a B-signed evolution (which then
        # does not verify against A's public key).
        foreign = self.log.sign_root(_SEED_B, 0)
        transition = self.log.prune_with_retention_transition(
            foreign, 3, _SEED_B
        )
        self.assertTrue(
            verify_retention_chain(
                foreign, (transition,), self.other_public_key
            )
        )
        self.assertFalse(
            verify_retention_chain(
                foreign, (transition,), self.public_key
            )
        )

    def test_before_root_mismatch_is_value_error(self):
        # Genuine signature over another log's boundary of the SAME size:
        # size == retain_from but root and chain head disagree.
        twin = AuditLog()
        for i in range(5):
            twin.append(f"other-{i}")
        self.log.prune(2, self.log.seal(2))
        twin.prune(2, twin.seal(2))
        other_boundary = twin.sign_root(_SEED_A, 2)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(
                other_boundary, 4, _SEED_A
            )
        # A boundary of a different size is rejected as not-current.
        other = AuditLog()
        for i in range(6):
            other.append(f"x{i}")
        other.prune(3, other.seal(3))
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(
                other.sign_root(_SEED_A, 3), 5, _SEED_A
            )

    def test_before_altered_signature_is_value_error(self):
        bogus = SignedRoot(
            self.initial.version,
            self.initial.hash_name,
            self.initial.size,
            self.initial.root,
            self.initial.head,
            b"\x00" * 64,
        )
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(bogus, 3, _SEED_A)

    def test_bypassed_before_fields_raise_like_constructor(self):
        for field, value in (
            ("version", 2),
            ("hash_name", 7),
            ("size", "3"),
            ("root", b"\x00" * 31),
            ("head", b"\x00" * 33),
            ("signature", b"\x00" * 63),
        ):
            forged = SignedRoot.__new__(SignedRoot)
            for name in (
                "version",
                "hash_name",
                "size",
                "root",
                "head",
                "signature",
            ):
                object.__setattr__(
                    forged, name, getattr(self.initial, name)
                )
            object.__setattr__(forged, field, value)
            with self.assertRaises(
                (TypeError, ValueError), msg=field
            ):
                self.log.prune_with_retention_transition(
                    forged, 3, _SEED_A
                )

    def test_before_other_hash_algorithm_is_value_error(self):
        other = _fresh_log(0, hash_name="sha512").sign_root(_SEED_A, 0)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(other, 3, _SEED_A)

    def test_failures_leave_all_state_untouched(self):
        failing_calls = (
            lambda: self.log.prune_with_retention_transition(
                None, 3, _SEED_A
            ),
            lambda: self.log.prune_with_retention_transition(
                self.initial, True, _SEED_A
            ),
            lambda: self.log.prune_with_retention_transition(
                self.initial, 3, b"bad"
            ),
            lambda: self.log.prune_with_retention_transition(
                self.initial, 0, _SEED_A
            ),
            lambda: self.log.prune_with_retention_transition(
                self.initial, 11, _SEED_A
            ),
            lambda: self.log.prune_with_retention_transition(
                self.log.sign_root(_SEED_A, 4), 6, _SEED_A
            ),
            lambda: self.log.prune_with_retention_transition(
                self.log.sign_root(_SEED_B, 0), 3, _SEED_A
            ),
        )
        for call in failing_calls:
            before = self._state()
            with self.assertRaises((TypeError, ValueError)):
                call()
            self._assert_unchanged(before)

    def test_failure_preserves_auth_encryption_and_nonce_state(self):
        log = AuditLog(key=_APPEND_KEY)
        for i in range(6):
            log.append(f"r{i}")
        log.auth(0)
        log.rotate_key()
        log.encrypt("secret", _APPEND_KEY, _NONCE)
        initial = log.sign_root(_SEED_A, 0)
        before = (
            log.retain_from,
            log.head,
            tuple(log.entries()),
            log.stage,
            log._key,
            dict(log._tags),
            set(log._used_nonces),
            {k: list(v) for k, v in log._encrypted_index.items()},
            dict(log._encrypted_locators),
        )
        with self.assertRaises(ValueError):
            log.prune_with_retention_transition(initial, 100, _SEED_A)
        self.assertEqual(log.retain_from, before[0])
        self.assertEqual(log.head, before[1])
        self.assertEqual(tuple(log.entries()), before[2])
        self.assertEqual(log.stage, before[3])
        self.assertEqual(log._key, before[4])
        self.assertEqual(dict(log._tags), before[5])
        self.assertEqual(set(log._used_nonces), before[6])
        self.assertEqual(
            {k: list(v) for k, v in log._encrypted_index.items()}, before[7]
        )
        self.assertEqual(dict(log._encrypted_locators), before[8])
        # The nonce is still recorded as used and cannot be reused.
        with self.assertRaises(ValueError):
            log.encrypt("another", _APPEND_KEY, _NONCE)


class VerifyRetentionChainTest(unittest.TestCase):
    def setUp(self):
        self.log = _fresh_log(8)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.initial = self.log.sign_root(_SEED_A, 0)
        self.t1 = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        self.log.append("r8")
        self.t2 = self.log.prune_with_retention_transition(
            self.t1.prune.checkpoint, 6, _SEED_A
        )
        self.log.append("r9")
        self.t3 = self.log.prune_with_retention_transition(
            self.t2.prune.checkpoint, 10, _SEED_A
        )
        self.chain = (self.t1, self.t2, self.t3)

    def test_genuine_chain(self):
        self.assertTrue(
            verify_retention_chain(
                self.initial, self.chain, self.public_key
            )
        )

    def test_prefixes_of_the_chain_verify(self):
        self.assertTrue(
            verify_retention_chain(
                self.initial, (self.t1,), self.public_key
            )
        )
        self.assertTrue(
            verify_retention_chain(
                self.initial, (self.t1, self.t2), self.public_key
            )
        )

    def test_empty_transitions_requires_valid_initial(self):
        self.assertTrue(
            verify_retention_chain(self.initial, (), self.public_key)
        )
        foreign = self.log.sign_root(_SEED_B, 0)
        self.assertFalse(
            verify_retention_chain(foreign, (), self.public_key)
        )

    def test_wrong_public_key_is_false(self):
        self.assertFalse(
            verify_retention_chain(
                self.initial, self.chain, self.other_public_key
            )
        )

    def test_wrong_initial_is_false(self):
        # A checkpoint that does not equal the first step's boundary.
        other = self.t1.prune.checkpoint
        self.assertFalse(
            verify_retention_chain(other, self.chain, self.public_key)
        )
        foreign = self.log.sign_root(_SEED_B, 0)
        self.assertFalse(
            verify_retention_chain(foreign, self.chain, self.public_key)
        )

    def test_reordered_steps_is_false(self):
        self.assertFalse(
            verify_retention_chain(
                self.initial, (self.t2, self.t1, self.t3),
                self.public_key,
            )
        )

    def test_missing_step_is_false(self):
        # A jump over a boundary cannot join: t2.before != t1 absent.
        self.assertFalse(
            verify_retention_chain(
                self.initial, (self.t1, self.t3), self.public_key
            )
        )

    def test_repeated_step_is_false(self):
        self.assertFalse(
            verify_retention_chain(
                self.initial, (self.t1, self.t1), self.public_key
            )
        )

    def test_step_signed_by_other_key_is_false(self):
        foreign = _fresh_log(8)
        foreign_initial = foreign.sign_root(_SEED_B, 0)
        ft1 = foreign.prune_with_retention_transition(
            foreign_initial, 3, _SEED_B
        )
        self.assertFalse(
            verify_retention_chain(
                self.initial, (ft1,), self.public_key
            )
        )

    def test_tampered_before_checkpoint_is_false(self):
        tampered_signature = SignedRoot(
            self.t1.before.version,
            self.t1.before.hash_name,
            self.t1.before.size,
            self.t1.before.root,
            self.t1.before.head,
            b"\x00" * 64,
        )
        consistency = SignedConsistency(
            old=tampered_signature,
            new=self.t1.prune.checkpoint,
            proof=self.t1.consistency.proof,
        )
        forged = RetentionTransition(
            tampered_signature, self.t1.prune, consistency
        )
        self.assertFalse(
            verify_retention_chain(
                self.initial, (forged,), self.public_key
            )
        )

    def test_tampered_prune_is_false(self):
        receipt = self.t1.prune.receipt
        bogus_receipt = type(receipt)(
            receipt.hash_name,
            receipt.size + 1,
            receipt.merkle_root,
            receipt.chain_hash,
        )
        forged_prune = SignedPrune(bogus_receipt, self.t1.prune.checkpoint)
        forged = RetentionTransition(
            self.t1.before, forged_prune, self.t1.consistency
        )
        self.assertFalse(
            verify_retention_chain(
                self.initial, (forged,), self.public_key
            )
        )

    def test_tampered_consistency_proof_is_false(self):
        nodes = self.t2.consistency.proof
        flipped = bytes([nodes[0][0] ^ 0xFF]) + nodes[0][1:]
        bogus_proof = (flipped,) + nodes[1:]
        bogus_consistency = SignedConsistency(
            self.t2.consistency.old,
            self.t2.consistency.new,
            bogus_proof,
        )
        forged = RetentionTransition(
            self.t2.before, self.t2.prune, bogus_consistency
        )
        self.assertFalse(
            verify_retention_chain(
                self.initial, (self.t1, forged), self.public_key
            )
        )

    def test_cross_wired_checkpoints_is_false(self):
        # Structurally genuine credentials that do not bind t3's two
        # snapshots: a real 3->10 consistency in place of t3's 6->10 one,
        # minted from an unpruned twin holding the whole history.
        twin = _fresh_log(10)
        other = twin.signed_consistency(3, _SEED_A, 10)
        bogus = RetentionTransition(
            self.t3.before, self.t3.prune, other
        )
        self.assertFalse(
            verify_retention_chain(
                self.initial, (self.t1, self.t2, bogus),
                self.public_key,
            )
        )

    def test_non_growing_handmade_step_is_false(self):
        checkpoint = self.t1.before
        receipt = PruneReceipt(
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
        )
        prune = SignedPrune(receipt, checkpoint)
        consistency = SignedConsistency(
            old=checkpoint, new=checkpoint, proof=()
        )
        same_step = RetentionTransition(checkpoint, prune, consistency)
        # The individual credentials are genuine, but the boundary does not
        # advance, so the chain must reject it.
        self.assertTrue(verify_signed_prune(prune, self.public_key))
        self.assertFalse(
            verify_retention_chain(
                self.initial, (same_step,), self.public_key
            )
        )

    def test_initial_type_error(self):
        for bad in (None, 1, b"bytes", self.t1, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_retention_chain(bad, self.chain, self.public_key)

    def test_transitions_type_error(self):
        for bad in (None, [], self.t1, (self.t1 for _ in (1,))):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_retention_chain(
                    self.initial, bad, self.public_key
                )

    def test_transition_element_type_error(self):
        for bad in (None, 1, "x", self.t1.prune, self.t1.consistency):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_retention_chain(
                    self.initial, (self.t1, bad), self.public_key
                )

    def test_bypassed_container_field_types_type_error(self):
        forged = RetentionTransition.__new__(RetentionTransition)
        object.__setattr__(forged, "before", None)
        object.__setattr__(forged, "prune", self.t1.prune)
        object.__setattr__(forged, "consistency", self.t1.consistency)
        with self.assertRaises(TypeError):
            verify_retention_chain(
                self.initial, (forged,), self.public_key
            )

    def test_public_key_type_and_shape(self):
        with self.assertRaises(TypeError):
            verify_retention_chain(
                self.initial, self.chain, bytearray(self.public_key)
            )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                verify_retention_chain(
                    self.initial, self.chain, bad
                )

    def test_illegal_proof_shape_propagates_value_error(self):
        # Container-legal (tuple of bytes) but a node of the wrong digest
        # width is structural corruption, not a mere mismatch.
        bogus_consistency = SignedConsistency(
            self.t2.consistency.old,
            self.t2.consistency.new,
            (b"\x00" * 7,) + self.t2.consistency.proof[1:],
        )
        forged = RetentionTransition(
            self.t2.before, self.t2.prune, bogus_consistency
        )
        with self.assertRaises(ValueError):
            verify_retention_chain(
                self.initial, (self.t1, forged), self.public_key
            )

    def test_read_only(self):
        before = (self.initial, self.chain)
        verify_retention_chain(self.initial, self.chain, self.public_key)
        self.assertEqual((self.initial, self.chain), before)


if __name__ == "__main__":
    unittest.main()
