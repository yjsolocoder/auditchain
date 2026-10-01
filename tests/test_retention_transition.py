import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
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


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _make_log(count: int = 8, *, key: bytes | None = None) -> AuditLog:
    log = AuditLog(key=key)
    for index in range(count):
        log.append(f"record-{index}")
    return log


def _mutate(field: str, value):
    """Build a RetentionTransition whose frozen field is bypassed."""
    log = _make_log()
    initial = log.sign_root(_SEED_A, 0)
    transition = log.prune_with_retention_transition(initial, 3, _SEED_A)
    object.__setattr__(transition, field, value)
    return transition


class RetentionTransitionConstructionTest(unittest.TestCase):
    def setUp(self):
        self.log = _make_log()
        self.initial = self.log.sign_root(_SEED_A, 0)
        self.transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )

    def test_fields(self):
        self.assertIsInstance(self.transition, RetentionTransition)
        self.assertEqual(self.transition.before, self.initial)
        self.assertEqual(self.transition.prune, self.log.sign_prune(_SEED_A, 3))
        self.assertEqual(
            self.transition.consistency,
            self.log.signed_consistency(0, _SEED_A, 3),
        )

    def test_positional_construction_and_equality(self):
        clone = RetentionTransition(
            self.transition.before,
            self.transition.prune,
            self.transition.consistency,
        )
        self.assertEqual(clone, self.transition)
        # A transition whose before checkpoint carries another signature is a
        # different object even though every other field is equal.
        other_before = self.log.sign_root(_SEED_B, 0)
        self.assertNotEqual(
            clone,
            RetentionTransition(other_before, self.transition.prune,
                                self.transition.consistency),
        )

    def test_keyword_construction(self):
        clone = RetentionTransition(
            before=self.transition.before,
            prune=self.transition.prune,
            consistency=self.transition.consistency,
        )
        self.assertIs(clone.before, self.transition.before)
        self.assertEqual(clone, self.transition)

    def test_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            self.transition.before = self.initial
        with self.assertRaises(FrozenInstanceError):
            self.transition.prune = self.transition.prune
        with self.assertRaises(FrozenInstanceError):
            self.transition.consistency = self.transition.consistency

    def test_wrong_field_types(self):
        before = self.transition.before
        prune = self.transition.prune
        consistency = self.transition.consistency
        for bad in (None, 1, "before", b"x", (), prune, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RetentionTransition(bad, prune, consistency)
        for bad in (None, 1, "prune", b"x", (), before, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RetentionTransition(before, bad, consistency)
        for bad in (None, 1, "consistency", b"x", (), before, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RetentionTransition(before, prune, bad)


class PruneWithRetentionTransitionIssuanceTest(unittest.TestCase):
    def test_first_release_from_zero_boundary(self):
        log = _make_log(8)
        initial = log.sign_root(_SEED_A, 0)
        transition = log.prune_with_retention_transition(initial, 3, _SEED_A)
        self.assertEqual(log.retain_from, 3)
        self.assertEqual(len(log), 8)
        self.assertEqual([e.index for e in log], [3, 4, 5, 6, 7])
        self.assertTrue(log.verify())
        # The bundled credentials are exactly the existing primitives.
        self.assertEqual(transition.before, initial)
        self.assertEqual(transition.prune.receipt.size, 3)
        self.assertEqual(transition.prune.checkpoint.size, 3)
        self.assertEqual(transition.consistency.old, initial)
        self.assertEqual(transition.consistency.new, transition.prune.checkpoint)
        # The new boundary is what the next call must hand back as before.
        self.assertEqual(transition.prune.checkpoint, log.sign_root(_SEED_A, 3))
        # Every credential verifies offline on its own.
        self.assertTrue(verify_signed_root(initial, _public_key(_SEED_A)))
        self.assertTrue(verify_signed_prune(transition.prune, _public_key(_SEED_A)))
        self.assertTrue(
            verify_signed_consistency(transition.consistency, _public_key(_SEED_A))
        )

    def test_chained_releases_grow_append_only(self):
        log = _make_log(8)
        initial = log.sign_root(_SEED_A, 0)
        first = log.prune_with_retention_transition(initial, 3, _SEED_A)
        log.append("record-8")
        log.append("record-9")
        second = log.prune_with_retention_transition(
            first.prune.checkpoint, 6, _SEED_A
        )
        self.assertEqual(log.retain_from, 6)
        self.assertEqual(len(log), 10)
        self.assertEqual(second.before, first.prune.checkpoint)
        self.assertEqual(second.consistency.old, first.prune.checkpoint)
        self.assertEqual(second.consistency.new, second.prune.checkpoint)
        self.assertEqual(second.prune.checkpoint, log.sign_root(_SEED_A, 6))
        public = _public_key(_SEED_A)
        self.assertTrue(verify_retention_chain(initial, (first, second), public))

    def test_release_to_log_end(self):
        log = _make_log(5)
        initial = log.sign_root(_SEED_A, 0)
        transition = log.prune_with_retention_transition(initial, 5, _SEED_A)
        self.assertEqual(log.retain_from, 5)
        self.assertEqual(log.entries(), [])
        self.assertTrue(log.verify())
        self.assertTrue(
            verify_retention_chain(initial, (transition,), _public_key(_SEED_A))
        )

    def test_appends_between_releases_still_extend(self):
        log = _make_log(4)
        initial = log.sign_root(_SEED_A, 0)
        first = log.prune_with_retention_transition(initial, 2, _SEED_A)
        for payload in ("more-a", "more-b", "more-c"):
            log.append(payload)
        second = log.prune_with_retention_transition(
            first.prune.checkpoint, 5, _SEED_A
        )
        self.assertEqual(second.before.size, 2)
        self.assertEqual(second.prune.checkpoint.size, 5)
        self.assertTrue(
            verify_retention_chain(initial, (first, second), _public_key(_SEED_A))
        )

    def test_non_sha256_log(self):
        log = AuditLog(hash_name="sha512")
        for index in range(6):
            log.append(f"r{index}")
        initial = log.sign_root(_SEED_A, 0)
        transition = log.prune_with_retention_transition(initial, 4, _SEED_A)
        self.assertEqual(transition.before.hash_name, "sha512")
        self.assertTrue(
            verify_retention_chain(initial, (transition,), _public_key(_SEED_A))
        )

    def test_returns_frozen_transition(self):
        log = _make_log()
        initial = log.sign_root(_SEED_A, 0)
        transition = log.prune_with_retention_transition(initial, 3, _SEED_A)
        with self.assertRaises(FrozenInstanceError):
            transition.prune = transition.prune


class PruneWithRetentionTransitionTypeErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = _make_log(8)
        self.initial = self.log.sign_root(_SEED_A, 0)

    def _assert_unchanged(self):
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 8)
        self.assertEqual([e.index for e in self.log], list(range(8)))

    def test_before_wrong_type(self):
        for bad in (None, 0, b"x", "checkpoint", (), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.log.prune_with_retention_transition(bad, 3, _SEED_A)
        self._assert_unchanged()

    def test_retain_from_wrong_type(self):
        for bad in (None, 1.5, "3", b"3", [3], (3,), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.log.prune_with_retention_transition(self.initial, bad, _SEED_A)
        self._assert_unchanged()

    def test_private_key_wrong_type(self):
        for bad in (None, 32, _SEED_A.decode("latin-1"), bytearray(_SEED_A),
                    memoryview(_SEED_A)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.log.prune_with_retention_transition(self.initial, 3, bad)
        self._assert_unchanged()


class PruneWithRetentionTransitionValueErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = _make_log(8)
        self.initial = self.log.sign_root(_SEED_A, 0)

    def _assert_unchanged(self):
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 8)
        self.assertEqual([e.index for e in self.log], list(range(8)))
        self.assertTrue(self.log.verify())

    def test_seed_wrong_length(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.log.prune_with_retention_transition(self.initial, 3, bad)
        self._assert_unchanged()

    def test_target_equal_to_before_size_is_reversed_or_empty(self):
        # A release must strictly advance the boundary.
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(self.initial, 0, _SEED_A)
        self._assert_unchanged()

    def test_target_behind_before_size(self):
        first = self.log.prune_with_retention_transition(self.initial, 3, _SEED_A)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(first.prune.checkpoint, 2, _SEED_A)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(len(self.log), 8)

    def test_target_beyond_log_length(self):
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(self.initial, 9, _SEED_A)
        self._assert_unchanged()

    def test_negative_before_size_checkpoint_rejected(self):
        # A SignedRoot cannot carry a negative size, but a checkpoint signed
        # at a different (smaller) size is not the current boundary.
        other = self.log.sign_root(_SEED_A, 2)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(other, 3, _SEED_A)
        self._assert_unchanged()

    def test_before_must_equal_current_retain_point(self):
        # First release done, then replaying the same old boundary fails.
        first = self.log.prune_with_retention_transition(self.initial, 3, _SEED_A)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(self.initial, 5, _SEED_A)
        self.assertEqual(self.log.retain_from, 3)
        # A same-sized checkpoint from a log with different entries has a
        # different boundary root/head and is rejected.
        divergent = AuditLog()
        divergent.append("totally")
        divergent.append("different")
        divergent.append("records")
        divergent.append("extra")
        wrong_boundary = divergent.sign_root(_SEED_A, 3)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(wrong_boundary, 5, _SEED_A)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(len(self.log), 8)

    def test_before_signed_by_another_key(self):
        foreign = self.log.sign_root(_SEED_B, 0)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(foreign, 3, _SEED_A)
        self._assert_unchanged()

    def test_before_hash_name_mismatch(self):
        twin = AuditLog(hash_name="sha512")
        for index in range(8):
            twin.append(f"record-{index}")
        foreign = twin.sign_root(_SEED_A, 0)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(foreign, 3, _SEED_A)
        self._assert_unchanged()

    def test_tampered_before_root(self):
        tampered = SignedRoot(
            self.initial.version,
            self.initial.hash_name,
            self.initial.size,
            b"\x01" * 32,
            self.initial.head,
            self.initial.signature,
        )
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(tampered, 3, _SEED_A)
        self._assert_unchanged()

    def test_future_snapshot_is_not_current_boundary(self):
        # A validly signed checkpoint of a non-boundary prefix is not a
        # legitimate starting boundary for an unpruned log.
        future = self.log.sign_root(_SEED_A, 5)
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(future, 6, _SEED_A)
        self._assert_unchanged()

    def test_tampered_before_signature(self):
        raw = bytearray(self.initial.signature)
        raw[0] ^= 0xFF
        tampered = SignedRoot(
            self.initial.version,
            self.initial.hash_name,
            self.initial.size,
            self.initial.root,
            self.initial.head,
            bytes(raw),
        )
        with self.assertRaises(ValueError):
            self.log.prune_with_retention_transition(tampered, 3, _SEED_A)
        self._assert_unchanged()


class PruneWithRetentionTransitionStatePreservationTest(unittest.TestCase):
    def _snapshot_state(self, log):
        return (
            log.retain_from,
            len(log),
            [e for e in log.entries()],
            log.head,
            log.merkle_root(),
            log.stage,
            dict(log._tags),
            dict(log._index),
            set(log._used_nonces),
            dict(log._frontier),
            log._checkpoint_head,
        )

    def test_failure_changes_nothing_with_auth_encryption(self):
        from auditchain import verify_auth

        key = b"\x02" * 32
        log = AuditLog(key=key)
        nonce = b"\x07" * 12
        log.encrypt("secret", key, nonce)
        for index in range(4):
            log.append(f"r{index}")
        verifier = log.export_verifier()
        tag = log.auth(0)
        initial = log.sign_root(_SEED_A, 0)
        before = self._snapshot_state(log)
        for bad_target in (-1, 0, 6):
            with self.assertRaises(ValueError):
                log.prune_with_retention_transition(initial, bad_target, _SEED_A)
        foreign = log.sign_root(_SEED_B, 0)
        with self.assertRaises(ValueError):
            log.prune_with_retention_transition(foreign, 3, _SEED_A)
        with self.assertRaises(ValueError):
            log.prune_with_retention_transition(initial, 3, b"\x00" * 31)
        with self.assertRaises(TypeError):
            log.prune_with_retention_transition(initial, True, _SEED_A)
        after = self._snapshot_state(log)
        self.assertEqual(before, after)
        # Authentication material and the nonce history are untouched.
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))
        self.assertIn(nonce, log._used_nonces)
        with self.assertRaises(ValueError):
            log.encrypt("other", key, nonce)

    def test_successful_release_prunes_like_prune_signed(self):
        log = _make_log(6)
        twin = _make_log(6)
        initial = log.sign_root(_SEED_A, 0)
        transition = log.prune_with_retention_transition(initial, 4, _SEED_A)
        twin.prune_signed(4, twin.sign_prune(_SEED_A, 4), _public_key(_SEED_A))
        self.assertEqual([e for e in log], [e for e in twin])
        self.assertEqual(log.head, twin.head)
        self.assertEqual(log.retain_from, twin.retain_from)
        self.assertEqual(log._frontier, twin._frontier)
        self.assertEqual(log._checkpoint_head, twin._checkpoint_head)
        self.assertEqual(log._index, twin._index)


class VerifyRetentionChainTest(unittest.TestCase):
    def setUp(self):
        self.public = _public_key(_SEED_A)

    def _chain(self):
        log = _make_log(8)
        initial = log.sign_root(_SEED_A, 0)
        first = log.prune_with_retention_transition(initial, 2, _SEED_A)
        log.append("x")
        log.append("y")
        second = log.prune_with_retention_transition(
            first.prune.checkpoint, 5, _SEED_A
        )
        log.append("z")
        third = log.prune_with_retention_transition(
            second.prune.checkpoint, 9, _SEED_A
        )
        return initial, (first, second, third)

    def test_genuine_chain(self):
        initial, transitions = self._chain()
        self.assertTrue(verify_retention_chain(initial, transitions, self.public))

    def test_empty_transitions_valid_initial(self):
        initial = _make_log().sign_root(_SEED_A, 0)
        self.assertTrue(verify_retention_chain(initial, (), self.public))

    def test_single_transition(self):
        log = _make_log(3)
        initial = log.sign_root(_SEED_A, 0)
        transition = log.prune_with_retention_transition(initial, 3, _SEED_A)
        self.assertTrue(
            verify_retention_chain(initial, (transition,), self.public)
        )

    def test_initial_must_be_signed_root(self):
        for bad in (None, 0, b"x", "cp", (), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_retention_chain(bad, (), self.public)

    def test_transitions_must_be_tuple(self):
        initial = _make_log().sign_root(_SEED_A, 0)
        for bad in ([], None, iter(())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_retention_chain(initial, bad, self.public)

    def test_transition_element_wrong_type(self):
        initial = _make_log().sign_root(_SEED_A, 0)
        for bad in (None, 1, "t", b"x", (), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_retention_chain(initial, (bad,), self.public)

    def test_public_key_wrong_type(self):
        initial, transitions = self._chain()
        for bad in (None, 32, self.public.decode("latin-1"),
                    bytearray(self.public), memoryview(self.public)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_retention_chain(initial, transitions, bad)

    def test_public_key_wrong_length(self):
        initial, transitions = self._chain()
        with self.assertRaises(ValueError):
            verify_retention_chain(initial, transitions, b"\x00" * 31)
        with self.assertRaises(ValueError):
            verify_retention_chain(initial, (), b"\x00" * 33)

    def test_empty_transitions_bad_initial_signature_returns_false(self):
        initial = _make_log().sign_root(_SEED_A, 0)
        raw = bytearray(initial.signature)
        raw[0] ^= 1
        bad = SignedRoot(
            initial.version, initial.hash_name, initial.size,
            initial.root, initial.head, bytes(raw),
        )
        self.assertFalse(verify_retention_chain(bad, (), self.public))

    def test_empty_transitions_other_key_returns_false(self):
        initial = _make_log().sign_root(_SEED_A, 0)
        self.assertFalse(
            verify_retention_chain(initial, (), _public_key(_SEED_B))
        )

    def test_wrong_initial(self):
        _, transitions = self._chain()
        other = _make_log(8).sign_root(_SEED_A, 1)
        self.assertFalse(verify_retention_chain(other, transitions, self.public))

    def test_dropped_prefix_transition(self):
        initial, transitions = self._chain()
        self.assertFalse(
            verify_retention_chain(initial, transitions[1:], self.public)
        )

    def test_dropped_suffix_still_verifies(self):
        initial, transitions = self._chain()
        self.assertTrue(
            verify_retention_chain(initial, transitions[:2], self.public)
        )

    def test_reversed_order(self):
        initial, transitions = self._chain()
        self.assertFalse(
            verify_retention_chain(initial, tuple(reversed(transitions)), self.public)
        )

    def test_repeated_transition(self):
        initial, transitions = self._chain()
        self.assertFalse(
            verify_retention_chain(initial, (transitions[0], transitions[0]), self.public)
        )

    def test_foreign_key_transition_returns_false(self):
        initial, transitions = self._chain()
        self.assertFalse(
            verify_retention_chain(initial, transitions, _public_key(_SEED_B))
        )

    def test_tampered_prune_returns_false(self):
        initial, transitions = self._chain()
        first = transitions[0]
        receipt = first.prune.receipt
        tampered_receipt = type(receipt)(
            receipt.hash_name,
            receipt.size,
            b"\x09" * len(receipt.merkle_root),
            receipt.chain_hash,
        )
        tampered_prune = SignedPrune(tampered_receipt, first.prune.checkpoint)
        tampered = RetentionTransition(first.before, tampered_prune,
                                       first.consistency)
        self.assertFalse(
            verify_retention_chain(initial, (tampered,) + transitions[1:], self.public)
        )

    def test_tampered_consistency_proof_returns_false(self):
        initial, transitions = self._chain()
        # The first transition (0 -> 2) carries the mandatory empty proof, so
        # tamper a later transition whose proof is non-empty.
        target = transitions[1]
        proof = target.consistency.proof
        self.assertTrue(proof)
        tampered_proof = (b"\x0a" * len(proof[0]),) + proof[1:]
        tampered_consistency = SignedConsistency(
            target.consistency.old, target.consistency.new, tampered_proof
        )
        tampered = RetentionTransition(target.before, target.prune, tampered_consistency)
        replaced = transitions[:1] + (tampered,) + transitions[2:]
        self.assertFalse(
            verify_retention_chain(initial, replaced, self.public)
        )

    def test_mismatched_consistency_endpoints_returns_false(self):
        initial, transitions = self._chain()
        first = transitions[0]
        # A genuine proof over a different span, spliced into the transition.
        log = _make_log(8)
        foreign = log.signed_consistency(1, _SEED_A, 3)
        tampered = RetentionTransition(first.before, first.prune, foreign)
        self.assertFalse(
            verify_retention_chain(initial, (tampered,) + transitions[1:], self.public)
        )

    def test_bypassed_field_types_raise_type_error(self):
        initial, transitions = self._chain()
        for field in ("before", "prune", "consistency"):
            tampered = _mutate(field, b"not-an-object")
            with self.assertRaises(TypeError):
                verify_retention_chain(initial, (tampered,), self.public)

    def test_bypassed_nested_field_types_raise(self):
        initial, transitions = self._chain()
        first = transitions[0]
        bad_prune = SignedPrune(first.prune.receipt, first.prune.checkpoint)
        object.__setattr__(bad_prune, "receipt", b"y")
        tampered = RetentionTransition(first.before, bad_prune, first.consistency)
        with self.assertRaises(TypeError):
            verify_retention_chain(initial, (tampered,), self.public)


class RetentionTransitionCodecTest(unittest.TestCase):
    def setUp(self):
        log = _make_log(8)
        initial = log.sign_root(_SEED_A, 0)
        first = log.prune_with_retention_transition(initial, 2, _SEED_A)
        log.append("x")
        second = log.prune_with_retention_transition(
            first.prune.checkpoint, 6, _SEED_A
        )
        self.transition = second
        self.public = _public_key(_SEED_A)
        self.initial = initial
        self.first = first

    def test_roundtrip(self):
        from auditchain import (
            encode_retention_transition,
            decode_retention_transition,
        )

        data = encode_retention_transition(self.transition)
        self.assertIsInstance(data, bytes)
        self.assertTrue(
            data.startswith(b"auditchain/retention-transition/v1\0")
        )
        restored = decode_retention_transition(data)
        self.assertEqual(restored, self.transition)
        self.assertEqual(encode_retention_transition(restored), data)

    def test_restored_transition_verifies_in_chain(self):
        from auditchain import (
            encode_retention_transition,
            decode_retention_transition,
        )

        log = _make_log(8)
        initial = log.sign_root(_SEED_A, 0)
        first = log.prune_with_retention_transition(initial, 2, _SEED_A)
        log.append("x")
        second = log.prune_with_retention_transition(
            first.prune.checkpoint, 6, _SEED_A
        )
        data = encode_retention_transition(second)
        restored = decode_retention_transition(data)
        self.assertTrue(
            verify_retention_chain(initial, (first, restored), self.public)
        )

    def test_first_transition_from_zero_roundtrips(self):
        from auditchain import (
            encode_retention_transition,
            decode_retention_transition,
        )

        data = encode_retention_transition(self.first)
        restored = decode_retention_transition(data)
        self.assertEqual(restored, self.first)
        self.assertTrue(
            verify_retention_chain(self.initial, (restored,), self.public)
        )

    def test_encode_wrong_type(self):
        from auditchain import encode_retention_transition

        for bad in (None, 1, b"x", "t", (), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_retention_transition(bad)

    def test_decode_wrong_type(self):
        from auditchain import (
            encode_retention_transition,
            decode_retention_transition,
        )

        data = encode_retention_transition(self.transition)
        for bad in (None, 1, "x", bytearray(data), memoryview(data), []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_retention_transition(bad)

    def test_decode_bad_magic(self):
        from auditchain import decode_retention_transition

        with self.assertRaises(ValueError):
            decode_retention_transition(b"not an encoding" + b"\x00" * 40)

    def test_decode_bad_version(self):
        from auditchain import (
            encode_retention_transition,
            decode_retention_transition,
        )

        data = bytearray(encode_retention_transition(self.transition))
        magic_len = len(b"auditchain/retention-transition/v1\0")
        data[magic_len + 7] = 2
        with self.assertRaises(ValueError):
            decode_retention_transition(bytes(data))

    def test_decode_truncated(self):
        from auditchain import (
            encode_retention_transition,
            decode_retention_transition,
        )

        data = encode_retention_transition(self.transition)
        for cut in (1, 32, len(data) - 1):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_retention_transition(data[:cut])

    def test_decode_trailing_bytes(self):
        from auditchain import (
            encode_retention_transition,
            decode_retention_transition,
        )

        data = encode_retention_transition(self.transition)
        with self.assertRaises(ValueError):
            decode_retention_transition(data + b"\x00")

    def test_decode_rejects_other_magic(self):
        from auditchain import (
            encode_signed_prune,
            decode_retention_transition,
        )

        with self.assertRaises(ValueError):
            decode_retention_transition(encode_signed_prune(self.transition.prune))

    def test_deterministic_across_calls(self):
        from auditchain import encode_retention_transition

        first = encode_retention_transition(self.transition)
        second = encode_retention_transition(self.transition)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
