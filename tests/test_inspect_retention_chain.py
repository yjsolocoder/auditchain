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
    RetentionReport,
    RetentionTransition,
    SignedConsistency,
    SignedPrune,
    SignedRoot,
    decode_retention_transition,
    encode_retention_transition,
    inspect_retention_chain,
    verify_retention_chain,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _fresh_log(count: int = 0, *, hash_name: str = "sha256") -> AuditLog:
    log = AuditLog(hash_name=hash_name)
    for i in range(count):
        log.append(f"r{i}")
    return log


def _bypassed(instance, field, value):
    forged = type(instance).__new__(type(instance))
    for name in instance.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(instance, name))
    object.__setattr__(forged, field, value)
    return forged


class InspectRetentionChainTest(unittest.TestCase):
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
        report = inspect_retention_chain(
            self.initial, self.chain, self.public_key
        )
        self.assertEqual(report, RetentionReport(True, None, None))
        self.assertEqual(
            report,
            inspect_retention_chain(
                self.initial, self.chain, self.public_key
            ),
        )

    def test_ok_matches_verify_retention_chain(self):
        cases = (
            (self.initial, self.chain),
            (self.initial, (self.t1,)),
            (self.initial, (self.t1, self.t2)),
            (self.initial, ()),
            (self.initial, (self.t1, self.t3)),
            (self.initial, (self.t2, self.t1, self.t3)),
            (self.initial, (self.t1, self.t1)),
            (self.t1.prune.checkpoint, self.chain),
            (self.initial, self.chain),
        )
        for initial, chain in cases:
            self.assertEqual(
                inspect_retention_chain(
                    initial, chain, self.public_key
                ).ok,
                verify_retention_chain(initial, chain, self.public_key),
                (initial.size, tuple(t.prune.checkpoint.size for t in chain)),
            )

    def test_prefixes_of_the_chain_pass(self):
        for prefix in ((), (self.t1,), (self.t1, self.t2), self.chain):
            self.assertEqual(
                inspect_retention_chain(
                    self.initial, prefix, self.public_key
                ),
                RetentionReport(True, None, None),
                len(prefix),
            )

    def test_empty_chain_with_invalid_initial_is_initial(self):
        foreign = self.log.sign_root(_SEED_B, 0)
        self.assertEqual(
            inspect_retention_chain(foreign, (), self.public_key),
            RetentionReport(False, None, "initial"),
        )

    def test_wrong_public_key_is_initial(self):
        self.assertEqual(
            inspect_retention_chain(
                self.initial, self.chain, self.other_public_key
            ),
            RetentionReport(False, None, "initial"),
        )
        # ...even for an empty chain.
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (), self.other_public_key
            ),
            RetentionReport(False, None, "initial"),
        )

    def test_wrong_initial_is_link_at_first_step(self):
        # A genuine checkpoint that is not the first step's boundary.
        other = self.t1.prune.checkpoint
        self.assertEqual(
            inspect_retention_chain(other, self.chain, self.public_key),
            RetentionReport(False, 0, "link"),
        )

    def test_reordered_steps_is_link(self):
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (self.t2, self.t1, self.t3), self.public_key
            ),
            RetentionReport(False, 0, "link"),
        )

    def test_missing_step_is_link_at_the_jump(self):
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (self.t1, self.t3), self.public_key
            ),
            RetentionReport(False, 1, "link"),
        )

    def test_repeated_step_is_link(self):
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (self.t1, self.t1), self.public_key
            ),
            RetentionReport(False, 1, "link"),
        )

    def test_tampered_prune_is_prune(self):
        receipt = self.t1.prune.receipt
        bogus_receipt = PruneReceipt(
            receipt.hash_name,
            receipt.size + 1,
            receipt.merkle_root,
            receipt.chain_hash,
        )
        forged_prune = SignedPrune(bogus_receipt, self.t1.prune.checkpoint)
        forged = RetentionTransition(
            self.t1.before, forged_prune, self.t1.consistency
        )
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (forged,), self.public_key
            ),
            RetentionReport(False, 0, "prune"),
        )

    def test_tampered_consistency_proof_is_consistency(self):
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
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (self.t1, forged), self.public_key
            ),
            RetentionReport(False, 1, "consistency"),
        )

    def test_wrong_length_consistency_proof_is_consistency_not_value_error(self):
        # Structurally legal fields (a tuple of digest-width bytes) whose
        # node count does not match the snapshot sizes: diagnosed, not
        # raised — unlike verify_retention_chain, which propagates the
        # structural ValueError for the same input.
        nodes = self.t2.consistency.proof
        self.assertGreater(len(nodes), 0)
        bogus_consistency = SignedConsistency(
            self.t2.consistency.old,
            self.t2.consistency.new,
            nodes[:-1],
        )
        forged = RetentionTransition(
            self.t2.before, self.t2.prune, bogus_consistency
        )
        with self.assertRaises(ValueError):
            verify_retention_chain(
                self.initial, (self.t1, forged), self.public_key
            )
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (self.t1, forged), self.public_key
            ),
            RetentionReport(False, 1, "consistency"),
        )

    def test_cross_wired_checkpoints_is_binding(self):
        # Structurally genuine credentials that do not bind t3's two
        # snapshots: a real 3->10 consistency in place of t3's 6->10 one,
        # minted from an unpruned twin holding the whole history.
        twin = _fresh_log(10)
        other = twin.signed_consistency(3, _SEED_A, 10)
        bogus = RetentionTransition(
            self.t3.before, self.t3.prune, other
        )
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (self.t1, self.t2, bogus), self.public_key
            ),
            RetentionReport(False, 2, "binding"),
        )

    def test_other_algorithm_credentials_is_binding(self):
        # Genuine sha512 credentials spliced into a sha256 chain: every
        # credential verifies on its own, but the algorithm is not the
        # initial checkpoint's.
        other = _fresh_log(8, hash_name="sha512")
        other_initial = other.sign_root(_SEED_A, 0)
        other_t1 = other.prune_with_retention_transition(
            other_initial, 3, _SEED_A
        )
        forged = RetentionTransition(
            self.t1.before, other_t1.prune, other_t1.consistency
        )
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (forged,), self.public_key
            ),
            RetentionReport(False, 0, "binding"),
        )

    def test_non_growing_handmade_step_is_growth(self):
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
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (same_step,), self.public_key
            ),
            RetentionReport(False, 0, "growth"),
        )

    def test_first_failure_only_is_reported(self):
        # t2 fails to link after t1 is dropped; t3 is never examined, even
        # though it cannot join either.
        report = inspect_retention_chain(
            self.initial, (self.t2, self.t3), self.public_key
        )
        self.assertEqual(report, RetentionReport(False, 0, "link"))
        # A step whose before both fails to link and belongs to a prune
        # that would fail reports only the link.
        receipt = self.t2.prune.receipt
        bogus_receipt = PruneReceipt(
            receipt.hash_name,
            receipt.size + 1,
            receipt.merkle_root,
            receipt.chain_hash,
        )
        forged = RetentionTransition(
            self.t2.before,
            SignedPrune(bogus_receipt, self.t2.prune.checkpoint),
            self.t2.consistency,
        )
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (forged,), self.public_key
            ),
            RetentionReport(False, 0, "link"),
        )

    def test_expected_end_of_genuine_chain_passes(self):
        self.assertEqual(
            inspect_retention_chain(
                self.initial,
                self.chain,
                self.public_key,
                expected_end=self.t3.prune.checkpoint,
            ),
            RetentionReport(True, None, None),
        )

    def test_truncated_tail_is_end_at_last_step(self):
        # A genuine chain whose tail was cut off: every retained step
        # verifies, but the promised end checkpoint is not reached.
        self.assertEqual(
            inspect_retention_chain(
                self.initial,
                (self.t1, self.t2),
                self.public_key,
                expected_end=self.t3.prune.checkpoint,
            ),
            RetentionReport(False, 1, "end"),
        )
        self.assertEqual(
            inspect_retention_chain(
                self.initial,
                self.chain,
                self.public_key,
                expected_end=self.t2.prune.checkpoint,
            ),
            RetentionReport(False, 2, "end"),
        )

    def test_expected_end_with_forged_signature_is_end(self):
        forged_end = SignedRoot(
            self.t3.prune.checkpoint.version,
            self.t3.prune.checkpoint.hash_name,
            self.t3.prune.checkpoint.size,
            self.t3.prune.checkpoint.root,
            self.t3.prune.checkpoint.head,
            b"\x00" * 64,
        )
        self.assertEqual(
            inspect_retention_chain(
                self.initial,
                self.chain,
                self.public_key,
                expected_end=forged_end,
            ),
            RetentionReport(False, 2, "end"),
        )

    def test_expected_end_signed_by_other_key_is_end(self):
        foreign = _fresh_log(10)
        foreign_end = foreign.sign_root(_SEED_B, 10)
        self.assertEqual(
            inspect_retention_chain(
                self.initial,
                self.chain,
                self.public_key,
                expected_end=foreign_end,
            ),
            RetentionReport(False, 2, "end"),
        )

    def test_empty_chain_end_is_the_initial_checkpoint(self):
        # The actual end of an empty chain is the initial checkpoint, so an
        # equal expected end passes...
        self.assertEqual(
            inspect_retention_chain(
                self.initial, (), self.public_key, expected_end=self.initial
            ),
            RetentionReport(True, None, None),
        )
        # ...and any other end fails with no step position...
        self.assertEqual(
            inspect_retention_chain(
                self.initial,
                (),
                self.public_key,
                expected_end=self.t1.prune.checkpoint,
            ),
            RetentionReport(False, None, "end"),
        )
        # ...while a wrong public key still blames the initial checkpoint.
        self.assertEqual(
            inspect_retention_chain(
                self.initial,
                (),
                self.other_public_key,
                expected_end=self.initial,
            ),
            RetentionReport(False, None, "initial"),
        )

    def test_expected_end_not_examined_before_chain_passes(self):
        # A broken chain reports its own first failure; the expected end is
        # only consulted once the whole chain verifies.
        self.assertEqual(
            inspect_retention_chain(
                self.initial,
                (self.t1, self.t3),
                self.public_key,
                expected_end=self.t3.prune.checkpoint,
            ),
            RetentionReport(False, 1, "link"),
        )

    def test_decoded_transitions_diagnose_like_fresh_ones(self):
        decoded = tuple(
            decode_retention_transition(encode_retention_transition(t))
            for t in self.chain
        )
        self.assertEqual(
            inspect_retention_chain(
                self.initial, decoded, self.public_key
            ),
            RetentionReport(True, None, None),
        )
        self.assertEqual(
            inspect_retention_chain(
                self.initial,
                decoded,
                self.public_key,
                expected_end=self.t3.prune.checkpoint,
            ),
            RetentionReport(True, None, None),
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
            self.assertEqual(
                inspect_retention_chain(
                    initial, (t1, t2), self.public_key
                ),
                RetentionReport(True, None, None),
                hash_name,
            )
            self.assertEqual(
                inspect_retention_chain(
                    initial,
                    (t1,),
                    self.public_key,
                    expected_end=t2.prune.checkpoint,
                ),
                RetentionReport(False, 0, "end"),
                hash_name,
            )

    def test_read_only(self):
        before = (self.initial, self.chain, self.t3.prune.checkpoint)
        inspect_retention_chain(
            self.initial,
            self.chain,
            self.public_key,
            expected_end=self.t3.prune.checkpoint,
        )
        inspect_retention_chain(
            self.initial, (self.t1, self.t3), self.public_key
        )
        self.assertEqual(
            (self.initial, self.chain, self.t3.prune.checkpoint), before
        )
        self.assertTrue(self.log.verify())


class InspectRetentionChainStructureTest(unittest.TestCase):
    def setUp(self):
        self.log = _fresh_log(8)
        self.public_key = _public_key(_SEED_A)
        self.initial = self.log.sign_root(_SEED_A, 0)
        self.t1 = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )

    def test_initial_type_error(self):
        for bad in (None, 1, b"bytes", self.t1, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                inspect_retention_chain(bad, (), self.public_key)

    def test_transitions_type_error(self):
        for bad in (None, [], self.t1, (self.t1 for _ in (1,))):
            with self.assertRaises(TypeError, msg=repr(bad)):
                inspect_retention_chain(
                    self.initial, bad, self.public_key
                )

    def test_transition_element_type_error(self):
        for bad in (None, 1, "x", self.t1.prune, self.t1.consistency):
            with self.assertRaises(TypeError, msg=repr(bad)):
                inspect_retention_chain(
                    self.initial, (self.t1, bad), self.public_key
                )

    def test_expected_end_type_error(self):
        for bad in (0, "x", b"bytes", self.t1, self.t1.prune, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                inspect_retention_chain(
                    self.initial,
                    (),
                    self.public_key,
                    expected_end=bad,
                )

    def test_public_key_type_and_shape(self):
        with self.assertRaises(TypeError):
            inspect_retention_chain(
                self.initial, (), bytearray(self.public_key)
            )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_retention_chain(self.initial, (), bad)

    def test_bypassed_container_field_types_type_error(self):
        forged = _bypassed(self.t1, "before", None)
        with self.assertRaises(TypeError):
            inspect_retention_chain(
                self.initial, (forged,), self.public_key
            )
        forged = _bypassed(self.t1, "prune", self.t1.consistency)
        with self.assertRaises(TypeError):
            inspect_retention_chain(
                self.initial, (forged,), self.public_key
            )

    def test_bypassed_nested_fields_raise_like_constructor(self):
        for field, value in (
            ("version", 2),
            ("hash_name", 7),
            ("size", "3"),
            ("root", b"\x00" * 31),
            ("head", b"\x00" * 33),
            ("signature", b"\x00" * 63),
        ):
            forged_before = _bypassed(self.t1.before, field, value)
            forged = _bypassed(self.t1, "before", forged_before)
            with self.assertRaises(
                (TypeError, ValueError), msg=field
            ):
                inspect_retention_chain(
                    self.initial, (forged,), self.public_key
                )

    def test_bypassed_unknown_hash_algorithm_is_value_error(self):
        forged_before = _bypassed(self.t1.before, "hash_name", "md0")
        forged = _bypassed(self.t1, "before", forged_before)
        with self.assertRaises(ValueError):
            inspect_retention_chain(
                self.initial, (forged,), self.public_key
            )

    def test_bypassed_expected_end_fields_raise_like_constructor(self):
        forged_end = _bypassed(
            self.t1.prune.checkpoint, "signature", b"\x00" * 63
        )
        with self.assertRaises(ValueError):
            inspect_retention_chain(
                self.initial,
                (),
                self.public_key,
                expected_end=forged_end,
            )

    def test_structure_error_anywhere_takes_priority_over_diagnosis(self):
        # The first step would fail to link, but the bypassed second step
        # is a structural error and must raise before any diagnosis.
        forged = _bypassed(self.t1, "before", None)
        other_initial = self.t1.prune.checkpoint
        with self.assertRaises(TypeError):
            inspect_retention_chain(
                other_initial, (self.t1, forged), self.public_key
            )

    def test_wrong_width_proof_node_is_value_error(self):
        log = _fresh_log(11)
        initial = log.sign_root(_SEED_A, 0)
        t1 = log.prune_with_retention_transition(initial, 3, _SEED_A)
        t2 = log.prune_with_retention_transition(
            t1.prune.checkpoint, 11, _SEED_A
        )
        bogus_consistency = SignedConsistency(
            t2.consistency.old,
            t2.consistency.new,
            (b"\x00" * 7,) + t2.consistency.proof[1:],
        )
        forged = RetentionTransition(
            t2.before, t2.prune, bogus_consistency
        )
        with self.assertRaises(ValueError):
            inspect_retention_chain(
                initial, (t1, forged), self.public_key
            )


class RetentionReportTest(unittest.TestCase):
    def test_success_report(self):
        report = RetentionReport(True, None, None)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)

    def test_failure_reports(self):
        for code, index in (
            ("initial", None),
            ("link", 0),
            ("before", 1),
            ("prune", 2),
            ("consistency", 3),
            ("binding", 4),
            ("growth", 5),
            ("end", 6),
            ("end", None),
        ):
            report = RetentionReport(False, index, code)
            self.assertFalse(report.ok)
            self.assertEqual(report.index, index)
            self.assertEqual(report.code, code)

    def test_frozen(self):
        report = RetentionReport(True, None, None)
        with self.assertRaises(FrozenInstanceError):
            report.ok = False
        with self.assertRaises(FrozenInstanceError):
            report.index = 0
        with self.assertRaises(FrozenInstanceError):
            report.code = "initial"

    def test_ok_type_error(self):
        for bad in (None, 0, 1, "x"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RetentionReport(bad, None, None)

    def test_success_must_carry_no_index_or_code(self):
        with self.assertRaises(ValueError):
            RetentionReport(True, 0, None)
        with self.assertRaises(ValueError):
            RetentionReport(True, None, "initial")
        with self.assertRaises(ValueError):
            RetentionReport(True, 0, "link")

    def test_failure_must_carry_a_code(self):
        with self.assertRaises(ValueError):
            RetentionReport(False, None, None)
        with self.assertRaises(ValueError):
            RetentionReport(False, 0, None)

    def test_code_type_and_value(self):
        with self.assertRaises(TypeError):
            RetentionReport(False, 0, 7)
        with self.assertRaises(ValueError):
            RetentionReport(False, 0, "unknown")

    def test_index_type_and_value(self):
        for bad in (True, False, 1.5, "0"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RetentionReport(False, bad, "link")
        with self.assertRaises(ValueError):
            RetentionReport(False, -1, "link")

    def test_initial_carries_no_position(self):
        with self.assertRaises(ValueError):
            RetentionReport(False, 0, "initial")

    def test_step_codes_must_carry_a_position(self):
        for code in (
            "link",
            "before",
            "prune",
            "consistency",
            "binding",
            "growth",
        ):
            with self.assertRaises(ValueError, msg=code):
                RetentionReport(False, None, code)

    def test_equality_and_hash(self):
        self.assertEqual(
            RetentionReport(False, 1, "prune"),
            RetentionReport(False, 1, "prune"),
        )
        self.assertNotEqual(
            RetentionReport(False, 1, "prune"),
            RetentionReport(False, 1, "growth"),
        )
        self.assertIn(
            RetentionReport(True, None, None),
            {RetentionReport(True, None, None)},
        )


if __name__ == "__main__":
    unittest.main()
