import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    SignedConsistency,
    SignedRoot,
    verify_consistency,
    verify_signed_consistency,
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


class SignedConsistencyIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_bundles_two_checkpoints_and_proof(self):
        receipt = self.log.signed_consistency(3, _SEED_A, 6)
        self.assertIsInstance(receipt, SignedConsistency)
        self.assertEqual(receipt.old, self.log.sign_root(_SEED_A, 3))
        self.assertEqual(receipt.new, self.log.sign_root(_SEED_A, 6))
        self.assertEqual(
            receipt.proof, self.log.consistency_proof(3, 6)
        )

    def test_proof_is_byte_for_byte_consistency_proof(self):
        for old_size, new_size in ((1, 7), (2, 5), (3, 6), (4, 7)):
            receipt = self.log.signed_consistency(old_size, _SEED_A, new_size)
            self.assertEqual(
                receipt.proof,
                self.log.consistency_proof(old_size, new_size),
                (old_size, new_size),
            )
            for element in receipt.proof:
                self.assertIsInstance(element, bytes)
                self.assertEqual(len(element), 32)

    def test_explicit_new_size(self):
        receipt = self.log.signed_consistency(2, _SEED_A, 5)
        self.assertEqual(receipt.old.size, 2)
        self.assertEqual(receipt.new.size, 5)
        self.assertEqual(receipt.old.root, self.log.merkle_root(2))
        self.assertEqual(receipt.new.root, self.log.merkle_root(5))
        self.assertEqual(receipt.old.head, self.log.entry(1).entry_hash)
        self.assertEqual(receipt.new.head, self.log.entry(4).entry_hash)
        self.assertTrue(verify_signed_consistency(receipt, self.public_key))

    def test_new_size_defaults_to_current_length(self):
        receipt = self.log.signed_consistency(3, _SEED_A)
        self.assertEqual(receipt.new.size, len(self.log))
        self.assertEqual(receipt.proof, self.log.consistency_proof(3))
        self.log.append("h")
        grown = self.log.signed_consistency(3, _SEED_A)
        self.assertEqual(grown.new.size, 8)
        self.assertTrue(verify_signed_consistency(grown, self.public_key))

    def test_zero_old_size_uses_canonical_root_zero_head_and_empty_proof(self):
        receipt = self.log.signed_consistency(0, _SEED_A, 5)
        self.assertEqual(receipt.old.size, 0)
        self.assertEqual(receipt.old.root, self.log.merkle_root(0))
        self.assertEqual(receipt.old.head, GENESIS_HASH)
        self.assertEqual(receipt.proof, ())
        self.assertTrue(verify_signed_consistency(receipt, self.public_key))

    def test_equal_sizes_carry_empty_proof_and_equal_roots(self):
        receipt = self.log.signed_consistency(4, _SEED_A, 4)
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.old.root, receipt.new.root)
        self.assertTrue(verify_signed_consistency(receipt, self.public_key))

    def test_empty_log(self):
        receipt = AuditLog().signed_consistency(0, _SEED_A)
        self.assertEqual(receipt.old.size, 0)
        self.assertEqual(receipt.new.size, 0)
        self.assertEqual(receipt.old.head, GENESIS_HASH)
        self.assertEqual(receipt.proof, ())
        self.assertTrue(verify_signed_consistency(receipt, self.public_key))

    def test_all_supported_size_pairs(self):
        for old_size in range(0, 8):
            for new_size in range(old_size, 8):
                receipt = self.log.signed_consistency(old_size, _SEED_A, new_size)
                self.assertTrue(
                    verify_signed_consistency(receipt, self.public_key),
                    (old_size, new_size),
                )

    def test_survives_later_appends(self):
        receipt = self.log.signed_consistency(2, _SEED_A, 5)
        self.log.append("h")
        self.assertTrue(verify_signed_consistency(receipt, self.public_key))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c", "d", "e"):
            log.append(record)
        receipt = log.signed_consistency(2, _SEED_A, 5)
        self.assertEqual(receipt.old.hash_name, "sha512")
        self.assertEqual(receipt.new.hash_name, "sha512")
        for element in receipt.proof:
            self.assertEqual(len(element), 64)
        self.assertTrue(verify_signed_consistency(receipt, self.public_key))

    def test_pruned_log(self):
        log = AuditLog()
        for i in range(7):
            log.append(f"r{i}")
        twin = AuditLog()
        for i in range(7):
            twin.append(f"r{i}")
        log.prune(3, log.seal(3))
        receipt = log.signed_consistency(3, _SEED_A, 6)
        self.assertEqual(receipt.old.root, twin.merkle_root(3))
        self.assertEqual(receipt.new.root, twin.merkle_root(6))
        self.assertEqual(
            receipt.proof, twin.consistency_proof(3, 6)
        )
        self.assertTrue(verify_signed_consistency(receipt, self.public_key))
        # The empty snapshot is a content-free constant, still available.
        empty = log.signed_consistency(0, _SEED_A, 5)
        self.assertTrue(verify_signed_consistency(empty, self.public_key))
        # Equal sizes stay available as an empty proof.
        equal = log.signed_consistency(5, _SEED_A, 5)
        self.assertTrue(verify_signed_consistency(equal, self.public_key))
        with self.assertRaises(ValueError):
            log.signed_consistency(2, _SEED_A, 6)

    def test_positional_construction_and_equality(self):
        receipt = self.log.signed_consistency(3, _SEED_A, 6)
        clone = SignedConsistency(receipt.old, receipt.new, receipt.proof)
        self.assertEqual(receipt, clone)
        other = self.log.signed_consistency(2, _SEED_A, 6)
        self.assertNotEqual(receipt, other)
        self.assertNotEqual(
            receipt, (receipt.old, receipt.new, receipt.proof)
        )

    def test_frozen(self):
        receipt = self.log.signed_consistency(3, _SEED_A, 6)
        with self.assertRaises(FrozenInstanceError):
            receipt.old = receipt.new
        with self.assertRaises(FrozenInstanceError):
            receipt.new = receipt.old
        with self.assertRaises(FrozenInstanceError):
            receipt.proof = ()

    def test_constructor_field_types(self):
        old = self.log.sign_root(_SEED_A, 3)
        new = self.log.sign_root(_SEED_A, 6)
        proof = self.log.consistency_proof(3, 6)
        with self.assertRaises(TypeError):
            SignedConsistency(("not", "a", "signed", "root"), new, proof)
        with self.assertRaises(TypeError):
            SignedConsistency(old, ("not", "a", "signed", "root"), proof)
        with self.assertRaises(TypeError):
            SignedConsistency(old, new, list(proof))
        with self.assertRaises(TypeError):
            SignedConsistency(None, new, proof)
        with self.assertRaises(TypeError):
            SignedConsistency(old, None, proof)
        with self.assertRaises(TypeError):
            SignedConsistency(old, new, None)

    def test_call_is_read_only(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        stage_log = AuditLog(key=b"shared-secret")
        stage_log.append("a")
        self.log.signed_consistency(2, _SEED_A, 6)
        self.log.signed_consistency(0, _SEED_A, 0)
        self.assertEqual((len(self.log), self.log.head, self.log.merkle_root()), before)
        self.assertTrue(self.log.verify())
        self.assertEqual(stage_log.stage, 0)

    def test_failure_leaves_state_unchanged(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        with self.assertRaises(ValueError):
            self.log.signed_consistency(3, _SEED_A, 99)
        with self.assertRaises(ValueError):
            self.log.signed_consistency(6, _SEED_A, 3)
        with self.assertRaises(ValueError):
            self.log.signed_consistency(-1, _SEED_A, 6)
        with self.assertRaises(TypeError):
            self.log.signed_consistency(3, "0" * 32, 6)
        with self.assertRaises(ValueError):
            self.log.signed_consistency(3, _SEED_A[:-1], 6)
        with self.assertRaises(TypeError):
            self.log.signed_consistency(True, _SEED_A, 6)
        with self.assertRaises(TypeError):
            self.log.signed_consistency(3, _SEED_A, "6")
        self.assertEqual((len(self.log), self.log.head, self.log.merkle_root()), before)
        self.assertTrue(self.log.verify())


class VerifySignedConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.receipt = self.log.signed_consistency(3, _SEED_A, 6)

    def bypass(self, *, old=None, new=None, proof=None):
        receipt = SignedConsistency.__new__(SignedConsistency)
        object.__setattr__(
            receipt, "old", self.receipt.old if old is None else old
        )
        object.__setattr__(
            receipt, "new", self.receipt.new if new is None else new
        )
        object.__setattr__(
            receipt,
            "proof",
            self.receipt.proof if proof is None else proof,
        )
        return receipt

    def test_genuine_receipts_verify(self):
        for old_size, new_size in (
            (0, None),
            (0, 0),
            (0, 5),
            (1, None),
            (3, 6),
            (4, 7),
            (5, 5),
            (7, 7),
        ):
            receipt = self.log.signed_consistency(old_size, _SEED_A, new_size)
            self.assertTrue(
                verify_signed_consistency(receipt, self.public_key),
                (old_size, new_size),
            )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_consistency(self.receipt, self.other_public_key)
        )

    def test_other_key_signing_returns_false(self):
        foreign = self.log.signed_consistency(3, _SEED_B, 6)
        self.assertEqual(foreign.old.root, self.receipt.old.root)
        self.assertFalse(
            verify_signed_consistency(foreign, self.public_key)
        )
        self.assertTrue(
            verify_signed_consistency(foreign, self.other_public_key)
        )

    def test_old_signed_by_other_key_returns_false(self):
        old = self.log.sign_root(_SEED_B, 3)
        forged = self.bypass(old=old)
        self.assertTrue(verify_signed_root(old, self.other_public_key))
        self.assertTrue(verify_signed_root(self.receipt.new, self.public_key))
        self.assertFalse(verify_signed_consistency(forged, self.public_key))

    def test_new_signed_by_other_key_returns_false(self):
        new = self.log.sign_root(_SEED_B, 6)
        forged = self.bypass(new=new)
        self.assertFalse(verify_signed_consistency(forged, self.public_key))

    def test_mixed_hash_name_returns_false(self):
        other_log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            other_log.append(record)
        foreign_new = other_log.sign_root(_SEED_A, 6)
        forged = self.bypass(new=foreign_new)
        # Both signatures are genuine under the trusted key; only the
        # snapshot association (hash_name) is wrong.
        self.assertTrue(verify_signed_root(forged.old, self.public_key))
        self.assertTrue(verify_signed_root(forged.new, self.public_key))
        self.assertFalse(verify_signed_consistency(forged, self.public_key))

    def test_unrelated_signed_roots_and_proof_return_false(self):
        other_log = AuditLog()
        for record in ("x", "y", "z", "w", "u", "v", "t"):
            other_log.append(record)
        foreign_new = other_log.sign_root(_SEED_A, 6)
        forged = self.bypass(new=foreign_new)
        self.assertTrue(verify_signed_root(forged.new, self.public_key))
        self.assertFalse(verify_signed_consistency(forged, self.public_key))

    def test_swapped_sizes_raises_value_error(self):
        # Both checkpoints are genuine and signed by the trusted key, but
        # old.size > new.size: verify_consistency treats that as a
        # structurally illegal pair and raises ValueError.
        swapped = SignedConsistency(
            self.receipt.new, self.receipt.old, ()
        )
        with self.assertRaises(ValueError):
            verify_signed_consistency(swapped, self.public_key)

    def test_tampered_proof_digest_returns_false(self):
        proof = self.receipt.proof
        tampered = (b"\x11" * 32,) + proof[1:]
        forged = self.bypass(proof=tampered)
        self.assertFalse(verify_signed_consistency(forged, self.public_key))

    def test_wrong_proof_node_count_raises_value_error(self):
        proof = self.receipt.proof
        forged = self.bypass(proof=proof[1:])
        with self.assertRaises(ValueError):
            verify_signed_consistency(forged, self.public_key)
        forged_extra = self.bypass(proof=proof + (b"\x22" * 32,))
        with self.assertRaises(ValueError):
            verify_signed_consistency(forged_extra, self.public_key)

    def test_non_empty_proof_for_zero_old_size_raises_value_error(self):
        receipt = self.log.signed_consistency(0, _SEED_A, 5)
        forged = self.bypass(proof=(b"\x33" * 32,))
        with self.assertRaises(ValueError):
            verify_signed_consistency(forged, self.public_key)

    def test_non_empty_proof_for_equal_sizes_raises_value_error(self):
        receipt = self.log.signed_consistency(4, _SEED_A, 4)
        forged = self.bypass(proof=(b"\x44" * 32,))
        with self.assertRaises(ValueError):
            verify_signed_consistency(forged, self.public_key)

    def test_proof_element_wrong_type_raises_type_error(self):
        forged = self.bypass(proof=("not-a-digest",) + self.receipt.proof[1:])
        with self.assertRaises(TypeError):
            verify_signed_consistency(forged, self.public_key)

    def test_not_a_receipt_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signed_consistency(
                (self.receipt.old, self.receipt.new, self.receipt.proof),
                self.public_key,
            )
        with self.assertRaises(TypeError):
            verify_signed_consistency(None, self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_consistency(self.receipt.old, self.public_key)

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_consistency(self.receipt, "0" * 32)
        with self.assertRaises(TypeError):
            verify_signed_consistency(self.receipt, bytearray(self.public_key))
        with self.assertRaises(TypeError):
            verify_signed_consistency(self.receipt, memoryview(self.public_key))
        with self.assertRaises(ValueError):
            verify_signed_consistency(self.receipt, self.public_key[:-1])
        with self.assertRaises(ValueError):
            verify_signed_consistency(self.receipt, self.public_key + b"\x00")

    def test_bypassed_container_type_errors_propagate(self):
        broken = self.bypass(old=("not", "a", "signed", "root"))
        with self.assertRaises(TypeError):
            verify_signed_consistency(broken, self.public_key)
        broken = self.bypass(new=("not", "a", "signed", "root"))
        with self.assertRaises(TypeError):
            verify_signed_consistency(broken, self.public_key)
        broken = self.bypass(proof=list(self.receipt.proof))
        with self.assertRaises(TypeError):
            verify_signed_consistency(broken, self.public_key)

    def test_nested_checkpoint_value_errors_propagate(self):
        checkpoint = self.receipt.new
        bad = SignedRoot.__new__(SignedRoot)
        for name, value in (
            ("version", checkpoint.version),
            ("hash_name", "not-a-hash"),
            ("size", checkpoint.size),
            ("root", checkpoint.root),
            ("head", checkpoint.head),
            ("signature", checkpoint.signature),
        ):
            object.__setattr__(bad, name, value)
        forged = self.bypass(new=bad)
        with self.assertRaises(ValueError):
            verify_signed_consistency(forged, self.public_key)

    def test_tampered_checkpoint_signature_returns_false(self):
        checkpoint = self.receipt.new
        bad = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = self.bypass(new=bad)
        self.assertFalse(verify_signed_consistency(forged, self.public_key))

    def test_relabeled_old_root_with_valid_signature_returns_false(self):
        # A genuine checkpoint signed by the trusted key but over another
        # log's size-3 snapshot: signatures all verify and the proof node
        # count still fits (3, 6), yet the proof cannot link that root to
        # the new one.
        other_log = AuditLog()
        for record in ("x", "y", "z", "w", "u", "v", "t"):
            other_log.append(record)
        foreign_old = other_log.sign_root(_SEED_A, 3)
        forged = self.bypass(old=foreign_old)
        self.assertTrue(verify_signed_root(forged.old, self.public_key))
        self.assertTrue(verify_signed_root(forged.new, self.public_key))
        self.assertFalse(verify_signed_consistency(forged, self.public_key))

    def test_underlying_verify_consistency_agrees(self):
        self.assertTrue(
            verify_consistency(
                self.receipt.old.size,
                self.receipt.old.root,
                self.receipt.new.size,
                self.receipt.new.root,
                self.receipt.proof,
                hash_name=self.receipt.old.hash_name,
            )
        )

    def test_call_is_read_only(self):
        verify_signed_consistency(self.receipt, self.other_public_key)
        self.assertEqual(
            self.receipt, self.log.signed_consistency(3, _SEED_A, 6)
        )


if __name__ == "__main__":
    unittest.main()
