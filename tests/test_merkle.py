import hashlib
import unittest

from auditchain import AuditLog, verify_inclusion

LEAF = b"auditchain/merkle-leaf/v1"
NODE = b"auditchain/merkle-node/v1"
EMPTY = b"auditchain/merkle-empty/v1"


def leaf(entry_hash, hash_name="sha256"):
    return hashlib.new(hash_name, LEAF + entry_hash).digest()


def node(left, right, hash_name="sha256"):
    return hashlib.new(hash_name, NODE + left + right).digest()


class MerkleRootTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_empty_root_is_domain_hash(self):
        self.assertEqual(AuditLog().merkle_root(), hashlib.sha256(EMPTY).digest())
        self.assertEqual(self.log.merkle_root(0), hashlib.sha256(EMPTY).digest())

    def test_single_leaf_root_is_leaf(self):
        entry = self.log.entry(0)
        self.assertEqual(self.log.merkle_root(1), leaf(entry.entry_hash))

    def test_two_leaves_combine(self):
        left = leaf(self.log.entry(0).entry_hash)
        right = leaf(self.log.entry(1).entry_hash)
        self.assertEqual(self.log.merkle_root(2), node(left, right))

    def test_odd_count_promotes_last(self):
        a, b, c = (leaf(self.log.entry(i).entry_hash) for i in range(3))
        self.assertEqual(self.log.merkle_root(3), node(node(a, b), c))

    def test_default_size_is_full_log(self):
        self.assertEqual(self.log.merkle_root(), self.log.merkle_root(len(self.log)))

    def test_size_type_and_range(self):
        with self.assertRaises(TypeError):
            self.log.merkle_root("3")
        with self.assertRaises(ValueError):
            self.log.merkle_root(-1)
        with self.assertRaises(ValueError):
            self.log.merkle_root(len(self.log) + 1)

    def test_appends_do_not_change_prefix_roots(self):
        before = {size: self.log.merkle_root(size) for size in range(len(self.log) + 1)}
        self.log.append("f")
        self.log.append("g")
        for size, root in before.items():
            self.assertEqual(self.log.merkle_root(size), root)

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        log.append("a")
        log.append("b")
        expected = node(leaf(log.entry(0).entry_hash, "sha3-256"), leaf(log.entry(1).entry_hash, "sha3-256"), "sha3-256")
        self.assertEqual(log.merkle_root(), expected)


class InclusionProofTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_proof_is_immutable_tuple(self):
        proof = self.log.inclusion_proof(2)
        self.assertIsInstance(proof, tuple)
        self.assertTrue(all(isinstance(digest, bytes) for digest in proof))

    def test_single_entry_proof_is_empty(self):
        self.assertEqual(self.log.inclusion_proof(0, 1), ())

    def test_index_validation(self):
        with self.assertRaises(TypeError):
            self.log.inclusion_proof("0")
        with self.assertRaises(ValueError):
            self.log.inclusion_proof(-1)
        with self.assertRaises(ValueError):
            self.log.inclusion_proof(len(self.log))
        with self.assertRaises(ValueError):
            self.log.inclusion_proof(0, 0)

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.inclusion_proof(0, 1.5)
        with self.assertRaises(ValueError):
            self.log.inclusion_proof(0, len(self.log) + 1)

    def test_appends_do_not_change_prefix_proofs(self):
        before = [self.log.inclusion_proof(i, 4) for i in range(4)]
        self.log.append("f")
        self.assertEqual([self.log.inclusion_proof(i, 4) for i in range(4)], before)

    def test_every_entry_verifies_against_full_root(self):
        root = self.log.merkle_root()
        for index in range(len(self.log)):
            entry = self.log.entry(index)
            proof = self.log.inclusion_proof(index)
            self.assertTrue(verify_inclusion(entry.entry_hash, index, len(self.log), root, proof))

    def test_every_prefix_verifies(self):
        for size in range(1, len(self.log) + 1):
            root = self.log.merkle_root(size)
            for index in range(size):
                entry = self.log.entry(index)
                proof = self.log.inclusion_proof(index, size)
                self.assertTrue(verify_inclusion(entry.entry_hash, index, size, root, proof))


class VerifyInclusionTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.root = self.log.merkle_root()

    def proof_for(self, index):
        entry = self.log.entry(index)
        return entry.entry_hash, self.log.inclusion_proof(index)

    def test_wrong_entry_hash_returns_false(self):
        _, proof = self.proof_for(2)
        self.assertFalse(verify_inclusion(b"\x00" * 32, 2, 5, self.root, proof))

    def test_wrong_root_returns_false(self):
        entry_hash, proof = self.proof_for(2)
        self.assertFalse(verify_inclusion(entry_hash, 2, 5, b"\x00" * 32, proof))

    def test_wrong_index_returns_false(self):
        entry_hash, proof = self.proof_for(2)
        self.assertFalse(verify_inclusion(entry_hash, 3, 5, self.root, proof))

    def test_wrong_size_rejected(self):
        entry_hash, proof = self.proof_for(1)
        # Proof for size 5 has more levels than size 4 expects.
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 1, 4, self.log.merkle_root(4), proof)

    def test_unknown_hash_algorithm(self):
        entry_hash, proof = self.proof_for(0)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, 5, self.root, proof, hash_name="not-a-hash")
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, 0, 5, self.root, proof, hash_name=None)

    def test_type_errors(self):
        entry_hash, proof = self.proof_for(0)
        with self.assertRaises(TypeError):
            verify_inclusion("not-bytes", 0, 5, self.root, proof)
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, 0, 5, "not-bytes", proof)
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, "0", 5, self.root, proof)
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, 0, "5", self.root, proof)
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, 0, 5, self.root, "not-a-sequence")
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, 0, 5, self.root, (b"\x00" * 32, "nope"))

    def test_negative_and_out_of_range(self):
        entry_hash, proof = self.proof_for(0)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, -1, 5, self.root, proof)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, -5, self.root, proof)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 5, 5, self.root, proof)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, 0, self.root, ())

    def test_digest_length_checked(self):
        entry_hash, proof = self.proof_for(0)
        with self.assertRaises(ValueError):
            verify_inclusion(b"\x00" * 31, 0, 5, self.root, proof)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, 5, b"\x00" * 33, proof)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, 5, self.root, (b"\x00" * 16,))

    def test_proof_level_count_checked(self):
        entry_hash, proof = self.proof_for(0)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, 5, self.root, proof[:-1])
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, 5, self.root, proof + (b"\x00" * 32,))

    def test_bytearray_and_list_accepted(self):
        entry_hash, proof = self.proof_for(3)
        self.assertTrue(
            verify_inclusion(bytearray(entry_hash), 3, 5, bytearray(self.root), list(proof))
        )

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        root = log.merkle_root()
        entry = log.entry(1)
        proof = log.inclusion_proof(1)
        self.assertTrue(
            verify_inclusion(entry.entry_hash, 1, 3, root, proof, hash_name="sha3-256")
        )
        # Proof generated under sha3-256 must not verify under sha256.
        self.assertFalse(verify_inclusion(entry.entry_hash, 1, 3, root, proof))


if __name__ == "__main__":
    unittest.main()
