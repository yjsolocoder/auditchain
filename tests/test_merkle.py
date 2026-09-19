import hashlib
import unittest

from auditchain import AuditLog, verify_inclusion

LEAF = b"auditchain/merkle-leaf/v1"
NODE = b"auditchain/merkle-node/v1"
EMPTY = b"auditchain/merkle-empty/v1"


def leaf(entry_hash):
    return hashlib.sha256(LEAF + entry_hash).digest()


def node(left, right):
    return hashlib.sha256(NODE + left + right).digest()


class MerkleRootTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_empty_root_is_domain_hash(self):
        empty = AuditLog()
        expected = hashlib.sha256(EMPTY).digest()
        self.assertEqual(empty.merkle_root(), expected)
        self.assertEqual(self.log.merkle_root(0), expected)

    def test_single_leaf_root_is_the_leaf(self):
        self.assertEqual(self.log.merkle_root(1), leaf(self.log.entry(0).entry_hash))

    def test_two_leaves(self):
        expected = node(leaf(self.log.entry(0).entry_hash), leaf(self.log.entry(1).entry_hash))
        self.assertEqual(self.log.merkle_root(2), expected)

    def test_odd_count_promotes_last_node(self):
        leaves = [leaf(self.log.entry(i).entry_hash) for i in range(3)]
        expected = node(node(leaves[0], leaves[1]), leaves[2])
        self.assertEqual(self.log.merkle_root(3), expected)

    def test_default_size_is_full_log(self):
        self.assertEqual(self.log.merkle_root(), self.log.merkle_root(len(self.log)))

    def test_appends_do_not_change_prefix_roots(self):
        roots = [self.log.merkle_root(size) for size in range(len(self.log) + 1)]
        self.log.append("f")
        self.log.append("g")
        for size, root in enumerate(roots):
            self.assertEqual(self.log.merkle_root(size), root)

    def test_size_type_and_range_checked(self):
        with self.assertRaises(TypeError):
            self.log.merkle_root("3")
        with self.assertRaises(ValueError):
            self.log.merkle_root(-1)
        with self.assertRaises(ValueError):
            self.log.merkle_root(len(self.log) + 1)

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        log.append("a")
        log.append("b")
        self.assertEqual(len(log.merkle_root()), hashlib.new("sha3-256").digest_size)


class InclusionProofTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_proof_is_immutable_tuple(self):
        proof = self.log.inclusion_proof(2)
        self.assertIsInstance(proof, tuple)
        self.assertTrue(all(isinstance(element, bytes) for element in proof))

    def test_single_entry_proof_is_empty(self):
        self.assertEqual(self.log.inclusion_proof(0, 1), ())

    def test_proof_verifies_for_every_index_and_size(self):
        for size in range(1, len(self.log) + 1):
            root = self.log.merkle_root(size)
            for index in range(size):
                proof = self.log.inclusion_proof(index, size)
                self.assertTrue(
                    verify_inclusion(self.log.entry(index).entry_hash, index, size, root, proof),
                    f"index={index} size={size}",
                )

    def test_appends_do_not_change_prefix_proofs(self):
        proofs = [(i, s, self.log.inclusion_proof(i, s)) for s in range(1, 6) for i in range(s)]
        self.log.append("f")
        for index, size, proof in proofs:
            self.assertEqual(self.log.inclusion_proof(index, size), proof)

    def test_index_bounds_checked(self):
        with self.assertRaises(TypeError):
            self.log.inclusion_proof("0")
        with self.assertRaises(ValueError):
            self.log.inclusion_proof(-1)
        with self.assertRaises(ValueError):
            self.log.inclusion_proof(len(self.log))
        with self.assertRaises(ValueError):
            AuditLog().inclusion_proof(0)


class VerifyInclusionTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.size = len(self.log)
        self.root = self.log.merkle_root()

    def proof(self, index):
        return self.log.inclusion_proof(index)

    def test_correct_proof_accepted(self):
        self.assertTrue(
            verify_inclusion(self.log.entry(3).entry_hash, 3, self.size, self.root, self.proof(3))
        )

    def test_wrong_entry_rejected(self):
        self.assertFalse(
            verify_inclusion(self.log.entry(2).entry_hash, 3, self.size, self.root, self.proof(3))
        )

    def test_wrong_root_rejected(self):
        other = self.log.merkle_root(4)
        self.assertFalse(
            verify_inclusion(self.log.entry(3).entry_hash, 3, self.size, other, self.proof(3))
        )

    def test_swapped_siblings_rejected(self):
        proof = list(self.proof(0))
        proof[0], proof[1] = proof[1], proof[0]
        self.assertFalse(
            verify_inclusion(self.log.entry(0).entry_hash, 0, self.size, self.root, tuple(proof))
        )

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        proof = log.inclusion_proof(1)
        self.assertTrue(
            verify_inclusion(
                log.entry(1).entry_hash, 1, 3, log.merkle_root(), proof, hash_name="sha3-256"
            )
        )

    def test_unknown_hash_rejected(self):
        with self.assertRaises(ValueError):
            verify_inclusion(
                self.log.entry(0).entry_hash, 0, self.size, self.root, self.proof(0),
                hash_name="not-a-hash",
            )

    def test_type_errors(self):
        entry_hash = self.log.entry(0).entry_hash
        proof = self.proof(0)
        with self.assertRaises(TypeError):
            verify_inclusion("not-bytes", 0, self.size, self.root, proof)
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, "0", self.size, self.root, proof)
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, 0, "5", self.root, proof)
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, 0, self.size, "root", proof)
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, 0, self.size, self.root, "not-a-tuple")
        with self.assertRaises(TypeError):
            verify_inclusion(entry_hash, 0, self.size, self.root, proof, hash_name=256)

    def test_negative_and_out_of_range_rejected(self):
        entry_hash = self.log.entry(0).entry_hash
        proof = self.proof(0)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, -1, self.size, self.root, proof)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, -1, self.root, proof)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, 0, self.root, ())
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, self.size, self.size, self.root, proof)

    def test_digest_lengths_checked(self):
        entry_hash = self.log.entry(0).entry_hash
        proof = self.proof(0)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash[:-1], 0, self.size, self.root, proof)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, self.size, self.root[:-1], proof)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, self.size, self.root, proof[:-1] + (b"\x00",))

    def test_proof_level_count_checked(self):
        entry_hash = self.log.entry(0).entry_hash
        proof = self.proof(0)
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, self.size, self.root, proof[:-1])
        with self.assertRaises(ValueError):
            verify_inclusion(entry_hash, 0, self.size, self.root, proof + (proof[-1],))


if __name__ == "__main__":
    unittest.main()
