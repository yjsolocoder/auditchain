import hashlib
import unittest

from auditchain import AuditLog, verify_consistency

LEAF = b"auditchain/merkle-leaf/v1"
NODE = b"auditchain/merkle-node/v1"
EMPTY = b"auditchain/merkle-empty/v1"


def leaf(entry_hash, hash_name="sha256"):
    return hashlib.new(hash_name, LEAF + entry_hash).digest()


def node(left, right, hash_name="sha256"):
    return hashlib.new(hash_name, NODE + left + right).digest()


class ConsistencyProofTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)

    def test_proof_is_immutable_tuple(self):
        proof = self.log.consistency_proof(3)
        self.assertIsInstance(proof, tuple)
        self.assertTrue(all(isinstance(digest, bytes) for digest in proof))

    def test_default_new_size_is_full_log(self):
        self.assertEqual(self.log.consistency_proof(3), self.log.consistency_proof(3, len(self.log)))

    def test_equal_sizes_and_zero_old_size_give_empty_proof(self):
        for size in range(len(self.log) + 1):
            self.assertEqual(self.log.consistency_proof(size, size), ())
            self.assertEqual(self.log.consistency_proof(0, size), ())

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.consistency_proof("3")
        with self.assertRaises(TypeError):
            self.log.consistency_proof(1, 2.5)
        with self.assertRaises(ValueError):
            self.log.consistency_proof(-1)
        with self.assertRaises(ValueError):
            self.log.consistency_proof(4, 2)
        with self.assertRaises(ValueError):
            self.log.consistency_proof(1, len(self.log) + 1)

    def test_appends_do_not_change_proofs(self):
        before = {
            (old, new): self.log.consistency_proof(old, new)
            for new in range(1, len(self.log) + 1)
            for old in range(1, new)
        }
        self.log.append("h")
        self.log.append("i")
        for (old, new), proof in before.items():
            self.assertEqual(self.log.consistency_proof(old, new), proof)

    def test_rfc6962_node_order(self):
        # RFC 6962 §2.1.3 example: PROOF(3, D[7]) = [c, d, g, l] with
        # c = MTH(D[2:3]), d = MTH(D[3:4]), g = MTH(D[0:2]), l = MTH(D[4:7]).
        leaves = [leaf(self.log.entry(i).entry_hash) for i in range(7)]
        expected = (
            leaves[2],
            leaves[3],
            node(leaves[0], leaves[1]),
            node(node(leaves[4], leaves[5]), leaves[6]),
        )
        self.assertEqual(self.log.consistency_proof(3, 7), expected)

    def test_rfc6962_right_branch_order(self):
        # RFC 6962 §2.1.3 example: PROOF(6, D[7]) = [i, j, k] with
        # i = MTH(D[4:6]), j = MTH(D[6:7]), k = MTH(D[0:4]).
        leaves = [leaf(self.log.entry(i).entry_hash) for i in range(7)]
        expected = (
            node(leaves[4], leaves[5]),
            leaves[6],
            node(node(leaves[0], leaves[1]), node(leaves[2], leaves[3])),
        )
        self.assertEqual(self.log.consistency_proof(6, 7), expected)


class VerifyConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)

    def test_every_pair_verifies(self):
        for new in range(1, len(self.log) + 1):
            new_root = self.log.merkle_root(new)
            for old in range(0, new + 1):
                old_root = self.log.merkle_root(old)
                proof = self.log.consistency_proof(old, new)
                self.assertTrue(
                    verify_consistency(old, old_root, new, new_root, proof),
                    f"pair ({old}, {new})",
                )

    def test_equal_snapshots(self):
        root = self.log.merkle_root(4)
        self.assertTrue(verify_consistency(4, root, 4, root, ()))
        other = self.log.merkle_root(5)
        self.assertFalse(verify_consistency(4, root, 4, other, ()))
        with self.assertRaises(ValueError):
            verify_consistency(4, root, 4, root, (b"\x00" * 32,))

    def test_zero_to_zero(self):
        empty = self.log.merkle_root(0)
        self.assertTrue(verify_consistency(0, empty, 0, empty, ()))
        self.assertFalse(verify_consistency(0, empty, 0, b"\x00" * 32, ()))

    def test_zero_old_size_accepts_any_well_formed_new_root(self):
        empty = self.log.merkle_root(0)
        self.assertEqual(empty, hashlib.sha256(EMPTY).digest())
        self.assertTrue(verify_consistency(0, empty, 5, self.log.merkle_root(5), ()))
        self.assertTrue(verify_consistency(0, empty, 5, b"\x00" * 32, ()))
        self.assertFalse(verify_consistency(0, b"\x00" * 32, 5, self.log.merkle_root(5), ()))
        with self.assertRaises(ValueError):
            verify_consistency(0, empty, 5, self.log.merkle_root(5), (b"\x00" * 32,))

    def test_wrong_old_root_returns_false(self):
        proof = self.log.consistency_proof(3, 7)
        self.assertFalse(
            verify_consistency(3, b"\x00" * 32, 7, self.log.merkle_root(7), proof)
        )

    def test_wrong_new_root_returns_false(self):
        proof = self.log.consistency_proof(3, 7)
        self.assertFalse(
            verify_consistency(3, self.log.merkle_root(3), 7, b"\x00" * 32, proof)
        )

    def test_tampered_proof_returns_false(self):
        proof = list(self.log.consistency_proof(3, 7))
        proof[1] = b"\x00" * 32
        self.assertFalse(
            verify_consistency(3, self.log.merkle_root(3), 7, self.log.merkle_root(7), proof)
        )

    def test_proof_node_count_checked(self):
        proof = self.log.consistency_proof(3, 7)
        old_root, new_root = self.log.merkle_root(3), self.log.merkle_root(7)
        with self.assertRaises(ValueError):
            verify_consistency(3, old_root, 7, new_root, proof[:-1])
        with self.assertRaises(ValueError):
            verify_consistency(3, old_root, 7, new_root, proof + (b"\x00" * 32,))
        with self.assertRaises(ValueError):
            verify_consistency(3, old_root, 7, new_root, ())

    def test_type_errors(self):
        old_root, new_root = self.log.merkle_root(3), self.log.merkle_root(7)
        proof = self.log.consistency_proof(3, 7)
        with self.assertRaises(TypeError):
            verify_consistency("3", old_root, 7, new_root, proof)
        with self.assertRaises(TypeError):
            verify_consistency(3, old_root, "7", new_root, proof)
        with self.assertRaises(TypeError):
            verify_consistency(3, "not-bytes", 7, new_root, proof)
        with self.assertRaises(TypeError):
            verify_consistency(3, old_root, 7, "not-bytes", proof)
        with self.assertRaises(TypeError):
            verify_consistency(3, old_root, 7, new_root, "not-a-sequence")
        with self.assertRaises(TypeError):
            verify_consistency(3, old_root, 7, new_root, (b"\x00" * 32, "nope"))
        with self.assertRaises(TypeError):
            verify_consistency(3, old_root, 7, new_root, proof, hash_name=None)

    def test_value_errors(self):
        old_root, new_root = self.log.merkle_root(3), self.log.merkle_root(7)
        proof = self.log.consistency_proof(3, 7)
        with self.assertRaises(ValueError):
            verify_consistency(-1, old_root, 7, new_root, proof)
        with self.assertRaises(ValueError):
            verify_consistency(3, old_root, -7, new_root, proof)
        with self.assertRaises(ValueError):
            verify_consistency(7, old_root, 3, new_root, proof)
        with self.assertRaises(ValueError):
            verify_consistency(3, old_root, 7, new_root, proof, hash_name="not-a-hash")

    def test_digest_length_checked(self):
        old_root, new_root = self.log.merkle_root(3), self.log.merkle_root(7)
        proof = self.log.consistency_proof(3, 7)
        with self.assertRaises(ValueError):
            verify_consistency(3, b"\x00" * 31, 7, new_root, proof)
        with self.assertRaises(ValueError):
            verify_consistency(3, old_root, 7, b"\x00" * 33, proof)
        with self.assertRaises(ValueError):
            verify_consistency(3, old_root, 7, new_root, (b"\x00" * 16,) * len(proof))

    def test_bytearray_and_list_accepted(self):
        old_root, new_root = self.log.merkle_root(3), self.log.merkle_root(7)
        proof = self.log.consistency_proof(3, 7)
        self.assertTrue(
            verify_consistency(
                3, bytearray(old_root), 7, bytearray(new_root), list(proof)
            )
        )

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c", "d", "e"):
            log.append(record)
        old_root, new_root = log.merkle_root(2), log.merkle_root(5)
        proof = log.consistency_proof(2, 5)
        self.assertTrue(
            verify_consistency(2, old_root, 5, new_root, proof, hash_name="sha3-256")
        )
        # Proof generated under sha3-256 must not verify under sha256.
        self.assertFalse(verify_consistency(2, old_root, 5, new_root, proof))


if __name__ == "__main__":
    unittest.main()
