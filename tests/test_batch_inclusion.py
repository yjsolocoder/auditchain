import hashlib
import itertools
import unittest

from auditchain import AuditLog, verify_batch_inclusion

LEAF = b"auditchain/merkle-leaf/v1"
NODE = b"auditchain/merkle-node/v1"
EMPTY = b"auditchain/merkle-empty/v1"


def leaf(entry_hash, hash_name="sha256"):
    return hashlib.new(hash_name, LEAF + entry_hash).digest()


def node(left, right, hash_name="sha256"):
    return hashlib.new(hash_name, NODE + left + right).digest()


class BatchInclusionProofTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(str(record))

    def test_returns_tuples_of_bytes(self):
        indices, proof = self.log.batch_inclusion_proof([0, 2])
        self.assertIsInstance(indices, tuple)
        self.assertIsInstance(proof, tuple)
        self.assertTrue(all(isinstance(index, int) for index in indices))
        self.assertTrue(all(isinstance(digest, bytes) for digest in proof))

    def test_indices_deduplicated_and_sorted(self):
        indices, proof = self.log.batch_inclusion_proof([4, 0, 2])
        self.assertEqual(indices, (0, 2, 4))
        indices_again, proof_again = self.log.batch_inclusion_proof((0, 2, 4))
        self.assertEqual(indices_again, (0, 2, 4))
        self.assertEqual(proof_again, proof)

    def test_default_size_is_current_length(self):
        indices, proof = self.log.batch_inclusion_proof([1, 3])
        indices_explicit, proof_explicit = self.log.batch_inclusion_proof(
            [1, 3], len(self.log)
        )
        self.assertEqual(indices, indices_explicit)
        self.assertEqual(proof, proof_explicit)

    def test_single_leaf_snapshot_has_empty_proof(self):
        indices, proof = self.log.batch_inclusion_proof([0], 1)
        self.assertEqual(indices, (0,))
        self.assertEqual(proof, ())

    def test_selecting_every_leaf_has_empty_proof(self):
        for size in range(1, len(self.log) + 1):
            indices, proof = self.log.batch_inclusion_proof(range(size), size)
            self.assertEqual(indices, tuple(range(size)))
            self.assertEqual(proof, ())

    def test_empty_selection_rejected(self):
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof(())
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([])
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof((), 0)

    def test_index_validation(self):
        with self.assertRaises(TypeError):
            self.log.batch_inclusion_proof(7)
        with self.assertRaises(TypeError):
            self.log.batch_inclusion_proof(["0"])
        with self.assertRaises(TypeError):
            self.log.batch_inclusion_proof([True])
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([1, 1])
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([-1])
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([len(self.log)])
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([1], 1)
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([6], 6)

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.batch_inclusion_proof([0], "5")
        with self.assertRaises(TypeError):
            self.log.batch_inclusion_proof([0], True)
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([0], len(self.log) + 1)

    def test_read_only(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        for bad in ((), [9], [0, 0], [-1]):
            with self.assertRaises((ValueError, TypeError)):
                self.log.batch_inclusion_proof(bad)
        self.log.batch_inclusion_proof([0, 3, 6])
        after = (len(self.log), self.log.head, self.log.merkle_root())
        self.assertEqual(before, after)

    def test_merges_shared_subtrees(self):
        # Two leaves sharing the subtree over [0,4): the proof must carry the
        # root of [4,8) only once, not two individual inclusion proofs.
        log = AuditLog()
        for record in range(8):
            log.append(str(record))
        single_0 = log.inclusion_proof(0, 8)
        single_1 = log.inclusion_proof(1, 8)
        _, batch = log.batch_inclusion_proof([0, 1], 8)
        self.assertLess(len(batch), len(single_0) + len(single_1))
        # The [4,8) subtree root appears exactly once.
        self.assertEqual(len(batch), 2)

    def test_proof_nodes_are_subtree_roots(self):
        log = AuditLog()
        for record in range(8):
            log.append(str(record))
        indices, proof = log.batch_inclusion_proof([0, 1], 8)
        self.assertEqual(indices, (0, 1))
        right_half = node(
            node(leaf(log.entry(4).entry_hash), leaf(log.entry(5).entry_hash)),
            node(leaf(log.entry(6).entry_hash), leaf(log.entry(7).entry_hash)),
        )
        # Recursion: left [0,4) recursed, then the right [4,8) root appended.
        self.assertEqual(proof[-1], right_half)


class BatchInclusionExhaustiveTest(unittest.TestCase):
    def test_every_subset_of_every_snapshot_verifies(self):
        for n in range(1, 9):
            log = AuditLog()
            for record in range(n):
                log.append(str(record))
            root = log.merkle_root(n)
            for size in range(1, n + 1):
                snapshot_root = log.merkle_root(size)
                for width in range(1, size + 1):
                    for chosen in itertools.combinations(range(size), width):
                        indices, proof = log.batch_inclusion_proof(chosen, size)
                        self.assertEqual(indices, tuple(chosen))
                        hashes = tuple(log.entry(i).entry_hash for i in indices)
                        self.assertTrue(
                            verify_batch_inclusion(
                                indices, hashes, size, snapshot_root, proof
                            ),
                            (n, size, chosen, proof),
                        )
                # The proof is independent of the entries after the snapshot.
                self.assertEqual(root, log.merkle_root(n))

    def test_appends_do_not_change_existing_proofs(self):
        log = AuditLog()
        for record in range(5):
            log.append(str(record))
        before = {
            chosen: log.batch_inclusion_proof(chosen, 5)
            for chosen in ((0,), (1, 3), (0, 2, 4))
        }
        log.append("f")
        log.append("g")
        for chosen, value in before.items():
            self.assertEqual(log.batch_inclusion_proof(chosen, 5), value)

    def test_works_after_prune(self):
        log = AuditLog()
        for record in range(6):
            log.append(str(record))
        receipt = log.seal(2)
        log.prune(2, receipt)
        root = log.merkle_root(6)
        indices, proof = log.batch_inclusion_proof([2, 4, 5])
        hashes = tuple(log.entry(i).entry_hash for i in indices)
        self.assertTrue(verify_batch_inclusion(indices, hashes, 6, root, proof))
        with self.assertRaises(ValueError):
            log.batch_inclusion_proof([0, 4])
        with self.assertRaises(ValueError):
            log.batch_inclusion_proof([2], 1)

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in range(5):
            log.append(str(record))
        root = log.merkle_root()
        indices, proof = log.batch_inclusion_proof([0, 3, 4])
        hashes = tuple(log.entry(i).entry_hash for i in indices)
        self.assertTrue(
            verify_batch_inclusion(
                indices, hashes, 5, root, proof, hash_name="sha3-256"
            )
        )
        # A proof generated under sha3-256 must not verify under sha256.
        self.assertFalse(verify_batch_inclusion(indices, hashes, 5, root, proof))


class VerifyBatchInclusionTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in range(7):
            self.log.append(str(record))
        self.size = len(self.log)
        self.root = self.log.merkle_root()
        self.indices, self.proof = self.log.batch_inclusion_proof([1, 3, 5])
        self.hashes = tuple(self.log.entry(i).entry_hash for i in self.indices)

    def test_valid_proof(self):
        self.assertTrue(
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, self.root, self.proof
            )
        )

    def test_wrong_entry_hash_returns_false(self):
        tampered = (b"\x00" * 32,) + self.hashes[1:]
        self.assertFalse(
            verify_batch_inclusion(
                self.indices, tampered, self.size, self.root, self.proof
            )
        )

    def test_permuted_hashes_return_false(self):
        swapped = (self.hashes[1], self.hashes[0]) + self.hashes[2:]
        self.assertFalse(
            verify_batch_inclusion(
                self.indices, swapped, self.size, self.root, self.proof
            )
        )

    def test_wrong_root_returns_false(self):
        self.assertFalse(
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, b"\x11" * 32, self.proof
            )
        )

    def test_wrong_node_values_return_false(self):
        bogus = (b"\x22" * 32,) * len(self.proof)
        self.assertFalse(
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, self.root, bogus
            )
        )

    def test_indices_must_be_tuple(self):
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                list(self.indices), self.hashes, self.size, self.root, self.proof
            )
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                iter(self.indices), self.hashes, self.size, self.root, self.proof
            )

    def test_entry_hashes_must_be_tuple(self):
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                self.indices, list(self.hashes), self.size, self.root, self.proof
            )

    def test_proof_must_be_tuple(self):
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, self.root, list(self.proof)
            )

    def test_index_element_types(self):
        two_hashes = (self.hashes[0], self.hashes[1])
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                (1, "3"), two_hashes, self.size, self.root, ()
            )
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                (1, True), two_hashes, self.size, self.root, ()
            )

    def test_hash_element_types(self):
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                self.indices, (self.hashes[0], 3, self.hashes[2]),
                self.size, self.root, self.proof,
            )
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                self.indices,
                tuple(bytearray(value) for value in self.hashes),
                self.size,
                self.root,
                self.proof,
            )

    def test_proof_element_types(self):
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, self.root, (1,)
            )
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, self.root,
                tuple(bytearray(node) for node in self.proof),
            )

    def test_root_type(self):
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, "not-bytes", self.proof
            )

    def test_size_type(self):
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                self.indices, self.hashes, "7", self.root, self.proof
            )
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                self.indices, self.hashes, True, self.root, self.proof
            )

    def test_hash_name_type(self):
        with self.assertRaises(TypeError):
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, self.root, self.proof,
                hash_name=None,
            )
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, self.root, self.proof,
                hash_name="not-a-hash",
            )

    def test_empty_indices_rejected(self):
        with self.assertRaises(ValueError):
            verify_batch_inclusion((), (), self.size, self.root, ())
        with self.assertRaises(ValueError):
            verify_batch_inclusion((), (), 0, self.log.merkle_root(0), ())

    def test_indices_must_be_ascending(self):
        hashes = tuple(self.log.entry(i).entry_hash for i in (3, 1))
        with self.assertRaises(ValueError):
            verify_batch_inclusion((3, 1), hashes, self.size, self.root, self.proof)
        with self.assertRaises(ValueError):
            verify_batch_inclusion((1, 1), hashes, self.size, self.root, ())

    def test_index_bounds(self):
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                (-1,), (self.hashes[0],), self.size, self.root, ()
            )
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                (self.size,), (self.hashes[0],), self.size, self.root, ()
            )
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                (0,), (self.hashes[0],), 0, self.log.merkle_root(0), ()
            )

    def test_negative_size(self):
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                self.indices, self.hashes, -1, self.root, self.proof
            )

    def test_sequence_widths_must_match(self):
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                self.indices, self.hashes[:-1], self.size, self.root, self.proof
            )
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                self.indices, self.hashes + (self.hashes[0],),
                self.size, self.root, self.proof,
            )

    def test_digest_widths_checked(self):
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                self.indices, (b"\x00" * 31,) * len(self.indices),
                self.size, self.root, self.proof,
            )
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, b"\x00" * 33, self.proof
            )
        if self.proof:
            with self.assertRaises(ValueError):
                verify_batch_inclusion(
                    self.indices, self.hashes, self.size, self.root,
                    self.proof[:-1] + (b"\x00" * 16,),
                )

    def test_proof_node_count_checked(self):
        if self.proof:
            with self.assertRaises(ValueError):
                verify_batch_inclusion(
                    self.indices, self.hashes, self.size, self.root, self.proof[:-1]
                )
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                self.indices, self.hashes, self.size, self.root,
                self.proof + (b"\x00" * 32,),
            )

    def test_proof_from_other_selection_rejected(self):
        other_indices, other_proof = self.log.batch_inclusion_proof([0, 2])
        other_hashes = tuple(self.log.entry(i).entry_hash for i in other_indices)
        # Either the node count does not fit this selection (ValueError), or it
        # coincides by chance and the rebuilt root simply does not match.
        try:
            result = verify_batch_inclusion(
                other_indices, other_hashes, self.size, self.root, self.proof
            )
        except ValueError:
            pass
        else:
            self.assertFalse(result)

    def test_proof_from_other_size_rejected(self):
        small_indices, small_proof = self.log.batch_inclusion_proof([0], 4)
        small_hashes = tuple(self.log.entry(i).entry_hash for i in small_indices)
        try:
            result = verify_batch_inclusion(
                small_indices, small_hashes, self.size, self.root, small_proof
            )
        except ValueError:
            pass
        else:
            self.assertFalse(result)

    def test_single_leaf_snapshot(self):
        indices, proof = self.log.batch_inclusion_proof([0], 1)
        hashes = (self.log.entry(0).entry_hash,)
        root = self.log.merkle_root(1)
        self.assertTrue(verify_batch_inclusion(indices, hashes, 1, root, proof))
        # An empty proof against a different root is a plain mismatch.
        self.assertFalse(
            verify_batch_inclusion(indices, hashes, 1, b"\x00" * 32, proof)
        )


if __name__ == "__main__":
    unittest.main()
