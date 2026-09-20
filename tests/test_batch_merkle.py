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
        for record in range(7):
            self.log.append(f"record-{record}")

    def test_returns_ascending_indices_and_tuple_proof(self):
        indices, proof = self.log.batch_inclusion_proof([5, 1, 3])
        self.assertEqual(indices, (1, 3, 5))
        self.assertIsInstance(indices, tuple)
        self.assertIsInstance(proof, tuple)
        self.assertTrue(all(isinstance(digest, bytes) for digest in proof))

    def test_generator_and_set_iterables_accepted(self):
        indices, proof = self.log.batch_inclusion_proof(i for i in (2, 4))
        self.assertEqual(indices, (2, 4))
        indices, proof = self.log.batch_inclusion_proof({4, 2})
        self.assertEqual(indices, (2, 4))

    def test_canonical_independent_of_input_order(self):
        first = self.log.batch_inclusion_proof([6, 0, 3])
        second = self.log.batch_inclusion_proof((0, 3, 6))
        self.assertEqual(first, second)
        self.assertEqual(first[0], (0, 3, 6))

    def test_single_leaf_proof_verifies(self):
        indices, proof = self.log.batch_inclusion_proof([0])
        self.assertEqual(indices, (0,))
        root = self.log.merkle_root()
        self.assertTrue(
            verify_batch_inclusion(
                indices,
                tuple(self.log.entry(i).entry_hash for i in indices),
                len(self.log),
                root,
                proof,
            )
        )

    def test_size_one_has_empty_proof(self):
        indices, proof = self.log.batch_inclusion_proof([0], 1)
        self.assertEqual(indices, (0,))
        self.assertEqual(proof, ())
        self.assertTrue(
            verify_batch_inclusion(
                indices,
                (self.log.entry(0).entry_hash,),
                1,
                self.log.merkle_root(1),
                (),
            )
        )

    def test_all_leaves_selected_has_empty_proof(self):
        selected = tuple(range(len(self.log)))
        indices, proof = self.log.batch_inclusion_proof(selected)
        self.assertEqual(indices, selected)
        self.assertEqual(proof, ())
        self.assertTrue(
            verify_batch_inclusion(
                indices,
                tuple(self.log.entry(i).entry_hash for i in indices),
                len(self.log),
                self.log.merkle_root(),
                (),
            )
        )

    def test_every_subset_of_every_prefix_verifies(self):
        for size in range(1, len(self.log) + 1):
            root = self.log.merkle_root(size)
            for count in range(1, size + 1):
                for selection in itertools.combinations(range(size), count):
                    indices, proof = self.log.batch_inclusion_proof(selection, size)
                    self.assertEqual(indices, selection)
                    hashes = tuple(self.log.entry(i).entry_hash for i in indices)
                    self.assertTrue(
                        verify_batch_inclusion(indices, hashes, size, root, proof),
                        (size, selection, proof),
                    )

    def test_proof_covers_whole_tree_and_merges_duplicates(self):
        # Selecting both leaves of the right aligned pair needs only the root
        # of the untouched left 4-subtree for size 6: one node instead of two
        # separate inclusion proofs.
        indices, proof = self.log.batch_inclusion_proof([4, 5], 6)
        self.assertEqual(indices, (4, 5))
        self.assertEqual(len(proof), 1)
        left_four = node(
            node(
                leaf(self.log.entry(0).entry_hash),
                leaf(self.log.entry(1).entry_hash),
            ),
            node(
                leaf(self.log.entry(2).entry_hash),
                leaf(self.log.entry(3).entry_hash),
            ),
        )
        self.assertEqual(proof, (left_four,))

    def test_default_size_is_current_length(self):
        indices, proof = self.log.batch_inclusion_proof([2])
        explicit = self.log.batch_inclusion_proof([2], len(self.log))
        self.assertEqual((indices, proof), explicit)

    def test_prefix_proofs_stable_after_appends(self):
        before = {
            selection: self.log.batch_inclusion_proof(selection, 6)
            for selection in ((0,), (1, 4), (0, 2, 5))
        }
        self.log.append("record-7")
        self.log.append("record-8")
        for selection, result in before.items():
            self.assertEqual(self.log.batch_inclusion_proof(selection, 6), result)

    def test_empty_selection_rejected(self):
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([])
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof(())
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof(set())

    def test_duplicate_indices_rejected(self):
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([1, 1])
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof((3, 3, 1))

    def test_index_types_rejected(self):
        for bad in (True, False, 1.0, "1", b"1", None):
            with self.assertRaises(TypeError):
                self.log.batch_inclusion_proof([bad])

    def test_non_iterable_rejected(self):
        with self.assertRaises(TypeError):
            self.log.batch_inclusion_proof(3)

    def test_out_of_range_indices_rejected(self):
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([-1])
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([len(self.log)])
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([0, len(self.log)])
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([3], 3)

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.batch_inclusion_proof([0], "7")
        with self.assertRaises(TypeError):
            self.log.batch_inclusion_proof([0], 1.5)
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([0], -1)
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([0], len(self.log) + 1)

    def test_pruned_snapshot_not_rebuildable(self):
        receipt = self.log.seal(3)
        self.log.prune(3, receipt)
        # Snapshot wholly inside the pruned prefix.
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([1, 2])
        # A selected index inside the pruned prefix is out of the retained range.
        with self.assertRaises(ValueError):
            self.log.batch_inclusion_proof([1, 4], 6)
        # A retained snapshot still works and verifies.
        indices, proof = self.log.batch_inclusion_proof([3, 6], 7)
        self.assertTrue(
            verify_batch_inclusion(
                indices,
                tuple(self.log.entry(i).entry_hash for i in indices),
                7,
                self.log.merkle_root(7),
                proof,
            )
        )

    def test_generation_is_read_only(self):
        snapshot = (
            self.log.head,
            len(self.log),
            self.log.retain_from,
            self.log.merkle_root(),
            tuple(e.entry_hash for e in self.log.entries()),
        )
        self.log.batch_inclusion_proof([0, 3, 6])
        self.log.batch_inclusion_proof([2], 5)
        after = (
            self.log.head,
            len(self.log),
            self.log.retain_from,
            self.log.merkle_root(),
            tuple(e.entry_hash for e in self.log.entries()),
        )
        self.assertEqual(snapshot, after)

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in range(6):
            log.append(f"record-{record}")
        root = log.merkle_root()
        for selection in ((0,), (1, 4), (0, 2, 5), tuple(range(6))):
            indices, proof = log.batch_inclusion_proof(selection)
            hashes = tuple(log.entry(i).entry_hash for i in indices)
            self.assertTrue(
                verify_batch_inclusion(
                    indices, hashes, len(log), root, proof, hash_name="sha3-256"
                ),
                selection,
            )
        # A proof generated under sha3-256 must not verify under sha256.
        indices, proof = log.batch_inclusion_proof([1, 4])
        hashes = tuple(log.entry(i).entry_hash for i in indices)
        self.assertFalse(
            verify_batch_inclusion(indices, hashes, len(log), root, proof)
        )


class VerifyBatchInclusionTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in range(7):
            self.log.append(f"record-{record}")
        self.indices, self.proof = self.log.batch_inclusion_proof([1, 3, 5])
        self.hashes = tuple(self.log.entry(i).entry_hash for i in self.indices)
        self.root = self.log.merkle_root()
        self.size = len(self.log)

    def verify(self, **overrides):
        arguments = dict(
            indices=self.indices,
            entry_hashes=self.hashes,
            size=self.size,
            root=self.root,
            proof=self.proof,
        )
        arguments.update(overrides)
        return verify_batch_inclusion(**arguments)

    def test_valid_proof_passes(self):
        self.assertIs(self.verify(), True)

    def test_wrong_entry_hash_returns_false(self):
        tampered = (b"\x00" * 32,) + self.hashes[1:]
        self.assertIs(self.verify(entry_hashes=tampered), False)

    def test_wrong_root_returns_false(self):
        self.assertIs(self.verify(root=b"\x01" * 32), False)

    def test_tampered_proof_node_returns_false(self):
        tampered = self.proof[:-1] + (b"\x00" * 32,)
        self.assertIs(self.verify(proof=tampered), False)

    def test_indices_must_be_tuple(self):
        with self.assertRaises(TypeError):
            self.verify(indices=list(self.indices))

    def test_entry_hashes_must_be_tuple(self):
        with self.assertRaises(TypeError):
            self.verify(entry_hashes=list(self.hashes))

    def test_proof_must_be_tuple(self):
        with self.assertRaises(TypeError):
            self.verify(proof=list(self.proof))

    def test_index_element_types(self):
        for bad in (True, False, 1.0, "1", None):
            with self.assertRaises(TypeError):
                self.verify(indices=(bad,) + self.indices[1:])

    def test_entry_hash_and_node_element_types(self):
        with self.assertRaises(TypeError):
            self.verify(entry_hashes=("not-bytes",) + self.hashes[1:])
        with self.assertRaises(TypeError):
            self.verify(entry_hashes=(bytearray(self.hashes[0]),) + self.hashes[1:])
        with self.assertRaises(TypeError):
            self.verify(proof=self.proof + ("not-bytes",))
        with self.assertRaises(TypeError):
            self.verify(root=bytearray(self.root))

    def test_indices_non_empty_ascending_in_range(self):
        with self.assertRaises(ValueError):
            self.verify(indices=())
        with self.assertRaises(ValueError):
            self.verify(indices=(5, 3, 1))
        with self.assertRaises(ValueError):
            self.verify(indices=(1, 1, 3))
        with self.assertRaises(ValueError):
            self.verify(indices=(-1, 3))
        with self.assertRaises(ValueError):
            self.verify(indices=(1, self.size))

    def test_sizes(self):
        with self.assertRaises(TypeError):
            self.verify(size="7")
        with self.assertRaises(TypeError):
            self.verify(size=1.0)
        with self.assertRaises(TypeError):
            self.verify(size=True)
        with self.assertRaises(ValueError):
            self.verify(size=-1)

    def test_lengths_must_match(self):
        with self.assertRaises(ValueError):
            self.verify(entry_hashes=self.hashes[:-1])
        with self.assertRaises(ValueError):
            self.verify(entry_hashes=self.hashes + (b"\x00" * 32,))

    def test_digest_widths_checked(self):
        with self.assertRaises(ValueError):
            self.verify(root=b"\x00" * 31)
        with self.assertRaises(ValueError):
            self.verify(entry_hashes=(b"\x00" * 31,) * len(self.hashes))
        with self.assertRaises(ValueError):
            self.verify(proof=self.proof[:-1] + (b"\x00" * 16,))

    def test_proof_node_count_checked(self):
        with self.assertRaises(ValueError):
            self.verify(proof=self.proof[:-1])
        if self.proof:
            with self.assertRaises(ValueError):
                self.verify(proof=self.proof + (b"\x00" * 32,))

    def test_wrong_size_changes_required_width(self):
        # The same proof cannot serve a different snapshot width.
        with self.assertRaises(ValueError):
            self.verify(size=self.size - 1)

    def test_hash_name_validation(self):
        with self.assertRaises(TypeError):
            self.verify(hash_name=None)
        with self.assertRaises(ValueError):
            self.verify(hash_name="not-a-hash")
        with self.assertRaises(ValueError):
            self.verify(hash_name="shake_128")


if __name__ == "__main__":
    unittest.main()
