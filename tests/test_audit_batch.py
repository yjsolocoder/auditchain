import itertools
import unittest

from auditchain import AuditLog, Entry, verify_audit_batch, verify_batch_inclusion


class AuditBatchIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_returns_five_tuple(self):
        receipt = self.log.audit_batch([1, 3])
        self.assertIsInstance(receipt, tuple)
        self.assertEqual(len(receipt), 5)
        hash_name, size, root, entries, proof = receipt
        self.assertEqual(hash_name, "sha256")
        self.assertEqual(size, 5)
        self.assertEqual(root, self.log.merkle_root(5))
        self.assertIsInstance(entries, tuple)
        self.assertIsInstance(proof, tuple)

    def test_last_entry_auto_added(self):
        _, size, _, entries, _ = self.log.audit_batch([0])
        self.assertEqual([entry.index for entry in entries], [0, 4])

    def test_explicit_last_entry_not_duplicated(self):
        _, _, _, entries, _ = self.log.audit_batch([2, 4])
        self.assertEqual([entry.index for entry in entries], [2, 4])

    def test_entries_sorted_regardless_of_input_order(self):
        _, _, _, entries, _ = self.log.audit_batch([3, 0, 1])
        self.assertEqual([entry.index for entry in entries], [0, 1, 3, 4])

    def test_empty_selection_still_carries_last_entry(self):
        receipt = self.log.audit_batch([])
        self.assertEqual([entry.index for entry in receipt[3]], [4])
        self.assertEqual(receipt[1], 5)
        self.assertEqual(receipt[2], self.log.merkle_root(5))
        self.assertTrue(verify_audit_batch(receipt))

    def test_empty_selection_explicit_non_empty_size_carries_last(self):
        receipt = self.log.audit_batch([], 3)
        self.assertEqual(receipt[1], 3)
        self.assertEqual([entry.index for entry in receipt[3]], [2])
        self.assertTrue(verify_audit_batch(receipt))

    def test_empty_snapshot(self):
        receipt = self.log.audit_batch((), 0)
        hash_name, size, root, entries, proof = receipt
        self.assertEqual(size, 0)
        self.assertEqual(entries, ())
        self.assertEqual(proof, ())
        self.assertEqual(root, self.log.merkle_root(0))
        self.assertTrue(verify_audit_batch(receipt))

    def test_explicit_size(self):
        receipt = self.log.audit_batch([1], 3)
        self.assertEqual(receipt[1], 3)
        self.assertEqual(receipt[2], self.log.merkle_root(3))
        self.assertEqual([entry.index for entry in receipt[3]], [1, 2])

    def test_entries_are_retained_entries(self):
        _, _, _, entries, _ = self.log.audit_batch([0, 2], 4)
        for entry in entries:
            self.assertIsInstance(entry, Entry)
            self.assertEqual(entry, self.log.entry(entry.index))

    def test_proof_byte_equal_to_batch_inclusion_proof(self):
        for chosen, size in (([0, 2], 5), ([3, 0, 1], None), ([1], 3), ([0, 4], 5)):
            receipt = self.log.audit_batch(chosen, size)
            _, snap_size, _, entries, proof = receipt
            wanted = sorted(set(chosen)) + ([snap_size - 1] if snap_size else [])
            indices, batch_proof = self.log.batch_inclusion_proof(
                sorted(set(wanted)), snap_size
            )
            self.assertEqual(tuple(e.index for e in entries), indices)
            self.assertEqual(proof, batch_proof)

    def test_default_size_is_current_length(self):
        explicit = self.log.audit_batch([1, 3], len(self.log))
        implicit = self.log.audit_batch([1, 3])
        self.assertEqual(explicit, implicit)

    def test_any_iterable_accepted(self):
        receipt = self.log.audit_batch(iter([1, 3]))
        self.assertEqual([e.index for e in receipt[3]], [1, 3, 4])
        receipt = self.log.audit_batch(i for i in (0,))
        self.assertEqual([e.index for e in receipt[3]], [0, 4])

    def test_single_leaf_snapshot_has_empty_proof(self):
        receipt = self.log.audit_batch([0], 1)
        self.assertEqual([e.index for e in receipt[3]], [0])
        self.assertEqual(receipt[4], ())
        self.assertTrue(verify_audit_batch(receipt))

    def test_selecting_every_leaf_has_empty_proof(self):
        for size in range(1, len(self.log) + 1):
            receipt = self.log.audit_batch(range(size), size)
            self.assertEqual(tuple(e.index for e in receipt[3]), tuple(range(size)))
            self.assertEqual(receipt[4], ())
            self.assertTrue(verify_audit_batch(receipt))

    def test_call_is_read_only(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        for bad in ([9], [0, 0], [-1]):
            with self.assertRaises(ValueError):
                self.log.audit_batch(bad)
        self.log.audit_batch([1, 2])
        after = (len(self.log), self.log.head, self.log.merkle_root())
        self.assertEqual(before, after)
        self.assertTrue(self.log.verify())

    def test_receipt_survives_later_appends(self):
        receipt = self.log.audit_batch([1], 4)
        self.log.append("f")
        self.assertTrue(verify_audit_batch(receipt))

    def test_index_type_errors(self):
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError):
                self.log.audit_batch([bad])
        with self.assertRaises(TypeError):
            self.log.audit_batch(1)

    def test_duplicate_indices_rejected(self):
        with self.assertRaises(ValueError):
            self.log.audit_batch([2, 2])
        with self.assertRaises(ValueError):
            self.log.audit_batch([4, 4])

    def test_index_range(self):
        with self.assertRaises(ValueError):
            self.log.audit_batch([-1])
        with self.assertRaises(ValueError):
            self.log.audit_batch([5])
        with self.assertRaises(ValueError):
            self.log.audit_batch([3], 3)

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.audit_batch([0], "3")
        with self.assertRaises(TypeError):
            self.log.audit_batch([0], True)
        with self.assertRaises(ValueError):
            self.log.audit_batch([0], -1)
        with self.assertRaises(ValueError):
            self.log.audit_batch([0], 6)


class AuditBatchPrunedLogTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.twin = AuditLog()
        for i in range(6):
            self.log.append(f"r{i}")
            self.twin.append(f"r{i}")
        self.log.prune(2, self.log.seal(2))

    def test_batch_after_prune(self):
        receipt = self.log.audit_batch([2, 4])
        self.assertEqual([e.index for e in receipt[3]], [2, 4, 5])
        self.assertEqual(receipt[2], self.twin.merkle_root(6))
        self.assertTrue(verify_audit_batch(receipt))

    def test_pruned_index_rejected(self):
        with self.assertRaises(ValueError):
            self.log.audit_batch([1])

    def test_pruned_snapshot_rejected(self):
        with self.assertRaises(ValueError):
            self.log.audit_batch([], 1)

    def test_empty_snapshot_still_available(self):
        receipt = self.log.audit_batch((), 0)
        self.assertEqual(receipt[3], ())
        self.assertTrue(verify_audit_batch(receipt))


class AuditBatchExhaustiveTest(unittest.TestCase):
    def test_every_subset_of_every_snapshot_verifies(self):
        for n in range(1, 9):
            log = AuditLog()
            for record in range(n):
                log.append(str(record))
            for size in range(1, n + 1):
                snapshot_root = log.merkle_root(size)
                for width in range(0, size + 1):
                    for chosen in itertools.combinations(range(size), width):
                        receipt = log.audit_batch(chosen, size)
                        hash_name, snap_size, root, entries, proof = receipt
                        self.assertEqual(snap_size, size)
                        self.assertEqual(root, snapshot_root)
                        # The last entry is always part of the shared proof.
                        self.assertEqual(entries[-1].index, size - 1)
                        self.assertTrue(
                            verify_audit_batch(receipt),
                            (n, size, chosen),
                        )
                        # Cross-check against the standalone batch verifier.
                        indices = tuple(e.index for e in entries)
                        hashes = tuple(e.entry_hash for e in entries)
                        self.assertTrue(
                            verify_batch_inclusion(
                                indices, hashes, size, root, proof
                            )
                        )

    def test_works_after_prune(self):
        log = AuditLog()
        for record in range(6):
            log.append(str(record))
        log.prune(2, log.seal(2))
        receipt = log.audit_batch([2, 4])
        self.assertTrue(verify_audit_batch(receipt))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in range(5):
            log.append(str(record))
        receipt = log.audit_batch([0, 3])
        self.assertEqual(receipt[0], "sha3-256")
        self.assertTrue(verify_audit_batch(receipt))
        # The same fields re-labeled as sha256 must not verify.
        relabeled = ("sha256",) + receipt[1:]
        self.assertFalse(verify_audit_batch(relabeled))

    def test_sha512_width(self):
        log = AuditLog(hash_name="sha512")
        for record in range(6):
            log.append(str(record))
        receipt = log.audit_batch([1, 3])
        self.assertEqual(len(receipt[2]), 64)
        self.assertTrue(all(len(node) == 64 for node in receipt[4]))
        self.assertTrue(verify_audit_batch(receipt))


class VerifyAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.receipt = self.log.audit_batch([0, 2, 4])
        self.hash_name, self.size, self.root, self.entries, self.proof = self.receipt

    def test_genuine_receipts_verify(self):
        for chosen, size in (
            ([0], None), ([1, 3], None), ([3], 4), ([], None),
            ([], 3), ([0, 6], None), (range(7), None),
        ):
            self.assertTrue(
                verify_audit_batch(self.log.audit_batch(chosen, size)),
                (chosen, size),
            )

    def test_empty_snapshot_verifies(self):
        self.assertTrue(verify_audit_batch(self.log.audit_batch((), 0)))

    def test_not_a_tuple_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_audit_batch(None)
        with self.assertRaises(TypeError):
            verify_audit_batch([self.hash_name, self.size, self.root, self.entries, self.proof])
        with self.assertRaises(TypeError):
            verify_audit_batch("receipt")

    def test_wrong_arity_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_audit_batch(
                (self.hash_name, self.size, self.root, self.entries)
            )
        with self.assertRaises(TypeError):
            verify_audit_batch(
                (self.hash_name, self.size, self.root, self.entries, self.proof, 1)
            )

    def test_field_types(self):
        with self.assertRaises(TypeError):
            verify_audit_batch((1, self.size, self.root, self.entries, self.proof))
        with self.assertRaises(TypeError):
            verify_audit_batch((self.hash_name, "7", self.root, self.entries, self.proof))
        with self.assertRaises(TypeError):
            verify_audit_batch((self.hash_name, True, self.root, self.entries, self.proof))
        with self.assertRaises(TypeError):
            verify_audit_batch((self.hash_name, self.size, "root", self.entries, self.proof))
        with self.assertRaises(TypeError):
            verify_audit_batch((self.hash_name, self.size, self.root, list(self.entries), self.proof))
        with self.assertRaises(TypeError):
            verify_audit_batch((self.hash_name, self.size, self.root, self.entries, list(self.proof)))

    def test_unknown_hash_algorithm_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_batch(("not-a-hash", self.size, self.root, self.entries, self.proof))

    def test_negative_size_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_batch((self.hash_name, -1, self.root, self.entries, self.proof))

    def test_digest_widths_checked(self):
        with self.assertRaises(ValueError):
            verify_audit_batch((self.hash_name, self.size, b"\x00" * 31, self.entries, self.proof))
        if self.proof:
            with self.assertRaises(ValueError):
                verify_audit_batch(
                    (self.hash_name, self.size, self.root, self.entries,
                     self.proof[:-1] + (b"\x00" * 31,))
                )

    def test_proof_node_type(self):
        with self.assertRaises(TypeError):
            verify_audit_batch(
                (self.hash_name, self.size, self.root, self.entries, (1,))
            )
        with self.assertRaises(TypeError):
            verify_audit_batch(
                (self.hash_name, self.size, self.root, self.entries,
                 tuple(bytearray(n) for n in self.proof))
            )

    def test_entries_must_be_entries(self):
        with self.assertRaises(TypeError):
            verify_audit_batch((self.hash_name, self.size, self.root, ("x",), self.proof))

    def test_entry_field_types(self):
        entry = self.entries[0]
        bad_index = Entry("0", entry.payload, entry.previous_hash, entry.entry_hash)
        with self.assertRaises(TypeError):
            verify_audit_batch(
                (self.hash_name, self.size, self.root,
                 (bad_index,) + self.entries[1:], self.proof)
            )
        for field, value in (
            ("payload", "payload"),
            ("previous_hash", 3),
            ("entry_hash", 3),
        ):
            kwargs = {
                "index": entry.index,
                "payload": entry.payload,
                "previous_hash": entry.previous_hash,
                "entry_hash": entry.entry_hash,
            }
            kwargs[field] = value
            bad = Entry(**kwargs)
            with self.assertRaises(TypeError):
                verify_audit_batch(
                    (self.hash_name, self.size, self.root,
                     (bad,) + self.entries[1:], self.proof)
                )

    def test_negative_entry_index_raises_value_error(self):
        entry = self.entries[0]
        neg = Entry(-1, entry.payload, entry.previous_hash, entry.entry_hash)
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (self.hash_name, self.size, self.root,
                 (neg,) + self.entries[1:], self.proof)
            )

    def test_entry_index_out_of_range_raises_value_error(self):
        entry = self.entries[0]
        big = Entry(self.size, entry.payload, entry.previous_hash, entry.entry_hash)
        # Keep the genuine last entry so the only failure is the bad range.
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (self.hash_name, self.size, self.root,
                 (big,) + self.entries[1:], self.proof)
            )

    def test_entries_must_be_ascending(self):
        reordered = (self.entries[1], self.entries[0]) + self.entries[2:]
        with self.assertRaises(ValueError):
            verify_audit_batch((self.hash_name, self.size, self.root, reordered, self.proof))

    def test_duplicate_entries_raise_value_error(self):
        duplicated = (self.entries[0],) + self.entries
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (self.hash_name, self.size, self.root, duplicated, self.proof)
            )

    def test_missing_last_entry_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (self.hash_name, self.size, self.root, self.entries[:-1], self.proof)
            )

    def test_zero_evidence_non_empty_snapshot_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_batch((self.hash_name, self.size, self.root, (), ()))
        # Even the genuine root with no entries is rejected.
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (self.hash_name, self.size, self.log.merkle_root(self.size), (), ())
            )

    def test_empty_snapshot_with_entries_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (self.hash_name, 0, self.log.merkle_root(0),
                 (self.entries[0],), ())
            )

    def test_empty_snapshot_with_proof_nodes_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (self.hash_name, 0, self.log.merkle_root(0), (),
                 (b"\x00" * 32,))
            )

    def test_proof_node_count_checked(self):
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (self.hash_name, self.size, self.root, self.entries,
                 self.proof + (b"\x00" * 32,))
            )
        if self.proof:
            with self.assertRaises(ValueError):
                verify_audit_batch(
                    (self.hash_name, self.size, self.root, self.entries,
                     self.proof[:-1])
                )

    def test_wrong_root_returns_false(self):
        self.assertFalse(
            verify_audit_batch(
                (self.hash_name, self.size, b"\x11" * 32, self.entries, self.proof)
            )
        )

    def test_tampered_payload_returns_false(self):
        entry = self.entries[0]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        self.assertFalse(
            verify_audit_batch(
                (self.hash_name, self.size, self.root,
                 (tampered,) + self.entries[1:], self.proof)
            )
        )

    def test_tampered_entry_hash_returns_false(self):
        entry = self.entries[0]
        tampered = Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 32)
        self.assertFalse(
            verify_audit_batch(
                (self.hash_name, self.size, self.root,
                 (tampered,) + self.entries[1:], self.proof)
            )
        )

    def test_wrong_proof_nodes_return_false(self):
        if self.proof:
            bogus = (b"\x22" * 32,) + self.proof[1:]
            self.assertFalse(
                verify_audit_batch(
                    (self.hash_name, self.size, self.root, self.entries, bogus)
                )
            )

    def test_permuted_entries_with_valid_last_return_false(self):
        # Swap two non-last entries but keep strictly ascending order violated
        # only by content: build entries whose indices stay valid by reusing
        # another entry's hash at a position. Swapping whole entries breaks
        # index ordering -> ValueError; instead permute the hashes/content at
        # fixed ascending indices.
        e0, e1 = self.entries[0], self.entries[1]
        swapped_hash0 = Entry(e0.index, e0.payload, e0.previous_hash, e1.entry_hash)
        # e0 digest no longer equals its entry_hash -> mismatch False.
        self.assertFalse(
            verify_audit_batch(
                (self.hash_name, self.size, self.root,
                 (swapped_hash0,) + self.entries[1:], self.proof)
            )
        )

    def test_proof_from_other_selection_rejected(self):
        other = self.log.audit_batch([0, 2])
        _, other_size, _, other_entries, other_proof = other
        # Reusing this selection's proof against [0,2,4] either fails the node
        # count (ValueError) or, by coincidence, rebuilds a different root.
        try:
            result = verify_audit_batch(
                (self.hash_name, self.size, self.root, self.entries, other_proof)
            )
        except ValueError:
            pass
        else:
            self.assertFalse(result)

    def test_empty_snapshot_wrong_root_returns_false(self):
        self.assertFalse(
            verify_audit_batch((self.hash_name, 0, b"\x00" * 32, (), ()))
        )

    def test_single_leaf_snapshot_wrong_root_returns_false(self):
        receipt = self.log.audit_batch([0], 1)
        _, size, _, entries, proof = receipt
        self.assertFalse(
            verify_audit_batch((self.hash_name, size, b"\x00" * 32, entries, proof))
        )


if __name__ == "__main__":
    unittest.main()
