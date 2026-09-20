import hashlib
import itertools
import os
import unittest

from auditchain import (
    AuditLog,
    AuditReceipt,
    Entry,
    decrypt_entry,
    verify_audit_batch,
)

EMPTY = b"auditchain/merkle-empty/v1"


def empty_root(hash_name="sha256"):
    return hashlib.new(hash_name, EMPTY).digest()


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

    def test_entries_are_ascending_entry_records(self):
        _, _, _, entries, _ = self.log.audit_batch([3, 0, 1])
        self.assertEqual(tuple(entry.index for entry in entries), (0, 1, 3, 4))
        self.assertTrue(all(isinstance(entry, Entry) for entry in entries))
        for entry in entries:
            self.assertEqual(entry, self.log.entry(entry.index))

    def test_proof_elements_are_bytes(self):
        *_, proof = self.log.audit_batch([0, 2])
        self.assertTrue(all(isinstance(node, bytes) for node in proof))

    def test_last_entry_auto_added(self):
        _, size, _, entries, _ = self.log.audit_batch([0])
        self.assertEqual(tuple(e.index for e in entries), (0, 4))
        self.assertEqual(entries[-1].index, size - 1)

    def test_explicit_last_entry_not_duplicated(self):
        _, _, _, entries, _ = self.log.audit_batch([2, 4])
        self.assertEqual(tuple(e.index for e in entries), (2, 4))

    def test_empty_selection_still_carries_last_entry(self):
        hash_name, size, root, entries, proof = self.log.audit_batch([])
        self.assertEqual(size, 5)
        self.assertEqual(tuple(e.index for e in entries), (4,))
        self.assertEqual(root, self.log.merkle_root(5))
        self.assertTrue(verify_audit_batch((hash_name, size, root, entries, proof)))

    def test_explicit_size(self):
        _, size, root, entries, proof = self.log.audit_batch([1], 3)
        self.assertEqual(size, 3)
        self.assertEqual(root, self.log.merkle_root(3))
        self.assertEqual(tuple(e.index for e in entries), (1, 2))
        self.assertEqual(
            proof, self.log.batch_inclusion_proof([1, 2], 3)[1]
        )

    def test_default_size_equals_current_length(self):
        default = self.log.audit_batch([1, 3])
        explicit = self.log.audit_batch([1, 3], len(self.log))
        self.assertEqual(default, explicit)

    def test_proof_byte_identical_to_batch_inclusion_proof(self):
        for selected in ((0,), (0, 2), (4, 0, 2), (1, 3), ()):
            _, size, _, entries, proof = self.log.audit_batch(selected)
            expected_indices = tuple(sorted(set(selected) | {size - 1}))
            batch_indices, batch_proof = self.log.batch_inclusion_proof(
                expected_indices, size
            )
            self.assertEqual(tuple(e.index for e in entries), batch_indices)
            self.assertEqual(proof, batch_proof, selected)

    def test_proof_is_compact(self):
        log = AuditLog()
        for record in range(8):
            log.append(str(record))
        # Select [0, 1]; the last entry (7) is auto-merged, so the selection
        # is {0, 1, 7}. Its single shared proof is shorter than three
        # individual inclusion proofs and equals batch_inclusion_proof output.
        *_, entries, proof = log.audit_batch([0, 1], 8)
        separate = sum(
            (log.inclusion_proof(index, 8) for index in (0, 1, 7)), ()
        )
        self.assertLess(len(proof), len(separate))
        self.assertEqual(
            proof, log.batch_inclusion_proof([0, 1, 7], 8)[1]
        )
        self.assertEqual(tuple(e.index for e in entries), (0, 1, 7))

    def test_empty_snapshot(self):
        hash_name, size, root, entries, proof = self.log.audit_batch((), 0)
        self.assertEqual(hash_name, "sha256")
        self.assertEqual(size, 0)
        self.assertEqual(root, empty_root())
        self.assertEqual(entries, ())
        self.assertEqual(proof, ())
        self.assertTrue(
            verify_audit_batch((hash_name, size, root, entries, proof))
        )

    def test_empty_snapshot_rejects_non_empty_selection(self):
        with self.assertRaises(ValueError):
            self.log.audit_batch([0], 0)
        with self.assertRaises(ValueError):
            self.log.audit_batch([0, 2], 0)

    def test_single_leaf_snapshot(self):
        receipt = self.log.audit_batch([0], 1)
        _, size, root, entries, proof = receipt
        self.assertEqual(size, 1)
        self.assertEqual(tuple(e.index for e in entries), (0,))
        self.assertEqual(proof, ())
        self.assertEqual(root, self.log.merkle_root(1))
        self.assertTrue(verify_audit_batch(receipt))

    def test_call_is_read_only(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        for bad in (([9], None), ([0, 0], None), ([-1], None), ([0], -1), ([0], 6), ([0], 0)):
            with self.assertRaises((ValueError, TypeError)):
                self.log.audit_batch(*bad)
        self.log.audit_batch([1, 2])
        self.log.audit_batch([])
        after = (len(self.log), self.log.head, self.log.merkle_root())
        self.assertEqual(before, after)
        self.assertTrue(self.log.verify())

    def test_index_type_errors(self):
        with self.assertRaises(TypeError):
            self.log.audit_batch(7)
        for bad in ("1", 1.0, True, None, b"1"):
            with self.assertRaises(TypeError):
                self.log.audit_batch([bad])

    def test_any_iterable_accepted(self):
        _, _, _, entries, _ = self.log.audit_batch(iter([1, 3]))
        self.assertEqual(tuple(e.index for e in entries), (1, 3, 4))
        _, _, _, entries, _ = self.log.audit_batch(i for i in (0,))
        self.assertEqual(tuple(e.index for e in entries), (0, 4))

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

    def test_receipt_survives_later_appends(self):
        receipt = self.log.audit_batch([1], 4)
        self.log.append("f")
        self.assertTrue(verify_audit_batch(receipt))


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
        hash_name, size, root, entries, proof = receipt
        self.assertEqual(tuple(e.index for e in entries), (2, 4, 5))
        self.assertEqual(size, 6)
        self.assertEqual(root, self.twin.merkle_root(6))
        self.assertEqual(
            proof, self.log.batch_inclusion_proof([2, 4, 5])[1]
        )
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
        self.assertEqual(receipt[4], ())
        self.assertTrue(verify_audit_batch(receipt))


class AuditBatchEncryptedTest(unittest.TestCase):
    def test_encrypted_entries_verify_and_decrypt_offline(self):
        log = AuditLog()
        key = os.urandom(32)
        for i in range(5):
            log.encrypt(f"secret-{i}", key)
        receipt = log.audit_batch([0, 2])
        _, _, _, entries, _ = receipt
        self.assertTrue(verify_audit_batch(receipt))
        self.assertEqual(
            decrypt_entry(entries[0], key), b"secret-0"
        )
        self.assertEqual(
            decrypt_entry(entries[2], key), b"secret-4"
        )


class AuditBatchExhaustiveTest(unittest.TestCase):
    def test_every_subset_of_every_snapshot_verifies(self):
        for n in range(1, 9):
            log = AuditLog()
            for record in range(n):
                log.append(str(record))
            for size in range(1, n + 1):
                snapshot_root = log.merkle_root(size)
                for width in range(0, size):
                    for chosen in itertools.combinations(range(size), width):
                        receipt = log.audit_batch(chosen, size)
                        hash_name, recv_size, root, entries, proof = receipt
                        self.assertEqual(recv_size, size)
                        self.assertEqual(root, snapshot_root)
                        expected = tuple(sorted(set(chosen) | {size - 1}))
                        self.assertEqual(
                            tuple(e.index for e in entries), expected
                        )
                        self.assertTrue(
                            verify_audit_batch(receipt),
                            (n, size, chosen),
                        )

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in range(6):
            log.append(str(record))
        receipt = log.audit_batch([0, 3, 4])
        hash_name, size, root, entries, proof = receipt
        self.assertEqual(hash_name, "sha3-256")
        self.assertTrue(verify_audit_batch(receipt))
        # The same receipt relabeled sha256 must not verify: the recomputed
        # entry digests no longer match the recorded ones.
        self.assertFalse(
            verify_audit_batch(("sha256", size, root, entries, proof))
        )

    def test_sha512_widths(self):
        log = AuditLog(hash_name="sha512")
        for record in range(5):
            log.append(str(record))
        receipt = log.audit_batch([1, 3])
        self.assertEqual(len(receipt[2]), 64)
        self.assertTrue(all(len(node) == 64 for node in receipt[4]))
        self.assertTrue(verify_audit_batch(receipt))


class VerifyAuditBatchValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.receipt = self.log.audit_batch([1, 3])

    def test_genuine_receipts_verify(self):
        for indices, size in (
            ([0], None), ([1, 3], None), ([3], 4), ([], None),
            ([], 3), ([0, 1, 2, 3, 4], None),
        ):
            self.assertTrue(
                verify_audit_batch(self.log.audit_batch(indices, size)),
                (indices, size),
            )

    def test_must_be_five_tuple(self):
        with self.assertRaises(TypeError):
            verify_audit_batch(None)
        with self.assertRaises(TypeError):
            verify_audit_batch([1, 2, 3, 4, 5])
        with self.assertRaises(TypeError):
            verify_audit_batch((1, 2, 3, 4))
        with self.assertRaises(TypeError):
            verify_audit_batch((1, 2, 3, 4, 5, 6))
        with self.assertRaises(TypeError):
            verify_audit_batch("12345")
        # An AuditReceipt is a different, incompatible receipt shape.
        with self.assertRaises(TypeError):
            verify_audit_batch(self.log.audit_receipt([1, 3]))

    def test_hash_name_must_be_string(self):
        _, size, root, entries, proof = self.receipt
        with self.assertRaises(TypeError):
            verify_audit_batch((None, size, root, entries, proof))
        with self.assertRaises(TypeError):
            verify_audit_batch((123, size, root, entries, proof))

    def test_unknown_hash_algorithm_raises_value_error(self):
        _, size, root, entries, proof = self.receipt
        with self.assertRaises(ValueError):
            verify_audit_batch(("not-a-hash", size, root, entries, proof))
        with self.assertRaises(ValueError):
            verify_audit_batch(("shake_128", size, root, entries, proof))

    def test_size_validation(self):
        hash_name, _, root, entries, proof = self.receipt
        with self.assertRaises(TypeError):
            verify_audit_batch((hash_name, "5", root, entries, proof))
        with self.assertRaises(TypeError):
            verify_audit_batch((hash_name, True, root, entries, proof))
        with self.assertRaises(ValueError):
            verify_audit_batch((hash_name, -1, root, entries, proof))

    def test_root_validation(self):
        hash_name, size, _, entries, proof = self.receipt
        with self.assertRaises(TypeError):
            verify_audit_batch((hash_name, size, "x" * 32, entries, proof))
        with self.assertRaises(TypeError):
            verify_audit_batch((hash_name, size, None, entries, proof))
        with self.assertRaises(ValueError):
            verify_audit_batch((hash_name, size, b"\x00" * 31, entries, proof))
        with self.assertRaises(ValueError):
            verify_audit_batch((hash_name, size, b"\x00" * 33, entries, proof))

    def test_cross_algorithm_width_mismatch_raises(self):
        _, size, root, entries, proof = self.receipt
        # sha512 receipts are 64 bytes wide; sha256 digests fail the check.
        with self.assertRaises(ValueError):
            verify_audit_batch(("sha512", size, root, entries, proof))

    def test_entries_must_be_tuple(self):
        hash_name, size, root, _, proof = self.receipt
        with self.assertRaises(TypeError):
            verify_audit_batch((hash_name, size, root, list(self.receipt[3]), proof))

    def test_proof_must_be_tuple(self):
        hash_name, size, root, entries, _ = self.receipt
        with self.assertRaises(TypeError):
            verify_audit_batch(
                (hash_name, size, root, entries, list(self.receipt[4]))
            )

    def test_entry_element_types(self):
        hash_name, size, root, entries, proof = self.receipt
        bogus = ((42,),) + entries[1:]
        with self.assertRaises(TypeError):
            verify_audit_batch((hash_name, size, root, bogus, proof))

    def test_entry_index_types(self):
        hash_name, size, root, entries, proof = self.receipt
        first = entries[0]
        bad_first = Entry(True, first.payload, first.previous_hash, first.entry_hash)
        with self.assertRaises(TypeError):
            verify_audit_batch(
                (hash_name, size, root, (bad_first,) + entries[1:], proof)
            )
        bad_first = Entry("1", first.payload, first.previous_hash, first.entry_hash)
        with self.assertRaises(TypeError):
            verify_audit_batch(
                (hash_name, size, root, (bad_first,) + entries[1:], proof)
            )

    def test_entry_field_types_and_widths(self):
        hash_name, size, root, entries, proof = self.receipt
        first = entries[0]
        for field, bogus in (
            ("payload", 123),
            ("previous_hash", "x" * 32),
            ("entry_hash", None),
        ):
            values = {
                "index": first.index,
                "payload": first.payload,
                "previous_hash": first.previous_hash,
                "entry_hash": first.entry_hash,
            }
            values[field] = bogus
            with self.assertRaises(TypeError):
                verify_audit_batch(
                    (
                        hash_name, size, root,
                        (Entry(**values),) + entries[1:], proof,
                    )
                )
        for field in ("previous_hash", "entry_hash"):
            values = {
                "index": first.index,
                "payload": first.payload,
                "previous_hash": first.previous_hash,
                "entry_hash": first.entry_hash,
            }
            values[field] = b"\x00" * 31
            with self.assertRaises(ValueError):
                verify_audit_batch(
                    (
                        hash_name, size, root,
                        (Entry(**values),) + entries[1:], proof,
                    )
                )

    def test_proof_node_types_and_widths(self):
        hash_name, size, root, entries, proof = self.receipt
        if proof:
            with self.assertRaises(TypeError):
                verify_audit_batch(
                    (hash_name, size, root, entries, (1,) + proof[1:])
                )
            with self.assertRaises(TypeError):
                verify_audit_batch(
                    (
                        hash_name, size, root, entries,
                        tuple(bytearray(n) for n in proof[:1]) + proof[1:],
                    )
                )
            with self.assertRaises(ValueError):
                verify_audit_batch(
                    (
                        hash_name, size, root, entries,
                        (b"\x00" * 16,) + proof[1:],
                    )
                )

    def test_entries_must_be_strictly_ascending(self):
        hash_name, size, root, entries, proof = self.receipt
        reordered = (entries[2], entries[0]) + entries[1:]
        with self.assertRaises(ValueError):
            verify_audit_batch((hash_name, size, root, reordered, proof))
        _, _, _, dup_entries, _ = self.log.audit_batch([0, 1])
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (hash_name, 3, self.log.merkle_root(3),
                 dup_entries[:1] + dup_entries[:1], ())
            )

    def test_entry_index_out_of_range(self):
        hash_name, _, root, entries, proof = self.receipt
        with self.assertRaises(ValueError):
            verify_audit_batch((hash_name, 3, root, entries, proof))

    def test_missing_last_entry_raises_value_error(self):
        # A hand-built tuple (there is no constructor to enforce this) whose
        # final entry is not index size - 1 must be refused.
        hash_name = self.receipt[0]
        root = self.log.merkle_root(5)
        entry0 = self.log.entry(0)
        indices, batch_proof = self.log.batch_inclusion_proof([0], 5)
        # Node count fits (0,) but the last entry is missing: ValueError.
        with self.assertRaises(ValueError):
            verify_audit_batch((hash_name, 5, root, (entry0,), batch_proof))

    def test_empty_entries_non_empty_snapshot_raises(self):
        hash_name = self.receipt[0]
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (hash_name, 5, self.log.merkle_root(5), (), ())
            )
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (hash_name, 5, b"X" * 32, (), ())
            )

    def test_empty_snapshot_rules(self):
        good = self.log.audit_batch((), 0)
        self.assertTrue(verify_audit_batch(good))
        hash_name, _, root, _, _ = good
        self.assertEqual(root, empty_root())
        # Wrong root with otherwise canonical empty receipt is a plain mismatch.
        self.assertFalse(
            verify_audit_batch((hash_name, 0, b"\x00" * 32, (), ()))
        )
        entry0 = self.log.entry(0)
        with self.assertRaises(ValueError):
            verify_audit_batch((hash_name, 0, root, (entry0,), ()))
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (hash_name, 0, root, (), (b"\x00" * 32,))
            )

    def test_proof_node_count_checked(self):
        hash_name, size, root, entries, proof = self.receipt
        with self.assertRaises(ValueError):
            verify_audit_batch(
                (hash_name, size, root, entries, proof + (b"\x00" * 32,))
            )
        if proof:
            with self.assertRaises(ValueError):
                verify_audit_batch(
                    (hash_name, size, root, entries, proof[:-1])
                )


class VerifyAuditBatchMismatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_tampered_payload_returns_false(self):
        hash_name, size, root, entries, proof = self.log.audit_batch([1])
        entry = entries[0]
        tampered = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        self.assertFalse(
            verify_audit_batch(
                (hash_name, size, root, (tampered,) + entries[1:], proof)
            )
        )

    def test_tampered_entry_hash_returns_false(self):
        hash_name, size, root, entries, proof = self.log.audit_batch([1])
        entry = entries[0]
        tampered = Entry(
            entry.index, entry.payload, entry.previous_hash, b"\x00" * 32
        )
        self.assertFalse(
            verify_audit_batch(
                (hash_name, size, root, (tampered,) + entries[1:], proof)
            )
        )

    def test_wrong_root_returns_false(self):
        hash_name, size, _, entries, proof = self.log.audit_batch([1])
        self.assertFalse(
            verify_audit_batch(
                (hash_name, size, b"\x11" * 32, entries, proof)
            )
        )

    def test_wrong_proof_node_returns_false(self):
        hash_name, size, root, entries, proof = self.log.audit_batch([0, 2])
        self.assertTrue(proof)
        bogus = (b"\x22" * 32,) * len(proof)
        # Same node count: structurally valid, the rebuilt root just differs.
        self.assertFalse(
            verify_audit_batch((hash_name, size, root, entries, bogus))
        )

    def test_proof_from_other_selection_rejected(self):
        receipt = self.log.audit_batch([1, 3])
        _, other_proof = self.log.batch_inclusion_proof([0, 2])
        hash_name, size, root, entries, _ = receipt
        try:
            result = verify_audit_batch(
                (hash_name, size, root, entries, other_proof)
            )
        except ValueError:
            pass
        else:
            self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
