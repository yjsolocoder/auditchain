import unittest

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    Entry,
    PruneReceipt,
    verify_consistency,
    verify_inclusion,
)


class SealTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_receipt_fields(self):
        receipt = self.log.seal(3)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 3)
        self.assertEqual(receipt.merkle_root, self.log.merkle_root(3))
        self.assertEqual(receipt.chain_hash, self.log.entry(2).entry_hash)

    def test_default_size_is_current_length(self):
        receipt = self.log.seal()
        self.assertEqual((receipt.size, receipt.merkle_root, receipt.chain_hash), (
            5,
            self.log.merkle_root(5),
            self.log.entry(4).entry_hash,
        ))

    def test_empty_prefix_uses_genesis(self):
        receipt = self.log.seal(0)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(receipt.chain_hash, GENESIS_HASH)
        self.assertEqual(receipt.merkle_root, self.log.merkle_root(0))

    def test_receipt_is_immutable(self):
        receipt = self.log.seal(2)
        with self.assertRaises(Exception):
            receipt.size = 5

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.seal("3")
        with self.assertRaises(ValueError):
            self.log.seal(-1)
        with self.assertRaises(ValueError):
            self.log.seal(len(self.log) + 1)

    def test_seal_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        receipt = self.log.seal(4)
        self.assertEqual(receipt.merkle_root, self.log.merkle_root(4))
        self.assertEqual(receipt.chain_hash, self.log.entry(3).entry_hash)
        with self.assertRaises(ValueError):
            self.log.seal(1)


class ReceiptValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.receipt = self.log.seal(2)

    def test_bad_hash_name_type(self):
        with self.assertRaises(TypeError):
            PruneReceipt(123, 2, self.receipt.merkle_root, self.receipt.chain_hash)

    def test_bad_size_type(self):
        with self.assertRaises(TypeError):
            PruneReceipt("sha256", "2", b"\x00" * 32, b"\x00" * 32)

    def test_bool_size_rejected(self):
        with self.assertRaises(TypeError):
            PruneReceipt("sha256", True, b"\x00" * 32, b"\x00" * 32)

    def test_negative_size(self):
        with self.assertRaises(ValueError):
            PruneReceipt("sha256", -1, b"\x00" * 32, b"\x00" * 32)

    def test_unknown_hash_name(self):
        with self.assertRaises(ValueError):
            PruneReceipt("not-a-hash", 2, b"\x00" * 32, b"\x00" * 32)

    def test_wrong_digest_lengths(self):
        with self.assertRaises(ValueError):
            PruneReceipt("sha256", 2, b"\x00" * 31, b"\x00" * 32)
        with self.assertRaises(ValueError):
            PruneReceipt("sha256", 2, b"\x00" * 32, b"\x00" * 33)

    def test_digest_must_be_bytes(self):
        with self.assertRaises(TypeError):
            PruneReceipt("sha256", 2, "0" * 32, b"\x00" * 32)
        with self.assertRaises(TypeError):
            PruneReceipt("sha256", 2, b"\x00" * 32, None)

    def test_bytearray_normalized_to_bytes(self):
        receipt = PruneReceipt(
            "sha256", 2, bytearray(self.receipt.merkle_root), bytearray(self.receipt.chain_hash)
        )
        self.assertIsInstance(receipt.merkle_root, bytes)
        self.assertIsInstance(receipt.chain_hash, bytes)


class ReceiptMatchesTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d"):
            self.log.append(record)

    def test_matches_first_retained(self):
        self.assertTrue(self.log.seal(2).matches(self.log.entry(2)))

    def test_other_entry_does_not_match(self):
        receipt = self.log.seal(2)
        self.assertFalse(receipt.matches(self.log.entry(1)))
        self.assertFalse(receipt.matches(self.log.entry(3)))

    def test_empty_prefix_receipt_never_matches(self):
        receipt = self.log.seal(0)
        for index in range(len(self.log)):
            self.assertFalse(receipt.matches(self.log.entry(index)))

    def test_wrong_type_raises(self):
        with self.assertRaises(TypeError):
            self.log.seal(2).matches(("not", "an", "entry"))

    def test_matches_after_prune(self):
        receipt = self.log.seal(2)
        self.log.prune(2, receipt)
        self.assertTrue(receipt.matches(self.log.entry(2)))
        self.assertFalse(receipt.matches(self.log.entry(3)))

    def test_matches_checks_predecessor(self):
        good = self.log.entry(2)
        forged = Entry(good.index, good.payload, b"\x01" * 32, good.entry_hash)
        self.assertFalse(self.log.seal(2).matches(forged))


class PruneErrorTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d"):
            self.log.append(record)

    def test_retain_must_equal_size(self):
        receipt = self.log.seal(2)
        with self.assertRaises(ValueError):
            self.log.prune(1, receipt)
        with self.assertRaises(ValueError):
            self.log.prune(3, receipt)

    def test_out_of_bounds(self):
        with self.assertRaises(ValueError):
            self.log.prune(5, self.log.seal(5))
        receipt = self.log.seal(0)
        with self.assertRaises(ValueError):
            self.log.prune(-1, receipt)

    def test_cannot_move_backwards(self):
        self.log.prune(3, self.log.seal(3))
        with self.assertRaises(ValueError):
            self.log.prune(2, self.log.seal(2))

    def test_wrong_root_rejected(self):
        good = self.log.seal(2)
        forged = PruneReceipt("sha256", 2, b"\x00" * 32, good.chain_hash)
        with self.assertRaises(ValueError):
            self.log.prune(2, forged)

    def test_wrong_chain_hash_rejected(self):
        good = self.log.seal(2)
        forged = PruneReceipt("sha256", 2, good.merkle_root, b"\x00" * 32)
        with self.assertRaises(ValueError):
            self.log.prune(2, forged)

    def test_wrong_hash_name_rejected(self):
        other = AuditLog(hash_name="sha3-256")
        for record in ("a", "b"):
            other.append(record)
        with self.assertRaises(ValueError):
            self.log.prune(2, other.seal(2))

    def test_no_valid_receipt(self):
        with self.assertRaises(TypeError):
            self.log.prune(2, ("not", "a", "receipt"))
        with self.assertRaises(TypeError):
            self.log.prune(2, None)

    def test_retain_from_type(self):
        with self.assertRaises(TypeError):
            self.log.prune(2.0, self.log.seal(2))
        with self.assertRaises(TypeError):
            self.log.prune(True, self.log.seal(2))

    def test_failed_prune_changes_nothing(self):
        good = self.log.seal(2)
        forged = PruneReceipt("sha256", 2, b"\x00" * 32, good.chain_hash)
        with self.assertRaises(ValueError):
            self.log.prune(2, forged)
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 4)
        self.assertEqual(self.log.entry(0).payload, b"a")

    def test_repruning_same_point_is_idempotent(self):
        self.log.prune(2, self.log.seal(2))
        self.log.prune(2, self.log.seal(2))
        self.assertEqual(self.log.retain_from, 2)
        self.assertTrue(self.log.verify())

    def test_released_prefix_cannot_be_re_sealed_or_pruned(self):
        self.log.prune(3, self.log.seal(3))
        with self.assertRaises(ValueError):
            self.log.seal(2)
        twin = AuditLog()
        for record in ("a", "b", "c", "d"):
            twin.append(record)
        with self.assertRaises(ValueError):
            self.log.prune(2, twin.seal(2))


class PrunedLogTest(unittest.TestCase):
    def setUp(self):
        self.records = [f"record-{i}" for i in range(7)]
        self.log = AuditLog()
        for record in self.records:
            self.log.append(record)
        self.twin = AuditLog()
        for record in self.records:
            self.twin.append(record)

    def prune_at(self, point):
        self.log.prune(point, self.log.seal(point))

    def test_len_is_cumulative(self):
        self.prune_at(3)
        self.assertEqual(len(self.log), 7)

    def test_head_unchanged(self):
        self.prune_at(3)
        self.assertEqual(self.log.head, self.twin.head)

    def test_retain_from(self):
        self.prune_at(3)
        self.assertEqual(self.log.retain_from, 3)

    def test_entries_only_retained(self):
        self.prune_at(3)
        entries = self.log.entries()
        self.assertEqual([entry.index for entry in entries], [3, 4, 5, 6])
        self.assertEqual([entry.payload for entry in entries], [f"record-{i}".encode() for i in range(3, 7)])

    def test_iteration_only_retained(self):
        self.prune_at(3)
        self.assertEqual([entry.index for entry in self.log], [3, 4, 5, 6])

    def test_old_indices_raise_index_error(self):
        self.prune_at(3)
        for index in (-1, 0, 1, 2, 7):
            with self.assertRaises(IndexError):
                self.log.entry(index)
        with self.assertRaises(TypeError):
            self.log.entry("3")

    def test_verify_entry_old_index_raises(self):
        self.prune_at(3)
        for index in (0, 1, 2):
            with self.assertRaises(IndexError):
                self.log.verify_entry(index)

    def test_retained_entries_accessible_with_absolute_index(self):
        self.prune_at(3)
        entry = self.log.entry(3)
        self.assertEqual(entry.index, 3)
        self.assertTrue(self.log.verify_entry(3))
        self.assertTrue(all(self.log.verify_entry(i) for i in range(3, 7)))

    def test_verify_from_checkpoint(self):
        self.prune_at(3)
        self.assertTrue(self.log.verify())

    def test_append_after_prune_matches_twin(self):
        self.prune_at(3)
        new = self.log.append("record-7")
        self.twin.append("record-7")
        self.assertEqual(new.index, 7)
        self.assertEqual(new.previous_hash, self.log.entry(6).entry_hash)
        self.assertEqual(self.log.head, self.twin.head)
        self.assertEqual(len(self.log), len(self.twin))
        self.assertTrue(self.log.verify())

    def test_new_entry_identical_to_unpruned(self):
        self.prune_at(3)
        entry = self.log.append("record-7")
        twin_entry = self.twin.append("record-7")
        self.assertEqual(entry, twin_entry)

    def test_inclusion_old_index_raises_value_error(self):
        self.prune_at(3)
        for index in (0, 1, 2):
            with self.assertRaises(ValueError):
                self.log.inclusion_proof(index, 7)

    def test_inclusion_retained_matches_twin(self):
        self.prune_at(3)
        for size in range(3, 8):
            for index in range(3, size):
                proof = self.log.inclusion_proof(index, size)
                self.assertEqual(proof, self.twin.inclusion_proof(index, size))
                self.assertTrue(
                    verify_inclusion(
                        self.twin.entry(index).entry_hash,
                        index,
                        size,
                        self.twin.merkle_root(size),
                        proof,
                    )
                )

    def test_merkle_root_retained_prefixes_match_twin(self):
        self.prune_at(3)
        for size in range(3, 8):
            self.assertEqual(self.log.merkle_root(size), self.twin.merkle_root(size))

    def test_merkle_root_pruned_snapshot_raises(self):
        self.prune_at(3)
        for size in (1, 2):
            with self.assertRaises(ValueError):
                self.log.merkle_root(size)

    def test_empty_root_still_available(self):
        self.prune_at(3)
        self.assertEqual(self.log.merkle_root(0), self.twin.merkle_root(0))

    def test_consistency_old_prefix_lost(self):
        self.prune_at(3)
        for old in (1, 2):
            with self.assertRaises(ValueError):
                self.log.consistency_proof(old, 7)

    def test_consistency_from_retain_point(self):
        self.prune_at(3)
        roots = [self.twin.merkle_root(size) for size in range(8)]
        for old in (3, 4, 5):
            for new in range(old, 8):
                proof = self.log.consistency_proof(old, new)
                self.assertEqual(proof, self.twin.consistency_proof(old, new))
                self.assertTrue(verify_consistency(old, roots[old], new, roots[new], proof))

    def test_consistency_to_future_prefixes_after_more_appends(self):
        self.prune_at(3)
        for i in range(8, 12):
            self.log.append(f"record-{i}")
            self.twin.append(f"record-{i}")
        root3 = self.twin.merkle_root(3)
        for new in range(4, 12):
            proof = self.log.consistency_proof(3, new)
            self.assertEqual(proof, self.twin.consistency_proof(3, new))
            self.assertTrue(
                verify_consistency(3, root3, new, self.twin.merkle_root(new), proof)
            )

    def test_payloads_released(self):
        self.prune_at(3)
        stored = b"".join(entry.payload for entry in self.log.entries())
        self.assertNotIn(b"record-0", stored)
        self.assertNotIn(b"record-2", stored)


class PruneAtTipTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)

    def test_prune_everything(self):
        head_before = self.log.head
        self.log.prune(3, self.log.seal(3))
        self.assertEqual(len(self.log), 3)
        self.assertEqual(self.log.entries(), [])
        self.assertEqual(self.log.head, head_before)
        self.assertEqual(self.log.retain_from, 3)
        self.assertTrue(self.log.verify())

    def test_append_after_full_prune_links_to_checkpoint(self):
        head_before = self.log.head
        self.log.prune(3, self.log.seal(3))
        entry = self.log.append("d")
        self.assertEqual(entry.index, 3)
        self.assertEqual(entry.previous_hash, head_before)
        self.assertTrue(self.log.verify())

    def test_root_at_tip_still_rebuildable(self):
        root_before = self.log.merkle_root()
        self.log.prune(3, self.log.seal(3))
        self.assertEqual(self.log.merkle_root(3), root_before)

    def test_consistency_from_tip_is_empty(self):
        self.log.prune(3, self.log.seal(3))
        self.assertEqual(self.log.consistency_proof(3, 3), ())
        self.log.append("d")
        proof = self.log.consistency_proof(3, 4)
        self.assertTrue(
            verify_consistency(
                3, self.log.merkle_root(3), 4, self.log.merkle_root(4), proof
            )
        )


class EmptyPrefixPruneTest(unittest.TestCase):
    def test_prune_empty_log(self):
        log = AuditLog()
        receipt = log.seal(0)
        self.assertEqual(receipt.chain_hash, GENESIS_HASH)
        log.prune(0, receipt)
        self.assertEqual(len(log), 0)
        self.assertEqual(log.head, GENESIS_HASH)
        self.assertTrue(log.verify())

    def test_empty_prefix_receipt_does_not_unlock_other_prefix(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            log.prune(1, log.seal(0))


class RepeatedPruneTest(unittest.TestCase):
    def test_multiple_forward_prunes(self):
        log = AuditLog()
        twin = AuditLog()
        for i in range(10):
            log.append(f"r{i}")
            twin.append(f"r{i}")
        log.prune(2, log.seal(2))
        log.append("r10")
        twin.append("r10")
        log.prune(7, log.seal(7))
        log.append("r11")
        twin.append("r11")
        self.assertEqual(log.retain_from, 7)
        self.assertEqual(len(log), 12)
        self.assertEqual(log.head, twin.head)
        self.assertTrue(log.verify())
        self.assertEqual([entry.index for entry in log.entries()], [7, 8, 9, 10, 11])
        self.assertEqual(log.merkle_root(), twin.merkle_root())
        proof = log.consistency_proof(7, 12)
        self.assertEqual(proof, twin.consistency_proof(7, 12))
        self.assertTrue(
            verify_consistency(7, twin.merkle_root(7), 12, twin.merkle_root(12), proof)
        )
        with self.assertRaises(ValueError):
            log.merkle_root(6)


class AlternateHashPruneTest(unittest.TestCase):
    def test_prune_with_sha3(self):
        log = AuditLog(hash_name="sha3-256")
        twin = AuditLog(hash_name="sha3-256")
        for i in range(6):
            log.append(f"r{i}")
            twin.append(f"r{i}")
        log.prune(4, log.seal(4))
        self.assertTrue(log.verify())
        self.assertEqual(log.head, twin.head)
        for size in range(4, 7):
            self.assertEqual(log.merkle_root(size), twin.merkle_root(size))
        for index in range(4, 6):
            proof = log.inclusion_proof(index)
            self.assertTrue(
                verify_inclusion(
                    twin.entry(index).entry_hash,
                    index,
                    len(twin),
                    twin.merkle_root(),
                    proof,
                    hash_name="sha3-256",
                )
            )

    def test_receipt_hash_name_must_match(self):
        log = AuditLog(hash_name="sha3-256")
        log.append("a")
        receipt = PruneReceipt("sha256", 1, b"\x00" * 32, b"\x00" * 32)
        with self.assertRaises(ValueError):
            log.prune(1, receipt)


class UnprunedCompatibilityTest(unittest.TestCase):
    def test_default_retain_from_zero(self):
        log = AuditLog()
        self.assertEqual(log.retain_from, 0)


if __name__ == "__main__":
    unittest.main()
