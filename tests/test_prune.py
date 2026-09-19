import unittest

from auditchain import GENESIS_HASH, AuditLog, Entry, PruneReceipt, verify_consistency, verify_inclusion


def make_log(n, hash_name="sha256"):
    log = AuditLog(hash_name=hash_name)
    for i in range(n):
        log.append(f"record-{i}")
    return log


class SealTest(unittest.TestCase):
    def test_default_seals_whole_log(self):
        log = make_log(4)
        receipt = log.seal()
        self.assertIsInstance(receipt, PruneReceipt)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 4)
        self.assertEqual(receipt.merkle_root, log.merkle_root())
        self.assertEqual(receipt.chain_hash, log.head)

    def test_prefix_seal(self):
        log = make_log(4)
        receipt = log.seal(2)
        self.assertEqual(receipt.size, 2)
        self.assertEqual(receipt.merkle_root, log.merkle_root(2))
        self.assertEqual(receipt.chain_hash, log.entry(1).entry_hash)

    def test_empty_prefix_uses_genesis_hash(self):
        log = make_log(3)
        receipt = log.seal(0)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(receipt.merkle_root, log.merkle_root(0))
        self.assertEqual(receipt.chain_hash, GENESIS_HASH)

    def test_receipt_is_immutable(self):
        receipt = make_log(2).seal()
        with self.assertRaises(AttributeError):
            receipt.size = 1

    def test_size_validation(self):
        log = make_log(2)
        with self.assertRaises(TypeError):
            log.seal("2")
        with self.assertRaises(ValueError):
            log.seal(-1)
        with self.assertRaises(ValueError):
            log.seal(3)

    def test_seal_of_pruned_snapshot_rejected(self):
        log = make_log(4)
        sealed = log.seal(2)
        log.prune(2, sealed)
        with self.assertRaises(ValueError):
            log.seal(1)
        # The retention point itself and later prefixes still seal.
        self.assertEqual(log.seal(2), sealed)
        self.assertEqual(log.seal().size, 4)

    def test_alternate_hash_algorithm(self):
        log = make_log(3, hash_name="sha3-256")
        receipt = log.seal(2)
        self.assertEqual(receipt.hash_name, "sha3-256")
        self.assertEqual(receipt.merkle_root, log.merkle_root(2))


class MatchesTest(unittest.TestCase):
    def test_matches_first_retained_entry(self):
        log = make_log(4)
        receipt = log.seal(2)
        self.assertTrue(receipt.matches(log.entry(2)))

    def test_mismatches(self):
        log = make_log(4)
        receipt = log.seal(2)
        self.assertFalse(receipt.matches(log.entry(1)))  # wrong index
        self.assertFalse(receipt.matches(log.entry(3)))  # wrong predecessor
        forged = Entry(2, b"x", GENESIS_HASH, b"\x00" * 32)
        self.assertFalse(receipt.matches(forged))  # wrong previous_hash

    def test_genesis_receipt_matches_first_entry(self):
        log = make_log(2)
        self.assertTrue(log.seal(0).matches(log.entry(0)))

    def test_type_error(self):
        receipt = make_log(2).seal(1)
        with self.assertRaises(TypeError):
            receipt.matches("not-an-entry")


class PruneTest(unittest.TestCase):
    def test_len_stays_cumulative(self):
        log = make_log(5)
        log.prune(3, log.seal(3))
        self.assertEqual(len(log), 5)
        log.append("record-5")
        self.assertEqual(len(log), 6)

    def test_entries_lists_only_retained(self):
        log = make_log(5)
        log.prune(3, log.seal(3))
        self.assertEqual([entry.index for entry in log.entries()], [3, 4])
        self.assertEqual([entry.index for entry in log], [3, 4])

    def test_old_indices_raise(self):
        log = make_log(5)
        log.prune(3, log.seal(3))
        for index in (0, 1, 2):
            with self.assertRaises(IndexError):
                log.entry(index)
            with self.assertRaises(IndexError):
                log.verify_entry(index)
            with self.assertRaises(ValueError):
                log.inclusion_proof(index)

    def test_head_append_and_entries_match_unpruned(self):
        reference = make_log(5)
        log = make_log(5)
        log.prune(3, log.seal(3))
        self.assertEqual(log.head, reference.head)
        for i in range(5, 8):
            expected = reference.append(f"record-{i}")
            actual = log.append(f"record-{i}")
            self.assertEqual(actual, expected)
        self.assertTrue(log.verify())
        self.assertEqual(log.head, reference.head)

    def test_verify_from_checkpoint(self):
        log = make_log(5)
        log.prune(3, log.seal(3))
        self.assertTrue(log.verify())
        self.assertTrue(all(log.verify_entry(i) for i in range(3, 5)))
        # Tampering with the checkpoint link is detected.
        entry = log.entry(3)
        log._entries[0] = Entry(entry.index, entry.payload, GENESIS_HASH, entry.entry_hash)
        self.assertFalse(log.verify_entry(3))
        self.assertFalse(log.verify())

    def test_prune_everything(self):
        reference = make_log(3)
        log = make_log(3)
        log.prune(3, log.seal(3))
        self.assertEqual(len(log), 3)
        self.assertEqual(log.entries(), [])
        self.assertEqual(log.head, reference.head)
        self.assertTrue(log.verify())
        self.assertEqual(log.append("more"), reference.append("more"))

    def test_prune_empty_prefix_is_noop(self):
        log = make_log(2)
        log.prune(0, log.seal(0))
        self.assertEqual([entry.index for entry in log.entries()], [0, 1])
        self.assertTrue(log.verify())

    def test_retention_point_moves_forward_only(self):
        log = make_log(6)
        log.prune(2, log.seal(2))
        log.append("record-6")
        log.prune(4, log.seal(4))
        self.assertEqual([entry.index for entry in log.entries()], [4, 5, 6])
        self.assertTrue(log.verify())
        with self.assertRaises(ValueError):
            log.prune(3, log.seal(3))  # regression, even with a valid old receipt
        # Re-sealing at the current point is accepted and stays put.
        log.prune(4, log.seal(4))
        self.assertEqual([entry.index for entry in log.entries()], [4, 5, 6])

    def test_out_of_bounds_rejected(self):
        log = make_log(3)
        with self.assertRaises(ValueError):
            log.prune(4, log.seal())
        with self.assertRaises(ValueError):
            log.prune(-1, log.seal(0))

    def test_retain_from_must_equal_receipt_size(self):
        log = make_log(3)
        with self.assertRaises(ValueError):
            log.prune(2, log.seal(3))
        with self.assertRaises(ValueError):
            log.prune(3, log.seal(2))

    def test_mismatched_receipts_rejected(self):
        log = make_log(3)
        other = AuditLog()
        other.append("unrelated")
        with self.assertRaises(ValueError):
            log.prune(1, other.seal(1))  # wrong root and chain hash
        sha3 = make_log(3, hash_name="sha3-256")
        with self.assertRaises(ValueError):
            log.prune(3, sha3.seal(3))  # wrong algorithm
        receipt = log.seal(2)
        tampered = PruneReceipt("sha256", 2, b"\x00" * 32, receipt.chain_hash)
        with self.assertRaises(ValueError):
            log.prune(2, tampered)
        tampered = PruneReceipt("sha256", 2, receipt.merkle_root, b"\x00" * 32)
        with self.assertRaises(ValueError):
            log.prune(2, tampered)

    def test_type_errors(self):
        log = make_log(3)
        with self.assertRaises(TypeError):
            log.prune("2", log.seal(2))
        with self.assertRaises(TypeError):
            log.prune(2, "not-a-receipt")
        with self.assertRaises(TypeError):
            log.prune(2, PruneReceipt(None, 2, b"\x00" * 32, b"\x00" * 32))
        with self.assertRaises(TypeError):
            log.prune(2, PruneReceipt("sha256", "2", b"\x00" * 32, b"\x00" * 32))
        with self.assertRaises(TypeError):
            log.prune(2, PruneReceipt("sha256", 2, "not-bytes", b"\x00" * 32))
        with self.assertRaises(TypeError):
            log.prune(2, PruneReceipt("sha256", 2, b"\x00" * 32, 42))

    def test_log_unchanged_after_failed_prune(self):
        log = make_log(3)
        with self.assertRaises(ValueError):
            log.prune(2, log.seal(3))
        self.assertEqual(len(log.entries()), 3)
        self.assertTrue(log.verify())

    def test_alternate_hash_algorithm(self):
        reference = make_log(5, hash_name="sha3-256")
        log = make_log(5, hash_name="sha3-256")
        log.prune(3, log.seal(3))
        self.assertEqual(log.head, reference.head)
        self.assertEqual(log.append("record-5"), reference.append("record-5"))
        self.assertTrue(log.verify())
        self.assertEqual(log.merkle_root(), reference.merkle_root())


class PrunedMerkleTest(unittest.TestCase):
    def test_merkle_roots_match_unpruned(self):
        reference = make_log(6)
        log = make_log(6)
        log.prune(3, log.seal(3))
        for size in range(3, 7):
            self.assertEqual(log.merkle_root(size), reference.merkle_root(size), size)
        for size in range(3):
            with self.assertRaises(ValueError):
                log.merkle_root(size)

    def test_inclusion_proofs_match_unpruned(self):
        reference = make_log(6)
        log = make_log(6)
        log.prune(3, log.seal(3))
        for size in range(3, 7):
            for index in range(3, size):
                proof = log.inclusion_proof(index, size)
                self.assertEqual(proof, reference.inclusion_proof(index, size), (index, size))
                self.assertTrue(
                    verify_inclusion(
                        log.entry(index).entry_hash, index, size, log.merkle_root(size), proof
                    )
                )

    def test_consistency_proofs_match_unpruned(self):
        reference = make_log(6)
        log = make_log(6)
        log.prune(3, log.seal(3))
        for old in range(3, 7):
            for new in range(old, 7):
                proof = log.consistency_proof(old, new)
                self.assertEqual(proof, reference.consistency_proof(old, new), (old, new))
                self.assertTrue(
                    verify_consistency(
                        old, log.merkle_root(old), new, log.merkle_root(new), proof
                    )
                )
        for old in range(3):
            with self.assertRaises(ValueError):
                log.consistency_proof(old)

    def test_exhaustive_equivalence(self):
        for n in range(1, 10):
            reference = make_log(n)
            for offset in range(n + 1):
                log = make_log(n)
                log.prune(offset, log.seal(offset))
                self.assertTrue(log.verify(), (n, offset))
                self.assertEqual(log.head, reference.head)
                for size in range(offset, n + 1):
                    self.assertEqual(
                        log.merkle_root(size), reference.merkle_root(size), (n, offset, size)
                    )
                    for index in range(offset, size):
                        self.assertEqual(
                            log.inclusion_proof(index, size),
                            reference.inclusion_proof(index, size),
                            (n, offset, index, size),
                        )
                    for old in range(offset, size + 1):
                        self.assertEqual(
                            log.consistency_proof(old, size),
                            reference.consistency_proof(old, size),
                            (n, offset, old, size),
                        )

    def test_appends_after_prune_keep_proofs_consistent(self):
        reference = make_log(4)
        log = make_log(4)
        log.prune(2, log.seal(2))
        for i in range(4, 7):
            reference.append(f"record-{i}")
            log.append(f"record-{i}")
        for size in range(2, 8):
            self.assertEqual(log.merkle_root(size), reference.merkle_root(size))
            for old in range(2, size + 1):
                self.assertEqual(
                    log.consistency_proof(old, size), reference.consistency_proof(old, size)
                )
            for index in range(2, size):
                self.assertEqual(
                    log.inclusion_proof(index, size), reference.inclusion_proof(index, size)
                )

    def test_repeated_forward_prunes(self):
        reference = make_log(9)
        log = make_log(9)
        for point in (2, 5, 7, 9):
            log.prune(point, log.seal(point))
            self.assertTrue(log.verify())
            for size in range(point, 10):
                self.assertEqual(log.merkle_root(size), reference.merkle_root(size), (point, size))
                for old in range(point, size + 1):
                    self.assertEqual(
                        log.consistency_proof(old, size),
                        reference.consistency_proof(old, size),
                        (point, old, size),
                    )


if __name__ == "__main__":
    unittest.main()
