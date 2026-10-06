import os
import unittest

from auditchain import AuditLog, PruneReceipt, decrypt_entry, verify_auth


class ApplyRetentionRetainFromTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for i in range(7):
            self.log.append(f"r{i}")

    def test_target_equals_value(self):
        receipt = self.log.apply_retention(3)
        self.assertIsInstance(receipt, PruneReceipt)
        self.assertEqual(receipt.size, 3)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(len(self.log), 7)
        self.assertEqual([e.index for e in self.log], [3, 4, 5, 6])
        self.assertTrue(self.log.verify())
        self.assertEqual(receipt.merkle_root, self.log.merkle_root(3))
        self.assertTrue(receipt.matches(self.log.entry(3)))

    def test_default_mode_is_retain_from(self):
        receipt = self.log.apply_retention(4)
        self.assertEqual(self.log.retain_from, 4)
        self.assertEqual(receipt.size, 4)

    def test_explicit_mode(self):
        receipt = self.log.apply_retention(5, mode="retain_from")
        self.assertEqual(self.log.retain_from, 5)
        self.assertEqual(receipt.size, 5)

    def test_equivalent_to_seal_then_prune(self):
        twin = AuditLog()
        for i in range(7):
            twin.append(f"r{i}")
        expected = twin.seal(3)
        twin.prune(3, expected)
        receipt = self.log.apply_retention(3)
        self.assertEqual(receipt, expected)
        self.assertEqual([e for e in self.log], [e for e in twin])
        self.assertEqual(self.log.head, twin.head)
        self.assertEqual(self.log.merkle_root(), twin.merkle_root())

    def test_zero_keeps_everything(self):
        receipt = self.log.apply_retention(0)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 7)

    def test_value_at_len_prunes_all(self):
        head = self.log.head
        receipt = self.log.apply_retention(7)
        self.assertEqual(receipt.size, 7)
        self.assertEqual(self.log.retain_from, 7)
        self.assertEqual(self.log.entries(), [])
        self.assertEqual(self.log.head, head)
        self.assertTrue(self.log.verify())

    def test_requires_existing_retain_point_boundary(self):
        self.log.apply_retention(3)
        # Exactly the current retain point is allowed (idempotent no-op prune).
        receipt = self.log.apply_retention(3)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(receipt.size, 3)

    def test_after_earlier_prune(self):
        self.log.prune(2, self.log.seal(2))
        receipt = self.log.apply_retention(5)
        self.assertEqual(self.log.retain_from, 5)
        self.assertEqual(receipt.size, 5)
        self.assertTrue(self.log.verify())


class ApplyRetentionKeepLastTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for i in range(7):
            self.log.append(f"r{i}")

    def test_keeps_newest_value_entries(self):
        receipt = self.log.apply_retention(3, mode="keep_last")
        self.assertEqual(receipt.size, 4)
        self.assertEqual(self.log.retain_from, 4)
        self.assertEqual(len(self.log), 7)
        self.assertEqual([e.index for e in self.log], [4, 5, 6])
        self.assertTrue(self.log.verify())

    def test_value_zero_prunes_everything(self):
        head = self.log.head
        receipt = self.log.apply_retention(0, mode="keep_last")
        self.assertEqual(receipt.size, 7)
        self.assertEqual(self.log.retain_from, 7)
        self.assertEqual(self.log.entries(), [])
        self.assertEqual(self.log.head, head)

    def test_value_larger_than_length_is_noop(self):
        receipt = self.log.apply_retention(100, mode="keep_last")
        self.assertEqual(receipt.size, 0)
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 7)

    def test_value_equal_length_is_noop(self):
        receipt = self.log.apply_retention(7, mode="keep_last")
        self.assertEqual(receipt.size, 0)
        self.assertEqual(self.log.retain_from, 0)

    def test_target_never_moves_backwards(self):
        self.log.prune(5, self.log.seal(5))
        self.assertEqual(len(self.log), 7)
        # len - value = 1, but retain point stays at 5.
        receipt = self.log.apply_retention(6, mode="keep_last")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(self.log.retain_from, 5)
        self.assertEqual([e.index for e in self.log], [5, 6])

    def test_keeps_fewer_after_more_appends(self):
        self.log.apply_retention(3, mode="keep_last")
        self.assertEqual(self.log.retain_from, 4)
        for i in range(7, 10):
            self.log.append(f"r{i}")
        receipt = self.log.apply_retention(2, mode="keep_last")
        self.assertEqual(receipt.size, 8)
        self.assertEqual(self.log.retain_from, 8)
        self.assertEqual([e.index for e in self.log], [8, 9])
        self.assertTrue(self.log.verify())

    def test_empty_log(self):
        log = AuditLog()
        receipt = log.apply_retention(0, mode="keep_last")
        self.assertEqual(receipt.size, 0)
        self.assertEqual(log.retain_from, 0)
        receipt = log.apply_retention(5, mode="keep_last")
        self.assertEqual(receipt.size, 0)


class ApplyRetentionValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for i in range(5):
            self.log.append(f"r{i}")

    def assert_state_unchanged(self):
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 5)
        self.assertEqual([e.payload for e in self.log], [f"r{i}".encode() for i in range(5)])
        self.assertTrue(self.log.verify())

    def test_unknown_mode_value_error(self):
        with self.assertRaises(ValueError):
            self.log.apply_retention(2, mode="keep_first")
        self.assert_state_unchanged()

    def test_bad_mode_type(self):
        for bad in (None, 1, 2.0, b"retain_from", ("retain_from",)):
            with self.assertRaises(TypeError):
                self.log.apply_retention(2, mode=bad)
        self.assert_state_unchanged()

    def test_bad_value_type(self):
        for bad in ("2", 2.0, None, b"2", [2]):
            with self.assertRaises(TypeError):
                self.log.apply_retention(bad)
            with self.assertRaises(TypeError):
                self.log.apply_retention(bad, mode="keep_last")
        self.assert_state_unchanged()

    def test_bool_value_rejected(self):
        with self.assertRaises(TypeError):
            self.log.apply_retention(True)
        with self.assertRaises(TypeError):
            self.log.apply_retention(False, mode="keep_last")
        self.assert_state_unchanged()

    def test_retain_from_out_of_range_high(self):
        with self.assertRaises(ValueError):
            self.log.apply_retention(6)
        with self.assertRaises(ValueError):
            self.log.apply_retention(6, mode="retain_from")
        self.assert_state_unchanged()

    def test_retain_from_negative(self):
        with self.assertRaises(ValueError):
            self.log.apply_retention(-1)
        self.assert_state_unchanged()

    def test_retain_from_before_current_point(self):
        self.log.prune(3, self.log.seal(3))
        with self.assertRaises(ValueError):
            self.log.apply_retention(2)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(len(self.log), 5)

    def test_keep_last_negative_rejected(self):
        with self.assertRaises(ValueError):
            self.log.apply_retention(-1, mode="keep_last")
        self.assert_state_unchanged()

    def test_type_errors_take_priority(self):
        # Non-bool/non-int value with an unknown mode is still a TypeError.
        with self.assertRaises(TypeError):
            self.log.apply_retention("x", mode="nope")
        with self.assertRaises(TypeError):
            self.log.apply_retention(True, mode=123)
        self.assert_state_unchanged()


class ApplyRetentionStatePreservationTest(unittest.TestCase):
    def _snapshot_state(self, log):
        return (
            log.retain_from,
            len(log),
            [e for e in log.entries()],
            log.head,
            log.merkle_root(),
            log.stage,
            dict(log._tags),
            dict(log._index),
            set(log._used_nonces),
            dict(log._frontier),
            log._checkpoint_head,
        )

    def test_failure_preserves_auth_index_proof_state(self):
        key = os.urandom(32)
        log = AuditLog(key=key)
        for i in range(5):
            log.append(f"r{i}")
        verifier = log.export_verifier()
        tag = log.auth(0)
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))
        before = self._snapshot_state(log)
        with self.assertRaises(ValueError):
            log.apply_retention(10)
        with self.assertRaises(ValueError):
            log.apply_retention(-1, mode="keep_last")
        with self.assertRaises(TypeError):
            log.apply_retention(True)
        after = self._snapshot_state(log)
        self.assertEqual(before, after)
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))

    def test_nonce_history_survives_retention(self):
        key = os.urandom(32)
        log = AuditLog()
        nonce = b"\x01" * 12
        entry = log.encrypt("secret", key, nonce)
        for i in range(4):
            log.append(f"r{i}")
        receipt = log.apply_retention(3, mode="keep_last")
        self.assertEqual(receipt.size, 2)
        # The encrypted entry (index 0) was released, but its nonce is spent.
        with self.assertRaises(ValueError):
            log.encrypt("again", key, nonce)
        self.assertEqual(decrypt_entry(entry, key), b"secret")
        self.assertTrue(log.verify())

    def test_success_releases_prefix_tags_but_keeps_rest(self):
        key = os.urandom(32)
        log = AuditLog(key=key)
        for i in range(6):
            log.append(f"r{i}")
        verifier = log.export_verifier()
        tag0 = log.auth(0)
        tag5 = log.auth(5)
        stage_before = log.stage
        receipt = log.apply_retention(5)
        self.assertEqual(receipt.size, 5)
        self.assertEqual(log.retain_from, 5)
        # Authentication state is untouched apart from the released prefix tags.
        self.assertEqual(log.stage, stage_before)
        self.assertNotIn(0, log._tags)
        self.assertIn(5, log._tags)
        # Remaining tag still verifies offline against the released entry's chain.
        self.assertTrue(verify_auth(log.entry(5), tag5, verifier))
        self.assertTrue(log.verify())
        # tag0 verified before; its release removes the log copy only.
        self.assertEqual(tag0.stage, 0)


class ApplyRetentionKeepBytesTest(unittest.TestCase):
    def _log_with_sizes(self, sizes):
        log = AuditLog()
        for size in sizes:
            log.append(bytes(range(size)) if size else b"")
        return log

    def test_spec_example_budget_three(self):
        # Payload sizes 2, 0, 3, 0 with budget 3 keeps the last three.
        log = self._log_with_sizes([2, 0, 3, 0])
        receipt = log.apply_retention(3, mode="keep_bytes")
        self.assertEqual(receipt.size, 1)
        self.assertEqual(log.retain_from, 1)
        self.assertEqual([e.index for e in log], [1, 2, 3])
        self.assertTrue(log.verify())

    def test_spec_example_budget_zero(self):
        # Budget 0 keeps only the trailing run of zero-byte payloads.
        log = self._log_with_sizes([2, 0, 3, 0])
        receipt = log.apply_retention(0, mode="keep_bytes")
        self.assertEqual(receipt.size, 3)
        self.assertEqual(log.retain_from, 3)
        self.assertEqual([e.index for e in log], [3])
        self.assertTrue(log.verify())

    def test_all_empty_payloads_zero_budget_is_noop(self):
        log = self._log_with_sizes([0, 0, 0])
        receipt = log.apply_retention(0, mode="keep_bytes")
        self.assertEqual(receipt.size, 0)
        self.assertEqual(log.retain_from, 0)
        self.assertEqual(len(log.entries()), 3)

    def test_total_equal_budget_keeps_everything(self):
        log = self._log_with_sizes([2, 0, 3])
        receipt = log.apply_retention(5, mode="keep_bytes")
        self.assertEqual(receipt.size, 0)
        self.assertEqual(log.retain_from, 0)
        self.assertEqual(len(log.entries()), 3)

    def test_ample_budget_is_noop(self):
        log = self._log_with_sizes([2, 3, 4])
        receipt = log.apply_retention(1000, mode="keep_bytes")
        self.assertEqual(receipt.size, 0)
        self.assertEqual(log.retain_from, 0)
        self.assertEqual(len(log.entries()), 3)

    def test_empty_log_is_noop(self):
        log = AuditLog()
        receipt = log.apply_retention(10, mode="keep_bytes")
        self.assertEqual(receipt.size, 0)
        self.assertEqual(log.retain_from, 0)
        receipt = log.apply_retention(0, mode="keep_bytes")
        self.assertEqual(receipt.size, 0)

    def test_fully_pruned_log_is_noop(self):
        log = self._log_with_sizes([1, 2])
        log.apply_retention(2)
        receipt = log.apply_retention(100, mode="keep_bytes")
        self.assertEqual(receipt.size, 2)
        self.assertEqual(log.retain_from, 2)
        self.assertEqual(log.entries(), [])

    def test_newest_entry_larger_than_budget_prunes_all(self):
        log = self._log_with_sizes([1, 1, 5])
        head = log.head
        receipt = log.apply_retention(2, mode="keep_bytes")
        self.assertEqual(receipt.size, 3)
        self.assertEqual(log.retain_from, 3)
        self.assertEqual(log.entries(), [])
        self.assertEqual(log.head, head)
        self.assertTrue(log.verify())

    def test_cannot_skip_large_middle_entry(self):
        # Sizes 1, 5, 1 with budget 2: the big middle entry blocks the
        # earlier small one, so only the newest entry is kept.
        log = self._log_with_sizes([1, 5, 1])
        receipt = log.apply_retention(2, mode="keep_bytes")
        self.assertEqual(receipt.size, 2)
        self.assertEqual([e.index for e in log], [2])

    def test_suffix_is_contiguous_from_budget(self):
        log = self._log_with_sizes([4, 1, 2, 1])
        # 1+2+1 = 4 fits; adding the leading 4 would exceed.
        receipt = log.apply_retention(4, mode="keep_bytes")
        self.assertEqual(receipt.size, 1)
        self.assertEqual([e.index for e in log], [1, 2, 3])

    def test_never_moves_retain_point_backwards(self):
        log = self._log_with_sizes([3, 3, 3])
        log.prune(2, log.seal(2))
        receipt = log.apply_retention(100, mode="keep_bytes")
        self.assertEqual(receipt.size, 2)
        self.assertEqual(log.retain_from, 2)
        self.assertEqual([e.index for e in log], [2])

    def test_budget_counts_only_retained_entries(self):
        log = self._log_with_sizes([9, 2, 2])
        log.prune(1, log.seal(1))
        # The released 9-byte payload no longer counts against the budget.
        receipt = log.apply_retention(4, mode="keep_bytes")
        self.assertEqual(receipt.size, 1)
        self.assertEqual(log.retain_from, 1)
        self.assertEqual(len(log.entries()), 2)

    def test_str_payload_metered_as_utf8_bytes(self):
        log = AuditLog()
        log.append("é")  # 2 UTF-8 bytes
        log.append("aa")  # 2 bytes
        receipt = log.apply_retention(2, mode="keep_bytes")
        self.assertEqual(receipt.size, 1)
        self.assertEqual([e.payload for e in log], [b"aa"])

    def test_encrypted_payload_metered_as_full_envelope(self):
        key = os.urandom(32)
        log = AuditLog()
        entry = log.encrypt("secret", key)
        envelope_size = len(entry.payload)
        self.assertGreater(envelope_size, len(b"secret"))
        log.append(b"x")
        # Budget below the envelope keeps only the plaintext tail.
        receipt = log.apply_retention(envelope_size - 1, mode="keep_bytes")
        self.assertEqual(receipt.size, 1)
        self.assertEqual([e.index for e in log], [1])
        # Budget at the full envelope size keeps both.
        log2 = AuditLog()
        log2.encrypt("secret", key)
        log2.append(b"x")
        receipt = log2.apply_retention(envelope_size + 1, mode="keep_bytes")
        self.assertEqual(receipt.size, 0)
        self.assertEqual(len(log2.entries()), 2)

    def test_receipt_matches_seal_at_target(self):
        log = self._log_with_sizes([2, 0, 3, 0])
        twin = self._log_with_sizes([2, 0, 3, 0])
        expected = twin.seal(1)
        receipt = log.apply_retention(3, mode="keep_bytes")
        self.assertEqual(receipt, expected)
        self.assertTrue(receipt.matches(log.entry(1)))
        self.assertEqual(receipt.merkle_root, log.merkle_root(1))

    def test_repeat_same_budget_equal_receipts(self):
        log = self._log_with_sizes([2, 0, 3, 0])
        first = log.apply_retention(3, mode="keep_bytes")
        second = log.apply_retention(3, mode="keep_bytes")
        self.assertEqual(first, second)
        self.assertEqual(log.retain_from, 1)

    def test_recomputed_after_append(self):
        log = self._log_with_sizes([2, 0, 3, 0])
        first = log.apply_retention(3, mode="keep_bytes")
        log.append(b"z")
        second = log.apply_retention(3, mode="keep_bytes")
        self.assertNotEqual(first, second)
        # Newest segment is 3 (index 2) + 0 (index 3) + 1 (index 4) > 3,
        # so the suffix is 0 + 1 starting at index 3.
        self.assertEqual(second.size, 3)
        self.assertEqual([e.index for e in log], [3, 4])
        self.assertTrue(log.verify())

    def test_state_after_success(self):
        key = os.urandom(32)
        log = AuditLog(key=key)
        for i in range(6):
            log.append(f"r{i}")
        head = log.head
        verifier = log.export_verifier()
        tag5 = log.auth(5)
        stage = log.stage
        proof4 = log.inclusion_proof(4)
        root = log.merkle_root()
        receipt = log.apply_retention(4, mode="keep_bytes")  # 6 x 2 bytes
        self.assertEqual(receipt.size, 4)
        # Absolute indexing, total length and head are untouched.
        self.assertEqual(len(log), 6)
        self.assertEqual(log.head, head)
        self.assertEqual(log.stage, stage)
        self.assertEqual([e.index for e in log], [4, 5])
        # Released entries are gone from queries and direct access.
        self.assertEqual(log.find("r0"), ())
        with self.assertRaises(IndexError):
            log.entry(0)
        # Retained entries still resolve, authenticate and prove.
        self.assertEqual(log.find("r4"), (4,))
        self.assertTrue(verify_auth(log.entry(5), tag5, verifier))
        self.assertEqual(log.inclusion_proof(4), proof4)
        self.assertEqual(log.merkle_root(), root)
        self.assertTrue(log.verify())
        # Appends continue the original chain.
        log.append("r6")
        self.assertEqual(log.entry(6).index, 6)
        self.assertTrue(log.verify())


class ApplyRetentionKeepBytesValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for i in range(5):
            self.log.append(f"r{i}")

    def assert_state_unchanged(self):
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 5)
        self.assertEqual(
            [e.payload for e in self.log], [f"r{i}".encode() for i in range(5)]
        )
        self.assertTrue(self.log.verify())

    def test_negative_rejected(self):
        with self.assertRaises(ValueError):
            self.log.apply_retention(-1, mode="keep_bytes")
        self.assert_state_unchanged()

    def test_bad_value_type(self):
        for bad in ("2", 2.0, None, b"2", [2]):
            with self.assertRaises(TypeError):
                self.log.apply_retention(bad, mode="keep_bytes")
        self.assert_state_unchanged()

    def test_bool_value_rejected(self):
        with self.assertRaises(TypeError):
            self.log.apply_retention(True, mode="keep_bytes")
        self.assert_state_unchanged()

    def test_type_errors_take_priority(self):
        with self.assertRaises(TypeError):
            self.log.apply_retention("x", mode="keep_bytes")
        with self.assertRaises(TypeError):
            self.log.apply_retention(True, mode=123)
        self.assert_state_unchanged()

    def test_failure_preserves_auth_index_nonce_state(self):
        key = os.urandom(32)
        log = AuditLog(key=key)
        nonce = b"\x02" * 12
        log.encrypt("secret", key, nonce)
        for i in range(4):
            log.append(f"r{i}")
        verifier = log.export_verifier()
        tag = log.auth(1)
        before = (
            log.retain_from,
            len(log),
            [e for e in log.entries()],
            log.head,
            log.merkle_root(),
            log.stage,
            dict(log._tags),
            dict(log._index),
            set(log._used_nonces),
            dict(log._frontier),
            log._checkpoint_head,
        )
        with self.assertRaises(ValueError):
            log.apply_retention(-1, mode="keep_bytes")
        with self.assertRaises(TypeError):
            log.apply_retention(1.5, mode="keep_bytes")
        after = (
            log.retain_from,
            len(log),
            [e for e in log.entries()],
            log.head,
            log.merkle_root(),
            log.stage,
            dict(log._tags),
            dict(log._index),
            set(log._used_nonces),
            dict(log._frontier),
            log._checkpoint_head,
        )
        self.assertEqual(before, after)
        self.assertTrue(verify_auth(log.entry(1), tag, verifier))

    def test_nonce_still_spent_after_keep_bytes_prune(self):
        key = os.urandom(32)
        log = AuditLog()
        nonce = b"\x03" * 12
        entry = log.encrypt("secret", key, nonce)
        for i in range(3):
            log.append(b"x")
        envelope_size = len(entry.payload)
        # Keep only the three 1-byte tails; the encrypted entry is released.
        receipt = log.apply_retention(3, mode="keep_bytes")
        self.assertEqual(receipt.size, 1)
        with self.assertRaises(ValueError):
            log.encrypt("again", key, nonce)
        self.assertEqual(decrypt_entry(entry, key), b"secret")
        self.assertTrue(log.verify())


if __name__ == "__main__":
    unittest.main()
