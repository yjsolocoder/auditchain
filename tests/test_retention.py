import os
import unittest

from auditchain import AuditLog, PruneReceipt, decrypt_entry, verify_auth


class ApplyRetentionRetainFromTest(unittest.TestCase):
    def setUp(self):
        self.records = [f"r{i}" for i in range(5)]
        self.log = AuditLog()
        for record in self.records:
            self.log.append(record)
        self.twin = AuditLog()
        for record in self.records:
            self.twin.append(record)

    def test_retain_from_prunes_to_value(self):
        receipt = self.log.apply_retention(2)
        self.assertIsInstance(receipt, PruneReceipt)
        self.assertEqual(receipt.size, 2)
        self.assertEqual(self.log.retain_from, 2)
        self.assertEqual(len(self.log), 5)
        self.assertEqual([e.index for e in self.log], [2, 3, 4])
        self.assertTrue(self.log.verify())
        self.assertEqual(self.log.head, self.twin.head)
        self.assertEqual(self.log.merkle_root(2), self.twin.merkle_root(2))

    def test_default_mode_is_retain_from(self):
        receipt = self.log.apply_retention(3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual(self.log.retain_from, 3)

    def test_receipt_matches_seal_then_prune(self):
        expected = self.twin.seal(2)
        self.twin.prune(2, expected)
        receipt = self.log.apply_retention(2)
        self.assertEqual(receipt, expected)
        self.assertEqual(self.log.entries(), self.twin.entries())

    def test_retain_at_tip_releases_everything(self):
        head_before = self.log.head
        receipt = self.log.apply_retention(5)
        self.assertEqual(receipt.size, 5)
        self.assertEqual(self.log.retain_from, 5)
        self.assertEqual(self.log.entries(), [])
        self.assertEqual(self.log.head, head_before)
        self.assertTrue(self.log.verify())

    def test_retain_at_current_point_is_noop(self):
        self.log.apply_retention(2)
        receipt = self.log.apply_retention(2)
        self.assertEqual(receipt.size, 2)
        self.assertEqual(self.log.retain_from, 2)
        self.assertTrue(self.log.verify())


class ApplyRetentionKeepLastTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for i in range(5):
            self.log.append(f"r{i}")

    def test_keeps_newest_entries(self):
        receipt = self.log.apply_retention(2, mode="keep_last")
        self.assertEqual(receipt.size, 3)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual([e.index for e in self.log], [3, 4])
        self.assertTrue(self.log.verify())

    def test_keep_zero_prunes_everything(self):
        receipt = self.log.apply_retention(0, mode="keep_last")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(self.log.retain_from, 5)
        self.assertEqual(self.log.entries(), [])

    def test_keeping_more_than_length_is_noop(self):
        receipt = self.log.apply_retention(10, mode="keep_last")
        self.assertEqual(receipt.size, 0)
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 5)
        self.assertEqual([e.index for e in self.log], [0, 1, 2, 3, 4])

    def test_target_never_moves_before_current_retain_point(self):
        self.log.apply_retention(2, mode="retain_from")
        # len 5, keep 4 newest would ask for retain point 1, but 2 is held.
        receipt = self.log.apply_retention(4, mode="keep_last")
        self.assertEqual(receipt.size, 2)
        self.assertEqual(self.log.retain_from, 2)
        self.assertEqual([e.index for e in self.log], [2, 3, 4])

    def test_keep_last_after_growth(self):
        self.log.apply_retention(3, mode="retain_from")
        for i in range(5, 8):
            self.log.append(f"r{i}")
        receipt = self.log.apply_retention(2, mode="keep_last")
        # len 8, keep 2 -> target 6, ahead of the current retain point 3.
        self.assertEqual(receipt.size, 6)
        self.assertEqual(self.log.retain_from, 6)
        self.assertEqual([e.index for e in self.log], [6, 7])
        self.assertTrue(self.log.verify())


class ApplyRetentionValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for i in range(4):
            self.log.append(f"r{i}")

    def test_value_must_be_non_bool_integer(self):
        for bad in ("2", 2.0, None, [2]):
            with self.assertRaises(TypeError):
                self.log.apply_retention(bad)
            with self.assertRaises(TypeError):
                self.log.apply_retention(bad, mode="keep_last")

    def test_bool_value_rejected(self):
        with self.assertRaises(TypeError):
            self.log.apply_retention(True)
        with self.assertRaises(TypeError):
            self.log.apply_retention(False, mode="keep_last")

    def test_mode_must_be_string(self):
        with self.assertRaises(TypeError):
            self.log.apply_retention(2, mode=1)
        with self.assertRaises(TypeError):
            self.log.apply_retention(2, mode=None)

    def test_unknown_mode_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.log.apply_retention(2, mode="keep-first")
        with self.assertRaises(ValueError):
            self.log.apply_retention(2, mode="")

    def test_retain_from_range(self):
        with self.assertRaises(ValueError):
            self.log.apply_retention(-1)
        with self.assertRaises(ValueError):
            self.log.apply_retention(len(self.log) + 1)
        self.log.apply_retention(2)
        with self.assertRaises(ValueError):
            self.log.apply_retention(1)

    def test_keep_last_range(self):
        with self.assertRaises(ValueError):
            self.log.apply_retention(-1, mode="keep_last")

    def test_failed_call_changes_nothing(self):
        head_before = self.log.head
        with self.assertRaises(ValueError):
            self.log.apply_retention(10)
        with self.assertRaises(ValueError):
            self.log.apply_retention(-1, mode="keep_last")
        with self.assertRaises(ValueError):
            self.log.apply_retention(2, mode="unknown")
        with self.assertRaises(TypeError):
            self.log.apply_retention(True)
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 4)
        self.assertEqual(self.log.head, head_before)
        self.assertEqual(self.log.find(b"r0"), (0,))
        self.assertEqual(
            [e.payload for e in self.log.entries()],
            [b"r0", b"r1", b"r2", b"r3"],
        )
        self.assertTrue(self.log.verify())
        self.assertEqual(self.log.merkle_root(), self.log.merkle_root(4))

    def test_failed_call_after_prior_prune_changes_nothing(self):
        self.log.apply_retention(2)
        with self.assertRaises(ValueError):
            self.log.apply_retention(1)
        self.assertEqual(self.log.retain_from, 2)
        self.assertEqual([e.index for e in self.log], [2, 3])
        self.assertTrue(self.log.verify())


class ApplyRetentionStateTest(unittest.TestCase):
    def test_nonce_history_survives_retention(self):
        key = os.urandom(32)
        log = AuditLog()
        nonce = b"\x01" * 12
        log.encrypt("secret-0", key, nonce)
        log.encrypt("secret-1", key, b"\x02" * 12)
        log.append("plain")
        # Release the first (encrypted) entry entirely.
        receipt = log.apply_retention(2, mode="keep_last")
        self.assertEqual(receipt.size, 1)
        self.assertNotIn(0, [e.index for e in log])
        # Its nonce is still forbidden.
        with self.assertRaises(ValueError):
            log.encrypt("secret-2", key, nonce)

    def test_encrypted_retained_entry_still_decrypts(self):
        key = os.urandom(32)
        log = AuditLog()
        log.append("a")
        entry = log.encrypt("secret", key, b"\x09" * 12)
        log.apply_retention(1)
        self.assertEqual(log.retain_from, 1)
        self.assertEqual(decrypt_entry(log.entry(1), key), b"secret")
        self.assertEqual(log.entry(1), entry)

    def test_auth_state_preserved_on_success(self):
        key = b"shared-secret"
        log = AuditLog(key=key)
        verifier = log.export_verifier()
        twin = AuditLog()
        for i in range(4):
            log.append(f"r{i}")
            twin.append(f"r{i}")
        tag0 = log.auth(0)
        stage_after_auth = log.stage
        log.apply_retention(2, mode="keep_last")  # target = max(0, 4-2) = 2
        self.assertEqual(log.retain_from, 2)
        # Key evolution state is untouched by retention.
        self.assertEqual(log.stage, stage_after_auth)
        tag2 = log.auth(2)
        self.assertTrue(verify_auth(log.entry(2), tag2, verifier))
        # The released entry's tag still verifies offline against a twin.
        self.assertTrue(verify_auth(twin.entry(0), tag0, verifier))

    def test_auth_state_preserved_on_failure(self):
        key = b"shared-secret"
        log = AuditLog(key=key)
        verifier = log.export_verifier()
        for i in range(3):
            log.append(f"r{i}")
        tag = log.auth(0)
        stage_before = log.stage
        with self.assertRaises(ValueError):
            log.apply_retention(10)
        self.assertEqual(log.stage, stage_before)
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))

    def test_locator_index_consistent_after_retention(self):
        log = AuditLog()
        for payload in ("a", "b", "a", "c", "a"):
            log.append(payload)
        log.apply_retention(3)
        self.assertEqual(log.find(b"a"), (4,))
        self.assertEqual(log.find(b"b"), ())
        self.assertEqual(log.find(b"c"), (3,))


if __name__ == "__main__":
    unittest.main()
