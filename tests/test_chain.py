import hashlib
import unittest

from auditchain import GENESIS_HASH, AuditLog, Entry, entry_digest


class DigestTest(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(entry_digest(0, GENESIS_HASH, b"x"), entry_digest(0, GENESIS_HASH, b"x"))

    def test_index_is_bound(self):
        self.assertNotEqual(entry_digest(0, GENESIS_HASH, b"x"), entry_digest(1, GENESIS_HASH, b"x"))

    def test_previous_hash_is_bound(self):
        self.assertNotEqual(entry_digest(1, GENESIS_HASH, b"x"), entry_digest(1, b"\x01" * 32, b"x"))

    def test_payload_is_bound(self):
        self.assertNotEqual(entry_digest(0, GENESIS_HASH, b"x"), entry_digest(0, GENESIS_HASH, b"y"))

    def test_negative_index_rejected(self):
        with self.assertRaises(ValueError):
            entry_digest(-1, GENESIS_HASH, b"x")

    def test_wrong_previous_hash_length_rejected(self):
        with self.assertRaises(ValueError):
            entry_digest(0, b"\x00" * 31, b"x")

    def test_matches_hashlib_composition(self):
        expected = hashlib.sha256(b"auditchain/entry/v1" + (0).to_bytes(8, "big") + GENESIS_HASH + b"x").digest()
        self.assertEqual(entry_digest(0, GENESIS_HASH, b"x"), expected)


class AppendTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()

    def test_empty_log_has_genesis_head(self):
        self.assertEqual(len(self.log), 0)
        self.assertEqual(self.log.head, GENESIS_HASH)
        self.assertTrue(self.log.verify())

    def test_indices_increment(self):
        self.assertEqual([self.log.append(f"record-{i}").index for i in range(3)], [0, 1, 2])

    def test_previous_hash_links_back(self):
        first = self.log.append("a")
        second = self.log.append("b")
        self.assertEqual(first.previous_hash, GENESIS_HASH)
        self.assertEqual(second.previous_hash, first.entry_hash)

    def test_str_is_utf8_encoded(self):
        self.assertEqual(self.log.append("héllo").payload, "héllo".encode("utf-8"))

    def test_bytes_pass_through(self):
        self.assertEqual(self.log.append(b"\x00\x01").payload, b"\x00\x01")

    def test_unsupported_payload_rejected(self):
        with self.assertRaises(TypeError):
            self.log.append(42)

    def test_entries_returns_a_copy(self):
        self.log.append("a")
        snapshot = self.log.entries()
        snapshot.clear()
        self.assertEqual(len(self.log), 1)

    def test_entry_lookup_bounds(self):
        self.log.append("a")
        self.assertIsInstance(self.log.entry(0), Entry)
        with self.assertRaises(IndexError):
            self.log.entry(1)
        with self.assertRaises(TypeError):
            self.log.entry("0")

    def test_unknown_hash_rejected(self):
        with self.assertRaises(ValueError):
            AuditLog(hash_name="not-a-hash")


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d"):
            self.log.append(record)

    def test_chain_verifies(self):
        self.assertTrue(self.log.verify())

    def test_every_entry_verifies(self):
        self.assertTrue(all(self.log.verify_entry(index) for index in range(len(self.log))))

    def test_modified_payload_breaks_that_entry(self):
        original = self.log.entry(2)
        self.log._entries[2] = Entry(original.index, b"tampered", original.previous_hash, original.entry_hash)
        self.assertFalse(self.log.verify_entry(2))
        self.assertFalse(self.log.verify())

    def test_relinked_payload_is_detected_by_successor(self):
        original = self.log.entry(1)
        forged = entry_digest(original.index, original.previous_hash, b"forged")
        self.log._entries[1] = Entry(original.index, b"forged", original.previous_hash, forged)
        # Entry 1 is now internally consistent, but entry 2 still points at the old hash.
        self.assertTrue(self.log.verify_entry(1))
        self.assertFalse(self.log.verify_entry(2))
        self.assertFalse(self.log.verify())

    def test_reordered_entries_are_detected(self):
        self.log._entries[0], self.log._entries[1] = self.log._entries[1], self.log._entries[0]
        self.assertFalse(self.log.verify())

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        log.append("a")
        log.append("b")
        self.assertTrue(log.verify())


if __name__ == "__main__":
    unittest.main()
