import unittest

from auditchain import (
    AuditLog,
    PrefixSearchReceipt,
    verify_prefix_search_receipt,
)


def make_log(records=("a", "b", "aa", "c", "az", "b", b"a\x00")):
    log = AuditLog()
    for record in records:
        log.append(record)
    return log


class PrefixSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_receipt_carries_snapshot_context(self):
        receipt = self.log.prefix_search_receipt(b"a")
        self.assertIsInstance(receipt, PrefixSearchReceipt)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, len(self.log))
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.prefix, b"a")
        self.assertEqual(receipt.start, 0)
        self.assertEqual(receipt.stop, len(self.log))

    def test_str_prefix_is_utf8_normalized(self):
        self.assertEqual(
            self.log.prefix_search_receipt("a"),
            self.log.prefix_search_receipt(b"a"),
        )

    def test_items_cover_every_entry_of_the_range(self):
        receipt = self.log.prefix_search_receipt(b"a", 1, 5)
        self.assertEqual(
            [entry.index for entry in receipt.items], [1, 2, 3, 4]
        )
        self.assertEqual(receipt.start, 1)
        self.assertEqual(receipt.stop, 5)

    def test_hits_match_find_prefix_over_authenticated_entries(self):
        for prefix, start, stop in (
            (b"a", None, None),
            (b"a", 1, 5),
            (b"aa", None, None),
            (b"b", None, None),
            (b"a\x00", None, None),
            (b"zz", None, None),
        ):
            receipt = self.log.prefix_search_receipt(prefix, start, stop)
            expected = tuple(
                entry.index
                for entry in receipt.items
                if entry.payload.startswith(prefix)
            )
            self.assertEqual(receipt.hits, expected)
            self.assertEqual(
                receipt.hits, self.log.find_prefix(prefix, start, stop)
            )

    def test_empty_prefix_hits_whole_covered_range(self):
        receipt = self.log.prefix_search_receipt(b"")
        self.assertEqual(
            receipt.hits, tuple(range(len(self.log)))
        )
        self.assertEqual(len(receipt.items), len(self.log))
        self.assertTrue(verify_prefix_search_receipt(receipt))

    def test_explicit_size(self):
        receipt = self.log.prefix_search_receipt(b"a", 0, 3, size=3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual([entry.index for entry in receipt.items], [0, 1, 2])
        self.assertEqual(receipt.hits, (0, 2))
        self.assertTrue(verify_prefix_search_receipt(receipt))


class PrefixSearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_genuine_receipt_verifies_offline(self):
        receipt = self.log.prefix_search_receipt(b"a")
        self.assertTrue(verify_prefix_search_receipt(receipt))

    def test_partial_range_verifies(self):
        receipt = self.log.prefix_search_receipt(b"a", 2, 6, size=7)
        self.assertTrue(verify_prefix_search_receipt(receipt))
        self.assertEqual(receipt.hits, (2, 4))

    def test_empty_prefix_partial_range_verifies(self):
        receipt = self.log.prefix_search_receipt(b"", 2, 5)
        self.assertTrue(verify_prefix_search_receipt(receipt))
        self.assertEqual(receipt.hits, (2, 3, 4))

    def test_deleting_a_hit_cannot_pass(self):
        receipt = self.log.prefix_search_receipt(b"a")
        hit_indices = set(receipt.hits)
        thinned = tuple(
            entry for entry in receipt.items if entry.index not in hit_indices
        )
        # Coverage is a structural error: the constructor rejects it.
        with self.assertRaises(ValueError):
            PrefixSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.prefix,
                receipt.start,
                receipt.stop,
                thinned,
                receipt.proof,
            )

    def test_deleting_an_out_of_range_entry_breaks_coverage_too(self):
        receipt = self.log.prefix_search_receipt(b"a")
        # Index 1 (payload b"b") is not a hit; dropping it must still fail.
        thinned = tuple(
            entry for entry in receipt.items if entry.index != 1
        )
        with self.assertRaises(ValueError):
            PrefixSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.prefix,
                receipt.start,
                receipt.stop,
                thinned,
                receipt.proof,
            )

    def test_duplicate_or_reordered_items_rejected(self):
        receipt = self.log.prefix_search_receipt(b"a", 1, 4)
        reordered = (receipt.items[1], receipt.items[0], receipt.items[2])
        with self.assertRaises(ValueError):
            PrefixSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.prefix,
                receipt.start,
                receipt.stop,
                reordered,
                receipt.proof,
            )

    def test_forging_empty_hits_by_mutating_payload_fails(self):
        receipt = self.log.prefix_search_receipt(b"a")
        self.assertTrue(receipt.hits)
        # Rewrite every payload so it no longer starts with b"a"; the
        # recorded entry digests no longer recompute, so verify is False.
        forged_items = tuple(
            type(entry)(entry.index, b"zz", entry.previous_hash, entry.entry_hash)
            for entry in receipt.items
        )
        forged = PrefixSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.prefix,
            receipt.start,
            receipt.stop,
            forged_items,
            receipt.proof,
        )
        self.assertEqual(forged.hits, ())
        self.assertFalse(verify_prefix_search_receipt(forged))

    def test_changing_prefix_to_hide_hits_fails(self):
        receipt = self.log.prefix_search_receipt(b"a")
        # Reclassifying under a longer prefix changes the hit set, but every
        # payload/proof is still genuine, so this receipt is authentic for
        # the new query; completeness is over the authenticated entries.
        narrowed = PrefixSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            b"aaa",
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
        )
        self.assertEqual(narrowed.hits, ())
        self.assertTrue(verify_prefix_search_receipt(narrowed))

    def test_tampered_root_returns_false(self):
        receipt = self.log.prefix_search_receipt(b"a")
        forged = PrefixSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            bytes(32),
            receipt.prefix,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
        )
        self.assertFalse(verify_prefix_search_receipt(forged))


class PrefixSearchReceiptEmptyTest(unittest.TestCase):
    def test_empty_log(self):
        log = AuditLog()
        receipt = log.prefix_search_receipt(b"a")
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertEqual(receipt.size, 0)
        self.assertTrue(verify_prefix_search_receipt(receipt))
        # Empty prefix over an empty snapshot is equally genuine.
        empty = log.prefix_search_receipt(b"")
        self.assertEqual(empty.hits, ())
        self.assertTrue(verify_prefix_search_receipt(empty))

    def test_empty_index_range_of_non_empty_snapshot(self):
        log = make_log()
        receipt = log.prefix_search_receipt(b"a", 3, 3)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        # An empty range of a non-empty snapshot attests no content.
        self.assertTrue(verify_prefix_search_receipt(receipt))

    def test_full_range_without_any_hit(self):
        log = make_log()
        receipt = log.prefix_search_receipt(b"zz")
        self.assertTrue(receipt.items)
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_prefix_search_receipt(receipt))


class PrefixSearchReceiptErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_prefix_type_errors(self):
        for bad in (None, 1, bytearray(b"a"), memoryview(b"a"), ["a"]):
            with self.assertRaises(TypeError):
                self.log.prefix_search_receipt(bad)

    def test_range_type_and_value_errors_follow_range_search(self):
        with self.assertRaises(TypeError):
            self.log.prefix_search_receipt(b"a", True)
        with self.assertRaises(TypeError):
            self.log.prefix_search_receipt(b"a", 0, "2")
        with self.assertRaises(ValueError):
            self.log.prefix_search_receipt(b"a", -1)
        with self.assertRaises(ValueError):
            self.log.prefix_search_receipt(b"a", 0, len(self.log) + 1)
        with self.assertRaises(ValueError):
            self.log.prefix_search_receipt(b"a", 4, 2)
        with self.assertRaises(TypeError):
            self.log.prefix_search_receipt(b"a", size=True)
        with self.assertRaises(ValueError):
            self.log.prefix_search_receipt(b"a", size=len(self.log) + 1)
        with self.assertRaises(ValueError):
            self.log.prefix_search_receipt(b"a", size=-1)

    def test_size_boundaries_are_accepted(self):
        receipt = self.log.prefix_search_receipt(b"a", 0, 0, size=0)
        self.assertEqual(receipt.size, 0)
        receipt = self.log.prefix_search_receipt(
            b"a", 0, len(self.log), size=len(self.log)
        )
        self.assertTrue(verify_prefix_search_receipt(receipt))

    def test_pruned_snapshot_and_range(self):
        log = make_log()
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            log.prefix_search_receipt(b"a", 0, 4)
        with self.assertRaises(ValueError):
            # Snapshot of size 1 can no longer be rebuilt.
            log.prefix_search_receipt(b"a", size=1)
        receipt = log.prefix_search_receipt(b"a", 2, 5)
        self.assertTrue(verify_prefix_search_receipt(receipt))
        self.assertEqual(receipt.hits, (2, 4))

    def test_constructor_version_and_range(self):
        receipt = self.log.prefix_search_receipt(b"a")
        with self.assertRaises(ValueError):
            PrefixSearchReceipt(
                2,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.prefix,
                receipt.start,
                receipt.stop,
                receipt.items,
                receipt.proof,
            )
        with self.assertRaises(ValueError):
            PrefixSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.prefix,
                4,
                2,
                receipt.items,
                receipt.proof,
            )

    def test_constructor_type_errors(self):
        receipt = self.log.prefix_search_receipt(b"a")
        with self.assertRaises(TypeError):
            PrefixSearchReceipt(
                "1",
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.prefix,
                receipt.start,
                receipt.stop,
                receipt.items,
                receipt.proof,
            )
        with self.assertRaises(TypeError):
            PrefixSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                bytearray(receipt.root),
                receipt.prefix,
                receipt.start,
                receipt.stop,
                receipt.items,
                receipt.proof,
            )
        with self.assertRaises(TypeError):
            PrefixSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                1,
                receipt.start,
                receipt.stop,
                receipt.items,
                receipt.proof,
            )

    def test_failure_does_not_change_log(self):
        log = make_log()
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        for call in (
            lambda: log.prefix_search_receipt(1),
            lambda: log.prefix_search_receipt(b"a", 0, len(log) + 1),
            lambda: log.prefix_search_receipt(b"a", size=len(log) + 1),
        ):
            with self.assertRaises((TypeError, ValueError)):
                call()
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)


class PrefixSearchReceiptEncryptedTest(unittest.TestCase):
    def test_envelopes_participate_as_raw_bytes(self):
        log = AuditLog()
        key = b"k" * 32
        log.append(b"m")
        log.encrypt(b"m", key)
        log.encrypt(b"n", key)
        # Sealed envelopes start with the encryption magic b"auditchain/...",
        # so an envelope prefix query matches envelopes only; nothing is
        # decrypted.
        receipt = log.prefix_search_receipt(b"auditchain/")
        self.assertEqual(
            receipt.hits,
            tuple(
                i
                for i in range(3)
                if log.entry(i).payload.startswith(b"auditchain/")
            ),
        )
        self.assertEqual(receipt.hits, (1, 2))
        self.assertTrue(verify_prefix_search_receipt(receipt))
        wide = log.prefix_search_receipt(b"")
        self.assertEqual(wide.hits, (0, 1, 2))
        self.assertTrue(verify_prefix_search_receipt(wide))


class PrefixSearchReceiptReadOnlyTest(unittest.TestCase):
    def test_issuance_is_read_only(self):
        log = AuditLog(key=b"k" * 32)
        for record in ("a", "b", "a"):
            log.append(record)
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        full = log.full_search_receipt("a")
        find = log.find("a")
        ranged = log.range_search_receipt(b"a", b"b")
        log.prefix_search_receipt(b"a")
        log.prefix_search_receipt(b"z")
        with self.assertRaises(TypeError):
            log.prefix_search_receipt(1)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(log.full_search_receipt("a"), full)
        self.assertEqual(log.find("a"), find)
        self.assertEqual(log.range_search_receipt(b"a", b"b"), ranged)
        self.assertEqual(log.find_prefix(b"a"), (0, 2))


class VerifyPrefixSearchReceiptArgumentsTest(unittest.TestCase):
    def test_non_receipt_raises_type_error(self):
        for bad in (None, 1, b"bytes", "x", (), object()):
            with self.assertRaises(TypeError):
                verify_prefix_search_receipt(bad)


if __name__ == "__main__":
    unittest.main()
