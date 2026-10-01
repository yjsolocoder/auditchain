import unittest

from auditchain import (
    AuditLog,
    RangeSearchReceipt,
    verify_range_search_receipt,
)


def make_log(records=("a", "b", "aa", "c", "az", "b", b"a\x00")):
    log = AuditLog()
    for record in records:
        log.append(record)
    return log


class RangeSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_receipt_carries_snapshot_context(self):
        receipt = self.log.range_search_receipt(b"a", b"b")
        self.assertIsInstance(receipt, RangeSearchReceipt)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, len(self.log))
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.left, b"a")
        self.assertEqual(receipt.right, b"b")
        self.assertEqual(receipt.start, 0)
        self.assertEqual(receipt.stop, len(self.log))

    def test_str_bounds_are_utf8_normalized(self):
        self.assertEqual(
            self.log.range_search_receipt("a", "b"),
            self.log.range_search_receipt(b"a", b"b"),
        )

    def test_items_cover_every_entry_of_the_range(self):
        receipt = self.log.range_search_receipt(b"a", b"c", 1, 5)
        self.assertEqual(
            [entry.index for entry in receipt.items], [1, 2, 3, 4]
        )
        self.assertEqual(receipt.start, 1)
        self.assertEqual(receipt.stop, 5)

    def test_hits_match_find_range_over_authenticated_entries(self):
        for left, right, start, stop in (
            (b"a", b"b", None, None),
            (b"a", b"c", 1, 5),
            (b"", b"z", None, None),
            (b"b", b"c", None, None),
            (b"a\x00", b"az", None, None),
        ):
            receipt = self.log.range_search_receipt(left, right, start, stop)
            expected = tuple(
                entry.index
                for entry in receipt.items
                if left <= entry.payload < right
            )
            self.assertEqual(receipt.hits, expected)
            self.assertEqual(receipt.hits, self.log.find_range(left, right, start, stop))

    def test_equal_bounds_yield_no_hits_but_full_coverage(self):
        receipt = self.log.range_search_receipt(b"a", b"a")
        self.assertEqual(len(receipt.items), len(self.log))
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_range_search_receipt(receipt))

    def test_explicit_size(self):
        receipt = self.log.range_search_receipt(b"a", b"c", 0, 3, size=3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual([entry.index for entry in receipt.items], [0, 1, 2])
        self.assertEqual(receipt.hits, (0, 1, 2))
        self.assertTrue(verify_range_search_receipt(receipt))


class RangeSearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_genuine_receipt_verifies_offline(self):
        receipt = self.log.range_search_receipt(b"a", b"b")
        self.assertTrue(verify_range_search_receipt(receipt))

    def test_partial_range_verifies(self):
        receipt = self.log.range_search_receipt(b"a", b"c", 2, 6, size=7)
        self.assertTrue(verify_range_search_receipt(receipt))
        self.assertEqual(receipt.hits, (2, 4, 5))

    def test_deleting_a_hit_cannot_pass(self):
        receipt = self.log.range_search_receipt(b"a", b"c")
        hit_indices = set(receipt.hits)
        thinned = tuple(
            entry for entry in receipt.items if entry.index not in hit_indices
        )
        # Coverage is a structural error: the constructor rejects it.
        with self.assertRaises(ValueError):
            RangeSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.left,
                receipt.right,
                receipt.start,
                receipt.stop,
                thinned,
                receipt.proof,
            )

    def test_deleting_an_out_of_range_entry_breaks_coverage_too(self):
        receipt = self.log.range_search_receipt(b"a", b"c")
        # Index 1 (payload b"b") is not a hit; dropping it must still fail.
        thinned = tuple(
            entry for entry in receipt.items if entry.index != 1
        )
        with self.assertRaises(ValueError):
            RangeSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.left,
                receipt.right,
                receipt.start,
                receipt.stop,
                thinned,
                receipt.proof,
            )

    def test_forging_empty_hits_by_mutating_payload_fails(self):
        receipt = self.log.range_search_receipt(b"a", b"b")
        self.assertTrue(receipt.hits)
        # Rewrite every payload to lie outside [left, right); the recorded
        # entry digests no longer recompute, so verification returns False.
        forged_items = tuple(
            type(entry)(entry.index, b"zz", entry.previous_hash, entry.entry_hash)
            for entry in receipt.items
        )
        forged = RangeSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.left,
            receipt.right,
            receipt.start,
            receipt.stop,
            forged_items,
            receipt.proof,
        )
        self.assertEqual(forged.hits, ())
        self.assertFalse(verify_range_search_receipt(forged))

    def test_tampered_root_returns_false(self):
        receipt = self.log.range_search_receipt(b"a", b"b")
        forged = RangeSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            bytes(32),
            receipt.left,
            receipt.right,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
        )
        self.assertFalse(verify_range_search_receipt(forged))

    def test_widening_bounds_does_not_fabricate_hits(self):
        # The hit set comes from the authenticated entries; widening the
        # interval only re-classifies the same payloads and cannot conjure an
        # entry the receipt does not carry.
        receipt = self.log.range_search_receipt(b"a", b"b", 0, 3)
        widened = RangeSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            b"",
            b"zz",
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
        )
        self.assertEqual(widened.hits, (0, 1, 2))
        self.assertTrue(verify_range_search_receipt(widened))


class RangeSearchReceiptEmptyTest(unittest.TestCase):
    def test_empty_log(self):
        log = AuditLog()
        receipt = log.range_search_receipt(b"a", b"c")
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertEqual(receipt.size, 0)
        self.assertTrue(verify_range_search_receipt(receipt))

    def test_empty_index_range_of_non_empty_snapshot(self):
        log = make_log()
        receipt = log.range_search_receipt(b"a", b"c", 3, 3)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        # An empty range of a non-empty snapshot attests no content.
        self.assertTrue(verify_range_search_receipt(receipt))

    def test_full_range_without_any_hit(self):
        log = make_log()
        receipt = log.range_search_receipt(b"x", b"z")
        self.assertTrue(receipt.items)
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_range_search_receipt(receipt))


class RangeSearchReceiptErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_left_greater_than_right_raises(self):
        with self.assertRaises(ValueError):
            self.log.range_search_receipt(b"b", b"a")

    def test_bound_type_errors(self):
        for bad in (None, 1, bytearray(b"a"), memoryview(b"a"), ["a"]):
            with self.assertRaises(TypeError):
                self.log.range_search_receipt(bad, b"z")
            with self.assertRaises(TypeError):
                self.log.range_search_receipt(b"a", bad)

    def test_range_type_and_value_errors_follow_full_search(self):
        with self.assertRaises(TypeError):
            self.log.range_search_receipt(b"a", b"c", True)
        with self.assertRaises(TypeError):
            self.log.range_search_receipt(b"a", b"c", 0, "2")
        with self.assertRaises(ValueError):
            self.log.range_search_receipt(b"a", b"c", -1)
        with self.assertRaises(ValueError):
            self.log.range_search_receipt(b"a", b"c", 0, len(self.log) + 1)
        with self.assertRaises(ValueError):
            self.log.range_search_receipt(b"a", b"c", 4, 2)
        with self.assertRaises(ValueError):
            self.log.range_search_receipt(b"a", b"c", size=len(self.log) + 1)

    def test_pruned_snapshot_and_range(self):
        log = make_log()
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            log.range_search_receipt(b"a", b"c", 0, 4)
        receipt = log.range_search_receipt(b"a", b"c", 2, 5)
        self.assertTrue(verify_range_search_receipt(receipt))
        self.assertEqual(receipt.hits, (2, 4))

    def test_constructor_inverted_bounds(self):
        receipt = self.log.range_search_receipt(b"a", b"c")
        with self.assertRaises(ValueError):
            RangeSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                b"z",
                b"a",
                receipt.start,
                receipt.stop,
                receipt.items,
                receipt.proof,
            )


class RangeSearchReceiptEncryptedTest(unittest.TestCase):
    def test_envelopes_participate_as_raw_bytes(self):
        log = AuditLog()
        key = b"k" * 32
        log.append(b"m")
        log.encrypt(b"m", key)
        log.encrypt(b"n", key)
        receipt = log.range_search_receipt(b"m", b"n")
        # Only the plain b"m" entry compares; the sealed envelopes are not
        # plaintext and nothing is decrypted.
        self.assertEqual(receipt.hits, (0,))
        self.assertTrue(verify_range_search_receipt(receipt))
        # A wide interval carries every envelope as a hit on raw bytes.
        wide = log.range_search_receipt(b"", b"\xff")
        self.assertEqual(
            wide.hits,
            tuple(i for i in range(3) if b"" <= log.entry(i).payload < b"\xff"),
        )
        self.assertTrue(verify_range_search_receipt(wide))


class RangeSearchReceiptReadOnlyTest(unittest.TestCase):
    def test_issuance_is_read_only(self):
        log = AuditLog(key=b"k" * 32)
        for record in ("a", "b", "a"):
            log.append(record)
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        full = log.full_search_receipt("a")
        find = log.find("a")
        log.range_search_receipt(b"a", b"b")
        log.range_search_receipt(b"z", b"zz")
        with self.assertRaises(ValueError):
            log.range_search_receipt(b"b", b"a")
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(log.full_search_receipt("a"), full)
        self.assertEqual(log.find("a"), find)


if __name__ == "__main__":
    unittest.main()
