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
            (b"", None, None),
            (b"b", None, None),
            (b"a\x00", None, None),
            (b"az", None, None),
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

    def test_empty_prefix_covers_and_hits_everything(self):
        receipt = self.log.prefix_search_receipt(b"")
        self.assertEqual(len(receipt.items), len(self.log))
        self.assertEqual(receipt.hits, tuple(range(len(self.log))))
        self.assertTrue(verify_prefix_search_receipt(receipt))

    def test_no_hit_prefix_keeps_full_coverage(self):
        receipt = self.log.prefix_search_receipt(b"zz")
        self.assertEqual(len(receipt.items), len(self.log))
        self.assertEqual(receipt.hits, ())
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
        # Entries 2..5 are aa, c, az, b; the a-prefix hits are 2 and 4.
        self.assertEqual(receipt.hits, (2, 4))

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

    def test_deleting_a_non_hit_breaks_coverage_too(self):
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

    def test_duplicate_and_reordered_indices_rejected(self):
        receipt = self.log.prefix_search_receipt(b"a", 0, 3)
        duplicated = receipt.items + (receipt.items[-1],)
        with self.assertRaises(ValueError):
            PrefixSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.prefix,
                receipt.start,
                receipt.stop,
                duplicated,
                receipt.proof,
            )
        reordered = (receipt.items[1], receipt.items[0]) + receipt.items[2:]
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
        # Rewrite every payload so it no longer starts with the prefix; the
        # recorded entry digests no longer recompute, so verify returns False.
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

    def test_tampered_proof_returns_false(self):
        # A partial range carries a non-empty shared batch proof.
        receipt = self.log.prefix_search_receipt(b"a", 1, 6)
        flipped = bytearray(receipt.proof[0])
        flipped[0] ^= 0xFF
        forged_proof = (bytes(flipped),) + receipt.proof[1:]
        forged = PrefixSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.prefix,
            receipt.start,
            receipt.stop,
            receipt.items,
            forged_proof,
        )
        self.assertFalse(verify_prefix_search_receipt(forged))

    def test_changing_prefix_only_reclassifies_authenticated_entries(self):
        # The hit set comes from the authenticated entries; changing the
        # prefix only re-classifies the same payloads and cannot conjure an
        # entry the receipt does not carry.
        receipt = self.log.prefix_search_receipt(b"a", 0, 3)
        widened = PrefixSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            b"",
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
        )
        self.assertEqual(widened.hits, (0, 1, 2))
        self.assertTrue(verify_prefix_search_receipt(widened))


class PrefixSearchReceiptEncryptedTest(unittest.TestCase):
    def test_encrypted_entries_compare_sealed_envelopes(self):
        log = AuditLog()
        key = b"k" * 32
        log.encrypt(b"apple", key)
        log.append(b"apple")
        receipt = log.prefix_search_receipt(b"auditchain/encrypted-entry")
        self.assertEqual(receipt.hits, (0,))
        self.assertEqual(
            receipt.hits,
            log.find_prefix(b"auditchain/encrypted-entry"),
        )
        self.assertTrue(verify_prefix_search_receipt(receipt))


class PrefixSearchReceiptEmptyTest(unittest.TestCase):
    def test_empty_log(self):
        log = AuditLog()
        receipt = log.prefix_search_receipt(b"a")
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertEqual(receipt.size, 0)
        self.assertTrue(verify_prefix_search_receipt(receipt))

    def test_empty_prefix_empty_log(self):
        receipt = AuditLog().prefix_search_receipt(b"")
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_prefix_search_receipt(receipt))

    def test_empty_index_range_of_non_empty_snapshot(self):
        log = make_log()
        receipt = log.prefix_search_receipt(b"a", 3, 3)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        # An empty range of a non-empty snapshot attests no content.
        self.assertTrue(verify_prefix_search_receipt(receipt))


class PrefixSearchReceiptErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_prefix_type_errors(self):
        for bad in (None, 1, bytearray(b"a"), memoryview(b"a"), ["a"]):
            with self.assertRaises(TypeError):
                self.log.prefix_search_receipt(bad)

    def test_range_type_and_value_errors_follow_full_search(self):
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
        with self.assertRaises(ValueError):
            self.log.prefix_search_receipt(b"a", size=len(self.log) + 1)

    def test_size_type_error(self):
        with self.assertRaises(TypeError):
            self.log.prefix_search_receipt(b"a", size=True)

    def test_pruned_snapshot_and_range(self):
        log = make_log()
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            log.prefix_search_receipt(b"a", 0, 4)
        with self.assertRaises(ValueError):
            log.prefix_search_receipt(b"a", size=1)
        receipt = log.prefix_search_receipt(b"a", 2, 5)
        self.assertTrue(verify_prefix_search_receipt(receipt))
        self.assertEqual(receipt.hits, (2, 4))

    def test_failure_does_not_change_the_log(self):
        log = make_log()
        entries = log.entries()
        head = log.head
        root = log.merkle_root()
        with self.assertRaises(TypeError):
            log.prefix_search_receipt(123)
        with self.assertRaises(ValueError):
            log.prefix_search_receipt(b"a", 0, len(log) + 1)
        with self.assertRaises(ValueError):
            log.prefix_search_receipt(b"a", size=len(log) + 1)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertTrue(log.verify())

    def test_constructor_version_errors(self):
        receipt = self.log.prefix_search_receipt(b"a")
        kwargs = dict(
            hash_name=receipt.hash_name,
            size=receipt.size,
            root=receipt.root,
            prefix=receipt.prefix,
            start=receipt.start,
            stop=receipt.stop,
            items=receipt.items,
            proof=receipt.proof,
        )
        with self.assertRaises(TypeError):
            PrefixSearchReceipt("1", **kwargs)
        with self.assertRaises(TypeError):
            PrefixSearchReceipt(True, **kwargs)
        with self.assertRaises(ValueError):
            PrefixSearchReceipt(2, **kwargs)

    def test_constructor_field_type_errors(self):
        receipt = self.log.prefix_search_receipt(b"a", 0, 2)
        base = (
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.prefix,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
        )
        # size wrong type / negative
        with self.assertRaises(TypeError):
            PrefixSearchReceipt(*base[:2], "2", *base[3:])
        with self.assertRaises(ValueError):
            PrefixSearchReceipt(*base[:2], -1, *base[3:])
        # root / prefix wrong types
        with self.assertRaises(TypeError):
            PrefixSearchReceipt(*base[:3], "x", *base[4:])
        with self.assertRaises(TypeError):
            PrefixSearchReceipt(*base[:4], 1, *base[5:])
        # bound wrong type and out of range
        with self.assertRaises(TypeError):
            PrefixSearchReceipt(*base[:5], True, *base[6:])
        with self.assertRaises(ValueError):
            PrefixSearchReceipt(*base[:5], 3, 2, *base[7:])
        with self.assertRaises(ValueError):
            PrefixSearchReceipt(*base[:6], receipt.size + 1, *base[7:])
        # items / proof wrong shape
        with self.assertRaises(TypeError):
            PrefixSearchReceipt(*base[:7], [receipt.items[0]], *base[8:])
        with self.assertRaises(TypeError):
            PrefixSearchReceipt(*base[:8], [1, 2])

    def test_verify_non_receipt_raises_type_error(self):
        for bad in (None, 1, b"bytes", object(), ()):
            with self.assertRaises(TypeError):
                verify_prefix_search_receipt(bad)


if __name__ == "__main__":
    unittest.main()
