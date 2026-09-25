import dataclasses
import unittest

from auditchain import (
    AuditLog,
    SearchReceipt,
    verify_search_receipt,
)

KEY = b"super-secret-key"


def replace_item(item, **changes):
    entry, proof = item
    return (dataclasses.replace(entry, **changes), proof)


class SearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a"):
            self.log.append(record)

    def test_fields(self):
        receipt = self.log.search_receipt("a")
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root(5))
        self.assertEqual(receipt.query, b"a")
        self.assertEqual((receipt.start, receipt.stop), (0, 5))
        self.assertEqual([entry.index for entry, _ in receipt.items], [0, 2, 4])

    def test_items_carry_entries_and_proofs(self):
        receipt = self.log.search_receipt("a", size=5)
        for entry, proof in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
            self.assertEqual(proof, self.log.inclusion_proof(entry.index, 5))

    def test_bytes_and_str_normalize_to_same_receipt(self):
        self.assertEqual(
            self.log.search_receipt("a"), self.log.search_receipt(b"a")
        )
        self.assertEqual(self.log.search_receipt("位置").query, "位置".encode("utf-8"))

    def test_duplicate_content_all_listed(self):
        receipt = self.log.search_receipt("a")
        self.assertEqual(len(receipt.items), 3)
        for entry, _ in receipt.items:
            self.assertEqual(entry.payload, b"a")

    def test_empty_result(self):
        receipt = self.log.search_receipt("missing")
        self.assertEqual(receipt.items, ())
        self.assertTrue(verify_search_receipt(receipt))

    def test_empty_payload_hits(self):
        self.log.append("")
        self.log.append(b"")
        receipt = self.log.search_receipt("")
        self.assertEqual([entry.index for entry, _ in receipt.items], [5, 6])
        self.assertTrue(verify_search_receipt(receipt))

    def test_unicode_hits(self):
        self.log.append("位置主张")
        self.log.append("位置主张")
        receipt = self.log.search_receipt("位置主张")
        self.assertEqual([entry.index for entry, _ in receipt.items], [5, 6])
        self.assertTrue(
            verify_search_receipt(self.log.search_receipt("位置主张".encode("utf-8")))
        )

    def test_range(self):
        receipt = self.log.search_receipt("a", 1, 4)
        self.assertEqual((receipt.start, receipt.stop), (1, 4))
        self.assertEqual([entry.index for entry, _ in receipt.items], [2])
        self.assertTrue(verify_search_receipt(receipt))
        self.assertEqual(
            [entry.index for entry, _ in self.log.search_receipt("a", 2, 5).items],
            [2, 4],
        )
        self.assertEqual(
            [entry.index for entry, _ in self.log.search_receipt("a", None, 2).items],
            [0],
        )
        self.assertEqual(
            [entry.index for entry, _ in self.log.search_receipt("a", 4).items],
            [4],
        )

    def test_empty_range_has_no_hits(self):
        receipt = self.log.search_receipt("a", 2, 2)
        self.assertEqual(receipt.items, ())
        self.assertTrue(verify_search_receipt(receipt))

    def test_explicit_size(self):
        receipt = self.log.search_receipt("a", size=3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual((receipt.start, receipt.stop), (0, 3))
        self.assertEqual([entry.index for entry, _ in receipt.items], [0, 2])
        self.assertTrue(verify_search_receipt(receipt))

    def test_frozen_and_all_fields_equal(self):
        receipt = self.log.search_receipt("a")
        with self.assertRaises(Exception):
            receipt.size = 4  # type: ignore[misc]
        same = self.log.search_receipt("a")
        self.assertEqual(receipt, same)
        self.assertEqual(
            receipt,
            SearchReceipt(
                1,
                "sha256",
                receipt.size,
                receipt.root,
                receipt.query,
                receipt.start,
                receipt.stop,
                receipt.items,
            ),
        )
        self.assertNotEqual(receipt, self.log.search_receipt("b"))

    def test_positional_construction(self):
        receipt = self.log.search_receipt("b")
        rebuilt = SearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.query,
            receipt.start,
            receipt.stop,
            receipt.items,
        )
        self.assertEqual(rebuilt, receipt)
        self.assertTrue(verify_search_receipt(rebuilt))

    def test_query_type_errors(self):
        for bad in (123, None, bytearray(b"a"), memoryview(b"a"), ["a"]):
            with self.assertRaises(TypeError):
                self.log.search_receipt(bad)

    def test_bound_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.search_receipt("a", bad)
            with self.assertRaises(TypeError):
                self.log.search_receipt("a", 0, bad)

    def test_size_type_error(self):
        with self.assertRaises(TypeError):
            self.log.search_receipt("a", size="3")
        with self.assertRaises(TypeError):
            self.log.search_receipt("a", size=True)

    def test_bound_range_errors(self):
        with self.assertRaises(ValueError):
            self.log.search_receipt("a", -1)
        with self.assertRaises(ValueError):
            self.log.search_receipt("a", 0, 6)
        with self.assertRaises(ValueError):
            self.log.search_receipt("a", 3, 2)
        with self.assertRaises(ValueError):
            self.log.search_receipt("a", 6)

    def test_size_range_errors(self):
        with self.assertRaises(ValueError):
            self.log.search_receipt("a", size=-1)
        with self.assertRaises(ValueError):
            self.log.search_receipt("a", size=6)

    def test_read_only(self):
        log = AuditLog(key=KEY)
        for record in ("a", "b", "a"):
            log.append(record)
        verifier = log.export_verifier()
        from auditchain import verify_auth

        tag = log.auth(0)
        head = log.head
        root = log.merkle_root()
        proof = log.inclusion_proof(1)
        entries = log.entries()
        stage = log.stage
        tags = dict(log._tags)

        self.assertTrue(verify_search_receipt(log.search_receipt("a")))
        self.assertTrue(verify_search_receipt(log.search_receipt("missing")))

        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.inclusion_proof(1), proof)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(log.stage, stage)
        self.assertEqual(log._tags, tags)
        self.assertTrue(log.verify())
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))


class SearchReceiptPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a", "b"):
            self.log.append(record)

    def test_default_range_is_retained_segment(self):
        self.log.prune(2, self.log.seal(2))
        receipt = self.log.search_receipt("a")
        self.assertEqual((receipt.start, receipt.stop), (2, 6))
        self.assertEqual([entry.index for entry, _ in receipt.items], [2, 4])
        self.assertTrue(verify_search_receipt(receipt))

    def test_released_prefix_range_rejected(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(ValueError):
            self.log.search_receipt("a", 0, 4)
        with self.assertRaises(ValueError):
            self.log.search_receipt("a", 0)
        receipt = self.log.search_receipt("a", 2, 4)
        self.assertEqual([entry.index for entry, _ in receipt.items], [2])
        self.assertTrue(verify_search_receipt(receipt))

    def test_pruned_snapshot_not_rebuildable(self):
        self.log.prune(3, self.log.seal(3))
        with self.assertRaises(ValueError):
            self.log.search_receipt("a", size=1)

    def test_empty_snapshot_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        receipt = self.log.search_receipt("a", size=0)
        self.assertEqual((receipt.size, receipt.start, receipt.stop), (0, 0, 0))
        self.assertEqual(receipt.items, ())
        self.assertTrue(verify_search_receipt(receipt))

    def test_append_after_prune_indexed(self):
        self.log.prune(4, self.log.seal(4))
        self.log.append("a")
        receipt = self.log.search_receipt("a")
        self.assertEqual([entry.index for entry, _ in receipt.items], [4, 6])


class SearchReceiptEmptySnapshotTest(unittest.TestCase):
    def test_empty_log(self):
        receipt = AuditLog().search_receipt("x")
        self.assertEqual((receipt.size, receipt.start, receipt.stop), (0, 0, 0))
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.root, AuditLog().merkle_root(0))
        self.assertTrue(verify_search_receipt(receipt))

    def test_explicit_zero_on_non_empty_log(self):
        log = AuditLog()
        log.append("x")
        receipt = log.search_receipt("x", 0, 0, 0)
        self.assertEqual(receipt.items, ())
        self.assertTrue(verify_search_receipt(receipt))
        with self.assertRaises(ValueError):
            log.search_receipt("x", 0, 1, 0)

    def test_empty_snapshot_bounds_must_be_zero(self):
        log = AuditLog()
        with self.assertRaises(ValueError):
            log.search_receipt("x", 1, 1, 0)
        with self.assertRaises(TypeError):
            log.search_receipt("x", "0", 0, 0)


class SearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a"):
            self.log.append(record)
        self.receipt = self.log.search_receipt("a")

    def test_issued_receipt_verifies(self):
        self.assertTrue(verify_search_receipt(self.receipt))

    def test_non_receipt_type_error(self):
        for bad in (None, 1, "a", b"a", (), [], object()):
            with self.assertRaises(TypeError):
                verify_search_receipt(bad)

    def test_bypassed_bad_fields_still_raise(self):
        # A SearchReceipt whose frozen constructor was bypassed must be
        # re-validated by the verifier instead of failing incidentally.
        forged = SearchReceipt.__new__(SearchReceipt)
        good = self.receipt
        for name, value, error in (
            ("version", "1", TypeError),
            ("version", 2, ValueError),
            ("hash_name", 256, TypeError),
            ("hash_name", "nope", ValueError),
            ("size", "5", TypeError),
            ("root", "00" * 32, TypeError),
            ("root", bytes(31), ValueError),
            ("query", "a", TypeError),
            ("start", "0", TypeError),
            ("stop", 6, ValueError),
            ("items", [], TypeError),
        ):
            object.__setattr__(forged, "version", good.version)
            object.__setattr__(forged, "hash_name", good.hash_name)
            object.__setattr__(forged, "size", good.size)
            object.__setattr__(forged, "root", good.root)
            object.__setattr__(forged, "query", good.query)
            object.__setattr__(forged, "start", good.start)
            object.__setattr__(forged, "stop", good.stop)
            object.__setattr__(forged, "items", good.items)
            object.__setattr__(forged, name, value)
            with self.assertRaises(error):
                verify_search_receipt(forged)

    def test_tampered_payload_returns_false(self):
        tampered = SearchReceipt(
            1,
            self.receipt.hash_name,
            self.receipt.size,
            self.receipt.root,
            b"a",
            self.receipt.start,
            self.receipt.stop,
            tuple(replace_item(item, payload=b"z") for item in self.receipt.items),
        )
        self.assertFalse(verify_search_receipt(tampered))

    def test_tampered_entry_hash_returns_false(self):
        entry, proof = self.receipt.items[0]
        bad_hash = bytes(31) + b"\x01" if entry.entry_hash != bytes(31) + b"\x01" else bytes(31) + b"\x02"
        tampered = SearchReceipt(
            1,
            self.receipt.hash_name,
            self.receipt.size,
            self.receipt.root,
            b"a",
            self.receipt.start,
            self.receipt.stop,
            ((dataclasses.replace(entry, entry_hash=bad_hash), proof),)
            + self.receipt.items[1:],
        )
        self.assertFalse(verify_search_receipt(tampered))

    def test_wrong_query_returns_false(self):
        tampered = SearchReceipt(
            1,
            self.receipt.hash_name,
            self.receipt.size,
            self.receipt.root,
            b"b",
            self.receipt.start,
            self.receipt.stop,
            self.receipt.items,
        )
        self.assertFalse(verify_search_receipt(tampered))

    def test_wrong_root_returns_false(self):
        root = self.receipt.root
        other = bytes(31) + (b"\x01" if root[-1] != 1 else b"\x02")
        tampered = SearchReceipt(
            1,
            self.receipt.hash_name,
            self.receipt.size,
            root[:-1] + other[-1:],
            self.receipt.query,
            self.receipt.start,
            self.receipt.stop,
            self.receipt.items,
        )
        self.assertFalse(verify_search_receipt(tampered))

    def test_tampered_proof_returns_false(self):
        entry, proof = self.receipt.items[0]
        node = proof[0]
        other = bytes(31) + (b"\x01" if node[-1] != 1 else b"\x02")
        bad_proof = (node[:-1] + other[-1:],) + proof[1:]
        tampered = SearchReceipt(
            1,
            self.receipt.hash_name,
            self.receipt.size,
            self.receipt.root,
            self.receipt.query,
            self.receipt.start,
            self.receipt.stop,
            ((entry, bad_proof),) + self.receipt.items[1:],
        )
        self.assertFalse(verify_search_receipt(tampered))

    def test_omitting_hits_still_verifies(self):
        # Verification judges listed hits only, never result completeness.
        partial = tuple(item for item in self.receipt.items if item[0].index != 2)
        receipt = SearchReceipt(
            1,
            self.receipt.hash_name,
            self.receipt.size,
            self.receipt.root,
            self.receipt.query,
            self.receipt.start,
            self.receipt.stop,
            partial,
        )
        self.assertTrue(verify_search_receipt(receipt))

    def test_non_hit_payload_listed_returns_false(self):
        b_entry = self.log.entry(1)
        proof = self.log.inclusion_proof(1, 5)
        receipt = SearchReceipt(
            1,
            "sha256",
            5,
            self.log.merkle_root(5),
            b"a",
            0,
            5,
            ((b_entry, proof),),
        )
        self.assertFalse(verify_search_receipt(receipt))

    def test_index_outside_range_raises_value_error(self):
        entry, proof = self.receipt.items[0]
        with self.assertRaises(ValueError):
            SearchReceipt(
                1,
                "sha256",
                5,
                self.receipt.root,
                b"a",
                1,
                5,
                ((entry, proof),),
            )

    def test_non_ascending_indices_raise_value_error(self):
        reordered = (self.receipt.items[2],) + self.receipt.items[:2]
        with self.assertRaises(ValueError):
            SearchReceipt(
                1,
                "sha256",
                5,
                self.receipt.root,
                b"a",
                0,
                5,
                reordered,
            )

    def test_duplicate_indices_raise_value_error(self):
        entry, proof = self.receipt.items[0]
        with self.assertRaises(ValueError):
            SearchReceipt(
                1,
                "sha256",
                5,
                self.receipt.root,
                b"a",
                0,
                5,
                ((entry, proof), (entry, proof)),
            )

    def test_constructor_type_errors(self):
        fields = dict(
            version=1,
            hash_name="sha256",
            size=5,
            root=self.receipt.root,
            query=b"a",
            start=0,
            stop=5,
            items=((self.log.entry(0), self.log.inclusion_proof(0, 5)),),
        )
        for name, bad in {
            "version": "1",
            "hash_name": 256,
            "size": "5",
            "root": "00" * 32,
            "query": "a",
            "start": "0",
            "stop": "5",
            "items": [],
        }.items():
            kwargs = dict(fields)
            kwargs[name] = bad
            with self.assertRaises(TypeError):
                SearchReceipt(**kwargs)

    def test_constructor_value_errors(self):
        entry = self.log.entry(0)
        proof = self.log.inclusion_proof(0, 5)
        good_items = ((entry, proof),)
        with self.assertRaises(ValueError):
            SearchReceipt(2, "sha256", 5, self.receipt.root, b"a", 0, 5, good_items)
        with self.assertRaises(ValueError):
            SearchReceipt(1, "nope", 5, self.receipt.root, b"a", 0, 5, good_items)
        with self.assertRaises(ValueError):
            SearchReceipt(1, "sha256", -1, self.receipt.root, b"a", 0, 0, ())
        with self.assertRaises(ValueError):
            SearchReceipt(1, "sha256", 5, bytes(31), b"a", 0, 5, good_items)
        with self.assertRaises(ValueError):
            SearchReceipt(1, "sha256", 5, self.receipt.root, b"a", 4, 2, ())
        with self.assertRaises(ValueError):
            SearchReceipt(1, "sha256", 5, self.receipt.root, b"a", 0, 6, ())
        with self.assertRaises(ValueError):
            SearchReceipt(1, "sha256", 0, self.log.merkle_root(0), b"a", 0, 0, good_items)


class SearchReceiptAlternateHashTest(unittest.TestCase):
    def test_sha3_issue_and_verify(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "a"):
            log.append(record)
        receipt = log.search_receipt("a")
        self.assertEqual(receipt.hash_name, "sha3-256")
        self.assertEqual([entry.index for entry, _ in receipt.items], [0, 2])
        self.assertTrue(verify_search_receipt(receipt))
        log.prune(1, log.seal(1))
        receipt = log.search_receipt("a")
        self.assertEqual([entry.index for entry, _ in receipt.items], [2])
        self.assertTrue(verify_search_receipt(receipt))


if __name__ == "__main__":
    unittest.main()
