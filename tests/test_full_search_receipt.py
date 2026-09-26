import unittest

from auditchain import (
    AuditLog,
    Entry,
    FullSearchReceipt,
    verify_full_search_receipt,
)

KEY = b"super-secret-key"


def make_log(records=("a", "b", "a", "c", "a"), **kwargs):
    log = AuditLog(**kwargs)
    for record in records:
        log.append(record)
    return log


class FullSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_fields_and_full_range_items(self):
        receipt = self.log.full_search_receipt("a")
        self.assertIsInstance(receipt, FullSearchReceipt)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.query, b"a")
        self.assertEqual((receipt.start, receipt.stop), (0, 5))
        # Every entry of the range is listed, one per absolute index.
        self.assertEqual([entry.index for entry in receipt.items], [0, 1, 2, 3, 4])
        for entry in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
        # The shared proof covers the whole selection at once.
        self.assertEqual(
            receipt.proof,
            self.log.batch_inclusion_proof((0, 1, 2, 3, 4), 5)[1],
        )

    def test_hits_are_derived_by_the_verifier(self):
        receipt = self.log.full_search_receipt("a")
        hits = [e.index for e in receipt.items if e.payload == receipt.query]
        self.assertEqual(hits, [0, 2, 4])
        self.assertEqual(hits, list(self.log.find("a")))

    def test_str_query_normalized_to_bytes(self):
        receipt = self.log.full_search_receipt("位置")
        self.assertEqual(receipt.query, "位置".encode("utf-8"))
        self.log.append("位置")
        receipt = self.log.full_search_receipt("位置")
        self.assertEqual(
            receipt, self.log.full_search_receipt("位置".encode("utf-8"))
        )
        self.assertEqual(receipt.items[-1].payload, "位置".encode("utf-8"))

    def test_bytes_and_str_queries_are_equivalent(self):
        self.assertEqual(
            self.log.full_search_receipt(b"a"), self.log.full_search_receipt("a")
        )

    def test_empty_query(self):
        log = make_log(("", "x", ""))
        receipt = log.full_search_receipt("")
        self.assertEqual(receipt.query, b"")
        self.assertEqual([e.index for e in receipt.items], [0, 1, 2])
        self.assertTrue(verify_full_search_receipt(receipt))

    def test_no_match_still_lists_the_whole_range(self):
        receipt = self.log.full_search_receipt("missing")
        self.assertEqual([e.index for e in receipt.items], [0, 1, 2, 3, 4])
        self.assertTrue(verify_full_search_receipt(receipt))

    def test_empty_range_and_empty_snapshot(self):
        receipt = self.log.full_search_receipt("a", 2, 2)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertTrue(verify_full_search_receipt(receipt))
        snapshot = AuditLog().full_search_receipt("a")
        self.assertEqual(snapshot.size, 0)
        self.assertEqual((snapshot.start, snapshot.stop), (0, 0))
        self.assertEqual(snapshot.items, ())
        self.assertEqual(snapshot.proof, ())
        self.assertTrue(verify_full_search_receipt(snapshot))

    def test_explicit_half_open_range(self):
        receipt = self.log.full_search_receipt("a", 1, 4)
        self.assertEqual((receipt.start, receipt.stop), (1, 4))
        self.assertEqual([e.index for e in receipt.items], [1, 2, 3])
        self.assertTrue(verify_full_search_receipt(receipt))
        self.assertEqual(
            [e.index for e in self.log.full_search_receipt("a", None, 2).items],
            [0, 1],
        )
        self.assertEqual(
            [e.index for e in self.log.full_search_receipt("a", 4).items], [4]
        )

    def test_explicit_snapshot_size(self):
        receipt = self.log.full_search_receipt("a", size=3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual((receipt.start, receipt.stop), (0, 3))
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual([e.index for e in receipt.items], [0, 1, 2])
        self.assertTrue(verify_full_search_receipt(receipt))

    def test_range_limited_to_snapshot(self):
        with self.assertRaises(ValueError):
            self.log.full_search_receipt("a", 0, 4, size=3)
        receipt = self.log.full_search_receipt("a", 0, 3, size=3)
        self.assertEqual([e.index for e in receipt.items], [0, 1, 2])

    def test_query_type_errors(self):
        for bad in (bytearray(b"a"), memoryview(b"a"), 123, None, ["a"]):
            with self.assertRaises(TypeError):
                self.log.full_search_receipt(bad)

    def test_bound_and_size_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.full_search_receipt("a", bad)
            with self.assertRaises(TypeError):
                self.log.full_search_receipt("a", 0, bad)
            with self.assertRaises(TypeError):
                self.log.full_search_receipt("a", size=bad)

    def test_bound_and_size_range_errors(self):
        for args in ((-1, None, None), (0, 6, None), (3, 2, None), (6, None, None)):
            start, stop, size = args
            with self.assertRaises(ValueError):
                self.log.full_search_receipt("a", start, stop, size=size)
        with self.assertRaises(ValueError):
            self.log.full_search_receipt("a", size=-1)
        with self.assertRaises(ValueError):
            self.log.full_search_receipt("a", size=6)
        # Boundary values themselves are accepted.
        self.assertTrue(
            verify_full_search_receipt(self.log.full_search_receipt("a", 0, 5, size=5))
        )

    def test_issue_is_read_only_and_repeatable(self):
        log = make_log(("a", "b", "a"), key=KEY)
        verifier = log.export_verifier()
        tag = log.auth(0)
        head = log.head
        root = log.merkle_root()
        stage = log.stage
        tags = dict(log._tags)
        first = log.full_search_receipt("a")
        second = log.full_search_receipt("a")
        self.assertEqual(first, second)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.stage, stage)
        self.assertEqual(log._tags, tags)
        self.assertTrue(log.verify())
        from auditchain import verify_auth

        self.assertTrue(verify_auth(log.entry(0), tag, verifier))
        self.assertTrue(verify_full_search_receipt(first))


class FullSearchReceiptPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(("a", "b", "a", "c", "a", "b"))

    def test_default_range_is_retained_segment(self):
        self.log.prune(2, self.log.seal(2))
        receipt = self.log.full_search_receipt("a")
        self.assertEqual((receipt.start, receipt.stop), (2, 6))
        self.assertEqual([e.index for e in receipt.items], [2, 3, 4, 5])
        self.assertTrue(verify_full_search_receipt(receipt))

    def test_explicit_range_may_not_reach_released_prefix(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(ValueError):
            self.log.full_search_receipt("a", 0, 4)
        receipt = self.log.full_search_receipt("a", 2, 4)
        self.assertEqual([e.index for e in receipt.items], [2, 3])
        self.assertTrue(verify_full_search_receipt(receipt))

    def test_pruned_snapshot_is_not_rebuildable(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(ValueError):
            self.log.full_search_receipt("a", size=1)
        # The retained suffix snapshot still works.
        receipt = self.log.full_search_receipt("b", size=6)
        self.assertEqual([e.index for e in receipt.items], [2, 3, 4, 5])
        self.assertTrue(verify_full_search_receipt(receipt))

    def test_prune_all_then_search(self):
        self.log.prune(6, self.log.seal(6))
        receipt = self.log.full_search_receipt("a")
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual((receipt.start, receipt.stop), (6, 6))
        self.assertTrue(verify_full_search_receipt(receipt))


class FullSearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.full_search_receipt("a")

    def rebuild(self, **overrides):
        fields = dict(
            version=self.receipt.version,
            hash_name=self.receipt.hash_name,
            size=self.receipt.size,
            root=self.receipt.root,
            query=self.receipt.query,
            start=self.receipt.start,
            stop=self.receipt.stop,
            items=self.receipt.items,
            proof=self.receipt.proof,
        )
        fields.update(overrides)
        return FullSearchReceipt(**fields)

    def test_genuine_receipt_verifies(self):
        self.assertTrue(verify_full_search_receipt(self.receipt))
        self.assertTrue(verify_full_search_receipt(self.log.full_search_receipt("missing")))

    def test_incomplete_coverage_is_rejected(self):
        # Unlike SearchReceipt, dropping an entry is a structural failure.
        with self.assertRaises(ValueError):
            self.rebuild(items=self.receipt.items[:4])
        with self.assertRaises(ValueError):
            self.rebuild(items=())
        # Duplicates and out-of-order entries are rejected too.
        with self.assertRaises(ValueError):
            self.rebuild(items=self.receipt.items + (self.receipt.items[-1],))
        with self.assertRaises(ValueError):
            self.rebuild(
                items=(self.receipt.items[1], self.receipt.items[0])
                + self.receipt.items[2:]
            )

    def test_tampered_payload_fails(self):
        entry = self.receipt.items[0]
        forged = Entry(entry.index, b"zz", entry.previous_hash, entry.entry_hash)
        self.assertFalse(
            verify_full_search_receipt(
                self.rebuild(items=(forged,) + self.receipt.items[1:])
            )
        )

    def test_tampered_entry_hash_fails(self):
        entry = self.receipt.items[0]
        forged = Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 32)
        self.assertFalse(
            verify_full_search_receipt(
                self.rebuild(items=(forged,) + self.receipt.items[1:])
            )
        )

    def test_tampered_proof_and_root_fail(self):
        # A range covering the whole snapshot carries an empty proof; use a
        # sub-range receipt to exercise proof tampering.
        receipt = self.log.full_search_receipt("a", 1, 4)
        bad_proof = (b"\x00" * 32,) + receipt.proof[1:]
        self.assertFalse(
            verify_full_search_receipt(self.rebuild(
                start=1, stop=4, items=receipt.items, proof=bad_proof
            ))
        )
        self.assertFalse(verify_full_search_receipt(self.rebuild(root=b"\x00" * 32)))

    def test_wrong_snapshot_root_fails(self):
        other = self.log.full_search_receipt("a", size=4)
        forged = FullSearchReceipt(
            other.version,
            other.hash_name,
            other.size,
            self.receipt.root,  # root of the size-5 snapshot, not size 4
            other.query,
            other.start,
            other.stop,
            other.items,
            other.proof,
        )
        self.assertFalse(verify_full_search_receipt(forged))

    def test_empty_snapshot_root_checked(self):
        snapshot = AuditLog().full_search_receipt("a")
        self.assertTrue(verify_full_search_receipt(snapshot))
        forged = FullSearchReceipt(
            1, "sha256", 0, b"\x00" * 32, b"a", 0, 0, (), ()
        )
        self.assertFalse(verify_full_search_receipt(forged))

    def test_proof_node_count_checked(self):
        receipt = self.log.full_search_receipt("a", 1, 4)
        with self.assertRaises(ValueError):
            verify_full_search_receipt(
                self.rebuild(start=1, stop=4, items=receipt.items, proof=())
            )
        with self.assertRaises(ValueError):
            verify_full_search_receipt(
                self.rebuild(
                    start=1,
                    stop=4,
                    items=receipt.items,
                    proof=receipt.proof + (b"\x00" * 32,),
                )
            )

    def test_verify_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2)):
            with self.assertRaises(TypeError):
                verify_full_search_receipt(bad)

    def test_verify_revalidates_bypassed_fields(self):
        forged = FullSearchReceipt.__new__(FullSearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", 5),
            ("root", self.receipt.root),
            ("query", b"a"),
            ("start", 0),
            ("stop", 5),
            ("items", self.receipt.items),
            ("proof", self.receipt.proof),
        ):
            object.__setattr__(forged, name, value)
        self.assertTrue(verify_full_search_receipt(forged))
        object.__setattr__(forged, "stop", 4)  # items no longer inside the range
        with self.assertRaises(ValueError):
            verify_full_search_receipt(forged)
        object.__setattr__(forged, "stop", 5)
        object.__setattr__(forged, "query", 123)
        with self.assertRaises(TypeError):
            verify_full_search_receipt(forged)

    def test_alternate_hash(self):
        log = make_log(("a", "b", "a"), hash_name="sha3-256")
        receipt = log.full_search_receipt("a")
        self.assertEqual(receipt.hash_name, "sha3-256")
        self.assertTrue(verify_full_search_receipt(receipt))


class FullSearchReceiptClassTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.full_search_receipt("a")

    def base(self, **overrides):
        fields = dict(
            version=1,
            hash_name="sha256",
            size=5,
            root=self.receipt.root,
            query=b"a",
            start=0,
            stop=5,
            items=self.receipt.items,
            proof=self.receipt.proof,
        )
        fields.update(overrides)
        return fields

    def test_positional_construction_and_equality(self):
        other = FullSearchReceipt(
            1,
            "sha256",
            self.receipt.size,
            self.receipt.root,
            b"a",
            0,
            5,
            self.receipt.items,
            self.receipt.proof,
        )
        self.assertEqual(other, self.receipt)
        self.assertNotEqual(other, self.log.full_search_receipt("b"))

    def test_frozen(self):
        with self.assertRaises(AttributeError):
            self.receipt.query = b"b"

    def test_constructor_type_errors(self):
        for key, bad in (
            ("version", "1"),
            ("version", True),
            ("hash_name", b"sha256"),
            ("size", "5"),
            ("size", True),
            ("root", "x" * 32),
            ("query", bytearray(b"a")),
            ("query", 1),
            ("start", True),
            ("stop", 1.5),
            ("items", list(self.receipt.items)),
            ("proof", list(self.receipt.proof)),
        ):
            with self.assertRaises(TypeError, msg=key):
                FullSearchReceipt(**self.base(**{key: bad}))

    def test_constructor_binary_fields_must_be_exact_bytes(self):
        first = self.receipt.items[0]
        # root, every Entry binary field and every proof node reject
        # bytearray / memoryview rather than silently copying them.
        with self.assertRaises(TypeError):
            FullSearchReceipt(**self.base(root=bytearray(self.receipt.root)))
        with self.assertRaises(TypeError):
            FullSearchReceipt(**self.base(root=memoryview(self.receipt.root)))
        for name in ("payload", "previous_hash", "entry_hash"):
            forged = Entry(
                first.index,
                **{
                    field: (
                        bytearray(getattr(first, field))
                        if field == name
                        else getattr(first, field)
                    )
                    for field in ("payload", "previous_hash", "entry_hash")
                },
            )
            with self.assertRaises(TypeError, msg=name):
                FullSearchReceipt(
                    **self.base(items=(forged,) + self.receipt.items[1:])
                )
        if self.receipt.proof:
            with self.assertRaises(TypeError):
                FullSearchReceipt(
                    **self.base(
                        proof=(bytearray(self.receipt.proof[0]),)
                        + self.receipt.proof[1:]
                    )
                )
            with self.assertRaises(TypeError):
                FullSearchReceipt(
                    **self.base(
                        proof=(memoryview(self.receipt.proof[0]),)
                        + self.receipt.proof[1:]
                    )
                )

    def test_constructor_value_errors(self):
        for key, bad in (
            ("version", 2),
            ("hash_name", "not-a-hash"),
            ("size", -1),
            ("size", 1 << 64),
            ("root", b"\x00" * 31),
            ("start", -1),
            ("stop", 6),
        ):
            with self.assertRaises(ValueError, msg=key):
                FullSearchReceipt(**self.base(**{key: bad}))
        with self.assertRaises(ValueError):
            FullSearchReceipt(**self.base(start=3, stop=2))

    def test_constructor_item_structure(self):
        first, second = self.receipt.items[:2]
        # Non-ascending and duplicate indices are rejected.
        with self.assertRaises(ValueError):
            FullSearchReceipt(**self.base(items=(second, first) + self.receipt.items[2:]))
        with self.assertRaises(ValueError):
            FullSearchReceipt(**self.base(items=(first, first) + self.receipt.items[2:]))
        # An index outside the recorded range is rejected.
        with self.assertRaises(ValueError):
            FullSearchReceipt(**self.base(stop=4))
        # Incomplete coverage of the range is rejected.
        with self.assertRaises(ValueError):
            FullSearchReceipt(**self.base(items=self.receipt.items[:4]))
        # A bad entry field width is rejected.
        forged = Entry(first.index, first.payload, b"\x00" * 16, first.entry_hash)
        with self.assertRaises(ValueError):
            FullSearchReceipt(**self.base(items=(forged,) + self.receipt.items[1:]))
        with self.assertRaises(TypeError):
            FullSearchReceipt(**self.base(items=((first, None),) + self.receipt.items[1:]))

    def test_constructor_proof_structure(self):
        # A non-empty proof on an empty range is rejected.
        with self.assertRaises(ValueError):
            FullSearchReceipt(**self.base(start=2, stop=2, items=(), proof=(b"\x00" * 32,)))
        # A bad proof element width is rejected.
        receipt = self.log.full_search_receipt("a", 1, 4)
        with self.assertRaises(ValueError):
            FullSearchReceipt(
                **self.base(
                    start=1,
                    stop=4,
                    items=receipt.items,
                    proof=receipt.proof + (b"\x00" * 16,),
                )
            )
        with self.assertRaises(TypeError):
            FullSearchReceipt(
                **self.base(start=1, stop=4, items=receipt.items, proof=(16,))
            )


if __name__ == "__main__":
    unittest.main()
