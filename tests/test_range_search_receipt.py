import unittest

from auditchain import (
    AuditLog,
    Entry,
    RangeSearchReceipt,
    verify_range_search_receipt,
)

KEY = b"super-secret-key"
ENC_KEY = b"k" * 32


def make_log(records=("a", "b", "aa", "c", "a", "b")):
    log = AuditLog()
    for record in records:
        log.append(record)
    return log


class RangeSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_fields_and_full_coverage(self):
        receipt = self.log.range_search_receipt(b"a", b"c")
        self.assertIsInstance(receipt, RangeSearchReceipt)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 6)
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.left, b"a")
        self.assertEqual(receipt.right, b"c")
        self.assertEqual((receipt.start, receipt.stop), (0, 6))
        self.assertEqual(
            [entry.index for entry in receipt.items], [0, 1, 2, 3, 4, 5]
        )
        for entry in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
        self.assertEqual(
            receipt.proof,
            self.log.batch_inclusion_proof((0, 1, 2, 3, 4, 5), 6)[1],
        )

    def test_hits_match_range_search_semantics(self):
        receipt = self.log.range_search_receipt(b"a", b"c")
        self.assertEqual(receipt.hits, (0, 1, 2, 4, 5))
        self.assertEqual(receipt.hits, self.log.range_search(b"a", b"c"))
        # Left-closed, right-open.
        self.assertEqual(
            self.log.range_search_receipt(b"c", b"d").hits, (3,)
        )
        self.assertEqual(
            self.log.range_search_receipt(b"d", b"e").hits, ()
        )

    def test_str_bounds_normalized_to_bytes(self):
        receipt = self.log.range_search_receipt("aa", "c")
        self.assertEqual(receipt.left, b"aa")
        self.assertEqual(receipt.right, b"c")
        self.assertEqual(
            self.log.range_search_receipt("a", "c"),
            self.log.range_search_receipt(b"a", b"c"),
        )

    def test_unicode_bounds(self):
        log = make_log(())
        log.append("位置")
        receipt = log.range_search_receipt("位置", "位置" + chr(0xFFFF))
        self.assertEqual(receipt.left, "位置".encode("utf-8"))
        self.assertEqual(receipt.hits, (0,))

    def test_equal_bounds_give_empty_hits_but_full_coverage(self):
        receipt = self.log.range_search_receipt(b"a", b"a")
        self.assertEqual(receipt.hits, ())
        # The whole range is still listed and authenticates.
        self.assertEqual(
            [entry.index for entry in receipt.items], [0, 1, 2, 3, 4, 5]
        )
        self.assertTrue(verify_range_search_receipt(receipt))

    def test_empty_boundaries(self):
        receipt = self.log.range_search_receipt(b"", b"c")
        self.assertEqual(receipt.hits, (0, 1, 2, 4, 5))
        self.assertTrue(verify_range_search_receipt(receipt))
        self.assertEqual(self.log.range_search_receipt(b"zz", b"zzz").hits, ())

    def test_empty_index_range_and_empty_snapshot(self):
        receipt = self.log.range_search_receipt(b"a", b"z", 2, 2)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_range_search_receipt(receipt))
        snapshot = AuditLog().range_search_receipt(b"a", b"z")
        self.assertEqual(snapshot.size, 0)
        self.assertEqual((snapshot.start, snapshot.stop), (0, 0))
        self.assertEqual(snapshot.items, ())
        self.assertTrue(verify_range_search_receipt(snapshot))

    def test_explicit_half_open_index_range(self):
        receipt = self.log.range_search_receipt(b"a", b"z", 1, 4)
        self.assertEqual((receipt.start, receipt.stop), (1, 4))
        self.assertEqual([e.index for e in receipt.items], [1, 2, 3])
        self.assertEqual(receipt.hits, (1, 2, 3))
        self.assertTrue(verify_range_search_receipt(receipt))
        self.assertEqual(
            [e.index for e in self.log.range_search_receipt(b"a", b"z", None, 2).items],
            [0, 1],
        )
        self.assertEqual(
            [e.index for e in self.log.range_search_receipt(b"a", b"z", 4).items],
            [4, 5],
        )

    def test_explicit_snapshot_size(self):
        receipt = self.log.range_search_receipt(b"a", b"z", size=3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual((receipt.start, receipt.stop), (0, 3))
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual([e.index for e in receipt.items], [0, 1, 2])
        self.assertTrue(verify_range_search_receipt(receipt))

    def test_encrypted_entries_compare_by_envelope_only(self):
        log = make_log(("plain",))
        entry = log.encrypt("secret", ENC_KEY)
        magic = b"auditchain/encrypted-entry/v1\0"
        receipt = log.range_search_receipt(magic, magic + b"\xff")
        self.assertEqual(receipt.hits, (entry.index,))
        self.assertTrue(verify_range_search_receipt(receipt))
        # Plaintext is not exposed by the interval.
        self.assertEqual(
            log.range_search_receipt(b"secret", b"secret\xff").hits, ()
        )

    def test_bound_type_errors(self):
        for bad in (bytearray(b"a"), memoryview(b"a"), 123, None, ["a"]):
            with self.assertRaises(TypeError):
                self.log.range_search_receipt(bad, b"a")
            with self.assertRaises(TypeError):
                self.log.range_search_receipt(b"a", bad)

    def test_inverted_bounds_raise_value_error(self):
        with self.assertRaises(ValueError):
            self.log.range_search_receipt(b"c", b"a")

    def test_index_bound_and_size_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.range_search_receipt(b"a", b"z", bad)
            with self.assertRaises(TypeError):
                self.log.range_search_receipt(b"a", b"z", 0, bad)
            with self.assertRaises(TypeError):
                self.log.range_search_receipt(b"a", b"z", size=bad)

    def test_index_bound_and_size_range_errors(self):
        for args in ((-1, None, None), (0, 7, None), (3, 2, None), (7, None, None)):
            start, stop, size = args
            with self.assertRaises(ValueError):
                self.log.range_search_receipt(b"a", b"z", start, stop, size=size)
        with self.assertRaises(ValueError):
            self.log.range_search_receipt(b"a", b"z", size=-1)
        with self.assertRaises(ValueError):
            self.log.range_search_receipt(b"a", b"z", size=7)
        self.assertTrue(
            verify_range_search_receipt(
                self.log.range_search_receipt(b"a", b"z", 0, 6, size=6)
            )
        )

    def test_issue_is_read_only_and_repeatable(self):
        log = make_log(("a", "b", "a"))
        log_with_key = AuditLog(key=KEY)
        log_with_key.append("a")
        verifier = log_with_key.export_verifier()
        tag = log_with_key.auth(0)
        head = log.head
        root = log.merkle_root()
        stage = log.stage
        tags = dict(log._tags)
        first = log.range_search_receipt(b"a", b"z")
        second = log.range_search_receipt(b"a", b"z")
        self.assertEqual(first, second)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.stage, stage)
        self.assertEqual(log._tags, tags)
        self.assertTrue(log.verify())
        self.assertTrue(verify_range_search_receipt(first))
        from auditchain import verify_auth

        self.assertTrue(
            verify_auth(log_with_key.entry(0), tag, verifier)
        )


class RangeSearchReceiptPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a", "b"):
            self.log.append(record)

    def test_default_range_is_retained_segment(self):
        self.log.prune(2, self.log.seal(2))
        receipt = self.log.range_search_receipt(b"a", b"z")
        self.assertEqual((receipt.start, receipt.stop), (2, 6))
        self.assertEqual([e.index for e in receipt.items], [2, 3, 4, 5])
        self.assertEqual(receipt.hits, (2, 3, 4, 5))
        self.assertTrue(verify_range_search_receipt(receipt))

    def test_explicit_range_may_not_reach_released_prefix(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(ValueError):
            self.log.range_search_receipt(b"a", b"z", 0, 4)
        receipt = self.log.range_search_receipt(b"a", b"z", 2, 4)
        self.assertEqual([e.index for e in receipt.items], [2, 3])
        self.assertTrue(verify_range_search_receipt(receipt))

    def test_pruned_snapshot_is_not_rebuildable(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(ValueError):
            self.log.range_search_receipt(b"a", b"z", size=1)
        receipt = self.log.range_search_receipt(b"b", b"z", size=6)
        self.assertEqual([e.index for e in receipt.items], [2, 3, 4, 5])
        self.assertTrue(verify_range_search_receipt(receipt))

    def test_prune_all_then_receipt(self):
        self.log.prune(6, self.log.seal(6))
        receipt = self.log.range_search_receipt(b"a", b"z")
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_range_search_receipt(receipt))


class RangeSearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.range_search_receipt(b"a", b"c")

    def rebuild(self, **overrides):
        fields = dict(
            version=self.receipt.version,
            hash_name=self.receipt.hash_name,
            size=self.receipt.size,
            root=self.receipt.root,
            left=self.receipt.left,
            right=self.receipt.right,
            start=self.receipt.start,
            stop=self.receipt.stop,
            items=self.receipt.items,
            proof=self.receipt.proof,
            hits=self.receipt.hits,
        )
        fields.update(overrides)
        return RangeSearchReceipt(**fields)

    def test_genuine_receipt_verifies(self):
        self.assertTrue(verify_range_search_receipt(self.receipt))
        self.assertTrue(
            verify_range_search_receipt(self.log.range_search_receipt(b"zz", b"zzz"))
        )

    def test_concealed_hit_fails(self):
        # Dropping a hit from the recorded hit set is a mismatch.
        self.assertFalse(verify_range_search_receipt(self.rebuild(hits=())))
        self.assertFalse(
            verify_range_search_receipt(self.rebuild(hits=(0, 1, 2, 4)))
        )

    def test_forged_hit_fails(self):
        # Index 3 holds b"c", which is outside [a, c).
        forged = self.rebuild(hits=(0, 1, 2, 3, 4, 5))
        self.assertFalse(verify_range_search_receipt(forged))
        # An index actually inside the interval but with the rest concealed.
        self.assertFalse(verify_range_search_receipt(self.rebuild(hits=(1,))))

    def test_faked_empty_hit_set_fails_when_entries_exist(self):
        # An empty hits tuple cannot pass when the authenticated entries
        # include payloads in the interval.
        sub = self.log.range_search_receipt(b"b", b"c")
        self.assertEqual(sub.hits, (1, 5))
        forged = RangeSearchReceipt(
            sub.version,
            sub.hash_name,
            sub.size,
            sub.root,
            sub.left,
            sub.right,
            sub.start,
            sub.stop,
            sub.items,
            sub.proof,
            (),
        )
        self.assertFalse(verify_range_search_receipt(forged))

    def test_tampered_payload_fails(self):
        entry = self.receipt.items[0]
        forged = Entry(entry.index, b"zz", entry.previous_hash, entry.entry_hash)
        self.assertFalse(
            verify_range_search_receipt(
                self.rebuild(items=(forged,) + self.receipt.items[1:])
            )
        )

    def test_tampered_entry_hash_fails(self):
        entry = self.receipt.items[0]
        forged = Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 32)
        self.assertFalse(
            verify_range_search_receipt(
                self.rebuild(items=(forged,) + self.receipt.items[1:])
            )
        )

    def test_tampered_proof_and_root_fail(self):
        receipt = self.log.range_search_receipt(b"a", b"z", 1, 4)
        self.assertTrue(receipt.proof)
        bad_proof = (b"\x00" * 32,) + receipt.proof[1:]
        self.assertFalse(
            verify_range_search_receipt(
                self.rebuild(
                    start=1, stop=4, items=receipt.items, proof=bad_proof,
                    hits=receipt.hits,
                )
            )
        )
        self.assertFalse(verify_range_search_receipt(self.rebuild(root=b"\x00" * 32)))

    def test_wrong_snapshot_root_fails(self):
        other = self.log.range_search_receipt(b"a", b"z", size=4)
        forged = RangeSearchReceipt(
            other.version,
            other.hash_name,
            other.size,
            self.receipt.root,  # root of the size-6 snapshot, not size 4
            other.left,
            other.right,
            other.start,
            other.stop,
            other.items,
            other.proof,
            other.hits,
        )
        self.assertFalse(verify_range_search_receipt(forged))

    def test_empty_snapshot_root_checked(self):
        snapshot = AuditLog().range_search_receipt(b"a", b"c")
        self.assertTrue(verify_range_search_receipt(snapshot))
        forged = RangeSearchReceipt(
            1, "sha256", 0, b"\x00" * 32, b"a", b"c", 0, 0, (), (), ()
        )
        self.assertFalse(verify_range_search_receipt(forged))

    def test_proof_node_count_checked(self):
        receipt = self.log.range_search_receipt(b"a", b"z", 1, 4)
        with self.assertRaises(ValueError):
            verify_range_search_receipt(
                self.rebuild(
                    start=1, stop=4, items=receipt.items, proof=(),
                    hits=receipt.hits,
                )
            )
        with self.assertRaises(ValueError):
            verify_range_search_receipt(
                self.rebuild(
                    start=1,
                    stop=4,
                    items=receipt.items,
                    proof=receipt.proof + (b"\x00" * 32,),
                    hits=receipt.hits,
                )
            )

    def test_verify_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2)):
            with self.assertRaises(TypeError):
                verify_range_search_receipt(bad)

    def test_verify_revalidates_bypassed_fields(self):
        forged = RangeSearchReceipt.__new__(RangeSearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", 6),
            ("root", self.receipt.root),
            ("left", b"a"),
            ("right", b"c"),
            ("start", 0),
            ("stop", 6),
            ("items", self.receipt.items),
            ("proof", self.receipt.proof),
            ("hits", self.receipt.hits),
        ):
            object.__setattr__(forged, name, value)
        self.assertTrue(verify_range_search_receipt(forged))
        object.__setattr__(forged, "stop", 4)  # items no longer cover the range
        with self.assertRaises(ValueError):
            verify_range_search_receipt(forged)
        object.__setattr__(forged, "stop", 6)
        object.__setattr__(forged, "left", 123)
        with self.assertRaises(TypeError):
            verify_range_search_receipt(forged)

    def test_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "a"):
            log.append(record)
        receipt = log.range_search_receipt(b"a", b"c")
        self.assertEqual(receipt.hash_name, "sha3-256")
        self.assertTrue(verify_range_search_receipt(receipt))


class RangeSearchReceiptClassTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.range_search_receipt(b"a", b"c")

    def base(self, **overrides):
        fields = dict(
            version=1,
            hash_name="sha256",
            size=6,
            root=self.receipt.root,
            left=b"a",
            right=b"c",
            start=0,
            stop=6,
            items=self.receipt.items,
            proof=self.receipt.proof,
            hits=self.receipt.hits,
        )
        fields.update(overrides)
        return fields

    def test_positional_construction_and_equality(self):
        other = RangeSearchReceipt(
            1,
            "sha256",
            self.receipt.size,
            self.receipt.root,
            b"a",
            b"c",
            0,
            6,
            self.receipt.items,
            self.receipt.proof,
            self.receipt.hits,
        )
        self.assertEqual(other, self.receipt)
        self.assertNotEqual(other, self.log.range_search_receipt(b"b", b"c"))

    def test_frozen(self):
        with self.assertRaises(AttributeError):
            self.receipt.left = b"b"

    def test_constructor_type_errors(self):
        for key, bad in (
            ("version", "1"),
            ("version", True),
            ("hash_name", b"sha256"),
            ("size", "6"),
            ("size", True),
            ("root", "x" * 32),
            ("left", "x"),  # str is NOT accepted at the dataclass boundary
            ("left", bytearray(b"a")),
            ("right", 1),
            ("start", True),
            ("stop", 1.5),
            ("items", list(self.receipt.items)),
            ("proof", list(self.receipt.proof)),
            ("hits", list(self.receipt.hits)),
        ):
            with self.assertRaises(TypeError, msg=key):
                RangeSearchReceipt(**self.base(**{key: bad}))

    def test_constructor_binary_fields_must_be_exact_bytes(self):
        with self.assertRaises(TypeError):
            RangeSearchReceipt(**self.base(root=bytearray(self.receipt.root)))
        with self.assertRaises(TypeError):
            RangeSearchReceipt(**self.base(root=memoryview(self.receipt.root)))
        with self.assertRaises(TypeError):
            RangeSearchReceipt(**self.base(left=memoryview(b"a")))
        with self.assertRaises(TypeError):
            RangeSearchReceipt(**self.base(right=bytearray(b"c")))
        first = self.receipt.items[0]
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
                RangeSearchReceipt(
                    **self.base(items=(forged,) + self.receipt.items[1:])
                )

    def test_constructor_value_errors(self):
        for key, bad in (
            ("version", 2),
            ("hash_name", "not-a-hash"),
            ("size", -1),
            ("size", 1 << 64),
            ("root", b"\x00" * 31),
            ("start", -1),
            ("stop", 7),
        ):
            with self.assertRaises(ValueError, msg=key):
                RangeSearchReceipt(**self.base(**{key: bad}))
        with self.assertRaises(ValueError):
            RangeSearchReceipt(**self.base(start=3, stop=2))

    def test_constructor_item_structure(self):
        first, second = self.receipt.items[:2]
        with self.assertRaises(ValueError):
            RangeSearchReceipt(
                **self.base(items=(second, first) + self.receipt.items[2:])
            )
        with self.assertRaises(ValueError):
            RangeSearchReceipt(
                **self.base(items=(first, first) + self.receipt.items[2:])
            )
        with self.assertRaises(ValueError):
            RangeSearchReceipt(**self.base(stop=4))
        with self.assertRaises(ValueError):
            RangeSearchReceipt(**self.base(items=self.receipt.items[:5]))
        forged = Entry(first.index, first.payload, b"\x00" * 16, first.entry_hash)
        with self.assertRaises(ValueError):
            RangeSearchReceipt(
                **self.base(items=(forged,) + self.receipt.items[1:])
            )

    def test_constructor_hits_structure(self):
        for bad_hits in ((7,), (6,), (0, 0), (2, 1), (-1,)):
            with self.assertRaises(ValueError, msg=bad_hits):
                RangeSearchReceipt(**self.base(hits=bad_hits))
        for bad_hits in (("0",), (0.0,), (False,)):
            with self.assertRaises(TypeError, msg=bad_hits):
                RangeSearchReceipt(**self.base(hits=bad_hits))

    def test_constructor_proof_structure(self):
        with self.assertRaises(ValueError):
            RangeSearchReceipt(
                **self.base(
                    start=2, stop=2, items=(), proof=(b"\x00" * 32,), hits=()
                )
            )
        receipt = self.log.range_search_receipt(b"a", b"z", 1, 4)
        base = self.base(
            start=1,
            stop=4,
            items=receipt.items,
            proof=receipt.proof + (b"\x00" * 16,),
            hits=receipt.hits,
        )
        with self.assertRaises(ValueError):
            RangeSearchReceipt(**base)
        with self.assertRaises(TypeError):
            RangeSearchReceipt(
                **self.base(start=1, stop=4, items=receipt.items, proof=(16,),
                            hits=receipt.hits)
            )


if __name__ == "__main__":
    unittest.main()
