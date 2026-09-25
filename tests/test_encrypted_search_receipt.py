import unittest

from auditchain import (
    AuditLog,
    EncryptedSearchReceipt,
    Entry,
    verify_encrypted_search_receipt,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(reversed(range(32)))
AUTH_KEY = b"super-secret-key"


def make_log(plaintexts=("a", "b", "a", "c", "a"), enc_key=KEY, **kwargs):
    log = AuditLog(**kwargs)
    for nonce, plaintext in enumerate(plaintexts):
        log.encrypt(plaintext, enc_key, nonce=bytes([nonce]) * 12)
    return log


class EncryptedSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_fields_and_ascending_items(self):
        receipt = self.log.encrypted_search_receipt("a", KEY)
        self.assertIsInstance(receipt, EncryptedSearchReceipt)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.query, b"a")
        self.assertEqual((receipt.start, receipt.stop), (0, 5))
        indices = [entry.index for entry, _ in receipt.items]
        self.assertEqual(indices, [0, 2, 4])
        for entry, proof in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
            self.assertEqual(proof, self.log.inclusion_proof(entry.index, 5))

    def test_str_query_normalized_to_bytes(self):
        receipt = self.log.encrypted_search_receipt("位置", KEY)
        self.assertEqual(receipt.query, "位置".encode("utf-8"))
        self.assertEqual(receipt.items, ())
        self.log.encrypt("位置", KEY, nonce=b"\xff" * 12)
        receipt = self.log.encrypted_search_receipt("位置", KEY)
        self.assertEqual([entry.index for entry, _ in receipt.items], [5])
        self.assertEqual(
            receipt,
            self.log.encrypted_search_receipt("位置".encode("utf-8"), KEY),
        )

    def test_bytes_and_str_queries_are_equivalent(self):
        self.assertEqual(
            self.log.encrypted_search_receipt(b"a", KEY),
            self.log.encrypted_search_receipt("a", KEY),
        )

    def test_empty_query_and_duplicates(self):
        log = make_log(("", "x", "", "x", ""))
        receipt = log.encrypted_search_receipt("", KEY)
        self.assertEqual(receipt.query, b"")
        self.assertEqual([entry.index for entry, _ in receipt.items], [0, 2, 4])
        self.assertTrue(verify_encrypted_search_receipt(receipt, KEY))

    def test_no_match_carries_no_items(self):
        receipt = self.log.encrypted_search_receipt("missing", KEY)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.size, 5)
        self.assertTrue(verify_encrypted_search_receipt(receipt, KEY))

    def test_empty_snapshot(self):
        receipt = AuditLog().encrypted_search_receipt("a", KEY)
        self.assertEqual(receipt.size, 0)
        self.assertEqual((receipt.start, receipt.stop), (0, 0))
        self.assertEqual(receipt.items, ())
        self.assertTrue(verify_encrypted_search_receipt(receipt, KEY))

    def test_wrong_key_and_plain_entries_never_hit(self):
        log = AuditLog()
        log.append("a")  # plain entry with the queried plaintext
        log.encrypt("a", KEY, nonce=b"0" * 12)
        log.encrypt("a", OTHER_KEY, nonce=b"1" * 12)
        receipt = log.encrypted_search_receipt("a", KEY)
        self.assertEqual([entry.index for entry, _ in receipt.items], [1])
        # The entry sealed under the other key is found only with that key.
        self.assertEqual(
            [e.index for e, _ in log.encrypted_search_receipt("a", OTHER_KEY).items],
            [2],
        )
        # A valid key that sealed nothing simply finds nothing.
        self.assertEqual(log.encrypted_search_receipt("a", b"\xff" * 32).items, ())

    def test_explicit_half_open_range(self):
        receipt = self.log.encrypted_search_receipt("a", KEY, 1, 4)
        self.assertEqual((receipt.start, receipt.stop), (1, 4))
        self.assertEqual([entry.index for entry, _ in receipt.items], [2])
        self.assertTrue(verify_encrypted_search_receipt(receipt, KEY))
        self.assertEqual(self.log.encrypted_search_receipt("a", KEY, 2, 2).items, ())
        self.assertEqual(
            [e.index for e, _ in self.log.encrypted_search_receipt("a", KEY, None, 2).items],
            [0],
        )
        self.assertEqual(
            [e.index for e, _ in self.log.encrypted_search_receipt("a", KEY, 4).items],
            [4],
        )

    def test_explicit_snapshot_size(self):
        receipt = self.log.encrypted_search_receipt("a", KEY, size=3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual((receipt.start, receipt.stop), (0, 3))
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual([entry.index for entry, _ in receipt.items], [0, 2])
        self.assertTrue(verify_encrypted_search_receipt(receipt, KEY))
        # A hit past the snapshot boundary is not covered.
        later = self.log.encrypted_search_receipt("a", KEY, size=3)
        self.assertNotIn(4, [e.index for e, _ in later.items])

    def test_range_limited_to_snapshot(self):
        with self.assertRaises(ValueError):
            self.log.encrypted_search_receipt("a", KEY, 0, 4, size=3)
        receipt = self.log.encrypted_search_receipt("a", KEY, 0, 3, size=3)
        self.assertEqual([e.index for e, _ in receipt.items], [0, 2])

    def test_query_type_errors(self):
        for bad in (bytearray(b"a"), memoryview(b"a"), 123, None, ["a"]):
            with self.assertRaises(TypeError):
                self.log.encrypted_search_receipt(bad, KEY)

    def test_key_type_and_length_errors(self):
        for bad in (bytearray(KEY), memoryview(KEY), "k" * 32, None, 123):
            with self.assertRaises(TypeError):
                self.log.encrypted_search_receipt("a", bad)
        for bad in (b"", KEY[:31], KEY + b"\x00"):
            with self.assertRaises(ValueError):
                self.log.encrypted_search_receipt("a", bad)

    def test_bound_and_size_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.encrypted_search_receipt("a", KEY, bad)
            with self.assertRaises(TypeError):
                self.log.encrypted_search_receipt("a", KEY, 0, bad)
            with self.assertRaises(TypeError):
                self.log.encrypted_search_receipt("a", KEY, size=bad)

    def test_bound_and_size_range_errors(self):
        for args in ((-1, None, None), (0, 6, None), (3, 2, None), (6, None, None)):
            start, stop, size = args
            with self.assertRaises(ValueError):
                self.log.encrypted_search_receipt("a", KEY, start, stop, size=size)
        with self.assertRaises(ValueError):
            self.log.encrypted_search_receipt("a", KEY, size=-1)
        with self.assertRaises(ValueError):
            self.log.encrypted_search_receipt("a", KEY, size=6)
        # Boundary values themselves are accepted.
        self.assertTrue(
            verify_encrypted_search_receipt(
                self.log.encrypted_search_receipt("a", KEY, 0, 5, size=5), KEY
            )
        )

    def test_issue_is_read_only(self):
        log = make_log(("a", "b", "a"), key=AUTH_KEY)
        verifier = log.export_verifier()
        tag = log.auth(0)
        head = log.head
        root = log.merkle_root()
        stage = log.stage
        tags = dict(log._tags)
        receipt = log.encrypted_search_receipt("a", KEY)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.stage, stage)
        self.assertEqual(log._tags, tags)
        self.assertTrue(log.verify())
        from auditchain import verify_auth

        self.assertTrue(verify_auth(log.entry(0), tag, verifier))
        self.assertTrue(verify_encrypted_search_receipt(receipt, KEY))


class EncryptedSearchReceiptPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(("a", "b", "a", "c", "a", "b"))

    def test_default_range_is_retained_segment(self):
        self.log.prune(2, self.log.seal(2))
        receipt = self.log.encrypted_search_receipt("a", KEY)
        self.assertEqual((receipt.start, receipt.stop), (2, 6))
        self.assertEqual([e.index for e, _ in receipt.items], [2, 4])
        self.assertTrue(verify_encrypted_search_receipt(receipt, KEY))

    def test_explicit_range_may_not_reach_released_prefix(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(ValueError):
            self.log.encrypted_search_receipt("a", KEY, 0, 4)
        receipt = self.log.encrypted_search_receipt("a", KEY, 2, 4)
        self.assertEqual([e.index for e, _ in receipt.items], [2])

    def test_pruned_snapshot_is_not_rebuildable(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(ValueError):
            self.log.encrypted_search_receipt("a", KEY, size=1)
        # The retained suffix snapshot still works.
        receipt = self.log.encrypted_search_receipt("b", KEY, size=6)
        self.assertEqual([e.index for e, _ in receipt.items], [5])
        self.assertTrue(verify_encrypted_search_receipt(receipt, KEY))

    def test_prune_all_then_search(self):
        self.log.prune(6, self.log.seal(6))
        receipt = self.log.encrypted_search_receipt("a", KEY)
        self.assertEqual(receipt.items, ())
        self.assertEqual((receipt.start, receipt.stop), (6, 6))
        self.assertTrue(verify_encrypted_search_receipt(receipt, KEY))


class EncryptedSearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.encrypted_search_receipt("a", KEY)

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
        )
        fields.update(overrides)
        return EncryptedSearchReceipt(**fields)

    def test_genuine_receipt_verifies(self):
        self.assertTrue(verify_encrypted_search_receipt(self.receipt, KEY))
        self.assertTrue(
            verify_encrypted_search_receipt(
                self.log.encrypted_search_receipt("missing", KEY), KEY
            )
        )

    def test_incomplete_result_set_is_not_a_failure(self):
        # Verification only attests the listed hits, not completeness.
        partial = self.rebuild(items=self.receipt.items[:1])
        self.assertTrue(verify_encrypted_search_receipt(partial, KEY))
        empty = self.rebuild(items=())
        self.assertTrue(verify_encrypted_search_receipt(empty, KEY))

    def test_wrong_key_returns_false(self):
        self.assertFalse(verify_encrypted_search_receipt(self.receipt, OTHER_KEY))

    def test_tampered_query_fails(self):
        self.assertFalse(verify_encrypted_search_receipt(self.rebuild(query=b"zzz"), KEY))

    def test_tampered_payload_fails(self):
        entry, proof = self.receipt.items[0]
        forged = Entry(entry.index, b"zz", entry.previous_hash, entry.entry_hash)
        self.assertFalse(
            verify_encrypted_search_receipt(
                self.rebuild(items=((forged, proof),) + self.receipt.items[1:]),
                KEY,
            )
        )

    def test_tampered_entry_hash_fails(self):
        entry, proof = self.receipt.items[0]
        forged = Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 32)
        self.assertFalse(
            verify_encrypted_search_receipt(
                self.rebuild(items=((forged, proof),) + self.receipt.items[1:]),
                KEY,
            )
        )

    def test_tampered_proof_and_root_fail(self):
        entry, proof = self.receipt.items[0]
        bad_proof = (b"\x00" * 32,) + proof[1:]
        self.assertFalse(
            verify_encrypted_search_receipt(
                self.rebuild(items=((entry, bad_proof),) + self.receipt.items[1:]),
                KEY,
            )
        )
        self.assertFalse(
            verify_encrypted_search_receipt(self.rebuild(root=b"\x00" * 32), KEY)
        )

    def test_wrong_snapshot_root_fails(self):
        other = self.log.encrypted_search_receipt("a", KEY, size=4)
        forged = EncryptedSearchReceipt(
            other.version,
            other.hash_name,
            other.size,
            self.receipt.root,  # root of the size-5 snapshot, not size 4
            other.query,
            other.start,
            other.stop,
            other.items,
        )
        self.assertFalse(verify_encrypted_search_receipt(forged, KEY))

    def test_verify_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2)):
            with self.assertRaises(TypeError):
                verify_encrypted_search_receipt(bad, KEY)
        for bad in (bytearray(KEY), "k" * 32, None, 123):
            with self.assertRaises(TypeError):
                verify_encrypted_search_receipt(self.receipt, bad)

    def test_verify_key_length_errors(self):
        for bad in (b"", KEY[:31], KEY + b"\x00"):
            with self.assertRaises(ValueError):
                verify_encrypted_search_receipt(self.receipt, bad)

    def test_verify_revalidates_bypassed_fields(self):
        forged = EncryptedSearchReceipt.__new__(EncryptedSearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", 5),
            ("root", self.receipt.root),
            ("query", b"a"),
            ("start", 0),
            ("stop", 5),
            ("items", self.receipt.items),
        ):
            object.__setattr__(forged, name, value)
        self.assertTrue(verify_encrypted_search_receipt(forged, KEY))
        object.__setattr__(forged, "stop", 2)  # items no longer inside the range
        with self.assertRaises(ValueError):
            verify_encrypted_search_receipt(forged, KEY)
        object.__setattr__(forged, "stop", 5)
        object.__setattr__(forged, "query", 123)
        with self.assertRaises(TypeError):
            verify_encrypted_search_receipt(forged, KEY)

    def test_alternate_hash(self):
        log = make_log(("a", "b", "a"), hash_name="sha3-256")
        receipt = log.encrypted_search_receipt("a", KEY)
        self.assertEqual(receipt.hash_name, "sha3-256")
        self.assertTrue(verify_encrypted_search_receipt(receipt, KEY))


class EncryptedSearchReceiptClassTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.encrypted_search_receipt("a", KEY)

    def test_positional_construction_and_equality(self):
        other = EncryptedSearchReceipt(
            1,
            "sha256",
            self.receipt.size,
            self.receipt.root,
            b"a",
            0,
            5,
            self.receipt.items,
        )
        self.assertEqual(other, self.receipt)
        self.assertNotEqual(other, self.log.encrypted_search_receipt("b", KEY))

    def test_frozen(self):
        with self.assertRaises(AttributeError):
            self.receipt.query = b"b"

    def test_constructor_type_errors(self):
        base = dict(
            version=1,
            hash_name="sha256",
            size=5,
            root=self.receipt.root,
            query=b"a",
            start=0,
            stop=5,
            items=self.receipt.items,
        )
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
        ):
            with self.assertRaises(TypeError, msg=key):
                EncryptedSearchReceipt(**{**base, key: bad})

    def test_constructor_value_errors(self):
        base = dict(
            version=1,
            hash_name="sha256",
            size=5,
            root=self.receipt.root,
            query=b"a",
            start=0,
            stop=5,
            items=self.receipt.items,
        )
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
                EncryptedSearchReceipt(**{**base, key: bad})
        with self.assertRaises(ValueError):
            EncryptedSearchReceipt(**{**base, "start": 3, "stop": 2})

    def test_constructor_item_structure(self):
        base = dict(
            version=1,
            hash_name="sha256",
            size=5,
            root=self.receipt.root,
            query=b"a",
            start=0,
            stop=5,
        )
        first, second = self.receipt.items[:2]
        # Non-ascending and duplicate indices are rejected.
        with self.assertRaises(ValueError):
            EncryptedSearchReceipt(**base, items=(second, first))
        with self.assertRaises(ValueError):
            EncryptedSearchReceipt(**base, items=(first, first))
        # An index outside the recorded range is rejected.
        with self.assertRaises(ValueError):
            EncryptedSearchReceipt(**{**base, "stop": 3}, items=self.receipt.items)
        # A bad proof width is rejected.
        entry, proof = first
        with self.assertRaises(ValueError):
            EncryptedSearchReceipt(**base, items=((entry, proof + (b"\x00" * 16,)),))
        with self.assertRaises(TypeError):
            EncryptedSearchReceipt(**base, items=((entry, [b"\x00" * 32]),))
        with self.assertRaises(TypeError):
            EncryptedSearchReceipt(**base, items=((entry,),))


if __name__ == "__main__":
    unittest.main()
