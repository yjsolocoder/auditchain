import unittest

from auditchain import (
    AuditLog,
    Entry,
    FullEncryptedSearchReceipt,
    decrypt_entry,
    verify_full_encrypted_search_receipt,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
NONCE = b"nonce-12byte"


def make_log(records=(("enc", "a"), ("plain", "a"), ("enc", "a"), ("enc-other", "a"), ("enc", "a")), **kwargs):
    """Build a mixed log; records are ("enc"|"enc-other"|"plain", value)."""
    log = AuditLog(**kwargs)
    nonce_counter = 0
    for kind, value in records:
        if kind == "enc":
            log.encrypt(value, KEY, nonce=bytes([nonce_counter]) * 12)
        elif kind == "enc-other":
            log.encrypt(value, OTHER_KEY, nonce=bytes([nonce_counter]) * 12)
        else:
            log.append(value)
        nonce_counter += 1
    return log


class FullEncryptedSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_fields_and_full_range_items(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        self.assertIsInstance(receipt, FullEncryptedSearchReceipt)
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

    def test_hits_are_derived_by_unsealing_with_the_key(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        # Only the entries sealed under KEY with plaintext b"a" hit: the
        # plain entry at 1 and the other-key envelope at 3 never hit, even
        # though their plaintexts would compare equal.
        self.assertEqual(receipt.hits, (0, 2, 4))
        self.assertEqual(receipt.hits, self.log.find_encrypted("a", KEY))
        for hit in receipt.hits:
            entry = receipt.items[hit]
            self.assertTrue(entry.payload.startswith(b"auditchain/encrypted-entry/v1\0"))
            self.assertEqual(decrypt_entry(entry, KEY), b"a")

    def test_str_query_normalized_to_bytes(self):
        log = AuditLog()
        log.encrypt("位置", KEY, nonce=NONCE)
        receipt = log.full_encrypted_search_receipt("位置", KEY)
        self.assertEqual(receipt.query, "位置".encode("utf-8"))
        self.assertEqual(receipt.hits, (0,))
        self.assertEqual(
            receipt,
            log.full_encrypted_search_receipt("位置".encode("utf-8"), KEY),
        )

    def test_bytes_and_str_queries_are_equivalent(self):
        self.assertEqual(
            self.log.full_encrypted_search_receipt(b"a", KEY),
            self.log.full_encrypted_search_receipt("a", KEY),
        )

    def test_empty_query_and_duplicates(self):
        log = AuditLog()
        log.encrypt(b"", KEY, nonce=b"a" * 12)
        log.encrypt("x", KEY, nonce=b"b" * 12)
        log.encrypt("", KEY, nonce=b"c" * 12)
        receipt = log.full_encrypted_search_receipt("", KEY)
        self.assertEqual(receipt.query, b"")
        self.assertEqual(receipt.hits, (0, 2))
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_no_match_still_lists_the_whole_range(self):
        receipt = self.log.full_encrypted_search_receipt("missing", KEY)
        self.assertEqual([e.index for e in receipt.items], [0, 1, 2, 3, 4])
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_unknown_key_yields_no_hits(self):
        receipt = self.log.full_encrypted_search_receipt("a", OTHER_KEY)
        self.assertEqual(receipt.hits, (3,))
        third = bytes(reversed(range(32)))
        receipt = self.log.full_encrypted_search_receipt("a", third)
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, third))

    def test_empty_range_and_empty_snapshot(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 2, 2)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))
        snapshot = AuditLog().full_encrypted_search_receipt("a", KEY)
        self.assertEqual(snapshot.size, 0)
        self.assertEqual((snapshot.start, snapshot.stop), (0, 0))
        self.assertEqual(snapshot.items, ())
        self.assertEqual(snapshot.proof, ())
        self.assertEqual(snapshot.hits, ())
        self.assertTrue(verify_full_encrypted_search_receipt(snapshot, KEY))

    def test_explicit_half_open_range(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4)
        self.assertEqual((receipt.start, receipt.stop), (1, 4))
        self.assertEqual([e.index for e in receipt.items], [1, 2, 3])
        self.assertEqual(receipt.hits, (2,))
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))
        self.assertEqual(
            [e.index for e in self.log.full_encrypted_search_receipt("a", KEY, None, 2).items],
            [0, 1],
        )
        self.assertEqual(
            [e.index for e in self.log.full_encrypted_search_receipt("a", KEY, 4).items],
            [4],
        )

    def test_explicit_snapshot_size(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, size=3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual((receipt.start, receipt.stop), (0, 3))
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual([e.index for e in receipt.items], [0, 1, 2])
        self.assertEqual(receipt.hits, (0, 2))
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_range_limited_to_snapshot(self):
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", KEY, 0, 4, size=3)
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 0, 3, size=3)
        self.assertEqual([e.index for e in receipt.items], [0, 1, 2])

    def test_query_type_errors(self):
        for bad in (bytearray(b"a"), memoryview(b"a"), 123, None, ["a"]):
            with self.assertRaises(TypeError):
                self.log.full_encrypted_search_receipt(bad, KEY)

    def test_key_type_and_length_errors(self):
        for bad in (bytearray(KEY), memoryview(KEY), "key", 123, None):
            with self.assertRaises(TypeError):
                self.log.full_encrypted_search_receipt("a", bad)
        for bad in (b"", KEY[:31], KEY + b"\x00"):
            with self.assertRaises(ValueError):
                self.log.full_encrypted_search_receipt("a", bad)

    def test_bound_and_size_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.full_encrypted_search_receipt("a", KEY, bad)
            with self.assertRaises(TypeError):
                self.log.full_encrypted_search_receipt("a", KEY, 0, bad)
            with self.assertRaises(TypeError):
                self.log.full_encrypted_search_receipt("a", KEY, size=bad)

    def test_bound_and_size_range_errors(self):
        for args in ((-1, None, None), (0, 6, None), (3, 2, None), (6, None, None)):
            start, stop, size = args
            with self.assertRaises(ValueError):
                self.log.full_encrypted_search_receipt("a", KEY, start, stop, size=size)
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", KEY, size=-1)
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", KEY, size=6)
        # Boundary values themselves are accepted.
        self.assertTrue(
            verify_full_encrypted_search_receipt(
                self.log.full_encrypted_search_receipt("a", KEY, 0, 5, size=5), KEY
            )
        )

    def test_issue_is_read_only_and_repeatable(self):
        head = self.log.head
        root = self.log.merkle_root()
        located = self.log.find_encrypted("a", KEY)
        first = self.log.full_encrypted_search_receipt("a", KEY)
        second = self.log.full_encrypted_search_receipt("a", KEY)
        self.assertEqual(first, second)
        self.assertEqual(self.log.head, head)
        self.assertEqual(self.log.merkle_root(), root)
        self.assertEqual(self.log.find_encrypted("a", KEY), located)
        self.assertTrue(self.log.verify())
        self.assertTrue(verify_full_encrypted_search_receipt(first, KEY))


class FullEncryptedSearchReceiptPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(
            (
                ("enc", "a"),
                ("plain", "b"),
                ("enc", "a"),
                ("enc-other", "c"),
                ("enc", "a"),
                ("plain", "b"),
            )
        )

    def test_default_range_is_retained_segment(self):
        self.log.prune(2, self.log.seal(2))
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        self.assertEqual((receipt.start, receipt.stop), (2, 6))
        self.assertEqual([e.index for e in receipt.items], [2, 3, 4, 5])
        self.assertEqual(receipt.hits, (2, 4))
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_explicit_range_may_not_reach_released_prefix(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", KEY, 0, 4)
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 2, 4)
        self.assertEqual([e.index for e in receipt.items], [2, 3])
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_pruned_snapshot_is_not_rebuildable(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", KEY, size=1)
        # The retained suffix snapshot still works.
        receipt = self.log.full_encrypted_search_receipt("b", KEY, size=6)
        self.assertEqual([e.index for e in receipt.items], [2, 3, 4, 5])
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_prune_all_then_search(self):
        self.log.prune(6, self.log.seal(6))
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertEqual((receipt.start, receipt.stop), (6, 6))
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))


class FullEncryptedSearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.full_encrypted_search_receipt("a", KEY)

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
            hits=self.receipt.hits,
        )
        fields.update(overrides)
        return FullEncryptedSearchReceipt(**fields)

    def test_genuine_receipt_verifies(self):
        self.assertTrue(verify_full_encrypted_search_receipt(self.receipt, KEY))
        self.assertTrue(
            verify_full_encrypted_search_receipt(
                self.log.full_encrypted_search_receipt("missing", KEY), KEY
            )
        )

    def test_wrong_key_fails_when_hits_are_recorded(self):
        self.assertNotEqual(self.receipt.hits, ())
        self.assertFalse(verify_full_encrypted_search_receipt(self.receipt, OTHER_KEY))

    def test_zero_hit_receipt_does_not_test_the_key(self):
        receipt = self.log.full_encrypted_search_receipt("missing", KEY)
        self.assertEqual(receipt.hits, ())
        # No recorded hit can be contradicted: any 32-byte key verifies as
        # long as the authenticity checks hold.
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, OTHER_KEY))
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_recorded_hits_must_match_the_recomputed_set(self):
        # Dropping a recorded hit or adding one is structurally legal but
        # contradicts what the key recovers.
        self.assertFalse(
            verify_full_encrypted_search_receipt(
                self.rebuild(hits=self.receipt.hits[:-1]), KEY
            )
        )
        self.assertFalse(
            verify_full_encrypted_search_receipt(self.rebuild(hits=(0, 1, 2, 4)), KEY)
        )
        self.assertFalse(
            verify_full_encrypted_search_receipt(self.rebuild(hits=()), KEY)
        )

    def test_plain_and_foreign_entries_are_not_hits(self):
        # Index 1 is a plain entry and index 3 is sealed under OTHER_KEY;
        # recording either as a hit fails verification.
        self.assertFalse(
            verify_full_encrypted_search_receipt(self.rebuild(hits=(0, 1, 2, 4)), KEY)
        )
        self.assertFalse(
            verify_full_encrypted_search_receipt(self.rebuild(hits=(0, 2, 3, 4)), KEY)
        )

    def test_incomplete_coverage_is_rejected(self):
        # Unlike EncryptedSearchReceipt, dropping an entry is a structural
        # failure.
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
            verify_full_encrypted_search_receipt(
                self.rebuild(items=(forged,) + self.receipt.items[1:]), KEY
            )
        )

    def test_tampered_entry_hash_fails(self):
        entry = self.receipt.items[0]
        forged = Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 32)
        self.assertFalse(
            verify_full_encrypted_search_receipt(
                self.rebuild(items=(forged,) + self.receipt.items[1:]), KEY
            )
        )

    def test_tampered_proof_and_root_fail(self):
        # A range covering the whole snapshot carries an empty proof; use a
        # sub-range receipt to exercise proof tampering.
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4)
        bad_proof = (b"\x00" * 32,) + receipt.proof[1:]
        self.assertFalse(
            verify_full_encrypted_search_receipt(
                self.rebuild(
                    start=1, stop=4, items=receipt.items, proof=bad_proof, hits=(2,)
                ),
                KEY,
            )
        )
        self.assertFalse(
            verify_full_encrypted_search_receipt(self.rebuild(root=b"\x00" * 32), KEY)
        )

    def test_wrong_snapshot_root_fails(self):
        other = self.log.full_encrypted_search_receipt("a", KEY, size=4)
        forged = FullEncryptedSearchReceipt(
            other.version,
            other.hash_name,
            other.size,
            self.receipt.root,  # root of the size-5 snapshot, not size 4
            other.query,
            other.start,
            other.stop,
            other.items,
            other.proof,
            other.hits,
        )
        self.assertFalse(verify_full_encrypted_search_receipt(forged, KEY))

    def test_empty_snapshot_root_checked(self):
        snapshot = AuditLog().full_encrypted_search_receipt("a", KEY)
        self.assertTrue(verify_full_encrypted_search_receipt(snapshot, KEY))
        forged = FullEncryptedSearchReceipt(
            1, "sha256", 0, b"\x00" * 32, b"a", 0, 0, (), (), ()
        )
        self.assertFalse(verify_full_encrypted_search_receipt(forged, KEY))

    def test_proof_node_count_checked(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4)
        with self.assertRaises(ValueError):
            verify_full_encrypted_search_receipt(
                self.rebuild(start=1, stop=4, items=receipt.items, proof=(), hits=(2,)),
                KEY,
            )
        with self.assertRaises(ValueError):
            verify_full_encrypted_search_receipt(
                self.rebuild(
                    start=1,
                    stop=4,
                    items=receipt.items,
                    proof=receipt.proof + (b"\x00" * 32,),
                    hits=(2,),
                ),
                KEY,
            )

    def test_verify_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2)):
            with self.assertRaises(TypeError):
                verify_full_encrypted_search_receipt(bad, KEY)
        for bad in (bytearray(KEY), "key", 123, None):
            with self.assertRaises(TypeError):
                verify_full_encrypted_search_receipt(self.receipt, bad)

    def test_verify_key_length_error(self):
        for bad in (b"", KEY[:31], KEY + b"\x00"):
            with self.assertRaises(ValueError):
                verify_full_encrypted_search_receipt(self.receipt, bad)

    def test_verify_revalidates_bypassed_fields(self):
        forged = FullEncryptedSearchReceipt.__new__(FullEncryptedSearchReceipt)
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
            ("hits", self.receipt.hits),
        ):
            object.__setattr__(forged, name, value)
        self.assertTrue(verify_full_encrypted_search_receipt(forged, KEY))
        object.__setattr__(forged, "stop", 4)  # items no longer inside the range
        with self.assertRaises(ValueError):
            verify_full_encrypted_search_receipt(forged, KEY)
        object.__setattr__(forged, "stop", 5)
        object.__setattr__(forged, "hits", (4, 0))  # not ascending
        with self.assertRaises(ValueError):
            verify_full_encrypted_search_receipt(forged, KEY)
        object.__setattr__(forged, "hits", self.receipt.hits)
        object.__setattr__(forged, "query", 123)
        with self.assertRaises(TypeError):
            verify_full_encrypted_search_receipt(forged, KEY)

    def test_alternate_hash(self):
        log = make_log((("enc", "a"), ("plain", "b"), ("enc", "a")), hash_name="sha3-256")
        receipt = log.full_encrypted_search_receipt("a", KEY)
        self.assertEqual(receipt.hash_name, "sha3-256")
        self.assertEqual(receipt.hits, (0, 2))
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))


class FullEncryptedSearchReceiptClassTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.full_encrypted_search_receipt("a", KEY)

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
            hits=self.receipt.hits,
        )
        fields.update(overrides)
        return fields

    def test_positional_construction_and_equality(self):
        other = FullEncryptedSearchReceipt(
            1,
            "sha256",
            self.receipt.size,
            self.receipt.root,
            b"a",
            0,
            5,
            self.receipt.items,
            self.receipt.proof,
            self.receipt.hits,
        )
        self.assertEqual(other, self.receipt)
        self.assertNotEqual(other, self.log.full_encrypted_search_receipt("b", KEY))

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
            ("hits", list(self.receipt.hits)),
            ("hits", (0, "2", 4)),
            ("hits", (0, True, 4)),
        ):
            with self.assertRaises(TypeError, msg=key):
                FullEncryptedSearchReceipt(**self.base(**{key: bad}))

    def test_constructor_binary_fields_must_be_exact_bytes(self):
        first = self.receipt.items[0]
        # root, every Entry binary field and every proof node reject
        # bytearray / memoryview rather than silently copying them.
        with self.assertRaises(TypeError):
            FullEncryptedSearchReceipt(**self.base(root=bytearray(self.receipt.root)))
        with self.assertRaises(TypeError):
            FullEncryptedSearchReceipt(**self.base(root=memoryview(self.receipt.root)))
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
                FullEncryptedSearchReceipt(
                    **self.base(items=(forged,) + self.receipt.items[1:])
                )
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4)
        self.assertTrue(receipt.proof)
        with self.assertRaises(TypeError):
            FullEncryptedSearchReceipt(
                **self.base(
                    start=1,
                    stop=4,
                    items=receipt.items,
                    proof=(bytearray(receipt.proof[0]),) + receipt.proof[1:],
                    hits=(2,),
                )
            )
        with self.assertRaises(TypeError):
            FullEncryptedSearchReceipt(
                **self.base(
                    start=1,
                    stop=4,
                    items=receipt.items,
                    proof=(memoryview(receipt.proof[0]),) + receipt.proof[1:],
                    hits=(2,),
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
                FullEncryptedSearchReceipt(**self.base(**{key: bad}))
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(**self.base(start=3, stop=2))

    def test_constructor_item_structure(self):
        first, second = self.receipt.items[:2]
        # Non-ascending and duplicate indices are rejected.
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(
                **self.base(items=(second, first) + self.receipt.items[2:])
            )
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(
                **self.base(items=(first, first) + self.receipt.items[2:])
            )
        # An index outside the recorded range is rejected.
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(**self.base(stop=4))
        # Incomplete coverage of the range is rejected.
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(**self.base(items=self.receipt.items[:4]))
        # A bad entry field width is rejected.
        forged = Entry(first.index, first.payload, b"\x00" * 16, first.entry_hash)
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(
                **self.base(items=(forged,) + self.receipt.items[1:])
            )
        with self.assertRaises(TypeError):
            FullEncryptedSearchReceipt(
                **self.base(items=((first, None),) + self.receipt.items[1:])
            )

    def test_constructor_proof_structure(self):
        # A non-empty proof on an empty range is rejected.
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(
                **self.base(start=2, stop=2, items=(), proof=(b"\x00" * 32,), hits=())
            )
        # A bad proof element width is rejected.
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4)
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(
                **self.base(
                    start=1,
                    stop=4,
                    items=receipt.items,
                    proof=receipt.proof + (b"\x00" * 16,),
                    hits=(2,),
                )
            )
        with self.assertRaises(TypeError):
            FullEncryptedSearchReceipt(
                **self.base(start=1, stop=4, items=receipt.items, proof=(16,), hits=(2,))
            )

    def test_constructor_hits_structure(self):
        # Hits must be strictly ascending, non-negative and inside the range.
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(**self.base(hits=(2, 0, 4)))
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(**self.base(hits=(0, 2, 2)))
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(**self.base(hits=(-1, 0, 2, 4)))
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(**self.base(hits=(0, 2, 5)))
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(**self.base(start=1, hits=(0,)))
        # An empty range carries no hits.
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 2, 2)
        self.assertEqual(receipt.hits, ())
        with self.assertRaises(ValueError):
            FullEncryptedSearchReceipt(
                **self.base(start=2, stop=2, items=(), proof=(), hits=(2,))
            )


if __name__ == "__main__":
    unittest.main()
