import unittest

from auditchain import (
    AuditLog,
    EncryptedSearchReceipt,
    Entry,
    SearchHitReport,
    SearchReceipt,
    inspect_encrypted_search_receipt,
    inspect_search_receipt,
    verify_encrypted_search_receipt,
    verify_search_receipt,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def make_plain_log(records=("a", "b", "a", "c", "a"), **kwargs):
    log = AuditLog(**kwargs)
    for record in records:
        log.append(record)
    return log


def make_mixed_log(
    records=(
        ("enc", "a"),
        ("plain", "b"),
        ("enc", "a"),
        ("enc", "c"),
        ("enc", "a"),
    ),
    **kwargs,
):
    """Build a mixed log; records are ("enc"|"plain", value)."""
    log = AuditLog(**kwargs)
    nonce_counter = 0
    for kind, value in records:
        if kind == "enc":
            log.encrypt(value, KEY, nonce=bytes([nonce_counter]) * 12)
        else:
            log.append(value)
        nonce_counter += 1
    return log


def rebuild_plain(receipt, **overrides):
    fields = dict(
        version=receipt.version,
        hash_name=receipt.hash_name,
        size=receipt.size,
        root=receipt.root,
        query=receipt.query,
        start=receipt.start,
        stop=receipt.stop,
        items=receipt.items,
    )
    fields.update(overrides)
    return SearchReceipt(**fields)


def rebuild_encrypted(receipt, **overrides):
    fields = dict(
        version=receipt.version,
        hash_name=receipt.hash_name,
        size=receipt.size,
        root=receipt.root,
        query=receipt.query,
        start=receipt.start,
        stop=receipt.stop,
        items=receipt.items,
    )
    fields.update(overrides)
    return EncryptedSearchReceipt(**fields)


def bypass(cls, **fields):
    """Build a receipt skipping the frozen dataclass __post_init__."""
    receipt = cls.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(receipt, name, value)
    return receipt


def with_item(receipt, position, entry=None, proof=None):
    """Rebuild a hit receipt replacing one (entry, proof) pair."""
    old_entry, old_proof = receipt.items[position]
    pair = (
        entry if entry is not None else old_entry,
        proof if proof is not None else old_proof,
    )
    items = receipt.items[:position] + (pair,) + receipt.items[position + 1 :]
    return rebuild_plain(receipt, items=items)


class SearchHitReportTest(unittest.TestCase):
    def test_success_constant(self):
        report = SearchHitReport(True, None, None)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)

    def test_positional_construction_and_equality(self):
        success = SearchHitReport(True, None, None)
        self.assertEqual(success, SearchHitReport(True, None, None))
        failure = SearchHitReport(False, 3, "hit")
        self.assertEqual(failure, SearchHitReport(False, 3, "hit"))
        self.assertNotEqual(failure, SearchHitReport(False, 4, "hit"))
        self.assertNotEqual(failure, SearchHitReport(False, 3, "entry"))
        self.assertNotEqual(success, failure)
        self.assertNotEqual(failure, (False, 3, "hit"))

    def test_report_is_frozen(self):
        with self.assertRaises(Exception):
            SearchHitReport(True, None, None).ok = False

    def test_ok_must_be_bool(self):
        with self.assertRaises(TypeError):
            SearchHitReport(1, None, None)
        with self.assertRaises(TypeError):
            SearchHitReport(0, None, None)

    def test_success_must_carry_neither_code_nor_index(self):
        with self.assertRaises(ValueError):
            SearchHitReport(True, 0, None)
        with self.assertRaises(ValueError):
            SearchHitReport(True, None, "root")
        with self.assertRaises(ValueError):
            SearchHitReport(True, 0, "hit")

    def test_failure_requires_a_known_code(self):
        with self.assertRaises(ValueError):
            SearchHitReport(False, None, None)
        with self.assertRaises(ValueError):
            SearchHitReport(False, 0, None)

    def test_code_type(self):
        with self.assertRaises(TypeError):
            SearchHitReport(False, None, b"hit")
        with self.assertRaises(TypeError):
            SearchHitReport(False, None, 0)

    def test_unknown_code_rejected(self):
        for code in ("verify", "", "hits", "last", "HIT"):
            with self.assertRaises(ValueError):
                SearchHitReport(False, None, code)

    def test_each_known_code_accepted_without_position(self):
        for code in ("root", "entry", "proof", "hit"):
            report = SearchHitReport(False, None, code)
            self.assertEqual(report.code, code)
            self.assertIsNone(report.index)

    def test_index_must_be_integer_or_none(self):
        with self.assertRaises(TypeError):
            SearchHitReport(False, 1.0, "entry")
        with self.assertRaises(TypeError):
            SearchHitReport(False, "1", "entry")
        with self.assertRaises(TypeError):
            SearchHitReport(False, True, "entry")

    def test_negative_index_rejected(self):
        with self.assertRaises(ValueError):
            SearchHitReport(False, -1, "entry")


class InspectSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_plain_log()

    def test_genuine_receipts_report_success(self):
        cases = [
            self.log.search_receipt("a"),
            self.log.search_receipt("missing"),
            self.log.search_receipt("a", 1, 3),
            self.log.search_receipt("a", 1, 3, size=3),
            self.log.search_receipt("a", 2, 2),
            AuditLog().search_receipt("a"),
        ]
        for receipt in cases:
            self.assertEqual(
                inspect_search_receipt(receipt),
                SearchHitReport(True, None, None),
                receipt,
            )
            self.assertEqual(report_ok(receipt), verify_search_receipt(receipt))

    def test_empty_snapshot_reports_success_even_with_bogus_root(self):
        # A zero-item receipt attests no content; the recorded root never
        # participates, so verify_search_receipt returns True here too.
        empty = AuditLog().search_receipt("a")
        forged = rebuild_plain(empty, root=b"\x00" * 32)
        self.assertTrue(verify_search_receipt(forged))
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(True, None, None)
        )

    def test_empty_range_of_nonempty_snapshot_carries_no_evidence(self):
        receipt = self.log.search_receipt("missing", 2, 2)
        forged = rebuild_plain(receipt, root=b"\x00" * 32)
        self.assertTrue(verify_search_receipt(forged))
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(True, None, None)
        )

    def test_tampered_payload_reports_entry_at_index(self):
        receipt = self.log.search_receipt("a")  # hits 0, 2, 4
        entry, proof = receipt.items[1]
        tampered = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        forged = with_item(receipt, 1, entry=tampered)
        self.assertEqual(
            inspect_search_receipt(forged),
            SearchHitReport(False, 2, "entry"),
        )
        self.assertFalse(verify_search_receipt(forged))

    def test_tampered_entry_hash_reports_entry_at_index(self):
        receipt = self.log.search_receipt("a", 0, 3)  # hits 0, 2
        entry, proof = receipt.items[0]
        tampered = Entry(
            entry.index, entry.payload, entry.previous_hash, b"\x00" * 32
        )
        forged = with_item(receipt, 0, entry=tampered)
        self.assertEqual(
            inspect_search_receipt(forged),
            SearchHitReport(False, 0, "entry"),
        )

    def test_wrong_proof_nodes_report_proof_at_index(self):
        receipt = self.log.search_receipt("a", 0, 3)  # hits 0, 2
        entry, proof = receipt.items[0]
        self.assertTrue(proof)
        forged = with_item(receipt, 0, proof=(b"\x00" * 32,) + proof[1:])
        self.assertEqual(
            inspect_search_receipt(forged),
            SearchHitReport(False, 0, "proof"),
        )
        self.assertFalse(verify_search_receipt(forged))

    def test_wrong_root_reports_proof_at_first_listed_index(self):
        receipt = self.log.search_receipt("a", 1, 4)  # hits 2
        forged = rebuild_plain(receipt, root=b"\x00" * 32)
        self.assertEqual(
            inspect_search_receipt(forged),
            SearchHitReport(False, 2, "proof"),
        )
        self.assertFalse(verify_search_receipt(forged))

    def test_genuine_non_hit_entry_reports_hit_at_index(self):
        # The entry at index 1 genuinely holds b"b" with its real proof, but
        # the receipt claims the query b"a".
        receipt = self.log.search_receipt("a")
        entry = self.log.entry(1)
        proof = self.log.inclusion_proof(1, 5)
        forged = SearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            b"a",
            0,
            5,
            ((entry, proof),),
        )
        self.assertEqual(
            inspect_search_receipt(forged),
            SearchHitReport(False, 1, "hit"),
        )
        self.assertFalse(verify_search_receipt(forged))

    def test_wrong_query_field_reports_hit(self):
        receipt = self.log.search_receipt("a")
        forged = rebuild_plain(receipt, query=b"a\x00")
        self.assertEqual(
            inspect_search_receipt(forged),
            SearchHitReport(False, 0, "hit"),
        )

    def test_entry_check_precedes_proof_and_hit_checks(self):
        receipt = self.log.search_receipt("a")
        entry, proof = receipt.items[0]
        tampered = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        forged = with_item(
            receipt,
            0,
            entry=tampered,
            proof=(b"\x00" * 32,) + proof[1:],
        )
        forged = rebuild_plain(forged, root=b"\x00" * 32, query=b"qq")
        self.assertEqual(
            inspect_search_receipt(forged),
            SearchHitReport(False, 0, "entry"),
        )

    def test_proof_check_precedes_hit_check(self):
        # A genuine b"b" entry (a real non-hit) with a broken proof and a
        # mismatching query: proof must be reported before hit.
        entry = self.log.entry(1)
        proof = tuple(b"\x00" * 32 for _ in self.log.inclusion_proof(1, 5))
        receipt = self.log.search_receipt("a")
        forged = SearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            b"qq",
            0,
            5,
            ((entry, proof),),
        )
        self.assertEqual(
            inspect_search_receipt(forged),
            SearchHitReport(False, 1, "proof"),
        )

    def test_only_first_false_hit_is_reported(self):
        receipt = self.log.search_receipt("a")  # hits 0, 2, 4
        tampered_items = []
        for position, (entry, proof) in enumerate(receipt.items):
            if position in (1, 2):
                tampered_items.append(
                    (
                        Entry(
                            entry.index,
                            b"tampered",
                            entry.previous_hash,
                            entry.entry_hash,
                        ),
                        proof,
                    )
                )
            else:
                tampered_items.append((entry, proof))
        forged = rebuild_plain(receipt, items=tuple(tampered_items))
        self.assertEqual(
            inspect_search_receipt(forged),
            SearchHitReport(False, 2, "entry"),
        )

    def test_proof_structure_errors_propagate(self):
        receipt = self.log.search_receipt("a", 0, 3)
        entry, proof = receipt.items[0]
        short = with_item(receipt, 0, proof=proof[:-1])
        long = with_item(receipt, 0, proof=proof + (b"\x00" * 32,))
        for forged in (short, long):
            with self.assertRaises(ValueError):
                inspect_search_receipt(forged)
            with self.assertRaises(ValueError):
                verify_search_receipt(forged)

    def test_not_a_receipt_raises_type_error(self):
        other = make_mixed_log().encrypted_search_receipt("a", KEY)
        for bad in (None, (), 42, b"", other):
            with self.assertRaises(TypeError):
                inspect_search_receipt(bad)

    def test_bypassed_structural_corruption_mirrors_verifier(self):
        base = self.log.search_receipt("a", 0, 2)
        wrong_hash = bypass(
            SearchReceipt,
            version=1,
            hash_name="nope",
            size=base.size,
            root=base.root,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
        )
        narrow_root = bypass(
            SearchReceipt,
            version=1,
            hash_name="sha256",
            size=base.size,
            root=b"\x00" * 16,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
        )
        wrong_version = bypass(
            SearchReceipt,
            version=2,
            hash_name=base.hash_name,
            size=base.size,
            root=base.root,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
        )
        for forged in (wrong_hash, narrow_root, wrong_version):
            with self.assertRaises(ValueError):
                verify_search_receipt(forged)
            with self.assertRaises(ValueError):
                inspect_search_receipt(forged)

    def test_alternate_hash_algorithm(self):
        log = make_plain_log(hash_name="sha3-256")
        receipt = log.search_receipt("a")
        self.assertEqual(
            inspect_search_receipt(receipt), SearchHitReport(True, None, None)
        )
        forged = rebuild_plain(receipt, hash_name="sha256")
        # The first listed entry's digest under sha256 no longer matches.
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(False, 0, "entry")
        )
        self.assertEqual(
            inspect_search_receipt(forged).ok, verify_search_receipt(forged)
        )

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.search_receipt("a", 1, 4)
        before = receipt
        first = inspect_search_receipt(receipt)
        second = inspect_search_receipt(receipt)
        self.assertEqual(first, second)
        self.assertEqual(receipt, before)

    def test_report_ok_matches_verifier_across_ranges_and_sizes(self):
        for size in range(0, 6):
            for start in range(0, size + 1):
                for stop in range(start, size + 1):
                    for query in ("a", "missing"):
                        receipt = self.log.search_receipt(
                            query, start, stop, size=size
                        )
                        self.assertEqual(
                            inspect_search_receipt(receipt).ok,
                            verify_search_receipt(receipt),
                            (size, start, stop, query),
                        )


def report_ok(receipt):
    return inspect_search_receipt(receipt).ok


class InspectEncryptedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_mixed_log()
        self.receipt = self.log.encrypted_search_receipt("a", KEY)  # hits 0,2,4

    def test_genuine_receipts_report_success(self):
        cases = [
            (self.log.encrypted_search_receipt("a", KEY), KEY),
            (self.log.encrypted_search_receipt("missing", KEY), KEY),
            (self.log.encrypted_search_receipt("a", KEY, 1, 3), KEY),
            (self.log.encrypted_search_receipt("a", KEY, 1, 3, size=3), KEY),
            (self.log.encrypted_search_receipt("a", KEY, 2, 2), KEY),
            (AuditLog().encrypted_search_receipt("a", KEY), KEY),
        ]
        for receipt, key in cases:
            self.assertEqual(
                inspect_encrypted_search_receipt(receipt, key),
                SearchHitReport(True, None, None),
                (receipt, key),
            )
            self.assertEqual(
                inspect_encrypted_search_receipt(receipt, key).ok,
                verify_encrypted_search_receipt(receipt, key),
            )

    def test_wrong_key_reports_hit_at_first_listed_index(self):
        self.assertEqual(
            inspect_encrypted_search_receipt(self.receipt, OTHER_KEY),
            SearchHitReport(False, 0, "hit"),
        )
        self.assertFalse(
            verify_encrypted_search_receipt(self.receipt, OTHER_KEY)
        )

    def test_zero_item_receipt_does_not_exercise_key(self):
        empty = AuditLog().encrypted_search_receipt("a", KEY)
        no_hits = self.log.encrypted_search_receipt("missing", KEY)
        for receipt in (empty, no_hits):
            for bogus_root in (receipt.root, b"\x00" * 32):
                forged = rebuild_encrypted(receipt, root=bogus_root)
                for key in (KEY, OTHER_KEY, b"\x00" * 32):
                    self.assertTrue(
                        verify_encrypted_search_receipt(forged, key),
                        (receipt, key),
                    )
                    self.assertEqual(
                        inspect_encrypted_search_receipt(forged, key),
                        SearchHitReport(True, None, None),
                    )

    def test_plain_entry_listed_as_hit_reports_hit(self):
        # Index 1 holds a plain b"b" entry; listing it (with its genuine
        # proof) as a hit cannot unseal and is a false hit, not an error.
        entry = self.log.entry(1)
        proof = self.log.inclusion_proof(1, 5)
        forged = EncryptedSearchReceipt(
            self.receipt.version,
            self.receipt.hash_name,
            5,
            self.receipt.root,
            b"b",
            0,
            5,
            ((entry, proof),),
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY),
            SearchHitReport(False, 1, "hit"),
        )
        self.assertFalse(verify_encrypted_search_receipt(forged, KEY))

    def test_foreign_key_envelope_listed_as_hit_reports_hit(self):
        log = AuditLog()
        log.encrypt("a", OTHER_KEY, nonce=b"\x00" * 12)
        entry = log.entry(0)
        proof = log.inclusion_proof(0, 1)
        forged = EncryptedSearchReceipt(
            1, "sha256", 1, log.merkle_root(1), b"a", 0, 1, ((entry, proof),)
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY),
            SearchHitReport(False, 0, "hit"),
        )
        self.assertFalse(verify_encrypted_search_receipt(forged, KEY))
        # The owning key, of course, verifies the same genuine receipt.
        self.assertTrue(verify_encrypted_search_receipt(forged, OTHER_KEY))

    def test_recovered_plaintext_differing_reports_hit(self):
        # Genuine envelope of "c", receipt claiming query "a".
        entry = self.log.entry(3)
        proof = self.log.inclusion_proof(3, 5)
        forged = EncryptedSearchReceipt(
            self.receipt.version,
            self.receipt.hash_name,
            5,
            self.receipt.root,
            b"a",
            0,
            5,
            ((entry, proof),),
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY),
            SearchHitReport(False, 3, "hit"),
        )
        self.assertFalse(verify_encrypted_search_receipt(forged, KEY))

    def test_tampered_payload_reports_entry_before_decryption(self):
        entry, proof = self.receipt.items[0]
        tampered = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        forged = rebuild_encrypted(
            self.receipt, items=((tampered, proof),) + self.receipt.items[1:]
        )
        # Fails as "entry" even under the correct key, which would otherwise
        # unseal successfully.
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY),
            SearchHitReport(False, 0, "entry"),
        )
        self.assertFalse(verify_encrypted_search_receipt(forged, KEY))

    def test_wrong_proof_reports_proof_before_decryption(self):
        entry, proof = self.receipt.items[0]
        self.assertTrue(proof)
        forged = rebuild_encrypted(
            self.receipt,
            items=((entry, (b"\x00" * 32,) + proof[1:]),)
            + self.receipt.items[1:],
        )
        # Wrong key would make the content check fail too; proof is earlier.
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, OTHER_KEY),
            SearchHitReport(False, 0, "proof"),
        )
        self.assertFalse(verify_encrypted_search_receipt(forged, OTHER_KEY))

    def test_wrong_root_reports_proof_at_first_listed_index(self):
        receipt = self.log.encrypted_search_receipt("a", KEY, 1, 4)  # hit 2
        forged = rebuild_encrypted(receipt, root=b"\x00" * 32)
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY),
            SearchHitReport(False, 2, "proof"),
        )

    def test_entry_precedes_proof_precedes_hit(self):
        entry, proof = self.receipt.items[0]
        tampered = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        forged = rebuild_encrypted(
            self.receipt,
            root=b"\x00" * 32,
            items=(
                (tampered, (b"\x00" * 32,) + proof[1:]),
            )
            + self.receipt.items[1:],
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, OTHER_KEY),
            SearchHitReport(False, 0, "entry"),
        )

    def test_only_first_false_hit_is_reported(self):
        # Wrong key fails every unsealing; only the first listed index is
        # reported.
        self.assertEqual(
            inspect_encrypted_search_receipt(self.receipt, OTHER_KEY),
            SearchHitReport(False, 0, "hit"),
        )

    def test_proof_structure_errors_propagate(self):
        entry, proof = self.receipt.items[0]
        short = rebuild_encrypted(
            self.receipt,
            items=((entry, proof[:-1]),) + self.receipt.items[1:],
        )
        long = rebuild_encrypted(
            self.receipt,
            items=((entry, proof + (b"\x00" * 32,)),)
            + self.receipt.items[1:],
        )
        for forged in (short, long):
            with self.assertRaises(ValueError):
                inspect_encrypted_search_receipt(forged, KEY)
            with self.assertRaises(ValueError):
                verify_encrypted_search_receipt(forged, KEY)

    def test_not_a_receipt_raises_type_error(self):
        plain = self.log.search_receipt("a")
        for bad in (None, (), 42, b"", plain):
            with self.assertRaises(TypeError):
                inspect_encrypted_search_receipt(bad, KEY)

    def test_key_type_and_length(self):
        for bad_key in ("k", None, 32, bytearray(32)):
            with self.assertRaises(TypeError):
                inspect_encrypted_search_receipt(self.receipt, bad_key)
            with self.assertRaises(TypeError):
                verify_encrypted_search_receipt(self.receipt, bad_key)
        for bad_key in (b"", b"\x00" * 16, b"\x00" * 33):
            with self.assertRaises(ValueError):
                inspect_encrypted_search_receipt(self.receipt, bad_key)
            with self.assertRaises(ValueError):
                verify_encrypted_search_receipt(self.receipt, bad_key)

    def test_bypassed_structural_corruption_mirrors_verifier(self):
        base = self.receipt
        wrong_hash = bypass(
            EncryptedSearchReceipt,
            version=1,
            hash_name="nope",
            size=base.size,
            root=base.root,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
        )
        narrow_root = bypass(
            EncryptedSearchReceipt,
            version=1,
            hash_name="sha256",
            size=base.size,
            root=b"\x00" * 16,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
        )
        for forged in (wrong_hash, narrow_root):
            with self.assertRaises(ValueError):
                verify_encrypted_search_receipt(forged, KEY)
            with self.assertRaises(ValueError):
                inspect_encrypted_search_receipt(forged, KEY)

    def test_alternate_hash_algorithm(self):
        log = make_mixed_log(hash_name="sha3-256")
        receipt = log.encrypted_search_receipt("a", KEY)
        self.assertEqual(
            inspect_encrypted_search_receipt(receipt, KEY),
            SearchHitReport(True, None, None),
        )
        forged = rebuild_encrypted(receipt, hash_name="sha256")
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY),
            SearchHitReport(False, 0, "entry"),
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY).ok,
            verify_encrypted_search_receipt(forged, KEY),
        )

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.encrypted_search_receipt("a", KEY, 1, 4)
        before = receipt
        first = inspect_encrypted_search_receipt(receipt, KEY)
        second = inspect_encrypted_search_receipt(receipt, KEY)
        self.assertEqual(first, second)
        self.assertEqual(receipt, before)

    def test_report_ok_matches_verifier_across_ranges_sizes_and_keys(self):
        for size in range(0, 6):
            for start in range(0, size + 1):
                for stop in range(start, size + 1):
                    for query in ("a", "missing"):
                        receipt = self.log.encrypted_search_receipt(
                            query, KEY, start, stop, size=size
                        )
                        for key in (KEY, OTHER_KEY):
                            self.assertEqual(
                                inspect_encrypted_search_receipt(
                                    receipt, key
                                ).ok,
                                verify_encrypted_search_receipt(receipt, key),
                                (size, start, stop, query, key == KEY),
                            )


if __name__ == "__main__":
    unittest.main()
