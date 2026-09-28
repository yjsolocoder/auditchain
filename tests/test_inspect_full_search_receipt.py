import itertools
import unittest

from auditchain import (
    AuditLog,
    Entry,
    FullEncryptedSearchReceipt,
    FullSearchReceipt,
    SearchReceiptReport,
    inspect_full_encrypted_search_receipt,
    inspect_full_search_receipt,
    verify_full_encrypted_search_receipt,
    verify_full_search_receipt,
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
        proof=receipt.proof,
    )
    fields.update(overrides)
    return FullSearchReceipt(**fields)


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
        proof=receipt.proof,
        hits=receipt.hits,
    )
    fields.update(overrides)
    return FullEncryptedSearchReceipt(**fields)


def bypass_plain(receipt, **fields):
    """Build a FullSearchReceipt skipping __post_init__ validation."""
    forged = FullSearchReceipt.__new__(FullSearchReceipt)
    defaults = dict(
        version=receipt.version,
        hash_name=receipt.hash_name,
        size=receipt.size,
        root=receipt.root,
        query=receipt.query,
        start=receipt.start,
        stop=receipt.stop,
        items=receipt.items,
        proof=receipt.proof,
    )
    defaults.update(fields)
    for name, value in defaults.items():
        object.__setattr__(forged, name, value)
    return forged


class SearchReceiptReportTest(unittest.TestCase):
    def test_success_constant(self):
        report = SearchReceiptReport(True, None, None)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)

    def test_positional_construction_and_equality(self):
        success = SearchReceiptReport(True, None, None)
        self.assertEqual(success, SearchReceiptReport(True, None, None))
        failure = SearchReceiptReport(False, 3, "entry")
        self.assertEqual(failure, SearchReceiptReport(False, 3, "entry"))
        self.assertNotEqual(failure, SearchReceiptReport(False, 4, "entry"))
        self.assertNotEqual(failure, SearchReceiptReport(False, 3, "proof"))
        self.assertNotEqual(success, failure)
        self.assertNotEqual(failure, (False, 3, "entry"))

    def test_report_is_frozen(self):
        report = SearchReceiptReport(True, None, None)
        with self.assertRaises(Exception):
            report.ok = False

    def test_ok_must_be_bool(self):
        with self.assertRaises(TypeError):
            SearchReceiptReport(1, None, None)
        with self.assertRaises(TypeError):
            SearchReceiptReport(0, None, None)

    def test_success_must_carry_neither_code_nor_index(self):
        with self.assertRaises(ValueError):
            SearchReceiptReport(True, 0, None)
        with self.assertRaises(ValueError):
            SearchReceiptReport(True, None, "root")
        with self.assertRaises(ValueError):
            SearchReceiptReport(True, 0, "entry")

    def test_failure_requires_a_known_code(self):
        with self.assertRaises(ValueError):
            SearchReceiptReport(False, None, None)
        with self.assertRaises(ValueError):
            SearchReceiptReport(False, 0, None)

    def test_code_type(self):
        with self.assertRaises(TypeError):
            SearchReceiptReport(False, None, b"entry")
        with self.assertRaises(TypeError):
            SearchReceiptReport(False, None, 0)

    def test_unknown_code_rejected(self):
        with self.assertRaises(ValueError):
            SearchReceiptReport(False, None, "last")
        with self.assertRaises(ValueError):
            SearchReceiptReport(False, None, "verify")
        with self.assertRaises(ValueError):
            SearchReceiptReport(False, None, "")

    def test_each_known_code_accepted_without_position(self):
        for code in ("root", "entry", "proof", "hits"):
            report = SearchReceiptReport(False, None, code)
            self.assertEqual(report.code, code)
            self.assertIsNone(report.index)

    def test_index_must_be_integer_or_none(self):
        with self.assertRaises(TypeError):
            SearchReceiptReport(False, 1.0, "entry")
        with self.assertRaises(TypeError):
            SearchReceiptReport(False, "1", "entry")
        with self.assertRaises(TypeError):
            SearchReceiptReport(False, True, "entry")

    def test_negative_index_rejected(self):
        with self.assertRaises(ValueError):
            SearchReceiptReport(False, -1, "entry")


class InspectFullSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_plain_log()

    def test_genuine_receipts_report_success(self):
        cases = [
            ("a", None, None, None),
            ("missing", None, None, None),
            ("a", 1, 4, None),
            ("a", 2, 2, None),
            ("a", None, None, 3),
            ("a", 0, 0, None),
        ]
        for query, start, stop, size in cases:
            receipt = self.log.full_search_receipt(query, start, stop, size)
            self.assertEqual(
                inspect_full_search_receipt(receipt),
                SearchReceiptReport(True, None, None),
                (query, start, stop, size),
            )

    def test_empty_snapshot_genuine(self):
        receipt = AuditLog().full_search_receipt("a")
        self.assertEqual(
            inspect_full_search_receipt(receipt),
            SearchReceiptReport(True, None, None),
        )

    def test_ok_corresponds_to_verifier_truth(self):
        for query, start, stop, size in (
            ("a", None, None, None),
            ("missing", None, None, None),
            ("a", 1, 4, None),
            ("a", 2, 2, None),
            ("a", None, None, 3),
        ):
            receipt = self.log.full_search_receipt(query, start, stop, size)
            self.assertEqual(
                inspect_full_search_receipt(receipt).ok,
                verify_full_search_receipt(receipt),
            )

    def test_empty_snapshot_wrong_root_reports_root(self):
        forged = FullSearchReceipt(
            1, "sha256", 0, b"\x00" * 32, b"a", 0, 0, (), ()
        )
        report = inspect_full_search_receipt(forged)
        self.assertEqual(report, SearchReceiptReport(False, None, "root"))
        self.assertEqual(report.ok, verify_full_search_receipt(forged))

    def test_pure_empty_range_records_no_evidence_and_succeeds(self):
        # size > 0, empty range: the recorded root is not compared.
        receipt = self.log.full_search_receipt("a", 2, 2)
        forged = rebuild_plain(receipt, root=b"\x00" * 32)
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(True, None, None),
        )
        self.assertTrue(verify_full_search_receipt(forged))

    def test_tampered_payload_reports_entry_at_index(self):
        receipt = self.log.full_search_receipt("a")
        entry = receipt.items[1]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = rebuild_plain(
            receipt, items=receipt.items[:1] + (tampered,) + receipt.items[2:]
        )
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, 1, "entry"),
        )
        self.assertFalse(verify_full_search_receipt(forged))

    def test_tampered_entry_hash_reports_entry_at_index(self):
        receipt = self.log.full_search_receipt("a")
        entry = receipt.items[3]
        tampered = Entry(
            entry.index, entry.payload, entry.previous_hash, b"\x00" * 32
        )
        forged = rebuild_plain(
            receipt, items=receipt.items[:3] + (tampered,) + receipt.items[4:]
        )
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, 3, "entry"),
        )

    def test_only_first_tampered_entry_is_reported(self):
        receipt = self.log.full_search_receipt("a")
        tampered = []
        for entry in receipt.items:
            if entry.index in (1, 4):
                tampered.append(
                    Entry(
                        entry.index,
                        b"tampered",
                        entry.previous_hash,
                        entry.entry_hash,
                    )
                )
            else:
                tampered.append(entry)
        forged = rebuild_plain(receipt, items=tuple(tampered))
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, 1, "entry"),
        )

    def test_wrong_root_reports_shared_proof_without_position(self):
        receipt = self.log.full_search_receipt("a")
        forged = rebuild_plain(receipt, root=b"\x00" * 32)
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, None, "proof"),
        )
        self.assertFalse(verify_full_search_receipt(forged))

    def test_wrong_proof_node_reports_shared_proof_without_position(self):
        receipt = self.log.full_search_receipt("a", 1, 4)
        bad_proof = (b"\x00" * 32,) + receipt.proof[1:]
        forged = rebuild_plain(receipt, proof=bad_proof)
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, None, "proof"),
        )
        self.assertFalse(verify_full_search_receipt(forged))

    def test_entry_mismatch_precedes_proof_check(self):
        receipt = self.log.full_search_receipt("a", 1, 4)
        entry = receipt.items[0]
        tampered = Entry(entry.index, b"zz", entry.previous_hash, entry.entry_hash)
        bad_proof = (b"\x00" * 32,) + receipt.proof[1:]
        forged = rebuild_plain(
            receipt,
            items=(tampered,) + receipt.items[1:],
            proof=bad_proof,
        )
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, entry.index, "entry"),
        )

    def test_root_check_runs_first_for_evidence_less_snapshot(self):
        # size == 0 with a wrong root reports "root" before anything else.
        wrong_root = FullSearchReceipt(
            1, "sha256", 0, b"\x00" * 32, b"a", 0, 0, (), ()
        )
        self.assertEqual(
            inspect_full_search_receipt(wrong_root),
            SearchReceiptReport(False, None, "root"),
        )
        # A bypassed size == 0 receipt that nonetheless carries an item is
        # structurally impossible past re-validation (its range cannot cover
        # the item), so both entry points raise ValueError identically
        # before the empty-root examination is reached.
        entry = self.log.entry(0)
        forged = bypass_plain(
            self.log.full_search_receipt("a"),
            size=0,
            root=b"\x00" * 32,
            start=0,
            stop=1,
            items=(entry,),
            proof=(),
        )
        with self.assertRaises(ValueError):
            verify_full_search_receipt(forged)
        with self.assertRaises(ValueError):
            inspect_full_search_receipt(forged)

    def test_proof_node_count_error_propagates(self):
        receipt = self.log.full_search_receipt("a", 1, 4)
        for bad_proof in ((), receipt.proof + (b"\x00" * 32,)):
            forged = rebuild_plain(receipt, proof=bad_proof)
            with self.assertRaises(ValueError):
                inspect_full_search_receipt(forged)
            with self.assertRaises(ValueError):
                verify_full_search_receipt(forged)

    def test_not_a_receipt_raises_type_error(self):
        for bad in (None, (), ("not", "a", "receipt"), 42, b"", self.log):
            with self.assertRaises(TypeError):
                inspect_full_search_receipt(bad)

    def test_bypassed_structural_corruption_mirrors_verifier(self):
        receipt = self.log.full_search_receipt("a")
        wrong_hash = bypass_plain(receipt, hash_name="nope")
        with self.assertRaises(ValueError):
            verify_full_search_receipt(wrong_hash)
        with self.assertRaises(ValueError):
            inspect_full_search_receipt(wrong_hash)

        wrong_version = bypass_plain(receipt, version=2)
        with self.assertRaises(ValueError):
            verify_full_search_receipt(wrong_version)
        with self.assertRaises(ValueError):
            inspect_full_search_receipt(wrong_version)

        wrong_query_type = bypass_plain(receipt, query=123)
        with self.assertRaises(TypeError):
            verify_full_search_receipt(wrong_query_type)
        with self.assertRaises(TypeError):
            inspect_full_search_receipt(wrong_query_type)

        incomplete = bypass_plain(receipt, stop=4, items=receipt.items[:4])
        with self.assertRaises(ValueError):
            verify_full_search_receipt(incomplete)
        with self.assertRaises(ValueError):
            inspect_full_search_receipt(incomplete)

    def test_alternate_hash_algorithm(self):
        log = make_plain_log(("a", "b", "a"), hash_name="sha3-256")
        receipt = log.full_search_receipt("a")
        self.assertEqual(
            inspect_full_search_receipt(receipt),
            SearchReceiptReport(True, None, None),
        )
        forged = rebuild_plain(receipt, hash_name="sha256")
        report = inspect_full_search_receipt(forged)
        self.assertEqual(report, SearchReceiptReport(False, 0, "entry"))
        self.assertEqual(report.ok, verify_full_search_receipt(forged))

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.full_search_receipt("a")
        before = receipt
        first = inspect_full_search_receipt(receipt)
        second = inspect_full_search_receipt(receipt)
        self.assertEqual(first, second)
        self.assertEqual(receipt, before)

    def test_success_across_sizes_ranges_and_subsets(self):
        for size in range(0, 6):
            for start in range(0, size + 1):
                for stop in range(start, size + 1):
                    receipt = self.log.full_search_receipt(
                        "a", start, stop, size=size
                    )
                    self.assertTrue(
                        verify_full_search_receipt(receipt), (size, start, stop)
                    )
                    self.assertEqual(
                        inspect_full_search_receipt(receipt),
                        SearchReceiptReport(True, None, None),
                        (size, start, stop),
                    )


class InspectFullEncryptedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_mixed_log()

    def test_genuine_receipts_report_success(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        self.assertEqual(
            inspect_full_encrypted_search_receipt(receipt, KEY),
            SearchReceiptReport(True, None, None),
        )
        for query, start, stop, size in (
            ("missing", None, None, None),
            ("a", 1, 4, None),
            ("a", 2, 2, None),
            ("a", None, None, 3),
        ):
            forged = self.log.full_encrypted_search_receipt(
                query, KEY, start, stop, size
            )
            self.assertEqual(
                inspect_full_encrypted_search_receipt(forged, KEY),
                SearchReceiptReport(True, None, None),
                (query, start, stop, size),
            )

    def test_empty_snapshot_genuine(self):
        receipt = AuditLog().full_encrypted_search_receipt("a", KEY)
        self.assertEqual(
            inspect_full_encrypted_search_receipt(receipt, KEY),
            SearchReceiptReport(True, None, None),
        )

    def test_ok_corresponds_to_verifier_truth(self):
        for query, key in (
            ("a", KEY),
            ("a", OTHER_KEY),
            ("missing", KEY),
            ("missing", OTHER_KEY),
        ):
            receipt = self.log.full_encrypted_search_receipt(query, KEY)
            self.assertEqual(
                inspect_full_encrypted_search_receipt(receipt, key).ok,
                verify_full_encrypted_search_receipt(receipt, key),
                (query, key == KEY),
            )

    def test_empty_snapshot_wrong_root_reports_root(self):
        forged = FullEncryptedSearchReceipt(
            1, "sha256", 0, b"\x00" * 32, b"a", 0, 0, (), (), ()
        )
        report = inspect_full_encrypted_search_receipt(forged, KEY)
        self.assertEqual(report, SearchReceiptReport(False, None, "root"))
        self.assertEqual(
            report.ok, verify_full_encrypted_search_receipt(forged, KEY)
        )

    def test_pure_empty_range_records_no_evidence_and_succeeds_under_any_key(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 3, 3)
        forged = rebuild_encrypted(receipt, root=b"\x00" * 32)
        for key in (KEY, OTHER_KEY, b"\x00" * 32):
            self.assertEqual(
                inspect_full_encrypted_search_receipt(forged, key),
                SearchReceiptReport(True, None, None),
            )
            self.assertTrue(
                verify_full_encrypted_search_receipt(forged, key)
            )

    def test_wrong_key_recording_hits_reports_hits_at_first_index(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        report = inspect_full_encrypted_search_receipt(receipt, OTHER_KEY)
        # Nothing unseals to the query, so the recorded hit set disagrees
        # first at its lowest recorded index.
        self.assertEqual(report, SearchReceiptReport(False, 0, "hits"))
        self.assertFalse(
            verify_full_encrypted_search_receipt(receipt, OTHER_KEY)
        )

    def test_zero_hit_receipt_does_not_exercise_the_key(self):
        receipt = self.log.full_encrypted_search_receipt("missing", KEY)
        self.assertEqual(receipt.hits, ())
        self.assertEqual(
            inspect_full_encrypted_search_receipt(receipt, OTHER_KEY),
            SearchReceiptReport(True, None, None),
        )
        self.assertTrue(
            verify_full_encrypted_search_receipt(receipt, OTHER_KEY)
        )

    def test_dropped_recorded_hit_reports_hits_at_missing_index(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        forged = rebuild_encrypted(receipt, hits=(0, 2))
        report = inspect_full_encrypted_search_receipt(forged, KEY)
        self.assertEqual(report, SearchReceiptReport(False, 4, "hits"))
        self.assertFalse(verify_full_encrypted_search_receipt(forged, KEY))

    def test_forged_recorded_hit_reports_hits_at_forged_index(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        # Index 3 holds ciphertext for "c"; claiming it hits disagrees first
        # at index 3.
        forged = rebuild_encrypted(receipt, hits=(0, 2, 3, 4))
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, 3, "hits"),
        )

    def test_swapped_hit_at_lowest_index_reported(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        forged = rebuild_encrypted(receipt, hits=(1, 2, 4))
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, 0, "hits"),
        )

    def test_tampered_payload_reports_entry_at_index(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        entry = receipt.items[2]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = rebuild_encrypted(
            receipt, items=receipt.items[:2] + (tampered,) + receipt.items[3:]
        )
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, 2, "entry"),
        )

    def test_wrong_root_and_proof_report_shared_proof_without_position(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        wrong_root = rebuild_encrypted(receipt, root=b"\x00" * 32)
        self.assertEqual(
            inspect_full_encrypted_search_receipt(wrong_root, KEY),
            SearchReceiptReport(False, None, "proof"),
        )
        sub = self.log.full_encrypted_search_receipt("a", KEY, 1, 4)
        bad_proof = (b"\x00" * 32,) + sub.proof[1:]
        wrong_proof = rebuild_encrypted(sub, proof=bad_proof)
        self.assertEqual(
            inspect_full_encrypted_search_receipt(wrong_proof, KEY),
            SearchReceiptReport(False, None, "proof"),
        )

    def test_entry_mismatch_precedes_proof_and_hits(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4)
        entry = receipt.items[0]
        tampered = Entry(entry.index, b"zz", entry.previous_hash, entry.entry_hash)
        forged = rebuild_encrypted(
            receipt,
            items=(tampered,) + receipt.items[1:],
            proof=(b"\x00" * 32,) + receipt.proof[1:],
            hits=(),
        )
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, entry.index, "entry"),
        )

    def test_proof_mismatch_precedes_hits_mismatch(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4)
        forged = rebuild_encrypted(
            receipt,
            proof=(b"\x00" * 32,) + receipt.proof[1:],
            hits=(),
        )
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, None, "proof"),
        )

    def test_root_precedes_everything_on_empty_snapshot(self):
        forged = FullEncryptedSearchReceipt(
            1, "sha256", 0, b"\x00" * 32, b"a", 0, 0, (), (), ()
        )
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, None, "root"),
        )

    def test_proof_node_count_error_propagates(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4)
        for bad_proof in ((), receipt.proof + (b"\x00" * 32,)):
            forged = rebuild_encrypted(receipt, proof=bad_proof)
            with self.assertRaises(ValueError):
                inspect_full_encrypted_search_receipt(forged, KEY)
            with self.assertRaises(ValueError):
                verify_full_encrypted_search_receipt(forged, KEY)

    def test_incomplete_coverage_and_bad_hits_propagate(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        with self.assertRaises(ValueError):
            rebuild_encrypted(receipt, items=receipt.items[:4])
        with self.assertRaises(ValueError):
            rebuild_encrypted(receipt, hits=(4, 2, 0))
        with self.assertRaises(ValueError):
            rebuild_encrypted(receipt, hits=(0, 0, 2))
        with self.assertRaises(ValueError):
            rebuild_encrypted(receipt, hits=(5,))

    def test_not_a_receipt_raises_type_error(self):
        for bad in (None, (), 42, b"", self.log):
            with self.assertRaises(TypeError):
                inspect_full_encrypted_search_receipt(bad, KEY)
        # A plaintext full receipt is not an encrypted full receipt.
        plain = self.log.full_search_receipt("a")
        with self.assertRaises(TypeError):
            inspect_full_encrypted_search_receipt(plain, KEY)

    def test_key_type_errors(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        for bad in (None, "0" * 32, bytearray(32), memoryview(bytes(32)), 32):
            with self.assertRaises(TypeError):
                inspect_full_encrypted_search_receipt(receipt, bad)

    def test_key_length_error(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        with self.assertRaises(ValueError):
            inspect_full_encrypted_search_receipt(receipt, b"short")
        with self.assertRaises(ValueError):
            inspect_full_encrypted_search_receipt(receipt, b"x" * 31)
        with self.assertRaises(ValueError):
            inspect_full_encrypted_search_receipt(receipt, b"x" * 33)

    def test_alternate_hash_algorithm(self):
        log = make_mixed_log(hash_name="sha3-256")
        receipt = log.full_encrypted_search_receipt("a", KEY)
        self.assertEqual(
            inspect_full_encrypted_search_receipt(receipt, KEY),
            SearchReceiptReport(True, None, None),
        )
        forged = rebuild_encrypted(receipt, hash_name="sha256")
        report = inspect_full_encrypted_search_receipt(forged, KEY)
        self.assertEqual(report, SearchReceiptReport(False, 0, "entry"))
        self.assertEqual(
            report.ok, verify_full_encrypted_search_receipt(forged, KEY)
        )

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        before = receipt
        first = inspect_full_encrypted_search_receipt(receipt, KEY)
        second = inspect_full_encrypted_search_receipt(receipt, KEY)
        self.assertEqual(first, second)
        self.assertEqual(receipt, before)

    def test_success_across_sizes_and_ranges(self):
        for size in range(0, 6):
            for start in range(0, size + 1):
                for stop in range(start, size + 1):
                    receipt = self.log.full_encrypted_search_receipt(
                        "a", KEY, start, stop, size=size
                    )
                    self.assertTrue(
                        verify_full_encrypted_search_receipt(receipt, KEY),
                        (size, start, stop),
                    )
                    self.assertEqual(
                        inspect_full_encrypted_search_receipt(receipt, KEY),
                        SearchReceiptReport(True, None, None),
                        (size, start, stop),
                    )


class SameTamperedReceiptCorrespondenceTest(unittest.TestCase):
    def setUp(self):
        self.log = make_mixed_log()

    def test_plain_codes_and_indices(self):
        receipt = self.log.full_search_receipt("a")
        cases = [
            (rebuild_plain(receipt, root=b"\x00" * 32), (False, None, "proof")),
            (
                FullSearchReceipt(
                    1, "sha256", 0, b"\x00" * 32, b"a", 0, 0, (), ()
                ),
                (False, None, "root"),
            ),
        ]
        entry = receipt.items[2]
        tampered = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        cases.append(
            (
                rebuild_plain(
                    receipt,
                    items=receipt.items[:2] + (tampered,) + receipt.items[3:],
                ),
                (False, 2, "entry"),
            )
        )
        for forged, expected in cases:
            with self.subTest(expected=expected):
                self.assertFalse(verify_full_search_receipt(forged))
                self.assertEqual(
                    inspect_full_search_receipt(forged),
                    SearchReceiptReport(*expected),
                )

    def test_encrypted_codes_and_indices(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        cases = [
            (
                rebuild_encrypted(receipt, root=b"\x00" * 32),
                KEY,
                (False, None, "proof"),
            ),
            (
                FullEncryptedSearchReceipt(
                    1, "sha256", 0, b"\x00" * 32, b"a", 0, 0, (), (), ()
                ),
                KEY,
                (False, None, "root"),
            ),
            (rebuild_encrypted(receipt, hits=(0, 2)), KEY, (False, 4, "hits")),
            (receipt, OTHER_KEY, (False, 0, "hits")),
        ]
        entry = receipt.items[2]
        tampered = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        cases.append(
            (
                rebuild_encrypted(
                    receipt,
                    items=receipt.items[:2] + (tampered,) + receipt.items[3:],
                ),
                KEY,
                (False, 2, "entry"),
            )
        )
        for forged, key, expected in cases:
            with self.subTest(expected=expected):
                self.assertFalse(
                    verify_full_encrypted_search_receipt(forged, key)
                )
                self.assertEqual(
                    inspect_full_encrypted_search_receipt(forged, key),
                    SearchReceiptReport(*expected),
                )


if __name__ == "__main__":
    unittest.main()
