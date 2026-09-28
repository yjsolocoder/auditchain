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


def bypass(cls, **fields):
    """Build a receipt skipping the frozen dataclass __post_init__."""
    receipt = cls.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(receipt, name, value)
    return receipt


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
            SearchReceiptReport(True, 0, "hits")

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
        for code in ("verify", "", "last", "HITS"):
            with self.assertRaises(ValueError):
                SearchReceiptReport(False, None, code)

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
            self.log.full_search_receipt("a"),
            self.log.full_search_receipt("missing"),
            self.log.full_search_receipt("a", 1, 3),
            self.log.full_search_receipt("a", 1, 3, size=3),
            self.log.full_search_receipt("a", 2, 2),
            AuditLog().full_search_receipt("a"),
        ]
        for receipt in cases:
            report = inspect_full_search_receipt(receipt)
            self.assertEqual(
                report, SearchReceiptReport(True, None, None), receipt
            )
            self.assertEqual(report.ok, verify_full_search_receipt(receipt))

    def test_empty_snapshot_wrong_root_reports_root(self):
        forged = FullSearchReceipt(1, "sha256", 0, b"\x00" * 32, b"a", 0, 0, (), ())
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, None, "root"),
        )
        self.assertFalse(verify_full_search_receipt(forged))

    def test_pure_empty_range_carries_no_evidence(self):
        # The recorded root of an empty range over a non-empty snapshot is
        # never compared, so even a bogus root reports success.
        receipt = self.log.full_search_receipt("a", 2, 2)
        forged = rebuild_plain(receipt, root=b"\x00" * 32)
        self.assertTrue(verify_full_search_receipt(forged))
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(True, None, None),
        )

    def test_tampered_payload_reports_entry_at_index(self):
        receipt = self.log.full_search_receipt("a", 0, 5)
        entry = receipt.items[2]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = rebuild_plain(
            receipt, items=receipt.items[:2] + (tampered,) + receipt.items[3:]
        )
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, 2, "entry"),
        )
        self.assertFalse(verify_full_search_receipt(forged))

    def test_tampered_entry_hash_reports_entry_at_index(self):
        receipt = self.log.full_search_receipt("a", 0, 4)
        entry = receipt.items[1]
        tampered = Entry(
            entry.index, entry.payload, entry.previous_hash, b"\x00" * 32
        )
        forged = rebuild_plain(
            receipt, items=receipt.items[:1] + (tampered,) + receipt.items[2:]
        )
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

    def test_wrong_proof_nodes_report_shared_proof_without_position(self):
        receipt = self.log.full_search_receipt("a", 0, 2)
        self.assertTrue(receipt.proof)
        forged = rebuild_plain(receipt, proof=(b"\x00" * 32,) + receipt.proof[1:])
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, None, "proof"),
        )
        self.assertFalse(verify_full_search_receipt(forged))

    def test_entry_mismatch_precedes_shared_proof_check(self):
        # A wrong proof node must not mask an earlier entry mismatch, even
        # though the shared proof is examined only afterwards.
        receipt = self.log.full_search_receipt("a", 0, 3)
        entry = receipt.items[0]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = rebuild_plain(
            receipt,
            items=(tampered,) + receipt.items[1:],
            proof=(b"\x00" * 32,) + receipt.proof[1:],
        )
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, entry.index, "entry"),
        )

    def test_only_first_mismatching_entry_is_reported(self):
        receipt = self.log.full_search_receipt("a", 0, 5)
        tampered = []
        for entry in receipt.items:
            if entry.index in (1, 3):
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

    def test_root_check_precedes_entry_check(self):
        # A zero-size snapshot with a non-canonical root reports "root" even
        # when fields are bypassed so an entry digest would also disagree.
        forged = bypass(
            FullSearchReceipt,
            version=1,
            hash_name="sha256",
            size=0,
            root=b"\x00" * 32,
            query=b"a",
            start=0,
            stop=0,
            items=(),
            proof=(),
        )
        self.assertEqual(
            inspect_full_search_receipt(forged),
            SearchReceiptReport(False, None, "root"),
        )

    def test_proof_structure_errors_propagate(self):
        receipt = self.log.full_search_receipt("a", 0, 3)
        short = rebuild_plain(receipt, proof=receipt.proof[:-1])
        long = rebuild_plain(receipt, proof=receipt.proof + (b"\x00" * 32,))
        for forged in (short, long):
            with self.assertRaises(ValueError):
                inspect_full_search_receipt(forged)
            with self.assertRaises(ValueError):
                verify_full_search_receipt(forged)

    def test_not_a_receipt_raises_type_error(self):
        for bad in (None, (), 42, b"", make_mixed_log().full_encrypted_search_receipt("a", KEY)):
            with self.assertRaises(TypeError):
                inspect_full_search_receipt(bad)

    def test_bypassed_structural_corruption_mirrors_verifier(self):
        base = self.log.full_search_receipt("a", 0, 2)
        wrong_hash = bypass(
            FullSearchReceipt,
            version=1,
            hash_name="nope",
            size=base.size,
            root=base.root,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
            proof=base.proof,
        )
        narrow_root = bypass(
            FullSearchReceipt,
            version=1,
            hash_name="sha256",
            size=base.size,
            root=b"\x00" * 16,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
            proof=base.proof,
        )
        for forged in (wrong_hash, narrow_root):
            with self.assertRaises(ValueError):
                verify_full_search_receipt(forged)
            with self.assertRaises(ValueError):
                inspect_full_search_receipt(forged)

        # version is re-validated through the frozen constructor, so a
        # bypassed version != 1 raises ValueError exactly as construction
        # does, in both the verifier and the diagnosis.
        wrong_version = bypass(
            FullSearchReceipt,
            version=2,
            hash_name=base.hash_name,
            size=base.size,
            root=base.root,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
            proof=base.proof,
        )
        with self.assertRaises(ValueError):
            verify_full_search_receipt(wrong_version)
        with self.assertRaises(ValueError):
            inspect_full_search_receipt(wrong_version)

    def test_alternate_hash_algorithm(self):
        log = make_plain_log(hash_name="sha3-256")
        receipt = log.full_search_receipt("a", 0, 4)
        self.assertEqual(
            inspect_full_search_receipt(receipt),
            SearchReceiptReport(True, None, None),
        )
        forged = rebuild_plain(receipt, hash_name="sha256")
        report = inspect_full_search_receipt(forged)
        # The first entry's digest recomputed under sha256 no longer matches.
        self.assertEqual(report, SearchReceiptReport(False, 0, "entry"))
        self.assertEqual(report.ok, verify_full_search_receipt(forged))

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.full_search_receipt("a", 1, 4)
        before = receipt
        first = inspect_full_search_receipt(receipt)
        second = inspect_full_search_receipt(receipt)
        self.assertEqual(first, second)
        self.assertEqual(receipt, before)

    def test_success_matches_verifier_across_ranges_and_sizes(self):
        for size in range(0, 6):
            for start in range(0, size + 1):
                for stop in range(start, size + 1):
                    receipt = self.log.full_search_receipt("a", start, stop, size=size)
                    self.assertTrue(verify_full_search_receipt(receipt), (size, start, stop))
                    self.assertEqual(
                        inspect_full_search_receipt(receipt),
                        SearchReceiptReport(True, None, None),
                        (size, start, stop),
                    )


class InspectFullEncryptedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_mixed_log()
        self.receipt = self.log.full_encrypted_search_receipt("a", KEY)

    def test_genuine_receipts_report_success(self):
        cases = [
            (self.log.full_encrypted_search_receipt("a", KEY), KEY),
            (self.log.full_encrypted_search_receipt("missing", KEY), KEY),
            (self.log.full_encrypted_search_receipt("a", KEY, 1, 3), KEY),
            (self.log.full_encrypted_search_receipt("a", KEY, 1, 3, size=3), KEY),
            (self.log.full_encrypted_search_receipt("a", KEY, 2, 2), KEY),
            (AuditLog().full_encrypted_search_receipt("a", KEY), KEY),
            # A zero-hit receipt does not exercise the key at all.
            (self.log.full_encrypted_search_receipt("missing", KEY), OTHER_KEY),
        ]
        for receipt, key in cases:
            report = inspect_full_encrypted_search_receipt(receipt, key)
            self.assertEqual(
                report, SearchReceiptReport(True, None, None), (receipt, key)
            )
            self.assertEqual(
                report.ok, verify_full_encrypted_search_receipt(receipt, key)
            )

    def test_empty_snapshot_wrong_root_reports_root(self):
        receipt = AuditLog().full_encrypted_search_receipt("a", KEY)
        forged = rebuild_encrypted(receipt, root=b"\x00" * 32)
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, None, "root"),
        )
        self.assertFalse(verify_full_encrypted_search_receipt(forged, KEY))

    def test_pure_empty_range_carries_no_evidence(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 2, 2)
        # Neither a bogus root nor a wrong key can be checked without items.
        forged = rebuild_encrypted(receipt, root=b"\x00" * 32)
        for key in (KEY, OTHER_KEY):
            self.assertTrue(verify_full_encrypted_search_receipt(forged, key))
            self.assertEqual(
                inspect_full_encrypted_search_receipt(forged, key),
                SearchReceiptReport(True, None, None),
            )

    def test_tampered_payload_reports_entry_at_index(self):
        entry = self.receipt.items[2]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = rebuild_encrypted(
            self.receipt, items=self.receipt.items[:2] + (tampered,) + self.receipt.items[3:]
        )
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, 2, "entry"),
        )
        self.assertFalse(verify_full_encrypted_search_receipt(forged, KEY))

    def test_wrong_root_reports_shared_proof_without_position(self):
        forged = rebuild_encrypted(self.receipt, root=b"\x00" * 32)
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, None, "proof"),
        )

    def test_wrong_proof_nodes_report_shared_proof_without_position(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 0, 2)
        self.assertTrue(receipt.proof)
        forged = rebuild_encrypted(receipt, proof=(b"\x00" * 32,) + receipt.proof[1:])
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, None, "proof"),
        )
        self.assertFalse(verify_full_encrypted_search_receipt(forged, KEY))

    def test_entry_mismatch_precedes_proof_and_hits(self):
        entry = self.receipt.items[0]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = rebuild_encrypted(
            self.receipt,
            items=(tampered,) + self.receipt.items[1:],
            proof=(b"\x00" * 32,) + self.receipt.proof[1:],
            hits=(),
        )
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, entry.index, "entry"),
        )

    def test_proof_mismatch_precedes_hits_mismatch(self):
        forged = rebuild_encrypted(
            self.receipt,
            root=b"\x00" * 32,
            hits=(),
        )
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, None, "proof"),
        )
        self.assertFalse(verify_full_encrypted_search_receipt(forged, KEY))

    def test_root_check_precedes_everything(self):
        receipt = AuditLog().full_encrypted_search_receipt("a", KEY)
        forged = rebuild_encrypted(receipt, root=b"\x00" * 32, hits=())
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, None, "root"),
        )

    def test_recorded_hit_removed_from_tail(self):
        # Real hits (0, 2, 4); dropping 4 makes the first mismatch index 4.
        forged = rebuild_encrypted(self.receipt, hits=(0, 2))
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, 4, "hits"),
        )
        self.assertFalse(verify_full_encrypted_search_receipt(forged, KEY))

    def test_extra_recorded_hit(self):
        forged = rebuild_encrypted(self.receipt, hits=(0, 1, 2, 4))
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, 1, "hits"),
        )

    def test_shifted_recorded_hits(self):
        # (1, 2, 4) vs (0, 2, 4): first disagreement at absolute index 0.
        forged = rebuild_encrypted(self.receipt, hits=(1, 2, 4))
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, 0, "hits"),
        )

    def test_empty_recorded_hits_point_at_first_real_hit(self):
        forged = rebuild_encrypted(self.receipt, hits=())
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, 0, "hits"),
        )

    def test_diverging_hit_value_reports_lower_index(self):
        # Real hits (0, 2, 4); recorded (0, 2, 3): item-by-item the first
        # disagreement is 3 vs 4, and the lower absolute index 3 is reported.
        forged = rebuild_encrypted(self.receipt, hits=(0, 2, 3))
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, 3, "hits"),
        )

    def test_dropping_recomputed_hits_points_at_first_real_hit(self):
        # Over [0, 3) the key unseals hits (0, 2); recording an empty hit
        # set makes the recorded tuple a strict prefix, so the longer
        # recomputed tuple's next index (0) is reported.
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 0, 3)
        self.assertEqual(receipt.hits, (0, 2))
        forged = rebuild_encrypted(receipt, hits=())
        self.assertEqual(
            inspect_full_encrypted_search_receipt(forged, KEY),
            SearchReceiptReport(False, 0, "hits"),
        )

    def test_wrong_key_reports_hits_at_first_recorded_hit(self):
        # No envelope unseals under the other key: recomputed hits are
        # empty, so the first disagreement is recorded hit 0.
        self.assertEqual(
            inspect_full_encrypted_search_receipt(self.receipt, OTHER_KEY),
            SearchReceiptReport(False, 0, "hits"),
        )
        self.assertFalse(
            verify_full_encrypted_search_receipt(self.receipt, OTHER_KEY)
        )

    def test_wrong_key_zero_hit_receipt_still_succeeds(self):
        receipt = self.log.full_encrypted_search_receipt("missing", KEY)
        self.assertEqual(receipt.hits, ())
        self.assertEqual(
            inspect_full_encrypted_search_receipt(receipt, OTHER_KEY),
            SearchReceiptReport(True, None, None),
        )

    def test_proof_structure_errors_propagate(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 0, 3)
        short = rebuild_encrypted(receipt, proof=receipt.proof[:-1])
        long = rebuild_encrypted(
            receipt, proof=receipt.proof + (b"\x00" * 32,)
        )
        for forged in (short, long):
            with self.assertRaises(ValueError):
                inspect_full_encrypted_search_receipt(forged, KEY)
            with self.assertRaises(ValueError):
                verify_full_encrypted_search_receipt(forged, KEY)

    def test_not_a_receipt_raises_type_error(self):
        plain = self.log.full_search_receipt("a")
        for bad in (None, (), 42, b"", plain):
            with self.assertRaises(TypeError):
                inspect_full_encrypted_search_receipt(bad, KEY)

    def test_key_must_be_bytes(self):
        for bad in (None, "0" * 32, bytearray(32), memoryview(bytes(32)), 32):
            with self.assertRaises(TypeError):
                inspect_full_encrypted_search_receipt(self.receipt, bad)

    def test_key_must_be_32_bytes(self):
        for bad in (b"", b"k" * 31, b"k" * 33):
            with self.assertRaises(ValueError):
                inspect_full_encrypted_search_receipt(self.receipt, bad)

    def test_bypassed_structural_corruption_mirrors_verifier(self):
        base = self.log.full_encrypted_search_receipt("a", KEY, 0, 2)

        duplicated_hits = bypass(
            FullEncryptedSearchReceipt,
            version=1,
            hash_name=base.hash_name,
            size=base.size,
            root=base.root,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
            proof=base.proof,
            hits=(0, 0),
        )
        with self.assertRaises(ValueError):
            verify_full_encrypted_search_receipt(duplicated_hits, KEY)
        with self.assertRaises(ValueError):
            inspect_full_encrypted_search_receipt(duplicated_hits, KEY)

        wrong_hash = bypass(
            FullEncryptedSearchReceipt,
            version=1,
            hash_name="nope",
            size=base.size,
            root=base.root,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
            proof=base.proof,
            hits=base.hits,
        )
        with self.assertRaises(ValueError):
            inspect_full_encrypted_search_receipt(wrong_hash, KEY)

        non_bytes_root = bypass(
            FullEncryptedSearchReceipt,
            version=1,
            hash_name=base.hash_name,
            size=base.size,
            root=bytearray(base.root),
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
            proof=base.proof,
            hits=base.hits,
        )
        with self.assertRaises(TypeError):
            inspect_full_encrypted_search_receipt(non_bytes_root, KEY)

    def test_alternate_hash_algorithm(self):
        log = make_mixed_log(hash_name="sha3-256")
        receipt = log.full_encrypted_search_receipt("a", KEY, 0, 4)
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
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4)
        before = receipt
        first = inspect_full_encrypted_search_receipt(receipt, KEY)
        second = inspect_full_encrypted_search_receipt(receipt, KEY)
        self.assertEqual(first, second)
        self.assertEqual(receipt, before)

    def test_success_matches_verifier_across_ranges_and_sizes(self):
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


if __name__ == "__main__":
    unittest.main()
