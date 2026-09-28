import unittest
from unittest.mock import patch

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
    key=KEY,
    **kwargs,
):
    """Build a mixed log; records are ("enc"|"plain", value)."""
    log = AuditLog(**kwargs)
    nonce_counter = 0
    for kind, value in records:
        if kind == "enc":
            log.encrypt(value, key, nonce=bytes([nonce_counter]) * 12)
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


def item_with(log, index, size=None):
    """A genuine (Entry, inclusion proof) pair from log at index."""
    return log.entry(index), log.inclusion_proof(index, size if size is not None else len(log))


def bypass(cls, **fields):
    """Build a receipt skipping the frozen dataclass __post_init__."""
    receipt = cls.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(receipt, name, value)
    return receipt


class SearchHitReportTest(unittest.TestCase):
    def test_success_constant(self):
        report = SearchHitReport(True, None, None)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)

    def test_positional_construction_and_equality(self):
        success = SearchHitReport(True, None, None)
        self.assertEqual(success, SearchHitReport(True, None, None))
        failure = SearchHitReport(False, 3, "entry")
        self.assertEqual(failure, SearchHitReport(False, 3, "entry"))
        self.assertNotEqual(failure, SearchHitReport(False, 4, "entry"))
        self.assertNotEqual(failure, SearchHitReport(False, 3, "proof"))
        self.assertNotEqual(failure, SearchHitReport(False, 3, "hit"))
        self.assertNotEqual(success, failure)
        self.assertNotEqual(failure, (False, 3, "entry"))

    def test_report_is_frozen(self):
        report = SearchHitReport(True, None, None)
        with self.assertRaises(Exception):
            report.ok = False

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
            SearchHitReport(True, 2, "hit")

    def test_failure_requires_a_known_code(self):
        with self.assertRaises(ValueError):
            SearchHitReport(False, None, None)
        with self.assertRaises(ValueError):
            SearchHitReport(False, 0, None)

    def test_code_type(self):
        with self.assertRaises(TypeError):
            SearchHitReport(False, None, b"entry")
        with self.assertRaises(TypeError):
            SearchHitReport(False, None, 0)

    def test_unknown_code_rejected(self):
        # Codes from the other diagnostic layers are not valid here.
        for code in ("", "verify", "last", "hits", "ENTRY", "h it"):
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
            self.log.search_receipt("a", 1, 4),
            self.log.search_receipt("a", 1, 4, size=4),
            self.log.search_receipt("a", 2, 2),
            AuditLog().search_receipt("a"),
        ]
        for receipt in cases:
            report = inspect_search_receipt(receipt)
            self.assertEqual(report, SearchHitReport(True, None, None), receipt)
            self.assertEqual(report.ok, verify_search_receipt(receipt))

    def test_no_hit_receipt_carries_no_evidence_even_with_bogus_root(self):
        receipt = self.log.search_receipt("missing")
        forged = rebuild_plain(receipt, root=b"\x00" * 32)
        self.assertTrue(verify_search_receipt(forged))
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(True, None, None)
        )
        empty = AuditLog().search_receipt("a")
        forged_empty = rebuild_plain(empty, root=b"\x00" * 32)
        self.assertTrue(verify_search_receipt(forged_empty))
        self.assertEqual(
            inspect_search_receipt(forged_empty),
            SearchHitReport(True, None, None),
        )

    def test_tampered_payload_reports_entry_at_that_index(self):
        receipt = self.log.search_receipt("a")  # hits at 0, 2, 4
        entry, proof = receipt.items[1]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = rebuild_plain(
            receipt,
            items=receipt.items[:1] + ((tampered, proof),) + receipt.items[2:],
        )
        self.assertEqual(
            inspect_search_receipt(forged),
            SearchHitReport(False, entry.index, "entry"),
        )
        self.assertFalse(verify_search_receipt(forged))

    def test_tampered_entry_hash_reports_entry_at_that_index(self):
        receipt = self.log.search_receipt("a", 0, 3)
        entry, proof = receipt.items[0]
        tampered = Entry(
            entry.index, entry.payload, entry.previous_hash, b"\x00" * 32
        )
        forged = rebuild_plain(
            receipt, items=((tampered, proof),) + receipt.items[1:]
        )
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(False, 0, "entry")
        )

    def test_wrong_root_reports_proof_at_first_listed_index(self):
        receipt = self.log.search_receipt("a")
        forged = rebuild_plain(receipt, root=b"\x00" * 32)
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(False, 0, "proof")
        )
        self.assertFalse(verify_search_receipt(forged))

    def test_wrong_proof_nodes_report_proof_at_that_index(self):
        receipt = self.log.search_receipt("a", 0, 5)
        entry, proof = receipt.items[1]
        self.assertTrue(proof)
        forged = rebuild_plain(
            receipt,
            items=receipt.items[:1]
            + ((entry, (b"\x00" * 32,) + proof[1:]),)
            + receipt.items[2:],
        )
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(False, 2, "proof")
        )
        self.assertFalse(verify_search_receipt(forged))

    def test_genuine_non_hit_entry_reports_hit_at_that_index(self):
        # Entry 1 ("b") is genuinely in the snapshot with a valid proof, but
        # its payload is not the query value: a false hit located at index 1.
        receipt = self.log.search_receipt("a")
        forged = rebuild_plain(
            receipt, items=receipt.items[:1] + (item_with(self.log, 1),) + receipt.items[1:]
        )
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(False, 1, "hit")
        )
        self.assertFalse(verify_search_receipt(forged))

    def test_only_first_false_hit_is_reported(self):
        receipt = self.log.search_receipt("a")
        # List a genuine non-hit at 1 and a tampered-entry false hit at 2;
        # indices stay ascending (0, 1, 2, 4), and only the earliest false
        # hit (index 1) is reported.
        non_hit = item_with(self.log, 1)
        entry, proof = receipt.items[1]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = rebuild_plain(
            receipt,
            items=(receipt.items[0], non_hit, (tampered, proof), receipt.items[2]),
        )
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(False, 1, "hit")
        )

    def test_entry_check_precedes_proof_and_hit(self):
        receipt = self.log.search_receipt("a")
        entry, proof = receipt.items[0]
        # Payload tampered (would also fail the hit comparison), proof broken,
        # root wrong: the entry digest mismatch must win.
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = rebuild_plain(
            receipt,
            root=b"\x00" * 32,
            items=((tampered, (b"\x00" * 32,) + proof[1:]),) + receipt.items[1:],
        )
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(False, 0, "entry")
        )

    def test_proof_check_precedes_hit(self):
        # A genuine non-hit entry carried under a wrong root: the entry is
        # authentic, but the proof fails first (proof precedes the content
        # comparison).
        entry, proof = item_with(self.log, 1)
        receipt = self.log.search_receipt("missing")
        forged = rebuild_plain(
            receipt, root=b"\x00" * 32, items=((entry, proof),)
        )
        self.assertEqual(
            inspect_search_receipt(forged), SearchHitReport(False, 1, "proof")
        )

    def test_root_fallback_when_every_listed_entry_checks_out(self):
        # The contract: if every listed entry passes entry/proof/hit yet the
        # verifier still rejects, "root" is reported with no position. That
        # disagreement is not reachable against the real verifier, so pin the
        # fallback to a forced disagreement.
        receipt = self.log.search_receipt("a")
        with patch(
            "auditchain.verify_search_receipt", return_value=False
        ):
            self.assertEqual(
                inspect_search_receipt(receipt),
                SearchHitReport(False, None, "root"),
            )

    def test_proof_structure_errors_propagate(self):
        receipt = self.log.search_receipt("a")
        entry, _ = receipt.items[0]
        # The constructor checks proof element widths but not level counts.
        short = rebuild_plain(receipt, items=((entry, ()),) + receipt.items[1:])
        long = rebuild_plain(
            receipt,
            items=((entry, receipt.items[0][1] + (b"\x00" * 32,)),)
            + receipt.items[1:],
        )
        for forged in (short, long):
            with self.assertRaises(ValueError):
                inspect_search_receipt(forged)
            with self.assertRaises(ValueError):
                verify_search_receipt(forged)

    def test_not_a_receipt_raises_type_error(self):
        for bad in (None, (), 42, b"", make_mixed_log()):
            with self.assertRaises(TypeError):
                inspect_search_receipt(bad)
        # An encrypted receipt is not the plain receipt either.
        other = make_mixed_log().encrypted_search_receipt("a", KEY)
        with self.assertRaises(TypeError):
            inspect_search_receipt(other)

    def test_too_many_arguments_raise_as_usual(self):
        receipt = self.log.search_receipt("a")
        with self.assertRaises(TypeError):
            inspect_search_receipt(receipt, KEY)

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
        non_tuple_items = bypass(
            SearchReceipt,
            version=1,
            hash_name=base.hash_name,
            size=base.size,
            root=base.root,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=[],
        )
        for forged, error in (
            (wrong_hash, ValueError),
            (wrong_version, ValueError),
            (non_tuple_items, TypeError),
        ):
            with self.assertRaises(error):
                verify_search_receipt(forged)
            with self.assertRaises(error):
                inspect_search_receipt(forged)

    def test_alternate_hash_algorithm(self):
        log = make_plain_log(hash_name="sha3-256")
        receipt = log.search_receipt("a", 0, 4)
        self.assertEqual(
            inspect_search_receipt(receipt), SearchHitReport(True, None, None)
        )
        forged = rebuild_plain(receipt, hash_name="sha256")
        report = inspect_search_receipt(forged)
        # The first listed entry's digest recomputed under sha256 mismatches.
        self.assertEqual(report, SearchHitReport(False, 0, "entry"))
        self.assertEqual(report.ok, verify_search_receipt(forged))

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.search_receipt("a", 1, 5)
        before = receipt
        first = inspect_search_receipt(receipt)
        second = inspect_search_receipt(receipt)
        self.assertEqual(first, second)
        self.assertEqual(receipt, before)
        # A failing diagnosis is deterministic too and leaves fields intact.
        forged = rebuild_plain(receipt, root=b"\x00" * 32)
        self.assertEqual(
            inspect_search_receipt(forged), inspect_search_receipt(forged)
        )
        self.assertEqual(forged.root, b"\x00" * 32)

    def test_success_matches_verifier_across_ranges_and_sizes(self):
        for size in range(0, 6):
            for start in range(0, size + 1):
                for stop in range(start, size + 1):
                    receipt = self.log.search_receipt(
                        "a", start, stop, size=size
                    )
                    self.assertTrue(
                        verify_search_receipt(receipt), (size, start, stop)
                    )
                    self.assertEqual(
                        inspect_search_receipt(receipt),
                        SearchHitReport(True, None, None),
                        (size, start, stop),
                    )

    def test_report_ok_pins_verifier_for_many_forgeries(self):
        receipt = self.log.search_receipt("a")
        forgeries = [
            rebuild_plain(receipt, root=b"\x00" * 32),
            rebuild_plain(receipt, query=b"other"),
        ]
        # A wrong proof tuple at each listed position.
        for position, (entry, proof) in enumerate(receipt.items):
            if proof:
                broken = (b"\x01" * 32,) + proof[1:]
                forgeries.append(
                    rebuild_plain(
                        receipt,
                        items=receipt.items[:position]
                        + ((entry, broken),)
                        + receipt.items[position + 1 :],
                    )
                )
        # A tampered payload at each listed position.
        for position, (entry, proof) in enumerate(receipt.items):
            tampered = Entry(
                entry.index, b"x", entry.previous_hash, entry.entry_hash
            )
            forgeries.append(
                rebuild_plain(
                    receipt,
                    items=receipt.items[:position]
                    + ((tampered, proof),)
                    + receipt.items[position + 1 :],
                )
            )
        for forged in forgeries:
            report = inspect_search_receipt(forged)
            self.assertFalse(report.ok)
            self.assertEqual(report.ok, verify_search_receipt(forged))
            self.assertIsNotNone(report.code)
            self.assertIsNotNone(report.index)
            self.assertGreaterEqual(report.index, 0)


class InspectEncryptedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_mixed_log()
        self.receipt = self.log.encrypted_search_receipt("a", KEY)

    def test_genuine_receipts_report_success(self):
        cases = [
            (self.log.encrypted_search_receipt("a", KEY), KEY),
            (self.log.encrypted_search_receipt("missing", KEY), KEY),
            (self.log.encrypted_search_receipt("a", KEY, 1, 4), KEY),
            (self.log.encrypted_search_receipt("a", KEY, 1, 4, size=4), KEY),
            (self.log.encrypted_search_receipt("a", KEY, 2, 2), KEY),
            (AuditLog().encrypted_search_receipt("a", KEY), KEY),
            # A zero-item receipt never exercises the key.
            (self.log.encrypted_search_receipt("missing", KEY), OTHER_KEY),
        ]
        for receipt, key in cases:
            report = inspect_encrypted_search_receipt(receipt, key)
            self.assertEqual(
                report, SearchHitReport(True, None, None), (receipt, key)
            )
            self.assertEqual(
                report.ok, verify_encrypted_search_receipt(receipt, key)
            )

    def test_zero_item_receipt_with_bogus_root_and_wrong_key_succeeds(self):
        receipt = self.log.encrypted_search_receipt("missing", KEY)
        forged = rebuild_encrypted(receipt, root=b"\x00" * 32)
        for key in (KEY, OTHER_KEY):
            self.assertTrue(verify_encrypted_search_receipt(forged, key))
            self.assertEqual(
                inspect_encrypted_search_receipt(forged, key),
                SearchHitReport(True, None, None),
            )

    def test_wrong_key_reports_hit_at_first_listed_index(self):
        # No envelope unseals under the other key: the first listed hit (0)
        # is a genuine entry that is not a query hit under that key.
        self.assertEqual(
            inspect_encrypted_search_receipt(self.receipt, OTHER_KEY),
            SearchHitReport(False, 0, "hit"),
        )
        self.assertFalse(
            verify_encrypted_search_receipt(self.receipt, OTHER_KEY)
        )

    def test_plain_entry_listed_as_hit_reports_hit(self):
        # Index 1 is a plain "b" entry; the envelope parse fails, but the
        # entry is authentic and its proof is valid, so the false hit is
        # located at index 1 rather than reported as an entry/proof failure.
        forged = rebuild_encrypted(
            self.receipt,
            items=self.receipt.items[:1]
            + (item_with(self.log, 1),)
            + self.receipt.items[1:],
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY),
            SearchHitReport(False, 1, "hit"),
        )
        self.assertFalse(verify_encrypted_search_receipt(forged, KEY))

    def test_foreign_key_envelope_listed_as_hit_reports_hit(self):
        foreign = make_mixed_log(
            (("enc", "a"), ("enc", "a")), key=OTHER_KEY
        )
        # The foreign entry is genuinely part of a log sealed under the same
        # snapshot shape; graft it into a receipt authenticated against the
        # foreign snapshot and inspect with the wrong (append) key.
        receipt = foreign.encrypted_search_receipt("a", OTHER_KEY)
        self.assertEqual(
            inspect_encrypted_search_receipt(receipt, KEY),
            SearchHitReport(False, 0, "hit"),
        )
        self.assertFalse(verify_encrypted_search_receipt(receipt, KEY))

    def test_decrypting_to_another_plaintext_reports_hit(self):
        # Index 3 is an authentic "c" envelope: unseals fine, content differs.
        forged = rebuild_encrypted(
            self.receipt,
            items=self.receipt.items[:2] + (item_with(self.log, 3),),
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY),
            SearchHitReport(False, 3, "hit"),
        )
        self.assertFalse(verify_encrypted_search_receipt(forged, KEY))

    def test_first_false_hit_when_leading_entries_are_genuine(self):
        # Listed 0 (genuine hit) then 1 (plain entry): the first false hit is
        # at absolute index 1.
        forged = rebuild_encrypted(
            self.receipt,
            items=self.receipt.items[:1] + (item_with(self.log, 1),),
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY),
            SearchHitReport(False, 1, "hit"),
        )

    def test_tampered_envelope_reports_entry_before_decryption(self):
        # Changing the sealed payload while keeping the recorded entry_hash
        # fails the recomputed digest first; it must not surface as "hit".
        entry, proof = self.receipt.items[0]
        tampered = Entry(
            entry.index, entry.payload + b"x", entry.previous_hash, entry.entry_hash
        )
        forged = rebuild_encrypted(
            self.receipt, items=((tampered, proof),) + self.receipt.items[1:]
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, OTHER_KEY),
            SearchHitReport(False, 0, "entry"),
        )

    def test_entry_check_precedes_proof_and_unseal(self):
        entry, proof = self.receipt.items[0]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = rebuild_encrypted(
            self.receipt,
            root=b"\x00" * 32,
            items=((tampered, (b"\x00" * 32,) + proof[1:]),)
            + self.receipt.items[1:],
        )
        # Even with the wrong key, the entry digest mismatch is first.
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, OTHER_KEY),
            SearchHitReport(False, 0, "entry"),
        )

    def test_proof_check_precedes_unseal(self):
        # A plain (non-hit) entry under a wrong root: authentic entry, proof
        # fails before the envelope is even attempted.
        entry, proof = item_with(self.log, 1)
        receipt = self.log.encrypted_search_receipt("missing", KEY)
        forged = rebuild_encrypted(
            receipt, root=b"\x00" * 32, items=((entry, proof),)
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, KEY),
            SearchHitReport(False, 1, "proof"),
        )
        # Same precedence with a genuine envelope and the wrong key.
        entry0, proof0 = self.receipt.items[0]
        forged2 = rebuild_encrypted(
            self.receipt,
            root=b"\x00" * 32,
            items=((entry0, proof0),),
        )
        self.assertEqual(
            inspect_encrypted_search_receipt(forged2, OTHER_KEY),
            SearchHitReport(False, 0, "proof"),
        )

    def test_root_fallback_when_every_listed_entry_checks_out(self):
        with patch(
            "auditchain.verify_encrypted_search_receipt", return_value=False
        ):
            self.assertEqual(
                inspect_encrypted_search_receipt(self.receipt, KEY),
                SearchHitReport(False, None, "root"),
            )

    def test_proof_structure_errors_propagate(self):
        entry, _ = self.receipt.items[0]
        short = rebuild_encrypted(
            self.receipt, items=((entry, ()),) + self.receipt.items[1:]
        )
        long = rebuild_encrypted(
            self.receipt,
            items=((entry, self.receipt.items[0][1] + (b"\x00" * 32,)),)
            + self.receipt.items[1:],
        )
        for forged in (short, long):
            with self.assertRaises(ValueError):
                inspect_encrypted_search_receipt(forged, KEY)
            with self.assertRaises(ValueError):
                verify_encrypted_search_receipt(forged, KEY)

    def test_not_a_receipt_raises_type_error(self):
        plain = make_plain_log().search_receipt("a")
        for bad in (None, (), 42, b"", plain):
            with self.assertRaises(TypeError):
                inspect_encrypted_search_receipt(bad, KEY)

    def test_key_must_be_bytes_even_for_zero_item_receipt(self):
        receipt = self.receipt
        zero = self.log.encrypted_search_receipt("missing", KEY)
        for target in (receipt, zero):
            for bad in (None, "0" * 32, bytearray(32), memoryview(bytes(32)), 32):
                with self.assertRaises(TypeError):
                    inspect_encrypted_search_receipt(target, bad)

    def test_key_must_be_32_bytes_even_for_zero_item_receipt(self):
        zero = self.log.encrypted_search_receipt("missing", KEY)
        for target in (self.receipt, zero):
            for bad in (b"", b"k" * 31, b"k" * 33):
                with self.assertRaises(ValueError):
                    inspect_encrypted_search_receipt(target, bad)

    def test_bypassed_structural_corruption_mirrors_verifier(self):
        base = self.log.encrypted_search_receipt("a", KEY, 0, 2)
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
        wrong_version = bypass(
            EncryptedSearchReceipt,
            version=2,
            hash_name=base.hash_name,
            size=base.size,
            root=base.root,
            query=base.query,
            start=base.start,
            stop=base.stop,
            items=base.items,
        )
        for forged in (wrong_hash, wrong_version):
            with self.assertRaises(ValueError):
                verify_encrypted_search_receipt(forged, KEY)
            with self.assertRaises(ValueError):
                inspect_encrypted_search_receipt(forged, KEY)

    def test_alternate_hash_algorithm(self):
        log = make_mixed_log(hash_name="sha3-256")
        receipt = log.encrypted_search_receipt("a", KEY, 0, 4)
        self.assertEqual(
            inspect_encrypted_search_receipt(receipt, KEY),
            SearchHitReport(True, None, None),
        )
        forged = rebuild_encrypted(receipt, hash_name="sha256")
        report = inspect_encrypted_search_receipt(forged, KEY)
        self.assertEqual(report, SearchHitReport(False, 0, "entry"))
        self.assertEqual(
            report.ok, verify_encrypted_search_receipt(forged, KEY)
        )

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.encrypted_search_receipt("a", KEY, 1, 5)
        before = receipt
        first = inspect_encrypted_search_receipt(receipt, KEY)
        second = inspect_encrypted_search_receipt(receipt, KEY)
        self.assertEqual(first, second)
        self.assertEqual(receipt, before)
        forged = rebuild_encrypted(receipt, root=b"\x00" * 32)
        self.assertEqual(
            inspect_encrypted_search_receipt(forged, OTHER_KEY),
            inspect_encrypted_search_receipt(forged, OTHER_KEY),
        )
        self.assertEqual(forged.root, b"\x00" * 32)

    def test_success_matches_verifier_across_ranges_and_sizes(self):
        for size in range(0, 6):
            for start in range(0, size + 1):
                for stop in range(start, size + 1):
                    receipt = self.log.encrypted_search_receipt(
                        "a", KEY, start, stop, size=size
                    )
                    self.assertTrue(
                        verify_encrypted_search_receipt(receipt, KEY),
                        (size, start, stop),
                    )
                    self.assertEqual(
                        inspect_encrypted_search_receipt(receipt, KEY),
                        SearchHitReport(True, None, None),
                        (size, start, stop),
                    )

    def test_report_ok_pins_verifier_for_many_forgeries(self):
        receipt = self.receipt
        forgeries = [
            (rebuild_encrypted(receipt, root=b"\x00" * 32), KEY),
            (rebuild_encrypted(receipt, query=b"other"), KEY),
            (receipt, OTHER_KEY),
        ]
        for position, (entry, proof) in enumerate(receipt.items):
            tampered = Entry(
                entry.index, b"x", entry.previous_hash, entry.entry_hash
            )
            forgeries.append(
                (
                    rebuild_encrypted(
                        receipt,
                        items=receipt.items[:position]
                        + ((tampered, proof),)
                        + receipt.items[position + 1 :],
                    ),
                    KEY,
                )
            )
            if proof:
                broken = (b"\x02" * 32,) + proof[1:]
                forgeries.append(
                    (
                        rebuild_encrypted(
                            receipt,
                            items=receipt.items[:position]
                            + ((entry, broken),)
                            + receipt.items[position + 1 :],
                        ),
                        KEY,
                    )
                )
        for forged, key in forgeries:
            report = inspect_encrypted_search_receipt(forged, key)
            self.assertFalse(report.ok)
            self.assertEqual(
                report.ok, verify_encrypted_search_receipt(forged, key)
            )
            self.assertIsNotNone(report.code)
            self.assertIsNotNone(report.index)


if __name__ == "__main__":
    unittest.main()
