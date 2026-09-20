import unittest

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    Entry,
    IntegrityIssue,
    IntegrityReport,
    entry_digest,
)


def relink(log, position, payload):
    """Replace the retained entry at ``position`` with a self-consistent relink.

    Only the payload changes; the recorded entry hash is recomputed over the
    new payload and the recorded predecessor is left intact. The log's cached
    head is deliberately not touched, modelling a tail rewrite an attacker can
    actually perform on a stored record.
    """
    original = log.entry(position)
    forged_hash = entry_digest(
        original.index,
        original.previous_hash,
        payload,
        hash_name=log.hash_name,
    )
    log._entries[position - log.retain_from] = Entry(
        original.index, payload, original.previous_hash, forged_hash
    )
    return original


class IntegrityIssueTypeTest(unittest.TestCase):
    def test_positional_and_keyword_construction(self):
        self.assertEqual(
            IntegrityIssue("index", 3), IntegrityIssue(code="index", index=3)
        )
        self.assertEqual(
            IntegrityIssue("head", None), IntegrityIssue(code="head", index=None)
        )

    def test_frozen_and_field_equality(self):
        self.assertEqual(IntegrityIssue("index", 3), IntegrityIssue("index", 3))
        self.assertEqual(
            hash(IntegrityIssue("index", 3)), hash(IntegrityIssue("index", 3))
        )
        self.assertNotEqual(IntegrityIssue("index", 3), IntegrityIssue("index", 4))
        self.assertNotEqual(
            IntegrityIssue("index", 3), IntegrityIssue("previous_hash", 3)
        )
        with self.assertRaises(Exception):
            IntegrityIssue("index", 3).code = "head"

    def test_unknown_code_rejected(self):
        with self.assertRaises(ValueError):
            IntegrityIssue("nope", 0)

    def test_code_type(self):
        with self.assertRaises(TypeError):
            IntegrityIssue(1, 0)

    def test_head_requires_none_index(self):
        IntegrityIssue("head", None)
        with self.assertRaises(ValueError):
            IntegrityIssue("head", 0)

    def test_indexed_issue_requires_integer_index(self):
        with self.assertRaises(TypeError):
            IntegrityIssue("index", None)
        with self.assertRaises(TypeError):
            IntegrityIssue("index", 1.0)
        with self.assertRaises(TypeError):
            IntegrityIssue("index", True)
        with self.assertRaises(ValueError):
            IntegrityIssue("index", -1)
        for code in ("previous_hash", "entry_hash"):
            with self.assertRaises(TypeError):
                IntegrityIssue(code, None)
            with self.assertRaises(ValueError):
                IntegrityIssue(code, -1)


class IntegrityReportTypeTest(unittest.TestCase):
    def test_empty_report(self):
        report = IntegrityReport(True, ())
        self.assertTrue(report.ok)
        self.assertEqual(report.issues, ())
        self.assertEqual(report, IntegrityReport(ok=True, issues=()))

    def test_ok_iff_issues_empty(self):
        issue = IntegrityIssue("index", 0)
        with self.assertRaises(ValueError):
            IntegrityReport(True, (issue,))
        with self.assertRaises(ValueError):
            IntegrityReport(False, ())
        report = IntegrityReport(False, (issue,))
        self.assertFalse(report.ok)
        self.assertEqual(report.issues, (issue,))

    def test_field_equality_and_frozen(self):
        a = IntegrityReport(False, (IntegrityIssue("head", None),))
        b = IntegrityReport(False, (IntegrityIssue("head", None),))
        self.assertEqual(a, b)
        self.assertFalse(a.ok)
        self.assertEqual(a.issues, (IntegrityIssue("head", None),))
        with self.assertRaises(Exception):
            a.ok = True

    def test_issues_must_be_tuple_of_issues(self):
        with self.assertRaises(TypeError):
            IntegrityReport(True, [])
        with self.assertRaises(TypeError):
            IntegrityReport(False, (("index", 0),))

    def test_ok_must_be_bool(self):
        with self.assertRaises(TypeError):
            IntegrityReport(1, ())
        with self.assertRaises(TypeError):
            IntegrityReport(0, ())

    def test_head_issue_must_be_last(self):
        with self.assertRaises(ValueError):
            IntegrityReport(
                False,
                (IntegrityIssue("head", None), IntegrityIssue("index", 0)),
            )

    def test_ascending_index_order(self):
        with self.assertRaises(ValueError):
            IntegrityReport(
                False,
                (IntegrityIssue("entry_hash", 2), IntegrityIssue("index", 1)),
            )

    def test_same_position_code_order(self):
        # Out of canonical order at the same index is rejected.
        with self.assertRaises(ValueError):
            IntegrityReport(
                False,
                (IntegrityIssue("entry_hash", 1), IntegrityIssue("index", 1)),
            )
        # Canonical order at the same index is accepted.
        report = IntegrityReport(
            False,
            (
                IntegrityIssue("index", 1),
                IntegrityIssue("previous_hash", 1),
                IntegrityIssue("entry_hash", 1),
                IntegrityIssue("head", None),
            ),
        )
        self.assertFalse(report.ok)
        self.assertEqual(len(report.issues), 4)


class VerifyReportCleanTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d"):
            self.log.append(record)

    def test_clean_chain_report(self):
        report = self.log.verify_report()
        self.assertTrue(report.ok)
        self.assertEqual(report.issues, ())

    def test_verify_matches_report_ok(self):
        self.assertIs(self.log.verify(), self.log.verify_report().ok)

    def test_empty_log_starts_from_zero_digest(self):
        empty = AuditLog()
        self.assertEqual(empty.head, GENESIS_HASH)
        report = empty.verify_report()
        self.assertTrue(report.ok)

    def test_empty_log_with_alternate_width(self):
        import hashlib

        for hash_name in ("sha512", "sha3-256"):
            log = AuditLog(hash_name=hash_name)
            width = hashlib.new(hash_name).digest_size
            self.assertEqual(log.head, bytes(width))
            self.assertTrue(log.verify_report().ok)
            log.append("a")
            self.assertTrue(log.verify_report().ok)

    def test_call_is_read_only(self):
        self.log._head = b"\x02" * 32  # force a head mismatch
        entries_before = list(self.log._entries)
        head_before = self.log.head
        report = self.log.verify_report()
        self.assertFalse(report.ok)
        self.assertEqual(self.log.head, head_before)
        self.assertEqual(list(self.log._entries), entries_before)


class TailRewriteTest(unittest.TestCase):
    """Regression: a self-consistent relink of the final record used to pass.

    The old verify() walked entry-to-entry and returned True once every held
    entry linked to the next; with no successor after the tail, a rewritten
    last record whose hash matched its payload was never compared to the
    cached chain head.
    """

    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d"):
            self.log.append(record)

    def test_tail_relink_is_detected_via_head(self):
        relink(self.log, 3, b"rewritten-tail")
        report = self.log.verify_report()
        self.assertFalse(report.ok)
        self.assertEqual(report.issues, (IntegrityIssue("head", None),))
        self.assertFalse(self.log.verify())

    def test_head_only_tamper_is_detected(self):
        self.log._head = b"\x09" * 32
        self.assertEqual(
            self.log.verify_report().issues, (IntegrityIssue("head", None),)
        )

    def test_tail_relink_after_prune_is_detected(self):
        self.log.prune(2, self.log.seal(2))
        relink(self.log, 3, b"post-prune-tail")
        report = self.log.verify_report()
        self.assertFalse(report.ok)
        self.assertEqual(report.issues[-1], IntegrityIssue("head", None))

    def test_tail_relink_with_alternate_hash(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b"):
            log.append(record)
        relink(log, 1, b"wide-tail")
        report = log.verify_report()
        self.assertFalse(report.ok)
        self.assertEqual(report.issues, (IntegrityIssue("head", None),))

    def test_fully_pruned_log_detects_head_rewrite(self):
        self.log.prune(4, self.log.seal(4))
        self.assertTrue(self.log.verify_report().ok)
        self.log._head = b"\x03" * 32
        report = self.log.verify_report()
        self.assertFalse(report.ok)
        self.assertEqual(report.issues, (IntegrityIssue("head", None),))


class IssueLocationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d"):
            self.log.append(record)

    def codes(self):
        return [(issue.code, issue.index) for issue in self.log.verify_report().issues]

    def test_payload_tamper_without_relink(self):
        original = self.log.entry(2)
        self.log._entries[2] = Entry(
            original.index, b"tampered", original.previous_hash, original.entry_hash
        )
        self.assertEqual(
            self.codes(),
            [("entry_hash", 2), ("previous_hash", 3), ("entry_hash", 3), ("head", None)],
        )

    def test_middle_relink_propagates_to_successors_and_head(self):
        relink(self.log, 1, b"forged")
        codes = self.codes()
        self.assertEqual(codes[0], ("previous_hash", 2))
        self.assertIn(("entry_hash", 2), codes)
        self.assertIn(("previous_hash", 3), codes)
        self.assertIn(("entry_hash", 3), codes)
        self.assertEqual(codes[-1], ("head", None))
        # Index order is non-decreasing across the whole report.
        indexed = [index for _, index in codes if index is not None]
        self.assertEqual(indexed, sorted(indexed))

    def test_genesis_predecessor_mismatch(self):
        first = self.log.entry(0)
        # Recorded hash still matches the real zero-predecessor digest; only
        # the claimed predecessor is wrong, so exactly one issue is located.
        self.log._entries[0] = Entry(
            first.index, first.payload, b"\x01" * 32, first.entry_hash
        )
        self.assertEqual(self.codes(), [("previous_hash", 0)])

    def test_all_three_codes_at_one_position_in_order(self):
        original = self.log.entry(2)
        self.log._entries[2] = Entry(
            99, original.payload, b"\x09" * 32, b"\x08" * 32
        )
        prefix = [
            ("index", 2),
            ("previous_hash", 2),
            ("entry_hash", 2),
        ]
        self.assertEqual(self.codes()[:3], prefix)

    def test_reordered_entries_are_reported(self):
        self.log._entries[0], self.log._entries[1] = (
            self.log._entries[1],
            self.log._entries[0],
        )
        report = self.log.verify_report()
        self.assertFalse(report.ok)
        self.assertFalse(self.log.verify())
        indices = {issue.index for issue in report.issues if issue.index is not None}
        self.assertTrue({0, 1}.issubset(indices))

    def test_walking_continues_with_expected_values(self):
        # Damage at index 1 does not stop diagnosis at index 2/3.
        relink(self.log, 1, b"x")
        damaged = self.log.entry(3)
        self.log._entries[3] = Entry(
            damaged.index, b"y", damaged.previous_hash, b"\x07" * 32
        )
        indices = {
            issue.index
            for issue in self.log.verify_report().issues
            if issue.index is not None
        }
        self.assertIn(2, indices)
        self.assertIn(3, indices)


class PrunedCheckpointTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in (f"r{i}" for i in range(6)):
            self.log.append(record)
        self.log.prune(2, self.log.seal(2))

    def test_clean_pruned_chain(self):
        self.assertTrue(self.log.verify_report().ok)

    def test_first_retained_predecessor_checked_against_checkpoint(self):
        entry = self.log.entry(2)
        self.log._entries[0] = Entry(
            entry.index, entry.payload, b"\x01" * 32,
            entry_digest(2, b"\x01" * 32, entry.payload),
        )
        report = self.log.verify_report()
        self.assertFalse(report.ok)
        self.assertIn(("previous_hash", 2), [(i.code, i.index) for i in report.issues])

    def test_absolute_indices_in_report(self):
        entry = self.log.entry(4)
        self.log._entries[2] = Entry(
            entry.index, b"z", entry.previous_hash, entry.entry_hash
        )
        indices = [
            issue.index
            for issue in self.log.verify_report().issues
            if issue.code == "entry_hash"
        ]
        # Indices are absolute (not offsets); the change propagates to entry 5.
        self.assertEqual(indices, [4, 5])

    def test_tail_append_after_prune_still_verifies(self):
        self.log.append("r6")
        self.assertTrue(self.log.verify_report().ok)


class IllegalFieldTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("a")

    def replace(self, entry):
        self.log._entries[0] = entry

    def test_non_entry_record(self):
        self.log._entries[0] = ("not", "an", "entry")
        with self.assertRaises(TypeError):
            self.log.verify_report()

    def test_index_wrong_type(self):
        self.replace(Entry("0", b"a", b"\x00" * 32, b"\x00" * 32))
        with self.assertRaises(TypeError):
            self.log.verify_report()

    def test_bool_index(self):
        self.replace(Entry(True, b"a", b"\x00" * 32, b"\x00" * 32))
        with self.assertRaises(TypeError):
            self.log.verify_report()

    def test_negative_index(self):
        self.replace(Entry(-1, b"a", b"\x00" * 32, b"\x00" * 32))
        with self.assertRaises(ValueError):
            self.log.verify_report()

    def test_non_bytes_fields(self):
        self.replace(Entry(0, "a-str", b"\x00" * 32, b"\x00" * 32))
        with self.assertRaises(TypeError):
            self.log.verify_report()
        self.replace(Entry(0, b"a", "0" * 32, b"\x00" * 32))
        with self.assertRaises(TypeError):
            self.log.verify_report()
        self.replace(Entry(0, b"a", b"\x00" * 32, "0" * 32))
        with self.assertRaises(TypeError):
            self.log.verify_report()

    def test_wrong_digest_width(self):
        self.replace(Entry(0, b"a", b"\x00" * 31, b"\x00" * 32))
        with self.assertRaises(ValueError):
            self.log.verify_report()
        self.replace(Entry(0, b"a", b"\x00" * 32, b"\x00" * 33))
        with self.assertRaises(ValueError):
            self.log.verify_report()


if __name__ == "__main__":
    unittest.main()
