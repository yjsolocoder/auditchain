import unittest

from auditchain import (
    AuditLog,
    Entry,
    IntegrityIssue,
    IntegrityReport,
    decode_integrity_report,
    encode_integrity_report,
)

MAGIC = b"auditchain/integrity-report/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def issue_bytes(code, position):
    return blob(code.encode("utf-8")) + u64(position)


class EncodeIntegrityReportTest(unittest.TestCase):
    def test_success_layout(self):
        data = encode_integrity_report(IntegrityReport(True, ()))
        self.assertEqual(data, MAGIC + u64(1) + u64(0) + u64(0))

    def test_failure_layout_single_issue(self):
        report = IntegrityReport(False, (IntegrityIssue("index", 3),))
        data = encode_integrity_report(report)
        self.assertEqual(
            data, MAGIC + u64(1) + u64(1) + u64(1) + issue_bytes("index", 3)
        )

    def test_head_issue_writes_zero_position(self):
        report = IntegrityReport(False, (IntegrityIssue("head", None),))
        data = encode_integrity_report(report)
        self.assertEqual(
            data, MAGIC + u64(1) + u64(1) + u64(1) + issue_bytes("head", 0)
        )

    def test_multi_issue_layout_in_report_order(self):
        report = IntegrityReport(
            False,
            (
                IntegrityIssue("index", 2),
                IntegrityIssue("previous_hash", 2),
                IntegrityIssue("entry_hash", 2),
                IntegrityIssue("previous_hash", 5),
                IntegrityIssue("head", None),
            ),
        )
        data = encode_integrity_report(report)
        self.assertEqual(
            data,
            MAGIC
            + u64(1)
            + u64(1)
            + u64(5)
            + issue_bytes("index", 2)
            + issue_bytes("previous_hash", 2)
            + issue_bytes("entry_hash", 2)
            + issue_bytes("previous_hash", 5)
            + issue_bytes("head", 0),
        )

    def test_deterministic(self):
        report = IntegrityReport(False, (IntegrityIssue("entry_hash", 7),))
        self.assertEqual(
            encode_integrity_report(report), encode_integrity_report(report)
        )

    def test_type_errors(self):
        for bad in (None, "report", b"bytes", (True, ()), 0):
            with self.assertRaises(TypeError):
                encode_integrity_report(bad)

    def test_bypassed_field_type_errors(self):
        for field, value in (("ok", 1), ("issues", []), ("issues", (("index", 0),))):
            report = IntegrityReport(False, (IntegrityIssue("index", 0),))
            object.__setattr__(report, field, value)
            with self.assertRaises(TypeError):
                encode_integrity_report(report)

    def test_bypassed_issue_field_type_errors(self):
        for field, value in (("code", 5), ("index", "x"), ("index", True)):
            report = IntegrityReport(False, (IntegrityIssue("index", 0),))
            object.__setattr__(report.issues[0], field, value)
            with self.assertRaises(TypeError):
                encode_integrity_report(report)

    def test_bypassed_value_errors(self):
        # An illegal code, a code/position mismatch or a broken issue order
        # raise ValueError even when the frozen constructor was bypassed.
        report = IntegrityReport(False, (IntegrityIssue("index", 0),))
        object.__setattr__(report.issues[0], "code", "nope")
        with self.assertRaises(ValueError):
            encode_integrity_report(report)
        report = IntegrityReport(False, (IntegrityIssue("head", None),))
        object.__setattr__(report.issues[0], "index", 1)
        with self.assertRaises(ValueError):
            encode_integrity_report(report)
        report = IntegrityReport(
            False, (IntegrityIssue("index", 0), IntegrityIssue("index", 1))
        )
        object.__setattr__(
            report,
            "issues",
            (IntegrityIssue("index", 1), IntegrityIssue("index", 0)),
        )
        with self.assertRaises(ValueError):
            encode_integrity_report(report)

    def test_index_out_of_u64_range(self):
        report = IntegrityReport(False, (IntegrityIssue("index", 0),))
        object.__setattr__(report.issues[0], "index", 1 << 64)
        with self.assertRaises(ValueError):
            encode_integrity_report(report)


class DecodeIntegrityReportTest(unittest.TestCase):
    def test_round_trip_success(self):
        report = IntegrityReport(True, ())
        data = encode_integrity_report(report)
        restored = decode_integrity_report(data)
        self.assertEqual(restored, report)
        self.assertTrue(restored.ok)
        self.assertEqual(encode_integrity_report(restored), data)

    def test_round_trip_failures(self):
        reports = [
            IntegrityReport(False, (IntegrityIssue(code, 3),))
            for code in ("index", "previous_hash", "entry_hash")
        ]
        reports.append(IntegrityReport(False, (IntegrityIssue("head", None),)))
        reports.append(
            IntegrityReport(
                False,
                (
                    IntegrityIssue("index", 2),
                    IntegrityIssue("previous_hash", 2),
                    IntegrityIssue("entry_hash", 2),
                    IntegrityIssue("entry_hash", 9),
                    IntegrityIssue("head", None),
                ),
            )
        )
        for report in reports:
            data = encode_integrity_report(report)
            restored = decode_integrity_report(data)
            self.assertEqual(restored, report)
            self.assertFalse(restored.ok)
            self.assertEqual(encode_integrity_report(restored), data)

    def test_round_trip_from_log(self):
        log = AuditLog()
        for record in ("a", "b", "c", "d"):
            log.append(record)
        clean = log.verify_report()
        self.assertEqual(decode_integrity_report(encode_integrity_report(clean)), clean)
        original = log.entry(2)
        log._entries[2] = Entry(
            original.index, b"tampered", original.previous_hash, original.entry_hash
        )
        damaged = log.verify_report()
        restored = decode_integrity_report(encode_integrity_report(damaged))
        self.assertEqual(restored, damaged)
        self.assertEqual(restored.ok, log.verify())

    def test_restored_report_is_frozen(self):
        restored = decode_integrity_report(
            encode_integrity_report(IntegrityReport(True, ()))
        )
        with self.assertRaises(Exception):
            restored.ok = False

    def test_type_errors(self):
        good = encode_integrity_report(IntegrityReport(True, ()))
        for bad in (None, "data", bytearray(good), memoryview(good)):
            with self.assertRaises(TypeError):
                decode_integrity_report(bad)

    def test_bad_magic(self):
        data = b"auditchain/integrity-report/v2\0" + u64(1) + u64(0) + u64(0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_bad_version(self):
        data = MAGIC + u64(2) + u64(0) + u64(0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_bad_verdict(self):
        data = MAGIC + u64(1) + u64(2) + u64(0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_success_with_issues(self):
        data = MAGIC + u64(1) + u64(0) + u64(1) + issue_bytes("index", 0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_failure_without_issues(self):
        data = MAGIC + u64(1) + u64(1) + u64(0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_unknown_code(self):
        data = MAGIC + u64(1) + u64(1) + u64(1) + issue_bytes("unknown", 0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_empty_code(self):
        data = MAGIC + u64(1) + u64(1) + u64(1) + u64(0) + u64(0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_invalid_utf8_code(self):
        data = MAGIC + u64(1) + u64(1) + u64(1) + blob(b"\xff") + u64(0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_head_with_nonzero_position(self):
        data = MAGIC + u64(1) + u64(1) + u64(1) + issue_bytes("head", 4)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_head_not_last(self):
        data = (
            MAGIC
            + u64(1)
            + u64(1)
            + u64(2)
            + issue_bytes("head", 0)
            + issue_bytes("index", 0)
        )
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_descending_positions(self):
        data = (
            MAGIC
            + u64(1)
            + u64(1)
            + u64(2)
            + issue_bytes("index", 2)
            + issue_bytes("index", 1)
        )
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_same_position_code_order(self):
        data = (
            MAGIC
            + u64(1)
            + u64(1)
            + u64(2)
            + issue_bytes("entry_hash", 1)
            + issue_bytes("index", 1)
        )
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_truncated(self):
        data = encode_integrity_report(
            IntegrityReport(False, (IntegrityIssue("index", 2),))
        )
        for cut in (len(MAGIC), len(MAGIC) + 4, len(data) - 1):
            with self.assertRaises(ValueError):
                decode_integrity_report(data[:cut])

    def test_trailing_bytes(self):
        data = encode_integrity_report(IntegrityReport(True, ())) + b"x"
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1) + u64(1) + u64(1 << 40)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)


if __name__ == "__main__":
    unittest.main()
