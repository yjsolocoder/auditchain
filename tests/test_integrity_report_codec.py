import unittest

from auditchain import (
    AuditLog,
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


CODES = ("index", "previous_hash", "entry_hash", "head")


def failing_report():
    return IntegrityReport(
        False,
        (
            IntegrityIssue("index", 3),
            IntegrityIssue("previous_hash", 3),
            IntegrityIssue("entry_hash", 3),
            IntegrityIssue("index", 7),
            IntegrityIssue("head", None),
        ),
    )


class EncodeIntegrityReportTest(unittest.TestCase):
    def test_success_layout(self):
        data = encode_integrity_report(IntegrityReport(True, ()))
        self.assertEqual(data, MAGIC + u64(1) + u64(0) + u64(0))

    def test_failure_layout(self):
        data = encode_integrity_report(failing_report())
        expected = MAGIC + u64(1) + u64(1) + u64(5)
        for code, position in (
            ("index", 3),
            ("previous_hash", 3),
            ("entry_hash", 3),
            ("index", 7),
            ("head", 0),
        ):
            expected += blob(code.encode("utf-8")) + u64(position)
        self.assertEqual(data, expected)

    def test_single_issue_layouts(self):
        for code in CODES:
            index = None if code == "head" else 0
            report = IntegrityReport(False, (IntegrityIssue(code, index),))
            data = encode_integrity_report(report)
            self.assertEqual(
                data,
                MAGIC + u64(1) + u64(1) + u64(1) + blob(code.encode("utf-8"))
                + u64(index or 0),
            )

    def test_deterministic(self):
        report = failing_report()
        self.assertEqual(
            encode_integrity_report(report), encode_integrity_report(report)
        )

    def test_from_verify_report(self):
        log = AuditLog()
        log.append("a")
        log.append("b")
        report = log.verify_report()
        self.assertTrue(report.ok)
        self.assertEqual(
            decode_integrity_report(encode_integrity_report(report)), report
        )

    def test_type_errors(self):
        for bad in (None, "report", b"bytes", (True, ()), 0):
            with self.assertRaises(TypeError):
                encode_integrity_report(bad)

    def test_bypassed_field_type_errors(self):
        report = IntegrityReport(False, (IntegrityIssue("index", 1),))
        object.__setattr__(report, "ok", 1)
        with self.assertRaises(TypeError):
            encode_integrity_report(report)
        report = IntegrityReport(False, (IntegrityIssue("index", 1),))
        object.__setattr__(report, "issues", [IntegrityIssue("index", 1)])
        with self.assertRaises(TypeError):
            encode_integrity_report(report)
        report = IntegrityReport(False, (IntegrityIssue("index", 1),))
        object.__setattr__(report, "issues", ("issue",))
        with self.assertRaises(TypeError):
            encode_integrity_report(report)
        for field, value in (("code", 5), ("index", "x")):
            issue = IntegrityIssue("index", 1)
            object.__setattr__(issue, field, value)
            report = IntegrityReport(False, (IntegrityIssue("index", 1),))
            object.__setattr__(report, "issues", (issue,))
            with self.assertRaises(TypeError):
                encode_integrity_report(report)

    def test_bypassed_field_value_errors(self):
        issue = IntegrityIssue("index", 1)
        object.__setattr__(issue, "code", "unknown")
        report = IntegrityReport(False, (IntegrityIssue("index", 1),))
        object.__setattr__(report, "issues", (issue,))
        with self.assertRaises(ValueError):
            encode_integrity_report(report)
        issue = IntegrityIssue("head", None)
        object.__setattr__(issue, "index", 4)
        report = IntegrityReport(False, (IntegrityIssue("index", 1),))
        object.__setattr__(report, "issues", (issue,))
        with self.assertRaises(ValueError):
            encode_integrity_report(report)
        report = IntegrityReport(False, (IntegrityIssue("index", 1),))
        object.__setattr__(
            report,
            "issues",
            (IntegrityIssue("index", 5), IntegrityIssue("index", 2)),
        )
        with self.assertRaises(ValueError):
            encode_integrity_report(report)

    def test_index_out_of_u64_range(self):
        issue = IntegrityIssue("index", 1)
        object.__setattr__(issue, "index", 1 << 64)
        report = IntegrityReport(False, (IntegrityIssue("index", 1),))
        object.__setattr__(report, "issues", (issue,))
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
        for index in (0, 1, 17):
            for code in CODES:
                issue = IntegrityIssue(
                    code, None if code == "head" else index
                )
                report = IntegrityReport(False, (issue,))
                data = encode_integrity_report(report)
                restored = decode_integrity_report(data)
                self.assertEqual(restored, report)
                self.assertFalse(restored.ok)
                self.assertEqual(encode_integrity_report(restored), data)

    def test_round_trip_multi_issue(self):
        report = failing_report()
        data = encode_integrity_report(report)
        restored = decode_integrity_report(data)
        self.assertEqual(restored, report)
        self.assertEqual(restored.issues, report.issues)
        self.assertEqual(encode_integrity_report(restored), data)

    def test_type_errors(self):
        good = encode_integrity_report(IntegrityReport(True, ()))
        for bad in (None, "data", bytearray(good), memoryview(good)):
            with self.assertRaises(TypeError):
                decode_integrity_report(bad)

    def test_bad_magic(self):
        data = b"auditchain/integrity-report/v2\0" + u64(1) * 3
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
        data = MAGIC + u64(1) + u64(0) + u64(1) + blob(b"head") + u64(0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_failure_missing_issues(self):
        data = MAGIC + u64(1) + u64(1) + u64(0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_unknown_code(self):
        data = MAGIC + u64(1) + u64(1) + u64(1) + blob(b"unknown") + u64(0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_invalid_utf8_code(self):
        data = MAGIC + u64(1) + u64(1) + u64(1) + blob(b"\xff") + u64(0)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_head_with_position(self):
        data = MAGIC + u64(1) + u64(1) + u64(1) + blob(b"head") + u64(5)
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_head_not_last(self):
        data = (
            MAGIC + u64(1) + u64(1) + u64(2)
            + blob(b"head") + u64(0)
            + blob(b"index") + u64(1)
        )
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_descending_positions(self):
        data = (
            MAGIC + u64(1) + u64(1) + u64(2)
            + blob(b"index") + u64(5)
            + blob(b"index") + u64(2)
        )
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_same_position_code_order(self):
        data = (
            MAGIC + u64(1) + u64(1) + u64(2)
            + blob(b"entry_hash") + u64(3)
            + blob(b"index") + u64(3)
        )
        with self.assertRaises(ValueError):
            decode_integrity_report(data)

    def test_truncated(self):
        data = encode_integrity_report(failing_report())
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
