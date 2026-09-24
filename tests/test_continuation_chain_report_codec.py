import unittest

from auditchain import (
    ContinuationChainReport,
    decode_continuation_chain_report,
    encode_continuation_chain_report,
)

MAGIC = b"auditchain/chain-report/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


CODES = (
    "verify",
    "growth",
    "duplicate",
    "link",
    "start",
    "end",
    "anchor_link",
    "rotation_duplicate",
    "rotation",
    "rotation_link",
)


class EncodeContinuationChainReportTest(unittest.TestCase):
    def test_success_layout(self):
        data = encode_continuation_chain_report(
            ContinuationChainReport(True, None, None)
        )
        self.assertEqual(data, MAGIC + u64(1) + u64(0) + u64(0) + u64(0))

    def test_failure_layout(self):
        for code in CODES:
            report = ContinuationChainReport(False, 3, code)
            data = encode_continuation_chain_report(report)
            self.assertEqual(
                data,
                MAGIC + u64(1) + u64(1) + u64(3) + blob(code.encode("utf-8")),
            )

    def test_failure_index_zero(self):
        report = ContinuationChainReport(False, 0, "verify")
        data = encode_continuation_chain_report(report)
        self.assertEqual(data, MAGIC + u64(1) + u64(1) + u64(0) + blob(b"verify"))

    def test_deterministic(self):
        report = ContinuationChainReport(False, 7, "link")
        self.assertEqual(
            encode_continuation_chain_report(report),
            encode_continuation_chain_report(report),
        )

    def test_type_errors(self):
        for bad in (None, "report", b"bytes", (True, None, None), 0):
            with self.assertRaises(TypeError):
                encode_continuation_chain_report(bad)

    def test_bypassed_field_type_errors(self):
        for field, value in (("ok", 1), ("index", "x"), ("code", 5)):
            report = ContinuationChainReport(False, 1, "verify")
            object.__setattr__(report, field, value)
            with self.assertRaises(TypeError):
                encode_continuation_chain_report(report)

    def test_index_out_of_u64_range(self):
        report = ContinuationChainReport(False, 1, "verify")
        object.__setattr__(report, "index", 1 << 64)
        with self.assertRaises(ValueError):
            encode_continuation_chain_report(report)


class DecodeContinuationChainReportTest(unittest.TestCase):
    def test_round_trip_success(self):
        report = ContinuationChainReport(True, None, None)
        data = encode_continuation_chain_report(report)
        restored = decode_continuation_chain_report(data)
        self.assertEqual(restored, report)
        self.assertTrue(restored.ok)
        self.assertEqual(encode_continuation_chain_report(restored), data)

    def test_round_trip_failures(self):
        for index in (0, 1, 17):
            for code in CODES:
                report = ContinuationChainReport(False, index, code)
                data = encode_continuation_chain_report(report)
                restored = decode_continuation_chain_report(data)
                self.assertEqual(restored, report)
                self.assertFalse(restored.ok)
                self.assertEqual(
                    encode_continuation_chain_report(restored), data
                )

    def test_type_errors(self):
        good = encode_continuation_chain_report(
            ContinuationChainReport(True, None, None)
        )
        for bad in (None, "data", bytearray(good), memoryview(good)):
            with self.assertRaises(TypeError):
                decode_continuation_chain_report(bad)

    def test_bad_magic(self):
        data = b"auditchain/chain-report/v2\0" + u64(1) * 4
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_bad_version(self):
        data = MAGIC + u64(2) + u64(0) + u64(0) + u64(0)
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_bad_verdict(self):
        data = MAGIC + u64(1) + u64(2) + u64(0) + u64(0)
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_success_with_position(self):
        data = MAGIC + u64(1) + u64(0) + u64(1) + u64(0)
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_success_with_code(self):
        data = MAGIC + u64(1) + u64(0) + u64(0) + blob(b"verify")
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_failure_missing_code(self):
        data = MAGIC + u64(1) + u64(1) + u64(2) + u64(0)
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_unknown_code(self):
        data = MAGIC + u64(1) + u64(1) + u64(2) + blob(b"unknown")
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_invalid_utf8_code(self):
        data = MAGIC + u64(1) + u64(1) + u64(2) + blob(b"\xff")
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_truncated(self):
        data = encode_continuation_chain_report(
            ContinuationChainReport(False, 2, "link")
        )
        for cut in (len(MAGIC), len(MAGIC) + 4, len(data) - 1):
            with self.assertRaises(ValueError):
                decode_continuation_chain_report(data[:cut])

    def test_trailing_bytes(self):
        data = (
            encode_continuation_chain_report(
                ContinuationChainReport(True, None, None)
            )
            + b"x"
        )
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1) + u64(2) + u64(1 << 40)
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)


if __name__ == "__main__":
    unittest.main()
