import struct
import unittest

from auditchain import (
    AuditLog,
    ContinuationChainReport,
    decode_continuation_chain_report,
    encode_continuation_chain_report,
    inspect_continuation_chain,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

_MAGIC = b"auditchain/chain-report/v1\0"
_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"
_ALL_CODES = (
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


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(n=8, key=_KEY, hash_name="sha256", prefix="record"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _chain(sizes, seed=_SEED_A, n=None, indices=(), **kwargs):
    if n is None:
        n = sizes[-1]
    receipts = []
    old = sizes[0]
    for new in sizes[1:]:
        receipt = _log(n, **kwargs).signed_auth_audit_continuation(
            old, indices, seed, size=new
        )
        receipts.append(receipt)
        old = new
    return tuple(receipts)


class EncodeContinuationChainReportTest(unittest.TestCase):
    def test_success_report_byte_layout(self):
        report = ContinuationChainReport(True, None, None)
        self.assertEqual(
            encode_continuation_chain_report(report),
            _MAGIC + _u64(1) + _u64(0) + _u64(0) + _u64(0),
        )

    def test_failure_report_byte_layout(self):
        report = ContinuationChainReport(False, 7, "verify")
        self.assertEqual(
            encode_continuation_chain_report(report),
            _MAGIC
            + _u64(1)
            + _u64(1)
            + _u64(7)
            + _u64(6)
            + b"verify",
        )

    def test_zero_length_code_blob_never_used_for_failure(self):
        # No legitimate code is the empty string; failure always carries a
        # non-empty blob, success an all-zero u64 prefixed empty one.
        success = encode_continuation_chain_report(
            ContinuationChainReport(True, None, None)
        )
        self.assertTrue(success.endswith(_u64(0)))

    def test_every_legal_code_round_trips(self):
        for position, code in enumerate(_ALL_CODES):
            report = ContinuationChainReport(False, position, code)
            data = encode_continuation_chain_report(report)
            restored = decode_continuation_chain_report(data)
            self.assertEqual(restored, report, code)
            self.assertEqual(
                encode_continuation_chain_report(restored), data, code
            )

    def test_u64_boundary_positions(self):
        for position in (0, 1, 2**32, 2**64 - 1):
            report = ContinuationChainReport(False, position, "end")
            data = encode_continuation_chain_report(report)
            restored = decode_continuation_chain_report(data)
            self.assertEqual(restored, report)
            self.assertEqual(restored.index, position)
            self.assertEqual(
                encode_continuation_chain_report(restored), data
            )

    def test_position_outside_u64_raises_value_error(self):
        report = ContinuationChainReport(False, 0, "verify")
        object.__setattr__(report, "index", 2**64)
        with self.assertRaises(ValueError):
            encode_continuation_chain_report(report)
        big = ContinuationChainReport(False, 0, "verify")
        object.__setattr__(big, "index", 2**64 + 5)
        with self.assertRaises(ValueError):
            encode_continuation_chain_report(big)

    def test_unknown_code_raises_value_error(self):
        for code in ("", "VERIFY", "gap", "rot", "anchor"):
            tampered = ContinuationChainReport(False, 0, "verify")
            object.__setattr__(tampered, "code", code)
            with self.assertRaises(ValueError, msg=code):
                encode_continuation_chain_report(tampered)

    def test_non_report_raises_type_error(self):
        for bad in (
            None,
            True,
            (True, None, None),
            b"",
            object(),
            "report",
            42,
            {"ok": True, "index": None, "code": None},
        ):
            with self.assertRaises(TypeError, msg=bad):
                encode_continuation_chain_report(bad)

    def test_bypassed_fields_of_wrong_type_raise_type_error(self):
        ok_int = ContinuationChainReport(True, None, None)
        object.__setattr__(ok_int, "ok", 1)
        with self.assertRaises(TypeError):
            encode_continuation_chain_report(ok_int)
        ok_str = ContinuationChainReport(True, None, None)
        object.__setattr__(ok_str, "ok", "yes")
        with self.assertRaises(TypeError):
            encode_continuation_chain_report(ok_str)

        for bad_index in (None, "2", 2.0, True, b"2"):
            tampered = ContinuationChainReport(False, 2, "verify")
            object.__setattr__(tampered, "index", bad_index)
            with self.assertRaises(TypeError, msg=bad_index):
                encode_continuation_chain_report(tampered)

        for bad_code in (None, b"verify", 7, 1.2, ("verify",)):
            tampered = ContinuationChainReport(False, 0, "verify")
            object.__setattr__(tampered, "code", bad_code)
            with self.assertRaises(TypeError, msg=bad_code):
                encode_continuation_chain_report(tampered)

    def test_bypassed_negative_index_raises_value_error(self):
        report = ContinuationChainReport(False, 0, "verify")
        object.__setattr__(report, "index", -1)
        with self.assertRaises(ValueError):
            encode_continuation_chain_report(report)

    def test_encode_is_read_only_and_deterministic(self):
        report = ContinuationChainReport(False, 3, "rotation_link")
        first = encode_continuation_chain_report(report)
        second = encode_continuation_chain_report(report)
        self.assertEqual(first, second)
        self.assertEqual(
            (report.ok, report.index, report.code),
            (False, 3, "rotation_link"),
        )


class DecodeContinuationChainReportTest(unittest.TestCase):
    def test_success_round_trip(self):
        report = ContinuationChainReport(True, None, None)
        restored = decode_continuation_chain_report(
            encode_continuation_chain_report(report)
        )
        self.assertEqual(restored, report)
        self.assertIsInstance(restored, ContinuationChainReport)
        self.assertEqual(
            (restored.ok, restored.index, restored.code),
            (True, None, None),
        )
        self.assertEqual(hash(restored), hash(report))

    def test_re_encoding_is_byte_identical(self):
        for report in (
            ContinuationChainReport(True, None, None),
            ContinuationChainReport(False, 0, "verify"),
            ContinuationChainReport(False, 12345, "anchor_link"),
            ContinuationChainReport(False, 2**64 - 1, "end"),
        ):
            data = encode_continuation_chain_report(report)
            restored = decode_continuation_chain_report(data)
            self.assertEqual(
                encode_continuation_chain_report(restored), data
            )

    def test_restored_report_is_frozen(self):
        restored = decode_continuation_chain_report(
            encode_continuation_chain_report(
                ContinuationChainReport(False, 1, "link")
            )
        )
        with self.assertRaises(Exception):
            restored.ok = True
        with self.assertRaises(Exception):
            restored.index = None
        with self.assertRaises(Exception):
            restored.code = None

    def test_non_bytes_raises_type_error(self):
        encoded = encode_continuation_chain_report(
            ContinuationChainReport(True, None, None)
        )
        for bad in (
            bytearray(encoded),
            memoryview(encoded),
            None,
            encoded.decode("latin-1"),
            42,
            [encoded],
        ):
            with self.assertRaises(TypeError, msg=type(bad)):
                decode_continuation_chain_report(bad)

    def test_bad_magic_raises_value_error(self):
        data = b"auditchain/chain-report/v2\0" + _u64(1) + _u64(0) * 3
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(b"")
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(_MAGIC[:-1])

    def test_bad_version_raises_value_error(self):
        good = encode_continuation_chain_report(
            ContinuationChainReport(True, None, None)
        )
        for version in (0, 2, 2**64 - 1):
            data = _MAGIC + _u64(version) + good[len(_MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_continuation_chain_report(data)

    def test_bad_verdict_raises_value_error(self):
        for verdict in (2, 3, 255, 2**64 - 1):
            data = (
                _MAGIC + _u64(1) + _u64(verdict) + _u64(0) + _u64(0)
            )
            with self.assertRaises(ValueError, msg=verdict):
                decode_continuation_chain_report(data)

    def test_truncation_raises_value_error(self):
        success = encode_continuation_chain_report(
            ContinuationChainReport(True, None, None)
        )
        failure = encode_continuation_chain_report(
            ContinuationChainReport(False, 4, "verify")
        )
        for full in (success, failure):
            for cut in range(len(_MAGIC), len(full)):
                with self.assertRaises(ValueError, msg=(len(full), cut)):
                    decode_continuation_chain_report(full[:cut])

    def test_trailing_bytes_raise_value_error(self):
        data = encode_continuation_chain_report(
            ContinuationChainReport(True, None, None)
        )
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data + b"\x00")
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data + b"trailing")

    def test_blob_length_overflow_raises_value_error(self):
        data = (
            _MAGIC
            + _u64(1)
            + _u64(1)
            + _u64(0)
            + _u64(2**64 - 1)
        )
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_success_with_position_raises_value_error(self):
        data = _MAGIC + _u64(1) + _u64(0) + _u64(9) + _u64(0)
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_success_with_code_raises_value_error(self):
        data = (
            _MAGIC
            + _u64(1)
            + _u64(0)
            + _u64(0)
            + _u64(6)
            + b"verify"
        )
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_failure_without_code_raises_value_error(self):
        data = _MAGIC + _u64(1) + _u64(1) + _u64(0) + _u64(0)
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)

    def test_unknown_code_raises_value_error(self):
        for code in ("", "VERIFY", "gap", "rot", "anchor_link "):
            raw = code.encode("utf-8")
            data = (
                _MAGIC
                + _u64(1)
                + _u64(1)
                + _u64(0)
                + _u64(len(raw))
                + raw
            )
            with self.assertRaises(ValueError, msg=code):
                decode_continuation_chain_report(data)

    def test_invalid_utf8_code_raises_value_error(self):
        data = (
            _MAGIC
            + _u64(1)
            + _u64(1)
            + _u64(0)
            + _u64(1)
            + b"\xff"
        )
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(data)
        truncated_utf8 = (
            _MAGIC
            + _u64(1)
            + _u64(1)
            + _u64(3)
            + _u64(2)
            + b"\xc3\x28"
        )
        with self.assertRaises(ValueError):
            decode_continuation_chain_report(truncated_utf8)


class DiagnosticIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_real_success_and_failure_reports_survive_round_trip(self):
        good = inspect_continuation_chain(
            _chain((0, 2, 5, 8)), self.public_key
        )
        bad = inspect_continuation_chain(
            _chain((0, 2, 5)), self.other_public_key
        )
        self.assertEqual(
            good, ContinuationChainReport(True, None, None)
        )
        self.assertEqual(
            bad, ContinuationChainReport(False, 0, "verify")
        )
        for report in (good, bad):
            data = encode_continuation_chain_report(report)
            restored = decode_continuation_chain_report(data)
            self.assertEqual(restored, report)
            self.assertIs(restored.ok, report.ok)
            self.assertEqual(restored.index, report.index)
            self.assertEqual(restored.code, report.code)
            self.assertEqual(
                encode_continuation_chain_report(restored), data
            )

    def test_conclusion_agrees_across_real_cases(self):
        cases = (
            inspect_continuation_chain(
                _chain((0, 2, 5)), self.public_key
            ),
            inspect_continuation_chain(
                _chain((0, 2, 5)), self.other_public_key
            ),
        )
        for report in cases:
            restored = decode_continuation_chain_report(
                encode_continuation_chain_report(report)
            )
            self.assertEqual(restored.ok, report.ok)
            self.assertEqual(
                (report.ok, report.index, report.code),
                (restored.ok, restored.index, restored.code),
            )


if __name__ == "__main__":
    unittest.main()
