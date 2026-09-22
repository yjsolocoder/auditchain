import unittest

from auditchain import (
    AuditLog,
    ContinuationChainReport,
    SignedAuthAuditContinuation,
    SignedConsistency,
    encode_signed_auth_audit_continuation,
    inspect_continuation_chain,
    verify_continuation_chain,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"


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


class ContinuationChainReportTest(unittest.TestCase):
    def test_success_report_shape(self):
        report = ContinuationChainReport(True, None, None)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)

    def test_positional_construction_and_field_equality(self):
        self.assertEqual(
            ContinuationChainReport(False, 1, "link"),
            ContinuationChainReport(False, 1, "link"),
        )
        self.assertNotEqual(
            ContinuationChainReport(False, 1, "link"),
            ContinuationChainReport(False, 1, "duplicate"),
        )
        self.assertNotEqual(
            ContinuationChainReport(False, 1, "link"),
            ContinuationChainReport(False, 2, "link"),
        )
        self.assertEqual(
            hash(ContinuationChainReport(False, 0, "verify")),
            hash(ContinuationChainReport(False, 0, "verify")),
        )

    def test_report_is_frozen(self):
        report = ContinuationChainReport(True, None, None)
        with self.assertRaises(AttributeError):
            report.ok = False

    def test_unknown_code_raises_value_error(self):
        with self.assertRaises(ValueError):
            ContinuationChainReport(False, 0, "bogus")

    def test_success_must_carry_no_index_or_code(self):
        with self.assertRaises(ValueError):
            ContinuationChainReport(True, 0, None)
        with self.assertRaises(ValueError):
            ContinuationChainReport(True, None, "verify")

    def test_failure_must_carry_index_and_code(self):
        with self.assertRaises(ValueError):
            ContinuationChainReport(False, None, "verify")
        with self.assertRaises(ValueError):
            ContinuationChainReport(False, 0, None)

    def test_field_type_errors(self):
        with self.assertRaises(TypeError):
            ContinuationChainReport(1, None, None)
        with self.assertRaises(TypeError):
            ContinuationChainReport(False, "0", "verify")
        with self.assertRaises(TypeError):
            ContinuationChainReport(False, True, "verify")
        with self.assertRaises(TypeError):
            ContinuationChainReport(False, 0, 1)

    def test_negative_index_raises_value_error(self):
        with self.assertRaises(ValueError):
            ContinuationChainReport(False, -1, "verify")


class InspectContinuationChainTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_valid_chain_returns_success_report(self):
        receipts = _chain((0, 2, 5, 8))
        self.assertEqual(
            inspect_continuation_chain(receipts, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_single_growing_segment_succeeds(self):
        self.assertEqual(
            inspect_continuation_chain(_chain((2, 5)), self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_untrusted_key_reports_verify_at_first_segment(self):
        receipts = _chain((0, 2, 5))
        self.assertEqual(
            inspect_continuation_chain(receipts, self.other_public_key),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_foreign_segment_reports_verify_at_its_position(self):
        first = _chain((0, 4))[0]
        bad = _chain((2, 6), seed=_SEED_B)[0]
        self.assertEqual(
            inspect_continuation_chain((first, bad), self.public_key),
            ContinuationChainReport(False, 1, "verify"),
        )

    def test_tampered_segment_reports_verify(self):
        receipts = list(_chain((0, 2, 5)))
        old = receipts[1].consistency.old
        forged_old = type(old)(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        forged_consistency = SignedConsistency(
            forged_old,
            receipts[1].consistency.new,
            receipts[1].consistency.proof,
        )
        receipts[1] = SignedAuthAuditContinuation(
            receipts[1].bundle, forged_consistency
        )
        self.assertEqual(
            inspect_continuation_chain(tuple(receipts), self.public_key),
            ContinuationChainReport(False, 1, "verify"),
        )

    def test_zero_length_segment_reports_growth(self):
        equal = _log(5).signed_auth_audit_continuation(
            3, (), _SEED_A, size=3
        )
        self.assertEqual(
            inspect_continuation_chain((equal,), self.public_key),
            ContinuationChainReport(False, 0, "growth"),
        )

    def test_growth_reported_at_its_own_position(self):
        first = _chain((0, 4))[0]
        equal = _log(5).signed_auth_audit_continuation(
            3, (), _SEED_A, size=3
        )
        self.assertEqual(
            inspect_continuation_chain((first, equal), self.public_key),
            ContinuationChainReport(False, 1, "growth"),
        )

    def test_adjacent_mismatch_reports_link(self):
        first = _chain((0, 5))[0]
        second = _chain((3, 8))[0]
        self.assertEqual(
            inspect_continuation_chain((first, second), self.public_key),
            ContinuationChainReport(False, 1, "link"),
        )

    def test_same_boundary_but_different_history_reports_link(self):
        first = _log(8, prefix="record").signed_auth_audit_continuation(
            0, (), _SEED_A, size=4
        )
        second = _log(8, prefix="other").signed_auth_audit_continuation(
            4, (), _SEED_A, size=8
        )
        self.assertEqual(
            inspect_continuation_chain((first, second), self.public_key),
            ContinuationChainReport(False, 1, "link"),
        )

    def test_duplicate_segment_reports_duplicate(self):
        receipt = _chain((2, 5))[0]
        self.assertEqual(
            inspect_continuation_chain(
                (receipt, receipt), self.public_key
            ),
            ContinuationChainReport(False, 1, "duplicate"),
        )

    def test_duplicate_non_adjacent_reports_earliest_repeat(self):
        first = _chain((0, 3))[0]
        middle = _chain((3, 6))[0]
        again = _chain((0, 3))[0]
        self.assertEqual(first, again)
        self.assertEqual(
            inspect_continuation_chain(
                (first, middle, again), self.public_key
            ),
            ContinuationChainReport(False, 2, "duplicate"),
        )

    def test_only_the_earliest_problem_is_reported(self):
        # The verify failure at index 0 hides the duplicate at index 1.
        bad = _chain((2, 6), seed=_SEED_B)[0]
        self.assertEqual(
            inspect_continuation_chain((bad, bad), self.public_key),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_agrees_with_verify_continuation_chain(self):
        receipt = _chain((2, 5))[0]
        equal = _log(5).signed_auth_audit_continuation(
            3, (), _SEED_A, size=3
        )
        cases = [
            (_chain((0, 2, 5, 8)), self.public_key),
            (_chain((0, 2, 5)), self.other_public_key),
            ((receipt, receipt), self.public_key),
            ((_chain((0, 5))[0], _chain((3, 8))[0]), self.public_key),
            ((equal,), self.public_key),
        ]
        for receipts, key in cases:
            with self.subTest(receipts=receipts):
                self.assertEqual(
                    inspect_continuation_chain(receipts, key).ok,
                    verify_continuation_chain(receipts, key),
                )

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            inspect_continuation_chain((), self.public_key)

    def test_non_tuple_raises_type_error(self):
        receipt = _chain((2, 5))[0]
        for bad in ([receipt], {receipt}, None, receipt, "receipts", 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_continuation_chain(bad, self.public_key)

    def test_generator_raises_type_error(self):
        gen = (r for r in _chain((2, 5)))
        with self.assertRaises(TypeError):
            inspect_continuation_chain(gen, self.public_key)

    def test_wrong_element_type_raises_type_error(self):
        receipt = _chain((2, 5))[0]
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                inspect_continuation_chain((bad,), self.public_key)
            with self.assertRaises(TypeError, msg=bad):
                inspect_continuation_chain((receipt, bad), self.public_key)

    def test_public_key_length_raises_value_error(self):
        receipts = _chain((2, 5))
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                inspect_continuation_chain(receipts, bad)

    def test_public_key_type_raises_type_error(self):
        receipts = _chain((2, 5))
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError):
                inspect_continuation_chain(receipts, bad)

    def test_call_is_read_only(self):
        receipts = _chain((0, 2, 5))
        before = tuple(
            encode_signed_auth_audit_continuation(r) for r in receipts
        )
        inspect_continuation_chain(receipts, self.public_key)
        after = tuple(
            encode_signed_auth_audit_continuation(r) for r in receipts
        )
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
