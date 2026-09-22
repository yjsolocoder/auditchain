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
    """Issue one fresh log per segment, all on identical content, so the
    checkpoints match across segments."""
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


class InspectContinuationChainTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_success_report_shape(self):
        report = inspect_continuation_chain(_chain((2, 5)), self.public_key)
        self.assertEqual(
            report, ContinuationChainReport(True, None, None)
        )
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)
        self.assertEqual((report.ok, report.index, report.code), (True, None, None))

    def test_single_growing_segment_reports_ok(self):
        self.assertEqual(
            inspect_continuation_chain(_chain((2, 5)), self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_continuous_multi_segment_chain_reports_ok(self):
        receipts = _chain((0, 2, 5, 8))
        self.assertEqual(
            inspect_continuation_chain(receipts, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_success_reports_agree_with_bool_verifier(self):
        receipts = _chain((0, 2, 5, 8))
        self.assertTrue(
            verify_continuation_chain(receipts, self.public_key)
        )
        self.assertEqual(
            inspect_continuation_chain(receipts, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_untrusted_key_reports_verify_at_zero(self):
        receipts = _chain((0, 2, 5))
        self.assertEqual(
            inspect_continuation_chain(receipts, self.other_public_key),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_one_bad_segment_reports_verify_at_its_index(self):
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

    def test_shrinking_segment_reports_growth_at_its_index(self):
        first = _chain((0, 5))[0]
        # A genuine receipt whose new size is smaller than its old size can
        # never be issued, so equal-size stands in for the non-growing class;
        # position is still the current segment.
        second = _log(5).signed_auth_audit_continuation(
            3, (), _SEED_A, size=3
        )
        self.assertEqual(
            inspect_continuation_chain((first, second), self.public_key),
            ContinuationChainReport(False, 1, "growth"),
        )

    def test_adjacent_mismatch_reports_link_at_following_index(self):
        first = _chain((0, 5))[0]
        second = _chain((3, 8))[0]
        self.assertEqual(
            inspect_continuation_chain(
                (first, second), self.public_key
            ),
            ContinuationChainReport(False, 1, "link"),
        )

    def test_same_boundary_different_history_reports_link(self):
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

    def test_duplicate_adjacent_segment_reports_duplicate(self):
        receipt = _chain((2, 5))[0]
        self.assertEqual(
            inspect_continuation_chain(
                (receipt, receipt), self.public_key
            ),
            ContinuationChainReport(False, 1, "duplicate"),
        )

    def test_duplicate_non_adjacent_segment_reports_duplicate(self):
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

    def test_only_earliest_problem_is_reported(self):
        # A broken join at index 1 masks a duplicate at index 2.
        first = _chain((0, 5))[0]
        mismatched = _chain((3, 8))[0]
        repeated = _chain((0, 5))[0]
        self.assertEqual(
            inspect_continuation_chain(
                (first, mismatched, repeated), self.public_key
            ),
            ContinuationChainReport(False, 1, "link"),
        )

    def test_verify_at_zero_masks_later_growth(self):
        bad = _chain((2, 6), seed=_SEED_B)[0]
        equal = _log(5).signed_auth_audit_continuation(
            3, (), _SEED_A, size=3
        )
        self.assertEqual(
            inspect_continuation_chain((bad, equal), self.public_key),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_growth_checked_before_duplicate_and_link(self):
        # The first segment is non-growing; even though it repeats nothing
        # later phases are never reached, the code is "growth".
        equal = _log(5).signed_auth_audit_continuation(
            3, (), _SEED_A, size=3
        )
        second = _chain((3, 8))[0]
        self.assertEqual(
            inspect_continuation_chain((equal, second), self.public_key),
            ContinuationChainReport(False, 0, "growth"),
        )

    def test_duplicate_checked_before_link_at_same_segment(self):
        # At index 2 the segment is both a repeat of an earlier receipt and a
        # broken join; within phase 2 the duplicate check fires first.
        first = _chain((0, 3))[0]
        middle = _chain((3, 6))[0]
        repeated = _chain((0, 3))[0]
        self.assertEqual(
            inspect_continuation_chain(
                (first, middle, repeated), self.public_key
            ),
            ContinuationChainReport(False, 2, "duplicate"),
        )

    def test_empty_tuple_value_error(self):
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
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_continuation_chain(receipts, bad)

    def test_public_key_type_raises_type_error(self):
        receipts = _chain((2, 5))
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_continuation_chain(receipts, bad)

    def test_nested_structural_violation_propagates(self):
        # Bypass the frozen constructors to plant a non-bytes proof node;
        # the nested verifier raises TypeError, which must propagate rather
        # than become a "verify" report.
        receipts = list(_chain((0, 2, 5)))
        corrupt = receipts[1]
        broken_consistency = SignedConsistency(
            corrupt.consistency.old,
            corrupt.consistency.new,
            corrupt.consistency.proof,
        )
        object.__setattr__(broken_consistency, "proof", ("not-bytes",))
        corrupt = SignedAuthAuditContinuation(
            corrupt.bundle, broken_consistency
        )
        receipts[1] = corrupt
        with self.assertRaises(TypeError):
            inspect_continuation_chain(tuple(receipts), self.public_key)

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

    def test_bool_verifier_unchanged(self):
        # The existing entry point still returns a plain bool on every case.
        good = _chain((0, 2, 5))
        self.assertIs(
            verify_continuation_chain(good, self.public_key), True
        )
        self.assertIs(
            verify_continuation_chain(good, self.other_public_key), False
        )
        receipt = good[0]
        self.assertIs(
            verify_continuation_chain((receipt, receipt), self.public_key),
            False,
        )


class ContinuationChainReportTest(unittest.TestCase):
    def test_positional_construction_and_field_equality(self):
        report = ContinuationChainReport(False, 3, "link")
        self.assertFalse(report.ok)
        self.assertEqual(report.index, 3)
        self.assertEqual(report.code, "link")
        self.assertEqual(
            report, ContinuationChainReport(ok=False, index=3, code="link")
        )
        self.assertEqual(
            (report.ok, report.index, report.code), (False, 3, "link")
        )

    def test_success_report_equality_and_hash(self):
        report = ContinuationChainReport(True, None, None)
        self.assertEqual(report, ContinuationChainReport(True, None, None))
        self.assertEqual(hash(report), hash(ContinuationChainReport(True, None, None)))
        self.assertEqual(
            {report: 1}[ContinuationChainReport(True, None, None)], 1
        )

    def test_reports_compare_by_fields(self):
        self.assertNotEqual(
            ContinuationChainReport(False, 0, "verify"),
            ContinuationChainReport(False, 1, "verify"),
        )
        self.assertNotEqual(
            ContinuationChainReport(False, 1, "verify"),
            ContinuationChainReport(False, 1, "growth"),
        )

    def test_frozen(self):
        report = ContinuationChainReport(True, None, None)
        with self.assertRaises(Exception):
            report.ok = False
        with self.assertRaises(Exception):
            report.index = 1
        with self.assertRaises(Exception):
            report.code = "link"

    def test_unknown_code_raises_value_error(self):
        for code in ("", "VERIFY", "sig", "signature", "gap", "repeat"):
            with self.assertRaises(ValueError, msg=code):
                ContinuationChainReport(False, 0, code)

    def test_code_type_error(self):
        with self.assertRaises(TypeError):
            ContinuationChainReport(False, 0, None)
        with self.assertRaises(TypeError):
            ContinuationChainReport(False, 0, 1)

    def test_ok_type_error(self):
        with self.assertRaises(TypeError):
            ContinuationChainReport(1, None, None)
        with self.assertRaises(TypeError):
            ContinuationChainReport(0, None, None)

    def test_success_report_must_carry_none_fields(self):
        with self.assertRaises(ValueError):
            ContinuationChainReport(True, 0, None)
        with self.assertRaises(ValueError):
            ContinuationChainReport(True, None, "verify")

    def test_index_validation(self):
        with self.assertRaises(TypeError):
            ContinuationChainReport(False, None, "verify")
        with self.assertRaises(TypeError):
            ContinuationChainReport(False, 1.0, "verify")
        with self.assertRaises(TypeError):
            ContinuationChainReport(False, True, "verify")
        with self.assertRaises(ValueError):
            ContinuationChainReport(False, -1, "verify")


if __name__ == "__main__":
    unittest.main()
