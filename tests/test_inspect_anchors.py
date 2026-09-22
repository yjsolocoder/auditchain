import unittest

from auditchain import (
    AuditLog,
    ContinuationChainReport,
    SignedAuthAuditContinuation,
    SignedConsistency,
    SignedRoot,
    encode_signed_auth_audit_continuation,
    inspect_anchors,
    inspect_continuation_chain,
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


def _anchors(receipts):
    """The exact endpoints a chain spans: its first old and last new."""
    return receipts[0].consistency.old, receipts[-1].consistency.new


def _replace(checkpoint, **changes):
    fields = {
        "version": checkpoint.version,
        "hash_name": checkpoint.hash_name,
        "size": checkpoint.size,
        "root": checkpoint.root,
        "head": checkpoint.head,
        "signature": checkpoint.signature,
    }
    fields.update(changes)
    return SignedRoot(**fields)


class InspectAnchorsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_success_report_shape(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        report = inspect_anchors(receipts, self.public_key, start, end)
        self.assertEqual(report, ContinuationChainReport(True, None, None))
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertEqual((report.ok, report.index, report.code), (True, None, None))

    def test_single_segment_chain_reports_ok(self):
        receipts = _chain((2, 5))
        start, end = _anchors(receipts)
        self.assertEqual(
            inspect_anchors(receipts, self.public_key, start, end),
            ContinuationChainReport(True, None, None),
        )

    def test_multi_segment_chain_reports_ok(self):
        receipts = _chain((0, 2, 5, 8))
        start, end = _anchors(receipts)
        self.assertEqual(
            inspect_anchors(receipts, self.public_key, start, end),
            ContinuationChainReport(True, None, None),
        )

    def test_truncated_prefix_reports_start_at_zero(self):
        # A valid sub-chain missing the expected leading segments.
        receipts = _chain((0, 2, 5, 8))
        start, _ = _anchors(receipts)
        sub = receipts[1:]
        _, sub_end = _anchors(sub)
        self.assertEqual(
            inspect_anchors(sub, self.public_key, start, sub_end),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_truncated_suffix_reports_end_at_last_index(self):
        # A valid sub-chain missing the expected trailing segments.
        receipts = _chain((0, 2, 5, 8))
        _, end = _anchors(receipts)
        sub = receipts[:-1]
        sub_start, _ = _anchors(sub)
        self.assertEqual(
            inspect_anchors(sub, self.public_key, sub_start, end),
            ContinuationChainReport(False, 1, "end"),
        )

    def test_wholesale_replacement_reports_start(self):
        # An internally continuous chain over a different span entirely.
        receipts = _chain((0, 2, 5))
        start, _ = _anchors(receipts)
        other = _chain((1, 4, 7))
        _, other_end = _anchors(other)
        self.assertEqual(
            inspect_anchors(other, self.public_key, start, other_end),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_start_mismatch_masks_end_mismatch(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        wrong_start = _replace(start, size=start.size + 1)
        wrong_end = _replace(end, size=end.size + 1)
        self.assertEqual(
            inspect_anchors(
                receipts, self.public_key, wrong_start, wrong_end
            ),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_anchor_equality_covers_every_field(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        digest = bytes(range(32))
        for field, value in (
            ("size", start.size + 1),
            ("root", digest),
            ("head", digest),
            ("signature", b"\x00" * 64),
        ):
            tampered = _replace(start, **{field: value})
            self.assertEqual(
                inspect_anchors(receipts, self.public_key, tampered, end),
                ContinuationChainReport(False, 0, "start"),
                msg=field,
            )

    def test_anchor_size_alone_does_not_satisfy_equality(self):
        # A checkpoint attesting the expected sizes but a different history
        # (and hence root/head/signature) is not the expected anchor.
        receipts = _chain((1, 3, 6))
        start, end = _anchors(receipts)
        other = _chain((1, 3, 6), prefix="other")
        other_start, other_end = _anchors(other)
        self.assertEqual(other_start.size, start.size)
        self.assertEqual(other_end.size, end.size)
        self.assertEqual(
            inspect_anchors(receipts, self.public_key, other_start, end),
            ContinuationChainReport(False, 0, "start"),
        )
        self.assertEqual(
            inspect_anchors(receipts, self.public_key, start, other_end),
            ContinuationChainReport(False, 1, "end"),
        )

    def test_end_mismatch_index_is_last_segment(self):
        receipts = _chain((0, 2, 5, 8))
        start, end = _anchors(receipts)
        wrong_end = _replace(end, signature=b"\x00" * 64)
        self.assertEqual(
            inspect_anchors(receipts, self.public_key, start, wrong_end),
            ContinuationChainReport(False, 2, "end"),
        )

    def test_internal_verify_failure_returned_unchanged(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        expected = inspect_continuation_chain(receipts, self.other_public_key)
        self.assertEqual(
            inspect_anchors(receipts, self.other_public_key, start, end),
            expected,
        )
        self.assertEqual(expected, ContinuationChainReport(False, 0, "verify"))

    def test_internal_failure_masks_anchor_mismatch(self):
        # Even with both anchors wrong, an internally broken chain reports
        # its internal first failure, never an anchor code.
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        wrong_start = _replace(start, size=start.size + 1)
        wrong_end = _replace(end, size=end.size + 1)
        report = inspect_anchors(
            receipts, self.other_public_key, wrong_start, wrong_end
        )
        self.assertEqual(report, ContinuationChainReport(False, 0, "verify"))

    def test_internal_growth_duplicate_link_pass_through(self):
        equal = _log(5).signed_auth_audit_continuation(
            3, (), _SEED_A, size=3
        )
        start, end = _anchors((equal,))
        self.assertEqual(
            inspect_anchors((equal,), self.public_key, start, end),
            ContinuationChainReport(False, 0, "growth"),
        )
        receipt = _chain((2, 5))[0]
        start, end = _anchors((receipt, receipt))
        self.assertEqual(
            inspect_anchors((receipt, receipt), self.public_key, start, end),
            ContinuationChainReport(False, 1, "duplicate"),
        )
        first = _chain((0, 5))[0]
        second = _chain((3, 8))[0]
        start, end = _anchors((first, second))
        self.assertEqual(
            inspect_anchors((first, second), self.public_key, start, end),
            ContinuationChainReport(False, 1, "link"),
        )

    def test_anchors_not_checked_when_chain_internally_broken(self):
        # Non-SignedRoot anchors still raise, but valid anchors that would
        # mismatch are irrelevant while the internal report fails.
        first = _chain((0, 5))[0]
        second = _chain((3, 8))[0]
        other = _chain((1, 4))
        other_start, other_end = _anchors(other)
        self.assertEqual(
            inspect_anchors(
                (first, second), self.public_key, other_start, other_end
            ),
            ContinuationChainReport(False, 1, "link"),
        )

    def test_empty_tuple_value_error(self):
        receipts = _chain((0, 2))
        start, end = _anchors(receipts)
        with self.assertRaises(ValueError):
            inspect_anchors((), self.public_key, start, end)

    def test_non_tuple_raises_type_error(self):
        receipts = _chain((2, 5))
        start, end = _anchors(receipts)
        for bad in ([receipts[0]], {receipts[0]}, None, receipts[0], "r", 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors(bad, self.public_key, start, end)

    def test_wrong_element_type_raises_type_error(self):
        receipts = _chain((2, 5))
        start, end = _anchors(receipts)
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors((bad,), self.public_key, start, end)
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors(
                    (receipts[0], bad), self.public_key, start, end
                )

    def test_public_key_type_raises_type_error(self):
        receipts = _chain((2, 5))
        start, end = _anchors(receipts)
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors(receipts, bad, start, end)

    def test_public_key_length_raises_value_error(self):
        receipts = _chain((2, 5))
        start, end = _anchors(receipts)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_anchors(receipts, bad, start, end)

    def test_non_signed_root_anchors_raise_type_error(self):
        receipts = _chain((2, 5))
        start, end = _anchors(receipts)
        for bad in (b"bytes", "anchor", None, 1, (start,), object()):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors(receipts, self.public_key, bad, end)
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors(receipts, self.public_key, start, bad)

    def test_anchor_validation_before_internal_diagnosis(self):
        # Bad anchor types raise even when the chain itself would fail.
        receipts = _chain((0, 2, 5))
        with self.assertRaises(TypeError):
            inspect_anchors(receipts, self.other_public_key, None, None)

    def test_nested_structural_violation_propagates(self):
        receipts = list(_chain((0, 2, 5)))
        corrupt = receipts[1]
        broken_consistency = SignedConsistency(
            corrupt.consistency.old,
            corrupt.consistency.new,
            corrupt.consistency.proof,
        )
        object.__setattr__(broken_consistency, "proof", ("not-bytes",))
        receipts[1] = SignedAuthAuditContinuation(
            corrupt.bundle, broken_consistency
        )
        receipts = tuple(receipts)
        start, end = _anchors(receipts)
        with self.assertRaises(TypeError):
            inspect_anchors(receipts, self.public_key, start, end)

    def test_call_is_read_only(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        before = tuple(
            encode_signed_auth_audit_continuation(r) for r in receipts
        )
        inspect_anchors(receipts, self.public_key, start, end)
        after = tuple(
            encode_signed_auth_audit_continuation(r) for r in receipts
        )
        self.assertEqual(after, before)

    def test_agrees_with_inspect_continuation_chain_on_success(self):
        receipts = _chain((0, 2, 5, 8))
        start, end = _anchors(receipts)
        self.assertEqual(
            inspect_anchors(receipts, self.public_key, start, end),
            inspect_continuation_chain(receipts, self.public_key),
        )


class AnchorChainReportTest(unittest.TestCase):
    def test_start_and_end_codes_construct_and_compare(self):
        start_report = ContinuationChainReport(False, 0, "start")
        self.assertEqual(start_report.code, "start")
        self.assertEqual(start_report.index, 0)
        end_report = ContinuationChainReport(False, 3, "end")
        self.assertEqual(end_report.code, "end")
        self.assertEqual(end_report.index, 3)
        self.assertNotEqual(start_report, end_report)
        self.assertEqual(
            hash(start_report),
            hash(ContinuationChainReport(False, 0, "start")),
        )

    def test_anchor_reports_are_frozen(self):
        report = ContinuationChainReport(False, 0, "start")
        with self.assertRaises(Exception):
            report.code = "end"

    def test_existing_codes_still_construct(self):
        for code in ("verify", "growth", "duplicate", "link"):
            self.assertEqual(
                ContinuationChainReport(False, 1, code).code, code
            )

    def test_unknown_code_still_raises_value_error(self):
        for code in ("", "START", "anchor", "begin", "finish"):
            with self.assertRaises(ValueError, msg=code):
                ContinuationChainReport(False, 0, code)


if __name__ == "__main__":
    unittest.main()
