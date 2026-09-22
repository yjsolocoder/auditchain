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


def _checkpoint(size, seed=_SEED_A, n=8, **kwargs):
    return _log(n, **kwargs).sign_root(seed, size=size)


class InspectAnchorsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.receipts = _chain((0, 2, 5, 8))
        self.start = self.receipts[0].consistency.old
        self.end = self.receipts[-1].consistency.new

    def test_anchored_chain_reports_ok(self):
        report = inspect_anchors(
            self.receipts, self.public_key, self.start, self.end
        )
        self.assertEqual(report, ContinuationChainReport(True, None, None))
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)

    def test_single_segment_chain_anchors(self):
        receipts = _chain((2, 5))
        report = inspect_anchors(
            receipts,
            self.public_key,
            receipts[0].consistency.old,
            receipts[-1].consistency.new,
        )
        self.assertEqual(report, ContinuationChainReport(True, None, None))

    def test_success_agrees_with_chain_diagnostic(self):
        self.assertEqual(
            inspect_continuation_chain(self.receipts, self.public_key),
            ContinuationChainReport(True, None, None),
        )
        self.assertEqual(
            inspect_anchors(
                self.receipts, self.public_key, self.start, self.end
            ),
            ContinuationChainReport(True, None, None),
        )

    def test_internal_failure_returned_unchanged(self):
        # An untrusted key still reports "verify"; the anchors are never
        # consulted on an internally failing chain.
        self.assertEqual(
            inspect_anchors(
                self.receipts, self.other_public_key, self.start, self.end
            ),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_internal_failure_masks_wrong_anchors(self):
        # The chain's own first error wins over any anchor mismatch.
        first = _chain((0, 5))[0]
        mismatched = _chain((3, 8))[0]
        self.assertEqual(
            inspect_anchors(
                (first, mismatched),
                self.public_key,
                _checkpoint(1),
                _checkpoint(6),
            ),
            ContinuationChainReport(False, 1, "link"),
        )

    def test_internal_first_error_order_unchanged(self):
        receipt = _chain((2, 5))[0]
        self.assertEqual(
            inspect_anchors(
                (receipt, receipt),
                self.public_key,
                receipt.consistency.old,
                receipt.consistency.new,
            ),
            ContinuationChainReport(False, 1, "duplicate"),
        )
        equal = _log(5).signed_auth_audit_continuation(
            3, (), _SEED_A, size=3
        )
        self.assertEqual(
            inspect_anchors(
                (equal,),
                self.public_key,
                equal.consistency.old,
                equal.consistency.new,
            ),
            ContinuationChainReport(False, 0, "growth"),
        )

    def test_wrong_start_reports_start_at_zero(self):
        self.assertEqual(
            inspect_anchors(
                self.receipts, self.public_key, _checkpoint(1), self.end
            ),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_wrong_end_reports_end_at_last_index(self):
        self.assertEqual(
            inspect_anchors(
                self.receipts, self.public_key, self.start, _checkpoint(6)
            ),
            ContinuationChainReport(False, 2, "end"),
        )

    def test_wrong_end_index_is_last_segment(self):
        receipts = _chain((0, 2, 5))
        self.assertEqual(
            inspect_anchors(
                receipts,
                self.public_key,
                receipts[0].consistency.old,
                _checkpoint(6),
            ),
            ContinuationChainReport(False, 1, "end"),
        )

    def test_start_mismatch_takes_priority_over_end(self):
        self.assertEqual(
            inspect_anchors(
                self.receipts,
                self.public_key,
                _checkpoint(1),
                _checkpoint(6),
            ),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_truncated_prefix_subchain_reports_start(self):
        # A genuine sub-chain missing the expected leading segments.
        subchain = _chain((2, 5, 8))
        self.assertEqual(
            inspect_anchors(
                subchain,
                self.public_key,
                _checkpoint(0),
                subchain[-1].consistency.new,
            ),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_truncated_suffix_subchain_reports_end(self):
        # A genuine sub-chain missing the expected trailing segments.
        subchain = _chain((0, 2, 5))
        self.assertEqual(
            inspect_anchors(
                subchain,
                self.public_key,
                subchain[0].consistency.old,
                _checkpoint(8),
            ),
            ContinuationChainReport(False, 1, "end"),
        )

    def test_wholesale_replacement_reports_start(self):
        # A fully valid chain over different content is not the expected one
        # (the size-0 checkpoint is content-independent, so the swap is
        # visible only once the replaced chain starts above it).
        replaced = _chain((2, 5, 8), prefix="other")
        self.assertEqual(
            inspect_anchors(
                replaced, self.public_key, self.start, self.end
            ),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_anchor_equality_covers_every_field(self):
        # Same snapshot fields but a foreign signature is not the anchor.
        forged_start = SignedRoot(
            self.start.version,
            self.start.hash_name,
            self.start.size,
            self.start.root,
            self.start.head,
            b"\x00" * 64,
        )
        self.assertEqual(
            inspect_anchors(
                self.receipts, self.public_key, forged_start, self.end
            ),
            ContinuationChainReport(False, 0, "start"),
        )
        forged_end = SignedRoot(
            self.end.version,
            self.end.hash_name,
            self.end.size,
            self.end.root,
            self.end.head,
            b"\x00" * 64,
        )
        self.assertEqual(
            inspect_anchors(
                self.receipts, self.public_key, self.start, forged_end
            ),
            ContinuationChainReport(False, 2, "end"),
        )

    def test_all_four_arguments_are_required(self):
        for args in (
            (self.receipts,),
            (self.receipts, self.public_key),
            (self.receipts, self.public_key, self.start),
        ):
            with self.assertRaises(TypeError, msg=len(args)):
                inspect_anchors(*args)

    def test_non_signed_root_anchor_raises_type_error(self):
        for bad in (b"bytes", "anchor", None, 1, (), self.receipts[0]):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors(
                    self.receipts, self.public_key, bad, self.end
                )
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors(
                    self.receipts, self.public_key, self.start, bad
                )

    def test_non_tuple_receipts_raises_type_error(self):
        receipt = self.receipts[0]
        for bad in ([receipt], {receipt}, None, receipt, "receipts", 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors(bad, self.public_key, self.start, self.end)

    def test_wrong_element_type_raises_type_error(self):
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors(
                    (bad,), self.public_key, self.start, self.end
                )

    def test_public_key_type_raises_type_error(self):
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchors(
                    self.receipts, bad, self.start, self.end
                )

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            inspect_anchors((), self.public_key, self.start, self.end)

    def test_public_key_length_raises_value_error(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_anchors(
                    self.receipts, bad, self.start, self.end
                )

    def test_nested_structural_violation_propagates(self):
        # Bypass the frozen constructors to plant a non-bytes proof node;
        # the nested verifier raises TypeError, which must propagate rather
        # than become a "verify" or anchor report.
        receipts = list(self.receipts)
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
        with self.assertRaises(TypeError):
            inspect_anchors(
                tuple(receipts), self.public_key, self.start, self.end
            )

    def test_call_is_read_only(self):
        before = tuple(
            encode_signed_auth_audit_continuation(r) for r in self.receipts
        )
        inspect_anchors(self.receipts, self.public_key, self.start, self.end)
        after = tuple(
            encode_signed_auth_audit_continuation(r) for r in self.receipts
        )
        self.assertEqual(after, before)


class ContinuationChainReportAnchorCodesTest(unittest.TestCase):
    def test_start_and_end_codes_are_accepted(self):
        start_report = ContinuationChainReport(False, 0, "start")
        self.assertFalse(start_report.ok)
        self.assertEqual(start_report.index, 0)
        self.assertEqual(start_report.code, "start")
        end_report = ContinuationChainReport(False, 3, "end")
        self.assertEqual(end_report.code, "end")
        self.assertNotEqual(start_report, end_report)

    def test_anchor_reports_compare_by_fields_and_hash(self):
        report = ContinuationChainReport(False, 0, "start")
        self.assertEqual(report, ContinuationChainReport(False, 0, "start"))
        self.assertEqual(
            hash(report), hash(ContinuationChainReport(False, 0, "start"))
        )
        self.assertNotEqual(
            report, ContinuationChainReport(False, 0, "end")
        )

    def test_anchor_reports_are_frozen(self):
        report = ContinuationChainReport(False, 0, "start")
        with self.assertRaises(Exception):
            report.code = "end"

    def test_unknown_codes_still_rejected(self):
        for code in ("", "START", "anchor", "begin", "stop"):
            with self.assertRaises(ValueError, msg=code):
                ContinuationChainReport(False, 0, code)


if __name__ == "__main__":
    unittest.main()
