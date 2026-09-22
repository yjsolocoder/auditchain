import unittest

from auditchain import (
    AnchoredContinuationChain,
    AuditLog,
    ContinuationChainReport,
    SignedAuthAuditContinuation,
    SignedConsistency,
    decode_anchored_continuations,
    encode_anchored_continuations,
    encode_signed_auth_audit_continuation,
    inspect_anchor_set,
    inspect_anchored_continuations,
    merge_anchor_set,
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


def _log(n=9, key=_KEY, hash_name="sha256", prefix="record"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _chain(sizes, seed=_SEED_A, n=None, prefix="record", **kwargs):
    """Issue one fresh log per segment, all on identical content, so the
    checkpoints match across segments."""
    if n is None:
        n = sizes[-1]
    receipts = []
    old = sizes[0]
    for new in sizes[1:]:
        receipt = _log(n, prefix=prefix, **kwargs)
        receipt = receipt.signed_auth_audit_continuation(
            old, (), seed, size=new
        )
        receipts.append(receipt)
        old = new
    return tuple(receipts)


def _bundle(receipts):
    """A chain together with the exact anchors it spans."""
    return AnchoredContinuationChain(
        receipts, receipts[0].consistency.old, receipts[-1].consistency.new
    )


def _split(sizes, cuts):
    """Cut one anchored chain over ``sizes`` into batches at the given cut
    points (counts of receipts per batch); the batches join end to end."""
    receipts = _chain(sizes)
    batches = []
    start = 0
    for width in cuts:
        part = receipts[start:start + width]
        batches.append(_bundle(part))
        start += width
    assert start == len(receipts)
    return tuple(batches), receipts


class InspectAnchorSetTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_success_report_shape_single_package(self):
        bundle = _bundle(_chain((0, 2, 5)))
        report = inspect_anchor_set((bundle,), self.public_key)
        self.assertEqual(report, ContinuationChainReport(True, None, None))
        self.assertIsInstance(report, ContinuationChainReport)

    def test_joining_batches_report_ok(self):
        batches, _ = _split((0, 2, 5, 8), (2, 1))
        self.assertEqual(
            inspect_anchor_set(batches, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_three_batches_report_ok(self):
        batches, _ = _split((0, 2, 5, 7, 9), (1, 2, 1))
        self.assertEqual(
            inspect_anchor_set(batches, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_matches_inspect_anchored_continuations_per_package(self):
        batches, _ = _split((0, 2, 5, 8), (2, 1))
        for bundle in batches:
            self.assertEqual(
                inspect_anchored_continuations(bundle, self.public_key),
                ContinuationChainReport(True, None, None),
            )

    def test_first_package_failure_has_no_offset(self):
        good = _bundle(_chain((5, 8)))
        first = _bundle(_chain((0, 2, 5), seed=_SEED_B))
        report = inspect_anchor_set((first, good), self.public_key)
        self.assertEqual(
            report, ContinuationChainReport(False, 0, "verify")
        )

    def test_local_failure_index_translated_to_global(self):
        # First package holds two receipts; the second package's single
        # receipt fails verification, so local index 0 becomes global 2.
        first = _bundle(_chain((0, 2, 5)))
        second = _bundle(_chain((5, 8), seed=_SEED_B))
        self.assertEqual(
            inspect_anchor_set((first, second), self.public_key),
            ContinuationChainReport(False, 2, "verify"),
        )

    def test_end_failure_index_translated_to_global(self):
        # A mis-anchored end inside the second package: local index 0 plus
        # the two prior credentials -> global 2.
        first = _bundle(_chain((0, 2, 5)))
        receipts = _chain((5, 8))
        wrong_end = _chain((5, 8), prefix="other")[0].consistency.new
        second = AnchoredContinuationChain(
            receipts, receipts[0].consistency.old, wrong_end
        )
        self.assertEqual(
            inspect_anchor_set((first, second), self.public_key),
            ContinuationChainReport(False, 2, "end"),
        )

    def test_failure_in_third_package_offsets_by_all_prior(self):
        b0 = _bundle(_chain((0, 2)))
        b1 = _bundle(_chain((2, 5)))
        b2 = _bundle(_chain((5, 7, 9), seed=_SEED_B))
        # Two earlier credentials precede the failing first receipt of b2.
        self.assertEqual(
            inspect_anchor_set((b0, b1, b2), self.public_key),
            ContinuationChainReport(False, 2, "verify"),
        )
        # And a failure at b2's second receipt keeps the global position.
        mixed = _chain((5, 7), seed=_SEED_A) + _chain(
            (7, 9), seed=_SEED_B
        )
        b2b = _bundle(mixed)
        self.assertEqual(
            inspect_anchor_set((b0, b1, b2b), self.public_key),
            ContinuationChainReport(False, 3, "verify"),
        )

    def test_anchor_link_when_sizes_align_but_histories_differ(self):
        first = _bundle(_chain((0, 2, 5)))
        # Individually sound package over a different history at the same
        # boundary size: its start does not equal the first package's end.
        other = _bundle(_chain((5, 8), prefix="other"))
        report = inspect_anchor_set((first, other), self.public_key)
        self.assertEqual(
            report, ContinuationChainReport(False, 2, "anchor_link")
        )

    def test_anchor_link_at_second_seam_uses_later_base(self):
        b0 = _bundle(_chain((0, 2)))          # 1 credential
        b1 = _bundle(_chain((2, 5)))          # 1 credential
        b2 = _bundle(_chain((5, 7, 9), prefix="other"))
        # The seam before b2 sits at the global position of b2's first
        # receipt: two prior credentials -> 2.
        self.assertEqual(
            inspect_anchor_set((b0, b1, b2), self.public_key),
            ContinuationChainReport(False, 2, "anchor_link"),
        )
        c0 = _bundle(_chain((0, 2, 5)))       # 2 credentials
        c1 = _bundle(_chain((5, 7)))          # 1 credential
        c2 = _bundle(_chain((7, 9), prefix="other"))
        self.assertEqual(
            inspect_anchor_set((c0, c1, c2), self.public_key),
            ContinuationChainReport(False, 3, "anchor_link"),
        )

    def test_package_failure_masks_seam_mismatch(self):
        # The seam would mismatch, but the second package is itself unsound,
        # so its internal "verify" failure is reported first.
        first = _bundle(_chain((0, 2, 5)))
        second = _bundle(_chain((5, 8), seed=_SEED_B))
        self.assertEqual(
            inspect_anchor_set((first, second), self.public_key),
            ContinuationChainReport(False, 2, "verify"),
        )

    def test_first_failure_only_is_reported(self):
        b0 = _bundle(_chain((0, 2)))
        bad = _bundle(_chain((2, 5), seed=_SEED_B))
        other = _bundle(_chain((5, 8), prefix="other"))
        self.assertEqual(
            inspect_anchor_set((b0, bad, other), self.public_key),
            ContinuationChainReport(False, 1, "verify"),
        )

    def test_non_tuple_raises_type_error(self):
        bundle = _bundle(_chain((0, 2)))
        for bad in (
            [bundle],
            bundle,
            iter((bundle,)),
            None,
            "items",
            1,
        ):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchor_set(bad, self.public_key)

    def test_wrong_element_type_raises_type_error(self):
        bundle = _bundle(_chain((0, 2)))
        for bad in (b"bytes", "bundle", None, 1, bundle.receipts, object()):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchor_set((bad,), self.public_key)
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchor_set((bundle, bad), self.public_key)

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            inspect_anchor_set((), self.public_key)

    def test_key_type_raises_type_error(self):
        bundle = _bundle(_chain((0, 2)))
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchor_set((bundle,), bad)

    def test_key_length_raises_value_error(self):
        bundle = _bundle(_chain((0, 2)))
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_anchor_set((bundle,), bad)

    def test_empty_set_validated_before_key(self):
        # Both illegal: the empty container is a ValueError regardless of the
        # key, never a silent success.
        with self.assertRaises(ValueError):
            inspect_anchor_set((), b"not-a-key")

    def test_nested_structural_violation_propagates(self):
        good = _bundle(_chain((0, 2)))
        corrupt_receipt = _chain((2, 5))[0]
        broken_consistency = SignedConsistency(
            corrupt_receipt.consistency.old,
            corrupt_receipt.consistency.new,
            corrupt_receipt.consistency.proof,
        )
        object.__setattr__(broken_consistency, "proof", ("not-bytes",))
        broken = SignedAuthAuditContinuation(
            corrupt_receipt.bundle, broken_consistency
        )
        bad = AnchoredContinuationChain(
            (broken,), broken.consistency.old, broken.consistency.new
        )
        with self.assertRaises(TypeError):
            inspect_anchor_set((good, bad), self.public_key)

    def test_call_is_read_only(self):
        batches, _ = _split((0, 2, 5, 8), (2, 1))
        before = tuple(encode_anchored_continuations(b) for b in batches)
        inspect_anchor_set(batches, self.public_key)
        after = tuple(encode_anchored_continuations(b) for b in batches)
        self.assertEqual(after, before)


class MergeAnchorSetTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_merge_concatenates_in_package_and_receipt_order(self):
        batches, receipts = _split((0, 2, 5, 7, 9), (2, 1, 1))
        merged = merge_anchor_set(batches, self.public_key)
        self.assertIsInstance(merged, AnchoredContinuationChain)
        self.assertEqual(merged.receipts, receipts)
        self.assertEqual(merged.start, batches[0].start)
        self.assertEqual(merged.end, batches[-1].end)

    def test_merge_equals_the_whole_chain_bundle(self):
        batches, receipts = _split((0, 2, 5, 8), (2, 1))
        whole = AnchoredContinuationChain(
            receipts, receipts[0].consistency.old, receipts[-1].consistency.new
        )
        self.assertEqual(merge_anchor_set(batches, self.public_key), whole)

    def test_single_package_merge_preserves_bundle(self):
        bundle = _bundle(_chain((0, 2, 5)))
        self.assertEqual(
            merge_anchor_set((bundle,), self.public_key), bundle
        )

    def test_merge_reuses_existing_encoding(self):
        batches, _ = _split((0, 2, 5, 8), (2, 1))
        merged = merge_anchor_set(batches, self.public_key)
        data = encode_anchored_continuations(merged)
        self.assertEqual(decode_anchored_continuations(data), merged)

    def test_merge_returns_new_frozen_object(self):
        batches, _ = _split((0, 2, 5, 8), (2, 1))
        merged = merge_anchor_set(batches, self.public_key)
        for bundle in batches:
            self.assertIsNot(merged, bundle)
        with self.assertRaises(Exception):
            merged.start = merged.end

    def test_merge_does_not_modify_inputs(self):
        batches, _ = _split((0, 2, 5, 8), (2, 1))
        before = tuple(encode_anchored_continuations(b) for b in batches)
        receipt_bytes = tuple(
            tuple(encode_signed_auth_audit_continuation(r) for r in b.receipts)
            for b in batches
        )
        merge_anchor_set(batches, self.public_key)
        self.assertEqual(
            tuple(encode_anchored_continuations(b) for b in batches), before
        )
        for bundle, encoded in zip(batches, receipt_bytes):
            self.assertEqual(
                tuple(
                    encode_signed_auth_audit_continuation(r)
                    for r in bundle.receipts
                ),
                encoded,
            )

    def test_merge_raises_value_error_on_anchor_link(self):
        first = _bundle(_chain((0, 2, 5)))
        other = _bundle(_chain((5, 8), prefix="other"))
        with self.assertRaises(ValueError):
            merge_anchor_set((first, other), self.public_key)

    def test_merge_raises_value_error_on_internal_failure(self):
        first = _bundle(_chain((0, 2, 5)))
        second = _bundle(
            _chain((5, 8), seed=_SEED_B)
        )
        with self.assertRaises(ValueError):
            merge_anchor_set((first, second), self.public_key)

    def test_merge_raises_value_error_on_empty_set(self):
        with self.assertRaises(ValueError):
            merge_anchor_set((), self.public_key)

    def test_merge_raises_value_error_on_bad_key_length(self):
        bundle = _bundle(_chain((0, 2)))
        with self.assertRaises(ValueError):
            merge_anchor_set((bundle,), b"\x00" * 31)

    def test_merge_type_errors_match_inspect(self):
        bundle = _bundle(_chain((0, 2)))
        for bad in ([bundle], bundle, None, 1):
            with self.assertRaises(TypeError, msg=bad):
                merge_anchor_set(bad, self.public_key)
        for bad in (b"x", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                merge_anchor_set((bundle, bad), self.public_key)
        for bad in ("key", bytearray(self.public_key)):
            with self.assertRaises(TypeError, msg=bad):
                merge_anchor_set((bundle,), bad)

    def test_nested_structural_violation_propagates(self):
        good = _bundle(_chain((0, 2)))
        corrupt_receipt = _chain((2, 5))[0]
        broken_consistency = SignedConsistency(
            corrupt_receipt.consistency.old,
            corrupt_receipt.consistency.new,
            corrupt_receipt.consistency.proof,
        )
        object.__setattr__(broken_consistency, "proof", ("not-bytes",))
        broken = SignedAuthAuditContinuation(
            corrupt_receipt.bundle, broken_consistency
        )
        bad = AnchoredContinuationChain(
            (broken,), broken.consistency.old, broken.consistency.new
        )
        with self.assertRaises(TypeError):
            merge_anchor_set((good, bad), self.public_key)


class AnchorLinkReportTest(unittest.TestCase):
    def test_anchor_link_constructs_and_compares(self):
        report = ContinuationChainReport(False, 2, "anchor_link")
        self.assertEqual(report.code, "anchor_link")
        self.assertEqual(report.index, 2)
        self.assertEqual(
            report, ContinuationChainReport(False, 2, "anchor_link")
        )
        self.assertEqual(
            hash(report),
            hash(ContinuationChainReport(False, 2, "anchor_link")),
        )
        self.assertNotEqual(report, ContinuationChainReport(False, 2, "link"))

    def test_report_is_frozen(self):
        report = ContinuationChainReport(False, 2, "anchor_link")
        with self.assertRaises(Exception):
            report.code = "link"

    def test_existing_codes_still_construct(self):
        for code in (
            "verify",
            "growth",
            "duplicate",
            "link",
            "start",
            "end",
        ):
            self.assertEqual(
                ContinuationChainReport(False, 1, code).code, code
            )

    def test_unknown_code_still_raises_value_error(self):
        for code in ("", "ANCHOR_LINK", "anchor", "seam", "anchor-link"):
            with self.assertRaises(ValueError, msg=code):
                ContinuationChainReport(False, 0, code)


if __name__ == "__main__":
    unittest.main()
