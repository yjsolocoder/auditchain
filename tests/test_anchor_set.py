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


def _split(sizes, cuts, **kwargs):
    """One continuous chain over ``sizes`` landed in ``len(cuts)`` batches;
    cut k owns receipts[cuts[k-1]:cuts[k]]."""
    receipts = _chain(sizes, **kwargs)
    packages = []
    start = 0
    for stop in cuts:
        group = receipts[start:stop]
        packages.append(
            AnchoredContinuationChain(
                group, group[0].consistency.old, group[-1].consistency.new
            )
        )
        start = stop
    return tuple(packages)


def _package(receipts):
    return AnchoredContinuationChain(
        receipts, receipts[0].consistency.old, receipts[-1].consistency.new
    )


def _replace(checkpoint, **changes):
    from auditchain import SignedRoot

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


class InspectAnchorSetTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_success_report_shape(self):
        packages = _split((0, 2, 5, 8), (2, 3))
        report = inspect_anchor_set(packages, self.public_key)
        self.assertEqual(report, ContinuationChainReport(True, None, None))
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertEqual((report.ok, report.index, report.code), (True, None, None))

    def test_single_package_reports_ok(self):
        packages = _split((0, 2, 5), (2,))
        self.assertEqual(
            inspect_anchor_set(packages, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_many_packages_report_ok(self):
        packages = _split((0, 2, 5, 8, 11), (1, 2, 3, 4))
        self.assertEqual(
            inspect_anchor_set(packages, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_restored_packages_report_ok(self):
        # The cross-process flow: each batch encoded and decoded on its own,
        # then the restored artifacts are diagnosed together.
        packages = _split((0, 2, 5, 8), (2, 3))
        restored = tuple(
            decode_anchored_continuations(encode_anchored_continuations(p))
            for p in packages
        )
        self.assertEqual(
            inspect_anchor_set(restored, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_agrees_with_inspect_anchored_continuations_per_package(self):
        packages = _split((0, 2, 5, 8), (1, 3))
        for package in packages:
            self.assertEqual(
                inspect_anchored_continuations(package, self.public_key),
                ContinuationChainReport(True, None, None),
            )
        self.assertEqual(
            inspect_anchor_set(packages, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_anchor_link_index_is_later_package_first_receipt(self):
        first = _package(_chain((0, 2)))
        # A sound package over a different history at the same boundary
        # size: it verifies and anchors internally but its start checkpoint
        # is not the first package's end.
        second = _package(_chain((2, 5), prefix="other"))
        self.assertEqual(
            inspect_anchor_set((first, second), self.public_key),
            ContinuationChainReport(False, 1, "anchor_link"),
        )

    def test_anchor_link_index_accumulates_prior_receipt_counts(self):
        first = _package(_chain((0, 2, 5)))
        second = _package(_chain((5, 8, 11), prefix="other"))
        self.assertEqual(
            inspect_anchor_set((first, second), self.public_key),
            ContinuationChainReport(False, 2, "anchor_link"),
        )
        third = _package(_chain((11, 13), prefix="other"))
        self.assertEqual(
            inspect_anchor_set((first, second, third), self.public_key),
            ContinuationChainReport(False, 2, "anchor_link"),
        )

    def test_anchor_link_requires_all_six_fields_equal(self):
        first = _package(_chain((0, 2, 5)))
        # Same boundary size over a different history: version, hash_name
        # and size agree, but root, head and signature all differ.
        other = _package(_chain((5, 8), prefix="other"))
        self.assertEqual(other.start.version, first.end.version)
        self.assertEqual(other.start.hash_name, first.end.hash_name)
        self.assertEqual(other.start.size, first.end.size)
        self.assertNotEqual(other.start.root, first.end.root)
        self.assertNotEqual(other.start.head, first.end.head)
        self.assertNotEqual(other.start.signature, first.end.signature)
        self.assertEqual(
            inspect_anchor_set((first, other), self.public_key),
            ContinuationChainReport(False, 2, "anchor_link"),
        )

    def test_anchor_link_reports_a_size_gap_between_sound_packages(self):
        first = _package(_chain((0, 2, 5)))
        # Internally sound (2 -> 5), but its start checkpoint is size 2,
        # not the first package's size-5 end.
        shifted = _package(_chain((2, 5)))
        self.assertNotEqual(shifted.start.size, first.end.size)
        self.assertEqual(
            inspect_anchor_set((first, shifted), self.public_key),
            ContinuationChainReport(False, 2, "anchor_link"),
        )

    def test_anchor_size_alone_does_not_satisfy_link(self):
        first = _package(_chain((0, 2)))
        second = _package(_chain((2, 5)))
        other = _package(_chain((2, 5), prefix="other"))
        self.assertEqual(other.start.size, second.start.size)
        self.assertNotEqual(other.start, second.start)
        self.assertEqual(
            inspect_anchor_set((first, other), self.public_key),
            ContinuationChainReport(False, 1, "anchor_link"),
        )

    def test_only_first_broken_boundary_is_reported(self):
        first = _package(_chain((0, 2)))
        second = _package(_chain((2, 5), prefix="other"))
        third = _package(_chain((5, 8), prefix="other"))
        self.assertEqual(
            inspect_anchor_set((first, second, third), self.public_key),
            ContinuationChainReport(False, 1, "anchor_link"),
        )

    def test_internal_failure_index_rebased_across_packages(self):
        first = _package(_chain((0, 2)))
        # Signed by another seed: sound under its own key, a verify failure
        # under the pre-trusted one, at its first global receipt position.
        second = _package(_chain((2, 5), seed=_SEED_B))
        self.assertEqual(
            inspect_anchor_set((first, second), self.public_key),
            ContinuationChainReport(False, 1, "verify"),
        )
        three = _package(_chain((0, 2, 5, 8)))
        # The second package itself is signed by another seed: both of its
        # receipts fail, so the first failure is that package's first
        # receipt at global position 3 (after three prior receipts).
        foreign = _package(_chain((8, 11, 13), seed=_SEED_B))
        self.assertEqual(len(three.receipts), 2 + 1)
        self.assertEqual(len(foreign.receipts), 2)
        self.assertEqual(
            inspect_anchor_set((three, foreign), self.public_key),
            ContinuationChainReport(False, 3, "verify"),
        )

    def test_first_package_internal_failure_reported_at_zero(self):
        first = _package(_chain((0, 2), seed=_SEED_B))
        second = _package(_chain((2, 5)))
        self.assertEqual(
            inspect_anchor_set((first, second), self.public_key),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_end_failure_index_rebased(self):
        receipts = _chain((0, 2, 5, 8))
        # Internally continuous receipts anchored against a span that drops
        # the trailing receipt: reports "end" at the last local receipt.
        shortened = AnchoredContinuationChain(
            receipts[:-1],
            receipts[0].consistency.old,
            receipts[-1].consistency.new,
        )
        first = _package(_chain((8, 11)))
        report = inspect_anchor_set((shortened, first), self.public_key)
        self.assertEqual(report, ContinuationChainReport(False, 1, "end"))

    def test_start_failure_in_later_package_rebased(self):
        first = _package(_chain((0, 2)))
        receipts = _chain((2, 5))
        shifted = AnchoredContinuationChain(
            receipts,
            _replace(receipts[0].consistency.old, size=0),
            receipts[-1].consistency.new,
        )
        self.assertEqual(
            inspect_anchor_set((first, shifted), self.public_key),
            ContinuationChainReport(False, 1, "start"),
        )

    def test_duplicate_failure_index_rebased(self):
        receipt = _chain((5, 8))[0]
        duplicate = AnchoredContinuationChain(
            (receipt, receipt),
            receipt.consistency.old,
            receipt.consistency.new,
        )
        first = _package(_chain((0, 2, 5)))
        self.assertEqual(
            inspect_anchor_set((first, duplicate), self.public_key),
            ContinuationChainReport(False, 3, "duplicate"),
        )

    def test_internal_failure_masks_broken_boundary(self):
        # The boundary also fails, but phase 1 reports the verify failure
        # first and the anchors are never compared.
        first = _package(_chain((0, 2)))
        second = _package(_chain((2, 5), seed=_SEED_B, prefix="other"))
        self.assertEqual(
            inspect_anchor_set((first, second), self.public_key),
            ContinuationChainReport(False, 1, "verify"),
        )

    def test_empty_tuple_value_error(self):
        with self.assertRaises(ValueError):
            inspect_anchor_set((), self.public_key)

    def test_non_tuple_raises_type_error(self):
        package = _package(_chain((0, 2)))
        for bad in ([package], {package}, None, package, "p", 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchor_set(bad, self.public_key)

    def test_wrong_element_type_raises_type_error(self):
        package = _package(_chain((0, 2)))
        receipt = package.receipts[0]
        for bad in (b"bytes", "package", None, 1, receipt, object()):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchor_set((bad,), self.public_key)
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchor_set((package, bad), self.public_key)

    def test_key_type_raises_type_error(self):
        packages = _split((0, 2), (1,))
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchor_set(packages, bad)

    def test_key_length_raises_value_error(self):
        packages = _split((0, 2), (1,))
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_anchor_set(packages, bad)

    def test_nested_structural_violation_propagates(self):
        packages = list(_split((0, 2, 5), (1, 2)))
        corrupt = packages[1].receipts[0]
        broken_consistency = SignedConsistency(
            corrupt.consistency.old,
            corrupt.consistency.new,
            corrupt.consistency.proof,
        )
        object.__setattr__(broken_consistency, "proof", ("not-bytes",))
        broken_receipt = SignedAuthAuditContinuation(
            corrupt.bundle, broken_consistency
        )
        packages[1] = AnchoredContinuationChain(
            (broken_receipt,),
            packages[1].start,
            packages[1].end,
        )
        with self.assertRaises(TypeError):
            inspect_anchor_set(tuple(packages), self.public_key)

    def test_call_is_read_only(self):
        packages = _split((0, 2, 5, 8), (2, 3))
        before = tuple(encode_anchored_continuations(p) for p in packages)
        inspect_anchor_set(packages, self.public_key)
        after = tuple(encode_anchored_continuations(p) for p in packages)
        self.assertEqual(after, before)


class MergeAnchorSetTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_merge_concatenates_in_package_and_within_order(self):
        packages = _split((0, 2, 5, 8, 11), (2, 3, 4))
        merged = merge_anchor_set(packages, self.public_key)
        self.assertIsInstance(merged, AnchoredContinuationChain)
        all_receipts = tuple(
            receipt for item in packages for receipt in item.receipts
        )
        self.assertEqual(merged.receipts, all_receipts)
        self.assertEqual(merged.start, packages[0].start)
        self.assertEqual(merged.end, packages[-1].end)

    def test_merge_returns_new_frozen_object(self):
        packages = _split((0, 2, 5), (1, 2))
        merged = merge_anchor_set(packages, self.public_key)
        self.assertNotIn(merged, packages)
        with self.assertRaises(Exception):
            merged.start = merged.end

    def test_merged_artifact_verifies_and_round_trips(self):
        packages = _split((0, 2, 5, 8), (1, 2, 3))
        merged = merge_anchor_set(packages, self.public_key)
        self.assertTrue(
            verify_continuation_chain(merged.receipts, self.public_key)
        )
        self.assertEqual(
            inspect_anchored_continuations(merged, self.public_key),
            ContinuationChainReport(True, None, None),
        )
        # The merged artifact uses the existing format with no new framing:
        # encoding it equals encoding the equivalent hand-built bundle.
        expected = AnchoredContinuationChain(
            tuple(r for p in packages for r in p.receipts),
            packages[0].start,
            packages[-1].end,
        )
        data = encode_anchored_continuations(merged)
        self.assertEqual(data, encode_anchored_continuations(expected))
        self.assertEqual(decode_anchored_continuations(data), merged)

    def test_single_package_merge_matches_endpoints(self):
        packages = _split((0, 2, 5), (2,))
        merged = merge_anchor_set(packages, self.public_key)
        self.assertEqual(merged.receipts, packages[0].receipts)
        self.assertEqual(merged.start, packages[0].start)
        self.assertEqual(merged.end, packages[0].end)

    def test_merge_failure_raises_value_error(self):
        first = _package(_chain((0, 2)))
        other = _package(_chain((2, 5), prefix="other"))
        with self.assertRaises(ValueError):
            merge_anchor_set((first, other), self.public_key)
        foreign = _package(_chain((2, 5), seed=_SEED_B))
        with self.assertRaises(ValueError):
            merge_anchor_set((first, foreign), self.public_key)

    def test_merge_only_runs_when_inspect_succeeds(self):
        packages = _split((0, 2, 5), (1, 2))
        self.assertEqual(
            inspect_anchor_set(packages, self.public_key),
            ContinuationChainReport(True, None, None),
        )
        merged = merge_anchor_set(packages, self.public_key)
        self.assertEqual(
            inspect_anchored_continuations(merged, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_empty_tuple_value_error(self):
        with self.assertRaises(ValueError):
            merge_anchor_set((), self.public_key)

    def test_non_tuple_raises_type_error(self):
        package = _package(_chain((0, 2)))
        for bad in ([package], {package}, None, package, "p", 1):
            with self.assertRaises(TypeError, msg=bad):
                merge_anchor_set(bad, self.public_key)

    def test_wrong_element_type_raises_type_error(self):
        package = _package(_chain((0, 2)))
        for bad in (b"bytes", "package", None, 1, package.receipts[0]):
            with self.assertRaises(TypeError, msg=bad):
                merge_anchor_set((bad,), self.public_key)

    def test_key_type_raises_type_error(self):
        packages = _split((0, 2), (1,))
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                merge_anchor_set(packages, bad)

    def test_key_length_raises_value_error(self):
        packages = _split((0, 2), (1,))
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                merge_anchor_set(packages, bad)

    def test_nested_structural_violation_propagates(self):
        packages = list(_split((0, 2, 5), (1, 2)))
        corrupt = packages[1].receipts[0]
        broken_consistency = SignedConsistency(
            corrupt.consistency.old,
            corrupt.consistency.new,
            corrupt.consistency.proof,
        )
        object.__setattr__(broken_consistency, "proof", ("not-bytes",))
        broken_receipt = SignedAuthAuditContinuation(
            corrupt.bundle, broken_consistency
        )
        packages[1] = AnchoredContinuationChain(
            (broken_receipt,),
            packages[1].start,
            packages[1].end,
        )
        with self.assertRaises(TypeError):
            merge_anchor_set(tuple(packages), self.public_key)

    def test_call_is_read_only(self):
        packages = _split((0, 2, 5, 8), (2, 3))
        before = tuple(
            (
                tuple(
                    encode_signed_auth_audit_continuation(r)
                    for r in p.receipts
                ),
                encode_anchored_continuations(p),
            )
            for p in packages
        )
        merge_anchor_set(packages, self.public_key)
        after = tuple(
            (
                tuple(
                    encode_signed_auth_audit_continuation(r)
                    for r in p.receipts
                ),
                encode_anchored_continuations(p),
            )
            for p in packages
        )
        self.assertEqual(after, before)

    def test_failed_merge_leaves_inputs_unchanged(self):
        first = _package(_chain((0, 2)))
        other = _package(_chain((2, 5), prefix="other"))
        before = (
            encode_anchored_continuations(first),
            encode_anchored_continuations(other),
        )
        with self.assertRaises(ValueError):
            merge_anchor_set((first, other), self.public_key)
        after = (
            encode_anchored_continuations(first),
            encode_anchored_continuations(other),
        )
        self.assertEqual(after, before)


class AnchorLinkCodeTest(unittest.TestCase):
    def test_anchor_link_constructs_and_compares(self):
        report = ContinuationChainReport(False, 2, "anchor_link")
        self.assertEqual(report.code, "anchor_link")
        self.assertEqual(report.index, 2)
        self.assertEqual(
            hash(report),
            hash(ContinuationChainReport(False, 2, "anchor_link")),
        )
        self.assertNotEqual(
            report, ContinuationChainReport(False, 2, "link")
        )

    def test_existing_codes_still_construct(self):
        for code in ("verify", "growth", "duplicate", "link", "start", "end"):
            self.assertEqual(
                ContinuationChainReport(False, 1, code).code, code
            )

    def test_unknown_code_still_raises_value_error(self):
        for code in ("", "ANCHOR_LINK", "anchor", "join", "splice"):
            with self.assertRaises(ValueError, msg=code):
                ContinuationChainReport(False, 0, code)


if __name__ == "__main__":
    unittest.main()
