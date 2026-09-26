import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AnchorSet,
    AnchoredContinuationChain,
    AuditLog,
    ContinuationChainReport,
    decode_anchor_set,
    encode_anchor_set,
    encode_anchored_continuations,
    inspect_anchor_set,
    merge_anchor_set,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"
_MAGIC = b"auditchain/anchor-set/v1\0"

_OK = ContinuationChainReport(True, None, None)


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


def _u64(value):
    return value.to_bytes(8, "big")


def _blob(material):
    return _u64(len(material)) + material


def _stream(version, package_blobs, *, package_count=None):
    n = len(package_blobs) if package_count is None else package_count
    return b"".join(
        (
            _MAGIC,
            _u64(version),
            _u64(n),
            *(_blob(blob) for blob in package_blobs),
        )
    )


class AnchorSetTest(unittest.TestCase):
    def setUp(self):
        self.packages = _split((0, 2, 5, 8), (2, 3))

    def test_constructs_positionally_and_compares_by_field(self):
        bundle = AnchorSet(self.packages)
        self.assertEqual(bundle.items, self.packages)
        self.assertEqual(bundle, AnchorSet(self.packages))
        self.assertEqual(hash(bundle), hash(AnchorSet(self.packages)))
        self.assertNotEqual(bundle, AnchorSet(self.packages[:1]))

    def test_keyword_construction(self):
        self.assertEqual(
            AnchorSet(items=self.packages), AnchorSet(self.packages)
        )

    def test_is_frozen(self):
        bundle = AnchorSet(self.packages)
        with self.assertRaises(Exception):
            bundle.items = self.packages[:1]

    def test_non_tuple_raises_type_error(self):
        for bad in ([self.packages[0]], {self.packages[0]}, None,
                    self.packages[0], "p", 1):
            with self.assertRaises(TypeError, msg=bad):
                AnchorSet(bad)

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            AnchorSet(())

    def test_wrong_element_type_raises_type_error(self):
        receipt = self.packages[0].receipts[0]
        for bad in (b"bytes", "package", None, 1, receipt, object()):
            with self.assertRaises(TypeError, msg=bad):
                AnchorSet((bad,))
            with self.assertRaises(TypeError, msg=bad):
                AnchorSet((self.packages[0], bad))


class EncodeAnchorSetTest(unittest.TestCase):
    def setUp(self):
        self.packages = _split((0, 2, 5, 8), (2, 3))
        self.bundle = AnchorSet(self.packages)

    def test_framing_is_exact(self):
        data = encode_anchor_set(self.bundle)
        expected = _stream(
            1, [encode_anchored_continuations(p) for p in self.packages]
        )
        self.assertEqual(data, expected)
        self.assertTrue(data.startswith(_MAGIC + _u64(1) + _u64(2)))

    def test_single_package_set(self):
        bundle = AnchorSet(self.packages[:1])
        self.assertEqual(
            encode_anchor_set(bundle),
            _stream(1, [encode_anchored_continuations(self.packages[0])]),
        )

    def test_encoding_is_deterministic(self):
        self.assertEqual(
            encode_anchor_set(self.bundle), encode_anchor_set(self.bundle)
        )

    def test_non_anchor_set_raises_type_error(self):
        for bad in (self.packages, [self.packages[0]], None, "p", 1,
                    self.packages[0], b"bytes"):
            with self.assertRaises(TypeError, msg=bad):
                encode_anchor_set(bad)

    def test_nested_structural_violation_propagates(self):
        corrupt = self.packages[0].receipts[0]
        from auditchain import SignedAuthAuditContinuation, SignedConsistency

        broken_consistency = SignedConsistency(
            corrupt.consistency.old,
            corrupt.consistency.new,
            corrupt.consistency.proof,
        )
        object.__setattr__(broken_consistency, "proof", ("not-bytes",))
        broken_receipt = SignedAuthAuditContinuation(
            corrupt.bundle, broken_consistency
        )
        broken_package = AnchoredContinuationChain(
            (broken_receipt,), self.packages[0].start, self.packages[0].end
        )
        with self.assertRaises(TypeError):
            encode_anchor_set(AnchorSet((broken_package,)))

    def test_call_is_read_only(self):
        before = tuple(
            encode_anchored_continuations(p) for p in self.packages
        )
        encode_anchor_set(self.bundle)
        after = tuple(
            encode_anchored_continuations(p) for p in self.packages
        )
        self.assertEqual(after, before)


class DecodeAnchorSetTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.packages = _split((0, 2, 5, 8), (2, 3))
        self.bundle = AnchorSet(self.packages)
        self.data = encode_anchor_set(self.bundle)

    def test_round_trip_restores_equal_frozen_object(self):
        restored = decode_anchor_set(self.data)
        self.assertIsInstance(restored, AnchorSet)
        self.assertEqual(restored, self.bundle)
        self.assertEqual(restored.items, self.packages)
        self.assertEqual(hash(restored), hash(self.bundle))

    def test_reencoding_reproduces_original_bytes(self):
        self.assertEqual(encode_anchor_set(decode_anchor_set(self.data)),
                         self.data)

    def test_single_package_round_trip(self):
        bundle = AnchorSet(self.packages[:1])
        self.assertEqual(
            decode_anchor_set(encode_anchor_set(bundle)), bundle
        )

    def test_restored_items_feed_inspect_and_merge(self):
        restored = decode_anchor_set(self.data)
        self.assertEqual(
            inspect_anchor_set(restored.items, self.public_key), _OK
        )
        merged = merge_anchor_set(restored.items, self.public_key)
        self.assertEqual(merged.start, self.packages[0].start)
        self.assertEqual(merged.end, self.packages[-1].end)
        self.assertEqual(
            merged.receipts,
            tuple(r for p in self.packages for r in p.receipts),
        )

    def test_unverifiable_but_structural_set_still_round_trips(self):
        # Two sound packages whose anchors do not join: the codec does not
        # check the seam, only inspect_anchor_set reports it.
        first = _package(_chain((0, 2)))
        other = _package(_chain((2, 5), prefix="other"))
        bundle = AnchorSet((first, other))
        restored = decode_anchor_set(encode_anchor_set(bundle))
        self.assertEqual(restored, bundle)
        self.assertEqual(
            inspect_anchor_set(restored.items, self.public_key),
            ContinuationChainReport(False, 1, "anchor_link"),
        )

    def test_non_bytes_raises_type_error(self):
        for bad in (bytearray(self.data), memoryview(self.data), None, 1,
                    "data", [self.data]):
            with self.assertRaises(TypeError, msg=bad):
                decode_anchor_set(bad)

    def test_bad_magic_raises_value_error(self):
        for bad in (b"", b"auditchain/anchor-set/v1",
                    b"auditchain/anchor-set/v2\0" + self.data[len(_MAGIC):],
                    b"auditchain/anchor/v1\0" + self.data[len(_MAGIC):]):
            with self.assertRaises(ValueError, msg=bad[:30]):
                decode_anchor_set(bad)

    def test_bad_version_raises_value_error(self):
        blobs = [encode_anchored_continuations(p) for p in self.packages]
        for version in (0, 2, 2**64 - 1):
            with self.assertRaises(ValueError, msg=version):
                decode_anchor_set(_stream(version, blobs))

    def test_zero_package_count_raises_value_error(self):
        with self.assertRaises(ValueError):
            decode_anchor_set(_stream(1, [], package_count=0))

    def test_truncation_raises_value_error(self):
        for cut in (len(_MAGIC), len(_MAGIC) + 4, len(_MAGIC) + 8,
                    len(_MAGIC) + 16, len(self.data) - 1):
            with self.assertRaises(ValueError, msg=cut):
                decode_anchor_set(self.data[:cut])

    def test_trailing_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            decode_anchor_set(self.data + b"\0")
        with self.assertRaises(ValueError):
            decode_anchor_set(self.data + self.data)

    def test_oversized_blob_length_raises_value_error(self):
        blob = encode_anchored_continuations(self.packages[0])
        oversized = _MAGIC + _u64(1) + _u64(1) + _u64(len(blob) + 1) + blob
        with self.assertRaises(ValueError):
            decode_anchor_set(oversized)
        huge = _MAGIC + _u64(1) + _u64(1) + _u64(2**64 - 1)
        with self.assertRaises(ValueError):
            decode_anchor_set(huge)

    def test_fewer_blobs_than_count_raises_value_error(self):
        blob = encode_anchored_continuations(self.packages[0])
        with self.assertRaises(ValueError):
            decode_anchor_set(_stream(1, [blob], package_count=2))

    def test_illegal_nested_encoding_raises_value_error(self):
        with self.assertRaises(ValueError):
            decode_anchor_set(_stream(1, [b"not-a-package"]))
        blob = encode_anchored_continuations(self.packages[0])
        with self.assertRaises(ValueError):
            decode_anchor_set(_stream(1, [blob[:-1]]))

    def test_nested_exception_type_propagates(self):
        # A nested blob that fails the nested decoder with ValueError
        # propagates as ValueError, not as a framing error of our own.
        blob = encode_anchored_continuations(self.packages[0])
        corrupted = blob[:26] + b"\xff" + blob[27:]
        with self.assertRaises(ValueError):
            decode_anchor_set(_stream(1, [corrupted]))

    def test_call_is_read_only(self):
        before = bytes(self.data)
        decode_anchor_set(self.data)
        self.assertEqual(self.data, before)


if __name__ == "__main__":
    unittest.main()
