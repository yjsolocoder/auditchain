import unittest

from auditchain import (
    AnchoredContinuationChain,
    AuditLog,
    ContinuationChainReport,
    SignedAuthAuditContinuation,
    SignedRoot,
    decode_anchored_continuations,
    decode_continuations,
    encode_anchored_continuations,
    encode_continuations,
    encode_signed_auth_audit_continuation,
    encode_signed_root,
    inspect_anchored_continuations,
    inspect_anchors,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"
_MAGIC = b"auditchain/anchor/v1\0"


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


def _bundle(sizes=(0, 2, 5), **kwargs):
    """A chain together with the exact anchors it spans."""
    receipts = _chain(sizes, **kwargs)
    return AnchoredContinuationChain(
        receipts, receipts[0].consistency.old, receipts[-1].consistency.new
    )


def _u64(value):
    return value.to_bytes(8, "big")


def _blob(material):
    return _u64(len(material)) + material


class AnchoredContinuationChainTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        bundle = _bundle()
        again = AnchoredContinuationChain(
            bundle.receipts, bundle.start, bundle.end
        )
        self.assertEqual(bundle, again)
        self.assertEqual(hash(bundle), hash(again))
        self.assertEqual(
            (bundle.receipts, bundle.start, bundle.end),
            (again.receipts, again.start, again.end),
        )

    def test_keyword_construction(self):
        bundle = _bundle()
        self.assertEqual(
            AnchoredContinuationChain(
                receipts=bundle.receipts, start=bundle.start, end=bundle.end
            ),
            bundle,
        )

    def test_inequality_by_each_field(self):
        bundle = _bundle((0, 2, 5))
        other = _bundle((0, 2, 5), prefix="other")
        shifted = _bundle((1, 3, 6))
        # A different payload prefix changes the receipts (and end anchor);
        # a shifted span supplies distinct anchor checkpoints.
        self.assertNotEqual(
            bundle,
            AnchoredContinuationChain(other.receipts, bundle.start, bundle.end),
        )
        self.assertNotEqual(
            bundle,
            AnchoredContinuationChain(
                bundle.receipts, shifted.start, bundle.end
            ),
        )
        self.assertNotEqual(
            bundle,
            AnchoredContinuationChain(
                bundle.receipts, bundle.start, shifted.end
            ),
        )

    def test_frozen(self):
        bundle = _bundle()
        with self.assertRaises(Exception):
            bundle.start = bundle.end

    def test_non_tuple_receipts_raise_type_error(self):
        bundle = _bundle()
        for bad in (
            list(bundle.receipts),
            bundle.receipts[0],
            None,
            "receipts",
            1,
        ):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(bad, bundle.start, bundle.end)

    def test_empty_tuple_raises_value_error(self):
        bundle = _bundle()
        with self.assertRaises(ValueError):
            AnchoredContinuationChain((), bundle.start, bundle.end)

    def test_wrong_element_type_raises_type_error(self):
        bundle = _bundle()
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain((bad,), bundle.start, bundle.end)
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(
                    (bundle.receipts[0], bad), bundle.start, bundle.end
                )

    def test_non_signed_root_anchors_raise_type_error(self):
        bundle = _bundle()
        for bad in (b"bytes", "anchor", None, 1, (bundle.start,), object()):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(bundle.receipts, bad, bundle.end)
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(bundle.receipts, bundle.start, bad)


class EncodeAnchoredContinuationsTest(unittest.TestCase):
    def test_canonical_stream_layout(self):
        bundle = _bundle((0, 2, 5, 8))
        expected = b"".join((
            _MAGIC,
            _u64(1),
            _blob(encode_continuations(bundle.receipts)),
            _blob(encode_signed_root(bundle.start)),
            _blob(encode_signed_root(bundle.end)),
        ))
        self.assertEqual(encode_anchored_continuations(bundle), expected)

    def test_chain_blob_equals_encode_continuations_output(self):
        bundle = _bundle()
        data = encode_anchored_continuations(bundle)
        offset = len(_MAGIC) + 8
        length = int.from_bytes(data[offset:offset + 8], "big")
        blob = data[offset + 8:offset + 8 + length]
        self.assertEqual(blob, encode_continuations(bundle.receipts))
        self.assertEqual(decode_continuations(blob), bundle.receipts)

    def test_non_bundle_raises_type_error(self):
        bundle = _bundle()
        for bad in (
            bundle.receipts,
            (bundle.receipts, bundle.start, bundle.end),
            b"bytes",
            "bundle",
            None,
            1,
            object(),
        ):
            with self.assertRaises(TypeError, msg=bad):
                encode_anchored_continuations(bad)

    def test_nested_encode_exception_propagates(self):
        bundle = _bundle()
        corrupt = SignedRoot(
            bundle.start.version,
            bundle.start.hash_name,
            bundle.start.size,
            bundle.start.root,
            bundle.start.head,
            bundle.start.signature,
        )
        object.__setattr__(corrupt, "signature", b"\x00" * 63)
        object.__setattr__(bundle, "start", corrupt)
        with self.assertRaises(ValueError):
            encode_anchored_continuations(bundle)

    def test_call_is_read_only(self):
        bundle = _bundle()
        before = tuple(
            encode_signed_auth_audit_continuation(r) for r in bundle.receipts
        )
        start_bytes = encode_signed_root(bundle.start)
        encode_anchored_continuations(bundle)
        self.assertEqual(
            tuple(
                encode_signed_auth_audit_continuation(r)
                for r in bundle.receipts
            ),
            before,
        )
        self.assertEqual(encode_signed_root(bundle.start), start_bytes)


class DecodeAnchoredContinuationsTest(unittest.TestCase):
    def test_round_trip_restores_equal_bundle(self):
        bundle = _bundle((0, 2, 5, 8))
        data = encode_anchored_continuations(bundle)
        restored = decode_anchored_continuations(data)
        self.assertIsInstance(restored, AnchoredContinuationChain)
        self.assertEqual(restored, bundle)
        self.assertEqual(encode_anchored_continuations(restored), data)

    def test_single_segment_round_trip(self):
        bundle = _bundle((2, 5))
        self.assertEqual(
            decode_anchored_continuations(
                encode_anchored_continuations(bundle)
            ),
            bundle,
        )

    def test_non_bytes_raises_type_error(self):
        data = encode_anchored_continuations(_bundle())
        for bad in (bytearray(data), memoryview(data), "data", None, 1):
            with self.assertRaises(TypeError, msg=bad):
                decode_anchored_continuations(bad)

    def test_bad_magic_raises_value_error(self):
        data = encode_anchored_continuations(_bundle())
        for bad in (b"", b"auditchain/anchor/v2\0" + data[len(_MAGIC):],
                    b"\x00" + data[1:]):
            with self.assertRaises(ValueError, msg=bad[:8]):
                decode_anchored_continuations(bad)

    def test_bad_version_raises_value_error(self):
        bundle = _bundle()
        data = encode_anchored_continuations(bundle)
        for version in (0, 2, 1 << 64 - 1):
            broken = _MAGIC + _u64(version) + data[len(_MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_anchored_continuations(broken)

    def test_truncation_raises_value_error(self):
        data = encode_anchored_continuations(_bundle())
        for cut in (len(_MAGIC), len(_MAGIC) + 4, len(_MAGIC) + 8,
                    len(data) - 1, len(data) // 2):
            with self.assertRaises(ValueError, msg=cut):
                decode_anchored_continuations(data[:cut])

    def test_trailing_bytes_raise_value_error(self):
        data = encode_anchored_continuations(_bundle())
        with self.assertRaises(ValueError):
            decode_anchored_continuations(data + b"\x00")

    def test_oversized_blob_length_raises_value_error(self):
        bundle = _bundle()
        data = encode_anchored_continuations(bundle)
        broken = _MAGIC + _u64(1) + _u64(len(data)) + data[len(_MAGIC) + 16:]
        with self.assertRaises(ValueError):
            decode_anchored_continuations(broken)

    def test_nested_chain_exception_propagates(self):
        bundle = _bundle()
        data = b"".join((
            _MAGIC,
            _u64(1),
            _blob(b"not a continuation chain"),
            _blob(encode_signed_root(bundle.start)),
            _blob(encode_signed_root(bundle.end)),
        ))
        with self.assertRaises(ValueError):
            decode_anchored_continuations(data)

    def test_nested_anchor_exception_propagates(self):
        bundle = _bundle()
        for position in ("start", "end"):
            anchors = {
                "start": encode_signed_root(bundle.start),
                "end": encode_signed_root(bundle.end),
            }
            anchors[position] = b"not a signed root"
            data = b"".join((
                _MAGIC,
                _u64(1),
                _blob(encode_continuations(bundle.receipts)),
                _blob(anchors["start"]),
                _blob(anchors["end"]),
            ))
            with self.assertRaises(ValueError, msg=position):
                decode_anchored_continuations(data)


class InspectAnchoredContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_success_report_shape(self):
        bundle = _bundle((0, 2, 5))
        report = inspect_anchored_continuations(bundle, self.public_key)
        self.assertEqual(report, ContinuationChainReport(True, None, None))
        self.assertIsInstance(report, ContinuationChainReport)

    def test_restored_bundle_reports_ok(self):
        # The cross-process flow: encode, decode, diagnose — no log held.
        bundle = _bundle((0, 2, 5, 8))
        restored = decode_anchored_continuations(
            encode_anchored_continuations(bundle)
        )
        self.assertEqual(
            inspect_anchored_continuations(restored, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_agrees_with_inspect_anchors(self):
        bundle = _bundle((0, 2, 5, 8))
        for key in (self.public_key, self.other_public_key):
            self.assertEqual(
                inspect_anchored_continuations(bundle, key),
                inspect_anchors(
                    bundle.receipts, key, bundle.start, bundle.end
                ),
            )

    def test_anchor_mismatch_codes_pass_through(self):
        bundle = _bundle((0, 2, 5, 8))
        truncated = AnchoredContinuationChain(
            bundle.receipts[1:], bundle.start, bundle.receipts[-1].consistency.new
        )
        self.assertEqual(
            inspect_anchored_continuations(truncated, self.public_key),
            ContinuationChainReport(False, 0, "start"),
        )
        shortened = AnchoredContinuationChain(
            bundle.receipts[:-1], bundle.receipts[0].consistency.old, bundle.end
        )
        self.assertEqual(
            inspect_anchored_continuations(shortened, self.public_key),
            ContinuationChainReport(False, 1, "end"),
        )

    def test_internal_failure_codes_pass_through(self):
        bundle = _bundle((0, 2, 5))
        self.assertEqual(
            inspect_anchored_continuations(bundle, self.other_public_key),
            ContinuationChainReport(False, 0, "verify"),
        )
        receipt = _chain((2, 5))[0]
        duplicate = AnchoredContinuationChain(
            (receipt, receipt),
            receipt.consistency.old,
            receipt.consistency.new,
        )
        self.assertEqual(
            inspect_anchored_continuations(duplicate, self.public_key),
            ContinuationChainReport(False, 1, "duplicate"),
        )

    def test_non_bundle_raises_type_error(self):
        bundle = _bundle()
        for bad in (
            bundle.receipts,
            (bundle.receipts, bundle.start, bundle.end),
            b"bytes",
            "bundle",
            None,
            1,
            object(),
        ):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchored_continuations(bad, self.public_key)

    def test_key_validation_propagates(self):
        bundle = _bundle()
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchored_continuations(bundle, bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_anchored_continuations(bundle, bad)

    def test_call_is_read_only(self):
        bundle = _bundle()
        before = encode_anchored_continuations(bundle)
        inspect_anchored_continuations(bundle, self.public_key)
        self.assertEqual(encode_anchored_continuations(bundle), before)


if __name__ == "__main__":
    unittest.main()
