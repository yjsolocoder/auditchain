import unittest
from dataclasses import fields

from auditchain import (
    AnchoredContinuationChain,
    AuditLog,
    ContinuationChainReport,
    SignedAuthAuditContinuation,
    SignedRoot,
    decode_anchored_continuations,
    decode_continuations,
    decode_signed_root,
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


def _anchors(receipts):
    """The exact endpoints a chain spans: its first old and last new."""
    return receipts[0].consistency.old, receipts[-1].consistency.new


def _bundle(sizes=(0, 2, 5, 8), **kwargs):
    receipts = _chain(sizes, **kwargs)
    start, end = _anchors(receipts)
    return AnchoredContinuationChain(receipts, start, end)


class AnchoredContinuationChainTest(unittest.TestCase):
    def test_positional_construction_and_field_equality(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        bundle = AnchoredContinuationChain(receipts, start, end)
        self.assertEqual(bundle.receipts, receipts)
        self.assertEqual(bundle.start, start)
        self.assertEqual(bundle.end, end)
        self.assertEqual(
            bundle, AnchoredContinuationChain(receipts, start, end)
        )
        self.assertEqual(
            hash(bundle), hash(AnchoredContinuationChain(receipts, start, end))
        )

    def test_field_order_is_receipts_start_end(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        bundle = AnchoredContinuationChain(receipts, start, end)
        self.assertEqual(
            tuple(field.name for field in fields(bundle)),
            ("receipts", "start", "end"),
        )
        self.assertEqual(
            (bundle.receipts, bundle.start, bundle.end),
            (receipts, start, end),
        )

    def test_fields_compare_individually(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        bundle = AnchoredContinuationChain(receipts, start, end)
        # A chain over different sizes: every field differs from bundle's.
        other_receipts = _chain((1, 3, 6))
        other_start, other_end = _anchors(other_receipts)
        self.assertNotEqual(other_start, start)
        self.assertNotEqual(other_end, end)
        self.assertNotEqual(
            bundle, AnchoredContinuationChain(other_receipts, start, end)
        )
        self.assertNotEqual(
            bundle, AnchoredContinuationChain(receipts, other_start, end)
        )
        self.assertNotEqual(
            bundle, AnchoredContinuationChain(receipts, start, other_end)
        )

    def test_is_frozen(self):
        bundle = _bundle((0, 2, 5))
        with self.assertRaises(Exception):
            bundle.start = bundle.end

    def test_non_tuple_receipts_raise_type_error(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        for bad in ([receipts[0]], {receipts[0]}, None, receipts[0], "r", 1):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(bad, start, end)

    def test_empty_receipts_raise_value_error(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        with self.assertRaises(ValueError):
            AnchoredContinuationChain((), start, end)

    def test_wrong_element_type_raises_type_error(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain((bad,), start, end)
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain((receipts[0], bad), start, end)

    def test_non_signed_root_anchors_raise_type_error(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        for bad in (b"bytes", "anchor", None, 1, (start,), object()):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(receipts, bad, end)
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(receipts, start, bad)


class EncodeAnchoredContinuationsTest(unittest.TestCase):
    def test_round_trip_preserves_fields(self):
        bundle = _bundle()
        data = encode_anchored_continuations(bundle)
        restored = decode_anchored_continuations(data)
        self.assertIsInstance(restored, AnchoredContinuationChain)
        self.assertEqual(restored, bundle)
        self.assertEqual(encode_anchored_continuations(restored), data)

    def test_single_segment_round_trip(self):
        bundle = _bundle((1, 4))
        data = encode_anchored_continuations(bundle)
        self.assertEqual(decode_anchored_continuations(data), bundle)

    def test_wire_format(self):
        bundle = _bundle((0, 2, 5))
        data = encode_anchored_continuations(bundle)
        self.assertTrue(data.startswith(_MAGIC))
        offset = len(_MAGIC)
        self.assertEqual(
            data[offset:offset + 8], (1).to_bytes(8, "big")
        )
        offset += 8
        for nested in (
            encode_continuations(bundle.receipts),
            encode_signed_root(bundle.start),
            encode_signed_root(bundle.end),
        ):
            self.assertEqual(
                data[offset:offset + 8], len(nested).to_bytes(8, "big")
            )
            self.assertEqual(
                data[offset + 8:offset + 8 + len(nested)], nested
            )
            offset += 8 + len(nested)
        self.assertEqual(offset, len(data))

    def test_non_bundle_raises_type_error(self):
        bundle = _bundle((0, 2, 5))
        for bad in (
            bundle.receipts,
            [bundle],
            None,
            "bundle",
            1,
            (bundle.receipts, bundle.start, bundle.end),
        ):
            with self.assertRaises(TypeError, msg=bad):
                encode_anchored_continuations(bad)

    def test_bypassed_constructor_field_type_raises_type_error(self):
        bundle = _bundle((0, 2, 5))
        object.__setattr__(bundle, "start", "not-a-signed-root")
        with self.assertRaises(TypeError):
            encode_anchored_continuations(bundle)

    def test_encoding_is_deterministic(self):
        bundle = _bundle()
        self.assertEqual(
            encode_anchored_continuations(bundle),
            encode_anchored_continuations(bundle),
        )

    def test_encoding_is_read_only(self):
        bundle = _bundle()
        before = tuple(
            encode_signed_auth_audit_continuation(r) for r in bundle.receipts
        )
        encode_anchored_continuations(bundle)
        after = tuple(
            encode_signed_auth_audit_continuation(r) for r in bundle.receipts
        )
        self.assertEqual(after, before)


class DecodeAnchoredContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.bundle = _bundle()
        self.data = encode_anchored_continuations(self.bundle)

    def test_non_bytes_raises_type_error(self):
        for bad in (bytearray(self.data), memoryview(self.data), None, 1, ""):
            with self.assertRaises(TypeError, msg=bad):
                decode_anchored_continuations(bad)

    def test_bad_magic_raises_value_error(self):
        bad = b"x" + self.data[1:]
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_unsupported_version_raises_value_error(self):
        offset = len(_MAGIC)
        bad = (
            self.data[:offset]
            + (2).to_bytes(8, "big")
            + self.data[offset + 8:]
        )
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_truncated_raises_value_error(self):
        for cut in (1, len(_MAGIC), len(_MAGIC) + 4, len(_MAGIC) + 8,
                    len(_MAGIC) + 9, len(self.data) - 1):
            with self.assertRaises(ValueError, msg=cut):
                decode_anchored_continuations(self.data[:cut])

    def test_blob_length_overflow_raises_value_error(self):
        offset = len(_MAGIC) + 8
        bad = (
            self.data[:offset]
            + (2**64 - 1).to_bytes(8, "big")
            + self.data[offset + 8:]
        )
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_trailing_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            decode_anchored_continuations(self.data + b"\x00")

    def test_missing_blob_raises_value_error(self):
        # Only the chain and start blobs, no end blob.
        offset = len(_MAGIC) + 8
        chain = encode_continuations(self.bundle.receipts)
        start = encode_signed_root(self.bundle.start)
        bad = (
            _MAGIC
            + (1).to_bytes(8, "big")
            + len(chain).to_bytes(8, "big") + chain
            + len(start).to_bytes(8, "big") + start
        )
        self.assertLess(offset, len(bad))
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_nested_chain_format_error_propagates(self):
        nested = encode_continuations(self.bundle.receipts)
        corrupt = nested[:-1]  # trailing cut inside the nested encoding
        bad = (
            _MAGIC
            + (1).to_bytes(8, "big")
            + len(corrupt).to_bytes(8, "big") + corrupt
        )
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_nested_anchor_format_error_propagates(self):
        chain = encode_continuations(self.bundle.receipts)
        corrupt = encode_signed_root(self.bundle.start)[:-1]
        bad = (
            _MAGIC
            + (1).to_bytes(8, "big")
            + len(chain).to_bytes(8, "big") + chain
            + len(corrupt).to_bytes(8, "big") + corrupt
        )
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_nested_decoders_see_whole_blobs(self):
        # A chain blob carrying trailing bytes of its own is rejected even
        # though the outer framing would still parse.
        chain = encode_continuations(self.bundle.receipts) + b"\x00"
        start = encode_signed_root(self.bundle.start)
        end = encode_signed_root(self.bundle.end)
        bad = (
            _MAGIC
            + (1).to_bytes(8, "big")
            + len(chain).to_bytes(8, "big") + chain
            + len(start).to_bytes(8, "big") + start
            + len(end).to_bytes(8, "big") + end
        )
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_decoded_bundle_matches_nested_decoders(self):
        restored = decode_anchored_continuations(self.data)
        offset = len(_MAGIC) + 8
        chain_length = int.from_bytes(self.data[offset:offset + 8], "big")
        chain_blob = self.data[offset + 8:offset + 8 + chain_length]
        self.assertEqual(restored.receipts, decode_continuations(chain_blob))
        self.assertIsInstance(restored.start, SignedRoot)
        self.assertIsInstance(restored.end, SignedRoot)

    def test_structurally_valid_but_unverifying_bundle_decodes(self):
        # Decoding does not check signatures or anchor relations.
        receipts = _chain((0, 2, 5))
        other = _chain((1, 4, 7))
        start, _ = _anchors(receipts)
        _, end = _anchors(other)
        bundle = AnchoredContinuationChain(receipts, start, end)
        data = encode_anchored_continuations(bundle)
        self.assertEqual(decode_anchored_continuations(data), bundle)


class InspectAnchoredContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_success_report_shape(self):
        bundle = _bundle()
        report = inspect_anchored_continuations(bundle, self.public_key)
        self.assertEqual(report, ContinuationChainReport(True, None, None))
        self.assertIsInstance(report, ContinuationChainReport)

    def test_matches_inspect_anchors_on_success(self):
        bundle = _bundle()
        self.assertEqual(
            inspect_anchored_continuations(bundle, self.public_key),
            inspect_anchors(
                bundle.receipts, self.public_key, bundle.start, bundle.end
            ),
        )

    def test_untrusted_key_reports_verify(self):
        bundle = _bundle()
        self.assertEqual(
            inspect_anchored_continuations(bundle, self.other_public_key),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_start_mismatch_reports_start(self):
        receipts = _chain((0, 2, 5, 8))
        _, end = _anchors(receipts)
        other_start, _ = _anchors(_chain((1, 4, 7)))
        bundle = AnchoredContinuationChain(receipts, other_start, end)
        self.assertEqual(
            inspect_anchored_continuations(bundle, self.public_key),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_end_mismatch_reports_end_at_last_segment(self):
        receipts = _chain((0, 2, 5, 8))
        start, _ = _anchors(receipts)
        _, other_end = _anchors(_chain((1, 4, 7)))
        bundle = AnchoredContinuationChain(receipts, start, other_end)
        self.assertEqual(
            inspect_anchored_continuations(bundle, self.public_key),
            ContinuationChainReport(False, 2, "end"),
        )

    def test_internal_failure_passes_through(self):
        receipt = _chain((2, 5))[0]
        start, end = _anchors((receipt, receipt))
        bundle = AnchoredContinuationChain((receipt, receipt), start, end)
        self.assertEqual(
            inspect_anchored_continuations(bundle, self.public_key),
            ContinuationChainReport(False, 1, "duplicate"),
        )

    def test_non_bundle_raises_type_error(self):
        bundle = _bundle((0, 2, 5))
        for bad in (
            bundle.receipts,
            [bundle],
            None,
            "bundle",
            1,
            (bundle.receipts, bundle.start, bundle.end),
        ):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchored_continuations(bad, self.public_key)

    def test_key_type_raises_type_error(self):
        bundle = _bundle((0, 2, 5))
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchored_continuations(bundle, bad)

    def test_key_length_raises_value_error(self):
        bundle = _bundle((0, 2, 5))
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_anchored_continuations(bundle, bad)

    def test_bypassed_constructor_field_type_raises_type_error(self):
        bundle = _bundle((0, 2, 5))
        object.__setattr__(bundle, "end", "not-a-signed-root")
        with self.assertRaises(TypeError):
            inspect_anchored_continuations(bundle, self.public_key)

    def test_call_is_read_only(self):
        bundle = _bundle()
        before = encode_anchored_continuations(bundle)
        inspect_anchored_continuations(bundle, self.public_key)
        self.assertEqual(encode_anchored_continuations(bundle), before)

    def test_decoded_bundle_diagnoses_like_original(self):
        bundle = _bundle()
        restored = decode_anchored_continuations(
            encode_anchored_continuations(bundle)
        )
        self.assertEqual(
            inspect_anchored_continuations(restored, self.public_key),
            ContinuationChainReport(True, None, None),
        )


class InspectAnchorsKeyParameterTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_second_parameter_is_named_key(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        self.assertEqual(
            inspect_anchors(receipts, key=self.public_key, start=start, end=end),
            ContinuationChainReport(True, None, None),
        )

    def test_positional_call_unchanged(self):
        receipts = _chain((0, 2, 5))
        start, end = _anchors(receipts)
        self.assertEqual(
            inspect_anchors(receipts, self.public_key, start, end),
            inspect_anchors(receipts, key=self.public_key, start=start, end=end),
        )


if __name__ == "__main__":
    unittest.main()
