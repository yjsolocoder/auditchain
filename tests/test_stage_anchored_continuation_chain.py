import unittest

from auditchain import (
    AuditLog,
    ContinuationChainReport,
    SignedConsistency,
    SignedStageAuthAuditContinuation,
    StageAnchoredContinuationChain,
    decode_stage_anchored_continuations,
    decode_stage_continuations,
    encode_signed_root,
    encode_stage_anchored_continuations,
    encode_stage_continuations,
    inspect_stage_anchors,
    verify_stage_continuation_chain,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"
_MAGIC = b"auditchain/stage-anchor/v1\0"


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
    log.rotate_key()
    return log


def _chain(sizes, seed=_SEED_A, n=None, indices=(), **kwargs):
    """Issue one fresh log per segment, all on identical content, so the
    checkpoints match across segments."""
    if n is None:
        n = sizes[-1]
    receipts = []
    old = sizes[0]
    for new in sizes[1:]:
        receipt = _log(n, **kwargs).signed_stage_auth_audit_continuation(
            old, indices, seed, size=new
        )
        receipts.append(receipt)
        old = new
    return tuple(receipts)


def _bundle(sizes=(0, 2, 5), **kwargs):
    """A stage chain together with the exact anchors it spans."""
    receipts = _chain(sizes, **kwargs)
    return StageAnchoredContinuationChain(
        receipts, receipts[0].consistency.old, receipts[-1].consistency.new
    )


def _u64(value):
    return value.to_bytes(8, "big")


def _blob(material):
    return _u64(len(material)) + material


class StageAnchoredContinuationChainTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        bundle = _bundle()
        again = StageAnchoredContinuationChain(
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
            StageAnchoredContinuationChain(
                receipts=bundle.receipts, start=bundle.start, end=bundle.end
            ),
            bundle,
        )

    def test_inequality_by_each_field(self):
        bundle = _bundle((0, 2, 5))
        other = _bundle((0, 2, 5), prefix="other")
        shifted = _bundle((1, 3, 6))
        self.assertNotEqual(
            bundle,
            StageAnchoredContinuationChain(
                other.receipts, bundle.start, bundle.end
            ),
        )
        self.assertNotEqual(
            bundle,
            StageAnchoredContinuationChain(
                bundle.receipts, shifted.start, bundle.end
            ),
        )
        self.assertNotEqual(
            bundle,
            StageAnchoredContinuationChain(
                bundle.receipts, bundle.start, shifted.end
            ),
        )

    def test_frozen(self):
        bundle = _bundle()
        with self.assertRaises(AttributeError):
            bundle.start = bundle.end

    def test_non_tuple_receipts_raise_type_error(self):
        bundle = _bundle()
        for bad in (list(bundle.receipts), None, "receipts", 1):
            with self.assertRaises(TypeError, msg=bad):
                StageAnchoredContinuationChain(bad, bundle.start, bundle.end)

    def test_empty_receipts_raise_value_error(self):
        bundle = _bundle()
        with self.assertRaises(ValueError):
            StageAnchoredContinuationChain((), bundle.start, bundle.end)

    def test_wrong_element_type_raises_type_error(self):
        bundle = _bundle()
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                StageAnchoredContinuationChain(
                    (bad,), bundle.start, bundle.end
                )

    def test_non_signed_root_anchor_raises_type_error(self):
        bundle = _bundle()
        for bad in (None, "anchor", b"\x00" * 32, 1):
            with self.assertRaises(TypeError, msg=bad):
                StageAnchoredContinuationChain(
                    bundle.receipts, bad, bundle.end
                )
            with self.assertRaises(TypeError, msg=bad):
                StageAnchoredContinuationChain(
                    bundle.receipts, bundle.start, bad
                )


class InspectStageAnchorsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_anchored_chain_reports_ok(self):
        bundle = _bundle((0, 2, 5, 8))
        self.assertEqual(
            inspect_stage_anchors(
                bundle.receipts, self.public_key, bundle.start, bundle.end
            ),
            ContinuationChainReport(True, None, None),
        )

    def test_truncated_prefix_reports_start_at_zero(self):
        bundle = _bundle((0, 2, 5, 8))
        self.assertEqual(
            inspect_stage_anchors(
                bundle.receipts[1:],
                self.public_key,
                bundle.start,
                bundle.end,
            ),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_truncated_suffix_reports_end_at_last_segment(self):
        bundle = _bundle((0, 2, 5, 8))
        receipts = bundle.receipts[:-1]
        self.assertEqual(
            inspect_stage_anchors(
                receipts, self.public_key, bundle.start, bundle.end
            ),
            ContinuationChainReport(False, len(receipts) - 1, "end"),
        )

    def test_start_mismatch_wins_over_end_mismatch(self):
        bundle = _bundle((0, 2, 5))
        other = _bundle((1, 3, 6))
        report = inspect_stage_anchors(
            bundle.receipts, self.public_key, other.start, other.end
        )
        self.assertEqual(report, ContinuationChainReport(False, 0, "start"))

    def test_internal_failure_report_returned_unchanged(self):
        bundle = _bundle((0, 2, 5))
        # An untrusted key fails the internal diagnosis at segment 0; the
        # anchor comparison never runs.
        self.assertEqual(
            inspect_stage_anchors(
                bundle.receipts,
                self.other_public_key,
                bundle.start,
                bundle.end,
            ),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_internal_link_failure_not_relabelled(self):
        first = _chain((0, 5))[0]
        second = _chain((3, 8))[0]
        receipts = (first, second)
        self.assertEqual(
            inspect_stage_anchors(
                receipts,
                self.public_key,
                first.consistency.old,
                second.consistency.new,
            ),
            ContinuationChainReport(False, 1, "link"),
        )

    def test_wrong_anchor_checkpoint_reports_anchor_code(self):
        # Anchor equality is full six-field SignedRoot equality: a
        # checkpoint over a different span — or the same size over a
        # different history — does not match.
        bundle = _bundle((0, 2, 5))
        wrong_start = _log(8).sign_root(_SEED_A, 1)
        wrong_end = _log(5, prefix="other").sign_root(_SEED_A, 5)
        self.assertEqual(
            inspect_stage_anchors(
                bundle.receipts, self.public_key, wrong_start, bundle.end
            ),
            ContinuationChainReport(False, 0, "start"),
        )
        self.assertEqual(
            inspect_stage_anchors(
                bundle.receipts, self.public_key, bundle.start, wrong_end
            ),
            ContinuationChainReport(False, len(bundle.receipts) - 1, "end"),
        )

    def test_non_tuple_raises_type_error(self):
        bundle = _bundle()
        for bad in (list(bundle.receipts), None, "receipts", 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_stage_anchors(
                    bad, self.public_key, bundle.start, bundle.end
                )

    def test_empty_tuple_raises_value_error(self):
        bundle = _bundle()
        with self.assertRaises(ValueError):
            inspect_stage_anchors(
                (), self.public_key, bundle.start, bundle.end
            )

    def test_wrong_element_type_raises_type_error(self):
        bundle = _bundle()
        with self.assertRaises(TypeError):
            inspect_stage_anchors(
                (b"bytes",), self.public_key, bundle.start, bundle.end
            )

    def test_public_key_type_raises_type_error(self):
        bundle = _bundle()
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_stage_anchors(
                    bundle.receipts, bad, bundle.start, bundle.end
                )

    def test_public_key_length_raises_value_error(self):
        bundle = _bundle()
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=bad):
                inspect_stage_anchors(
                    bundle.receipts, bad, bundle.start, bundle.end
                )

    def test_non_signed_root_anchor_raises_type_error(self):
        bundle = _bundle()
        for bad in (None, "anchor", b"\x00" * 32):
            with self.assertRaises(TypeError, msg=bad):
                inspect_stage_anchors(
                    bundle.receipts, self.public_key, bad, bundle.end
                )
            with self.assertRaises(TypeError, msg=bad):
                inspect_stage_anchors(
                    bundle.receipts, self.public_key, bundle.start, bad
                )


class EncodeStageAnchoredContinuationsTest(unittest.TestCase):
    def test_wire_format(self):
        bundle = _bundle((0, 2, 5))
        data = encode_stage_anchored_continuations(bundle)
        chain_blob = encode_stage_continuations(bundle.receipts)
        start_blob = encode_signed_root(bundle.start)
        end_blob = encode_signed_root(bundle.end)
        self.assertEqual(
            data,
            _MAGIC
            + _u64(1)
            + _blob(chain_blob)
            + _blob(start_blob)
            + _blob(end_blob),
        )

    def test_non_bundle_raises_type_error(self):
        bundle = _bundle()
        for bad in (
            bundle.receipts,
            (bundle.receipts, bundle.start, bundle.end),
            None,
            "bundle",
            1,
        ):
            with self.assertRaises(TypeError, msg=bad):
                encode_stage_anchored_continuations(bad)

    def test_encoding_is_deterministic_and_read_only(self):
        bundle = _bundle((0, 2, 5, 8))
        first = encode_stage_anchored_continuations(bundle)
        second = encode_stage_anchored_continuations(bundle)
        self.assertEqual(first, second)
        self.assertEqual(
            bundle,
            StageAnchoredContinuationChain(
                bundle.receipts, bundle.start, bundle.end
            ),
        )


class DecodeStageAnchoredContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.bundle = _bundle((0, 2, 5, 8))
        self.data = encode_stage_anchored_continuations(self.bundle)

    def test_round_trip_preserves_fields(self):
        restored = decode_stage_anchored_continuations(self.data)
        self.assertIsInstance(restored, StageAnchoredContinuationChain)
        self.assertEqual(restored, self.bundle)
        self.assertEqual(
            (restored.receipts, restored.start, restored.end),
            (self.bundle.receipts, self.bundle.start, self.bundle.end),
        )

    def test_reencoding_reproduces_original_bytes(self):
        restored = decode_stage_anchored_continuations(self.data)
        self.assertEqual(
            encode_stage_anchored_continuations(restored), self.data
        )
        self.assertEqual(
            decode_stage_anchored_continuations(
                encode_stage_anchored_continuations(restored)
            ),
            restored,
        )

    def test_decoded_chain_still_verifies_and_anchors(self):
        restored = decode_stage_anchored_continuations(self.data)
        self.assertTrue(
            verify_stage_continuation_chain(
                restored.receipts, self.public_key
            )
        )
        self.assertEqual(
            inspect_stage_anchors(
                restored.receipts,
                self.public_key,
                restored.start,
                restored.end,
            ),
            ContinuationChainReport(True, None, None),
        )

    def test_non_bytes_raises_type_error(self):
        for bad in (bytearray(self.data), memoryview(self.data), None, 1, ""):
            with self.assertRaises(TypeError, msg=bad):
                decode_stage_anchored_continuations(bad)

    def test_bad_magic_raises_value_error(self):
        bad = b"x" + self.data[1:]
        with self.assertRaises(ValueError):
            decode_stage_anchored_continuations(bad)

    def test_unsupported_version_raises_value_error(self):
        offset = len(_MAGIC)
        bad = self.data[:offset] + _u64(2) + self.data[offset + 8:]
        with self.assertRaises(ValueError):
            decode_stage_anchored_continuations(bad)

    def test_truncated_raises_value_error(self):
        for cut in (1, 8, 16, 24, len(self.data) // 2, len(self.data) - 1):
            with self.assertRaises(ValueError, msg=cut):
                decode_stage_anchored_continuations(self.data[:cut])

    def test_trailing_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            decode_stage_anchored_continuations(self.data + b"\x00")

    def test_blob_length_overflow_raises_value_error(self):
        offset = len(_MAGIC) + 8
        bad = self.data[:offset] + _u64(1 << 40) + self.data[offset + 8:]
        with self.assertRaises(ValueError):
            decode_stage_anchored_continuations(bad)

    def test_nested_chain_format_error_propagates(self):
        chain_blob = bytearray(encode_stage_continuations(self.bundle.receipts))
        chain_blob[0] ^= 0xFF  # break the nested chain magic
        bad = (
            _MAGIC
            + _u64(1)
            + _blob(bytes(chain_blob))
            + _blob(encode_signed_root(self.bundle.start))
            + _blob(encode_signed_root(self.bundle.end))
        )
        with self.assertRaises(ValueError):
            decode_stage_anchored_continuations(bad)

    def test_nested_anchor_format_error_propagates(self):
        anchor_blob = bytearray(encode_signed_root(self.bundle.end))
        anchor_blob[0] ^= 0xFF  # break the nested signed-root magic
        bad = (
            _MAGIC
            + _u64(1)
            + _blob(encode_stage_continuations(self.bundle.receipts))
            + _blob(encode_signed_root(self.bundle.start))
            + _blob(bytes(anchor_blob))
        )
        with self.assertRaises(ValueError):
            decode_stage_anchored_continuations(bad)

    def test_structurally_valid_but_unverifiable_round_trips(self):
        # A receipt whose nested signature bytes were replaced still encodes
        # and decodes; only the diagnosis reports the mismatch.
        receipt = self.bundle.receipts[0]
        old = receipt.consistency.old
        forged_old = type(old)(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        forged = SignedStageAuthAuditContinuation(
            receipt.bundle,
            SignedConsistency(
                forged_old,
                receipt.consistency.new,
                receipt.consistency.proof,
            ),
        )
        bundle = StageAnchoredContinuationChain(
            (forged,), self.bundle.start, self.bundle.end
        )
        data = encode_stage_anchored_continuations(bundle)
        restored = decode_stage_anchored_continuations(data)
        self.assertEqual(restored, bundle)
        report = inspect_stage_anchors(
            restored.receipts, self.public_key, restored.start, restored.end
        )
        self.assertFalse(report.ok)


if __name__ == "__main__":
    unittest.main()
