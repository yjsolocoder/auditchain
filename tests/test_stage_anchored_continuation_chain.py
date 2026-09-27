import unittest

from auditchain import (
    AuditLog,
    ContinuationChainReport,
    SignedConsistency,
    SignedRoot,
    SignedStageAuthAuditContinuation,
    StageAnchoredContinuationChain,
    decode_stage_anchored_continuations,
    decode_stage_continuations,
    encode_signed_root,
    encode_signed_stage_auth_audit_continuation,
    encode_stage_anchored_continuations,
    encode_stage_continuations,
    inspect_stage_anchors,
    inspect_stage_continuation_chain,
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
                receipts=bundle.receipts,
                start=bundle.start,
                end=bundle.end,
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
                StageAnchoredContinuationChain(
                    bad, bundle.start, bundle.end
                )

    def test_empty_tuple_raises_value_error(self):
        bundle = _bundle()
        with self.assertRaises(ValueError):
            StageAnchoredContinuationChain(
                (), bundle.start, bundle.end
            )

    def test_wrong_element_type_raises_type_error(self):
        bundle = _bundle()
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                StageAnchoredContinuationChain(
                    (bad,), bundle.start, bundle.end
                )
            with self.assertRaises(TypeError, msg=bad):
                StageAnchoredContinuationChain(
                    (bundle.receipts[0], bad), bundle.start, bundle.end
                )

    def test_non_stage_receipt_raises_type_error(self):
        # A plain SignedRoot or bytes in place of a stage receipt is rejected.
        bundle = _bundle()
        with self.assertRaises(TypeError):
            StageAnchoredContinuationChain(
                (bundle.start,), bundle.start, bundle.end
            )

    def test_non_signed_root_anchors_raise_type_error(self):
        bundle = _bundle()
        for bad in (b"bytes", "anchor", None, 1, (bundle.start,), object()):
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

    def test_success_report_shape(self):
        receipts = _chain((0, 2, 5))
        start = receipts[0].consistency.old
        end = receipts[-1].consistency.new
        report = inspect_stage_anchors(
            receipts, self.public_key, start, end
        )
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertEqual(report, ContinuationChainReport(True, None, None))

    def test_multi_segment_chain_reports_ok(self):
        receipts = _chain((0, 2, 5, 8))
        self.assertEqual(
            inspect_stage_anchors(
                receipts,
                self.public_key,
                receipts[0].consistency.old,
                receipts[-1].consistency.new,
            ),
            ContinuationChainReport(True, None, None),
        )

    def test_single_segment_reports_ok(self):
        receipts = _chain((2, 5))
        self.assertEqual(
            inspect_stage_anchors(
                receipts,
                self.public_key,
                receipts[0].consistency.old,
                receipts[0].consistency.new,
            ),
            ContinuationChainReport(True, None, None),
        )

    def test_start_mismatch_reports_start_at_zero(self):
        receipts = _chain((0, 2, 5, 8))
        start = receipts[1].consistency.old
        self.assertEqual(
            inspect_stage_anchors(
                receipts,
                self.public_key,
                start,
                receipts[-1].consistency.new,
            ),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_end_mismatch_reports_end_at_last_segment(self):
        receipts = _chain((0, 2, 5, 8))
        truncated = receipts[:-1]
        self.assertEqual(
            inspect_stage_anchors(
                truncated,
                self.public_key,
                receipts[0].consistency.old,
                receipts[-1].consistency.new,
            ),
            ContinuationChainReport(False, len(truncated) - 1, "end"),
        )

    def test_start_mismatch_takes_precedence_over_end(self):
        receipts = _chain((0, 2, 5, 8))
        middle = _chain((2, 5))
        # Both endpoints mismatch: the "start" failure must win.
        self.assertEqual(
            inspect_stage_anchors(
                middle,
                self.public_key,
                receipts[0].consistency.old,
                receipts[-1].consistency.new,
            ),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_anchor_compares_all_six_fields(self):
        receipts = _chain((0, 2, 5))
        end = receipts[-1].consistency.new
        forged_signature = SignedRoot(
            end.version,
            end.hash_name,
            end.size,
            end.root,
            end.head,
            b"\x00" * 64,
        )
        self.assertEqual(
            inspect_stage_anchors(
                receipts,
                self.public_key,
                receipts[0].consistency.old,
                forged_signature,
            ),
            ContinuationChainReport(False, len(receipts) - 1, "end"),
        )

    def test_internal_failure_codes_pass_through(self):
        receipts = _chain((0, 2, 5))
        start = receipts[0].consistency.old
        end = receipts[-1].consistency.new
        # An untrusted key fails internal verification at index 0 even when
        # both anchors match exactly.
        self.assertEqual(
            inspect_stage_anchors(
                receipts, self.other_public_key, start, end
            ),
            ContinuationChainReport(False, 0, "verify"),
        )
        receipt = _chain((2, 5))[0]
        self.assertEqual(
            inspect_stage_anchors(
                (receipt, receipt),
                self.public_key,
                receipt.consistency.old,
                receipt.consistency.new,
            ),
            ContinuationChainReport(False, 1, "duplicate"),
        )
        first = _chain((0, 5))[0]
        second = _chain((3, 8))[0]
        self.assertEqual(
            inspect_stage_anchors(
                (first, second),
                self.public_key,
                first.consistency.old,
                second.consistency.new,
            ),
            ContinuationChainReport(False, 1, "link"),
        )

    def test_agrees_with_internal_inspection(self):
        receipts = _chain((0, 2, 5, 8))
        start = receipts[0].consistency.old
        end = receipts[-1].consistency.new
        for key in (self.public_key, self.other_public_key):
            self.assertEqual(
                inspect_stage_anchors(receipts, key, start, end),
                inspect_stage_continuation_chain(receipts, key),
            )

    def test_non_tuple_raises_type_error(self):
        receipts = _chain((2, 5))
        start = receipts[0].consistency.old
        end = receipts[0].consistency.new
        for bad in (list(receipts), None, receipts[0], "receipts", 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_stage_anchors(bad, self.public_key, start, end)

    def test_generator_raises_type_error(self):
        gen = (r for r in _chain((2, 5)))
        receipts = _chain((2, 5))
        with self.assertRaises(TypeError):
            inspect_stage_anchors(
                gen,
                self.public_key,
                receipts[0].consistency.old,
                receipts[0].consistency.new,
            )

    def test_wrong_element_type_raises_type_error(self):
        bundle = _bundle()
        with self.assertRaises(TypeError):
            inspect_stage_anchors(
                (b"bytes",), self.public_key, bundle.start, bundle.end
            )

    def test_public_key_type_raises_type_error(self):
        receipts = _chain((2, 5))
        start = receipts[0].consistency.old
        end = receipts[0].consistency.new
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_stage_anchors(receipts, bad, start, end)

    def test_public_key_length_raises_value_error(self):
        receipts = _chain((2, 5))
        start = receipts[0].consistency.old
        end = receipts[0].consistency.new
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_stage_anchors(receipts, bad, start, end)

    def test_anchor_type_raises_type_error(self):
        receipts = _chain((2, 5))
        end = receipts[0].consistency.new
        for bad in (b"bytes", "anchor", None, 1, (end,), object()):
            with self.assertRaises(TypeError, msg=bad):
                inspect_stage_anchors(
                    receipts, self.public_key, bad, end
                )
            with self.assertRaises(TypeError, msg=bad):
                inspect_stage_anchors(
                    receipts,
                    self.public_key,
                    receipts[0].consistency.old,
                    bad,
                )

    def test_empty_tuple_raises_value_error(self):
        bundle = _bundle()
        with self.assertRaises(ValueError):
            inspect_stage_anchors(
                (), self.public_key, bundle.start, bundle.end
            )

    def test_call_is_read_only(self):
        receipts = _chain((0, 2, 5))
        before = tuple(
            encode_signed_stage_auth_audit_continuation(r) for r in receipts
        )
        inspect_stage_anchors(
            receipts,
            self.public_key,
            receipts[0].consistency.old,
            receipts[-1].consistency.new,
        )
        after = tuple(
            encode_signed_stage_auth_audit_continuation(r) for r in receipts
        )
        self.assertEqual(after, before)


class EncodeStageAnchoredContinuationsTest(unittest.TestCase):
    def test_canonical_stream_layout(self):
        bundle = _bundle((0, 2, 5, 8))
        expected = b"".join((
            _MAGIC,
            _u64(1),
            _blob(encode_stage_continuations(bundle.receipts)),
            _blob(encode_signed_root(bundle.start)),
            _blob(encode_signed_root(bundle.end)),
        ))
        self.assertEqual(
            encode_stage_anchored_continuations(bundle), expected
        )

    def test_magic_version_and_three_blobs_only(self):
        bundle = _bundle((2, 5))
        data = encode_stage_anchored_continuations(bundle)
        self.assertTrue(data.startswith(_MAGIC))
        self.assertEqual(
            data[len(_MAGIC):len(_MAGIC) + 8], _u64(1)
        )
        cursor = len(_MAGIC) + 8
        chain_blob = encode_stage_continuations(bundle.receipts)
        for material in (
            chain_blob,
            encode_signed_root(bundle.start),
            encode_signed_root(bundle.end),
        ):
            length = int.from_bytes(data[cursor:cursor + 8], "big")
            self.assertEqual(length, len(material))
            self.assertEqual(
                data[cursor + 8:cursor + 8 + length], material
            )
            cursor += 8 + length
        self.assertEqual(cursor, len(data))

    def test_chain_blob_equals_encode_stage_continuations_output(self):
        bundle = _bundle()
        data = encode_stage_anchored_continuations(bundle)
        offset = len(_MAGIC) + 8
        length = int.from_bytes(data[offset:offset + 8], "big")
        blob = data[offset + 8:offset + 8 + length]
        self.assertEqual(blob, encode_stage_continuations(bundle.receipts))
        self.assertEqual(decode_stage_continuations(blob), bundle.receipts)

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
                encode_stage_anchored_continuations(bad)

    def test_deterministic(self):
        bundle = _bundle((0, 4, 8))
        self.assertEqual(
            encode_stage_anchored_continuations(bundle),
            encode_stage_anchored_continuations(bundle),
        )

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
            encode_stage_anchored_continuations(bundle)

    def test_call_is_read_only(self):
        bundle = _bundle()
        before = tuple(
            encode_signed_stage_auth_audit_continuation(r)
            for r in bundle.receipts
        )
        start_bytes = encode_signed_root(bundle.start)
        encode_stage_anchored_continuations(bundle)
        self.assertEqual(
            tuple(
                encode_signed_stage_auth_audit_continuation(r)
                for r in bundle.receipts
            ),
            before,
        )
        self.assertEqual(encode_signed_root(bundle.start), start_bytes)


class DecodeStageAnchoredContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.bundle = _bundle((0, 2, 5))
        self.data = encode_stage_anchored_continuations(self.bundle)

    def test_round_trip_restores_equal_bundle(self):
        bundle = _bundle((0, 2, 5, 8))
        data = encode_stage_anchored_continuations(bundle)
        restored = decode_stage_anchored_continuations(data)
        self.assertIsInstance(restored, StageAnchoredContinuationChain)
        self.assertEqual(restored, bundle)
        self.assertEqual(
            encode_stage_anchored_continuations(restored), data
        )

    def test_single_segment_round_trip(self):
        bundle = _bundle((2, 5))
        self.assertEqual(
            decode_stage_anchored_continuations(
                encode_stage_anchored_continuations(bundle)
            ),
            bundle,
        )

    def test_re_encode_is_byte_identical(self):
        restored = decode_stage_anchored_continuations(self.data)
        self.assertEqual(
            encode_stage_anchored_continuations(restored), self.data
        )

    def test_non_bytes_raises_type_error(self):
        for bad in (
            bytearray(self.data),
            memoryview(self.data),
            "data",
            None,
            1,
        ):
            with self.assertRaises(TypeError, msg=bad):
                decode_stage_anchored_continuations(bad)

    def test_bad_magic_raises_value_error(self):
        for bad in (
            b"",
            b"auditchain/stage-anchor/v2\0" + self.data[len(_MAGIC):],
            b"\x00" + self.data[1:],
        ):
            with self.assertRaises(ValueError, msg=bad[:8]):
                decode_stage_anchored_continuations(bad)

    def test_bad_version_raises_value_error(self):
        for version in (0, 2, (1 << 64) - 1):
            broken = (
                _MAGIC + _u64(version) + self.data[len(_MAGIC) + 8:]
            )
            with self.assertRaises(ValueError, msg=version):
                decode_stage_anchored_continuations(broken)

    def test_truncation_raises_value_error(self):
        for cut in (
            len(_MAGIC),
            len(_MAGIC) + 4,
            len(_MAGIC) + 8,
            len(self.data) - 1,
            len(self.data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_stage_anchored_continuations(self.data[:cut])

    def test_trailing_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            decode_stage_anchored_continuations(self.data + b"\x00")

    def test_oversized_blob_length_raises_value_error(self):
        broken = (
            _MAGIC
            + _u64(1)
            + _u64(len(self.data))
            + self.data[len(_MAGIC) + 16:]
        )
        with self.assertRaises(ValueError):
            decode_stage_anchored_continuations(broken)

    def test_missing_third_blob_raises_value_error(self):
        # Magic, version and only the chain blob: truncated before anchors.
        broken = (
            _MAGIC
            + _u64(1)
            + _blob(encode_stage_continuations(self.bundle.receipts))
        )
        with self.assertRaises(ValueError):
            decode_stage_anchored_continuations(broken)

    def test_nested_chain_exception_propagates(self):
        data = b"".join((
            _MAGIC,
            _u64(1),
            _blob(b"not a stage continuation chain"),
            _blob(encode_signed_root(self.bundle.start)),
            _blob(encode_signed_root(self.bundle.end)),
        ))
        with self.assertRaises(ValueError):
            decode_stage_anchored_continuations(data)

    def test_nested_anchor_exception_propagates(self):
        for position in ("start", "end"):
            anchors = {
                "start": encode_signed_root(self.bundle.start),
                "end": encode_signed_root(self.bundle.end),
            }
            anchors[position] = b"not a signed root"
            data = b"".join((
                _MAGIC,
                _u64(1),
                _blob(encode_stage_continuations(self.bundle.receipts)),
                _blob(anchors["start"]),
                _blob(anchors["end"]),
            ))
            with self.assertRaises(ValueError, msg=position):
                decode_stage_anchored_continuations(data)

    def test_structurally_valid_but_unverifiable_round_trips(self):
        # A receipt whose nested old checkpoint signature bytes were
        # replaced still encodes and decodes; only verification reports
        # False and the anchor diagnosis says so.
        receipt = self.bundle.receipts[0]
        old = receipt.consistency.old
        forged_old = SignedRoot(
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
            (forged,), forged_old, receipt.consistency.new
        )
        data = encode_stage_anchored_continuations(bundle)
        restored = decode_stage_anchored_continuations(data)
        self.assertEqual(restored, bundle)
        self.assertFalse(
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
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_decoded_bundle_diagnoses_ok(self):
        restored = decode_stage_anchored_continuations(self.data)
        self.assertEqual(
            inspect_stage_anchors(
                restored.receipts,
                self.public_key,
                restored.start,
                restored.end,
            ),
            ContinuationChainReport(True, None, None),
        )


if __name__ == "__main__":
    unittest.main()
