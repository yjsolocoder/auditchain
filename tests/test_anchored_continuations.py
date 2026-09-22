import dataclasses
import inspect
import unittest

from auditchain import (
    AnchoredContinuationChain,
    AuditLog,
    ContinuationChainReport,
    SignedAuthAuditContinuation,
    SignedConsistency,
    SignedRoot,
    decode_anchored_continuations,
    decode_continuations,
    encode_anchored_continuations,
    encode_continuations,
    encode_signed_auth_audit_continuation,
    encode_signed_root,
    inspect_anchored_continuations,
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
    return receipts[0].consistency.old, receipts[-1].consistency.new


class AnchoredContinuationChainTest(unittest.TestCase):
    def setUp(self):
        self.receipts = _chain((0, 2, 5))
        self.start, self.end = _anchors(self.receipts)

    def test_is_frozen_dataclass_with_three_fields(self):
        self.assertTrue(dataclasses.is_dataclass(AnchoredContinuationChain))
        bundle = AnchoredContinuationChain(
            self.receipts, self.start, self.end
        )
        self.assertEqual(
            [f.name for f in dataclasses.fields(bundle)],
            ["receipts", "start", "end"],
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            bundle.start = self.end

    def test_positional_and_keyword_construction_agree(self):
        self.assertEqual(
            AnchoredContinuationChain(self.receipts, self.start, self.end),
            AnchoredContinuationChain(
                receipts=self.receipts, start=self.start, end=self.end
            ),
        )

    def test_equality_covers_every_field(self):
        bundle = AnchoredContinuationChain(
            self.receipts, self.start, self.end
        )
        self.assertEqual(
            bundle,
            AnchoredContinuationChain(self.receipts, self.start, self.end),
        )
        self.assertEqual(
            hash(bundle),
            hash(AnchoredContinuationChain(
                self.receipts, self.start, self.end
            )),
        )
        self.assertNotEqual(
            bundle,
            AnchoredContinuationChain(
                self.receipts[1:], self.start, self.end
            ),
        )
        self.assertNotEqual(bundle, (self.receipts, self.start, self.end))

    def test_non_tuple_receipts_raises_type_error(self):
        for bad in ([self.receipts], None, 1, "x"):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(bad, self.start, self.end)

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            AnchoredContinuationChain((), self.start, self.end)

    def test_wrong_element_type_raises_type_error(self):
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain((bad,), self.start, self.end)

    def test_non_signed_root_fields_raise_type_error(self):
        for bad in (b"bytes", None, 1, (self.start,), object()):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(self.receipts, bad, self.end)
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(self.receipts, self.start, bad)


class EncodeAnchoredContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.receipts = _chain((0, 2, 5, 8))
        self.start, self.end = _anchors(self.receipts)
        self.bundle = AnchoredContinuationChain(
            self.receipts, self.start, self.end
        )
        self.data = encode_anchored_continuations(self.bundle)

    def test_wire_format(self):
        data = self.data
        self.assertTrue(data.startswith(_MAGIC))
        offset = len(_MAGIC)
        self.assertEqual(
            int.from_bytes(data[offset:offset + 8], "big"), 1
        )
        offset += 8

        chain = encode_continuations(self.receipts)
        start = encode_signed_root(self.start)
        end = encode_signed_root(self.end)
        for blob in (chain, start, end):
            length = int.from_bytes(data[offset:offset + 8], "big")
            self.assertEqual(length, len(blob))
            offset += 8
            self.assertEqual(data[offset:offset + length], blob)
            offset += length
        self.assertEqual(offset, len(data))

    def test_nested_chain_is_encode_continuations_output(self):
        offset = len(_MAGIC) + 8
        length = int.from_bytes(
            self.data[offset:offset + 8], "big"
        )
        self.assertEqual(length, len(encode_continuations(self.receipts)))

    def test_round_trip(self):
        restored = decode_anchored_continuations(self.data)
        self.assertIsInstance(restored, AnchoredContinuationChain)
        self.assertEqual(restored, self.bundle)
        self.assertEqual(
            encode_anchored_continuations(restored), self.data
        )
        self.assertEqual(type(restored.receipts), tuple)
        self.assertEqual(restored.receipts, self.receipts)

    def test_encoding_is_deterministic(self):
        self.assertEqual(
            encode_anchored_continuations(self.bundle),
            encode_anchored_continuations(self.bundle),
        )

    def test_non_bundle_raises_type_error(self):
        for bad in (None, 1, self.receipts, b"x", object()):
            with self.assertRaises(TypeError, msg=bad):
                encode_anchored_continuations(bad)

    def test_bypassed_field_corruption_raises_type_error(self):
        bundle = AnchoredContinuationChain(
            self.receipts, self.start, self.end
        )
        object.__setattr__(bundle, "start", "not-a-root")
        with self.assertRaises(TypeError):
            encode_anchored_continuations(bundle)

    def test_empty_bypassed_chain_raises_value_error(self):
        bundle = AnchoredContinuationChain(
            self.receipts, self.start, self.end
        )
        object.__setattr__(bundle, "receipts", ())
        with self.assertRaises(ValueError):
            encode_anchored_continuations(bundle)

    def test_call_is_read_only(self):
        before = tuple(
            encode_signed_auth_audit_continuation(r) for r in self.receipts
        )
        encode_anchored_continuations(self.bundle)
        after = tuple(
            encode_signed_auth_audit_continuation(r) for r in self.receipts
        )
        self.assertEqual(after, before)


class DecodeAnchoredContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.receipts = _chain((0, 2, 5))
        self.start, self.end = _anchors(self.receipts)
        self.bundle = AnchoredContinuationChain(
            self.receipts, self.start, self.end
        )
        self.data = encode_anchored_continuations(self.bundle)

    def test_non_bytes_raises_type_error(self):
        for bad in (
            bytearray(self.data),
            memoryview(self.data),
            None,
            1,
            "",
        ):
            with self.assertRaises(TypeError, msg=bad):
                decode_anchored_continuations(bad)

    def test_bad_magic_raises_value_error(self):
        with self.assertRaises(ValueError):
            decode_anchored_continuations(b"x" + self.data[1:])

    def test_unsupported_version_raises_value_error(self):
        offset = len(_MAGIC)
        bad = (
            self.data[:offset]
            + (2).to_bytes(8, "big")
            + self.data[offset + 8:]
        )
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_truncation_raises_value_error(self):
        for cut in (
            len(_MAGIC),
            len(_MAGIC) + 8,
            len(self.data) // 2,
            len(self.data) - 1,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_anchored_continuations(self.data[:cut])

    def test_blob_length_overflow_raises_value_error(self):
        offset = len(_MAGIC) + 8
        bad = (
            self.data[:offset]
            + (1 << 40).to_bytes(8, "big")
            + self.data[offset + 8:]
        )
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_trailing_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            decode_anchored_continuations(self.data + b"\x00")

    def _frame(self, chain, start, end):
        return b"".join((
            _MAGIC,
            (1).to_bytes(8, "big"),
            len(chain).to_bytes(8, "big"),
            chain,
            len(start).to_bytes(8, "big"),
            start,
            len(end).to_bytes(8, "big"),
            end,
        ))

    def test_nested_chain_format_error_propagates(self):
        chain = bytearray(encode_continuations(self.receipts))
        chain[0] ^= 0xFF
        bad = self._frame(
            bytes(chain),
            encode_signed_root(self.start),
            encode_signed_root(self.end),
        )
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_nested_anchor_format_error_propagates(self):
        start = bytearray(encode_signed_root(self.start))
        start[0] ^= 0xFF
        bad = self._frame(
            encode_continuations(self.receipts),
            bytes(start),
            encode_signed_root(self.end),
        )
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_decoded_nested_chain_is_consistent(self):
        restored = decode_anchored_continuations(self.data)
        self.assertEqual(
            encode_continuations(restored.receipts),
            encode_continuations(self.receipts),
        )

    def test_decoded_anchors_are_signed_roots(self):
        restored = decode_anchored_continuations(self.data)
        self.assertIsInstance(restored.start, SignedRoot)
        self.assertIsInstance(restored.end, SignedRoot)
        self.assertEqual(restored.start, self.start)
        self.assertEqual(restored.end, self.end)


class InspectAnchoredContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.receipts = _chain((0, 2, 5, 8))
        self.start, self.end = _anchors(self.receipts)
        self.bundle = AnchoredContinuationChain(
            self.receipts, self.start, self.end
        )

    def test_second_parameter_is_named_key(self):
        self.assertEqual(
            list(inspect.signature(inspect_anchors).parameters),
            ["receipts", "key", "start", "end"],
        )
        self.assertEqual(
            list(
                inspect.signature(
                    inspect_anchored_continuations
                ).parameters
            ),
            ["bundle", "key"],
        )

    def test_success_matches_inspect_anchors(self):
        self.assertEqual(
            inspect_anchored_continuations(self.bundle, self.public_key),
            ContinuationChainReport(True, None, None),
        )
        self.assertEqual(
            inspect_anchored_continuations(self.bundle, self.public_key),
            inspect_anchors(
                self.receipts, self.public_key, self.start, self.end
            ),
        )

    def test_start_mismatch(self):
        bundle = AnchoredContinuationChain(
            self.receipts[1:], self.start, self.end
        )
        self.assertEqual(
            inspect_anchored_continuations(bundle, self.public_key),
            ContinuationChainReport(False, 0, "start"),
        )

    def test_end_mismatch(self):
        bundle = AnchoredContinuationChain(
            self.receipts[:-1], self.start, self.end
        )
        self.assertEqual(
            inspect_anchored_continuations(bundle, self.public_key),
            ContinuationChainReport(False, 1, "end"),
        )

    def test_internal_verify_failure_passes_through(self):
        self.assertEqual(
            inspect_anchored_continuations(
                self.bundle, self.other_public_key
            ),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_internal_failure_masks_anchor_mismatch(self):
        other = _chain((1, 4, 7))
        other_start, other_end = _anchors(other)
        bundle = AnchoredContinuationChain(other, other_start, other_end)
        self.assertEqual(
            inspect_anchored_continuations(
                bundle, self.other_public_key
            ),
            inspect_continuation_chain(other, self.other_public_key),
        )

    def test_non_bundle_raises_type_error(self):
        for bad in (None, 1, self.receipts, b"x", object()):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchored_continuations(bad, self.public_key)

    def test_key_type_raises_type_error(self):
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchored_continuations(self.bundle, bad)

    def test_key_length_raises_value_error(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_anchored_continuations(self.bundle, bad)

    def test_empty_bypassed_chain_raises_value_error(self):
        bundle = AnchoredContinuationChain(
            self.receipts, self.start, self.end
        )
        object.__setattr__(bundle, "receipts", ())
        with self.assertRaises(ValueError):
            inspect_anchored_continuations(bundle, self.public_key)

    def test_nested_structural_violation_propagates(self):
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
        bundle = AnchoredContinuationChain(
            tuple(receipts), self.start, self.end
        )
        with self.assertRaises(TypeError):
            inspect_anchored_continuations(bundle, self.public_key)

    def test_call_is_read_only(self):
        before = tuple(
            encode_signed_auth_audit_continuation(r) for r in self.receipts
        )
        inspect_anchored_continuations(self.bundle, self.public_key)
        after = tuple(
            encode_signed_auth_audit_continuation(r) for r in self.receipts
        )
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
