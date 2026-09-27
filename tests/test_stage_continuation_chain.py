import unittest

from auditchain import (
    AuditLog,
    ContinuationChainReport,
    SignedConsistency,
    SignedStageAuthAuditContinuation,
    decode_stage_continuations,
    encode_signed_stage_auth_audit_continuation,
    encode_stage_continuations,
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
_MAGIC = b"auditchain/stage-cont-chain/v1\0"


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


class VerifyStageContinuationChainTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_single_growing_segment_verifies(self):
        receipts = _chain((2, 5))
        self.assertEqual(len(receipts), 1)
        self.assertTrue(
            verify_stage_continuation_chain(receipts, self.public_key)
        )

    def test_continuous_multi_segment_chain_verifies(self):
        receipts = _chain((0, 2, 5, 8))
        self.assertTrue(
            verify_stage_continuation_chain(receipts, self.public_key)
        )

    def test_untrusted_key_returns_false(self):
        receipts = _chain((0, 2, 5))
        self.assertFalse(
            verify_stage_continuation_chain(receipts, self.other_public_key)
        )

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_stage_continuation_chain((), self.public_key)

    def test_non_tuple_raises_type_error(self):
        receipt = _chain((2, 5))[0]
        for bad in ([receipt], {receipt}, None, receipt, "receipts", 1):
            with self.assertRaises(TypeError, msg=bad):
                verify_stage_continuation_chain(bad, self.public_key)

    def test_generator_raises_type_error(self):
        gen = (r for r in _chain((2, 5)))
        with self.assertRaises(TypeError):
            verify_stage_continuation_chain(gen, self.public_key)

    def test_wrong_element_type_raises_type_error(self):
        receipt = _chain((2, 5))[0]
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                verify_stage_continuation_chain((bad,), self.public_key)
            with self.assertRaises(TypeError, msg=bad):
                verify_stage_continuation_chain(
                    (receipt, bad), self.public_key
                )

    def test_zero_length_segment_returns_false(self):
        # old.size == new.size never describes an append.
        equal = _log(5).signed_stage_auth_audit_continuation(
            3, (), _SEED_A, size=3
        )
        self.assertFalse(
            verify_stage_continuation_chain((equal,), self.public_key)
        )

    def test_adjacent_mismatch_returns_false(self):
        # First segment ends at size 5, second starts at size 3: genuine
        # receipts individually, but they do not join.
        first = _chain((0, 5))[0]
        second = _chain((3, 8))[0]
        self.assertFalse(
            verify_stage_continuation_chain(
                (first, second), self.public_key
            )
        )

    def test_same_boundary_but_different_history_returns_false(self):
        # Matching sizes at the join but different payloads, so the new
        # checkpoint of the first differs from the old of the second.
        first = _log(8, prefix="record").signed_stage_auth_audit_continuation(
            0, (), _SEED_A, size=4
        )
        second = _log(8, prefix="other").signed_stage_auth_audit_continuation(
            4, (), _SEED_A, size=8
        )
        self.assertFalse(
            verify_stage_continuation_chain(
                (first, second), self.public_key
            )
        )

    def test_duplicate_segment_returns_false(self):
        receipt = _chain((2, 5))[0]
        self.assertFalse(
            verify_stage_continuation_chain(
                (receipt, receipt), self.public_key
            )
        )

    def test_duplicate_non_adjacent_segment_returns_false(self):
        first = _chain((0, 3))[0]
        middle = _chain((3, 6))[0]
        # A fresh receipt equal to `first` (identical log content/key).
        again = _chain((0, 3))[0]
        self.assertEqual(first, again)
        self.assertFalse(
            verify_stage_continuation_chain(
                (first, middle, again), self.public_key
            )
        )

    def test_tampered_segment_returns_false(self):
        receipts = list(_chain((0, 2, 5)))
        old = receipts[1].consistency.old
        forged_old = type(old)(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        forged_consistency = SignedConsistency(
            forged_old,
            receipts[1].consistency.new,
            receipts[1].consistency.proof,
        )
        receipts[1] = SignedStageAuthAuditContinuation(
            receipts[1].bundle, forged_consistency
        )
        self.assertFalse(
            verify_stage_continuation_chain(tuple(receipts), self.public_key)
        )

    def test_one_bad_segment_breaks_whole_chain(self):
        first = _chain((0, 4))[0]
        bad = _chain((2, 6), seed=_SEED_B)[0]
        self.assertFalse(
            verify_stage_continuation_chain(
                (first, bad), self.public_key
            )
        )

    def test_public_key_length_raises_value_error(self):
        receipts = _chain((2, 5))
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                verify_stage_continuation_chain(receipts, bad)

    def test_public_key_type_raises_type_error(self):
        receipts = _chain((2, 5))
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError):
                verify_stage_continuation_chain(receipts, bad)

    def test_call_is_read_only(self):
        receipts = _chain((0, 2, 5))
        before = tuple(
            encode_signed_stage_auth_audit_continuation(r) for r in receipts
        )
        verify_stage_continuation_chain(receipts, self.public_key)
        after = tuple(
            encode_signed_stage_auth_audit_continuation(r) for r in receipts
        )
        self.assertEqual(after, before)


class InspectStageContinuationChainTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_success_report_shape(self):
        report = inspect_stage_continuation_chain(
            _chain((2, 5)), self.public_key
        )
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertEqual(report, ContinuationChainReport(True, None, None))
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)

    def test_multi_segment_chain_reports_ok(self):
        receipts = _chain((0, 2, 5, 8))
        self.assertEqual(
            inspect_stage_continuation_chain(receipts, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_untrusted_key_reports_verify_at_zero(self):
        receipts = _chain((0, 2, 5))
        self.assertEqual(
            inspect_stage_continuation_chain(receipts, self.other_public_key),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_one_bad_segment_reports_verify_at_its_index(self):
        first = _chain((0, 4))[0]
        bad = _chain((2, 6), seed=_SEED_B)[0]
        self.assertEqual(
            inspect_stage_continuation_chain((first, bad), self.public_key),
            ContinuationChainReport(False, 1, "verify"),
        )

    def test_zero_length_segment_reports_growth(self):
        equal = _log(5).signed_stage_auth_audit_continuation(
            3, (), _SEED_A, size=3
        )
        self.assertEqual(
            inspect_stage_continuation_chain((equal,), self.public_key),
            ContinuationChainReport(False, 0, "growth"),
        )

    def test_duplicate_reports_duplicate_at_second_position(self):
        receipt = _chain((2, 5))[0]
        self.assertEqual(
            inspect_stage_continuation_chain(
                (receipt, receipt), self.public_key
            ),
            ContinuationChainReport(False, 1, "duplicate"),
        )

    def test_broken_join_reports_link_at_following_segment(self):
        first = _chain((0, 5))[0]
        second = _chain((3, 8))[0]
        self.assertEqual(
            inspect_stage_continuation_chain(
                (first, second), self.public_key
            ),
            ContinuationChainReport(False, 1, "link"),
        )

    def test_earliest_problem_wins(self):
        # The verify failure at index 0 hides the broken join at index 1.
        bad = _chain((0, 4), seed=_SEED_B)[0]
        second = _chain((3, 8))[0]
        self.assertEqual(
            inspect_stage_continuation_chain((bad, second), self.public_key),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            inspect_stage_continuation_chain((), self.public_key)

    def test_non_tuple_raises_type_error(self):
        receipt = _chain((2, 5))[0]
        for bad in ([receipt], None, receipt, "receipts"):
            with self.assertRaises(TypeError, msg=bad):
                inspect_stage_continuation_chain(bad, self.public_key)

    def test_wrong_element_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            inspect_stage_continuation_chain((b"bytes",), self.public_key)

    def test_public_key_type_raises_type_error(self):
        receipts = _chain((2, 5))
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError):
                inspect_stage_continuation_chain(receipts, bad)

    def test_public_key_length_raises_value_error(self):
        receipts = _chain((2, 5))
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                inspect_stage_continuation_chain(receipts, bad)

    def test_report_agrees_with_bool_verifier(self):
        receipts = _chain((0, 2, 5, 8))
        self.assertTrue(
            verify_stage_continuation_chain(receipts, self.public_key)
        )
        self.assertEqual(
            inspect_stage_continuation_chain(receipts, self.public_key),
            ContinuationChainReport(True, None, None),
        )
        self.assertFalse(
            verify_stage_continuation_chain(receipts, self.other_public_key)
        )
        self.assertFalse(
            inspect_stage_continuation_chain(
                receipts, self.other_public_key
            ).ok
        )


class EncodeStageContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_round_trip_preserves_order_and_elements(self):
        receipts = _chain((0, 2, 5, 8))
        data = encode_stage_continuations(receipts)
        restored = decode_stage_continuations(data)
        self.assertIsInstance(restored, tuple)
        self.assertEqual(restored, receipts)
        self.assertEqual(encode_stage_continuations(restored), data)

    def test_single_receipt_round_trip(self):
        receipts = _chain((1, 4))
        data = encode_stage_continuations(receipts)
        self.assertEqual(decode_stage_continuations(data), receipts)

    def test_wire_format(self):
        receipts = _chain((2, 5))
        data = encode_stage_continuations(receipts)
        self.assertTrue(data.startswith(_MAGIC))
        self.assertEqual(
            data[len(_MAGIC):len(_MAGIC) + 8], (1).to_bytes(8, "big")
        )
        self.assertEqual(
            data[len(_MAGIC) + 8:len(_MAGIC) + 16], (1).to_bytes(8, "big")
        )
        nested = encode_signed_stage_auth_audit_continuation(receipts[0])
        self.assertEqual(
            data[len(_MAGIC) + 16:len(_MAGIC) + 24],
            len(nested).to_bytes(8, "big"),
        )
        self.assertEqual(data[len(_MAGIC) + 24:], nested)
        self.assertEqual(len(data), len(_MAGIC) + 24 + len(nested))

    def test_wire_format_multi_count_and_blob_order(self):
        receipts = _chain((0, 3, 6))
        data = encode_stage_continuations(receipts)
        offset = len(_MAGIC)
        self.assertEqual(
            int.from_bytes(data[offset + 8:offset + 16], "big"), 2
        )
        blobs = tuple(
            encode_signed_stage_auth_audit_continuation(r) for r in receipts
        )
        cursor = offset + 16
        for blob in blobs:
            length = int.from_bytes(data[cursor:cursor + 8], "big")
            self.assertEqual(length, len(blob))
            self.assertEqual(data[cursor + 8:cursor + 8 + length], blob)
            cursor += 8 + length
        self.assertEqual(cursor, len(data))

    def test_non_tuple_raises_type_error(self):
        receipt = _chain((2, 5))[0]
        for bad in ([receipt], {receipt}, None, receipt, "x"):
            with self.assertRaises(TypeError, msg=bad):
                encode_stage_continuations(bad)

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            encode_stage_continuations(())

    def test_wrong_element_type_raises_type_error(self):
        receipt = _chain((2, 5))[0]
        with self.assertRaises(TypeError):
            encode_stage_continuations((b"bytes",))
        with self.assertRaises(TypeError):
            encode_stage_continuations((receipt, None))

    def test_encoding_is_deterministic(self):
        receipts = _chain((0, 4, 8))
        self.assertEqual(
            encode_stage_continuations(receipts),
            encode_stage_continuations(receipts),
        )


class DecodeStageContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.receipts = _chain((0, 2, 5))
        self.data = encode_stage_continuations(self.receipts)

    def test_non_bytes_raises_type_error(self):
        for bad in (bytearray(self.data), memoryview(self.data), None, 1, ""):
            with self.assertRaises(TypeError, msg=bad):
                decode_stage_continuations(bad)

    def test_bad_magic_raises_value_error(self):
        bad = b"x" + self.data[1:]
        with self.assertRaises(ValueError):
            decode_stage_continuations(bad)

    def test_unsupported_version_raises_value_error(self):
        offset = len(_MAGIC)
        bad = (
            self.data[:offset]
            + (2).to_bytes(8, "big")
            + self.data[offset + 8:]
        )
        with self.assertRaises(ValueError):
            decode_stage_continuations(bad)

    def test_zero_count_raises_value_error(self):
        bad = _MAGIC + (1).to_bytes(8, "big") + (0).to_bytes(8, "big")
        with self.assertRaises(ValueError):
            decode_stage_continuations(bad)

    def test_truncated_header_raises_value_error(self):
        for cut in (1, 8, 16, 20):
            with self.assertRaises(ValueError, msg=cut):
                decode_stage_continuations(self.data[:cut])

    def test_truncated_blob_raises_value_error(self):
        with self.assertRaises(ValueError):
            decode_stage_continuations(self.data[:-1])
        with self.assertRaises(ValueError):
            decode_stage_continuations(self.data[: len(self.data) // 2])

    def test_blob_length_overflow_raises_value_error(self):
        offset = len(_MAGIC) + 16
        bad = (
            self.data[:offset]
            + (1 << 40).to_bytes(8, "big")
            + self.data[offset + 8:]
        )
        with self.assertRaises(ValueError):
            decode_stage_continuations(bad)

    def test_trailing_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            decode_stage_continuations(self.data + b"\x00")

    def test_declared_count_exceeds_blobs_raises_value_error(self):
        bad = (
            _MAGIC
            + (1).to_bytes(8, "big")
            + (9).to_bytes(8, "big")
            + self.data[len(_MAGIC) + 16:]
        )
        with self.assertRaises(ValueError):
            decode_stage_continuations(bad)

    def test_nested_format_error_propagates(self):
        nested = bytearray(
            encode_signed_stage_auth_audit_continuation(self.receipts[0])
        )
        nested[-1] ^= 0xFF
        bad = (
            _MAGIC
            + (1).to_bytes(8, "big")
            + (1).to_bytes(8, "big")
            + len(nested).to_bytes(8, "big")
            + bytes(nested)
        )
        with self.assertRaises(ValueError):
            decode_stage_continuations(bad)

    def test_nested_decoder_sees_whole_blob(self):
        restored = decode_stage_continuations(self.data)
        self.assertEqual(len(restored), 2)
        self.assertEqual(
            tuple(
                encode_signed_stage_auth_audit_continuation(r)
                for r in restored
            ),
            tuple(
                encode_signed_stage_auth_audit_continuation(r)
                for r in self.receipts
            ),
        )

    def test_structurally_valid_but_unverifiable_round_trips(self):
        # A receipt whose nested signature bytes were replaced still
        # encodes and decodes; only verification reports False.
        receipt = self.receipts[0]
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
        data = encode_stage_continuations((forged,))
        restored = decode_stage_continuations(data)
        self.assertEqual(restored, (forged,))
        self.assertFalse(
            verify_stage_continuation_chain(restored, self.public_key)
        )

    def test_decoded_chain_verifies(self):
        restored = decode_stage_continuations(self.data)
        self.assertTrue(
            verify_stage_continuation_chain(restored, self.public_key)
        )


if __name__ == "__main__":
    unittest.main()
