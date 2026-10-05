import json
import unittest

from auditchain import (
    AuditLog,
    MultiQueryReceipt,
    decode_multi_query_receipt,
    encode_multi_query_receipt,
    encode_signed_json_multi_index,
    verify_multi_query_receipt,
)

from tests.test_signed_json_multi_index import SEED_A, SEED_B, j, public_key

POINTERS = ("/a", "/b", "/z")


def make_log():
    log = AuditLog()
    # 0: integer 1 at /a and string x at /b
    log.append(j({"a": 1, "b": "x"}))
    # 1: float 1.0 at /a (the JSON number 1) and string y at /b
    log.append(j({"a": 1.0, "b": "y"}))
    # 2: boolean true at /a and string x at /b
    log.append(j({"a": True, "b": "x"}))
    # 3: string "1" at /a and string x at /b
    log.append(j({"a": "1", "b": "x"}))
    # 4: a matches the number 1 but /b is missing
    log.append(j({"a": 1, "z": 9}))
    # 5: not JSON
    log.append(b"not json")
    # 6: non-scalar at /a
    log.append(j({"a": [1], "b": "x"}))
    # 7: no queried fields
    log.append(j({"other": 1}))
    return log


def make_bundle():
    return make_log().signed_json_multi_index(POINTERS, SEED_A)


class QueryReceiptBasicsTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()

    def test_returns_immutable_multi_query_receipt(self):
        receipt = self.bundle.query_receipt((("/a", 1), ("/b", "x")))
        self.assertIsInstance(receipt, MultiQueryReceipt)
        self.assertEqual(receipt.bundle, self.bundle)
        self.assertEqual(receipt.conditions, (("/a", 1), ("/b", "x")))
        self.assertEqual((receipt.start, receipt.stop), (0, 8))
        self.assertEqual(receipt.hits, (0,))
        with self.assertRaises(AttributeError):
            receipt.hits = ()

    def test_hits_match_find_all(self):
        conditions = (("/a", 1), ("/b", "x"))
        receipt = self.bundle.query_receipt(conditions, 1, 6)
        self.assertEqual(
            receipt.hits, self.bundle.find_all(conditions, 1, 6)
        )
        self.assertEqual((receipt.start, receipt.stop), (1, 6))

    def test_default_range_covers_retained_segment(self):
        receipt = self.bundle.query_receipt((("/a", True), ("/b", "x")))
        self.assertEqual((receipt.start, receipt.stop), (0, 8))
        self.assertEqual(receipt.hits, (2,))

    def test_empty_conditions_covers_whole_range(self):
        receipt = self.bundle.query_receipt(())
        self.assertEqual(receipt.hits, tuple(range(8)))
        receipt = self.bundle.query_receipt((), 2, 5)
        self.assertEqual(receipt.hits, (2, 3, 4))

    def test_empty_range_and_no_match_yield_empty_hits(self):
        receipt = self.bundle.query_receipt((("/a", 1),), 3, 3)
        self.assertEqual(receipt.hits, ())
        receipt = self.bundle.query_receipt((("/a", 1), ("/a", 2)))
        self.assertEqual(receipt.hits, ())

    def test_needs_no_log_or_private_key(self):
        from auditchain import (
            decode_signed_json_multi_index,
            encode_signed_json_multi_index,
        )

        blob = encode_signed_json_multi_index(self.bundle)
        decoded = decode_signed_json_multi_index(blob)
        receipt = decoded.query_receipt((("/a", 1), ("/b", "x")))
        self.assertEqual(receipt.hits, (0,))
        self.assertTrue(verify_multi_query_receipt(receipt, public_key(SEED_A)))

    def test_issuing_does_not_imply_verification(self):
        # A bundle whose signature belongs to another key still issues
        # receipts; only verification reports the mismatch.
        other = make_log().signed_json_multi_index(POINTERS, SEED_B)
        receipt = other.query_receipt((("/a", 1), ("/b", "x")))
        self.assertFalse(verify_multi_query_receipt(receipt, public_key(SEED_A)))
        self.assertTrue(verify_multi_query_receipt(receipt, public_key(SEED_B)))

    def test_condition_and_range_errors_match_find_all(self):
        for bad in ([("/a", 1)], "/a", None):
            with self.assertRaises(TypeError):
                self.bundle.query_receipt(bad)
        with self.assertRaises(TypeError):
            self.bundle.query_receipt((["/a", 1],))
        with self.assertRaises(ValueError):
            self.bundle.query_receipt((("/a",),))
        with self.assertRaises(TypeError):
            self.bundle.query_receipt(((b"/a", 1),))
        with self.assertRaises(ValueError):
            self.bundle.query_receipt((("/missing", 1),))
        with self.assertRaises(TypeError):
            self.bundle.query_receipt((("/a", [1]),))
        with self.assertRaises(ValueError):
            self.bundle.query_receipt((("/a", float("nan")),))
        with self.assertRaises(TypeError):
            self.bundle.query_receipt((("/a", 1),), True)
        with self.assertRaises(ValueError):
            self.bundle.query_receipt((("/a", 1),), -1)
        with self.assertRaises(ValueError):
            self.bundle.query_receipt((("/a", 1),), 4, 2)

    def test_empty_range_does_not_mask_invalid_condition(self):
        with self.assertRaises(ValueError):
            self.bundle.query_receipt((("/missing", 1),), 3, 3)
        with self.assertRaises(TypeError):
            self.bundle.query_receipt((("/a", [1]),), 3, 3)

    def test_issuing_is_read_only(self):
        blob = encode_signed_json_multi_index(self.bundle)
        self.bundle.query_receipt((("/a", 1), ("/b", "x")))
        self.bundle.query_receipt(())
        with self.assertRaises(ValueError):
            self.bundle.query_receipt((("/missing", 1),))
        self.assertEqual(encode_signed_json_multi_index(self.bundle), blob)


class VerifyMultiQueryReceiptTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()
        self.conditions = (("/a", 1), ("/b", "x"))
        self.receipt = self.bundle.query_receipt(self.conditions)

    def test_genuine_receipt_verifies(self):
        self.assertTrue(
            verify_multi_query_receipt(self.receipt, public_key(SEED_A))
        )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_multi_query_receipt(self.receipt, public_key(SEED_B))
        )

    def test_tampered_signature_returns_false(self):
        from auditchain import SignedJsonMultiIndex

        forged = SignedJsonMultiIndex(self.bundle.index, b"\x00" * 64)
        receipt = MultiQueryReceipt(forged, self.conditions, 0, 8, (0,))
        self.assertFalse(
            verify_multi_query_receipt(receipt, public_key(SEED_A))
        )

    def test_tampered_index_evidence_returns_false(self):
        from auditchain import Entry, SignedJsonMultiIndex

        index = self.bundle.index
        items = list(index.items)
        first = items[0]
        items[0] = Entry(
            first.index,
            j({"a": 1, "b": "tampered"}),
            first.previous_hash,
            first.entry_hash,
        )
        tampered = type(index)(
            index.version,
            index.hash_name,
            index.size,
            index.root,
            index.head,
            index.retain_from,
            index.pointers,
            tuple(items),
            index.proof,
            index.groups,
        )
        bundle = SignedJsonMultiIndex(tampered, self.bundle.signature)
        receipt = MultiQueryReceipt(bundle, self.conditions, 0, 8, (0,))
        self.assertFalse(
            verify_multi_query_receipt(receipt, public_key(SEED_A))
        )

    def test_under_reported_hits_return_false(self):
        receipt = MultiQueryReceipt(self.bundle, self.conditions, 0, 8, ())
        self.assertFalse(
            verify_multi_query_receipt(receipt, public_key(SEED_A))
        )

    def test_over_reported_hits_return_false(self):
        receipt = MultiQueryReceipt(self.bundle, self.conditions, 0, 8, (0, 1))
        self.assertFalse(
            verify_multi_query_receipt(receipt, public_key(SEED_A))
        )

    def test_modified_conditions_pass_when_hits_still_match(self):
        # The conditions are not separately signed: a receipt whose
        # conditions were changed verifies whenever the recorded hits
        # are exactly the new conditions' complete result.
        receipt = MultiQueryReceipt(self.bundle, (("/b", "x"),), 0, 8, (0, 2, 3, 6))
        self.assertTrue(verify_multi_query_receipt(receipt, public_key(SEED_A)))
        # The same modified conditions with stale hits fail.
        stale = MultiQueryReceipt(self.bundle, (("/b", "x"),), 0, 8, (0,))
        self.assertFalse(verify_multi_query_receipt(stale, public_key(SEED_A)))

    def test_type_errors(self):
        for bad in (None, "receipt", self.bundle, 42):
            with self.assertRaises(TypeError):
                verify_multi_query_receipt(bad, public_key(SEED_A))
        with self.assertRaises(TypeError):
            verify_multi_query_receipt(self.receipt, "not-bytes")
        with self.assertRaises(TypeError):
            verify_multi_query_receipt(self.receipt, bytearray(public_key(SEED_A)))

    def test_public_key_length_raises_value_error(self):
        for bad in (b"", b"k" * 31, b"k" * 33):
            with self.assertRaises(ValueError):
                verify_multi_query_receipt(self.receipt, bad)

    def test_hit_structure_errors_raise(self):
        # Out of range, duplicated and misordered hits are ValueError.
        for hits in ((8,), (0, 0), (2, 0)):
            with self.assertRaises(ValueError):
                MultiQueryReceipt(self.bundle, self.conditions, 0, 8, hits)
        with self.assertRaises(TypeError):
            MultiQueryReceipt(self.bundle, self.conditions, 0, 8, [0])
        with self.assertRaises(TypeError):
            MultiQueryReceipt(self.bundle, self.conditions, 0, 8, (True,))

    def test_structural_validation_precedes_signature_check(self):
        # A receipt with an invalid condition raises even though its
        # signature would not verify either.
        forged_bundle = type(self.bundle)(self.bundle.index, b"\x00" * 64)
        receipt = object.__new__(MultiQueryReceipt)
        object.__setattr__(receipt, "bundle", forged_bundle)
        object.__setattr__(receipt, "conditions", (("/missing", 1),))
        object.__setattr__(receipt, "start", 0)
        object.__setattr__(receipt, "stop", 8)
        object.__setattr__(receipt, "hits", ())
        with self.assertRaises(ValueError):
            verify_multi_query_receipt(receipt, public_key(SEED_A))

    def test_empty_snapshot(self):
        log = AuditLog()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.query_receipt(())
        self.assertEqual((receipt.start, receipt.stop, receipt.hits), (0, 0, ()))
        self.assertTrue(verify_multi_query_receipt(receipt, public_key(SEED_A)))
        blob = encode_multi_query_receipt(receipt)
        self.assertEqual(decode_multi_query_receipt(blob), receipt)

    def test_pruned_snapshot(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.query_receipt((("/a", True), ("/b", "x")))
        self.assertEqual((receipt.start, receipt.stop), (2, 8))
        self.assertEqual(receipt.hits, (2,))
        self.assertTrue(verify_multi_query_receipt(receipt, public_key(SEED_A)))
        # A range reaching into the pruned prefix is rejected.
        with self.assertRaises(ValueError):
            bundle.query_receipt((("/a", 1),), 0, 4)

    def test_other_hash_algorithms(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            log.append(j({"a": 1, "b": "x"}))
            log.append(j({"a": 2, "b": "x"}))
            bundle = log.signed_json_multi_index(POINTERS, SEED_A)
            receipt = bundle.query_receipt((("/a", 1), ("/b", "x")))
            self.assertEqual(receipt.hits, (0,))
            self.assertTrue(
                verify_multi_query_receipt(receipt, public_key(SEED_A))
            )
            decoded = decode_multi_query_receipt(encode_multi_query_receipt(receipt))
            self.assertEqual(decoded, receipt)
            self.assertTrue(
                verify_multi_query_receipt(decoded, public_key(SEED_A))
            )

    def test_log_growth_and_pruning_do_not_change_old_receipt(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.query_receipt((("/a", 1), ("/b", "x")))
        blob = encode_multi_query_receipt(receipt)
        log.append(j({"a": 1, "b": "x"}))
        log.prune(4, log.seal(4))
        self.assertEqual(receipt.hits, (0,))
        self.assertEqual(encode_multi_query_receipt(receipt), blob)
        self.assertTrue(
            verify_multi_query_receipt(receipt, public_key(SEED_A))
        )


class MultiQueryReceiptCodecTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()

    def test_round_trip_preserves_fields_and_bytes(self):
        receipt = self.bundle.query_receipt((("/a", 1), ("/b", "x")), 1, 6)
        blob = encode_multi_query_receipt(receipt)
        decoded = decode_multi_query_receipt(blob)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.conditions, receipt.conditions)
        self.assertEqual(encode_multi_query_receipt(decoded), blob)

    def test_condition_order_is_preserved(self):
        conditions = (("/b", "x"), ("/a", 1), ("/z", 9))
        receipt = self.bundle.query_receipt(conditions)
        decoded = decode_multi_query_receipt(encode_multi_query_receipt(receipt))
        self.assertEqual(decoded.conditions, conditions)

    def test_scalar_types_and_big_integers_are_preserved(self):
        log = AuditLog()
        big = 2**200 + 7
        log.append(j({"a": big, "b": "x"}))
        log.append(j({"a": -0.5, "b": None}))
        log.append(j({"a": False, "b": "x"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        for value in (big, -big, 0, -0.5, 1.5, True, False, None, "", "héllo"):
            receipt = bundle.query_receipt((("/a", value),))
            decoded = decode_multi_query_receipt(
                encode_multi_query_receipt(receipt)
            )
            self.assertEqual(decoded, receipt)
            self.assertEqual(
                type(decoded.conditions[0][1]), type(value)
            )
            self.assertTrue(
                verify_multi_query_receipt(decoded, public_key(SEED_A))
            )

    def test_unverifiable_receipt_still_round_trips(self):
        # Structurally valid but signed by the wrong key: encodes and
        # decodes, only verification reports False.
        other = make_log().signed_json_multi_index(POINTERS, SEED_B)
        receipt = other.query_receipt((("/a", 1),))
        blob = encode_multi_query_receipt(receipt)
        decoded = decode_multi_query_receipt(blob)
        self.assertEqual(decoded, receipt)
        self.assertFalse(verify_multi_query_receipt(decoded, public_key(SEED_A)))

    def test_encode_type_errors(self):
        for bad in (None, "receipt", self.bundle, 42):
            with self.assertRaises(TypeError):
                encode_multi_query_receipt(bad)

    def test_decode_requires_exact_bytes(self):
        receipt = self.bundle.query_receipt((("/a", 1),))
        blob = encode_multi_query_receipt(receipt)
        for bad in (bytearray(blob), memoryview(blob), "x", None, 42):
            with self.assertRaises(TypeError):
                decode_multi_query_receipt(bad)

    def test_decode_bad_magic_version_truncation_and_trailing(self):
        receipt = self.bundle.query_receipt((("/a", 1), ("/b", "x")))
        blob = encode_multi_query_receipt(receipt)
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(b"auditchain/other/v1\0" + blob[32:])
        # Unknown version.
        magic_len = len(b"auditchain/multi-query-receipt/v1\0")
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(
                blob[:magic_len] + (2).to_bytes(8, "big") + blob[magic_len + 8:]
            )
        # Every truncation is rejected.
        for cut in range(len(blob)):
            with self.assertRaises(ValueError):
                decode_multi_query_receipt(blob[:cut])
        # Trailing data is rejected.
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(blob + b"\x00")

    def test_decode_illegal_field_values(self):
        receipt = self.bundle.query_receipt((("/a", 1),))
        blob = encode_multi_query_receipt(receipt)
        # A hit beyond the range: rewrite the trailing hit u64.
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(blob[:-8] + (99).to_bytes(8, "big"))
        # An unknown value type tag.
        magic_len = len(b"auditchain/multi-query-receipt/v1\0")
        # version (8) + bundle blob length (8) + bundle blob
        bundle_len = int.from_bytes(blob[magic_len + 8: magic_len + 16], "big")
        conditions_count_at = magic_len + 16 + bundle_len
        pointer_len_at = conditions_count_at + 8
        pointer_len = int.from_bytes(
            blob[pointer_len_at: pointer_len_at + 8], "big"
        )
        tag_at = pointer_len_at + 8 + pointer_len
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(
                blob[:tag_at] + (99).to_bytes(8, "big") + blob[tag_at + 8:]
            )


if __name__ == "__main__":
    unittest.main()
