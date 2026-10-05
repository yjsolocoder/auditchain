import dataclasses
import unittest

from auditchain import (
    AuditLog,
    MultiQueryReceipt,
    SignedJsonMultiIndex,
    decode_multi_query_receipt,
    encode_multi_query_receipt,
    encode_signed_json_multi_index,
    verify_multi_query_receipt,
    verify_signed_json_multi_index,
)

from tests.test_signed_json_multi_index import SEED_A, SEED_B, j, public_key

MAGIC = b"auditchain/multi-query-receipt/v1\0"

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
    # 4: a matches the number 1 but /b is missing; /z is 9
    log.append(j({"a": 1, "z": 9}))
    # 5: not JSON
    log.append(b"not json")
    # 6: no queried fields
    log.append(j({"other": 1}))
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


class QueryReceiptBasicsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_fields_and_defaults(self):
        receipt = self.bundle.query_receipt((("/a", 1), ("/b", "x")))
        self.assertIsInstance(receipt, MultiQueryReceipt)
        self.assertEqual(receipt.bundle, self.bundle)
        self.assertEqual(receipt.conditions, (("/a", 1), ("/b", "x")))
        # The default range covers the whole retained segment.
        self.assertEqual(receipt.start, 0)
        self.assertEqual(receipt.stop, 7)
        self.assertEqual(receipt.hits, (0,))

    def test_hits_match_find_all(self):
        for conditions, start, stop in (
            ((("/a", 1), ("/b", "x")), None, None),
            ((("/a", 1.0), ("/b", "y")), None, None),
            ((("/a", True), ("/b", "x")), None, None),
            ((("/z", 9),), 1, 6),
            ((("/a", 1),), 2, 5),
        ):
            receipt = self.bundle.query_receipt(conditions, start, stop)
            self.assertEqual(
                receipt.hits, self.bundle.find_all(conditions, start, stop)
            )

    def test_empty_conditions_returns_whole_range(self):
        receipt = self.bundle.query_receipt(())
        self.assertEqual(receipt.hits, tuple(range(7)))
        receipt = self.bundle.query_receipt((), 2, 4)
        self.assertEqual(receipt.hits, (2, 3))

    def test_empty_range_and_no_match_return_empty_tuple(self):
        self.assertEqual(self.bundle.query_receipt((), 3, 3).hits, ())
        self.assertEqual(
            self.bundle.query_receipt((("/a", 1),), 3, 3).hits, ()
        )
        self.assertEqual(
            self.bundle.query_receipt((("/a", False),)).hits, ()
        )

    def test_hits_are_strictly_ascending_without_duplicates(self):
        log = AuditLog()
        for value in (1, 1, 2, 1, 1):
            log.append(j({"a": value, "b": "x"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.query_receipt((("/a", 1), ("/b", "x")))
        self.assertEqual(receipt.hits, (0, 1, 3, 4))
        self.assertEqual(receipt.hits, tuple(sorted(set(receipt.hits))))

    def test_receipt_is_immutable(self):
        receipt = self.bundle.query_receipt(())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            receipt.hits = ()

    def test_receipt_is_positional_and_compares_by_fields(self):
        receipt = self.bundle.query_receipt((("/a", 1),))
        clone = MultiQueryReceipt(
            receipt.bundle,
            receipt.conditions,
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        self.assertEqual(receipt, clone)

    def test_condition_and_range_errors_follow_find_all(self):
        bundle = self.bundle
        with self.assertRaises(TypeError):
            bundle.query_receipt(["/a", 1])
        with self.assertRaises(TypeError):
            bundle.query_receipt((["/a", 1],))
        with self.assertRaises(ValueError):
            bundle.query_receipt((("/a",),))
        with self.assertRaises(TypeError):
            bundle.query_receipt(((1, 1),))
        with self.assertRaises(ValueError):
            bundle.query_receipt((("a", 1),))
        with self.assertRaises(ValueError):
            bundle.query_receipt((("/missing", 1),))
        with self.assertRaises(TypeError):
            bundle.query_receipt((("/a", [1]),))
        with self.assertRaises(ValueError):
            bundle.query_receipt((("/a", float("inf")),))
        with self.assertRaises(TypeError):
            bundle.query_receipt((), "0")
        with self.assertRaises(TypeError):
            bundle.query_receipt((), 0, 1.5)
        with self.assertRaises(ValueError):
            bundle.query_receipt((), -1)
        with self.assertRaises(ValueError):
            bundle.query_receipt((), 0, 8)
        with self.assertRaises(ValueError):
            bundle.query_receipt((), 4, 2)

    def test_empty_range_does_not_mask_later_illegal_condition(self):
        # Every condition is validated before the range, so an empty
        # range or an early miss never hides a bad condition.
        with self.assertRaises(ValueError):
            self.bundle.query_receipt((("/missing", 1),), 2, 2)
        with self.assertRaises(ValueError):
            self.bundle.query_receipt(
                (("/a", False), ("/missing", 1))
            )
        with self.assertRaises(TypeError):
            self.bundle.query_receipt((("/a", False), ("/a", [1])))


class VerifyMultiQueryReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.key = public_key(SEED_A)

    def test_genuine_receipt_verifies(self):
        receipt = self.bundle.query_receipt((("/a", 1), ("/b", "x")))
        self.assertTrue(verify_multi_query_receipt(receipt, self.key))

    def test_empty_and_full_range_receipts_verify(self):
        for receipt in (
            self.bundle.query_receipt(()),
            self.bundle.query_receipt((), 3, 3),
            self.bundle.query_receipt((("/a", False),)),
            self.bundle.query_receipt((("/a", 1),), 2, 5),
        ):
            self.assertTrue(verify_multi_query_receipt(receipt, self.key))

    def test_wrong_public_key_returns_false(self):
        receipt = self.bundle.query_receipt((("/a", 1),))
        self.assertFalse(
            verify_multi_query_receipt(receipt, public_key(SEED_B))
        )

    def test_tampered_signature_returns_false(self):
        receipt = self.bundle.query_receipt((("/a", 1),))
        other = make_log().signed_json_multi_index(POINTERS, SEED_B)
        repackaged = SignedJsonMultiIndex(
            receipt.bundle.index, other.signature
        )
        tampered = MultiQueryReceipt(
            repackaged,
            receipt.conditions,
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        self.assertFalse(verify_multi_query_receipt(tampered, self.key))

    def test_tampered_index_evidence_returns_false(self):
        # A bundle over a different log signed by the same key does not
        # authenticate this receipt's hits.
        log = make_log()
        log.append(j({"a": 1, "b": "x"}))
        other = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = self.bundle.query_receipt((("/a", 1), ("/b", "x")))
        shifted = MultiQueryReceipt(
            other, receipt.conditions, 0, 8, receipt.hits
        )
        self.assertFalse(verify_multi_query_receipt(shifted, self.key))

    def test_under_reported_hit_returns_false(self):
        # /a == 1 matches 0, 1 and 4; dropping any of them fails.
        for hits in ((0, 1), (1, 4), (0, 4), ()):
            receipt = MultiQueryReceipt(
                self.bundle, (("/a", 1),), 0, 7, hits
            )
            self.assertFalse(verify_multi_query_receipt(receipt, self.key))

    def test_over_reported_hit_returns_false(self):
        for hits in ((0, 1, 2, 4), (0, 1, 3, 4), (0, 1, 4, 5)):
            receipt = MultiQueryReceipt(
                self.bundle, (("/a", 1),), 0, 7, hits
            )
            self.assertFalse(verify_multi_query_receipt(receipt, self.key))

    def test_conditions_are_not_separately_authenticated(self):
        # Editing the conditions (and range) still verifies whenever the
        # declared hits remain the complete result of the edited query.
        receipt = self.bundle.query_receipt((("/a", 1), ("/b", "x")))
        edited = MultiQueryReceipt(
            receipt.bundle, (("/b", "x"), (("/a", 1))), 0, 7, (0,)
        )
        self.assertTrue(verify_multi_query_receipt(edited, self.key))
        narrowed = MultiQueryReceipt(
            receipt.bundle, (("/a", 1),), 0, 2, (0, 1)
        )
        self.assertTrue(verify_multi_query_receipt(narrowed, self.key))

    def test_non_receipt_raises_type_error(self):
        for bad in ("x", 1, None, self.bundle):
            with self.assertRaises(TypeError):
                verify_multi_query_receipt(bad, self.key)

    def test_public_key_type_and_length(self):
        receipt = self.bundle.query_receipt(())
        for bad in ("x", 1, None, bytearray(self.key)):
            with self.assertRaises(TypeError):
                verify_multi_query_receipt(receipt, bad)
        for bad in (b"", self.key[:-1], self.key + b"\x00"):
            with self.assertRaises(ValueError):
                verify_multi_query_receipt(receipt, bad)

    def test_structural_errors_raise(self):
        bundle = self.bundle
        with self.assertRaises(TypeError):
            MultiQueryReceipt("not-a-bundle", (), 0, 7, ())
        with self.assertRaises(TypeError):
            MultiQueryReceipt(bundle, [("/a", 1)], 0, 7, (0,))
        with self.assertRaises(ValueError):
            MultiQueryReceipt(bundle, (("/missing", 1),), 0, 7, ())
        with self.assertRaises(TypeError):
            MultiQueryReceipt(bundle, (), None, 7, ())
        with self.assertRaises(TypeError):
            MultiQueryReceipt(bundle, (), 0, True, ())
        with self.assertRaises(ValueError):
            MultiQueryReceipt(bundle, (), 6, 3, ())
        with self.assertRaises(ValueError):
            MultiQueryReceipt(bundle, (), 0, 8, ())
        with self.assertRaises(TypeError):
            MultiQueryReceipt(bundle, (), 0, 7, [0])
        with self.assertRaises(TypeError):
            MultiQueryReceipt(bundle, (), 0, 7, (0.5,))
        with self.assertRaises(TypeError):
            MultiQueryReceipt(bundle, (), 0, 7, (True,))
        # Hit outside [start, stop).
        with self.assertRaises(ValueError):
            MultiQueryReceipt(bundle, (), 0, 7, (7,))
        with self.assertRaises(ValueError):
            MultiQueryReceipt(bundle, (), 2, 7, (1,))
        # Duplicates and misordering.
        with self.assertRaises(ValueError):
            MultiQueryReceipt(bundle, (), 0, 7, (2, 2))
        with self.assertRaises(ValueError):
            MultiQueryReceipt(bundle, (), 0, 7, (3, 1))

    def test_signature_failure_does_not_mask_structural_errors(self):
        # The signature is invalid here, but the illegal hit tuple must
        # still raise rather than return False.
        other = make_log().signed_json_multi_index(POINTERS, SEED_B)
        repackaged = SignedJsonMultiIndex(self.bundle.index, other.signature)
        with self.assertRaises(ValueError):
            verify_multi_query_receipt(
                _raw_receipt(repackaged, (("/a", 1),), 0, 7, (2, 2)),
                self.key,
            )
        with self.assertRaises(ValueError):
            verify_multi_query_receipt(
                _raw_receipt(repackaged, (("/missing", 1),), 0, 7, ()),
                self.key,
            )

    def test_bypassed_fields_raise_like_the_constructor(self):
        receipt = self.bundle.query_receipt((("/a", 1),))
        object.__setattr__(receipt, "hits", (2, 2))
        with self.assertRaises(ValueError):
            verify_multi_query_receipt(receipt, self.key)


def _raw_receipt(bundle, conditions, start, stop, hits):
    """Build a MultiQueryReceipt with frozen-field validation bypassed."""
    receipt = MultiQueryReceipt.__new__(MultiQueryReceipt)
    object.__setattr__(receipt, "bundle", bundle)
    object.__setattr__(receipt, "conditions", conditions)
    object.__setattr__(receipt, "start", start)
    object.__setattr__(receipt, "stop", stop)
    object.__setattr__(receipt, "hits", hits)
    return receipt


class MultiQueryReceiptCodecTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()
        self.key = public_key(SEED_A)

    def test_magic_prefix(self):
        blob = encode_multi_query_receipt(self.bundle.query_receipt(()))
        self.assertTrue(blob.startswith(MAGIC))

    def test_roundtrip_preserves_fields(self):
        receipt = self.bundle.query_receipt((("/a", 1), ("/b", "x")), 0, 5)
        decoded = decode_multi_query_receipt(encode_multi_query_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.conditions, receipt.conditions)
        self.assertTrue(verify_multi_query_receipt(decoded, self.key))

    def test_reencode_is_byte_identical(self):
        receipt = self.bundle.query_receipt((("/z", 9),))
        blob = encode_multi_query_receipt(receipt)
        self.assertEqual(encode_multi_query_receipt(decode_multi_query_receipt(blob)), blob)

    def test_condition_order_and_scalar_types_survive(self):
        big = 2**90 + 7
        log = AuditLog()
        log.append(j({"s": "héllo", "n": big, "f": 1.5, "t": True,
                      "u": False, "z": None}))
        bundle = log.signed_json_multi_index(
            ("/f", "/n", "/s", "/t", "/u", "/z"), SEED_A
        )
        conditions = (
            ("/s", "héllo"),
            ("/n", big),
            ("/f", 1.5),
            ("/t", True),
            ("/u", False),
            ("/z", None),
        )
        receipt = bundle.query_receipt(conditions)
        decoded = decode_multi_query_receipt(encode_multi_query_receipt(receipt))
        self.assertEqual(decoded.conditions, conditions)
        for (_, value), (_, original) in zip(
            decoded.conditions, conditions
        ):
            self.assertIs(type(value), type(original))
        self.assertTrue(verify_multi_query_receipt(decoded, self.key))

    def test_negative_and_float_values_roundtrip(self):
        log = AuditLog()
        log.append(j({"a": -42, "b": "x"}))
        log.append(j({"a": -0.5, "b": "x"}))
        bundle = log.signed_json_multi_index(("/a", "/b"), SEED_A)
        for value in (-42, -0.5, 0.0):
            receipt = bundle.query_receipt((("/a", value),))
            decoded = decode_multi_query_receipt(
                encode_multi_query_receipt(receipt)
            )
            self.assertEqual(decoded, receipt)
            self.assertTrue(verify_multi_query_receipt(decoded, self.key))

    def test_encode_rejects_non_receipt(self):
        for bad in ("x", 1, None, self.bundle):
            with self.assertRaises(TypeError):
                encode_multi_query_receipt(bad)

    def test_decode_rejects_non_bytes(self):
        blob = encode_multi_query_receipt(self.bundle.query_receipt(()))
        for bad in ("x", 1, None, bytearray(blob), memoryview(blob)):
            with self.assertRaises(TypeError):
                decode_multi_query_receipt(bad)

    def test_bad_magic_and_version_rejected(self):
        blob = encode_multi_query_receipt(self.bundle.query_receipt(()))
        raw = bytearray(blob)
        raw[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(bytes(raw))
        raw = bytearray(blob)
        raw[len(MAGIC) + 7] = 2
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(bytes(raw))

    def test_truncation_and_trailing_bytes_rejected(self):
        blob = encode_multi_query_receipt(
            self.bundle.query_receipt((("/a", 1),))
        )
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(blob + b"\x00")
        for cut in (len(MAGIC), len(MAGIC) + 4, len(blob) - 1):
            with self.assertRaises(ValueError):
                decode_multi_query_receipt(blob[:cut])

    def test_illegal_decoded_field_values_rejected(self):
        u64 = lambda value: value.to_bytes(8, "big")
        blob = lambda material: u64(len(material)) + material
        bundle_blob = blob(encode_signed_json_multi_index(self.bundle))

        def raw_with_condition(tag, key):
            return (
                MAGIC
                + u64(1)
                + bundle_blob
                + u64(1)
                + blob(b"/a")
                + u64(tag)
                + blob(key)
                + u64(0)
                + u64(7)
                + u64(0)
            )

        # Unknown value tag.
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(raw_with_condition(9, b""))
        # Non-empty boolean value blob.
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(raw_with_condition(3, b"x"))
        # Non-canonical integer spellings.
        for key in (b"007", b"-0", b"+1", b"", b"1.0"):
            with self.assertRaises(ValueError):
                decode_multi_query_receipt(raw_with_condition(1, key))
        # Non-canonical / non-finite float spellings.
        for key in (b"1", b"inf", b"nan", b"1.50"):
            with self.assertRaises(ValueError):
                decode_multi_query_receipt(raw_with_condition(2, key))
        # Invalid UTF-8 string value.
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(raw_with_condition(0, b"\xff"))
        # A hit outside the declared range.
        raw = (
            MAGIC + u64(1) + bundle_blob + u64(0) + u64(0) + u64(7)
            + u64(1) + u64(9)
        )
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(raw)
        # Misordered hits.
        raw = (
            MAGIC + u64(1) + bundle_blob + u64(0) + u64(0) + u64(7)
            + u64(2) + u64(3) + u64(1)
        )
        with self.assertRaises(ValueError):
            decode_multi_query_receipt(raw)

    def test_verify_false_receipt_still_roundtrips(self):
        # Structurally valid but the hits do not match the conditions.
        receipt = MultiQueryReceipt(
            self.bundle, (("/a", 1),), 0, 7, (0,)
        )
        self.assertFalse(verify_multi_query_receipt(receipt, self.key))
        blob = encode_multi_query_receipt(receipt)
        decoded = decode_multi_query_receipt(blob)
        self.assertEqual(decoded, receipt)
        self.assertEqual(encode_multi_query_receipt(decoded), blob)

    def test_empty_snapshot_roundtrip(self):
        bundle = AuditLog().signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.query_receipt(())
        self.assertEqual((receipt.start, receipt.stop, receipt.hits), (0, 0, ()))
        blob = encode_multi_query_receipt(receipt)
        self.assertEqual(decode_multi_query_receipt(blob), receipt)
        self.assertTrue(verify_multi_query_receipt(receipt, self.key))

    def test_pruned_snapshot_roundtrip(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.query_receipt((("/a", 1),))
        self.assertEqual((receipt.start, receipt.stop), (3, 7))
        self.assertEqual(receipt.hits, (4,))
        decoded = decode_multi_query_receipt(encode_multi_query_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertTrue(verify_multi_query_receipt(decoded, self.key))

    def test_other_hash_algorithm_roundtrip(self):
        log = AuditLog(hash_name="sha512")
        log.append(j({"a": 1, "b": "x"}))
        log.append(j({"a": 2, "b": "y"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.query_receipt((("/b", "y"),))
        self.assertEqual(receipt.hits, (1,))
        decoded = decode_multi_query_receipt(encode_multi_query_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertTrue(verify_multi_query_receipt(decoded, self.key))

    def test_later_appends_and_prunes_do_not_change_old_receipt(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.query_receipt((("/a", 1),))
        blob = encode_multi_query_receipt(receipt)
        log.append(j({"a": 1, "b": "x"}))
        log.prune(2, log.seal(2))
        self.assertEqual(encode_multi_query_receipt(receipt), blob)
        self.assertTrue(verify_multi_query_receipt(receipt, self.key))
        self.assertTrue(
            verify_signed_json_multi_index(receipt.bundle, self.key)
        )


if __name__ == "__main__":
    unittest.main()
