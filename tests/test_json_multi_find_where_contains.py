import unittest

from auditchain import (
    AuditLog,
    SignedJsonMultiIndex,
    SignedWhereReceipt,
    WhereReceipt,
    decode_signed_where_receipt,
    decode_where_receipt,
    encode_signed_json_multi_index,
    encode_signed_where_receipt,
    encode_where_receipt,
    sign_where_receipt,
    verify_signed_where_receipt,
    verify_where_receipt,
)

from tests.test_signed_json_multi_index import SEED_A, SEED_B, j, public_key

POINTERS = ("", "/a", "/arr", "/arr/0", "/b/c")

KEY = bytes(range(32))


def make_log():
    log = AuditLog()
    # 0: /a is [1, 2], /arr is [10, 20], /b/c is [3]
    log.append(j({"a": [1, 2], "arr": [10, 20], "b": {"c": [3]}}))
    # 1: /a is [1.0, "x"] — the float is the same JSON number as 1
    log.append(j({"a": [1.0, "x"]}))
    # 2: /a is [True, False] — booleans are not numbers
    log.append(j({"a": [True, False]}))
    # 3: /a is [None]
    log.append(j({"a": [None]}))
    # 4: /a is ["1", "x"] — the string "1" is not the number 1
    log.append(j({"a": ["1", "x"]}))
    # 5: /a is the empty array
    log.append(j({"a": []}))
    # 6: /a is an object, not an array
    log.append(j({"a": {}}))
    # 7: /a is a scalar, not an array
    log.append(j({"a": 1}))
    # 8: /a missing; /b/c is a scalar
    log.append(j({"b": {"c": 2}}))
    # 9: not JSON
    log.append(b"not json")
    # 10: repeated member name
    log.append(b'{"a": [1], "a": [2]}')
    # 11: invalid UTF-8
    log.append(b"\xff\xfe")
    # 12: encrypted entry whose plaintext would have /a [1]
    log.encrypt(j({"a": [1]}), KEY)
    # 13: the whole document is the array [1, 2]
    log.append(j([1, 2]))
    # 14: the whole document is the empty array
    log.append(j([]))
    # 15: /a is [[1], {"x": 1}] (nested containers), /arr is [1, 1]
    log.append(j({"a": [[1], {"x": 1}], "arr": [1, 1]}))
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


class FindWhereContainsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_number_matches_integer_and_float_elements(self):
        # The number 1 matches both the integer 1 and the float 1.0.
        self.assertEqual(self.bundle.find_where(("contains", "/a", 1)), (0, 1))
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", 1.0)), (0, 1)
        )

    def test_boolean_is_not_a_number(self):
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", True)), (2,)
        )
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", False)), (2,)
        )
        # The number 1 never matches the boolean true, nor vice versa.
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", 1)), (0, 1)
        )

    def test_null_and_string_elements(self):
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", None)), (3,)
        )
        # The string "1" is a different kind from the number 1.
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", "1")), (4,)
        )
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", "x")), (1, 4)
        )

    def test_string_match_is_case_sensitive(self):
        log = AuditLog()
        log.append(j({"a": ["X"]}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("contains", "/a", "x")), ())
        self.assertEqual(bundle.find_where(("contains", "/a", "X")), (0,))

    def test_empty_array_and_non_array_never_match(self):
        # 5 (empty array), 6 (object) and 7 (scalar) hit nothing.
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", "x")), (1, 4)
        )
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", 1)), (0, 1)
        )

    def test_empty_pointer_addresses_whole_document(self):
        # Entry 13's document is itself the array [1, 2]; entry 14's is
        # the empty array.
        self.assertEqual(self.bundle.find_where(("contains", "", 1)), (13,))
        self.assertEqual(self.bundle.find_where(("contains", "", 2)), (13,))
        self.assertEqual(self.bundle.find_where(("contains", "", "x")), ())

    def test_nested_and_array_positions(self):
        self.assertEqual(
            self.bundle.find_where(("contains", "/arr", 20)), (0,)
        )
        # /arr/0 is a scalar everywhere, never an array.
        self.assertEqual(
            self.bundle.find_where(("contains", "/arr/0", 10)), ()
        )
        self.assertEqual(
            self.bundle.find_where(("contains", "/b/c", 3)), (0,)
        )
        # 8's /b/c is the scalar 2, not an array.
        self.assertEqual(
            self.bundle.find_where(("contains", "/b/c", 2)), ()
        )

    def test_duplicate_elements_yield_one_hit(self):
        # 15's /arr is [1, 1]: the repeated element still hits once.
        self.assertEqual(
            self.bundle.find_where(("contains", "/arr", 1)), (15,)
        )

    def test_nested_containers_are_not_unfolded(self):
        # 15's /a is [[1], {"x": 1}]: the nested array and object are
        # direct elements, and containers never equal a scalar.
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", 1)), (0, 1)
        )

    def test_invalid_and_encrypted_entries_never_match(self):
        # 9 (not JSON), 10 (repeated member), 11 (bad UTF-8) and 12
        # (encrypted) hit no contains leaf, so they hit its negation.
        self.assertEqual(
            self.bundle.find_where(("not", ("contains", "/a", 1))),
            (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        )

    def test_combines_with_other_leaves_and_nests(self):
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("contains", "/a", 1), ("contains", "/a", "x")))
            ),
            (1,),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("or", (("contains", "/a", True), ("contains", "/a", None)))
            ),
            (2, 3),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("contains", "/a", 1), ("type", "/a", "array")))
            ),
            (0, 1),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("exists", "/a"), ("not", ("contains", "/a", 1))))
            ),
            (2, 3, 4, 5, 6, 7, 15),
        )
        self.assertEqual(
            self.bundle.find_where(("not", ("not", ("contains", "/a", 1)))),
            (0, 1),
        )

    def test_range_clipping_and_empty_range(self):
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", 1), 1, 15), (1,)
        )
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", 1), 2, 2), ()
        )
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", 1), None, 1), (0,)
        )

    def test_default_range_covers_retained_segment(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("contains", "/a", "x")), (4,))
        self.assertEqual(
            bundle.find_where(("not", ("contains", "/a", "x"))),
            (3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        )
        with self.assertRaises(ValueError):
            bundle.find_where(("contains", "/a", "x"), 0, 4)

    def test_result_is_ascending_duplicate_free_tuple(self):
        result = self.bundle.find_where(
            (
                "or",
                (
                    ("contains", "/a", 1),
                    ("contains", "/a", 1.0),
                    ("contains", "", 1),
                ),
            )
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, (0, 1, 13))

    def test_type_errors(self):
        for expression in (
            ["contains", "/a", 1],  # node not a tuple
            (1, "/a", 1),  # operator not a string
            ("contains", 1, 1),  # pointer not a string
            ("contains", "/a", [1]),  # candidate is a container
            ("contains", "/a", {"x": 1}),
            ("contains", "/a", b"x"),  # candidate of another type
            ("contains", "/a", (1,)),
        ):
            with self.assertRaises(TypeError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_value_errors(self):
        for expression in (
            ("contains",),  # wrong length
            ("contains", "/a"),
            ("contains", "/a", 1, 2),
            ("contains", "a", 1),  # malformed pointer
            ("contains", "/a/~2", 1),  # illegal escape
            ("contains", "/missing", 1),  # uncovered pointer
            ("contains", "/a", float("nan")),  # non-finite float
            ("contains", "/a", float("inf")),
        ):
            with self.assertRaises(ValueError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_expression_validated_before_range(self):
        # An empty range never masks an illegal expression, and the
        # expression's own nodes are validated before the range.
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (("contains", "/a", 1), ("contains", "/a", [1]))),
                2,
                2,
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(("contains", "/missing", 1), 2, 2)
        # The range is still validated after a legal expression.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("contains", "/a", 1), 2, 1)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("contains", "/a", 1), 3, 17)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("contains", "/a", 1), "0", 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("contains", "/a", 1), True, 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("contains", "/a", 1), 0, False)

    def test_read_only_and_snapshot_stable(self):
        before = self.bundle.find_where(("contains", "/a", 1))
        self.log.append(j({"a": [1]}))
        self.assertEqual(self.bundle.find_where(("contains", "/a", 1)), before)
        self.assertEqual(
            self.log.signed_json_multi_index(POINTERS, SEED_A).find_where(
                ("contains", "/a", 1)
            ),
            (0, 1, 16),
        )

    def test_frozen_snapshot_survives_append_and_prune(self):
        receipt_before = self.bundle.where_receipt(("contains", "/a", 1))
        self.log.append(j({"a": [1]}))
        self.log.prune(5, self.log.seal(5))
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", 1)), (0, 1)
        )
        self.assertTrue(verify_where_receipt(receipt_before, public_key(SEED_A)))


class WhereReceiptContainsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = (
            "and",
            (
                ("contains", "/a", 1),
                ("not", ("contains", "/a", "x")),
            ),
        )
        self.receipt = self.bundle.where_receipt(self.expression)

    def test_receipt_fields(self):
        self.assertIsInstance(self.receipt, WhereReceipt)
        self.assertEqual(self.receipt.expression, self.expression)
        self.assertEqual((self.receipt.start, self.receipt.stop), (0, 16))
        self.assertEqual(self.receipt.hits, (0,))

    def test_verify_true_with_trusted_key(self):
        self.assertTrue(verify_where_receipt(self.receipt, public_key(SEED_A)))

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(verify_where_receipt(self.receipt, public_key(SEED_B)))

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (0, 1), (0, 15)):
            receipt = WhereReceipt(
                self.receipt.bundle,
                self.receipt.expression,
                self.receipt.start,
                self.receipt.stop,
                hits,
            )
            self.assertFalse(
                verify_where_receipt(receipt, public_key(SEED_A)),
                msg=repr(hits),
            )

    def test_verify_false_on_tampered_bundle(self):
        # A self-consistent bundle from another signer does not verify
        # against the trusted key.
        other = self.log.signed_json_multi_index(POINTERS, SEED_B)
        receipt = WhereReceipt(
            other,
            self.expression,
            self.receipt.start,
            self.receipt.stop,
            other.find_where(self.expression),
        )
        self.assertFalse(verify_where_receipt(receipt, public_key(SEED_A)))

    def test_verify_false_on_flipped_signature(self):
        signature = self.receipt.bundle.signature
        tampered = SignedJsonMultiIndex(
            self.receipt.bundle.index,
            bytes([signature[0] ^ 1]) + signature[1:],
        )
        receipt = WhereReceipt(
            tampered,
            self.expression,
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        self.assertFalse(verify_where_receipt(receipt, public_key(SEED_A)))

    def test_plain_receipt_does_not_authenticate_query(self):
        # Editing the expression (and range) still verifies whenever the
        # declared hits remain exactly the complete result of the edited
        # query — ("contains", "/a", 1.0) has the same hits as
        # ("contains", "/a", 1).
        receipt = WhereReceipt(
            self.receipt.bundle,
            ("contains", "/a", 1.0),
            self.receipt.start,
            self.receipt.stop,
            (0, 1),
        )
        self.assertTrue(verify_where_receipt(receipt, public_key(SEED_A)))

    def test_constructor_validates_expression_and_range(self):
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.receipt.bundle, ("contains", "/missing", 1), 0, 16, ()
            )
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.receipt.bundle, ("contains", "/a", float("nan")), 0, 16, ()
            )
        with self.assertRaises(TypeError):
            WhereReceipt(self.receipt.bundle, ("contains", "/a", [1]), 0, 16, ())
        with self.assertRaises(ValueError):
            WhereReceipt(self.receipt.bundle, self.expression, 5, 4, ())

    def test_round_trip_preserves_structure_and_bytes(self):
        expression = (
            "or",
            (
                ("contains", "/a", 1),
                ("and", (("contains", "", 2), ("contains", "/arr", 20))),
                ("contains", "/a", 1),
                ("not", ("contains", "/a", "x")),
            ),
        )
        receipt = self.bundle.where_receipt(expression)
        data = encode_where_receipt(receipt)
        restored = decode_where_receipt(data)
        self.assertEqual(restored, receipt)
        self.assertEqual(restored.expression, expression)
        self.assertEqual(encode_where_receipt(restored), data)
        self.assertTrue(verify_where_receipt(restored, public_key(SEED_A)))

    def test_scalar_type_is_bound_exactly(self):
        # ("contains", "/a", 1) and ("contains", "/a", 1.0) have the same
        # hits but encode differently, and each round-trips field-equal.
        int_receipt = self.bundle.where_receipt(("contains", "/a", 1))
        float_receipt = self.bundle.where_receipt(("contains", "/a", 1.0))
        self.assertEqual(int_receipt.hits, float_receipt.hits)
        int_data = encode_where_receipt(int_receipt)
        float_data = encode_where_receipt(float_receipt)
        self.assertNotEqual(int_data, float_data)
        self.assertEqual(decode_where_receipt(int_data), int_receipt)
        self.assertEqual(decode_where_receipt(float_data), float_receipt)
        self.assertEqual(encode_where_receipt(decode_where_receipt(int_data)), int_data)
        self.assertTrue(verify_where_receipt(int_receipt, public_key(SEED_A)))
        self.assertTrue(verify_where_receipt(float_receipt, public_key(SEED_A)))

    def test_decode_type_error(self):
        data = encode_where_receipt(self.receipt)
        for bad in (bytearray(data), memoryview(data), data.decode("latin1"), 1):
            with self.assertRaises(TypeError, msg=type(bad).__name__):
                decode_where_receipt(bad)

    def test_decode_truncation_and_trailing_bytes(self):
        data = encode_where_receipt(self.receipt)
        with self.assertRaises(ValueError):
            decode_where_receipt(data[:-1])
        with self.assertRaises(ValueError):
            decode_where_receipt(data + b"\x00")

    def test_decode_rejects_unknown_node_tag(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(13)  # unknown node tag
            + u64(0)
            + u64(16)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_invalid_utf8_contains_pointer(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(12)  # contains node tag
            + blob(b"\xff")
            + u64(1)
            + blob(b"1")
            + u64(0)
            + u64(16)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_unknown_contains_value_tag(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(12)  # contains node tag
            + blob(b"/a")
            + u64(9)  # unknown value tag
            + blob(b"")
            + u64(0)
            + u64(16)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_noncanonical_contains_integer(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(12)  # contains node tag
            + blob(b"/a")
            + u64(1)  # integer value tag
            + blob(b"007")
            + u64(0)
            + u64(16)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_uncovered_contains_pointer(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(12)  # contains node tag
            + blob(b"/missing")
            + u64(1)
            + blob(b"1")
            + u64(0)
            + u64(16)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_historical_index_queries_without_resigning(self):
        # A bundle's encoding — and therefore its signed message — is
        # untouched by the new leaf: an index frozen before the feature
        # answers contains queries as-is.
        data = encode_signed_json_multi_index(self.bundle)
        self.assertEqual(encode_signed_json_multi_index(self.bundle), data)
        self.assertEqual(
            self.bundle.find_where(("contains", "/a", 1)), (0, 1)
        )


class SignedWhereReceiptContainsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = ("contains", "/a", 1)
        self.receipt = self.bundle.where_receipt(self.expression)
        self.signed = sign_where_receipt(self.receipt, SEED_A)

    def test_signed_receipt_verifies(self):
        self.assertTrue(
            verify_signed_where_receipt(self.signed, public_key(SEED_A))
        )

    def test_signature_binds_the_expression(self):
        # ("contains", "/a", 1.0) has exactly the same hits as
        # ("contains", "/a", 1), but swapping the expression without
        # re-signing fails: the signature binds the exact query.
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("contains", "/a", 1.0),
            self.receipt.start,
            self.receipt.stop,
            (0, 1),
        )
        bundle = SignedWhereReceipt(swapped, self.signed.signature)
        self.assertFalse(
            verify_signed_where_receipt(bundle, public_key(SEED_A))
        )

    def test_resigned_swapped_receipt_verifies(self):
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("contains", "/a", 1.0),
            self.receipt.start,
            self.receipt.stop,
            (0, 1),
        )
        resigned = sign_where_receipt(swapped, SEED_A)
        self.assertTrue(
            verify_signed_where_receipt(resigned, public_key(SEED_A))
        )

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(
            verify_signed_where_receipt(self.signed, public_key(SEED_B))
        )

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (0,), (0, 1, 15)):
            receipt = WhereReceipt(
                self.receipt.bundle,
                self.expression,
                self.receipt.start,
                self.receipt.stop,
                hits,
            )
            signed = sign_where_receipt(receipt, SEED_A)
            self.assertFalse(
                verify_signed_where_receipt(signed, public_key(SEED_A)),
                msg=repr(hits),
            )

    def test_signed_round_trip_bytes_identical(self):
        data = encode_signed_where_receipt(self.signed)
        restored = decode_signed_where_receipt(data)
        self.assertEqual(restored, self.signed)
        self.assertEqual(encode_signed_where_receipt(restored), data)
        self.assertTrue(
            verify_signed_where_receipt(restored, public_key(SEED_A))
        )


if __name__ == "__main__":
    unittest.main()
