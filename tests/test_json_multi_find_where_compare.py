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

POINTERS = ("", "/a", "/arr/0", "/arr/1", "/b", "/v")

KEY = bytes(range(32))

BIG = 2**70


def make_log():
    log = AuditLog()
    # 0: /a 10 > /b 5
    log.append(j({"a": 10, "b": 5}))
    # 1: /a 3 < /b 5
    log.append(j({"a": 3, "b": 5}))
    # 2: /a 5 == /b 5
    log.append(j({"a": 5, "b": 5}))
    # 3: /a 2.5 == /b 2.5 (floats)
    log.append(j({"a": 2.5, "b": 2.5}))
    # 4: /a -0.0 == /b 0 (negative zero equals positive zero)
    log.append(j({"a": -0.0, "b": 0}))
    # 5: /a 2**70 < /b 2**70 + 2 — equal if rounded to floats
    log.append(j({"a": BIG, "b": BIG + 2}))
    # 6: /a is a boolean, not a number
    log.append(j({"a": True, "b": 1}))
    # 7: /a is a string, not a number
    log.append(j({"a": "5", "b": 5}))
    # 8: /a is null, not a number
    log.append(j({"a": None, "b": 0}))
    # 9: /a is an array, not a number
    log.append(j({"a": [1], "b": 1}))
    # 10: /b missing
    log.append(j({"a": 9}))
    # 11: /a missing
    log.append(j({"b": 9}))
    # 12: not JSON
    log.append(b"not json")
    # 13: repeated member name
    log.append(b'{"a": 9, "a": 1, "b": 0}')
    # 14: invalid UTF-8
    log.append(b"\xff\xfe")
    # 15: encrypted entry whose plaintext would have /a 99 > /b 0
    log.encrypt(j({"a": 99, "b": 0}), KEY)
    # 16: only /v is 7 (same-pointer comparisons)
    log.append(j({"v": 7}))
    # 17: /a is an object, not a number
    log.append(j({"a": {"x": 1}, "b": 1}))
    # 18: /arr/0 is 3 > /arr/1 is 1
    log.append(j({"arr": [3, 1]}))
    # 19: /arr/1 missing (array too short)
    log.append(j({"arr": [3]}))
    # 20: the whole document is the number 9
    log.append(j(9))
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


class FindWhereCompareTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_all_five_relations(self):
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "gt", "/b")), (0,)
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "lt", "/b")), (1, 5)
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "eq", "/b")), (2, 3, 4)
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "le", "/b")),
            (1, 2, 3, 4, 5),
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "ge", "/b")), (0, 2, 3, 4)
        )

    def test_integer_and_float_compare_by_value(self):
        # 3's floats 2.5 and 2.5 are equal; 4's float -0.0 equals the
        # integer 0.
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "eq", "/b")), (2, 3, 4)
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "lt", "/b")), (1, 5)
        )

    def test_big_integers_never_round_to_float(self):
        # 2**70 and 2**70 + 2 are distinct integers whose float64
        # roundings coincide: the comparison must stay exact.
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "lt", "/b")), (1, 5)
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/b", "gt", "/a")), (1, 5)
        )
        self.assertNotIn(
            5, self.bundle.find_where(("compare", "/a", "eq", "/b"))
        )
        self.assertNotIn(
            5, self.bundle.find_where(("compare", "/a", "ge", "/b"))
        )

    def test_negative_zero_equals_positive_zero(self):
        # 4's /a is -0.0 and /b is 0.
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "eq", "/b")), (2, 3, 4)
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "le", "/b")),
            (1, 2, 3, 4, 5),
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "ge", "/b")), (0, 2, 3, 4)
        )

    def test_non_numeric_targets_never_match(self):
        # 6 (boolean), 7 (string), 8 (null), 9 (array) and 17 (object)
        # hit no compare leaf, so they hit its negation.
        for relation in ("eq", "lt", "le", "gt", "ge"):
            hits = self.bundle.find_where(("compare", "/a", relation, "/b"))
            for index in (6, 7, 8, 9, 17):
                self.assertNotIn(index, hits, msg=(relation, index))

    def test_missing_field_and_invalid_array_position_never_match(self):
        # 10 misses /b, 11 misses /a and 19 misses /arr/1.
        for relation in ("eq", "lt", "le", "gt", "ge"):
            hits = self.bundle.find_where(("compare", "/a", relation, "/b"))
            self.assertNotIn(10, hits, msg=relation)
            self.assertNotIn(11, hits, msg=relation)
            hits = self.bundle.find_where(
                ("compare", "/arr/0", relation, "/arr/1")
            )
            self.assertNotIn(19, hits, msg=relation)

    def test_invalid_and_encrypted_entries_never_match(self):
        # 12 (not JSON), 13 (repeated member), 14 (bad UTF-8) and 15
        # (encrypted) hit no compare leaf, so they hit its negation.
        for relation in ("eq", "lt", "le", "gt", "ge"):
            hits = self.bundle.find_where(("compare", "/a", relation, "/b"))
            for index in (12, 13, 14, 15):
                self.assertNotIn(index, hits, msg=(relation, index))
        self.assertEqual(
            self.bundle.find_where(("not", ("compare", "/a", "eq", "/b"))),
            (0, 1, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
        )

    def test_same_pointer_may_serve_as_both_ends(self):
        self.assertEqual(
            self.bundle.find_where(("compare", "/v", "eq", "/v")), (16,)
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/v", "le", "/v")), (16,)
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/v", "ge", "/v")), (16,)
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/v", "lt", "/v")), ()
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/v", "gt", "/v")), ()
        )

    def test_empty_pointer_addresses_whole_document(self):
        # 20's document is itself the number 9; every other document is
        # an object, an array or invalid, never a number.
        self.assertEqual(
            self.bundle.find_where(("compare", "", "eq", "")), (20,)
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "", "lt", "")), ()
        )

    def test_array_positions(self):
        self.assertEqual(
            self.bundle.find_where(("compare", "/arr/0", "gt", "/arr/1")),
            (18,),
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/arr/0", "le", "/arr/1")),
            (),
        )

    def test_nests_with_and_or_not(self):
        self.assertEqual(
            self.bundle.find_where(
                (
                    "and",
                    (
                        ("compare", "/a", "ge", "/b"),
                        ("compare", "/a", "le", "/b"),
                    ),
                )
            ),
            (2, 3, 4),
        )
        self.assertEqual(
            self.bundle.find_where(
                (
                    "or",
                    (
                        ("compare", "/a", "gt", "/b"),
                        ("compare", "/a", "lt", "/b"),
                    ),
                )
            ),
            (0, 1, 5),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("compare", "/a", "eq", "/b"), ("type", "/a", "number")))
            ),
            (2, 3, 4),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("not", ("not", ("compare", "/a", "gt", "/b")))
            ),
            (0,),
        )

    def test_range_clipping_and_empty_range(self):
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "le", "/b"), 2, 5),
            (2, 3, 4),
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "le", "/b"), 2, 2), ()
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "le", "/b"), None, 2),
            (1,),
        )

    def test_default_range_covers_retained_segment(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(
            bundle.find_where(("compare", "/a", "eq", "/b")), (3, 4)
        )
        self.assertEqual(
            bundle.find_where(("not", ("compare", "/a", "eq", "/b"))),
            (5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20),
        )
        with self.assertRaises(ValueError):
            bundle.find_where(("compare", "/a", "eq", "/b"), 0, 4)

    def test_result_is_ascending_duplicate_free_tuple(self):
        result = self.bundle.find_where(
            (
                "or",
                (
                    ("compare", "/a", "eq", "/b"),
                    ("compare", "/a", "le", "/b"),
                    ("compare", "/a", "ge", "/b"),
                ),
            )
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, (0, 1, 2, 3, 4, 5))

    def test_type_errors(self):
        for expression in (
            ["compare", "/a", "gt", "/b"],  # node not a tuple
            (1, "/a", "gt", "/b"),  # operator not a string
            ("compare", 1, "gt", "/b"),  # left pointer not a string
            ("compare", "/a", 1, "/b"),  # relation not a string
            ("compare", "/a", "gt", 1),  # right pointer not a string
            ("compare", "/a", b"gt", "/b"),
        ):
            with self.assertRaises(TypeError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_value_errors(self):
        for expression in (
            ("compare",),  # wrong length
            ("compare", "/a", "gt"),
            ("compare", "/a", "gt", "/b", "extra"),
            ("compare", "a", "gt", "/b"),  # malformed left pointer
            ("compare", "/a/~2", "gt", "/b"),  # illegal escape
            ("compare", "/missing", "gt", "/b"),  # uncovered left pointer
            ("compare", "/a", "ne", "/b"),  # unsupported relation
            ("compare", "/a", "EQ", "/b"),  # relations are case-sensitive
            ("compare", "/a", "", "/b"),
            ("compare", "/a", "gt", "b"),  # malformed right pointer
            ("compare", "/a", "gt", "/missing"),  # uncovered right pointer
        ):
            with self.assertRaises(ValueError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_validation_order_length_left_relation_right(self):
        # Length before the left pointer: a short node with a non-string
        # left pointer still raises the length ValueError.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("compare", 1, 2))
        # Left pointer before the relation: a non-string left pointer
        # raises TypeError even with a non-string relation.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("compare", 1, 2, 3))
        # Relation before the right pointer: a non-string relation
        # raises TypeError even with a non-string right pointer.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("compare", "/a", 2, 3))
        # An unsupported relation raises ValueError before a malformed
        # right pointer is reported.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("compare", "/a", "ne", 3))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("compare", "/a", "ne", "b"))

    def test_expression_validated_before_range(self):
        # An empty range never masks an illegal expression, and the
        # expression's own nodes are validated before the range.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("compare", "/a", "ne", "/b"), 2, 2)
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (("compare", "/a", "gt", "/b"), ("compare", "/a", 1, "/b"))),
                2,
                2,
            )
        # The range is still validated after a legal expression.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("compare", "/a", "gt", "/b"), 2, 1)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("compare", "/a", "gt", "/b"), 3, 22)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("compare", "/a", "gt", "/b"), "0", 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("compare", "/a", "gt", "/b"), True, 1)

    def test_read_only_and_snapshot_stable(self):
        before = self.bundle.find_where(("compare", "/a", "gt", "/b"))
        self.log.append(j({"a": 100, "b": 1}))
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "gt", "/b")), before
        )
        self.assertEqual(
            self.log.signed_json_multi_index(POINTERS, SEED_A).find_where(
                ("compare", "/a", "gt", "/b")
            ),
            (0, 21),
        )

    def test_frozen_snapshot_survives_append_and_prune(self):
        receipt_before = self.bundle.where_receipt(("compare", "/a", "gt", "/b"))
        self.log.append(j({"a": 100, "b": 1}))
        self.log.prune(5, self.log.seal(5))
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "gt", "/b")), (0,)
        )
        self.assertTrue(verify_where_receipt(receipt_before, public_key(SEED_A)))


class WhereReceiptCompareTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = (
            "and",
            (
                ("compare", "/a", "ge", "/b"),
                ("not", ("compare", "/a", "gt", "/b")),
            ),
        )
        self.receipt = self.bundle.where_receipt(self.expression)

    def test_receipt_fields(self):
        self.assertIsInstance(self.receipt, WhereReceipt)
        self.assertEqual(self.receipt.expression, self.expression)
        self.assertEqual((self.receipt.start, self.receipt.stop), (0, 21))
        self.assertEqual(self.receipt.hits, (2, 3, 4))

    def test_verify_true_with_trusted_key(self):
        self.assertTrue(verify_where_receipt(self.receipt, public_key(SEED_A)))

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(verify_where_receipt(self.receipt, public_key(SEED_B)))

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (2, 3), (2, 3, 4, 5)):
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

    def test_constructor_validates_expression_and_range(self):
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.receipt.bundle, ("compare", "/a", "ne", "/b"), 0, 21, ()
            )
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.receipt.bundle,
                ("compare", "/missing", "gt", "/b"),
                0,
                21,
                (),
            )
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.receipt.bundle, ("compare", "/a", "gt"), 0, 21, ()
            )
        with self.assertRaises(TypeError):
            WhereReceipt(
                self.receipt.bundle, ("compare", "/a", 1, "/b"), 0, 21, ()
            )
        with self.assertRaises(TypeError):
            WhereReceipt(
                self.receipt.bundle, ("compare", 1, "gt", "/b"), 0, 21, ()
            )
        with self.assertRaises(ValueError):
            WhereReceipt(self.receipt.bundle, self.expression, 5, 4, ())

    def test_round_trip_preserves_structure_and_bytes(self):
        expression = (
            "or",
            (
                ("compare", "/a", "gt", "/b"),
                ("and", (("compare", "/v", "eq", "/v"), ("compare", "", "eq", ""))),
                ("compare", "/a", "gt", "/b"),
                ("not", ("compare", "/arr/0", "le", "/arr/1")),
            ),
        )
        receipt = self.bundle.where_receipt(expression)
        data = encode_where_receipt(receipt)
        restored = decode_where_receipt(data)
        self.assertEqual(restored, receipt)
        self.assertEqual(restored.expression, expression)
        self.assertEqual(encode_where_receipt(restored), data)
        self.assertTrue(verify_where_receipt(restored, public_key(SEED_A)))

    def test_compare_parameters_are_bound_exactly(self):
        # ("compare", "/a", "gt", "/b") and ("compare", "/b", "lt", "/a")
        # have the same hits but encode differently, and each round-trips
        # field-equal.
        forward = self.bundle.where_receipt(("compare", "/a", "gt", "/b"))
        flipped = self.bundle.where_receipt(("compare", "/b", "lt", "/a"))
        self.assertEqual(forward.hits, flipped.hits)
        forward_data = encode_where_receipt(forward)
        flipped_data = encode_where_receipt(flipped)
        self.assertNotEqual(forward_data, flipped_data)
        self.assertEqual(decode_where_receipt(forward_data), forward)
        self.assertEqual(decode_where_receipt(flipped_data), flipped)
        self.assertEqual(
            encode_where_receipt(decode_where_receipt(forward_data)),
            forward_data,
        )
        self.assertTrue(verify_where_receipt(forward, public_key(SEED_A)))
        self.assertTrue(verify_where_receipt(flipped, public_key(SEED_A)))

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
            + u64(14)  # unknown node tag
            + u64(0)
            + u64(21)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_invalid_utf8_compare_fields(self):
        for bad_blob in (
            blob(b"\xff") + blob(b"gt") + blob(b"/b"),  # left pointer
            blob(b"/a") + blob(b"\xff") + blob(b"/b"),  # relation
            blob(b"/a") + blob(b"gt") + blob(b"\xff"),  # right pointer
        ):
            raw = (
                b"auditchain/where-receipt/v1\0"
                + u64(1)
                + blob(encode_signed_json_multi_index(self.bundle))
                + u64(13)  # compare node tag
                + bad_blob
                + u64(0)
                + u64(21)
                + u64(0)
            )
            with self.assertRaises(ValueError, msg=repr(bad_blob)):
                decode_where_receipt(raw)

    def test_decode_rejects_unknown_compare_relation(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(13)  # compare node tag
            + blob(b"/a")
            + blob(b"ne")
            + blob(b"/b")
            + u64(0)
            + u64(21)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_uncovered_compare_pointer(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(13)  # compare node tag
            + blob(b"/a")
            + blob(b"gt")
            + blob(b"/missing")
            + u64(0)
            + u64(21)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_historical_index_queries_without_resigning(self):
        # A bundle's encoding — and therefore its signed message — is
        # untouched by the new leaf: an index frozen before the feature
        # answers compare queries as-is.
        data = encode_signed_json_multi_index(self.bundle)
        self.assertEqual(encode_signed_json_multi_index(self.bundle), data)
        self.assertEqual(
            self.bundle.find_where(("compare", "/a", "gt", "/b")), (0,)
        )


class SignedWhereReceiptCompareTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = ("compare", "/a", "gt", "/b")
        self.receipt = self.bundle.where_receipt(self.expression)
        self.signed = sign_where_receipt(self.receipt, SEED_A)

    def test_signed_receipt_verifies(self):
        self.assertTrue(
            verify_signed_where_receipt(self.signed, public_key(SEED_A))
        )

    def test_signature_binds_the_expression(self):
        # ("compare", "/b", "lt", "/a") has exactly the same hits as
        # ("compare", "/a", "gt", "/b"), but swapping the expression
        # without re-signing fails: the signature binds the exact query.
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("compare", "/b", "lt", "/a"),
            self.receipt.start,
            self.receipt.stop,
            (0,),
        )
        bundle = SignedWhereReceipt(swapped, self.signed.signature)
        self.assertFalse(
            verify_signed_where_receipt(bundle, public_key(SEED_A))
        )

    def test_signature_binds_the_relation(self):
        # ("compare", "/a", "ge", "/b") has different hits, and even a
        # same-hit relation swap fails without re-signing.
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("compare", "/a", "ge", "/b"),
            self.receipt.start,
            self.receipt.stop,
            (0, 2, 3, 4),
        )
        bundle = SignedWhereReceipt(swapped, self.signed.signature)
        self.assertFalse(
            verify_signed_where_receipt(bundle, public_key(SEED_A))
        )

    def test_resigned_swapped_receipt_verifies(self):
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("compare", "/b", "lt", "/a"),
            self.receipt.start,
            self.receipt.stop,
            (0,),
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
        for hits in ((), (0, 1), (0, 20)):
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

    def test_signed_decode_type_error(self):
        data = encode_signed_where_receipt(self.signed)
        for bad in (bytearray(data), memoryview(data), data.decode("latin1"), 1):
            with self.assertRaises(TypeError, msg=type(bad).__name__):
                decode_signed_where_receipt(bad)

    def test_signed_decode_truncation_and_trailing_bytes(self):
        data = encode_signed_where_receipt(self.signed)
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(data[:-1])
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(data + b"\x00")


if __name__ == "__main__":
    unittest.main()
