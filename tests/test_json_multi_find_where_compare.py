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

POINTERS = ("", "/actual", "/arr/0", "/arr/1", "/b/c", "/limit")

KEY = bytes(range(32))


def make_log():
    log = AuditLog()
    # 0: actual exceeds the limit
    log.append(j({"actual": 10, "limit": 5}))
    # 1: actual equals the limit (integer kinds)
    log.append(j({"actual": 5, "limit": 5}))
    # 2: actual below the limit
    log.append(j({"actual": 1, "limit": 5}))
    # 3: a huge integer is numerically equal to the float of itself
    log.append(j({"actual": 2**100, "limit": float(2**100)}))
    # 4: a huge integer exceeds the float of the same power of two even
    #    though float() would round it back down
    log.append(j({"actual": 2**100 + 1, "limit": float(2**100)}))
    # 5: negative zero equals positive zero across the int/float kinds
    log.append(j({"actual": -0.0, "limit": 0}))
    # 6: float kinds, actual below limit
    log.append(j({"actual": 1.5, "limit": 2.5}))
    # 7: actual is a string — not a number
    log.append(j({"actual": "10", "limit": 5}))
    # 8: actual is a boolean — booleans are not numbers
    log.append(j({"actual": True, "limit": 0}))
    # 9: right side is a boolean
    log.append(j({"actual": 1, "limit": False}))
    # 10: right side missing
    log.append(j({"actual": 10}))
    # 11: left side missing
    log.append(j({"limit": 5}))
    # 12: left side explicitly null
    log.append(j({"actual": None, "limit": 0}))
    # 13: left side is an array, right side an object
    log.append(j({"actual": [10], "limit": {"n": 5}}))
    # 14: a path through a scalar and an out-of-range array position;
    #     the two numbers here deliberately do not satisfy gt
    log.append(j({"actual": 10, "limit": 20, "arr": [1]}))
    # 15: not JSON
    log.append(b"not json")
    # 16: repeated member name
    log.append(b'{"actual": 10, "limit": 5, "actual": 1}')
    # 17: invalid UTF-8
    log.append(b"\xff\xfe")
    # 18: encrypted entry whose plaintext would compare true
    log.encrypt(j({"actual": 10, "limit": 1}), KEY)
    # 19: ordinary unequal numbers kept past the encrypted entry
    log.append(j({"actual": 5, "limit": 6}))
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


GT = ("compare", "/actual", "gt", "/limit")
EQ = ("compare", "/actual", "eq", "/limit")


class FindWhereCompareTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_each_relation(self):
        self.assertEqual(self.bundle.find_where(GT), (0, 4))
        self.assertEqual(
            self.bundle.find_where(("compare", "/actual", "lt", "/limit")),
            (2, 6, 14, 19),
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/actual", "eq", "/limit")),
            (1, 3, 5),
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/actual", "le", "/limit")),
            (1, 2, 3, 5, 6, 14, 19),
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/actual", "ge", "/limit")),
            (0, 1, 3, 4, 5),
        )

    def test_integers_and_floats_compare_numerically(self):
        # 3's huge integer equals float(2**100) exactly as a number...
        self.assertEqual(
            self.bundle.find_where(
                ("compare", "/actual", "eq", "/limit"), 3, 4
            ),
            (3,),
        )
        # ...and 4's 2**100 + 1 survives a float threshold that would
        # round it down: a float conversion based comparison would miss.
        self.assertEqual(
            self.bundle.find_where(GT, 4, 5),
            (4,),
        )

    def test_negative_zero_equals_positive_zero(self):
        self.assertEqual(
            self.bundle.find_where(EQ, 5, 6),
            (5,),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("compare", "/actual", "le", "/limit"), 5, 6
            ),
            (5,),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("compare", "/actual", "ge", "/limit"), 5, 6
            ),
            (5,),
        )

    def test_same_pointer_on_both_ends(self):
        # Every record whose /actual resolves to a non-boolean number
        # equals itself; the right side is the same pointer, so a
        # missing /limit is irrelevant. Booleans, strings, null,
        # containers, invalid documents and the encrypted entry still
        # do not hit.
        self.assertEqual(
            self.bundle.find_where(("compare", "/actual", "eq", "/actual")),
            (0, 1, 2, 3, 4, 5, 6, 9, 10, 14, 19),
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/actual", "gt", "/actual")),
            (),
        )

    def test_non_numeric_missing_invalid_and_encrypted_never_hit(self):
        # Only the six genuinely numeric-comparable records hit gt...
        self.assertEqual(self.bundle.find_where(GT), (0, 4))
        # ...so every other index — string, boolean, null, container,
        # missing field, invalid array position, bad document, duplicate
        # member, encrypted entry — hits the negation.
        self.assertEqual(
            self.bundle.find_where(("not", GT)),
            tuple(i for i in range(20) if i not in (0, 4)),
        )

    def test_invalid_array_position_and_path_through_scalar(self):
        self.assertEqual(
            self.bundle.find_where(
                ("compare", "/arr/1", "gt", "/b/c"), 14, 15
            ),
            (),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("compare", "/arr/0", "eq", "/actual"), 14, 15
            ),
            (),
        )

    def test_empty_pointer_addresses_the_whole_document(self):
        # The root document is an object here, never a JSON number.
        self.assertEqual(
            self.bundle.find_where(("compare", "", "eq", "/actual")), ()
        )
        self.assertEqual(
            self.bundle.find_where(("compare", "/actual", "gt", "")), ()
        )

    def test_nests_in_and_or_not(self):
        self.assertEqual(
            self.bundle.find_where(
                ("and", (GT, ("compare", "/actual", "ge", "/limit")))
            ),
            (0, 4),
        )
        self.assertEqual(
            self.bundle.find_where(
                (
                    "or",
                    (
                        ("compare", "/actual", "lt", "/limit"),
                        EQ,
                    ),
                )
            ),
            (1, 2, 3, 5, 6, 14, 19),
        )
        self.assertEqual(
            self.bundle.find_where(("not", ("not", GT))),
            (0, 4),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("type", "/actual", "number"), GT))
            ),
            (0, 4),
        )

    def test_range_clipping_and_empty_range(self):
        self.assertEqual(self.bundle.find_where(GT, 1, 5), (4,))
        self.assertEqual(self.bundle.find_where(GT, 2, 2), ())
        self.assertEqual(self.bundle.find_where(GT, None, 1), (0,))

    def test_default_range_covers_retained_segment(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(GT), (4,))
        self.assertEqual(
            bundle.find_where(("not", GT)),
            tuple(i for i in range(3, 20) if i != 4),
        )
        with self.assertRaises(ValueError):
            bundle.find_where(GT, 0, 4)

    def test_result_is_ascending_duplicate_free_tuple(self):
        result = self.bundle.find_where(
            ("or", (GT, ("compare", "/limit", "le", "/actual"), EQ))
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(
            result,
            tuple(sorted(set(result))),
        )

    def test_type_errors(self):
        for expression in (
            ["compare", "/actual", "gt", "/limit"],  # node not a tuple
            (1, "/actual", "gt", "/limit"),  # operator not a string
            ("compare", 1, "gt", "/limit"),  # left pointer not a string
            ("compare", "/actual", 5, "/limit"),  # relation not a string
            ("compare", "/actual", "gt", 2),  # right pointer not a string
            ("compare", None, "gt", "/limit"),
            ("compare", "/actual", "gt", None),
        ):
            with self.assertRaises(TypeError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_value_errors(self):
        for expression in (
            ("compare",),
            ("compare", "/actual"),
            ("compare", "/actual", "gt"),
            ("compare", "/actual", "gt", "/limit", "extra"),
            ("compare", "actual", "gt", "/limit"),  # malformed left
            ("compare", "/missing", "gt", "/limit"),  # left unbound
            ("compare", "/actual", "xx", "/limit"),  # bad relation
            ("compare", "/actual", "GT", "/limit"),  # case-sensitive
            ("compare", "/actual", "gt", "limit"),  # malformed right
            ("compare", "/actual", "gt", "/missing"),  # right unbound
            ("compare", "/actual/~2", "gt", "/limit"),  # bad escape left
            ("compare", "/actual", "gt", "/limit/~2"),  # bad escape right
            ("bogus",),
            (),
        ):
            with self.assertRaises(ValueError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_validation_order_node_length_left_relation_right(self):
        # Left-pointer binding is checked before the relation's type...
        with self.assertRaises(ValueError):
            self.bundle.find_where(("compare", "/missing", 5, "/limit"))
        # ...and the relation's type before the right pointer's binding.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("compare", "/actual", 5, "/missing"))
        # The relation's support after the left pointer binds.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("compare", "/actual", "xx", "/missing"))
        # A non-string left pointer fails before the relation is read.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("compare", 7, 5, 9))

    def test_whole_expression_validated_before_lookups(self):
        # An empty range never masks an illegal branch...
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (GT, ("compare", "/missing", "gt", "/limit"))),
                2,
                2,
            )
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                (
                    "or",
                    (
                        ("compare", "/actual", "gt", "/limit"),
                        ("compare", "/actual", 5, "/limit"),
                    ),
                ),
                2,
                2,
            )
        # ...children are validated left to right, the leftmost illegal
        # one winning...
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                (
                    "and",
                    (
                        ("compare", "/missing", "gt", "/limit"),
                        ("compare", "/actual", 5, "/limit"),
                    ),
                )
            )
        # ...and the range is validated only after the whole expression.
        with self.assertRaises(ValueError):
            self.bundle.find_where(GT, 2, 1)
        with self.assertRaises(ValueError):
            self.bundle.find_where(GT, 3, 21)
        with self.assertRaises(TypeError):
            self.bundle.find_where(GT, "0", 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(GT, True, 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(GT, 0, False)

    def test_read_only_and_snapshot_stable(self):
        before = self.bundle.find_where(GT)
        self.log.append(j({"actual": 99, "limit": 1}))
        self.assertEqual(self.bundle.find_where(GT), before)
        self.assertEqual(
            make_bundle(self.log).find_where(GT),
            (0, 4, 20),
        )

    def test_frozen_snapshot_survives_append_and_prune(self):
        receipt_before = self.bundle.where_receipt(GT)
        self.log.append(j({"actual": 99, "limit": 1}))
        self.log.prune(5, self.log.seal(5))
        self.assertEqual(self.bundle.find_where(GT), (0, 4))
        self.assertTrue(verify_where_receipt(receipt_before, public_key(SEED_A)))


class WhereReceiptCompareTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = (
            "and",
            (
                GT,
                ("not", ("compare", "/actual", "eq", "/limit")),
            ),
        )
        self.receipt = self.bundle.where_receipt(self.expression)

    def test_receipt_fields(self):
        self.assertIsInstance(self.receipt, WhereReceipt)
        self.assertEqual(self.receipt.expression, self.expression)
        self.assertEqual((self.receipt.start, self.receipt.stop), (0, 20))
        self.assertEqual(self.receipt.hits, (0, 4))

    def test_verify_true_with_trusted_key(self):
        self.assertTrue(verify_where_receipt(self.receipt, public_key(SEED_A)))

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(
            verify_where_receipt(self.receipt, public_key(SEED_B))
        )

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (0,), (0, 4, 5)):
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
        # The bare receipt carries no expression signature: a swapped
        # relation verifies whenever its hits stay exactly complete.
        # Over the single-record range [1, 2) the operands are equal, so
        # "eq" and "le" (and "ge") all have the exact same hit set.
        receipt = self.bundle.where_receipt(
            ("compare", "/actual", "eq", "/limit"), 1, 2
        )
        self.assertEqual(receipt.hits, (1,))
        swapped = WhereReceipt(
            self.bundle,
            ("compare", "/actual", "le", "/limit"),
            1,
            2,
            (1,),
        )
        self.assertTrue(verify_where_receipt(swapped, public_key(SEED_A)))

    def test_constructor_validates_expression_and_range(self):
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.bundle, ("compare", "/missing", "gt", "/limit"),
                0, 20, (),
            )
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.bundle, ("compare", "/actual", "xx", "/limit"),
                0, 20, (),
            )
        with self.assertRaises(TypeError):
            WhereReceipt(
                self.bundle, ("compare", "/actual", 5, "/limit"),
                0, 20, (),
            )
        with self.assertRaises(TypeError):
            WhereReceipt(
                self.bundle, ("compare", 7, "gt", "/limit"), 0, 20, ()
            )
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.bundle, self.expression, 5, 4, ()
            )

    def test_round_trip_preserves_structure_and_bytes(self):
        expression = (
            "or",
            (
                GT,
                ("and", (EQ, ("not", ("compare", "/limit", "lt", "/actual")))),
                GT,  # repeated branch survives
                ("compare", "/actual", "eq", "/actual"),
            ),
        )
        receipt = self.bundle.where_receipt(expression)
        data = encode_where_receipt(receipt)
        restored = decode_where_receipt(data)
        self.assertEqual(restored, receipt)
        self.assertEqual(restored.expression, expression)
        self.assertEqual(encode_where_receipt(restored), data)
        self.assertTrue(verify_where_receipt(restored, public_key(SEED_A)))

    def test_empty_hits_round_trip(self):
        receipt = self.bundle.where_receipt(
            ("compare", "/actual", "lt", "/limit"), 0, 1
        )
        self.assertEqual(receipt.hits, ())
        data = encode_where_receipt(receipt)
        restored = decode_where_receipt(data)
        self.assertEqual(restored, receipt)
        self.assertEqual(encode_where_receipt(restored), data)

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
            + u64(14)  # unknown node tag (compare is 13)
            + u64(0)
            + u64(20)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_truncated_compare_node(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(13)  # compare node tag
            + blob(b"/actual")
            + u64(0)  # truncation: relation and right pointer missing
            + u64(20)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_invalid_utf8_compare_fields(self):
        for field in (
            (blob(b"\xff") + blob(b"gt") + blob(b"/limit")),
            (blob(b"/actual") + blob(b"\xff") + blob(b"/limit")),
            (blob(b"/actual") + blob(b"gt") + blob(b"\xff")),
        ):
            raw = (
                b"auditchain/where-receipt/v1\0"
                + u64(1)
                + blob(encode_signed_json_multi_index(self.bundle))
                + u64(13)
                + field
                + u64(0)
                + u64(20)
                + u64(0)
            )
            with self.assertRaises(ValueError):
                decode_where_receipt(raw)

    def test_decode_rejects_unsupported_relation(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(13)
            + blob(b"/actual")
            + blob(b"ne")
            + blob(b"/limit")
            + u64(0)
            + u64(20)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_uncovered_compare_pointers(self):
        for field in (
            (blob(b"/missing") + blob(b"gt") + blob(b"/limit")),
            (blob(b"/actual") + blob(b"gt") + blob(b"/missing")),
        ):
            raw = (
                b"auditchain/where-receipt/v1\0"
                + u64(1)
                + blob(encode_signed_json_multi_index(self.bundle))
                + u64(13)
                + field
                + u64(0)
                + u64(20)
                + u64(0)
            )
            with self.assertRaises(ValueError):
                decode_where_receipt(raw)

    def test_historical_index_queries_without_resigning(self):
        # The index encoding — and therefore its signed message — is
        # untouched by the new leaf: an index frozen before the feature
        # answers compare queries as-is and keeps identical bytes.
        data = encode_signed_json_multi_index(self.bundle)
        self.assertEqual(
            encode_signed_json_multi_index(self.bundle), data
        )
        self.assertEqual(self.bundle.find_where(GT), (0, 4))


class SignedWhereReceiptCompareTest(unittest.TestCase):
    def setUp(self):
        # One equal record, queried over [0, 1), so every parameter or
        # relation swap below keeps the exact same hit set (0,).
        log = AuditLog()
        log.append(j({"actual": 5, "limit": 5, "other": 5}))
        log.append(j({"actual": 1, "limit": 9, "other": 9}))
        self.bundle = log.signed_json_multi_index(
            ("", "/actual", "/limit", "/other"), SEED_A
        )
        self.expression = ("compare", "/actual", "eq", "/limit")
        self.receipt = self.bundle.where_receipt(self.expression, 0, 1)
        self.signed = sign_where_receipt(self.receipt, SEED_A)

    def test_signed_receipt_verifies(self):
        self.assertTrue(
            verify_signed_where_receipt(
                self.signed, public_key(SEED_A)
            )
        )

    def test_signature_binds_every_compare_parameter(self):
        # Every swap below keeps the exact same hit set (0,); each must
        # still fail against the original signature.
        for swapped_expression in (
            ("compare", "/other", "eq", "/limit"),
            ("compare", "/actual", "eq", "/other"),
            ("compare", "/limit", "eq", "/actual"),
            ("compare", "/actual", "le", "/limit"),
            ("compare", "/actual", "ge", "/limit"),
        ):
            self.assertEqual(
                self.bundle.find_where(
                    swapped_expression,
                    self.receipt.start,
                    self.receipt.stop,
                ),
                self.receipt.hits,
                msg=repr(swapped_expression),
            )
            swapped = WhereReceipt(
                self.receipt.bundle,
                swapped_expression,
                self.receipt.start,
                self.receipt.stop,
                self.receipt.hits,
            )
            bundle = SignedWhereReceipt(swapped, self.signed.signature)
            self.assertFalse(
                verify_signed_where_receipt(bundle, public_key(SEED_A)),
                msg=repr(swapped_expression),
            )

    def test_resigned_swapped_receipt_verifies(self):
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("compare", "/limit", "eq", "/actual"),
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        resigned = sign_where_receipt(swapped, SEED_A)
        self.assertTrue(
            verify_signed_where_receipt(resigned, public_key(SEED_A))
        )

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(
            verify_signed_where_receipt(
                self.signed, public_key(SEED_B)
            )
        )

    def test_verify_false_on_under_and_over_report(self):
        # Use the full bundle range so the over-reported hit (1) is
        # structurally in range.
        full = self.bundle.where_receipt(self.expression, 0, 2)
        self.assertEqual(full.hits, (0,))
        for hits in ((), (0, 1)):
            receipt = WhereReceipt(
                full.bundle,
                full.expression,
                full.start,
                full.stop,
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
