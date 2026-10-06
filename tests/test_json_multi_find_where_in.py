import dataclasses
import unittest

from auditchain import (
    AuditLog,
    SignedJsonMultiIndex,
    SignedWhereReceipt,
    WhereReceipt,
    decode_where_receipt,
    encode_signed_json_multi_index,
    encode_where_receipt,
    sign_where_receipt,
    verify_signed_json_multi_index,
    verify_signed_where_receipt,
    verify_where_receipt,
)

from tests.test_signed_json_multi_index import SEED_A, SEED_B, j, public_key

POINTERS = ("/a", "/b", "/z")

MAGIC = b"auditchain/where-receipt/v1\0"

# Expression node tags of the where-receipt framing.
TAG = {
    "eq": 0,
    "lt": 1,
    "le": 2,
    "gt": 3,
    "ge": 4,
    "and": 5,
    "or": 6,
    "not": 7,
    "prefix": 8,
    "exists": 9,
    "in": 10,
}

# Scalar value kind tags, shared with the multi-query receipt framing.
VALUE_TAG = {
    "string": 0,
    "integer": 1,
    "float": 2,
    "true": 3,
    "null": 4,
    "false": 5,
}


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


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
    # 6: non-scalar at /a
    log.append(j({"a": [1], "b": "x"}))
    # 7: no queried fields
    log.append(j({"other": 1}))
    return log


def make_bundle(log=None, seed=SEED_A):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, seed)


def raw_scalar(value):
    if isinstance(value, str):
        return u64(VALUE_TAG["string"]) + blob(value.encode("utf-8"))
    if isinstance(value, bool):
        return u64(VALUE_TAG["true" if value else "false"]) + blob(b"")
    if value is None:
        return u64(VALUE_TAG["null"]) + blob(b"")
    if isinstance(value, int):
        return u64(VALUE_TAG["integer"]) + blob(str(value).encode("ascii"))
    return u64(VALUE_TAG["float"]) + blob(repr(value).encode("ascii"))


def raw_expression(expression):
    operator = expression[0]
    if operator in ("eq", "lt", "le", "gt", "ge", "prefix"):
        _, pointer, value = expression
        return (
            u64(TAG[operator])
            + blob(pointer.encode("utf-8"))
            + raw_scalar(value)
        )
    if operator == "in":
        _, pointer, values = expression
        return (
            u64(TAG["in"])
            + blob(pointer.encode("utf-8"))
            + u64(len(values))
            + b"".join(raw_scalar(value) for value in values)
        )
    if operator in ("and", "or"):
        children = expression[1]
        return (
            u64(TAG[operator])
            + u64(len(children))
            + b"".join(raw_expression(child) for child in children)
        )
    if operator == "not":
        return u64(TAG["not"]) + raw_expression(expression[1])
    # "exists"
    return u64(TAG["exists"]) + blob(expression[1].encode("utf-8"))


def raw_receipt_bytes(bundle, expression, start, stop, hits):
    return (
        MAGIC
        + u64(1)
        + blob(encode_signed_json_multi_index(bundle))
        + raw_expression(expression)
        + u64(start)
        + u64(stop)
        + u64(len(hits))
        + b"".join(u64(hit) for hit in hits)
    )


class FindWhereInBasicsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_single_candidate_matches_eq(self):
        self.assertEqual(
            self.bundle.find_where(("in", "/a", (1,))),
            self.bundle.find_where(("eq", "/a", 1)),
        )
        self.assertEqual(self.bundle.find_where(("in", "/a", (1,))), (0, 1, 4))

    def test_any_candidate_hits(self):
        self.assertEqual(
            self.bundle.find_where(("in", "/a", (1, True))), (0, 1, 2, 4)
        )
        self.assertEqual(
            self.bundle.find_where(("in", "/a", (1, "1"))), (0, 1, 3, 4)
        )
        self.assertEqual(
            self.bundle.find_where(("in", "/b", ("x", "y"))),
            (0, 1, 2, 3, 6),
        )

    def test_result_is_ascending_without_duplicates(self):
        result = self.bundle.find_where(("in", "/a", (True, 1, "1")))
        self.assertEqual(result, (0, 1, 2, 3, 4))
        self.assertEqual(result, tuple(sorted(set(result))))

    def test_duplicate_candidates_add_no_hits(self):
        self.assertEqual(
            self.bundle.find_where(("in", "/a", (1, 1.0, 1, 1.0))),
            (0, 1, 4),
        )
        self.assertEqual(
            self.bundle.find_where(("in", "/b", ("x", "x", "y", "x"))),
            (0, 1, 2, 3, 6),
        )

    def test_empty_candidates_match_nothing(self):
        self.assertEqual(self.bundle.find_where(("in", "/a", ())), ())
        self.assertEqual(
            self.bundle.find_where(("not", ("in", "/a", ()))),
            tuple(range(len(self.log))),
        )

    def test_int_and_float_candidates_compare_by_exact_value(self):
        self.assertEqual(
            self.bundle.find_where(("in", "/a", (1.0,))), (0, 1, 4)
        )
        self.assertEqual(
            self.bundle.find_where(("in", "/a", (2, 2.0))), ()
        )

    def test_boolean_candidates_stay_apart_from_numbers(self):
        self.assertEqual(self.bundle.find_where(("in", "/a", (True,))), (2,))
        self.assertEqual(self.bundle.find_where(("in", "/a", (False,))), ())

    def test_string_candidates_are_not_unicode_normalized(self):
        log = AuditLog()
        log.append(j({"a": "é"}))  # composed U+00E9
        log.append(j({"a": "é"}))  # decomposed e + U+0301
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("in", "/a", ("é",))), (0,))
        self.assertEqual(bundle.find_where(("in", "/a", ("é",))), (1,))
        self.assertEqual(
            bundle.find_where(("in", "/a", ("é", "é"))), (0, 1)
        )

    def test_none_candidate_matches_only_explicit_null(self):
        log = AuditLog()
        log.append(j({"a": None}))
        log.append(j({"other": 1}))
        log.append(j({"a": "null"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("in", "/a", (None,))), (0,))
        self.assertEqual(
            bundle.find_where(("not", ("in", "/a", (None,)))), (1, 2)
        )

    def test_missing_field_non_json_and_non_scalar_never_hit(self):
        # Entries 5 (not JSON), 6 (array at /a) and 7 (no /a) never hit.
        self.assertEqual(
            self.bundle.find_where(("in", "/a", (1, 2))),
            (0, 1, 4),
        )
        self.assertEqual(
            self.bundle.find_where(("not", ("in", "/b", ("x", "y")))),
            (4, 5, 7),
        )

    def test_encrypted_entries_never_match(self):
        log = AuditLog()
        log.append(j({"a": 1, "b": "x"}))
        log.encrypt(j({"a": 1, "b": "x"}), b"k" * 32)
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("in", "/a", (1,))), (0,))
        self.assertEqual(bundle.find_where(("not", ("in", "/a", (1,)))), (1,))

    def test_embeds_in_and_or_not(self):
        expression = (
            "and",
            (
                ("in", "/a", (1, True)),
                ("or", (("eq", "/b", "x"), ("in", "/b", ("y", "z")))),
                ("not", ("in", "/a", (False,))),
            ),
        )
        # Entry 4 has no /b, so the or-branch drops it.
        self.assertEqual(self.bundle.find_where(expression), (0, 1, 2))
        self.assertEqual(
            self.bundle.find_where(("not", ("in", "/a", (1, True)))),
            (3, 5, 6, 7),
        )

    def test_signed_and_inner_index_agree(self):
        expression = ("and", (("in", "/a", (1, True)), ("not", ("eq", "/b", "y"))))
        self.assertEqual(
            self.bundle.find_where(expression),
            self.bundle.index.find_where(expression),
        )


class FindWhereInRangeTest(unittest.TestCase):
    def setUp(self):
        log = AuditLog()
        for value in (1, 2, 1, 1, 3, 1):
            log.append(j({"a": value, "b": "x"}))
        self.log = log
        self.bundle = log.signed_json_multi_index(POINTERS, SEED_A)

    def test_default_range_covers_retained_segment(self):
        self.assertEqual(
            self.bundle.find_where(("in", "/a", (1, 3))), (0, 2, 3, 4, 5)
        )

    def test_explicit_half_open_ranges(self):
        expression = ("in", "/a", (1, 3))
        self.assertEqual(self.bundle.find_where(expression, 0, 3), (0, 2))
        self.assertEqual(self.bundle.find_where(expression, 2, 5), (2, 3, 4))
        self.assertEqual(self.bundle.find_where(expression, 3, 3), ())
        self.assertEqual(self.bundle.find_where(expression, None, 3), (0, 2))
        self.assertEqual(self.bundle.find_where(expression, 4), (4, 5))

    def test_not_complement_is_clipped_to_the_range(self):
        self.assertEqual(
            self.bundle.find_where(("not", ("in", "/a", (1, 3))), 0, 3),
            (1,),
        )
        self.assertEqual(
            self.bundle.find_where(("not", ("in", "/a", (1, 3))), 3, 3), ()
        )

    def test_pruned_snapshot_ranges(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("in", "/a", (1, True))), (2, 4))
        self.assertEqual(
            bundle.find_where(("not", ("in", "/a", (1, True)))),
            (3, 5, 6, 7),
        )
        with self.assertRaises(ValueError):
            bundle.find_where(("in", "/a", (1,)), 0, 3)


class FindWhereInArgumentsTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()

    def test_node_length_must_be_three(self):
        for bad in (("in", "/a"), ("in", "/a", (1,), 2), ("in",)):
            with self.assertRaises(ValueError):
                self.bundle.find_where(bad)

    def test_pointer_rules_match_eq(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", b"/a", (1,)))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "a", (1,)))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/a~2", (1,)))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/missing", (1,)))

    def test_candidates_must_be_a_tuple(self):
        for bad in ([1], "1", 1, None, True, {1}, {"x": 1}, b"1"):
            with self.assertRaises(TypeError):
                self.bundle.find_where(("in", "/a", bad))

    def test_candidates_must_be_supported_scalars(self):
        for bad in ([1], {"x": 1}, b"1", bytearray(b"1"), (1,), object()):
            with self.assertRaises(TypeError):
                self.bundle.find_where(("in", "/a", (bad,)))

    def test_candidate_floats_must_be_finite(self):
        for bad in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                self.bundle.find_where(("in", "/a", (bad,)))

    def test_range_bound_rules_match_eq(self):
        expression = ("in", "/a", (1,))
        with self.assertRaises(TypeError):
            self.bundle.find_where(expression, True)
        with self.assertRaises(TypeError):
            self.bundle.find_where(expression, 0, "3")
        with self.assertRaises(ValueError):
            self.bundle.find_where(expression, -1)
        with self.assertRaises(ValueError):
            self.bundle.find_where(expression, 0, 99)
        with self.assertRaises(ValueError):
            self.bundle.find_where(expression, 4, 2)

    def test_length_and_pointer_precede_candidates(self):
        # A bad node length wins over a bad pointer and bad candidates.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", b"/a", [1], "extra"))
        # A bad pointer wins over a non-tuple candidate container.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", b"/a", [1]))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/missing", [1]))
        # The container check wins over a bad candidate.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", "/a", [float("nan")]))
        # Candidates are checked left to right.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/a", (float("nan"), [1])))
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", "/a", ([1], float("nan"))))

    def test_node_errors_precede_child_errors(self):
        with self.assertRaises(ValueError):
            self.bundle.find_where(("and", (("in", "/a"), ("eq", b"/a", 1))))
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (("in", "/a", [1]), ("eq", "/missing", 1)))
            )

    def test_children_are_checked_left_to_right(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (("in", "/a", [1]), ("in", "/missing", (1,))))
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (("in", "/missing", (1,)), ("in", "/a", [1])))
            )

    def test_range_is_checked_last(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", "/a", [1]), 0, 99)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/a", (1,)), 0, 99)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", b"/a", (1,)), True)

    def test_invalid_branches_are_not_masked(self):
        # Empty candidates, an empty range and an already determined
        # conjunction never mask an invalid branch.
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (("in", "/a", ()), ("in", "/missing", (1,))))
            )
        contradicting = ("and", (("eq", "/a", 1), ("eq", "/a", 2)))
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (contradicting, ("in", "/missing", (1,))))
            )
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (contradicting, ("in", "/a", [1])))
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/missing", (1,)), 3, 3)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", "/a", [1]), 3, 3)


class FindWhereInSnapshotAndOfflineTest(unittest.TestCase):
    def test_frozen_snapshot_survives_append_and_prune(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        expression = ("in", "/a", (1, True))
        expected = bundle.find_where(expression)
        log.append(j({"a": 1, "b": "x"}))
        log.prune(5, log.seal(5))
        self.assertEqual(bundle.find_where(expression), expected)
        self.assertTrue(
            verify_signed_json_multi_index(bundle, public_key(SEED_A))
        )

    def test_works_off_decoded_bytes_without_log_or_key(self):
        from auditchain import (
            decode_json_multi_index,
            decode_signed_json_multi_index,
            encode_json_multi_index,
        )

        bundle = make_bundle()
        index_blob = encode_json_multi_index(bundle.index)
        signed_blob = encode_signed_json_multi_index(bundle)
        decoded_index = decode_json_multi_index(index_blob)
        decoded_bundle = decode_signed_json_multi_index(signed_blob)
        expression = ("in", "/a", (1, True))
        self.assertEqual(decoded_index.find_where(expression), (0, 1, 2, 4))
        self.assertEqual(decoded_bundle.find_where(expression), (0, 1, 2, 4))
        # Re-encoding is byte-identical: queries change nothing.
        self.assertEqual(encode_json_multi_index(decoded_index), index_blob)
        self.assertEqual(
            encode_signed_json_multi_index(decoded_bundle), signed_blob
        )

    def test_successful_and_failed_queries_are_read_only(self):
        bundle = make_bundle()
        blob_ = encode_signed_json_multi_index(bundle)
        bundle.find_where(("in", "/a", (1, True)))
        bundle.find_where(("in", "/a", ()))
        bundle.find_where(("not", ("in", "/b", ("x", "y"))), 1, 3)
        for bad in (
            lambda: bundle.find_where(("in", "/a")),
            lambda: bundle.find_where(("in", "/a", [1])),
            lambda: bundle.find_where(("in", "/missing", (1,))),
            lambda: bundle.find_where(("in", "/a", (float("nan"),))),
            lambda: bundle.find_where(("in", "/a", (1,)), 99),
        ):
            with self.assertRaises((TypeError, ValueError)):
                bad()
        self.assertEqual(encode_signed_json_multi_index(bundle), blob_)


class WhereReceiptInTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.key = public_key(SEED_A)

    def test_receipt_issues_and_verifies(self):
        receipt = self.bundle.where_receipt(("in", "/a", (1, True)))
        self.assertIsInstance(receipt, WhereReceipt)
        self.assertEqual(receipt.expression, ("in", "/a", (1, True)))
        self.assertEqual(receipt.hits, (0, 1, 2, 4))
        self.assertEqual((receipt.start, receipt.stop), (0, 8))
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_receipt_preserves_candidate_order_and_duplicates(self):
        expression = ("in", "/a", (True, 1, True, 1.0))
        receipt = self.bundle.where_receipt(expression)
        self.assertEqual(receipt.expression, expression)
        self.assertEqual(receipt.hits, (0, 1, 2, 4))
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_empty_candidates_and_empty_range_verify(self):
        receipt = self.bundle.where_receipt(("in", "/a", ()))
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_where_receipt(receipt, self.key))
        receipt = self.bundle.where_receipt(("in", "/a", (1,)), 3, 3)
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_nested_expression_receipt_verifies(self):
        expression = (
            "or",
            (
                ("and", (("in", "/a", (1, True)), ("eq", "/b", "x"))),
                ("not", ("in", "/b", ("x", "y"))),
            ),
        )
        receipt = self.bundle.where_receipt(expression, 1, 7)
        self.assertEqual(
            receipt.hits, self.bundle.find_where(expression, 1, 7)
        )
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_under_and_over_report_fail(self):
        expression = ("in", "/a", (1, True))
        for hits in ((0, 1, 2), (0, 1, 2, 4, 5), (1, 2, 4), ()):
            receipt = WhereReceipt(self.bundle, expression, 0, 8, hits)
            self.assertFalse(verify_where_receipt(receipt, self.key))

    def test_wrong_key_and_tampered_evidence_fail(self):
        receipt = self.bundle.where_receipt(("in", "/a", (1, True)))
        self.assertFalse(verify_where_receipt(receipt, public_key(SEED_B)))
        other = make_bundle(seed=SEED_B)
        repackaged = SignedJsonMultiIndex(
            receipt.bundle.index, other.signature
        )
        tampered = WhereReceipt(
            repackaged,
            receipt.expression,
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        self.assertFalse(verify_where_receipt(tampered, self.key))

    def test_unsigned_receipt_tolerates_equivalent_expression(self):
        # The bare receipt authenticates no expression: reordering the
        # candidates or re-spelling a number keeps the same complete
        # result, so the edited receipt still verifies.
        receipt = self.bundle.where_receipt(("in", "/a", (True, 1)))
        reordered = WhereReceipt(
            receipt.bundle,
            ("in", "/a", (1, True)),
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        self.assertTrue(verify_where_receipt(reordered, self.key))
        respelled = WhereReceipt(
            receipt.bundle,
            ("in", "/a", (True, 1.0)),
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        self.assertTrue(verify_where_receipt(respelled, self.key))

    def test_receipt_validates_like_find_where(self):
        with self.assertRaises(TypeError):
            self.bundle.where_receipt(("in", "/a", [1]))
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(("in", "/missing", (1,)))
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(("in", "/a", (float("nan"),)))
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(("in", "/a", (1,)), 0, 99)


class WhereReceiptInCodecTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.key = public_key(SEED_A)

    def test_roundtrip_preserves_candidates_exactly(self):
        expression = ("in", "/a", (True, 1, True, 1.0, "1", None))
        receipt = self.bundle.where_receipt(expression)
        blob_ = encode_where_receipt(receipt)
        decoded = decode_where_receipt(blob_)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.expression, expression)
        for value, original in zip(decoded.expression[2], expression[2]):
            self.assertIs(type(value), type(original))
        self.assertEqual(encode_where_receipt(decoded), blob_)
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_negative_zero_candidate_keeps_sign(self):
        log = AuditLog()
        log.append(j({"a": 0.0, "b": "x"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("in", "/a", (-0.0, 1)))
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertEqual(repr(decoded.expression[2][0]), "-0.0")
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_big_integer_and_string_candidates_roundtrip(self):
        big = 2**90 + 7
        log = AuditLog()
        log.append(j({"a": big, "b": "héllo"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("in", "/a", (big, 1)))
        self.assertEqual(receipt.hits, (0,))
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertIs(type(decoded.expression[2][0]), int)
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_empty_candidates_roundtrip(self):
        receipt = self.bundle.where_receipt(("in", "/a", ()))
        blob_ = encode_where_receipt(receipt)
        decoded = decode_where_receipt(blob_)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.expression, ("in", "/a", ()))
        self.assertEqual(encode_where_receipt(decoded), blob_)

    def test_raw_layout(self):
        expression = ("in", "/a", (1, "x"))
        receipt = self.bundle.where_receipt(expression)
        blob_ = encode_where_receipt(receipt)
        expected = raw_receipt_bytes(
            self.bundle, expression, receipt.start, receipt.stop, receipt.hits
        )
        self.assertEqual(blob_, expected)
        self.assertEqual(decode_where_receipt(blob_), receipt)

    def test_old_expressions_keep_their_encoding(self):
        # Expressions without an "in" node encode exactly as before.
        for expression in (
            ("eq", "/a", 1),
            ("and", (("eq", "/a", 1), ("not", ("eq", "/b", "y")))),
            ("or", (("lt", "/a", 2), ("prefix", "/b", "x"), ("exists", "/z"))),
        ):
            receipt = self.bundle.where_receipt(expression)
            blob_ = encode_where_receipt(receipt)
            expected = raw_receipt_bytes(
                self.bundle,
                expression,
                receipt.start,
                receipt.stop,
                receipt.hits,
            )
            self.assertEqual(blob_, expected)
            self.assertEqual(decode_where_receipt(blob_), receipt)

    def test_nested_in_nodes_roundtrip(self):
        expression = (
            "and",
            (
                ("in", "/a", (1, True)),
                ("or", (("in", "/b", ("x", "y")), ("not", ("in", "/z", (9,))))),
            ),
        )
        receipt = self.bundle.where_receipt(expression)
        blob_ = encode_where_receipt(receipt)
        decoded = decode_where_receipt(blob_)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.expression, expression)
        self.assertEqual(encode_where_receipt(decoded), blob_)
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_later_appends_and_prunes_do_not_change_bytes(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("in", "/a", (1, True)))
        blob_ = encode_where_receipt(receipt)
        log.append(j({"a": 1, "b": "x"}))
        log.prune(2, log.seal(2))
        self.assertEqual(encode_where_receipt(receipt), blob_)
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_decode_rejects_non_bytes(self):
        blob_ = encode_where_receipt(self.bundle.where_receipt(("in", "/a", (1,))))
        for bad in ("x", 1, None, bytearray(blob_), memoryview(blob_)):
            with self.assertRaises(TypeError):
                decode_where_receipt(bad)

    def test_truncated_in_node_rejected(self):
        receipt = self.bundle.where_receipt(("in", "/a", (1, True)))
        blob_ = encode_where_receipt(receipt)
        for cut in range(len(MAGIC), len(blob_)):
            with self.assertRaises(ValueError):
                decode_where_receipt(blob_[:cut])
        with self.assertRaises(ValueError):
            decode_where_receipt(blob_ + b"\x00")

    def test_illegal_decoded_in_node_rejected(self):
        bundle_blob = blob(encode_signed_json_multi_index(self.bundle))

        def raw_with_expression(expression_bytes):
            return (
                MAGIC
                + u64(1)
                + bundle_blob
                + expression_bytes
                + u64(0)
                + u64(8)
                + u64(0)
            )

        def raw_in(pointer_bytes, candidates):
            return (
                u64(TAG["in"])
                + blob(pointer_bytes)
                + u64(len(candidates))
                + b"".join(candidates)
            )

        # Invalid UTF-8 pointer.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(raw_in(b"\xff", []))
            )
        # A pointer the index does not cover.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(
                    raw_in(b"/missing", [raw_scalar(1)])
                )
            )
        # An unknown candidate value tag.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(raw_in(b"/a", [u64(9) + blob(b"")]))
            )
        # A non-canonical integer candidate.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(
                    raw_in(b"/a", [u64(VALUE_TAG["integer"]) + blob(b"007")])
                )
            )
        # A non-finite / non-canonical float candidate.
        for key in (b"inf", b"nan", b"1.50"):
            with self.assertRaises(ValueError):
                decode_where_receipt(
                    raw_with_expression(
                        raw_in(b"/a", [u64(VALUE_TAG["float"]) + blob(key)])
                    )
                )
        # A non-empty boolean candidate blob.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(
                    raw_in(b"/a", [u64(VALUE_TAG["true"]) + blob(b"x")])
                )
            )
        # Invalid UTF-8 string candidate.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(
                    raw_in(b"/a", [u64(VALUE_TAG["string"]) + blob(b"\xff")])
                )
            )
        # A declared candidate count that does not match the candidates.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(
                    u64(TAG["in"])
                    + blob(b"/a")
                    + u64(2)
                    + raw_scalar(1)
                )
            )

    def test_decoded_receipt_is_immutable(self):
        receipt = self.bundle.where_receipt(("in", "/a", (1,)))
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            decoded.hits = ()


class SignedWhereReceiptInTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.key = public_key(SEED_A)

    def test_sign_and_verify(self):
        receipt = self.bundle.where_receipt(("in", "/a", (1, True)))
        signed = sign_where_receipt(receipt, SEED_A)
        self.assertIsInstance(signed, SignedWhereReceipt)
        self.assertTrue(verify_signed_where_receipt(signed, self.key))

    def test_repeated_signing_is_byte_identical(self):
        from auditchain import encode_signed_where_receipt

        receipt = self.bundle.where_receipt(("in", "/a", (True, 1, True)))
        first = sign_where_receipt(receipt, SEED_A)
        second = sign_where_receipt(receipt, SEED_A)
        self.assertEqual(first, second)
        self.assertEqual(
            encode_signed_where_receipt(first),
            encode_signed_where_receipt(second),
        )

    def test_reordered_candidates_fail_against_signature(self):
        # The hits are identical, but the signature binds the candidate
        # order, so the reordered expression fails verification.
        receipt = self.bundle.where_receipt(("in", "/a", (True, 1)))
        signed = sign_where_receipt(receipt, SEED_A)
        reordered = WhereReceipt(
            receipt.bundle,
            ("in", "/a", (1, True)),
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        self.assertEqual(reordered.hits, receipt.hits)
        tampered = SignedWhereReceipt(reordered, signed.signature)
        self.assertFalse(verify_signed_where_receipt(tampered, self.key))

    def test_int_candidate_respelled_as_float_fails(self):
        # 1 and 1.0 hit the same entries, but the signature binds the
        # scalar type, so the re-spelled candidate fails verification.
        receipt = self.bundle.where_receipt(("in", "/a", (1, True)))
        signed = sign_where_receipt(receipt, SEED_A)
        respelled = WhereReceipt(
            receipt.bundle,
            ("in", "/a", (1.0, True)),
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        self.assertEqual(respelled.hits, receipt.hits)
        tampered = SignedWhereReceipt(respelled, signed.signature)
        self.assertFalse(verify_signed_where_receipt(tampered, self.key))

    def test_dropped_duplicate_candidate_fails(self):
        receipt = self.bundle.where_receipt(("in", "/a", (1, 1, True)))
        signed = sign_where_receipt(receipt, SEED_A)
        dropped = WhereReceipt(
            receipt.bundle,
            ("in", "/a", (1, True)),
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        tampered = SignedWhereReceipt(dropped, signed.signature)
        self.assertFalse(verify_signed_where_receipt(tampered, self.key))

    def test_wrong_key_fails(self):
        receipt = self.bundle.where_receipt(("in", "/a", (1,)))
        signed = sign_where_receipt(receipt, SEED_A)
        self.assertFalse(
            verify_signed_where_receipt(signed, public_key(SEED_B))
        )

    def test_signed_receipt_roundtrip_bytes(self):
        from auditchain import (
            decode_signed_where_receipt,
            encode_signed_where_receipt,
        )

        receipt = self.bundle.where_receipt(
            ("and", (("in", "/a", (1, True)), ("eq", "/b", "x")))
        )
        signed = sign_where_receipt(receipt, SEED_A)
        blob_ = encode_signed_where_receipt(signed)
        decoded = decode_signed_where_receipt(blob_)
        self.assertEqual(decoded, signed)
        self.assertEqual(encode_signed_where_receipt(decoded), blob_)
        self.assertTrue(verify_signed_where_receipt(decoded, self.key))


if __name__ == "__main__":
    unittest.main()
