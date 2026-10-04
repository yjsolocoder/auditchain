import unittest

from auditchain import (
    AuditLog,
    decode_json_multi_index,
    decode_signed_json_multi_index,
    encode_json_multi_index,
    encode_signed_json_multi_index,
    verify_signed_json_multi_index,
)

from tests.test_signed_json_multi_index import SEED_A, j, public_key

POINTERS = ("/a", "/b", "/z")

# Expression shorthand.
def eq(pointer, value):
    return ("eq", pointer, value)


def AND(*children):
    return ("and", tuple(children))


def OR(*children):
    return ("or", tuple(children))


def NOT(child):
    return ("not", child)


def make_log():
    log = AuditLog()
    # 0: integer 1 at /a and string x at /b
    log.append(j({"a": 1, "b": "x"}))
    # 1: float 1.0 at /a and string y at /b
    log.append(j({"a": 1.0, "b": "y"}))
    # 2: boolean true at /a and string x at /b
    log.append(j({"a": True, "b": "x"}))
    # 3: string "1" at /a and string x at /b
    log.append(j({"a": "1", "b": "x"}))
    # 4: /a is the number 1 but /b is missing
    log.append(j({"a": 1, "z": 9}))
    # 5: not JSON
    log.append(b"not json")
    # 6: non-scalar at /a
    log.append(j({"a": [1], "b": "x"}))
    # 7: no queried fields
    log.append(j({"other": 1}))
    return log


class FindWhereLeafTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)

    def test_eq_leaf_matches_find(self):
        for pointer, value in (
            ("/a", 1),
            ("/a", 1.0),
            ("/a", True),
            ("/a", "1"),
            ("/b", "x"),
            ("/z", 9),
            ("/z", None),
        ):
            self.assertEqual(
                self.bundle.find_where(eq(pointer, value)),
                self.bundle.find(pointer, value),
            )

    def test_eq_non_json_missing_and_non_scalar_never_hit(self):
        # /a == 1 hits exactly entries 0, 1 and 4 (numeric equality).
        self.assertEqual(self.bundle.find_where(eq("/a", 1)), (0, 1, 4))
        # The bound pointer /z is absent from every entry but 4; a missing
        # field is never treated as null.
        self.assertEqual(self.bundle.find_where(eq("/z", None)), ())
        self.assertEqual(self.bundle.find_where(eq("/z", 1)), ())

    def test_encrypted_entries_never_hit_eq(self):
        log = AuditLog()
        log.append(j({"a": 1, "b": "x"}))
        log.encrypt(j({"a": 1, "b": "x"}), b"k" * 32)
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(eq("/a", 1)), (0,))


class FindWhereCombinatorTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)

    def test_and_matches_find_all(self):
        expression = AND(eq("/a", 1), eq("/b", "x"))
        conditions = (("/a", 1), ("/b", "x"))
        self.assertEqual(
            self.bundle.find_where(expression),
            self.bundle.find_all(conditions),
        )
        self.assertEqual(self.bundle.find_where(expression), (0,))

    def test_or_is_the_union(self):
        # /a == 1 -> (0, 1, 4); /b == "y" -> (1); union keeps one 1.
        self.assertEqual(
            self.bundle.find_where(OR(eq("/a", 1), eq("/b", "y"))),
            (0, 1, 4),
        )

    def test_or_across_separated_kinds(self):
        # Number 1 (0, 1, 4) and boolean true (2) stay separate kinds.
        self.assertEqual(
            self.bundle.find_where(OR(eq("/a", 1), eq("/a", True))),
            (0, 1, 2, 4),
        )

    def test_not_is_complement_over_the_whole_range(self):
        # Everything except the numeric-1 entries: 2, 3, 5, 6, 7.
        self.assertEqual(
            self.bundle.find_where(NOT(eq("/a", 1))), (2, 3, 5, 6, 7)
        )

    def test_negation_of_missing_field_hits_everything(self):
        # The bound pointer /z is absent from every entry but 4; missing is
        # not null, so "not /z == 1" and "not /z == null" match all eight.
        self.assertEqual(
            self.bundle.find_where(NOT(eq("/z", 1))), tuple(range(8))
        )
        self.assertEqual(
            self.bundle.find_where(NOT(eq("/z", None))), tuple(range(8))
        )
        # Sanity: /z does carry 9 in entry 4, whose negation excludes it.
        self.assertEqual(
            self.bundle.find_where(NOT(eq("/z", 9))),
            (0, 1, 2, 3, 5, 6, 7),
        )

    def test_negation_includes_non_json_missing_and_non_scalar(self):
        # /b == "x" hits 0, 2, 3, 6; its negation hits 1, 4, 5, 7 —
        # including the missing-field entry 4, non-JSON 5 and the
        # field-less entry 7.
        self.assertEqual(
            self.bundle.find_where(NOT(eq("/b", "x"))), (1, 4, 5, 7)
        )

    def test_double_negation_restores_the_result(self):
        leaf = eq("/a", 1)
        self.assertEqual(
            self.bundle.find_where(NOT(NOT(leaf))),
            self.bundle.find_where(leaf),
        )
        self.assertEqual(
            self.bundle.find_where(NOT(NOT(NOT(NOT(leaf))))),
            self.bundle.find_where(leaf),
        )

    def test_de_morgan(self):
        left = NOT(AND(eq("/a", 1), eq("/b", "x")))
        right = OR(NOT(eq("/a", 1)), NOT(eq("/b", "x")))
        self.assertEqual(
            self.bundle.find_where(left), self.bundle.find_where(right)
        )

    def test_nested_boolean_expression(self):
        # (/a == 1 and /b == "x") or /z == 9 -> entries 0 and 4.
        expression = OR(
            AND(eq("/a", 1), eq("/b", "x")),
            eq("/z", 9),
        )
        self.assertEqual(self.bundle.find_where(expression), (0, 4))

    def test_not_of_a_combinator(self):
        # not ((/a == 1) or (/b == "y")) -> neither: 2, 3, 5, 6, 7.
        self.assertEqual(
            self.bundle.find_where(NOT(OR(eq("/a", 1), eq("/b", "y")))),
            (2, 3, 5, 6, 7),
        )

    def test_empty_and_returns_whole_range(self):
        self.assertEqual(
            self.bundle.find_where(("and", ())), tuple(range(8))
        )

    def test_empty_or_returns_empty(self):
        self.assertEqual(self.bundle.find_where(("or", ())), ())

    def test_complement_of_empty_and_is_empty(self):
        self.assertEqual(self.bundle.find_where(NOT(("and", ()))), ())

    def test_repeated_branches_add_no_duplicates(self):
        leaf = eq("/a", 1)
        once = self.bundle.find_where(leaf)
        self.assertEqual(
            self.bundle.find_where(OR(leaf, leaf, leaf)), once
        )
        self.assertEqual(
            self.bundle.find_where(AND(leaf, leaf)), once
        )
        # A tautological or with its own negation covers the range once.
        self.assertEqual(
            self.bundle.find_where(OR(leaf, NOT(leaf))), tuple(range(8))
        )
        self.assertEqual(
            self.bundle.find_where(AND(leaf, NOT(leaf))), ()
        )

    def test_results_strictly_ascending_and_unique(self):
        log = AuditLog()
        for value in (1, 2, 1, 1, 2, 1):
            log.append(j({"a": value, "b": "x"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        result = bundle.find_where(
            OR(eq("/a", 1), AND(eq("/b", "x"), NOT(eq("/a", 2))))
        )
        self.assertEqual(result, tuple(sorted(set(result))))
        self.assertEqual(result, (0, 2, 3, 5))


class FindWhereRangeTest(unittest.TestCase):
    def setUp(self):
        log = AuditLog()
        for value in (1, 2, 1, 1, 3, 1):
            log.append(j({"a": value, "b": "x"}))
        self.log = log
        self.bundle = log.signed_json_multi_index(POINTERS, SEED_A)

    def test_default_range_is_retained_segment(self):
        self.assertEqual(
            self.bundle.find_where(eq("/a", 1)), (0, 2, 3, 5)
        )

    def test_explicit_half_open_ranges(self):
        leaf = eq("/a", 1)
        self.assertEqual(self.bundle.find_where(leaf, 0, 3), (0, 2))
        self.assertEqual(self.bundle.find_where(leaf, 2, 5), (2, 3))
        self.assertEqual(self.bundle.find_where(leaf, 3, 3), ())
        self.assertEqual(self.bundle.find_where(leaf, None, 3), (0, 2))
        self.assertEqual(self.bundle.find_where(leaf, 5), (5,))

    def test_not_complement_is_taken_within_the_range(self):
        # Range [1, 5): entries 1..4; /a == 1 hits 2, 3 there, so the
        # complement is (1, 4).
        self.assertEqual(
            self.bundle.find_where(NOT(eq("/a", 1)), 1, 5), (1, 4)
        )
        self.assertEqual(
            self.bundle.find_where(("and", ()), 2, 5), (2, 3, 4)
        )

    def test_empty_range_returns_empty_even_under_double_negation(self):
        self.assertEqual(self.bundle.find_where(eq("/a", 1), 3, 3), ())
        self.assertEqual(
            self.bundle.find_where(NOT(eq("/a", 1)), 3, 3), ()
        )
        self.assertEqual(self.bundle.find_where(("and", ()), 3, 3), ())

    def test_pruned_snapshot_ranges(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(
            bundle.find_where(AND(eq("/a", True), eq("/b", "x"))), (2,)
        )
        self.assertEqual(
            bundle.find_where(("and", ())), (2, 3, 4, 5, 6, 7)
        )
        self.assertEqual(
            bundle.find_where(NOT(eq("/a", True))),
            (3, 4, 5, 6, 7),
        )
        with self.assertRaises(ValueError):
            bundle.find_where(eq("/a", True), 0, 3)


class FindWhereValidationTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_log().signed_json_multi_index(POINTERS, SEED_A)

    def test_node_must_be_a_tuple(self):
        for bad in (
            ["and", ()],
            "and",
            None,
            42,
            {"op": "and"},
            (item for item in ()),
        ):
            with self.assertRaises(TypeError):
                self.bundle.find_where(bad)

    def test_children_must_be_a_tuple(self):
        for bad in (
            ("and", [eq("/a", 1)]),
            ("and", eq("/a", 1)),
            ("or", []),
            ("not", ["eq", "/a", 1]),
        ):
            with self.assertRaises(TypeError):
                self.bundle.find_where(bad)

    def test_a_child_node_must_be_a_tuple(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("and", ("/a",)))
        with self.assertRaises(TypeError):
            self.bundle.find_where(("or", (None,)))
        with self.assertRaises(TypeError):
            self.bundle.find_where(("not", "eq"))

    def test_operator_must_be_a_string(self):
        for bad in ((1,), (None, ()), (True, ()), (b"and", ())):
            with self.assertRaises(TypeError):
                self.bundle.find_where(bad)

    def test_empty_node_is_value_error(self):
        with self.assertRaises(ValueError):
            self.bundle.find_where(())
        with self.assertRaises(ValueError):
            self.bundle.find_where(("and", ((),)))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("not", ()))

    def test_unknown_operator(self):
        for bad in (("xor", ()), ("EQ", "/a", 1), ("not", ("maybe", ()))):
            with self.assertRaises(ValueError):
                self.bundle.find_where(bad)

    def test_node_length_must_match_arity(self):
        for bad in (
            ("eq",),
            ("eq", "/a"),
            ("eq", "/a", 1, 2),
            ("and",),
            ("or", (), 1),
            ("not",),
            ("not", eq("/a", 1), eq("/b", "x")),
        ):
            with self.assertRaises(ValueError):
                self.bundle.find_where(bad)

    def test_pointer_rules_match_find(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(eq(b"/a", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(eq("a", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(eq("/a~2", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(eq("/missing", 1))

    def test_value_rules_match_find(self):
        for bad in ([1], {"x": 1}, b"1", bytearray(b"1")):
            with self.assertRaises(TypeError):
                self.bundle.find_where(eq("/a", bad))
        for bad in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                self.bundle.find_where(eq("/a", bad))

    def test_range_bound_rules_match_find(self):
        expression = eq("/a", 1)
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

    def test_determined_results_do_not_mask_invalid_branches(self):
        # An empty or still validates its branches.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("or", (eq(b"/a", 1),)))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("or", (eq("/missing", 1),)))
        # An and whose first branch alone would decide still validates
        # later branches.
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                AND(eq("/a", 1), eq("/a", 2), eq(b"/a", 1))
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                AND(eq("/a", 1), eq("/a", 2), eq("/missing", 1))
            )
        # not never excuses an invalid subtree.
        with self.assertRaises(ValueError):
            self.bundle.find_where(NOT(("xor", ())))
        with self.assertRaises(TypeError):
            self.bundle.find_where(NOT(eq("/a", [1])))

    def test_empty_range_does_not_mask_invalid_expression(self):
        with self.assertRaises(ValueError):
            self.bundle.find_where(eq("/missing", 1), 3, 3)
        with self.assertRaises(TypeError):
            self.bundle.find_where(eq(b"/a", 1), 3, 3)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("or", (eq(b"/a", 1),)), 3, 3)

    def test_node_error_precedes_child_errors(self):
        # Children carried as a list fail at the node before any child is
        # inspected.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("and", [eq(b"/bad-ptr", 1)]))
        # A wrong arity at the node beats child errors beneath it.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("and", (eq("/a", 1),), "extra"))

    def test_children_errors_reported_left_to_right(self):
        # First child has a non-str pointer (TypeError); the second carries
        # a non-finite float (ValueError) — the first error wins.
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                OR(eq(b"/a", 1), eq("/a", float("nan")))
            )
        # First child has a syntax error; the second a coverage error.
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                OR(eq("bad", 1), eq("/missing", 1))
            )

    def test_expression_is_fully_validated_before_the_range(self):
        # Both the expression and the range are invalid; the expression
        # error is reported first.
        with self.assertRaises(TypeError):
            self.bundle.find_where(eq(b"/a", 1), -1, 99)
        with self.assertRaises(ValueError):
            self.bundle.find_where(eq("/missing", 1), 4, 2)


class FindWhereSnapshotAndOfflineTest(unittest.TestCase):
    def test_frozen_snapshot_survives_append_and_prune(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        expression = OR(
            AND(eq("/a", 1), eq("/b", "x")),
            NOT(eq("/b", "x")),
        )
        expected = bundle.find_where(expression)
        log.append(j({"a": 1, "b": "x"}))
        log.prune(5, log.seal(5))
        self.assertEqual(bundle.find_where(expression), expected)
        self.assertTrue(
            verify_signed_json_multi_index(bundle, public_key(SEED_A))
        )

    def test_works_off_decoded_bytes_without_log_or_key(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        index_blob = encode_json_multi_index(bundle.index)
        signed_blob = encode_signed_json_multi_index(bundle)
        decoded_index = decode_json_multi_index(index_blob)
        decoded_bundle = decode_signed_json_multi_index(signed_blob)
        expression = OR(
            AND(eq("/a", 1), eq("/b", "x")),
            eq("/z", 9),
        )
        self.assertEqual(decoded_index.find_where(expression), (0, 4))
        self.assertEqual(decoded_bundle.find_where(expression), (0, 4))
        self.assertEqual(
            decoded_bundle.find_where(expression),
            decoded_index.find_where(expression),
        )
        self.assertEqual(
            encode_json_multi_index(decoded_index), index_blob
        )
        self.assertEqual(
            encode_signed_json_multi_index(decoded_bundle), signed_blob
        )

    def test_signed_and_inner_index_always_agree(self):
        bundle = make_log().signed_json_multi_index(POINTERS, SEED_A)
        expression = NOT(
            OR(
                AND(eq("/a", 1), eq("/b", "x")),
                eq("/a", True),
            )
        )
        self.assertEqual(
            bundle.find_where(expression),
            bundle.index.find_where(expression),
        )

    def test_successful_and_failed_queries_are_read_only(self):
        bundle = make_log().signed_json_multi_index(POINTERS, SEED_A)
        blob = encode_signed_json_multi_index(bundle)
        bundle.find_where(AND(eq("/a", 1), NOT(eq("/b", "y"))))
        bundle.find_where(("and", ()))
        bundle.find_where(("or", ()))
        bundle.find_where(NOT(eq("/a", 1)), 1, 6)
        for bad in (
            lambda: bundle.find_where(["and", ()]),
            lambda: bundle.find_where(("eq", "/a")),
            lambda: bundle.find_where(("xor", ())),
            lambda: bundle.find_where(eq("/missing", 1)),
            lambda: bundle.find_where(eq("/a", float("nan"))),
            lambda: bundle.find_where(eq("/a", 1), 99),
            lambda: bundle.find_where(("or", (eq(b"/a", 1),)), 3, 3),
        ):
            with self.assertRaises((TypeError, ValueError)):
                bad()
        self.assertEqual(encode_signed_json_multi_index(bundle), blob)


if __name__ == "__main__":
    unittest.main()
