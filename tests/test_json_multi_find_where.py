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


class FindWhereBasicsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)

    def test_single_eq_leaf_matches_find(self):
        expression = ("eq", "/a", 1)
        self.assertEqual(
            self.bundle.find_where(expression),
            self.bundle.find("/a", 1),
        )
        self.assertEqual(self.bundle.find_where(expression), (0, 1, 4))

    def test_and_intersects(self):
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("eq", "/a", 1), ("eq", "/b", "x")))
            ),
            (0,),
        )

    def test_or_unions(self):
        self.assertEqual(
            self.bundle.find_where(
                ("or", (("eq", "/a", True), ("eq", "/b", "y")))
            ),
            (1, 2),
        )

    def test_not_complements_within_range(self):
        self.assertEqual(
            self.bundle.find_where(("not", ("eq", "/a", 1))),
            (2, 3, 5, 6, 7),
        )
        self.assertEqual(
            self.bundle.find_where(("not", ("eq", "/a", 1)), 1, 4),
            (2, 3),
        )

    def test_nested_combinations(self):
        expression = (
            "and",
            (
                ("or", (("eq", "/a", 1), ("eq", "/a", True))),
                ("not", ("eq", "/b", "y")),
            ),
        )
        self.assertEqual(self.bundle.find_where(expression), (0, 2, 4))

    def test_empty_and_returns_whole_range(self):
        self.assertEqual(
            self.bundle.find_where(("and", ())), tuple(range(len(self.log)))
        )
        self.assertEqual(self.bundle.find_where(("and", ()), 2, 5), (2, 3, 4))

    def test_empty_or_returns_empty(self):
        self.assertEqual(self.bundle.find_where(("or", ())), ())

    def test_double_negation_restores_result(self):
        leaf = ("eq", "/a", 1)
        self.assertEqual(
            self.bundle.find_where(("not", ("not", leaf))),
            self.bundle.find_where(leaf),
        )

    def test_duplicate_branches_add_no_duplicates(self):
        leaf = ("eq", "/a", 1)
        result = self.bundle.find_where(("or", (leaf, leaf, leaf)))
        self.assertEqual(result, (0, 1, 4))
        self.assertEqual(result, tuple(sorted(set(result))))
        self.assertEqual(
            self.bundle.find_where(("and", (leaf, leaf))), result
        )

    def test_numeric_kinds_and_cross_kind_number_equality(self):
        # 1 and 1.0 are the same JSON number; true and "1" are not.
        self.assertEqual(
            self.bundle.find_where(("eq", "/a", 1.0)), (0, 1, 4)
        )
        self.assertEqual(self.bundle.find_where(("eq", "/a", True)), (2,))
        self.assertEqual(self.bundle.find_where(("eq", "/a", "1")), (3,))

    def test_missing_field_non_json_and_non_scalar_miss_eq_hit_not(self):
        # Entries 4 (missing /b), 5 (not JSON) and 6 (array at /a) never
        # match the eq leaf but do match its negation.
        self.assertEqual(
            self.bundle.find_where(("not", ("eq", "/b", "x"))),
            (1, 4, 5, 7),
        )

    def test_missing_field_is_not_null(self):
        log = AuditLog()
        log.append(j({"a": None}))
        log.append(j({"other": 1}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("eq", "/a", None)), (0,))
        self.assertEqual(bundle.find_where(("not", ("eq", "/a", None))), (1,))

    def test_encrypted_entries_never_match_eq(self):
        log = AuditLog()
        log.append(j({"a": 1, "b": "x"}))
        log.encrypt(j({"a": 1, "b": "x"}), b"k" * 32)
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("eq", "/a", 1)), (0,))
        self.assertEqual(bundle.find_where(("not", ("eq", "/a", 1))), (1,))

    def test_signed_and_inner_index_agree(self):
        expression = (
            "and",
            (("eq", "/a", 1), ("not", ("eq", "/b", "y"))),
        )
        self.assertEqual(
            self.bundle.find_where(expression),
            self.bundle.index.find_where(expression),
        )


class FindWhereRangeTest(unittest.TestCase):
    def setUp(self):
        log = AuditLog()
        for value in (1, 2, 1, 1, 3, 1):
            log.append(j({"a": value, "b": "x"}))
        self.log = log
        self.bundle = log.signed_json_multi_index(POINTERS, SEED_A)

    def test_default_range_covers_retained_segment(self):
        self.assertEqual(
            self.bundle.find_where(("eq", "/a", 1)), (0, 2, 3, 5)
        )

    def test_explicit_half_open_ranges(self):
        expression = ("eq", "/a", 1)
        self.assertEqual(self.bundle.find_where(expression, 0, 3), (0, 2))
        self.assertEqual(self.bundle.find_where(expression, 2, 5), (2, 3))
        self.assertEqual(self.bundle.find_where(expression, 3, 3), ())
        self.assertEqual(self.bundle.find_where(expression, None, 3), (0, 2))
        self.assertEqual(self.bundle.find_where(expression, 5), (5,))

    def test_not_complement_is_clipped_to_the_range(self):
        self.assertEqual(
            self.bundle.find_where(("not", ("eq", "/a", 1)), 1, 5),
            (1, 4),
        )
        self.assertEqual(
            self.bundle.find_where(("not", ("eq", "/a", 1)), 3, 3), ()
        )

    def test_pruned_snapshot_ranges(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("eq", "/a", True)), (2,))
        self.assertEqual(
            bundle.find_where(("and", ())), (2, 3, 4, 5, 6, 7)
        )
        with self.assertRaises(ValueError):
            bundle.find_where(("eq", "/a", True), 0, 3)


class FindWhereArgumentsTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_log().signed_json_multi_index(POINTERS, SEED_A)

    def test_node_must_be_a_tuple(self):
        for bad in (["eq", "/a", 1], "eq", None, 1, {"op": "eq"}):
            with self.assertRaises(TypeError):
                self.bundle.find_where(bad)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("not", ["eq", "/a", 1]))

    def test_empty_node_is_a_value_error(self):
        with self.assertRaises(ValueError):
            self.bundle.find_where(())
        with self.assertRaises(ValueError):
            self.bundle.find_where(("and", ((),)))

    def test_operator_must_be_a_string(self):
        for bad in ((1, (("eq", "/a", 1),)), (None,), (b"eq", "/a", 1)):
            with self.assertRaises(TypeError):
                self.bundle.find_where(bad)

    def test_unknown_operator_is_a_value_error(self):
        for bad in (("EQ", "/a", 1), ("xor", (("eq", "/a", 1),)), ("",)):
            with self.assertRaises(ValueError):
                self.bundle.find_where(bad)

    def test_node_length_must_match_the_operator(self):
        for bad in (
            ("eq", "/a"),
            ("eq", "/a", 1, 2),
            ("and",),
            ("and", (("eq", "/a", 1),), ()),
            ("or",),
            ("not",),
            ("not", ("eq", "/a", 1), ("eq", "/a", 1)),
        ):
            with self.assertRaises(ValueError):
                self.bundle.find_where(bad)

    def test_children_must_be_a_tuple(self):
        for bad in (
            ("and", ["eq", "/a", 1]),
            ("or", ("eq", "/a", 1)),
            ("and", None),
        ):
            with self.assertRaises(TypeError):
                self.bundle.find_where(bad)

    def test_pointer_rules_match_find(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("eq", b"/a", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("eq", "a", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("eq", "/a~2", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("eq", "/missing", 1))

    def test_value_rules_match_find(self):
        for bad in ([1], {"x": 1}, b"1", bytearray(b"1")):
            with self.assertRaises(TypeError):
                self.bundle.find_where(("eq", "/a", bad))
        for bad in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                self.bundle.find_where(("eq", "/a", bad))

    def test_range_bound_rules_match_find(self):
        expression = ("eq", "/a", 1)
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

    def test_node_errors_precede_child_errors(self):
        # A bad operator on the parent wins over a bad child.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("bogus", (("eq", b"/a", 1),)))
        # A bad node length wins over a bad child.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("and", (("eq", b"/a", 1),), "extra"))

    def test_children_are_checked_left_to_right(self):
        # The TypeError of the first child precedes the second's ValueError.
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (("eq", b"/a", 1), ("eq", "/missing", 1)))
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (("eq", "/missing", 1), ("eq", b"/a", 1)))
            )

    def test_range_is_checked_last(self):
        # An invalid expression reports its own error even with an invalid
        # range, and a valid expression reports the range error.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("eq", "/missing", 1), 0, 99)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("eq", "/a", 1), 0, 99)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("eq", b"/a", 1), True)

    def test_invalid_branches_are_not_masked(self):
        # The first leaf already determines an empty conjunction, and the
        # range is empty; the later invalid branch must still raise.
        contradicting = ("and", (("eq", "/a", 1), ("eq", "/a", 2)))
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (contradicting, ("eq", "/missing", 1)))
            )
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (contradicting, ("eq", "/a", [1])))
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(("eq", "/missing", 1), 3, 3)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("eq", "/a", [1]), 3, 3)


class FindWhereComparisonTest(unittest.TestCase):
    def setUp(self):
        log = AuditLog()
        # 0: int 1
        log.append(j({"a": 1, "b": "x"}))
        # 1: float 1.5
        log.append(j({"a": 1.5, "b": "y"}))
        # 2: int 2
        log.append(j({"a": 2, "b": "x"}))
        # 3: float 2.0 (the JSON number 2)
        log.append(j({"a": 2.0, "b": "x"}))
        # 4: boolean true (not a number)
        log.append(j({"a": True, "b": "x"}))
        # 5: string "2" (not a number)
        log.append(j({"a": "2", "b": "x"}))
        # 6: null (not a number)
        log.append(j({"a": None, "b": "x"}))
        # 7: array (non-scalar)
        log.append(j({"a": [2], "b": "x"}))
        # 8: missing /a
        log.append(j({"b": "x"}))
        # 9: not JSON
        log.append(b"not json")
        self.log = log
        self.bundle = log.signed_json_multi_index(POINTERS, SEED_A)

    def test_lt_le_gt_ge(self):
        self.assertEqual(self.bundle.find_where(("lt", "/a", 2)), (0, 1))
        self.assertEqual(
            self.bundle.find_where(("le", "/a", 2)), (0, 1, 2, 3)
        )
        self.assertEqual(
            self.bundle.find_where(("gt", "/a", 1)), (1, 2, 3)
        )
        self.assertEqual(
            self.bundle.find_where(("ge", "/a", 2)), (2, 3)
        )

    def test_float_threshold_compares_across_kinds(self):
        self.assertEqual(self.bundle.find_where(("lt", "/a", 1.5)), (0,))
        self.assertEqual(
            self.bundle.find_where(("le", "/a", 1.5)), (0, 1)
        )
        self.assertEqual(
            self.bundle.find_where(("gt", "/a", 1.5)), (2, 3)
        )
        self.assertEqual(
            self.bundle.find_where(("ge", "/a", 2.0)), (2, 3)
        )

    def test_big_integer_threshold_does_not_round(self):
        log = AuditLog()
        log.append(j({"a": 9007199254740992}))  # 0: exactly 2**53
        log.append(j({"a": 9007199254740993}))  # 1: 2**53 + 1
        log.append(j({"a": 9007199254740994.0}))  # 2: 2**53 + 2
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        # 2**53 + 1 is not representable as a float; it must still
        # compare strictly greater than the float 2**53.
        self.assertEqual(
            bundle.find_where(("gt", "/a", 9007199254740992.0)), (1, 2)
        )
        self.assertEqual(
            bundle.find_where(("lt", "/a", 9007199254740993)), (0,)
        )
        self.assertEqual(
            bundle.find_where(("ge", "/a", 9007199254740993)), (1, 2)
        )
        self.assertEqual(
            bundle.find_where(("le", "/a", 9007199254740993)), (0, 1)
        )

    def test_zero_threshold_matches_both_zero_spellings(self):
        log = AuditLog()
        log.append(j({"a": 0}))
        log.append(j({"a": -0.0}))
        log.append(j({"a": 0.5}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("le", "/a", 0)), (0, 1))
        self.assertEqual(bundle.find_where(("ge", "/a", -0.0)), (0, 1, 2))
        self.assertEqual(bundle.find_where(("lt", "/a", 0.0)), ())
        self.assertEqual(bundle.find_where(("gt", "/a", 0)), (2,))

    def test_non_numeric_targets_miss_comparison_hit_not(self):
        # Entries 4..9 (bool, string, null, array, missing, non-JSON)
        # never match a comparison leaf but do match its negation.
        for operator in ("lt", "le", "gt", "ge"):
            self.assertEqual(
                self.bundle.find_where((operator, "/a", 2)),
                self.bundle.find_where(
                    ("not", ("not", (operator, "/a", 2)))
                ),
            )
        self.assertEqual(
            self.bundle.find_where(("not", ("ge", "/a", 1))),
            (4, 5, 6, 7, 8, 9),
        )

    def test_encrypted_entries_never_match_comparison(self):
        log = AuditLog()
        log.append(j({"a": 1, "b": "x"}))
        log.encrypt(j({"a": 2, "b": "x"}), b"k" * 32)
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("ge", "/a", 1)), (0,))
        self.assertEqual(bundle.find_where(("not", ("ge", "/a", 1))), (1,))

    def test_and_expresses_closed_and_open_intervals(self):
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("ge", "/a", 1), ("le", "/a", 2)))
            ),
            (0, 1, 2, 3),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("gt", "/a", 1), ("lt", "/a", 2)))
            ),
            (1,),
        )

    def test_combines_with_eq_and_or(self):
        expression = (
            "or",
            (
                ("and", (("ge", "/a", 2), ("eq", "/b", "x"))),
                ("eq", "/b", "y"),
            ),
        )
        self.assertEqual(self.bundle.find_where(expression), (1, 2, 3))

    def test_duplicate_comparison_branches_add_no_duplicates(self):
        leaf = ("lt", "/a", 2)
        result = self.bundle.find_where(("or", (leaf, leaf, leaf)))
        self.assertEqual(result, (0, 1))
        self.assertEqual(result, tuple(sorted(set(result))))

    def test_range_clips_comparison_hits(self):
        self.assertEqual(
            self.bundle.find_where(("le", "/a", 2), 1, 3), (1, 2)
        )
        self.assertEqual(self.bundle.find_where(("le", "/a", 2), 3, 3), ())
        self.assertEqual(
            self.bundle.find_where(("le", "/a", 2), None, 2), (0, 1)
        )

    def test_signed_and_inner_index_agree(self):
        expression = ("and", (("gt", "/a", 1), ("not", ("eq", "/b", "y"))))
        self.assertEqual(
            self.bundle.find_where(expression),
            self.bundle.index.find_where(expression),
        )


class FindWhereComparisonArgumentsTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_log().signed_json_multi_index(POINTERS, SEED_A)

    def test_threshold_must_be_a_number(self):
        for operator in ("lt", "le", "gt", "ge"):
            for bad in (True, False, "1", None, [1], {"x": 1}, b"1"):
                with self.assertRaises(TypeError):
                    self.bundle.find_where((operator, "/a", bad))

    def test_threshold_must_be_finite(self):
        for operator in ("lt", "le", "gt", "ge"):
            for bad in (float("nan"), float("inf"), -float("inf")):
                with self.assertRaises(ValueError):
                    self.bundle.find_where((operator, "/a", bad))

    def test_comparison_node_length(self):
        for bad in (
            ("lt", "/a"),
            ("le", "/a", 1, 2),
            ("gt",),
            ("ge", "/a", 1, 2, 3),
        ):
            with self.assertRaises(ValueError):
                self.bundle.find_where(bad)

    def test_comparison_pointer_rules_match_eq(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("lt", b"/a", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "a", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "/a~2", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "/missing", 1))

    def test_comparison_range_rules_match_eq(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("lt", "/a", 1), True)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("lt", "/a", 1), 0, "3")
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "/a", 1), -1)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "/a", 1), 0, 99)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "/a", 1), 4, 2)

    def test_invalid_comparison_branches_are_not_masked(self):
        contradicting = ("and", (("eq", "/a", 1), ("eq", "/a", 2)))
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (contradicting, ("lt", "/missing", 1)))
            )
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (contradicting, ("lt", "/a", "1")))
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "/missing", 1), 3, 3)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("lt", "/a", None), 3, 3)


class FindWhereSnapshotAndOfflineTest(unittest.TestCase):
    def test_frozen_snapshot_survives_append_and_prune(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        expression = ("and", (("eq", "/a", 1), ("eq", "/b", "x")))
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
        expression = (
            "and",
            (("eq", "/a", 1), ("not", ("eq", "/b", "y"))),
        )
        self.assertEqual(decoded_index.find_where(expression), (0, 4))
        self.assertEqual(decoded_bundle.find_where(expression), (0, 4))
        self.assertEqual(
            decoded_bundle.find_where(expression),
            decoded_index.find_where(expression),
        )
        # Re-encoding is byte-identical: queries change nothing.
        self.assertEqual(encode_json_multi_index(decoded_index), index_blob)
        self.assertEqual(
            encode_signed_json_multi_index(decoded_bundle), signed_blob
        )

    def test_comparison_works_off_decoded_bytes_without_log_or_key(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        index_blob = encode_json_multi_index(bundle.index)
        signed_blob = encode_signed_json_multi_index(bundle)
        decoded_index = decode_json_multi_index(index_blob)
        decoded_bundle = decode_signed_json_multi_index(signed_blob)
        expression = ("and", (("ge", "/a", 1), ("le", "/a", 1)))
        self.assertEqual(decoded_index.find_where(expression), (0, 1, 4))
        self.assertEqual(decoded_bundle.find_where(expression), (0, 1, 4))
        self.assertEqual(
            decoded_bundle.find_where(expression),
            decoded_index.find_where(expression),
        )
        self.assertTrue(
            verify_signed_json_multi_index(decoded_bundle, public_key(SEED_A))
        )
        # Re-encoding is byte-identical: queries change nothing.
        self.assertEqual(encode_json_multi_index(decoded_index), index_blob)
        self.assertEqual(
            encode_signed_json_multi_index(decoded_bundle), signed_blob
        )

    def test_successful_and_failed_queries_are_read_only(self):
        bundle = make_log().signed_json_multi_index(POINTERS, SEED_A)
        blob = encode_signed_json_multi_index(bundle)
        expression = ("and", (("eq", "/a", 1), ("eq", "/b", "x")))
        bundle.find_where(expression)
        bundle.find_where(("and", ()))
        bundle.find_where(("not", expression), 1, 3)
        for bad in (
            lambda: bundle.find_where(["eq", "/a", 1]),
            lambda: bundle.find_where(("eq", "/a")),
            lambda: bundle.find_where(("eq", "/missing", 1)),
            lambda: bundle.find_where(("eq", "/a", float("nan"))),
            lambda: bundle.find_where(expression, 99),
        ):
            with self.assertRaises((TypeError, ValueError)):
                bad()
        self.assertEqual(encode_signed_json_multi_index(bundle), blob)


if __name__ == "__main__":
    unittest.main()
