import unittest

from auditchain import (
    AuditLog,
    decode_signed_json_multi_index,
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
    # 8: big integer beyond the exact float range
    log.append(j({"a": 9007199254740993}))
    # 9: negative zero
    log.append(j({"a": -0.0}))
    # 10: fractional float
    log.append(j({"a": 2.5}))
    return log


class FindWhereCompareBasicsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)

    def test_lt_le_gt_ge(self):
        self.assertEqual(
            self.bundle.find_where(("lt", "/a", 2)), (0, 1, 4, 9)
        )
        self.assertEqual(
            self.bundle.find_where(("le", "/a", 1)), (0, 1, 4, 9)
        )
        self.assertEqual(self.bundle.find_where(("gt", "/a", 1)), (8, 10))
        self.assertEqual(
            self.bundle.find_where(("ge", "/a", 1)), (0, 1, 4, 8, 10)
        )

    def test_int_and_float_thresholds_compare_across_kinds(self):
        # The float threshold 1.0 matches the integer 1 buckets and the
        # integer threshold 1 matches the float 1.0 bucket.
        self.assertEqual(
            self.bundle.find_where(("le", "/a", 1.0)), (0, 1, 4, 9)
        )
        self.assertEqual(
            self.bundle.find_where(("ge", "/a", 1.0)), (0, 1, 4, 8, 10)
        )
        self.assertEqual(
            self.bundle.find_where(("lt", "/a", 1.5)), (0, 1, 4, 9)
        )

    def test_big_integer_is_not_misjudged_by_float_rounding(self):
        # 9007199254740993 rounds to 9007199254740992.0 as a float but
        # must still compare greater than that float threshold.
        self.assertEqual(
            self.bundle.find_where(("gt", "/a", 9007199254740992.0)),
            (8,),
        )
        self.assertEqual(
            self.bundle.find_where(("le", "/a", 9007199254740992.0)),
            (0, 1, 4, 9, 10),
        )
        self.assertEqual(
            self.bundle.find_where(("ge", "/a", 9007199254740993)), (8,)
        )

    def test_zeroes_compare_equal(self):
        self.assertEqual(self.bundle.find_where(("lt", "/a", 0.0)), ())
        self.assertEqual(self.bundle.find_where(("le", "/a", 0)), (9,))
        self.assertEqual(self.bundle.find_where(("ge", "/a", 0.0)), (0, 1, 4, 8, 9, 10))
        self.assertEqual(self.bundle.find_where(("gt", "/a", -0.0)), (0, 1, 4, 8, 10))

    def test_non_numeric_kinds_never_match(self):
        # Boolean, string, null, object and array targets, non-JSON and
        # missing fields are no comparison hit but hit the negation.
        for operator in ("lt", "le", "gt", "ge"):
            self.assertNotIn(
                2, self.bundle.find_where((operator, "/a", 5))
            )
            self.assertNotIn(
                3, self.bundle.find_where((operator, "/a", 5))
            )
        self.assertEqual(
            self.bundle.find_where(("not", ("lt", "/a", 2))),
            (2, 3, 5, 6, 7, 8, 10),
        )

    def test_encrypted_entries_never_match_comparison(self):
        log = AuditLog()
        log.append(j({"a": 1}))
        log.encrypt(j({"a": 1}), b"k" * 32)
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("le", "/a", 1)), (0,))
        self.assertEqual(bundle.find_where(("not", ("le", "/a", 1))), (1,))

    def test_and_expresses_open_closed_intervals(self):
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("gt", "/a", 1), ("le", "/a", 2.5)))
            ),
            (10,),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("ge", "/a", 1), ("lt", "/a", 1)))
            ),
            (),
        )

    def test_nested_combinations_with_eq(self):
        expression = (
            "or",
            (
                ("and", (("ge", "/a", 1), ("eq", "/b", "x"))),
                ("eq", "/a", True),
            ),
        )
        self.assertEqual(self.bundle.find_where(expression), (0, 2))

    def test_duplicate_branches_add_no_duplicates(self):
        leaf = ("lt", "/a", 2)
        result = self.bundle.find_where(("or", (leaf, leaf, leaf)))
        self.assertEqual(result, (0, 1, 4, 9))
        self.assertEqual(result, tuple(sorted(set(result))))
        self.assertEqual(
            self.bundle.find_where(("and", (leaf, leaf))), result
        )

    def test_double_negation_restores_result(self):
        leaf = ("gt", "/a", 1)
        self.assertEqual(
            self.bundle.find_where(("not", ("not", leaf))),
            self.bundle.find_where(leaf),
        )

    def test_signed_and_inner_index_agree(self):
        expression = ("and", (("ge", "/a", 1), ("not", ("eq", "/b", "y"))))
        self.assertEqual(
            self.bundle.find_where(expression),
            self.bundle.index.find_where(expression),
        )


class FindWhereCompareRangeTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)

    def test_default_range_covers_retained_segment(self):
        self.assertEqual(
            self.bundle.find_where(("ge", "/a", 1)), (0, 1, 4, 8, 10)
        )

    def test_explicit_half_open_ranges(self):
        expression = ("lt", "/a", 2)
        self.assertEqual(self.bundle.find_where(expression, 0, 3), (0, 1))
        self.assertEqual(self.bundle.find_where(expression, 1, 5), (1, 4))
        self.assertEqual(self.bundle.find_where(expression, 3, 3), ())
        self.assertEqual(self.bundle.find_where(expression, None, 2), (0, 1))
        self.assertEqual(self.bundle.find_where(expression, 9), (9,))

    def test_not_complement_is_clipped_to_the_range(self):
        self.assertEqual(
            self.bundle.find_where(("not", ("lt", "/a", 2)), 1, 5),
            (2, 3),
        )

    def test_pruned_snapshot_ranges(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("lt", "/a", 2)), (4, 9))
        self.assertEqual(
            bundle.find_where(("not", ("lt", "/a", 2))),
            (2, 3, 5, 6, 7, 8, 10),
        )
        with self.assertRaises(ValueError):
            bundle.find_where(("lt", "/a", 2), 0, 3)


class FindWhereCompareArgumentsTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_log().signed_json_multi_index(POINTERS, SEED_A)

    def test_threshold_type_rules(self):
        for bad in (True, False, "1", None, [1], {"x": 1}, b"1"):
            with self.assertRaises(TypeError):
                self.bundle.find_where(("lt", "/a", bad))

    def test_threshold_must_be_finite(self):
        for bad in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                self.bundle.find_where(("ge", "/a", bad))

    def test_node_length_must_match_the_operator(self):
        for bad in (
            ("lt", "/a"),
            ("le", "/a", 1, 2),
            ("gt",),
            ("ge", "/a", 1, 2, 3),
        ):
            with self.assertRaises(ValueError):
                self.bundle.find_where(bad)

    def test_pointer_rules_match_eq(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("lt", b"/a", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "a", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "/a~2", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "/missing", 1))

    def test_range_bound_rules_match_eq(self):
        expression = ("lt", "/a", 2)
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
        # A bad comparison node length wins over a bad child.
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (("lt", "/a"), ("eq", b"/a", 1)))
            )
        # A bad threshold type wins over a later bad child.
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (("lt", "/a", "x"), ("eq", "/missing", 1)))
            )

    def test_children_are_checked_left_to_right(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (("lt", "/a", True), ("eq", "/missing", 1)))
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (("eq", "/missing", 1), ("lt", "/a", True)))
            )

    def test_range_is_checked_last(self):
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "/missing", 1), 0, 99)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("lt", "/a", 1), 0, 99)

    def test_empty_results_do_not_mask_invalid_branches(self):
        # The first child already determines an empty intersection and
        # the range is empty; the invalid later branch must still raise.
        contradicting = ("and", (("lt", "/a", 0), ("gt", "/a", 1)))
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (contradicting, ("lt", "/missing", 1))), 3, 3
            )
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (contradicting, ("lt", "/a", "x"))), 3, 3
            )


class FindWhereCompareOfflineTest(unittest.TestCase):
    def test_restored_index_answers_after_verify(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        blob = encode_signed_json_multi_index(bundle)
        restored = decode_signed_json_multi_index(blob)
        self.assertTrue(
            verify_signed_json_multi_index(restored, public_key(SEED_A))
        )
        expression = ("and", (("ge", "/a", 1), ("lt", "/a", 2)))
        self.assertEqual(restored.find_where(expression), (0, 1, 4))
        self.assertEqual(
            restored.find_where(expression), bundle.find_where(expression)
        )

    def test_later_appends_and_prunes_do_not_change_frozen_index(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        expression = ("le", "/a", 1)
        expected = bundle.find_where(expression)
        log.append(j({"a": 0}))
        log.prune(2, log.seal(2))
        self.assertEqual(bundle.find_where(expression), expected)

    def test_queries_are_read_only(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        blob = encode_signed_json_multi_index(bundle)
        bundle.find_where(("lt", "/a", 2))
        bundle.find_where(("and", (("ge", "/a", 1), ("le", "/a", 2))))
        for bad in (
            lambda: bundle.find_where(("lt", "/a", True)),
            lambda: bundle.find_where(("gt", "/a", float("nan"))),
            lambda: bundle.find_where(("le", "/missing", 1)),
        ):
            with self.assertRaises((TypeError, ValueError)):
                bad()
        self.assertEqual(encode_signed_json_multi_index(bundle), blob)


if __name__ == "__main__":
    unittest.main()
