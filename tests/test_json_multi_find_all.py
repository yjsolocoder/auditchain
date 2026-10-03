import json
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


class FindAllBasicsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)

    def test_example_conjunction(self):
        # Only the first entry has both /a == 1 and /b == "x"; entry 1's
        # /b is "y" and entry 2's /a is the boolean true.
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/b", "x"))), (0,)
        )
        self.assertEqual(
            self.bundle.index.find_all((("/a", 1), ("/b", "x"))), (0,)
        )

    def test_float_query_matches_numeric_integer_entry(self):
        self.assertEqual(
            self.bundle.find_all((("/a", 1.0), ("/b", "y"))), (1,)
        )

    def test_boolean_and_string_kinds_are_separate_from_numbers(self):
        # /a == true intersects /b == "x" at entry 2 only.
        self.assertEqual(
            self.bundle.find_all((("/a", True), ("/b", "x"))), (2,)
        )
        # The string "1" is its own kind.
        self.assertEqual(
            self.bundle.find_all((("/a", "1"), ("/b", "x"))), (3,)
        )
        # No entry pairs /a == false with anything.
        self.assertEqual(
            self.bundle.find_all((("/a", False), ("/b", "x"))), ()
        )

    def test_result_is_strictly_ascending_without_duplicates(self):
        log = AuditLog()
        for value in (1, 1, 2, 1, 1):
            log.append(j({"a": value, "b": "x"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        result = bundle.find_all((("/a", 1), ("/b", "x")))
        self.assertEqual(result, (0, 1, 3, 4))
        self.assertEqual(result, tuple(sorted(set(result))))

    def test_condition_order_is_irrelevant(self):
        conditions = (("/a", 1), ("/b", "x"))
        self.assertEqual(
            self.bundle.find_all(conditions),
            self.bundle.find_all(tuple(reversed(conditions))),
        )

    def test_same_pointer_may_repeat(self):
        # 1.0 and 1 are the same JSON number, so this is a repeat.
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/a", 1.0), ("/b", "x"))),
            (0,),
        )

    def test_duplicate_condition_does_not_change_result(self):
        once = self.bundle.find_all((("/a", 1),))
        twice = self.bundle.find_all((("/a", 1), ("/a", 1)))
        thrice = self.bundle.find_all(
            (("/a", 1), ("/b", "x"), ("/a", 1), ("/b", "x"))
        )
        self.assertEqual(twice, once)
        self.assertEqual(thrice, (0,))

    def test_mutually_exclusive_conditions_return_empty(self):
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/a", 2))), ()
        )
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/a", True))), ()
        )
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/a", "1"))), ()
        )

    def test_empty_conditions_returns_whole_range(self):
        self.assertEqual(
            self.bundle.find_all(()), tuple(range(len(self.log)))
        )

    def test_missing_field_non_json_and_non_scalar_do_not_hit(self):
        # Entry 4 has /a == 1 but misses /b; 5 is not JSON; 6's /a is an
        # array. None survives the conjunction.
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/b", "x"))), (0,)
        )
        # Missing /b alone likewise excludes entry 4.
        self.assertEqual(
            self.bundle.find_all((("/z", 9), ("/b", "x"))), ()
        )

    def test_encrypted_entries_never_hit(self):
        log = AuditLog()
        log.append(j({"a": 1, "b": "x"}))
        log.encrypt(j({"a": 1, "b": "x"}), b"k" * 32)
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(
            bundle.find_all((("/a", 1), ("/b", "x"))), (0,)
        )

    def test_signed_and_inner_index_agree(self):
        conditions = (("/a", 1), ("/b", "x"))
        self.assertEqual(
            self.bundle.find_all(conditions),
            self.bundle.index.find_all(conditions),
        )


class FindAllRangeTest(unittest.TestCase):
    def setUp(self):
        log = AuditLog()
        for value in (1, 2, 1, 1, 3, 1):
            log.append(j({"a": value, "b": "x"}))
        self.log = log
        self.bundle = log.signed_json_multi_index(POINTERS, SEED_A)

    def test_default_range_covers_retained_segment(self):
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/b", "x"))),
            (0, 2, 3, 5),
        )

    def test_explicit_half_open_ranges(self):
        conditions = (("/a", 1), ("/b", "x"))
        self.assertEqual(self.bundle.find_all(conditions, 0, 3), (0, 2))
        self.assertEqual(self.bundle.find_all(conditions, 2, 5), (2, 3))
        self.assertEqual(self.bundle.find_all(conditions, 3, 3), ())
        self.assertEqual(self.bundle.find_all(conditions, None, 3), (0, 2))
        self.assertEqual(self.bundle.find_all(conditions, 5), (5,))

    def test_empty_conditions_empty_range(self):
        self.assertEqual(self.bundle.find_all((), 3, 3), ())
        self.assertEqual(self.bundle.find_all((), 2, 5), (2, 3, 4))

    def test_pruned_snapshot_ranges(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        # Default range starts at the retain point.
        self.assertEqual(
            bundle.find_all((("/a", True), ("/b", "x"))), (2,)
        )
        self.assertEqual(bundle.find_all(()), (2, 3, 4, 5, 6, 7))
        with self.assertRaises(ValueError):
            bundle.find_all((("/a", True),), 0, 3)


class FindAllArgumentsTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_log().signed_json_multi_index(POINTERS, SEED_A)

    def test_conditions_must_be_a_tuple(self):
        for bad in (
            [("/a", 1)],
            ("/a", 1),
            "/a",
            None,
            (item for item in (("/a", 1),)),
        ):
            with self.assertRaises(TypeError):
                self.bundle.find_all(bad)

    def test_condition_must_be_a_tuple(self):
        for bad in (["/a", 1], "/a", None, {"/a": 1}):
            with self.assertRaises(TypeError):
                self.bundle.find_all((bad,))

    def test_condition_length_must_be_two(self):
        for bad in ((), ("/a",), ("/a", 1, 2)):
            with self.assertRaises(ValueError):
                self.bundle.find_all((bad,))

    def test_pointer_rules_match_find(self):
        with self.assertRaises(TypeError):
            self.bundle.find_all(((b"/a", 1),))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("a", 1),))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a~2", 1),))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/missing", 1),))

    def test_value_rules_match_find(self):
        for bad in ([1], {"x": 1}, b"1", bytearray(b"1")):
            with self.assertRaises(TypeError):
                self.bundle.find_all((("/a", bad),))
        for bad in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                self.bundle.find_all((("/a", bad),))

    def test_range_bound_rules_match_find(self):
        conditions = (("/a", 1),)
        with self.assertRaises(TypeError):
            self.bundle.find_all(conditions, True)
        with self.assertRaises(TypeError):
            self.bundle.find_all(conditions, 0, "3")
        with self.assertRaises(ValueError):
            self.bundle.find_all(conditions, -1)
        with self.assertRaises(ValueError):
            self.bundle.find_all(conditions, 0, 99)
        with self.assertRaises(ValueError):
            self.bundle.find_all(conditions, 4, 2)

    def test_later_condition_errors_are_reported_after_empty_hit_set(self):
        # The first two conditions are mutually exclusive, so the result
        # is already empty; errors in a later condition must still fire.
        with self.assertRaises(TypeError):
            self.bundle.find_all((("/a", 1), ("/a", 2), (b"/a", 1)))
        with self.assertRaises(TypeError):
            self.bundle.find_all((("/a", 1), ("/a", 2), ("/a", [1])))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a", 1), ("/a", 2), ("bad", 1)))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a", 1), ("/a", 2), ("/missing", 1)))
        with self.assertRaises(ValueError):
            self.bundle.find_all(
                (("/a", 1), ("/a", 2), ("/a", float("nan")))
            )
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a", 1), ("/a", 2)), -1)
        with self.assertRaises(TypeError):
            self.bundle.find_all((("/a", 1), ("/a", 2)), None, True)

    def test_later_condition_errors_reported_when_range_is_empty(self):
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/missing", 1),), 3, 3)
        with self.assertRaises(TypeError):
            self.bundle.find_all((("/a", [1]),), 3, 3)

    def test_error_in_earlier_condition_short_circuits_validation_order(self):
        # A non-str pointer in the very first condition raises TypeError
        # regardless of anything else.
        with self.assertRaises(TypeError):
            self.bundle.find_all(((b"/a", 1), ("bad-ptr", 1)))


class FindAllSnapshotAndOfflineTest(unittest.TestCase):
    def test_frozen_snapshot_survives_append_and_prune(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        conditions = (("/a", 1), ("/b", "x"))
        expected = bundle.find_all(conditions)
        log.append(j({"a": 1, "b": "x"}))
        log.prune(5, log.seal(5))
        self.assertEqual(bundle.find_all(conditions), expected)
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
        conditions = (("/a", 1), ("/b", "x"))
        self.assertEqual(decoded_index.find_all(conditions), (0,))
        self.assertEqual(decoded_bundle.find_all(conditions), (0,))
        self.assertEqual(
            decoded_bundle.find_all(conditions),
            decoded_index.find_all(conditions),
        )
        # Re-encoding is byte-identical: queries change nothing.
        self.assertEqual(
            encode_json_multi_index(decoded_index), index_blob
        )
        self.assertEqual(
            encode_signed_json_multi_index(decoded_bundle), signed_blob
        )

    def test_successful_and_failed_queries_are_read_only(self):
        bundle = make_log().signed_json_multi_index(POINTERS, SEED_A)
        blob = encode_signed_json_multi_index(bundle)
        conditions = (("/a", 1), ("/b", "x"))
        bundle.find_all(conditions)
        bundle.find_all(())
        bundle.find_all(conditions, 1, 3)
        for bad in (
            lambda: bundle.find_all([("/a", 1)]),
            lambda: bundle.find_all((("/a", 1, 2),)),
            lambda: bundle.find_all((("/missing", 1),)),
            lambda: bundle.find_all((("/a", float("nan")),)),
            lambda: bundle.find_all(conditions, 99),
        ):
            with self.assertRaises((TypeError, ValueError)):
                bad()
        self.assertEqual(encode_signed_json_multi_index(bundle), blob)


if __name__ == "__main__":
    unittest.main()
