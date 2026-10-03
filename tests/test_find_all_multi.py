import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    decode_json_multi_index,
    decode_signed_json_multi_index,
    encode_json_multi_index,
    encode_signed_json_multi_index,
    verify_signed_json_multi_index,
)

SEED_A = bytes(range(1, 33))


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def public_key(seed):
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def make_log():
    log = AuditLog()
    # 0: integer 1 at /a, "x" at /b
    log.append(j({"a": 1, "b": "x"}))
    # 1: float 1.0 at /a (same JSON number as 1), "y" at /b
    log.append(j({"a": 1.0, "b": "y"}))
    # 2: boolean true at /a (different kind), "x" at /b
    log.append(j({"a": True, "b": "x"}))
    # 3: string "1" at /a (different kind), "x" at /b
    log.append(j({"a": "1", "b": "x"}))
    # 4: explicit null at /a, integer 5 at /c
    log.append(j({"a": None, "b": "x", "c": 5}))
    # 5: not JSON
    log.append(b"not json")
    # 6: non-scalar target at /a
    log.append(j({"a": {"nested": 1}, "b": "x"}))
    # 7: missing /a and /c
    log.append(j({"b": "x"}))
    return log


POINTERS = ("/a", "/b", "/c")


class FindAllCoreTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)
        self.index = self.bundle.index

    def test_spec_example_only_first_entry(self):
        # /a == 1 matches 0 (int 1) and 1 (float 1.0), /b == "x" matches
        # 0, 2, 3, 4, 6, 7; the conjunction is exactly entry 0.
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/b", "x"))), (0,)
        )
        self.assertEqual(
            self.index.find_all((("/a", 1), ("/b", "x"))), (0,)
        )

    def test_result_is_strictly_ascending_tuple(self):
        result = self.bundle.find_all((("/b", "x"),))
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, tuple(sorted(result)))
        self.assertEqual(len(result), len(set(result)))

    def test_single_condition_matches_find(self):
        for pointer, value in (
            ("/a", 1),
            ("/a", 1.0),
            ("/a", True),
            ("/a", "1"),
            ("/a", None),
            ("/b", "x"),
            ("/c", 5),
        ):
            conditions = ((pointer, value),)
            self.assertEqual(
                self.bundle.find_all(conditions),
                self.bundle.find(pointer, value),
                conditions,
            )

    def test_numeric_cross_kind_but_bool_and_string_separated(self):
        # 1 (int) and 1.0 (float) are the same JSON number.
        self.assertEqual(
            self.bundle.find_all((("/a", 1.0), ("/b", "x"))), (0,)
        )
        # true is not the number 1.
        self.assertEqual(
            self.bundle.find_all((("/a", True), ("/b", "x"))), (2,)
        )
        # the string "1" is not the number 1.
        self.assertEqual(
            self.bundle.find_all((("/a", "1"), ("/b", "x"))), (3,)
        )

    def test_non_json_missing_and_non_scalar_miss(self):
        # Entries 5, 6, 7 satisfy no condition set that mentions /a.
        result = self.bundle.find_all((("/a", 1),))
        self.assertEqual(set(result), {0, 1})
        result = self.bundle.find_all((("/b", "x"), ("/a", None)))
        self.assertEqual(result, (4,))

    def test_conditions_need_not_be_sorted(self):
        self.assertEqual(
            self.bundle.find_all((("/b", "x"), ("/c", 5), ("/a", None))),
            (4,),
        )

    def test_repeated_pointer_compatible_and_exclusive(self):
        # The same condition repeated changes nothing.
        self.assertEqual(
            self.bundle.find_all(
                (("/a", 1), ("/b", "x"), ("/a", 1))
            ),
            (0,),
        )
        # int 1 and float 1.0 are the same scalar value.
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/a", 1.0))), (0, 1)
        )
        # Mutually exclusive values on one field yield nothing.
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/a", 2))), ()
        )
        self.assertEqual(
            self.bundle.find_all((("/b", "x"), ("/b", "y"))), ()
        )
        # Number 1 vs boolean true are mutually exclusive.
        self.assertEqual(
            self.bundle.find_all((("/a", 1), ("/a", True))), ()
        )

    def test_empty_conditions_returns_whole_range(self):
        self.assertEqual(
            self.bundle.find_all(()), tuple(range(len(self.log)))
        )
        self.assertEqual(self.bundle.find_all((), 2, 6), (2, 3, 4, 5))
        self.assertEqual(self.bundle.find_all((), 3, 3), ())

    def test_half_open_ranges(self):
        self.assertEqual(
            self.bundle.find_all((("/b", "x"),), 0, 3), (0, 2)
        )
        self.assertEqual(
            self.bundle.find_all((("/b", "x"),), 3), (3, 4, 6, 7)
        )
        self.assertEqual(
            self.bundle.find_all((("/b", "x"),), None, 4), (0, 2, 3)
        )
        self.assertEqual(self.bundle.find_all((("/a", 1),), 3, 3), ())
        # A range excluding every hit returns empty.
        self.assertEqual(
            self.bundle.find_all((("/a", 1),), 2, 8), ()
        )

    def test_encrypted_entries_take_no_part(self):
        log = AuditLog()
        log.append(j({"a": 1, "b": "x"}))
        log.encrypt(j({"a": 1, "b": "x"}), b"k" * 32)
        log.append(j({"a": 1, "b": "y"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_all((("/a", 1), ("/b", "x"))), (0,))

    def test_signed_and_unsigned_agree_with_decoded(self):
        blob = encode_signed_json_multi_index(self.bundle)
        restored = decode_signed_json_multi_index(blob)
        index_blob = encode_json_multi_index(self.index)
        restored_index = decode_json_multi_index(index_blob)
        condition_sets = (
            (),
            (("/a", 1),),
            (("/a", 1), ("/b", "x")),
            (("/b", "x"), ("/a", None), ("/c", 5)),
            (("/a", 1), ("/a", 2)),
        )
        for conditions in condition_sets:
            expected = self.index.find_all(conditions)
            self.assertEqual(self.bundle.find_all(conditions), expected)
            self.assertEqual(restored.find_all(conditions), expected)
            self.assertEqual(restored_index.find_all(conditions), expected)


class FindAllPrunedTest(unittest.TestCase):
    def test_default_range_is_retained_segment_with_absolute_indices(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        index = bundle.index
        self.assertEqual(index.retain_from, 2)
        # Empty conditions enumerate the covered absolute indices.
        self.assertEqual(
            bundle.find_all(()), tuple(range(2, len(log)))
        )
        # /a == 1 has no surviving hit; true at entry 2 does.
        self.assertEqual(bundle.find_all((("/a", 1),)), ())
        self.assertEqual(
            bundle.find_all((("/a", True), ("/b", "x"))), (2,)
        )
        self.assertEqual(
            bundle.find_all((("/b", "x"),), 4, 7), (4, 6)
        )
        self.assertTrue(
            verify_signed_json_multi_index(bundle, public_key(SEED_A))
        )

    def test_empty_coverage(self):
        log = make_log()
        log.prune(len(log), log.seal(len(log)))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_all(()), ())
        self.assertEqual(
            bundle.find_all((("/a", 1), ("/b", "x"))), ()
        )


class FindAllFrozenSnapshotTest(unittest.TestCase):
    def test_later_append_and_prune_do_not_change_results(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        log.append(j({"a": 1, "b": "x", "c": 5}))
        log.prune(5, log.seal(5))
        conditions = (("/a", 1), ("/b", "x"))
        self.assertEqual(bundle.find_all(conditions), (0,))
        self.assertEqual(bundle.find_all(()), (0, 1, 2, 3, 4, 5, 6, 7))
        blob = encode_signed_json_multi_index(bundle)
        self.assertEqual(
            encode_signed_json_multi_index(
                decode_signed_json_multi_index(blob)
            ),
            blob,
        )


class FindAllErrorTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_log().signed_json_multi_index(POINTERS, SEED_A)

    def test_conditions_outer_type(self):
        for bad in (None, [("/a", 1)], "/a", ("/a", 1)):
            with self.assertRaises(TypeError):
                self.bundle.find_all(bad)

    def test_condition_element_type(self):
        for bad in (["/a", 1], "/a", 42, None):
            with self.assertRaises(TypeError):
                self.bundle.find_all((bad,))

    def test_condition_length(self):
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a",),))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a", 1, 2),))

    def test_pointer_type_and_syntax_and_coverage(self):
        with self.assertRaises(TypeError):
            self.bundle.find_all(((b"/a", 1),))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("a", 1),))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a~2", 1),))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/missing", 1),))

    def test_value_type(self):
        for bad in ([1], {"x": 1}, b"1", bytearray(b"1")):
            with self.assertRaises(TypeError):
                self.bundle.find_all((("/a", bad),))

    def test_non_finite_float(self):
        for bad in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                self.bundle.find_all((("/a", bad),))

    def test_range_types_and_bounds(self):
        with self.assertRaises(TypeError):
            self.bundle.find_all((), True)
        with self.assertRaises(TypeError):
            self.bundle.find_all((), 0, "3")
        with self.assertRaises(ValueError):
            self.bundle.find_all((), -1)
        with self.assertRaises(ValueError):
            self.bundle.find_all((), 0, 99)
        with self.assertRaises(ValueError):
            self.bundle.find_all((), 3, 2)

    def test_later_condition_errors_still_reported(self):
        # Even though the first condition already has no hit...
        self.assertEqual(self.bundle.find("/a", 999), ())
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a", 999), ("/a", float("nan"))))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a", 999), ("/missing", 1)))
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a", 999), ("bad-syntax", 1)))
        with self.assertRaises(TypeError):
            self.bundle.find_all((("/a", 999), (b"/a", 1)))
        with self.assertRaises(TypeError):
            self.bundle.find_all((("/a", 999), ("/a", [1])))
        # ...and even when the range itself is empty, later validation
        # errors are still reported rather than an early empty result.
        with self.assertRaises(ValueError):
            self.bundle.find_all(
                (("/a", 1), ("/a", float("nan"))), 3, 3
            )
        with self.assertRaises(ValueError):
            self.bundle.find_all((("/a", 1), ("/missing", 1)), 3, 3)

    def test_failed_and_successful_calls_are_read_only(self):
        blob = encode_signed_json_multi_index(self.bundle)
        self.bundle.find_all((("/a", 1), ("/b", "x")))
        self.bundle.find_all(())
        for bad in (
            [("/a", 1)],
            (["/a", 1],),
            (("/a", 1, 2),),
            ((b"/a", 1),),
            (("a", 1),),
            (("/missing", 1),),
            (("/a", float("nan")),),
        ):
            with self.assertRaises((TypeError, ValueError)):
                self.bundle.find_all(bad)
        with self.assertRaises(ValueError):
            self.bundle.find_all((), 3, 2)
        self.assertEqual(
            encode_signed_json_multi_index(self.bundle), blob
        )
        self.assertEqual(
            encode_json_multi_index(self.bundle.index),
            encode_json_multi_index(
                decode_json_multi_index(
                    encode_json_multi_index(self.bundle.index)
                )
            ),
        )


if __name__ == "__main__":
    unittest.main()
