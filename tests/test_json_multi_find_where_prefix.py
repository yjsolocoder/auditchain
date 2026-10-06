import unittest

from auditchain import AuditLog

from tests.test_signed_json_multi_index import SEED_A, j

POINTERS = ("/n", "/name")


def make_log():
    log = AuditLog()
    # 0: string alice at /name, integer 1 at /n
    log.append(j({"name": "alice", "n": 1}))
    # 1: string alicia at /name, integer 2 at /n
    log.append(j({"name": "alicia", "n": 2}))
    # 2: string Alice (capital) at /name
    log.append(j({"name": "Alice", "n": 3}))
    # 3: empty string at /name
    log.append(j({"name": "", "n": 4}))
    # 4: string bob at /name, /n missing
    log.append(j({"name": "bob"}))
    # 5: non-string (number) at /name
    log.append(j({"name": 123, "n": 5}))
    # 6: not JSON
    log.append(b"not json")
    # 7: /name missing
    log.append(j({"other": "alice"}))
    # 8: precomposed á (U+00E1) at /name
    log.append(j({"name": "á" + "lix"}))
    # 9: non-scalar at /name
    log.append(j({"name": ["alice"]}))
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


class FindWherePrefixBasicsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_prefix_matches_string_prefixes(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "ali")), (0, 1)
        )
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "alicia")), (1,)
        )
        self.assertEqual(self.bundle.find_where(("prefix", "/name", "b")), (4,))

    def test_prefix_is_case_sensitive(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "Ali")), (2,)
        )
        self.assertEqual(self.bundle.find_where(("prefix", "/name", "ALI")), ())

    def test_prefix_does_no_unicode_normalization(self):
        # The precomposed á (U+00E1) entry does not match the combining
        # sequence a + U+0301, and vice versa.
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "á")), (8,)
        )
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "á")), ()
        )

    def test_empty_prefix_matches_every_string(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "")),
            (0, 1, 2, 3, 4, 8),
        )

    def test_whole_string_matches(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "alice")), (0,)
        )
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "alicex")), ()
        )

    def test_missing_non_string_non_json_and_non_scalar_miss(self):
        # Entries 5 (number), 6 (not JSON), 7 (missing) and 9 (array)
        # never satisfy a prefix leaf but do satisfy its negation.
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "ali")), (0, 1)
        )
        self.assertEqual(
            self.bundle.find_where(("not", ("prefix", "/name", "ali"))),
            (2, 3, 4, 5, 6, 7, 8, 9),
        )

    def test_ciphertext_never_matches(self):
        log = AuditLog()
        log.encrypt(j({"name": "alice"}), bytes(range(32)), nonce=b"0" * 12)
        log.append(j({"name": "alice"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("prefix", "/name", "ali")), (1,))
        self.assertEqual(
            bundle.find_where(("not", ("prefix", "/name", "ali"))), (0,)
        )

    def test_combines_with_eq_numeric_and_boolean_nodes(self):
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("prefix", "/name", "ali"), ("ge", "/n", 2)))
            ),
            (1,),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("or", (("prefix", "/name", "bob"), ("eq", "/n", 1)))
            ),
            (0, 4),
        )
        self.assertEqual(
            self.bundle.find_where(
                (
                    "and",
                    (
                        ("prefix", "/name", ""),
                        ("not", ("prefix", "/name", "ali")),
                    ),
                )
            ),
            (2, 3, 4, 8),
        )

    def test_range_defaults_and_clipping(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", ""), 1, 3), (1, 2)
        )
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "ali"), 1, None), (1,)
        )
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", ""), 2, 2), ()
        )

    def test_result_is_strictly_ascending_without_duplicates(self):
        leaf = ("prefix", "/name", "ali")
        result = self.bundle.find_where(("or", (leaf, leaf, leaf)))
        self.assertEqual(result, (0, 1))
        self.assertEqual(result, tuple(sorted(set(result))))

    def test_signed_bundle_delegates(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "ali")),
            self.bundle.index.find_where(("prefix", "/name", "ali")),
        )

    def test_later_appends_and_prunes_do_not_change_issued_index(self):
        before = self.bundle.find_where(("prefix", "/name", "ali"))
        self.log.append(j({"name": "alina"}))
        self.assertEqual(self.bundle.find_where(("prefix", "/name", "ali")), before)


class FindWherePrefixValidationTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()

    def test_non_tuple_node_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(["prefix", "/name", "a"])

    def test_non_string_operator_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where((1, "/name", "a"))

    def test_non_string_pointer_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("prefix", 1, "a"))

    def test_non_string_prefix_raises_type_error(self):
        for text in (1, 1.5, True, None, b"a", ["a"]):
            with self.assertRaises(TypeError):
                self.bundle.find_where(("prefix", "/name", text))

    def test_wrong_node_length_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.bundle.find_where(("prefix", "/name"))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("prefix", "/name", "a", "b"))

    def test_unknown_operator_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.bundle.find_where(("startswith", "/name", "a"))

    def test_malformed_pointer_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.bundle.find_where(("prefix", "name", "a"))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("prefix", "/name/", "a"))

    def test_uncovered_pointer_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.bundle.find_where(("prefix", "/missing", "a"))

    def test_expression_validated_before_range_and_lookup(self):
        # An empty range or an already determined intermediate result
        # never masks an illegal branch.
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (("prefix", "/name", "a"), ("prefix", "/missing", "x"))),
                2,
                2,
            )
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (("prefix", "/name", "a"), ("prefix", "/name", 5))),
                2,
                2,
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("or", (("prefix", "/name", ""), ("prefix", "/missing", "x")))
            )

    def test_parent_validated_before_children_left_to_right(self):
        # The parent's own length error beats the children's errors, and
        # the left child's error beats the right child's.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("and", (("prefix", "/missing", "x"),), 1))
        try:
            self.bundle.find_where(
                (
                    "and",
                    (
                        ("prefix", "/name", 1),
                        ("prefix", "/missing", "x"),
                    ),
                )
            )
        except TypeError:
            pass
        else:
            self.fail("left child's TypeError must beat the right child's")

    def test_range_rules_unchanged(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("prefix", "/name", "a"), "0")
        with self.assertRaises(ValueError):
            self.bundle.find_where(("prefix", "/name", "a"), 5, 2)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("prefix", "/name", "a"), 0, 99)


if __name__ == "__main__":
    unittest.main()
