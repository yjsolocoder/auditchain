import dataclasses
import unittest

from auditchain import (
    AuditLog,
    SignedJsonMultiIndex,
    WhereReceipt,
    decode_signed_json_multi_index,
    encode_signed_json_multi_index,
    verify_signed_json_multi_index,
    verify_where_receipt,
)

from tests.test_signed_json_multi_index import SEED_A, SEED_B, j, public_key

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
    # 4: a matches the number 1 but /b is missing; /z is 9
    log.append(j({"a": 1, "z": 9}))
    # 5: not JSON
    log.append(b"not json")
    # 6: no queried fields
    log.append(j({"other": 1}))
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


def _raw_receipt(bundle, expression, start, stop, hits):
    """Build a WhereReceipt with frozen-field validation bypassed."""
    receipt = WhereReceipt.__new__(WhereReceipt)
    object.__setattr__(receipt, "bundle", bundle)
    object.__setattr__(receipt, "expression", expression)
    object.__setattr__(receipt, "start", start)
    object.__setattr__(receipt, "stop", stop)
    object.__setattr__(receipt, "hits", hits)
    return receipt


class WhereReceiptBasicsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_fields_and_defaults(self):
        expression = ("and", (("eq", "/a", 1), ("eq", "/b", "x")))
        receipt = self.bundle.where_receipt(expression)
        self.assertIsInstance(receipt, WhereReceipt)
        self.assertEqual(receipt.bundle, self.bundle)
        self.assertEqual(receipt.expression, expression)
        # The default range covers the whole retained segment.
        self.assertEqual(receipt.start, 0)
        self.assertEqual(receipt.stop, 7)
        self.assertEqual(receipt.hits, (0,))

    def test_hits_match_find_where(self):
        cases = (
            (("eq", "/a", 1), None, None),
            (("eq", "/a", True), None, None),
            (("lt", "/a", 2), None, None),
            (("le", "/a", 1.0), None, None),
            (("gt", "/a", 0), 1, 6),
            (("ge", "/z", 9), None, None),
            (("or", (("eq", "/a", True), ("eq", "/b", "y"))), None, None),
            (("not", ("eq", "/a", 1)), 1, 4),
            (
                (
                    "and",
                    (
                        ("or", (("eq", "/a", 1), ("eq", "/a", True))),
                        ("not", ("eq", "/b", "y")),
                    ),
                ),
                None,
                None,
            ),
        )
        for expression, start, stop in cases:
            receipt = self.bundle.where_receipt(expression, start, stop)
            self.assertEqual(
                receipt.hits, self.bundle.find_where(expression, start, stop)
            )

    def test_empty_and_matches_whole_range(self):
        receipt = self.bundle.where_receipt(("and", ()))
        self.assertEqual(receipt.hits, tuple(range(7)))
        receipt = self.bundle.where_receipt(("and", ()), 2, 4)
        self.assertEqual(receipt.hits, (2, 3))

    def test_empty_or_matches_nothing(self):
        self.assertEqual(self.bundle.where_receipt(("or", ())).hits, ())

    def test_not_complements_every_index_of_the_range(self):
        # Non-JSON, missing-field and non-scalar entries miss the leaf
        # and therefore hit its negation.
        receipt = self.bundle.where_receipt(("not", ("eq", "/a", 1)))
        self.assertEqual(receipt.hits, (2, 3, 5, 6))
        receipt = self.bundle.where_receipt(("not", ("eq", "/a", 1)), 3, 3)
        self.assertEqual(receipt.hits, ())

    def test_empty_range_and_no_match_return_empty_tuple(self):
        self.assertEqual(self.bundle.where_receipt(("and", ()), 3, 3).hits, ())
        self.assertEqual(
            self.bundle.where_receipt(("eq", "/a", 1), 3, 3).hits, ()
        )
        self.assertEqual(
            self.bundle.where_receipt(("eq", "/a", False)).hits, ()
        )

    def test_hits_are_strictly_ascending_without_duplicates(self):
        log = AuditLog()
        for value in (1, 1, 2, 1, 1):
            log.append(j({"a": value, "b": "x"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(
            ("or", (("eq", "/a", 1), ("eq", "/a", 1.0), ("eq", "/a", 1)))
        )
        self.assertEqual(receipt.hits, (0, 1, 3, 4))
        self.assertEqual(receipt.hits, tuple(sorted(set(receipt.hits))))

    def test_receipt_is_immutable(self):
        receipt = self.bundle.where_receipt(("and", ()))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            receipt.hits = ()

    def test_receipt_is_positional_and_compares_by_fields(self):
        receipt = self.bundle.where_receipt(("eq", "/a", 1))
        clone = WhereReceipt(
            receipt.bundle,
            receipt.expression,
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        self.assertEqual(receipt, clone)

    def test_expression_and_range_errors_follow_find_where(self):
        bundle = self.bundle
        with self.assertRaises(TypeError):
            bundle.where_receipt(["eq", "/a", 1])
        with self.assertRaises(ValueError):
            bundle.where_receipt(())
        with self.assertRaises(TypeError):
            bundle.where_receipt((1, (("eq", "/a", 1),)))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("xor", (("eq", "/a", 1),)))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "/a"))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("not",))
        with self.assertRaises(TypeError):
            bundle.where_receipt(("and", ["eq", "/a", 1]))
        with self.assertRaises(TypeError):
            bundle.where_receipt(("eq", 1, 1))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "a", 1))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "/missing", 1))
        with self.assertRaises(TypeError):
            bundle.where_receipt(("eq", "/a", [1]))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "/a", float("inf")))
        with self.assertRaises(TypeError):
            bundle.where_receipt(("lt", "/a", True))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("ge", "/a", float("nan")))
        with self.assertRaises(TypeError):
            bundle.where_receipt(("and", ()), "0")
        with self.assertRaises(TypeError):
            bundle.where_receipt(("and", ()), 0, 1.5)
        with self.assertRaises(ValueError):
            bundle.where_receipt(("and", ()), -1)
        with self.assertRaises(ValueError):
            bundle.where_receipt(("and", ()), 0, 8)
        with self.assertRaises(ValueError):
            bundle.where_receipt(("and", ()), 4, 2)

    def test_validation_order_matches_find_where(self):
        bundle = self.bundle
        # A node's own errors precede its children's.
        with self.assertRaises(ValueError):
            bundle.where_receipt(("bogus", (("eq", 1, 1),)))
        # Children are checked from left to right.
        with self.assertRaises(TypeError):
            bundle.where_receipt(
                ("and", (("eq", 1, 1), ("eq", "/missing", 1)))
            )
        with self.assertRaises(ValueError):
            bundle.where_receipt(
                ("and", (("eq", "/missing", 1), ("eq", 1, 1)))
            )
        # The range is checked last.
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "/missing", 1), 0, 99)
        with self.assertRaises(TypeError):
            bundle.where_receipt(("eq", 1, 1), True)

    def test_empty_result_does_not_mask_invalid_branch(self):
        # An empty range or an already determined intermediate result
        # never hides a later illegal branch.
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(("eq", "/missing", 1), 2, 2)
        contradicting = ("and", (("eq", "/a", 1), ("eq", "/a", 2)))
        self.assertEqual(self.bundle.find_where(contradicting), ())
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(
                ("and", (contradicting, ("eq", "/missing", 1)))
            )
        with self.assertRaises(TypeError):
            self.bundle.where_receipt(
                ("and", (contradicting, ("eq", "/a", [1])))
            )


class VerifyWhereReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.key = public_key(SEED_A)

    def test_genuine_receipt_verifies(self):
        receipt = self.bundle.where_receipt(
            ("and", (("eq", "/a", 1), ("eq", "/b", "x")))
        )
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_empty_and_full_range_receipts_verify(self):
        for receipt in (
            self.bundle.where_receipt(("and", ())),
            self.bundle.where_receipt(("or", ())),
            self.bundle.where_receipt(("and", ()), 3, 3),
            self.bundle.where_receipt(("eq", "/a", False)),
            self.bundle.where_receipt(("not", ("eq", "/a", 1)), 1, 4),
            self.bundle.where_receipt(("lt", "/a", 2), 2, 5),
        ):
            self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_wrong_public_key_returns_false(self):
        receipt = self.bundle.where_receipt(("eq", "/a", 1))
        self.assertFalse(verify_where_receipt(receipt, public_key(SEED_B)))

    def test_tampered_signature_returns_false(self):
        receipt = self.bundle.where_receipt(("eq", "/a", 1))
        other = make_log().signed_json_multi_index(POINTERS, SEED_B)
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

    def test_tampered_index_evidence_returns_false(self):
        # A bundle over a different log signed by the same key does not
        # authenticate this receipt's hits.
        log = make_log()
        log.append(j({"a": 1, "b": "x"}))
        other = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = self.bundle.where_receipt(
            ("and", (("eq", "/a", 1), ("eq", "/b", "x")))
        )
        shifted = WhereReceipt(
            other, receipt.expression, 0, 8, receipt.hits
        )
        self.assertFalse(verify_where_receipt(shifted, self.key))

    def test_under_reported_hit_returns_false(self):
        # /a == 1 matches 0, 1 and 4; dropping any of them fails.
        for hits in ((0, 1), (1, 4), (0, 4), ()):
            receipt = WhereReceipt(
                self.bundle, ("eq", "/a", 1), 0, 7, hits
            )
            self.assertFalse(verify_where_receipt(receipt, self.key))

    def test_over_reported_hit_returns_false(self):
        for hits in ((0, 1, 2, 4), (0, 1, 3, 4), (0, 1, 4, 5)):
            receipt = WhereReceipt(
                self.bundle, ("eq", "/a", 1), 0, 7, hits
            )
            self.assertFalse(verify_where_receipt(receipt, self.key))

    def test_expression_is_not_separately_authenticated(self):
        # Editing the expression (and range) still verifies whenever the
        # declared hits remain the complete result of the edited query.
        receipt = self.bundle.where_receipt(
            ("and", (("eq", "/a", 1), ("eq", "/b", "x")))
        )
        edited = WhereReceipt(
            receipt.bundle,
            ("or", (("and", (("eq", "/a", 1), ("eq", "/b", "x"))),)),
            0,
            7,
            (0,),
        )
        self.assertTrue(verify_where_receipt(edited, self.key))
        narrowed = WhereReceipt(
            receipt.bundle, ("eq", "/a", 1), 0, 2, (0, 1)
        )
        self.assertTrue(verify_where_receipt(narrowed, self.key))

    def test_non_receipt_raises_type_error(self):
        for bad in ("x", 1, None, self.bundle):
            with self.assertRaises(TypeError):
                verify_where_receipt(bad, self.key)

    def test_public_key_type_and_length(self):
        receipt = self.bundle.where_receipt(("and", ()))
        for bad in ("x", 1, None, bytearray(self.key)):
            with self.assertRaises(TypeError):
                verify_where_receipt(receipt, bad)
        for bad in (b"", self.key[:-1], self.key + b"\x00"):
            with self.assertRaises(ValueError):
                verify_where_receipt(receipt, bad)

    def test_structural_errors_raise(self):
        bundle = self.bundle
        with self.assertRaises(TypeError):
            WhereReceipt("not-a-bundle", ("and", ()), 0, 7, ())
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ["eq", "/a", 1], 0, 7, (0,))
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("eq", "/missing", 1), 0, 7, ())
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("and", ()), None, 7, ())
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("and", ()), 0, True, ())
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 6, 3, ())
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 0, 8, ())
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("and", ()), 0, 7, [0])
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("and", ()), 0, 7, (0.5,))
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("and", ()), 0, 7, (True,))
        # Hit outside [start, stop).
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 0, 7, (7,))
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 2, 7, (1,))
        # Duplicates and misordering.
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 0, 7, (2, 2))
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 0, 7, (3, 1))

    def test_expression_validated_before_range_and_hits(self):
        bundle = self.bundle
        # An illegal branch raises even with an illegal range or hits.
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("eq", "/missing", 1), 6, 3, (9,))
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("eq", "/a", [1]), 0, 7, [0])
        # The range is checked before the hit tuple.
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 0, 8, (2, 2))

    def test_signature_failure_does_not_mask_structural_errors(self):
        # The signature is invalid here, but the illegal hit tuple must
        # still raise rather than return False.
        other = make_log().signed_json_multi_index(POINTERS, SEED_B)
        repackaged = SignedJsonMultiIndex(self.bundle.index, other.signature)
        with self.assertRaises(ValueError):
            verify_where_receipt(
                _raw_receipt(repackaged, ("eq", "/a", 1), 0, 7, (2, 2)),
                self.key,
            )
        with self.assertRaises(ValueError):
            verify_where_receipt(
                _raw_receipt(repackaged, ("eq", "/missing", 1), 0, 7, ()),
                self.key,
            )

    def test_bypassed_fields_raise_like_the_constructor(self):
        receipt = self.bundle.where_receipt(("eq", "/a", 1))
        object.__setattr__(receipt, "hits", (2, 2))
        with self.assertRaises(ValueError):
            verify_where_receipt(receipt, self.key)


class WhereReceiptCompatibilityTest(unittest.TestCase):
    def setUp(self):
        self.key = public_key(SEED_A)

    def test_decoded_index_bundle(self):
        bundle = make_bundle()
        decoded = decode_signed_json_multi_index(
            encode_signed_json_multi_index(bundle)
        )
        expression = ("and", (("ge", "/a", 1), ("not", ("eq", "/b", "y"))))
        receipt = decoded.where_receipt(expression, 1, 6)
        self.assertEqual(receipt.hits, bundle.find_where(expression, 1, 6))
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_pruned_snapshot(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("not", ("eq", "/a", True)))
        self.assertEqual(receipt.start, 2)
        self.assertEqual(receipt.stop, 7)
        self.assertEqual(receipt.hits, (3, 4, 5, 6))
        self.assertTrue(verify_where_receipt(receipt, self.key))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("and", ()), 0, 3)

    def test_other_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        log.append(j({"a": 1, "b": "x"}))
        log.append(j({"a": 2, "b": "y"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("or", (("eq", "/b", "y"),)))
        self.assertEqual(receipt.hits, (1,))
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_empty_snapshot(self):
        bundle = AuditLog().signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("and", ()))
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_later_appends_and_prunes_do_not_change_receipt(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("not", ("eq", "/a", 1)))
        hits = receipt.hits
        log.append(j({"a": 1, "b": "x"}))
        log.prune(1, log.seal(1))
        self.assertEqual(receipt.hits, hits)
        self.assertTrue(verify_where_receipt(receipt, self.key))
        self.assertTrue(verify_signed_json_multi_index(receipt.bundle, self.key))


if __name__ == "__main__":
    unittest.main()
