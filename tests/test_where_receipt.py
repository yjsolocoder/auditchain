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
    # 6: non-scalar at /a
    log.append(j({"a": [1], "b": "x"}))
    # 7: no queried fields
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
        self.assertEqual(receipt.stop, 8)
        self.assertEqual(receipt.hits, (0,))

    def test_hits_match_find_where(self):
        cases = (
            (("eq", "/a", 1), None, None),
            (("or", (("eq", "/a", True), ("eq", "/b", "y"))), None, None),
            (("not", ("eq", "/a", 1)), None, None),
            (("and", (("ge", "/a", 1), ("le", "/a", 1))), 0, 5),
            (("eq", "/z", 9), 1, 6),
            (("and", ()), 2, 4),
        )
        for expression, start, stop in cases:
            receipt = self.bundle.where_receipt(expression, start, stop)
            self.assertEqual(
                receipt.hits, self.bundle.find_where(expression, start, stop)
            )

    def test_empty_and_matches_whole_range(self):
        receipt = self.bundle.where_receipt(("and", ()))
        self.assertEqual(receipt.hits, tuple(range(8)))
        receipt = self.bundle.where_receipt(("and", ()), 2, 4)
        self.assertEqual(receipt.hits, (2, 3))

    def test_empty_or_matches_nothing(self):
        self.assertEqual(self.bundle.where_receipt(("or", ())).hits, ())

    def test_not_complements_against_the_range(self):
        receipt = self.bundle.where_receipt(("not", ("eq", "/a", 1)))
        self.assertEqual(receipt.hits, (2, 3, 5, 6, 7))
        receipt = self.bundle.where_receipt(("not", ("eq", "/a", 1)), 1, 4)
        self.assertEqual(receipt.hits, (2, 3))

    def test_non_matching_entries_hit_the_negation(self):
        # Non-JSON (5), missing-field (4, 7) and non-scalar (6) entries
        # never match the eq leaf but do match its negation.
        receipt = self.bundle.where_receipt(("not", ("eq", "/b", "x")))
        self.assertEqual(receipt.hits, (1, 4, 5, 7))

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
        leaf = ("eq", "/a", 1)
        receipt = bundle.where_receipt(("or", (leaf, leaf, leaf)))
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
            bundle.where_receipt(("and",))
        with self.assertRaises(TypeError):
            bundle.where_receipt(("and", ["eq", "/a", 1]))
        with self.assertRaises(TypeError):
            bundle.where_receipt(("eq", b"/a", 1))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "a", 1))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "/missing", 1))
        with self.assertRaises(TypeError):
            bundle.where_receipt(("eq", "/a", [1]))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "/a", float("inf")))
        with self.assertRaises(TypeError):
            bundle.where_receipt(("lt", "/a", "1"))
        with self.assertRaises(ValueError):
            bundle.where_receipt(("ge", "/a", float("nan")))
        with self.assertRaises(TypeError):
            bundle.where_receipt(("eq", "/a", 1), "0")
        with self.assertRaises(TypeError):
            bundle.where_receipt(("eq", "/a", 1), 0, 1.5)
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "/a", 1), -1)
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "/a", 1), 0, 9)
        with self.assertRaises(ValueError):
            bundle.where_receipt(("eq", "/a", 1), 4, 2)

    def test_empty_result_does_not_mask_invalid_branch(self):
        # The whole expression is validated before any lookup, so an
        # already determined intermediate result or an empty range never
        # hides a bad branch.
        contradicting = ("and", (("eq", "/a", 1), ("eq", "/a", 2)))
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(
                ("and", (contradicting, ("eq", "/missing", 1)))
            )
        with self.assertRaises(TypeError):
            self.bundle.where_receipt(
                ("and", (contradicting, ("eq", "/a", [1])))
            )
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(("eq", "/missing", 1), 3, 3)
        with self.assertRaises(TypeError):
            self.bundle.where_receipt(("eq", "/a", [1]), 3, 3)

    def test_validation_order_parent_children_range(self):
        # A bad parent operator wins over a bad child; children are
        # checked left to right; the range is checked last.
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(("bogus", (("eq", b"/a", 1),)))
        with self.assertRaises(TypeError):
            self.bundle.where_receipt(
                ("and", (("eq", b"/a", 1), ("eq", "/missing", 1)))
            )
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(("eq", "/missing", 1), 0, 99)
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(("eq", "/a", 1), 0, 99)


class VerifyWhereReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.key = public_key(SEED_A)

    def test_genuine_receipt_verifies(self):
        expression = ("and", (("eq", "/a", 1), ("not", ("eq", "/b", "y"))))
        receipt = self.bundle.where_receipt(expression)
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_empty_and_full_range_receipts_verify(self):
        for receipt in (
            self.bundle.where_receipt(("and", ())),
            self.bundle.where_receipt(("or", ())),
            self.bundle.where_receipt(("and", ()), 3, 3),
            self.bundle.where_receipt(("eq", "/a", False)),
            self.bundle.where_receipt(("not", ("eq", "/a", 1)), 1, 4),
            self.bundle.where_receipt(("ge", "/a", 1)),
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
            other, receipt.expression, 0, 9, receipt.hits
        )
        self.assertFalse(verify_where_receipt(shifted, self.key))

    def test_under_reported_hit_returns_false(self):
        # ("eq", "/a", 1) matches 0, 1 and 4; dropping any of them fails.
        for hits in ((0, 1), (1, 4), (0, 4), ()):
            receipt = WhereReceipt(
                self.bundle, ("eq", "/a", 1), 0, 8, hits
            )
            self.assertFalse(verify_where_receipt(receipt, self.key))

    def test_over_reported_hit_returns_false(self):
        for hits in ((0, 1, 2, 4), (0, 1, 3, 4), (0, 1, 4, 5)):
            receipt = WhereReceipt(
                self.bundle, ("eq", "/a", 1), 0, 8, hits
            )
            self.assertFalse(verify_where_receipt(receipt, self.key))

    def test_expression_is_not_separately_authenticated(self):
        # Editing the expression (and the range) still verifies whenever
        # the declared hits remain the complete result of the edited
        # query.
        receipt = self.bundle.where_receipt(
            ("and", (("eq", "/a", 1), ("eq", "/b", "x")))
        )
        edited = WhereReceipt(
            receipt.bundle,
            ("not", ("not", ("eq", "/a", 1))),
            0,
            8,
            (0, 1, 4),
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
            WhereReceipt("not-a-bundle", ("and", ()), 0, 8, ())
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ["eq", "/a", 1], 0, 8, (0,))
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("eq", "/missing", 1), 0, 8, ())
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("and", ()), None, 8, ())
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("and", ()), 0, True, ())
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 6, 3, ())
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 0, 9, ())
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("and", ()), 0, 8, [0])
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("and", ()), 0, 8, (0.5,))
        with self.assertRaises(TypeError):
            WhereReceipt(bundle, ("and", ()), 0, 8, (True,))
        # Hit outside [start, stop).
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 0, 8, (8,))
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 2, 8, (1,))
        # Duplicates and misordering.
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 0, 8, (2, 2))
        with self.assertRaises(ValueError):
            WhereReceipt(bundle, ("and", ()), 0, 8, (3, 1))

    def test_signature_failure_does_not_mask_structural_errors(self):
        # The signature is invalid here, but the illegal hit tuple and
        # the illegal expression must still raise rather than return
        # False.
        other = make_log().signed_json_multi_index(POINTERS, SEED_B)
        repackaged = SignedJsonMultiIndex(self.bundle.index, other.signature)
        with self.assertRaises(ValueError):
            verify_where_receipt(
                _raw_receipt(repackaged, ("eq", "/a", 1), 0, 8, (2, 2)),
                self.key,
            )
        with self.assertRaises(ValueError):
            verify_where_receipt(
                _raw_receipt(repackaged, ("eq", "/missing", 1), 0, 8, ()),
                self.key,
            )
        with self.assertRaises(TypeError):
            verify_where_receipt(
                _raw_receipt(repackaged, ("eq", "/a", 1), 0, 8, [0]),
                self.key,
            )

    def test_bypassed_fields_raise_like_the_constructor(self):
        receipt = self.bundle.where_receipt(("eq", "/a", 1))
        object.__setattr__(receipt, "hits", (2, 2))
        with self.assertRaises(ValueError):
            verify_where_receipt(receipt, self.key)
        object.__setattr__(receipt, "hits", (0, 1, 4))
        object.__setattr__(receipt, "expression", ["eq", "/a", 1])
        with self.assertRaises(TypeError):
            verify_where_receipt(receipt, self.key)


class WhereReceiptSnapshotAndOfflineTest(unittest.TestCase):
    def setUp(self):
        self.key = public_key(SEED_A)

    def test_works_off_decoded_bundle_without_log_or_key(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        decoded = decode_signed_json_multi_index(
            encode_signed_json_multi_index(bundle)
        )
        expression = ("and", (("eq", "/a", 1), ("not", ("eq", "/b", "y"))))
        receipt = decoded.where_receipt(expression)
        self.assertEqual(receipt.hits, (0, 4))
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_pruned_snapshot(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("eq", "/a", 1))
        self.assertEqual((receipt.start, receipt.stop), (3, 8))
        self.assertEqual(receipt.hits, (4,))
        self.assertTrue(verify_where_receipt(receipt, self.key))
        # The complement is clipped to the retained segment.
        receipt = bundle.where_receipt(("not", ("eq", "/a", 1)))
        self.assertEqual(receipt.hits, (3, 5, 6, 7))
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_other_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        log.append(j({"a": 1, "b": "x"}))
        log.append(j({"a": 2, "b": "y"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("eq", "/b", "y"))
        self.assertEqual(receipt.hits, (1,))
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_later_appends_and_prunes_do_not_change_old_receipt(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        expression = ("and", (("eq", "/a", 1), ("eq", "/b", "x")))
        receipt = bundle.where_receipt(expression)
        hits = receipt.hits
        log.append(j({"a": 1, "b": "x"}))
        log.prune(2, log.seal(2))
        self.assertEqual(receipt.hits, hits)
        self.assertTrue(verify_where_receipt(receipt, self.key))
        self.assertTrue(
            verify_signed_json_multi_index(receipt.bundle, self.key)
        )

    def test_issuing_and_verifying_are_read_only(self):
        bundle = make_bundle()
        blob = encode_signed_json_multi_index(bundle)
        receipt = bundle.where_receipt(("not", ("eq", "/a", 1)), 1, 4)
        verify_where_receipt(receipt, self.key)
        for bad in (
            lambda: bundle.where_receipt(["eq", "/a", 1]),
            lambda: bundle.where_receipt(("eq", "/missing", 1)),
            lambda: bundle.where_receipt(("eq", "/a", 1), 99),
        ):
            with self.assertRaises((TypeError, ValueError)):
                bad()
        self.assertEqual(encode_signed_json_multi_index(bundle), blob)


if __name__ == "__main__":
    unittest.main()
