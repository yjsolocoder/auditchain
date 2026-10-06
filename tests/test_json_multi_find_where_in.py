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

POINTERS = ("/n", "/name")

KEY = bytes(range(32))


def make_log():
    log = AuditLog()
    # 0: string "alpha" at /name, integer 1 at /n
    log.append(j({"name": "alpha", "n": 1}))
    # 1: string "alpine" at /name, integer 2 at /n
    log.append(j({"name": "alpine", "n": 2}))
    # 2: string "beta" at /name, integer 3 at /n
    log.append(j({"name": "beta", "n": 3}))
    # 3: empty string at /name, integer 4 at /n
    log.append(j({"name": "", "n": 4}))
    # 4: non-string (integer 7) at /name, integer 5 at /n
    log.append(j({"name": 7, "n": 5}))
    # 5: /name and /n missing
    log.append(j({"other": "alpha"}))
    # 6: not JSON
    log.append(b"not json")
    # 7: case differs ("Alpha"), integer 6 at /n
    log.append(j({"name": "Alpha", "n": 6}))
    # 8: encrypted entry whose plaintext would match
    log.encrypt(j({"name": "albatross", "n": 7}), KEY)
    # 9: explicit null at /name and /n
    log.append(j({"name": None, "n": None}))
    # 10: booleans at /name and /n
    log.append(j({"name": True, "n": True}))
    # 11: arrays at /name and /n
    log.append(j({"name": [1], "n": [2]}))
    # 12: objects at /name and /n
    log.append(j({"name": {"x": 1}, "n": {"y": 2}}))
    # 13: float 1.5 at /name, negative zero at /n
    log.append(j({"name": 1.5, "n": -0.0}))
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


class FindWhereInTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_basic_in(self):
        self.assertEqual(
            self.bundle.find_where(("in", "/name", ("alpha", "beta"))),
            (0, 2),
        )
        self.assertEqual(
            self.bundle.find_where(("in", "/n", (1, 3, 5))), (0, 2, 4)
        )

    def test_single_candidate_matches_eq(self):
        self.assertEqual(
            self.bundle.find_where(("in", "/name", ("alpha",))),
            self.bundle.find_where(("eq", "/name", "alpha")),
        )

    def test_empty_candidates_match_nothing(self):
        self.assertEqual(self.bundle.find_where(("in", "/name", ())), ())
        self.assertEqual(self.bundle.find_where(("in", "/n", ())), ())

    def test_duplicate_candidates_add_no_hits(self):
        result = self.bundle.find_where(
            ("in", "/name", ("alpha", "alpha", "beta", "alpha"))
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, (0, 2))
        self.assertEqual(
            self.bundle.find_where(("in", "/n", (1, 1.0, 1))), (0,)
        )

    def test_result_is_strictly_ascending_without_duplicates(self):
        result = self.bundle.find_where(("in", "/n", (5, 1, 3, 2)))
        self.assertEqual(result, (0, 1, 2, 4))
        self.assertEqual(tuple(sorted(set(result))), result)

    def test_int_and_float_candidates_compare_by_exact_value(self):
        # A float candidate matches integer entries of the same value and
        # vice versa.
        self.assertEqual(self.bundle.find_where(("in", "/n", (2.0,))), (1,))
        self.assertEqual(
            self.bundle.find_where(("in", "/name", (7, 1.5))), (4, 13)
        )
        # A big integer never rounds to a nearby float candidate.
        log = AuditLog()
        log.append(j({"n": 2**53 + 1}))
        bundle = log.signed_json_multi_index(("/n",), SEED_A)
        self.assertEqual(bundle.find_where(("in", "/n", (2.0**53,))), ())
        self.assertEqual(bundle.find_where(("in", "/n", (2**53 + 1,))), (0,))

    def test_negative_zero_matches_zero(self):
        self.assertEqual(self.bundle.find_where(("in", "/n", (-0.0,))), (13,))
        self.assertEqual(self.bundle.find_where(("in", "/n", (0,))), (13,))
        self.assertEqual(self.bundle.find_where(("in", "/n", (0.0,))), (13,))

    def test_booleans_are_not_numbers(self):
        self.assertEqual(self.bundle.find_where(("in", "/n", (True,))), (10,))
        self.assertEqual(self.bundle.find_where(("in", "/n", (False,))), ())
        # 1 does not match the boolean entry and True does not match the
        # integer entries.
        self.assertEqual(
            self.bundle.find_where(("in", "/n", (1, True))), (0, 10)
        )

    def test_none_matches_only_explicit_null(self):
        self.assertEqual(
            self.bundle.find_where(("in", "/name", (None,))), (9,)
        )
        # A missing field (entry 5) is not null.
        self.assertEqual(self.bundle.find_where(("in", "/n", (None,))), (9,))

    def test_strings_match_without_unicode_normalization(self):
        precomposed = "\u00e9lan"  # precomposed é (U+00E9)
        decomposed = "e\u0301lan"  # "e" + combining acute (U+0301)
        self.assertNotEqual(precomposed, decomposed)
        log = AuditLog()
        log.append(j({"s": precomposed}))
        log.append(j({"s": decomposed}))
        bundle = log.signed_json_multi_index(("/s",), SEED_A)
        self.assertEqual(
            bundle.find_where(("in", "/s", (precomposed,))), (0,)
        )
        self.assertEqual(
            bundle.find_where(("in", "/s", (decomposed,))), (1,)
        )
        self.assertEqual(
            bundle.find_where(("in", "/s", (precomposed, decomposed))),
            (0, 1),
        )

    def test_missing_non_json_non_scalar_and_encrypted_never_match(self):
        # Entries 5 (missing), 6 (not JSON), 8 (encrypted), 11 (array)
        # and 12 (object) never satisfy an in leaf, so all of them
        # satisfy its negation.
        everything = ("in", "/n", (1, 2, 3, 4, 5, 6, 0.0, None, True))
        self.assertEqual(
            self.bundle.find_where(everything), (0, 1, 2, 3, 4, 7, 9, 10, 13)
        )
        self.assertEqual(
            self.bundle.find_where(("not", everything)), (5, 6, 8, 11, 12)
        )

    def test_combines_with_and_or_not(self):
        self.assertEqual(
            self.bundle.find_where(
                (
                    "and",
                    (
                        ("in", "/name", ("alpha", "alpine", "beta")),
                        ("ge", "/n", 2),
                    ),
                )
            ),
            (1, 2),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("or", (("in", "/n", (1,)), ("in", "/n", (2, 3))))
            ),
            (0, 1, 2),
        )
        self.assertEqual(
            self.bundle.find_where(
                (
                    "and",
                    (
                        ("in", "/name", ("alpha", "alpine")),
                        ("not", ("in", "/n", (1,))),
                    ),
                )
            ),
            (1,),
        )

    def test_range_clipping_and_empty_range(self):
        self.assertEqual(
            self.bundle.find_where(("in", "/name", ("alpha", "beta")), 1, 3),
            (2,),
        )
        self.assertEqual(
            self.bundle.find_where(("in", "/name", ("alpha", "beta")), 2, 2),
            (),
        )
        self.assertEqual(
            self.bundle.find_where(("in", "/n", (1,)), 0, 0), ()
        )

    def test_pruned_snapshot_ranges(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        # The default range is the whole retained segment.
        self.assertEqual(
            bundle.find_where(("in", "/n", (1, 2, 3, 4))), (2, 3)
        )
        self.assertEqual(
            bundle.find_where(("not", ("in", "/n", (3,)))),
            (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13),
        )
        with self.assertRaises(ValueError):
            bundle.find_where(("in", "/n", (1,)), 0, 3)

    def test_frozen_snapshot_survives_append_and_prune(self):
        before = self.bundle.find_where(("in", "/name", ("alpha", "beta")))
        self.assertEqual(before, (0, 2))
        self.log.append(j({"name": "beta", "n": 8}))
        self.log.prune(1, self.log.seal(1))
        self.assertEqual(
            self.bundle.find_where(("in", "/name", ("alpha", "beta"))), before
        )
        # A fresh index covers only the retained segment: entry 0 is
        # pruned away, the new matching entry 14 is covered.
        self.assertEqual(
            self.log.signed_json_multi_index(POINTERS, SEED_A).find_where(
                ("in", "/name", ("alpha", "beta"))
            ),
            (2, 14),
        )

    def test_type_errors(self):
        for expression in (
            ["in", "/n", (1,)],  # node not a tuple
            (1, "/n", (1,)),  # operator not a string
            ("in", 1, (1,)),  # pointer not a string
            ("in", None, (1,)),
            ("in", "/n", [1, 2]),  # values not a tuple
            ("in", "/n", "alpha"),
            ("in", "/n", 1),
            ("in", "/n", None),
            ("in", "/n", (b"1",)),  # candidate not a supported scalar
            ("in", "/n", ((1,),)),
            ("in", "/n", ([1],)),
            ("in", "/n", ({"a": 1},)),
        ):
            with self.assertRaises(TypeError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_value_errors(self):
        for expression in (
            ("in", "/n"),  # wrong length
            ("in", "/n", (1,), "extra"),
            ("in",),  # wrong length
            ("inn", "/n", (1,)),  # unknown operator
            ("in", "n", (1,)),  # malformed pointer
            ("in", "/missing", (1,)),  # uncovered pointer
            ("in", "/n", (float("nan"),)),  # non-finite candidate
            ("in", "/n", (float("inf"),)),
            ("in", "/n", (1, float("-inf"))),
        ):
            with self.assertRaises(ValueError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_range_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", "/n", (1,)), True, 3)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", "/n", (1,)), 0, "3")
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", "/n", (1,)), 0.0, 3)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/n", (1,)), 3, 2)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/n", (1,)), 0, 15)

    def test_node_validated_before_container_and_candidates(self):
        # Length and pointer come before the candidate container.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", 1, [1], "extra"))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/missing", [1]))
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", 1, [1]))
        # The container comes before each candidate.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", "/n", [float("nan")]))
        # Candidates are checked in order.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", "/n", (1, b"x", float("nan"))))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/n", (1, float("nan"), b"x")))

    def test_expression_fully_validated_before_any_lookup(self):
        # An empty candidate tuple, an empty range or an already
        # determined intermediate result never masks an illegal branch.
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (("in", "/n", ()), ("eq", "/n", b"x")))
            )
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("and", (("eq", "/n", 999), ("in", "/n", (b"x",))))
            )
        with self.assertRaises(TypeError):
            self.bundle.find_where(("in", "/n", (b"x",)), 2, 2)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/missing", (1,)), 2, 2)
        # Children are checked left to right.
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("or", (("in", "/missing", (1,)), ("in", "/n", [1])))
            )
        # The range is validated after a legal expression.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("in", "/n", (1,)), 2, 1)

    def test_read_only(self):
        before = self.bundle.find_where(("in", "/n", (1, 2, 3)))
        self.bundle.find_where(("in", "/n", (1, 2, 3)))
        self.assertEqual(
            self.bundle.find_where(("in", "/n", (1, 2, 3))), before
        )


class WhereReceiptInTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = (
            "and",
            (
                ("in", "/name", ("alpha", "alpine", "beta")),
                ("not", ("in", "/n", (1,))),
            ),
        )
        self.receipt = self.bundle.where_receipt(self.expression)

    def test_receipt_fields(self):
        self.assertIsInstance(self.receipt, WhereReceipt)
        self.assertEqual(self.receipt.expression, self.expression)
        self.assertEqual((self.receipt.start, self.receipt.stop), (0, 14))
        self.assertEqual(self.receipt.hits, (1, 2))

    def test_verify_true_with_trusted_key(self):
        self.assertTrue(
            verify_where_receipt(self.receipt, public_key(SEED_A))
        )

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(
            verify_where_receipt(self.receipt, public_key(SEED_B))
        )

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (1,), (1, 2, 3)):
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

    def test_unsigned_receipt_checks_only_the_current_query(self):
        # The bare receipt's expression carries no signature: reordering
        # the candidates still verifies whenever the declared hits remain
        # exactly the complete result of the edited query.
        receipt = WhereReceipt(
            self.receipt.bundle,
            (
                "and",
                (
                    ("in", "/name", ("beta", "alpine", "alpha")),
                    ("not", ("in", "/n", (1,))),
                ),
            ),
            self.receipt.start,
            self.receipt.stop,
            (1, 2),
        )
        self.assertTrue(verify_where_receipt(receipt, public_key(SEED_A)))

    def test_round_trip_preserves_candidates_and_bytes(self):
        expression = (
            "or",
            (
                ("in", "/n", (3, 1, 3, -0.0, True, None)),
                ("in", "/name", ("alpha", "alpha", "é")),
                ("in", "/name", ()),
            ),
        )
        receipt = self.bundle.where_receipt(expression)
        data = encode_where_receipt(receipt)
        restored = decode_where_receipt(data)
        self.assertEqual(restored, receipt)
        self.assertEqual(restored.expression, expression)
        # Candidate order, repetitions, scalar types and negative zero
        # survive the round trip exactly.
        candidates = restored.expression[1][0][2]
        self.assertEqual(candidates, (3, 1, 3, -0.0, True, None))
        self.assertIsInstance(candidates[0], int)
        self.assertIsInstance(candidates[3], float)
        self.assertEqual(repr(candidates[3]), "-0.0")
        self.assertIs(candidates[4], True)
        self.assertIs(candidates[5], None)
        self.assertEqual(encode_where_receipt(restored), data)
        self.assertTrue(verify_where_receipt(restored, public_key(SEED_A)))

    def test_old_expression_encoding_unchanged(self):
        # An expression without the in operator encodes with the same
        # tags as before and old encodings still decode byte-identically.
        expression = (
            "or",
            (("eq", "/name", "alpha"), ("lt", "/n", 3), ("not", ("ge", "/n", 2))),
        )
        receipt = self.bundle.where_receipt(expression)
        data = encode_where_receipt(receipt)
        self.assertEqual(encode_where_receipt(decode_where_receipt(data)), data)

    def test_decode_type_error(self):
        data = encode_where_receipt(self.receipt)
        for bad in (bytearray(data), memoryview(data), data.decode("latin1"), 1):
            with self.assertRaises(TypeError, msg=type(bad).__name__):
                decode_where_receipt(bad)

    def test_decode_truncation_and_trailing_bytes(self):
        data = encode_where_receipt(self.receipt)
        for cut in (len(data) - 1, len(data) - 9, 40):
            with self.assertRaises(ValueError, msg=str(cut)):
                decode_where_receipt(data[:cut])
        with self.assertRaises(ValueError):
            decode_where_receipt(data + b"\x00")

    def test_decode_rejects_unknown_node_tag(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(11)  # unknown node tag
            + u64(0)
            + u64(14)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_illegal_candidate_scalar(self):
        for tag, key in (
            (1, b"1.0"),  # non-canonical integer
            (1, b""),  # empty integer
            (2, b"nan"),  # non-finite float
            (2, b"1.50"),  # non-canonical float
            (3, b"x"),  # non-empty boolean blob
            (0, b"\xff"),  # invalid UTF-8 string
            (9, b""),  # unknown value tag
        ):
            raw = (
                b"auditchain/where-receipt/v1\0"
                + u64(1)
                + blob(encode_signed_json_multi_index(self.bundle))
                + u64(10)  # in node tag
                + blob(b"/n")
                + u64(1)  # one candidate
                + u64(tag)
                + blob(key)
                + u64(0)
                + u64(14)
                + u64(0)
            )
            with self.assertRaises(ValueError, msg=repr((tag, key))):
                decode_where_receipt(raw)

    def test_decode_rejects_candidate_count_mismatch(self):
        receipt = self.bundle.where_receipt(("in", "/n", (1, 2)))
        data = encode_where_receipt(receipt)
        marker = blob(b"/n") + u64(2)
        position = data.index(marker) + len(marker)
        # Declaring fewer candidates than present misaligns the rest.
        fewer = data[:position] + u64(1) + data[position:]
        with self.assertRaises(ValueError):
            decode_where_receipt(fewer)
        # Declaring more candidates than present truncates the rest.
        more = data[:position] + u64(3) + data[position:]
        with self.assertRaises(ValueError):
            decode_where_receipt(more)

    def test_decode_rejects_invalid_utf8_pointer(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(10)  # in node tag
            + blob(b"\xff")
            + u64(0)
            + u64(0)
            + u64(14)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)


class SignedWhereReceiptInTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.public = public_key(SEED_A)
        self.expression = ("in", "/n", (3, 1, -0.0))
        self.receipt = self.bundle.where_receipt(self.expression)
        self.signed = sign_where_receipt(self.receipt, SEED_A)

    def test_sign_is_deterministic(self):
        again = sign_where_receipt(self.receipt, SEED_A)
        self.assertEqual(
            encode_signed_where_receipt(self.signed),
            encode_signed_where_receipt(again),
        )

    def test_verify_true(self):
        self.assertTrue(verify_signed_where_receipt(self.signed, self.public))

    def test_signed_round_trip_byte_identical(self):
        data = encode_signed_where_receipt(self.signed)
        restored = decode_signed_where_receipt(data)
        self.assertEqual(restored, self.signed)
        self.assertEqual(encode_signed_where_receipt(restored), data)
        self.assertTrue(verify_signed_where_receipt(restored, self.public))

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(
            verify_signed_where_receipt(self.signed, public_key(SEED_B))
        )

    def test_verify_false_on_under_and_over_report(self):
        # The complete result of ("in", "/n", (3, 1, -0.0)) is (0, 2, 13).
        for hits in ((), (0,), (0, 2), (0, 2, 9, 13)):
            receipt = WhereReceipt(
                self.receipt.bundle,
                self.expression,
                self.receipt.start,
                self.receipt.stop,
                hits,
            )
            signed = sign_where_receipt(receipt, SEED_A)
            self.assertFalse(
                verify_signed_where_receipt(signed, self.public),
                msg=repr(hits),
            )

    def test_reordered_candidates_fail_even_with_same_hits(self):
        # The complete result of the reordered query is identical, but
        # the signature binds the candidate order.
        reordered = WhereReceipt(
            self.receipt.bundle,
            ("in", "/n", (1, 3, -0.0)),
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        self.assertEqual(
            self.bundle.find_where(reordered.expression), self.receipt.hits
        )
        forged = SignedWhereReceipt(reordered, self.signed.signature)
        self.assertFalse(verify_signed_where_receipt(forged, self.public))

    def test_int_candidate_respelled_as_float_fails(self):
        # 1 and 1.0 hit the same entries, but the signature binds the
        # scalar type.
        respelled = WhereReceipt(
            self.receipt.bundle,
            ("in", "/n", (3, 1.0, -0.0)),
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        self.assertEqual(
            self.bundle.find_where(respelled.expression), self.receipt.hits
        )
        forged = SignedWhereReceipt(respelled, self.signed.signature)
        self.assertFalse(verify_signed_where_receipt(forged, self.public))

    def test_negative_zero_candidate_respelled_fails(self):
        respelled = WhereReceipt(
            self.receipt.bundle,
            ("in", "/n", (3, 1, 0.0)),
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        self.assertEqual(
            self.bundle.find_where(respelled.expression), self.receipt.hits
        )
        forged = SignedWhereReceipt(respelled, self.signed.signature)
        self.assertFalse(verify_signed_where_receipt(forged, self.public))


if __name__ == "__main__":
    unittest.main()
