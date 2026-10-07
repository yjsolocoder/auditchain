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

POINTERS = ("", "/a", "/arr", "/arr/0", "/b/c")

KEY = bytes(range(32))


def make_log():
    log = AuditLog()
    # 0: integer /a, array /arr, nested string /b/c
    log.append(j({"a": 1, "arr": [10, 20], "b": {"c": "x"}}))
    # 1: explicit null at /a
    log.append(j({"a": None}))
    # 2: object at /a
    log.append(j({"a": {"nested": 1}}))
    # 3: empty array at /a
    log.append(j({"a": []}))
    # 4: empty object at /a
    log.append(j({"a": {}}))
    # 5: empty object document; /a missing
    log.append(j({}))
    # 6: empty array document; /a missing
    log.append(j([]))
    # 7: not JSON
    log.append(b"not json")
    # 8: repeated member name
    log.append(b'{"a": 1, "a": 2}')
    # 9: invalid UTF-8
    log.append(b"\xff\xfe")
    # 10: encrypted entry whose plaintext would have /a and /arr
    log.encrypt(j({"a": 1, "arr": [1]}), KEY)
    # 11: integer /a and empty array /arr
    log.append(j({"a": 5, "arr": []}))
    # 12: a bare number document
    log.append(j(7))
    # 13: boolean at /a
    log.append(j({"a": True}))
    # 14: float at /a
    log.append(j({"a": 2.5}))
    # 15: string at /a
    log.append(j({"a": "hi"}))
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


class FindWhereTypeTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_every_kind(self):
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number")), (0, 11, 14)
        )
        self.assertEqual(self.bundle.find_where(("type", "/a", "null")), (1,))
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "object")), (2, 4)
        )
        self.assertEqual(self.bundle.find_where(("type", "/a", "array")), (3,))
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "boolean")), (13,)
        )
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "string")), (15,)
        )

    def test_integers_and_floats_are_both_numbers(self):
        # 0 and 11 are integers, 14 is a float; the boolean of 13 and
        # the null of 1 are not numbers.
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number")), (0, 11, 14)
        )
        self.assertEqual(
            self.bundle.find_where(("type", "", "number")), (12,)
        )

    def test_empty_containers_hit_their_kind(self):
        # 3 is the empty array, 4 the empty object; 11's /arr is empty.
        self.assertEqual(self.bundle.find_where(("type", "/a", "array")), (3,))
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "object")), (2, 4)
        )
        self.assertEqual(
            self.bundle.find_where(("type", "/arr", "array")), (0, 11)
        )

    def test_empty_pointer_addresses_the_whole_document(self):
        self.assertEqual(
            self.bundle.find_where(("type", "", "object")),
            (0, 1, 2, 3, 4, 5, 11, 13, 14, 15),
        )
        self.assertEqual(self.bundle.find_where(("type", "", "array")), (6,))
        self.assertEqual(self.bundle.find_where(("type", "", "number")), (12,))
        self.assertEqual(self.bundle.find_where(("type", "", "string")), ())
        self.assertEqual(self.bundle.find_where(("type", "", "null")), ())

    def test_nested_and_array_positions(self):
        self.assertEqual(
            self.bundle.find_where(("type", "/arr/0", "number")), (0,)
        )
        self.assertEqual(
            self.bundle.find_where(("type", "/b/c", "string")), (0,)
        )

    def test_missing_invalid_and_encrypted_never_match(self):
        # 5 and 6 lack /a; 7 (not JSON), 8 (repeated member), 9 (bad
        # UTF-8) and 10 (encrypted) never hit any type leaf.
        for kind in ("null", "boolean", "number", "string", "array", "object"):
            hits = self.bundle.find_where(("type", "/a", kind))
            for absent in (5, 6, 7, 8, 9, 10):
                self.assertNotIn(absent, hits, msg=kind)

    def test_invalid_documents_hit_the_negation(self):
        self.assertEqual(
            self.bundle.find_where(("not", ("type", "/a", "number"))),
            (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15),
        )

    def test_combines_with_and_or_not(self):
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("type", "/a", "number"), ("gt", "/a", 4)))
            ),
            (11,),
        )
        self.assertEqual(
            self.bundle.find_where(
                (
                    "or",
                    (("type", "/a", "boolean"), ("type", "/a", "null")),
                )
            ),
            (1, 13),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("not", ("not", ("type", "/a", "object")))
            ),
            (2, 4),
        )

    def test_range_clipping_and_empty_range(self):
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number"), 1, 12), (11,)
        )
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number"), 3, 3), ()
        )
        self.assertEqual(
            self.bundle.find_where(("type", "", "object"), 0, 0), ()
        )

    def test_pruned_snapshot_ranges(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        # The default range is the whole retained segment.
        self.assertEqual(
            bundle.find_where(("type", "/a", "number")), (11, 14)
        )
        self.assertEqual(
            bundle.find_where(("not", ("type", "/a", "number"))),
            (2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15),
        )
        with self.assertRaises(ValueError):
            bundle.find_where(("type", "/a", "number"), 0, 3)

    def test_frozen_snapshot_survives_append_and_prune(self):
        before = self.bundle.find_where(("type", "/a", "number"))
        self.assertEqual(before, (0, 11, 14))
        self.log.append(j({"a": 8}))
        self.log.prune(1, self.log.seal(1))
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number")), before
        )
        # A fresh index covers only the retained segment: entry 0 is
        # pruned away, the new matching entry 16 is covered.
        self.assertEqual(
            self.log.signed_json_multi_index(POINTERS, SEED_A).find_where(
                ("type", "/a", "number")
            ),
            (11, 14, 16),
        )

    def test_type_errors(self):
        for expression in (
            ["type", "/a", "number"],  # node not a tuple
            (1, "/a", "number"),  # operator not a string
            ("type", 1, "number"),  # pointer not a string
            ("type", None, "number"),
            ("type", "/a", 1),  # kind not a string
            ("type", "/a", b"number"),
            ("type", "/a", None),
            ("type", "/a", True),
            ("type", "/a", ("number",)),
        ):
            with self.assertRaises(TypeError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_value_errors(self):
        for expression in (
            ("type", "/a"),  # wrong length
            ("type",),  # wrong length
            ("type", "/a", "number", "extra"),
            (),  # empty node
            ("types", "/a", "number"),  # unknown operator
            ("type", "a", "number"),  # malformed pointer
            ("type", "/missing", "number"),  # uncovered pointer
            ("type", "/a", "integer"),  # unknown kind name
            ("type", "/a", "Number"),  # kind names are case-sensitive
            ("type", "/a", "NUMBER"),
            ("type", "/a", ""),
            ("type", "/a", " number"),
        ):
            with self.assertRaises(ValueError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_range_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            self.bundle.find_where(("type", "/a", "number"), True, 3)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("type", "/a", "number"), 0, "3")
        with self.assertRaises(TypeError):
            self.bundle.find_where(("type", "/a", "number"), 0.0, 3)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", "/a", "number"), 3, 2)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", "/a", "number"), 0, 17)

    def test_node_validated_before_pointer_and_kind(self):
        # Length comes before the pointer and the kind.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", 1, 1, "extra"))
        # The pointer comes before the kind: an uncovered pointer
        # reports its ValueError even when the kind has a type error.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", "/missing", 1))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", "/missing", "badkind"))
        # A legal pointer with a wrong-typed kind raises TypeError.
        with self.assertRaises(TypeError):
            self.bundle.find_where(("type", "/a", 1))

    def test_expression_fully_validated_before_any_lookup(self):
        # An empty range or an already determined intermediate result
        # never masks an illegal branch.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", "/a", "badkind"), 2, 2)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("type", "/a", 1), 2, 2)
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("and", (("eq", "/a", 999), ("type", "/a", "badkind")))
            )
        # Children are checked left to right.
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("or", (("type", "/missing", "number"), ("type", "/a", 1)))
            )
        # The range is validated after a legal expression.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", "/a", "number"), 2, 1)

    def test_read_only(self):
        before = self.bundle.find_where(("type", "/a", "number"))
        self.bundle.find_where(("type", "/a", "number"))
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number")), before
        )


class WhereReceiptTypeTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = (
            "and",
            (("type", "/a", "number"), ("not", ("eq", "/a", 5))),
        )
        self.receipt = self.bundle.where_receipt(self.expression)

    def test_receipt_fields(self):
        self.assertIsInstance(self.receipt, WhereReceipt)
        self.assertEqual(self.receipt.expression, self.expression)
        self.assertEqual((self.receipt.start, self.receipt.stop), (0, 16))
        self.assertEqual(self.receipt.hits, (0, 14))

    def test_verify_true_with_trusted_key(self):
        self.assertTrue(
            verify_where_receipt(self.receipt, public_key(SEED_A))
        )

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(
            verify_where_receipt(self.receipt, public_key(SEED_B))
        )

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (0,), (0, 13, 14)):
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
        # The bare receipt's expression carries no signature: a swapped
        # kind still verifies whenever the declared hits remain exactly
        # the complete result of the edited query.
        receipt = WhereReceipt(
            self.receipt.bundle,
            ("type", "/a", "object"),
            self.receipt.start,
            self.receipt.stop,
            (2, 4),
        )
        self.assertTrue(verify_where_receipt(receipt, public_key(SEED_A)))

    def test_round_trip_preserves_expression_and_bytes(self):
        expression = (
            "or",
            (
                ("type", "/a", "number"),
                ("not", ("type", "", "object")),
                ("and", (("type", "/arr", "array"), ("exists", "/b/c"))),
            ),
        )
        receipt = self.bundle.where_receipt(expression)
        data = encode_where_receipt(receipt)
        self.assertEqual(encode_where_receipt(receipt), data)
        restored = decode_where_receipt(data)
        self.assertEqual(restored, receipt)
        self.assertEqual(restored.expression, expression)
        self.assertEqual(encode_where_receipt(restored), data)
        self.assertTrue(verify_where_receipt(restored, public_key(SEED_A)))

    def test_old_expression_encoding_unchanged(self):
        # An expression without the type operator encodes with the same
        # tags as before and old encodings still decode byte-identically.
        expression = (
            "or",
            (
                ("eq", "/a", 1),
                ("in", "/a", (None, True)),
                ("not", ("exists", "/arr")),
            ),
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
            + u64(12)  # unknown node tag
            + u64(0)
            + u64(16)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_unknown_kind_name(self):
        for kind in (b"integer", b"Number", b"", b" number"):
            raw = (
                b"auditchain/where-receipt/v1\0"
                + u64(1)
                + blob(encode_signed_json_multi_index(self.bundle))
                + u64(11)  # type node tag
                + blob(b"/a")
                + blob(kind)
                + u64(0)
                + u64(16)
                + u64(0)
            )
            with self.assertRaises(ValueError, msg=repr(kind)):
                decode_where_receipt(raw)

    def test_decode_rejects_invalid_utf8(self):
        for pointer, kind in ((b"\xff", b"number"), (b"/a", b"\xff")):
            raw = (
                b"auditchain/where-receipt/v1\0"
                + u64(1)
                + blob(encode_signed_json_multi_index(self.bundle))
                + u64(11)  # type node tag
                + blob(pointer)
                + blob(kind)
                + u64(0)
                + u64(16)
                + u64(0)
            )
            with self.assertRaises(ValueError, msg=repr((pointer, kind))):
                decode_where_receipt(raw)

    def test_decode_rejects_uncovered_pointer(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(11)  # type node tag
            + blob(b"/missing")
            + blob(b"number")
            + u64(0)
            + u64(16)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)


class SignedWhereReceiptTypeTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.public = public_key(SEED_A)
        self.expression = ("type", "/a", "number")
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
        # The complete result of ("type", "/a", "number") is (0, 11, 14).
        for hits in ((), (0,), (0, 11), (0, 11, 13, 14)):
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

    def test_swapped_kind_fails_even_with_matching_hits(self):
        # The complete result of ("type", "/a", "object") is (2, 4);
        # declaring those hits under the original signature fails
        # because the signature binds the kind.
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("type", "/a", "object"),
            self.receipt.start,
            self.receipt.stop,
            (2, 4),
        )
        self.assertEqual(
            self.bundle.find_where(swapped.expression), swapped.hits
        )
        forged = SignedWhereReceipt(swapped, self.signed.signature)
        self.assertFalse(verify_signed_where_receipt(forged, self.public))

    def test_resigned_swapped_kind_verifies(self):
        # Re-signing the swapped query with the trusted key verifies.
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("type", "/a", "object"),
            self.receipt.start,
            self.receipt.stop,
            (2, 4),
        )
        resigned = sign_where_receipt(swapped, SEED_A)
        self.assertTrue(verify_signed_where_receipt(resigned, self.public))


if __name__ == "__main__":
    unittest.main()
