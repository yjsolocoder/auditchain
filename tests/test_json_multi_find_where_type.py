import unittest

from auditchain import (
    AuditLog,
    SignedJsonMultiIndex,
    SignedWhereReceipt,
    WhereReceipt,
    decode_where_receipt,
    encode_signed_json_multi_index,
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
    # 0: integer at /a, array /arr, nested /b/c
    log.append(j({"a": 1, "arr": [10, 20], "b": {"c": "x"}}))
    # 1: float at /a — the same JSON kind as the integer
    log.append(j({"a": 1.5}))
    # 2: boolean at /a — not a number
    log.append(j({"a": True}))
    # 3: explicit null at /a
    log.append(j({"a": None}))
    # 4: string at /a
    log.append(j({"a": "x"}))
    # 5: empty array at /a
    log.append(j({"a": []}))
    # 6: empty object at /a
    log.append(j({"a": {}}))
    # 7: /a missing
    log.append(j({"b": {"c": 2}}))
    # 8: not JSON
    log.append(b"not json")
    # 9: repeated member name
    log.append(b'{"a": 1, "a": 2}')
    # 10: invalid UTF-8
    log.append(b"\xff\xfe")
    # 11: encrypted entry whose plaintext would have /a
    log.encrypt(j({"a": 1}), KEY)
    # 12: empty array document
    log.append(j([]))
    # 13: empty object document
    log.append(j({}))
    # 14: bare number document
    log.append(j(7))
    # 15: /a present but /b is a scalar, so /b/c passes through a scalar
    log.append(j({"a": 9, "b": 5}))
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

    def test_number_covers_integers_and_floats(self):
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number")), (0, 1, 15)
        )

    def test_boolean_is_not_a_number(self):
        self.assertEqual(self.bundle.find_where(("type", "/a", "boolean")), (2,))

    def test_null_string_and_containers(self):
        self.assertEqual(self.bundle.find_where(("type", "/a", "null")), (3,))
        self.assertEqual(self.bundle.find_where(("type", "/a", "string")), (4,))
        # The empty array and the empty object hit their own kinds.
        self.assertEqual(self.bundle.find_where(("type", "/a", "array")), (5,))
        self.assertEqual(self.bundle.find_where(("type", "/a", "object")), (6,))

    def test_empty_pointer_addresses_whole_document(self):
        self.assertEqual(
            self.bundle.find_where(("type", "", "array")), (12,)
        )
        self.assertEqual(
            self.bundle.find_where(("type", "", "object")),
            (0, 1, 2, 3, 4, 5, 6, 7, 13, 15),
        )
        self.assertEqual(self.bundle.find_where(("type", "", "number")), (14,))

    def test_nested_and_array_positions(self):
        self.assertEqual(
            self.bundle.find_where(("type", "/arr", "array")), (0,)
        )
        self.assertEqual(
            self.bundle.find_where(("type", "/arr/0", "number")), (0,)
        )
        # Only 0 and 7 have an object at /b; 15's /b is a scalar.
        self.assertEqual(
            self.bundle.find_where(("type", "/b/c", "string")), (0,)
        )
        self.assertEqual(
            self.bundle.find_where(("type", "/b/c", "number")), (7,)
        )

    def test_invalid_and_encrypted_entries_never_match(self):
        # 8 (not JSON), 9 (repeated member), 10 (bad UTF-8) and 11
        # (encrypted) hit no type leaf, so they hit its negation.
        self.assertEqual(
            self.bundle.find_where(("not", ("type", "/a", "number"))),
            (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14),
        )

    def test_combines_with_other_leaves_and_nests(self):
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("type", "/a", "number"), ("ge", "/a", 2)))
            ),
            (15,),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("or", (("type", "/a", "null"), ("type", "/a", "boolean")))
            ),
            (2, 3),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("exists", "/a"), ("not", ("type", "/a", "null"))))
            ),
            (0, 1, 2, 4, 5, 6, 15),
        )
        self.assertEqual(
            self.bundle.find_where(("not", ("not", ("type", "/a", "array")))),
            (5,),
        )

    def test_range_clipping_and_empty_range(self):
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number"), 1, 15), (1,)
        )
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number"), 2, 2), ()
        )
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number"), None, 1), (0,)
        )

    def test_default_range_covers_retained_segment(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.find_where(("type", "/a", "number")), (15,))
        self.assertEqual(
            bundle.find_where(("not", ("type", "/a", "number"))),
            (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14),
        )
        with self.assertRaises(ValueError):
            bundle.find_where(("type", "/a", "number"), 0, 4)

    def test_result_is_ascending_duplicate_free_tuple(self):
        result = self.bundle.find_where(
            (
                "or",
                (
                    ("type", "/a", "number"),
                    ("type", "/a", "number"),
                    ("type", "", "number"),
                ),
            )
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, (0, 1, 14, 15))

    def test_type_errors(self):
        for expression in (
            ["type", "/a", "number"],  # node not a tuple
            (1, "/a", "number"),  # operator not a string
            ("type", 1, "number"),  # pointer not a string
            ("type", None, "number"),
            ("type", b"/a", "number"),
            ("type", "/a", 1),  # kind not a string
            ("type", "/a", None),
            ("type", "/a", b"number"),
            ("type", "/a", True),
        ):
            with self.assertRaises(TypeError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_value_errors(self):
        for expression in (
            ("type",),  # wrong length
            ("type", "/a"),
            ("type", "/a", "number", "extra"),
            ("type", "a", "number"),  # malformed pointer
            ("type", "/a/~2", "number"),  # illegal escape
            ("type", "/missing", "number"),  # uncovered pointer
            ("type", "/a", "Number"),  # kind names are case-sensitive
            ("type", "/a", "integer"),  # unknown kind name
            ("type", "/a", ""),
            ("typee", "/a", "number"),  # unknown operator
        ):
            with self.assertRaises(ValueError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_validation_order_length_then_pointer_then_kind(self):
        # The node's own length is checked before its pointer, and the
        # pointer before the kind.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", 1))
        with self.assertRaises(TypeError):
            self.bundle.find_where(("type", 1, "bogus"))
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", "/missing", "bogus"))

    def test_expression_validated_before_range(self):
        # An empty range never masks an illegal branch, and children are
        # checked left to right.
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("or", (("type", "/a", "number"), ("type", "/a", 1))), 2, 2
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", "/a", "bogus"), 2, 2)
        # The range is still validated after a legal expression.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", "/a", "number"), 2, 1)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("type", "/a", "number"), 3, 17)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("type", "/a", "number"), "0", 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("type", "/a", "number"), True, 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("type", "/a", "number"), 0, False)

    def test_read_only_and_snapshot_stable(self):
        before = self.bundle.find_where(("type", "/a", "number"))
        self.log.append(j({"a": 100}))
        self.assertEqual(self.bundle.find_where(("type", "/a", "number")), before)
        self.assertEqual(
            self.log.signed_json_multi_index(POINTERS, SEED_A).find_where(
                ("type", "/a", "number")
            ),
            before + (16,),
        )

    def test_frozen_snapshot_survives_append_and_prune(self):
        receipt_before = self.bundle.where_receipt(("type", "/a", "number"))
        self.log.append(j({"a": 100}))
        self.log.prune(5, self.log.seal(5))
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number")), (0, 1, 15)
        )
        self.assertTrue(verify_where_receipt(receipt_before, public_key(SEED_A)))


class WhereReceiptTypeTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = (
            "and",
            (
                ("type", "/a", "number"),
                ("not", ("eq", "/a", 9)),
            ),
        )
        self.receipt = self.bundle.where_receipt(self.expression)

    def test_receipt_fields(self):
        self.assertIsInstance(self.receipt, WhereReceipt)
        self.assertEqual(self.receipt.expression, self.expression)
        self.assertEqual((self.receipt.start, self.receipt.stop), (0, 16))
        self.assertEqual(self.receipt.hits, (0, 1))

    def test_verify_true_with_trusted_key(self):
        self.assertTrue(verify_where_receipt(self.receipt, public_key(SEED_A)))

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(verify_where_receipt(self.receipt, public_key(SEED_B)))

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (0,), (0, 1, 15)):
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
        # A self-consistent bundle from another signer does not verify
        # against the trusted key.
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

    def test_plain_receipt_does_not_authenticate_query(self):
        # Editing the expression (and range) still verifies whenever the
        # declared hits remain exactly the complete result of the edited
        # query.
        receipt = WhereReceipt(
            self.receipt.bundle,
            ("type", "/a", "boolean"),
            self.receipt.start,
            self.receipt.stop,
            (2,),
        )
        self.assertTrue(verify_where_receipt(receipt, public_key(SEED_A)))

    def test_constructor_validates_expression_and_range(self):
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.receipt.bundle, ("type", "/missing", "number"), 0, 16, ()
            )
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.receipt.bundle, ("type", "/a", "bogus"), 0, 16, ()
            )
        with self.assertRaises(TypeError):
            WhereReceipt(self.receipt.bundle, ("type", "/a", 1), 0, 16, ())
        with self.assertRaises(ValueError):
            WhereReceipt(self.receipt.bundle, self.expression, 5, 4, ())

    def test_round_trip_preserves_structure_and_bytes(self):
        expression = (
            "or",
            (
                ("type", "/a", "number"),
                ("and", (("type", "", "object"), ("type", "/arr/0", "number"))),
                ("type", "/a", "number"),
                ("not", ("type", "/a", "string")),
            ),
        )
        receipt = self.bundle.where_receipt(expression)
        data = encode_where_receipt(receipt)
        restored = decode_where_receipt(data)
        self.assertEqual(restored, receipt)
        self.assertEqual(restored.expression, expression)
        self.assertEqual(encode_where_receipt(restored), data)
        self.assertTrue(verify_where_receipt(restored, public_key(SEED_A)))

    def test_old_receipt_still_decodes_byte_identically(self):
        # An expression using only the pre-type operators encodes with
        # the same tags as before and round-trips unchanged.
        expression = (
            "or",
            (
                ("eq", "/a", 1),
                ("exists", "/arr"),
                ("not", ("ge", "/a", 2)),
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
        with self.assertRaises(ValueError):
            decode_where_receipt(data[:-1])
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

    def test_decode_rejects_invalid_utf8_type_pointer(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(11)  # type node tag
            + blob(b"\xff")
            + blob(b"number")
            + u64(0)
            + u64(16)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_invalid_utf8_type_kind(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(11)  # type node tag
            + blob(b"/a")
            + blob(b"\xff")
            + u64(0)
            + u64(16)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_unknown_type_kind(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(11)  # type node tag
            + blob(b"/a")
            + blob(b"integer")
            + u64(0)
            + u64(16)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_uncovered_type_pointer(self):
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

    def test_historical_index_queries_without_resigning(self):
        # A bundle's encoding — and therefore its signed message — is
        # untouched by the new condition: an index frozen before the
        # feature answers type queries as-is.
        data = encode_signed_json_multi_index(self.bundle)
        self.assertEqual(encode_signed_json_multi_index(self.bundle), data)
        self.assertEqual(
            self.bundle.find_where(("type", "/a", "number")), (0, 1, 15)
        )


class SignedWhereReceiptTypeTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = ("type", "/a", "number")
        self.receipt = self.bundle.where_receipt(self.expression)
        self.signed = sign_where_receipt(self.receipt, SEED_A)

    def test_signed_receipt_verifies(self):
        self.assertTrue(
            verify_signed_where_receipt(self.signed, public_key(SEED_A))
        )

    def test_signature_binds_the_type_kind(self):
        # Swapping the kind for another legal one without re-signing
        # fails even though the swapped receipt is structurally valid
        # and its hits are exactly the complete result of the new query.
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("type", "/a", "string"),
            self.receipt.start,
            self.receipt.stop,
            (4,),
        )
        bundle = SignedWhereReceipt(swapped, self.signed.signature)
        self.assertFalse(
            verify_signed_where_receipt(bundle, public_key(SEED_A))
        )

    def test_resigned_swapped_receipt_verifies(self):
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("type", "/a", "string"),
            self.receipt.start,
            self.receipt.stop,
            (4,),
        )
        resigned = sign_where_receipt(swapped, SEED_A)
        self.assertTrue(
            verify_signed_where_receipt(resigned, public_key(SEED_A))
        )

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(
            verify_signed_where_receipt(self.signed, public_key(SEED_B))
        )

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (0,), (0, 1, 2, 15)):
            receipt = WhereReceipt(
                self.receipt.bundle,
                self.expression,
                self.receipt.start,
                self.receipt.stop,
                hits,
            )
            signed = sign_where_receipt(receipt, SEED_A)
            self.assertFalse(
                verify_signed_where_receipt(signed, public_key(SEED_A)),
                msg=repr(hits),
            )


if __name__ == "__main__":
    unittest.main()
