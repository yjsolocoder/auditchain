import dataclasses
import unittest

from auditchain import (
    AuditLog,
    SignedJsonMultiIndex,
    WhereReceipt,
    decode_where_receipt,
    encode_signed_json_multi_index,
    encode_where_receipt,
    verify_where_receipt,
)

from tests.test_signed_json_multi_index import SEED_A, SEED_B, j, public_key

MAGIC = b"auditchain/where-receipt/v1\0"

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


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


# Expression node tags of the where-receipt framing.
TAG = {
    "eq": 0,
    "lt": 1,
    "le": 2,
    "gt": 3,
    "ge": 4,
    "and": 5,
    "or": 6,
    "not": 7,
}

# Scalar value kind tags, shared with the multi-query receipt framing.
VALUE_TAG = {
    "string": 0,
    "integer": 1,
    "float": 2,
    "true": 3,
    "null": 4,
    "false": 5,
}


def raw_leaf(operator, pointer, value_tag, key):
    return (
        u64(TAG[operator])
        + blob(pointer.encode("utf-8"))
        + u64(value_tag)
        + blob(key)
    )


def raw_expression(expression):
    operator = expression[0]
    if operator in ("eq", "lt", "le", "gt", "ge"):
        _, pointer, value = expression
        if isinstance(value, str):
            tag, key = VALUE_TAG["string"], value.encode("utf-8")
        elif isinstance(value, bool):
            tag, key = VALUE_TAG["true" if value else "false"], b""
        elif value is None:
            tag, key = VALUE_TAG["null"], b""
        elif isinstance(value, int):
            tag, key = VALUE_TAG["integer"], str(value).encode("ascii")
        else:
            tag, key = VALUE_TAG["float"], repr(value).encode("ascii")
        return raw_leaf(operator, pointer, tag, key)
    if operator in ("and", "or"):
        children = expression[1]
        return (
            u64(TAG[operator])
            + u64(len(children))
            + b"".join(raw_expression(child) for child in children)
        )
    return u64(TAG["not"]) + raw_expression(expression[1])


def raw_receipt_bytes(bundle, expression, start, stop, hits):
    return (
        MAGIC
        + u64(1)
        + blob(encode_signed_json_multi_index(bundle))
        + raw_expression(expression)
        + u64(start)
        + u64(stop)
        + u64(len(hits))
        + b"".join(u64(hit) for hit in hits)
    )


class WhereReceiptCodecTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.key = public_key(SEED_A)

    def test_magic_prefix(self):
        blob_ = encode_where_receipt(self.bundle.where_receipt(("and", ())))
        self.assertTrue(blob_.startswith(MAGIC))

    def test_roundtrip_preserves_fields(self):
        expression = ("and", (("eq", "/a", 1), ("not", ("eq", "/b", "y"))))
        receipt = self.bundle.where_receipt(expression, 0, 5)
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.expression, expression)
        self.assertEqual(
            (decoded.start, decoded.stop, decoded.hits),
            (receipt.start, receipt.stop, receipt.hits),
        )
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_repeated_encode_is_byte_identical(self):
        receipt = self.bundle.where_receipt(
            ("or", (("eq", "/a", 1), ("lt", "/a", 2)))
        )
        first = encode_where_receipt(receipt)
        self.assertEqual(encode_where_receipt(receipt), first)
        self.assertEqual(encode_where_receipt(decode_where_receipt(first)), first)

    def test_all_leaf_operators_roundtrip(self):
        for operator in ("eq", "lt", "le", "gt", "ge"):
            expression = (operator, "/a", 1)
            receipt = self.bundle.where_receipt(expression)
            decoded = decode_where_receipt(encode_where_receipt(receipt))
            self.assertEqual(decoded, receipt)
            self.assertEqual(decoded.expression, expression)
            self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_nested_structure_order_and_duplicates_survive(self):
        leaf_a = ("eq", "/a", 1)
        leaf_b = ("eq", "/b", "x")
        expression = (
            "or",
            (
                ("and", (leaf_a, leaf_b, leaf_a)),
                ("not", ("or", (leaf_b,))),
                ("and", ()),
                leaf_a,
            ),
        )
        receipt = self.bundle.where_receipt(expression)
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        # The tree is preserved exactly: no merging of equal-result branches.
        self.assertEqual(decoded.expression, expression)
        self.assertEqual(decoded, receipt)
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_scalar_types_roundtrip_exactly(self):
        big = 2**90 + 7
        log = AuditLog()
        log.append(
            j({"s": "héllo", "n": big, "f": 1.5, "t": True,
               "u": False, "z": None})
        )
        bundle = log.signed_json_multi_index(
            ("/f", "/n", "/s", "/t", "/u", "/z"), SEED_A
        )
        leaves = (
            ("eq", "/s", "héllo"),
            ("eq", "/n", big),
            ("eq", "/f", 1.5),
            ("eq", "/t", True),
            ("eq", "/u", False),
            ("eq", "/z", None),
            ("le", "/n", big),
            ("gt", "/f", 0.5),
        )
        receipt = bundle.where_receipt(("and", leaves))
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertEqual(decoded.expression, receipt.expression)
        for (_, _, value), (_, _, original) in zip(
            decoded.expression[1], leaves
        ):
            self.assertIs(type(value), type(original))
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_negative_zero_float_keeps_sign(self):
        log = AuditLog()
        log.append(j({"a": 0.0, "b": "x"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("eq", "/a", -0.0))
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertEqual(
            repr(decoded.expression[2]), "-0.0"
        )
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_empty_and_empty_or_and_no_hits_roundtrip(self):
        for expression in (("and", ()), ("or", ()), ("eq", "/a", False)):
            receipt = self.bundle.where_receipt(expression)
            decoded = decode_where_receipt(encode_where_receipt(receipt))
            self.assertEqual(decoded, receipt)
            self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_empty_range_roundtrip(self):
        receipt = self.bundle.where_receipt(("and", ()), 3, 3)
        self.assertEqual(receipt.hits, ())
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertEqual((decoded.start, decoded.stop), (3, 3))
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_pruned_snapshot_roundtrip(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("eq", "/a", 1))
        self.assertEqual((receipt.start, receipt.stop), (3, 7))
        self.assertEqual(receipt.hits, (4,))
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_other_hash_algorithm_roundtrip(self):
        log = AuditLog(hash_name="sha512")
        log.append(j({"a": 1, "b": "x"}))
        log.append(j({"a": 2, "b": "y"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("eq", "/b", "y"))
        self.assertEqual(receipt.hits, (1,))
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_later_appends_and_prunes_do_not_change_bytes(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("eq", "/a", 1))
        blob_ = encode_where_receipt(receipt)
        log.append(j({"a": 1, "b": "x"}))
        log.prune(2, log.seal(2))
        self.assertEqual(encode_where_receipt(receipt), blob_)
        self.assertTrue(verify_where_receipt(receipt, self.key))

    def test_encode_rejects_non_receipt(self):
        for bad in ("x", 1, None, self.bundle, b""):
            with self.assertRaises(TypeError):
                encode_where_receipt(bad)

    def test_encode_revalidates_bypassed_fields(self):
        receipt = self.bundle.where_receipt(("eq", "/a", 1))
        object.__setattr__(receipt, "hits", (2, 2))
        with self.assertRaises(ValueError):
            encode_where_receipt(receipt)
        receipt = self.bundle.where_receipt(("eq", "/a", 1))
        object.__setattr__(receipt, "expression", ["eq", "/a", 1])
        with self.assertRaises(TypeError):
            encode_where_receipt(receipt)

    def test_decode_rejects_non_bytes(self):
        blob_ = encode_where_receipt(self.bundle.where_receipt(("and", ())))
        for bad in ("x", 1, None, bytearray(blob_), memoryview(blob_)):
            with self.assertRaises(TypeError):
                decode_where_receipt(bad)

    def test_bad_magic_and_version_rejected(self):
        blob_ = encode_where_receipt(self.bundle.where_receipt(("and", ())))
        raw = bytearray(blob_)
        raw[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decode_where_receipt(bytes(raw))
        raw = bytearray(blob_)
        raw[len(MAGIC) + 7] = 2
        with self.assertRaises(ValueError):
            decode_where_receipt(bytes(raw))

    def test_truncation_and_trailing_bytes_rejected(self):
        blob_ = encode_where_receipt(
            self.bundle.where_receipt(("eq", "/a", 1))
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(blob_ + b"\x00")
        for cut in (len(MAGIC), len(MAGIC) + 4, len(blob_) - 1):
            with self.assertRaises(ValueError):
                decode_where_receipt(blob_[:cut])

    def test_illegal_decoded_expression_rejected(self):
        bundle_blob = blob(encode_signed_json_multi_index(self.bundle))

        def raw_with_expression(expression_bytes):
            return (
                MAGIC
                + u64(1)
                + bundle_blob
                + expression_bytes
                + u64(0)
                + u64(7)
                + u64(0)
            )

        # Unknown node tag.
        with self.assertRaises(ValueError):
            decode_where_receipt(raw_with_expression(u64(9)))
        # Invalid UTF-8 pointer.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(
                    u64(TAG["eq"]) + blob(b"\xff") + u64(1) + blob(b"1")
                )
            )
        # Unknown value tag.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(raw_leaf("eq", "/a", 9, b""))
            )
        # Non-empty boolean value blob.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(
                    raw_leaf("eq", "/a", VALUE_TAG["true"], b"x")
                )
            )
        # Non-canonical integer spellings.
        for key in (b"007", b"-0", b"+1", b"", b"1.0"):
            with self.assertRaises(ValueError):
                decode_where_receipt(
                    raw_with_expression(
                        raw_leaf("eq", "/a", VALUE_TAG["integer"], key)
                    )
                )
        # Non-canonical / non-finite float spellings.
        for key in (b"1", b"inf", b"nan", b"1.50"):
            with self.assertRaises(ValueError):
                decode_where_receipt(
                    raw_with_expression(
                        raw_leaf("eq", "/a", VALUE_TAG["float"], key)
                    )
                )
        # Invalid UTF-8 string value.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(
                    raw_leaf("eq", "/a", VALUE_TAG["string"], b"\xff")
                )
            )
        # A comparison leaf with a non-numeric threshold.
        for tag, key in (
            (VALUE_TAG["string"], b"x"),
            (VALUE_TAG["true"], b""),
            (VALUE_TAG["null"], b""),
        ):
            with self.assertRaises(ValueError):
                decode_where_receipt(
                    raw_with_expression(raw_leaf("lt", "/a", tag, key))
                )
        # A pointer the index does not cover.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(
                    raw_leaf("eq", "/missing", VALUE_TAG["integer"], b"1")
                )
            )
        # A declared child count that does not match the children.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_with_expression(
                    u64(TAG["and"])
                    + u64(2)
                    + raw_leaf("eq", "/a", VALUE_TAG["integer"], b"1")
                )
            )

    def test_illegal_decoded_range_and_hits_rejected(self):
        bundle = self.bundle
        expression = ("eq", "/a", 1)
        # Reversed range.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_receipt_bytes(bundle, expression, 5, 2, ())
            )
        # Range beyond the covered segment.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_receipt_bytes(bundle, expression, 0, 8, ())
            )
        # Hit outside [start, stop).
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_receipt_bytes(bundle, expression, 0, 7, (7,))
            )
        # Duplicated and misordered hits.
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_receipt_bytes(bundle, expression, 0, 7, (2, 2))
            )
        with self.assertRaises(ValueError):
            decode_where_receipt(
                raw_receipt_bytes(bundle, expression, 0, 7, (3, 1))
            )

    def test_nested_bundle_framing_errors_rejected(self):
        bundle_bytes = encode_signed_json_multi_index(self.bundle)
        # Truncated nested bundle blob.
        raw = (
            MAGIC
            + u64(1)
            + blob(bundle_bytes[:-1])
            + raw_expression(("and", ()))
            + u64(0)
            + u64(7)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)
        # A nested blob that is not a signed index at all.
        raw = (
            MAGIC
            + u64(1)
            + blob(b"not a signed index")
            + raw_expression(("and", ()))
            + u64(0)
            + u64(7)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_verify_false_receipt_still_roundtrips(self):
        # Structurally valid but the hits do not match the expression.
        receipt = WhereReceipt(
            self.bundle, ("eq", "/a", 1), 0, 7, (0,)
        )
        self.assertFalse(verify_where_receipt(receipt, self.key))
        blob_ = encode_where_receipt(receipt)
        decoded = decode_where_receipt(blob_)
        self.assertEqual(decoded, receipt)
        self.assertEqual(encode_where_receipt(decoded), blob_)

    def test_tampered_signature_still_decodes_but_fails_verification(self):
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
        decoded = decode_where_receipt(encode_where_receipt(tampered))
        self.assertEqual(decoded, tampered)
        self.assertFalse(verify_where_receipt(decoded, self.key))

    def test_decoded_receipt_is_immutable(self):
        receipt = self.bundle.where_receipt(("and", ()))
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            decoded.hits = ()

    def test_empty_snapshot_roundtrip(self):
        bundle = AuditLog().signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("and", ()))
        self.assertEqual((receipt.start, receipt.stop, receipt.hits), (0, 0, ()))
        blob_ = encode_where_receipt(receipt)
        self.assertEqual(decode_where_receipt(blob_), receipt)
        self.assertTrue(verify_where_receipt(receipt, self.key))


if __name__ == "__main__":
    unittest.main()
