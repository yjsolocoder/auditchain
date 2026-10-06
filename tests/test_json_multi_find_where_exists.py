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

POINTERS = ("", "/a", "/arr", "/arr/-", "/arr/0", "/arr/00", "/b/c", "/k~0e", "/k~1e")

KEY = bytes(range(32))


def make_log():
    log = AuditLog()
    # 0: every field present — scalar /a, array /arr, nested /b/c, escaped keys
    log.append(j({"a": 1, "arr": [10, 20], "b": {"c": "x"}, "k~e": 1, "k/e": 2}))
    # 1: explicit null at /a — present, unlike a missing field
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
    # 11: scalar /a and empty array /arr (so /arr/0 is out of range)
    log.append(j({"a": 5, "arr": []}))
    # 12: a bare scalar document — valid JSON, but every path misses
    log.append(j(7))
    # 13: /a present, but /b is a scalar so /b/c passes through a scalar
    log.append(j({"a": 9, "b": 5}))
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


class FindWhereExistsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_null_scalar_object_and_array_all_exist(self):
        # 0: scalar, 1: null, 2: object, 3: empty array, 4: empty object,
        # 11 and 13: scalars — a missing field (5, 6) is not null.
        self.assertEqual(
            self.bundle.find_where(("exists", "/a")),
            (0, 1, 2, 3, 4, 11, 13),
        )

    def test_empty_pointer_hits_every_valid_document(self):
        # The empty object (5), the empty array (6) and the bare scalar
        # document (12) all exist; invalid JSON (7), a repeated member
        # (8), invalid UTF-8 (9) and the encrypted entry (10) do not.
        self.assertEqual(
            self.bundle.find_where(("exists", "")),
            (0, 1, 2, 3, 4, 5, 6, 11, 12, 13),
        )

    def test_empty_containers_exist(self):
        self.assertEqual(
            self.bundle.find_where(("exists", "/arr")), (0, 11)
        )

    def test_array_resolution_rules(self):
        # In-range index hits; out-of-range (11's arr is empty), the
        # append position and a leading-zero index never hit.
        self.assertEqual(self.bundle.find_where(("exists", "/arr/0")), (0,))
        self.assertEqual(self.bundle.find_where(("exists", "/arr/-")), ())
        self.assertEqual(self.bundle.find_where(("exists", "/arr/00")), ())

    def test_path_through_scalar_and_missing_member_miss(self):
        # Only 0 has an object at /b; 13's /b is a scalar.
        self.assertEqual(self.bundle.find_where(("exists", "/b/c")), (0,))

    def test_escaped_object_keys(self):
        self.assertEqual(self.bundle.find_where(("exists", "/k~0e")), (0,))
        self.assertEqual(self.bundle.find_where(("exists", "/k~1e")), (0,))

    def test_invalid_and_encrypted_entries_never_exist(self):
        # 7 (not JSON), 8 (repeated member), 9 (bad UTF-8) and 10
        # (encrypted) hit no exists leaf, so they hit its negation.
        self.assertEqual(
            self.bundle.find_where(("not", ("exists", "/a"))),
            (5, 6, 7, 8, 9, 10, 12),
        )

    def test_distinguishes_missing_from_null(self):
        # Present and null vs present and non-null vs absent.
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("exists", "/a"), ("eq", "/a", None)))
            ),
            (1,),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("exists", "/a"), ("not", ("eq", "/a", None))))
            ),
            (0, 2, 3, 4, 11, 13),
        )

    def test_combines_with_other_leaves_and_nests(self):
        self.assertEqual(
            self.bundle.find_where(
                ("or", (("exists", "/arr"), ("exists", "/b/c")))
            ),
            (0, 11),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("exists", "/a"), ("ge", "/a", 5)))
            ),
            (11, 13),
        )
        self.assertEqual(
            self.bundle.find_where(("not", ("not", ("exists", "/arr")))),
            (0, 11),
        )

    def test_range_clipping_and_empty_range(self):
        self.assertEqual(
            self.bundle.find_where(("exists", "/a"), 1, 4), (1, 2, 3)
        )
        self.assertEqual(self.bundle.find_where(("exists", "/a"), 2, 2), ())
        self.assertEqual(
            self.bundle.find_where(("exists", "/a"), None, 2), (0, 1)
        )

    def test_default_range_covers_retained_segment(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(
            bundle.find_where(("exists", "/a")), (3, 4, 11, 13)
        )
        self.assertEqual(
            bundle.find_where(("not", ("exists", "/a"))),
            (5, 6, 7, 8, 9, 10, 12),
        )
        with self.assertRaises(ValueError):
            bundle.find_where(("exists", "/a"), 0, 4)

    def test_result_is_ascending_duplicate_free_tuple(self):
        result = self.bundle.find_where(
            ("or", (("exists", "/a"), ("exists", "/a"), ("exists", "/arr")))
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, (0, 1, 2, 3, 4, 11, 13))

    def test_type_errors(self):
        for expression in (
            ["exists", "/a"],  # node not a tuple
            (1, "/a"),  # operator not a string
            ("exists", 1),  # pointer not a string
            ("exists", None),
            ("exists", b"/a"),
            ("exists", True),
        ):
            with self.assertRaises(TypeError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_value_errors(self):
        for expression in (
            ("exists",),  # wrong length
            ("exists", "/a", "extra"),
            ("exists", "a"),  # malformed pointer
            ("exists", "/a/~2"),  # illegal escape
            ("exists", "/missing"),  # uncovered pointer
            ("existss", "/a"),  # unknown operator
        ):
            with self.assertRaises(ValueError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_expression_validated_before_range(self):
        # An empty range never masks an illegal branch, and children are
        # checked left to right.
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("or", (("exists", "/a"), ("exists", 1))), 2, 2
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(("exists", "/missing"), 2, 2)
        # The range is still validated after a legal expression.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("exists", "/a"), 2, 1)
        with self.assertRaises(ValueError):
            self.bundle.find_where(("exists", "/a"), 3, 15)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("exists", "/a"), "0", 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("exists", "/a"), True, 1)

    def test_read_only_and_snapshot_stable(self):
        before = self.bundle.find_where(("exists", "/a"))
        self.log.append(j({"a": 100}))
        self.assertEqual(
            self.bundle.find_where(("exists", "/a")), before
        )
        self.assertEqual(
            self.log.signed_json_multi_index(POINTERS, SEED_A).find_where(
                ("exists", "/a")
            ),
            before + (14,),
        )

    def test_frozen_snapshot_survives_append_and_prune(self):
        receipt_before = self.bundle.where_receipt(("exists", "/a"))
        self.log.append(j({"a": 100}))
        self.log.prune(5, self.log.seal(5))
        self.assertEqual(
            self.bundle.find_where(("exists", "/a")),
            (0, 1, 2, 3, 4, 11, 13),
        )
        self.assertTrue(
            verify_where_receipt(receipt_before, public_key(SEED_A))
        )


class WhereReceiptExistsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = (
            "and",
            (
                ("exists", "/a"),
                ("not", ("eq", "/a", None)),
            ),
        )
        self.receipt = self.bundle.where_receipt(self.expression)

    def test_receipt_fields(self):
        self.assertIsInstance(self.receipt, WhereReceipt)
        self.assertEqual(self.receipt.expression, self.expression)
        self.assertEqual((self.receipt.start, self.receipt.stop), (0, 14))
        self.assertEqual(self.receipt.hits, (0, 2, 3, 4, 11, 13))

    def test_verify_true_with_trusted_key(self):
        self.assertTrue(
            verify_where_receipt(self.receipt, public_key(SEED_A))
        )

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(
            verify_where_receipt(self.receipt, public_key(SEED_B))
        )

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (0, 2, 3, 4, 11), (0, 2, 3, 4, 11, 12, 13)):
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

    def test_expression_carries_no_independent_signature(self):
        # Editing the expression (and range) still verifies whenever the
        # declared hits remain exactly the complete result of the edited
        # query.
        receipt = WhereReceipt(
            self.receipt.bundle,
            ("exists", "/arr"),
            self.receipt.start,
            self.receipt.stop,
            (0, 11),
        )
        self.assertTrue(verify_where_receipt(receipt, public_key(SEED_A)))

    def test_constructor_validates_expression_and_range(self):
        with self.assertRaises(ValueError):
            WhereReceipt(
                self.receipt.bundle, ("exists", "/missing"), 0, 14, ()
            )
        with self.assertRaises(TypeError):
            WhereReceipt(self.receipt.bundle, ("exists", 1), 0, 14, ())
        with self.assertRaises(ValueError):
            WhereReceipt(self.receipt.bundle, self.expression, 5, 4, ())

    def test_round_trip_preserves_structure_and_bytes(self):
        expression = (
            "or",
            (
                ("exists", "/a"),
                ("and", (("exists", ""), ("exists", "/arr/0"))),
                ("exists", "/a"),
                ("not", ("exists", "/k~0e")),
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
        # An expression using only the pre-exists operators encodes with
        # the same tags as before and round-trips unchanged.
        expression = (
            "or",
            (
                ("eq", "/a", 1),
                ("prefix", "/b/c", "x"),
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
            + u64(10)  # unknown node tag
            + u64(0)
            + u64(14)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_invalid_utf8_exists_pointer(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(9)  # exists node tag
            + blob(b"\xff")
            + u64(0)
            + u64(14)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_uncovered_exists_pointer(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(9)  # exists node tag
            + blob(b"/missing")
            + u64(0)
            + u64(14)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_historical_index_queries_without_resigning(self):
        # A bundle's encoding — and therefore its signed message — is
        # untouched by the new condition: an index frozen before the
        # feature answers exists queries as-is.
        data = encode_signed_json_multi_index(self.bundle)
        self.assertEqual(
            encode_signed_json_multi_index(self.bundle), data
        )
        self.assertEqual(
            self.bundle.find_where(("exists", "/a")),
            (0, 1, 2, 3, 4, 11, 13),
        )


if __name__ == "__main__":
    unittest.main()
