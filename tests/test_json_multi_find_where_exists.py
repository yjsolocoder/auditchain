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

POINTERS = ("", "/a", "/a/b", "/a/b/-", "/a/b/0", "/a/b/01", "/a/b/2", "/n")

KEY = bytes(range(32))


def make_log():
    log = AuditLog()
    # 0: null at /a, integer 1 at /n
    log.append(j({"a": None, "n": 1}))
    # 1: integer 1 at /a, integer 2 at /n
    log.append(j({"a": 1, "n": 2}))
    # 2: empty object at /a, integer 3 at /n
    log.append(j({"a": {}, "n": 3}))
    # 3: empty array at /a, integer 4 at /n
    log.append(j({"a": [], "n": 4}))
    # 4: nested object/array at /a, integer 5 at /n
    log.append(j({"a": {"b": [10, 20]}, "n": 5}))
    # 5: /a missing, integer 6 at /n
    log.append(j({"b": 1, "n": 6}))
    # 6: not JSON
    log.append(b"not json")
    # 7: duplicate object member
    log.append(b'{"a": 1, "a": 2}')
    # 8: invalid UTF-8
    log.append(b"\xff\xfe")
    # 9: encrypted entry whose plaintext holds /a
    log.encrypt(j({"a": 1, "n": 7}), KEY)
    # 10: top-level array
    log.append(j([1, 2, 3]))
    # 11: top-level scalar
    log.append(j("scalar"))
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
        self.assertEqual(
            self.bundle.find_where(("exists", "/a")), (0, 1, 2, 3, 4)
        )

    def test_empty_object_and_array_exist(self):
        self.assertEqual(
            self.bundle.find_where(
                ("or", (("exists", "/a"), ("eq", "/n", 99)))
            ),
            (0, 1, 2, 3, 4),
        )
        self.assertEqual(
            self.bundle.find_where(("and", (("exists", "/a"), ("le", "/n", 4)))),
            (0, 1, 2, 3),
        )

    def test_empty_pointer_matches_every_valid_document(self):
        self.assertEqual(
            self.bundle.find_where(("exists", "")),
            (0, 1, 2, 3, 4, 5, 10, 11),
        )

    def test_missing_field_is_not_null(self):
        # Entry 0 holds an explicit null (it exists) while entry 5 lacks
        # /a entirely (it does not).
        self.assertEqual(self.bundle.find_where(("eq", "/a", None)), (0,))
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("exists", "/a"), ("not", ("eq", "/a", None))))
            ),
            (1, 2, 3, 4),
        )

    def test_nested_and_array_paths(self):
        self.assertEqual(self.bundle.find_where(("exists", "/a/b")), (4,))
        self.assertEqual(self.bundle.find_where(("exists", "/a/b/0")), (4,))

    def test_array_out_of_range_leading_zero_and_append_miss(self):
        self.assertEqual(self.bundle.find_where(("exists", "/a/b/2")), ())
        self.assertEqual(self.bundle.find_where(("exists", "/a/b/01")), ())
        self.assertEqual(self.bundle.find_where(("exists", "/a/b/-")), ())

    def test_path_through_scalar_misses(self):
        # Entry 1 holds the scalar 1 at /a, so /a/b traverses a scalar;
        # only entry 4 resolves.
        self.assertEqual(self.bundle.find_where(("exists", "/a/b")), (4,))

    def test_non_json_duplicate_member_and_encrypted_miss_hit_not(self):
        # Entries 6 (not JSON), 7 (duplicate member), 8 (invalid UTF-8)
        # and 9 (encrypted) never satisfy an exists leaf, so all of them
        # satisfy its negation.
        self.assertEqual(
            self.bundle.find_where(("not", ("exists", "/a"))),
            (5, 6, 7, 8, 9, 10, 11),
        )
        self.assertEqual(
            self.bundle.find_where(("not", ("exists", ""))), (6, 7, 8, 9)
        )

    def test_combines_with_eq_numeric_prefix_and_boolean_nodes(self):
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("exists", "/a"), ("ge", "/n", 2)))
            ),
            (1, 2, 3, 4),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("or", (("exists", "/a/b"), ("eq", "/n", 1)))
            ),
            (0, 4),
        )
        self.assertEqual(
            self.bundle.find_where(
                (
                    "and",
                    (
                        ("exists", "/a"),
                        ("not", ("exists", "/a/b")),
                    ),
                )
            ),
            (0, 1, 2, 3),
        )

    def test_range_clipping_defaults_and_empty_range(self):
        self.assertEqual(
            self.bundle.find_where(("exists", "/a"), 1, 3), (1, 2)
        )
        self.assertEqual(self.bundle.find_where(("exists", "/a"), 2, 2), ())
        self.assertEqual(
            self.bundle.find_where(("not", ("exists", "/a")), 0, 6), (5,)
        )

    def test_result_is_ascending_duplicate_free_tuple(self):
        result = self.bundle.find_where(
            ("or", (("exists", "/a"), ("exists", "/a/b")))
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, (0, 1, 2, 3, 4))

    def test_signed_and_inner_index_agree(self):
        for expression in (
            ("exists", "/a"),
            ("exists", ""),
            ("not", ("exists", "/a/b")),
        ):
            self.assertEqual(
                self.bundle.find_where(expression),
                self.bundle.index.find_where(expression),
            )

    def test_type_errors(self):
        for expression in (
            ["exists", "/a"],  # node not a tuple
            (1, "/a"),  # operator not a string
            ("exists", 1),  # pointer not a string
            ("exists", None),
            ("exists", b"/a"),
        ):
            with self.assertRaises(TypeError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_value_errors(self):
        for expression in (
            ("exists",),  # wrong length
            ("exists", "/a", "extra"),
            ("exists", "a"),  # malformed pointer
            ("exists", "/a~2"),  # malformed escape
            ("exists", "/missing"),  # uncovered pointer
        ):
            with self.assertRaises(ValueError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_expression_validated_before_range(self):
        # An empty range never masks an illegal branch, and children are
        # checked left to right.
        with self.assertRaises(ValueError):
            self.bundle.find_where(
                ("or", (("exists", "/a"), ("exists", "/missing"))), 2, 2
            )
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("or", (("exists", "/a"), ("exists", 1))), 2, 2
            )
        # The range is still validated after a legal expression.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("exists", "/a"), 2, 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("exists", "/a"), "0", 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("exists", "/a"), True)

    def test_read_only_and_snapshot_stable(self):
        before = self.bundle.find_where(("exists", "/a"))
        self.log.append(j({"a": "new", "n": 8}))
        self.assertEqual(self.bundle.find_where(("exists", "/a")), before)
        self.assertEqual(
            self.log.signed_json_multi_index(POINTERS, SEED_A).find_where(
                ("exists", "/a")
            ),
            before + (12,),
        )

    def test_pruned_snapshot_ranges(self):
        log = AuditLog()
        for value in ({"a": 1}, {"b": 2}, {"a": None}, {}):
            log.append(j(value))
        log.prune(1, log.seal(1))
        bundle = log.signed_json_multi_index(("/a",), SEED_A)
        self.assertEqual(bundle.find_where(("exists", "/a")), (2,))
        self.assertEqual(bundle.find_where(("not", ("exists", "/a"))), (1, 3))
        receipt = bundle.where_receipt(("exists", "/a"))
        self.assertEqual((receipt.start, receipt.stop), (1, 4))
        self.assertTrue(verify_where_receipt(receipt, public_key(SEED_A)))


class WhereReceiptExistsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = (
            "and",
            (
                ("exists", "/a"),
                ("not", ("exists", "/a/b")),
            ),
        )
        self.receipt = self.bundle.where_receipt(self.expression)

    def test_receipt_fields(self):
        self.assertIsInstance(self.receipt, WhereReceipt)
        self.assertEqual(self.receipt.expression, self.expression)
        self.assertEqual((self.receipt.start, self.receipt.stop), (0, 12))
        self.assertEqual(self.receipt.hits, (0, 1, 2, 3))

    def test_verify_true_with_trusted_key(self):
        self.assertTrue(
            verify_where_receipt(self.receipt, public_key(SEED_A))
        )

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(
            verify_where_receipt(self.receipt, public_key(SEED_B))
        )

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (0, 1, 2), (0, 1, 2, 3, 4)):
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
            ("exists", "/a"),
            self.receipt.start,
            self.receipt.stop,
            (0, 1, 2, 3, 4),
        )
        self.assertTrue(verify_where_receipt(receipt, public_key(SEED_A)))

    def test_round_trip_preserves_structure_and_bytes(self):
        expression = (
            "or",
            (
                ("exists", "/a"),
                ("and", (("exists", ""), ("exists", "/a/b"))),
                ("exists", "/a"),
                ("not", ("exists", "/a/b/0")),
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
                ("eq", "/n", 1),
                ("prefix", "/a", "x"),
                ("not", ("ge", "/n", 2)),
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
            + u64(99)  # unknown node tag
            + u64(0)
            + u64(12)
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
            + u64(12)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_malformed_and_uncovered_exists_pointer(self):
        for pointer in (b"a", b"/missing"):
            raw = (
                b"auditchain/where-receipt/v1\0"
                + u64(1)
                + blob(encode_signed_json_multi_index(self.bundle))
                + u64(9)  # exists node tag
                + blob(pointer)
                + u64(0)
                + u64(12)
                + u64(0)
            )
            with self.assertRaises(ValueError, msg=repr(pointer)):
                decode_where_receipt(raw)


if __name__ == "__main__":
    unittest.main()
