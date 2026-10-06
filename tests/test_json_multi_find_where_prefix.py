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
    # 4: non-string (integer) at /name
    log.append(j({"name": 7, "n": 5}))
    # 5: /name missing
    log.append(j({"other": "alpha"}))
    # 6: not JSON
    log.append(b"not json")
    # 7: case differs ("Alpha")
    log.append(j({"name": "Alpha", "n": 6}))
    # 8: encrypted entry whose plaintext would match
    log.encrypt(j({"name": "albatross", "n": 7}), KEY)
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


class FindWherePrefixTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)

    def test_basic_prefix(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "al")), (0, 1)
        )
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "beta")), (2,)
        )

    def test_case_sensitive(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "Al")), (7,)
        )
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "AL")), ()
        )

    def test_empty_prefix_matches_every_string(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "")),
            (0, 1, 2, 3, 7),
        )

    def test_prefix_longer_than_string_misses(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "alphas")), ()
        )

    def test_non_string_missing_non_json_and_encrypted_never_match(self):
        # Entries 4 (integer), 5 (missing), 6 (not JSON) and 8
        # (encrypted) never satisfy a prefix leaf, so all of them
        # satisfy its negation.
        self.assertEqual(
            self.bundle.find_where(("not", ("prefix", "/name", "al"))),
            (2, 3, 4, 5, 6, 7, 8),
        )

    def test_no_unicode_normalization(self):
        log = AuditLog()
        log.append(j({"s": "élan"}))  # precomposed é (U+00E9)
        log.append(j({"s": "élan"}))  # "e" + combining acute (U+0301)
        bundle = log.signed_json_multi_index(("/s",), SEED_A)
        self.assertEqual(bundle.find_where(("prefix", "/s", "é")), (0,))
        self.assertEqual(bundle.find_where(("prefix", "/s", "e")), (1,))

    def test_combines_with_eq_and_numeric_and_boolean_nodes(self):
        self.assertEqual(
            self.bundle.find_where(
                ("and", (("prefix", "/name", "al"), ("ge", "/n", 2)))
            ),
            (1,),
        )
        self.assertEqual(
            self.bundle.find_where(
                ("or", (("prefix", "/name", "beta"), ("eq", "/n", 2)))
            ),
            (1, 2),
        )
        self.assertEqual(
            self.bundle.find_where(
                (
                    "and",
                    (
                        ("prefix", "/name", "al"),
                        ("not", ("eq", "/n", 1)),
                    ),
                )
            ),
            (1,),
        )

    def test_range_clipping_and_empty_range(self):
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "al"), 1, 2), (1,)
        )
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "al"), 2, 2), ()
        )
        self.assertEqual(
            self.bundle.find_where(("prefix", "/name", "")), (0, 1, 2, 3, 7)
        )

    def test_result_is_ascending_duplicate_free_tuple(self):
        result = self.bundle.find_where(
            ("or", (("prefix", "/name", "al"), ("prefix", "/name", "alp")))
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, (0, 1))

    def test_type_errors(self):
        for expression in (
            ["prefix", "/name", "al"],  # node not a tuple
            (1, "/name", "al"),  # operator not a string
            ("prefix", 1, "al"),  # pointer not a string
            ("prefix", "/name", 1),  # text not a string
            ("prefix", "/name", True),
            ("prefix", "/name", b"al"),
            ("prefix", "/name", None),
        ):
            with self.assertRaises(TypeError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_value_errors(self):
        for expression in (
            (),  # empty node
            ("prefix", "/name"),  # wrong length
            ("prefix", "/name", "al", "extra"),
            ("prefixx", "/name", "al"),  # unknown operator
            ("prefix", "name", "al"),  # malformed pointer
            ("prefix", "/missing", "al"),  # uncovered pointer
        ):
            with self.assertRaises(ValueError, msg=repr(expression)):
                self.bundle.find_where(expression)

    def test_expression_validated_before_range(self):
        # An empty range never masks an illegal branch, and children are
        # checked left to right.
        with self.assertRaises(TypeError):
            self.bundle.find_where(
                ("or", (("prefix", "/name", "al"), ("prefix", "/name", 1))),
                2,
                2,
            )
        with self.assertRaises(ValueError):
            self.bundle.find_where(("prefix", "/missing", "al"), 2, 2)
        # The range is still validated after a legal expression.
        with self.assertRaises(ValueError):
            self.bundle.find_where(("prefix", "/name", "al"), 2, 1)
        with self.assertRaises(TypeError):
            self.bundle.find_where(("prefix", "/name", "al"), "0", 1)

    def test_read_only_and_snapshot_stable(self):
        before = self.bundle.find_where(("prefix", "/name", "al"))
        self.log.append(j({"name": "also", "n": 8}))
        self.assertEqual(self.bundle.find_where(("prefix", "/name", "al")), before)
        self.assertEqual(
            self.log.signed_json_multi_index(POINTERS, SEED_A).find_where(
                ("prefix", "/name", "al")
            ),
            before + (9,),
        )


class WhereReceiptPrefixTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = (
            "and",
            (
                ("prefix", "/name", "al"),
                ("not", ("eq", "/n", 1)),
            ),
        )
        self.receipt = self.bundle.where_receipt(self.expression)

    def test_receipt_fields(self):
        self.assertIsInstance(self.receipt, WhereReceipt)
        self.assertEqual(self.receipt.expression, self.expression)
        self.assertEqual((self.receipt.start, self.receipt.stop), (0, 9))
        self.assertEqual(self.receipt.hits, (1,))

    def test_verify_true_with_trusted_key(self):
        self.assertTrue(
            verify_where_receipt(self.receipt, public_key(SEED_A))
        )

    def test_verify_false_with_wrong_key(self):
        self.assertFalse(
            verify_where_receipt(self.receipt, public_key(SEED_B))
        )

    def test_verify_false_on_under_and_over_report(self):
        for hits in ((), (0, 1), (1, 2)):
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
            ("prefix", "/name", "al"),
            self.receipt.start,
            self.receipt.stop,
            (0, 1),
        )
        self.assertTrue(verify_where_receipt(receipt, public_key(SEED_A)))

    def test_round_trip_preserves_structure_and_bytes(self):
        expression = (
            "or",
            (
                ("prefix", "/name", "al"),
                ("and", (("prefix", "/name", ""), ("prefix", "/name", "al"))),
                ("prefix", "/name", "al"),
                ("not", ("prefix", "/name", "é")),
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
        # An expression using only the pre-prefix operators encodes with
        # the same tags as before and round-trips unchanged.
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
        with self.assertRaises(ValueError):
            decode_where_receipt(data[:-1])
        with self.assertRaises(ValueError):
            decode_where_receipt(data + b"\x00")

    def test_decode_rejects_non_string_prefix_text(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(8)  # prefix node tag
            + blob(b"/name")
            + u64(1)  # integer value tag: illegal for a prefix text
            + blob(b"1")
            + u64(0)
            + u64(9)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_invalid_utf8_prefix_text(self):
        raw = (
            b"auditchain/where-receipt/v1\0"
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + u64(8)  # prefix node tag
            + blob(b"/name")
            + u64(0)  # string value tag
            + blob(b"\xff")
            + u64(0)
            + u64(9)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)


if __name__ == "__main__":
    unittest.main()
