import unittest

from auditchain import (
    AuditLog,
    SignedJsonMultiIndex,
    WhereReceipt,
    decode_signed_json_multi_index,
    decode_where_receipt,
    encode_signed_json_multi_index,
    encode_where_receipt,
    verify_signed_json_multi_index,
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


class WhereReceiptCodecTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()
        self.key = public_key(SEED_A)

    def test_magic_prefix(self):
        blob = encode_where_receipt(self.bundle.where_receipt(("and", ())))
        self.assertTrue(blob.startswith(MAGIC))

    def test_roundtrip_preserves_fields(self):
        expression = ("and", (("eq", "/a", 1), ("not", ("eq", "/b", "y"))))
        receipt = self.bundle.where_receipt(expression, 0, 5)
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.expression, expression)
        self.assertEqual((decoded.start, decoded.stop), (0, 5))
        self.assertEqual(decoded.hits, receipt.hits)
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_reencode_is_byte_identical(self):
        for expression in (
            ("eq", "/a", 1),
            ("and", ()),
            ("or", ()),
            ("not", ("eq", "/a", 1)),
            ("and", (("ge", "/a", 1), ("le", "/a", 1))),
        ):
            blob = encode_where_receipt(self.bundle.where_receipt(expression))
            self.assertEqual(
                encode_where_receipt(decode_where_receipt(blob)), blob
            )
            # Encoding the same receipt twice is deterministic.
            receipt = decode_where_receipt(blob)
            self.assertEqual(encode_where_receipt(receipt), blob)

    def test_nested_structure_order_and_duplicates_survive(self):
        leaf_a = ("eq", "/a", 1)
        leaf_b = ("eq", "/b", "x")
        expression = (
            "or",
            (
                ("and", (leaf_a, ("not", leaf_b), leaf_a)),
                ("not", ("not", leaf_b)),
                leaf_a,
                ("and", (leaf_b, leaf_a)),
            ),
        )
        receipt = self.bundle.where_receipt(expression)
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        # The tree is preserved exactly: no reordering, no merging of
        # duplicate or result-equivalent branches.
        self.assertEqual(decoded.expression, expression)
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_all_leaf_operators_roundtrip(self):
        for expression in (
            ("eq", "/a", 1),
            ("lt", "/a", 2),
            ("le", "/a", 1),
            ("gt", "/a", 0),
            ("ge", "/a", 1),
            ("lt", "/a", 1.5),
            ("ge", "/a", -0.5),
        ):
            receipt = self.bundle.where_receipt(expression)
            decoded = decode_where_receipt(encode_where_receipt(receipt))
            self.assertEqual(decoded, receipt)
            self.assertEqual(decoded.expression, expression)
            self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_scalar_types_survive(self):
        big = 2**90 + 7
        log = AuditLog()
        log.append(j({"s": "héllo", "n": big, "f": 1.5, "t": True,
                      "u": False, "z": None}))
        bundle = log.signed_json_multi_index(
            ("/f", "/n", "/s", "/t", "/u", "/z"), SEED_A
        )
        for value in ("héllo", big, -big, 1.5, True, False, None, 0, ""):
            expression = ("eq", "/s" if isinstance(value, str) else
                          "/n" if isinstance(value, int) and not isinstance(value, bool) else
                          "/f" if isinstance(value, float) else
                          "/t" if value is True else
                          "/u" if value is False else "/z", value)
            receipt = bundle.where_receipt(expression)
            decoded = decode_where_receipt(encode_where_receipt(receipt))
            self.assertEqual(decoded.expression, expression)
            self.assertIs(type(decoded.expression[2]), type(value))
            self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_negative_zero_float_keeps_its_sign(self):
        log = AuditLog()
        log.append(j({"a": 0.0, "b": "x"}))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        for expression in (("eq", "/a", -0.0), ("le", "/a", -0.0)):
            receipt = bundle.where_receipt(expression)
            decoded = decode_where_receipt(encode_where_receipt(receipt))
            self.assertEqual(decoded.expression[2], 0.0)
            self.assertIs(type(decoded.expression[2]), float)
            self.assertEqual(repr(decoded.expression[2]), "-0.0")
            blob = encode_where_receipt(receipt)
            self.assertEqual(encode_where_receipt(decoded), blob)
            self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_empty_branches_empty_range_and_no_hits_roundtrip(self):
        for receipt in (
            self.bundle.where_receipt(("and", ())),
            self.bundle.where_receipt(("or", ())),
            self.bundle.where_receipt(("and", ()), 3, 3),
            self.bundle.where_receipt(("eq", "/a", 1), 3, 3),
            self.bundle.where_receipt(("eq", "/a", False)),
        ):
            decoded = decode_where_receipt(encode_where_receipt(receipt))
            self.assertEqual(decoded, receipt)
            self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_encode_rejects_non_receipt(self):
        for bad in ("x", 1, None, self.bundle, b""):
            with self.assertRaises(TypeError):
                encode_where_receipt(bad)

    def test_encode_bypassed_fields_raise_like_the_constructor(self):
        receipt = self.bundle.where_receipt(("eq", "/a", 1))
        object.__setattr__(receipt, "hits", (2, 2))
        with self.assertRaises(ValueError):
            encode_where_receipt(receipt)
        object.__setattr__(receipt, "hits", (0, 1, 4))
        object.__setattr__(receipt, "expression", ["eq", "/a", 1])
        with self.assertRaises(TypeError):
            encode_where_receipt(receipt)
        object.__setattr__(receipt, "expression", ("eq", "/missing", 1))
        with self.assertRaises(ValueError):
            encode_where_receipt(receipt)

    def test_decode_rejects_non_bytes(self):
        blob = encode_where_receipt(self.bundle.where_receipt(("and", ())))
        for bad in ("x", 1, None, bytearray(blob), memoryview(blob)):
            with self.assertRaises(TypeError):
                decode_where_receipt(bad)

    def test_bad_magic_and_version_rejected(self):
        blob = encode_where_receipt(self.bundle.where_receipt(("and", ())))
        raw = bytearray(blob)
        raw[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decode_where_receipt(bytes(raw))
        raw = bytearray(blob)
        raw[len(MAGIC) + 7] = 2
        with self.assertRaises(ValueError):
            decode_where_receipt(bytes(raw))

    def test_truncation_and_trailing_bytes_rejected(self):
        blob = encode_where_receipt(
            self.bundle.where_receipt(("and", (("eq", "/a", 1),)))
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(blob + b"\x00")
        for cut in (len(MAGIC), len(MAGIC) + 4, len(blob) - 1):
            with self.assertRaises(ValueError):
                decode_where_receipt(blob[:cut])
        # Every interior cut is a truncation too.
        for cut in range(len(MAGIC), len(blob)):
            with self.assertRaises(ValueError):
                decode_where_receipt(blob[:cut])

    def u64(self, value):
        return value.to_bytes(8, "big")

    def blob(self, material):
        return self.u64(len(material)) + material

    def raw_envelope(self, expression_bytes, start=0, stop=8, hits=()):
        return (
            MAGIC
            + self.u64(1)
            + self.blob(encode_signed_json_multi_index(self.bundle))
            + expression_bytes
            + self.u64(start)
            + self.u64(stop)
            + self.u64(len(hits))
            + b"".join(self.u64(hit) for hit in hits)
        )

    def test_unknown_node_tag_rejected(self):
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(self.u64(99)))

    def test_invalid_pointer_text_rejected(self):
        leaf = self.u64(0) + self.blob(b"\xff") + self.u64(1) + self.blob(b"1")
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(leaf))
        # A pointer the index does not cover.
        leaf = (
            self.u64(0) + self.blob(b"/missing")
            + self.u64(1) + self.blob(b"1")
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(leaf))

    def test_illegal_scalar_spellings_rejected(self):
        def leaf(tag, key, operator=0):
            return (
                self.u64(operator) + self.blob(b"/a")
                + self.u64(tag) + self.blob(key)
            )

        # Unknown value tag.
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(leaf(9, b"")))
        # Non-empty boolean value blob.
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(leaf(3, b"x")))
        # Non-canonical integer spellings.
        for key in (b"007", b"-0", b"+1", b"", b"1.0"):
            with self.assertRaises(ValueError):
                decode_where_receipt(self.raw_envelope(leaf(1, key)))
        # Non-canonical / non-finite float spellings.
        for key in (b"1", b"inf", b"nan", b"1.50"):
            with self.assertRaises(ValueError):
                decode_where_receipt(self.raw_envelope(leaf(2, key)))
        # Invalid UTF-8 string value.
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(leaf(0, b"\xff")))

    def test_non_numeric_threshold_rejected(self):
        # A comparison leaf may only carry an integer or float threshold.
        for tag, key in ((0, b"x"), (3, b""), (4, b""), (5, b"")):
            leaf = (
                self.u64(1) + self.blob(b"/a")
                + self.u64(tag) + self.blob(key)
            )
            with self.assertRaises(ValueError):
                decode_where_receipt(self.raw_envelope(leaf))

    def test_illegal_hits_rejected(self):
        leaf = self.u64(0) + self.blob(b"/a") + self.u64(1) + self.blob(b"1")
        # A hit outside the declared range.
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(leaf, hits=(8,)))
        with self.assertRaises(ValueError):
            decode_where_receipt(
                self.raw_envelope(leaf, start=2, stop=8, hits=(1,))
            )
        # Duplicates and misordering.
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(leaf, hits=(2, 2)))
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(leaf, hits=(3, 1)))

    def test_illegal_range_rejected(self):
        leaf = self.u64(0) + self.blob(b"/a") + self.u64(1) + self.blob(b"1")
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(leaf, start=6, stop=3))
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(leaf, start=0, stop=9))

    def test_count_length_mismatch_rejected(self):
        # Declared children count beyond the actual input truncates.
        node = self.u64(5) + self.u64(2)  # "and" with two children, none follow
        with self.assertRaises(ValueError):
            decode_where_receipt(self.raw_envelope(node))
        # Declared hit count beyond the actual input truncates.
        leaf = self.u64(0) + self.blob(b"/a") + self.u64(1) + self.blob(b"1")
        raw = self.raw_envelope(leaf) + b""
        raw = raw[: -8] + self.u64(1)  # claim one hit, supply none
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_verify_false_receipt_still_roundtrips(self):
        # Structurally valid but the hits do not match the expression.
        receipt = WhereReceipt(
            self.bundle, ("eq", "/a", 1), 0, 8, (0,)
        )
        self.assertFalse(verify_where_receipt(receipt, self.key))
        blob = encode_where_receipt(receipt)
        decoded = decode_where_receipt(blob)
        self.assertEqual(decoded, receipt)
        self.assertEqual(encode_where_receipt(decoded), blob)
        self.assertFalse(verify_where_receipt(decoded, self.key))

    def test_tampered_signature_receipt_still_roundtrips(self):
        other = make_log().signed_json_multi_index(POINTERS, SEED_B)
        repackaged = SignedJsonMultiIndex(self.bundle.index, other.signature)
        receipt = WhereReceipt(
            repackaged, ("eq", "/a", 1), 0, 8, (0, 1, 4)
        )
        blob = encode_where_receipt(receipt)
        decoded = decode_where_receipt(blob)
        self.assertEqual(decoded, receipt)
        self.assertFalse(verify_where_receipt(decoded, self.key))

    def test_expression_is_not_separately_authenticated(self):
        # An edited expression whose declared hits remain the complete
        # result of the edited query still verifies after the round-trip.
        receipt = WhereReceipt(
            self.bundle, ("not", ("not", ("eq", "/a", 1))), 0, 8, (0, 1, 4)
        )
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_empty_snapshot_roundtrip(self):
        bundle = AuditLog().signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("and", ()))
        self.assertEqual((receipt.start, receipt.stop, receipt.hits), (0, 0, ()))
        decoded = decode_where_receipt(encode_where_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertTrue(verify_where_receipt(decoded, self.key))

    def test_pruned_snapshot_roundtrip(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("not", ("eq", "/a", 1)))
        self.assertEqual((receipt.start, receipt.stop), (3, 8))
        self.assertEqual(receipt.hits, (3, 5, 6, 7))
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

    def test_later_appends_and_prunes_do_not_change_old_receipt(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(
            ("and", (("eq", "/a", 1), ("eq", "/b", "x")))
        )
        blob = encode_where_receipt(receipt)
        log.append(j({"a": 1, "b": "x"}))
        log.prune(2, log.seal(2))
        self.assertEqual(encode_where_receipt(receipt), blob)
        self.assertTrue(verify_where_receipt(receipt, self.key))
        self.assertTrue(
            verify_signed_json_multi_index(receipt.bundle, self.key)
        )

    def test_offline_delivery_without_log_or_private_key(self):
        # The receiver holds only the bytes and the pre-trusted public key.
        bundle = make_bundle()
        expression = ("and", (("ge", "/a", 1), ("not", ("eq", "/b", "y"))))
        blob = encode_where_receipt(bundle.where_receipt(expression, 1, 6))
        decoded = decode_where_receipt(blob)
        self.assertIsInstance(decoded, WhereReceipt)
        self.assertEqual(decoded.expression, expression)
        self.assertEqual((decoded.start, decoded.stop), (1, 6))
        self.assertEqual(decoded.hits, (4,))
        self.assertTrue(verify_where_receipt(decoded, self.key))
        # The nested bundle survives with its canonical bytes intact.
        self.assertEqual(
            encode_signed_json_multi_index(decoded.bundle),
            encode_signed_json_multi_index(bundle),
        )
        self.assertEqual(
            decode_signed_json_multi_index(
                encode_signed_json_multi_index(decoded.bundle)
            ),
            decoded.bundle,
        )


if __name__ == "__main__":
    unittest.main()
