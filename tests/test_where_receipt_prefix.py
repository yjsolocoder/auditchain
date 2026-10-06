import unittest

from auditchain import (
    AuditLog,
    JsonMultiIndex,
    SignedJsonMultiIndex,
    WhereReceipt,
    decode_where_receipt,
    encode_signed_json_multi_index,
    encode_where_receipt,
    verify_where_receipt,
)

from tests.test_signed_json_multi_index import SEED_A, SEED_B, j, public_key

MAGIC = b"auditchain/where-receipt/v1\0"

POINTERS = ("/n", "/name")


def make_log():
    log = AuditLog()
    # 0: string alice at /name, integer 1 at /n
    log.append(j({"name": "alice", "n": 1}))
    # 1: string alicia at /name, integer 2 at /n
    log.append(j({"name": "alicia", "n": 2}))
    # 2: string Alice (capital) at /name
    log.append(j({"name": "Alice", "n": 3}))
    # 3: empty string at /name
    log.append(j({"name": "", "n": 4}))
    # 4: non-string at /name
    log.append(j({"name": 123, "n": 5}))
    # 5: not JSON
    log.append(b"not json")
    # 6: /name missing
    log.append(j({"other": "alice"}))
    return log


def make_bundle(log=None):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, SEED_A)


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def tampered_bundle(bundle):
    """The bundle with one covered entry hash zeroed, signature unchanged."""
    index = bundle.index
    items = list(index.items)
    entry = items[0]
    items[0] = type(entry)(
        entry.index,
        entry.payload,
        entry.previous_hash,
        bytes(len(entry.entry_hash)),
    )
    tampered = JsonMultiIndex(
        index.version,
        index.hash_name,
        index.size,
        index.root,
        index.head,
        index.retain_from,
        index.pointers,
        tuple(items),
        index.proof,
        index.groups,
    )
    return SignedJsonMultiIndex(tampered, bundle.signature)


class WhereReceiptPrefixTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.expression = (
            "and",
            (("prefix", "/name", "ali"), ("not", ("eq", "/n", 1))),
        )
        self.receipt = self.bundle.where_receipt(self.expression)

    def test_receipt_keeps_expression_range_and_hits(self):
        self.assertEqual(self.receipt.expression, self.expression)
        self.assertEqual((self.receipt.start, self.receipt.stop), (0, 7))
        self.assertEqual(self.receipt.hits, (1,))

    def test_receipt_resolves_explicit_and_empty_ranges(self):
        receipt = self.bundle.where_receipt(("prefix", "/name", ""), 1, 3)
        self.assertEqual((receipt.start, receipt.stop), (1, 3))
        self.assertEqual(receipt.hits, (1, 2))
        empty = self.bundle.where_receipt(("prefix", "/name", ""), 2, 2)
        self.assertEqual(empty.hits, ())

    def test_receipt_validates_expression_before_range(self):
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(("prefix", "/missing", "a"), 2, 2)
        with self.assertRaises(TypeError):
            self.bundle.where_receipt(("prefix", "/name", 1), 2, 2)
        with self.assertRaises(ValueError):
            self.bundle.where_receipt(("prefix", "/name", "a"), 3, 2)

    def test_verify_accepts_genuine_receipt(self):
        self.assertIs(
            verify_where_receipt(self.receipt, public_key(SEED_A)), True
        )

    def test_verify_rejects_wrong_public_key(self):
        self.assertIs(
            verify_where_receipt(self.receipt, public_key(SEED_B)), False
        )

    def test_verify_rejects_under_and_over_reported_hits(self):
        under = WhereReceipt(
            bundle=self.receipt.bundle,
            expression=self.expression,
            start=self.receipt.start,
            stop=self.receipt.stop,
            hits=(),
        )
        self.assertIs(verify_where_receipt(under, public_key(SEED_A)), False)
        over = WhereReceipt(
            bundle=self.receipt.bundle,
            expression=self.expression,
            start=self.receipt.start,
            stop=self.receipt.stop,
            hits=(1, 2),
        )
        self.assertIs(verify_where_receipt(over, public_key(SEED_A)), False)

    def test_verify_rejects_tampered_index_evidence(self):
        forged = WhereReceipt(
            bundle=tampered_bundle(self.bundle),
            expression=self.expression,
            start=self.receipt.start,
            stop=self.receipt.stop,
            hits=self.receipt.hits,
        )
        self.assertIs(verify_where_receipt(forged, public_key(SEED_A)), False)

    def test_verify_rejects_forged_signature(self):
        forged_bundle = SignedJsonMultiIndex(
            self.bundle.index, bytes(64)
        )
        forged = WhereReceipt(
            bundle=forged_bundle,
            expression=self.expression,
            start=self.receipt.start,
            stop=self.receipt.stop,
            hits=self.receipt.hits,
        )
        self.assertIs(verify_where_receipt(forged, public_key(SEED_A)), False)

    def test_expression_carries_no_independent_signature(self):
        # Editing the expression (and range) still verifies whenever the
        # declared hits remain exactly the complete result of the edited
        # query.
        edited = WhereReceipt(
            bundle=self.receipt.bundle,
            expression=("prefix", "/name", "ali"),
            start=self.receipt.start,
            stop=self.receipt.stop,
            hits=(0, 1),
        )
        self.assertIs(verify_where_receipt(edited, public_key(SEED_A)), True)


class WhereReceiptPrefixCodecTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()

    def round_trip(self, expression, start=None, stop=None):
        receipt = self.bundle.where_receipt(expression, start, stop)
        data = encode_where_receipt(receipt)
        decoded = decode_where_receipt(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(encode_where_receipt(decoded), data)
        self.assertIs(verify_where_receipt(decoded, public_key(SEED_A)), True)
        return data

    def test_prefix_leaf_round_trip(self):
        self.round_trip(("prefix", "/name", "ali"))

    def test_empty_prefix_round_trip(self):
        self.round_trip(("prefix", "/name", ""))

    def test_nested_order_and_repeated_branches_round_trip(self):
        expression = (
            "or",
            (
                ("prefix", "/name", "ali"),
                ("prefix", "/name", "ali"),
                (
                    "and",
                    (
                        ("prefix", "/name", ""),
                        ("not", ("prefix", "/name", "b")),
                        ("eq", "/n", 2),
                    ),
                ),
            ),
        )
        data = self.round_trip(expression, 1, 6)
        decoded = decode_where_receipt(data)
        self.assertEqual(decoded.expression, expression)

    def test_string_content_round_trip_exactly(self):
        expression = (
            "and",
            (
                ("prefix", "/name", "á"),
                ("prefix", "/name", "á"),
                ("prefix", "/name", "Alice \n\t ~0 ~1"),
            ),
        )
        data = self.round_trip(expression)
        self.assertEqual(decode_where_receipt(data).expression, expression)

    def test_repeated_encoding_is_byte_identical(self):
        receipt = self.bundle.where_receipt(("prefix", "/name", "ali"))
        self.assertEqual(
            encode_where_receipt(decode_where_receipt(encode_where_receipt(receipt))),
            encode_where_receipt(receipt),
        )

    def test_old_receipts_without_prefix_still_decode_unchanged(self):
        expression = (
            "and",
            (("eq", "/n", 1), ("not", ("ge", "/n", 5)), ("or", (("le", "/n", 2),))),
        )
        receipt = self.bundle.where_receipt(expression)
        data = encode_where_receipt(receipt)
        self.assertEqual(encode_where_receipt(decode_where_receipt(data)), data)
        self.assertIs(
            verify_where_receipt(decode_where_receipt(data), public_key(SEED_A)),
            True,
        )

    def test_decode_rejects_non_bytes(self):
        receipt = self.bundle.where_receipt(("prefix", "/name", "ali"))
        data = encode_where_receipt(receipt)
        with self.assertRaises(TypeError):
            decode_where_receipt(bytearray(data))
        with self.assertRaises(TypeError):
            decode_where_receipt(memoryview(data))

    def test_decode_rejects_truncation_and_trailing_bytes(self):
        receipt = self.bundle.where_receipt(("prefix", "/name", "ali"))
        data = encode_where_receipt(receipt)
        with self.assertRaises(ValueError):
            decode_where_receipt(data[:-1])
        with self.assertRaises(ValueError):
            decode_where_receipt(data + b"\x00")

    def test_decode_rejects_prefix_leaf_with_non_string_value(self):
        # tag 8 is the prefix leaf; a non-string value tag is illegal.
        expression = u64(8) + blob(b"/name") + u64(1) + blob(b"5")
        raw = (
            MAGIC
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + expression
            + u64(0)
            + u64(7)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_prefix_leaf_with_invalid_utf8(self):
        expression = u64(8) + blob(b"/name") + u64(0) + blob(b"\xff")
        raw = (
            MAGIC
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + expression
            + u64(0)
            + u64(7)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)

    def test_decode_rejects_unknown_node_tag(self):
        expression = u64(9) + blob(b"/name") + u64(0) + blob(b"a")
        raw = (
            MAGIC
            + u64(1)
            + blob(encode_signed_json_multi_index(self.bundle))
            + expression
            + u64(0)
            + u64(7)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_where_receipt(raw)


if __name__ == "__main__":
    unittest.main()
