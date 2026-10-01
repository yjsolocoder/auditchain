import unittest

from auditchain import (
    AuditLog,
    Entry,
    PrefixSearchReceipt,
    decode_prefix_search_receipt,
    encode_prefix_search_receipt,
    verify_prefix_search_receipt,
)

MAGIC = b"auditchain/prefix-search/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def make_log(records=("a", "b", "aa", "c", "az")):
    log = AuditLog()
    for record in records:
        log.append(record)
    return log


def encode_entry(entry):
    return (
        u64(entry.index)
        + blob(entry.payload)
        + blob(entry.previous_hash)
        + blob(entry.entry_hash)
    )


class EncodePrefixSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_magic_and_field_layout(self):
        receipt = self.log.prefix_search_receipt(b"a", 1, 4)
        data = encode_prefix_search_receipt(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(5))  # size
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(32))  # root length
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.root)
        offset += 32
        self.assertEqual(data[offset:offset + 8], u64(1))  # prefix length
        offset += 8
        self.assertEqual(data[offset:offset + 1], b"a")
        offset += 1
        self.assertEqual(data[offset:offset + 8], u64(1))  # start
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(4))  # stop
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(3))  # items 1, 2, 3
        offset += 8
        for entry in receipt.items:
            frame = encode_entry(entry)
            self.assertEqual(data[offset:offset + len(frame)], frame)
            offset += len(frame)
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.proof)))
        offset += 8
        for node in receipt.proof:
            self.assertEqual(data[offset:offset + 8], u64(32))
            offset += 8
            self.assertEqual(data[offset:offset + 32], node)
            offset += 32
        self.assertEqual(offset, len(data))

    def test_encode_is_deterministic(self):
        receipt = self.log.prefix_search_receipt(b"a", 1, 4, size=4)
        data = encode_prefix_search_receipt(receipt)
        self.assertEqual(data, encode_prefix_search_receipt(receipt))

    def test_empty_prefix_is_zero_length_blob(self):
        receipt = self.log.prefix_search_receipt(b"")
        data = encode_prefix_search_receipt(receipt)
        offset = len(MAGIC) + 8 + len(blob(b"sha256")) + 8 + 8 + 32
        self.assertEqual(data[offset:offset + 8], u64(0))

    def test_empty_range_and_empty_snapshot(self):
        empty_range = self.log.prefix_search_receipt(b"a", 2, 2)
        data = encode_prefix_search_receipt(empty_range)
        self.assertTrue(data.endswith(u64(0) + u64(0)))
        snapshot = AuditLog().prefix_search_receipt(b"a")
        self.assertEqual(
            encode_prefix_search_receipt(snapshot),
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(0)
            + blob(snapshot.root)
            + blob(b"a")
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0),
        )

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2)):
            with self.assertRaises(TypeError):
                encode_prefix_search_receipt(bad)


class PrefixSearchReceiptRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def assert_round_trip(self, receipt):
        data = encode_prefix_search_receipt(receipt)
        restored = decode_prefix_search_receipt(data)
        self.assertEqual(restored, receipt)
        self.assertEqual(encode_prefix_search_receipt(restored), data)
        self.assertEqual(
            verify_prefix_search_receipt(restored),
            verify_prefix_search_receipt(receipt),
        )

    def test_full_range_partial_range_and_empty(self):
        self.assert_round_trip(self.log.prefix_search_receipt(b"a"))
        self.assert_round_trip(self.log.prefix_search_receipt(b"a", 1, 4))
        self.assert_round_trip(self.log.prefix_search_receipt(b"a", 2, 2))
        self.assert_round_trip(self.log.prefix_search_receipt(b"aa"))
        self.assert_round_trip(AuditLog().prefix_search_receipt(b""))

    def test_empty_and_binary_prefix_round_trip(self):
        self.assert_round_trip(self.log.prefix_search_receipt(b""))
        self.assert_round_trip(self.log.prefix_search_receipt(b"a\x00"))
        self.assert_round_trip(self.log.prefix_search_receipt(b"b\xff"))


class DecodePrefixSearchReceiptErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.data = encode_prefix_search_receipt(
            self.log.prefix_search_receipt(b"a")
        )

    def test_non_bytes_raises_type_error(self):
        for bad in ("x", bytearray(self.data), memoryview(self.data), 1, None):
            with self.assertRaises(TypeError):
                decode_prefix_search_receipt(bad)

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(b"x" + self.data[1:])

    def test_other_receipt_magic_rejected(self):
        other = b"auditchain/range-search/v1\0" + self.data[len(MAGIC):]
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(other)

    def test_truncation_is_rejected(self):
        for cut in range(len(MAGIC), len(self.data)):
            with self.assertRaises(ValueError):
                decode_prefix_search_receipt(self.data[:cut])

    def test_trailing_bytes_are_rejected(self):
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(self.data + b"\x00")

    def test_bad_version(self):
        bad = self.data[:len(MAGIC)] + u64(2) + self.data[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(bad)

    def test_bad_hash_name(self):
        head = MAGIC + u64(1) + blob(b"nonsense256")
        tail = self.data[len(MAGIC) + 8 + len(blob(b"sha256")):]
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(head + tail)

    def test_wrong_digest_width_root_rejected(self):
        offset = len(MAGIC) + 8 + len(blob(b"sha256")) + 8
        bad = (
            self.data[:offset]
            + u64(31)
            + b"\x00" * 31
            + self.data[offset + 8 + 32:]
        )
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(bad)

    def test_out_of_range_index_rejected(self):
        receipt = self.log.prefix_search_receipt(b"a", 1, 4)
        items_at = (
            len(MAGIC)
            + 8
            + len(blob(b"sha256"))
            + 8
            + 8 + 32  # size, root blob
            + 8 + 1  # prefix blob
            + 8 + 8  # start, stop
            + 8  # item count
        )
        encoded = encode_prefix_search_receipt(receipt)
        bad = encoded[:items_at] + u64(4) + encoded[items_at + 8:]
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(bad)

    def test_duplicate_item_index_rejected(self):
        receipt = self.log.prefix_search_receipt(b"a", 1, 4)
        first_entry = encode_entry(receipt.items[0])
        items_at = (
            len(MAGIC)
            + 8
            + len(blob(b"sha256"))
            + 8
            + 8 + 32
            + 8 + 1
            + 8 + 8
            + 8
        )
        encoded = encode_prefix_search_receipt(receipt)
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(
                encoded[:items_at] + first_entry + encoded[items_at:]
            )

    def test_incomplete_coverage_rejected(self):
        receipt = self.log.prefix_search_receipt(b"a", 1, 4)
        prefix = encode_prefix_search_receipt(receipt)
        count_at = (
            len(MAGIC)
            + 8
            + len(blob(b"sha256"))
            + 8
            + 8 + 32
            + 8 + 1
            + 8 + 8
        )
        frames = b"".join(encode_entry(e) for e in receipt.items[:2])
        proof_at = count_at + 8 + sum(
            len(encode_entry(e)) for e in receipt.items
        )
        bad = prefix[:count_at] + u64(2) + frames + prefix[proof_at:]
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(bad)

    def test_wrong_proof_node_count_rejected(self):
        receipt = self.log.prefix_search_receipt(b"a", 1, 4)
        prefix = encode_prefix_search_receipt(receipt)
        proof_count_at = len(prefix) - 8 - (8 + 32) * len(receipt.proof)
        bad = (
            prefix[:proof_count_at]
            + u64(len(receipt.proof) + 1)
            + prefix[proof_count_at + 8:]
        )
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(bad)


class DecodeTamperedContentStillDecodesTest(unittest.TestCase):
    def test_structurally_fine_tampered_root_round_trips_but_fails_verify(self):
        log = make_log()
        receipt = log.prefix_search_receipt(b"a")
        forged = PrefixSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            bytes(32),
            receipt.prefix,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
        )
        restored = decode_prefix_search_receipt(
            encode_prefix_search_receipt(forged)
        )
        self.assertEqual(restored, forged)
        self.assertFalse(verify_prefix_search_receipt(restored))


if __name__ == "__main__":
    unittest.main()
