import unittest

from auditchain import (
    AuditLog,
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

    def test_empty_prefix_is_zero_length_blob(self):
        receipt = self.log.prefix_search_receipt(b"")
        data = encode_prefix_search_receipt(receipt)
        root_blob_end = len(MAGIC) + 8 + len(blob(b"sha256")) + 8 + 8 + 32
        self.assertEqual(data[root_blob_end:root_blob_end + 8], u64(0))

    def test_encode_is_deterministic(self):
        receipt = self.log.prefix_search_receipt(b"a", 1, 4, size=4)
        data = encode_prefix_search_receipt(receipt)
        self.assertEqual(data, encode_prefix_search_receipt(receipt))

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
        self.assert_round_trip(self.log.prefix_search_receipt(b""))
        self.assert_round_trip(AuditLog().prefix_search_receipt(b""))

    def test_binary_prefix_round_trips(self):
        self.assert_round_trip(self.log.prefix_search_receipt(b"\x00\xff"))
        self.assert_round_trip(self.log.prefix_search_receipt(b"a\x00"))


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

    def test_range_receipt_magic_is_rejected(self):
        from auditchain import encode_range_search_receipt

        foreign = encode_range_search_receipt(
            self.log.range_search_receipt(b"a", b"b")
        )
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(foreign)

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
        data = encode_prefix_search_receipt(receipt)
        items_at = (
            len(MAGIC)
            + 8
            + len(blob(b"sha256"))
            + 8
            + 8
            + 32
            + 8
            + 1  # prefix blob
            + 8
            + 8
            + 8
        )
        bad = data[:items_at] + u64(4) + data[items_at + 8:]
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(bad)

    def test_missing_coverage_entry_rejected(self):
        receipt = self.log.prefix_search_receipt(b"a", 1, 4)
        # Drop the second item frame entirely.
        first_frame = encode_entry(receipt.items[0])
        head = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(receipt.size)
            + blob(receipt.root)
            + blob(receipt.prefix)
            + u64(receipt.start)
            + u64(receipt.stop)
        )
        # Count says 3 but only two item frames follow: the third read is a
        # proof count misparse or a width error, either way ValueError.
        tail_frames = first_frame + encode_entry(receipt.items[2])
        proof_blob = b"".join(blob(node) for node in receipt.proof)
        bad = head + u64(3) + tail_frames + u64(len(receipt.proof)) + proof_blob
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(bad)
        # Same byte slice parsed as 2 items would cover only [1, 3), which
        # fails the start/stop coverage check.
        bad2 = head + u64(2) + tail_frames + u64(len(receipt.proof)) + proof_blob
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(bad2)

    def test_non_empty_proof_for_empty_range_rejected(self):
        receipt = self.log.prefix_search_receipt(b"a", 2, 2)
        self.assertEqual(receipt.items, ())
        data = encode_prefix_search_receipt(receipt)
        # Append a bogus proof node after the proof count without removing
        # the trailing-byte requirement: flip count from 0 to 1 and append a
        # digest-width blob.
        bad = data[:-8] + u64(1) + blob(bytes(32))
        with self.assertRaises(ValueError):
            decode_prefix_search_receipt(bad)

    def test_structurally_valid_but_tampered_still_decodes(self):
        # A wrong root still parses; verification (not decode) catches it.
        receipt = self.log.prefix_search_receipt(b"a")
        data = encode_prefix_search_receipt(receipt)
        root_at = len(MAGIC) + 8 + len(blob(b"sha256")) + 8 + 8
        forged_root = bytes(32)
        bad = data[:root_at] + forged_root + data[root_at + 32:]
        restored = decode_prefix_search_receipt(bad)
        self.assertEqual(restored.root, forged_root)
        self.assertFalse(verify_prefix_search_receipt(restored))


if __name__ == "__main__":
    unittest.main()
