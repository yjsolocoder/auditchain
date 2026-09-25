import dataclasses
import unittest

from auditchain import (
    AuditLog,
    SearchReceipt,
    decode_search_receipt,
    encode_search_receipt,
    verify_search_receipt,
)

MAGIC = b"auditchain/search-receipt/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


class EncodeSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a"):
            self.log.append(record)

    def test_magic_and_field_layout(self):
        receipt = self.log.search_receipt("b")
        data = encode_search_receipt(receipt)
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
        self.assertEqual(data[offset:offset + 8], u64(1))  # query length
        offset += 8
        self.assertEqual(data[offset:offset + 1], b"b")
        offset += 1
        self.assertEqual(data[offset:offset + 8], u64(0))  # start
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(5))  # stop
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(1))  # one hit

    def test_empty_query_blob_is_all_zero_u64(self):
        self.log.append("")
        receipt = self.log.search_receipt("")
        data = encode_search_receipt(receipt)
        decoded = decode_search_receipt(data)
        self.assertEqual(decoded.query, b"")
        for entry, _ in decoded.items:
            self.assertEqual(entry.payload, b"")
        self.assertIn(u64(0), data)

    def test_encode_is_deterministic(self):
        receipt = self.log.search_receipt("a")
        self.assertEqual(
            encode_search_receipt(receipt), encode_search_receipt(receipt)
        )

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2), []):
            with self.assertRaises(TypeError):
                encode_search_receipt(bad)

    def make_bypassed(self, **fields):
        """Receipt bypassing the frozen constructor's validation."""
        receipt = self.log.search_receipt("a")
        forged = SearchReceipt.__new__(SearchReceipt)
        values = dict(
            version=receipt.version,
            hash_name=receipt.hash_name,
            size=receipt.size,
            root=receipt.root,
            query=receipt.query,
            start=receipt.start,
            stop=receipt.stop,
            items=receipt.items,
        )
        values.update(fields)
        for name, value in values.items():
            object.__setattr__(forged, name, value)
        return forged

    def test_encode_revalidates_bad_fields(self):
        # A bypassed receipt with wrong field types must still be rejected.
        with self.assertRaises(TypeError):
            encode_search_receipt(self.make_bypassed(query="a"))
        with self.assertRaises(TypeError):
            encode_search_receipt(self.make_bypassed(size="5"))
        with self.assertRaises(TypeError):
            encode_search_receipt(self.make_bypassed(root="00" * 32))
        with self.assertRaises(ValueError):
            encode_search_receipt(self.make_bypassed(hash_name="nope"))
        with self.assertRaises(ValueError):
            encode_search_receipt(self.make_bypassed(stop=6))

    def test_tampered_content_still_encodes(self):
        receipt = self.log.search_receipt("a")
        tampered = SearchReceipt(
            1,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            b"a",
            receipt.start,
            receipt.stop,
            tuple(
                (dataclasses.replace(entry, payload=b"z"), proof)
                for entry, proof in receipt.items
            ),
        )
        data = encode_search_receipt(tampered)
        self.assertFalse(verify_search_receipt(decode_search_receipt(data)))


class DecodeSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a"):
            self.log.append(record)

    def roundtrip(self, receipt):
        data = encode_search_receipt(receipt)
        decoded = decode_search_receipt(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.hash_name, receipt.hash_name)
        self.assertEqual(decoded.size, receipt.size)
        self.assertEqual(decoded.root, receipt.root)
        self.assertEqual(decoded.query, receipt.query)
        self.assertEqual(decoded.start, receipt.start)
        self.assertEqual(decoded.stop, receipt.stop)
        self.assertEqual(decoded.items, receipt.items)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_search_receipt(decoded), data)
        self.assertTrue(verify_search_receipt(decoded))
        return decoded

    def test_roundtrip_variants(self):
        cases = (
            self.log.search_receipt("a"),
            self.log.search_receipt("b"),
            self.log.search_receipt("missing"),
            self.log.search_receipt("a", 1, 4),
            self.log.search_receipt("a", 2, 2),
            self.log.search_receipt("a", size=3),
            self.log.search_receipt(b"a"),
        )
        for receipt in cases:
            self.roundtrip(receipt)

    def test_roundtrip_empty_snapshot(self):
        receipt = AuditLog().search_receipt("x")
        data = encode_search_receipt(receipt)
        decoded = self.roundtrip(receipt)
        self.assertEqual((decoded.size, decoded.start, decoded.stop), (0, 0, 0))
        self.assertEqual(decoded.items, ())

    def test_roundtrip_empty_snapshot_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.search_receipt("a", size=0))

    def test_roundtrip_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.search_receipt("a"))
        self.roundtrip(self.log.search_receipt("b"))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "a"):
            log.append(record)
        self.roundtrip(log.search_receipt("a"))

    def test_only_bytes_accepted(self):
        data = encode_search_receipt(self.log.search_receipt("a"))
        for bad in (bytearray(data), memoryview(data), "text", None, 1):
            with self.assertRaises(TypeError):
                decode_search_receipt(bad)

    def test_bad_magic(self):
        data = encode_search_receipt(self.log.search_receipt("a"))
        with self.assertRaises(ValueError):
            decode_search_receipt(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_search_receipt(b"")
        with self.assertRaises(ValueError):
            decode_search_receipt(MAGIC[:-1])

    def test_bad_version(self):
        receipt = self.log.search_receipt("a")
        data = MAGIC + u64(2) + encode_search_receipt(receipt)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_search_receipt(data)

    def test_unknown_hash_algorithm(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"not-a-hash")
            + u64(0)
            + blob(b"")
            + blob(b"")
            + u64(0)
            + u64(0)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_search_receipt(data)

    def test_invalid_utf8_hash_name(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"\xff\xfe")
            + u64(0)
            + blob(b"")
            + blob(b"")
            + u64(0)
            + u64(0)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_search_receipt(data)

    def test_truncation(self):
        data = encode_search_receipt(self.log.search_receipt("a"))
        for cut in (len(MAGIC) + 3, len(data) - 1, len(data) // 2):
            with self.assertRaises(ValueError):
                decode_search_receipt(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_search_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_search_receipt(self.log.search_receipt("a"))
        with self.assertRaises(ValueError):
            decode_search_receipt(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_search_receipt(data)

    def test_digest_length_checked(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(5)
            + blob(b"\x00" * 31)
            + blob(b"a")
            + u64(0)
            + u64(5)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_search_receipt(data)

    def test_range_structure_checked(self):
        root = self.log.merkle_root(5)
        header = (
            MAGIC + u64(1) + blob(b"sha256") + u64(5) + blob(root) + blob(b"a")
        )
        # start > stop
        with self.assertRaises(ValueError):
            decode_search_receipt(header + u64(4) + u64(2) + u64(0))
        # stop > size
        with self.assertRaises(ValueError):
            decode_search_receipt(header + u64(0) + u64(6) + u64(0))

    def test_empty_snapshot_with_items_rejected(self):
        root = self.log.merkle_root(0)
        item = self.log.entry(0)
        data = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(0)
            + blob(root)
            + blob(b"a")
            + u64(0)
            + u64(0)
            + u64(1)
            + u64(0)
            + blob(item.payload)
            + blob(item.previous_hash)
            + blob(item.entry_hash)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_search_receipt(data)

    def make_bypassed(self, items, start=0, stop=5, size=5, query=b"a"):
        forged = SearchReceipt.__new__(SearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", size),
            ("root", self.log.merkle_root(size)),
            ("query", query),
            ("start", start),
            ("stop", stop),
            ("items", items),
        ):
            object.__setattr__(forged, name, value)
        return forged

    def test_index_outside_range_rejected(self):
        # Index 0 listed under a recorded range [1, 5).
        item = (self.log.entry(0), self.log.inclusion_proof(0, 5))
        forged = self.make_bypassed((item,), start=1, stop=5)
        with self.assertRaises(ValueError):
            decode_search_receipt(encode_search_receipt(forged))

    def test_index_order_and_duplicates(self):
        first = (self.log.entry(2), self.log.inclusion_proof(2, 5))
        second = (self.log.entry(0), self.log.inclusion_proof(0, 5))
        for items in ((first, second), (first, first)):
            with self.assertRaises(ValueError):
                decode_search_receipt(encode_search_receipt(self.make_bypassed(items)))

    def test_proof_structure_checked(self):
        receipt = self.log.search_receipt("a")
        (entry, proof), *rest = receipt.items
        for bad_proof in (proof[:-1], proof + (b"\x00" * 32,)):
            forged = self.make_bypassed(((entry, bad_proof),) + tuple(rest))
            with self.assertRaises(ValueError):
                decode_search_receipt(encode_search_receipt(forged))
            with self.assertRaises(ValueError):
                encode_search_receipt(forged)

    def test_tampered_receipt_roundtrips_but_verifies_false(self):
        receipt = self.log.search_receipt("a")
        tampered = SearchReceipt(
            1,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            b"a",
            receipt.start,
            receipt.stop,
            tuple(
                (dataclasses.replace(entry, payload=b"z"), proof)
                for entry, proof in receipt.items
            ),
        )
        data = encode_search_receipt(tampered)
        decoded = decode_search_receipt(data)
        self.assertEqual(decoded, tampered)
        self.assertEqual(encode_search_receipt(decoded), data)
        self.assertFalse(verify_search_receipt(decoded))


if __name__ == "__main__":
    unittest.main()
