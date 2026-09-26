import unittest

from auditchain import (
    AuditLog,
    Entry,
    FullSearchReceipt,
    decode_full_search_receipt,
    encode_full_search_receipt,
    verify_full_search_receipt,
)

MAGIC = b"auditchain/full-search/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def make_log(records=("a", "b", "a", "c", "a")):
    log = AuditLog()
    for record in records:
        log.append(record)
    return log


class EncodeFullSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_magic_and_field_layout(self):
        receipt = self.log.full_search_receipt("a")
        data = encode_full_search_receipt(receipt)
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
        self.assertEqual(data[offset:offset + 1], b"a")
        offset += 1
        self.assertEqual(data[offset:offset + 8], u64(0))  # start
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(5))  # stop
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(5))  # items: 0..4
        offset += 8
        for entry in receipt.items:
            self.assertEqual(data[offset:offset + 8], u64(entry.index))
            offset += 8
            self.assertEqual(data[offset:offset + 8], u64(len(entry.payload)))
            offset += 8
            self.assertEqual(data[offset:offset + len(entry.payload)], entry.payload)
            offset += len(entry.payload)
            self.assertEqual(data[offset:offset + 8], u64(32))
            offset += 8
            self.assertEqual(data[offset:offset + 32], entry.previous_hash)
            offset += 32
            self.assertEqual(data[offset:offset + 8], u64(32))
            offset += 8
            self.assertEqual(data[offset:offset + 32], entry.entry_hash)
            offset += 32
        # The whole range is selected, so the shared proof carries no nodes.
        self.assertEqual(data[offset:offset + 8], u64(0))
        self.assertEqual(offset + 8, len(data))

    def test_encode_is_deterministic(self):
        receipt = self.log.full_search_receipt("a", 1, 4, size=4)
        self.assertEqual(
            encode_full_search_receipt(receipt), encode_full_search_receipt(receipt)
        )

    def test_empty_range_and_empty_snapshot_encode(self):
        empty = self.log.full_search_receipt("a", 2, 2)
        data = encode_full_search_receipt(empty)
        self.assertTrue(data.endswith(u64(0) + u64(0)))  # zero items, zero nodes
        snapshot = AuditLog().full_search_receipt("a")
        self.assertEqual(
            encode_full_search_receipt(snapshot),
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
                encode_full_search_receipt(bad)

    def make_bypassed(self, **fields):
        """Receipt with invalid structure, bypassing FullSearchReceipt validation."""
        receipt = self.log.full_search_receipt("a")
        forged = FullSearchReceipt.__new__(FullSearchReceipt)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "query",
            "start",
            "stop",
            "items",
            "proof",
        ):
            object.__setattr__(forged, name, fields.get(name, getattr(receipt, name)))
        return forged

    def test_encode_revalidates_bypassed_fields(self):
        with self.assertRaises(ValueError):
            encode_full_search_receipt(self.make_bypassed(version=2))
        with self.assertRaises(ValueError):
            encode_full_search_receipt(self.make_bypassed(stop=2))  # items outside range
        with self.assertRaises(TypeError):
            encode_full_search_receipt(self.make_bypassed(query=123))
        with self.assertRaises(TypeError):
            encode_full_search_receipt(self.make_bypassed(items="not-a-tuple"))
        with self.assertRaises(TypeError):
            encode_full_search_receipt(self.make_bypassed(proof="not-a-tuple"))


class DecodeFullSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def roundtrip(self, receipt):
        data = encode_full_search_receipt(receipt)
        decoded = decode_full_search_receipt(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.hash_name, receipt.hash_name)
        self.assertEqual(decoded.size, receipt.size)
        self.assertEqual(decoded.root, receipt.root)
        self.assertEqual(decoded.query, receipt.query)
        self.assertEqual((decoded.start, decoded.stop), (receipt.start, receipt.stop))
        self.assertEqual(decoded.items, receipt.items)
        self.assertEqual(decoded.proof, receipt.proof)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_full_search_receipt(decoded), data)
        self.assertTrue(verify_full_search_receipt(decoded))
        return decoded

    def test_roundtrip_variants(self):
        self.roundtrip(self.log.full_search_receipt("a"))
        self.roundtrip(self.log.full_search_receipt("b"))
        self.roundtrip(self.log.full_search_receipt("missing"))
        self.roundtrip(self.log.full_search_receipt("a", 1, 4))
        self.roundtrip(self.log.full_search_receipt("a", size=3))
        self.roundtrip(self.log.full_search_receipt("a", 0, 3, size=3))

    def test_roundtrip_empty_range_and_empty_snapshot(self):
        self.roundtrip(self.log.full_search_receipt("a", 2, 2))
        self.roundtrip(AuditLog().full_search_receipt("a"))

    def test_roundtrip_unicode_query(self):
        self.log.append("位置主张")
        receipt = self.log.full_search_receipt("位置主张")
        decoded = self.roundtrip(receipt)
        self.assertEqual(decoded.query, "位置主张".encode("utf-8"))

    def test_roundtrip_after_prune(self):
        self.log.append("b")
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.full_search_receipt("a"))
        self.roundtrip(self.log.full_search_receipt("b"))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "a"):
            log.append(record)
        self.roundtrip(log.full_search_receipt("a"))

    def test_tampered_receipt_still_roundtrips_and_fails_verification(self):
        receipt = self.log.full_search_receipt("a")
        entry = receipt.items[0]
        forged_entry = Entry(entry.index, b"zz", entry.previous_hash, entry.entry_hash)
        tampered = FullSearchReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            receipt.query,
            receipt.start,
            receipt.stop,
            (forged_entry,) + receipt.items[1:],
            receipt.proof,
        )
        data = encode_full_search_receipt(tampered)
        decoded = decode_full_search_receipt(data)
        self.assertEqual(decoded, tampered)
        self.assertEqual(encode_full_search_receipt(decoded), data)
        self.assertFalse(verify_full_search_receipt(decoded))

    def test_only_bytes_accepted(self):
        data = encode_full_search_receipt(self.log.full_search_receipt("a"))
        for bad in (bytearray(data), memoryview(data), "text", None, 1):
            with self.assertRaises(TypeError):
                decode_full_search_receipt(bad)

    def test_bad_magic(self):
        data = encode_full_search_receipt(self.log.full_search_receipt("a"))
        with self.assertRaises(ValueError):
            decode_full_search_receipt(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_full_search_receipt(b"")
        with self.assertRaises(ValueError):
            decode_full_search_receipt(MAGIC[:-1])

    def test_bad_version(self):
        data = encode_full_search_receipt(self.log.full_search_receipt("a"))
        forged = MAGIC + u64(2) + data[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_full_search_receipt(forged)

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
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_full_search_receipt(data)

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
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_full_search_receipt(data)

    def test_truncation(self):
        data = encode_full_search_receipt(self.log.full_search_receipt("a"))
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_full_search_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_full_search_receipt(self.log.full_search_receipt("a"))
        with self.assertRaises(ValueError):
            decode_full_search_receipt(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_full_search_receipt(data)

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
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_full_search_receipt(data)
        # A proof node of the wrong width is rejected too.
        receipt = self.log.full_search_receipt("a", 1, 5)
        forged = FullSearchReceipt.__new__(FullSearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", receipt.size),
            ("root", receipt.root),
            ("query", receipt.query),
            ("start", receipt.start),
            ("stop", receipt.stop),
            ("items", receipt.items),
            ("proof", (b"\x00" * 16,) + receipt.proof[1:]),
        ):
            object.__setattr__(forged, name, value)
        with self.assertRaises(ValueError):
            encode_full_search_receipt(forged)

    def make_bypassed(self, items, proof=(), size=5, start=0, stop=5):
        forged = FullSearchReceipt.__new__(FullSearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", size),
            ("root", self.log.merkle_root(size)),
            ("query", b"a"),
            ("start", start),
            ("stop", stop),
            ("items", items),
            ("proof", proof),
        ):
            object.__setattr__(forged, name, value)
        return forged

    def test_index_order_and_duplicates(self):
        first = self.log.entry(2)
        second = self.log.entry(0)
        for items in ((first, second), (first, first)):
            with self.assertRaises(ValueError):
                decode_full_search_receipt(
                    encode_full_search_receipt(self.make_bypassed(items))
                )

    def test_index_outside_recorded_range(self):
        item = self.log.entry(4)
        with self.assertRaises(ValueError):
            decode_full_search_receipt(
                encode_full_search_receipt(self.make_bypassed((item,), stop=4))
            )

    def test_proof_without_items_rejected(self):
        with self.assertRaises(ValueError):
            decode_full_search_receipt(
                encode_full_search_receipt(
                    self.make_bypassed((), proof=(b"\x00" * 32,), start=2, stop=2)
                )
            )


if __name__ == "__main__":
    unittest.main()
