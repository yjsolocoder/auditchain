import unittest

from auditchain import (
    AuditLog,
    AuditReceipt,
    Entry,
    decode_audit_receipt,
    encode_audit_receipt,
    verify_audit_receipt,
)

MAGIC = b"auditchain/audit-receipt/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(data):
    return u64(len(data)) + data


class EncodeAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_magic_prefix(self):
        data = encode_audit_receipt(self.log.audit_receipt([1]))
        self.assertTrue(data.startswith(MAGIC))

    def test_layout(self):
        receipt = self.log.audit_receipt([1], 3)
        expected = bytearray(MAGIC)
        expected += u64(1)
        expected += blob(b"sha256")
        expected += u64(3)
        expected += blob(receipt.root)
        expected += u64(len(receipt.items))
        for entry, proof in receipt.items:
            expected += u64(entry.index)
            expected += blob(entry.payload)
            expected += blob(entry.previous_hash)
            expected += blob(entry.entry_hash)
            expected += u64(len(proof))
            for sibling in proof:
                expected += blob(sibling)
        self.assertEqual(encode_audit_receipt(receipt), bytes(expected))

    def test_zero_length_blob_is_all_zero_u64(self):
        receipt = self.log.audit_receipt([], 0)
        data = encode_audit_receipt(receipt)
        # version, empty hash-name length slot is non-empty; the items count
        # is zero and the encoding ends right after it.
        self.assertTrue(data.endswith(u64(0)))

    def test_encode_is_deterministic(self):
        receipt = self.log.audit_receipt([0, 2])
        self.assertEqual(encode_audit_receipt(receipt), encode_audit_receipt(receipt))

    def test_encode_type_error(self):
        for bad in ("receipt", None, b"", 42, self.log):
            with self.assertRaises(TypeError):
                encode_audit_receipt(bad)

    def test_encode_integer_overflow(self):
        receipt = AuditReceipt(1, "sha256", 0, self.log.merkle_root(0), ())
        oversized = AuditReceipt(1, "sha256", 1 << 64, receipt.root, ())
        with self.assertRaises(ValueError):
            encode_audit_receipt(oversized)


class DecodeAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def roundtrip(self, indices, size=None):
        receipt = self.log.audit_receipt(indices, size)
        decoded = decode_audit_receipt(encode_audit_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertTrue(verify_audit_receipt(decoded))
        return receipt, decoded

    def test_roundtrip(self):
        for indices, size in (([0], None), ([1, 3], None), ([3], 4), ([], None), ([], 3)):
            self.roundtrip(indices, size)

    def test_roundtrip_empty_snapshot(self):
        self.roundtrip((), 0)

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        receipt = log.audit_receipt([0, 2])
        decoded = decode_audit_receipt(encode_audit_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertTrue(verify_audit_receipt(decoded))

    def test_decoded_fields_match(self):
        receipt = self.log.audit_receipt([1, 3])
        decoded = decode_audit_receipt(encode_audit_receipt(receipt))
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.hash_name, receipt.hash_name)
        self.assertEqual(decoded.size, receipt.size)
        self.assertEqual(decoded.root, receipt.root)
        self.assertEqual(decoded.items, receipt.items)

    def test_decode_then_encode_is_byte_identical(self):
        data = encode_audit_receipt(self.log.audit_receipt([0, 2, 4]))
        self.assertEqual(encode_audit_receipt(decode_audit_receipt(data)), data)

    def test_decode_type_error(self):
        for bad in ("text", bytearray(encode_audit_receipt(self.log.audit_receipt([]))), None, 42):
            with self.assertRaises(TypeError):
                decode_audit_receipt(bad)

    def test_bad_magic(self):
        data = encode_audit_receipt(self.log.audit_receipt([0]))
        with self.assertRaises(ValueError):
            decode_audit_receipt(b"auditchain/audit-receipt/v2\0" + data[len(MAGIC):])
        with self.assertRaises(ValueError):
            decode_audit_receipt(b"")
        with self.assertRaises(ValueError):
            decode_audit_receipt(MAGIC[:-1])

    def test_bad_version(self):
        data = encode_audit_receipt(self.log.audit_receipt([0]))
        with self.assertRaises(ValueError):
            decode_audit_receipt(MAGIC + u64(2) + data[len(MAGIC) + 8:])
        with self.assertRaises(ValueError):
            decode_audit_receipt(MAGIC + u64(0) + data[len(MAGIC) + 8:])

    def test_unknown_algorithm(self):
        data = MAGIC + u64(1) + blob(b"not-a-hash") + u64(0) + blob(b"\x00" * 32) + u64(0)
        with self.assertRaises(ValueError):
            decode_audit_receipt(data)

    def test_invalid_utf8_hash_name(self):
        data = MAGIC + u64(1) + blob(b"\xff\xfe") + u64(0) + blob(b"\x00" * 32) + u64(0)
        with self.assertRaises(ValueError):
            decode_audit_receipt(data)

    def test_truncation(self):
        data = encode_audit_receipt(self.log.audit_receipt([0, 2]))
        for cut in (len(MAGIC) + 3, len(data) - 1, len(data) // 2):
            with self.assertRaises(ValueError):
                decode_audit_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_audit_receipt(self.log.audit_receipt([0]))
        with self.assertRaises(ValueError):
            decode_audit_receipt(data + b"\x00")

    def test_overlong_blob_length(self):
        # A blob length that exceeds the remaining data.
        data = MAGIC + u64(1) + u64(1 << 64 - 1) + b"sha256"
        with self.assertRaises(ValueError):
            decode_audit_receipt(data)
        data = MAGIC + u64(1) + u64(10) + b"sha256"
        with self.assertRaises(ValueError):
            decode_audit_receipt(data)

    def test_digest_length_checked(self):
        receipt = self.log.audit_receipt([0])
        data = encode_audit_receipt(receipt)
        # Rebuild with a 31-byte root.
        bad = MAGIC + u64(1) + blob(b"sha256") + u64(receipt.size) + blob(b"\x00" * 31)
        bad += data[len(MAGIC) + 8 + 8 + 6 + 8 + 8 + 32:]
        with self.assertRaises(ValueError):
            decode_audit_receipt(bad)

    def test_index_order_and_duplicates(self):
        receipt = self.log.audit_receipt([0, 2])
        items = receipt.items
        # Encode items in swapped order by hand.
        def encode_items(pair):
            entry, proof = pair
            out = bytearray(u64(entry.index))
            out += blob(entry.payload) + blob(entry.previous_hash) + blob(entry.entry_hash)
            out += u64(len(proof))
            for sibling in proof:
                out += blob(sibling)
            return bytes(out)

        header = MAGIC + u64(1) + blob(b"sha256") + u64(receipt.size) + blob(receipt.root)
        with self.assertRaises(ValueError):
            decode_audit_receipt(header + u64(2) + encode_items(items[1]) + encode_items(items[0]))
        with self.assertRaises(ValueError):
            decode_audit_receipt(header + u64(2) + encode_items(items[0]) + encode_items(items[0]))

    def test_missing_last_entry(self):
        receipt = self.log.audit_receipt([0, 2])
        entry, proof = receipt.items[0]
        data = bytearray(MAGIC + u64(1) + blob(b"sha256") + u64(receipt.size) + blob(receipt.root))
        data += u64(1)
        data += u64(entry.index) + blob(entry.payload) + blob(entry.previous_hash) + blob(entry.entry_hash)
        data += u64(len(proof))
        for sibling in proof:
            data += blob(sibling)
        with self.assertRaises(ValueError):
            decode_audit_receipt(bytes(data))

    def test_proof_structure_checked(self):
        receipt = self.log.audit_receipt([1])
        (entry, proof), *rest = receipt.items
        short = AuditReceipt(1, "sha256", receipt.size, receipt.root, ((entry, proof[:-1]),) + tuple(rest))
        with self.assertRaises(ValueError):
            verify_audit_receipt(decode_audit_receipt(encode_audit_receipt(short)))


if __name__ == "__main__":
    unittest.main()
