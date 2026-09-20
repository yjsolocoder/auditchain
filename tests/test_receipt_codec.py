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


def blob(material):
    return u64(len(material)) + material


class EncodeAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_magic_and_field_layout(self):
        receipt = self.log.audit_receipt([1])
        data = encode_audit_receipt(receipt)
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
        self.assertEqual(data[offset:offset + 8], u64(2))  # items: 1 and 4

    def test_zero_length_blob_is_all_zero_u64(self):
        self.log.append(b"")
        receipt = self.log.audit_receipt([5])
        data = encode_audit_receipt(receipt)
        decoded = decode_audit_receipt(data)
        entry, _ = decoded.items[-1]
        self.assertEqual(entry.payload, b"")
        # The empty payload is framed as an all-zero u64 length.
        self.assertIn(u64(0), data)

    def test_encode_is_deterministic(self):
        receipt = self.log.audit_receipt([0, 2, 3])
        self.assertEqual(encode_audit_receipt(receipt), encode_audit_receipt(receipt))

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2)):
            with self.assertRaises(TypeError):
                encode_audit_receipt(bad)

    def test_integer_overflow(self):
        receipt = self.log.audit_receipt([1])
        # size == 2**64 with no items is rejected by the constructor, so
        # bypass it to exercise the encoder's own u64 range check.
        big = AuditReceipt.__new__(AuditReceipt)
        object.__setattr__(big, "version", 1)
        object.__setattr__(big, "hash_name", "sha256")
        object.__setattr__(big, "size", 1 << 64)
        object.__setattr__(big, "root", receipt.root)
        object.__setattr__(big, "items", ())
        with self.assertRaises(ValueError):
            encode_audit_receipt(big)
        entry = Entry(1 << 64, b"x", receipt.root, receipt.root)
        oversized = AuditReceipt(1, "sha256", (1 << 64) + 1, receipt.root, ((entry, ()),))
        with self.assertRaises(ValueError):
            encode_audit_receipt(oversized)


class DecodeAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def roundtrip(self, receipt):
        data = encode_audit_receipt(receipt)
        decoded = decode_audit_receipt(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.hash_name, receipt.hash_name)
        self.assertEqual(decoded.size, receipt.size)
        self.assertEqual(decoded.root, receipt.root)
        self.assertEqual(decoded.items, receipt.items)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_audit_receipt(decoded), data)
        self.assertTrue(verify_audit_receipt(decoded))
        return decoded

    def test_roundtrip_variants(self):
        for indices, size in (([0], None), ([1, 3], None), ([3], 4), ([], None), ([], 3)):
            self.roundtrip(self.log.audit_receipt(indices, size))

    def test_roundtrip_empty_snapshot(self):
        self.roundtrip(self.log.audit_receipt((), 0))

    def test_roundtrip_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.audit_receipt([2, 4]))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        self.roundtrip(log.audit_receipt([0, 2]))

    def test_only_bytes_accepted(self):
        receipt = self.log.audit_receipt([1])
        data = encode_audit_receipt(receipt)
        for bad in (bytearray(data), memoryview(data), "text", None, 1):
            with self.assertRaises(TypeError):
                decode_audit_receipt(bad)

    def test_bad_magic(self):
        receipt = self.log.audit_receipt([1])
        data = encode_audit_receipt(receipt)
        with self.assertRaises(ValueError):
            decode_audit_receipt(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_audit_receipt(b"")
        with self.assertRaises(ValueError):
            decode_audit_receipt(MAGIC[:-1])

    def test_bad_version(self):
        receipt = self.log.audit_receipt([1])
        data = MAGIC + u64(2) + encode_audit_receipt(receipt)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_audit_receipt(data)

    def test_unknown_hash_algorithm(self):
        data = MAGIC + u64(1) + blob(b"not-a-hash") + u64(0) + blob(b"") + u64(0)
        with self.assertRaises(ValueError):
            decode_audit_receipt(data)

    def test_invalid_utf8_hash_name(self):
        data = MAGIC + u64(1) + blob(b"\xff\xfe") + u64(0) + blob(b"") + u64(0)
        with self.assertRaises(ValueError):
            decode_audit_receipt(data)

    def test_truncation(self):
        receipt = self.log.audit_receipt([1, 3])
        data = encode_audit_receipt(receipt)
        for cut in (len(MAGIC) + 3, len(data) - 1, len(data) // 2):
            with self.assertRaises(ValueError):
                decode_audit_receipt(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_audit_receipt(data[:cut])

    def test_trailing_bytes(self):
        receipt = self.log.audit_receipt([1])
        data = encode_audit_receipt(receipt)
        with self.assertRaises(ValueError):
            decode_audit_receipt(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_audit_receipt(data)

    def make_bypassed(self, items, size=5):
        """Receipt with invalid structure, bypassing AuditReceipt validation."""
        forged = AuditReceipt.__new__(AuditReceipt)
        object.__setattr__(forged, "version", 1)
        object.__setattr__(forged, "hash_name", "sha256")
        object.__setattr__(forged, "size", size)
        object.__setattr__(forged, "root", self.log.merkle_root(size))
        object.__setattr__(forged, "items", items)
        return forged

    def test_digest_length_checked(self):
        data = MAGIC + u64(1) + blob(b"sha256") + u64(5) + blob(b"\x00" * 31) + u64(0)
        with self.assertRaises(ValueError):
            decode_audit_receipt(data)
        # A proof element of the wrong length is rejected too.
        receipt = self.log.audit_receipt([1])
        (entry, proof), *rest = receipt.items
        bad = ((entry, (b"\x00" * 16,) + proof[1:]),) + tuple(rest)
        with self.assertRaises(ValueError):
            decode_audit_receipt(encode_audit_receipt(self.make_bypassed(bad)))

    def test_index_order_and_duplicates(self):
        first = (self.log.entry(2), self.log.inclusion_proof(2))
        second = (self.log.entry(0), self.log.inclusion_proof(0))
        for items in ((first, second), (first, first)):
            with self.assertRaises(ValueError):
                decode_audit_receipt(encode_audit_receipt(self.make_bypassed(items)))

    def test_missing_last_entry(self):
        item = (self.log.entry(0), self.log.inclusion_proof(0))
        with self.assertRaises(ValueError):
            decode_audit_receipt(encode_audit_receipt(self.make_bypassed((item,))))

    def test_non_empty_snapshot_with_zero_items_rejected(self):
        # size > 0 but an empty item list: the last entry and its inclusion
        # proof are missing, so the zero-evidence receipt must not decode.
        data = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(5)
            + blob(self.log.merkle_root(5))
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_audit_receipt(data)

    def test_proof_structure_checked(self):
        receipt = self.log.audit_receipt([1])
        (entry, proof), *rest = receipt.items
        for bad_proof in (proof[:-1], proof + (b"\x00" * 32,)):
            bad = ((entry, bad_proof),) + tuple(rest)
            with self.assertRaises(ValueError):
                decode_audit_receipt(encode_audit_receipt(self.make_bypassed(bad)))
            with self.assertRaises(ValueError):
                encode_audit_receipt(self.make_bypassed(bad))


if __name__ == "__main__":
    unittest.main()
