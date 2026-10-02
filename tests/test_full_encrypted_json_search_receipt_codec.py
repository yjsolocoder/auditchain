import json
import unittest

from auditchain import (
    AuditLog,
    decode_full_encrypted_json_search_receipt,
    encode_full_encrypted_json_search_receipt,
    verify_full_encrypted_json_search_receipt,
)

MAGIC = b"auditchain/full-encrypted-json-search/v1\0"

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def make_log():
    log = AuditLog()
    log.encrypt(j({"a": 1, "b": {"c": "x"}}), KEY, nonce=b"0" * 12)  # 0 hit
    log.append(j({"a": 1}))  # 1 plain JSON: never a hit
    log.encrypt(j({"a": 1.0}), KEY, nonce=b"1" * 12)  # 2 hit
    log.encrypt(j({"a": "1"}), KEY, nonce=b"2" * 12)  # 3
    log.encrypt(j({"a": 1}), OTHER_KEY, nonce=b"3" * 12)  # 4 foreign key
    return log


def encode_entry(entry):
    return (
        u64(entry.index)
        + blob(entry.payload)
        + blob(entry.previous_hash)
        + blob(entry.entry_hash)
    )


class EncodeFullEncryptedJsonSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_magic_and_field_layout(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 1, 4, size=4)
        data = encode_full_encrypted_json_search_receipt(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(4))  # size
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(32))  # root length
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.root)
        offset += 32
        self.assertEqual(data[offset:offset + 8], u64(2))  # pointer length
        offset += 8
        self.assertEqual(data[offset:offset + 2], b"/a")
        offset += 2
        self.assertEqual(data[offset:offset + 8], u64(1))  # integer value tag
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(1))  # value blob length
        offset += 8
        self.assertEqual(data[offset:offset + 1], b"1")
        offset += 1
        self.assertEqual(data[offset:offset + 8], u64(1))  # start
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(4))  # stop
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(3))  # items: 1, 2 and 3
        offset += 8
        for entry in receipt.items:
            self.assertEqual(
                data[offset:offset + len(encode_entry(entry))], encode_entry(entry)
            )
            offset += len(encode_entry(entry))
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.proof)))
        offset += 8
        for node in receipt.proof:
            self.assertEqual(data[offset:offset + 8], u64(32))
            offset += 8
            self.assertEqual(data[offset:offset + 32], node)
            offset += 32
        # The hit segment is a bare count followed by bare u64 indices.
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.hits)))
        offset += 8
        for hit in receipt.hits:
            self.assertEqual(data[offset:offset + 8], u64(hit))
            offset += 8
        # The key confirmation closes the encoding as one blob.
        self.assertEqual(data[offset:offset + 8], u64(32))
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.key_check)
        offset += 32
        self.assertEqual(offset, len(data))

    def test_encode_is_deterministic(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 1, 4, size=4)
        self.assertEqual(
            encode_full_encrypted_json_search_receipt(receipt),
            encode_full_encrypted_json_search_receipt(receipt),
        )

    def test_value_tags_round_trip(self):
        for value in ("x", 1, -5, 1.5, -0.0, True, False, None, "位置"):
            receipt = self.log.full_encrypted_json_search_receipt("/a", value, KEY)
            decoded = decode_full_encrypted_json_search_receipt(
                encode_full_encrypted_json_search_receipt(receipt)
            )
            self.assertEqual(decoded, receipt)
            self.assertEqual(type(decoded.value), type(receipt.value))

    def test_encode_rejects_other_types(self):
        with self.assertRaises(TypeError):
            encode_full_encrypted_json_search_receipt("not a receipt")
        with self.assertRaises(TypeError):
            encode_full_encrypted_json_search_receipt(
                self.log.full_encrypted_json_search_receipt("/a", 1, KEY).items
            )

    def test_encoding_records_neither_key_nor_plaintext(self):
        receipt = self.log.full_encrypted_json_search_receipt("/b/c", "x", KEY)
        data = encode_full_encrypted_json_search_receipt(receipt)
        self.assertNotIn(KEY, data)
        self.assertNotIn(j({"a": 1, "b": {"c": "x"}}), data)


class DecodeFullEncryptedJsonSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        self.data = encode_full_encrypted_json_search_receipt(self.receipt)

    def test_round_trip(self):
        decoded = decode_full_encrypted_json_search_receipt(self.data)
        self.assertEqual(decoded, self.receipt)
        self.assertEqual(encode_full_encrypted_json_search_receipt(decoded), self.data)
        self.assertTrue(verify_full_encrypted_json_search_receipt(decoded, KEY))

    def test_empty_range_round_trip(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 2, 2)
        data = encode_full_encrypted_json_search_receipt(receipt)
        self.assertEqual(decode_full_encrypted_json_search_receipt(data), receipt)

    def test_empty_snapshot_round_trip(self):
        receipt = AuditLog().full_encrypted_json_search_receipt("/a", 1, KEY)
        data = encode_full_encrypted_json_search_receipt(receipt)
        self.assertEqual(decode_full_encrypted_json_search_receipt(data), receipt)

    def test_non_bytes_rejected(self):
        for data in (bytearray(self.data), memoryview(self.data), "str", None):
            with self.assertRaises(TypeError, msg=type(data)):
                decode_full_encrypted_json_search_receipt(data)

    def test_bad_magic_rejected(self):
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(b"auditchain/json-search/v1\0" + self.data[len(MAGIC):])
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(b"")

    def test_truncation_rejected(self):
        for cut in (1, len(MAGIC), len(MAGIC) + 8, len(self.data) - 40, len(self.data) - 1):
            with self.assertRaises(ValueError, msg=cut):
                decode_full_encrypted_json_search_receipt(self.data[:cut])

    def test_trailing_bytes_rejected(self):
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(self.data + b"x")

    def test_bad_version_rejected(self):
        data = MAGIC + u64(2) + self.data[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data)

    def test_unknown_hash_rejected(self):
        data = MAGIC + u64(1) + blob(b"nope") + self.data[len(MAGIC) + 8 + 14:]
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data)

    def test_invalid_utf8_hash_name_rejected(self):
        data = MAGIC + u64(1) + blob(b"\xff") + self.data[len(MAGIC) + 8 + 14:]
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data)

    def test_unknown_value_tag_rejected(self):
        # The value type tag follows version, hash_name, size, root, pointer.
        prefix = MAGIC + u64(1) + blob(b"sha256") + u64(self.receipt.size)
        prefix += blob(self.receipt.root) + blob(b"/a")
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(prefix + u64(99) + blob(b""))

    def test_non_finite_float_value_rejected(self):
        prefix = MAGIC + u64(1) + blob(b"sha256") + u64(self.receipt.size)
        prefix += blob(self.receipt.root) + blob(b"/a")
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(prefix + u64(2) + blob(b"nan"))

    def test_structural_conflicts_rejected(self):
        # Duplicate hit indices: rebuild the encoding with hits (0, 0).
        # The tail is the hit count, two hit u64s and the key_check blob.
        head = self.data[:len(self.data) - (8 + 8 + 8 + 8 + 32)]
        data = head + u64(2) + u64(0) + u64(0) + blob(self.receipt.key_check)
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data)

    def test_oversized_blob_length_rejected(self):
        # Corrupt the hash_name length to an enormous value.
        data = MAGIC + u64(1) + u64(1 << 40) + self.data[len(MAGIC) + 16:]
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data)


if __name__ == "__main__":
    unittest.main()
