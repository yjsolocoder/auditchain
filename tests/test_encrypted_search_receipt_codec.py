import unittest

from auditchain import (
    AuditLog,
    EncryptedSearchReceipt,
    Entry,
    decode_encrypted_search_receipt,
    encode_encrypted_search_receipt,
    verify_encrypted_search_receipt,
)

MAGIC = b"auditchain/encrypted-search/v1\0"

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def make_log(records=("a", "b", "a", "c", "a")):
    log = AuditLog()
    for counter, record in enumerate(records):
        log.encrypt(record, KEY, nonce=bytes([counter]) * 12)
    return log


class EncodeEncryptedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_magic_and_field_layout(self):
        receipt = self.log.encrypted_search_receipt("a", KEY)
        data = encode_encrypted_search_receipt(receipt)
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
        self.assertEqual(data[offset:offset + 8], u64(3))  # items: 0, 2 and 4

    def test_magic_has_nul_terminator(self):
        self.assertTrue(MAGIC.endswith(b"\0"))
        self.assertEqual(MAGIC, b"auditchain/encrypted-search/v1" + b"\0")

    def test_item_payload_is_the_sealed_envelope(self):
        receipt = self.log.encrypted_search_receipt("a", KEY)
        data = encode_encrypted_search_receipt(receipt)
        entry = receipt.items[0][0]
        self.assertTrue(entry.payload.startswith(b"auditchain/encrypted-entry/v1\0"))
        # Each item writes the sealed envelope verbatim as its payload blob.
        self.assertIn(blob(entry.payload), data)

    def test_encode_is_deterministic(self):
        receipt = self.log.encrypted_search_receipt("a", KEY, 1, 4, size=4)
        self.assertEqual(
            encode_encrypted_search_receipt(receipt),
            encode_encrypted_search_receipt(receipt),
        )

    def test_empty_result_and_empty_snapshot_encode(self):
        empty = self.log.encrypted_search_receipt("missing", KEY)
        data = encode_encrypted_search_receipt(empty)
        self.assertTrue(data.endswith(u64(0)))  # zero items
        snapshot = AuditLog().encrypted_search_receipt("a", KEY)
        self.assertEqual(
            encode_encrypted_search_receipt(snapshot),
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(0)
            + blob(snapshot.root)
            + blob(b"a")
            + u64(0)
            + u64(0)
            + u64(0),
        )

    def test_not_decodable_as_plain_search_receipt(self):
        from auditchain import decode_search_receipt

        receipt = self.log.encrypted_search_receipt("a", KEY)
        data = encode_encrypted_search_receipt(receipt)
        # Only the magic distinguishes the two wire formats; each decoder
        # rejects the other's magic.
        with self.assertRaises(ValueError):
            decode_search_receipt(data)
        plain_log = AuditLog()
        for record in ("a", "b", "a", "c", "a"):
            plain_log.append(record)
        plain_data = __import__("auditchain").encode_search_receipt(
            plain_log.search_receipt("a")
        )
        with self.assertRaises(ValueError):
            decode_encrypted_search_receipt(plain_data)

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2)):
            with self.assertRaises(TypeError):
                encode_encrypted_search_receipt(bad)

    def make_bypassed(self, **fields):
        """Receipt with invalid structure, bypassing the constructor."""
        receipt = self.log.encrypted_search_receipt("a", KEY)
        forged = EncryptedSearchReceipt.__new__(EncryptedSearchReceipt)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "query",
            "start",
            "stop",
            "items",
        ):
            object.__setattr__(forged, name, fields.get(name, getattr(receipt, name)))
        return forged

    def test_encode_revalidates_bypassed_fields(self):
        with self.assertRaises(ValueError):
            encode_encrypted_search_receipt(self.make_bypassed(version=2))
        with self.assertRaises(ValueError):
            encode_encrypted_search_receipt(self.make_bypassed(stop=2))
        with self.assertRaises(TypeError):
            encode_encrypted_search_receipt(self.make_bypassed(query=123))
        with self.assertRaises(TypeError):
            encode_encrypted_search_receipt(self.make_bypassed(items="not-a-tuple"))

    def test_proof_level_count_checked(self):
        receipt = self.log.encrypted_search_receipt("a", KEY)
        (entry, proof), *rest = receipt.items
        short = ((entry, proof[:-1]),) + tuple(rest)
        with self.assertRaises(ValueError):
            encode_encrypted_search_receipt(self.make_bypassed(items=short))
        long = ((entry, proof + (b"\x00" * 32,)),) + tuple(rest)
        with self.assertRaises(ValueError):
            encode_encrypted_search_receipt(self.make_bypassed(items=long))


class DecodeEncryptedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def roundtrip(self, receipt, key=KEY):
        data = encode_encrypted_search_receipt(receipt)
        decoded = decode_encrypted_search_receipt(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.hash_name, receipt.hash_name)
        self.assertEqual(decoded.size, receipt.size)
        self.assertEqual(decoded.root, receipt.root)
        self.assertEqual(decoded.query, receipt.query)
        self.assertEqual((decoded.start, decoded.stop), (receipt.start, receipt.stop))
        self.assertEqual(decoded.items, receipt.items)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_encrypted_search_receipt(decoded), data)
        self.assertTrue(verify_encrypted_search_receipt(decoded, key))
        return decoded

    def test_roundtrip_variants(self):
        self.roundtrip(self.log.encrypted_search_receipt("a", KEY))
        self.roundtrip(self.log.encrypted_search_receipt("b", KEY))
        self.roundtrip(self.log.encrypted_search_receipt("a", KEY, 1, 4))
        self.roundtrip(self.log.encrypted_search_receipt("a", KEY, size=3))
        self.roundtrip(self.log.encrypted_search_receipt("a", KEY, 0, 3, size=3))

    def test_roundtrip_empty_result_and_empty_snapshot(self):
        self.roundtrip(self.log.encrypted_search_receipt("missing", KEY))
        self.roundtrip(AuditLog().encrypted_search_receipt("a", KEY))

    def test_roundtrip_unicode_query(self):
        self.log.encrypt("位置主张", KEY, nonce=b"u" * 12)
        self.log.encrypt("位置主张", KEY, nonce=b"v" * 12)
        receipt = self.log.encrypted_search_receipt("位置主张", KEY)
        decoded = self.roundtrip(receipt)
        self.assertEqual(decoded.query, "位置主张".encode("utf-8"))

    def test_roundtrip_after_prune(self):
        self.log.encrypt("b", KEY, nonce=b"9" * 12)
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.encrypted_search_receipt("a", KEY))
        self.roundtrip(self.log.encrypted_search_receipt("b", KEY))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3_256")
        for counter, record in enumerate(("a", "b", "a")):
            log.encrypt(record, KEY, nonce=bytes([counter]) * 12)
        self.roundtrip(log.encrypted_search_receipt("a", KEY))

    def test_decoded_object_is_frozen(self):
        data = encode_encrypted_search_receipt(self.log.encrypted_search_receipt("a", KEY))
        decoded = decode_encrypted_search_receipt(data)
        with self.assertRaises(AttributeError):
            decoded.query = b"b"

    def test_tampered_envelope_still_roundtrips_and_fails_verification(self):
        receipt = self.log.encrypted_search_receipt("a", KEY)
        entry, proof = receipt.items[0]
        raw = entry.payload[:-1] + bytes([entry.payload[-1] ^ 0x01])
        forged_entry = Entry(entry.index, raw, entry.previous_hash, entry.entry_hash)
        tampered = EncryptedSearchReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            receipt.query,
            receipt.start,
            receipt.stop,
            ((forged_entry, proof),) + receipt.items[1:],
        )
        data = encode_encrypted_search_receipt(tampered)
        decoded = decode_encrypted_search_receipt(data)
        self.assertEqual(decoded, tampered)
        self.assertEqual(encode_encrypted_search_receipt(decoded), data)
        self.assertFalse(verify_encrypted_search_receipt(decoded, KEY))

    def test_wrong_key_content_roundtrips_but_fails_verification(self):
        log = AuditLog()
        log.encrypt("secret", KEY, nonce=b"0" * 12)
        log.encrypt("secret", OTHER_KEY, nonce=b"1" * 12)
        receipt = log.encrypted_search_receipt("secret", OTHER_KEY)
        data = encode_encrypted_search_receipt(receipt)
        decoded = decode_encrypted_search_receipt(data)
        self.assertEqual(decoded, receipt)
        self.assertTrue(verify_encrypted_search_receipt(decoded, OTHER_KEY))
        self.assertFalse(verify_encrypted_search_receipt(decoded, KEY))

    def test_only_bytes_accepted(self):
        data = encode_encrypted_search_receipt(self.log.encrypted_search_receipt("a", KEY))
        for bad in (bytearray(data), memoryview(data), "text", None, 1):
            with self.assertRaises(TypeError):
                decode_encrypted_search_receipt(bad)

    def test_bad_magic(self):
        data = encode_encrypted_search_receipt(self.log.encrypted_search_receipt("a", KEY))
        with self.assertRaises(ValueError):
            decode_encrypted_search_receipt(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_encrypted_search_receipt(b"")
        with self.assertRaises(ValueError):
            decode_encrypted_search_receipt(MAGIC[:-1])

    def test_bad_version(self):
        data = encode_encrypted_search_receipt(self.log.encrypted_search_receipt("a", KEY))
        forged = MAGIC + u64(2) + data[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_encrypted_search_receipt(forged)

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
            decode_encrypted_search_receipt(data)

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
            decode_encrypted_search_receipt(data)

    def test_truncation(self):
        data = encode_encrypted_search_receipt(self.log.encrypted_search_receipt("a", KEY))
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_encrypted_search_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_encrypted_search_receipt(self.log.encrypted_search_receipt("a", KEY))
        with self.assertRaises(ValueError):
            decode_encrypted_search_receipt(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_encrypted_search_receipt(data)

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
            decode_encrypted_search_receipt(data)
        receipt = self.log.encrypted_search_receipt("a", KEY)
        (entry, proof), *rest = receipt.items
        bad = ((entry, (b"\x00" * 16,) + proof[1:]),) + tuple(rest)
        forged = EncryptedSearchReceipt.__new__(EncryptedSearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", 5),
            ("root", self.log.merkle_root()),
            ("query", b"a"),
            ("start", 0),
            ("stop", 5),
            ("items", bad),
        ):
            object.__setattr__(forged, name, value)
        with self.assertRaises(ValueError):
            encode_encrypted_search_receipt(forged)

    def make_bypassed(self, items, size=5, start=0, stop=5):
        forged = EncryptedSearchReceipt.__new__(EncryptedSearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", size),
            ("root", self.log.merkle_root(size)),
            ("query", b"a"),
            ("start", start),
            ("stop", stop),
            ("items", items),
        ):
            object.__setattr__(forged, name, value)
        return forged

    def test_index_order_and_duplicates(self):
        first = (self.log.entry(2), self.log.inclusion_proof(2))
        second = (self.log.entry(0), self.log.inclusion_proof(0))
        for items in ((first, second), (first, first)):
            with self.assertRaises(ValueError):
                decode_encrypted_search_receipt(
                    encode_encrypted_search_receipt(self.make_bypassed(items))
                )

    def test_index_outside_recorded_range(self):
        item = (self.log.entry(4), self.log.inclusion_proof(4))
        with self.assertRaises(ValueError):
            decode_encrypted_search_receipt(
                encode_encrypted_search_receipt(self.make_bypassed((item,), stop=4))
            )

    def test_proof_structure_checked(self):
        entry = self.log.entry(1)
        proof = self.log.inclusion_proof(1)
        for bad_proof in (proof[:-1], proof + (b"\x00" * 32,)):
            with self.assertRaises(ValueError):
                decode_encrypted_search_receipt(
                    encode_encrypted_search_receipt(
                        self.make_bypassed(((entry, bad_proof),))
                    )
                )


if __name__ == "__main__":
    unittest.main()
