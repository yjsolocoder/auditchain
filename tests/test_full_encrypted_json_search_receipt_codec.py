import json
import unittest

from auditchain import (
    AuditLog,
    FullEncryptedJsonSearchReceipt,
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
    if isinstance(material, str):
        material = material.encode("utf-8")
    return u64(len(material)) + material


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def make_log():
    log = AuditLog()
    log.encrypt(j({"a": 1}), KEY, nonce=b"0" * 12)
    log.encrypt(j({"a": 1.0}), KEY, nonce=b"1" * 12)
    log.encrypt(j({"a": "1"}), KEY, nonce=b"2" * 12)
    log.append(j({"a": 1}))
    log.encrypt(b"{bad", KEY, nonce=b"3" * 12)
    log.encrypt(j({"a": 1}), OTHER_KEY, nonce=b"4" * 12)
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
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        data = encode_full_encrypted_json_search_receipt(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8 + 6
        self.assertEqual(data[offset:offset + 8], u64(receipt.size))
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(32))  # root length
        offset += 8 + 32
        self.assertEqual(data[offset:offset + 8], u64(2))  # pointer "/a"
        offset += 8 + 2
        # value: type tag 1 (integer) + blob "1"
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        self.assertEqual(data[offset:offset + 1], b"1")
        offset += 1
        self.assertEqual(data[offset:offset + 8], u64(receipt.start))
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(receipt.stop))
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.items)))
        offset += 8
        for entry in receipt.items:
            self.assertEqual(
                data[offset:offset + len(encode_entry(entry))],
                encode_entry(entry),
            )
            offset += len(encode_entry(entry))
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.proof)))
        offset += 8
        for node in receipt.proof:
            self.assertEqual(data[offset:offset + 8], u64(32))
            offset += 8 + 32
        # Hit segment: bare u64 indices.
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.hits)))
        offset += 8
        for hit in receipt.hits:
            self.assertEqual(data[offset:offset + 8], u64(hit))
            offset += 8
        # Final confirmation blob.
        self.assertEqual(data[offset:offset + 8], u64(32))
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.confirmation)
        offset += 32
        self.assertEqual(offset, len(data))

    def test_value_kinds(self):
        cases = {
            "string": ("/a", "x", 0, b"x"),
            "integer": ("/a", 1, 1, b"1"),
            "float": ("/a", 1.5, 2, repr(1.5).encode()),
            "true": ("/a", True, 3, b""),
            "null": ("/a", None, 4, b""),
            "false": ("/a", False, 5, b""),
        }
        log = AuditLog()
        docs = [
            {"a": "x"}, {"a": 1}, {"a": 1.5}, {"a": True}, {"a": None},
            {"a": False},
        ]
        for index, doc in enumerate(docs):
            log.encrypt(j(doc), KEY, nonce=bytes([index]) * 12)
        for name, (pointer, value, tag, raw) in cases.items():
            with self.subTest(name):
                receipt = log.full_encrypted_json_search_receipt(pointer, value, KEY)
                data = encode_full_encrypted_json_search_receipt(receipt)
                self.assertIn(u64(tag) + blob(raw), data)

    def test_encode_is_deterministic(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        self.assertEqual(
            encode_full_encrypted_json_search_receipt(receipt),
            encode_full_encrypted_json_search_receipt(receipt),
        )

    def test_empty_range_and_empty_snapshot(self):
        receipt = self.log.full_encrypted_json_search_receipt(
            "/a", 1, KEY, 2, 2, size=6
        )
        data = encode_full_encrypted_json_search_receipt(receipt)
        # zero items, zero proof, zero hits, then confirmation blob
        self.assertTrue(data.endswith(u64(0) + u64(0) + u64(0) + u64(32) + receipt.confirmation))
        snapshot = AuditLog().full_encrypted_json_search_receipt("/a", 1, KEY)
        encoded = encode_full_encrypted_json_search_receipt(snapshot)
        self.assertEqual(
            encoded,
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(0)
            + blob(snapshot.root)
            + blob("/a")
            + u64(1)
            + blob(b"1")
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(32)
            + snapshot.confirmation,
        )

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                encode_full_encrypted_json_search_receipt(bad)

    def test_encode_revalidates_bypassed_fields(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        names = (
            "version", "hash_name", "size", "root", "pointer", "value",
            "start", "stop", "items", "proof", "hits", "confirmation",
        )

        def bypassed(**fields):
            forged = FullEncryptedJsonSearchReceipt.__new__(
                FullEncryptedJsonSearchReceipt
            )
            for name in names:
                object.__setattr__(forged, name, fields.get(name, getattr(receipt, name)))
            return forged

        with self.assertRaises(ValueError):
            encode_full_encrypted_json_search_receipt(bypassed(version=2))
        with self.assertRaises(TypeError):
            encode_full_encrypted_json_search_receipt(bypassed(value=[1]))
        with self.assertRaises(ValueError):
            encode_full_encrypted_json_search_receipt(
                bypassed(confirmation=b"\x00" * 31)
            )

    def test_proof_node_count_checked(self):
        receipt = self.log.full_encrypted_json_search_receipt(
            "/a", 1, KEY, 1, 4, size=6
        )
        self.assertTrue(receipt.proof)
        names = (
            "version", "hash_name", "size", "root", "pointer", "value",
            "start", "stop", "items", "proof", "hits", "confirmation",
        )

        def bypassed(**fields):
            forged = FullEncryptedJsonSearchReceipt.__new__(
                FullEncryptedJsonSearchReceipt
            )
            for name in names:
                object.__setattr__(forged, name, fields.get(name, getattr(receipt, name)))
            return forged

        with self.assertRaises(ValueError):
            encode_full_encrypted_json_search_receipt(bypassed(proof=()))
        with self.assertRaises(ValueError):
            encode_full_encrypted_json_search_receipt(
                bypassed(proof=receipt.proof + (b"\x00" * 32,))
            )


class DecodeFullEncryptedJsonSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def roundtrip(self, receipt):
        data = encode_full_encrypted_json_search_receipt(receipt)
        decoded = decode_full_encrypted_json_search_receipt(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.pointer, receipt.pointer)
        self.assertEqual(decoded.value, receipt.value)
        self.assertEqual(decoded.hits, receipt.hits)
        self.assertEqual(decoded.confirmation, receipt.confirmation)
        self.assertEqual(
            encode_full_encrypted_json_search_receipt(decoded), data
        )
        return decoded

    def test_roundtrip_variants(self):
        receipt = self.roundtrip(
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        )
        self.assertTrue(
            verify_full_encrypted_json_search_receipt(receipt, KEY)
        )
        for value in ("1", 1, 1.0, True, False, None):
            self.roundtrip(
                self.log.full_encrypted_json_search_receipt("/a", value, KEY)
            )
        self.roundtrip(
            self.log.full_encrypted_json_search_receipt("/b/c", "x", KEY)
        )
        self.roundtrip(
            self.log.full_encrypted_json_search_receipt("/a~1b", 1, KEY)
        )
        self.roundtrip(
            self.log.full_encrypted_json_search_receipt("", 1, KEY)
        )
        self.roundtrip(
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 1, 4, size=4)
        )

    def test_roundtrip_empty_range_and_snapshot(self):
        self.roundtrip(
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 2, 2, size=6)
        )
        self.roundtrip(
            AuditLog().full_encrypted_json_search_receipt("/a", 1, KEY)
        )

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        log.encrypt(j({"a": 1}), KEY, nonce=b"0" * 12)
        receipt = self.roundtrip(
            log.full_encrypted_json_search_receipt("/a", 1, KEY)
        )
        self.assertTrue(
            verify_full_encrypted_json_search_receipt(receipt, KEY)
        )

    def test_roundtrip_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        receipt = self.roundtrip(
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        )
        self.assertTrue(
            verify_full_encrypted_json_search_receipt(receipt, KEY)
        )

    def test_tampered_receipt_roundtrips_but_fails_verification(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        forged = FullEncryptedJsonSearchReceipt(
            1,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.pointer,
            receipt.value,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
            (),  # conceal a hit
            receipt.confirmation,
        )
        data = encode_full_encrypted_json_search_receipt(forged)
        decoded = decode_full_encrypted_json_search_receipt(data)
        self.assertEqual(decoded, forged)
        self.assertEqual(encode_full_encrypted_json_search_receipt(decoded), data)
        self.assertFalse(
            verify_full_encrypted_json_search_receipt(decoded, KEY)
        )

    def test_only_bytes_accepted(self):
        data = encode_full_encrypted_json_search_receipt(
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        )
        for bad in (bytearray(data), memoryview(data), "text", None, 1, []):
            with self.assertRaises(TypeError):
                decode_full_encrypted_json_search_receipt(bad)

    def test_bad_magic(self):
        data = encode_full_encrypted_json_search_receipt(
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(b"")
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(MAGIC[:-1])

    def test_bad_version(self):
        data = encode_full_encrypted_json_search_receipt(
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        )
        forged = MAGIC + u64(2) + data[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(forged)

    def test_unknown_hash_algorithm(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"not-a-hash")
            + u64(0)
            + blob(b"")
            + blob("/a")
            + u64(1)
            + blob(b"1")
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data)

    def test_invalid_utf8_fields(self):
        good = encode_full_encrypted_json_search_receipt(
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        )
        # Flip the hash_name blob bytes directly by rebuilding a minimal
        # invalid stream with bad UTF-8 in hash_name.
        data = (
            MAGIC
            + u64(1)
            + blob(b"\xff\xfe")
            + u64(0)
            + blob(b"")
            + blob("/a")
            + u64(1)
            + blob(b"1")
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data)
        self.assertTrue(len(good) > 0)

    def test_bad_pointer_utf8(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        good = encode_full_encrypted_json_search_receipt(receipt)
        pre_pointer = (
            MAGIC + u64(1) + blob(b"sha256") + u64(receipt.size)
            + blob(receipt.root)
        )
        rest = good[len(pre_pointer):]
        old_len = int.from_bytes(rest[:8], "big")
        suffix = rest[8 + old_len:]
        corrupted = pre_pointer + u64(2) + b"\xff\xfe" + suffix
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(corrupted)

    def _splice_value(self, receipt, new_tag, new_blob):
        good = encode_full_encrypted_json_search_receipt(receipt)
        pre_pointer = (
            MAGIC + u64(1) + blob(b"sha256") + u64(receipt.size)
            + blob(receipt.root)
        )
        rest = good[len(pre_pointer):]
        pointer_len = int.from_bytes(rest[:8], "big")
        after_pointer = rest[8 + pointer_len:]
        after_tag = after_pointer[8:]
        old_len = int.from_bytes(after_tag[:8], "big")
        suffix = after_tag[8 + old_len:]
        return (
            pre_pointer
            + u64(pointer_len)
            + rest[8:8 + pointer_len]
            + u64(new_tag)
            + u64(len(new_blob))
            + new_blob
            + suffix
        )

    def test_unknown_value_tag(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        corrupted = self._splice_value(receipt, 99, b"1")
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(corrupted)

    def test_bad_encoded_integer(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        # Mirroring _decode_json_value of the existing JSON receipt codec:
        # non-digit content is rejected (leading zeros are tolerated and
        # normalize on re-encode).
        for bad in (b"", b"-", b"1.0", b"x"):
            with self.subTest(bad=bad):
                corrupted = self._splice_value(receipt, 1, bad)
                with self.assertRaises(ValueError):
                    decode_full_encrypted_json_search_receipt(corrupted)

    def test_non_finite_encoded_float(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1.0, KEY)
        for bad in (b"nan", b"inf", b"-Infinity"):
            with self.subTest(bad=bad):
                corrupted = self._splice_value(receipt, 2, bad)
                with self.assertRaises(ValueError):
                    decode_full_encrypted_json_search_receipt(corrupted)

    def test_malformed_pointer_syntax(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        good = encode_full_encrypted_json_search_receipt(receipt)
        pre_pointer = (
            MAGIC + u64(1) + blob(b"sha256") + u64(receipt.size)
            + blob(receipt.root)
        )
        rest = good[len(pre_pointer):]
        old_len = int.from_bytes(rest[:8], "big")
        suffix = rest[8 + old_len:]
        corrupted = pre_pointer + blob(b"a") + suffix
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(corrupted)

    def test_truncation(self):
        data = encode_full_encrypted_json_search_receipt(
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        )
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_full_encrypted_json_search_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_full_encrypted_json_search_receipt(
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data)

    def test_digest_length_checked(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)

        def bypassed(**fields):
            forged = FullEncryptedJsonSearchReceipt.__new__(
                FullEncryptedJsonSearchReceipt
            )
            names = (
                "version", "hash_name", "size", "root", "pointer", "value",
                "start", "stop", "items", "proof", "hits", "confirmation",
            )
            for name in names:
                object.__setattr__(
                    forged, name, fields.get(name, getattr(receipt, name))
                )
            return forged

        with self.assertRaises(ValueError):
            encode_full_encrypted_json_search_receipt(
                bypassed(root=b"\x00" * 31)
            )
        with self.assertRaises(ValueError):
            encode_full_encrypted_json_search_receipt(
                bypassed(confirmation=b"\x00" * 16)
            )

    def test_item_order_duplicates_and_coverage(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        names = (
            "version", "hash_name", "size", "root", "pointer", "value",
            "start", "stop", "items", "proof", "hits", "confirmation",
        )

        def encode_bypassed(items, proof, stop=None):
            forged = FullEncryptedJsonSearchReceipt.__new__(
                FullEncryptedJsonSearchReceipt
            )
            values = dict(
                version=1,
                hash_name="sha256",
                size=6,
                root=self.log.merkle_root(6),
                pointer="/a",
                value=1,
                start=0,
                stop=len(items) if stop is None else stop,
                items=items,
                proof=proof,
                hits=(),
                confirmation=receipt.confirmation,
            )
            for name in names:
                object.__setattr__(forged, name, values[name])
            return encode_full_encrypted_json_search_receipt(forged)

        items = tuple(self.log.entry(i) for i in range(6))
        _, proof = self.log.batch_inclusion_proof(tuple(range(6)), 6)
        # Out-of-order / duplicate indices are rejected at encode time.
        with self.assertRaises(ValueError):
            encode_bypassed((items[1], items[0]) + items[2:], proof)
        # An incomplete coverage of the range is rejected at encode time.
        _, short_proof = self.log.batch_inclusion_proof(tuple(range(5)), 6)
        with self.assertRaises(ValueError):
            encode_bypassed(items[:5], short_proof, stop=6)

    def test_hit_segment_errors(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        names = (
            "version", "hash_name", "size", "root", "pointer", "value",
            "start", "stop", "items", "proof", "hits", "confirmation",
        )

        def encode_with_hits(hits):
            forged = FullEncryptedJsonSearchReceipt.__new__(
                FullEncryptedJsonSearchReceipt
            )
            for name in names:
                object.__setattr__(
                    forged, name, getattr(receipt, name)
                )
            object.__setattr__(forged, "hits", hits)
            return encode_full_encrypted_json_search_receipt(forged)

        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(encode_with_hits((1, 0)))
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(encode_with_hits((0, 0)))
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(encode_with_hits((6,)))


if __name__ == "__main__":
    unittest.main()
