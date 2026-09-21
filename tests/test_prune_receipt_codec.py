import hashlib
import unittest

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    PruneReceipt,
    decode_prune_receipt,
    encode_prune_receipt,
)

MAGIC = b"auditchain/prune-receipt/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


class EncodePruneReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_magic_and_field_layout(self):
        receipt = self.log.seal(3)
        data = encode_prune_receipt(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(3))  # size
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(32))  # merkle_root length
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.merkle_root)
        offset += 32
        self.assertEqual(data[offset:offset + 8], u64(32))  # chain_hash length
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.chain_hash)
        offset += 32
        # Nothing follows the chain_hash blob.
        self.assertEqual(len(data), offset)

    def test_expected_canonical_bytes(self):
        receipt = self.log.seal(3)
        expected = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(3)
            + blob(receipt.merkle_root)
            + blob(receipt.chain_hash)
        )
        self.assertEqual(encode_prune_receipt(receipt), expected)

    def test_empty_prefix_layout(self):
        receipt = self.log.seal(0)
        data = encode_prune_receipt(receipt)
        self.assertEqual(
            data,
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(0)
            + blob(receipt.merkle_root)
            + blob(GENESIS_HASH),
        )

    def test_encode_is_deterministic(self):
        receipt = self.log.seal(4)
        self.assertEqual(
            encode_prune_receipt(receipt), encode_prune_receipt(receipt)
        )

    def test_encode_is_read_only(self):
        receipt = self.log.seal(2)
        before = (
            receipt.hash_name,
            receipt.size,
            receipt.merkle_root,
            receipt.chain_hash,
        )
        encode_prune_receipt(receipt)
        self.assertEqual(
            before,
            (
                receipt.hash_name,
                receipt.size,
                receipt.merkle_root,
                receipt.chain_hash,
            ),
        )

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                encode_prune_receipt(bad)

    def make_bypassed(self, **overrides):
        """Receipt with arbitrary fields, bypassing PruneReceipt validation."""
        receipt = self.log.seal(3)
        forged = PruneReceipt.__new__(PruneReceipt)
        fields = {
            "hash_name": receipt.hash_name,
            "size": receipt.size,
            "merkle_root": receipt.merkle_root,
            "chain_hash": receipt.chain_hash,
        }
        fields.update(overrides)
        for name, value in fields.items():
            object.__setattr__(forged, name, value)
        return forged

    def test_bypassed_wrong_field_types_raise_type_error(self):
        cases = (
            {"hash_name": 123},
            {"hash_name": b"sha256"},
            {"size": "3"},
            {"size": True},
            {"merkle_root": "0" * 32},
            {"merkle_root": None},
            {"chain_hash": 1},
            {"chain_hash": [0] * 32},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                forged = self.make_bypassed(**overrides)
                with self.assertRaises(TypeError):
                    encode_prune_receipt(forged)

    def test_bypassed_size_overflow_raises_value_error(self):
        forged = self.make_bypassed(size=1 << 64)
        with self.assertRaises(ValueError):
            encode_prune_receipt(forged)

    def test_bypassed_negative_size_raises_value_error(self):
        forged = self.make_bypassed(size=-1)
        with self.assertRaises(ValueError):
            encode_prune_receipt(forged)

    def test_bypassed_digest_width_mismatch_raises_value_error(self):
        root = self.log.merkle_root(3)
        chain = self.log.entry(2).entry_hash
        for merkle_root, chain_hash in (
            (b"\x00" * 31, chain),
            (root, b"\x00" * 33),
            (root, b"\x00" * 16),  # unequal widths
            (b"\x01" * 16, chain),  # unequal widths the other way
        ):
            with self.subTest(widths=(len(merkle_root), len(chain_hash))):
                forged = self.make_bypassed(
                    merkle_root=merkle_root, chain_hash=chain_hash
                )
                with self.assertRaises(ValueError):
                    encode_prune_receipt(forged)

    def test_bypassed_variable_length_hash_raises_value_error(self):
        forged = self.make_bypassed(
            hash_name="shake_128",
            merkle_root=b"\x00" * 16,
            chain_hash=b"\x00" * 16,
        )
        self.assertEqual(hashlib.new("shake_128").digest_size, 0)
        with self.assertRaises(ValueError):
            encode_prune_receipt(forged)

    def test_bypassed_unknown_hash_raises_value_error(self):
        forged = self.make_bypassed(
            hash_name="not-a-hash",
            merkle_root=b"\x00" * 32,
            chain_hash=b"\x00" * 32,
        )
        with self.assertRaises(ValueError):
            encode_prune_receipt(forged)


class DecodePruneReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def roundtrip(self, receipt):
        data = encode_prune_receipt(receipt)
        decoded = decode_prune_receipt(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.hash_name, receipt.hash_name)
        self.assertEqual(decoded.size, receipt.size)
        self.assertEqual(decoded.merkle_root, receipt.merkle_root)
        self.assertEqual(decoded.chain_hash, receipt.chain_hash)
        # Re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_prune_receipt(decoded), data)
        return decoded

    def test_roundtrip_variants(self):
        for size in (0, 1, 3, 5):
            decoded = self.roundtrip(self.log.seal(size))
            self.assertIsInstance(decoded, PruneReceipt)

    def test_roundtrip_default_size(self):
        self.roundtrip(self.log.seal())

    def test_roundtrip_alternate_hashes(self):
        for hash_name in ("sha3-256", "sha512", "blake2b"):
            log = AuditLog(hash_name=hash_name)
            for record in ("a", "b", "c"):
                log.append(record)
            self.roundtrip(log.seal(0))
            self.roundtrip(log.seal(2))
            self.roundtrip(log.seal())

    def test_decoded_receipt_is_frozen(self):
        decoded = decode_prune_receipt(encode_prune_receipt(self.log.seal(2)))
        with self.assertRaises(Exception):
            decoded.size = 5
        with self.assertRaises(Exception):
            decoded.merkle_root = b"\x00" * 32

    def test_decoded_fields_are_plain_bytes(self):
        decoded = self.roundtrip(self.log.seal(2))
        self.assertIs(type(decoded.merkle_root), bytes)
        self.assertIs(type(decoded.chain_hash), bytes)

    def test_decoded_receipt_prunes_fresh_same_algorithm_log(self):
        # Simulate cross-process recovery: the bytes travel alone, and a log
        # rebuilt in another process prunes with the decoded receipt exactly as
        # it would with the original.
        receipt = self.log.seal(3)
        data = encode_prune_receipt(receipt)

        recovered_log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            recovered_log.append(record)
        recovered_log.prune(3, decode_prune_receipt(bytes(data)))
        self.assertEqual(recovered_log.retain_from, 3)
        self.assertEqual(len(recovered_log), 5)
        self.assertEqual(
            recovered_log.merkle_root(5), self.log.merkle_root(5)
        )
        self.assertTrue(recovered_log.verify())
        # The first retained entry still matches the checkpoint.
        self.assertTrue(receipt.matches(recovered_log.entry(3)))

    def test_decoded_receipt_after_empty_prefix_prune(self):
        data = encode_prune_receipt(self.log.seal(0))
        fresh = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            fresh.append(record)
        decoded = decode_prune_receipt(data)
        fresh.prune(0, decoded)
        self.assertEqual(fresh.retain_from, 0)
        self.assertTrue(decoded.matches(fresh.entry(0)))

    def test_only_bytes_accepted(self):
        data = encode_prune_receipt(self.log.seal(2))
        for bad in (bytearray(data), memoryview(data), "text", None, 1, []):
            with self.assertRaises(TypeError):
                decode_prune_receipt(bad)

    def test_bad_magic(self):
        data = encode_prune_receipt(self.log.seal(2))
        with self.assertRaises(ValueError):
            decode_prune_receipt(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_prune_receipt(b"")
        with self.assertRaises(ValueError):
            decode_prune_receipt(MAGIC[:-1])

    def test_bad_version(self):
        receipt = self.log.seal(2)
        data = MAGIC + u64(2) + encode_prune_receipt(receipt)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)
        data = MAGIC + u64(0) + encode_prune_receipt(receipt)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)

    def test_unknown_hash_algorithm(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"not-a-hash")
            + u64(0)
            + blob(b"\x00" * 32)
            + blob(b"\x00" * 32)
        )
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)

    def test_variable_length_hash_algorithm(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"shake_128")
            + u64(0)
            + blob(b"\x00" * 16)
            + blob(b"\x00" * 16)
        )
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)

    def test_invalid_utf8_hash_name(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"\xff\xfe")
            + u64(0)
            + blob(b"\x00" * 32)
            + blob(b"\x00" * 32)
        )
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)

    def test_truncation(self):
        data = encode_prune_receipt(self.log.seal(3))
        for cut in (
            len(MAGIC) + 3,
            len(data) - 1,
            len(data) // 2,
            len(MAGIC),
        ):
            with self.assertRaises(ValueError):
                decode_prune_receipt(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_prune_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_prune_receipt(self.log.seal(2))
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_prune_receipt(data + extra)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)
        # size itself fits the u64 framing, but the merkle_root length that
        # follows must not claim bytes beyond the remaining buffer.
        data = MAGIC + u64(1) + blob(b"sha256") + u64(2) + u64(1 << 63)
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)

    def test_digest_length_checked(self):
        root = self.log.merkle_root(3)
        chain = self.log.entry(2).entry_hash
        # merkle_root one byte short.
        data = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(3)
            + blob(root[:31])
            + blob(chain)
        )
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)
        # chain_hash one byte long.
        data = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(3)
            + blob(root)
            + blob(chain + b"\x00")
        )
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)
        # Equal but wrong widths for the named algorithm are rejected too.
        data = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(3)
            + blob(b"\x00" * 16)
            + blob(b"\x00" * 16)
        )
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)

    def test_unequal_digest_widths_checked(self):
        root = self.log.merkle_root(3)
        chain = self.log.entry(2).entry_hash
        data = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(3)
            + blob(root)
            + blob(chain[:16])
        )
        with self.assertRaises(ValueError):
            decode_prune_receipt(data)


if __name__ == "__main__":
    unittest.main()
