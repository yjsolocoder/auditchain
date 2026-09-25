import copy
import unittest

from auditchain import (
    AuditLog,
    MerkleFrontier,
    decode_merkle_frontier,
    encode_merkle_frontier,
    rebuild_merkle_root,
)

MAGIC = b"auditchain/frontier/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def build(hash_name, size, subtrees, version=1):
    """Hand-build a merkle-frontier encoding with arbitrary content."""
    out = MAGIC + u64(version) + blob(hash_name) + u64(size)
    out += u64(len(subtrees))
    for height, digest in subtrees:
        out += u64(height) + blob(digest)
    return out


class MerkleFrontierCodecTestBase(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.credential = self.log.merkle_frontier()


class EncodeMerkleFrontierTest(MerkleFrontierCodecTestBase):
    def test_magic_and_field_layout(self):
        data = encode_merkle_frontier(self.credential)
        expected = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(self.credential.size)
            + u64(len(self.credential.subtrees))
            + b"".join(
                u64(height) + blob(digest)
                for height, digest in self.credential.subtrees
            )
        )
        self.assertEqual(data, expected)

    def test_encode_is_deterministic(self):
        self.assertEqual(
            encode_merkle_frontier(self.credential),
            encode_merkle_frontier(self.credential),
        )

    def test_encoding_is_read_only(self):
        snapshot = (
            self.credential.hash_name,
            self.credential.size,
            self.credential.subtrees,
        )
        encode_merkle_frontier(self.credential)
        self.assertEqual(
            (
                self.credential.hash_name,
                self.credential.size,
                self.credential.subtrees,
            ),
            snapshot,
        )

    def test_only_credential_accepted(self):
        for bad in (None, "x", b"bytes", 1, (), object()):
            with self.assertRaises(TypeError):
                encode_merkle_frontier(bad)

    def test_bypassed_fields_revalidated(self):
        digest = b"\x00" * 32
        for name, value, exc in (
            ("hash_name", 1, TypeError),
            ("hash_name", "not-a-hash", ValueError),
            ("size", "7", TypeError),
            ("size", True, TypeError),
            ("size", -1, ValueError),
            ("size", 1 << 64, ValueError),
            ("subtrees", list(self.credential.subtrees), TypeError),
            ("subtrees", ((0, bytearray(32)),), TypeError),
            ("subtrees", ((0, b"\x00" * 31),), ValueError),
            ("subtrees", ((1, digest), (0, digest)), ValueError),
            ("subtrees", ((0, digest),), ValueError),  # not the set bits of 7
        ):
            forged = copy.copy(self.credential)
            object.__setattr__(forged, name, value)
            with self.assertRaises(exc):
                encode_merkle_frontier(forged)


class DecodeMerkleFrontierTest(MerkleFrontierCodecTestBase):
    def roundtrip(self, credential):
        data = encode_merkle_frontier(credential)
        decoded = decode_merkle_frontier(data)
        self.assertIsInstance(decoded, MerkleFrontier)
        self.assertEqual(decoded, credential)
        self.assertEqual(encode_merkle_frontier(decoded), data)
        return decoded

    def test_roundtrip_variants(self):
        for size in range(len(self.log) + 1):
            self.roundtrip(self.log.merkle_frontier(size))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        self.roundtrip(log.merkle_frontier())

    def test_roundtrip_empty_frontier(self):
        self.roundtrip(self.log.merkle_frontier(0))

    def test_decoded_is_frozen(self):
        decoded = self.roundtrip(self.credential)
        with self.assertRaises(Exception):
            decoded.size = 1

    def test_only_exact_bytes_accepted(self):
        data = encode_merkle_frontier(self.credential)
        for bad in (bytearray(data), memoryview(data), "text", None, 1, [data]):
            with self.assertRaises(TypeError):
                decode_merkle_frontier(bad)

    def test_bad_magic(self):
        data = encode_merkle_frontier(self.credential)
        with self.assertRaises(ValueError):
            decode_merkle_frontier(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_merkle_frontier(b"")
        with self.assertRaises(ValueError):
            decode_merkle_frontier(MAGIC[:-1])

    def test_bad_version(self):
        data = encode_merkle_frontier(self.credential)
        with self.assertRaises(ValueError):
            decode_merkle_frontier(MAGIC + u64(2) + data[len(MAGIC) + 8:])

    def test_unknown_hash_algorithm(self):
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build(b"not-a-hash", 0, ()))

    def test_invalid_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build(b"\xff\xfe", 0, ()))

    def test_truncation(self):
        data = encode_merkle_frontier(self.credential)
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_merkle_frontier(data[:cut])

    def test_trailing_bytes(self):
        data = encode_merkle_frontier(self.credential)
        with self.assertRaises(ValueError):
            decode_merkle_frontier(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_merkle_frontier(data)

    def test_digest_width_checked(self):
        digest = b"\x00" * 32
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build(b"sha256", 1, ((0, b"\x00" * 31),)))
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build(b"sha256", 1, ((0, b""),)))
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build(b"sha256", 3, ((0, digest), (1, b"\x00" * 31))))

    def test_height_order_checked(self):
        digest = b"\x00" * 32
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build(b"sha256", 3, ((1, digest), (0, digest))))
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build(b"sha256", 3, ((0, digest), (0, digest))))

    def test_set_bit_mismatch_rejected(self):
        digest = b"\x00" * 32
        # 6 == 0b110: heights must be exactly (1, 2).
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build(b"sha256", 6, ((1, digest),)))
        with self.assertRaises(ValueError):
            decode_merkle_frontier(
                build(b"sha256", 6, ((0, digest), (1, digest), (2, digest)))
            )
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build(b"sha256", 6, ((1, digest), (3, digest))))

    def test_size_range_checked(self):
        digest = b"\x00" * 32
        # The u64 wire field itself cannot express 2**64; the largest
        # encodable size fails the set-bit coverage check instead.
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build(b"sha256", (1 << 64) - 1, ()))

    def test_decoded_matches_live_capture(self):
        decoded = self.roundtrip(self.credential)
        self.assertEqual(
            rebuild_merkle_root(decoded, ()),
            self.log.merkle_root(),
        )


if __name__ == "__main__":
    unittest.main()
