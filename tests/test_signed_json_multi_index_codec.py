import unittest

from auditchain import (
    AuditLog,
    JsonMultiIndex,
    SignedJsonMultiIndex,
    decode_json_multi_index,
    decode_signed_json_multi_index,
    encode_json_multi_index,
    encode_signed_json_multi_index,
    verify_json_multi_index,
    verify_signed_json_multi_index,
)

from tests.test_signed_json_multi_index import SEED_A, SEED_B, j, public_key

INDEX_MAGIC = b"auditchain/json-multi-index/v1\0"
SIGNED_MAGIC = b"auditchain/signed-json-multi-index/v1\0"

POINTERS = ("/a", "/b/c", "/z")


def make_log():
    log = AuditLog()
    log.append(j({"a": 1, "b": {"c": "x"}, "z": True}))
    log.append(j({"a": 1.0, "b": {"c": "y"}}))
    log.append(j({"a": True, "z": None}))
    log.append(j({"a": "x"}))
    log.append(j({"a": None, "z": 5}))
    log.append(b"not json")
    log.append(j({"other": 1}))
    return log


def make_bundle(log=None, pointers=POINTERS):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(pointers, SEED_A)


class JsonMultiIndexCodecTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()
        self.blob = encode_json_multi_index(self.bundle.index)

    def test_magic_prefix(self):
        self.assertTrue(self.blob.startswith(INDEX_MAGIC))

    def test_roundtrip_preserves_fields(self):
        decoded = decode_json_multi_index(self.blob)
        self.assertEqual(decoded, self.bundle.index)
        self.assertTrue(verify_json_multi_index(decoded))

    def test_reencode_is_byte_identical(self):
        decoded = decode_json_multi_index(self.blob)
        self.assertEqual(encode_json_multi_index(decoded), self.blob)

    def test_input_must_be_bytes(self):
        for bad in ("x", bytearray(self.blob), memoryview(self.blob), 1, None):
            with self.assertRaises(TypeError):
                decode_json_multi_index(bad)

    def test_bad_magic_raises_value_error(self):
        raw = bytearray(self.blob)
        raw[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decode_json_multi_index(bytes(raw))

    def test_non_index_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_json_multi_index("not-an-index")

    def test_trailing_and_truncated_bytes_rejected(self):
        with self.assertRaises(ValueError):
            decode_json_multi_index(self.blob + b"\x00")
        for cut in (
            len(INDEX_MAGIC),
            len(self.blob) - 1,
            len(self.blob) - 64,
        ):
            with self.assertRaises(ValueError):
                decode_json_multi_index(self.blob[:cut])

    def test_bad_version_rejected(self):
        # Version is the first u64 after the magic.
        cut = len(INDEX_MAGIC) + 8
        raw = bytearray(self.blob)
        raw[cut - 1] = 2
        with self.assertRaises(ValueError):
            decode_json_multi_index(bytes(raw))

    def test_empty_pointer_tuple_rejected(self):
        index = self.bundle.index
        with self.assertRaises(ValueError):
            JsonMultiIndex(
                index.version,
                index.hash_name,
                index.size,
                index.root,
                index.head,
                index.retain_from,
                (),
                index.items,
                index.proof,
                (),
            )

    def test_decoded_zero_pointer_count_rejected(self):
        # Hand-craft an otherwise well-framed encoding of an empty log
        # whose pointer count is zero; framing parses, semantics reject.
        import hashlib

        digest_size = len(hashlib.new(AuditLog().hash_name).digest())
        u64 = lambda value: value.to_bytes(8, "big")
        blob = lambda material: u64(len(material)) + material
        raw = (
            INDEX_MAGIC
            + u64(1)
            + blob(AuditLog().hash_name.encode("utf-8"))
            + u64(0)
            + blob(bytes(digest_size))
            + blob(bytes(digest_size))
            + u64(0)
            + u64(0)  # pointer count == 0
            + u64(0)  # item count
            + u64(0)  # proof count
        )
        with self.assertRaises(ValueError):
            decode_json_multi_index(raw)

    def test_decoded_group_section_count_mismatch_rejected(self):
        # Patch the first u64 inside the group-sections region from the
        # 1-group count to 0: framing then shifts and must fail with
        # ValueError (it cannot silently accept fewer pointer sections).
        index = self.bundle.index
        # Layout up to the group sections: magic, version, hash blob,
        # size, root blob, head blob, retain, pointer count, one pointer
        # blob each, item count, per-item 4 blobs, proof count+blobs.
        u64 = lambda value: value.to_bytes(8, "big")
        blob = lambda material: u64(len(material)) + material
        prefix = (
            INDEX_MAGIC
            + u64(index.version)
            + blob(index.hash_name.encode("utf-8"))
            + u64(index.size)
            + blob(bytes(index.root))
            + blob(bytes(index.head))
            + u64(index.retain_from)
            + u64(len(index.pointers))
        )
        for pointer in index.pointers:
            prefix += blob(pointer.encode("utf-8"))
        prefix += u64(len(index.items))
        for entry in index.items:
            prefix += u64(entry.index) + blob(entry.payload) + blob(
                entry.previous_hash
            ) + blob(entry.entry_hash)
        prefix += u64(len(index.proof))
        for node in index.proof:
            prefix += blob(node)
        self.assertEqual(self.blob[: len(prefix)], prefix)
        # The first pointer's group count is the next u64 and is >= 1 for
        # this log; flip it to 0. Trailing bytes then fail framing.
        raw = bytearray(self.blob)
        raw[len(prefix) + 7] = 0
        with self.assertRaises(ValueError):
            decode_json_multi_index(bytes(raw))

    def test_root_pointer_and_empty_log_roundtrip(self):
        log = AuditLog()
        log.append(b"42")
        log.append(b'"hello"')
        bundle = log.signed_json_multi_index(("", "/x"), SEED_A)
        blob = encode_json_multi_index(bundle.index)
        decoded = decode_json_multi_index(blob)
        self.assertEqual(encode_json_multi_index(decoded), blob)
        self.assertEqual(decoded.find("", 42), (0,))
        self.assertEqual(decoded.find("", "hello"), (1,))
        self.assertEqual(decoded.find("/x", 1), ())

    def test_empty_log_roundtrip(self):
        bundle = AuditLog().signed_json_multi_index(POINTERS, SEED_A)
        blob = encode_json_multi_index(bundle.index)
        decoded = decode_json_multi_index(blob)
        self.assertEqual(blob, encode_json_multi_index(decoded))
        self.assertEqual(decoded.size, 0)
        self.assertEqual(decoded.groups, ((), (), ()))

    def test_multiple_pointers_with_disjoint_hits_roundtrip(self):
        bundle = make_bundle()
        decoded = decode_json_multi_index(self.blob)
        self.assertEqual(decoded.pointers, POINTERS)
        self.assertEqual(decoded.find("/a", 1), bundle.find("/a", 1))
        self.assertEqual(decoded.find("/z", 5), (4,))
        self.assertEqual(decoded.find("/b/c", "x"), (0,))


class SignedJsonMultiIndexCodecTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()
        self.blob = encode_signed_json_multi_index(self.bundle)

    def test_magic_prefix(self):
        self.assertTrue(self.blob.startswith(SIGNED_MAGIC))

    def test_roundtrip_preserves_bundle(self):
        decoded = decode_signed_json_multi_index(self.blob)
        self.assertEqual(decoded, self.bundle)
        self.assertTrue(
            verify_signed_json_multi_index(decoded, public_key(SEED_A))
        )

    def test_reencode_is_byte_identical(self):
        decoded = decode_signed_json_multi_index(self.blob)
        self.assertEqual(
            encode_signed_json_multi_index(decoded), self.blob
        )

    def test_input_must_be_bytes(self):
        for bad in ("x", bytearray(self.blob), memoryview(self.blob), 1, None):
            with self.assertRaises(TypeError):
                decode_signed_json_multi_index(bad)

    def test_bad_magic_raises_value_error(self):
        raw = bytearray(self.blob)
        raw[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decode_signed_json_multi_index(bytes(raw))

    def test_non_bundle_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_signed_json_multi_index("not-a-bundle")

    def test_trailing_and_truncated_bytes_rejected(self):
        with self.assertRaises(ValueError):
            decode_signed_json_multi_index(self.blob + b"\x00")
        for cut in (
            len(SIGNED_MAGIC),
            len(self.blob) - 1,
            len(self.blob) - 32,
        ):
            with self.assertRaises(ValueError):
                decode_signed_json_multi_index(self.blob[:cut])

    def test_bad_version_rejected(self):
        cut = len(SIGNED_MAGIC) + 8
        raw = bytearray(self.blob)
        raw[cut - 1] = 2
        with self.assertRaises(ValueError):
            decode_signed_json_multi_index(bytes(raw))

    def test_wrong_key_signature_still_decodes_but_fails_verification(self):
        other_signed = make_log().signed_json_multi_index(POINTERS, SEED_B)
        repackaged = SignedJsonMultiIndex(
            self.bundle.index, other_signed.signature
        )
        blob = encode_signed_json_multi_index(repackaged)
        decoded = decode_signed_json_multi_index(blob)
        self.assertEqual(encode_signed_json_multi_index(decoded), blob)
        self.assertFalse(
            verify_signed_json_multi_index(decoded, public_key(SEED_A))
        )

    def test_pruned_index_roundtrip(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        blob = encode_signed_json_multi_index(bundle)
        decoded = decode_signed_json_multi_index(blob)
        self.assertEqual(encode_signed_json_multi_index(decoded), blob)
        self.assertEqual(decoded.index.retain_from, 3)
        self.assertTrue(
            verify_signed_json_multi_index(decoded, public_key(SEED_A))
        )


if __name__ == "__main__":
    unittest.main()
