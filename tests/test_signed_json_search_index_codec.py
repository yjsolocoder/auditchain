import json
import unittest

from auditchain import (
    AuditLog,
    SignedJsonSearchIndex,
    decode_json_search_index,
    decode_signed_json_search_index,
    encode_json_search_index,
    encode_signed_json_search_index,
    verify_json_search_index,
    verify_signed_json_search_index,
)

from tests.test_signed_json_search_index import SEED_A, SEED_B, j, public_key

INDEX_MAGIC = b"auditchain/json-search-index/v1\0"
SIGNED_MAGIC = b"auditchain/signed-json-search-index/v1\0"


def make_bundle(log=None, pointer="/a"):
    log = log if log is not None else make_log()
    return log.signed_json_search_index(pointer, SEED_A)


def make_log():
    log = AuditLog()
    log.append(j({"a": 1}))
    log.append(j({"a": 1.0}))
    log.append(j({"a": True}))
    log.append(j({"a": "x"}))
    log.append(j({"a": None}))
    log.append(b"not json")
    log.append(j({"other": 1}))
    return log


class JsonSearchIndexCodecTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()
        self.blob = encode_json_search_index(self.bundle.index)

    def test_magic_prefix(self):
        self.assertTrue(self.blob.startswith(INDEX_MAGIC))

    def test_roundtrip_preserves_fields(self):
        decoded = decode_json_search_index(self.blob)
        self.assertEqual(decoded, self.bundle.index)
        self.assertTrue(verify_json_search_index(decoded))

    def test_reencode_is_byte_identical(self):
        decoded = decode_json_search_index(self.blob)
        self.assertEqual(encode_json_search_index(decoded), self.blob)

    def test_input_must_be_bytes(self):
        for bad in ("x", bytearray(self.blob), memoryview(self.blob), 1, None):
            with self.assertRaises(TypeError):
                decode_json_search_index(bad)

    def test_bad_magic_raises_value_error(self):
        raw = bytearray(self.blob)
        raw[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decode_json_search_index(bytes(raw))

    def test_non_index_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_json_search_index("not-an-index")

    def test_trailing_and_truncated_bytes_rejected(self):
        with self.assertRaises(ValueError):
            decode_json_search_index(self.blob + b"\x00")
        for cut in (len(INDEX_MAGIC), len(self.blob) - 1, len(self.blob) - 64):
            with self.assertRaises(ValueError):
                decode_json_search_index(self.blob[:cut])

    def test_root_pointer_and_empty_log_roundtrip(self):
        log = AuditLog()
        log.append(b"42")
        log.append(b'"hello"')
        bundle = log.signed_json_search_index("", SEED_A)
        blob = encode_json_search_index(bundle.index)
        decoded = decode_json_search_index(blob)
        self.assertEqual(encode_json_search_index(decoded), blob)
        self.assertEqual(decoded.find(42), (0,))
        self.assertEqual(decoded.find("hello"), (1,))

    def test_empty_log_roundtrip(self):
        bundle = AuditLog().signed_json_search_index("/a", SEED_A)
        blob = encode_json_search_index(bundle.index)
        decoded = decode_json_search_index(blob)
        self.assertEqual(blob, encode_json_search_index(decoded))
        self.assertEqual(decoded.size, 0)
        self.assertEqual(decoded.groups, ())


class SignedJsonSearchIndexCodecTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()
        self.blob = encode_signed_json_search_index(self.bundle)

    def test_magic_prefix(self):
        self.assertTrue(self.blob.startswith(SIGNED_MAGIC))

    def test_roundtrip_preserves_bundle(self):
        decoded = decode_signed_json_search_index(self.blob)
        self.assertEqual(decoded, self.bundle)
        self.assertTrue(
            verify_signed_json_search_index(decoded, public_key(SEED_A))
        )

    def test_reencode_is_byte_identical(self):
        decoded = decode_signed_json_search_index(self.blob)
        self.assertEqual(encode_signed_json_search_index(decoded), self.blob)

    def test_input_must_be_bytes(self):
        for bad in ("x", bytearray(self.blob), memoryview(self.blob), 1, None):
            with self.assertRaises(TypeError):
                decode_signed_json_search_index(bad)

    def test_bad_magic_raises_value_error(self):
        raw = bytearray(self.blob)
        raw[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decode_signed_json_search_index(bytes(raw))

    def test_non_bundle_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_signed_json_search_index("not-a-bundle")

    def test_trailing_and_truncated_bytes_rejected(self):
        with self.assertRaises(ValueError):
            decode_signed_json_search_index(self.blob + b"\x00")
        for cut in (
            len(SIGNED_MAGIC),
            len(self.blob) - 1,
            len(self.blob) - 32,
        ):
            with self.assertRaises(ValueError):
                decode_signed_json_search_index(self.blob[:cut])

    def test_unsigned_signature_still_decodes_but_fails_verification(self):
        # Swap in a signature from another key; the encoding stays sound.
        other_signed = make_log().signed_json_search_index("/a", SEED_B)
        repackaged = SignedJsonSearchIndex(
            self.bundle.index, other_signed.signature
        )
        blob = encode_signed_json_search_index(repackaged)
        decoded = decode_signed_json_search_index(blob)
        self.assertEqual(encode_signed_json_search_index(decoded), blob)
        self.assertFalse(
            verify_signed_json_search_index(decoded, public_key(SEED_A))
        )

    def test_pruned_index_roundtrip(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_search_index("/a", SEED_A)
        blob = encode_signed_json_search_index(bundle)
        decoded = decode_signed_json_search_index(blob)
        self.assertEqual(encode_signed_json_search_index(decoded), blob)
        self.assertEqual(decoded.index.retain_from, 3)
        self.assertTrue(
            verify_signed_json_search_index(decoded, public_key(SEED_A))
        )


if __name__ == "__main__":
    unittest.main()
