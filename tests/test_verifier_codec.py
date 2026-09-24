import unittest

from auditchain import (
    AuditLog,
    Verifier,
    decode_verifier,
    encode_verifier,
    verify_auth,
    verify_auth_batch,
)

MAGIC = b"auditchain/verifier/v1\0"

_KEY = b"super-secret-stage0-key"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _material(key=_KEY, hash_name="sha256", records=("a", "b", "c")):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in records:
        log.append(record)
    return log.export_verifier()


class EncodeVerifierTest(unittest.TestCase):
    def test_magic_and_field_layout(self):
        material = _material()
        data = encode_verifier(material)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(len(material.key)))
        offset += 8
        self.assertEqual(data[offset:offset + len(material.key)], material.key)
        offset += len(material.key)
        self.assertEqual(offset, len(data))

    def test_layout_matches_blob_framing(self):
        material = _material(key=b"k", hash_name="sha3_256")
        expected = (
            MAGIC
            + u64(1)
            + blob(material.hash_name.encode("utf-8"))
            + blob(material.key)
        )
        self.assertEqual(encode_verifier(material), expected)

    def test_any_non_empty_key_width(self):
        for key in (b"k", b"x" * 100, bytes(32)):
            material = Verifier(key, "sha256")
            data = encode_verifier(material)
            self.assertEqual(decode_verifier(data), material)

    def test_encode_is_deterministic(self):
        material = _material()
        self.assertEqual(encode_verifier(material), encode_verifier(material))

    def test_type_errors(self):
        for bad in (None, "material", b"bytes", 1, (b"k", "sha256"), object()):
            with self.assertRaises(TypeError):
                encode_verifier(bad)

    def test_bypassed_wrong_field_types_raise_type_error(self):
        material = _material()
        for field, value in (
            ("key", bytearray(material.key)),
            ("key", "text"),
            ("hash_name", 1),
            ("hash_name", b"sha256"),
        ):
            forged = Verifier.__new__(Verifier)
            for name in ("key", "hash_name"):
                object.__setattr__(forged, name, getattr(material, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_verifier(forged)

    def test_bypassed_bad_structure_raises_value_error(self):
        material = _material()
        for field, value in (
            ("key", b""),
            ("hash_name", "not-a-hash"),
            ("hash_name", "shake_128"),
        ):
            forged = Verifier.__new__(Verifier)
            for name in ("key", "hash_name"):
                object.__setattr__(forged, name, getattr(material, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(ValueError, msg=field):
                encode_verifier(forged)

    def test_call_is_read_only(self):
        material = _material()
        before = encode_verifier(material)
        encode_verifier(material)
        self.assertEqual(encode_verifier(material), before)


class DecodeVerifierTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=_KEY)
        for record in ("a", "b", "c", "d"):
            self.log.append(record)
        self.material = self.log.export_verifier()
        self.tag0 = self.log.auth(0)
        self.tag1 = self.log.auth(1)

    def roundtrip(self, material):
        data = encode_verifier(material)
        decoded = decode_verifier(data)
        self.assertEqual(decoded, material)
        self.assertEqual(decoded.key, material.key)
        self.assertEqual(decoded.hash_name, material.hash_name)
        self.assertIsInstance(decoded.key, bytes)
        self.assertIsInstance(decoded.hash_name, str)
        with self.assertRaises(Exception):
            decoded.key = material.key + b"x"
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_verifier(decoded), data)
        return decoded

    def test_roundtrip(self):
        self.roundtrip(self.material)

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256", "sha3_224"):
            self.roundtrip(_material(hash_name=hash_name))

    def test_persistence_across_process_boundary(self):
        data = encode_verifier(self.material)
        restored = decode_verifier(bytes(data))
        self.assertEqual(restored, self.material)
        # The restored material reaches the same verdicts on the same tags.
        for entry, tag in (
            (self.log.entry(0), self.tag0),
            (self.log.entry(1), self.tag1),
        ):
            self.assertEqual(
                verify_auth(entry, tag, restored),
                verify_auth(entry, tag, self.material),
            )
            self.assertTrue(verify_auth(entry, tag, restored))
        items = (
            (self.log.entry(0), self.tag0),
            (self.log.entry(1), self.tag1),
        )
        self.assertEqual(
            verify_auth_batch(items, restored),
            verify_auth_batch(items, self.material),
        )
        self.assertEqual(verify_auth_batch(items, restored), (True, True))

    def test_tampered_material_still_codecs(self):
        # A structurally valid material whose key or algorithm was altered
        # encodes and decodes fine; verification just reaches a different
        # verdict instead of raising.
        for tampered in (
            Verifier(b"other-key", self.material.hash_name),
            Verifier(self.material.key, "sha3_256"),
        ):
            restored = decode_verifier(encode_verifier(tampered))
            self.assertEqual(restored, tampered)
            self.assertFalse(
                verify_auth(self.log.entry(0), self.tag0, restored)
            )

    def test_only_bytes_accepted(self):
        data = encode_verifier(self.material)
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_verifier(bad)

    def test_bad_magic(self):
        data = encode_verifier(self.material)
        with self.assertRaises(ValueError):
            decode_verifier(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_verifier(b"")
        with self.assertRaises(ValueError):
            decode_verifier(MAGIC[:-1])
        with self.assertRaises(ValueError):
            decode_verifier(
                b"auditchain/stage-verifier/v1\0" + data[len(MAGIC):]
            )

    def test_bad_version(self):
        data = MAGIC + u64(2) + encode_verifier(self.material)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_verifier(data)

    def test_unknown_hash_algorithm(self):
        data = MAGIC + u64(1) + blob(b"not-a-hash") + blob(bytes(32))
        with self.assertRaises(ValueError):
            decode_verifier(data)

    def test_variable_length_hash_algorithm_rejected(self):
        data = MAGIC + u64(1) + blob(b"shake_128") + blob(b"x" * 32)
        with self.assertRaises(ValueError):
            decode_verifier(data)

    def test_invalid_utf8_hash_name(self):
        data = MAGIC + u64(1) + blob(b"\xff\xfe") + blob(bytes(32))
        with self.assertRaises(ValueError):
            decode_verifier(data)

    def test_truncation(self):
        data = encode_verifier(self.material)
        for cut in (
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError):
                decode_verifier(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_verifier(data[:cut])

    def test_trailing_bytes(self):
        data = encode_verifier(self.material)
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_verifier(data + extra)

    def test_oversized_blob_length(self):
        data = (
            MAGIC
            + u64(1)
            + u64(1 << 63)
            + b"sha256"
        )
        with self.assertRaises(ValueError):
            decode_verifier(data)

    def test_empty_key_rejected(self):
        data = MAGIC + u64(1) + blob(b"sha256") + blob(b"")
        with self.assertRaises(ValueError):
            decode_verifier(data)

    def test_call_is_read_only(self):
        data = encode_verifier(self.material)
        decode_verifier(data)
        self.assertEqual(decode_verifier(data), self.material)


if __name__ == "__main__":
    unittest.main()
