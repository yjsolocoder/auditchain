import unittest

from auditchain import (
    AuditLog,
    StageVerifier,
    decode_stage_verifier,
    encode_stage_verifier,
    verify_auth_stage,
)

MAGIC = b"auditchain/stage-verifier/v1\0"

_KEY = b"super-secret-stage-key"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _material(key=_KEY, hash_name="sha256", records=("a", "b", "c"),
              evolve=1):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in records:
        log.append(record)
    for index in range(evolve):
        log.auth(index)
    return log.export_stage_verifier()


class EncodeStageVerifierTest(unittest.TestCase):
    def test_magic_and_field_layout(self):
        material = _material()
        data = encode_stage_verifier(material)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(1))  # stage
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
        material = _material(key=b"k", hash_name="sha3_256", evolve=2)
        expected = (
            MAGIC
            + u64(1)
            + u64(material.stage)
            + blob(material.hash_name.encode("utf-8"))
            + blob(material.key)
        )
        self.assertEqual(encode_stage_verifier(material), expected)

    def test_stage_zero_any_length_key(self):
        material = StageVerifier(0, b"k", "sha256")
        data = encode_stage_verifier(material)
        self.assertEqual(decode_stage_verifier(data), material)
        material = StageVerifier(0, b"x" * 100, "sha512")
        data = encode_stage_verifier(material)
        self.assertEqual(decode_stage_verifier(data), material)

    def test_max_stage_roundtrips(self):
        material = StageVerifier((1 << 64) - 1, bytes(28), "sha3_224")
        data = encode_stage_verifier(material)
        self.assertEqual(decode_stage_verifier(data), material)

    def test_encode_is_deterministic(self):
        material = _material()
        self.assertEqual(
            encode_stage_verifier(material), encode_stage_verifier(material)
        )

    def test_type_errors(self):
        for bad in (None, "material", b"bytes", 1, (1, b"k", "sha256"), object()):
            with self.assertRaises(TypeError):
                encode_stage_verifier(bad)

    def test_bypassed_wrong_field_types_raise_type_error(self):
        material = _material()
        for field, value in (
            ("stage", "1"),
            ("key", bytearray(material.key)),
            ("hash_name", 1),
        ):
            forged = StageVerifier.__new__(StageVerifier)
            for name in ("stage", "key", "hash_name"):
                object.__setattr__(forged, name, getattr(material, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_stage_verifier(forged)

    def test_bypassed_bad_structure_raises_value_error(self):
        material = _material()
        for field, value in (
            ("stage", -1),
            ("stage", 1 << 64),
            ("key", b""),
            ("key", b"short"),
            ("hash_name", "not-a-hash"),
        ):
            forged = StageVerifier.__new__(StageVerifier)
            for name in ("stage", "key", "hash_name"):
                object.__setattr__(forged, name, getattr(material, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(ValueError, msg=field):
                encode_stage_verifier(forged)

    def test_call_is_read_only(self):
        material = _material()
        before = encode_stage_verifier(material)
        encode_stage_verifier(material)
        self.assertEqual(encode_stage_verifier(material), before)


class DecodeStageVerifierTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=_KEY)
        for record in ("a", "b", "c", "d"):
            self.log.append(record)
        self.tag0 = self.log.auth(0)
        self.material = self.log.export_stage_verifier()

    def roundtrip(self, material):
        data = encode_stage_verifier(material)
        decoded = decode_stage_verifier(data)
        self.assertEqual(decoded, material)
        self.assertEqual(decoded.stage, material.stage)
        self.assertEqual(decoded.key, material.key)
        self.assertEqual(decoded.hash_name, material.hash_name)
        self.assertIsInstance(decoded.key, bytes)
        self.assertIsInstance(decoded.hash_name, str)
        with self.assertRaises(Exception):
            decoded.stage = material.stage + 1
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_stage_verifier(decoded), data)
        return decoded

    def test_roundtrip(self):
        self.roundtrip(self.material)

    def test_roundtrip_later_stages(self):
        self.log.auth(1)
        self.roundtrip(self.log.export_stage_verifier())
        self.log.auth(2)
        self.roundtrip(self.log.export_stage_verifier())

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256", "sha3_224"):
            self.roundtrip(_material(hash_name=hash_name))

    def test_roundtrip_stage_zero(self):
        self.roundtrip(StageVerifier(0, b"arbitrary-length", "sha256"))
        self.roundtrip(StageVerifier(0, b"x", "sha3_256"))

    def test_persistence_across_process_boundary(self):
        data = encode_stage_verifier(self.material)
        restored = decode_stage_verifier(bytes(data))
        self.assertEqual(restored, self.material)
        # The restored material reaches the same verdict on the same tag.
        tag1 = self.log.auth(1)
        self.assertEqual(
            verify_auth_stage(self.log.entry(0), self.tag0, restored),
            verify_auth_stage(self.log.entry(0), self.tag0, self.material),
        )
        self.assertEqual(
            verify_auth_stage(self.log.entry(1), tag1, restored),
            verify_auth_stage(self.log.entry(1), tag1, self.material),
        )
        self.assertTrue(verify_auth_stage(self.log.entry(1), tag1, restored))

    def test_only_bytes_accepted(self):
        data = encode_stage_verifier(self.material)
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_stage_verifier(bad)

    def test_bad_magic(self):
        data = encode_stage_verifier(self.material)
        with self.assertRaises(ValueError):
            decode_stage_verifier(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_stage_verifier(b"")
        with self.assertRaises(ValueError):
            decode_stage_verifier(MAGIC[:-1])
        with self.assertRaises(ValueError):
            decode_stage_verifier(
                b"auditchain/signed-stage/v1\0" + data[len(MAGIC):]
            )

    def test_bad_version(self):
        data = MAGIC + u64(2) + encode_stage_verifier(self.material)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_unknown_hash_algorithm(self):
        data = MAGIC + u64(1) + u64(1) + blob(b"not-a-hash") + blob(bytes(32))
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_variable_length_hash_algorithm_rejected(self):
        data = MAGIC + u64(1) + u64(1) + blob(b"shake_128") + blob(b"x" * 32)
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_invalid_utf8_hash_name(self):
        data = MAGIC + u64(1) + u64(1) + blob(b"\xff\xfe") + blob(bytes(32))
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_truncation(self):
        data = encode_stage_verifier(self.material)
        for cut in (
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError):
                decode_stage_verifier(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_stage_verifier(data[:cut])

    def test_trailing_bytes(self):
        data = encode_stage_verifier(self.material)
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_stage_verifier(data + extra)

    def test_oversized_blob_length(self):
        data = (
            MAGIC
            + u64(1)
            + u64(1)
            + u64(1 << 63)
            + b"sha256"
        )
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_max_stage_decodes(self):
        # A wire u64 cannot reach 2**64; the maximum value 2**64 - 1 decodes
        # when the key matches the digest width.
        data = (
            MAGIC
            + u64(1)
            + b"\xff" * 8
            + blob(b"sha256")
            + blob(bytes(32))
        )
        decoded = decode_stage_verifier(data)
        self.assertEqual(decoded.stage, (1 << 64) - 1)
        self.assertEqual(encode_stage_verifier(decoded), data)

    def test_empty_key_rejected(self):
        data = MAGIC + u64(1) + u64(1) + blob(b"sha256") + blob(b"")
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)
        # An empty key is invalid even at stage 0.
        data = MAGIC + u64(1) + u64(0) + blob(b"sha256") + blob(b"")
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_positive_stage_key_width_checked(self):
        base = MAGIC + u64(1) + u64(1)
        with self.assertRaises(ValueError):
            decode_stage_verifier(base + blob(b"sha256") + blob(b"k"))
        with self.assertRaises(ValueError):
            decode_stage_verifier(base + blob(b"sha256") + blob(bytes(33)))
        # sha3-224 needs a 28-byte key at a positive stage.
        base = MAGIC + u64(1) + u64(4) + blob(b"sha3_224")
        with self.assertRaises(ValueError):
            decode_stage_verifier(base + blob(bytes(32)))
        self.assertEqual(
            decode_stage_verifier(base + blob(bytes(28))).key, bytes(28)
        )

    def test_call_is_read_only(self):
        data = encode_stage_verifier(self.material)
        decode_stage_verifier(data)
        self.assertEqual(decode_stage_verifier(data), self.material)


if __name__ == "__main__":
    unittest.main()
