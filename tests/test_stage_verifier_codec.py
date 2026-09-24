import unittest
from dataclasses import FrozenInstanceError

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


def delivered_material(stage, hash_name="sha256"):
    """A log evolved to ``stage``, its exported material and a stage-``stage`` tag."""
    log = AuditLog(key=_KEY, hash_name=hash_name)
    for record in ("a", "b", "c"):
        log.append(record)
    for index in range(stage):
        log.auth(index % 3)
    material = log.export_stage_verifier()
    tag = log.auth(1)  # minted at the delivery stage, before the next evolution
    return log, material, tag


class EncodeStageVerifierTest(unittest.TestCase):
    def test_magic_and_field_layout(self):
        _, material, _ = delivered_material(3)
        data = encode_stage_verifier(material)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(3))  # stage
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(32))  # key length
        offset += 8
        self.assertEqual(data[offset:offset + 32], material.key)
        offset += 32
        self.assertEqual(offset, len(data))

    def test_encode_is_deterministic(self):
        _, material, _ = delivered_material(2)
        self.assertEqual(
            encode_stage_verifier(material), encode_stage_verifier(material)
        )

    def test_type_errors(self):
        for bad in (None, "material", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                encode_stage_verifier(bad)

    def test_bypassed_wrong_field_types_raise_type_error(self):
        _, material, _ = delivered_material(1)
        for field, value in (
            ("stage", "1"),
            ("stage", True),
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
        _, material, _ = delivered_material(1)
        for field, value in (
            ("stage", -1),
            ("stage", 1 << 64),
            ("key", b""),
            ("key", b"\x00" * 31),  # positive stage requires digest width
            ("hash_name", "not-a-hash"),
        ):
            forged = StageVerifier.__new__(StageVerifier)
            for name in ("stage", "key", "hash_name"):
                object.__setattr__(forged, name, getattr(material, name))
            object.__setattr__(forged, field, value)
            with self.assertRaises(ValueError, msg=f"{field}={value!r}"):
                encode_stage_verifier(forged)

    def test_call_is_read_only(self):
        log, material, tag = delivered_material(1)
        before = encode_stage_verifier(material)
        encode_stage_verifier(material)
        self.assertEqual(encode_stage_verifier(material), before)
        self.assertTrue(verify_auth_stage(log.entry(1), tag, material))


class DecodeStageVerifierTest(unittest.TestCase):
    def roundtrip(self, material):
        data = encode_stage_verifier(material)
        decoded = decode_stage_verifier(data)
        self.assertEqual(decoded, material)
        self.assertIsNot(decoded, material)
        self.assertEqual(decoded.stage, material.stage)
        self.assertEqual(decoded.key, material.key)
        self.assertEqual(decoded.hash_name, material.hash_name)
        self.assertIsInstance(decoded.key, bytes)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_stage_verifier(decoded), data)
        return decoded

    def test_roundtrip_variants(self):
        for stage in (1, 2, 5):
            _, material, _ = delivered_material(stage)
            self.roundtrip(material)

    def test_roundtrip_stage_zero_construction_key(self):
        # At stage 0 the construction key may have any non-empty length.
        for key in (b"k", _KEY, b"x" * 100):
            self.roundtrip(StageVerifier(0, key, "sha256"))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            _, material, _ = delivered_material(2, hash_name)
            self.roundtrip(material)

    def test_roundtrip_max_stage(self):
        self.roundtrip(StageVerifier((1 << 64) - 1, bytes(32), "sha256"))

    def test_decoded_is_frozen(self):
        _, material, _ = delivered_material(1)
        decoded = self.roundtrip(material)
        with self.assertRaises(FrozenInstanceError):
            decoded.stage = 9

    def test_persistence_across_process_boundary(self):
        log = AuditLog(key=_KEY)
        for record in ("a", "b", "c"):
            log.append(record)
        early = log.auth(0)  # minted at stage 0
        log.auth(1)  # evolve to stage 2
        material = log.export_stage_verifier()  # delivered at stage 2
        tag = log.auth(1)  # minted at the delivery stage
        data = encode_stage_verifier(material)
        # A fresh byte sequence (as read back from disk or a socket) decodes
        # into material that draws the same verify_auth_stage conclusions.
        restored = decode_stage_verifier(bytes(data))
        self.assertEqual(restored, material)
        self.assertTrue(verify_auth_stage(log.entry(1), tag, restored))
        self.assertFalse(verify_auth_stage(log.entry(0), early, restored))

    def test_only_bytes_accepted(self):
        _, material, _ = delivered_material(1)
        data = encode_stage_verifier(material)
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_stage_verifier(bad)

    def test_bad_magic(self):
        _, material, _ = delivered_material(1)
        data = encode_stage_verifier(material)
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
        _, material, _ = delivered_material(1)
        data = MAGIC + u64(2) + encode_stage_verifier(material)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_unknown_hash_algorithm(self):
        data = MAGIC + u64(1) + u64(0) + blob(b"not-a-hash") + blob(b"k")
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_invalid_utf8_hash_name(self):
        data = MAGIC + u64(1) + u64(0) + blob(b"\xff\xfe") + blob(b"k")
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_truncation(self):
        _, material, _ = delivered_material(1)
        data = encode_stage_verifier(material)
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_stage_verifier(data[:cut])

    def test_trailing_bytes(self):
        _, material, _ = delivered_material(1)
        data = encode_stage_verifier(material)
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_stage_verifier(data + extra)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(0) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_empty_key_rejected(self):
        data = MAGIC + u64(1) + u64(0) + blob(b"sha256") + blob(b"")
        with self.assertRaises(ValueError):
            decode_stage_verifier(data)

    def test_positive_stage_key_width_checked(self):
        # A short key is fine at stage 0 but not at a positive stage.
        good = MAGIC + u64(1) + u64(0) + blob(b"sha256") + blob(b"short")
        self.assertEqual(decode_stage_verifier(good).key, b"short")
        bad = MAGIC + u64(1) + u64(1) + blob(b"sha256") + blob(b"short")
        with self.assertRaises(ValueError):
            decode_stage_verifier(bad)
        bad = MAGIC + u64(1) + u64(1) + blob(b"sha256") + blob(b"\x00" * 33)
        with self.assertRaises(ValueError):
            decode_stage_verifier(bad)

    def test_call_is_read_only(self):
        _, material, _ = delivered_material(1)
        data = encode_stage_verifier(material)
        decode_stage_verifier(data)
        self.assertEqual(decode_stage_verifier(data), material)


if __name__ == "__main__":
    unittest.main()
