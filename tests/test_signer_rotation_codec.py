import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedRoot,
    decode_rotation,
    decode_signed_root,
    encode_rotation,
    encode_signed_root,
    verify_rotation,
)

MAGIC = b"auditchain/signer-rotation-record/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _split_envelope(data):
    """Split an envelope into (version, old_blob, key_blob, new_blob, auth_blob)."""
    assert data.startswith(MAGIC)
    offset = len(MAGIC)
    version = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8

    def take():
        nonlocal offset
        length = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        part = data[offset:offset + length]
        offset += length
        return part

    old_blob = take()
    key_blob = take()
    new_blob = take()
    auth_blob = take()
    assert offset == len(data)
    return version, old_blob, key_blob, new_blob, auth_blob


class EncodeRotationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.old_public = _public_key(_SEED_A)
        self.new_public = _public_key(_SEED_B)
        self.item = self.log.rotate_signer(_SEED_A, _SEED_B)

    def test_magic_and_field_layout(self):
        old, new_key, new, auth = self.item
        data = encode_rotation(self.item)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # O blob: u64 length then the complete encode_signed_root(old) bytes.
        old_bytes = encode_signed_root(old)
        self.assertEqual(data[offset:offset + 8], u64(len(old_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(old_bytes)], old_bytes)
        offset += len(old_bytes)
        # K blob: raw new_key.
        self.assertEqual(data[offset:offset + 8], u64(32))
        offset += 8
        self.assertEqual(data[offset:offset + 32], new_key)
        offset += 32
        # N blob: complete encode_signed_root(new) bytes.
        new_bytes = encode_signed_root(new)
        self.assertEqual(data[offset:offset + 8], u64(len(new_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(new_bytes)], new_bytes)
        offset += len(new_bytes)
        # A blob: raw auth.
        self.assertEqual(data[offset:offset + 8], u64(64))
        offset += 8
        self.assertEqual(data[offset:offset + 64], auth)
        offset += 64
        # Nothing follows the auth blob.
        self.assertEqual(offset, len(data))

    def test_expected_canonical_bytes(self):
        old, new_key, new, auth = self.item
        expected = (
            MAGIC
            + u64(1)
            + blob(encode_signed_root(old))
            + blob(new_key)
            + blob(encode_signed_root(new))
            + blob(auth)
        )
        self.assertEqual(encode_rotation(self.item), expected)

    def test_blobs_are_exact_existing_encodings(self):
        old, new_key, new, auth = self.item
        version, old_blob, key_blob, new_blob, auth_blob = _split_envelope(
            encode_rotation(self.item)
        )
        self.assertEqual(version, 1)
        self.assertEqual(old_blob, encode_signed_root(old))
        self.assertEqual(new_blob, encode_signed_root(new))
        self.assertEqual(key_blob, new_key)
        self.assertEqual(auth_blob, auth)
        # The checkpoint blobs are independently decodable by the codec.
        self.assertEqual(decode_signed_root(old_blob), old)
        self.assertEqual(decode_signed_root(new_blob), new)

    def test_encode_is_deterministic(self):
        self.assertEqual(
            encode_rotation(self.item), encode_rotation(self.item)
        )

    def test_no_new_signing_message(self):
        # The checkpoints and signatures ride along verbatim; encoding
        # introduces no signature of its own.
        old, new_key, new, auth = self.item
        _, old_blob, _, new_blob, auth_blob = _split_envelope(
            encode_rotation(self.item)
        )
        self.assertEqual(old_blob, encode_signed_root(self.log.sign_root(_SEED_A)))
        self.assertEqual(new_blob, encode_signed_root(self.log.sign_root(_SEED_B)))
        self.assertEqual(auth_blob, auth)
        self.assertEqual(auth_blob, self.item[3])

    def test_empty_prefix_layout(self):
        item = AuditLog().rotate_signer(_SEED_A, _SEED_B, 0)
        version, old_blob, key_blob, new_blob, auth_blob = _split_envelope(
            encode_rotation(item)
        )
        self.assertEqual(version, 1)
        self.assertEqual(old_blob, encode_signed_root(item[0]))
        self.assertEqual(key_blob, item[1])
        self.assertEqual(new_blob, encode_signed_root(item[2]))
        self.assertEqual(auth_blob, item[3])

    def test_alternate_hash_layout(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        item = log.rotate_signer(_SEED_A, _SEED_B)
        _, old_blob, _, new_blob, _ = _split_envelope(encode_rotation(item))
        self.assertEqual(old_blob, encode_signed_root(item[0]))
        self.assertEqual(new_blob, encode_signed_root(item[2]))

    def test_returns_bytes(self):
        self.assertIsInstance(encode_rotation(self.item), bytes)

    def test_only_tuple_accepted(self):
        old, new_key, new, auth = self.item
        for bad in (
            None,
            1,
            "item",
            b"bytes",
            [old, new_key, new, auth],
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                encode_rotation(bad)

    def test_tuple_length_validation(self):
        old, new_key, new, auth = self.item
        for bad in (
            (),
            (old,),
            (old, new_key),
            (old, new_key, new),
            (old, new_key, new, auth, b"extra"),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_rotation(bad)

    def test_element_type_validation(self):
        old, new_key, new, auth = self.item
        with self.assertRaises(TypeError):
            encode_rotation(("old", new_key, new, auth))
        with self.assertRaises(TypeError):
            encode_rotation((old, new_key, "new", auth))
        with self.assertRaises(TypeError):
            encode_rotation((old, bytearray(new_key), new, auth))
        with self.assertRaises(TypeError):
            encode_rotation((old, new_key, new, bytearray(auth)))

    def test_width_validation(self):
        old, new_key, new, auth = self.item
        with self.assertRaises(ValueError):
            encode_rotation((old, new_key[:-1], new, auth))
        with self.assertRaises(ValueError):
            encode_rotation((old, new_key + b"\x00", new, auth))
        with self.assertRaises(ValueError):
            encode_rotation((old, new_key, new, auth[:-1]))
        with self.assertRaises(ValueError):
            encode_rotation((old, new_key, new, auth + b"\x00"))

    def test_nested_checkpoint_value_error_propagates(self):
        old, new_key, new, auth = self.item
        corrupt = SignedRoot.__new__(SignedRoot)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "head",
            "signature",
        ):
            object.__setattr__(corrupt, name, getattr(new, name))
        object.__setattr__(corrupt, "version", 2)
        with self.assertRaises(ValueError):
            encode_rotation((old, new_key, corrupt, auth))

    def test_bypassed_checkpoint_type_error_propagates(self):
        old, new_key, new, auth = self.item
        corrupt = SignedRoot.__new__(SignedRoot)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "head",
            "signature",
        ):
            object.__setattr__(corrupt, name, getattr(new, name))
        object.__setattr__(corrupt, "hash_name", 123)
        with self.assertRaises(TypeError):
            encode_rotation((old, new_key, corrupt, auth))

    def test_call_is_read_only(self):
        before = encode_rotation(self.item)
        encode_rotation(self.item)
        self.assertEqual(encode_rotation(self.item), before)
        self.assertEqual(
            self.item,
            tuple(self.item),
        )
        self.assertTrue(verify_rotation(self.item, self.old_public))


class DecodeRotationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.old_public = _public_key(_SEED_A)
        self.new_public = _public_key(_SEED_B)

    def roundtrip(self, item):
        data = encode_rotation(item)
        decoded = decode_rotation(data)
        self.assertIsInstance(decoded, tuple)
        self.assertEqual(len(decoded), 4)
        old, new_key, new, auth = decoded
        self.assertIsInstance(old, SignedRoot)
        self.assertIsInstance(new, SignedRoot)
        self.assertIsInstance(new_key, bytes)
        self.assertIsInstance(auth, bytes)
        self.assertEqual(decoded, item)
        # Field-by-field equality.
        self.assertEqual(old, item[0])
        self.assertEqual(new_key, item[1])
        self.assertEqual(new, item[2])
        self.assertEqual(auth, item[3])
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(encode_rotation(decoded), data)
        self.assertTrue(verify_rotation(decoded, self.old_public))
        return decoded

    def test_roundtrip_variants(self):
        for size in (0, 1, 3, 5, 7):
            self.roundtrip(self.log.rotate_signer(_SEED_A, _SEED_B, size))

    def test_roundtrip_default_size(self):
        self.roundtrip(self.log.rotate_signer(_SEED_A, _SEED_B))

    def test_roundtrip_empty_log(self):
        self.roundtrip(AuditLog().rotate_signer(_SEED_A, _SEED_B))

    def test_roundtrip_same_seed(self):
        self.roundtrip(self.log.rotate_signer(_SEED_A, _SEED_A))

    def test_roundtrip_alternate_hashes(self):
        for hash_name in ("sha3-256", "sha512", "blake2b"):
            log = AuditLog(hash_name=hash_name)
            for record in ("a", "b", "c"):
                log.append(record)
            self.roundtrip(log.rotate_signer(_SEED_A, _SEED_B, 0))
            self.roundtrip(log.rotate_signer(_SEED_A, _SEED_B))

    def test_persistence_across_process_boundary(self):
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 5)
        data = encode_rotation(item)
        # Fresh bytes, as read from disk or a socket; a process that never saw
        # the rotation recovers the tuple and verifies it purely offline.
        restored = decode_rotation(bytes(data))
        self.assertEqual(restored, item)
        self.assertTrue(verify_rotation(restored, self.old_public))

    def test_only_bytes_accepted(self):
        data = encode_rotation(self.log.rotate_signer(_SEED_A, _SEED_B, 3))
        for bad in (
            bytearray(data),
            memoryview(data),
            "text",
            None,
            1,
            (),
            [],
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_rotation(bad)

    def test_bad_magic(self):
        data = encode_rotation(self.log.rotate_signer(_SEED_A, _SEED_B, 3))
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/signer-rotation/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-root/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:40])):
                decode_rotation(bad)

    def test_bad_version(self):
        data = encode_rotation(self.log.rotate_signer(_SEED_A, _SEED_B, 3))
        payload = data[len(MAGIC) + 8:]
        for version in (0, 2, 255, (1 << 64) - 1):
            with self.assertRaises(ValueError, msg=version):
                decode_rotation(MAGIC + u64(version) + payload)

    def test_truncation(self):
        data = encode_rotation(self.log.rotate_signer(_SEED_A, _SEED_B, 3))
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_rotation(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_rotation(data[:cut])

    def test_trailing_bytes(self):
        data = encode_rotation(self.log.rotate_signer(_SEED_A, _SEED_B, 3))
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_rotation(data + extra)

    def test_oversized_blob_length(self):
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 3)
        old, new_key, new, auth = item
        old_b = blob(encode_signed_root(old))
        new_b = blob(encode_signed_root(new))
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + old_b + u64(1 << 63),
            MAGIC + u64(1) + old_b + blob(new_key) + u64(1 << 63),
            MAGIC
            + u64(1)
            + old_b
            + blob(new_key)
            + new_b
            + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_rotation(bad)

    def test_missing_blobs(self):
        version, old_b, key_b, new_b, _auth_b = _split_envelope(
            encode_rotation(self.log.rotate_signer(_SEED_A, _SEED_B, 3))
        )
        # Stop after each prefix of the four blobs.
        self.assertEqual(version, 1)
        with self.assertRaises(ValueError):
            decode_rotation(MAGIC + u64(1) + blob(old_b))
        with self.assertRaises(ValueError):
            decode_rotation(MAGIC + u64(1) + blob(old_b) + blob(key_b))
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC + u64(1) + blob(old_b) + blob(key_b) + blob(new_b)
            )

    def test_swapped_blob_order_rejected(self):
        # Swapping O and K puts raw 32-byte key material in the old-checkpoint
        # slot: decode_signed_root rejects its framing.
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 5)
        _, old_b, key_b, new_b, auth_b = _split_envelope(
            encode_rotation(item)
        )
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC
                + u64(1)
                + blob(key_b)
                + blob(old_b)
                + blob(new_b)
                + blob(auth_b)
            )
        # Swapping K and A violates the fixed 32- and 64-byte slot widths.
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC
                + u64(1)
                + blob(old_b)
                + blob(auth_b)
                + blob(new_b)
                + blob(key_b)
            )

    def test_garbage_checkpoint_blob_rejected(self):
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 3)
        _, old_b, key_b, new_b, auth_b = _split_envelope(encode_rotation(item))
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC
                + u64(1)
                + blob(b"hello")
                + blob(key_b)
                + blob(new_b)
                + blob(auth_b)
            )
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC
                + u64(1)
                + blob(old_b)
                + blob(key_b)
                + blob(b"hello")
                + blob(auth_b)
            )

    def test_nested_checkpoint_framing_error_rejected(self):
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 3)
        _, old_b, key_b, new_b, auth_b = _split_envelope(encode_rotation(item))
        tampered = b"x" + new_b[1:]
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC
                + u64(1)
                + blob(old_b)
                + blob(key_b)
                + blob(tampered)
                + blob(auth_b)
            )

    def test_bad_new_key_width_rejected(self):
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 3)
        old, _, new, auth = item
        old_b = blob(encode_signed_root(old))
        new_b = blob(encode_signed_root(new))
        for bad_key in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad_key)):
                decode_rotation(
                    MAGIC
                    + u64(1)
                    + old_b
                    + blob(bad_key)
                    + new_b
                    + blob(auth)
                )

    def test_bad_auth_width_rejected(self):
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 3)
        old, new_key, new, _ = item
        old_b = blob(encode_signed_root(old))
        new_b = blob(encode_signed_root(new))
        for bad_auth in (b"", b"\x00" * 63, b"\x00" * 65):
            with self.assertRaises(ValueError, msg=len(bad_auth)):
                decode_rotation(
                    MAGIC
                    + u64(1)
                    + old_b
                    + blob(new_key)
                    + new_b
                    + blob(bad_auth)
                )

    def test_wrong_key_still_decodes_but_verifies_false(self):
        item = self.log.rotate_signer(_SEED_B, _SEED_C)
        decoded = decode_rotation(encode_rotation(item))
        self.assertEqual(decoded, item)
        self.assertFalse(verify_rotation(decoded, self.old_public))
        self.assertTrue(verify_rotation(decoded, _public_key(_SEED_B)))

    def test_forged_signatures_still_decode_but_verify_false(self):
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 3)
        old, new_key, new, _ = item
        forged = (old, new_key, replace(new, signature=b"\x00" * 64), b"\x00" * 64)
        decoded = decode_rotation(encode_rotation(forged))
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_rotation(decoded, self.old_public))

    def test_disagreeing_checkpoints_still_decode_but_verify_false(self):
        # Codec checks framing only: two genuine checkpoints over different
        # prefixes decode fine; same-snapshot linkage is left to verification.
        old = self.log.sign_root(_SEED_A, 2)
        new = self.log.sign_root(_SEED_B, 5)
        new_key = _public_key(_SEED_B)
        forged = (old, new_key, new, b"\x00" * 64)
        decoded = decode_rotation(encode_rotation(forged))
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_rotation(decoded, self.old_public))

    def test_call_is_read_only(self):
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 4)
        data = encode_rotation(item)
        self.assertEqual(decode_rotation(data), item)
        self.assertEqual(decode_rotation(data), item)


if __name__ == "__main__":
    unittest.main()
