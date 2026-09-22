import unittest

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
    """Split an envelope into (version, O, K, N, A) blobs."""
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

    parts = [take() for _ in range(4)]
    assert offset == len(data)
    return (version, *parts)


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
        # O: u64 length then the complete encode_signed_root(old) bytes.
        old_bytes = encode_signed_root(old)
        self.assertEqual(data[offset:offset + 8], u64(len(old_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(old_bytes)], old_bytes)
        offset += len(old_bytes)
        # K: raw new_key.
        self.assertEqual(data[offset:offset + 8], u64(32))
        offset += 8
        self.assertEqual(data[offset:offset + 32], new_key)
        offset += 32
        # N: complete encode_signed_root(new) bytes.
        new_bytes = encode_signed_root(new)
        self.assertEqual(data[offset:offset + 8], u64(len(new_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(new_bytes)], new_bytes)
        offset += len(new_bytes)
        # A: raw 64-byte auth.
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
        _, old_blob, key_blob, new_blob, auth_blob = _split_envelope(
            encode_rotation(self.item)
        )
        # O/N are byte-for-byte encode_signed_root output; K/A are raw bytes.
        self.assertEqual(old_blob, encode_signed_root(old))
        self.assertEqual(key_blob, new_key)
        self.assertEqual(new_blob, encode_signed_root(new))
        self.assertEqual(auth_blob, auth)
        # The checkpoint blobs are independently decodable by the existing codec.
        self.assertEqual(decode_signed_root(old_blob), old)
        self.assertEqual(decode_signed_root(new_blob), new)

    def test_encode_is_deterministic(self):
        data = encode_rotation(self.item)
        self.assertEqual(data, encode_rotation(self.item))

    def test_no_new_signing_message(self):
        # The checkpoints and auth ride along verbatim; the envelope introduces
        # no signature of its own.
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 4)
        old, new_key, new, auth = item
        _, old_blob, _, new_blob, auth_blob = _split_envelope(
            encode_rotation(item)
        )
        self.assertEqual(old_blob, encode_signed_root(self.log.sign_root(_SEED_A, 4)))
        self.assertEqual(new_blob, encode_signed_root(self.log.sign_root(_SEED_B, 4)))
        self.assertEqual(auth_blob, auth)
        self.assertEqual(decode_signed_root(old_blob), old)
        self.assertEqual(decode_signed_root(new_blob), new)

    def test_empty_prefix_layout(self):
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 0)
        _, old_blob, key_blob, new_blob, auth_blob = _split_envelope(
            encode_rotation(item)
        )
        old, new_key, new, auth = item
        self.assertEqual(old_blob, encode_signed_root(self.log.sign_root(_SEED_A, 0)))
        self.assertEqual(new_blob, encode_signed_root(self.log.sign_root(_SEED_B, 0)))
        self.assertEqual(key_blob, new_key)
        self.assertEqual(auth_blob, auth)

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        item = log.rotate_signer(_SEED_A, _SEED_B)
        _, old_blob, _, new_blob, _ = _split_envelope(encode_rotation(item))
        self.assertEqual(old_blob, encode_signed_root(item[0]))
        self.assertEqual(new_blob, encode_signed_root(item[2]))

    def test_only_tuple_accepted(self):
        old, new_key, new, auth = self.item
        for bad in (
            None,
            1,
            "item",
            b"bytes",
            [],
            [old, new_key, new, auth],
            old,
            new,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_rotation(bad)

    def test_wrong_tuple_length_raises_value_error(self):
        old, new_key, new, auth = self.item
        for bad in (
            (),
            (old,),
            (old, new_key),
            (old, new_key, new),
            (old, new_key, new, auth, b"extra"),
        ):
            with self.assertRaises(ValueError, msg=len(bad)):
                encode_rotation(bad)

    def test_wrong_element_types_raise_type_error(self):
        old, new_key, new, auth = self.item
        for bad in (
            ("old", new_key, new, auth),
            (old, new_key, "new", auth),
            (old, bytearray(new_key), new, auth),
            (old, memoryview(new_key), new, auth),
            (old, new_key, new, bytearray(auth)),
            (old, new_key, new, memoryview(auth)),
            (None, new_key, new, auth),
            (old, new_key, None, auth),
            (old, None, new, auth),
            (old, new_key, new, None),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_rotation(bad)

    def test_field_widths(self):
        old, new_key, new, auth = self.item
        with self.assertRaises(ValueError):
            encode_rotation((old, new_key[:-1], new, auth))
        with self.assertRaises(ValueError):
            encode_rotation((old, new_key + b"\x00", new, auth))
        with self.assertRaises(ValueError):
            encode_rotation((old, new_key, new, auth[:-1]))
        with self.assertRaises(ValueError):
            encode_rotation((old, new_key, new, auth + b"\x00"))

    def test_nested_signed_root_type_error_propagates(self):
        old, new_key, new, auth = self.item
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(checkpoint, name, getattr(old, name))
        object.__setattr__(checkpoint, "hash_name", 123)
        with self.assertRaises(TypeError):
            encode_rotation((checkpoint, new_key, new, auth))

    def test_nested_signed_root_value_error_propagates(self):
        old, new_key, new, auth = self.item
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(checkpoint, name, getattr(new, name))
        object.__setattr__(checkpoint, "version", 2)
        with self.assertRaises(ValueError):
            encode_rotation((old, new_key, checkpoint, auth))

    def test_call_is_read_only(self):
        before = encode_rotation(self.item)
        encode_rotation(self.item)
        self.assertEqual(encode_rotation(self.item), before)
        self.assertTrue(verify_rotation(self.item, self.old_public))


class DecodeRotationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.old_public = _public_key(_SEED_A)
        self.new_public = _public_key(_SEED_B)
        self.item = self.log.rotate_signer(_SEED_A, _SEED_B)

    def roundtrip(self, item, trusted_key=None):
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
        self.assertEqual((old, new_key, new, auth), item)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(encode_rotation(decoded), data)
        self.assertTrue(
            verify_rotation(decoded, trusted_key or self.old_public)
        )
        return decoded

    def test_roundtrip_variants(self):
        for size in (0, 1, 3, 5):
            self.roundtrip(self.log.rotate_signer(_SEED_A, _SEED_B, size))

    def test_roundtrip_default_size(self):
        self.roundtrip(self.log.rotate_signer(_SEED_A, _SEED_B))

    def test_roundtrip_empty_log(self):
        self.roundtrip(AuditLog().rotate_signer(_SEED_A, _SEED_B))

    def test_roundtrip_after_prune(self):
        self.log.prune(3, self.log.seal(3))
        self.roundtrip(self.log.rotate_signer(_SEED_A, _SEED_B, 4))

    def test_roundtrip_alternate_hashes(self):
        for hash_name in ("sha512", "sha3_256", "blake2b"):
            log = AuditLog(hash_name=hash_name)
            for record in ("a", "b", "c"):
                log.append(record)
            self.roundtrip(log.rotate_signer(_SEED_A, _SEED_B, 0))
            self.roundtrip(log.rotate_signer(_SEED_A, _SEED_B))

    def test_roundtrip_same_seed(self):
        self.roundtrip(self.log.rotate_signer(_SEED_A, _SEED_A))

    def test_persistence_across_process_boundary(self):
        item = self.log.rotate_signer(_SEED_A, _SEED_B, 3)
        data = encode_rotation(item)
        # Fresh bytes, as read from disk or a socket; the restored four-tuple
        # still verifies offline against the pre-trusted old public key.
        restored = decode_rotation(bytes(data))
        self.assertEqual(restored, item)
        self.assertTrue(verify_rotation(restored, self.old_public))

    def test_only_bytes_accepted(self):
        data = encode_rotation(self.item)
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
        data = encode_rotation(self.item)
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/signed-root/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-prune/v1\0" + data[len(MAGIC):],
            # The rotation *authorization* domain is a distinct lookalike.
            b"auditchain/signer-rotation/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:40])):
                decode_rotation(bad)

    def test_bad_version(self):
        data = encode_rotation(self.item)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_rotation(bad)

    def test_truncation(self):
        data = encode_rotation(self.item)
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
        data = encode_rotation(self.item)
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_rotation(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_rotation(bad)

    def test_missing_blobs(self):
        old, new_key, new, auth = self.item
        # Three blobs where four are required.
        short = (
            MAGIC
            + u64(1)
            + blob(encode_signed_root(old))
            + blob(new_key)
            + blob(encode_signed_root(new))
        )
        with self.assertRaises(ValueError):
            decode_rotation(short)
        # Two blobs.
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC + u64(1) + blob(encode_signed_root(old)) + blob(new_key)
            )

    def test_new_key_width_checked(self):
        old, new_key, new, auth = self.item
        for width in (0, 1, 31, 33, 64):
            bad = (
                MAGIC
                + u64(1)
                + blob(encode_signed_root(old))
                + blob(b"\x00" * width)
                + blob(encode_signed_root(new))
                + blob(auth)
            )
            with self.assertRaises(ValueError, msg=width):
                decode_rotation(bad)

    def test_auth_width_checked(self):
        old, new_key, new, auth = self.item
        for width in (0, 1, 63, 65):
            bad = (
                MAGIC
                + u64(1)
                + blob(encode_signed_root(old))
                + blob(new_key)
                + blob(encode_signed_root(new))
                + blob(b"\x00" * width)
            )
            with self.assertRaises(ValueError, msg=width):
                decode_rotation(bad)

    def test_key_and_checkpoint_slots_cannot_be_exchanged(self):
        old, new_key, new, auth = self.item
        # A raw 32-byte key in the old-checkpoint slot fails the nested
        # signed-root framing.
        bad = (
            MAGIC
            + u64(1)
            + blob(new_key)
            + blob(encode_signed_root(old))
            + blob(encode_signed_root(new))
            + blob(auth)
        )
        with self.assertRaises(ValueError):
            decode_rotation(bad)
        # A checkpoint encoding in the key slot is the wrong width.
        bad = (
            MAGIC
            + u64(1)
            + blob(encode_signed_root(old))
            + blob(encode_signed_root(new))
            + blob(encode_signed_root(new))
            + blob(auth)
        )
        with self.assertRaises(ValueError):
            decode_rotation(bad)

    def test_swapped_checkpoints_decode_but_verify_false(self):
        # O and N both encode SignedRoots over one snapshot and differ only in
        # signature, so exchanging them stays structurally decodable; the
        # codec never judges the mismatch, verify_rotation does.
        old, new_key, new, auth = self.item
        swapped = (
            MAGIC
            + u64(1)
            + blob(encode_signed_root(new))
            + blob(new_key)
            + blob(encode_signed_root(old))
            + blob(auth)
        )
        decoded = decode_rotation(swapped)
        self.assertEqual(decoded, (new, new_key, old, auth))
        self.assertNotEqual(decoded, self.item)
        self.assertNotEqual(encode_rotation(decoded), encode_rotation(self.item))
        self.assertFalse(verify_rotation(decoded, self.old_public))

    def test_garbage_checkpoint_blob_rejected(self):
        old, new_key, new, auth = self.item
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC
                + u64(1)
                + blob(b"hello")
                + blob(new_key)
                + blob(encode_signed_root(new))
                + blob(auth)
            )
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC
                + u64(1)
                + blob(encode_signed_root(old))
                + blob(new_key)
                + blob(b"hello")
                + blob(auth)
            )

    def test_nested_checkpoint_framing_error_rejected(self):
        old, new_key, new, auth = self.item
        tampered_old = b"x" + encode_signed_root(old)[1:]
        tampered_new = b"x" + encode_signed_root(new)[1:]
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC
                + u64(1)
                + blob(tampered_old)
                + blob(new_key)
                + blob(encode_signed_root(new))
                + blob(auth)
            )
        with self.assertRaises(ValueError):
            decode_rotation(
                MAGIC
                + u64(1)
                + blob(encode_signed_root(old))
                + blob(new_key)
                + blob(tampered_new)
                + blob(auth)
            )

    def test_bad_auth_still_decodes_but_verifies_false(self):
        old, new_key, new, _ = self.item
        forged = (old, new_key, new, b"\x00" * 64)
        decoded = decode_rotation(encode_rotation(forged))
        self.assertEqual(decoded, forged)
        self.assertEqual(decoded[3], b"\x00" * 64)
        self.assertFalse(verify_rotation(decoded, self.old_public))

    def test_tampered_checkpoint_still_decodes_but_verifies_false(self):
        old, new_key, new, auth = self.item
        bogus = SignedRoot(
            new.version,
            new.hash_name,
            new.size,
            new.root,
            new.head,
            b"\x00" * 64,
        )
        forged = (old, new_key, bogus, auth)
        decoded = decode_rotation(encode_rotation(forged))
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_rotation(decoded, self.old_public))

    def test_mismatched_snapshots_decode_but_verify_false(self):
        old, new_key, _, auth = self.item
        other = self.log.sign_root(_SEED_B, 2)
        forged = (old, new_key, other, auth)
        decoded = decode_rotation(encode_rotation(forged))
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_rotation(decoded, self.old_public))

    def test_wrong_old_key_decodes_but_verifies_false(self):
        item = self.log.rotate_signer(_SEED_B, _SEED_C)
        decoded = decode_rotation(encode_rotation(item))
        self.assertEqual(decoded, item)
        self.assertFalse(verify_rotation(decoded, self.old_public))
        self.assertTrue(
            verify_rotation(decoded, _public_key(_SEED_B))
        )

    def test_call_is_read_only(self):
        data = encode_rotation(self.item)
        self.assertEqual(decode_rotation(data), self.item)
        decode_rotation(data)
        self.assertEqual(decode_rotation(data), self.item)


if __name__ == "__main__":
    unittest.main()
