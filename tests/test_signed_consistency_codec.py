import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedConsistency,
    SignedRoot,
    decode_signed_consistency,
    decode_signed_root,
    encode_signed_consistency,
    encode_signed_root,
    verify_signed_consistency,
)

MAGIC = b"auditchain/signed-consistency/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


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


def _parse_envelope(data):
    """Split an envelope into (version, old_blob, new_blob, proof_nodes)."""
    assert data.startswith(MAGIC)
    offset = len(MAGIC)
    version = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    length = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    old_blob = data[offset:offset + length]
    offset += length
    length = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    new_blob = data[offset:offset + length]
    offset += length
    count = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    nodes = []
    for _ in range(count):
        length = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        nodes.append(data[offset:offset + length])
        offset += length
    assert offset == len(data)
    return version, old_blob, new_blob, nodes


class EncodeSignedConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        data = encode_signed_consistency(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # old blob: u64 length then the complete encode_signed_root bytes.
        old_bytes = encode_signed_root(receipt.old)
        self.assertEqual(data[offset:offset + 8], u64(len(old_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(old_bytes)], old_bytes)
        offset += len(old_bytes)
        # new blob: u64 length then the complete encode_signed_root bytes.
        new_bytes = encode_signed_root(receipt.new)
        self.assertEqual(data[offset:offset + 8], u64(len(new_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(new_bytes)], new_bytes)
        offset += len(new_bytes)
        # proof count, then one length-prefixed blob per node in tuple order.
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.proof)))
        offset += 8
        for node in receipt.proof:
            self.assertEqual(data[offset:offset + 8], u64(len(node)))
            offset += 8
            self.assertEqual(data[offset:offset + len(node)], node)
            offset += len(node)
        self.assertEqual(offset, len(data))

    def test_blobs_are_exact_existing_encodings(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        version, old_blob, new_blob, nodes = _parse_envelope(
            encode_signed_consistency(receipt)
        )
        self.assertEqual(version, 1)
        self.assertEqual(old_blob, encode_signed_root(receipt.old))
        self.assertEqual(new_blob, encode_signed_root(receipt.new))
        self.assertEqual(tuple(nodes), receipt.proof)
        # The checkpoint blobs are independently decodable by the existing
        # codec.
        self.assertEqual(decode_signed_root(old_blob), receipt.old)
        self.assertEqual(decode_signed_root(new_blob), receipt.new)

    def test_encode_is_deterministic(self):
        receipt = self.log.signed_consistency(3, _SEED_A)
        self.assertEqual(
            encode_signed_consistency(receipt),
            encode_signed_consistency(receipt),
        )

    def test_no_new_signing_message(self):
        # Both checkpoints ride along verbatim; their bytes are exactly
        # sign_root's. Encoding introduces no signature of its own.
        receipt = self.log.signed_consistency(2, _SEED_A, 4)
        _, old_blob, new_blob, _ = _parse_envelope(
            encode_signed_consistency(receipt)
        )
        self.assertEqual(
            old_blob, encode_signed_root(self.log.sign_root(_SEED_A, 2))
        )
        self.assertEqual(
            new_blob, encode_signed_root(self.log.sign_root(_SEED_A, 4))
        )

    def test_only_signed_consistency_accepted(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        for bad in (
            None,
            1,
            "receipt",
            b"bytes",
            (),
            receipt.old,
            (receipt.old, receipt.new, receipt.proof),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_consistency(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        for field, value in (
            ("old", None),
            ("old", receipt.proof),
            ("new", None),
            ("new", receipt.proof),
            ("proof", None),
            ("proof", list(receipt.proof)),
            ("proof", (b"x", 1)),
        ):
            forged = SignedConsistency.__new__(SignedConsistency)
            object.__setattr__(
                forged, "old", value if field == "old" else receipt.old
            )
            object.__setattr__(
                forged, "new", value if field == "new" else receipt.new
            )
            object.__setattr__(
                forged, "proof", value if field == "proof" else receipt.proof
            )
            with self.assertRaises(TypeError, msg=field):
                encode_signed_consistency(forged)

    def test_nested_checkpoint_type_error_propagates(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(
                checkpoint, name, getattr(receipt.new, name)
            )
        object.__setattr__(checkpoint, "version", "1")
        forged = SignedConsistency.__new__(SignedConsistency)
        object.__setattr__(forged, "old", receipt.old)
        object.__setattr__(forged, "new", checkpoint)
        object.__setattr__(forged, "proof", receipt.proof)
        with self.assertRaises(TypeError):
            encode_signed_consistency(forged)

    def test_nested_checkpoint_value_error_propagates(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(
                checkpoint, name, getattr(receipt.old, name)
            )
        object.__setattr__(checkpoint, "signature", b"\x00" * 63)
        forged = SignedConsistency.__new__(SignedConsistency)
        object.__setattr__(forged, "old", checkpoint)
        object.__setattr__(forged, "new", receipt.new)
        object.__setattr__(forged, "proof", receipt.proof)
        with self.assertRaises(ValueError):
            encode_signed_consistency(forged)

    def test_call_is_read_only(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        before = encode_signed_consistency(receipt)
        encode_signed_consistency(receipt)
        self.assertEqual(encode_signed_consistency(receipt), before)
        self.assertTrue(
            verify_signed_consistency(receipt, self.public_key)
        )


class DecodeSignedConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, receipt):
        data = encode_signed_consistency(receipt)
        decoded = decode_signed_consistency(data)
        self.assertIsInstance(decoded, SignedConsistency)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.old, receipt.old)
        self.assertEqual(decoded.new, receipt.new)
        self.assertEqual(decoded.proof, receipt.proof)
        self.assertIs(type(decoded.proof), tuple)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(encode_signed_consistency(decoded), data)
        self.assertTrue(
            verify_signed_consistency(decoded, self.public_key)
        )
        return decoded

    def test_roundtrip_variants(self):
        for old_size, new_size in (
            (0, None),
            (0, 3),
            (1, None),
            (2, 4),
            (3, None),
            (4, 4),
            (7, None),
            (7, 7),
        ):
            self.roundtrip(
                self.log.signed_consistency(old_size, _SEED_A, new_size)
            )

    def test_roundtrip_empty_log(self):
        self.roundtrip(AuditLog().signed_consistency(0, _SEED_A))

    def test_roundtrip_after_prune(self):
        twin = AuditLog()
        for i in range(6):
            record = f"r{i}"
            self.log.append(record)
            twin.append(record)
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.signed_consistency(2, _SEED_A))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            for record in ("a", "b", "c"):
                log.append(record)
            self.roundtrip(log.signed_consistency(1, _SEED_A))

    def test_frozen(self):
        data = encode_signed_consistency(
            self.log.signed_consistency(2, _SEED_A)
        )
        decoded = decode_signed_consistency(data)
        with self.assertRaises(FrozenInstanceError):
            decoded.old = decoded.old
        with self.assertRaises(FrozenInstanceError):
            decoded.new = decoded.new
        with self.assertRaises(FrozenInstanceError):
            decoded.proof = ()

    def test_persistence_across_process_boundary(self):
        data = encode_signed_consistency(
            self.log.signed_consistency(2, _SEED_A)
        )
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_signed_consistency(bytes(data))
        self.assertEqual(
            restored, self.log.signed_consistency(2, _SEED_A)
        )
        self.assertTrue(
            verify_signed_consistency(restored, self.public_key)
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_consistency(
            self.log.signed_consistency(2, _SEED_A)
        )
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
                decode_signed_consistency(bad)

    def test_bad_magic(self):
        data = encode_signed_consistency(
            self.log.signed_consistency(2, _SEED_A)
        )
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/signed-root/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-audit-batch/v1\0" + data[len(MAGIC):],
            b"auditchain/batch/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:32])):
                decode_signed_consistency(bad)

    def test_bad_version(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        data = encode_signed_consistency(receipt)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_consistency(bad)

    def test_truncation(self):
        data = encode_signed_consistency(
            self.log.signed_consistency(2, _SEED_A)
        )
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_consistency(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_consistency(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_consistency(
            self.log.signed_consistency(2, _SEED_A)
        )
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_consistency(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
            MAGIC + u64(1) + blob(b"") + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_consistency(bad)

    def test_missing_new_blob(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, _, _ = _parse_envelope(data)
        with self.assertRaises(ValueError):
            decode_signed_consistency(MAGIC + u64(1) + blob(old_blob))

    def test_missing_proof_count(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, new_blob, _ = _parse_envelope(data)
        with self.assertRaises(ValueError):
            decode_signed_consistency(
                MAGIC + u64(1) + blob(old_blob) + blob(new_blob)
            )

    def test_garbage_checkpoint_blob_rejected(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, new_blob, nodes = _parse_envelope(data)
        proof = b"".join(blob(node) for node in nodes)
        for old_material, new_material in (
            (b"hello", new_blob),
            (old_blob, b"hello"),
        ):
            with self.assertRaises(ValueError):
                decode_signed_consistency(
                    MAGIC
                    + u64(1)
                    + blob(old_material)
                    + blob(new_material)
                    + u64(len(nodes))
                    + proof
                )

    def test_trailing_bytes_inside_blob_rejected(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, new_blob, nodes = _parse_envelope(data)
        proof = b"".join(blob(node) for node in nodes)
        with self.assertRaises(ValueError):
            decode_signed_consistency(
                MAGIC
                + u64(1)
                + blob(old_blob + b"\x00")
                + blob(new_blob)
                + u64(len(nodes))
                + proof
            )

    def test_nested_checkpoint_framing_error_rejected(self):
        # A checkpoint blob whose own magic is wrong must surface ValueError.
        receipt = self.log.signed_consistency(2, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, new_blob, nodes = _parse_envelope(data)
        proof = b"".join(blob(node) for node in nodes)
        for old_material, new_material in (
            (b"x" + old_blob[1:], new_blob),
            (old_blob, b"x" + new_blob[1:]),
        ):
            with self.assertRaises(ValueError):
                decode_signed_consistency(
                    MAGIC
                    + u64(1)
                    + blob(old_material)
                    + blob(new_material)
                    + u64(len(nodes))
                    + proof
                )

    def test_bad_proof_width_rejected(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        for bad_node in (b"", b"\x00" * 16, b"\x00" * 33, b"\x00" * 64):
            forged = SignedConsistency.__new__(SignedConsistency)
            object.__setattr__(forged, "old", receipt.old)
            object.__setattr__(forged, "new", receipt.new)
            object.__setattr__(forged, "proof", (bad_node,) + receipt.proof)
            # Encoding is structural and does not inspect proof content...
            data = encode_signed_consistency(forged)
            # ...but decoding rejects a digest of the wrong width.
            with self.assertRaises(ValueError, msg=len(bad_node)):
                decode_signed_consistency(data)

    def test_bad_signature_still_decodes_but_verifies_false(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        checkpoint = receipt.new
        bogus = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = SignedConsistency(receipt.old, bogus, receipt.proof)
        decoded = decode_signed_consistency(
            encode_signed_consistency(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_consistency(decoded, self.public_key)
        )

    def test_tampered_proof_still_decodes_but_verifies_false(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        tampered = SignedConsistency(
            receipt.old,
            receipt.new,
            (b"\x00" * 32,) + receipt.proof[1:],
        )
        decoded = decode_signed_consistency(
            encode_signed_consistency(tampered)
        )
        self.assertEqual(decoded, tampered)
        self.assertFalse(
            verify_signed_consistency(decoded, self.public_key)
        )

    def test_wrong_key_decodes_but_verifies_false(self):
        receipt = self.log.signed_consistency(2, _SEED_B)
        decoded = decode_signed_consistency(
            encode_signed_consistency(receipt)
        )
        self.assertFalse(
            verify_signed_consistency(decoded, self.public_key)
        )
        self.assertTrue(
            verify_signed_consistency(decoded, self.other_public_key)
        )

    def test_call_is_read_only(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        data = encode_signed_consistency(receipt)
        decode_signed_consistency(data)
        self.assertEqual(
            decode_signed_consistency(data),
            self.log.signed_consistency(2, _SEED_A),
        )


if __name__ == "__main__":
    unittest.main()
