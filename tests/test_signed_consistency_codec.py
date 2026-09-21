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


def _split_envelope(data):
    """Split an envelope into (version, old_blob, new_blob, proof_nodes)."""
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
    new_blob = take()
    count = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    nodes = []
    for _ in range(count):
        nodes.append(take())
    assert offset == len(data)
    return version, old_blob, new_blob, tuple(nodes)


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
        # new blob likewise.
        new_bytes = encode_signed_root(receipt.new)
        self.assertEqual(data[offset:offset + 8], u64(len(new_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(new_bytes)], new_bytes)
        offset += len(new_bytes)
        # proof count then one length-prefixed blob per node, tuple order.
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.proof)))
        offset += 8
        for node in receipt.proof:
            self.assertEqual(data[offset:offset + 8], u64(len(node)))
            offset += 8
            self.assertEqual(data[offset:offset + len(node)], node)
            offset += len(node)
        self.assertEqual(offset, len(data))

    def test_blobs_are_exact_existing_encodings(self):
        receipt = self.log.signed_consistency(1, _SEED_A, 4)
        _, old_blob, new_blob, nodes = _split_envelope(
            encode_signed_consistency(receipt)
        )
        self.assertEqual(old_blob, encode_signed_root(receipt.old))
        self.assertEqual(new_blob, encode_signed_root(receipt.new))
        # The checkpoint blobs are independently decodable by the codec.
        self.assertEqual(decode_signed_root(old_blob), receipt.old)
        self.assertEqual(decode_signed_root(new_blob), receipt.new)
        self.assertEqual(nodes, receipt.proof)

    def test_encode_is_deterministic(self):
        receipt = self.log.signed_consistency(2, _SEED_A)
        self.assertEqual(
            encode_signed_consistency(receipt),
            encode_signed_consistency(receipt),
        )

    def test_no_new_signing_message(self):
        # Both checkpoints ride along verbatim; their bytes are exactly
        # sign_root's. Encoding introduces no signature of its own.
        receipt = self.log.signed_consistency(2, _SEED_A, 4)
        _, old_blob, new_blob, _ = _split_envelope(
            encode_signed_consistency(receipt)
        )
        self.assertEqual(old_blob, encode_signed_root(self.log.sign_root(_SEED_A, 2)))
        self.assertEqual(new_blob, encode_signed_root(self.log.sign_root(_SEED_A, 4)))

    def test_empty_proof_variants(self):
        for old, new in ((0, 5), (3, 3), (0, 0)):
            receipt = self.log.signed_consistency(old, _SEED_A, new)
            self.assertEqual(receipt.proof, ())
            data = encode_signed_consistency(receipt)
            _, _, _, nodes = _split_envelope(data)
            self.assertEqual(nodes, ())

    def test_only_signed_consistency_accepted(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        for bad in (
            None,
            1,
            "receipt",
            b"bytes",
            (),
            (receipt.old, receipt.new, receipt.proof),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_consistency(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        for field, value in (
            ("old", None),
            ("old", receipt.proof),
            ("new", None),
            ("new", "not-a-checkpoint"),
            ("proof", None),
            ("proof", [b"x" * 32]),
            ("proof", "digests"),
        ):
            forged = SignedConsistency.__new__(SignedConsistency)
            object.__setattr__(
                forged, "old", receipt.old if field != "old" else value
            )
            object.__setattr__(
                forged, "new", receipt.new if field != "new" else value
            )
            object.__setattr__(
                forged, "proof", receipt.proof if field != "proof" else value
            )
            with self.assertRaises(TypeError, msg=field):
                encode_signed_consistency(forged)

    def test_bypassed_proof_element_type_raises_type_error(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        forged = SignedConsistency.__new__(SignedConsistency)
        object.__setattr__(forged, "old", receipt.old)
        object.__setattr__(forged, "new", receipt.new)
        object.__setattr__(
            forged, "proof", ("not-bytes",) + receipt.proof[1:]
        )
        with self.assertRaises(TypeError):
            encode_signed_consistency(forged)

    def test_nested_checkpoint_type_error_propagates(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
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
        receipt = self.log.signed_consistency(1, _SEED_A)
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(
                checkpoint, name, getattr(receipt.new, name)
            )
        object.__setattr__(checkpoint, "version", 2)
        forged = SignedConsistency.__new__(SignedConsistency)
        object.__setattr__(forged, "old", receipt.old)
        object.__setattr__(forged, "new", checkpoint)
        object.__setattr__(forged, "proof", receipt.proof)
        with self.assertRaises(ValueError):
            encode_signed_consistency(forged)

    def test_proof_width_violation_raises_value_error(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        self.assertTrue(receipt.proof)
        forged = SignedConsistency(
            receipt.old,
            receipt.new,
            (b"\x00" * 31,) + receipt.proof[1:],
        )
        with self.assertRaises(ValueError):
            encode_signed_consistency(forged)

    def test_call_is_read_only(self):
        receipt = self.log.signed_consistency(1, _SEED_A, 4)
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
        for old, new in (
            (0, None),
            (1, 7),
            (2, 6),
            (3, 7),
            (4, 4),
            (0, 0),
            (6, 7),
        ):
            self.roundtrip(
                self.log.signed_consistency(old, _SEED_A, new)
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
            for record in ("a", "b", "c", "d"):
                log.append(record)
            self.roundtrip(log.signed_consistency(1, _SEED_A, 4))

    def test_frozen(self):
        data = encode_signed_consistency(
            self.log.signed_consistency(1, _SEED_A)
        )
        decoded = decode_signed_consistency(data)
        with self.assertRaises(FrozenInstanceError):
            decoded.old = decoded.old
        with self.assertRaises(FrozenInstanceError):
            decoded.new = decoded.new
        with self.assertRaises(FrozenInstanceError):
            decoded.proof = ()

    def test_persistence_across_process_boundary(self):
        receipt = self.log.signed_consistency(1, _SEED_A, 6)
        data = encode_signed_consistency(receipt)
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_signed_consistency(bytes(data))
        self.assertEqual(restored, receipt)
        self.assertTrue(
            verify_signed_consistency(restored, self.public_key)
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_consistency(
            self.log.signed_consistency(1, _SEED_A)
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
            self.log.signed_consistency(1, _SEED_A)
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
        receipt = self.log.signed_consistency(1, _SEED_A)
        data = encode_signed_consistency(receipt)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_consistency(bad)

    def test_truncation(self):
        data = encode_signed_consistency(
            self.log.signed_consistency(1, _SEED_A)
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
            self.log.signed_consistency(1, _SEED_A)
        )
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_consistency(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_consistency(bad)

    def test_missing_new_blob(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, _, _ = _split_envelope(data)
        with self.assertRaises(ValueError):
            decode_signed_consistency(
                MAGIC + u64(1) + blob(old_blob)
            )

    def test_missing_proof_count(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, new_blob, _ = _split_envelope(data)
        with self.assertRaises(ValueError):
            decode_signed_consistency(
                MAGIC + u64(1) + blob(old_blob) + blob(new_blob)
            )

    def test_declared_node_count_too_large(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, new_blob, nodes = _split_envelope(data)
        rebuilt = (
            MAGIC
            + u64(1)
            + blob(old_blob)
            + blob(new_blob)
            + u64(len(nodes) + 1)
            + b"".join(blob(node) for node in nodes)
        )
        with self.assertRaises(ValueError):
            decode_signed_consistency(rebuilt)

    def test_declared_node_count_too_small(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, new_blob, nodes = _split_envelope(data)
        self.assertTrue(nodes)
        rebuilt = (
            MAGIC
            + u64(1)
            + blob(old_blob)
            + blob(new_blob)
            + u64(len(nodes) - 1)
            + b"".join(blob(node) for node in nodes)
        )
        with self.assertRaises(ValueError):
            decode_signed_consistency(rebuilt)

    def test_swapped_blob_order_changes_receipt(self):
        receipt = self.log.signed_consistency(1, _SEED_A, 6)
        data = encode_signed_consistency(receipt)
        _, old_blob, new_blob, nodes = _split_envelope(data)
        swapped = (
            MAGIC
            + u64(1)
            + blob(new_blob)
            + blob(old_blob)
            + u64(len(nodes))
            + b"".join(blob(node) for node in nodes)
        )
        # A swapped envelope never reproduces the original receipt: old and
        # new are distinct, positionally decoded fields.
        decoded = decode_signed_consistency(swapped)
        self.assertNotEqual(decoded, receipt)
        self.assertEqual(decoded.old, receipt.new)
        self.assertEqual(decoded.new, receipt.old)

    def test_garbage_old_blob_rejected(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, _, new_blob, nodes = _split_envelope(data)
        with self.assertRaises(ValueError):
            decode_signed_consistency(
                MAGIC
                + u64(1)
                + blob(b"hello")
                + blob(new_blob)
                + u64(len(nodes))
                + b"".join(blob(node) for node in nodes)
            )

    def test_garbage_new_blob_rejected(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, _, nodes = _split_envelope(data)
        with self.assertRaises(ValueError):
            decode_signed_consistency(
                MAGIC
                + u64(1)
                + blob(old_blob)
                + blob(b"hello")
                + u64(len(nodes))
                + b"".join(blob(node) for node in nodes)
            )

    def test_nested_checkpoint_framing_error_rejected(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, new_blob, nodes = _split_envelope(data)
        tampered = b"x" + old_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_consistency(
                MAGIC
                + u64(1)
                + blob(tampered)
                + blob(new_blob)
                + u64(len(nodes))
                + b"".join(blob(node) for node in nodes)
            )

    def test_wrong_width_proof_node_rejected(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        data = encode_signed_consistency(receipt)
        _, old_blob, new_blob, nodes = _split_envelope(data)
        self.assertTrue(nodes)
        bad_nodes = list(nodes)
        bad_nodes[0] = bad_nodes[0][:-1]
        evil = (
            MAGIC
            + u64(1)
            + blob(old_blob)
            + blob(new_blob)
            + u64(len(bad_nodes))
            + b"".join(blob(node) for node in bad_nodes)
        )
        with self.assertRaises(ValueError):
            decode_signed_consistency(evil)

    def test_wrong_width_proof_node_against_other_hash(self):
        # A 64-byte node is fine for sha512 but invalid against a sha256
        # old checkpoint: width is judged from the decoded old checkpoint.
        sha512_log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            sha512_log.append(record)
        wide_node = b"\x00" * 64
        old = self.log.sign_root(_SEED_A, 1)
        new = self.log.sign_root(_SEED_A, 2)
        evil = (
            MAGIC
            + u64(1)
            + blob(encode_signed_root(old))
            + blob(encode_signed_root(new))
            + u64(1)
            + blob(wide_node)
        )
        with self.assertRaises(ValueError):
            decode_signed_consistency(evil)
        # The same width is accepted for a sha512 old checkpoint; the proof
        # content is not checked, so a structurally valid but content-free
        # receipt still decodes.
        receipt512 = sha512_log.signed_consistency(1, _SEED_A)
        good_nodes = list(receipt512.proof)
        self.assertTrue(all(len(n) == 64 for n in good_nodes))
        decoded = decode_signed_consistency(
            encode_signed_consistency(receipt512)
        )
        self.assertEqual(decoded, receipt512)

    def test_proof_content_not_validated_on_decode(self):
        # The nodes need not link the roots: that is the restored
        # verification contract's job. The node count is kept (a wrong count
        # is verify_consistency's own structural ValueError, just as before
        # persistence existed) while every node is replaced by junk.
        receipt = self.log.signed_consistency(1, _SEED_A)
        self.assertTrue(receipt.proof)
        junk = tuple(b"\x11" * 32 for _ in receipt.proof)
        forged = SignedConsistency(receipt.old, receipt.new, junk)
        decoded = decode_signed_consistency(
            encode_signed_consistency(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_consistency(decoded, self.public_key)
        )

    def test_hash_algorithm_disagreement_still_decodes(self):
        sha512_log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c", "d", "e", "f"):
            sha512_log.append(record)
        old512 = sha512_log.sign_root(_SEED_A, 2)
        new256 = self.log.sign_root(_SEED_A, 6)
        forged = SignedConsistency(old512, new256, ())
        decoded = decode_signed_consistency(
            encode_signed_consistency(forged)
        )
        self.assertEqual(decoded, forged)
        # Width is measured against the old checkpoint's algorithm; this
        # empty-proof bundle is structurally decodable but fails linkage.
        self.assertFalse(
            verify_signed_consistency(decoded, self.public_key)
        )

    def test_bad_signature_still_decodes_but_verifies_false(self):
        receipt = self.log.signed_consistency(1, _SEED_A)
        new = receipt.new
        bogus_new = SignedRoot(
            new.version,
            new.hash_name,
            new.size,
            new.root,
            new.head,
            b"\x00" * 64,
        )
        forged = SignedConsistency(receipt.old, bogus_new, receipt.proof)
        decoded = decode_signed_consistency(
            encode_signed_consistency(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_consistency(decoded, self.public_key)
        )

    def test_wrong_key_decodes_but_verifies_false(self):
        receipt = self.log.signed_consistency(1, _SEED_B)
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
        receipt = self.log.signed_consistency(1, _SEED_A, 6)
        data = encode_signed_consistency(receipt)
        decode_signed_consistency(data)
        self.assertEqual(
            decode_signed_consistency(data), receipt
        )


if __name__ == "__main__":
    unittest.main()
