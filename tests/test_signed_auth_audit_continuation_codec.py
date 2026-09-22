import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedAuthAuditBundle,
    SignedAuthAuditContinuation,
    SignedAuthBundle,
    SignedConsistency,
    SignedRoot,
    decode_signed_auth_audit_bundle,
    decode_signed_auth_audit_continuation,
    decode_signed_consistency,
    encode_signed_auth_audit_bundle,
    encode_signed_auth_audit_continuation,
    encode_signed_consistency,
    verify_signed_auth_audit_continuation,
)

MAGIC = b"auditchain/auth-audit-continuation/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"


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


def _log(n=5, key=_KEY, hash_name="sha256", prefix="record"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _issue(old_size=2, indices=(0, 2), seed=_SEED_A, size=4, n=5, **kwargs):
    return _log(n, **kwargs).signed_auth_audit_continuation(
        old_size, indices, seed, size
    )


def _split_envelope(data):
    """Split an envelope into (version, bundle_blob, consistency_blob)."""
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

    bundle_blob = take()
    consistency_blob = take()
    assert offset == len(data)
    return version, bundle_blob, consistency_blob


class EncodeSignedAuthAuditContinuationTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        receipt = _issue(old_size=2, indices=(0, 2), size=5)
        data = encode_signed_auth_audit_continuation(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # bundle blob: u64 length then the complete
        # encode_signed_auth_audit_bundle bytes.
        bundle_bytes = encode_signed_auth_audit_bundle(receipt.bundle)
        self.assertEqual(data[offset:offset + 8], u64(len(bundle_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(bundle_bytes)], bundle_bytes)
        offset += len(bundle_bytes)
        # consistency blob likewise.
        consistency_bytes = encode_signed_consistency(receipt.consistency)
        self.assertEqual(data[offset:offset + 8], u64(len(consistency_bytes)))
        offset += 8
        self.assertEqual(
            data[offset:offset + len(consistency_bytes)], consistency_bytes
        )
        offset += len(consistency_bytes)
        # Nothing follows the consistency blob.
        self.assertEqual(offset, len(data))

    def test_expected_canonical_bytes(self):
        receipt = _issue(old_size=1, indices=(3, 0), size=4)
        expected = (
            MAGIC
            + u64(1)
            + blob(encode_signed_auth_audit_bundle(receipt.bundle))
            + blob(encode_signed_consistency(receipt.consistency))
        )
        self.assertEqual(
            encode_signed_auth_audit_continuation(receipt), expected
        )

    def test_blobs_are_exact_existing_encodings(self):
        receipt = _issue(old_size=1, indices=(0, 2), size=4)
        _, bundle_blob, consistency_blob = _split_envelope(
            encode_signed_auth_audit_continuation(receipt)
        )
        self.assertEqual(
            bundle_blob, encode_signed_auth_audit_bundle(receipt.bundle)
        )
        self.assertEqual(
            consistency_blob, encode_signed_consistency(receipt.consistency)
        )
        # The blobs are independently decodable by the existing codecs.
        self.assertEqual(
            decode_signed_auth_audit_bundle(bundle_blob), receipt.bundle
        )
        self.assertEqual(
            decode_signed_consistency(consistency_blob),
            receipt.consistency,
        )

    def test_encode_is_deterministic(self):
        receipt = _issue()
        self.assertEqual(
            encode_signed_auth_audit_continuation(receipt),
            encode_signed_auth_audit_continuation(receipt),
        )

    def test_no_new_signing_message(self):
        # Both halves ride along verbatim as their existing canonical
        # encodings; the continuation introduces no signature of its own.
        log = _log(6)
        receipt = log.signed_auth_audit_continuation(2, (4, 0), _SEED_A, size=5)
        _, bundle_blob, consistency_blob = _split_envelope(
            encode_signed_auth_audit_continuation(receipt)
        )
        twin = _log(6)
        self.assertEqual(
            bundle_blob,
            encode_signed_auth_audit_bundle(
                twin.signed_auth_audit_bundle((4, 0), _SEED_A, size=5)
            ),
        )
        self.assertEqual(
            consistency_blob,
            encode_signed_consistency(
                _log(6).signed_consistency(2, _SEED_A, new_size=5)
            ),
        )

    def test_empty_proof_variants(self):
        for old, new in ((0, 5), (3, 3), (0, 0)):
            receipt = _issue(
                old_size=old, indices=(), seed=_SEED_A, size=new, n=max(new, 1)
            )
            self.assertEqual(receipt.consistency.proof, ())
            data = encode_signed_auth_audit_continuation(receipt)
            _, _, consistency_blob = _split_envelope(data)
            self.assertEqual(
                decode_signed_consistency(consistency_blob),
                receipt.consistency,
            )

    def test_only_continuation_accepted(self):
        receipt = _issue()
        for bad in (
            None,
            1,
            "receipt",
            b"bytes",
            (),
            (receipt.bundle, receipt.consistency),
            receipt.bundle,
            receipt.consistency,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_auth_audit_continuation(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        receipt = _issue()
        for field, value in (
            ("bundle", None),
            ("bundle", receipt.consistency),
            ("bundle", "not-a-bundle"),
            ("consistency", None),
            ("consistency", receipt.bundle),
            ("consistency", "not-a-consistency"),
        ):
            forged = SignedAuthAuditContinuation.__new__(
                SignedAuthAuditContinuation
            )
            object.__setattr__(
                forged, "bundle", receipt.bundle if field != "bundle" else value
            )
            object.__setattr__(
                forged,
                "consistency",
                receipt.consistency if field != "consistency" else value,
            )
            with self.assertRaises(TypeError, msg=field):
                encode_signed_auth_audit_continuation(forged)

    def test_nested_bundle_type_error_propagates(self):
        receipt = _issue()
        bad_auth = SignedAuthBundle.__new__(SignedAuthBundle)
        object.__setattr__(
            bad_auth, "verifier", receipt.bundle.auth.verifier
        )
        object.__setattr__(bad_auth, "hash_name", 123)
        object.__setattr__(bad_auth, "items", receipt.bundle.auth.items)
        bad_bundle = SignedAuthAuditBundle(bad_auth, receipt.bundle.audit)
        forged = SignedAuthAuditContinuation(
            bad_bundle, receipt.consistency
        )
        with self.assertRaises(TypeError):
            encode_signed_auth_audit_continuation(forged)

    def test_nested_consistency_value_error_propagates(self):
        receipt = _issue(old_size=1, indices=(0,), size=5)
        self.assertTrue(receipt.consistency.proof)
        bad_consistency = SignedConsistency(
            receipt.consistency.old,
            receipt.consistency.new,
            (b"\x00" * 31,) + receipt.consistency.proof[1:],
        )
        forged = SignedAuthAuditContinuation(
            receipt.bundle, bad_consistency
        )
        with self.assertRaises(ValueError):
            encode_signed_auth_audit_continuation(forged)

    def test_nested_checkpoint_value_error_propagates(self):
        receipt = _issue()
        old = receipt.consistency.old
        bad_old = SignedRoot(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        # A replaced signature keeps the nested encoding structurally valid
        # (it decodes); instead break the checkpoint version so the nested
        # signed-root encoder raises ValueError.
        bad_version = SignedRoot.__new__(SignedRoot)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "head",
            "signature",
        ):
            object.__setattr__(
                bad_version, name, getattr(old, name)
            )
        object.__setattr__(bad_version, "version", 2)
        bad_consistency = SignedConsistency(
            bad_version, receipt.consistency.new, receipt.consistency.proof
        )
        forged = SignedAuthAuditContinuation(
            receipt.bundle, bad_consistency
        )
        with self.assertRaises(ValueError):
            encode_signed_auth_audit_continuation(forged)
        # Sanity: a bad signature alone encodes (verification, not framing,
        # judges it).
        signed_bad = SignedConsistency(
            bad_old, receipt.consistency.new, receipt.consistency.proof
        )
        encodable = SignedAuthAuditContinuation(
            receipt.bundle, signed_bad
        )
        encode_signed_auth_audit_continuation(encodable)

    def test_call_is_read_only(self):
        receipt = _issue(old_size=1, indices=(0, 2), size=5)
        before = encode_signed_auth_audit_continuation(receipt)
        encode_signed_auth_audit_continuation(receipt)
        self.assertEqual(
            encode_signed_auth_audit_continuation(receipt), before
        )
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                receipt, self.public_key
            )
        )


class DecodeSignedAuthAuditContinuationTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, receipt):
        data = encode_signed_auth_audit_continuation(receipt)
        decoded = decode_signed_auth_audit_continuation(data)
        self.assertIsInstance(decoded, SignedAuthAuditContinuation)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.bundle, receipt.bundle)
        self.assertEqual(decoded.consistency, receipt.consistency)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(
            encode_signed_auth_audit_continuation(decoded), data
        )
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                decoded, self.public_key
            )
        )
        return decoded

    def test_roundtrip_variants(self):
        self.roundtrip(_issue(old_size=0, indices=(0, 2), size=5))
        self.roundtrip(_issue(old_size=1, indices=(3, 0), size=5))
        self.roundtrip(_issue(old_size=2, indices=(2, 4), size=5))
        self.roundtrip(_issue(old_size=3, indices=(1,), size=3))
        self.roundtrip(_issue(old_size=0, indices=(), size=0, n=3))
        self.roundtrip(_issue(old_size=2, indices=(), size=5))

    def test_roundtrip_default_size(self):
        self.roundtrip(
            _log(6).signed_auth_audit_continuation(
                2, (1,), _SEED_A
            )
        )

    def test_roundtrip_empty_log(self):
        log = AuditLog(key=_KEY)
        self.roundtrip(
            log.signed_auth_audit_continuation(0, (), _SEED_A, size=0)
        )

    def test_roundtrip_after_prune(self):
        log = _log(6)
        log.prune(2, log.seal(2))
        self.roundtrip(
            log.signed_auth_audit_continuation(2, (5, 2), _SEED_A)
        )

    def test_roundtrip_alternate_hashes(self):
        for hash_name in ("sha512", "sha3_256"):
            self.roundtrip(
                _issue(
                    old_size=1,
                    indices=(2, 0),
                    size=3,
                    n=3,
                    hash_name=hash_name,
                )
            )

    def test_frozen(self):
        decoded = decode_signed_auth_audit_continuation(
            encode_signed_auth_audit_continuation(_issue())
        )
        with self.assertRaises(FrozenInstanceError):
            decoded.bundle = decoded.bundle
        with self.assertRaises(FrozenInstanceError):
            decoded.consistency = decoded.consistency

    def test_persistence_across_process_boundary(self):
        receipt = _issue(old_size=1, indices=(4, 0), size=5)
        data = encode_signed_auth_audit_continuation(receipt)
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_signed_auth_audit_continuation(bytes(data))
        self.assertEqual(restored, receipt)
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                restored, self.public_key
            )
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_auth_audit_continuation(_issue())
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
                decode_signed_auth_audit_continuation(bad)

    def test_bad_magic(self):
        data = encode_signed_auth_audit_continuation(_issue())
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/auth-audit/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-consistency/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-auth-bundle/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-prune/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:40])):
                decode_signed_auth_audit_continuation(bad)

    def test_bad_version(self):
        receipt = _issue()
        data = encode_signed_auth_audit_continuation(receipt)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_auth_audit_continuation(bad)

    def test_truncation(self):
        data = encode_signed_auth_audit_continuation(_issue())
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_auth_audit_continuation(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_auth_audit_continuation(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_auth_audit_continuation(_issue())
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_auth_audit_continuation(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_auth_audit_continuation(bad)

    def test_missing_consistency_blob(self):
        receipt = _issue()
        data = encode_signed_auth_audit_continuation(receipt)
        _, bundle_blob, _ = _split_envelope(data)
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC + u64(1) + blob(bundle_blob)
            )

    def test_swapped_blob_order_rejected(self):
        # Putting the consistency encoding in the bundle slot (and vice
        # versa) fails each nested decoder's own magic framing.
        receipt = _issue(old_size=1, indices=(0,), size=5)
        data = encode_signed_auth_audit_continuation(receipt)
        _, bundle_blob, consistency_blob = _split_envelope(data)
        swapped = (
            MAGIC
            + u64(1)
            + blob(consistency_blob)
            + blob(bundle_blob)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(swapped)

    def test_garbage_bundle_blob_rejected(self):
        receipt = _issue()
        data = encode_signed_auth_audit_continuation(receipt)
        _, _, consistency_blob = _split_envelope(data)
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC
                + u64(1)
                + blob(b"hello")
                + blob(consistency_blob)
            )

    def test_garbage_consistency_blob_rejected(self):
        receipt = _issue()
        data = encode_signed_auth_audit_continuation(receipt)
        _, bundle_blob, _ = _split_envelope(data)
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC
                + u64(1)
                + blob(bundle_blob)
                + blob(b"hello")
            )

    def test_nested_bundle_framing_error_rejected(self):
        receipt = _issue()
        data = encode_signed_auth_audit_continuation(receipt)
        _, bundle_blob, consistency_blob = _split_envelope(data)
        tampered = b"x" + bundle_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC
                + u64(1)
                + blob(tampered)
                + blob(consistency_blob)
            )

    def test_nested_consistency_framing_error_rejected(self):
        receipt = _issue()
        data = encode_signed_auth_audit_continuation(receipt)
        _, bundle_blob, consistency_blob = _split_envelope(data)
        tampered = b"x" + consistency_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC
                + u64(1)
                + blob(bundle_blob)
                + blob(tampered)
            )

    def test_wrong_width_proof_node_in_nested_blob_rejected(self):
        receipt = _issue(old_size=1, indices=(0,), size=5)
        data = encode_signed_auth_audit_continuation(receipt)
        _, bundle_blob, consistency_blob = _split_envelope(data)
        # Rebuild the nested consistency with a wrong-width proof node.
        inner_magic = b"auditchain/signed-consistency/v1\0"
        self.assertTrue(consistency_blob.startswith(inner_magic))
        offset = len(inner_magic) + 8

        def take():
            nonlocal offset
            length = int.from_bytes(
                consistency_blob[offset:offset + 8], "big"
            )
            offset += 8
            part = consistency_blob[offset:offset + length]
            offset += length
            return part

        old_blob = take()
        new_blob = take()
        count = int.from_bytes(
            consistency_blob[offset:offset + 8], "big"
        )
        offset += 8
        nodes = [take() for _ in range(count)]
        self.assertTrue(nodes)
        nodes[0] = nodes[0][:-1]
        bad_inner = (
            inner_magic
            + u64(1)
            + blob(old_blob)
            + blob(new_blob)
            + u64(len(nodes))
            + b"".join(blob(node) for node in nodes)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_audit_continuation(
                MAGIC + u64(1) + blob(bundle_blob) + blob(bad_inner)
            )

    def test_packages_describing_different_snapshots_still_decode(self):
        # Codec checks framing only: a genuine bundle over size 4 and a
        # genuine consistency extending 1 -> 5 decode fine; the snapshot
        # linkage is left to verification.
        bundle = _log(5).signed_auth_audit_bundle(
            (0,), _SEED_A, size=4
        )
        consistency = _log(5).signed_consistency(
            1, _SEED_A, new_size=5
        )
        forged = SignedAuthAuditContinuation(bundle, consistency)
        decoded = decode_signed_auth_audit_continuation(
            encode_signed_auth_audit_continuation(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                decoded, self.public_key
            )
        )

    def test_algorithm_mismatch_between_packages_still_decodes(self):
        bundle = _log(3, hash_name="sha256").signed_auth_audit_bundle(
            (0,), _SEED_A, size=3
        )
        consistency = _log(3, hash_name="sha512").signed_consistency(
            1, _SEED_A, new_size=3
        )
        forged = SignedAuthAuditContinuation(bundle, consistency)
        decoded = decode_signed_auth_audit_continuation(
            encode_signed_auth_audit_continuation(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                decoded, self.public_key
            )
        )

    def test_bad_signature_still_decodes_but_verifies_false(self):
        receipt = _issue()
        old = receipt.consistency.old
        bogus_old = SignedRoot(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        forged = SignedAuthAuditContinuation(
            receipt.bundle,
            SignedConsistency(
                bogus_old,
                receipt.consistency.new,
                receipt.consistency.proof,
            ),
        )
        decoded = decode_signed_auth_audit_continuation(
            encode_signed_auth_audit_continuation(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                decoded, self.public_key
            )
        )

    def test_wrong_key_decodes_but_verifies_false(self):
        receipt = _issue(seed=_SEED_B)
        decoded = decode_signed_auth_audit_continuation(
            encode_signed_auth_audit_continuation(receipt)
        )
        self.assertEqual(decoded, receipt)
        self.assertFalse(
            verify_signed_auth_audit_continuation(
                decoded, self.public_key
            )
        )
        self.assertTrue(
            verify_signed_auth_audit_continuation(
                decoded, self.other_public_key
            )
        )

    def test_call_is_read_only(self):
        receipt = _issue(old_size=1, indices=(0, 2), size=5)
        data = encode_signed_auth_audit_continuation(receipt)
        self.assertEqual(
            decode_signed_auth_audit_continuation(data), receipt
        )


if __name__ == "__main__":
    unittest.main()
