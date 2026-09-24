import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedStageAuthBundle,
    decode_auth_batch,
    decode_signed_stage_auth_bundle,
    decode_signed_stage_verifier,
    encode_auth_batch,
    encode_signed_stage_auth_bundle,
    encode_signed_stage_verifier,
    verify_signed_stage_auth_bundle,
)

MAGIC = b"auditchain/signed-stage-auth-bundle/v1\0"
STAGE_MAGIC = b"auditchain/signed-stage/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-stage-bundle-key"


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


def _log(records=5, key=_KEY, hash_name="sha256", evolve=1):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(records):
        log.append(f"record-{record}")
    for _ in range(evolve):
        log.rotate_key()
    return log


def _bundle(
    seed=_SEED_A,
    key=_KEY,
    hash_name="sha256",
    indices=(0, 2, 4),
    records=5,
    evolve=1,
):
    log = _log(records=records, key=key, hash_name=hash_name, evolve=evolve)
    receipt = log.export_signed_stage_verifier(seed)
    items = log.auth_batch(indices)
    return SignedStageAuthBundle(receipt, hash_name, items)


def _parse_blobs(data):
    """Split an envelope into (version, verifier_blob, batch_blob)."""
    assert data.startswith(MAGIC)
    offset = len(MAGIC)
    version = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    length = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    verifier_blob = data[offset:offset + length]
    offset += length
    length = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    batch_blob = data[offset:offset + length]
    offset += length
    assert offset == len(data)
    return version, verifier_blob, batch_blob


class EncodeSignedStageAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        bundle = _bundle()
        data = encode_signed_stage_auth_bundle(bundle)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # verifier blob: u64 length then encode_signed_stage_verifier bytes.
        verifier_bytes = encode_signed_stage_verifier(bundle.verifier)
        self.assertEqual(data[offset:offset + 8], u64(len(verifier_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(verifier_bytes)], verifier_bytes)
        offset += len(verifier_bytes)
        # auth batch blob: u64 length then encode_auth_batch bytes.
        batch_bytes = encode_auth_batch(
            bundle.items, hash_name=bundle.hash_name
        )
        self.assertEqual(data[offset:offset + 8], u64(len(batch_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(batch_bytes)], batch_bytes)
        offset += len(batch_bytes)
        self.assertEqual(offset, len(data))

    def test_layout_matches_blob_framing(self):
        bundle = _bundle(hash_name="sha3_256", indices=(1, 3))
        expected = (
            MAGIC
            + u64(1)
            + blob(encode_signed_stage_verifier(bundle.verifier))
            + blob(
                encode_auth_batch(bundle.items, hash_name=bundle.hash_name)
            )
        )
        self.assertEqual(encode_signed_stage_auth_bundle(bundle), expected)

    def test_blobs_are_exact_existing_encodings(self):
        bundle = _bundle(indices=(0, 2, 4))
        _, verifier_blob, batch_blob = _parse_blobs(
            encode_signed_stage_auth_bundle(bundle)
        )
        self.assertEqual(
            verifier_blob, encode_signed_stage_verifier(bundle.verifier)
        )
        self.assertEqual(
            batch_blob,
            encode_auth_batch(bundle.items, hash_name=bundle.hash_name),
        )
        # The inner blobs are independently decodable by the existing codecs.
        self.assertEqual(
            decode_signed_stage_verifier(verifier_blob), bundle.verifier
        )
        decoded_hash, decoded_items = decode_auth_batch(batch_blob)
        self.assertEqual(decoded_hash, bundle.hash_name)
        self.assertEqual(decoded_items, bundle.items)

    def test_empty_batch_layout(self):
        bundle = _bundle(indices=())
        data = encode_signed_stage_auth_bundle(bundle)
        _, verifier_blob, batch_blob = _parse_blobs(data)
        self.assertEqual(
            verifier_blob, encode_signed_stage_verifier(bundle.verifier)
        )
        # The empty batch keeps its own complete framing: no envelope
        # structure is omitted for zero items.
        self.assertEqual(
            batch_blob,
            encode_auth_batch((), hash_name=bundle.hash_name),
        )

    def test_encode_is_deterministic(self):
        bundle = _bundle()
        self.assertEqual(
            encode_signed_stage_auth_bundle(bundle),
            encode_signed_stage_auth_bundle(bundle),
        )

    def test_only_signed_stage_auth_bundle_accepted(self):
        bundle = _bundle()
        for bad in (
            None,
            1,
            "bundle",
            b"bytes",
            (),
            bundle.verifier,
            (bundle.verifier, bundle.hash_name, bundle.items),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_stage_auth_bundle(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        bundle = _bundle()
        for field, value in (
            ("verifier", "not-a-verifier"),
            ("hash_name", 1),
            ("items", list(bundle.items)),
        ):
            forged = SignedStageAuthBundle.__new__(SignedStageAuthBundle)
            object.__setattr__(forged, "verifier", bundle.verifier)
            object.__setattr__(forged, "hash_name", bundle.hash_name)
            object.__setattr__(forged, "items", bundle.items)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_signed_stage_auth_bundle(forged)

    def test_nested_verifier_type_error_propagates(self):
        bundle = _bundle()
        forged = SignedStageAuthBundle.__new__(SignedStageAuthBundle)
        object.__setattr__(forged, "verifier", "not-a-verifier")
        object.__setattr__(forged, "hash_name", bundle.hash_name)
        object.__setattr__(forged, "items", bundle.items)
        # The constructor re-validation classifies the wrong container
        # field as TypeError.
        with self.assertRaises(TypeError):
            encode_signed_stage_auth_bundle(forged)

    def test_nested_verifier_value_error_propagates(self):
        # A signed stage verifier carrying a 63-byte signature is
        # structurally invalid; built while bypassing the frozen
        # constructor (which would reject it) the outer container accepts
        # it, and the existing verifier encoder raises ValueError when it
        # re-validates.
        from auditchain import SignedStageVerifier

        bundle = _bundle()
        bad_verifier = SignedStageVerifier.__new__(SignedStageVerifier)
        object.__setattr__(bad_verifier, "version", bundle.verifier.version)
        object.__setattr__(
            bad_verifier, "verifier", bundle.verifier.verifier
        )
        object.__setattr__(
            bad_verifier, "signature", bundle.verifier.signature[:-1]
        )
        forged = SignedStageAuthBundle(
            bad_verifier, bundle.hash_name, bundle.items
        )
        with self.assertRaises(ValueError):
            encode_signed_stage_auth_bundle(forged)

    def test_nested_batch_value_error_propagates(self):
        # Non-consecutive tag stages make encode_auth_batch raise
        # ValueError, verbatim through the envelope.
        bundle = _bundle()
        forged = SignedStageAuthBundle(
            bundle.verifier,
            bundle.hash_name,
            (bundle.items[0], bundle.items[2]),
        )
        with self.assertRaises(ValueError):
            encode_signed_stage_auth_bundle(forged)

    def test_algorithm_mismatch_raises_value_error(self):
        # A bundle whose batch algorithm disagrees with the signed stage
        # verifier's algorithm can only be built by hand; encoding refuses
        # it from both ends.
        sha256 = _bundle(hash_name="sha256")
        sha512 = _bundle(hash_name="sha512")
        forged = SignedStageAuthBundle(
            sha256.verifier, "sha512", sha512.items
        )
        with self.assertRaises(ValueError):
            encode_signed_stage_auth_bundle(forged)
        forged = SignedStageAuthBundle(
            sha512.verifier, "sha256", sha256.items
        )
        with self.assertRaises(ValueError):
            encode_signed_stage_auth_bundle(forged)

    def test_no_new_signing_message(self):
        # The signed stage verifier rides along verbatim; its bytes are
        # exactly export_signed_stage_verifier's from the same state.
        # Encoding introduces no signature of its own.
        log = _log(evolve=2)
        receipt = log.export_signed_stage_verifier(_SEED_A)
        bundle = log.signed_stage_auth_bundle((0, 2), _SEED_A)
        _, verifier_blob, _ = _parse_blobs(
            encode_signed_stage_auth_bundle(bundle)
        )
        self.assertEqual(
            verifier_blob,
            encode_signed_stage_verifier(receipt),
        )

    def test_call_is_read_only(self):
        bundle = _bundle()
        snapshot = (bundle.verifier, bundle.hash_name, bundle.items)
        before = encode_signed_stage_auth_bundle(bundle)
        encode_signed_stage_auth_bundle(bundle)
        self.assertEqual(encode_signed_stage_auth_bundle(bundle), before)
        self.assertEqual(
            (bundle.verifier, bundle.hash_name, bundle.items), snapshot
        )
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.public_key),
            (True, True, True),
        )


class DecodeSignedStageAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.log = _log(records=7, evolve=1)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, bundle):
        data = encode_signed_stage_auth_bundle(bundle)
        decoded = decode_signed_stage_auth_bundle(data)
        self.assertIsInstance(decoded, SignedStageAuthBundle)
        self.assertEqual(decoded, bundle)
        self.assertEqual(decoded.verifier, bundle.verifier)
        self.assertEqual(decoded.hash_name, bundle.hash_name)
        self.assertEqual(decoded.items, bundle.items)
        self.assertIs(type(decoded.items), tuple)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(encode_signed_stage_auth_bundle(decoded), data)
        self.assertEqual(
            verify_signed_stage_auth_bundle(decoded, self.public_key),
            verify_signed_stage_auth_bundle(bundle, self.public_key),
        )
        return decoded

    def test_roundtrip(self):
        self.roundtrip(_bundle(indices=(0, 2, 4)))

    def test_roundtrip_single_item(self):
        self.roundtrip(_bundle(indices=(3,)))

    def test_roundtrip_empty_batch(self):
        decoded = self.roundtrip(_bundle(indices=()))
        self.assertEqual(decoded.items, ())
        self.assertEqual(
            verify_signed_stage_auth_bundle(decoded, self.public_key), ()
        )

    def test_roundtrip_later_stages(self):
        self.roundtrip(_bundle(evolve=3))
        self.roundtrip(_bundle(evolve=5, indices=(0, 1, 2)))

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            self.roundtrip(_bundle(hash_name=hash_name))

    def test_roundtrip_atomic_issuance(self):
        self.roundtrip(self.log.signed_stage_auth_bundle((4, 0, 2), _SEED_A))
        self.roundtrip(self.log.signed_stage_auth_bundle((), _SEED_A))

    def test_roundtrip_after_prune(self):
        log = _log(records=6, evolve=1)
        log.prune(2, log.seal(2))
        bundle = log.signed_stage_auth_bundle((5, 2), _SEED_A)
        self.roundtrip(bundle)

    def test_frozen(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        decoded = decode_signed_stage_auth_bundle(data)
        with self.assertRaises(FrozenInstanceError):
            decoded.verifier = decoded.verifier
        with self.assertRaises(FrozenInstanceError):
            decoded.hash_name = "sha512"
        with self.assertRaises(FrozenInstanceError):
            decoded.items = ()

    def test_persistence_across_process_boundary(self):
        bundle = _bundle(indices=(1, 3))
        data = encode_signed_stage_auth_bundle(bundle)
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_signed_stage_auth_bundle(bytes(data))
        self.assertEqual(restored, bundle)
        self.assertEqual(
            verify_signed_stage_auth_bundle(restored, self.public_key),
            (True, True),
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
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
                decode_signed_stage_auth_bundle(bad)

    def test_bad_magic(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            STAGE_MAGIC + data[len(MAGIC):],
            b"auditchain/signed-auth-bundle/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:40])):
                decode_signed_stage_auth_bundle(bad)

    def test_bad_version(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_signed_stage_auth_bundle(bad)

    def test_truncation(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_stage_auth_bundle(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_stage_auth_bundle(data[:cut])

    def test_truncated_empty_batch(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=()))
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_stage_auth_bundle(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_stage_auth_bundle(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_stage_auth_bundle(bad)

    def test_missing_second_blob(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        _, verifier_blob, _ = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC + u64(1) + blob(verifier_blob)
            )

    def test_extra_third_blob_rejected(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        _, verifier_blob, batch_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC
                + u64(1)
                + blob(verifier_blob)
                + blob(batch_blob)
                + blob(b"extra")
            )

    def test_swapped_blob_order_rejected(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        _, verifier_blob, batch_blob = _parse_blobs(data)
        swapped = (
            MAGIC
            + u64(1)
            + blob(batch_blob)
            + blob(verifier_blob)
        )
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(swapped)

    def test_garbage_verifier_blob_rejected(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        _, _, batch_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC + u64(1) + blob(b"hello") + blob(batch_blob)
            )

    def test_garbage_batch_blob_rejected(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        _, verifier_blob, _ = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC + u64(1) + blob(verifier_blob) + blob(b"hello")
            )

    def test_trailing_bytes_inside_blob_rejected(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        _, verifier_blob, batch_blob = _parse_blobs(data)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC
                + u64(1)
                + blob(verifier_blob + b"\x00")
                + blob(batch_blob)
            )
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC
                + u64(1)
                + blob(verifier_blob)
                + blob(batch_blob + b"\x00")
            )

    def test_nested_verifier_framing_error_rejected(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        _, verifier_blob, batch_blob = _parse_blobs(data)
        tampered = b"x" + verifier_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC + u64(1) + blob(tampered) + blob(batch_blob)
            )

    def test_nested_batch_framing_error_rejected(self):
        data = encode_signed_stage_auth_bundle(_bundle(indices=(1,)))
        _, verifier_blob, batch_blob = _parse_blobs(data)
        tampered = b"x" + batch_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC + u64(1) + blob(verifier_blob) + blob(tampered)
            )

    def test_algorithm_mismatch_between_blobs_rejected(self):
        # A genuinely encoded sha256 verifier paired with a genuinely
        # encoded sha512 auth batch: each nested blob is legal on its own,
        # but the two parts do not describe one delivery.
        sha256 = _bundle(hash_name="sha256")
        sha512 = _bundle(hash_name="sha512")
        verifier_blob = encode_signed_stage_verifier(sha256.verifier)
        batch_blob = encode_auth_batch(
            sha512.items, hash_name="sha512"
        )
        forged = (
            MAGIC
            + u64(1)
            + blob(verifier_blob)
            + blob(batch_blob)
        )
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(forged)

    def test_bad_signature_still_decodes_but_verifies_false(self):
        from auditchain import SignedStageVerifier

        bundle = _bundle()
        forged = SignedStageAuthBundle(
            SignedStageVerifier(
                bundle.verifier.version,
                bundle.verifier.verifier,
                b"\x00" * 64,
            ),
            bundle.hash_name,
            bundle.items,
        )
        decoded = decode_signed_stage_auth_bundle(
            encode_signed_stage_auth_bundle(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertEqual(
            verify_signed_stage_auth_bundle(decoded, self.public_key),
            (False, False, False),
        )

    def test_tampered_tag_still_decodes_but_verifies_false_at_position(self):
        from auditchain import AuthTag

        bundle = _bundle()
        entry, tag = bundle.items[1]
        bad_tag = AuthTag(tag.stage, bytes([tag.tag[0] ^ 1]) + tag.tag[1:])
        items = bundle.items[:1] + ((entry, bad_tag),) + bundle.items[2:]
        forged = SignedStageAuthBundle(
            bundle.verifier, bundle.hash_name, items
        )
        decoded = decode_signed_stage_auth_bundle(
            encode_signed_stage_auth_bundle(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertEqual(
            verify_signed_stage_auth_bundle(decoded, self.public_key),
            (True, False, True),
        )

    def test_wrong_key_decodes_but_verifies_false(self):
        bundle = _bundle(seed=_SEED_B)
        decoded = decode_signed_stage_auth_bundle(
            encode_signed_stage_auth_bundle(bundle)
        )
        self.assertEqual(
            verify_signed_stage_auth_bundle(decoded, self.public_key),
            (False, False, False),
        )
        self.assertEqual(
            verify_signed_stage_auth_bundle(
                decoded, self.other_public_key
            ),
            (True, True, True),
        )

    def test_empty_bundle_wrong_key_roundtrip_and_empty_verdict(self):
        bundle = _bundle(indices=(), seed=_SEED_B)
        decoded = decode_signed_stage_auth_bundle(
            encode_signed_stage_auth_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)
        self.assertEqual(
            verify_signed_stage_auth_bundle(decoded, self.public_key), ()
        )

    def test_call_is_read_only(self):
        bundle = _bundle(indices=(1, 2))
        data = encode_signed_stage_auth_bundle(bundle)
        decode_signed_stage_auth_bundle(data)
        self.assertEqual(decode_signed_stage_auth_bundle(data), bundle)


if __name__ == "__main__":
    unittest.main()
