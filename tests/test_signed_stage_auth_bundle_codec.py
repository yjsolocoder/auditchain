import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    SignedStageAuthBundle,
    SignedStageVerifier,
    decode_signed_stage_auth_bundle,
    encode_auth_batch,
    encode_signed_stage_auth_bundle,
    encode_signed_stage_verifier,
    verify_signed_stage_auth_bundle,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAGIC = b"auditchain/signed-stage-auth-bundle/v1\0"

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


def _log(records=5, key=_KEY, hash_name="sha256", evolve=1):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(records):
        log.append(f"record-{record}")
    for _ in range(evolve):
        log.rotate_key()
    return log


def _bundle(seed=_SEED_A, key=_KEY, hash_name="sha256", indices=(0, 2, 4),
            records=5, evolve=1):
    log = _log(records=records, key=key, hash_name=hash_name, evolve=evolve)
    receipt = log.export_signed_stage_verifier(seed)
    items = log.auth_batch(indices)
    return SignedStageAuthBundle(receipt, hash_name, items)


class EncodeSignedStageAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_byte_layout(self):
        bundle = _bundle()
        expected = (
            MAGIC
            + u64(1)
            + blob(encode_signed_stage_verifier(bundle.verifier))
            + blob(encode_auth_batch(bundle.items, hash_name=bundle.hash_name))
        )
        data = encode_signed_stage_auth_bundle(bundle)
        self.assertEqual(data, expected)
        self.assertTrue(data.startswith(MAGIC + u64(1)))
        self.assertEqual(len(MAGIC), len(b"auditchain/signed-stage-auth-bundle/v1") + 1)

    def test_empty_batch_round_trips_its_structure(self):
        bundle = _bundle(indices=())
        data = encode_signed_stage_auth_bundle(bundle)
        decoded = decode_signed_stage_auth_bundle(data)
        self.assertEqual(decoded, bundle)
        self.assertEqual(decoded.items, ())
        self.assertEqual(encode_signed_stage_auth_bundle(decoded), data)

    def test_encode_is_deterministic(self):
        bundle = _bundle()
        self.assertEqual(
            encode_signed_stage_auth_bundle(bundle),
            encode_signed_stage_auth_bundle(bundle),
        )

    def test_type_errors(self):
        for bad in (None, "bundle", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                encode_signed_stage_auth_bundle(bad)

    def test_bypassed_container_fields_raise_type_error(self):
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

    def test_nested_structural_errors_propagate(self):
        bundle = _bundle()
        verifier = SignedStageVerifier.__new__(SignedStageVerifier)
        object.__setattr__(verifier, "version", 2)
        object.__setattr__(verifier, "verifier", bundle.verifier.verifier)
        object.__setattr__(verifier, "signature", bundle.verifier.signature)
        forged = SignedStageAuthBundle.__new__(SignedStageAuthBundle)
        object.__setattr__(forged, "verifier", verifier)
        object.__setattr__(forged, "hash_name", bundle.hash_name)
        object.__setattr__(forged, "items", bundle.items)
        with self.assertRaises(ValueError):
            encode_signed_stage_auth_bundle(forged)

    def test_algorithm_mismatch_raises_value_error(self):
        # A bundle whose batch algorithm disagrees with the signed stage
        # material's algorithm can only be built by hand; encoding rejects
        # it at both ends rather than emitting an undeliverable artifact.
        bundle = _bundle()
        forged = SignedStageAuthBundle(bundle.verifier, "sha512", ())
        with self.assertRaises(ValueError):
            encode_signed_stage_auth_bundle(forged)

    def test_call_is_read_only(self):
        bundle = _bundle()
        before = encode_signed_stage_auth_bundle(bundle)
        encode_signed_stage_auth_bundle(bundle)
        self.assertEqual(encode_signed_stage_auth_bundle(bundle), before)
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.public_key),
            (True, True, True),
        )


class DecodeSignedStageAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, bundle):
        data = encode_signed_stage_auth_bundle(bundle)
        decoded = decode_signed_stage_auth_bundle(data)
        self.assertEqual(decoded, bundle)
        self.assertEqual(decoded.verifier, bundle.verifier)
        self.assertEqual(decoded.hash_name, bundle.hash_name)
        self.assertEqual(decoded.items, bundle.items)
        self.assertIsInstance(decoded.items, tuple)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_signed_stage_auth_bundle(decoded), data)
        return decoded

    def test_roundtrip(self):
        bundle = self.roundtrip(_bundle())
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.public_key),
            (True, True, True),
        )

    def test_roundtrip_empty_batch(self):
        bundle = self.roundtrip(_bundle(indices=()))
        self.assertEqual(bundle.items, ())
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.public_key), ()
        )

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            bundle = self.roundtrip(_bundle(hash_name=hash_name))
            self.assertEqual(bundle.hash_name, hash_name)
            self.assertEqual(
                verify_signed_stage_auth_bundle(bundle, self.public_key),
                (True, True, True),
            )

    def test_persistence_across_process_boundary(self):
        data = encode_signed_stage_auth_bundle(_bundle())
        # A fresh byte sequence (as read back from disk or a socket) decodes
        # into a bundle equal to the original and still verified offline.
        restored = decode_signed_stage_auth_bundle(bytes(data))
        self.assertEqual(restored, _bundle())
        self.assertEqual(
            verify_signed_stage_auth_bundle(restored, self.public_key),
            (True, True, True),
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_stage_auth_bundle(_bundle())
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_signed_stage_auth_bundle(bad)

    def test_bad_magic(self):
        data = encode_signed_stage_auth_bundle(_bundle())
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(b"")
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(MAGIC[:-1])
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                b"auditchain/signed-auth-bundle/v1\0" + data[len(MAGIC):]
            )
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                b"auditchain/signed-stage/v1\0" + data[len(MAGIC):]
            )

    def test_bad_version(self):
        bundle = _bundle()
        data = MAGIC + u64(2) + encode_signed_stage_auth_bundle(bundle)[
            len(MAGIC) + 8:
        ]
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(data)

    def test_truncation(self):
        data = encode_signed_stage_auth_bundle(_bundle())
        for cut in (
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError):
                decode_signed_stage_auth_bundle(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_signed_stage_auth_bundle(data[:cut])

    def test_empty_batch_is_not_truncated(self):
        # An empty batch keeps both length-prefixed blobs; no structure is
        # omitted for zero items.
        bundle = _bundle(indices=())
        data = encode_signed_stage_auth_bundle(bundle)
        decoded = decode_signed_stage_auth_bundle(data)
        self.assertEqual(decoded.items, ())

    def test_trailing_bytes(self):
        data = encode_signed_stage_auth_bundle(_bundle())
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_signed_stage_auth_bundle(data + extra)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"x" * 16
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(data)

    def test_illegal_nested_encodings(self):
        bundle = _bundle()
        verifier_blob = encode_signed_stage_verifier(bundle.verifier)
        batch_blob = encode_auth_batch(
            bundle.items, hash_name=bundle.hash_name
        )
        # Garbage inside the signed-stage-material blob.
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC + u64(1) + blob(b"garbage") + blob(batch_blob)
            )
        # Garbage inside the auth-batch blob.
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC + u64(1) + blob(verifier_blob) + blob(b"garbage")
            )
        # The two blobs swapped.
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(
                MAGIC + u64(1) + blob(batch_blob) + blob(verifier_blob)
            )

    def test_nested_hash_algorithm_mismatch(self):
        bundle = _bundle()
        verifier_blob = encode_signed_stage_verifier(bundle.verifier)
        # A structurally valid auth batch under a different hash algorithm
        # than the signed stage material's.
        other_batch = encode_auth_batch((), hash_name="sha512")
        data = MAGIC + u64(1) + blob(verifier_blob) + blob(other_batch)
        with self.assertRaises(ValueError):
            decode_signed_stage_auth_bundle(data)

    def test_wrong_signature_decodes_but_verifies_false_per_item(self):
        bundle = _bundle()
        forged_verifier = SignedStageVerifier(
            1, bundle.verifier.verifier, b"\x00" * 64
        )
        data = (
            MAGIC
            + u64(1)
            + blob(encode_signed_stage_verifier(forged_verifier))
            + blob(encode_auth_batch(bundle.items, hash_name=bundle.hash_name))
        )
        decoded = decode_signed_stage_auth_bundle(data)
        self.assertEqual(decoded.verifier.signature, b"\x00" * 64)
        self.assertEqual(
            verify_signed_stage_auth_bundle(decoded, self.public_key),
            (False, False, False),
        )

    def test_tampered_tag_decodes_but_verifies_false(self):
        bundle = _bundle()
        entry, tag = bundle.items[1]
        bad_tag = AuthTag(tag.stage, bytes([tag.tag[0] ^ 1]) + tag.tag[1:])
        items = bundle.items[:1] + ((entry, bad_tag),) + bundle.items[2:]
        data = (
            MAGIC
            + u64(1)
            + blob(encode_signed_stage_verifier(bundle.verifier))
            + blob(encode_auth_batch(items, hash_name=bundle.hash_name))
        )
        decoded = decode_signed_stage_auth_bundle(data)
        self.assertEqual(
            verify_signed_stage_auth_bundle(decoded, self.public_key),
            (True, False, True),
        )

    def test_wrong_key_roundtrip_verifies_false(self):
        data = encode_signed_stage_auth_bundle(_bundle(seed=_SEED_B))
        decoded = decode_signed_stage_auth_bundle(data)
        self.assertEqual(
            verify_signed_stage_auth_bundle(decoded, self.public_key),
            (False, False, False),
        )
        self.assertEqual(
            verify_signed_stage_auth_bundle(decoded, self.other_public_key),
            (True, True, True),
        )

    def test_verification_conclusions_match_original(self):
        # The restored bundle must give byte-identical per-item conclusions
        # against both keys compared with the original.
        bundle = _bundle()
        restored = decode_signed_stage_auth_bundle(
            encode_signed_stage_auth_bundle(bundle)
        )
        for key in (self.public_key, self.other_public_key):
            self.assertEqual(
                verify_signed_stage_auth_bundle(restored, key),
                verify_signed_stage_auth_bundle(bundle, key),
            )

    def test_call_is_read_only(self):
        bundle = _bundle()
        data = encode_signed_stage_auth_bundle(bundle)
        decode_signed_stage_auth_bundle(data)
        self.assertEqual(encode_signed_stage_auth_bundle(bundle), data)


if __name__ == "__main__":
    unittest.main()
