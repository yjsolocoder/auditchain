import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    Entry,
    SignedAuthBundle,
    SignedVerifier,
    Verifier,
    decode_signed_auth_bundle,
    encode_auth_batch,
    encode_signed_auth_bundle,
    encode_signed_verifier,
    verify_auth_batch,
    verify_signed_auth_bundle,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAGIC = b"auditchain/signed-auth-bundle/v1\0"

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


def _bundle(seed=_SEED_A, key=_KEY, hash_name="sha256", indices=(0, 2, 4), records=5):
    # export_signed_verifier shares a one-shot export eligibility with
    # export_verifier, so every bundle needs a fresh stage-0 log.
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(records):
        log.append(f"record-{record}")
    receipt = log.export_signed_verifier(seed)
    items = log.auth_batch(indices)
    return SignedAuthBundle(receipt, hash_name, items)


class SignedAuthBundleTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        bundle = _bundle()
        again = SignedAuthBundle(bundle.verifier, bundle.hash_name, bundle.items)
        self.assertEqual(bundle, again)
        self.assertEqual(bundle.verifier, again.verifier)
        self.assertEqual(bundle.hash_name, "sha256")
        self.assertIsInstance(bundle.items, tuple)
        self.assertNotEqual(bundle, _bundle(indices=(1,)))

    def test_frozen(self):
        bundle = _bundle()
        for field in ("verifier", "hash_name", "items"):
            with self.assertRaises(Exception):
                setattr(bundle, field, None)

    def test_container_type_errors(self):
        bundle = _bundle()
        with self.assertRaises(TypeError):
            SignedAuthBundle("not-a-verifier", bundle.hash_name, bundle.items)
        with self.assertRaises(TypeError):
            SignedAuthBundle(bundle.verifier, 1, bundle.items)
        with self.assertRaises(TypeError):
            SignedAuthBundle(bundle.verifier, bundle.hash_name, list(bundle.items))

    def test_unknown_hash_name_raises_value_error(self):
        bundle = _bundle()
        with self.assertRaises(ValueError):
            SignedAuthBundle(bundle.verifier, "not-a-hash", bundle.items)


class VerifySignedAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_genuine_bundle_verifies_per_item(self):
        bundle = _bundle()
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key),
            (True, True, True),
        )

    def test_empty_bundle(self):
        bundle = _bundle(indices=())
        self.assertEqual(verify_signed_auth_bundle(bundle, self.public_key), ())
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.other_public_key), ()
        )

    def test_untrusted_public_key_fails_per_item(self):
        bundle = _bundle()
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.other_public_key),
            (False, False, False),
        )

    def test_tampered_signature_fails_per_item(self):
        bundle = _bundle()
        forged = SignedAuthBundle(
            SignedVerifier(1, bundle.verifier.verifier, b"\x00" * 64),
            bundle.hash_name,
            bundle.items,
        )
        self.assertEqual(
            verify_signed_auth_bundle(forged, self.public_key),
            (False, False, False),
        )

    def test_tampered_tag_fails_at_its_position(self):
        bundle = _bundle()
        entry, tag = bundle.items[1]
        bad_tag = AuthTag(tag.stage, bytes([tag.tag[0] ^ 1]) + tag.tag[1:])
        items = bundle.items[:1] + ((entry, bad_tag),) + bundle.items[2:]
        forged = SignedAuthBundle(bundle.verifier, bundle.hash_name, items)
        self.assertEqual(
            verify_signed_auth_bundle(forged, self.public_key),
            (True, False, True),
        )

    def test_tampered_entry_fails_at_its_position(self):
        bundle = _bundle()
        entry, tag = bundle.items[0]
        bad_entry = Entry(
            entry.index, b"forged", entry.previous_hash, entry.entry_hash
        )
        items = ((bad_entry, tag),) + bundle.items[1:]
        forged = SignedAuthBundle(bundle.verifier, bundle.hash_name, items)
        results = verify_signed_auth_bundle(forged, self.public_key)
        self.assertEqual(results[0], False)
        self.assertEqual(results[1:], (True, True))

    def test_hash_name_mismatch_fails_per_item(self):
        # A bundle whose batch algorithm disagrees with the signed verifier's
        # algorithm can only be built by hand (decode rejects it); every item
        # fails rather than raising.
        bundle = _bundle()
        forged = SignedAuthBundle(bundle.verifier, "sha512", bundle.items)
        self.assertEqual(
            verify_signed_auth_bundle(forged, self.public_key),
            (False, False, False),
        )

    def test_type_errors(self):
        for bad in (None, "bundle", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                verify_signed_auth_bundle(bad, self.public_key)
        bundle = _bundle()
        for bad_key in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError):
                verify_signed_auth_bundle(bundle, bad_key)

    def test_public_key_length_raises_value_error(self):
        bundle = _bundle()
        for bad_key in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                verify_signed_auth_bundle(bundle, bad_key)

    def test_bypassed_container_fields_raise_type_error(self):
        bundle = _bundle()
        for field, value in (
            ("verifier", "not-a-verifier"),
            ("hash_name", 1),
            ("items", list(bundle.items)),
        ):
            forged = SignedAuthBundle.__new__(SignedAuthBundle)
            object.__setattr__(forged, "verifier", bundle.verifier)
            object.__setattr__(forged, "hash_name", bundle.hash_name)
            object.__setattr__(forged, "items", bundle.items)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                verify_signed_auth_bundle(forged, self.public_key)

    def test_structurally_invalid_items_raise(self):
        bundle = _bundle()
        entry, tag = bundle.items[0]
        bad_tag = AuthTag(tag.stage, tag.tag[:-1])  # wrong digest width
        forged = SignedAuthBundle(
            bundle.verifier,
            bundle.hash_name,
            ((entry, bad_tag),) + bundle.items[1:],
        )
        with self.assertRaises(ValueError):
            verify_signed_auth_bundle(forged, self.public_key)

    def test_call_is_read_only(self):
        bundle = _bundle()
        before = encode_signed_auth_bundle(bundle)
        verify_signed_auth_bundle(bundle, self.public_key)
        self.assertEqual(encode_signed_auth_bundle(bundle), before)


class EncodeSignedAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_byte_layout(self):
        bundle = _bundle()
        expected = (
            MAGIC
            + u64(1)
            + blob(encode_signed_verifier(bundle.verifier))
            + blob(encode_auth_batch(bundle.items, hash_name=bundle.hash_name))
        )
        self.assertEqual(encode_signed_auth_bundle(bundle), expected)

    def test_encode_is_deterministic(self):
        bundle = _bundle()
        self.assertEqual(
            encode_signed_auth_bundle(bundle), encode_signed_auth_bundle(bundle)
        )

    def test_type_errors(self):
        for bad in (None, "bundle", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                encode_signed_auth_bundle(bad)

    def test_bypassed_container_fields_raise_type_error(self):
        bundle = _bundle()
        for field, value in (
            ("verifier", "not-a-verifier"),
            ("hash_name", 1),
            ("items", list(bundle.items)),
        ):
            forged = SignedAuthBundle.__new__(SignedAuthBundle)
            object.__setattr__(forged, "verifier", bundle.verifier)
            object.__setattr__(forged, "hash_name", bundle.hash_name)
            object.__setattr__(forged, "items", bundle.items)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                encode_signed_auth_bundle(forged)

    def test_nested_structural_errors_propagate(self):
        bundle = _bundle()
        verifier = SignedVerifier.__new__(SignedVerifier)
        object.__setattr__(verifier, "version", 2)
        object.__setattr__(verifier, "verifier", bundle.verifier.verifier)
        object.__setattr__(verifier, "signature", bundle.verifier.signature)
        forged = SignedAuthBundle.__new__(SignedAuthBundle)
        object.__setattr__(forged, "verifier", verifier)
        object.__setattr__(forged, "hash_name", bundle.hash_name)
        object.__setattr__(forged, "items", bundle.items)
        with self.assertRaises(ValueError):
            encode_signed_auth_bundle(forged)

    def test_call_is_read_only(self):
        bundle = _bundle()
        before = encode_signed_auth_bundle(bundle)
        encode_signed_auth_bundle(bundle)
        self.assertEqual(encode_signed_auth_bundle(bundle), before)
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key),
            (True, True, True),
        )


class DecodeSignedAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, bundle):
        data = encode_signed_auth_bundle(bundle)
        decoded = decode_signed_auth_bundle(data)
        self.assertEqual(decoded, bundle)
        self.assertEqual(decoded.verifier, bundle.verifier)
        self.assertEqual(decoded.hash_name, bundle.hash_name)
        self.assertEqual(decoded.items, bundle.items)
        self.assertIsInstance(decoded.items, tuple)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_signed_auth_bundle(decoded), data)
        return decoded

    def test_roundtrip(self):
        bundle = self.roundtrip(_bundle())
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key),
            (True, True, True),
        )

    def test_roundtrip_empty_batch(self):
        bundle = self.roundtrip(_bundle(indices=()))
        self.assertEqual(bundle.items, ())
        self.assertEqual(verify_signed_auth_bundle(bundle, self.public_key), ())

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            bundle = self.roundtrip(_bundle(hash_name=hash_name))
            self.assertEqual(bundle.hash_name, hash_name)
            self.assertEqual(
                verify_signed_auth_bundle(bundle, self.public_key),
                (True, True, True),
            )

    def test_persistence_across_process_boundary(self):
        data = encode_signed_auth_bundle(_bundle())
        # A fresh byte sequence (as read back from disk or a socket) decodes
        # into a bundle that still verifies against the pre-trusted key, and
        # the delivered verifier authenticates the items exactly as
        # verify_auth_batch would.
        restored = decode_signed_auth_bundle(bytes(data))
        self.assertEqual(restored, _bundle())
        self.assertEqual(
            verify_signed_auth_bundle(restored, self.public_key),
            verify_auth_batch(restored.items, restored.verifier.verifier),
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_auth_bundle(_bundle())
        for bad in (bytearray(data), memoryview(data), "text", None, 1, ()):
            with self.assertRaises(TypeError):
                decode_signed_auth_bundle(bad)

    def test_bad_magic(self):
        data = encode_signed_auth_bundle(_bundle())
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(b"")
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(MAGIC[:-1])
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                b"auditchain/signed-verifier/v1\0" + data[len(MAGIC):]
            )

    def test_bad_version(self):
        bundle = _bundle()
        data = MAGIC + u64(2) + encode_signed_auth_bundle(bundle)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(data)

    def test_truncation(self):
        data = encode_signed_auth_bundle(_bundle())
        for cut in (
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError):
                decode_signed_auth_bundle(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_signed_auth_bundle(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_auth_bundle(_bundle())
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                decode_signed_auth_bundle(data + extra)

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"x" * 16
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(data)

    def test_illegal_nested_encodings(self):
        bundle = _bundle()
        verifier_blob = encode_signed_verifier(bundle.verifier)
        batch_blob = encode_auth_batch(bundle.items, hash_name=bundle.hash_name)
        # Garbage inside the verifier blob.
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                MAGIC + u64(1) + blob(b"garbage") + blob(batch_blob)
            )
        # Garbage inside the auth-batch blob.
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                MAGIC + u64(1) + blob(verifier_blob) + blob(b"garbage")
            )
        # The two blobs swapped.
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                MAGIC + u64(1) + blob(batch_blob) + blob(verifier_blob)
            )

    def test_nested_hash_algorithm_mismatch(self):
        bundle = _bundle()
        verifier_blob = encode_signed_verifier(bundle.verifier)
        # A structurally valid auth batch under a different hash algorithm
        # than the signed verifier's.
        other_batch = encode_auth_batch((), hash_name="sha512")
        data = MAGIC + u64(1) + blob(verifier_blob) + blob(other_batch)
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(data)

    def test_wrong_signature_decodes_but_verifies_false_per_item(self):
        bundle = _bundle()
        forged_verifier = SignedVerifier(
            1, bundle.verifier.verifier, b"\x00" * 64
        )
        data = (
            MAGIC
            + u64(1)
            + blob(encode_signed_verifier(forged_verifier))
            + blob(encode_auth_batch(bundle.items, hash_name=bundle.hash_name))
        )
        decoded = decode_signed_auth_bundle(data)
        self.assertEqual(decoded.verifier.signature, b"\x00" * 64)
        self.assertEqual(
            verify_signed_auth_bundle(decoded, self.public_key),
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
            + blob(encode_signed_verifier(bundle.verifier))
            + blob(encode_auth_batch(items, hash_name=bundle.hash_name))
        )
        decoded = decode_signed_auth_bundle(data)
        self.assertEqual(
            verify_signed_auth_bundle(decoded, self.public_key),
            (True, False, True),
        )

    def test_wrong_key_roundtrip_verifies_false(self):
        data = encode_signed_auth_bundle(_bundle(seed=_SEED_B))
        decoded = decode_signed_auth_bundle(data)
        self.assertEqual(
            verify_signed_auth_bundle(decoded, self.public_key),
            (False, False, False),
        )
        self.assertEqual(
            verify_signed_auth_bundle(decoded, self.other_public_key),
            (True, True, True),
        )

    def test_call_is_read_only(self):
        bundle = _bundle()
        data = encode_signed_auth_bundle(bundle)
        decode_signed_auth_bundle(data)
        self.assertEqual(encode_signed_auth_bundle(bundle), data)


if __name__ == "__main__":
    unittest.main()
