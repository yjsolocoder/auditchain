import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    AuthTag,
    SignedAuthBundle,
    SignedVerifier,
    decode_auth_batch,
    decode_signed_auth_bundle,
    decode_signed_verifier,
    encode_auth_batch,
    encode_signed_auth_bundle,
    encode_signed_verifier,
    verify_signed_auth_bundle,
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


def _make_bundle(indices=(1, 3), *, key=_KEY, seed=_SEED_A, hash_name="sha256"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in ("a", "b", "c", "d", "e"):
        log.append(record)
    receipt = log.export_signed_verifier(seed)
    items = log.auth_batch(list(indices))
    return log, receipt, items, SignedAuthBundle(receipt, hash_name, items)


def _parse_blobs(data):
    """Split an envelope into (version, verifier_blob, auth_batch_blob)."""
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
    auth_batch_blob = data[offset:offset + length]
    offset += length
    assert offset == len(data)
    return version, verifier_blob, auth_batch_blob


class EncodeSignedAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.log, self.receipt, self.items, self.bundle = _make_bundle(
            (1, 3)
        )

    def test_magic_and_field_layout(self):
        data = encode_signed_auth_bundle(self.bundle)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        verifier_bytes = encode_signed_verifier(self.receipt)
        self.assertEqual(data[offset:offset + 8], u64(len(verifier_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(verifier_bytes)], verifier_bytes)
        offset += len(verifier_bytes)
        auth_batch_bytes = encode_auth_batch(self.items, hash_name="sha256")
        self.assertEqual(data[offset:offset + 8], u64(len(auth_batch_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(auth_batch_bytes)], auth_batch_bytes)
        offset += len(auth_batch_bytes)
        self.assertEqual(offset, len(data))

    def test_blobs_are_exact_existing_encodings(self):
        _, verifier_blob, auth_batch_blob = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        self.assertEqual(verifier_blob, encode_signed_verifier(self.receipt))
        self.assertEqual(
            auth_batch_blob,
            encode_auth_batch(self.items, hash_name="sha256"),
        )
        # The inner blobs are independently decodable by the existing codecs.
        self.assertEqual(decode_signed_verifier(verifier_blob), self.receipt)
        self.assertEqual(
            decode_auth_batch(auth_batch_blob), ("sha256", self.items)
        )

    def test_encode_is_deterministic(self):
        self.assertEqual(
            encode_signed_auth_bundle(self.bundle),
            encode_signed_auth_bundle(self.bundle),
        )

    def test_no_new_signing_message(self):
        # The SignedVerifier rides along verbatim; its bytes are exactly
        # export_signed_verifier's. The envelope introduces no signature.
        _, verifier_blob, _ = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        self.assertEqual(verifier_blob, encode_signed_verifier(self.receipt))

    def test_empty_items(self):
        bundle = SignedAuthBundle(self.receipt, "sha256", ())
        data = encode_signed_auth_bundle(bundle)
        _, verifier_blob, auth_batch_blob = _parse_blobs(data)
        self.assertEqual(verifier_blob, encode_signed_verifier(self.receipt))
        self.assertEqual(
            auth_batch_blob, encode_auth_batch((), hash_name="sha256")
        )

    def test_alternate_hash_name_flows_into_auth_blob(self):
        log = AuditLog(key=_KEY, hash_name="sha512")
        log.append("a")
        receipt = log.export_signed_verifier(_SEED_A)
        items = log.auth_batch([0])
        bundle = SignedAuthBundle(receipt, "sha512", items)
        _, verifier_blob, auth_batch_blob = _parse_blobs(
            encode_signed_auth_bundle(bundle)
        )
        self.assertEqual(decode_signed_verifier(verifier_blob), receipt)
        self.assertEqual(decode_auth_batch(auth_batch_blob), ("sha512", items))

    def test_only_signed_auth_bundle_accepted(self):
        for bad in (
            None,
            1,
            "bundle",
            b"bytes",
            (),
            (self.receipt, "sha256", self.items),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signed_auth_bundle(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        for field, value in (
            ("verifier", None),
            ("hash_name", 1),
            ("items", None),
        ):
            forged = SignedAuthBundle.__new__(SignedAuthBundle)
            object.__setattr__(
                forged,
                "verifier",
                self.receipt if field != "verifier" else value,
            )
            object.__setattr__(
                forged,
                "hash_name",
                "sha256" if field != "hash_name" else value,
            )
            object.__setattr__(
                forged,
                "items",
                self.items if field != "items" else value,
            )
            with self.assertRaises(TypeError, msg=field):
                encode_signed_auth_bundle(forged)

    def test_items_not_a_tuple_type_error(self):
        forged = SignedAuthBundle.__new__(SignedAuthBundle)
        object.__setattr__(forged, "verifier", self.receipt)
        object.__setattr__(forged, "hash_name", "sha256")
        object.__setattr__(forged, "items", list(self.items))
        with self.assertRaises(TypeError):
            encode_signed_auth_bundle(forged)

    def test_algorithm_mismatch_value_error(self):
        log512 = AuditLog(key=_KEY, hash_name="sha512")
        receipt512 = log512.export_signed_verifier(_SEED_A)
        with self.assertRaises(ValueError):
            encode_signed_auth_bundle(
                SignedAuthBundle(receipt512, "sha256", ())
            )

    def test_unknown_hash_name_value_error(self):
        with self.assertRaises(ValueError):
            encode_signed_auth_bundle(
                SignedAuthBundle(self.receipt, "not-a-hash", ())
            )

    def test_nested_items_value_error_propagates(self):
        # Non-consecutive tag stages are rejected by encode_auth_batch.
        entry, tag = self.items[0]
        bad_items = (
            (entry, AuthTag(0, tag.tag)),
            (self.items[1][0], AuthTag(7, self.items[1][1].tag)),
        )
        bundle = SignedAuthBundle(self.receipt, "sha256", bad_items)
        with self.assertRaises(ValueError):
            encode_signed_auth_bundle(bundle)

    def test_bad_signature_still_encodes(self):
        bogus = SignedVerifier(
            self.receipt.version,
            self.receipt.verifier,
            b"\x00" * 64,
        )
        bundle = SignedAuthBundle(bogus, "sha256", self.items)
        data = encode_signed_auth_bundle(bundle)
        self.assertEqual(decode_signed_auth_bundle(data), bundle)

    def test_call_is_read_only(self):
        before = encode_signed_auth_bundle(self.bundle)
        encode_signed_auth_bundle(self.bundle)
        self.assertEqual(encode_signed_auth_bundle(self.bundle), before)


class DecodeSignedAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.log, self.receipt, self.items, self.bundle = _make_bundle(
            (0, 2, 4)
        )
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, bundle, public_key=None):
        data = encode_signed_auth_bundle(bundle)
        decoded = decode_signed_auth_bundle(data)
        self.assertIsInstance(decoded, SignedAuthBundle)
        self.assertEqual(decoded, bundle)
        self.assertEqual(decoded.verifier, bundle.verifier)
        self.assertEqual(decoded.hash_name, bundle.hash_name)
        self.assertEqual(decoded.items, bundle.items)
        self.assertIs(type(decoded.items), tuple)
        self.assertEqual(encode_signed_auth_bundle(decoded), data)
        if public_key is not None:
            self.assertEqual(
                verify_signed_auth_bundle(decoded, public_key),
                verify_signed_auth_bundle(bundle, public_key),
            )
        return decoded

    def test_roundtrip_variants(self):
        for indices in ([0], [1, 3], [0, 2, 4], (), range(5)):
            _, receipt, items, bundle = _make_bundle(indices)
            self.roundtrip(bundle, self.public_key)

    def test_roundtrip_empty_log_empty_batch(self):
        log = AuditLog(key=_KEY)
        receipt = log.export_signed_verifier(_SEED_A)
        bundle = SignedAuthBundle(receipt, "sha256", ())
        self.roundtrip(bundle, self.public_key)
        self.assertEqual(
            verify_signed_auth_bundle(
                decode_signed_auth_bundle(encode_signed_auth_bundle(bundle)),
                self.public_key,
            ),
            (),
        )

    def test_roundtrip_after_prune(self):
        log = AuditLog(key=_KEY)
        for i in range(6):
            log.append(f"r{i}")
        receipt = log.export_signed_verifier(_SEED_A)
        log.prune(2, log.seal(2))
        items = log.auth_batch([2, 4])
        bundle = SignedAuthBundle(receipt, "sha256", items)
        self.roundtrip(bundle, self.public_key)

    def test_roundtrip_alternate_hash(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(key=_KEY, hash_name=hash_name)
            for record in ("a", "b", "c"):
                log.append(record)
            receipt = log.export_signed_verifier(_SEED_A)
            items = log.auth_batch([0, 2])
            bundle = SignedAuthBundle(receipt, hash_name, items)
            self.roundtrip(bundle, self.public_key)

    def test_roundtrip_with_prior_key_rotation(self):
        log = AuditLog(key=_KEY)
        for record in ("a", "b", "c"):
            log.append(record)
        # The verifier is still exported at stage 0; the batch is minted
        # later at higher stages and still verifies against it.
        receipt = log.export_signed_verifier(_SEED_A)
        log.rotate_key()
        items = log.auth_batch([1, 2])
        self.assertEqual([tag.stage for _, tag in items], [1, 2])
        bundle = SignedAuthBundle(receipt, "sha256", items)
        self.roundtrip(bundle, self.public_key)

    def test_frozen(self):
        decoded = decode_signed_auth_bundle(
            encode_signed_auth_bundle(self.bundle)
        )
        with self.assertRaises(FrozenInstanceError):
            decoded.verifier = decoded.verifier
        with self.assertRaises(FrozenInstanceError):
            decoded.hash_name = "sha512"
        with self.assertRaises(FrozenInstanceError):
            decoded.items = ()

    def test_persistence_across_process_boundary(self):
        data = encode_signed_auth_bundle(self.bundle)
        restored = decode_signed_auth_bundle(bytes(data))
        self.assertEqual(restored, self.bundle)
        self.assertEqual(
            verify_signed_auth_bundle(restored, self.public_key),
            (True, True, True),
        )

    def test_only_bytes_accepted(self):
        data = encode_signed_auth_bundle(self.bundle)
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
                decode_signed_auth_bundle(bad)

    def test_bad_magic(self):
        data = encode_signed_auth_bundle(self.bundle)
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/signed-verifier/v1\0" + data[len(MAGIC):],
            b"auditchain/auth-batch/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-audit-batch/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:32])):
                decode_signed_auth_bundle(bad)

    def test_bad_version(self):
        _, verifier_blob, auth_batch_blob = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = (
                MAGIC
                + u64(version)
                + blob(verifier_blob)
                + blob(auth_batch_blob)
            )
            with self.assertRaises(ValueError, msg=version):
                decode_signed_auth_bundle(bad)

    def test_truncation(self):
        data = encode_signed_auth_bundle(self.bundle)
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_auth_bundle(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_signed_auth_bundle(data[:cut])

    def test_trailing_bytes(self):
        data = encode_signed_auth_bundle(self.bundle)
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_signed_auth_bundle(data + extra)

    def test_oversized_blob_length(self):
        _, verifier_blob, auth_batch_blob = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        for bad in (
            MAGIC + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + blob(verifier_blob) + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_signed_auth_bundle(bad)

    def test_missing_second_blob(self):
        _, verifier_blob, _ = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                MAGIC + u64(1) + blob(verifier_blob)
            )

    def test_swapped_blob_order_rejected(self):
        _, verifier_blob, auth_batch_blob = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        swapped = (
            MAGIC
            + u64(1)
            + blob(auth_batch_blob)
            + blob(verifier_blob)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(swapped)

    def test_garbage_verifier_blob_rejected(self):
        _, _, auth_batch_blob = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                MAGIC + u64(1) + blob(b"hello") + blob(auth_batch_blob)
            )

    def test_garbage_auth_batch_blob_rejected(self):
        _, verifier_blob, _ = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                MAGIC + u64(1) + blob(verifier_blob) + blob(b"hello")
            )

    def test_trailing_bytes_inside_blob_rejected(self):
        _, verifier_blob, auth_batch_blob = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                MAGIC
                + u64(1)
                + blob(verifier_blob + b"\x00")
                + blob(auth_batch_blob)
            )
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                MAGIC
                + u64(1)
                + blob(verifier_blob)
                + blob(auth_batch_blob + b"\x00")
            )

    def test_nested_verifier_framing_error_rejected(self):
        _, verifier_blob, auth_batch_blob = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        tampered = b"x" + verifier_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                MAGIC + u64(1) + blob(tampered) + blob(auth_batch_blob)
            )

    def test_nested_auth_batch_framing_error_rejected(self):
        _, verifier_blob, auth_batch_blob = _parse_blobs(
            encode_signed_auth_bundle(self.bundle)
        )
        tampered = b"x" + auth_batch_blob[1:]
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(
                MAGIC + u64(1) + blob(verifier_blob) + blob(tampered)
            )

    def test_cross_part_algorithm_mismatch_rejected(self):
        # A sha512 SignedVerifier paired with a sha256 auth batch must not
        # decode, even though both nested blobs are individually valid.
        log512 = AuditLog(key=_KEY, hash_name="sha512")
        log512.append("a")
        verifier512 = log512.export_signed_verifier(_SEED_A)
        verifier_blob = encode_signed_verifier(verifier512)
        auth_batch_blob = encode_auth_batch(self.items, hash_name="sha256")
        raw = MAGIC + u64(1) + blob(verifier_blob) + blob(auth_batch_blob)
        with self.assertRaises(ValueError):
            decode_signed_auth_bundle(raw)

    def test_bad_signature_still_decodes_but_verifies_false(self):
        bogus = SignedVerifier(
            self.receipt.version,
            self.receipt.verifier,
            b"\x00" * 64,
        )
        bundle = SignedAuthBundle(bogus, "sha256", self.items)
        decoded = decode_signed_auth_bundle(
            encode_signed_auth_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)
        self.assertEqual(
            verify_signed_auth_bundle(decoded, self.public_key),
            (False, False, False),
        )

    def test_wrong_key_decodes_but_verifies_false(self):
        _, receipt, items, _ = _make_bundle((0, 2, 4), seed=_SEED_B)
        bundle = SignedAuthBundle(receipt, "sha256", items)
        decoded = decode_signed_auth_bundle(
            encode_signed_auth_bundle(bundle)
        )
        self.assertEqual(
            verify_signed_auth_bundle(decoded, self.public_key),
            (False, False, False),
        )
        self.assertEqual(
            verify_signed_auth_bundle(decoded, self.other_public_key),
            (True, True, True),
        )

    def test_tampered_tag_still_decodes_but_that_item_false(self):
        entry, tag = self.items[0]
        replacement = b"\x00" * len(tag.tag)
        if replacement == tag.tag:
            replacement = b"\x01" * len(tag.tag)
        forged_items = ((entry, AuthTag(tag.stage, replacement)),) + self.items[1:]
        bundle = SignedAuthBundle(self.receipt, "sha256", forged_items)
        decoded = decode_signed_auth_bundle(
            encode_signed_auth_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)
        self.assertEqual(
            verify_signed_auth_bundle(decoded, self.public_key),
            (False, True, True),
        )

    def test_call_is_read_only(self):
        data = encode_signed_auth_bundle(self.bundle)
        decode_signed_auth_bundle(data)
        self.assertEqual(
            decode_signed_auth_bundle(data), self.bundle
        )


if __name__ == "__main__":
    unittest.main()
