import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    RetentionTransition,
    SignedConsistency,
    SignedPrune,
    SignedRoot,
    decode_retention_transition,
    decode_signed_consistency,
    decode_signed_prune,
    decode_signed_root,
    encode_retention_transition,
    encode_signed_consistency,
    encode_signed_prune,
    encode_signed_root,
    verify_retention_chain,
)

MAGIC = b"auditchain/retention-transition/v1\0"

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
    """Split an envelope into (version, before_blob, prune_blob, consistency_blob)."""
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

    before_blob = take()
    prune_blob = take()
    consistency_blob = take()
    assert offset == len(data)
    return version, before_blob, prune_blob, consistency_blob


def _make_chain(count1=3, count2=7, hash_name="sha256"):
    log = AuditLog(hash_name=hash_name)
    for i in range(count2):
        log.append(f"r{i}")
    initial = log.sign_root(_SEED_A, 0)
    transition = log.prune_with_retention_transition(
        initial, count1, _SEED_A
    )
    return log, initial, transition


class EncodeRetentionTransitionTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.initial = self.log.sign_root(_SEED_A, 0)
        self.transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )

    def test_magic_and_field_layout(self):
        data = encode_retention_transition(self.transition)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        before_bytes = encode_signed_root(self.transition.before)
        self.assertEqual(data[offset:offset + 8], u64(len(before_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(before_bytes)], before_bytes)
        offset += len(before_bytes)
        prune_bytes = encode_signed_prune(self.transition.prune)
        self.assertEqual(data[offset:offset + 8], u64(len(prune_bytes)))
        offset += 8
        self.assertEqual(data[offset:offset + len(prune_bytes)], prune_bytes)
        offset += len(prune_bytes)
        consistency_bytes = encode_signed_consistency(
            self.transition.consistency
        )
        self.assertEqual(data[offset:offset + 8], u64(len(consistency_bytes)))
        offset += 8
        self.assertEqual(
            data[offset:offset + len(consistency_bytes)], consistency_bytes
        )
        offset += len(consistency_bytes)
        self.assertEqual(offset, len(data))

    def test_expected_canonical_bytes(self):
        expected = (
            MAGIC
            + u64(1)
            + blob(encode_signed_root(self.transition.before))
            + blob(encode_signed_prune(self.transition.prune))
            + blob(encode_signed_consistency(self.transition.consistency))
        )
        self.assertEqual(
            encode_retention_transition(self.transition), expected
        )

    def test_blobs_are_exact_existing_encodings(self):
        _, before_blob, prune_blob, consistency_blob = _split_envelope(
            encode_retention_transition(self.transition)
        )
        self.assertEqual(
            before_blob, encode_signed_root(self.transition.before)
        )
        self.assertEqual(
            prune_blob, encode_signed_prune(self.transition.prune)
        )
        self.assertEqual(
            consistency_blob,
            encode_signed_consistency(self.transition.consistency),
        )
        # Each blob is independently decodable by the existing codecs.
        self.assertEqual(
            decode_signed_root(before_blob), self.transition.before
        )
        self.assertEqual(
            decode_signed_prune(prune_blob), self.transition.prune
        )
        self.assertEqual(
            decode_signed_consistency(consistency_blob),
            self.transition.consistency,
        )

    def test_encode_is_deterministic(self):
        data = encode_retention_transition(self.transition)
        self.assertEqual(data, data)
        self.assertEqual(
            encode_retention_transition(self.transition), data
        )

    def test_no_new_signing_message(self):
        # The three credentials ride along verbatim.
        _, before_blob, prune_blob, consistency_blob = _split_envelope(
            encode_retention_transition(self.transition)
        )
        self.assertEqual(before_blob, encode_signed_root(self.initial))
        self.assertEqual(
            prune_blob,
            encode_signed_prune(self.log.sign_prune(_SEED_A, 3)),
        )
        self.assertEqual(
            consistency_blob,
            encode_signed_consistency(self.transition.consistency),
        )

    def test_nonempty_proof_layout(self):
        log = AuditLog()
        for i in range(11):
            log.append(f"r{i}")
        initial = log.sign_root(_SEED_A, 0)
        first = log.prune_with_retention_transition(initial, 3, _SEED_A)
        log.append("r11")
        second = log.prune_with_retention_transition(
            first.prune.checkpoint, 12, _SEED_A
        )
        self.assertTrue(len(second.consistency.proof) > 0)
        data = encode_retention_transition(second)
        restored = decode_retention_transition(data)
        self.assertEqual(restored, second)
        self.assertEqual(
            restored.consistency.proof, second.consistency.proof
        )

    def test_only_retention_transition_accepted(self):
        for bad in (
            None,
            1,
            "item",
            b"bytes",
            (),
            (
                self.transition.before,
                self.transition.prune,
                self.transition.consistency,
            ),
            self.transition.before,
            self.transition.prune,
            self.transition.consistency,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_retention_transition(bad)

    def test_bypassed_container_field_types_raise_type_error(self):
        t = self.transition
        for field, value in (
            ("before", None),
            ("before", t.prune),
            ("before", "not-a-checkpoint"),
            ("prune", None),
            ("prune", t.before),
            ("prune", "not-a-prune"),
            ("consistency", None),
            ("consistency", t.prune),
            ("consistency", "not-a-consistency"),
        ):
            forged = RetentionTransition.__new__(RetentionTransition)
            object.__setattr__(
                forged, "before", t.before if field != "before" else value
            )
            object.__setattr__(
                forged, "prune", t.prune if field != "prune" else value
            )
            object.__setattr__(
                forged,
                "consistency",
                t.consistency if field != "consistency" else value,
            )
            with self.assertRaises(TypeError, msg=field):
                encode_retention_transition(forged)

    def test_nested_value_error_propagates(self):
        t = self.transition
        checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "head",
            "signature",
        ):
            object.__setattr__(
                checkpoint, name, getattr(t.before, name)
            )
        object.__setattr__(checkpoint, "version", 2)
        forged = RetentionTransition.__new__(RetentionTransition)
        object.__setattr__(forged, "before", checkpoint)
        object.__setattr__(forged, "prune", t.prune)
        object.__setattr__(forged, "consistency", t.consistency)
        with self.assertRaises(ValueError):
            encode_retention_transition(forged)

    def test_call_is_read_only(self):
        before = encode_retention_transition(self.transition)
        encode_retention_transition(self.transition)
        self.assertEqual(
            encode_retention_transition(self.transition), before
        )


class DecodeRetentionTransitionTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for i in range(7):
            self.log.append(f"r{i}")
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.initial = self.log.sign_root(_SEED_A, 0)

    def roundtrip(self, transition, initial):
        data = encode_retention_transition(transition)
        decoded = decode_retention_transition(data)
        self.assertIsInstance(decoded, RetentionTransition)
        self.assertEqual(decoded, transition)
        self.assertEqual(decoded.before, transition.before)
        self.assertEqual(decoded.prune, transition.prune)
        self.assertEqual(decoded.consistency, transition.consistency)
        self.assertEqual(encode_retention_transition(decoded), data)
        self.assertTrue(
            verify_retention_chain(
                initial, (decoded,), self.public_key
            )
        )
        return decoded

    def test_roundtrip_variants(self):
        for target in (1, 3, 7):
            log = AuditLog()
            for i in range(7):
                log.append(f"r{i}")
            initial = log.sign_root(_SEED_A, 0)
            transition = log.prune_with_retention_transition(
                initial, target, _SEED_A
            )
            self.roundtrip(transition, initial)

    def test_roundtrip_nonempty_before_boundary(self):
        first = self.log.prune_with_retention_transition(
            self.initial, 2, _SEED_A
        )
        self.log.append("r7")
        second = self.log.prune_with_retention_transition(
            first.prune.checkpoint, 8, _SEED_A
        )
        # The second step only joins the initial checkpoint through the first.
        data = encode_retention_transition(second)
        decoded = decode_retention_transition(data)
        self.assertEqual(decoded, second)
        self.assertEqual(encode_retention_transition(decoded), data)
        self.assertTrue(
            verify_retention_chain(
                self.initial, (first, decoded), self.public_key
            )
        )

    def test_roundtrip_full_release(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 7, _SEED_A
        )
        self.roundtrip(transition, self.initial)

    def test_roundtrip_empty_log(self):
        log = AuditLog()
        # No entries means no strictly greater target exists; the codec
        # itself still round-trips a structurally valid (but unusable)
        # transition assembled from genuine empty-snapshot credentials.
        initial = log.sign_root(_SEED_A, 0)
        prune = log.sign_prune(_SEED_A, 0)
        consistency = SignedConsistency(
            old=initial, new=prune.checkpoint, proof=()
        )
        transition = RetentionTransition(
            initial, prune, consistency
        )
        data = encode_retention_transition(transition)
        decoded = decode_retention_transition(data)
        self.assertEqual(decoded, transition)
        self.assertEqual(encode_retention_transition(decoded), data)

    def test_roundtrip_alternate_hashes(self):
        for hash_name in ("sha3-256", "sha512", "blake2b"):
            log = AuditLog(hash_name=hash_name)
            for i in range(5):
                log.append(f"r{i}")
            initial = log.sign_root(_SEED_A, 0)
            transition = log.prune_with_retention_transition(
                initial, 4, _SEED_A
            )
            data = encode_retention_transition(transition)
            decoded = decode_retention_transition(data)
            self.assertEqual(decoded, transition)
            self.assertEqual(encode_retention_transition(decoded), data)

    def test_frozen(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        decoded = decode_retention_transition(
            encode_retention_transition(transition)
        )
        with self.assertRaises(FrozenInstanceError):
            decoded.before = decoded.before
        with self.assertRaises(FrozenInstanceError):
            decoded.prune = decoded.prune
        with self.assertRaises(FrozenInstanceError):
            decoded.consistency = decoded.consistency

    def test_persistence_across_process_boundary_and_chain(self):
        log = AuditLog()
        for i in range(9):
            log.append(f"r{i}")
        initial = log.sign_root(_SEED_A, 0)
        t1 = log.prune_with_retention_transition(initial, 3, _SEED_A)
        log.append("r9")
        t2 = log.prune_with_retention_transition(
            t1.prune.checkpoint, 10, _SEED_A
        )
        restored = tuple(
            decode_retention_transition(
                bytes(encode_retention_transition(t))
            )
            for t in (t1, t2)
        )
        self.assertEqual(restored, (t1, t2))
        self.assertTrue(
            verify_retention_chain(initial, restored, self.public_key)
        )

    def test_only_bytes_accepted(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        data = encode_retention_transition(transition)
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
                decode_retention_transition(bad)

    def test_bad_magic(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        data = encode_retention_transition(transition)
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/signed-prune/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-consistency/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:32])):
                decode_retention_transition(bad)

    def test_bad_version(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        data = encode_retention_transition(transition)
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_retention_transition(bad)

    def test_truncation(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        data = encode_retention_transition(transition)
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_retention_transition(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_retention_transition(data[:cut])

    def test_trailing_bytes(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        data = encode_retention_transition(transition)
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_retention_transition(data + extra)

    def test_oversized_blob_length(self):
        prefix = MAGIC + u64(1)
        for bad in (
            prefix + u64(1 << 63) + b"x",
            prefix + blob(b"") + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_retention_transition(bad)

    def test_missing_blobs(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        data = encode_retention_transition(transition)
        _, before_blob, prune_blob, consistency_blob = _split_envelope(data)
        # Only before.
        with self.assertRaises(ValueError):
            decode_retention_transition(
                MAGIC + u64(1) + blob(before_blob)
            )
        # before + prune but no consistency blob.
        with self.assertRaises(ValueError):
            decode_retention_transition(
                MAGIC
                + u64(1)
                + blob(before_blob)
                + blob(prune_blob)
            )

    def test_swapped_blob_order_rejected(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        data = encode_retention_transition(transition)
        _, before_blob, prune_blob, consistency_blob = _split_envelope(data)
        swapped = (
            MAGIC
            + u64(1)
            + blob(prune_blob)
            + blob(before_blob)
            + blob(consistency_blob)
        )
        with self.assertRaises(ValueError):
            decode_retention_transition(swapped)

    def test_garbage_nested_blob_rejected(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        data = encode_retention_transition(transition)
        _, before_blob, prune_blob, consistency_blob = _split_envelope(data)
        cases = (
            (b"hello", prune_blob, consistency_blob),
            (before_blob, b"hello", consistency_blob),
            (before_blob, prune_blob, b"hello"),
        )
        for parts in cases:
            with self.assertRaises(ValueError):
                decode_retention_transition(
                    MAGIC + u64(1) + b"".join(blob(p) for p in parts)
                )

    def test_disagreeing_parts_still_decode_but_verify_false(self):
        # Codec judges framing only: genuine credentials of two different
        # transitions decode fine; the chain rejects their mismatch.
        log = AuditLog()
        for i in range(7):
            log.append(f"r{i}")
        initial = log.sign_root(_SEED_A, 0)
        t3 = log.prune_with_retention_transition(initial, 3, _SEED_A)
        t5 = log.prune_with_retention_transition(
            t3.prune.checkpoint, 5, _SEED_A
        )
        forged = RetentionTransition(
            t3.before, t5.prune, t5.consistency
        )
        decoded = decode_retention_transition(
            encode_retention_transition(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_retention_chain(initial, (decoded,), self.public_key)
        )

    def test_bad_signature_still_decodes_but_verifies_false(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 3, _SEED_A
        )
        bogus_checkpoint = SignedRoot(
            transition.before.version,
            transition.before.hash_name,
            transition.before.size,
            transition.before.root,
            transition.before.head,
            b"\x00" * 64,
        )
        bogus_consistency = SignedConsistency(
            old=bogus_checkpoint,
            new=transition.prune.checkpoint,
            proof=transition.consistency.proof,
        )
        forged = RetentionTransition(
            bogus_checkpoint, transition.prune, bogus_consistency
        )
        decoded = decode_retention_transition(
            encode_retention_transition(forged)
        )
        self.assertEqual(decoded, forged)
        self.assertFalse(
            verify_retention_chain(
                self.initial, (decoded,), self.public_key
            )
        )

    def test_wrong_key_decodes_but_verifies_false(self):
        transition = self.log.prune_with_retention_transition(
            self.log.sign_root(_SEED_B, 0), 3, _SEED_B
        )
        decoded = decode_retention_transition(
            encode_retention_transition(transition)
        )
        self.assertEqual(decoded, transition)
        self.assertFalse(
            verify_retention_chain(
                self.initial, (decoded,), self.public_key
            )
        )
        self.assertTrue(
            verify_retention_chain(
                transition.before, (decoded,), self.other_public_key
            )
        )

    def test_call_is_read_only(self):
        transition = self.log.prune_with_retention_transition(
            self.initial, 4, _SEED_A
        )
        data = encode_retention_transition(transition)
        self.assertEqual(decode_retention_transition(data), transition)


if __name__ == "__main__":
    unittest.main()
