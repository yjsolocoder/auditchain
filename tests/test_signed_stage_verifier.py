import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedStageVerifier,
    StageVerifier,
    verify_auth_stage,
    verify_signed_stage_verifier,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-stage-key"


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _blob(material: bytes) -> bytes:
    return _u64(len(material)) + material


class ExportSignedStageVerifierTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=_KEY)
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_fields(self):
        self.log.auth(0)  # evolve to stage 1
        receipt = self.log.export_signed_stage_verifier(_SEED_A)
        self.assertIsInstance(receipt, SignedStageVerifier)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.verifier, self.log.export_stage_verifier())
        self.assertEqual(receipt.verifier.stage, 1)
        self.assertEqual(receipt.verifier.key, self.log._key)
        self.assertEqual(receipt.verifier.hash_name, "sha256")
        self.assertIsInstance(receipt.signature, bytes)
        self.assertEqual(len(receipt.signature), 64)

    def test_signature_is_over_specified_message(self):
        self.log.auth(0)
        material = self.log.export_stage_verifier()
        receipt = self.log.export_signed_stage_verifier(_SEED_A)
        message = (
            b"auditchain/signed-stage/v1\0"
            + b"\x01"
            + _u64(1)
            + _blob(b"sha256")
            + _blob(material.key)
        )
        signing_key = Ed25519PrivateKey.from_private_bytes(_SEED_A)
        # Ed25519 is deterministic: signing the message again must reproduce
        # exactly the signature carried by the receipt.
        self.assertEqual(signing_key.sign(message), receipt.signature)

    def test_repeatable_and_byte_identical(self):
        self.log.auth(0)
        first = self.log.export_signed_stage_verifier(_SEED_A)
        second = self.log.export_signed_stage_verifier(_SEED_A)
        self.assertIsNot(first, second)
        self.assertEqual(first, second)
        self.assertEqual(first.signature, second.signature)

    def test_export_is_read_only(self):
        self.log.auth(0)
        self.log.auth(1)
        before = (
            self.log.stage,
            self.log._key,
            self.log.head,
            len(self.log),
            self.log._verifier_exported,
            dict(self.log._tags),
        )
        self.log.export_signed_stage_verifier(_SEED_A)
        self.log.export_signed_stage_verifier(_SEED_A)
        after = (
            self.log.stage,
            self.log._key,
            self.log.head,
            len(self.log),
            self.log._verifier_exported,
            dict(self.log._tags),
        )
        self.assertEqual(before, after)

    def test_not_available_at_initial_stage(self):
        self.assertEqual(self.log.stage, 0)
        with self.assertRaises(ValueError):
            self.log.export_signed_stage_verifier(_SEED_A)

    def test_keyless_mode_rejected(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            log.export_signed_stage_verifier(_SEED_A)

    def test_available_after_bare_rotation(self):
        self.log.rotate_key()
        receipt = self.log.export_signed_stage_verifier(_SEED_A)
        self.assertEqual(receipt.verifier.stage, 1)
        self.assertTrue(verify_signed_stage_verifier(receipt, self.public_key))

    def test_does_not_consume_stage_zero_export(self):
        stage0 = self.log.export_verifier()
        self.assertEqual(stage0.key, _KEY)
        self.log.rotate_key()
        receipt = self.log.export_signed_stage_verifier(_SEED_A)
        self.assertEqual(receipt.verifier.stage, 1)
        self.assertTrue(verify_signed_stage_verifier(receipt, self.public_key))
        # The one-shot stage-0 export stays consumed; the signed stage export
        # keeps working independently.
        with self.assertRaises(ValueError):
            self.log.export_verifier()
        self.assertEqual(
            self.log.export_signed_stage_verifier(_SEED_A), receipt
        )

    def test_later_export_freezes_later_stage(self):
        self.log.auth(0)
        receipt1 = self.log.export_signed_stage_verifier(_SEED_A)
        self.assertEqual(receipt1.verifier.stage, 1)
        self.log.auth(1)
        receipt2 = self.log.export_signed_stage_verifier(_SEED_A)
        self.assertEqual(receipt2.verifier.stage, 2)
        self.assertNotEqual(receipt1, receipt2)
        self.assertTrue(verify_signed_stage_verifier(receipt1, self.public_key))
        self.assertTrue(verify_signed_stage_verifier(receipt2, self.public_key))

    def test_private_key_validation(self):
        self.log.auth(0)
        with self.assertRaises(TypeError):
            self.log.export_signed_stage_verifier("0" * 32)
        with self.assertRaises(TypeError):
            self.log.export_signed_stage_verifier(32)
        with self.assertRaises(TypeError):
            self.log.export_signed_stage_verifier(None)
        with self.assertRaises(TypeError):
            self.log.export_signed_stage_verifier(bytearray(_SEED_A))
        with self.assertRaises(TypeError):
            self.log.export_signed_stage_verifier(memoryview(_SEED_A))
        with self.assertRaises(ValueError):
            self.log.export_signed_stage_verifier(_SEED_A[:-1])
        with self.assertRaises(ValueError):
            self.log.export_signed_stage_verifier(_SEED_A + b"\x00")

    def test_failure_leaves_state_untouched(self):
        keyless = AuditLog()
        keyless.append("a")
        before = (keyless.stage, keyless._key, keyless.head)
        with self.assertRaises(ValueError):
            keyless.export_signed_stage_verifier(_SEED_A)
        self.assertEqual((keyless.stage, keyless._key, keyless.head), before)

        fresh = AuditLog(key=_KEY)
        fresh.append("a")
        before = (fresh.stage, fresh._key, fresh.head, fresh._verifier_exported)
        for bad in ("0" * 32, 32, None, b"short", _SEED_A + b"\x00", _SEED_A):
            with self.assertRaises((TypeError, ValueError)):
                fresh.export_signed_stage_verifier(bad)
        self.assertEqual(
            (fresh.stage, fresh._key, fresh.head, fresh._verifier_exported),
            before,
        )

    def test_alternate_hash_algorithm(self):
        log = AuditLog(key=_KEY, hash_name="sha3_256")
        log.append("a")
        log.auth(0)
        receipt = log.export_signed_stage_verifier(_SEED_A)
        self.assertEqual(receipt.verifier.hash_name, "sha3_256")
        message = (
            b"auditchain/signed-stage/v1\0"
            + b"\x01"
            + _u64(1)
            + _blob(b"sha3_256")
            + _blob(receipt.verifier.key)
        )
        self.assertEqual(
            Ed25519PrivateKey.from_private_bytes(_SEED_A).sign(message),
            receipt.signature,
        )
        self.assertTrue(verify_signed_stage_verifier(receipt, self.public_key))


class SignedStageVerifierConstructionTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=_KEY)
        self.log.append("a")
        self.log.auth(0)
        self.receipt = self.log.export_signed_stage_verifier(_SEED_A)

    def test_positional_construction_and_equality(self):
        clone = SignedStageVerifier(1, self.receipt.verifier, self.receipt.signature)
        self.assertEqual(self.receipt, clone)
        self.assertNotEqual(
            self.receipt,
            SignedStageVerifier(
                1, StageVerifier(2, self.receipt.verifier.key, "sha256"),
                self.receipt.signature,
            ),
        )
        self.assertNotEqual(
            self.receipt,
            SignedStageVerifier(1, self.receipt.verifier, b"\x00" * 64),
        )

    def test_receipt_is_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            self.receipt.version = 2
        with self.assertRaises(FrozenInstanceError):
            self.receipt.signature = b"\x00" * 64

    def test_version_must_be_one(self):
        with self.assertRaises(ValueError):
            SignedStageVerifier(2, self.receipt.verifier, self.receipt.signature)
        with self.assertRaises(ValueError):
            SignedStageVerifier(0, self.receipt.verifier, self.receipt.signature)

    def test_version_must_be_non_bool_integer(self):
        with self.assertRaises(TypeError):
            SignedStageVerifier("1", self.receipt.verifier, self.receipt.signature)
        with self.assertRaises(TypeError):
            SignedStageVerifier(True, self.receipt.verifier, self.receipt.signature)
        with self.assertRaises(TypeError):
            SignedStageVerifier(1.0, self.receipt.verifier, self.receipt.signature)

    def test_verifier_must_be_a_stage_verifier(self):
        with self.assertRaises(TypeError):
            SignedStageVerifier(1, (1, b"k", "sha256"), self.receipt.signature)
        with self.assertRaises(TypeError):
            SignedStageVerifier(1, None, self.receipt.signature)
        with self.assertRaises(TypeError):
            SignedStageVerifier(1, b"not-a-verifier", self.receipt.signature)

    def test_nested_verifier_is_validated(self):
        with self.assertRaises(ValueError):
            SignedStageVerifier(
                1, StageVerifier(1, b"short", "sha256"), self.receipt.signature
            )
        with self.assertRaises(ValueError):
            SignedStageVerifier(
                1, StageVerifier(1, bytes(32), "not-a-hash"), self.receipt.signature
            )
        with self.assertRaises(TypeError):
            SignedStageVerifier(
                1, StageVerifier(1, "key-not-bytes", "sha256"),
                self.receipt.signature,
            )

    def test_signature_validation(self):
        with self.assertRaises(TypeError):
            SignedStageVerifier(1, self.receipt.verifier, "0" * 64)
        with self.assertRaises(TypeError):
            SignedStageVerifier(
                1, self.receipt.verifier, bytearray(self.receipt.signature)
            )
        with self.assertRaises(TypeError):
            SignedStageVerifier(
                1, self.receipt.verifier, memoryview(self.receipt.signature)
            )
        with self.assertRaises(ValueError):
            SignedStageVerifier(1, self.receipt.verifier, b"")
        with self.assertRaises(ValueError):
            SignedStageVerifier(1, self.receipt.verifier, b"\x00" * 63)
        with self.assertRaises(ValueError):
            SignedStageVerifier(1, self.receipt.verifier, b"\x00" * 65)


class VerifySignedStageVerifierTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=_KEY)
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.log.auth(0)  # evolve to stage 1
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.receipt = self.log.export_signed_stage_verifier(_SEED_A)

    def bypass(self, **fields):
        receipt = SignedStageVerifier.__new__(SignedStageVerifier)
        defaults = {
            "version": 1,
            "verifier": self.receipt.verifier,
            "signature": self.receipt.signature,
        }
        defaults.update(fields)
        for name, value in defaults.items():
            object.__setattr__(receipt, name, value)
        return receipt

    def bypass_verifier(self, **fields):
        verifier = StageVerifier.__new__(StageVerifier)
        defaults = {
            "stage": self.receipt.verifier.stage,
            "key": self.receipt.verifier.key,
            "hash_name": "sha256",
        }
        defaults.update(fields)
        for name, value in defaults.items():
            object.__setattr__(verifier, name, value)
        return verifier

    def test_genuine_receipt_verifies(self):
        self.assertTrue(
            verify_signed_stage_verifier(self.receipt, self.public_key)
        )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_stage_verifier(self.receipt, self.other_public_key)
        )

    def test_tampered_stage_returns_false(self):
        forged = self.bypass(
            verifier=self.bypass_verifier(stage=self.receipt.verifier.stage + 1)
        )
        self.assertFalse(verify_signed_stage_verifier(forged, self.public_key))

    def test_tampered_key_returns_false(self):
        forged = self.bypass(verifier=self.bypass_verifier(key=b"\x00" * 32))
        self.assertFalse(verify_signed_stage_verifier(forged, self.public_key))

    def test_relabeled_hash_algorithm_returns_false(self):
        # sha3_256 is a structurally legal algorithm name with the same digest
        # width, so the relabeled receipt parses but no longer matches the
        # signed message.
        forged = self.bypass(verifier=self.bypass_verifier(hash_name="sha3_256"))
        self.assertFalse(verify_signed_stage_verifier(forged, self.public_key))

    def test_unknown_hash_algorithm_raises(self):
        forged = self.bypass(verifier=self.bypass_verifier(hash_name="nope"))
        with self.assertRaises(ValueError):
            verify_signed_stage_verifier(forged, self.public_key)

    def test_tampered_signature_returns_false(self):
        forged = self.bypass(signature=b"\x00" * 64)
        self.assertFalse(verify_signed_stage_verifier(forged, self.public_key))

    def test_flipped_signature_byte_returns_false(self):
        raw = bytearray(self.receipt.signature)
        raw[0] ^= 0x01
        forged = self.bypass(signature=bytes(raw))
        self.assertFalse(verify_signed_stage_verifier(forged, self.public_key))

    def test_other_key_signing_same_material_returns_false(self):
        # Sign the same stage material with the other key.
        message = (
            b"auditchain/signed-stage/v1\0"
            + b"\x01"
            + _u64(self.receipt.verifier.stage)
            + _blob(b"sha256")
            + _blob(self.receipt.verifier.key)
        )
        signature = Ed25519PrivateKey.from_private_bytes(_SEED_B).sign(message)
        foreign = SignedStageVerifier(1, self.receipt.verifier, signature)
        self.assertEqual(foreign.verifier, self.receipt.verifier)
        self.assertNotEqual(foreign.signature, self.receipt.signature)
        self.assertFalse(verify_signed_stage_verifier(foreign, self.public_key))
        self.assertTrue(
            verify_signed_stage_verifier(foreign, self.other_public_key)
        )

    def test_tampered_version_raises(self):
        # Version is structural: a bypassed version other than 1 raises
        # ValueError rather than verifying or returning False.
        forged = self.bypass(version=2)
        with self.assertRaises(ValueError):
            verify_signed_stage_verifier(forged, self.public_key)

    def test_bypassed_wrong_types_raise(self):
        with self.assertRaises(TypeError):
            verify_signed_stage_verifier(self.bypass(verifier=b"x"), self.public_key)
        forged = self.bypass(verifier=self.bypass_verifier(key="not-bytes"))
        with self.assertRaises(TypeError):
            verify_signed_stage_verifier(forged, self.public_key)
        forged = self.bypass(verifier=self.bypass_verifier(stage=True))
        with self.assertRaises(TypeError):
            verify_signed_stage_verifier(forged, self.public_key)

    def test_bypassed_bad_values_raise(self):
        forged = self.bypass(verifier=self.bypass_verifier(stage=-1))
        with self.assertRaises(ValueError):
            verify_signed_stage_verifier(forged, self.public_key)
        forged = self.bypass(verifier=self.bypass_verifier(stage=1 << 64))
        with self.assertRaises(ValueError):
            verify_signed_stage_verifier(forged, self.public_key)
        forged = self.bypass(verifier=self.bypass_verifier(key=b""))
        with self.assertRaises(ValueError):
            verify_signed_stage_verifier(forged, self.public_key)
        forged = self.bypass(verifier=self.bypass_verifier(key=b"short"))
        with self.assertRaises(ValueError):
            verify_signed_stage_verifier(forged, self.public_key)
        forged = self.bypass(signature=b"\x00" * 63)
        with self.assertRaises(ValueError):
            verify_signed_stage_verifier(forged, self.public_key)

    def test_not_a_receipt_raises(self):
        for bad in (None, 42, (1, self.receipt.verifier, b""), self.receipt.verifier):
            with self.assertRaises(TypeError):
                verify_signed_stage_verifier(bad, self.public_key)

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_stage_verifier(self.receipt, "0" * 32)
        with self.assertRaises(TypeError):
            verify_signed_stage_verifier(self.receipt, 32)
        with self.assertRaises(TypeError):
            verify_signed_stage_verifier(self.receipt, None)
        with self.assertRaises(TypeError):
            verify_signed_stage_verifier(self.receipt, bytearray(self.public_key))
        with self.assertRaises(TypeError):
            verify_signed_stage_verifier(self.receipt, memoryview(self.public_key))
        with self.assertRaises(ValueError):
            verify_signed_stage_verifier(self.receipt, self.public_key[:-1])
        with self.assertRaises(ValueError):
            verify_signed_stage_verifier(self.receipt, self.public_key + b"\x00")

    def test_call_is_read_only(self):
        verify_signed_stage_verifier(self.receipt, self.other_public_key)
        self.assertTrue(
            verify_signed_stage_verifier(self.receipt, self.public_key)
        )


class DeliveredStageVerifierAuthTest(unittest.TestCase):
    def test_delivered_material_authenticates_later_stage_tags(self):
        # The point of the signed delivery: a receiver that only trusts the
        # public key obtains a StageVerifier that validates tags minted at
        # the delivery stage or later.
        log = AuditLog(key=_KEY)
        for record in ("a", "b", "c"):
            log.append(record)
        tag0 = log.auth(0)  # mints at stage 0, advances to stage 1
        signed = log.export_signed_stage_verifier(_SEED_A)
        public_key = _public_key(_SEED_A)
        self.assertTrue(verify_signed_stage_verifier(signed, public_key))
        material = signed.verifier
        self.assertEqual(material.stage, 1)
        # A tag minted before the delivery point never verifies...
        self.assertFalse(verify_auth_stage(log.entry(0), tag0, material))
        # ...while tags at the delivery stage or later do.
        tag1 = log.auth(1)
        tag2 = log.auth(2)
        self.assertEqual((tag1.stage, tag2.stage), (1, 2))
        self.assertTrue(verify_auth_stage(log.entry(1), tag1, material))
        self.assertTrue(verify_auth_stage(log.entry(2), tag2, material))


if __name__ == "__main__":
    unittest.main()
