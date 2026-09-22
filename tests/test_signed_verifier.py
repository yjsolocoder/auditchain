import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedVerifier,
    Verifier,
    verify_signed_verifier,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"shared-secret"


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


class ExportSignedVerifierTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=_KEY)
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_fields(self):
        receipt = self.log.export_signed_verifier(_SEED_A)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.verifier, Verifier(key=_KEY, hash_name="sha256"))
        self.assertIsInstance(receipt.signature, bytes)
        self.assertEqual(len(receipt.signature), 64)

    def test_signature_is_over_specified_message(self):
        receipt = self.log.export_signed_verifier(_SEED_A)

        def u64(value):
            return value.to_bytes(8, "big")

        def blob(material):
            return u64(len(material)) + material

        message = (
            b"auditchain/signed-verifier/v1\0"
            + b"\x01"
            + blob(b"sha256")
            + blob(_KEY)
        )
        signing_key = Ed25519PrivateKey.from_private_bytes(_SEED_A)
        # Ed25519 is deterministic: signing the message again must reproduce
        # exactly the signature carried by the receipt.
        self.assertEqual(signing_key.sign(message), receipt.signature)

    def test_alternate_hash_algorithm(self):
        log = AuditLog(key=_KEY, hash_name="sha512")
        log.append("a")
        receipt = log.export_signed_verifier(_SEED_A)
        self.assertEqual(receipt.verifier.hash_name, "sha512")
        self.assertTrue(verify_signed_verifier(receipt, self.public_key))

    def test_empty_log(self):
        receipt = AuditLog(key=_KEY).export_signed_verifier(_SEED_A)
        self.assertTrue(verify_signed_verifier(receipt, self.public_key))

    def test_export_consumes_the_entitlement(self):
        self.log.export_signed_verifier(_SEED_A)
        with self.assertRaises(ValueError):
            self.log.export_signed_verifier(_SEED_A)
        with self.assertRaises(ValueError):
            self.log.export_verifier()

    def test_export_verifier_consumes_the_entitlement_too(self):
        self.log.export_verifier()
        with self.assertRaises(ValueError):
            self.log.export_signed_verifier(_SEED_A)

    def test_unavailable_after_key_evolution(self):
        self.log.auth(0)
        with self.assertRaises(ValueError):
            self.log.export_signed_verifier(_SEED_A)
        rotated = AuditLog(key=_KEY)
        rotated.append("a")
        rotated.rotate_key()
        with self.assertRaises(ValueError):
            rotated.export_signed_verifier(_SEED_A)

    def test_keyless_log_raises(self):
        with self.assertRaises(ValueError):
            AuditLog().export_signed_verifier(_SEED_A)

    def test_private_key_validation(self):
        with self.assertRaises(TypeError):
            self.log.export_signed_verifier("0" * 32)
        with self.assertRaises(TypeError):
            self.log.export_signed_verifier(bytearray(_SEED_A))
        with self.assertRaises(TypeError):
            self.log.export_signed_verifier(memoryview(_SEED_A))
        with self.assertRaises(ValueError):
            self.log.export_signed_verifier(_SEED_A[:-1])
        with self.assertRaises(ValueError):
            self.log.export_signed_verifier(_SEED_A + b"\x00")

    def test_failed_export_keeps_the_entitlement(self):
        for bad in ("0" * 32, _SEED_A[:-1], _SEED_A + b"\x00"):
            with self.assertRaises((TypeError, ValueError)):
                self.log.export_signed_verifier(bad)
        receipt = self.log.export_signed_verifier(_SEED_A)
        self.assertTrue(verify_signed_verifier(receipt, self.public_key))

    def test_call_leaves_log_state_untouched(self):
        head = self.log.head
        self.log.export_signed_verifier(_SEED_A)
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 3)
        self.assertEqual(self.log.stage, 0)
        self.assertTrue(self.log.verify())
        tag = self.log.auth(0)
        self.assertEqual(tag.stage, 0)


class SignedVerifierValidationTest(unittest.TestCase):
    def setUp(self):
        log = AuditLog(key=_KEY)
        log.append("a")
        self.receipt = log.export_signed_verifier(_SEED_A)

    def make(self, **overrides):
        fields = {
            "version": 1,
            "verifier": self.receipt.verifier,
            "signature": self.receipt.signature,
        }
        fields.update(overrides)
        return SignedVerifier(**fields)

    def test_version_must_be_one(self):
        with self.assertRaises(ValueError):
            self.make(version=2)
        with self.assertRaises(ValueError):
            self.make(version=0)
        with self.assertRaises(TypeError):
            self.make(version="1")
        with self.assertRaises(TypeError):
            self.make(version=True)

    def test_verifier_must_be_a_verifier(self):
        with self.assertRaises(TypeError):
            self.make(verifier=(_KEY, "sha256"))
        with self.assertRaises(TypeError):
            self.make(verifier=None)

    def test_signature_validation(self):
        with self.assertRaises(TypeError):
            self.make(signature="0" * 64)
        with self.assertRaises(TypeError):
            self.make(signature=bytearray(self.receipt.signature))
        with self.assertRaises(TypeError):
            self.make(signature=memoryview(self.receipt.signature))
        with self.assertRaises(ValueError):
            self.make(signature=b"\x00" * 63)
        with self.assertRaises(ValueError):
            self.make(signature=b"\x00" * 65)

    def test_positional_construction_and_equality(self):
        clone = SignedVerifier(1, self.receipt.verifier, self.receipt.signature)
        self.assertEqual(self.receipt, clone)
        other = self.make(signature=b"\x00" * 64)
        self.assertNotEqual(self.receipt, other)

    def test_receipt_is_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            self.receipt.version = 2


class VerifySignedVerifierTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=_KEY)
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.receipt = self.log.export_signed_verifier(_SEED_A)

    def bypass(self, **fields):
        receipt = SignedVerifier.__new__(SignedVerifier)
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
        verifier = Verifier.__new__(Verifier)
        defaults = {"key": _KEY, "hash_name": "sha256"}
        defaults.update(fields)
        for name, value in defaults.items():
            object.__setattr__(verifier, name, value)
        return verifier

    def test_genuine_receipt_verifies(self):
        self.assertTrue(verify_signed_verifier(self.receipt, self.public_key))

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_verifier(self.receipt, self.other_public_key)
        )

    def test_tampered_key_returns_false(self):
        forged = self.bypass(
            verifier=self.bypass_verifier(key=b"forged-secret")
        )
        self.assertFalse(verify_signed_verifier(forged, self.public_key))

    def test_tampered_hash_name_returns_false(self):
        forged = self.bypass(
            verifier=self.bypass_verifier(hash_name="sha512")
        )
        self.assertFalse(verify_signed_verifier(forged, self.public_key))

    def test_tampered_signature_returns_false(self):
        forged = self.bypass(signature=b"\x00" * 64)
        self.assertFalse(verify_signed_verifier(forged, self.public_key))

    def test_other_key_signing_same_fields_returns_false(self):
        log = AuditLog(key=_KEY)
        foreign = log.export_signed_verifier(_SEED_B)
        self.assertEqual(foreign.verifier, self.receipt.verifier)
        self.assertNotEqual(foreign.signature, self.receipt.signature)
        self.assertFalse(verify_signed_verifier(foreign, self.public_key))
        self.assertTrue(verify_signed_verifier(foreign, self.other_public_key))

    def test_not_a_receipt_raises(self):
        with self.assertRaises(TypeError):
            verify_signed_verifier(("not", "a", "receipt"), self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_verifier(None, self.public_key)

    def test_bypassed_structural_corruption_raises(self):
        with self.assertRaises(ValueError):
            verify_signed_verifier(self.bypass(version=2), self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_verifier(
                self.bypass(verifier=(_KEY, "sha256")), self.public_key
            )
        with self.assertRaises(ValueError):
            verify_signed_verifier(
                self.bypass(signature=b"\x00" * 63), self.public_key
            )
        with self.assertRaises(ValueError):
            verify_signed_verifier(
                self.bypass(verifier=self.bypass_verifier(key=b"")),
                self.public_key,
            )
        with self.assertRaises(ValueError):
            verify_signed_verifier(
                self.bypass(verifier=self.bypass_verifier(hash_name="nope")),
                self.public_key,
            )

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_verifier(self.receipt, "0" * 32)
        with self.assertRaises(TypeError):
            verify_signed_verifier(self.receipt, bytearray(self.public_key))
        with self.assertRaises(TypeError):
            verify_signed_verifier(self.receipt, memoryview(self.public_key))
        with self.assertRaises(ValueError):
            verify_signed_verifier(self.receipt, self.public_key[:-1])
        with self.assertRaises(ValueError):
            verify_signed_verifier(self.receipt, self.public_key + b"\x00")

    def test_call_is_read_only(self):
        verify_signed_verifier(self.receipt, self.other_public_key)
        self.assertEqual(
            self.receipt,
            SignedVerifier(1, Verifier(key=_KEY, hash_name="sha256"),
                           self.receipt.signature),
        )


if __name__ == "__main__":
    unittest.main()
