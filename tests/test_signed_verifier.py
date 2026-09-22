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
    verify_auth,
    verify_signed_verifier,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"


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


class ExportSignedVerifierTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=_KEY)
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_fields(self):
        receipt = self.log.export_signed_verifier(_SEED_A)
        self.assertIsInstance(receipt, SignedVerifier)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.verifier, Verifier(_KEY, "sha256"))
        self.assertEqual(receipt.verifier.key, _KEY)
        self.assertEqual(receipt.verifier.hash_name, "sha256")
        self.assertIsInstance(receipt.signature, bytes)
        self.assertEqual(len(receipt.signature), 64)

    def test_signature_is_over_specified_message(self):
        receipt = self.log.export_signed_verifier(_SEED_A)
        message = (
            b"auditchain/signed-verifier/v1\0"
            + b"\x01"
            + _blob(b"sha256")
            + _blob(_KEY)
        )
        signing_key = Ed25519PrivateKey.from_private_bytes(_SEED_A)
        # Ed25519 is deterministic: signing the message again must reproduce
        # exactly the signature carried by the receipt.
        self.assertEqual(signing_key.sign(message), receipt.signature)

    def test_does_not_evolve_key_or_change_log(self):
        head = self.log.head
        receipt = self.log.export_signed_verifier(_SEED_A)
        self.assertEqual(self.log.stage, 0)
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 3)
        # The stage-0 key is untouched: the next auth is minted at stage 0 and
        # verifies against the delivered verifier.
        entry = self.log.entry(0)
        tag = self.log.auth(0)
        self.assertEqual(tag.stage, 0)
        self.assertTrue(verify_auth(entry, tag, receipt.verifier))

    def test_empty_log(self):
        receipt = AuditLog(key=_KEY).export_signed_verifier(_SEED_A)
        self.assertTrue(verify_signed_verifier(receipt, self.public_key))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(key=_KEY, hash_name="sha512")
        log.append("a")
        receipt = log.export_signed_verifier(_SEED_A)
        self.assertEqual(receipt.verifier.hash_name, "sha512")
        message = (
            b"auditchain/signed-verifier/v1\0"
            + b"\x01"
            + _blob(b"sha512")
            + _blob(_KEY)
        )
        self.assertEqual(
            Ed25519PrivateKey.from_private_bytes(_SEED_A).sign(message),
            receipt.signature,
        )
        self.assertTrue(verify_signed_verifier(receipt, self.public_key))

    def test_export_consumes_the_one_verifier_export(self):
        receipt = self.log.export_signed_verifier(_SEED_A)
        self.assertTrue(verify_signed_verifier(receipt, self.public_key))
        with self.assertRaises(ValueError):
            self.log.export_signed_verifier(_SEED_A)
        with self.assertRaises(ValueError):
            self.log.export_verifier()

    def test_plain_export_disqualifies_signed_export(self):
        verifier = self.log.export_verifier()
        self.assertEqual(verifier.key, _KEY)
        with self.assertRaises(ValueError):
            self.log.export_signed_verifier(_SEED_A)

    def test_requires_keyed_log(self):
        with self.assertRaises(ValueError):
            AuditLog().export_signed_verifier(_SEED_A)

    def test_requires_stage_zero(self):
        self.log.rotate_key()
        with self.assertRaises(ValueError):
            self.log.export_signed_verifier(_SEED_A)
        log = AuditLog(key=_KEY)
        log.append("a")
        log.auth(0)
        with self.assertRaises(ValueError):
            log.export_signed_verifier(_SEED_A)

    def test_private_key_validation(self):
        with self.assertRaises(TypeError):
            self.log.export_signed_verifier("0" * 32)
        with self.assertRaises(TypeError):
            self.log.export_signed_verifier(32)
        with self.assertRaises(TypeError):
            self.log.export_signed_verifier(None)
        with self.assertRaises(TypeError):
            self.log.export_signed_verifier(bytearray(_SEED_A))
        with self.assertRaises(TypeError):
            self.log.export_signed_verifier(memoryview(_SEED_A))
        with self.assertRaises(ValueError):
            self.log.export_signed_verifier(_SEED_A[:-1])
        with self.assertRaises(ValueError):
            self.log.export_signed_verifier(_SEED_A + b"\x00")

    def test_failed_validation_does_not_consume_eligibility(self):
        for bad in (
            "0" * 32,
            32,
            None,
            b"short",
            _SEED_A + b"\x00",
            bytearray(_SEED_A),
        ):
            with self.assertRaises((TypeError, ValueError)):
                self.log.export_signed_verifier(bad)
        # Eligibility survives every rejected call.
        receipt = self.log.export_signed_verifier(_SEED_A)
        self.assertTrue(verify_signed_verifier(receipt, self.public_key))

    def test_keyless_rejection_leaves_log_usable(self):
        log = AuditLog()
        with self.assertRaises(ValueError):
            log.export_signed_verifier(_SEED_A)
        self.assertEqual(log.stage, 0)


class SignedVerifierConstructionTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=_KEY)
        self.receipt = self.log.export_signed_verifier(_SEED_A)

    def test_positional_construction_and_equality(self):
        clone = SignedVerifier(1, Verifier(_KEY, "sha256"), self.receipt.signature)
        self.assertEqual(self.receipt, clone)
        self.assertNotEqual(
            self.receipt,
            SignedVerifier(1, Verifier(b"other-key", "sha256"), self.receipt.signature),
        )

    def test_receipt_is_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            self.receipt.version = 2
        with self.assertRaises(FrozenInstanceError):
            self.receipt.signature = b"\x00" * 64

    def test_version_must_be_one(self):
        with self.assertRaises(ValueError):
            SignedVerifier(2, self.receipt.verifier, self.receipt.signature)
        with self.assertRaises(ValueError):
            SignedVerifier(0, self.receipt.verifier, self.receipt.signature)

    def test_version_must_be_non_bool_integer(self):
        with self.assertRaises(TypeError):
            SignedVerifier("1", self.receipt.verifier, self.receipt.signature)
        with self.assertRaises(TypeError):
            SignedVerifier(True, self.receipt.verifier, self.receipt.signature)
        with self.assertRaises(TypeError):
            SignedVerifier(1.0, self.receipt.verifier, self.receipt.signature)

    def test_verifier_must_be_a_verifier(self):
        with self.assertRaises(TypeError):
            SignedVerifier(1, (_KEY, "sha256"), self.receipt.signature)
        with self.assertRaises(TypeError):
            SignedVerifier(1, None, self.receipt.signature)
        with self.assertRaises(TypeError):
            SignedVerifier(1, b"not-a-verifier", self.receipt.signature)

    def test_nested_verifier_is_validated(self):
        with self.assertRaises(ValueError):
            SignedVerifier(1, Verifier(b"", "sha256"), self.receipt.signature)
        with self.assertRaises(ValueError):
            SignedVerifier(
                1, Verifier(_KEY, "not-a-hash"), self.receipt.signature
            )
        with self.assertRaises(TypeError):
            SignedVerifier(
                1, Verifier("key-not-bytes", "sha256"), self.receipt.signature
            )

    def test_signature_validation(self):
        with self.assertRaises(TypeError):
            SignedVerifier(1, self.receipt.verifier, "0" * 64)
        with self.assertRaises(TypeError):
            SignedVerifier(1, self.receipt.verifier, bytearray(self.receipt.signature))
        with self.assertRaises(TypeError):
            SignedVerifier(1, self.receipt.verifier, memoryview(self.receipt.signature))
        with self.assertRaises(ValueError):
            SignedVerifier(1, self.receipt.verifier, b"")
        with self.assertRaises(ValueError):
            SignedVerifier(1, self.receipt.verifier, b"\x00" * 63)
        with self.assertRaises(ValueError):
            SignedVerifier(1, self.receipt.verifier, b"\x00" * 65)


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
        forged = self.bypass(verifier=self.bypass_verifier(key=b"other-key-value"))
        self.assertTrue(verify_signed_verifier(self.receipt, self.public_key))
        self.assertFalse(verify_signed_verifier(forged, self.public_key))

    def test_relabeled_hash_algorithm_returns_false(self):
        # sha512 is a structurally legal algorithm name, so the relabeled
        # receipt parses but no longer matches the signed message.
        forged = self.bypass(verifier=self.bypass_verifier(hash_name="sha512"))
        self.assertFalse(verify_signed_verifier(forged, self.public_key))

    def test_unknown_hash_algorithm_raises(self):
        forged = self.bypass(verifier=self.bypass_verifier(hash_name="nope"))
        with self.assertRaises(ValueError):
            verify_signed_verifier(forged, self.public_key)

    def test_empty_bypassed_key_raises(self):
        forged = self.bypass(verifier=self.bypass_verifier(key=b""))
        with self.assertRaises(ValueError):
            verify_signed_verifier(forged, self.public_key)

    def test_bypassed_wrong_types_raise(self):
        with self.assertRaises(TypeError):
            verify_signed_verifier(self.bypass(verifier=b"x"), self.public_key)
        forged = self.bypass(
            verifier=self.bypass_verifier(key="not-bytes")
        )
        with self.assertRaises(TypeError):
            verify_signed_verifier(forged, self.public_key)

    def test_tampered_version_raises(self):
        # Version is structural: a bypassed version other than 1 raises
        # ValueError rather than verifying or returning False.
        forged = self.bypass(version=2)
        with self.assertRaises(ValueError):
            verify_signed_verifier(forged, self.public_key)

    def test_tampered_signature_returns_false(self):
        forged = self.bypass(signature=b"\x00" * 64)
        self.assertFalse(verify_signed_verifier(forged, self.public_key))

    def test_flipped_signature_byte_returns_false(self):
        raw = bytearray(self.receipt.signature)
        raw[0] ^= 0x01
        forged = self.bypass(signature=bytes(raw))
        self.assertFalse(verify_signed_verifier(forged, self.public_key))

    def test_other_key_signing_same_verifier_returns_false(self):
        # Sign the same verifier fields with the other key.
        message = (
            b"auditchain/signed-verifier/v1\0"
            + b"\x01"
            + _blob(b"sha256")
            + _blob(_KEY)
        )
        signature = Ed25519PrivateKey.from_private_bytes(_SEED_B).sign(message)
        foreign_receipt = SignedVerifier(1, self.receipt.verifier, signature)
        self.assertEqual(foreign_receipt.verifier, self.receipt.verifier)
        self.assertNotEqual(foreign_receipt.signature, self.receipt.signature)
        self.assertFalse(verify_signed_verifier(foreign_receipt, self.public_key))
        self.assertTrue(
            verify_signed_verifier(foreign_receipt, self.other_public_key)
        )

    def test_not_a_receipt_raises(self):
        for bad in (None, 42, (1, self.receipt.verifier, b""), self.receipt.verifier):
            with self.assertRaises(TypeError):
                verify_signed_verifier(bad, self.public_key)

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_verifier(self.receipt, "0" * 32)
        with self.assertRaises(TypeError):
            verify_signed_verifier(self.receipt, 32)
        with self.assertRaises(TypeError):
            verify_signed_verifier(self.receipt, None)
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
        self.assertTrue(verify_signed_verifier(self.receipt, self.public_key))


class DeliveredVerifierAuthTest(unittest.TestCase):
    def test_delivered_verifier_authenticates_later_stage_tags(self):
        # The point of the signed delivery: a receiver that only trusts the
        # public key obtains a Verifier that validates tags minted at stages
        # long after the export.
        log = AuditLog(key=_KEY)
        entries = [log.append(record) for record in ("a", "b", "c")]
        signed = log.export_signed_verifier(_SEED_A)
        public_key = _public_key(_SEED_A)
        self.assertTrue(verify_signed_verifier(signed, public_key))
        tags = tuple(log.auth(index) for index in range(3))
        self.assertEqual([tag.stage for tag in tags], [0, 1, 2])
        for entry, tag in zip(entries, tags):
            self.assertTrue(verify_auth(entry, tag, signed.verifier))


if __name__ == "__main__":
    unittest.main()
