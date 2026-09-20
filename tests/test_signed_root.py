import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    SignedRoot,
    verify_signed_root,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


class SignRootTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_fields(self):
        receipt = self.log.sign_root(_SEED_A)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root(5))
        self.assertEqual(receipt.head, self.log.head)
        self.assertIsInstance(receipt.signature, bytes)
        self.assertEqual(len(receipt.signature), 64)

    def test_signature_is_over_specified_message(self):
        receipt = self.log.sign_root(_SEED_A, 4)

        def u64(value):
            return value.to_bytes(8, "big")

        def blob(material):
            return u64(len(material)) + material

        message = (
            b"auditchain/signed-root/v1\0"
            + b"\x01"
            + blob(b"sha256")
            + u64(4)
            + blob(self.log.merkle_root(4))
            + blob(self.log.entry(3).entry_hash)
        )
        signing_key = Ed25519PrivateKey.from_private_bytes(_SEED_A)
        # Ed25519 is deterministic: signing the message again must reproduce
        # exactly the signature carried by the receipt.
        self.assertEqual(signing_key.sign(message), receipt.signature)

    def test_prefix_size(self):
        receipt = self.log.sign_root(_SEED_A, 3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual(receipt.head, self.log.entry(2).entry_hash)
        self.assertTrue(verify_signed_root(receipt, self.public_key))

    def test_size_defaults_to_log_length(self):
        self.assertEqual(self.log.sign_root(_SEED_A).size, len(self.log))
        self.log.append("f")
        self.assertEqual(self.log.sign_root(_SEED_A).size, 6)

    def test_empty_prefix_uses_canonical_root_and_zero_head(self):
        receipt = self.log.sign_root(_SEED_A, 0)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(receipt.root, self.log.merkle_root(0))
        self.assertEqual(receipt.head, GENESIS_HASH)
        self.assertTrue(verify_signed_root(receipt, self.public_key))

    def test_empty_log(self):
        receipt = AuditLog().sign_root(_SEED_A)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(receipt.head, GENESIS_HASH)
        self.assertTrue(verify_signed_root(receipt, self.public_key))

    def test_survives_later_appends(self):
        receipt = self.log.sign_root(_SEED_A, 4)
        self.log.append("f")
        self.assertTrue(verify_signed_root(receipt, self.public_key))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        receipt = log.sign_root(_SEED_A)
        self.assertEqual(receipt.hash_name, "sha512")
        self.assertEqual(len(receipt.root), 64)
        self.assertEqual(len(receipt.head), 64)
        self.assertTrue(verify_signed_root(receipt, self.public_key))

    def test_pruned_log_prefixes(self):
        self.log.prune(3, self.log.seal(3))
        receipt = self.log.sign_root(_SEED_A, 4)
        self.assertEqual(receipt.root, self.log.merkle_root(4))
        self.assertTrue(verify_signed_root(receipt, self.public_key))
        empty = self.log.sign_root(_SEED_A, 0)
        self.assertEqual(empty.head, GENESIS_HASH)
        self.assertTrue(verify_signed_root(empty, self.public_key))
        with self.assertRaises(ValueError):
            self.log.sign_root(_SEED_A, 2)

    def test_positional_construction_and_equality(self):
        receipt = self.log.sign_root(_SEED_A)
        clone = SignedRoot(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            receipt.head,
            receipt.signature,
        )
        self.assertEqual(receipt, clone)
        self.assertNotEqual(receipt, self.log.sign_root(_SEED_A, 3))

    def test_receipt_is_frozen(self):
        receipt = self.log.sign_root(_SEED_A)
        with self.assertRaises(FrozenInstanceError):
            receipt.size = 3

    def test_call_is_read_only(self):
        head = self.log.head
        root = self.log.merkle_root()
        stage_log = AuditLog(key=b"shared-secret")
        stage_log.append("a")
        self.log.sign_root(_SEED_A)
        self.log.sign_root(_SEED_A, 2)
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.merkle_root(), root)
        self.assertTrue(self.log.verify())
        self.assertEqual(stage_log.stage, 0)

    def test_private_key_validation(self):
        with self.assertRaises(TypeError):
            self.log.sign_root("0" * 32)
        with self.assertRaises(TypeError):
            self.log.sign_root(bytearray(_SEED_A))
        with self.assertRaises(TypeError):
            self.log.sign_root(memoryview(_SEED_A))
        with self.assertRaises(ValueError):
            self.log.sign_root(_SEED_A[:-1])
        with self.assertRaises(ValueError):
            self.log.sign_root(_SEED_A + b"\x00")

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.sign_root(_SEED_A, "3")
        with self.assertRaises(TypeError):
            self.log.sign_root(_SEED_A, True)
        with self.assertRaises(ValueError):
            self.log.sign_root(_SEED_A, -1)
        with self.assertRaises(ValueError):
            self.log.sign_root(_SEED_A, 6)


class SignedRootValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.receipt = self.log.sign_root(_SEED_A)

    def make(self, **overrides):
        fields = {
            "version": 1,
            "hash_name": "sha256",
            "size": self.receipt.size,
            "root": self.receipt.root,
            "head": self.receipt.head,
            "signature": self.receipt.signature,
        }
        fields.update(overrides)
        return SignedRoot(**fields)

    def test_version_must_be_one(self):
        with self.assertRaises(ValueError):
            self.make(version=2)
        with self.assertRaises(TypeError):
            self.make(version="1")
        with self.assertRaises(TypeError):
            self.make(version=True)

    def test_hash_name_validation(self):
        with self.assertRaises(TypeError):
            self.make(hash_name=123)
        with self.assertRaises(ValueError):
            self.make(hash_name="not-a-hash")

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.make(size="3")
        with self.assertRaises(TypeError):
            self.make(size=True)
        with self.assertRaises(TypeError):
            self.make(size=3.0)
        with self.assertRaises(ValueError):
            self.make(size=-1)
        with self.assertRaises(ValueError):
            self.make(size=1 << 64)

    def test_root_validation(self):
        with self.assertRaises(TypeError):
            self.make(root="0" * 32)
        with self.assertRaises(ValueError):
            self.make(root=b"\x00" * 31)
        with self.assertRaises(ValueError):
            self.make(root=b"\x00" * 33)

    def test_head_validation(self):
        with self.assertRaises(TypeError):
            self.make(head="0" * 32)
        with self.assertRaises(ValueError):
            self.make(head=b"\x00" * 31)

    def test_signature_validation(self):
        with self.assertRaises(TypeError):
            self.make(signature="0" * 64)
        with self.assertRaises(ValueError):
            self.make(signature=b"\x00" * 63)
        with self.assertRaises(ValueError):
            self.make(signature=b"\x00" * 65)

    def test_bytearray_fields_normalized(self):
        receipt = self.make(
            root=bytearray(self.receipt.root),
            head=bytearray(self.receipt.head),
            signature=bytearray(self.receipt.signature),
        )
        self.assertIsInstance(receipt.root, bytes)
        self.assertIsInstance(receipt.head, bytes)
        self.assertIsInstance(receipt.signature, bytes)
        self.assertEqual(receipt, self.receipt)


class VerifySignedRootTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.receipt = self.log.sign_root(_SEED_A)

    def bypass(self, **fields):
        receipt = SignedRoot.__new__(SignedRoot)
        defaults = {
            "version": 1,
            "hash_name": "sha256",
            "size": self.receipt.size,
            "root": self.receipt.root,
            "head": self.receipt.head,
            "signature": self.receipt.signature,
        }
        defaults.update(fields)
        for name, value in defaults.items():
            object.__setattr__(receipt, name, value)
        return receipt

    def test_genuine_receipts_verify(self):
        for size in (None, 0, 1, 3, 5):
            receipt = self.log.sign_root(_SEED_A, size)
            self.assertTrue(
                verify_signed_root(receipt, self.public_key), size
            )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_root(self.receipt, self.other_public_key)
        )

    def test_tampered_root_returns_false(self):
        forged = self.bypass(root=b"\x00" * 32)
        self.assertFalse(verify_signed_root(forged, self.public_key))

    def test_tampered_head_returns_false(self):
        forged = self.bypass(head=b"\x00" * 32)
        self.assertFalse(verify_signed_root(forged, self.public_key))

    def test_tampered_signature_returns_false(self):
        forged = self.bypass(signature=b"\x00" * 64)
        self.assertFalse(verify_signed_root(forged, self.public_key))

    def test_tampered_size_returns_false(self):
        forged = self.bypass(size=4)
        self.assertFalse(verify_signed_root(forged, self.public_key))

    def test_relabeled_hash_algorithm_returns_false(self):
        root64 = self.log.sign_root(_SEED_A).root
        forged = self.bypass(hash_name="sha512")
        with self.assertRaises(ValueError):
            # A sha256-width root under a sha512 label is structurally wrong.
            verify_signed_root(forged, self.public_key)

    def test_other_key_signing_same_fields_returns_false(self):
        foreign = self.log.sign_root(_SEED_B)
        self.assertEqual(foreign.root, self.receipt.root)
        self.assertEqual(foreign.head, self.receipt.head)
        self.assertNotEqual(foreign.signature, self.receipt.signature)
        self.assertFalse(verify_signed_root(foreign, self.public_key))
        self.assertTrue(verify_signed_root(foreign, self.other_public_key))

    def test_not_a_receipt_raises(self):
        with self.assertRaises(TypeError):
            verify_signed_root(("not", "a", "receipt"), self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_root(None, self.public_key)

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_root(self.receipt, "0" * 32)
        with self.assertRaises(TypeError):
            verify_signed_root(self.receipt, bytearray(self.public_key))
        with self.assertRaises(TypeError):
            verify_signed_root(self.receipt, memoryview(self.public_key))
        with self.assertRaises(ValueError):
            verify_signed_root(self.receipt, self.public_key[:-1])
        with self.assertRaises(ValueError):
            verify_signed_root(self.receipt, self.public_key + b"\x00")

    def test_call_is_read_only(self):
        verify_signed_root(self.receipt, self.other_public_key)
        self.assertEqual(
            self.receipt, self.log.sign_root(_SEED_A)
        )


if __name__ == "__main__":
    unittest.main()
