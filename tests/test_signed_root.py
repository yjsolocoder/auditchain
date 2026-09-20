import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from auditchain import (
    AuditLog,
    SignedRoot,
    verify_signed_root,
)


def make_keypair(seed_byte=7):
    seed = bytes([seed_byte]) * 32
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes_raw()
    return seed, public


class SignedRootIssueTest(unittest.TestCase):
    def setUp(self):
        self.seed, self.public_key = make_keypair()
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_fields(self):
        receipt = self.log.sign_root(self.seed)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root(5))
        self.assertEqual(receipt.head, self.log.head)
        self.assertEqual(len(receipt.signature), 64)

    def test_positional_construction_and_equality(self):
        receipt = self.log.sign_root(self.seed)
        clone = SignedRoot(
            1, "sha256", 5, receipt.root, receipt.head, receipt.signature
        )
        self.assertEqual(receipt, clone)
        self.assertEqual(hash(receipt), hash(clone))

    def test_default_size_is_log_length(self):
        receipt = self.log.sign_root(self.seed)
        self.assertEqual(receipt.size, len(self.log))

    def test_explicit_size(self):
        receipt = self.log.sign_root(self.seed, 3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual(receipt.head, self.log.entry(2).entry_hash)
        self.assertTrue(verify_signed_root(receipt, self.public_key))

    def test_empty_log_signs_canonical_empty_root_and_zero_head(self):
        log = AuditLog()
        receipt = log.sign_root(self.seed)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(receipt.root, log.merkle_root(0))
        self.assertEqual(receipt.head, bytes(32))
        self.assertTrue(verify_signed_root(receipt, self.public_key))

    def test_explicit_empty_prefix(self):
        receipt = self.log.sign_root(self.seed, 0)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(receipt.root, self.log.merkle_root(0))
        self.assertEqual(receipt.head, bytes(32))
        self.assertTrue(verify_signed_root(receipt, self.public_key))

    def test_signature_is_deterministic(self):
        first = self.log.sign_root(self.seed)
        second = self.log.sign_root(self.seed)
        self.assertEqual(first, second)

    def test_message_framing_matches_specification(self):
        receipt = self.log.sign_root(self.seed, 3)

        def U(value):
            return value.to_bytes(8, "big")

        def B(blob):
            return U(len(blob)) + blob

        message = (
            b"auditchain/signed-root/v1\0"
            + b"\x01"
            + B("sha256".encode("utf-8"))
            + U(3)
            + B(receipt.root)
            + B(receipt.head)
        )
        # Raises if the signature does not cover exactly this byte string.
        Ed25519PublicKey.from_public_bytes(self.public_key).verify(
            receipt.signature, message
        )

    def test_other_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        receipt = log.sign_root(self.seed)
        self.assertEqual(receipt.hash_name, "sha512")
        self.assertEqual(len(receipt.root), 64)
        self.assertEqual(len(receipt.head), 64)
        self.assertTrue(verify_signed_root(receipt, self.public_key))

    def test_signing_is_read_only(self):
        before = (len(self.log), self.log.head, self.log.entries())
        receipt = self.log.sign_root(self.seed)
        self.assertEqual((len(self.log), self.log.head, self.log.entries()), before)
        self.assertTrue(self.log.verify())
        self.assertTrue(verify_signed_root(receipt, self.public_key))

    def test_pruned_log_signs_retain_point(self):
        receipt = self.log.seal(3)
        self.log.prune(3, receipt)
        signed = self.log.sign_root(self.seed, 3)
        self.assertEqual(signed.root, receipt.merkle_root)
        self.assertEqual(signed.head, receipt.chain_hash)
        self.assertTrue(verify_signed_root(signed, self.public_key))

    def test_pruned_away_snapshot_raises(self):
        receipt = self.log.seal(3)
        self.log.prune(3, receipt)
        with self.assertRaises(ValueError):
            self.log.sign_root(self.seed, 2)


class SignedRootVerifyTest(unittest.TestCase):
    def setUp(self):
        self.seed, self.public_key = make_keypair()
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.receipt = self.log.sign_root(self.seed)

    def replace(self, **changes):
        fields = dict(
            version=self.receipt.version,
            hash_name=self.receipt.hash_name,
            size=self.receipt.size,
            root=self.receipt.root,
            head=self.receipt.head,
            signature=self.receipt.signature,
        )
        fields.update(changes)
        return SignedRoot(**fields)

    def test_genuine_receipt_verifies(self):
        self.assertTrue(verify_signed_root(self.receipt, self.public_key))

    def test_wrong_public_key_returns_false(self):
        _, other_public = make_keypair(seed_byte=9)
        self.assertFalse(verify_signed_root(self.receipt, other_public))

    def test_tampered_root_returns_false(self):
        root = bytes([self.receipt.root[0] ^ 1]) + self.receipt.root[1:]
        self.assertFalse(verify_signed_root(self.replace(root=root), self.public_key))

    def test_tampered_head_returns_false(self):
        head = bytes([self.receipt.head[0] ^ 1]) + self.receipt.head[1:]
        self.assertFalse(verify_signed_root(self.replace(head=head), self.public_key))

    def test_tampered_signature_returns_false(self):
        signature = bytes([self.receipt.signature[0] ^ 1]) + self.receipt.signature[1:]
        self.assertFalse(
            verify_signed_root(self.replace(signature=signature), self.public_key)
        )

    def test_tampered_size_returns_false(self):
        self.assertFalse(verify_signed_root(self.replace(size=2), self.public_key))

    def test_tampered_hash_name_returns_false(self):
        # Rebind the signature to a different same-width algorithm: the
        # receipt stays structurally valid but the signed message changes.
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        receipt = log.sign_root(self.seed)
        rebound = SignedRoot(
            1, "sha3-512", receipt.size, receipt.root, receipt.head,
            receipt.signature,
        )
        self.assertFalse(verify_signed_root(rebound, self.public_key))

    def test_signature_from_other_key_returns_false(self):
        other_seed, _ = make_keypair(seed_byte=9)
        other_receipt = self.log.sign_root(other_seed)
        self.assertFalse(verify_signed_root(other_receipt, self.public_key))

    def test_verification_is_read_only(self):
        self.assertTrue(verify_signed_root(self.receipt, self.public_key))
        self.assertTrue(verify_signed_root(self.receipt, self.public_key))
        self.assertTrue(self.log.verify())


class SignedRootValidationTest(unittest.TestCase):
    def setUp(self):
        self.seed, self.public_key = make_keypair()
        self.log = AuditLog()
        self.log.append("a")
        self.receipt = self.log.sign_root(self.seed)

    def test_private_key_type(self):
        with self.assertRaises(TypeError):
            self.log.sign_root("not bytes")
        with self.assertRaises(TypeError):
            self.log.sign_root(bytearray(self.seed))

    def test_private_key_length(self):
        with self.assertRaises(ValueError):
            self.log.sign_root(self.seed[:31])
        with self.assertRaises(ValueError):
            self.log.sign_root(self.seed + b"x")

    def test_public_key_type(self):
        with self.assertRaises(TypeError):
            verify_signed_root(self.receipt, "not bytes")

    def test_public_key_length(self):
        with self.assertRaises(ValueError):
            verify_signed_root(self.receipt, self.public_key[:31])

    def test_receipt_type(self):
        with self.assertRaises(TypeError):
            verify_signed_root("not a receipt", self.public_key)

    def test_size_type(self):
        with self.assertRaises(TypeError):
            self.log.sign_root(self.seed, "1")
        with self.assertRaises(TypeError):
            self.log.sign_root(self.seed, True)

    def test_size_range(self):
        with self.assertRaises(ValueError):
            self.log.sign_root(self.seed, -1)
        with self.assertRaises(ValueError):
            self.log.sign_root(self.seed, 2)

    def test_version_must_be_one(self):
        with self.assertRaises(ValueError):
            SignedRoot(2, "sha256", 1, self.receipt.root, self.receipt.head,
                       self.receipt.signature)
        with self.assertRaises(TypeError):
            SignedRoot("1", "sha256", 1, self.receipt.root, self.receipt.head,
                       self.receipt.signature)

    def test_hash_name_validation(self):
        with self.assertRaises(TypeError):
            SignedRoot(1, 256, 1, self.receipt.root, self.receipt.head,
                       self.receipt.signature)
        with self.assertRaises(ValueError):
            SignedRoot(1, "no-such-hash", 1, self.receipt.root, self.receipt.head,
                       self.receipt.signature)
        with self.assertRaises(ValueError):
            SignedRoot(1, "shake_128", 1, self.receipt.root, self.receipt.head,
                       self.receipt.signature)

    def test_digest_width_validation(self):
        with self.assertRaises(ValueError):
            SignedRoot(1, "sha256", 1, self.receipt.root[:31], self.receipt.head,
                       self.receipt.signature)
        with self.assertRaises(ValueError):
            SignedRoot(1, "sha256", 1, self.receipt.root, self.receipt.head + b"x",
                       self.receipt.signature)
        with self.assertRaises(TypeError):
            SignedRoot(1, "sha256", 1, "root", self.receipt.head,
                       self.receipt.signature)

    def test_signature_validation(self):
        with self.assertRaises(TypeError):
            SignedRoot(1, "sha256", 1, self.receipt.root, self.receipt.head, "sig")
        with self.assertRaises(ValueError):
            SignedRoot(1, "sha256", 1, self.receipt.root, self.receipt.head,
                       self.receipt.signature[:63])

    def test_size_field_validation(self):
        with self.assertRaises(TypeError):
            SignedRoot(1, "sha256", "1", self.receipt.root, self.receipt.head,
                       self.receipt.signature)
        with self.assertRaises(ValueError):
            SignedRoot(1, "sha256", -1, self.receipt.root, self.receipt.head,
                       self.receipt.signature)

    def test_bytearray_fields_normalized(self):
        receipt = SignedRoot(
            1, "sha256", 1, bytearray(self.receipt.root),
            bytearray(self.receipt.head), bytearray(self.receipt.signature),
        )
        self.assertIsInstance(receipt.root, bytes)
        self.assertIsInstance(receipt.head, bytes)
        self.assertIsInstance(receipt.signature, bytes)
        self.assertEqual(receipt, self.receipt)
        self.assertTrue(verify_signed_root(receipt, self.public_key))


if __name__ == "__main__":
    unittest.main()
