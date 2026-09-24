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
    AuditReceipt,
    Entry,
    SignedAuditReceipt,
    SignedRoot,
    verify_audit_receipt,
    verify_signed_audit_receipt,
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


def _signed_root_message(hash_name, size, root, head):
    def u64(value):
        return value.to_bytes(8, "big")

    def blob(material):
        return u64(len(material)) + material

    return (
        b"auditchain/signed-root/v1\0"
        + b"\x01"
        + blob(hash_name.encode("utf-8"))
        + u64(size)
        + blob(root)
        + blob(head)
    )


def _sign(seed, hash_name, size, root, head):
    message = _signed_root_message(hash_name, size, root, head)
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


class SignedAuditReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_bundles_genuine_receipt_and_checkpoint(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        self.assertIsInstance(bundle, SignedAuditReceipt)
        self.assertEqual(bundle.receipt, self.log.audit_receipt([1, 3]))
        self.assertEqual(bundle.checkpoint, self.log.sign_root(_SEED_A))

    def test_no_new_signing_message(self):
        # Ed25519 is deterministic: the checkpoint is exactly sign_root's
        # output, signed over exactly the documented message.
        bundle = self.log.signed_audit_receipt([0, 2], _SEED_A, 4)
        self.assertEqual(bundle.checkpoint, self.log.sign_root(_SEED_A, 4))
        signature = _sign(
            _SEED_A,
            "sha256",
            4,
            self.log.merkle_root(4),
            self.log.entry(3).entry_hash,
        )
        self.assertEqual(bundle.checkpoint.signature, signature)

    def test_explicit_size(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A, 3)
        self.assertEqual(bundle.receipt.size, 3)
        self.assertEqual(bundle.receipt.root, self.log.merkle_root(3))
        self.assertEqual(bundle.checkpoint.size, 3)
        self.assertEqual(bundle.checkpoint.head, self.log.entry(2).entry_hash)
        self.assertTrue(verify_signed_audit_receipt(bundle, self.public_key))

    def test_size_defaults_to_current_length(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        self.assertEqual(bundle.receipt.size, len(self.log))
        self.assertEqual(bundle.checkpoint.size, len(self.log))
        self.log.append("f")
        grown = self.log.signed_audit_receipt([1, 3], _SEED_A)
        self.assertEqual(grown.checkpoint.size, 6)

    def test_empty_snapshot_uses_canonical_root_and_zero_head(self):
        bundle = self.log.signed_audit_receipt((), _SEED_A, 0)
        self.assertEqual(bundle.receipt.size, 0)
        self.assertEqual(bundle.receipt.items, ())
        self.assertEqual(bundle.receipt.root, self.log.merkle_root(0))
        self.assertEqual(bundle.checkpoint.head, GENESIS_HASH)
        self.assertTrue(verify_signed_audit_receipt(bundle, self.public_key))

    def test_empty_log(self):
        bundle = AuditLog().signed_audit_receipt((), _SEED_A)
        self.assertEqual(bundle.receipt.size, 0)
        self.assertEqual(bundle.checkpoint.head, GENESIS_HASH)
        self.assertTrue(verify_signed_audit_receipt(bundle, self.public_key))

    def test_last_entry_auto_added_and_its_hash_is_the_head(self):
        bundle = self.log.signed_audit_receipt([0], _SEED_A)
        entries = [entry for entry, _proof in bundle.receipt.items]
        self.assertEqual([entry.index for entry in entries], [0, 4])
        self.assertEqual(entries[-1].entry_hash, self.log.head)
        self.assertEqual(bundle.checkpoint.head, entries[-1].entry_hash)
        self.assertTrue(verify_signed_audit_receipt(bundle, self.public_key))

    def test_survives_later_appends(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A, 4)
        self.log.append("f")
        self.assertTrue(verify_signed_audit_receipt(bundle, self.public_key))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        bundle = log.signed_audit_receipt([0, 2], _SEED_A)
        self.assertEqual(bundle.receipt.hash_name, "sha512")
        self.assertEqual(bundle.checkpoint.hash_name, "sha512")
        self.assertTrue(verify_signed_audit_receipt(bundle, self.public_key))

    def test_pruned_log(self):
        log = AuditLog()
        twin = AuditLog()
        for i in range(6):
            log.append(f"r{i}")
            twin.append(f"r{i}")
        log.prune(2, log.seal(2))
        bundle = log.signed_audit_receipt([2, 4], _SEED_A)
        self.assertEqual(bundle.receipt.root, twin.merkle_root(6))
        self.assertTrue(verify_signed_audit_receipt(bundle, self.public_key))
        with self.assertRaises(ValueError):
            log.signed_audit_receipt([1], _SEED_A)

    def test_positional_construction_and_equality(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        clone = SignedAuditReceipt(bundle.receipt, bundle.checkpoint)
        self.assertEqual(bundle, clone)
        other = self.log.signed_audit_receipt([1], _SEED_A, 3)
        self.assertNotEqual(bundle, other)
        self.assertNotEqual(bundle, (bundle.receipt, bundle.checkpoint))

    def test_frozen(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        with self.assertRaises(FrozenInstanceError):
            bundle.receipt = None
        with self.assertRaises(FrozenInstanceError):
            bundle.checkpoint = bundle.checkpoint

    def test_constructor_field_types(self):
        receipt = self.log.audit_receipt([1])
        checkpoint = self.log.sign_root(_SEED_A)
        with self.assertRaises(TypeError):
            SignedAuditReceipt((receipt,), checkpoint)
        with self.assertRaises(TypeError):
            SignedAuditReceipt(receipt, tuple(checkpoint))
        with self.assertRaises(TypeError):
            SignedAuditReceipt(None, checkpoint)
        with self.assertRaises(TypeError):
            SignedAuditReceipt(receipt, None)

    def test_call_is_read_only(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        stage_log = AuditLog(key=b"shared-secret")
        stage_log.append("a")
        self.log.signed_audit_receipt([1, 2], _SEED_A)
        self.log.signed_audit_receipt((), _SEED_A, 0)
        self.assertEqual((len(self.log), self.log.head, self.log.merkle_root()), before)
        self.assertTrue(self.log.verify())
        self.assertEqual(stage_log.stage, 0)

    def test_failure_leaves_state_unchanged(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        for bad_indices in ([9], [0, 0], [-1]):
            with self.assertRaises(ValueError):
                self.log.signed_audit_receipt(bad_indices, _SEED_A)
        with self.assertRaises(TypeError):
            self.log.signed_audit_receipt([1], "0" * 32)
        with self.assertRaises(ValueError):
            self.log.signed_audit_receipt([1], _SEED_A[:-1])
        with self.assertRaises(ValueError):
            self.log.signed_audit_receipt([1], _SEED_A, 99)
        with self.assertRaises(TypeError):
            self.log.signed_audit_receipt([0], _SEED_A, True)
        self.assertEqual((len(self.log), self.log.head, self.log.merkle_root()), before)
        self.assertTrue(self.log.verify())


class VerifySignedAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)

    def bypass(self, *, receipt=None, checkpoint=None):
        bundle = SignedAuditReceipt.__new__(SignedAuditReceipt)
        object.__setattr__(
            bundle, "receipt", self.bundle.receipt if receipt is None else receipt
        )
        object.__setattr__(
            bundle,
            "checkpoint",
            self.bundle.checkpoint if checkpoint is None else checkpoint,
        )
        return bundle

    def test_genuine_bundles_verify(self):
        for chosen, size in (
            ([0], None),
            ([1, 3], None),
            ([3], 4),
            ([], None),
            ([], 3),
            ([0, 6], None),
            (range(7), None),
            ((), 0),
        ):
            self.assertTrue(
                verify_signed_audit_receipt(
                    self.log.signed_audit_receipt(chosen, _SEED_A, size),
                    self.public_key,
                ),
                (chosen, size),
            )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_audit_receipt(self.bundle, self.other_public_key)
        )

    def test_other_key_signing_returns_false(self):
        foreign = self.log.signed_audit_receipt([0, 2, 4], _SEED_B)
        self.assertEqual(foreign.receipt, self.bundle.receipt)
        self.assertFalse(
            verify_signed_audit_receipt(foreign, self.public_key)
        )
        self.assertTrue(
            verify_signed_audit_receipt(foreign, self.other_public_key)
        )

    def test_not_a_bundle_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signed_audit_receipt(self.bundle.receipt, self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_audit_receipt(None, self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_audit_receipt(
                (self.bundle.receipt, self.bundle.checkpoint), self.public_key
            )

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_audit_receipt(self.bundle, "0" * 32)
        with self.assertRaises(TypeError):
            verify_signed_audit_receipt(self.bundle, bytearray(self.public_key))
        with self.assertRaises(TypeError):
            verify_signed_audit_receipt(self.bundle, memoryview(self.public_key))
        with self.assertRaises(ValueError):
            verify_signed_audit_receipt(self.bundle, self.public_key[:-1])
        with self.assertRaises(ValueError):
            verify_signed_audit_receipt(self.bundle, self.public_key + b"\x00")

    def test_nested_receipt_type_errors_propagate(self):
        # A container field bypassed to the wrong type raises TypeError,
        # rather than being reported as False.
        broken = self.bypass(receipt=(self.bundle.receipt,))
        with self.assertRaises(TypeError):
            verify_signed_audit_receipt(broken, self.public_key)
        # A receipt field bypassed to the wrong type raises the same
        # TypeError the AuditReceipt constructor would.
        receipt = AuditReceipt.__new__(AuditReceipt)
        for name in ("version", "hash_name", "size", "root", "items"):
            object.__setattr__(
                receipt, name, getattr(self.bundle.receipt, name)
            )
        object.__setattr__(receipt, "version", "1")
        with self.assertRaises(TypeError):
            verify_signed_audit_receipt(
                self.bypass(receipt=receipt), self.public_key
            )

    def test_nested_receipt_value_errors_propagate(self):
        receipt = AuditReceipt.__new__(AuditReceipt)
        for name in ("version", "hash_name", "size", "root", "items"):
            object.__setattr__(
                receipt, name, getattr(self.bundle.receipt, name)
            )
        object.__setattr__(receipt, "hash_name", "not-a-hash")
        with self.assertRaises(ValueError):
            verify_signed_audit_receipt(
                self.bypass(receipt=receipt), self.public_key
            )

    def test_tampered_receipt_payload_returns_false(self):
        receipt = self.bundle.receipt
        entry, proof = receipt.items[0]
        tampered = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        forged_receipt = AuditReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            ((tampered, proof),) + receipt.items[1:],
        )
        forged = self.bypass(receipt=forged_receipt)
        self.assertFalse(verify_signed_audit_receipt(forged, self.public_key))

    def test_tampered_receipt_root_returns_false(self):
        receipt = self.bundle.receipt
        forged_receipt = AuditReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            b"\x11" * 32,
            receipt.items,
        )
        forged = self.bypass(receipt=forged_receipt)
        self.assertFalse(verify_signed_audit_receipt(forged, self.public_key))

    def test_tampered_checkpoint_signature_returns_false(self):
        checkpoint = self.bundle.checkpoint
        forged_checkpoint = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = self.bypass(checkpoint=forged_checkpoint)
        self.assertFalse(verify_signed_audit_receipt(forged, self.public_key))

    def test_mixed_size_returns_false(self):
        # Both parts are genuine and individually verifiable, but describe
        # different snapshot sizes.
        other = self.log.signed_audit_receipt([0, 2], _SEED_A, 4)
        forged = self.bypass(checkpoint=other.checkpoint)
        self.assertTrue(verify_audit_receipt(forged.receipt))
        self.assertTrue(verify_signed_root(forged.checkpoint, self.public_key))
        self.assertFalse(verify_signed_audit_receipt(forged, self.public_key))

    def test_mixed_root_returns_false(self):
        # Same size and key, but the checkpoint attests a different log's
        # root: the cross-check must reject it.
        other_log = AuditLog()
        for record in ("x", "y", "z", "w", "u", "v", "t"):
            other_log.append(record)
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass(checkpoint=foreign_checkpoint)
        self.assertTrue(verify_signed_root(forged.checkpoint, self.public_key))
        self.assertFalse(verify_signed_audit_receipt(forged, self.public_key))

    def test_mixed_hash_name_returns_false(self):
        other_log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            other_log.append(record)
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass(checkpoint=foreign_checkpoint)
        self.assertTrue(verify_signed_root(forged.checkpoint, self.public_key))
        self.assertFalse(verify_signed_audit_receipt(forged, self.public_key))

    def test_call_is_read_only(self):
        verify_signed_audit_receipt(self.bundle, self.other_public_key)
        self.assertEqual(
            self.bundle,
            self.log.signed_audit_receipt([0, 2, 4], _SEED_A),
        )


if __name__ == "__main__":
    unittest.main()
