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
    PruneReceipt,
    SignedPrune,
    SignedRoot,
    verify_signed_prune,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


class SignPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_fields(self):
        item = self.log.sign_prune(_SEED_A, 3)
        self.assertIsInstance(item, SignedPrune)
        self.assertEqual(item.receipt, self.log.seal(3))
        self.assertEqual(item.checkpoint, self.log.sign_root(_SEED_A, 3))
        receipt = item.receipt
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 3)
        self.assertEqual(receipt.merkle_root, self.log.merkle_root(3))
        self.assertEqual(receipt.chain_hash, self.log.entry(2).entry_hash)
        checkpoint = item.checkpoint
        self.assertEqual(checkpoint.size, 3)
        self.assertEqual(checkpoint.root, receipt.merkle_root)
        self.assertEqual(checkpoint.head, receipt.chain_hash)

    def test_combines_seal_and_sign_root(self):
        item = self.log.sign_prune(_SEED_A, 4)
        self.assertEqual(item, SignedPrune(self.log.seal(4), self.log.sign_root(_SEED_A, 4)))

    def test_size_defaults_to_log_length(self):
        item = self.log.sign_prune(_SEED_A)
        self.assertEqual(item.receipt.size, len(self.log))
        self.assertEqual(item.checkpoint.size, len(self.log))
        self.log.append("f")
        self.assertEqual(self.log.sign_prune(_SEED_A).receipt.size, 6)

    def test_empty_prefix(self):
        item = self.log.sign_prune(_SEED_A, 0)
        self.assertEqual(item.receipt.size, 0)
        self.assertEqual(item.checkpoint.size, 0)
        self.assertEqual(item.receipt.merkle_root, self.log.merkle_root(0))
        self.assertEqual(item.receipt.chain_hash, GENESIS_HASH)
        self.assertEqual(item.checkpoint.head, GENESIS_HASH)
        self.assertTrue(verify_signed_prune(item, self.public_key))

    def test_empty_log(self):
        item = AuditLog().sign_prune(_SEED_A)
        self.assertEqual(item.receipt.size, 0)
        self.assertTrue(verify_signed_prune(item, self.public_key))

    def test_survives_later_appends(self):
        item = self.log.sign_prune(_SEED_A, 4)
        self.log.append("f")
        self.assertTrue(verify_signed_prune(item, self.public_key))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        item = log.sign_prune(_SEED_A)
        self.assertEqual(item.receipt.hash_name, "sha512")
        self.assertEqual(item.checkpoint.hash_name, "sha512")
        self.assertEqual(len(item.receipt.merkle_root), 64)
        self.assertEqual(len(item.receipt.chain_hash), 64)
        self.assertTrue(verify_signed_prune(item, self.public_key))

    def test_pruned_prefix_cannot_be_signed(self):
        self.log.prune(3, self.log.seal(3))
        item = self.log.sign_prune(_SEED_A, 4)
        self.assertTrue(verify_signed_prune(item, self.public_key))
        with self.assertRaises(ValueError):
            self.log.sign_prune(_SEED_A, 2)

    def test_positional_construction_and_equality(self):
        item = self.log.sign_prune(_SEED_A)
        clone = SignedPrune(item.receipt, item.checkpoint)
        self.assertEqual(item, clone)
        self.assertNotEqual(item, self.log.sign_prune(_SEED_A, 3))

    def test_frozen(self):
        item = self.log.sign_prune(_SEED_A)
        with self.assertRaises(FrozenInstanceError):
            item.receipt = item.receipt
        with self.assertRaises(FrozenInstanceError):
            item.checkpoint = item.checkpoint

    def test_call_is_read_only(self):
        head = self.log.head
        root = self.log.merkle_root()
        self.log.sign_prune(_SEED_A)
        self.log.sign_prune(_SEED_A, 2)
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.merkle_root(), root)
        self.assertEqual(self.log.retain_from, 0)
        self.assertTrue(self.log.verify())

    def test_seed_validation(self):
        with self.assertRaises(TypeError):
            self.log.sign_prune("0" * 32)
        with self.assertRaises(TypeError):
            self.log.sign_prune(bytearray(_SEED_A))
        with self.assertRaises(TypeError):
            self.log.sign_prune(memoryview(_SEED_A))
        with self.assertRaises(ValueError):
            self.log.sign_prune(_SEED_A[:-1])
        with self.assertRaises(ValueError):
            self.log.sign_prune(_SEED_A + b"\x00")

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.sign_prune(_SEED_A, "3")
        with self.assertRaises(TypeError):
            self.log.sign_prune(_SEED_A, True)
        with self.assertRaises(ValueError):
            self.log.sign_prune(_SEED_A, -1)
        with self.assertRaises(ValueError):
            self.log.sign_prune(_SEED_A, 6)


class SignedPruneValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.item = self.log.sign_prune(_SEED_A, 2)

    def test_receipt_must_be_prune_receipt(self):
        with self.assertRaises(TypeError):
            SignedPrune(("not", "a", "receipt"), self.item.checkpoint)
        with self.assertRaises(TypeError):
            SignedPrune(None, self.item.checkpoint)
        with self.assertRaises(TypeError):
            SignedPrune(self.item.checkpoint, self.item.checkpoint)

    def test_checkpoint_must_be_signed_root(self):
        with self.assertRaises(TypeError):
            SignedPrune(self.item.receipt, ("not", "a", "checkpoint"))
        with self.assertRaises(TypeError):
            SignedPrune(self.item.receipt, None)
        with self.assertRaises(TypeError):
            SignedPrune(self.item.receipt, self.item.receipt)


class VerifySignedPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.item = self.log.sign_prune(_SEED_A, 3)

    def bypass(self, **fields):
        item = SignedPrune.__new__(SignedPrune)
        defaults = {
            "receipt": self.item.receipt,
            "checkpoint": self.item.checkpoint,
        }
        defaults.update(fields)
        for name, value in defaults.items():
            object.__setattr__(item, name, value)
        return item

    def replace_receipt(self, **overrides):
        receipt = self.item.receipt
        values = {
            "hash_name": receipt.hash_name,
            "size": receipt.size,
            "merkle_root": receipt.merkle_root,
            "chain_hash": receipt.chain_hash,
        }
        values.update(overrides)
        return PruneReceipt(**values)

    def replace_checkpoint(self, **overrides):
        checkpoint = self.item.checkpoint
        values = {
            "version": checkpoint.version,
            "hash_name": checkpoint.hash_name,
            "size": checkpoint.size,
            "root": checkpoint.root,
            "head": checkpoint.head,
            "signature": checkpoint.signature,
        }
        values.update(overrides)
        return SignedRoot(**values)

    def test_genuine_items_verify(self):
        for size in (None, 0, 1, 3, 5):
            item = self.log.sign_prune(_SEED_A, size)
            self.assertTrue(verify_signed_prune(item, self.public_key), size)

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(verify_signed_prune(self.item, self.other_public_key))

    def test_other_key_signing_same_fields_returns_false(self):
        foreign = self.log.sign_prune(_SEED_B, 3)
        self.assertEqual(foreign.receipt, self.item.receipt)
        self.assertFalse(verify_signed_prune(foreign, self.public_key))
        self.assertTrue(verify_signed_prune(foreign, self.other_public_key))

    def test_size_disagreement_returns_false(self):
        forged = SignedPrune(self.replace_receipt(size=2), self.item.checkpoint)
        self.assertFalse(verify_signed_prune(forged, self.public_key))
        forged = SignedPrune(self.item.receipt, self.replace_checkpoint(size=2))
        self.assertFalse(verify_signed_prune(forged, self.public_key))

    def test_root_disagreement_returns_false(self):
        forged = SignedPrune(
            self.replace_receipt(merkle_root=b"\x00" * 32),
            self.item.checkpoint,
        )
        self.assertFalse(verify_signed_prune(forged, self.public_key))

    def test_head_disagreement_returns_false(self):
        forged = SignedPrune(
            self.replace_receipt(chain_hash=b"\x00" * 32),
            self.item.checkpoint,
        )
        self.assertFalse(verify_signed_prune(forged, self.public_key))

    def test_checkpoint_fields_tampered_return_false(self):
        self.assertFalse(
            verify_signed_prune(
                SignedPrune(
                    self.item.receipt, self.replace_checkpoint(root=b"\x00" * 32)
                ),
                self.public_key,
            )
        )
        self.assertFalse(
            verify_signed_prune(
                SignedPrune(
                    self.item.receipt, self.replace_checkpoint(head=b"\x00" * 32)
                ),
                self.public_key,
            )
        )
        self.assertFalse(
            verify_signed_prune(
                SignedPrune(
                    self.item.receipt,
                    self.replace_checkpoint(signature=b"\x00" * 64),
                ),
                self.public_key,
            )
        )

    def test_hash_algorithm_disagreement_returns_false(self):
        # A structurally valid sha512-width receipt paired with the sha256
        # checkpoint is a linkage mismatch, not a structural error.
        foreign = self.replace_receipt(
            hash_name="sha512", merkle_root=b"\x00" * 64, chain_hash=b"\x00" * 64
        )
        forged = SignedPrune(foreign, self.item.checkpoint)
        self.assertFalse(verify_signed_prune(forged, self.public_key))

    def test_mismatched_but_individiously_valid_pair_returns_false(self):
        # A genuine receipt for size 2 paired with a genuine checkpoint for
        # size 3: both verify individually, the pair does not.
        other = self.log.sign_prune(_SEED_A, 2)
        forged = SignedPrune(other.receipt, self.item.checkpoint)
        self.assertFalse(verify_signed_prune(forged, self.public_key))

    def test_not_an_item_raises(self):
        with self.assertRaises(TypeError):
            verify_signed_prune(("not", "an", "item"), self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_prune(None, self.public_key)

    def test_bypassed_container_field_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            verify_signed_prune(self.bypass(receipt=None), self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_prune(
                self.bypass(receipt=self.item.checkpoint), self.public_key
            )
        with self.assertRaises(TypeError):
            verify_signed_prune(
                self.bypass(checkpoint=None), self.public_key
            )
        with self.assertRaises(TypeError):
            verify_signed_prune(
                self.bypass(checkpoint=self.item.receipt), self.public_key
            )

    def bypass_receipt(self, **fields):
        receipt = PruneReceipt.__new__(PruneReceipt)
        defaults = {
            "hash_name": self.item.receipt.hash_name,
            "size": self.item.receipt.size,
            "merkle_root": self.item.receipt.merkle_root,
            "chain_hash": self.item.receipt.chain_hash,
        }
        defaults.update(fields)
        for name, value in defaults.items():
            object.__setattr__(receipt, name, value)
        return self.bypass(receipt=receipt)

    def test_bypassed_receipt_type_corruption_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signed_prune(
                self.bypass_receipt(hash_name=123), self.public_key
            )

    def test_bypassed_receipt_value_corruption_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_signed_prune(
                self.bypass_receipt(size=-1), self.public_key
            )
        with self.assertRaises(ValueError):
            verify_signed_prune(
                self.bypass_receipt(merkle_root=b"\x00" * 31),
                self.public_key,
            )

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_prune(self.item, "0" * 32)
        with self.assertRaises(TypeError):
            verify_signed_prune(self.item, bytearray(self.public_key))
        with self.assertRaises(TypeError):
            verify_signed_prune(self.item, memoryview(self.public_key))
        with self.assertRaises(ValueError):
            verify_signed_prune(self.item, self.public_key[:-1])
        with self.assertRaises(ValueError):
            verify_signed_prune(self.item, self.public_key + b"\x00")

    def test_call_is_read_only(self):
        verify_signed_prune(self.item, self.other_public_key)
        self.assertEqual(self.item, self.log.sign_prune(_SEED_A, 3))


class PruneSignedTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def snapshot(self):
        return (
            self.log.retain_from,
            len(self.log),
            self.log.head,
            [entry.payload for entry in self.log.entries()],
        )

    def test_prune_signed_succeeds(self):
        item = self.log.sign_prune(_SEED_A, 3)
        self.log.prune_signed(3, item, self.public_key)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(len(self.log), 5)
        self.assertEqual([entry.index for entry in self.log.entries()], [3, 4])
        self.assertTrue(self.log.verify())

    def test_prune_signed_at_tip(self):
        head_before = self.log.head
        item = self.log.sign_prune(_SEED_A, 5)
        self.log.prune_signed(5, item, self.public_key)
        self.assertEqual(self.log.entries(), [])
        self.assertEqual(self.log.head, head_before)
        entry = self.log.append("f")
        self.assertEqual(entry.index, 5)
        self.assertEqual(entry.previous_hash, head_before)
        self.assertTrue(self.log.verify())

    def test_empty_prefix(self):
        item = self.log.sign_prune(_SEED_A, 0)
        self.log.prune_signed(0, item, self.public_key)
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 5)
        self.assertTrue(self.log.verify())

    def test_idempotent(self):
        item = self.log.sign_prune(_SEED_A, 3)
        self.log.prune_signed(3, item, self.public_key)
        self.log.prune_signed(3, item, self.public_key)
        self.assertEqual(self.log.retain_from, 3)
        self.assertTrue(self.log.verify())

    def test_wrong_key_raises_and_changes_nothing(self):
        item = self.log.sign_prune(_SEED_A, 3)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.log.prune_signed(3, item, self.other_public_key)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.log.retain_from, 0)

    def test_tampered_item_raises_and_changes_nothing(self):
        item = self.log.sign_prune(_SEED_A, 3)
        receipt = item.receipt
        forged_receipt = PruneReceipt(
            receipt.hash_name,
            receipt.size,
            b"\x00" * 32,
            receipt.chain_hash,
        )
        forged = SignedPrune(forged_receipt, item.checkpoint)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.log.prune_signed(3, forged, self.public_key)
        self.assertEqual(self.snapshot(), before)

    def test_n_must_equal_receipt_size(self):
        item = self.log.sign_prune(_SEED_A, 3)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.log.prune_signed(2, item, self.public_key)
        with self.assertRaises(ValueError):
            self.log.prune_signed(4, item, self.public_key)
        self.assertEqual(self.snapshot(), before)

    def test_cannot_move_backwards(self):
        item = self.log.sign_prune(_SEED_A, 3)
        self.log.prune_signed(3, item, self.public_key)
        # A genuine signed item for an earlier prefix comes from an unpruned
        # twin holding the same records; verification passes, but the log
        # refuses to move its retain point from 3 back to 2.
        twin = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            twin.append(record)
        older = twin.sign_prune(_SEED_A, 2)
        with self.assertRaises(ValueError):
            self.log.prune_signed(2, older, self.public_key)
        self.assertEqual(self.log.retain_from, 3)

    def test_wrong_hash_log_raises_and_changes_nothing(self):
        other = AuditLog(hash_name="sha3-256")
        for record in ("a", "b"):
            other.append(record)
        item = other.sign_prune(_SEED_A, 2)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.log.prune_signed(2, item, self.public_key)
        self.assertEqual(self.snapshot(), before)

    def test_item_type_error(self):
        with self.assertRaises(TypeError):
            self.log.prune_signed(2, ("not", "an", "item"), self.public_key)
        with self.assertRaises(TypeError):
            self.log.prune_signed(2, None, self.public_key)
        self.assertEqual(self.log.retain_from, 0)

    def test_n_type_error(self):
        item = self.log.sign_prune(_SEED_A, 3)
        with self.assertRaises(TypeError):
            self.log.prune_signed(3.0, item, self.public_key)
        with self.assertRaises(TypeError):
            self.log.prune_signed(True, item, self.public_key)

    def test_key_type_and_length(self):
        item = self.log.sign_prune(_SEED_A, 3)
        with self.assertRaises(TypeError):
            self.log.prune_signed(3, item, "0" * 32)
        with self.assertRaises(ValueError):
            self.log.prune_signed(3, item, self.public_key[:-1])
        self.assertEqual(self.log.retain_from, 0)


if __name__ == "__main__":
    unittest.main()
