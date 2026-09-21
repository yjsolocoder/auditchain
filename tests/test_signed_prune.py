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


class SignedPruneConstructionTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.receipt = self.log.seal(3)
        self.checkpoint = self.log.sign_root(_SEED_A, 3)

    def test_positional_construction_and_equality(self):
        item = SignedPrune(self.receipt, self.checkpoint)
        clone = SignedPrune(self.receipt, self.checkpoint)
        self.assertEqual(item, clone)
        self.assertEqual(item.receipt, self.receipt)
        self.assertEqual(item.checkpoint, self.checkpoint)
        # A bundle for another prefix is a different object.
        self.assertNotEqual(
            item,
            SignedPrune(self.log.seal(2), self.log.sign_root(_SEED_A, 2)),
        )

    def test_keyword_construction(self):
        item = SignedPrune(receipt=self.receipt, checkpoint=self.checkpoint)
        self.assertIs(item.receipt, self.receipt)
        self.assertIs(item.checkpoint, self.checkpoint)

    def test_frozen(self):
        item = SignedPrune(self.receipt, self.checkpoint)
        with self.assertRaises(FrozenInstanceError):
            item.receipt = self.receipt
        with self.assertRaises(FrozenInstanceError):
            item.checkpoint = self.checkpoint

    def test_receipt_must_be_prune_receipt(self):
        for bad in (
            None,
            1,
            "receipt",
            b"bytes",
            (),
            self.checkpoint,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SignedPrune(bad, self.checkpoint)

    def test_checkpoint_must_be_signed_root(self):
        for bad in (
            None,
            1,
            "checkpoint",
            b"bytes",
            (),
            self.receipt,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SignedPrune(self.receipt, bad)

    def test_parts_need_not_agree(self):
        # The container only checks shape: a receipt/checkpoint pair
        # describing different prefixes is constructible; linkage is left to
        # verify_signed_prune.
        item = SignedPrune(self.log.seal(2), self.log.sign_root(_SEED_A, 4))
        self.assertEqual(item.receipt.size, 2)
        self.assertEqual(item.checkpoint.size, 4)


class SignPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_combines_seal_and_sign_root(self):
        item = self.log.sign_prune(_SEED_A, 3)
        self.assertIsInstance(item, SignedPrune)
        self.assertEqual(item.receipt, self.log.seal(3))
        self.assertEqual(item.checkpoint, self.log.sign_root(_SEED_A, 3))
        self.assertEqual(item.receipt.hash_name, item.checkpoint.hash_name)
        self.assertEqual(item.receipt.size, item.checkpoint.size)
        self.assertEqual(item.receipt.merkle_root, item.checkpoint.root)
        self.assertEqual(item.receipt.chain_hash, item.checkpoint.head)

    def test_size_defaults_to_log_length(self):
        item = self.log.sign_prune(_SEED_A)
        self.assertEqual(item.receipt.size, len(self.log))
        self.assertEqual(item.checkpoint.size, len(self.log))
        self.assertEqual(item.receipt, self.log.seal())
        self.assertEqual(item.checkpoint, self.log.sign_root(_SEED_A))
        self.log.append("f")
        self.assertEqual(self.log.sign_prune(_SEED_A).receipt.size, 6)

    def test_fields(self):
        item = self.log.sign_prune(_SEED_A, 3)
        self.assertEqual(item.receipt.size, 3)
        self.assertEqual(item.receipt.merkle_root, self.log.merkle_root(3))
        self.assertEqual(item.receipt.chain_hash, self.log.entry(2).entry_hash)
        self.assertEqual(item.checkpoint.version, 1)
        self.assertEqual(item.checkpoint.root, self.log.merkle_root(3))
        self.assertEqual(item.checkpoint.head, self.log.entry(2).entry_hash)
        self.assertEqual(len(item.checkpoint.signature), 64)

    def test_empty_prefix(self):
        item = self.log.sign_prune(_SEED_A, 0)
        self.assertEqual(item.receipt.size, 0)
        self.assertEqual(item.checkpoint.size, 0)
        self.assertEqual(item.receipt.chain_hash, GENESIS_HASH)
        self.assertEqual(item.checkpoint.head, GENESIS_HASH)
        self.assertEqual(item.receipt.merkle_root, self.log.merkle_root(0))
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
        self.assertEqual(len(item.checkpoint.head), 64)
        self.assertTrue(verify_signed_prune(item, self.public_key))

    def test_after_prune(self):
        self.log.prune(3, self.log.seal(3))
        item = self.log.sign_prune(_SEED_A, 4)
        self.assertTrue(verify_signed_prune(item, self.public_key))
        with self.assertRaises(ValueError):
            self.log.sign_prune(_SEED_A, 2)

    def test_call_is_read_only(self):
        head = self.log.head
        root = self.log.merkle_root()
        keylog = AuditLog(key=b"shared-secret")
        keylog.append("a")
        self.log.sign_prune(_SEED_A)
        self.log.sign_prune(_SEED_A, 2)
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.merkle_root(), root)
        self.assertTrue(self.log.verify())
        self.assertEqual(keylog.stage, 0)

    def test_seed_validation(self):
        with self.assertRaises(TypeError):
            self.log.sign_prune("0" * 32)
        with self.assertRaises(TypeError):
            self.log.sign_prune(bytearray(_SEED_A))
        with self.assertRaises(ValueError):
            self.log.sign_prune(_SEED_A[:-1])

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.sign_prune(_SEED_A, "3")
        with self.assertRaises(TypeError):
            self.log.sign_prune(_SEED_A, True)
        with self.assertRaises(ValueError):
            self.log.sign_prune(_SEED_A, -1)
        with self.assertRaises(ValueError):
            self.log.sign_prune(_SEED_A, 6)

    def test_failure_changes_nothing(self):
        before = (
            self.log.head,
            len(self.log),
            self.log.retain_from,
            self.log.merkle_root(),
        )
        for make in (
            lambda: self.log.sign_prune("0" * 32),
            lambda: self.log.sign_prune(_SEED_A, 6),
        ):
            with self.assertRaises((TypeError, ValueError)):
                make()
            self.assertEqual(
                (
                    self.log.head,
                    len(self.log),
                    self.log.retain_from,
                    self.log.merkle_root(),
                ),
                before,
            )


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

    def test_genuine_bundles_verify(self):
        for size in (None, 0, 1, 3, 5):
            item = self.log.sign_prune(_SEED_A, size)
            self.assertTrue(verify_signed_prune(item, self.public_key), size)

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_prune(self.item, self.other_public_key)
        )

    def test_other_key_signing_same_fields_returns_false(self):
        foreign = self.log.sign_prune(_SEED_B, 3)
        self.assertEqual(foreign.receipt, self.item.receipt)
        self.assertFalse(verify_signed_prune(foreign, self.public_key))
        self.assertTrue(
            verify_signed_prune(foreign, self.other_public_key)
        )

    def test_disagreeing_size_returns_false(self):
        receipt = self.log.seal(2)
        forged = SignedPrune(receipt, self.item.checkpoint)
        self.assertFalse(verify_signed_prune(forged, self.public_key))

    def test_disagreeing_root_returns_false(self):
        receipt = self.item.receipt
        forged_receipt = PruneReceipt(
            receipt.hash_name,
            receipt.size,
            b"\x00" * 32,
            receipt.chain_hash,
        )
        self.assertFalse(
            verify_signed_prune(
                SignedPrune(forged_receipt, self.item.checkpoint),
                self.public_key,
            )
        )

    def test_disagreeing_head_returns_false(self):
        receipt = self.item.receipt
        forged_receipt = PruneReceipt(
            receipt.hash_name,
            receipt.size,
            receipt.merkle_root,
            b"\x01" * 32,
        )
        self.assertFalse(
            verify_signed_prune(
                SignedPrune(forged_receipt, self.item.checkpoint),
                self.public_key,
            )
        )

    def test_tampered_checkpoint_signature_returns_false(self):
        checkpoint = self.item.checkpoint
        bogus = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = SignedPrune(self.item.receipt, bogus)
        self.assertFalse(verify_signed_prune(forged, self.public_key))

    def test_checkpoint_of_another_prefix_returns_false(self):
        # A genuine signature and receipt, just not over the same prefix.
        forged = SignedPrune(
            self.log.seal(3), self.log.sign_root(_SEED_A, 4)
        )
        self.assertFalse(verify_signed_prune(forged, self.public_key))

    def test_disagreeing_hash_name_returns_false(self):
        # Both parts carry sha256-width 32-byte digests, so relabeling the
        # receipt's algorithm (sha3-256 is also 32 bytes) keeps both parts
        # structurally valid; the algorithm disagreement is a linkage mismatch
        # the signature cannot cover and returns False.
        receipt = self.item.receipt
        relabeled = PruneReceipt(
            "sha3-256",
            receipt.size,
            receipt.merkle_root,
            receipt.chain_hash,
        )
        forged = SignedPrune(relabeled, self.item.checkpoint)
        self.assertFalse(verify_signed_prune(forged, self.public_key))

    def test_structurally_invalid_nested_receipt_raises_value_error(self):
        # A 16-byte digest under a sha256 label is not a valid PruneReceipt;
        # the nested structural ValueError propagates rather than becoming
        # False, exactly as the baseline prune receipt contract specifies.
        checkpoint = self.item.checkpoint
        bad_receipt = PruneReceipt.__new__(PruneReceipt)
        object.__setattr__(bad_receipt, "hash_name", "sha256")
        object.__setattr__(bad_receipt, "size", checkpoint.size)
        object.__setattr__(bad_receipt, "merkle_root", checkpoint.root[:16])
        object.__setattr__(bad_receipt, "chain_hash", checkpoint.head[:16])
        forged = self.bypass(receipt=bad_receipt)
        with self.assertRaises(ValueError):
            verify_signed_prune(forged, self.public_key)

    def test_not_a_bundle_raises(self):
        for bad in (
            None,
            1,
            "item",
            b"bytes",
            (),
            (self.item.receipt, self.item.checkpoint),
            self.item.receipt,
            self.item.checkpoint,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_signed_prune(bad, self.public_key)

    def test_bypassed_container_field_types_raise_type_error(self):
        for field, value in (
            ("receipt", None),
            ("receipt", self.item.checkpoint),
            ("receipt", "not-a-receipt"),
            ("checkpoint", None),
            ("checkpoint", self.item.receipt),
            ("checkpoint", "not-a-checkpoint"),
        ):
            forged = self.bypass(
                **{
                    field: value,
                }
            )
            with self.assertRaises(TypeError, msg=field):
                verify_signed_prune(forged, self.public_key)

    def test_nested_checkpoint_value_error_propagates(self):
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
                checkpoint, name, getattr(self.item.checkpoint, name)
            )
        object.__setattr__(checkpoint, "version", 2)
        forged = self.bypass(checkpoint=checkpoint)
        with self.assertRaises(ValueError):
            verify_signed_prune(forged, self.public_key)

    def test_nested_checkpoint_type_error_propagates(self):
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
                checkpoint, name, getattr(self.item.checkpoint, name)
            )
        object.__setattr__(checkpoint, "version", "1")
        forged = self.bypass(checkpoint=checkpoint)
        with self.assertRaises(TypeError):
            verify_signed_prune(forged, self.public_key)

    def test_nested_receipt_type_error_propagates(self):
        receipt = PruneReceipt.__new__(PruneReceipt)
        for name in ("hash_name", "size", "merkle_root", "chain_hash"):
            object.__setattr__(receipt, name, getattr(self.item.receipt, name))
        object.__setattr__(receipt, "hash_name", 123)
        forged = self.bypass(receipt=receipt)
        with self.assertRaises(TypeError):
            verify_signed_prune(forged, self.public_key)

    def test_nested_receipt_unknown_hash_value_error_propagates(self):
        receipt = PruneReceipt.__new__(PruneReceipt)
        object.__setattr__(receipt, "hash_name", "not-a-hash")
        object.__setattr__(receipt, "size", 3)
        object.__setattr__(receipt, "merkle_root", b"\x00" * 32)
        object.__setattr__(receipt, "chain_hash", b"\x00" * 32)
        forged = self.bypass(receipt=receipt)
        with self.assertRaises(ValueError):
            verify_signed_prune(forged, self.public_key)

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
        self.records = [f"record-{i}" for i in range(7)]
        self.log = AuditLog()
        for record in self.records:
            self.log.append(record)
        self.twin = AuditLog()
        for record in self.records:
            self.twin.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_successful_signed_prune(self):
        item = self.log.sign_prune(_SEED_A, 3)
        self.log.prune_signed(3, item, self.public_key)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(len(self.log), 7)
        self.assertEqual([e.index for e in self.log.entries()], [3, 4, 5, 6])
        self.assertEqual(self.log.head, self.twin.head)
        self.assertTrue(self.log.verify())
        for size in range(3, 8):
            self.assertEqual(
                self.log.merkle_root(size), self.twin.merkle_root(size)
            )

    def test_prune_everything(self):
        head_before = self.log.head
        item = self.log.sign_prune(_SEED_A)
        self.log.prune_signed(7, item, self.public_key)
        self.assertEqual(self.log.retain_from, 7)
        self.assertEqual(self.log.entries(), [])
        self.assertEqual(self.log.head, head_before)
        self.assertTrue(self.log.verify())

    def test_empty_prefix(self):
        log = AuditLog()
        log.append("a")
        item = log.sign_prune(_SEED_A, 0)
        log.prune_signed(0, item, self.public_key)
        self.assertEqual(log.retain_from, 0)
        self.assertTrue(log.verify())

    def test_wrong_key_raises_and_changes_nothing(self):
        item = self.log.sign_prune(_SEED_A, 3)
        with self.assertRaises(ValueError):
            self.log.prune_signed(3, item, self.other_public_key)
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 7)
        self.assertEqual(self.log.entry(0).payload, b"record-0")
        self.assertTrue(self.log.verify())
        self.assertEqual(self.log.head, self.twin.head)

    def test_unauthorized_bundle_raises_and_changes_nothing(self):
        # A genuine receipt signed by nobody trusted: bundle the receipt with
        # another key's checkpoint over a different prefix -> verify False.
        receipt = self.log.seal(3)
        foreign_checkpoint = AuditLog().sign_root(_SEED_B, 0)
        item = SignedPrune(receipt, foreign_checkpoint)
        with self.assertRaises(ValueError):
            self.log.prune_signed(3, item, self.public_key)
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 7)
        self.assertTrue(self.log.verify())

    def test_retain_must_equal_size(self):
        item = self.log.sign_prune(_SEED_A, 3)
        for n in (0, 2, 4, 7):
            with self.assertRaises(ValueError, msg=n):
                self.log.prune_signed(n, item, self.public_key)
        self.assertEqual(self.log.retain_from, 0)
        self.assertEqual(len(self.log), 7)

    def test_out_of_bounds(self):
        item = self.log.sign_prune(_SEED_A, 3)
        for n in (-1, 8):
            with self.assertRaises(ValueError, msg=n):
                self.log.prune_signed(n, item, self.public_key)

    def test_retain_from_type(self):
        item = self.log.sign_prune(_SEED_A, 3)
        with self.assertRaises(TypeError):
            self.log.prune_signed(True, item, self.public_key)
        with self.assertRaises(TypeError):
            self.log.prune_signed(3.0, item, self.public_key)
        with self.assertRaises(TypeError):
            self.log.prune_signed("3", item, self.public_key)

    def test_not_a_bundle_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.log.prune_signed(3, None, self.public_key)
        with self.assertRaises(TypeError):
            self.log.prune_signed(3, ("not", "a", "bundle"), self.public_key)

    def test_bad_key_type_propagates(self):
        item = self.log.sign_prune(_SEED_A, 3)
        with self.assertRaises(TypeError):
            self.log.prune_signed(3, item, "0" * 32)
        with self.assertRaises(ValueError):
            self.log.prune_signed(3, item, self.public_key[:-1])

    def test_append_after_signed_prune_matches_twin(self):
        item = self.log.sign_prune(_SEED_A, 3)
        self.log.prune_signed(3, item, self.public_key)
        entry = self.log.append("record-7")
        self.twin.append("record-7")
        self.assertEqual(entry, self.twin.entry(7))
        self.assertEqual(self.log.head, self.twin.head)
        self.assertTrue(self.log.verify())

    def test_repeated_signed_prune(self):
        self.log.prune_signed(
            2, self.log.sign_prune(_SEED_A, 2), self.public_key
        )
        self.twin.append("r10")
        self.log.append("r10")
        self.log.prune_signed(
            7, self.log.sign_prune(_SEED_A, 7), self.public_key
        )
        self.assertEqual(self.log.retain_from, 7)
        self.assertEqual([e.index for e in self.log.entries()], [7])
        self.assertTrue(self.log.verify())

    def test_signed_prune_then_plain_prune_at_same_point(self):
        # Authorization passes once; re-applying the same point stays a no-op
        # exactly like plain prune.
        item = self.log.sign_prune(_SEED_A, 3)
        self.log.prune_signed(3, item, self.public_key)
        self.log.prune(3, item.receipt)
        self.assertEqual(self.log.retain_from, 3)
        self.assertTrue(self.log.verify())

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        twin = AuditLog(hash_name="sha3-256")
        for i in range(6):
            log.append(f"r{i}")
            twin.append(f"r{i}")
        item = log.sign_prune(_SEED_A, 4)
        log.prune_signed(4, item, self.public_key)
        self.assertEqual(log.retain_from, 4)
        self.assertEqual(log.head, twin.head)
        self.assertTrue(log.verify())

    def test_failure_after_a_prior_prune_changes_nothing(self):
        self.log.prune(3, self.log.seal(3))
        retained = [e.index for e in self.log.entries()]
        # A checkpoint signed by an untrusted key must never move the retain
        # point (here it would move it forward to 5).
        forged = SignedPrune(
            self.log.seal(5), self.log.sign_root(_SEED_B, 5)
        )
        with self.assertRaises(ValueError):
            self.log.prune_signed(5, forged, self.public_key)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual([e.index for e in self.log.entries()], retained)
        self.assertTrue(self.log.verify())


if __name__ == "__main__":
    unittest.main()
