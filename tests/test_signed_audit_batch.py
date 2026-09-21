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
    Entry,
    SignedAuditBatch,
    SignedRoot,
    verify_audit_batch,
    verify_signed_audit_batch,
    verify_signed_root,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _blob(material: bytes) -> bytes:
    return _u64(len(material)) + material


def _signed_message(hash_name: str, size: int, root: bytes, head: bytes) -> bytes:
    return (
        b"auditchain/signed-root/v1\0"
        + b"\x01"
        + _blob(hash_name.encode("utf-8"))
        + _u64(size)
        + _blob(root)
        + _blob(head)
    )


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


class SignedAuditBatchIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_bundles_batch_and_checkpoint_of_same_snapshot(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        self.assertIsInstance(receipt, SignedAuditBatch)
        self.assertEqual(receipt.batch, self.log.audit_batch([1, 3]))
        self.assertEqual(receipt.checkpoint, self.log.sign_root(_SEED_A))
        hash_name, size, root, entries, proof = receipt.batch
        self.assertEqual(hash_name, receipt.checkpoint.hash_name)
        self.assertEqual(size, receipt.checkpoint.size)
        self.assertEqual(root, receipt.checkpoint.root)
        self.assertEqual(entries[-1].entry_hash, receipt.checkpoint.head)

    def test_size_defaults_to_log_length(self):
        receipt = self.log.signed_audit_batch([0], _SEED_A)
        self.assertEqual(receipt.batch[1], len(self.log))
        self.assertEqual(receipt.checkpoint.size, len(self.log))
        self.log.append("f")
        receipt = self.log.signed_audit_batch([0], _SEED_A)
        self.assertEqual(receipt.batch[1], 6)
        self.assertEqual(receipt.checkpoint.size, 6)

    def test_explicit_size(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A, 3)
        self.assertEqual(receipt.batch[1], 3)
        self.assertEqual(receipt.checkpoint.size, 3)
        self.assertEqual(receipt.batch[2], self.log.merkle_root(3))
        self.assertEqual(
            receipt.checkpoint.head, self.log.entry(2).entry_hash
        )
        self.assertTrue(
            verify_signed_audit_batch(receipt, self.public_key)
        )

    def test_genuine_receipts_verify_offline(self):
        for indices, size in (
            ([1, 3], None),
            ([], None),
            ([0], 1),
            ([1], 3),
            ((), 0),
        ):
            receipt = self.log.signed_audit_batch(indices, _SEED_A, size)
            self.assertTrue(
                verify_signed_audit_batch(receipt, self.public_key),
                (indices, size),
            )

    def test_survives_later_appends(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A, 4)
        self.log.append("f")
        self.assertTrue(
            verify_signed_audit_batch(receipt, self.public_key)
        )

    def test_empty_log(self):
        receipt = AuditLog().signed_audit_batch((), _SEED_A)
        self.assertEqual(receipt.batch[1], 0)
        self.assertEqual(receipt.batch[3], ())
        self.assertEqual(receipt.checkpoint.size, 0)
        self.assertEqual(receipt.checkpoint.head, GENESIS_HASH)
        self.assertTrue(
            verify_signed_audit_batch(receipt, self.public_key)
        )

    def test_empty_snapshot_zero_width_head(self):
        receipt = self.log.signed_audit_batch((), _SEED_A, 0)
        self.assertEqual(receipt.batch[3], ())
        self.assertEqual(receipt.checkpoint.head, bytes(32))
        self.assertTrue(
            verify_signed_audit_batch(receipt, self.public_key)
        )

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        receipt = log.signed_audit_batch([0], _SEED_A)
        self.assertEqual(receipt.batch[0], "sha512")
        self.assertEqual(len(receipt.checkpoint.head), 64)
        self.assertTrue(
            verify_signed_audit_batch(receipt, self.public_key)
        )

    def test_pruned_log_prefix(self):
        self.log.prune(3, self.log.seal(3))
        receipt = self.log.signed_audit_batch([3], _SEED_A, 4)
        self.assertTrue(
            verify_signed_audit_batch(receipt, self.public_key)
        )

    def test_positional_construction_and_equality(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        clone = SignedAuditBatch(receipt.batch, receipt.checkpoint)
        self.assertEqual(receipt, clone)
        other = self.log.signed_audit_batch([1, 3], _SEED_A, 4)
        self.assertNotEqual(receipt, other)
        self.assertNotEqual(receipt, (receipt.batch, receipt.checkpoint))

    def test_receipt_is_frozen(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        with self.assertRaises(FrozenInstanceError):
            receipt.batch = ()
        with self.assertRaises(FrozenInstanceError):
            receipt.checkpoint = receipt.checkpoint

    def test_call_is_read_only(self):
        head = self.log.head
        root = self.log.merkle_root()
        stage_log = AuditLog(key=b"shared-secret")
        stage_log.append("a")
        self.log.signed_audit_batch([1, 3], _SEED_A)
        self.log.signed_audit_batch([1], _SEED_A, 3)
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.merkle_root(), root)
        self.assertTrue(self.log.verify())
        self.assertEqual(stage_log.stage, 0)

    def test_failure_leaves_state_unchanged(self):
        head = self.log.head
        length = len(self.log)
        with self.assertRaises(ValueError):
            self.log.signed_audit_batch([99], _SEED_A)
        with self.assertRaises(TypeError):
            self.log.signed_audit_batch([1], "0" * 32)
        with self.assertRaises(ValueError):
            self.log.signed_audit_batch([1], _SEED_A[:-1])
        self.assertEqual(len(self.log), length)
        self.assertEqual(self.log.head, head)
        self.assertTrue(self.log.verify())

    def test_batch_is_built_before_signing(self):
        # Bad indices must surface from audit_batch before the key is ever
        # touched, so an invalid index plus an invalid key reports the index
        # failure and no signature material is produced.
        with self.assertRaises(ValueError):
            self.log.signed_audit_batch([99], "0" * 32)


class SignedAuditBatchConstructionTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.checkpoint = self.log.sign_root(_SEED_A)

    def test_batch_must_be_tuple(self):
        with self.assertRaises(TypeError):
            SignedAuditBatch([], self.checkpoint)
        with self.assertRaises(TypeError):
            SignedAuditBatch(None, self.checkpoint)

    def test_checkpoint_must_be_signed_root(self):
        with self.assertRaises(TypeError):
            SignedAuditBatch((), ("not", "a", "checkpoint"))
        with self.assertRaises(TypeError):
            SignedAuditBatch((), None)

    def test_nested_validation_is_deferred_to_verifiers(self):
        # Only the field types are checked: any tuple batch is constructible;
        # nested structural problems surface through the existing validators.
        loose = SignedAuditBatch((1, 2), self.checkpoint)
        self.assertEqual(loose.batch, (1, 2))


class VerifySignedAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.receipt = self.log.signed_audit_batch([1, 3], _SEED_A)

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_audit_batch(self.receipt, self.other_public_key)
        )

    def test_not_a_receipt_raises(self):
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(
                (self.receipt.batch, self.receipt.checkpoint),
                self.public_key,
            )
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(None, self.public_key)

    def test_bypassed_field_types_raise(self):
        receipt = SignedAuditBatch.__new__(SignedAuditBatch)
        object.__setattr__(receipt, "batch", [])
        object.__setattr__(
            receipt, "checkpoint", self.receipt.checkpoint
        )
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(receipt, self.public_key)

        receipt = SignedAuditBatch.__new__(SignedAuditBatch)
        object.__setattr__(receipt, "batch", self.receipt.batch)
        object.__setattr__(receipt, "checkpoint", None)
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(receipt, self.public_key)

    def test_nested_type_errors_propagate(self):
        bad = SignedAuditBatch(
            ("sha256", 5, b"", (), ()), self.receipt.checkpoint
        )
        with self.assertRaises(ValueError):
            verify_signed_audit_batch(bad, self.public_key)
        bad = SignedAuditBatch(
            (123, 5, b"\x00" * 32, (), ()), self.receipt.checkpoint
        )
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(bad, self.public_key)

    def test_public_key_validation_propagates(self):
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(self.receipt, "0" * 32)
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(
                self.receipt, bytearray(self.public_key)
            )
        with self.assertRaises(ValueError):
            verify_signed_audit_batch(
                self.receipt, self.public_key[:-1]
            )

    def test_tampered_batch_entry_returns_false(self):
        hash_name, size, root, entries, proof = self.receipt.batch
        bad_entry = Entry(
            entries[-1].index,
            b"tampered",
            entries[-1].previous_hash,
            entries[-1].entry_hash,
        )
        tampered_entries = entries[:-1] + (bad_entry,)
        batch = (hash_name, size, root, tampered_entries, proof)
        tampered = SignedAuditBatch(batch, self.receipt.checkpoint)
        self.assertFalse(
            verify_signed_audit_batch(tampered, self.public_key)
        )

    def test_tampered_batch_root_returns_false(self):
        hash_name, size, root, entries, proof = self.receipt.batch
        other_root = bytes(0xFF for _ in root)
        batch = (hash_name, size, other_root, entries, proof)
        tampered = SignedAuditBatch(batch, self.receipt.checkpoint)
        self.assertFalse(
            verify_signed_audit_batch(tampered, self.public_key)
        )

    def test_tampered_checkpoint_signature_returns_false(self):
        checkpoint = SignedRoot(
            self.receipt.checkpoint.version,
            self.receipt.checkpoint.hash_name,
            self.receipt.checkpoint.size,
            self.receipt.checkpoint.root,
            self.receipt.checkpoint.head,
            b"\x00" * 64,
        )
        tampered = SignedAuditBatch(self.receipt.batch, checkpoint)
        self.assertFalse(
            verify_signed_audit_batch(tampered, self.public_key)
        )

    def _checkpoint(self, *, hash_name=None, size=None, root=None,
                    head=None, seed=_SEED_A):
        current = self.receipt.checkpoint
        hash_name = current.hash_name if hash_name is None else hash_name
        size = current.size if size is None else size
        root = current.root if root is None else root
        head = current.head if head is None else head
        signing_key = Ed25519PrivateKey.from_private_bytes(seed)
        signature = signing_key.sign(
            _signed_message(hash_name, size, root, head)
        )
        return SignedRoot(1, hash_name, size, root, head, signature)

    def test_checkpoint_size_mismatch_returns_false(self):
        # A genuinely signed checkpoint for another snapshot: its signature is
        # valid, but the batch's size disagrees.
        checkpoint = self._checkpoint(size=4)
        paired = SignedAuditBatch(self.receipt.batch, checkpoint)
        self.assertTrue(verify_signed_root(checkpoint, self.public_key))
        self.assertFalse(
            verify_signed_audit_batch(paired, self.public_key)
        )

    def test_checkpoint_root_mismatch_returns_false(self):
        other_root = bytes(0xAB for _ in self.receipt.batch[2])
        checkpoint = self._checkpoint(root=other_root)
        paired = SignedAuditBatch(self.receipt.batch, checkpoint)
        self.assertTrue(verify_signed_root(checkpoint, self.public_key))
        self.assertFalse(
            verify_signed_audit_batch(paired, self.public_key)
        )

    def test_checkpoint_head_mismatch_returns_false(self):
        # Same signed hash_name/size/root but a head that is not the last
        # entry's hash: the signature is genuine, so only the binding check
        # can reject it.
        checkpoint = self._checkpoint(head=b"\x01" * 32)
        paired = SignedAuditBatch(self.receipt.batch, checkpoint)
        self.assertTrue(verify_signed_root(checkpoint, self.public_key))
        self.assertFalse(
            verify_signed_audit_batch(paired, self.public_key)
        )

    def test_empty_snapshot_nonzero_head_returns_false(self):
        empty = self.log.audit_batch((), 0)
        hash_name, size, root, _entries, _proof = empty
        signing_key = Ed25519PrivateKey.from_private_bytes(_SEED_A)
        signature = signing_key.sign(
            _signed_message(hash_name, size, root, b"\x01" * 32)
        )
        checkpoint = SignedRoot(
            1, hash_name, size, root, b"\x01" * 32, signature
        )
        paired = SignedAuditBatch(empty, checkpoint)
        self.assertTrue(verify_signed_root(checkpoint, self.public_key))
        self.assertTrue(verify_audit_batch(empty))
        self.assertFalse(
            verify_signed_audit_batch(paired, self.public_key)
        )

    def test_cross_snapshot_pairing_returns_false(self):
        # A batch for size 5 paired with the checkpoint of size 4: both parts
        # are individually genuine and verify, only the binding fails.
        other = self.log.signed_audit_batch([1], _SEED_A, 4)
        paired = SignedAuditBatch(self.receipt.batch, other.checkpoint)
        self.assertTrue(verify_audit_batch(self.receipt.batch))
        self.assertTrue(
            verify_signed_root(other.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_audit_batch(paired, self.public_key)
        )

    def test_call_is_read_only(self):
        verify_signed_audit_batch(self.receipt, self.other_public_key)
        self.assertEqual(
            self.receipt, self.log.signed_audit_batch([1, 3], _SEED_A)
        )


if __name__ == "__main__":
    unittest.main()
