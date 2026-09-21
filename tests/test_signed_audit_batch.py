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
    SignedAuditBatch,
    SignedRoot,
    verify_audit_batch,
    verify_signed_audit_batch,
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


class SignedAuditBatchIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_bundles_genuine_batch_and_checkpoint(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        self.assertIsInstance(receipt, SignedAuditBatch)
        self.assertEqual(receipt.batch, self.log.audit_batch([1, 3]))
        self.assertEqual(receipt.checkpoint, self.log.sign_root(_SEED_A))

    def test_no_new_signing_message(self):
        # Ed25519 is deterministic: the checkpoint is exactly sign_root's
        # output, signed over exactly the documented message.
        receipt = self.log.signed_audit_batch([0, 2], _SEED_A, 4)
        self.assertEqual(receipt.checkpoint, self.log.sign_root(_SEED_A, 4))
        signature = _sign(
            _SEED_A,
            "sha256",
            4,
            self.log.merkle_root(4),
            self.log.entry(3).entry_hash,
        )
        self.assertEqual(receipt.checkpoint.signature, signature)

    def test_explicit_size(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A, 3)
        self.assertEqual(receipt.batch[1], 3)
        self.assertEqual(receipt.batch[2], self.log.merkle_root(3))
        self.assertEqual(receipt.checkpoint.size, 3)
        self.assertEqual(receipt.checkpoint.head, self.log.entry(2).entry_hash)
        self.assertTrue(verify_signed_audit_batch(receipt, self.public_key))

    def test_size_defaults_to_current_length(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        self.assertEqual(receipt.batch[1], len(self.log))
        self.assertEqual(receipt.checkpoint.size, len(self.log))
        self.log.append("f")
        grown = self.log.signed_audit_batch([1, 3], _SEED_A)
        self.assertEqual(grown.checkpoint.size, 6)

    def test_empty_snapshot_uses_canonical_root_and_zero_head(self):
        receipt = self.log.signed_audit_batch((), _SEED_A, 0)
        hash_name, size, root, entries, proof = receipt.batch
        self.assertEqual(size, 0)
        self.assertEqual(entries, ())
        self.assertEqual(proof, ())
        self.assertEqual(root, self.log.merkle_root(0))
        self.assertEqual(receipt.checkpoint.head, GENESIS_HASH)
        self.assertTrue(verify_signed_audit_batch(receipt, self.public_key))

    def test_empty_log(self):
        receipt = AuditLog().signed_audit_batch((), _SEED_A)
        self.assertEqual(receipt.batch[1], 0)
        self.assertEqual(receipt.checkpoint.head, GENESIS_HASH)
        self.assertTrue(verify_signed_audit_batch(receipt, self.public_key))

    def test_last_entry_auto_added_and_its_hash_is_the_head(self):
        receipt = self.log.signed_audit_batch([0], _SEED_A)
        entries = receipt.batch[3]
        self.assertEqual([entry.index for entry in entries], [0, 4])
        self.assertEqual(entries[-1].entry_hash, self.log.head)
        self.assertEqual(receipt.checkpoint.head, entries[-1].entry_hash)
        self.assertTrue(verify_signed_audit_batch(receipt, self.public_key))

    def test_survives_later_appends(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A, 4)
        self.log.append("f")
        self.assertTrue(verify_signed_audit_batch(receipt, self.public_key))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        receipt = log.signed_audit_batch([0, 2], _SEED_A)
        self.assertEqual(receipt.batch[0], "sha512")
        self.assertEqual(receipt.checkpoint.hash_name, "sha512")
        self.assertTrue(verify_signed_audit_batch(receipt, self.public_key))

    def test_pruned_log(self):
        log = AuditLog()
        twin = AuditLog()
        for i in range(6):
            log.append(f"r{i}")
            twin.append(f"r{i}")
        log.prune(2, log.seal(2))
        receipt = log.signed_audit_batch([2, 4], _SEED_A)
        self.assertEqual(receipt.batch[2], twin.merkle_root(6))
        self.assertTrue(verify_signed_audit_batch(receipt, self.public_key))
        with self.assertRaises(ValueError):
            log.signed_audit_batch([1], _SEED_A)

    def test_positional_construction_and_equality(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        clone = SignedAuditBatch(receipt.batch, receipt.checkpoint)
        self.assertEqual(receipt, clone)
        other = self.log.signed_audit_batch([1], _SEED_A, 3)
        self.assertNotEqual(receipt, other)
        self.assertNotEqual(receipt, (receipt.batch, receipt.checkpoint))

    def test_frozen(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        with self.assertRaises(FrozenInstanceError):
            receipt.batch = ()
        with self.assertRaises(FrozenInstanceError):
            receipt.checkpoint = receipt.checkpoint

    def test_constructor_field_types(self):
        batch = self.log.audit_batch([1])
        checkpoint = self.log.sign_root(_SEED_A)
        with self.assertRaises(TypeError):
            SignedAuditBatch(list(batch), checkpoint)
        with self.assertRaises(TypeError):
            SignedAuditBatch(batch, tuple(checkpoint))
        with self.assertRaises(TypeError):
            SignedAuditBatch(None, checkpoint)
        with self.assertRaises(TypeError):
            SignedAuditBatch(batch, None)

    def test_call_is_read_only(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        stage_log = AuditLog(key=b"shared-secret")
        stage_log.append("a")
        self.log.signed_audit_batch([1, 2], _SEED_A)
        self.log.signed_audit_batch((), _SEED_A, 0)
        self.assertEqual((len(self.log), self.log.head, self.log.merkle_root()), before)
        self.assertTrue(self.log.verify())
        self.assertEqual(stage_log.stage, 0)

    def test_failure_leaves_state_unchanged(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        for bad_indices in ([9], [0, 0], [-1]):
            with self.assertRaises(ValueError):
                self.log.signed_audit_batch(bad_indices, _SEED_A)
        with self.assertRaises(TypeError):
            self.log.signed_audit_batch([1], "0" * 32)
        with self.assertRaises(ValueError):
            self.log.signed_audit_batch([1], _SEED_A[:-1])
        with self.assertRaises(ValueError):
            self.log.signed_audit_batch([1], _SEED_A, 99)
        with self.assertRaises(TypeError):
            self.log.signed_audit_batch([0], _SEED_A, True)
        self.assertEqual((len(self.log), self.log.head, self.log.merkle_root()), before)
        self.assertTrue(self.log.verify())


class VerifySignedAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)

    def bypass(self, *, batch=None, checkpoint=None):
        receipt = SignedAuditBatch.__new__(SignedAuditBatch)
        object.__setattr__(
            receipt, "batch", self.receipt.batch if batch is None else batch
        )
        object.__setattr__(
            receipt,
            "checkpoint",
            self.receipt.checkpoint if checkpoint is None else checkpoint,
        )
        return receipt

    def test_genuine_receipts_verify(self):
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
                verify_signed_audit_batch(
                    self.log.signed_audit_batch(chosen, _SEED_A, size),
                    self.public_key,
                ),
                (chosen, size),
            )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_audit_batch(self.receipt, self.other_public_key)
        )

    def test_other_key_signing_returns_false(self):
        foreign = self.log.signed_audit_batch([0, 2, 4], _SEED_B)
        self.assertEqual(foreign.batch, self.receipt.batch)
        self.assertFalse(
            verify_signed_audit_batch(foreign, self.public_key)
        )
        self.assertTrue(
            verify_signed_audit_batch(foreign, self.other_public_key)
        )

    def test_not_a_receipt_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(self.receipt.batch, self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(None, self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(
                (self.receipt.batch, self.receipt.checkpoint), self.public_key
            )

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(self.receipt, "0" * 32)
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(self.receipt, bytearray(self.public_key))
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(self.receipt, memoryview(self.public_key))
        with self.assertRaises(ValueError):
            verify_signed_audit_batch(self.receipt, self.public_key[:-1])
        with self.assertRaises(ValueError):
            verify_signed_audit_batch(self.receipt, self.public_key + b"\x00")

    def test_nested_batch_type_errors_propagate(self):
        # A nested batch field of the wrong type raises the same TypeError
        # verify_audit_batch would, rather than being reported as False.
        bad = self.bypass(batch=(1,) + self.receipt.batch[1:])
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(bad, self.public_key)
        # Container fields bypassed to wrong types raise TypeError, not False.
        broken = self.bypass(batch=["sha256"])
        with self.assertRaises(TypeError):
            verify_signed_audit_batch(broken, self.public_key)

    def test_nested_batch_value_errors_propagate(self):
        bad = self.bypass(
            batch=("not-a-hash",) + self.receipt.batch[1:]
        )
        with self.assertRaises(ValueError):
            verify_signed_audit_batch(bad, self.public_key)

    def test_tampered_batch_payload_returns_false(self):
        from auditchain import Entry

        hash_name, size, root, entries, proof = self.receipt.batch
        entry = entries[0]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = self.bypass(
            batch=(hash_name, size, root, (tampered,) + entries[1:], proof)
        )
        self.assertFalse(verify_signed_audit_batch(forged, self.public_key))

    def test_tampered_batch_root_returns_false(self):
        hash_name, size, _root, entries, proof = self.receipt.batch
        forged = self.bypass(
            batch=(hash_name, size, b"\x11" * 32, entries, proof)
        )
        self.assertFalse(verify_signed_audit_batch(forged, self.public_key))

    def test_tampered_checkpoint_signature_returns_false(self):
        checkpoint = self.receipt.checkpoint
        forged_checkpoint = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = self.bypass(checkpoint=forged_checkpoint)
        self.assertFalse(verify_signed_audit_batch(forged, self.public_key))

    def test_mixed_size_returns_false(self):
        # Both parts are genuine and individually verifiable, but describe
        # different snapshot sizes.
        other = self.log.signed_audit_batch([0, 2], _SEED_A, 4)
        forged = self.bypass(checkpoint=other.checkpoint)
        self.assertTrue(verify_audit_batch(forged.batch))
        self.assertTrue(verify_signed_root(forged.checkpoint, self.public_key))
        self.assertFalse(verify_signed_audit_batch(forged, self.public_key))

    def test_mixed_root_returns_false(self):
        # Same size and key, but the checkpoint attests a different log's
        # root (and head): the cross-check must reject it.
        other_log = AuditLog()
        for record in ("x", "y", "z", "w", "u", "v", "t"):
            other_log.append(record)
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass(checkpoint=foreign_checkpoint)
        self.assertTrue(verify_signed_root(forged.checkpoint, self.public_key))
        self.assertFalse(verify_signed_audit_batch(forged, self.public_key))

    def test_mixed_hash_name_returns_false(self):
        other_log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            other_log.append(record)
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass(checkpoint=foreign_checkpoint)
        self.assertTrue(verify_signed_root(forged.checkpoint, self.public_key))
        self.assertFalse(verify_signed_audit_batch(forged, self.public_key))

    def test_checkpoint_head_not_last_entry_hash_returns_false(self):
        # Sign a checkpoint over the genuine size and root but a bogus head:
        # the signature stays valid for those exact fields, verify_signed_root
        # passes, but the head must equal the batch's last entry hash.
        checkpoint = self.receipt.checkpoint
        bogus_signature = _sign(
            _SEED_A,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            b"\x00" * 32,
        )
        bogus = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            b"\x00" * 32,
            bogus_signature,
        )
        forged = self.bypass(checkpoint=bogus)
        self.assertTrue(verify_signed_root(bogus, self.public_key))
        self.assertFalse(verify_signed_audit_batch(forged, self.public_key))

    def test_empty_snapshot_requires_zero_head(self):
        empty = self.log.signed_audit_batch((), _SEED_A, 0)
        bogus_signature = _sign(
            _SEED_A, "sha256", 0, empty.batch[2], b"\x11" * 32
        )
        bogus = SignedRoot(
            1, "sha256", 0, empty.batch[2], b"\x11" * 32, bogus_signature
        )
        forged = self.bypass(batch=empty.batch, checkpoint=bogus)
        self.assertTrue(verify_audit_batch(forged.batch))
        self.assertTrue(verify_signed_root(bogus, self.public_key))
        self.assertFalse(verify_signed_audit_batch(forged, self.public_key))

    def test_call_is_read_only(self):
        verify_signed_audit_batch(self.receipt, self.other_public_key)
        self.assertEqual(
            self.receipt,
            self.log.signed_audit_batch([0, 2, 4], _SEED_A),
        )


if __name__ == "__main__":
    unittest.main()
