import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    AuditReceipt,
    Entry,
    SignedAuditBatch,
    SignedAuditReceipt,
    SignedAuditReport,
    SignedRoot,
    inspect_signed_audit_batch,
    inspect_signed_audit_receipt,
    verify_audit_batch,
    verify_audit_receipt,
    verify_signed_audit_batch,
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
    return Ed25519PrivateKey.from_private_bytes(seed).sign(
        _signed_root_message(hash_name, size, root, head)
    )


class SignedAuditReportTest(unittest.TestCase):
    def test_success_constant(self):
        report = SignedAuditReport(True, None, None)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)

    def test_positional_construction_and_equality(self):
        success = SignedAuditReport(True, None, None)
        self.assertEqual(success, SignedAuditReport(True, None, None))
        failure = SignedAuditReport(False, 3, "entry")
        self.assertEqual(failure, SignedAuditReport(False, 3, "entry"))
        self.assertNotEqual(failure, SignedAuditReport(False, 4, "entry"))
        self.assertNotEqual(
            failure, SignedAuditReport(False, None, "checkpoint")
        )
        self.assertNotEqual(success, failure)
        self.assertNotEqual(failure, (False, 3, "entry"))

    def test_frozen(self):
        report = SignedAuditReport(True, None, None)
        with self.assertRaises(FrozenInstanceError):
            report.ok = False

    def test_ok_must_be_bool(self):
        with self.assertRaises(TypeError):
            SignedAuditReport(1, None, None)
        with self.assertRaises(TypeError):
            SignedAuditReport(0, None, None)

    def test_success_must_carry_neither_code_nor_index(self):
        with self.assertRaises(ValueError):
            SignedAuditReport(True, 0, None)
        with self.assertRaises(ValueError):
            SignedAuditReport(True, None, "entry")
        with self.assertRaises(ValueError):
            SignedAuditReport(True, 0, "entry")

    def test_failure_requires_a_known_code(self):
        with self.assertRaises(ValueError):
            SignedAuditReport(False, None, None)
        with self.assertRaises(ValueError):
            SignedAuditReport(False, 0, None)

    def test_code_type(self):
        with self.assertRaises(TypeError):
            SignedAuditReport(False, None, b"entry")
        with self.assertRaises(TypeError):
            SignedAuditReport(False, None, 0)

    def test_unknown_code_rejected(self):
        with self.assertRaises(ValueError):
            SignedAuditReport(False, None, "verify")
        with self.assertRaises(ValueError):
            SignedAuditReport(False, None, "")

    def test_positionless_codes_reject_and_accept_position(self):
        for code in ("proof", "root", "last", "checkpoint", "binding"):
            report = SignedAuditReport(False, None, code)
            self.assertEqual(report.code, code)
            self.assertIsNone(report.index)
            with self.assertRaises(ValueError):
                SignedAuditReport(False, 0, code)

    def test_entry_requires_non_negative_index(self):
        report = SignedAuditReport(False, 5, "entry")
        self.assertEqual(report.index, 5)
        with self.assertRaises(ValueError):
            SignedAuditReport(False, None, "entry")
        with self.assertRaises(ValueError):
            SignedAuditReport(False, -1, "entry")

    def test_index_type(self):
        with self.assertRaises(TypeError):
            SignedAuditReport(False, 1.0, "entry")
        with self.assertRaises(TypeError):
            SignedAuditReport(False, "1", "entry")
        with self.assertRaises(TypeError):
            SignedAuditReport(False, True, "entry")
        # A non-integer position is a TypeError even for a positionless code.
        with self.assertRaises(TypeError):
            SignedAuditReport(False, 1.0, "checkpoint")


class _SignedAuditFixture(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)


class InspectSignedAuditReceiptTest(_SignedAuditFixture):
    def bypass(self, *, receipt=None, checkpoint=None):
        bundle = SignedAuditReceipt.__new__(SignedAuditReceipt)
        genuine = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        object.__setattr__(
            bundle,
            "receipt",
            genuine.receipt if receipt is None else receipt,
        )
        object.__setattr__(
            bundle,
            "checkpoint",
            genuine.checkpoint if checkpoint is None else checkpoint,
        )
        return bundle

    def test_genuine_bundle_succeeds(self):
        for chosen, size in (
            ([0], None),
            ([1, 3], None),
            ([3], 4),
            ([0, 6], None),
            ((), 0),
        ):
            bundle = self.log.signed_audit_receipt(chosen, _SEED_A, size)
            self.assertEqual(
                inspect_signed_audit_receipt(bundle, self.public_key),
                SignedAuditReport(True, None, None),
                (chosen, size),
            )

    def test_ok_matches_boolean_verifier(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        for key in (self.public_key, self.other_public_key):
            self.assertEqual(
                inspect_signed_audit_receipt(bundle, key).ok,
                verify_signed_audit_receipt(bundle, key),
            )

    def test_empty_log_succeeds(self):
        bundle = AuditLog().signed_audit_receipt((), _SEED_A)
        self.assertEqual(
            inspect_signed_audit_receipt(bundle, self.public_key),
            SignedAuditReport(True, None, None),
        )

    def test_wrong_public_key_is_checkpoint(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        self.assertEqual(
            inspect_signed_audit_receipt(bundle, self.other_public_key),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_tampered_entry_is_entry_at_its_index(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        receipt = bundle.receipt
        entry, proof = receipt.items[0]
        tampered = Entry(entry.index, b"changed", entry.previous_hash, entry.entry_hash)
        bad_receipt = AuditReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            ((tampered, proof),) + receipt.items[1:],
        )
        self.assertEqual(
            inspect_signed_audit_receipt(
                SignedAuditReceipt(bad_receipt, bundle.checkpoint),
                self.public_key,
            ),
            SignedAuditReport(False, 0, "entry"),
        )

    def test_tampered_proof_is_proof_with_no_position(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        receipt = bundle.receipt
        entry, proof = receipt.items[0]
        bad_proof = proof[:-1] + (b"\x00" * 32,)
        bad_receipt = AuditReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            ((entry, bad_proof),) + receipt.items[1:],
        )
        report = inspect_signed_audit_receipt(
            SignedAuditReceipt(bad_receipt, bundle.checkpoint),
            self.public_key,
        )
        self.assertEqual(report, SignedAuditReport(False, None, "proof"))

    def test_forged_signature_is_checkpoint(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        checkpoint = bundle.checkpoint
        forged_checkpoint = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        self.assertEqual(
            inspect_signed_audit_receipt(
                self.bypass(checkpoint=forged_checkpoint), self.public_key
            ),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_body_failure_masks_a_forged_signature(self):
        # The body is examined before the checkpoint: a body that already
        # fails must be reported even though the signature is also bogus.
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        receipt = bundle.receipt
        entry, proof = receipt.items[0]
        tampered = Entry(entry.index, b"changed", entry.previous_hash, entry.entry_hash)
        bad_receipt = AuditReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            ((tampered, proof),) + receipt.items[1:],
        )
        checkpoint = bundle.checkpoint
        forged_checkpoint = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        self.assertEqual(
            inspect_signed_audit_receipt(
                self.bypass(
                    receipt=bad_receipt, checkpoint=forged_checkpoint
                ),
                self.public_key,
            ),
            SignedAuditReport(False, 0, "entry"),
        )

    def test_individually_true_halves_of_different_snapshots_is_binding(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        other = self.log.signed_audit_receipt([0, 2], _SEED_A, 4)
        mixed = self.bypass(checkpoint=other.checkpoint)
        self.assertTrue(verify_audit_receipt(mixed.receipt))
        self.assertTrue(verify_signed_root(mixed.checkpoint, self.public_key))
        self.assertFalse(
            verify_signed_audit_receipt(mixed, self.public_key)
        )
        self.assertEqual(
            inspect_signed_audit_receipt(mixed, self.public_key),
            SignedAuditReport(False, None, "binding"),
        )

    def test_not_a_bundle_raises_type_error(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        for bad in (None, 42, (bundle.receipt, bundle.checkpoint), object()):
            with self.assertRaises(TypeError):
                inspect_signed_audit_receipt(bad, self.public_key)

    def test_public_key_validation_matches_verifier(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        for bad_key, error in (
            ("0" * 32, TypeError),
            (bytearray(self.public_key), TypeError),
            (memoryview(self.public_key), TypeError),
            (self.public_key[:-1], ValueError),
            (self.public_key + b"\x00", ValueError),
        ):
            with self.assertRaises(error):
                inspect_signed_audit_receipt(bundle, bad_key)
            with self.assertRaises(error):
                verify_signed_audit_receipt(bundle, bad_key)

    def test_call_is_read_only_and_deterministic(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        before = (
            self.log.signed_audit_receipt([0, 2, 4], _SEED_A),
        )
        first = inspect_signed_audit_receipt(bundle, self.other_public_key)
        second = inspect_signed_audit_receipt(bundle, self.other_public_key)
        self.assertEqual(first, second)
        self.assertEqual(
            bundle, self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        )
        self.assertEqual(
            before,
            (self.log.signed_audit_receipt([0, 2, 4], _SEED_A),),
        )


class InspectSignedAuditBatchTest(_SignedAuditFixture):
    def bypass(self, *, batch=None, checkpoint=None):
        receipt = SignedAuditBatch.__new__(SignedAuditBatch)
        genuine = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        object.__setattr__(
            receipt, "batch", genuine.batch if batch is None else batch
        )
        object.__setattr__(
            receipt,
            "checkpoint",
            genuine.checkpoint if checkpoint is None else checkpoint,
        )
        return receipt

    def test_genuine_receipts_succeed(self):
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
            receipt = self.log.signed_audit_batch(chosen, _SEED_A, size)
            self.assertEqual(
                inspect_signed_audit_batch(receipt, self.public_key),
                SignedAuditReport(True, None, None),
                (chosen, size),
            )

    def test_ok_matches_boolean_verifier(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        for key in (self.public_key, self.other_public_key):
            self.assertEqual(
                inspect_signed_audit_batch(receipt, key).ok,
                verify_signed_audit_batch(receipt, key),
            )

    def test_empty_log_succeeds(self):
        receipt = AuditLog().signed_audit_batch((), _SEED_A)
        self.assertEqual(
            inspect_signed_audit_batch(receipt, self.public_key),
            SignedAuditReport(True, None, None),
        )

    def test_wrong_public_key_is_checkpoint(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        self.assertEqual(
            inspect_signed_audit_batch(receipt, self.other_public_key),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_tampered_entry_is_entry_at_its_index(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        hash_name, size, root, entries, proof = receipt.batch
        entry = entries[0]
        tampered = Entry(
            entry.index, b"changed", entry.previous_hash, entry.entry_hash
        )
        forged = self.bypass(
            batch=(hash_name, size, root, (tampered,) + entries[1:], proof)
        )
        self.assertEqual(
            inspect_signed_audit_batch(forged, self.public_key),
            SignedAuditReport(False, 0, "entry"),
        )

    def test_tampered_shared_proof_is_proof_with_no_position(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        hash_name, size, root, entries, proof = receipt.batch
        forged = self.bypass(
            batch=(
                hash_name,
                size,
                root,
                entries,
                proof[:-1] + (b"\x22" * 32,),
            )
        )
        self.assertEqual(
            inspect_signed_audit_batch(forged, self.public_key),
            SignedAuditReport(False, None, "proof"),
        )

    def test_non_canonical_empty_root_is_root(self):
        empty = self.log.signed_audit_batch((), _SEED_A, 0)
        hash_name, size, _root, entries, proof = empty.batch
        forged = self.bypass(
            batch=(hash_name, size, b"\x33" * 32, entries, proof)
        )
        self.assertFalse(verify_audit_batch(forged.batch))
        self.assertEqual(
            inspect_signed_audit_batch(forged, self.public_key),
            SignedAuditReport(False, None, "root"),
        )

    def test_forged_signature_is_checkpoint(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        checkpoint = receipt.checkpoint
        forged_checkpoint = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        self.assertEqual(
            inspect_signed_audit_batch(
                self.bypass(checkpoint=forged_checkpoint), self.public_key
            ),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_body_failure_masks_a_forged_signature(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        hash_name, size, root, entries, proof = receipt.batch
        entry = entries[0]
        tampered = Entry(
            entry.index, b"changed", entry.previous_hash, entry.entry_hash
        )
        checkpoint = receipt.checkpoint
        forged_checkpoint = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = self.bypass(
            batch=(hash_name, size, root, (tampered,) + entries[1:], proof),
            checkpoint=forged_checkpoint,
        )
        self.assertEqual(
            inspect_signed_audit_batch(forged, self.public_key),
            SignedAuditReport(False, 0, "entry"),
        )

    def test_different_snapshot_sizes_is_binding(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        other = self.log.signed_audit_batch([0, 2], _SEED_A, 4)
        forged = self.bypass(checkpoint=other.checkpoint)
        self.assertTrue(verify_audit_batch(forged.batch))
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_audit_batch(forged, self.public_key)
        )
        self.assertEqual(
            inspect_signed_audit_batch(forged, self.public_key),
            SignedAuditReport(False, None, "binding"),
        )

    def test_valid_signature_but_wrong_head_is_binding(self):
        # Sign a genuine size/root checkpoint over a bogus chain head: the
        # signature verifies, but the head must bind to the last entry hash.
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        checkpoint = receipt.checkpoint
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
        self.assertFalse(
            verify_signed_audit_batch(forged, self.public_key)
        )
        self.assertEqual(
            inspect_signed_audit_batch(forged, self.public_key),
            SignedAuditReport(False, None, "binding"),
        )

    def test_empty_snapshot_non_zero_head_is_binding(self):
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
        self.assertEqual(
            inspect_signed_audit_batch(forged, self.public_key),
            SignedAuditReport(False, None, "binding"),
        )

    def test_not_a_receipt_raises_type_error(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        for bad in (None, 42, receipt.batch, (receipt.batch, receipt.checkpoint)):
            with self.assertRaises(TypeError):
                inspect_signed_audit_batch(bad, self.public_key)

    def test_public_key_validation_matches_verifier(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        for bad_key, error in (
            ("0" * 32, TypeError),
            (bytearray(self.public_key), TypeError),
            (memoryview(self.public_key), TypeError),
            (self.public_key[:-1], ValueError),
            (self.public_key + b"\x00", ValueError),
        ):
            with self.assertRaises(error):
                inspect_signed_audit_batch(receipt, bad_key)
            with self.assertRaises(error):
                verify_signed_audit_batch(receipt, bad_key)

    def test_nested_batch_type_error_propagates(self):
        bad = self.bypass(batch=(1,) + self.log.signed_audit_batch([0, 2, 4], _SEED_A).batch[1:])
        with self.assertRaises(TypeError):
            inspect_signed_audit_batch(bad, self.public_key)
        broken = self.bypass(batch=["sha256"])
        with self.assertRaises(TypeError):
            inspect_signed_audit_batch(broken, self.public_key)

    def test_nested_batch_value_error_propagates(self):
        genuine = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        bad = self.bypass(
            batch=("not-a-hash",) + genuine.batch[1:]
        )
        with self.assertRaises(ValueError):
            inspect_signed_audit_batch(bad, self.public_key)
        with self.assertRaises(ValueError):
            verify_signed_audit_batch(bad, self.public_key)

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        first = inspect_signed_audit_batch(receipt, self.other_public_key)
        second = inspect_signed_audit_batch(receipt, self.other_public_key)
        self.assertEqual(first, second)
        self.assertEqual(
            receipt, self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        )


if __name__ == "__main__":
    unittest.main()
