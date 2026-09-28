import itertools
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
    AuditReceiptReport,
    Entry,
    SignedAuditBatch,
    SignedAuditReceipt,
    SignedAuditReport,
    SignedRoot,
    inspect_audit_batch,
    inspect_audit_receipt,
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


def _public_key(seed):
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _sign(seed, hash_name, size, root, head):
    def u64(value):
        return value.to_bytes(8, "big")

    def blob(material):
        return u64(len(material)) + material

    message = (
        b"auditchain/signed-root/v1\0"
        + b"\x01"
        + blob(hash_name.encode("utf-8"))
        + u64(size)
        + blob(root)
        + blob(head)
    )
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


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

    def test_report_is_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            SignedAuditReport(True, None, None).ok = False

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
            SignedAuditReport(True, 0, "binding")

    def test_failure_requires_a_code(self):
        with self.assertRaises(ValueError):
            SignedAuditReport(False, None, None)
        with self.assertRaises(ValueError):
            SignedAuditReport(False, 0, None)

    def test_code_must_be_a_string(self):
        with self.assertRaises(TypeError):
            SignedAuditReport(False, None, b"entry")
        with self.assertRaises(TypeError):
            SignedAuditReport(False, None, 0)

    def test_unknown_code_rejected(self):
        with self.assertRaises(ValueError):
            SignedAuditReport(False, None, "verify")
        with self.assertRaises(ValueError):
            SignedAuditReport(False, None, "")

    def test_six_known_codes_without_position(self):
        for code in ("proof", "root", "last", "checkpoint", "binding"):
            report = SignedAuditReport(False, None, code)
            self.assertEqual(report.code, code)
            self.assertIsNone(report.index)

    def test_entry_carries_non_negative_index(self):
        report = SignedAuditReport(False, 0, "entry")
        self.assertEqual(report.index, 0)
        report = SignedAuditReport(False, 7, "entry")
        self.assertEqual(report.index, 7)

    def test_entry_requires_a_position(self):
        with self.assertRaises(ValueError):
            SignedAuditReport(False, None, "entry")

    def test_non_entry_codes_must_have_no_position(self):
        for code in ("proof", "root", "last", "checkpoint", "binding"):
            with self.assertRaises(ValueError):
                SignedAuditReport(False, 0, code)

    def test_index_must_be_integer_or_none(self):
        with self.assertRaises(TypeError):
            SignedAuditReport(False, 1.0, "entry")
        with self.assertRaises(TypeError):
            SignedAuditReport(False, "1", "entry")
        with self.assertRaises(TypeError):
            SignedAuditReport(False, True, "entry")

    def test_negative_index_rejected(self):
        with self.assertRaises(ValueError):
            SignedAuditReport(False, -1, "entry")


class _Base(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def bypass_receipt(self, bundle, *, receipt=None, checkpoint=None):
        forged = SignedAuditReceipt.__new__(SignedAuditReceipt)
        object.__setattr__(
            forged,
            "receipt",
            bundle.receipt if receipt is None else receipt,
        )
        object.__setattr__(
            forged,
            "checkpoint",
            bundle.checkpoint if checkpoint is None else checkpoint,
        )
        return forged

    def bypass_batch(self, receipt, *, batch=None, checkpoint=None):
        forged = SignedAuditBatch.__new__(SignedAuditBatch)
        object.__setattr__(
            forged, "batch", receipt.batch if batch is None else batch
        )
        object.__setattr__(
            forged,
            "checkpoint",
            receipt.checkpoint if checkpoint is None else checkpoint,
        )
        return forged


class InspectSignedAuditReceiptTest(_Base):
    def inspect(self, bundle, key=None):
        return inspect_signed_audit_receipt(
            bundle, self.public_key if key is None else key
        )

    def verify(self, bundle, key=None):
        return verify_signed_audit_receipt(
            bundle, self.public_key if key is None else key
        )

    def test_genuine_bundles_report_success(self):
        for chosen, size in (
            ([0], None),
            ([1, 3], None),
            ([3], 4),
            ([], None),
            ([], 3),
            ((), 0),
            ([0, 6], None),
            (range(7), None),
        ):
            bundle = self.log.signed_audit_receipt(chosen, _SEED_A, size)
            self.assertEqual(
                self.inspect(bundle),
                SignedAuditReport(True, None, None),
                (chosen, size),
            )

    def test_success_corresponds_to_verifier_truth(self):
        for size in range(0, 8):
            for count in range(size + 1):
                for chosen in itertools.combinations(range(size), count):
                    bundle = self.log.signed_audit_receipt(
                        chosen, _SEED_A, size
                    )
                    self.assertEqual(
                        self.inspect(bundle).ok, self.verify(bundle)
                    )

    def test_wrong_public_key_reports_checkpoint(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        self.assertFalse(self.verify(bundle, self.other_public_key))
        self.assertEqual(
            self.inspect(bundle, self.other_public_key),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_other_key_signing_reports_checkpoint(self):
        foreign = self.log.signed_audit_receipt([0, 2, 4], _SEED_B)
        self.assertTrue(verify_audit_receipt(foreign.receipt))
        self.assertTrue(
            verify_signed_root(foreign.checkpoint, self.other_public_key)
        )
        self.assertFalse(self.verify(foreign))
        self.assertEqual(
            self.inspect(foreign),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_forged_checkpoint_signature_reports_checkpoint(self):
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
        forged = self.bypass_receipt(bundle, checkpoint=forged_checkpoint)
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_tampered_entry_reports_entry_at_absolute_index(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        receipt = bundle.receipt
        (entry1, proof1), rest = receipt.items[0], receipt.items[1:]
        tampered = Entry(
            entry1.index,
            b"tampered",
            entry1.previous_hash,
            entry1.entry_hash,
        )
        forged_receipt = AuditReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            ((tampered, proof1),) + tuple(rest),
        )
        forged = self.bypass_receipt(bundle, receipt=forged_receipt)
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, 1, "entry")
        )

    def test_tampered_proof_reports_proof_without_position(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        receipt = bundle.receipt
        (entry, proof), *rest = receipt.items
        forged_proof = (b"\x00" * 32,) + proof[1:]
        forged_receipt = AuditReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            ((entry, forged_proof),) + tuple(rest),
        )
        forged = self.bypass_receipt(bundle, receipt=forged_receipt)
        # The unsigned body locates the proof at that entry's index, but this
        # layer lifts only "entry" positions, so its proof carries none.
        self.assertEqual(
            inspect_audit_receipt(forged_receipt),
            AuditReceiptReport(False, 1, "proof"),
        )
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, None, "proof")
        )

    def test_wrong_empty_root_reports_root(self):
        empty = self.log.signed_audit_receipt((), _SEED_A, 0)
        forged_receipt = AuditReceipt(1, "sha256", 0, b"\x11" * 32, ())
        forged = self.bypass_receipt(empty, receipt=forged_receipt)
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, None, "root")
        )

    def test_body_failure_precedes_checkpoint_failure(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        receipt = bundle.receipt
        (entry, proof), *rest = receipt.items
        tampered = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        forged_receipt = AuditReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            ((tampered, proof),) + tuple(rest),
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
        forged = self.bypass_receipt(
            bundle, receipt=forged_receipt, checkpoint=forged_checkpoint
        )
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, 1, "entry")
        )

    def test_checkpoint_failure_precedes_binding_failure(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        other_log = AuditLog()
        for record in ("x", "y", "z", "w", "u", "v", "t"):
            other_log.append(record)
        foreign = other_log.sign_root(_SEED_A)
        # A genuinely-signed checkpoint of another snapshot would be a
        # binding failure; blanking its signature makes it a checkpoint
        # failure as well — checkpoint must be reported first.
        self.assertTrue(verify_signed_root(foreign, self.public_key))
        forged_checkpoint = SignedRoot(
            foreign.version,
            foreign.hash_name,
            foreign.size,
            foreign.root,
            foreign.head,
            b"\x00" * 64,
        )
        forged = self.bypass_receipt(bundle, checkpoint=forged_checkpoint)
        self.assertEqual(
            self.inspect(forged),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_two_genuine_halves_of_different_snapshots_report_binding(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        other = self.log.signed_audit_receipt([0, 2], _SEED_A, 4)
        forged = self.bypass_receipt(bundle, checkpoint=other.checkpoint)
        self.assertTrue(verify_audit_receipt(forged.receipt))
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, None, "binding")
        )

    def test_genuine_checkpoint_of_foreign_log_reports_binding(self):
        bundle = self.log.signed_audit_receipt([0, 2, 4], _SEED_A)
        other_log = AuditLog()
        for record in ("x", "y", "z", "w", "u", "v", "t"):
            other_log.append(record)
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass_receipt(
            bundle, checkpoint=foreign_checkpoint
        )
        self.assertTrue(
            verify_signed_root(foreign_checkpoint, self.public_key)
        )
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, None, "binding")
        )

    def test_not_a_bundle_raises_type_error(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        for bad in (None, (bundle.receipt, bundle.checkpoint), 42, b""):
            with self.assertRaises(TypeError):
                self.inspect(bad)
        # The batch package is a different type.
        batch = self.log.signed_audit_batch([1], _SEED_A)
        with self.assertRaises(TypeError):
            self.inspect(batch)

    def test_bypassed_container_field_types_raise_type_error(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        with self.assertRaises(TypeError):
            self.inspect(self.bypass_receipt(bundle, receipt="x"))
        with self.assertRaises(TypeError):
            self.inspect(self.bypass_receipt(bundle, checkpoint="x"))

    def test_nested_structural_value_errors_propagate(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        # Missing last entry: the nested AuditReceipt constructor (which the
        # verifier itself runs) raises ValueError rather than the unsigned
        # layer's "last" diagnosis.
        forged_receipt = AuditReceipt.__new__(AuditReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", 5),
            ("root", self.log.merkle_root(5)),
            (
                "items",
                ((self.log.entry(0), self.log.inclusion_proof(0, 5)),),
            ),
        ):
            object.__setattr__(forged_receipt, name, value)
        forged = self.bypass_receipt(bundle, receipt=forged_receipt)
        with self.assertRaises(ValueError):
            self.verify(forged)
        with self.assertRaises(ValueError):
            self.inspect(forged)

    def test_nested_checkpoint_value_errors_propagate(self):
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        forged_checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "head",
            "signature",
        ):
            object.__setattr__(
                forged_checkpoint,
                name,
                getattr(bundle.checkpoint, name),
            )
        object.__setattr__(forged_checkpoint, "signature", b"\x00" * 32)
        forged = self.bypass_receipt(bundle, checkpoint=forged_checkpoint)
        with self.assertRaises(ValueError):
            self.verify(forged)
        with self.assertRaises(ValueError):
            self.inspect(forged)

    def test_public_key_validation_always_raises(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        receipt = bundle.receipt
        (entry, proof), *rest = receipt.items
        tampered = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        broken = self.bypass_receipt(
            bundle,
            receipt=AuditReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                ((tampered, proof),) + tuple(rest),
            ),
        )
        for bad in ("0" * 32, bytearray(self.public_key), memoryview(
            self.public_key
        )):
            with self.assertRaises(TypeError):
                self.inspect(bundle, bad)
            # A broken body must not mask a malformed key.
            with self.assertRaises(TypeError):
                self.inspect(broken, bad)
        for bad in (self.public_key[:-1], self.public_key + b"\x00"):
            with self.assertRaises(ValueError):
                self.inspect(bundle, bad)
            with self.assertRaises(ValueError):
                self.inspect(broken, bad)

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        bundle = log.signed_audit_receipt([0, 2], _SEED_A)
        self.assertEqual(
            self.inspect(bundle), SignedAuditReport(True, None, None)
        )

    def test_call_is_read_only_and_deterministic(self):
        bundle = self.log.signed_audit_receipt([1, 3], _SEED_A)
        checkpoint = bundle.checkpoint
        forged_checkpoint = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = self.bypass_receipt(bundle, checkpoint=forged_checkpoint)
        first = self.inspect(forged)
        second = self.inspect(forged)
        self.assertEqual(first, second)
        self.assertEqual(
            (bundle.receipt, bundle.checkpoint),
            (
                self.log.signed_audit_receipt([1, 3], _SEED_A).receipt,
                self.log.signed_audit_receipt([1, 3], _SEED_A).checkpoint,
            ),
        )


class InspectSignedAuditBatchTest(_Base):
    def inspect(self, receipt, key=None):
        return inspect_signed_audit_batch(
            receipt, self.public_key if key is None else key
        )

    def verify(self, receipt, key=None):
        return verify_signed_audit_batch(
            receipt, self.public_key if key is None else key
        )

    def test_genuine_batches_report_success(self):
        for chosen, size in (
            ([0], None),
            ([1, 3], None),
            ([3], 4),
            ([], None),
            ([], 3),
            ((), 0),
            ([0, 6], None),
            (range(7), None),
        ):
            receipt = self.log.signed_audit_batch(chosen, _SEED_A, size)
            self.assertEqual(
                self.inspect(receipt),
                SignedAuditReport(True, None, None),
                (chosen, size),
            )

    def test_success_corresponds_to_verifier_truth(self):
        for size in range(0, 8):
            for count in range(size + 1):
                for chosen in itertools.combinations(range(size), count):
                    receipt = self.log.signed_audit_batch(
                        chosen, _SEED_A, size
                    )
                    self.assertEqual(
                        self.inspect(receipt).ok, self.verify(receipt)
                    )

    def test_wrong_public_key_reports_checkpoint(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        self.assertFalse(self.verify(receipt, self.other_public_key))
        self.assertEqual(
            self.inspect(receipt, self.other_public_key),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_other_key_signing_reports_checkpoint(self):
        foreign = self.log.signed_audit_batch([0, 2, 4], _SEED_B)
        self.assertTrue(verify_audit_batch(foreign.batch))
        self.assertTrue(
            verify_signed_root(foreign.checkpoint, self.other_public_key)
        )
        self.assertFalse(self.verify(foreign))
        self.assertEqual(
            self.inspect(foreign),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_forged_checkpoint_signature_reports_checkpoint(self):
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
        forged = self.bypass_batch(receipt, checkpoint=forged_checkpoint)
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_tampered_entry_reports_entry_at_absolute_index(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        hash_name, size, root, entries, nodes = receipt.batch
        tampered = []
        for entry in entries:
            if entry.index == 1:
                tampered.append(
                    Entry(
                        entry.index,
                        b"tampered",
                        entry.previous_hash,
                        entry.entry_hash,
                    )
                )
            else:
                tampered.append(entry)
        forged_batch = (hash_name, size, root, tuple(tampered), nodes)
        forged = SignedAuditBatch(forged_batch, receipt.checkpoint)
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, 1, "entry")
        )

    def test_tampered_shared_proof_reports_proof_without_position(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        hash_name, size, root, entries, nodes = receipt.batch
        forged_batch = (
            hash_name,
            size,
            root,
            entries,
            (b"\x00" * 32,) + nodes[1:],
        )
        forged = SignedAuditBatch(forged_batch, receipt.checkpoint)
        self.assertEqual(
            inspect_audit_batch(forged_batch),
            AuditReceiptReport(False, None, "proof"),
        )
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, None, "proof")
        )

    def test_wrong_empty_root_reports_root(self):
        receipt = self.log.signed_audit_batch((), _SEED_A, 0)
        forged = SignedAuditBatch(
            ("sha256", 0, b"\x11" * 32, (), ()), receipt.checkpoint
        )
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, None, "root")
        )

    def test_body_failure_precedes_checkpoint_failure(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        hash_name, size, root, entries, nodes = receipt.batch
        tampered = (
            Entry(
                entries[0].index,
                b"tampered",
                entries[0].previous_hash,
                entries[0].entry_hash,
            ),
        ) + entries[1:]
        checkpoint = receipt.checkpoint
        forged_checkpoint = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = SignedAuditBatch(
            (hash_name, size, root, tampered, nodes), forged_checkpoint
        )
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, 1, "entry")
        )

    def test_checkpoint_failure_precedes_binding_failure(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        other_log = AuditLog()
        for record in ("x", "y", "z", "w", "u", "v", "t"):
            other_log.append(record)
        foreign = other_log.sign_root(_SEED_A)
        forged_checkpoint = SignedRoot(
            foreign.version,
            foreign.hash_name,
            foreign.size,
            foreign.root,
            foreign.head,
            b"\x00" * 64,
        )
        forged = self.bypass_batch(receipt, checkpoint=forged_checkpoint)
        self.assertEqual(
            self.inspect(forged),
            SignedAuditReport(False, None, "checkpoint"),
        )

    def test_different_snapshot_size_reports_binding(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        other = self.log.signed_audit_batch([0, 2], _SEED_A, 4)
        forged = self.bypass_batch(receipt, checkpoint=other.checkpoint)
        self.assertTrue(verify_audit_batch(forged.batch))
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, None, "binding")
        )

    def test_genuine_checkpoint_of_foreign_log_reports_binding(self):
        receipt = self.log.signed_audit_batch([0, 2, 4], _SEED_A)
        other_log = AuditLog()
        for record in ("x", "y", "z", "w", "u", "v", "t"):
            other_log.append(record)
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass_batch(receipt, checkpoint=foreign_checkpoint)
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, None, "binding")
        )

    def test_valid_signature_over_wrong_head_reports_binding(self):
        # The checkpoint signature is genuine over the snapshot's algorithm,
        # size and root but a zero head: verify_signed_root passes, but the
        # batch's last entry hash is the real chain head, so the halves do
        # not bind.
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
        forged = self.bypass_batch(receipt, checkpoint=bogus)
        self.assertTrue(verify_signed_root(bogus, self.public_key))
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, None, "binding")
        )

    def test_empty_snapshot_wrong_head_reports_binding(self):
        receipt = self.log.signed_audit_batch((), _SEED_A, 0)
        checkpoint = receipt.checkpoint
        bogus_signature = _sign(
            _SEED_A, checkpoint.hash_name, 0, checkpoint.root, b"\x11" * 32
        )
        bogus = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            0,
            checkpoint.root,
            b"\x11" * 32,
            bogus_signature,
        )
        forged = self.bypass_batch(receipt, checkpoint=bogus)
        self.assertTrue(verify_signed_root(bogus, self.public_key))
        self.assertFalse(self.verify(forged))
        self.assertEqual(
            self.inspect(forged), SignedAuditReport(False, None, "binding")
        )

    def test_not_a_batch_raises_type_error(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        for bad in (None, receipt.batch, 42, b""):
            with self.assertRaises(TypeError):
                self.inspect(bad)
        bundle = self.log.signed_audit_receipt([1], _SEED_A)
        with self.assertRaises(TypeError):
            self.inspect(bundle)

    def test_bypassed_container_field_types_raise_type_error(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        with self.assertRaises(TypeError):
            self.inspect(self.bypass_batch(receipt, batch=[1, 2]))
        with self.assertRaises(TypeError):
            self.inspect(self.bypass_batch(receipt, checkpoint="x"))

    def test_nested_structural_value_errors_propagate(self):
        receipt = self.log.signed_audit_batch([0, 2], _SEED_A)
        # An empty snapshot carrying an entry is a batch structural
        # ValueError, not a located failure.
        forged = SignedAuditBatch(
            (
                "sha256",
                0,
                self.log.merkle_root(0),
                (self.log.entry(0),),
                (),
            ),
            receipt.checkpoint,
        )
        with self.assertRaises(ValueError):
            self.verify(forged)
        with self.assertRaises(ValueError):
            self.inspect(forged)

    def test_nested_checkpoint_value_errors_propagate(self):
        receipt = self.log.signed_audit_batch([1], _SEED_A)
        forged_checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "head",
            "signature",
        ):
            object.__setattr__(
                forged_checkpoint,
                name,
                getattr(receipt.checkpoint, name),
            )
        object.__setattr__(forged_checkpoint, "signature", b"\x00" * 32)
        forged = self.bypass_batch(receipt, checkpoint=forged_checkpoint)
        with self.assertRaises(ValueError):
            self.verify(forged)
        with self.assertRaises(ValueError):
            self.inspect(forged)

    def test_public_key_validation_always_raises(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        hash_name, size, root, entries, nodes = receipt.batch
        broken = SignedAuditBatch(
            (
                hash_name,
                size,
                root,
                (
                    Entry(
                        entries[0].index,
                        b"tampered",
                        entries[0].previous_hash,
                        entries[0].entry_hash,
                    ),
                )
                + entries[1:],
                nodes,
            ),
            receipt.checkpoint,
        )
        for bad in ("0" * 32, bytearray(self.public_key), memoryview(
            self.public_key
        )):
            with self.assertRaises(TypeError):
                self.inspect(receipt, bad)
            with self.assertRaises(TypeError):
                self.inspect(broken, bad)
        for bad in (self.public_key[:-1], self.public_key + b"\x00"):
            with self.assertRaises(ValueError):
                self.inspect(receipt, bad)
            with self.assertRaises(ValueError):
                self.inspect(broken, bad)

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        receipt = log.signed_audit_batch([0, 2], _SEED_A)
        self.assertEqual(
            self.inspect(receipt), SignedAuditReport(True, None, None)
        )

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.signed_audit_batch([1, 3], _SEED_A)
        checkpoint = receipt.checkpoint
        forged_checkpoint = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = self.bypass_batch(receipt, checkpoint=forged_checkpoint)
        first = self.inspect(forged)
        second = self.inspect(forged)
        self.assertEqual(first, second)
        self.assertEqual(
            (receipt.batch, receipt.checkpoint),
            (
                self.log.signed_audit_batch([1, 3], _SEED_A).batch,
                self.log.signed_audit_batch([1, 3], _SEED_A).checkpoint,
            ),
        )


if __name__ == "__main__":
    unittest.main()
