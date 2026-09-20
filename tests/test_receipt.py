import hashlib
import unittest
from dataclasses import FrozenInstanceError

from auditchain import (
    AuditLog,
    AuditReceipt,
    Entry,
    verify_audit_receipt,
)


class AuditReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_receipt_fields(self):
        receipt = self.log.audit_receipt([1, 3])
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertIsInstance(receipt.items, tuple)

    def test_default_size_is_full_log(self):
        receipt = self.log.audit_receipt([0])
        self.assertEqual(receipt.size, len(self.log))

    def test_items_are_sorted_and_anchored(self):
        receipt = self.log.audit_receipt([3, 1])
        indices = [entry.index for entry, _ in receipt.items]
        self.assertEqual(indices, [1, 3, 4])
        last_entry, _ = receipt.items[-1]
        self.assertEqual(last_entry.index, receipt.size - 1)

    def test_last_index_added_automatically(self):
        receipt = self.log.audit_receipt([0])
        self.assertEqual([entry.index for entry, _ in receipt.items], [0, 4])
        # Already present: no duplicate is introduced.
        receipt = self.log.audit_receipt([4])
        self.assertEqual([entry.index for entry, _ in receipt.items], [4])

    def test_empty_snapshot_has_no_items(self):
        receipt = self.log.audit_receipt([], 0)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.root, hashlib.sha256(b"auditchain/merkle-empty/v1").digest())
        self.assertEqual(AuditLog().audit_receipt([]).items, ())

    def test_explicit_size(self):
        receipt = self.log.audit_receipt([1], 3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual([entry.index for entry, _ in receipt.items], [1, 2])

    def test_entries_and_proofs_match_log(self):
        receipt = self.log.audit_receipt([0, 2, 4])
        for entry, proof in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
            self.assertEqual(proof, self.log.inclusion_proof(entry.index))

    def test_iterable_indices(self):
        self.assertEqual(self.log.audit_receipt(iter([1, 2])), self.log.audit_receipt([1, 2]))
        self.assertEqual(
            self.log.audit_receipt(index for index in (2, 0)),
            self.log.audit_receipt([0, 2]),
        )

    def test_receipt_is_frozen_and_compares_by_fields(self):
        receipt = self.log.audit_receipt([1])
        clone = AuditReceipt(
            receipt.version, receipt.hash_name, receipt.size, receipt.root, receipt.items
        )
        self.assertEqual(receipt, clone)
        self.assertEqual(hash(receipt), hash(clone))
        with self.assertRaises(FrozenInstanceError):
            receipt.size = 3

    def test_call_is_read_only(self):
        receipt = self.log.audit_receipt([0, 2])
        self.assertEqual(receipt, self.log.audit_receipt([0, 2]))
        self.assertEqual(len(self.log), 5)
        self.assertTrue(self.log.verify())

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.audit_receipt([], "3")
        with self.assertRaises(TypeError):
            self.log.audit_receipt([], True)
        with self.assertRaises(TypeError):
            self.log.audit_receipt([], 1.5)
        with self.assertRaises(ValueError):
            self.log.audit_receipt([], -1)
        with self.assertRaises(ValueError):
            self.log.audit_receipt([], len(self.log) + 1)

    def test_indices_must_be_an_iterable_of_integers(self):
        with self.assertRaises(TypeError):
            self.log.audit_receipt(3)
        with self.assertRaises(TypeError):
            self.log.audit_receipt("abc")
        with self.assertRaises(TypeError):
            self.log.audit_receipt(b"\x00\x01")
        with self.assertRaises(TypeError):
            self.log.audit_receipt([1, "2"])
        with self.assertRaises(TypeError):
            self.log.audit_receipt([True])
        with self.assertRaises(TypeError):
            self.log.audit_receipt([1.0])

    def test_index_range_and_duplicates(self):
        with self.assertRaises(ValueError):
            self.log.audit_receipt([-1])
        with self.assertRaises(ValueError):
            self.log.audit_receipt([5])
        with self.assertRaises(ValueError):
            self.log.audit_receipt([4], 3)
        with self.assertRaises(ValueError):
            self.log.audit_receipt([1, 1])
        with self.assertRaises(ValueError):
            self.log.audit_receipt([0], 0)

    def test_pruned_log(self):
        receipt = self.log.seal(3)
        self.log.prune(3, receipt)
        self.log.append("f")
        with self.assertRaises(ValueError):
            self.log.audit_receipt([2])
        with self.assertRaises(ValueError):
            self.log.audit_receipt([], 3)
        with self.assertRaises(ValueError):
            self.log.audit_receipt([], 2)
        offline = self.log.audit_receipt([3, 5])
        self.assertEqual([entry.index for entry, _ in offline.items], [3, 5])
        self.assertTrue(verify_audit_receipt(offline))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        receipt = log.audit_receipt([0])
        self.assertEqual(receipt.hash_name, "sha3-256")
        self.assertEqual(receipt.root, log.merkle_root())
        self.assertTrue(verify_audit_receipt(receipt))


class VerifyAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.receipt = self.log.audit_receipt([1, 3])

    def rebuild(self, **changes):
        fields = {
            "version": self.receipt.version,
            "hash_name": self.receipt.hash_name,
            "size": self.receipt.size,
            "root": self.receipt.root,
            "items": self.receipt.items,
        }
        fields.update(changes)
        return AuditReceipt(**fields)

    def test_valid_receipt_verifies(self):
        self.assertTrue(verify_audit_receipt(self.receipt))
        self.assertTrue(verify_audit_receipt(self.log.audit_receipt([], 0)))
        self.assertTrue(verify_audit_receipt(AuditLog().audit_receipt([])))

    def test_every_subset_verifies(self):
        for indices in ([0], [2], [0, 1, 2, 3, 4], [4]):
            self.assertTrue(verify_audit_receipt(self.log.audit_receipt(indices)))

    def test_not_a_receipt(self):
        with self.assertRaises(TypeError):
            verify_audit_receipt("receipt")
        with self.assertRaises(TypeError):
            verify_audit_receipt(None)

    def test_version_checked(self):
        with self.assertRaises(ValueError):
            verify_audit_receipt(self.rebuild(version=2))
        with self.assertRaises(TypeError):
            verify_audit_receipt(self.rebuild(version="1"))
        with self.assertRaises(TypeError):
            verify_audit_receipt(self.rebuild(version=True))

    def test_hash_name_checked(self):
        with self.assertRaises(ValueError):
            verify_audit_receipt(self.rebuild(hash_name="not-a-hash"))
        with self.assertRaises(TypeError):
            verify_audit_receipt(self.rebuild(hash_name=None))

    def test_size_checked(self):
        with self.assertRaises(ValueError):
            verify_audit_receipt(self.rebuild(size=-1))
        with self.assertRaises(TypeError):
            verify_audit_receipt(self.rebuild(size="5"))
        with self.assertRaises(TypeError):
            verify_audit_receipt(self.rebuild(size=False))

    def test_root_checked(self):
        with self.assertRaises(TypeError):
            verify_audit_receipt(self.rebuild(root="root"))
        with self.assertRaises(ValueError):
            verify_audit_receipt(self.rebuild(root=b"\x00" * 31))
        self.assertFalse(verify_audit_receipt(self.rebuild(root=b"\x00" * 32)))

    def test_items_structure_checked(self):
        with self.assertRaises(TypeError):
            verify_audit_receipt(self.rebuild(items=list(self.receipt.items)))
        with self.assertRaises(TypeError):
            verify_audit_receipt(self.rebuild(items=(["x"],)))
        with self.assertRaises(ValueError):
            verify_audit_receipt(self.rebuild(items=(("x",),)))
        with self.assertRaises(TypeError):
            verify_audit_receipt(self.rebuild(items=((("not-an-entry", ()),))))
        entry, proof = self.receipt.items[0]
        with self.assertRaises(TypeError):
            verify_audit_receipt(self.rebuild(items=((entry, list(proof)),) + self.receipt.items[1:]))
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                self.rebuild(items=((entry, proof + (b"\x00" * 16,)),) + self.receipt.items[1:])
            )

    def test_items_must_cover_snapshot_head(self):
        headless = self.rebuild(items=self.receipt.items[:-1])
        with self.assertRaises(ValueError):
            verify_audit_receipt(headless)
        with self.assertRaises(ValueError):
            verify_audit_receipt(self.rebuild(items=()))

    def test_items_must_be_ascending_and_distinct(self):
        items = self.receipt.items
        with self.assertRaises(ValueError):
            verify_audit_receipt(self.rebuild(items=(items[1], items[0], items[2])))
        with self.assertRaises(ValueError):
            verify_audit_receipt(self.rebuild(items=(items[0], items[0], items[2])))

    def test_item_index_out_of_range(self):
        entry, proof = self.receipt.items[-1]
        moved = Entry(entry.index + 1, entry.payload, entry.previous_hash, entry.entry_hash)
        with self.assertRaises(ValueError):
            verify_audit_receipt(self.rebuild(items=self.receipt.items[:-1] + ((moved, proof),)))
        huge = Entry(2**64, entry.payload, entry.previous_hash, entry.entry_hash)
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                self.rebuild(size=2**64 + 1, items=self.receipt.items[:-1] + ((huge, proof),))
            )

    def test_tampered_entry_returns_false(self):
        entry, proof = self.receipt.items[0]
        forged = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        receipt = self.rebuild(items=((forged, proof),) + self.receipt.items[1:])
        self.assertFalse(verify_audit_receipt(receipt))

    def test_tampered_entry_hash_returns_false(self):
        entry, proof = self.receipt.items[0]
        forged = Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 32)
        receipt = self.rebuild(items=((forged, proof),) + self.receipt.items[1:])
        self.assertFalse(verify_audit_receipt(receipt))

    def test_tampered_proof_returns_false(self):
        entry, proof = self.receipt.items[-1]
        wrong = (b"\x00" * 32,) + proof[1:]
        receipt = self.rebuild(items=self.receipt.items[:-1] + ((entry, wrong),))
        self.assertFalse(verify_audit_receipt(receipt))

    def test_malformed_proof_rejected(self):
        entry, proof = self.receipt.items[-1]
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                self.rebuild(items=self.receipt.items[:-1] + ((entry, proof[:-1]),))
            )
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                self.rebuild(
                    items=self.receipt.items[:-1] + ((entry, proof + (b"\x00" * 32,)),)
                )
            )

    def test_empty_snapshot_root_checked(self):
        receipt = self.log.audit_receipt([], 0)
        self.assertTrue(verify_audit_receipt(receipt))
        self.assertFalse(verify_audit_receipt(self.rebuild(size=0, root=b"\x00" * 32, items=())))

    def test_cross_algorithm_receipt_fails(self):
        other = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c", "d", "e"):
            other.append(record)
        receipt = other.audit_receipt([1, 3])
        self.assertTrue(verify_audit_receipt(receipt))
        # Same entries under the wrong algorithm name must not verify.
        mismatched = self.rebuild(hash_name="sha3-256")
        self.assertFalse(verify_audit_receipt(mismatched))


if __name__ == "__main__":
    unittest.main()
