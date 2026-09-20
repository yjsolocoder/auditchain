import unittest

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

    def test_fields(self):
        receipt = self.log.audit_receipt([1, 3])
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root(5))
        self.assertEqual([entry.index for entry, _ in receipt.items], [1, 3, 4])

    def test_last_entry_auto_added(self):
        receipt = self.log.audit_receipt([0])
        self.assertEqual([entry.index for entry, _ in receipt.items], [0, 4])

    def test_explicit_last_entry_not_duplicated(self):
        receipt = self.log.audit_receipt([2, 4])
        self.assertEqual([entry.index for entry, _ in receipt.items], [2, 4])

    def test_items_sorted_regardless_of_input_order(self):
        receipt = self.log.audit_receipt([3, 0, 1])
        self.assertEqual([entry.index for entry, _ in receipt.items], [0, 1, 3, 4])

    def test_empty_selection_still_carries_last_entry(self):
        receipt = self.log.audit_receipt([])
        self.assertEqual(receipt.size, 5)
        self.assertEqual([entry.index for entry, _ in receipt.items], [4])
        self.assertEqual(receipt.root, self.log.merkle_root(5))
        self.assertTrue(verify_audit_receipt(receipt))

    def test_empty_selection_on_explicit_size_carries_that_last_entry(self):
        receipt = self.log.audit_receipt([], 3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual([entry.index for entry, _ in receipt.items], [2])
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertTrue(verify_audit_receipt(receipt))

    def test_empty_snapshot(self):
        receipt = self.log.audit_receipt((), 0)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.root, self.log.merkle_root(0))

    def test_explicit_size(self):
        receipt = self.log.audit_receipt([1], 3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual([entry.index for entry, _ in receipt.items], [1, 2])

    def test_items_carry_entries_and_proofs(self):
        receipt = self.log.audit_receipt([0, 2], 4)
        for entry, proof in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
            self.assertEqual(proof, self.log.inclusion_proof(entry.index, 4))

    def test_receipt_is_immutable(self):
        receipt = self.log.audit_receipt([0])
        with self.assertRaises(Exception):
            receipt.size = 3

    def test_positional_construction_and_equality(self):
        receipt = self.log.audit_receipt([1])
        clone = AuditReceipt(1, "sha256", receipt.size, receipt.root, receipt.items)
        self.assertEqual(receipt, clone)
        self.assertNotEqual(receipt, self.log.audit_receipt([2]))

    def test_call_is_read_only(self):
        head = self.log.head
        root = self.log.merkle_root()
        self.log.audit_receipt([1, 2])
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.merkle_root(), root)
        self.assertTrue(self.log.verify())

    def test_receipt_survives_later_appends(self):
        receipt = self.log.audit_receipt([1], 4)
        self.log.append("f")
        self.assertTrue(verify_audit_receipt(receipt))

    def test_index_type_errors(self):
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError):
                self.log.audit_receipt([bad])
        with self.assertRaises(TypeError):
            self.log.audit_receipt(1)

    def test_duplicate_indices_rejected(self):
        with self.assertRaises(ValueError):
            self.log.audit_receipt([2, 2])
        with self.assertRaises(ValueError):
            self.log.audit_receipt([4, 4])

    def test_index_range(self):
        with self.assertRaises(ValueError):
            self.log.audit_receipt([-1])
        with self.assertRaises(ValueError):
            self.log.audit_receipt([5])
        with self.assertRaises(ValueError):
            self.log.audit_receipt([3], 3)

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.audit_receipt([0], "3")
        with self.assertRaises(ValueError):
            self.log.audit_receipt([0], -1)
        with self.assertRaises(ValueError):
            self.log.audit_receipt([0], 6)

    def test_any_iterable_accepted(self):
        receipt = self.log.audit_receipt(iter([1, 3]))
        self.assertEqual([entry.index for entry, _ in receipt.items], [1, 3, 4])
        receipt = self.log.audit_receipt((i for i in (0,)))
        self.assertEqual([entry.index for entry, _ in receipt.items], [0, 4])


class AuditReceiptPrunedLogTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.twin = AuditLog()
        for i in range(6):
            self.log.append(f"r{i}")
            self.twin.append(f"r{i}")
        self.log.prune(2, self.log.seal(2))

    def test_receipt_after_prune(self):
        receipt = self.log.audit_receipt([2, 4])
        self.assertEqual([entry.index for entry, _ in receipt.items], [2, 4, 5])
        self.assertEqual(receipt.root, self.twin.merkle_root(6))
        self.assertTrue(verify_audit_receipt(receipt))

    def test_pruned_index_rejected(self):
        with self.assertRaises(ValueError):
            self.log.audit_receipt([1])

    def test_pruned_snapshot_rejected(self):
        with self.assertRaises(ValueError):
            self.log.audit_receipt([], 1)

    def test_empty_snapshot_still_available(self):
        receipt = self.log.audit_receipt((), 0)
        self.assertEqual(receipt.items, ())
        self.assertTrue(verify_audit_receipt(receipt))


class AuditReceiptValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.receipt = self.log.audit_receipt([0])

    def make(self, **overrides):
        fields = {
            "version": 1,
            "hash_name": "sha256",
            "size": self.receipt.size,
            "root": self.receipt.root,
            "items": self.receipt.items,
        }
        fields.update(overrides)
        return AuditReceipt(**fields)

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
        with self.assertRaises(ValueError):
            self.make(size=-1)

    def test_root_validation(self):
        with self.assertRaises(TypeError):
            self.make(root="0" * 32)
        with self.assertRaises(ValueError):
            self.make(root=b"\x00" * 31)

    def test_root_bytearray_normalized(self):
        receipt = self.make(root=bytearray(self.receipt.root))
        self.assertIsInstance(receipt.root, bytes)
        self.assertEqual(receipt, self.receipt)

    def test_items_must_be_tuple_of_pairs(self):
        with self.assertRaises(TypeError):
            self.make(items=list(self.receipt.items))
        with self.assertRaises(TypeError):
            self.make(items=("not-a-pair",))
        with self.assertRaises(TypeError):
            self.make(items=((self.log.entry(0),),))

    def test_item_entry_must_be_entry(self):
        with self.assertRaises(TypeError):
            self.make(items=(("not-an-entry", ()),))

    def test_item_proof_must_be_tuple_of_digests(self):
        entry = self.log.entry(2)
        with self.assertRaises(TypeError):
            self.make(items=((entry, list(self.log.inclusion_proof(2))),))
        with self.assertRaises(TypeError):
            self.make(items=((entry, ("nope",)),))
        with self.assertRaises(ValueError):
            self.make(items=((entry, (b"\x00" * 16,)),))

    def test_item_indices_must_be_ascending(self):
        first = (self.log.entry(2), self.log.inclusion_proof(2))
        second = (self.log.entry(0), self.log.inclusion_proof(0))
        with self.assertRaises(ValueError):
            self.make(items=(first, second))
        with self.assertRaises(ValueError):
            self.make(items=(first, first))

    def test_non_empty_receipt_must_include_last_entry(self):
        with self.assertRaises(ValueError):
            self.make(items=((self.log.entry(0), self.log.inclusion_proof(0)),))

    def test_non_empty_receipt_with_no_items_rejected(self):
        # size > 0 with items == () is a missing last entry, not a valid
        # "empty selection": such a receipt would carry zero evidence.
        with self.assertRaises(ValueError):
            self.make(items=())

    def test_empty_snapshot_requires_empty_items(self):
        empty = self.log.audit_receipt((), 0)
        self.assertEqual(empty.items, ())
        with self.assertRaises(ValueError):
            self.make(size=0)


class VerifyAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_genuine_receipts_verify(self):
        for indices, size in (([0], None), ([1, 3], None), ([3], 4), ([], None), ([], 3)):
            receipt = self.log.audit_receipt(indices, size)
            self.assertTrue(verify_audit_receipt(receipt), (indices, size))

    def test_empty_snapshot_verifies(self):
        self.assertTrue(verify_audit_receipt(self.log.audit_receipt((), 0)))

    def test_empty_snapshot_wrong_root_returns_false(self):
        receipt = self.log.audit_receipt((), 0)
        forged = AuditReceipt(1, "sha256", 0, b"\x00" * 32, ())
        self.assertFalse(verify_audit_receipt(forged))
        self.assertTrue(verify_audit_receipt(receipt))

    def make_bypassed(self, **overrides):
        receipt = self.log.audit_receipt([1])
        fields = {
            "version": 1,
            "hash_name": "sha256",
            "size": receipt.size,
            "root": receipt.root,
            "items": receipt.items,
        }
        fields.update(overrides)
        forged = AuditReceipt.__new__(AuditReceipt)
        for name, value in fields.items():
            object.__setattr__(forged, name, value)
        return forged

    def test_zero_evidence_non_empty_receipt_returns_false(self):
        # The bypass under repair: size > 0, items == () and an arbitrary
        # root must never be accepted without the last entry and its proof.
        for root in (b"\x00" * 32, self.log.merkle_root(5), b"\xff" * 32):
            forged = self.make_bypassed(root=root, items=())
            self.assertFalse(verify_audit_receipt(forged))

    def test_bypassed_receipt_missing_last_entry_returns_false(self):
        receipt = self.log.audit_receipt([1])
        entry, proof = receipt.items[0]
        forged = self.make_bypassed(items=((entry, proof),))
        self.assertFalse(verify_audit_receipt(forged))

    def test_bypassed_empty_snapshot_with_items_returns_false(self):
        forged = self.make_bypassed(
            size=0,
            root=b"\x00" * 32,
            items=((self.log.entry(0), ()),),
        )
        self.assertFalse(verify_audit_receipt(forged))

    def test_wrong_root_returns_false(self):
        receipt = self.log.audit_receipt([1])
        forged = AuditReceipt(1, "sha256", receipt.size, b"\x00" * 32, receipt.items)
        self.assertFalse(verify_audit_receipt(forged))

    def test_tampered_entry_payload_returns_false(self):
        receipt = self.log.audit_receipt([1])
        entry, proof = receipt.items[0]
        tampered = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        forged = AuditReceipt(1, "sha256", receipt.size, receipt.root, ((tampered, proof),) + receipt.items[1:])
        self.assertFalse(verify_audit_receipt(forged))

    def test_tampered_entry_hash_returns_false(self):
        receipt = self.log.audit_receipt([1])
        entry, proof = receipt.items[0]
        tampered = Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 32)
        forged = AuditReceipt(1, "sha256", receipt.size, receipt.root, ((tampered, proof),) + receipt.items[1:])
        self.assertFalse(verify_audit_receipt(forged))

    def test_wrong_proof_digest_returns_false(self):
        receipt = self.log.audit_receipt([1])
        (entry, proof), *rest = receipt.items
        forged_proof = (b"\x00" * 32,) + proof[1:]
        forged = AuditReceipt(1, "sha256", receipt.size, receipt.root, ((entry, forged_proof),) + tuple(rest))
        self.assertFalse(verify_audit_receipt(forged))

    def test_proof_structure_checked(self):
        receipt = self.log.audit_receipt([1])
        (entry, proof), *rest = receipt.items
        short = AuditReceipt(1, "sha256", receipt.size, receipt.root, ((entry, proof[:-1]),) + tuple(rest))
        with self.assertRaises(ValueError):
            verify_audit_receipt(short)
        long = AuditReceipt(
            1, "sha256", receipt.size, receipt.root,
            ((entry, proof + (b"\x00" * 32,)),) + tuple(rest),
        )
        with self.assertRaises(ValueError):
            verify_audit_receipt(long)

    def test_not_a_receipt_raises(self):
        with self.assertRaises(TypeError):
            verify_audit_receipt(("not", "a", "receipt"))
        with self.assertRaises(TypeError):
            verify_audit_receipt(None)

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c", "d"):
            log.append(record)
        receipt = log.audit_receipt([0, 2])
        self.assertEqual(receipt.hash_name, "sha3-256")
        self.assertTrue(verify_audit_receipt(receipt))
        # The same fields re-labeled as sha256 must not verify.
        forged = AuditReceipt(1, "sha256", receipt.size, receipt.root, receipt.items)
        self.assertFalse(verify_audit_receipt(forged))


if __name__ == "__main__":
    unittest.main()
