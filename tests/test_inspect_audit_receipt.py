import itertools
import unittest

from auditchain import (
    AuditLog,
    AuditReceipt,
    AuditReceiptReport,
    Entry,
    inspect_audit_batch,
    inspect_audit_receipt,
    verify_audit_batch,
    verify_audit_receipt,
)


class AuditReceiptReportTest(unittest.TestCase):
    def test_success_constant(self):
        report = AuditReceiptReport(True, None, None)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)

    def test_positional_construction_and_equality(self):
        success = AuditReceiptReport(True, None, None)
        self.assertEqual(success, AuditReceiptReport(True, None, None))
        failure = AuditReceiptReport(False, 3, "entry")
        self.assertEqual(failure, AuditReceiptReport(False, 3, "entry"))
        self.assertNotEqual(failure, AuditReceiptReport(False, 4, "entry"))
        self.assertNotEqual(failure, AuditReceiptReport(False, 3, "proof"))
        self.assertNotEqual(success, failure)
        self.assertNotEqual(failure, (False, 3, "entry"))

    def test_report_is_frozen(self):
        report = AuditReceiptReport(True, None, None)
        with self.assertRaises(Exception):
            report.ok = False

    def test_ok_must_be_bool(self):
        with self.assertRaises(TypeError):
            AuditReceiptReport(1, None, None)
        with self.assertRaises(TypeError):
            AuditReceiptReport(0, None, None)

    def test_success_must_carry_neither_code_nor_index(self):
        with self.assertRaises(ValueError):
            AuditReceiptReport(True, 0, None)
        with self.assertRaises(ValueError):
            AuditReceiptReport(True, None, "root")
        with self.assertRaises(ValueError):
            AuditReceiptReport(True, 0, "entry")

    def test_failure_requires_a_known_code(self):
        with self.assertRaises(ValueError):
            AuditReceiptReport(False, None, None)
        with self.assertRaises(ValueError):
            AuditReceiptReport(False, 0, None)

    def test_code_type(self):
        with self.assertRaises(TypeError):
            AuditReceiptReport(False, None, b"entry")
        with self.assertRaises(TypeError):
            AuditReceiptReport(False, None, 0)

    def test_unknown_code_rejected(self):
        with self.assertRaises(ValueError):
            AuditReceiptReport(False, None, "verify")
        with self.assertRaises(ValueError):
            AuditReceiptReport(False, None, "")

    def test_each_known_code_accepted_without_position(self):
        for code in ("entry", "proof", "root", "last"):
            report = AuditReceiptReport(False, None, code)
            self.assertEqual(report.code, code)
            self.assertIsNone(report.index)

    def test_index_must_be_integer_or_none(self):
        with self.assertRaises(TypeError):
            AuditReceiptReport(False, 1.0, "entry")
        with self.assertRaises(TypeError):
            AuditReceiptReport(False, "1", "entry")
        with self.assertRaises(TypeError):
            AuditReceiptReport(False, True, "entry")

    def test_negative_index_rejected(self):
        with self.assertRaises(ValueError):
            AuditReceiptReport(False, -1, "entry")


class InspectAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    @staticmethod
    def bypass(**fields):
        """Build a receipt skipping AuditReceipt.__post_init__ validation."""
        receipt = AuditReceipt.__new__(AuditReceipt)
        defaults = {
            "version": 1,
            "hash_name": "sha256",
            "size": 5,
            "root": b"",
            "items": (),
        }
        defaults.update(fields)
        for name, value in defaults.items():
            object.__setattr__(receipt, name, value)
        return receipt

    def test_genuine_receipts_report_success(self):
        for indices, size in (
            ([0], None),
            ([1, 3], None),
            ([3], 4),
            ([], None),
            ([], 3),
            ((), 0),
        ):
            receipt = self.log.audit_receipt(indices, size)
            report = inspect_audit_receipt(receipt)
            self.assertEqual(report, AuditReceiptReport(True, None, None), (indices, size))

    def test_success_corresponds_to_verifier_truth(self):
        for indices, size in (
            ([0], None),
            ([1, 3], None),
            ([3], 4),
            ([], None),
            ([], 3),
            ((), 0),
        ):
            receipt = self.log.audit_receipt(indices, size)
            self.assertEqual(
                inspect_audit_receipt(receipt).ok, verify_audit_receipt(receipt)
            )

    def test_empty_snapshot_wrong_root_reports_root(self):
        forged = AuditReceipt(1, "sha256", 0, b"\x00" * 32, ())
        report = inspect_audit_receipt(forged)
        self.assertEqual(report, AuditReceiptReport(False, None, "root"))
        self.assertFalse(verify_audit_receipt(forged))

    def test_tampered_payload_reports_entry_at_index(self):
        receipt = self.log.audit_receipt([1, 3])
        (entry1, proof1), (entry3, proof3), (entry4, proof4) = receipt.items
        tampered = Entry(entry1.index, b"tampered", entry1.previous_hash, entry1.entry_hash)
        forged = AuditReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            ((tampered, proof1), (entry3, proof3), (entry4, proof4)),
        )
        report = inspect_audit_receipt(forged)
        self.assertEqual(report, AuditReceiptReport(False, 1, "entry"))
        self.assertFalse(verify_audit_receipt(forged))

    def test_tampered_entry_hash_reports_entry_at_index(self):
        receipt = self.log.audit_receipt([1, 3])
        (entry1, proof1), rest = receipt.items[0], receipt.items[1:]
        tampered = Entry(
            entry1.index, entry1.payload, entry1.previous_hash, b"\x00" * 32
        )
        forged = AuditReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            ((tampered, proof1),) + tuple(rest),
        )
        self.assertEqual(
            inspect_audit_receipt(forged), AuditReceiptReport(False, 1, "entry")
        )

    def test_wrong_root_reports_proof_at_first_item(self):
        receipt = self.log.audit_receipt([1, 3])
        forged = AuditReceipt(1, "sha256", receipt.size, b"\x00" * 32, receipt.items)
        report = inspect_audit_receipt(forged)
        self.assertEqual(report, AuditReceiptReport(False, 1, "proof"))
        self.assertFalse(verify_audit_receipt(forged))

    def test_wrong_proof_reports_proof_at_that_index(self):
        receipt = self.log.audit_receipt([1, 3])
        (entry, proof), *rest = receipt.items
        forged_proof = (b"\x00" * 32,) + proof[1:]
        forged = AuditReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            ((entry, forged_proof),) + tuple(rest),
        )
        self.assertEqual(
            inspect_audit_receipt(forged), AuditReceiptReport(False, 1, "proof")
        )

    def test_entry_mismatch_precedes_proof_mismatch_on_same_item(self):
        receipt = self.log.audit_receipt([1])
        entry, proof = receipt.items[0]
        tampered_entry = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        forged_proof = (b"\x00" * 32,) + proof[1:]
        forged = AuditReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            ((tampered_entry, forged_proof),) + receipt.items[1:],
        )
        self.assertEqual(
            inspect_audit_receipt(forged), AuditReceiptReport(False, 1, "entry")
        )

    def test_earlier_index_proof_precedes_later_index_entry(self):
        receipt = self.log.audit_receipt([1, 3])
        (entry1, proof1), (entry3, proof3), (entry4, proof4) = receipt.items
        forged_proof1 = (b"\x00" * 32,) + proof1[1:]
        tampered3 = Entry(
            entry3.index, b"tampered", entry3.previous_hash, entry3.entry_hash
        )
        forged = AuditReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            ((entry1, forged_proof1), (tampered3, proof3), (entry4, proof4)),
        )
        self.assertEqual(
            inspect_audit_receipt(forged), AuditReceiptReport(False, 1, "proof")
        )

    def test_only_first_mismatch_is_reported(self):
        # Two tampered entries: only the lower absolute index is reported.
        receipt = self.log.audit_receipt([1, 3])
        rebuilt = []
        for entry, proof in receipt.items:
            if entry.index in (1, 3):
                tampered = Entry(
                    entry.index,
                    b"tampered",
                    entry.previous_hash,
                    entry.entry_hash,
                )
                rebuilt.append((tampered, proof))
            else:
                rebuilt.append((entry, proof))
        forged = AuditReceipt(
            1, "sha256", receipt.size, receipt.root, tuple(rebuilt)
        )
        self.assertEqual(
            inspect_audit_receipt(forged), AuditReceiptReport(False, 1, "entry")
        )

    def test_bypassed_missing_last_entry_reports_last(self):
        forged = self.bypass(
            size=5,
            root=self.log.merkle_root(5),
            items=((self.log.entry(0), self.log.inclusion_proof(0)),),
        )
        report = inspect_audit_receipt(forged)
        self.assertEqual(report, AuditReceiptReport(False, None, "last"))
        self.assertEqual(report.ok, verify_audit_receipt(forged))
        self.assertFalse(verify_audit_receipt(forged))

    def test_bypassed_zero_evidence_reports_last(self):
        forged = self.bypass(size=5, root=b"X" * 32, items=())
        self.assertEqual(
            inspect_audit_receipt(forged), AuditReceiptReport(False, None, "last")
        )
        genuine_root_no_evidence = self.bypass(
            size=5, root=self.log.merkle_root(5), items=()
        )
        self.assertEqual(
            inspect_audit_receipt(genuine_root_no_evidence),
            AuditReceiptReport(False, None, "last"),
        )

    def test_bypassed_items_on_empty_snapshot_report_failure(self):
        # verify_audit_receipt returns False for size == 0 with items, so
        # the diagnosis must report a failure rather than raise; the root
        # is canonical, hence it is the item's proof that cannot connect
        # to the empty snapshot root.
        forged = self.bypass(
            size=0,
            root=self.log.merkle_root(0),
            items=((self.log.entry(0), ()),),
        )
        report = inspect_audit_receipt(forged)
        self.assertEqual(report, AuditReceiptReport(False, 0, "proof"))
        self.assertEqual(report.ok, bool(verify_audit_receipt(forged)))

    def test_bypassed_items_on_empty_snapshot_wrong_root_report_root(self):
        forged = self.bypass(
            size=0,
            root=b"\x00" * 32,
            items=((self.log.entry(0), ()),),
        )
        self.assertEqual(
            inspect_audit_receipt(forged), AuditReceiptReport(False, None, "root")
        )
        self.assertFalse(verify_audit_receipt(forged))

    def test_bypassed_empty_canonical_root_garbage_items_still_reports_failure(self):
        # verify_audit_receipt returns False without reading the items, so
        # the diagnosis must report a failure for the same stop point even
        # when the bypassed first item carries no usable index.
        uninitialized_entry = Entry.__new__(Entry)
        for forged in (
            self.bypass(size=0, root=self.log.merkle_root(0), items=(1,)),
            self.bypass(
                size=0,
                root=self.log.merkle_root(0),
                items=((uninitialized_entry, ()),),
            ),
        ):
            self.assertFalse(verify_audit_receipt(forged))
            report = inspect_audit_receipt(forged)
            self.assertEqual(report.code, "proof")
            self.assertFalse(report.ok)

    def test_last_precedes_per_item_mismatches(self):
        # A genuine item at index 0 does not excuse the missing last entry.
        forged = self.bypass(
            size=5,
            root=b"X" * 32,
            items=((self.log.entry(0), self.log.inclusion_proof(0, 5)),),
        )
        self.assertEqual(
            inspect_audit_receipt(forged), AuditReceiptReport(False, None, "last")
        )

    def test_proof_structure_errors_propagate(self):
        receipt = self.log.audit_receipt([1])
        entry, proof = receipt.items[0]
        short = AuditReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            ((entry, proof[:-1]),) + receipt.items[1:],
        )
        with self.assertRaises(ValueError):
            inspect_audit_receipt(short)
        long = AuditReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            ((entry, proof + (b"\x00" * 32,)),) + receipt.items[1:],
        )
        with self.assertRaises(ValueError):
            inspect_audit_receipt(long)

    def test_not_a_receipt_raises_type_error(self):
        for bad in (None, (), ("not", "a", "receipt"), 42, b""):
            with self.assertRaises(TypeError):
                inspect_audit_receipt(bad)

    def test_bypassed_structural_corruption_mirrors_verifier(self):
        # The diagnosis performs exactly the checks verify_audit_receipt
        # performs: whatever the verifier raises propagates, whatever it
        # rejects with False becomes a located failure.
        base = self.log.audit_receipt([1])
        wrong_hash = self.bypass(
            hash_name="nope", size=base.size, root=base.root, items=base.items
        )
        narrow_root = self.bypass(
            size=base.size, root=b"\x00" * 16, items=base.items
        )
        for forged in (wrong_hash, narrow_root):
            with self.assertRaises(ValueError):
                verify_audit_receipt(forged)
            with self.assertRaises(ValueError):
                inspect_audit_receipt(forged)

        # version is not re-checked by the verifier itself.
        wrong_version = self.bypass(
            version=2, size=base.size, root=base.root, items=base.items
        )
        self.assertTrue(verify_audit_receipt(wrong_version))
        self.assertEqual(
            inspect_audit_receipt(wrong_version),
            AuditReceiptReport(True, None, None),
        )

        # A genuine receipt relabeled with size == -1 simply omits its
        # (index -2) last entry, so the verifier returns False and the
        # diagnosis locates it with "last".
        negative_size = self.bypass(
            size=-1, root=base.root, items=base.items
        )
        self.assertFalse(verify_audit_receipt(negative_size))
        self.assertEqual(
            inspect_audit_receipt(negative_size),
            AuditReceiptReport(False, None, "last"),
        )

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c", "d"):
            log.append(record)
        receipt = log.audit_receipt([0, 2])
        self.assertEqual(inspect_audit_receipt(receipt), AuditReceiptReport(True, None, None))
        forged = AuditReceipt(1, "sha256", receipt.size, receipt.root, receipt.items)
        report = inspect_audit_receipt(forged)
        # The first item's digest recomputed under sha256 no longer matches.
        self.assertEqual(report, AuditReceiptReport(False, 0, "entry"))
        self.assertEqual(report.ok, verify_audit_receipt(forged))

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.audit_receipt([1, 3])
        before = receipt
        first = inspect_audit_receipt(receipt)
        second = inspect_audit_receipt(receipt)
        self.assertEqual(first, second)
        self.assertEqual(receipt, before)

    def test_success_matches_verifier_across_all_subsets(self):
        for size in range(0, 6):
            choices = range(size)
            for count in range(size + 1):
                for chosen in itertools.combinations(choices, count):
                    receipt = self.log.audit_receipt(chosen, size)
                    self.assertTrue(verify_audit_receipt(receipt), (size, chosen))
                    self.assertEqual(
                        inspect_audit_receipt(receipt),
                        AuditReceiptReport(True, None, None),
                        (size, chosen),
                    )


class InspectAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_genuine_batches_report_success(self):
        for indices, size in (
            ([0], None),
            ([1, 3], None),
            ([3], 4),
            ([], None),
            ([], 3),
            ((), 0),
        ):
            receipt = self.log.audit_batch(indices, size)
            self.assertEqual(
                inspect_audit_batch(receipt),
                AuditReceiptReport(True, None, None),
                (indices, size),
            )
            self.assertEqual(
                inspect_audit_batch(receipt).ok, verify_audit_batch(receipt)
            )

    def test_empty_snapshot_wrong_root_reports_root(self):
        forged = ("sha256", 0, b"\x00" * 32, (), ())
        report = inspect_audit_batch(forged)
        self.assertEqual(report, AuditReceiptReport(False, None, "root"))
        self.assertEqual(report.ok, verify_audit_batch(forged))

    def test_tampered_payload_reports_entry_at_index(self):
        hash_name, size, root, entries, nodes = self.log.audit_batch([1, 3])
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
        forged = (hash_name, size, root, tuple(tampered), nodes)
        report = inspect_audit_batch(forged)
        self.assertEqual(report, AuditReceiptReport(False, 1, "entry"))
        self.assertEqual(report.ok, verify_audit_batch(forged))

    def test_wrong_root_reports_shared_proof_without_position(self):
        hash_name, size, _root, entries, nodes = self.log.audit_batch([1, 3])
        forged = (hash_name, size, b"\x00" * 32, entries, nodes)
        report = inspect_audit_batch(forged)
        self.assertEqual(report, AuditReceiptReport(False, None, "proof"))
        self.assertEqual(report.ok, verify_audit_batch(forged))

    def test_wrong_proof_nodes_report_shared_proof_without_position(self):
        hash_name, size, root, entries, nodes = self.log.audit_batch([1, 3])
        forged = (hash_name, size, root, entries, (b"\x00" * 32,) + nodes[1:])
        report = inspect_audit_batch(forged)
        self.assertEqual(report, AuditReceiptReport(False, None, "proof"))
        self.assertEqual(report.ok, verify_audit_batch(forged))

    def test_only_first_mismatching_entry_is_reported(self):
        receipt = self.log.audit_batch([0, 2])
        hash_name, size, root, entries, nodes = receipt
        tampered = tuple(
            Entry(e.index, b"tampered", e.previous_hash, e.entry_hash)
            for e in entries
        )
        forged = (hash_name, size, root, tampered, nodes)
        self.assertEqual(
            inspect_audit_batch(forged), AuditReceiptReport(False, 0, "entry")
        )

    def test_entry_mismatch_precedes_shared_proof_check(self):
        # A wrong proof node must not mask an earlier entry mismatch, even
        # though the shared proof is what would fail afterwards.
        hash_name, size, root, entries, nodes = self.log.audit_batch([1, 3])
        bad_entries = (
            Entry(
                entries[0].index,
                b"tampered",
                entries[0].previous_hash,
                entries[0].entry_hash,
            ),
        ) + entries[1:]
        forged = (
            hash_name,
            size,
            root,
            bad_entries,
            (b"\x00" * 32,) + nodes[1:],
        )
        self.assertEqual(
            inspect_audit_batch(forged),
            AuditReceiptReport(False, entries[0].index, "entry"),
        )

    def test_single_leaf_wrong_root_reports_proof(self):
        receipt = self.log.audit_batch((), 1)
        hash_name, size, _root, entries, nodes = receipt
        forged = (hash_name, size, b"\x00" * 32, entries, nodes)
        self.assertEqual(
            inspect_audit_batch(forged), AuditReceiptReport(False, None, "proof")
        )
        self.assertFalse(verify_audit_batch(forged))

    def test_missing_last_entry_raises_value_error(self):
        hash_name, size, root, entries, _nodes = self.log.audit_batch([0, 2])
        forged = (hash_name, size, root, entries[:-1], ())
        with self.assertRaises(ValueError):
            inspect_audit_batch(forged)
        with self.assertRaises(ValueError):
            verify_audit_batch(forged)

    def test_zero_evidence_non_empty_snapshot_raises_value_error(self):
        hash_name, _size, root, _entries, _nodes = self.log.audit_batch([1])
        for forged in (
            (hash_name, 5, root, (), ()),
            (hash_name, 5, root, (), (b"\x00" * 32,)),
        ):
            with self.assertRaises(ValueError):
                inspect_audit_batch(forged)

    def test_empty_snapshot_with_entries_raises_value_error(self):
        forged = ("sha256", 0, self.log.merkle_root(0), (self.log.entry(0),), ())
        with self.assertRaises(ValueError):
            inspect_audit_batch(forged)

    def test_not_a_tuple_raises_type_error(self):
        for bad in (None, [], b"", 42):
            with self.assertRaises(TypeError):
                inspect_audit_batch(bad)

    def test_wrong_arity_raises_type_error(self):
        for bad in ((), ("sha256",), ("sha256", 5), tuple(range(6))):
            with self.assertRaises(TypeError):
                inspect_audit_batch(bad)

    def test_field_type_errors_propagate(self):
        hash_name, size, root, entries, nodes = self.log.audit_batch([1])
        for forged in (
            (1, size, root, entries, nodes),
            (hash_name, "5", root, entries, nodes),
            (hash_name, size, "0" * 32, entries, nodes),
            (hash_name, size, root, list(entries), nodes),
            (hash_name, size, root, entries, list(nodes)),
            (hash_name, size, root, (None,), nodes),
        ):
            with self.assertRaises(TypeError):
                inspect_audit_batch(forged)

    def test_structural_value_errors_propagate(self):
        hash_name, size, root, entries, nodes = self.log.audit_batch([0, 2])
        e0, e2, e4 = entries
        for forged in (
            ("nope", size, root, entries, nodes),
            (hash_name, -1, root, entries, nodes),
            (hash_name, size, b"\x00" * 16, entries, nodes),
            (hash_name, size, root, (e2, e0), nodes),
            (hash_name, size, root, entries, nodes + (b"\x00" * 32,)),
        ):
            with self.assertRaises(ValueError):
                inspect_audit_batch(forged)

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c", "d"):
            log.append(record)
        receipt = log.audit_batch([0, 2])
        self.assertEqual(inspect_audit_batch(receipt), AuditReceiptReport(True, None, None))
        hash_name, size, root, entries, nodes = receipt
        relabeled = ("sha256", size, root, entries, nodes)
        report = inspect_audit_batch(relabeled)
        self.assertEqual(report, AuditReceiptReport(False, 0, "entry"))
        self.assertEqual(report.ok, verify_audit_batch(relabeled))

    def test_call_is_read_only_and_deterministic(self):
        receipt = self.log.audit_batch([1, 3])
        before = receipt
        first = inspect_audit_batch(receipt)
        second = inspect_audit_batch(receipt)
        self.assertEqual(first, second)
        self.assertEqual(receipt, before)

    def test_success_matches_verifier_across_all_subsets(self):
        for size in range(0, 6):
            choices = range(size)
            for count in range(size + 1):
                for chosen in itertools.combinations(choices, count):
                    receipt = self.log.audit_batch(chosen, size)
                    self.assertTrue(verify_audit_batch(receipt), (size, chosen))
                    self.assertEqual(
                        inspect_audit_batch(receipt),
                        AuditReceiptReport(True, None, None),
                        (size, chosen),
                    )


class SameTamperedReceiptCorrespondenceTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_itemized_codes_and_indices(self):
        receipt = self.log.audit_receipt([1, 3])
        (entry1, proof1), (entry3, proof3), (entry4, proof4) = receipt.items

        cases = [
            (
                AuditReceipt(
                    1,
                    "sha256",
                    receipt.size,
                    b"\x00" * 32,
                    receipt.items,
                ),
                (False, 1, "proof"),
            ),
            (
                AuditReceipt(
                    1,
                    "sha256",
                    receipt.size,
                    receipt.root,
                    (
                        (
                            Entry(
                                entry1.index,
                                b"tampered",
                                entry1.previous_hash,
                                entry1.entry_hash,
                            ),
                            proof1,
                        ),
                        (entry3, proof3),
                        (entry4, proof4),
                    ),
                ),
                (False, 1, "entry"),
            ),
            (
                AuditReceipt(1, "sha256", 0, b"\x00" * 32, ()),
                (False, None, "root"),
            ),
        ]
        for forged, expected in cases:
            with self.subTest(expected=expected):
                self.assertFalse(verify_audit_receipt(forged))
                self.assertEqual(
                    inspect_audit_receipt(forged),
                    AuditReceiptReport(*expected),
                )

    def test_batch_codes_and_indices(self):
        hash_name, size, root, entries, nodes = self.log.audit_batch([1, 3])
        cases = [
            ((hash_name, size, b"\x00" * 32, entries, nodes), (False, None, "proof")),
            (
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
                (False, entries[0].index, "entry"),
            ),
            (("sha256", 0, b"\x00" * 32, (), ()), (False, None, "root")),
        ]
        for forged, expected in cases:
            with self.subTest(expected=expected):
                self.assertFalse(verify_audit_batch(forged))
                self.assertEqual(
                    inspect_audit_batch(forged), AuditReceiptReport(*expected)
                )


if __name__ == "__main__":
    unittest.main()
