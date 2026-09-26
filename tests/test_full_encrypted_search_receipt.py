import unittest

from auditchain import (
    AuditLog,
    Entry,
    FullEncryptedSearchReceipt,
    decrypt_entry,
    verify_full_encrypted_search_receipt,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
NONCE = b"nonce-12byte"


def make_log(records=(("enc", "a"), ("plain", "b"), ("enc", "a"), ("enc", "c"), ("enc", "a")), **kwargs):
    """Build a mixed log; records are ("enc"|"plain", value)."""
    log = AuditLog(**kwargs)
    nonce_counter = 0
    for kind, value in records:
        if kind == "enc":
            log.encrypt(value, KEY, nonce=bytes([nonce_counter]) * 12)
        else:
            log.append(value)
        nonce_counter += 1
    return log


def rebuild(receipt, **overrides):
    fields = dict(
        version=receipt.version,
        hash_name=receipt.hash_name,
        size=receipt.size,
        root=receipt.root,
        query=receipt.query,
        start=receipt.start,
        stop=receipt.stop,
        items=receipt.items,
        proof=receipt.proof,
        hits=receipt.hits,
    )
    fields.update(overrides)
    return FullEncryptedSearchReceipt(**fields)


class FullEncryptedSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_fields_and_full_range_items(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        self.assertIsInstance(receipt, FullEncryptedSearchReceipt)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.query, b"a")
        self.assertEqual((receipt.start, receipt.stop), (0, 5))
        # Every entry of the range is listed, one per absolute index.
        self.assertEqual([entry.index for entry in receipt.items], [0, 1, 2, 3, 4])
        for entry in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
        # The shared proof covers the whole selection at once.
        self.assertEqual(
            receipt.proof,
            self.log.batch_inclusion_proof((0, 1, 2, 3, 4), 5)[1],
        )
        # The issuer recorded the hits find_encrypted would report.
        self.assertEqual(receipt.hits, (0, 2, 4))
        self.assertEqual(receipt.hits, self.log.find_encrypted("a", KEY))

    def test_hits_match_what_the_key_unseals(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        hits = []
        for entry in receipt.items:
            try:
                plaintext = decrypt_entry(entry, KEY)
            except ValueError:
                continue
            if plaintext == receipt.query:
                hits.append(entry.index)
        self.assertEqual(tuple(hits), receipt.hits)

    def test_str_query_normalized_to_bytes(self):
        log = AuditLog()
        log.encrypt("位置", KEY, nonce=NONCE)
        receipt = log.full_encrypted_search_receipt("位置", KEY)
        self.assertEqual(receipt.query, "位置".encode("utf-8"))
        self.assertEqual(receipt.hits, (0,))
        self.assertEqual(
            receipt, log.full_encrypted_search_receipt("位置".encode("utf-8"), KEY)
        )

    def test_bytes_and_str_queries_are_equivalent(self):
        self.assertEqual(
            self.log.full_encrypted_search_receipt(b"a", KEY),
            self.log.full_encrypted_search_receipt("a", KEY),
        )

    def test_no_match_records_no_hits(self):
        receipt = self.log.full_encrypted_search_receipt("missing", KEY)
        self.assertEqual(receipt.hits, ())
        self.assertEqual(len(receipt.items), 5)
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_plain_and_foreign_key_entries_never_hit(self):
        log = make_log()
        log.encrypt("a", OTHER_KEY, nonce=b"f" * 12)
        receipt = log.full_encrypted_search_receipt("a", KEY)
        self.assertEqual(receipt.hits, (0, 2, 4))
        # The foreign-key envelope and the plain entry are still listed.
        self.assertEqual([entry.index for entry in receipt.items], [0, 1, 2, 3, 4, 5])
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_explicit_range_and_size(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4, size=4)
        self.assertEqual((receipt.start, receipt.stop), (1, 4))
        self.assertEqual(receipt.size, 4)
        self.assertEqual(receipt.root, self.log.merkle_root(4))
        self.assertEqual([entry.index for entry in receipt.items], [1, 2, 3])
        self.assertEqual(receipt.hits, (2,))
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_empty_range_and_empty_snapshot(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 2, 2)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

        empty = AuditLog()
        receipt = empty.full_encrypted_search_receipt("a", KEY)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))

    def test_issue_is_read_only_and_repeatable(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.find_encrypted("a", KEY),
        )
        first = self.log.full_encrypted_search_receipt("a", KEY)
        second = self.log.full_encrypted_search_receipt("a", KEY)
        self.assertEqual(first, second)
        after = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.find_encrypted("a", KEY),
        )
        self.assertEqual(before, after)

    def test_pruned_log_defaults_to_retained_segment(self):
        log = make_log()
        receipt = log.seal(2)
        log.prune(2, receipt)
        result = log.full_encrypted_search_receipt("a", KEY)
        self.assertEqual((result.start, result.stop), (2, 5))
        self.assertEqual([entry.index for entry in result.items], [2, 3, 4])
        self.assertEqual(result.hits, (2, 4))
        self.assertTrue(verify_full_encrypted_search_receipt(result, KEY))
        with self.assertRaises(ValueError):
            log.full_encrypted_search_receipt("a", KEY, 0, 2)
        with self.assertRaises(ValueError):
            log.full_encrypted_search_receipt("a", KEY, size=1)

    def test_issue_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            self.log.full_encrypted_search_receipt(1, KEY)
        with self.assertRaises(TypeError):
            self.log.full_encrypted_search_receipt(bytearray(b"a"), KEY)
        with self.assertRaises(TypeError):
            self.log.full_encrypted_search_receipt("a", "not-bytes")
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", b"short")
        with self.assertRaises(TypeError):
            self.log.full_encrypted_search_receipt("a", KEY, start=True)
        with self.assertRaises(TypeError):
            self.log.full_encrypted_search_receipt("a", KEY, stop="3")
        with self.assertRaises(TypeError):
            self.log.full_encrypted_search_receipt("a", KEY, size=True)
        with self.assertRaises(TypeError):
            self.log.full_encrypted_search_receipt("a", KEY, size="5")
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", KEY, 3, 2)
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", KEY, -1, 2)
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", KEY, 0, 6)
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", KEY, size=6)
        with self.assertRaises(ValueError):
            self.log.full_encrypted_search_receipt("a", KEY, size=-1)


class FullEncryptedSearchReceiptClassTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.full_encrypted_search_receipt("a", KEY)

    def test_positional_construction_and_equality(self):
        receipt = FullEncryptedSearchReceipt(
            1,
            "sha256",
            self.receipt.size,
            self.receipt.root,
            b"a",
            0,
            5,
            self.receipt.items,
            self.receipt.proof,
            (0, 2, 4),
        )
        self.assertEqual(receipt, self.receipt)
        self.assertNotEqual(receipt, rebuild(self.receipt, hits=(0, 2)))

    def test_frozen(self):
        with self.assertRaises(AttributeError):
            self.receipt.hits = ()

    def test_query_str_normalized_at_construction(self):
        receipt = rebuild(self.receipt, query="a")
        self.assertEqual(receipt.query, b"a")
        self.assertEqual(receipt, self.receipt)

    def test_binary_fields_require_exact_bytes(self):
        with self.assertRaises(TypeError):
            rebuild(self.receipt, root=bytearray(self.receipt.root))
        entry = self.receipt.items[0]
        forged = Entry(entry.index, bytearray(entry.payload), entry.previous_hash, entry.entry_hash)
        with self.assertRaises(TypeError):
            rebuild(self.receipt, items=(forged,) + self.receipt.items[1:])
        # A sub-range receipt carries a non-empty shared proof.
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 0, 2)
        self.assertTrue(receipt.proof)
        with self.assertRaises(TypeError):
            rebuild(receipt, proof=tuple(bytearray(node) for node in receipt.proof))

    def test_coverage_enforced(self):
        items = self.receipt.items
        with self.assertRaises(ValueError):
            rebuild(self.receipt, items=items[:-1])  # incomplete
        with self.assertRaises(ValueError):
            rebuild(self.receipt, items=items + (items[-1],))  # duplicate
        with self.assertRaises(ValueError):
            rebuild(self.receipt, items=(items[1], items[0]) + items[2:])  # order
        moved = Entry(9, items[0].payload, items[0].previous_hash, items[0].entry_hash)
        with self.assertRaises(ValueError):
            rebuild(self.receipt, items=(moved,) + items[1:])  # out of range

    def test_hits_validation(self):
        with self.assertRaises(TypeError):
            rebuild(self.receipt, hits=[0, 2, 4])
        with self.assertRaises(TypeError):
            rebuild(self.receipt, hits=(0, "2", 4))
        with self.assertRaises(TypeError):
            rebuild(self.receipt, hits=(0, True, 4))
        with self.assertRaises(ValueError):
            rebuild(self.receipt, hits=(0, 0, 4))  # duplicate
        with self.assertRaises(ValueError):
            rebuild(self.receipt, hits=(2, 0, 4))  # out of order
        with self.assertRaises(ValueError):
            rebuild(self.receipt, hits=(0, 2, 5))  # out of range
        with self.assertRaises(ValueError):
            rebuild(self.receipt, hits=(-1, 2, 4))  # out of range

    def test_empty_range_must_carry_empty_proof(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 2, 2)
        with self.assertRaises(ValueError):
            rebuild(receipt, proof=(bytes(32),))

    def test_structural_type_errors(self):
        with self.assertRaises(TypeError):
            rebuild(self.receipt, version="1")
        with self.assertRaises(ValueError):
            rebuild(self.receipt, version=2)
        with self.assertRaises(TypeError):
            rebuild(self.receipt, hash_name=b"sha256")
        with self.assertRaises(ValueError):
            rebuild(self.receipt, hash_name="no-such-hash")
        with self.assertRaises(TypeError):
            rebuild(self.receipt, size=True)
        with self.assertRaises(ValueError):
            rebuild(self.receipt, size=-1)
        with self.assertRaises(ValueError):
            rebuild(self.receipt, size=1 << 64)
        with self.assertRaises(ValueError):
            rebuild(self.receipt, root=bytes(16))
        with self.assertRaises(TypeError):
            rebuild(self.receipt, query=1)
        with self.assertRaises(TypeError):
            rebuild(self.receipt, start=True)
        with self.assertRaises(ValueError):
            rebuild(self.receipt, start=4, stop=2)
        with self.assertRaises(TypeError):
            rebuild(self.receipt, items=list(self.receipt.items))
        with self.assertRaises(TypeError):
            rebuild(self.receipt, items=(object(),) * 5)
        with self.assertRaises(TypeError):
            rebuild(self.receipt, proof=list(self.receipt.proof))
        with self.assertRaises(ValueError):
            rebuild(self.receipt, proof=self.receipt.proof + (bytes(16),))


class FullEncryptedSearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.full_encrypted_search_receipt("a", KEY)

    def test_valid_receipt_verifies(self):
        self.assertTrue(verify_full_encrypted_search_receipt(self.receipt, KEY))

    def test_wrong_key_fails_when_hits_are_recorded(self):
        self.assertFalse(verify_full_encrypted_search_receipt(self.receipt, OTHER_KEY))

    def test_zero_hit_receipt_does_not_exercise_the_key(self):
        receipt = self.log.full_encrypted_search_receipt("missing", KEY)
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, OTHER_KEY))

    def test_tampered_entry_returns_false(self):
        entry = self.receipt.items[2]
        forged = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        items = self.receipt.items[:2] + (forged,) + self.receipt.items[3:]
        self.assertFalse(
            verify_full_encrypted_search_receipt(rebuild(self.receipt, items=items), KEY)
        )

    def test_tampered_proof_returns_false(self):
        proof = self.receipt.proof
        if not proof:
            # Cover a sub-range whose shared proof is non-empty.
            receipt = self.log.full_encrypted_search_receipt("a", KEY, 0, 2)
            self.assertTrue(receipt.proof)
            proof = receipt.proof
            tampered = rebuild(receipt, proof=(bytes(32),) + proof[1:])
            self.assertFalse(verify_full_encrypted_search_receipt(tampered, KEY))
            return
        tampered = rebuild(self.receipt, proof=(bytes(32),) + proof[1:])
        self.assertFalse(verify_full_encrypted_search_receipt(tampered, KEY))

    def test_tampered_root_returns_false(self):
        tampered = rebuild(self.receipt, root=bytes(32))
        self.assertFalse(verify_full_encrypted_search_receipt(tampered, KEY))

    def test_tampered_hits_return_false(self):
        for hits in ((), (0, 2), (0, 2, 4, 4 - 1), (1, 2, 4), (0, 1, 2, 4)):
            if hits == self.receipt.hits:
                continue
            try:
                tampered = rebuild(self.receipt, hits=hits)
            except ValueError:
                continue  # structurally illegal hits are rejected outright
            self.assertFalse(verify_full_encrypted_search_receipt(tampered, KEY))

    def test_empty_snapshot_requires_canonical_empty_root(self):
        empty = AuditLog()
        receipt = empty.full_encrypted_search_receipt("a", KEY)
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))
        self.assertFalse(
            verify_full_encrypted_search_receipt(
                rebuild(receipt, root=bytes(32)), KEY
            )
        )

    def test_verify_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            verify_full_encrypted_search_receipt(object(), KEY)
        with self.assertRaises(TypeError):
            verify_full_encrypted_search_receipt(self.receipt, "not-bytes")
        with self.assertRaises(ValueError):
            verify_full_encrypted_search_receipt(self.receipt, b"short")

    def test_bypassed_fields_raise_as_construction(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        object.__setattr__(receipt, "hits", (0, 0, 4))
        with self.assertRaises(ValueError):
            verify_full_encrypted_search_receipt(receipt, KEY)
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        object.__setattr__(receipt, "root", bytearray(receipt.root))
        with self.assertRaises(TypeError):
            verify_full_encrypted_search_receipt(receipt, KEY)


if __name__ == "__main__":
    unittest.main()
