import dataclasses
import unittest

from auditchain import (
    AuditLog,
    EncryptedPrefixReceipt,
    Entry,
    decrypt_entry,
    verify_encrypted_prefix_receipt,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
THIRD_KEY = bytes(reversed(range(32)))
NONCE = b"nonce-12byte"


def make_log(
    records=(
        ("enc", "apple"),
        ("plain", "apricot"),
        ("enc", "application"),
        ("enc", "banana"),
        ("enc", "apply"),
    ),
    **kwargs,
):
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
        prefix=receipt.prefix,
        start=receipt.start,
        stop=receipt.stop,
        items=receipt.items,
        proof=receipt.proof,
        hits=receipt.hits,
    )
    fields.update(overrides)
    return EncryptedPrefixReceipt(**fields)


class EncryptedPrefixReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_fields_and_full_range_items(self):
        receipt = self.log.encrypted_prefix_receipt("app", KEY)
        self.assertIsInstance(receipt, EncryptedPrefixReceipt)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.prefix, b"app")
        self.assertEqual((receipt.start, receipt.stop), (0, 5))
        # Every entry of the range is listed, one per absolute index.
        self.assertEqual(
            [entry.index for entry in receipt.items], [0, 1, 2, 3, 4]
        )
        for entry in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
        # The shared proof covers the whole selection at once.
        self.assertEqual(
            receipt.proof,
            self.log.batch_inclusion_proof((0, 1, 2, 3, 4), 5)[1],
        )
        # The issuer recorded the hits find_encrypted_prefix reports:
        # the plain entry at index 1 never hits, even though it starts
        # with the prefix.
        self.assertEqual(receipt.hits, (0, 2, 4))
        self.assertEqual(receipt.hits, self.log.find_encrypted_prefix("app", KEY))

    def test_hits_match_what_the_key_unseals(self):
        receipt = self.log.encrypted_prefix_receipt("app", KEY)
        hits = []
        for entry in receipt.items:
            try:
                plaintext = decrypt_entry(entry, KEY)
            except ValueError:
                continue
            if plaintext.startswith(receipt.prefix):
                hits.append(entry.index)
        self.assertEqual(tuple(hits), receipt.hits)

    def test_str_prefix_normalized_to_bytes(self):
        log = AuditLog()
        log.encrypt("位置prefix", KEY, nonce=NONCE)
        receipt = log.encrypted_prefix_receipt("位置", KEY)
        self.assertEqual(receipt.prefix, "位置".encode("utf-8"))
        self.assertEqual(receipt.hits, (0,))
        self.assertEqual(
            receipt,
            log.encrypted_prefix_receipt("位置".encode("utf-8"), KEY),
        )

    def test_bytes_and_str_prefixes_are_equivalent(self):
        self.assertEqual(
            self.log.encrypted_prefix_receipt(b"app", KEY),
            self.log.encrypted_prefix_receipt("app", KEY),
        )

    def test_no_match_records_no_hits(self):
        receipt = self.log.encrypted_prefix_receipt("missing", KEY)
        self.assertEqual(receipt.hits, ())
        self.assertEqual(len(receipt.items), 5)
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))

    def test_empty_prefix_hits_all_unsealed_including_empty_plaintext(self):
        log = AuditLog()
        log.encrypt("apple", KEY, nonce=b"0" * 12)
        log.encrypt(b"", KEY, nonce=b"1" * 12)
        log.append(b"")
        log.encrypt("foreign", OTHER_KEY, nonce=b"3" * 12)
        receipt = log.encrypted_prefix_receipt(b"", KEY)
        self.assertEqual(receipt.hits, (0, 1))
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))
        self.assertEqual(
            receipt.hits, log.find_encrypted_prefix(b"", KEY)
        )

    def test_plain_and_foreign_key_entries_never_hit(self):
        log = make_log()
        log.encrypt("apple-foreign", OTHER_KEY, nonce=b"f" * 12)
        receipt = log.encrypted_prefix_receipt("app", KEY)
        self.assertEqual(receipt.hits, (0, 2, 4))
        # The foreign-key envelope and the plain entry are still listed.
        self.assertEqual(
            [entry.index for entry in receipt.items], [0, 1, 2, 3, 4, 5]
        )
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))

    def test_payloads_remain_sealed_no_key_or_plaintext_recorded(self):
        from auditchain import decrypt_entry

        log = AuditLog()
        log.encrypt("TOPSECRET-APPLE", KEY, nonce=b"0" * 12)
        receipt = log.encrypted_prefix_receipt("TOPSECRET", KEY)
        # The encrypted entry is still carried as its sealed envelope and
        # only yields the plaintext with the key.
        sealed = receipt.items[0].payload
        self.assertEqual(sealed, log.entry(0).payload)
        self.assertEqual(decrypt_entry(receipt.items[0], KEY), b"TOPSECRET-APPLE")
        self.assertNotIn(b"TOPSECRET-APPLE", sealed)
        # The key appears nowhere in the frozen receipt's state.
        state = repr(dataclasses.asdict(receipt))
        self.assertNotIn(repr(KEY), state)

    def test_explicit_range_and_size(self):
        receipt = self.log.encrypted_prefix_receipt("app", KEY, 1, 4, size=4)
        self.assertEqual((receipt.start, receipt.stop), (1, 4))
        self.assertEqual(receipt.size, 4)
        self.assertEqual(receipt.root, self.log.merkle_root(4))
        self.assertEqual([entry.index for entry in receipt.items], [1, 2, 3])
        self.assertEqual(receipt.hits, (2,))
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))

    def test_empty_range_and_empty_snapshot(self):
        receipt = self.log.encrypted_prefix_receipt("app", KEY, 2, 2)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))

        empty = AuditLog()
        receipt = empty.encrypted_prefix_receipt("app", KEY)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))

    def test_size_defaults_to_current_length(self):
        self.assertEqual(
            self.log.encrypted_prefix_receipt("app", KEY),
            self.log.encrypted_prefix_receipt("app", KEY, size=len(self.log)),
        )

    def test_issue_is_read_only_and_repeatable(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.find_encrypted_prefix("app", KEY),
        )
        first = self.log.encrypted_prefix_receipt("app", KEY)
        second = self.log.encrypted_prefix_receipt("app", KEY)
        self.assertEqual(first, second)
        after = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.find_encrypted_prefix("app", KEY),
        )
        self.assertEqual(before, after)

    def test_pruned_log_defaults_to_retained_segment(self):
        log = make_log()
        log.prune(2, log.seal(2))
        result = log.encrypted_prefix_receipt("app", KEY)
        self.assertEqual((result.start, result.stop), (2, 5))
        self.assertEqual([entry.index for entry in result.items], [2, 3, 4])
        self.assertEqual(result.hits, (2, 4))
        self.assertTrue(verify_encrypted_prefix_receipt(result, KEY))
        with self.assertRaises(ValueError):
            log.encrypted_prefix_receipt("app", KEY, 0, 2)
        with self.assertRaises(ValueError):
            log.encrypted_prefix_receipt("app", KEY, size=1)

    def test_old_receipt_verifies_after_append_and_prune(self):
        receipt = self.log.encrypted_prefix_receipt("app", KEY)
        self.log.encrypt("appended", KEY, nonce=b"a" * 12)
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))
        self.log.prune(3, self.log.seal(3))
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))

    def test_issue_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt(1, KEY)
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt(bytearray(b"app"), KEY)
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt("app", "not-bytes")
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt("app", b"short")
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt("app", KEY, start=True)
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt("app", KEY, stop="3")
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt("app", KEY, size=True)
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt("app", KEY, size="5")
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt("app", KEY, 3, 2)
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt("app", KEY, -1, 2)
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt("app", KEY, 0, 6)
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt("app", KEY, size=6)
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt("app", KEY, size=-1)


class EncryptedPrefixReceiptClassTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.encrypted_prefix_receipt("app", KEY)

    def test_positional_construction_and_equality(self):
        receipt = EncryptedPrefixReceipt(
            1,
            "sha256",
            self.receipt.size,
            self.receipt.root,
            b"app",
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

    def test_prefix_str_normalized_at_construction(self):
        receipt = rebuild(self.receipt, prefix="app")
        self.assertEqual(receipt.prefix, b"app")
        self.assertEqual(receipt, self.receipt)

    def test_binary_fields_require_exact_bytes(self):
        with self.assertRaises(TypeError):
            rebuild(self.receipt, root=bytearray(self.receipt.root))
        entry = self.receipt.items[0]
        forged = Entry(
            entry.index,
            bytearray(entry.payload),
            entry.previous_hash,
            entry.entry_hash,
        )
        with self.assertRaises(TypeError):
            rebuild(self.receipt, items=(forged,) + self.receipt.items[1:])
        receipt = self.log.encrypted_prefix_receipt("app", KEY, 0, 2)
        self.assertTrue(receipt.proof)
        with self.assertRaises(TypeError):
            rebuild(
                receipt,
                proof=tuple(bytearray(node) for node in receipt.proof),
            )

    def test_coverage_enforced(self):
        items = self.receipt.items
        with self.assertRaises(ValueError):
            rebuild(self.receipt, items=items[:-1])  # incomplete
        with self.assertRaises(ValueError):
            rebuild(self.receipt, items=items + (items[-1],))  # duplicate
        with self.assertRaises(ValueError):
            rebuild(
                self.receipt,
                items=(items[1], items[0]) + items[2:],  # out of order
            )
        moved = Entry(
            9,
            items[0].payload,
            items[0].previous_hash,
            items[0].entry_hash,
        )
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
        receipt = self.log.encrypted_prefix_receipt("app", KEY, 2, 2)
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
            rebuild(self.receipt, prefix=1)
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


class EncryptedPrefixReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.encrypted_prefix_receipt("app", KEY)

    def test_valid_receipt_verifies(self):
        self.assertTrue(verify_encrypted_prefix_receipt(self.receipt, KEY))

    def test_wrong_key_fails_when_hits_are_recorded(self):
        self.assertFalse(
            verify_encrypted_prefix_receipt(self.receipt, OTHER_KEY)
        )
        # A 32-byte key that sealed nothing fails the same way.
        self.assertFalse(
            verify_encrypted_prefix_receipt(self.receipt, THIRD_KEY)
        )

    def test_wrong_key_empty_hit_set_still_passes_authenticity(self):
        receipt = self.log.encrypted_prefix_receipt("missing", KEY)
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))
        # Everything fails to unseal: the recomputed set is empty and the
        # recorded set is empty, so authenticity alone decides.
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, OTHER_KEY))

    def test_empty_prefix_wrong_key_fails_with_real_hits(self):
        log = AuditLog()
        log.encrypt("apple", KEY, nonce=b"0" * 12)
        receipt = log.encrypted_prefix_receipt(b"", KEY)
        self.assertEqual(receipt.hits, (0,))
        self.assertFalse(verify_encrypted_prefix_receipt(receipt, OTHER_KEY))

    def test_forged_hit_returns_false(self):
        self.assertFalse(
            verify_encrypted_prefix_receipt(
                rebuild(self.receipt, hits=(0, 2, 3, 4)), KEY
            )
        )

    def test_concealed_hit_returns_false(self):
        self.assertFalse(
            verify_encrypted_prefix_receipt(
                rebuild(self.receipt, hits=(0, 2)), KEY
            )
        )
        self.assertFalse(
            verify_encrypted_prefix_receipt(rebuild(self.receipt, hits=()), KEY)
        )

    def test_tampered_entry_returns_false(self):
        entry = self.receipt.items[2]
        forged = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        items = self.receipt.items[:2] + (forged,) + self.receipt.items[3:]
        self.assertFalse(
            verify_encrypted_prefix_receipt(
                rebuild(self.receipt, items=items), KEY
            )
        )

    def test_tampered_proof_returns_false(self):
        receipt = self.log.encrypted_prefix_receipt("app", KEY, 0, 2)
        self.assertTrue(receipt.proof)
        tampered = rebuild(receipt, proof=(bytes(32),) + receipt.proof[1:])
        self.assertFalse(verify_encrypted_prefix_receipt(tampered, KEY))

    def test_tampered_root_returns_false(self):
        tampered = rebuild(self.receipt, root=bytes(32))
        self.assertFalse(verify_encrypted_prefix_receipt(tampered, KEY))

    def test_tampered_prefix_changes_the_hit_set(self):
        # Claiming prefix "apple" drops "application" (index 2) and "apply"
        # (index 4); the recorded hits (0, 2, 4) can no longer be reproduced.
        tampered = rebuild(self.receipt, prefix=b"apple")
        self.assertFalse(verify_encrypted_prefix_receipt(tampered, KEY))
        # A wider prefix that every hit actually starts with still matches.
        widened = rebuild(self.receipt, prefix=b"a", hits=(0, 2, 4))
        self.assertTrue(verify_encrypted_prefix_receipt(widened, KEY))

    def test_empty_range_of_nonempty_snapshot_validates_structure_only(self):
        receipt = self.log.encrypted_prefix_receipt("app", KEY, 3, 3)
        self.assertEqual((receipt.items, receipt.proof, receipt.hits), ((), (), ()))
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))
        # No content is carried, so an arbitrary root cannot be contradicted.
        self.assertTrue(
            verify_encrypted_prefix_receipt(
                rebuild(receipt, root=bytes(32)), KEY
            )
        )

    def test_empty_snapshot_requires_canonical_empty_root(self):
        empty = AuditLog()
        receipt = empty.encrypted_prefix_receipt("app", KEY)
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))
        self.assertFalse(
            verify_encrypted_prefix_receipt(
                rebuild(receipt, root=bytes(32)), KEY
            )
        )

    def test_proof_node_count_mismatch_raises_value_error(self):
        receipt = self.log.encrypted_prefix_receipt("app", KEY, 0, 2)
        with self.assertRaises(ValueError):
            verify_encrypted_prefix_receipt(rebuild(receipt, proof=()), KEY)

    def test_verify_argument_errors(self):
        with self.assertRaises(TypeError):
            verify_encrypted_prefix_receipt(None, KEY)
        with self.assertRaises(TypeError):
            verify_encrypted_prefix_receipt("not-a-receipt", KEY)
        with self.assertRaises(TypeError):
            verify_encrypted_prefix_receipt(object(), KEY)
        with self.assertRaises(TypeError):
            verify_encrypted_prefix_receipt(self.receipt, "not-bytes")
        with self.assertRaises(TypeError):
            verify_encrypted_prefix_receipt(self.receipt, None)
        with self.assertRaises(ValueError):
            verify_encrypted_prefix_receipt(self.receipt, b"short")
        with self.assertRaises(ValueError):
            verify_encrypted_prefix_receipt(self.receipt, b"x" * 33)


class EncryptedPrefixReceiptAlternateHashTest(unittest.TestCase):
    def test_sha3_receipt_roundtrip(self):
        log = AuditLog(hash_name="sha3_256")
        log.encrypt("apple", KEY, nonce=NONCE)
        log.encrypt("apricot", OTHER_KEY, nonce=b"1" * 12)
        log.append("apple")
        receipt = log.encrypted_prefix_receipt("app", KEY)
        self.assertEqual(receipt.hits, (0,))
        self.assertEqual(receipt.hash_name, "sha3_256")
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))
        self.assertFalse(verify_encrypted_prefix_receipt(receipt, OTHER_KEY))


if __name__ == "__main__":
    unittest.main()
