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


def make_log(records=(("enc", "alpha"), ("plain", "alpine"), ("enc", "alps"),
                      ("enc", "beta"), ("enc", "al")), **kwargs):
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


class FindEncryptedPrefixTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_basic_hits(self):
        self.assertEqual(self.log.find_encrypted_prefix(b"al", KEY), (0, 2, 4))
        self.assertEqual(self.log.find_encrypted_prefix(b"alp", KEY), (0, 2))
        self.assertEqual(self.log.find_encrypted_prefix(b"beta", KEY), (3,))
        self.assertEqual(self.log.find_encrypted_prefix(b"gamma", KEY), ())

    def test_str_prefix_is_utf8_encoded(self):
        self.assertEqual(self.log.find_encrypted_prefix("al", KEY), (0, 2, 4))
        log = AuditLog()
        log.encrypt("héllo", KEY, nonce=b"\x00" * 12)
        self.assertEqual(log.find_encrypted_prefix("hél", KEY), (0,))
        self.assertEqual(
            log.find_encrypted_prefix("hél".encode("utf-8"), KEY), (0,)
        )

    def test_empty_prefix_hits_every_decryptable_entry(self):
        log = AuditLog()
        log.encrypt(b"", KEY, nonce=b"\x00" * 12)
        log.encrypt(b"x", KEY, nonce=b"\x01" * 12)
        log.append(b"")
        self.assertEqual(log.find_encrypted_prefix(b"", KEY), (0, 1))

    def test_plain_and_foreign_key_entries_never_hit(self):
        log = make_log()
        # Index 1 is a plain entry whose payload starts with b"al".
        self.assertNotIn(1, log.find_encrypted_prefix(b"al", KEY))
        # A valid but wrong key unseals nothing and does not raise.
        self.assertEqual(log.find_encrypted_prefix(b"", OTHER_KEY), ())

    def test_range_defaults_and_bounds(self):
        self.assertEqual(self.log.find_encrypted_prefix(b"al", KEY, 1, 4), (2,))
        self.assertEqual(self.log.find_encrypted_prefix(b"al", KEY, 2), (2, 4))
        self.assertEqual(self.log.find_encrypted_prefix(b"al", KEY, None, 1), (0,))
        with self.assertRaises(ValueError):
            self.log.find_encrypted_prefix(b"al", KEY, 3, 2)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_prefix(b"al", KEY, -1, 2)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_prefix(b"al", KEY, 0, 6)
        with self.assertRaises(TypeError):
            self.log.find_encrypted_prefix(b"al", KEY, True)
        with self.assertRaises(TypeError):
            self.log.find_encrypted_prefix(b"al", KEY, 0, "5")

    def test_type_and_key_errors(self):
        with self.assertRaises(TypeError):
            self.log.find_encrypted_prefix(1, KEY)
        with self.assertRaises(TypeError):
            self.log.find_encrypted_prefix(bytearray(b"al"), KEY)
        with self.assertRaises(TypeError):
            self.log.find_encrypted_prefix(b"al", "not-bytes")
        with self.assertRaises(ValueError):
            self.log.find_encrypted_prefix(b"al", b"short")

    def test_pruned_log_covers_retained_segment(self):
        log = make_log()
        receipt = log.seal(2)
        log.prune(2, receipt)
        self.assertEqual(log.find_encrypted_prefix(b"al", KEY), (2, 4))
        with self.assertRaises(ValueError):
            log.find_encrypted_prefix(b"al", KEY, 0, 3)

    def test_read_only(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        self.log.find_encrypted_prefix(b"al", KEY)
        after = (len(self.log), self.log.head, self.log.merkle_root())
        self.assertEqual(before, after)


class EncryptedPrefixReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_fields_and_full_range_items(self):
        receipt = self.log.encrypted_prefix_receipt(b"al", KEY)
        self.assertIsInstance(receipt, EncryptedPrefixReceipt)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.prefix, b"al")
        self.assertEqual((receipt.start, receipt.stop), (0, 5))
        self.assertEqual([entry.index for entry in receipt.items], [0, 1, 2, 3, 4])
        for entry in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
        self.assertEqual(
            receipt.proof,
            self.log.batch_inclusion_proof((0, 1, 2, 3, 4), 5)[1],
        )
        self.assertEqual(receipt.hits, (0, 2, 4))
        self.assertEqual(receipt.hits, self.log.find_encrypted_prefix(b"al", KEY))

    def test_str_prefix_normalized(self):
        receipt = self.log.encrypted_prefix_receipt("al", KEY)
        self.assertEqual(receipt.prefix, b"al")
        self.assertEqual(receipt.hits, (0, 2, 4))

    def test_empty_prefix(self):
        receipt = self.log.encrypted_prefix_receipt(b"", KEY)
        self.assertEqual(receipt.hits, (0, 2, 3, 4))
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))

    def test_explicit_range_and_size(self):
        receipt = self.log.encrypted_prefix_receipt(b"al", KEY, 1, 4, size=4)
        self.assertEqual((receipt.start, receipt.stop, receipt.size), (1, 4, 4))
        self.assertEqual([entry.index for entry in receipt.items], [1, 2, 3])
        self.assertEqual(receipt.hits, (2,))
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))

    def test_empty_range(self):
        receipt = self.log.encrypted_prefix_receipt(b"al", KEY, 2, 2)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))

    def test_empty_snapshot(self):
        log = AuditLog()
        receipt = log.encrypted_prefix_receipt(b"al", KEY)
        self.assertEqual(receipt.size, 0)
        self.assertEqual((receipt.items, receipt.proof, receipt.hits), ((), (), ()))
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))

    def test_receipt_records_no_key_or_plaintext(self):
        receipt = self.log.encrypted_prefix_receipt(b"al", KEY)
        for entry in receipt.items:
            if entry.index == 1:
                continue
            self.assertNotEqual(entry.payload, b"alpha")
        # Sealed payloads stay sealed; the key appears nowhere.
        for field in (receipt.root, receipt.prefix) + tuple(receipt.proof):
            self.assertNotIn(KEY, field)

    def test_pruned_log_defaults_to_retained_segment(self):
        log = make_log()
        receipt = log.seal(2)
        log.prune(2, receipt)
        result = log.encrypted_prefix_receipt(b"al", KEY)
        self.assertEqual((result.start, result.stop), (2, 5))
        self.assertEqual([entry.index for entry in result.items], [2, 3, 4])
        self.assertEqual(result.hits, (2, 4))
        self.assertTrue(verify_encrypted_prefix_receipt(result, KEY))
        with self.assertRaises(ValueError):
            log.encrypted_prefix_receipt(b"al", KEY, 0, 2)
        with self.assertRaises(ValueError):
            log.encrypted_prefix_receipt(b"al", KEY, size=1)

    def test_issue_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt(1, KEY)
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt(bytearray(b"al"), KEY)
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt(b"al", "not-bytes")
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt(b"al", b"short")
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt(b"al", KEY, start=True)
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt(b"al", KEY, stop="3")
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt(b"al", KEY, size=True)
        with self.assertRaises(TypeError):
            self.log.encrypted_prefix_receipt(b"al", KEY, size="5")
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt(b"al", KEY, 3, 2)
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt(b"al", KEY, -1, 2)
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt(b"al", KEY, 0, 6)
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt(b"al", KEY, size=6)
        with self.assertRaises(ValueError):
            self.log.encrypted_prefix_receipt(b"al", KEY, size=-1)

    def test_issue_is_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.find_encrypted_prefix(b"al", KEY),
        )
        self.log.encrypted_prefix_receipt(b"al", KEY)
        after = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.find_encrypted_prefix(b"al", KEY),
        )
        self.assertEqual(before, after)


class EncryptedPrefixReceiptClassTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.encrypted_prefix_receipt(b"al", KEY)

    def test_frozen_and_equality(self):
        with self.assertRaises(AttributeError):
            self.receipt.prefix = b"xx"
        self.assertEqual(self.receipt, rebuild(self.receipt))
        self.assertNotEqual(self.receipt, rebuild(self.receipt, prefix=b"xx"))

    def test_positional_construction(self):
        other = EncryptedPrefixReceipt(
            1,
            "sha256",
            self.receipt.size,
            self.receipt.root,
            b"al",
            0,
            5,
            self.receipt.items,
            self.receipt.proof,
            self.receipt.hits,
        )
        self.assertEqual(self.receipt, other)

    def test_field_type_errors(self):
        with self.assertRaises(TypeError):
            rebuild(self.receipt, version="1")
        with self.assertRaises(TypeError):
            rebuild(self.receipt, version=True)
        with self.assertRaises(ValueError):
            rebuild(self.receipt, version=2)
        with self.assertRaises(TypeError):
            rebuild(self.receipt, hash_name=1)
        with self.assertRaises(ValueError):
            rebuild(self.receipt, hash_name="nope")
        with self.assertRaises(TypeError):
            rebuild(self.receipt, size="5")
        with self.assertRaises(ValueError):
            rebuild(self.receipt, size=-1)
        with self.assertRaises(TypeError):
            rebuild(self.receipt, root=bytearray(self.receipt.root))
        with self.assertRaises(ValueError):
            rebuild(self.receipt, root=b"short")
        with self.assertRaises(TypeError):
            rebuild(self.receipt, prefix=1)
        with self.assertRaises(TypeError):
            rebuild(self.receipt, start=True)
        with self.assertRaises(TypeError):
            rebuild(self.receipt, stop="5")
        with self.assertRaises(ValueError):
            rebuild(self.receipt, start=3, stop=2)
        with self.assertRaises(ValueError):
            rebuild(self.receipt, stop=6)
        with self.assertRaises(TypeError):
            rebuild(self.receipt, items=list(self.receipt.items))
        with self.assertRaises(TypeError):
            rebuild(self.receipt, proof=list(self.receipt.proof))
        with self.assertRaises(TypeError):
            rebuild(self.receipt, hits=list(self.receipt.hits))
        with self.assertRaises(TypeError):
            rebuild(self.receipt, hits=(True,))

    def test_item_validation(self):
        entries = self.receipt.items
        with self.assertRaises(TypeError):
            rebuild(self.receipt, items=("x",) * 5)
        # Duplicate index.
        with self.assertRaises(ValueError):
            rebuild(
                self.receipt,
                items=(entries[0], entries[0]) + entries[2:],
            )
        # Out-of-order indices.
        with self.assertRaises(ValueError):
            rebuild(
                self.receipt,
                items=(entries[1], entries[0]) + entries[2:],
            )
        # Incomplete coverage.
        with self.assertRaises(ValueError):
            rebuild(self.receipt, items=entries[:4])
        # Entry outside the range.
        log = make_log()
        wider = log.encrypted_prefix_receipt(b"al", KEY)
        foreign = Entry(9, b"p", bytes(32), bytes(32))
        with self.assertRaises(ValueError):
            rebuild(wider, items=wider.items + (foreign,), stop=6, size=9)
        # Wrong digest widths.
        bad_prev = Entry(0, b"p", bytes(31), bytes(32))
        with self.assertRaises(ValueError):
            rebuild(self.receipt, items=(bad_prev,) + entries[1:])
        bad_hash = Entry(0, b"p", bytes(32), bytes(31))
        with self.assertRaises(ValueError):
            rebuild(self.receipt, items=(bad_hash,) + entries[1:])
        with self.assertRaises(TypeError):
            rebuild(
                self.receipt,
                items=(Entry(0, bytearray(b"p"), bytes(32), bytes(32)),)
                + entries[1:],
            )

    def test_proof_and_hit_validation(self):
        with self.assertRaises(TypeError):
            rebuild(self.receipt, proof=("not-bytes",))
        with self.assertRaises(ValueError):
            rebuild(self.receipt, proof=(b"\x00" * 31,))
        # Empty range must carry an empty proof.
        empty = self.log.encrypted_prefix_receipt(b"al", KEY, 2, 2)
        with self.assertRaises(ValueError):
            rebuild(empty, proof=(bytes(32),))
        # Hits must be ascending, in range, non-bool.
        with self.assertRaises(ValueError):
            rebuild(self.receipt, hits=(2, 0, 4))
        with self.assertRaises(ValueError):
            rebuild(self.receipt, hits=(0, 0, 4))
        with self.assertRaises(ValueError):
            rebuild(self.receipt, hits=(0, 2, 5))
        with self.assertRaises(ValueError):
            rebuild(self.receipt, hits=(-1, 0, 2))


class VerifyEncryptedPrefixReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.encrypted_prefix_receipt(b"al", KEY)

    def test_genuine_receipt_verifies(self):
        self.assertTrue(verify_encrypted_prefix_receipt(self.receipt, KEY))

    def test_hits_recomputed_from_sealed_entries(self):
        hits = []
        for entry in self.receipt.items:
            try:
                plaintext = decrypt_entry(entry, KEY)
            except ValueError:
                continue
            if plaintext.startswith(self.receipt.prefix):
                hits.append(entry.index)
        self.assertEqual(tuple(hits), self.receipt.hits)

    def test_tampered_content_proof_root_or_hits_fail(self):
        entries = self.receipt.items
        tampered_entry = Entry(0, b"evil", entries[0].previous_hash, entries[0].entry_hash)
        self.assertFalse(
            verify_encrypted_prefix_receipt(
                rebuild(self.receipt, items=(tampered_entry,) + entries[1:]), KEY
            )
        )
        # A sub-range receipt carries a non-empty shared proof; corrupting a
        # node keeps the count but breaks the rebuilt root.
        ranged = self.log.encrypted_prefix_receipt(b"al", KEY, 1, 4)
        self.assertTrue(ranged.proof)
        bad_proof = (bytes(32),) + ranged.proof[1:]
        self.assertFalse(
            verify_encrypted_prefix_receipt(
                rebuild(ranged, proof=bad_proof), KEY
            )
        )
        other_root = make_log((("enc", "alpha"),)).encrypted_prefix_receipt(b"al", KEY)
        self.assertFalse(
            verify_encrypted_prefix_receipt(
                rebuild(self.receipt, root=bytes(32)), KEY
            )
        )
        self.assertFalse(
            verify_encrypted_prefix_receipt(
                rebuild(self.receipt, hits=(0, 2)), KEY
            )
        )
        self.assertFalse(
            verify_encrypted_prefix_receipt(
                rebuild(self.receipt, hits=(0, 2, 3, 4)), KEY
            )
        )

    def test_wrong_key(self):
        # Recorded hits cannot be reproduced under a wrong key.
        self.assertFalse(verify_encrypted_prefix_receipt(self.receipt, OTHER_KEY))
        # A zero-hit receipt stays genuine: recomputed and recorded sets are
        # both empty, so authenticity alone decides.
        empty_hits = self.log.encrypted_prefix_receipt(b"gamma", KEY)
        self.assertEqual(empty_hits.hits, ())
        self.assertTrue(verify_encrypted_prefix_receipt(empty_hits, OTHER_KEY))

    def test_empty_range_of_non_empty_snapshot(self):
        receipt = self.log.encrypted_prefix_receipt(b"al", KEY, 3, 3)
        self.assertEqual((receipt.items, receipt.proof, receipt.hits), ((), (), ()))
        # Structure only: any digest-width root is accepted.
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))
        self.assertTrue(
            verify_encrypted_prefix_receipt(rebuild(receipt, root=bytes(32)), KEY)
        )

    def test_empty_snapshot_requires_canonical_empty_root(self):
        log = AuditLog()
        receipt = log.encrypted_prefix_receipt(b"al", KEY)
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))
        self.assertFalse(
            verify_encrypted_prefix_receipt(rebuild(receipt, root=bytes(32)), KEY)
        )

    def test_verify_argument_errors(self):
        with self.assertRaises(TypeError):
            verify_encrypted_prefix_receipt("not a receipt", KEY)
        with self.assertRaises(TypeError):
            verify_encrypted_prefix_receipt(self.receipt, "not-bytes")
        with self.assertRaises(ValueError):
            verify_encrypted_prefix_receipt(self.receipt, b"short")

    def test_verify_revalidates_bypassed_fields(self):
        object.__setattr__(self.receipt, "hits", (True,))
        with self.assertRaises(TypeError):
            verify_encrypted_prefix_receipt(self.receipt, KEY)
        receipt = self.log.encrypted_prefix_receipt(b"al", KEY)
        object.__setattr__(receipt, "hash_name", "nope")
        with self.assertRaises(ValueError):
            verify_encrypted_prefix_receipt(receipt, KEY)

    def test_bad_proof_node_count_raises(self):
        receipt = rebuild(self.receipt, proof=self.receipt.proof + (bytes(32),))
        with self.assertRaises(ValueError):
            verify_encrypted_prefix_receipt(receipt, KEY)

    def test_offline_verification_survives_append_and_prune(self):
        receipt = self.log.encrypted_prefix_receipt(b"al", KEY)
        self.log.encrypt("alumni", KEY, nonce=b"\x09" * 12)
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))
        sealed = self.log.seal(2)
        self.log.prune(2, sealed)
        self.assertTrue(verify_encrypted_prefix_receipt(receipt, KEY))


if __name__ == "__main__":
    unittest.main()
