import json
import unittest

from auditchain import (
    AuditLog,
    Entry,
    FullEncryptedJsonSearchReceipt,
    decrypt_entry,
    verify_full_encrypted_json_search_receipt,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def make_log():
    log = AuditLog()
    log.encrypt(j({"a": 1, "b": {"c": "x"}}), KEY, nonce=b"0" * 12)  # 0 hit a==1
    log.append(j({"a": 1}))  # 1 plain JSON: never a hit
    log.encrypt(j({"a": 1.0}), KEY, nonce=b"1" * 12)  # 2 hit by numeric equality
    log.encrypt(j({"a": "1"}), KEY, nonce=b"2" * 12)  # 3
    log.encrypt(j({"a": 1}), OTHER_KEY, nonce=b"3" * 12)  # 4 foreign key
    log.encrypt(b"not json", KEY, nonce=b"4" * 12)  # 5
    log.encrypt(j({"a": {"n": 1}}), KEY, nonce=b"5" * 12)  # 6 non-scalar
    log.encrypt(j({"other": 1}), KEY, nonce=b"6" * 12)  # 7 missing field
    return log


def rebuild(receipt, **overrides):
    fields = dict(
        version=receipt.version,
        hash_name=receipt.hash_name,
        size=receipt.size,
        root=receipt.root,
        pointer=receipt.pointer,
        value=receipt.value,
        start=receipt.start,
        stop=receipt.stop,
        items=receipt.items,
        proof=receipt.proof,
        hits=receipt.hits,
        key_check=receipt.key_check,
    )
    fields.update(overrides)
    return FullEncryptedJsonSearchReceipt(**fields)


class FullEncryptedJsonSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_fields_and_full_range_items(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        self.assertIsInstance(receipt, FullEncryptedJsonSearchReceipt)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 8)
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.pointer, "/a")
        self.assertEqual(receipt.value, 1)
        self.assertEqual((receipt.start, receipt.stop), (0, 8))
        # Every entry of the range is listed, one per absolute index.
        self.assertEqual([entry.index for entry in receipt.items], list(range(8)))
        for entry in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
        # The shared proof covers the whole selection at once.
        self.assertEqual(
            receipt.proof,
            self.log.batch_inclusion_proof(tuple(range(8)), 8)[1],
        )
        # The issuer recorded the hits find_encrypted_json would report.
        self.assertEqual(receipt.hits, (0, 2))
        self.assertEqual(receipt.hits, self.log.find_encrypted_json("/a", 1, KEY))
        # The key confirmation is a digest-width blob, not the key.
        self.assertEqual(len(receipt.key_check), 32)
        self.assertNotEqual(receipt.key_check, KEY)

    def test_hits_match_what_the_key_unseals(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        hits = []
        for entry in receipt.items:
            try:
                plaintext = decrypt_entry(entry, KEY)
                document = json.loads(plaintext.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(document, dict) and document.get("a") == 1 and not isinstance(document.get("a"), bool):
                hits.append(entry.index)
        self.assertEqual(tuple(hits), receipt.hits)

    def test_pointer_is_canonicalized(self):
        receipt = self.log.full_encrypted_json_search_receipt("/b/c", "x", KEY)
        self.assertEqual(receipt.pointer, "/b/c")
        escaped = self.log.full_encrypted_json_search_receipt("/b~1c", "x", KEY)
        self.assertEqual(escaped.pointer, "/b~1c")

    def test_explicit_range_and_size(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 1, 5, size=5)
        self.assertEqual((receipt.start, receipt.stop), (1, 5))
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.root, self.log.merkle_root(5))
        self.assertEqual([entry.index for entry in receipt.items], [1, 2, 3, 4])
        self.assertEqual(receipt.hits, (2,))
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))

    def test_no_match_records_no_hits(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 999, KEY)
        self.assertEqual(receipt.hits, ())
        self.assertEqual(len(receipt.items), 8)
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))

    def test_empty_range_and_empty_snapshot(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 3, 3)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))
        empty = AuditLog()
        receipt = empty.full_encrypted_json_search_receipt("/a", 1, KEY)
        self.assertEqual(receipt.size, 0)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))

    def test_pruned_log_defaults_to_retained_segment(self):
        log = make_log()
        receipt = log.seal(2)
        log.prune(2, receipt)
        result = log.full_encrypted_json_search_receipt("/a", 1, KEY)
        self.assertEqual((result.start, result.stop), (2, 8))
        self.assertEqual([entry.index for entry in result.items], [2, 3, 4, 5, 6, 7])
        self.assertEqual(result.hits, (2,))
        self.assertTrue(verify_full_encrypted_json_search_receipt(result, KEY))
        with self.assertRaises(ValueError):
            log.full_encrypted_json_search_receipt("/a", 1, KEY, 0, 2)
        with self.assertRaises(ValueError):
            log.full_encrypted_json_search_receipt("/a", 1, KEY, size=1)

    def test_issuance_is_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.find_encrypted_json("/a", 1, KEY),
        )
        self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        after = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.find_encrypted_json("/a", 1, KEY),
        )
        self.assertEqual(before, after)

    def test_type_errors(self):
        for call in (
            lambda: self.log.full_encrypted_json_search_receipt(1, 1, KEY),
            lambda: self.log.full_encrypted_json_search_receipt("/a", object(), KEY),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, "key"),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, KEY, "0"),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, KEY, True),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 0, True),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, KEY, size=True),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, KEY, size="8"),
        ):
            with self.assertRaises(TypeError, msg=call):
                call()

    def test_value_errors(self):
        for call in (
            lambda: self.log.full_encrypted_json_search_receipt("a", 1, KEY),
            lambda: self.log.full_encrypted_json_search_receipt("/a", float("nan"), KEY),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, b"short"),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, KEY, -1),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 2, 1),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 0, 9),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, KEY, size=9),
            lambda: self.log.full_encrypted_json_search_receipt("/a", 1, KEY, size=-1),
        ):
            with self.assertRaises(ValueError, msg=call):
                call()


class FullEncryptedJsonSearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)

    def test_valid_receipt_verifies(self):
        self.assertTrue(verify_full_encrypted_json_search_receipt(self.receipt, KEY))

    def test_wrong_key_fails_even_with_hits(self):
        self.assertFalse(verify_full_encrypted_json_search_receipt(self.receipt, OTHER_KEY))

    def test_wrong_key_fails_with_empty_hits(self):
        # A zero-hit receipt still binds the key via key_check.
        receipt = self.log.full_encrypted_json_search_receipt("/a", 999, KEY)
        self.assertEqual(receipt.hits, ())
        self.assertFalse(verify_full_encrypted_json_search_receipt(receipt, OTHER_KEY))

    def test_wrong_key_fails_on_empty_snapshot(self):
        receipt = AuditLog().full_encrypted_json_search_receipt("/a", 1, KEY)
        self.assertFalse(verify_full_encrypted_json_search_receipt(receipt, OTHER_KEY))

    def test_tampered_pointer_value_or_range_fails(self):
        for overrides in (
            {"pointer": "/b"},
            {"pointer": ""},
            {"value": 2},
            {"value": "1"},
            {"value": True},
        ):
            receipt = rebuild(self.receipt, **overrides)
            self.assertFalse(
                verify_full_encrypted_json_search_receipt(receipt, KEY), overrides
            )

    def test_tampered_hits_fail(self):
        for hits in ((), (0,), (2,), (0, 2, 3), (0, 3)):
            receipt = rebuild(self.receipt, hits=hits)
            self.assertFalse(
                verify_full_encrypted_json_search_receipt(receipt, KEY), hits
            )

    def test_tampered_key_check_fails(self):
        other = self.log.full_encrypted_json_search_receipt("/a", 2, KEY)
        receipt = rebuild(self.receipt, key_check=other.key_check)
        self.assertFalse(verify_full_encrypted_json_search_receipt(receipt, KEY))
        receipt = rebuild(self.receipt, key_check=bytes(32))
        self.assertFalse(verify_full_encrypted_json_search_receipt(receipt, KEY))

    def test_tampered_entries_fail(self):
        # A forged ciphertext inside a listed item breaks authentication.
        entry = self.receipt.items[0]
        forged = Entry(entry.index, entry.payload + b"x", entry.previous_hash, entry.entry_hash)
        items = (forged,) + self.receipt.items[1:]
        receipt = rebuild(self.receipt, items=items)
        self.assertFalse(verify_full_encrypted_json_search_receipt(receipt, KEY))
        # A swapped entry hash breaks the digest check.
        other = self.receipt.items[1]
        swapped = Entry(entry.index, entry.payload, entry.previous_hash, other.entry_hash)
        receipt = rebuild(self.receipt, items=(swapped,) + self.receipt.items[1:])
        self.assertFalse(verify_full_encrypted_json_search_receipt(receipt, KEY))

    def test_tampered_proof_root_or_size_fails(self):
        # A sub-range receipt carries a non-empty shared proof.
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 0, 5)
        self.assertTrue(receipt.proof)
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))
        # Flip one bit of a proof node, keeping the node count intact.
        node = receipt.proof[0]
        forged_node = bytes([node[0] ^ 1]) + node[1:]
        tampered = rebuild(receipt, proof=(forged_node,) + receipt.proof[1:])
        self.assertFalse(verify_full_encrypted_json_search_receipt(tampered, KEY))
        # A root that is not the snapshot's Merkle root.
        other = self.log.full_encrypted_json_search_receipt("/a", 1, KEY, 1, 5, size=5)
        receipt = rebuild(self.receipt, root=other.root)
        self.assertFalse(verify_full_encrypted_json_search_receipt(receipt, KEY))
        # A size that still covers the recorded range but is not the
        # snapshot the key confirmation and proof were built for.
        receipt = rebuild(self.receipt, size=self.receipt.size + 1)
        self.assertFalse(verify_full_encrypted_json_search_receipt(receipt, KEY))

    def test_dropped_item_breaks_coverage(self):
        with self.assertRaises(ValueError):
            rebuild(self.receipt, items=self.receipt.items[1:])

    def test_verify_type_and_key_errors(self):
        with self.assertRaises(TypeError):
            verify_full_encrypted_json_search_receipt("not a receipt", KEY)
        with self.assertRaises(TypeError):
            verify_full_encrypted_json_search_receipt(self.receipt, "key")
        with self.assertRaises(ValueError):
            verify_full_encrypted_json_search_receipt(self.receipt, b"short")

    def test_receipt_is_immutable_and_compares_by_fields(self):
        same = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        self.assertEqual(self.receipt, same)
        self.assertNotEqual(self.receipt, rebuild(self.receipt, hits=()))
        with self.assertRaises(AttributeError):
            self.receipt.hits = ()

    def test_constructor_validation(self):
        base = self.receipt
        for overrides, error in (
            ({"version": 2}, ValueError),
            ({"version": "1"}, TypeError),
            ({"hash_name": 1}, TypeError),
            ({"hash_name": "nope"}, ValueError),
            ({"size": -1}, ValueError),
            ({"size": True}, TypeError),
            ({"root": b"short"}, ValueError),
            ({"root": bytearray(32)}, TypeError),
            ({"pointer": 1}, TypeError),
            ({"pointer": "a"}, ValueError),
            ({"value": float("inf")}, ValueError),
            ({"value": object()}, TypeError),
            ({"start": -1}, ValueError),
            ({"stop": base.size + 1}, ValueError),
            ({"items": list(base.items)}, TypeError),
            ({"items": base.items[1:]}, ValueError),
            ({"proof": list(base.proof)}, TypeError),
            ({"hits": (2, 0)}, ValueError),
            ({"hits": (0, 8)}, ValueError),
            ({"hits": (0, True)}, TypeError),
            ({"hits": [0, 2]}, TypeError),
            ({"key_check": b"short"}, ValueError),
            ({"key_check": bytearray(32)}, TypeError),
        ):
            with self.assertRaises(error, msg=overrides):
                rebuild(base, **overrides)


if __name__ == "__main__":
    unittest.main()
