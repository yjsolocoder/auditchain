import dataclasses
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
THIRD_KEY = bytes(reversed(range(32)))
NONCE = b"nonce-12byte"


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def make_log():
    log = AuditLog()
    # 0: match for /a == 1
    log.encrypt(j({"a": 1, "b": "x"}), KEY, nonce=b"0" * 12)
    # 1: float numerically equal
    log.encrypt(j({"a": 1.0, "b": "y"}), KEY, nonce=b"1" * 12)
    # 2: string "1"
    log.encrypt(j({"a": "1"}), KEY, nonce=b"2" * 12)
    # 3: boolean
    log.encrypt(j({"a": True}), KEY, nonce=b"3" * 12)
    # 4: non-scalar target
    log.encrypt(j({"a": [1]}), KEY, nonce=b"4" * 12)
    # 5: plain JSON entry
    log.append(j({"a": 1}))
    # 6: same value under another key
    log.encrypt(j({"a": 1}), OTHER_KEY, nonce=b"6" * 12)
    # 7: malformed JSON under KEY
    log.encrypt(b"{not json", KEY, nonce=b"7" * 12)
    # 8: repeated member name
    log.encrypt(b'{"a": 1, "a": 2}', KEY, nonce=b"8" * 12)
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
        confirmation=receipt.confirmation,
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
        self.assertEqual(receipt.size, 9)
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.pointer, "/a")
        self.assertEqual(receipt.value, 1)
        self.assertEqual((receipt.start, receipt.stop), (0, 9))
        self.assertEqual([entry.index for entry in receipt.items], list(range(9)))
        for entry in receipt.items:
            self.assertEqual(entry, self.log.entry(entry.index))
        self.assertEqual(
            receipt.proof,
            self.log.batch_inclusion_proof(tuple(range(9)), 9)[1],
        )
        self.assertEqual(receipt.hits, (0, 1))
        self.assertEqual(receipt.hits, self.log.find_encrypted_json("/a", 1, KEY))
        self.assertEqual(len(receipt.confirmation), 32)
        # Neither the key nor plaintext is embedded.
        encoded = dataclasses.astuple(receipt)
        self.assertNotIn(KEY, encoded)

    def test_pointer_is_canonicalized(self):
        receipt = self.log.full_encrypted_json_search_receipt("/~01/a", 1, KEY)
        # Tokens ("~1", "a") re-spell to the same canonical RFC 6901 form.
        self.assertEqual(receipt.pointer, "/~01/a")
        receipt = self.log.full_encrypted_json_search_receipt("/a~1b/c~0d", 7, KEY)
        self.assertEqual(receipt.pointer, "/a~1b/c~0d")

    def test_hits_match_what_the_key_unseals(self):
        def reject_duplicates(pairs):
            document = {}
            for key, member in pairs:
                if key in document:
                    raise ValueError(f"duplicate member {key!r}")
                document[key] = member
            return document

        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        hits = []
        for entry in receipt.items:
            try:
                plaintext = decrypt_entry(entry, KEY)
                document = json.loads(
                    plaintext, object_pairs_hook=reject_duplicates
                )
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(document, dict):
                value = document.get("a")
                if (
                    not isinstance(value, bool)
                    and isinstance(value, (int, float))
                    and value == 1
                ):
                    hits.append(entry.index)
        self.assertEqual(tuple(hits), receipt.hits)

    def test_plain_and_foreign_key_entries_never_hit(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        self.assertEqual(receipt.hits, (0, 1))
        other = self.log.full_encrypted_json_search_receipt("/a", 1, OTHER_KEY)
        self.assertEqual(other.hits, (6,))

    def test_json_kinds_are_separated(self):
        self.assertEqual(
            self.log.full_encrypted_json_search_receipt("/a", "1", KEY).hits,
            (2,),
        )
        self.assertEqual(
            self.log.full_encrypted_json_search_receipt("/a", True, KEY).hits,
            (3,),
        )

    def test_empty_result_is_never_forged_with_a_wrong_legal_key(self):
        # THIRD_KEY unseals nothing in this log.
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, THIRD_KEY)
        self.assertEqual(receipt.hits, ())
        self.assertTrue(
            verify_full_encrypted_json_search_receipt(receipt, THIRD_KEY)
        )
        # The honest empty-result receipt fails under any other legal key.
        self.assertFalse(
            verify_full_encrypted_json_search_receipt(receipt, KEY)
        )

    def test_explicit_range_and_size(self):
        receipt = self.log.full_encrypted_json_search_receipt(
            "/a", 1, KEY, 1, 7, size=7
        )
        self.assertEqual((receipt.start, receipt.stop), (1, 7))
        self.assertEqual(receipt.size, 7)
        self.assertEqual(receipt.root, self.log.merkle_root(7))
        self.assertEqual([entry.index for entry in receipt.items], [1, 2, 3, 4, 5, 6])
        self.assertEqual(receipt.hits, (1,))
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))

    def test_range_starting_after_zero(self):
        receipt = self.log.full_encrypted_json_search_receipt(
            "/a", 1, KEY, 3, 9, size=9
        )
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))

    def test_empty_range(self):
        receipt = self.log.full_encrypted_json_search_receipt(
            "/a", 1, KEY, 4, 4, size=9
        )
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))

    def test_empty_snapshot_matches_only_canonical_root(self):
        receipt = AuditLog().full_encrypted_json_search_receipt("/a", 1, KEY)
        from auditchain import _hash_parts, _EMPTY_DOMAIN

        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))
        self.assertEqual(
            receipt.root, _hash_parts("sha256", _EMPTY_DOMAIN)
        )
        forged = rebuild(receipt, root=b"\x00" * 32)
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        log.encrypt(j({"a": 1}), KEY, nonce=NONCE)
        receipt = log.full_encrypted_json_search_receipt("/a", 1, KEY)
        self.assertEqual(len(receipt.confirmation), 32)
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))
        self.assertFalse(
            verify_full_encrypted_json_search_receipt(receipt, OTHER_KEY)
        )

    def test_frozen_and_field_equality(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            receipt.hits = ()  # type: ignore[misc]
        self.assertEqual(
            receipt,
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY),
        )
        self.assertNotEqual(
            receipt,
            self.log.full_encrypted_json_search_receipt("/a", 2, KEY),
        )


class FullEncryptedJsonSearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)

    def test_verifies_with_the_issuing_key(self):
        self.assertTrue(
            verify_full_encrypted_json_search_receipt(self.receipt, KEY)
        )

    def test_wrong_legal_key_fails(self):
        self.assertFalse(
            verify_full_encrypted_json_search_receipt(self.receipt, OTHER_KEY)
        )
        self.assertFalse(
            verify_full_encrypted_json_search_receipt(self.receipt, THIRD_KEY)
        )

    def test_key_type_and_length(self):
        with self.assertRaises(TypeError):
            verify_full_encrypted_json_search_receipt(self.receipt, "k" * 32)
        with self.assertRaises(ValueError):
            verify_full_encrypted_json_search_receipt(self.receipt, b"short")

    def test_receipt_type_required(self):
        for bad in (None, 1, "r", (), object()):
            with self.assertRaises(TypeError):
                verify_full_encrypted_json_search_receipt(bad, KEY)

    def test_tampered_hits_fail(self):
        forged = rebuild(self.receipt, hits=())
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))
        forged = rebuild(self.receipt, hits=(0,))
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))
        forged = rebuild(self.receipt, hits=(0, 1, 2))
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_tampered_confirmation_fails(self):
        forged = rebuild(
            self.receipt,
            confirmation=b"\x00" * len(self.receipt.confirmation),
        )
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_tampered_pointer_fails(self):
        forged = rebuild(self.receipt, pointer="/b")
        # Constructor-valid receipt: confirmation no longer matches.
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_tampered_query_value_fails(self):
        forged = rebuild(self.receipt, value=2)
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))
        forged = rebuild(self.receipt, value="1")
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_tampered_range_fails(self):
        # Build a structurally coherent [1, 9) receipt with the genuine
        # subrange proof and recomputed hits, but keep the original [0, 9)
        # confirmation: the confirmation binds the range, so it fails.
        sub_items = self.receipt.items[1:]
        _, sub_proof = self.log.batch_inclusion_proof(tuple(range(1, 9)), 9)
        forged = rebuild(
            self.receipt,
            start=1,
            items=sub_items,
            proof=sub_proof,
            hits=(1,),
        )
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))
        # An incoherently cut proof raises exactly as
        # verify_batch_inclusion does for the other full-range receipts.
        incoherent = rebuild(
            self.receipt,
            start=1,
            items=sub_items,
            hits=(),
        )
        with self.assertRaises(ValueError):
            verify_full_encrypted_json_search_receipt(incoherent, KEY)

    def test_tampered_size_or_root_fails(self):
        forged = rebuild(self.receipt, root=b"\x00" * 32)
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_tampered_ciphertext_fails(self):
        entry = self.receipt.items[0]
        raw = entry.payload[:-1] + bytes([entry.payload[-1] ^ 0x01])
        tampered_entry = Entry(
            entry.index, raw, entry.previous_hash, entry.entry_hash
        )
        forged = rebuild(
            self.receipt,
            items=(tampered_entry,) + self.receipt.items[1:],
            hits=(),
        )
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_tampered_entry_hash_fails(self):
        entry = self.receipt.items[0]
        tampered_entry = Entry(
            entry.index,
            entry.payload,
            entry.previous_hash,
            b"\x00" * len(entry.entry_hash),
        )
        forged = rebuild(
            self.receipt,
            items=(tampered_entry,) + self.receipt.items[1:],
        )
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_tampered_previous_hash_fails(self):
        entry = self.receipt.items[1]
        tampered_entry = Entry(
            entry.index,
            entry.payload,
            b"\x00" * len(entry.previous_hash),
            entry.entry_hash,
        )
        forged = rebuild(
            self.receipt,
            items=self.receipt.items[:1] + (tampered_entry,) + self.receipt.items[2:],
        )
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_chain_must_start_at_genesis_when_range_covers_zero(self):
        from auditchain import entry_digest

        entry = self.receipt.items[0]
        fake_previous = b"\x01" * 32
        fake_hash = entry_digest(
            entry.index,
            fake_previous,
            entry.payload,
            hash_name=self.receipt.hash_name,
        )
        tampered_entry = Entry(
            entry.index, entry.payload, fake_previous, fake_hash
        )
        forged = rebuild(
            self.receipt,
            items=(tampered_entry,) + self.receipt.items[1:],
        )
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_tampered_proof_fails(self):
        receipt = self.log.full_encrypted_json_search_receipt(
            "/a", 1, KEY, 1, 8, size=9
        )
        self.assertTrue(receipt.proof)
        proof = receipt.proof
        flipped = proof[0][:-1] + bytes([proof[0][-1] ^ 0x01])
        forged = rebuild(receipt, proof=(flipped,) + proof[1:])
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_tampered_hit_payload_changes_field_match(self):
        # Replace a hit's envelope with another authentic envelope under the
        # same key carrying a different document; the root must fail.
        other = make_log()
        source = other.entry(2)  # {"a": "1"}
        entry = self.receipt.items[0]
        tampered_entry = Entry(
            entry.index,
            source.payload,
            entry.previous_hash,
            entry.entry_hash,
        )
        forged = rebuild(
            self.receipt,
            items=(tampered_entry,) + self.receipt.items[1:],
        )
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))

    def test_replayed_items_with_foreign_key_confirmation_fail(self):
        # A valid receipt under OTHER_KEY must not validate the KEY receipt
        # even though both list overlapping entries.
        other = self.log.full_encrypted_json_search_receipt("/a", 1, OTHER_KEY)
        # other.hits == (6,); swapping only the confirmation can't work.
        forged = rebuild(self.receipt, confirmation=other.confirmation)
        self.assertFalse(verify_full_encrypted_json_search_receipt(forged, KEY))
        self.assertFalse(
            verify_full_encrypted_json_search_receipt(forged, OTHER_KEY)
        )


class FullEncryptedJsonSearchReceiptValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def issue(self, *args, **kwargs):
        return self.log.full_encrypted_json_search_receipt(*args, **kwargs)

    def test_pointer_errors(self):
        with self.assertRaises(TypeError):
            self.issue(1, 1, KEY)
        with self.assertRaises(ValueError):
            self.issue("a", 1, KEY)

    def test_value_errors(self):
        with self.assertRaises(TypeError):
            self.issue("/a", [1], KEY)
        with self.assertRaises(ValueError):
            self.issue("/a", float("inf"), KEY)

    def test_key_errors(self):
        with self.assertRaises(TypeError):
            self.issue("/a", 1, "k" * 32)
        with self.assertRaises(ValueError):
            self.issue("/a", 1, b"short")

    def test_range_and_size_errors(self):
        with self.assertRaises(TypeError):
            self.issue("/a", 1, KEY, "0")
        with self.assertRaises(TypeError):
            self.issue("/a", 1, KEY, 0, "9")
        with self.assertRaises(TypeError):
            self.issue("/a", 1, KEY, size=True)
        with self.assertRaises(ValueError):
            self.issue("/a", 1, KEY, -1)
        with self.assertRaises(ValueError):
            self.issue("/a", 1, KEY, 0, 10)
        with self.assertRaises(ValueError):
            self.issue("/a", 1, KEY, 3, 2)
        with self.assertRaises(ValueError):
            self.issue("/a", 1, KEY, size=100)

    def test_pruned_snapshot_size_below_retain_point(self):
        self.log.prune(3, self.log.seal(3))
        with self.assertRaises(ValueError):
            self.issue("/a", 1, KEY, size=2)
        with self.assertRaises(ValueError):
            self.issue("/a", 1, KEY, 0, 4, size=4)
        # The retained segment still issues a verifiable receipt.
        receipt = self.issue("/a", 1, KEY)
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))


class FullEncryptedJsonSearchReceiptConstructorTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)

    def test_bypassed_fields_are_revalidated(self):
        def bypassed(**fields):
            forged = FullEncryptedJsonSearchReceipt.__new__(
                FullEncryptedJsonSearchReceipt
            )
            base = (
                self.receipt.version,
                self.receipt.hash_name,
                self.receipt.size,
                self.receipt.root,
                self.receipt.pointer,
                self.receipt.value,
                self.receipt.start,
                self.receipt.stop,
                self.receipt.items,
                self.receipt.proof,
                self.receipt.hits,
                self.receipt.confirmation,
            )
            names = (
                "version",
                "hash_name",
                "size",
                "root",
                "pointer",
                "value",
                "start",
                "stop",
                "items",
                "proof",
                "hits",
                "confirmation",
            )
            for name, value in zip(names, base):
                object.__setattr__(forged, name, fields.get(name, value))
            return forged

        with self.assertRaises(ValueError):
            verify_full_encrypted_json_search_receipt(
                bypassed(version=2), KEY
            )
        with self.assertRaises(TypeError):
            verify_full_encrypted_json_search_receipt(
                bypassed(pointer=1), KEY
            )
        with self.assertRaises(TypeError):
            verify_full_encrypted_json_search_receipt(
                bypassed(root=bytearray(32)), KEY
            )
        with self.assertRaises(ValueError):
            verify_full_encrypted_json_search_receipt(
                bypassed(confirmation=b"\x00" * 31), KEY
            )
        with self.assertRaises(ValueError):
            verify_full_encrypted_json_search_receipt(
                bypassed(hits=(9,)), KEY
            )


if __name__ == "__main__":
    unittest.main()
