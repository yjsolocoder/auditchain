import json
import math
import unittest

from auditchain import (
    AuditLog,
    Entry,
    JsonSearchReceipt,
    decode_json_search_receipt,
    encode_json_search_receipt,
    verify_json_search_receipt,
)

MAGIC = b"auditchain/json-search/v1\0"


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def make_log():
    log = AuditLog()
    log.append(j({"a": 1, "b": {"c": "x"}, "arr": [10, 20]}))  # 0 hit a==1
    log.append(j({"a": 1.0}))  # 1 hit by numeric equality
    log.append(j({"a": True}))  # 2
    log.append(j({"a": "1"}))  # 3
    log.append(j({"a": None}))  # 4
    log.append(b"not json")  # 5
    log.append(j({"a": {"nested": 1}}))  # 6 non-scalar
    log.append(j({"a": [1, 2]}))  # 7 non-scalar
    log.append(j({"other": 1}))  # 8 missing
    log.encrypt(j({"a": 1}), b"k" * 32)  # 9 envelope, never hits
    return log


class JsonSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_receipt_carries_snapshot_context(self):
        receipt = self.log.json_search_receipt("/a", 1)
        self.assertIsInstance(receipt, JsonSearchReceipt)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, len(self.log))
        self.assertEqual(receipt.root, self.log.merkle_root())
        self.assertEqual(receipt.pointer, "/a")
        self.assertEqual(receipt.value, 1)
        self.assertEqual(receipt.start, 0)
        self.assertEqual(receipt.stop, len(self.log))

    def test_items_cover_every_entry_of_the_range(self):
        receipt = self.log.json_search_receipt("/a", 1, 2, 6)
        self.assertEqual([entry.index for entry in receipt.items], [2, 3, 4, 5])
        self.assertEqual(receipt.start, 2)
        self.assertEqual(receipt.stop, 6)

    def test_hits_equal_find_json(self):
        for pointer, value, start, stop in (
            ("/a", 1, None, None),
            ("/a", 1.0, None, None),
            ("/a", True, None, None),
            ("/a", "1", None, None),
            ("/a", None, None, None),
            ("/b/c", "x", None, None),
            ("/arr/1", 20, None, None),
            ("/a", 1, 1, 5),
            ("/missing", 1, None, None),
        ):
            receipt = self.log.json_search_receipt(pointer, value, start, stop)
            self.assertEqual(
                receipt.hits,
                self.log.find_json(pointer, value, start, stop),
                (pointer, value, start, stop),
            )

    def test_empty_reference_token_pointer(self):
        receipt = self.log.json_search_receipt("/a/", 1)
        # Tokens ("a", "") address an empty-named member nobody has.
        self.assertEqual(receipt.pointer, "/a/")
        self.assertEqual(receipt.hits, ())
        self.assertTrue(verify_json_search_receipt(receipt))

    def test_explicit_size(self):
        receipt = self.log.json_search_receipt("/a", 1, 0, 3, size=3)
        self.assertEqual(receipt.size, 3)
        self.assertEqual(receipt.root, self.log.merkle_root(3))
        self.assertEqual([entry.index for entry in receipt.items], [0, 1, 2])
        self.assertEqual(receipt.hits, (0, 1))
        self.assertTrue(verify_json_search_receipt(receipt))

    def test_root_pointer_scalar_document(self):
        log = AuditLog()
        log.append(b"7")
        log.append(b'"7"')
        log.append(b"true")
        log.append(b"[7]")
        receipt = log.json_search_receipt("", 7)
        self.assertEqual(receipt.hits, (0,))
        self.assertTrue(verify_json_search_receipt(receipt))


class JsonSearchReceiptVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_genuine_receipt_verifies_offline(self):
        receipt = self.log.json_search_receipt("/a", 1)
        self.assertTrue(verify_json_search_receipt(receipt))
        self.assertEqual(receipt.hits, (0, 1))

    def test_partial_range_verifies(self):
        receipt = self.log.json_search_receipt("/a", 1, 0, 3, size=4)
        self.assertTrue(verify_json_search_receipt(receipt))
        self.assertEqual(receipt.hits, (0, 1))

    def test_omitting_a_hit_is_a_structural_error(self):
        receipt = self.log.json_search_receipt("/a", 1)
        hit_indices = set(receipt.hits)
        thinned = tuple(
            entry for entry in receipt.items if entry.index not in hit_indices
        )
        with self.assertRaises(ValueError):
            JsonSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.pointer,
                receipt.value,
                receipt.start,
                receipt.stop,
                thinned,
                receipt.proof,
            )

    def test_omitting_a_non_hit_also_breaks_coverage(self):
        receipt = self.log.json_search_receipt("/a", 1)
        thinned = tuple(
            entry for entry in receipt.items if entry.index != 2
        )
        with self.assertRaises(ValueError):
            JsonSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.pointer,
                receipt.value,
                receipt.start,
                receipt.stop,
                thinned,
                receipt.proof,
            )

    def test_duplicate_or_reordered_items_rejected(self):
        receipt = self.log.json_search_receipt("/a", 1, 1, 4)
        reordered = (receipt.items[1], receipt.items[0], receipt.items[2])
        with self.assertRaises(ValueError):
            JsonSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                receipt.root,
                receipt.pointer,
                receipt.value,
                receipt.start,
                receipt.stop,
                reordered,
                receipt.proof,
            )

    def test_forging_empty_hits_by_mutating_payload_fails(self):
        log = AuditLog()
        log.append(j({"a": 1}))
        log.append(j({"a": 2}))
        receipt = log.json_search_receipt("/a", 1)
        replacement = j({"a": 2})
        forged_items = tuple(
            Entry(
                entry.index,
                replacement,
                entry.previous_hash,
                entry.entry_hash,
            )
            for entry in receipt.items
        )
        forged = JsonSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.pointer,
            receipt.value,
            receipt.start,
            receipt.stop,
            forged_items,
            receipt.proof,
        )
        self.assertEqual(forged.hits, ())
        self.assertFalse(verify_json_search_receipt(forged))

    def test_forging_a_hit_fails(self):
        log = AuditLog()
        log.append(j({"a": 2}))
        receipt = log.json_search_receipt("/a", 1)
        self.assertEqual(receipt.hits, ())
        replacement = j({"a": 1})
        forged_items = tuple(
            Entry(
                entry.index,
                replacement,
                entry.previous_hash,
                entry.entry_hash,
            )
            for entry in receipt.items
        )
        forged = JsonSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.pointer,
            receipt.value,
            receipt.start,
            receipt.stop,
            forged_items,
            receipt.proof,
        )
        self.assertEqual(forged.hits, (0,))
        self.assertFalse(verify_json_search_receipt(forged))

    def test_tampered_root_returns_false(self):
        receipt = self.log.json_search_receipt("/a", 1)
        forged = JsonSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            bytes(32),
            receipt.pointer,
            receipt.value,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
        )
        self.assertFalse(verify_json_search_receipt(forged))

    def test_tampered_proof_returns_false(self):
        # A partial range leaves unselected siblings in the shared proof.
        receipt = self.log.json_search_receipt("/a", 1, 2, 7)
        self.assertTrue(receipt.proof)
        proof = receipt.proof
        tampered = (bytes(reversed(proof[0])),) + proof[1:]
        forged = JsonSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.pointer,
            receipt.value,
            receipt.start,
            receipt.stop,
            receipt.items,
            tampered,
        )
        self.assertFalse(verify_json_search_receipt(forged))

    def test_same_entries_under_a_different_query_are_authentic_for_it(self):
        # Exactly the prefix-receipt design: reusing genuine entries/proof
        # with another scalar query is authentic; completeness is judged
        # over the authenticated entries themselves.
        receipt = self.log.json_search_receipt("/a", 1)
        other = JsonSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.pointer,
            999,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
        )
        self.assertEqual(other.hits, ())
        self.assertTrue(verify_json_search_receipt(other))


class JsonSearchReceiptEmptyTest(unittest.TestCase):
    def test_empty_log(self):
        log = AuditLog()
        receipt = log.json_search_receipt("", None)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        self.assertEqual(receipt.size, 0)
        self.assertTrue(verify_json_search_receipt(receipt))

    def test_empty_log_wrong_root(self):
        log = AuditLog()
        receipt = log.json_search_receipt("", None)
        forged = JsonSearchReceipt(
            receipt.version,
            receipt.hash_name,
            0,
            bytes(32),
            receipt.pointer,
            receipt.value,
            0,
            0,
            (),
            (),
        )
        self.assertFalse(verify_json_search_receipt(forged))

    def test_empty_index_range_of_non_empty_snapshot(self):
        log = make_log()
        receipt = log.json_search_receipt("/a", 1, 3, 3)
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())
        # An empty range of a non-empty snapshot attests no content.
        self.assertTrue(verify_json_search_receipt(receipt))


class JsonSearchReceiptErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_query_type_errors(self):
        for bad in ([1], {"x": 1}, b"1", bytearray(b"1")):
            with self.assertRaises(TypeError):
                self.log.json_search_receipt("/a", bad)

    def test_non_finite_float_is_value_error(self):
        for bad in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                self.log.json_search_receipt("/a", bad)

    def test_pointer_errors(self):
        with self.assertRaises(TypeError):
            self.log.json_search_receipt(b"/a", 1)
        for bad in ("a", "/a~", "/a~9"):
            with self.assertRaises(ValueError):
                self.log.json_search_receipt(bad, 1)

    def test_range_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            self.log.json_search_receipt("/a", 1, True)
        with self.assertRaises(TypeError):
            self.log.json_search_receipt("/a", 1, 0, "2")
        with self.assertRaises(ValueError):
            self.log.json_search_receipt("/a", 1, -1)
        with self.assertRaises(ValueError):
            self.log.json_search_receipt("/a", 1, 0, len(self.log) + 1)
        with self.assertRaises(ValueError):
            self.log.json_search_receipt("/a", 1, 4, 2)
        with self.assertRaises(TypeError):
            self.log.json_search_receipt("/a", 1, size=True)
        with self.assertRaises(ValueError):
            self.log.json_search_receipt("/a", 1, size=len(self.log) + 1)

    def test_pruned_snapshot_and_range(self):
        log = make_log()
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            log.json_search_receipt("/a", 1, 0, 4)
        with self.assertRaises(ValueError):
            log.json_search_receipt("/a", 1, size=1)
        receipt = log.json_search_receipt("/a", True)
        self.assertTrue(verify_json_search_receipt(receipt))
        self.assertEqual(receipt.hits, (2,))

    def test_constructor_rejects_bytearray_binary_fields(self):
        receipt = self.log.json_search_receipt("/a", 1)
        with self.assertRaises(TypeError):
            JsonSearchReceipt(
                receipt.version,
                receipt.hash_name,
                receipt.size,
                bytearray(receipt.root),
                receipt.pointer,
                receipt.value,
                receipt.start,
                receipt.stop,
                receipt.items,
                receipt.proof,
            )

    def test_non_receipt_verifier_argument(self):
        for bad in (None, 1, b"bytes", "x", (), object()):
            with self.assertRaises(TypeError):
                verify_json_search_receipt(bad)

    def test_failure_does_not_change_log(self):
        log = make_log()
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        for call in (
            lambda: log.json_search_receipt("/a", [1]),
            lambda: log.json_search_receipt("/a", 1, 0, len(log) + 1),
            lambda: log.json_search_receipt("/a", 1, size=len(log) + 1),
            lambda: log.json_search_receipt("bad", 1),
        ):
            with self.assertRaises((TypeError, ValueError)):
                call()
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)


class JsonSearchReceiptPruneAndLoadTest(unittest.TestCase):
    def test_receipt_equal_before_and_after_prune_rebuild(self):
        log = AuditLog()
        log.append(j({"a": 1}))
        log.append(j({"a": 2}))
        log.append(j({"a": 1}))
        before = log.json_search_receipt("/a", 1, 2, 3)
        log.prune(2, log.seal(2))
        after = log.json_search_receipt("/a", 1, 2, 3)
        self.assertTrue(verify_json_search_receipt(before))
        self.assertTrue(verify_json_search_receipt(after))
        self.assertEqual(before, after)

    def test_consistent_across_dump_and_load(self):
        from auditchain import dump_log, load_log
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        log = AuditLog()
        for payload in (j({"a": 1}), j({"a": 2}), b"plain"):
            log.append(payload)
        seed = bytes(range(32))
        blob = dump_log(log, seed)
        public_key = (
            Ed25519PrivateKey.from_private_bytes(seed)
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        restored = load_log(blob, public_key)
        self.assertEqual(
            restored.json_search_receipt("/a", 1),
            log.json_search_receipt("/a", 1),
        )


class JsonSearchReceiptCodecTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_magic_prefix(self):
        receipt = self.log.json_search_receipt("/a", 1)
        self.assertTrue(encode_json_search_receipt(receipt).startswith(MAGIC))

    def test_round_trip_for_each_scalar_kind(self):
        cases = (
            ("/b/c", "x"),
            ("/a", "1"),
            ("/a", 1),
            ("/a", -12345678901234567890),
            ("/a", 0),
            ("/a", 1.5),
            ("/a", 1.0e300),
            ("/a", True),
            ("/a", False),
            ("/a", None),
            ("", 42),
        )
        for pointer, value in cases:
            log = AuditLog()
            log.append(j({"a": 1, "b": {"c": "x"}}))
            log.append(b"42")
            receipt = log.json_search_receipt(pointer, value)
            data = encode_json_search_receipt(receipt)
            decoded = decode_json_search_receipt(data)
            self.assertEqual(decoded, receipt, (pointer, value))
            self.assertEqual(encode_json_search_receipt(decoded), data)
            self.assertEqual(
                verify_json_search_receipt(decoded),
                verify_json_search_receipt(receipt),
            )

    def test_round_trip_full_and_partial_ranges(self):
        for kwargs in (
            dict(),
            dict(start=2, stop=7),
            dict(start=0, stop=0),
            dict(size=5),
        ):
            receipt = self.log.json_search_receipt("/a", 1, **kwargs)
            data = encode_json_search_receipt(receipt)
            decoded = decode_json_search_receipt(data)
            self.assertEqual(decoded, receipt)
            self.assertEqual(encode_json_search_receipt(decoded), data)
            self.assertTrue(verify_json_search_receipt(decoded))

    def test_escaped_pointer_round_trips(self):
        log = AuditLog()
        log.append(j({"a/b": {"c~d": 7}}))
        receipt = log.json_search_receipt("/a~1b/c~0d", 7)
        decoded = decode_json_search_receipt(encode_json_search_receipt(receipt))
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.pointer, "/a~1b/c~0d")
        self.assertEqual(decoded.hits, (0,))
        self.assertTrue(verify_json_search_receipt(decoded))

    def test_decode_rejects_non_bytes(self):
        for bad in ("x", bytearray(b"x"), None, 7):
            with self.assertRaises(TypeError):
                decode_json_search_receipt(bad)

    def test_decode_rejects_bad_magic_and_trailing_bytes(self):
        receipt = self.log.json_search_receipt("/a", 1)
        data = encode_json_search_receipt(receipt)
        with self.assertRaises(ValueError):
            decode_json_search_receipt(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_json_search_receipt(data + b"\x00")
        with self.assertRaises(ValueError):
            decode_json_search_receipt(data[:-1])

    def test_decode_rejects_unknown_value_tag(self):
        receipt = self.log.json_search_receipt("/a", 1)
        data = bytearray(encode_json_search_receipt(receipt))
        # Locate the value tag: magic, version, hash_name blob, size, root
        # blob, pointer blob, then the tag u64.
        offset = len(MAGIC) + 8  # magic + version
        offset += 8 + 6  # hash_name blob
        offset += 8  # size
        offset += 8 + 32  # root blob
        pointer = receipt.pointer.encode("utf-8")
        offset += 8 + len(pointer)
        self.assertEqual(data[offset:offset + 8], (1).to_bytes(8, "big"))
        data[offset:offset + 8] = (99).to_bytes(8, "big")
        with self.assertRaises(ValueError):
            decode_json_search_receipt(bytes(data))

    def test_bool_and_null_tags_are_distinguishable(self):
        log = AuditLog()
        log.append(j({"a": True}))
        true_receipt = log.json_search_receipt("/a", True)
        false_receipt = log.json_search_receipt("/a", False)
        null_receipt = log.json_search_receipt("/a", None)
        true_data = encode_json_search_receipt(true_receipt)
        self.assertEqual(decode_json_search_receipt(true_data).value, True)
        self.assertEqual(
            decode_json_search_receipt(
                encode_json_search_receipt(false_receipt)
            ).value,
            False,
        )
        self.assertIsNone(
            decode_json_search_receipt(
                encode_json_search_receipt(null_receipt)
            ).value
        )

    def test_field_layout(self):
        receipt = self.log.json_search_receipt("/a", 1, 2, 5)
        data = encode_json_search_receipt(receipt)
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], (1).to_bytes(8, "big"))
        offset += 8
        offset += 8 + 6  # hash_name
        self.assertEqual(data[offset:offset + 8], (10).to_bytes(8, "big"))
        offset += 8  # size
        offset += 8 + 32  # root
        pointer = b"/a"
        self.assertEqual(data[offset:offset + 8], (2).to_bytes(8, "big"))
        offset += 8
        self.assertEqual(data[offset:offset + 2], pointer)
        offset += 2
        # integer tag == 1
        self.assertEqual(data[offset:offset + 8], (1).to_bytes(8, "big"))
        offset += 8
        offset += 8 + 1  # value blob "1"
        self.assertEqual(data[offset:offset + 8], (2).to_bytes(8, "big"))
        offset += 8  # start
        self.assertEqual(data[offset:offset + 8], (5).to_bytes(8, "big"))
        offset += 8  # stop
        self.assertEqual(data[offset:offset + 8], (3).to_bytes(8, "big"))


if __name__ == "__main__":
    unittest.main()
