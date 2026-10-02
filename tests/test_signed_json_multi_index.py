import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    Entry,
    JsonMultiIndex,
    JsonSearchIndexBucket,
    JsonSearchIndexGroup,
    SignedJsonMultiIndex,
    decode_json_multi_index,
    decode_signed_json_multi_index,
    encode_json_multi_index,
    encode_signed_json_multi_index,
    verify_json_multi_index,
    verify_signed_json_multi_index,
)

SEED_A = bytes(range(1, 33))
SEED_B = bytes(range(33, 65))

POINTERS = ("", "/a", "/a~0b", "/b/c")


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def public_key(seed):
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def make_log():
    log = AuditLog()
    # 0: integer 1 at /a, string x at /b/c
    log.append(j({"a": 1, "b": {"c": "x"}, "arr": [10, 20]}))
    # 1: float 1.0 at /a (same JSON number as 1)
    log.append(j({"a": 1.0, "b": {"c": "y"}}))
    # 2: boolean true is a different kind from the number 1
    log.append(j({"a": True}))
    # 3: the string "1" is a different kind from the number 1
    log.append(j({"a": "1"}))
    # 4: explicit null
    log.append(j({"a": None}))
    # 5: payload that is not JSON at all
    log.append(b"not json")
    # 6: non-scalar object at /a
    log.append(j({"a": {"nested": 1}}))
    # 7: non-scalar array at /a
    log.append(j({"a": [1, 2]}))
    # 8: missing field
    log.append(j({"other": 1}))
    # 9: escaped member names
    log.append(j({"a/b": {"c~d": 7}}))
    # 10: top-level scalar document
    log.append(b"42")
    # 11: top-level string document
    log.append(b'"hello"')
    # 12: empty object
    log.append(b"{}")
    return log


def rebuild(index, **changes):
    fields = dict(
        version=index.version,
        hash_name=index.hash_name,
        size=index.size,
        root=index.root,
        head=index.head,
        retain_from=index.retain_from,
        pointers=index.pointers,
        items=index.items,
        proof=index.proof,
        groups=index.groups,
    )
    fields.update(changes)
    return JsonMultiIndex(**fields)


class SignedJsonMultiIndexBasicsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)
        self.public = public_key(SEED_A)

    def test_bundle_fields_bind_pointers_snapshot_and_chain(self):
        index = self.bundle.index
        self.assertEqual(index.pointers, POINTERS)
        self.assertEqual(self.bundle.pointers, POINTERS)
        self.assertEqual(index.version, 1)
        self.assertEqual(index.hash_name, "sha256")
        self.assertEqual(index.size, len(self.log))
        self.assertEqual(index.retain_from, 0)
        self.assertEqual(index.root, self.log.merkle_root())
        self.assertEqual(index.head, self.log.head)
        self.assertEqual(len(index.groups), len(POINTERS))
        self.assertEqual(len(index.items), len(self.log))
        self.assertEqual(len(self.bundle.signature), 64)

    def test_items_cover_the_whole_range(self):
        index = self.bundle.index
        self.assertEqual(
            tuple(entry.index for entry in index.items),
            tuple(range(len(self.log))),
        )
        for entry in index.items:
            self.assertEqual(entry.payload, self.log.entry(entry.index).payload)

    def test_repeatable_byte_for_byte(self):
        again = self.log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(again, self.bundle)
        self.assertEqual(
            encode_signed_json_multi_index(again),
            encode_signed_json_multi_index(self.bundle),
        )

    def test_size_freezes_a_prefix_snapshot(self):
        bundle = self.log.signed_json_multi_index(POINTERS, SEED_A, 5)
        self.assertEqual(bundle.index.size, 5)
        self.assertEqual(len(bundle.index.items), 5)
        self.assertEqual(bundle.index.root, self.log.merkle_root(5))
        self.assertEqual(bundle.find("/a", 1), (0, 1))
        self.assertTrue(verify_signed_json_multi_index(bundle, self.public))

    def test_issuing_is_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.retain_from,
        )
        self.log.signed_json_multi_index(POINTERS, SEED_A)
        after = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.retain_from,
        )
        self.assertEqual(before, after)


class SignedJsonMultiIndexFindTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)

    def test_find_matches_find_json_for_every_pointer(self):
        values = (1, 1.0, 2.5, True, False, None, "1", "x", "y", 42, "hello")
        for pointer in POINTERS:
            for value in values:
                self.assertEqual(
                    self.bundle.find(pointer, value),
                    self.log.find_json(pointer, value),
                    (pointer, value),
                )

    def test_find_matches_find_json_over_subranges(self):
        for pointer in POINTERS:
            for value in (1, "x", None, True):
                for start, stop in ((0, 5), (1, 4), (2, 2), (0, 13)):
                    self.assertEqual(
                        self.bundle.find(pointer, value, start, stop),
                        self.log.find_json(pointer, value, start, stop),
                        (pointer, value, start, stop),
                    )

    def test_find_hits_are_strictly_ascending(self):
        for pointer in POINTERS:
            hits = self.bundle.find(pointer, 1)
            self.assertEqual(list(hits), sorted(set(hits)))

    def test_find_root_pointer(self):
        self.assertEqual(self.bundle.find("", 42), (10,))
        self.assertEqual(self.bundle.find("", "hello"), (11,))

    def test_find_escaped_pointer(self):
        self.assertEqual(self.bundle.find("/a~0b", 1), ())
        log = make_log()
        bundle = log.signed_json_multi_index(("/a~1b/c~0d",), SEED_A)
        self.assertEqual(bundle.find("/a~1b/c~0d", 7), (9,))

    def test_find_uncovered_pointer_raises(self):
        with self.assertRaises(ValueError):
            self.bundle.find("/missing", 1)

    def test_find_pointer_type_and_syntax_errors(self):
        with self.assertRaises(TypeError):
            self.bundle.find(1, 1)
        with self.assertRaises(ValueError):
            self.bundle.find("a", 1)
        with self.assertRaises(ValueError):
            self.bundle.find("/a~2", 1)

    def test_find_value_type_errors(self):
        with self.assertRaises(TypeError):
            self.bundle.find("/a", b"1")
        with self.assertRaises(TypeError):
            self.bundle.find("/a", [1])
        with self.assertRaises(ValueError):
            self.bundle.find("/a", float("nan"))
        with self.assertRaises(ValueError):
            self.bundle.find("/a", float("inf"))

    def test_find_range_errors(self):
        with self.assertRaises(TypeError):
            self.bundle.find("/a", 1, "0")
        with self.assertRaises(TypeError):
            self.bundle.find("/a", 1, 0, True)
        with self.assertRaises(ValueError):
            self.bundle.find("/a", 1, -1)
        with self.assertRaises(ValueError):
            self.bundle.find("/a", 1, 5, 4)
        with self.assertRaises(ValueError):
            self.bundle.find("/a", 1, 0, 14)


class SignedJsonMultiIndexConstructionTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_pointers_must_be_a_tuple(self):
        with self.assertRaises(TypeError):
            self.log.signed_json_multi_index(["/a"], SEED_A)
        with self.assertRaises(TypeError):
            self.log.signed_json_multi_index("/a", SEED_A)

    def test_pointers_must_be_non_empty(self):
        with self.assertRaises(ValueError):
            self.log.signed_json_multi_index((), SEED_A)

    def test_pointer_element_type_and_syntax(self):
        with self.assertRaises(TypeError):
            self.log.signed_json_multi_index((1,), SEED_A)
        with self.assertRaises(ValueError):
            self.log.signed_json_multi_index(("a",), SEED_A)
        with self.assertRaises(ValueError):
            self.log.signed_json_multi_index(("/~2",), SEED_A)

    def test_pointers_must_be_unique_and_ascending(self):
        with self.assertRaises(ValueError):
            self.log.signed_json_multi_index(("/a", "/a"), SEED_A)
        with self.assertRaises(ValueError):
            self.log.signed_json_multi_index(("/b", "/a"), SEED_A)
        with self.assertRaises(ValueError):
            self.log.signed_json_multi_index(("/a", "", "/b"), SEED_A)

    def test_single_pointer_is_accepted(self):
        bundle = self.log.signed_json_multi_index(("/a",), SEED_A)
        self.assertEqual(bundle.pointers, ("/a",))
        self.assertEqual(bundle.find("/a", 1), (0, 1))

    def test_private_key_errors(self):
        with self.assertRaises(TypeError):
            self.log.signed_json_multi_index(POINTERS, "seed")
        with self.assertRaises(ValueError):
            self.log.signed_json_multi_index(POINTERS, b"short")

    def test_size_errors(self):
        with self.assertRaises(TypeError):
            self.log.signed_json_multi_index(POINTERS, SEED_A, True)
        with self.assertRaises(TypeError):
            self.log.signed_json_multi_index(POINTERS, SEED_A, "5")
        with self.assertRaises(ValueError):
            self.log.signed_json_multi_index(POINTERS, SEED_A, -1)
        with self.assertRaises(ValueError):
            self.log.signed_json_multi_index(POINTERS, SEED_A, 14)

    def test_pruned_snapshot_is_not_rebuildable(self):
        log = make_log()
        receipt = log.seal(5)
        log.prune(5, receipt)
        with self.assertRaises(ValueError):
            log.signed_json_multi_index(POINTERS, SEED_A, 4)


class SignedJsonMultiIndexVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)
        self.public = public_key(SEED_A)

    def test_genuine_bundle_verifies(self):
        self.assertTrue(verify_json_multi_index(self.bundle.index))
        self.assertTrue(verify_signed_json_multi_index(self.bundle, self.public))

    def test_verify_type_errors(self):
        with self.assertRaises(TypeError):
            verify_json_multi_index(self.bundle)
        with self.assertRaises(TypeError):
            verify_signed_json_multi_index(self.bundle.index, self.public)
        with self.assertRaises(TypeError):
            verify_signed_json_multi_index(self.bundle, "key")
        with self.assertRaises(ValueError):
            verify_signed_json_multi_index(self.bundle, b"short")

    def test_wrong_key_returns_false(self):
        self.assertFalse(
            verify_signed_json_multi_index(self.bundle, public_key(SEED_B))
        )

    def test_forged_signature_returns_false(self):
        forged = SignedJsonMultiIndex(self.bundle.index, bytes(64))
        self.assertFalse(verify_signed_json_multi_index(forged, self.public))

    def test_forged_empty_sections_return_false(self):
        index = self.bundle.index
        forged = rebuild(index, groups=((),) * len(POINTERS))
        self.assertFalse(verify_json_multi_index(forged))
        bundle = SignedJsonMultiIndex(forged, self.bundle.signature)
        self.assertFalse(verify_signed_json_multi_index(bundle, self.public))

    def test_dropped_hit_returns_false(self):
        index = self.bundle.index
        section = index.groups[3]  # /b/c: "x" hits 0, "y" hits 1
        group = section[0]
        self.assertEqual(
            tuple(bucket.hits for bucket in group.buckets), ((0,), (1,))
        )
        # Dropping the "y" bucket conceals entry 1's hit.
        section = (JsonSearchIndexGroup(group.kind, group.buckets[:1]),)
        groups = index.groups[:3] + (section,)
        self.assertFalse(verify_json_multi_index(rebuild(index, groups=groups)))

    def test_forged_hit_returns_false(self):
        index = self.bundle.index
        section = index.groups[3]
        group = section[0]
        bucket = group.buckets[0]
        grown = JsonSearchIndexBucket(bucket.key, (0, 1, 4))
        section = (JsonSearchIndexGroup(group.kind, (grown,)),)
        groups = index.groups[:3] + (section,)
        self.assertFalse(verify_json_multi_index(rebuild(index, groups=groups)))

    def test_tampered_payload_returns_false(self):
        index = self.bundle.index
        entry = index.items[0]
        items = (
            Entry(entry.index, b'{"a": 2}', entry.previous_hash, entry.entry_hash),
        ) + index.items[1:]
        self.assertFalse(verify_json_multi_index(rebuild(index, items=items)))

    def test_tampered_root_returns_false(self):
        index = self.bundle.index
        self.assertFalse(verify_json_multi_index(rebuild(index, root=bytes(32))))

    def test_dropped_item_returns_false(self):
        index = self.bundle.index
        items = index.items[:-1]
        with self.assertRaises(ValueError):
            rebuild(index, items=items)

    def test_empty_log_bundle_verifies(self):
        log = AuditLog()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.index.items, ())
        self.assertEqual(bundle.index.groups, ((),) * len(POINTERS))
        self.assertTrue(verify_signed_json_multi_index(bundle, self.public))
        self.assertEqual(bundle.find("/a", 1), ())

    def test_pruned_log_bundle_verifies(self):
        log = make_log()
        receipt = log.seal(5)
        log.prune(5, receipt)
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.index.retain_from, 5)
        self.assertTrue(verify_signed_json_multi_index(bundle, self.public))
        for pointer in POINTERS:
            for value in (1, "x", None, True, 42):
                self.assertEqual(
                    bundle.find(pointer, value),
                    log.find_json(pointer, value),
                    (pointer, value),
                )

    def test_fully_pruned_log_bundle_verifies(self):
        log = make_log()
        receipt = log.seal(len(log))
        log.prune(len(log), receipt)
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(bundle.index.items, ())
        self.assertTrue(verify_signed_json_multi_index(bundle, self.public))

    def test_encrypted_entries_never_hit(self):
        log = AuditLog()
        key = bytes(32)
        log.encrypt(j({"a": 1}), key)
        log.append(j({"a": 1}))
        bundle = log.signed_json_multi_index(("/a",), SEED_A)
        self.assertEqual(bundle.find("/a", 1), (1,))
        self.assertTrue(verify_signed_json_multi_index(bundle, self.public))


class JsonMultiIndexStructureTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.index = self.log.signed_json_multi_index(POINTERS, SEED_A).index

    def test_version_must_be_one(self):
        with self.assertRaises(ValueError):
            rebuild(self.index, version=2)
        with self.assertRaises(TypeError):
            rebuild(self.index, version="1")

    def test_groups_must_match_pointer_count(self):
        with self.assertRaises(ValueError):
            rebuild(self.index, groups=self.index.groups[:-1])
        with self.assertRaises(ValueError):
            rebuild(self.index, groups=self.index.groups + ((),))
        with self.assertRaises(TypeError):
            rebuild(self.index, groups=list(self.index.groups))

    def test_constructor_rejects_unordered_pointers(self):
        with self.assertRaises(ValueError):
            rebuild(self.index, pointers=tuple(reversed(POINTERS)))
        with self.assertRaises(ValueError):
            rebuild(self.index, pointers=())
        with self.assertRaises(TypeError):
            rebuild(self.index, pointers=list(POINTERS))

    def test_signed_bundle_field_types(self):
        with self.assertRaises(TypeError):
            SignedJsonMultiIndex(self.index, "sig")
        with self.assertRaises(ValueError):
            SignedJsonMultiIndex(self.index, b"short")
        with self.assertRaises(TypeError):
            SignedJsonMultiIndex("index", bytes(64))


class JsonMultiIndexCodecTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_multi_index(POINTERS, SEED_A)
        self.public = public_key(SEED_A)

    def test_index_round_trip(self):
        blob = encode_json_multi_index(self.bundle.index)
        decoded = decode_json_multi_index(blob)
        self.assertEqual(decoded, self.bundle.index)
        self.assertEqual(encode_json_multi_index(decoded), blob)
        self.assertTrue(verify_json_multi_index(decoded))

    def test_signed_round_trip(self):
        blob = encode_signed_json_multi_index(self.bundle)
        decoded = decode_signed_json_multi_index(blob)
        self.assertEqual(decoded, self.bundle)
        self.assertEqual(encode_signed_json_multi_index(decoded), blob)
        self.assertTrue(verify_signed_json_multi_index(decoded, self.public))

    def test_empty_log_round_trip(self):
        bundle = AuditLog().signed_json_multi_index(POINTERS, SEED_A)
        blob = encode_signed_json_multi_index(bundle)
        decoded = decode_signed_json_multi_index(blob)
        self.assertEqual(decoded, bundle)
        self.assertTrue(verify_signed_json_multi_index(decoded, self.public))

    def test_encode_type_errors(self):
        with self.assertRaises(TypeError):
            encode_json_multi_index(self.bundle)
        with self.assertRaises(TypeError):
            encode_signed_json_multi_index(self.bundle.index)

    def test_decode_type_errors(self):
        with self.assertRaises(TypeError):
            decode_json_multi_index(bytearray(b"x"))
        with self.assertRaises(TypeError):
            decode_signed_json_multi_index(bytearray(b"x"))

    def test_decode_bad_magic(self):
        with self.assertRaises(ValueError):
            decode_json_multi_index(b"garbage")
        with self.assertRaises(ValueError):
            decode_signed_json_multi_index(b"garbage")

    def test_decode_truncation(self):
        blob = encode_signed_json_multi_index(self.bundle)
        for cut in (1, len(blob) // 2, len(blob) - 1):
            with self.assertRaises(ValueError):
                decode_signed_json_multi_index(blob[:-cut])
        index_blob = encode_json_multi_index(self.bundle.index)
        for cut in (1, len(index_blob) // 2, len(index_blob) - 1):
            with self.assertRaises(ValueError):
                decode_json_multi_index(index_blob[:-cut])

    def test_decode_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_json_multi_index(
                encode_json_multi_index(self.bundle.index) + b"\0"
            )
        with self.assertRaises(ValueError):
            decode_signed_json_multi_index(
                encode_signed_json_multi_index(self.bundle) + b"\0"
            )

    def test_decode_bad_version(self):
        blob = bytearray(encode_signed_json_multi_index(self.bundle))
        magic_len = len(b"auditchain/signed-json-multi-index/v1\0")
        blob[magic_len:magic_len + 8] = (2).to_bytes(8, "big")
        with self.assertRaises(ValueError):
            decode_signed_json_multi_index(bytes(blob))

    def test_tampered_encoding_fails_verification_not_decoding(self):
        blob = bytearray(encode_json_multi_index(self.bundle.index))
        # Flip a payload byte inside the first item's payload blob.
        marker = j({"a": 1, "b": {"c": "x"}, "arr": [10, 20]})
        at = bytes(blob).find(marker)
        self.assertGreater(at, 0)
        blob[at + 2] ^= 0x01
        decoded = decode_json_multi_index(bytes(blob))
        self.assertFalse(verify_json_multi_index(decoded))


if __name__ == "__main__":
    unittest.main()
