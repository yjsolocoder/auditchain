import json
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    Entry,
    JsonSearchIndex,
    SignedJsonSearchIndex,
    decode_json_search_index,
    decode_signed_json_search_index,
    encode_json_search_index,
    encode_signed_json_search_index,
    verify_signed_json_search_index,
)

_SEED_A = bytes(range(32))
_SEED_B = bytes(range(1, 33))


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
    # 0: integer 1
    log.append(j({"a": 1, "b": {"c": "x"}, "arr": [10, 20]}))
    # 1: float numerically equal to 1
    log.append(j({"a": 1.0, "b": {"c": "y"}}))
    # 2: boolean true is a different kind
    log.append(j({"a": True}))
    # 3: the string "1" is a different kind
    log.append(j({"a": "1"}))
    # 4: explicit null
    log.append(j({"a": None}))
    # 5: payload that is not JSON at all
    log.append(b"not json")
    # 6: field present but an object (non-scalar)
    log.append(j({"a": {"nested": 1}}))
    # 7: missing field
    log.append(j({"other": 1}))
    # 8: escaped member names
    log.append(j({"a/b": {"c~d": 7}}))
    # 9: encrypted envelope never participates
    log.encrypt(j({"a": 1}), b"k" * 32)
    return log


class IssueAndFindTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_search_index("/a", _SEED_A)

    def test_finds_match_find_json_for_every_kind(self):
        for value in (1, 1.0, 2, True, False, "1", "x", None, 7):
            self.assertEqual(
                self.bundle.find(value),
                self.log.find_json("/a", value),
                value,
            )

    def test_number_equality_classes_share_one_term(self):
        self.assertEqual(self.bundle.find(1), (0, 1))
        self.assertEqual(self.bundle.find(1.0), (0, 1))
        self.assertEqual(self.bundle.find(True), (2,))
        self.assertEqual(self.bundle.find(False), ())
        self.assertEqual(self.bundle.find("1"), (3,))
        self.assertEqual(self.bundle.find(None), (4,))
        term_values = tuple(value for value, _ in self.bundle.index.terms)
        self.assertEqual(
            sum(1 for value in term_values if type(value) is int and value == 1),
            1,
        )
        self.assertFalse(
            any(type(value) is float and value == 1.0 for value in term_values)
        )

    def test_nested_and_escaped_pointers(self):
        nested = self.log.signed_json_search_index("/b/c", _SEED_A)
        self.assertEqual(nested.find("x"), (0,))
        self.assertEqual(nested.find("y"), (1,))
        escaped = self.log.signed_json_search_index("/a~1b/c~0d", _SEED_A)
        self.assertEqual(escaped.find(7), (8,))

    def test_root_pointer(self):
        log = AuditLog()
        log.append(b"42")
        log.append(b'"hello"')
        bundle = log.signed_json_search_index("", _SEED_A)
        self.assertEqual(bundle.find(42), (0,))
        self.assertEqual(bundle.find("hello"), (1,))
        self.assertEqual(bundle.find(True), ())

    def test_big_integer_and_distinct_float_classes(self):
        log = AuditLog()
        log.append(j({"a": 10**40}))
        log.append(j({"a": 1e40}))
        log.append(j({"a": 2.5}))
        log.append(j({"a": -0.0}))
        log.append(j({"a": 0}))
        bundle = log.signed_json_search_index("/a", _SEED_A)
        self.assertEqual(bundle.find(10**40), (0,))
        self.assertEqual(bundle.find(1e40), (1,))
        self.assertEqual(bundle.find(2.5), (2,))
        self.assertEqual(bundle.find(0), (3, 4))
        self.assertEqual(bundle.find(0.0), (3, 4))

    def test_default_and_explicit_ranges(self):
        self.assertEqual(self.bundle.find(1, 0, 1), (0,))
        self.assertEqual(self.bundle.find(1, 1, 2), (1,))
        self.assertEqual(self.bundle.find(1, 2), ())
        self.assertEqual(self.bundle.find(1, stop=1), (0,))
        self.assertEqual(self.bundle.find(1, 0, None), (0, 1))

    def test_repeated_queries_for_different_values(self):
        first = self.bundle.find(1)
        self.assertEqual(self.bundle.find(True), (2,))
        self.assertEqual(self.bundle.find(None), (4,))
        self.assertEqual(self.bundle.find("1"), (3,))
        # Repeated queries stay stable.
        self.assertEqual(self.bundle.find(1), first)

    def test_value_type_errors_match_find_json(self):
        for bad in ([1], {"x": 1}, b"1", bytearray(b"1")):
            with self.assertRaises(TypeError):
                self.bundle.find(bad)
        for bad in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                self.bundle.find(bad)

    def test_range_type_and_value_errors(self):
        size = self.bundle.index.size
        with self.assertRaises(TypeError):
            self.bundle.find(1, True)
        with self.assertRaises(TypeError):
            self.bundle.find(1, 0, "2")
        with self.assertRaises(ValueError):
            self.bundle.find(1, -1)
        with self.assertRaises(ValueError):
            self.bundle.find(1, 0, size + 1)
        with self.assertRaises(ValueError):
            self.bundle.find(1, 4, 2)


class SnapshotSemanticsTest(unittest.TestCase):
    def test_snapshot_is_frozen_across_appends(self):
        log = make_log()
        bundle = log.signed_json_search_index("/a", _SEED_A)
        size = bundle.index.size
        values = (1, True, "1", None)
        before = tuple((value, bundle.find(value)) for value in values)
        log.append(j({"a": 1}))
        log.append(j({"a": "new"}))
        self.assertEqual(bundle.index.size, size)
        for value, hits in before:
            self.assertEqual(bundle.find(value), hits)
        # A freshly built index does see the new entries.
        grown = log.signed_json_search_index("/a", _SEED_A)
        self.assertEqual(grown.find(1), (0, 1, size))
        self.assertEqual(grown.find("new"), (size + 1,))

    def test_pruned_log_covers_only_the_retained_suffix(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_search_index("/a", _SEED_A)
        self.assertEqual(bundle.index.start, 2)
        self.assertEqual(bundle.find(1), ())
        self.assertEqual(bundle.find(True), (2,))
        self.assertEqual(bundle.find(None), (4,))
        # The covered interval cannot be addressed below the retain point.
        with self.assertRaises(ValueError):
            bundle.find(True, 0, 3)
        self.assertEqual(bundle.find(True, 2), (2,))

    def test_pruned_prefix_snapshot_is_unrebuildable(self):
        log = make_log()
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            log.signed_json_search_index("/a", _SEED_A, size=0)
        with self.assertRaises(ValueError):
            log.signed_json_search_index("/a", _SEED_A, size=1)
        # size exactly at the retain point yields legal empty coverage.
        boundary = log.signed_json_search_index("/a", _SEED_A, size=2)
        self.assertEqual(boundary.index.items, ())
        self.assertEqual(boundary.index.proof, ())
        self.assertEqual(boundary.find(1), ())

    def test_empty_log(self):
        bundle = AuditLog().signed_json_search_index("", _SEED_A)
        self.assertEqual(bundle.index.size, 0)
        self.assertEqual(bundle.index.start, 0)
        self.assertEqual(bundle.find(1), ())
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(_SEED_A))
        )


class IssuerArgumentsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_pointer_must_be_a_string(self):
        for bad in (b"/a", 1, None, ["/a"], object()):
            with self.assertRaises(TypeError):
                self.log.signed_json_search_index(bad, _SEED_A)

    def test_malformed_pointer_is_value_error(self):
        for bad in ("a", "/a~", "/a~2", "/a~x"):
            with self.assertRaises(ValueError):
                self.log.signed_json_search_index(bad, _SEED_A)

    def test_private_key_must_be_32_bytes(self):
        with self.assertRaises(TypeError):
            self.log.signed_json_search_index("/a", "x" * 32)
        with self.assertRaises(TypeError):
            self.log.signed_json_search_index("/a", bytearray(32))
        with self.assertRaises(ValueError):
            self.log.signed_json_search_index("/a", b"short")

    def test_size_rules(self):
        with self.assertRaises(TypeError):
            self.log.signed_json_search_index("/a", _SEED_A, size=True)
        with self.assertRaises(ValueError):
            self.log.signed_json_search_index("/a", _SEED_A, size=-1)
        with self.assertRaises(ValueError):
            self.log.signed_json_search_index(
                "/a", _SEED_A, size=len(self.log) + 1
            )

    def test_failure_is_read_only(self):
        log = make_log()
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        retain = log.retain_from
        with self.assertRaises(TypeError):
            log.signed_json_search_index(b"/a", _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_json_search_index("bad", _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_json_search_index("/a", b"short")
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(log.retain_from, retain)


class VerifyOfflineTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_search_index("/a", _SEED_A)

    def test_genuine_bundle_verifies_with_only_the_public_key(self):
        self.assertTrue(
            verify_signed_json_search_index(self.bundle, public_key(_SEED_A))
        )

    def test_wrong_key_returns_false(self):
        self.assertFalse(
            verify_signed_json_search_index(self.bundle, public_key(_SEED_B))
        )

    def test_tampered_signature_returns_false(self):
        raw = bytearray(encode_signed_json_search_index(self.bundle))
        raw[-1] ^= 0x01
        decoded = decode_signed_json_search_index(bytes(raw))
        self.assertFalse(
            verify_signed_json_search_index(decoded, public_key(_SEED_A))
        )

    def _rebuild(self, **changes):
        source = self.bundle.index
        index = replace(source, **changes)
        return SignedJsonSearchIndex(index=index, signature=self.bundle.signature)

    def test_tampered_payload_returns_false(self):
        items = list(self.bundle.index.items)
        entry = items[0]
        items[0] = Entry(
            entry.index, entry.payload + b" ", entry.previous_hash, entry.entry_hash
        )
        self.assertFalse(
            verify_signed_json_search_index(
                self._rebuild(items=tuple(items)), public_key(_SEED_A)
            )
        )

    def test_tampered_root_or_head_returns_false(self):
        root = bytearray(self.bundle.index.root)
        root[0] ^= 0x01
        self.assertFalse(
            verify_signed_json_search_index(
                self._rebuild(root=bytes(root)), public_key(_SEED_A)
            )
        )
        head = bytearray(self.bundle.index.head)
        head[0] ^= 0x01
        self.assertFalse(
            verify_signed_json_search_index(
                self._rebuild(head=bytes(head)), public_key(_SEED_A)
            )
        )

    def test_forged_hit_returns_false(self):
        terms = [
            (value, hits + (7,) if value == 1 else hits)
            for value, hits in self.bundle.index.terms
        ]
        self.assertFalse(
            verify_signed_json_search_index(
                self._rebuild(terms=tuple(terms)), public_key(_SEED_A)
            )
        )

    def test_concealed_hit_returns_false(self):
        terms = [
            (value, tuple(index for index in hits if index != 0))
            if value == 1
            else (value, hits)
            for value, hits in self.bundle.index.terms
        ]
        self.assertFalse(
            verify_signed_json_search_index(
                self._rebuild(terms=tuple(terms)), public_key(_SEED_A)
            )
        )

    def test_swapped_hit_list_returns_false(self):
        terms = []
        for value, hits in self.bundle.index.terms:
            if value is True:
                terms.append((value, (4,)))
            elif value is None:
                terms.append((value, (2,)))
            else:
                terms.append((value, hits))
        self.assertFalse(
            verify_signed_json_search_index(
                self._rebuild(terms=tuple(terms)), public_key(_SEED_A)
            )
        )

    def test_pruned_suffix_bundle_verifies_offline(self):
        log = make_log()
        log.prune(3, log.seal(3))
        bundle = log.signed_json_search_index("/a", _SEED_A)
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(_SEED_A))
        )

    def test_verify_argument_types(self):
        with self.assertRaises(TypeError):
            verify_signed_json_search_index("x", public_key(_SEED_A))
        with self.assertRaises(TypeError):
            verify_signed_json_search_index(self.bundle, "x")
        with self.assertRaises(ValueError):
            verify_signed_json_search_index(self.bundle, b"short")


class CodecTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_search_index("/a", _SEED_A)

    def test_signed_round_trip_is_byte_identical(self):
        blob = encode_signed_json_search_index(self.bundle)
        decoded = decode_signed_json_search_index(blob)
        self.assertEqual(decoded, self.bundle)
        self.assertEqual(encode_signed_json_search_index(decoded), blob)

    def test_index_round_trip_is_byte_identical(self):
        blob = encode_json_search_index(self.bundle.index)
        decoded = decode_json_search_index(blob)
        self.assertEqual(decoded, self.bundle.index)
        self.assertEqual(encode_json_search_index(decoded), blob)

    def test_round_trip_keeps_find_and_verification(self):
        decoded = decode_signed_json_search_index(
            encode_signed_json_search_index(self.bundle)
        )
        for value in (1, 1.0, True, "1", None, 99):
            self.assertEqual(
                decoded.find(value), self.bundle.find(value), value
            )
        self.assertTrue(
            verify_signed_json_search_index(decoded, public_key(_SEED_A))
        )

    def test_empty_coverage_round_trip(self):
        log = AuditLog()
        bundle = log.signed_json_search_index("/a", _SEED_A)
        blob = encode_signed_json_search_index(bundle)
        decoded = decode_signed_json_search_index(blob)
        self.assertEqual(encode_signed_json_search_index(decoded), blob)
        self.assertEqual(decoded, bundle)

    def test_pruned_suffix_round_trip(self):
        log = make_log()
        log.prune(4, log.seal(4))
        bundle = log.signed_json_search_index("/a", _SEED_A)
        blob = encode_signed_json_search_index(bundle)
        decoded = decode_signed_json_search_index(blob)
        self.assertEqual(encode_signed_json_search_index(decoded), blob)
        self.assertTrue(
            verify_signed_json_search_index(decoded, public_key(_SEED_A))
        )

    def test_same_state_and_seed_emit_byte_identical_artifacts(self):
        first = encode_signed_json_search_index(
            self.log.signed_json_search_index("/a", _SEED_A)
        )
        second = encode_signed_json_search_index(
            self.log.signed_json_search_index("/a", _SEED_A)
        )
        self.assertEqual(first, second)

    def test_decode_input_must_be_bytes(self):
        with self.assertRaises(TypeError):
            decode_json_search_index("x")
        with self.assertRaises(TypeError):
            decode_signed_json_search_index(bytearray(8))

    def test_bad_framing_is_value_error(self):
        with self.assertRaises(ValueError):
            decode_json_search_index(b"not an auditchain artifact")
        with self.assertRaises(ValueError):
            decode_signed_json_search_index(b"not an auditchain artifact")
        blob = encode_signed_json_search_index(self.bundle)
        with self.assertRaises(ValueError):
            decode_signed_json_search_index(blob[:-1])
        with self.assertRaises(ValueError):
            decode_signed_json_search_index(blob + b"\x00")
        index_blob = encode_json_search_index(self.bundle.index)
        with self.assertRaises(ValueError):
            decode_json_search_index(index_blob[:-1])
        with self.assertRaises(ValueError):
            decode_json_search_index(index_blob + b"\x00")


class ConstructorTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.index = self.log.signed_json_search_index("/a", _SEED_A).index

    def test_integral_float_term_is_canonicalized_to_integer(self):
        terms = ((1.0, (0, 1)),)
        rebuilt = JsonSearchIndex(
            self.index.version,
            self.index.hash_name,
            self.index.size,
            self.index.root,
            self.index.head,
            self.index.pointer,
            self.index.start,
            self.index.items,
            self.index.proof,
            terms,
        )
        self.assertEqual(rebuilt.terms[0][0], 1)

    def test_repeated_value_term_is_value_error(self):
        with self.assertRaises(ValueError):
            JsonSearchIndex(
                self.index.version,
                self.index.hash_name,
                self.index.size,
                self.index.root,
                self.index.head,
                self.index.pointer,
                self.index.start,
                self.index.items,
                self.index.proof,
                ((1, (0,)), (1.0, (1,))),
            )

    def test_term_and_hit_shape_rules(self):
        with self.assertRaises(TypeError):
            replace(self.index, terms=((1, [0]),))
        with self.assertRaises(ValueError):
            JsonSearchIndex(
                self.index.version,
                self.index.hash_name,
                self.index.size,
                self.index.root,
                self.index.head,
                self.index.pointer,
                self.index.start,
                self.index.items,
                self.index.proof,
                ((1, (0, 0)),),
            )
        with self.assertRaises(ValueError):
            JsonSearchIndex(
                self.index.version,
                self.index.hash_name,
                self.index.size,
                self.index.root,
                self.index.head,
                self.index.pointer,
                self.index.start,
                self.index.items,
                self.index.proof,
                ((1, (self.index.size,)),),
            )
        with self.assertRaises(TypeError):
            JsonSearchIndex(
                self.index.version,
                self.index.hash_name,
                self.index.size,
                self.index.root,
                self.index.head,
                self.index.pointer,
                self.index.start,
                self.index.items,
                self.index.proof,
                (([1], (0,)),),
            )

    def test_signed_container_rules(self):
        with self.assertRaises(TypeError):
            SignedJsonSearchIndex("x", b"\x00" * 64)
        with self.assertRaises(TypeError):
            SignedJsonSearchIndex(self.index, "x" * 64)
        with self.assertRaises(ValueError):
            SignedJsonSearchIndex(self.index, b"\x00" * 63)


if __name__ == "__main__":
    unittest.main()
