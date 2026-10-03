import json
import math
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    Entry,
    JsonSearchIndex,
    JsonSearchIndexBucket,
    JsonSearchIndexGroup,
    SignedJsonSearchIndex,
    decode_json_search_index,
    decode_signed_json_search_index,
    encode_json_search_index,
    encode_signed_json_search_index,
    verify_json_search_index,
    verify_signed_json_search_index,
)

SEED_A = bytes(range(1, 33))
SEED_B = bytes(range(33, 65))


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


class SignedJsonSearchIndexBasicsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_json_search_index("/a", SEED_A)
        self.public = public_key(SEED_A)

    def test_bundle_fields_bind_pointer_snapshot_and_chain(self):
        index = self.bundle.index
        self.assertEqual(index.pointer, "/a")
        self.assertEqual(index.version, 1)
        self.assertEqual(index.hash_name, self.log.hash_name)
        self.assertEqual(index.size, len(self.log))
        self.assertEqual(index.retain_from, 0)
        self.assertEqual(index.root, self.log.merkle_root())
        self.assertEqual(index.head, self.log.head)
        self.assertEqual(len(index.items), len(self.log))
        self.assertEqual(index.items[0], self.log.entry(0))
        self.assertEqual(self.bundle.pointer, "/a")

    def test_verifies_offline_against_trusted_key(self):
        self.assertTrue(
            verify_signed_json_search_index(self.bundle, self.public)
        )
        self.assertTrue(verify_json_search_index(self.bundle.index))

    def test_find_integer_matches_integer_and_float(self):
        self.assertEqual(self.bundle.find(1), (0, 1))
        self.assertEqual(self.bundle.find(2), ())

    def test_find_float_matches_by_numeric_value(self):
        self.assertEqual(self.bundle.find(1.0), (0, 1))

    def test_find_kind_separation(self):
        self.assertEqual(self.bundle.find(True), (2,))
        self.assertEqual(self.bundle.find(False), ())
        self.assertEqual(self.bundle.find("1"), (3,))
        self.assertEqual(self.bundle.find(None), (4,))

    def test_find_agrees_with_find_json_for_every_scalar_type(self):
        for value in (1, 1.0, 2.5, True, False, "1", "x", "z", None, -7, 0):
            self.assertEqual(
                self.bundle.find(value),
                self.log.find_json("/a", value),
                value,
            )

    def test_nested_pointer_and_escapes(self):
        nested = self.log.signed_json_search_index("/b/c", SEED_A)
        self.assertEqual(nested.find("x"), (0,))
        self.assertEqual(nested.find("y"), (1,))
        escaped = self.log.signed_json_search_index("/a~1b/c~0d", SEED_A)
        self.assertEqual(escaped.find(7), (9,))
        self.assertTrue(
            verify_signed_json_search_index(escaped, self.public)
        )

    def test_root_pointer_scalar_documents(self):
        root_index = self.log.signed_json_search_index("", SEED_A)
        self.assertEqual(root_index.find(42), (10,))
        self.assertEqual(root_index.find("hello"), (11,))

    def test_non_queryable_entries_land_in_no_bucket(self):
        all_listed = {
            hit
            for group in self.bundle.index.groups
            for bucket in group.buckets
            for hit in bucket.hits
        }
        # Indices 0..4 resolve to scalars; indices 5..12 are non-JSON,
        # non-scalar, missing-field, escaped-other-name or top-level
        # documents that resolve to nothing at /a.
        self.assertEqual(all_listed, {0, 1, 2, 3, 4})


class SignedJsonSearchIndexRangeTest(unittest.TestCase):
    def setUp(self):
        log = AuditLog()
        for value in (1, 2, 1, 1, 3, 1):
            log.append(j({"a": value}))
        self.log = log
        self.bundle = log.signed_json_search_index("/a", SEED_A)

    def test_default_range_is_the_whole_coverage(self):
        self.assertEqual(self.bundle.find(1), (0, 2, 3, 5))

    def test_half_open_explicit_ranges(self):
        self.assertEqual(self.bundle.find(1, 0, 3), (0, 2))
        self.assertEqual(self.bundle.find(1, 2, 5), (2, 3))
        self.assertEqual(self.bundle.find(1, 3, 3), ())
        self.assertEqual(self.bundle.find(3, None, 5), (4,))
        self.assertEqual(self.bundle.find(1, 5), (5,))

    def test_range_type_and_bounds_errors(self):
        with self.assertRaises(TypeError):
            self.bundle.find(1, True)
        with self.assertRaises(TypeError):
            self.bundle.find(1, 0, "3")
        with self.assertRaises(ValueError):
            self.bundle.find(1, -1)
        with self.assertRaises(ValueError):
            self.bundle.find(1, 0, len(self.log) + 1)
        with self.assertRaises(ValueError):
            self.bundle.find(1, 3, 2)


class SignedJsonSearchIndexQueryTypeTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_log().signed_json_search_index("/a", SEED_A)

    def test_value_must_be_scalar_json_type(self):
        for bad in ([1], {"x": 1}, b"1", bytearray(b"1"), (1,)):
            with self.assertRaises(TypeError):
                self.bundle.find(bad)

    def test_non_finite_float_is_value_error(self):
        for bad in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                self.bundle.find(bad)


class SignedJsonSearchIndexArgumentsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_pointer_must_be_string(self):
        for bad in (b"/a", 1, None, ["/a"], object()):
            with self.assertRaises(TypeError):
                self.log.signed_json_search_index(bad, SEED_A)

    def test_malformed_pointer_is_value_error(self):
        for bad in ("a", "/a~", "/a~2", "/a~x"):
            with self.assertRaises(ValueError):
                self.log.signed_json_search_index(bad, SEED_A)

    def test_private_key_must_be_thirty_two_bytes(self):
        with self.assertRaises(TypeError):
            self.log.signed_json_search_index("/a", "not bytes")
        with self.assertRaises(ValueError):
            self.log.signed_json_search_index("/a", b"too-short")

    def test_size_rules(self):
        with self.assertRaises(TypeError):
            self.log.signed_json_search_index("/a", SEED_A, size=True)
        with self.assertRaises(TypeError):
            self.log.signed_json_search_index("/a", SEED_A, size="3")
        with self.assertRaises(ValueError):
            self.log.signed_json_search_index(
                "/a", SEED_A, size=len(self.log) + 1
            )
        with self.assertRaises(ValueError):
            self.log.signed_json_search_index("/a", SEED_A, size=-1)

    def test_constructor_types(self):
        index = self.log.signed_json_search_index("/a", SEED_A).index
        with self.assertRaises(TypeError):
            SignedJsonSearchIndex("not-an-index", bytes(64))
        with self.assertRaises(TypeError):
            SignedJsonSearchIndex(index, "not-bytes")
        with self.assertRaises(ValueError):
            SignedJsonSearchIndex(index, bytes(63))


class SignedJsonSearchIndexSnapshotTest(unittest.TestCase):
    def test_repeated_queries_without_log_after_append(self):
        log = AuditLog()
        for value in (1, 2, 1):
            log.append(j({"a": value}))
        bundle = log.signed_json_search_index("/a", SEED_A)
        log.append(j({"a": 1}))
        log.append(j({"a": 2}))
        # The frozen snapshot does not see the new entries.
        self.assertEqual(bundle.find(1), (0, 2))
        self.assertEqual(bundle.find(2), (1,))
        public = public_key(SEED_A)
        self.assertTrue(verify_signed_json_search_index(bundle, public))

    def test_explicit_historical_size(self):
        log = AuditLog()
        for value in (1, 1, 2, 1):
            log.append(j({"a": value}))
        bundle = log.signed_json_search_index("/a", SEED_A, size=3)
        self.assertEqual(bundle.index.size, 3)
        self.assertEqual(bundle.find(1), (0, 1))
        self.assertEqual(bundle.find(2), (2,))
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )

    def test_pruned_log_covers_only_retained_segment(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_search_index("/a", SEED_A)
        self.assertEqual(bundle.index.retain_from, 2)
        self.assertEqual(bundle.index.size, len(log))
        self.assertEqual(bundle.find(1), ())
        self.assertEqual(bundle.find(True), (2,))
        self.assertEqual(len(bundle.index.items), len(log) - 2)
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )

    def test_historical_pruned_snapshot_is_not_rebuildable(self):
        log = make_log()
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            log.signed_json_search_index("/a", SEED_A, size=1)

    def test_pruned_snapshot_at_retain_point(self):
        log = make_log()
        log.prune(2, log.seal(2))
        # size == retain_from: empty covered segment, no entries.
        bundle = log.signed_json_search_index("/a", SEED_A, size=2)
        self.assertEqual(bundle.index.items, ())
        self.assertEqual(bundle.index.groups, ())
        self.assertEqual(bundle.find(1), ())
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )

    def test_empty_log(self):
        bundle = AuditLog().signed_json_search_index("/a", SEED_A)
        self.assertEqual(bundle.index.size, 0)
        self.assertEqual(bundle.find(1), ())
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )

    def test_later_prune_does_not_change_frozen_snapshot(self):
        log = make_log()
        bundle = log.signed_json_search_index("/a", SEED_A)
        log.prune(5, log.seal(5))
        self.assertEqual(bundle.find(1), (0, 1))
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )


class SignedJsonSearchIndexEncryptedTest(unittest.TestCase):
    def test_encrypted_entries_take_no_part(self):
        log = AuditLog()
        log.append(j({"a": 1}))
        log.encrypt(j({"a": 1}), b"k" * 32)
        bundle = log.signed_json_search_index("/a", SEED_A)
        self.assertEqual(bundle.find(1), (0,))
        self.assertEqual(bundle.find(1), log.find_json("/a", 1))
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )


class SignedJsonSearchIndexNumberSemanticsTest(unittest.TestCase):
    def _index(self, values, pointer=""):
        log = AuditLog()
        for value in values:
            log.append(j(value))
        return log.signed_json_search_index(pointer, SEED_A)

    def test_signed_zeroes_merge_across_spellings(self):
        bundle = self._index([-0.0, 0.0, 0, -0])
        self.assertEqual(bundle.find(0.0), (0, 1, 2, 3))
        self.assertEqual(bundle.find(-0.0), (0, 1, 2, 3))
        self.assertEqual(bundle.find(0), (0, 1, 2, 3))

    def test_large_integers_compare_exactly_against_floats(self):
        big = 10**40
        bundle = self._index([big, float(10**16), 10**16 + 1])
        # The huge integer has no equal float; float(10**16) is exactly the
        # integer 10**16 but not 10**16 + 1, so cross-kind equality stays
        # exact without rounding the integer side.
        self.assertEqual(bundle.find(big), (0,))
        self.assertEqual(bundle.find(10**16 + 1), (2,))
        self.assertEqual(bundle.find(float(10**16)), (1,))
        self.assertEqual(bundle.find(10**16), (1,))

    def test_negative_numbers(self):
        bundle = self._index([-3, -3.0, -2.5, -4])
        self.assertEqual(bundle.find(-3), (0, 1))
        self.assertEqual(bundle.find(-2.5), (2,))
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )

    def test_overflowing_numeric_literal_hits_no_bucket_but_verifies(self):
        log = AuditLog()
        # Python's json parses this literal to inf (RFC 8259 itself has no
        # Infinity): it can never equal a finite query and appears in no
        # bucket, but the genuine index must still verify.
        log.append(b'{"a": 1}')
        log.append(b'{"a": 1e999}')
        bundle = log.signed_json_search_index("/a", SEED_A)
        self.assertEqual(bundle.find(1), (0,))
        with self.assertRaises(ValueError):
            bundle.find(float("inf"))
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )


class SignedJsonSearchIndexSignatureTest(unittest.TestCase):
    def setUp(self):
        log = AuditLog()
        for value in (1, 1, 2):
            log.append(j({"a": value}))
        self.log = log
        self.bundle = log.signed_json_search_index("/a", SEED_A)
        self.public = public_key(SEED_A)

    def test_wrong_signer_returns_false(self):
        other = self.log.signed_json_search_index("/a", SEED_B)
        bundle = SignedJsonSearchIndex(self.bundle.index, other.signature)
        self.assertFalse(
            verify_signed_json_search_index(bundle, self.public)
        )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_json_search_index(
                self.bundle, public_key(SEED_B)
            )
        )

    def test_public_key_types(self):
        with self.assertRaises(TypeError):
            verify_signed_json_search_index(self.bundle, "not bytes")
        with self.assertRaises(ValueError):
            verify_signed_json_search_index(self.bundle, b"too-short")

    def test_non_bundle_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signed_json_search_index("not a bundle", self.public)

    def test_signature_tamper_returns_false(self):
        bad_signature = bytearray(self.bundle.signature)
        bad_signature[-1] ^= 0x01
        bundle = SignedJsonSearchIndex(
            self.bundle.index, bytes(bad_signature)
        )
        self.assertFalse(
            verify_signed_json_search_index(bundle, self.public)
        )

    def test_head_tamper_returns_false(self):
        index = self.bundle.index
        bad = JsonSearchIndex(
            index.version,
            index.hash_name,
            index.size,
            index.root,
            bytes(len(index.head)),
            index.retain_from,
            index.pointer,
            index.items,
            index.proof,
            index.groups,
        )
        bundle = SignedJsonSearchIndex(bad, self.bundle.signature)
        self.assertFalse(
            verify_signed_json_search_index(bundle, self.public)
        )


class SignedJsonSearchIndexHitSetTamperTest(unittest.TestCase):
    def setUp(self):
        log = AuditLog()
        for value in (1, 1, 2):
            log.append(j({"a": value}))
        self.index = log.signed_json_search_index("/a", SEED_A).index

    def _with_groups(self, groups):
        index = self.index
        return JsonSearchIndex(
            index.version,
            index.hash_name,
            index.size,
            index.root,
            index.head,
            index.retain_from,
            index.pointer,
            index.items,
            index.proof,
            tuple(groups),
        )

    def test_forged_hit_returns_false(self):
        group = self.index.groups[0]
        one = group.buckets[0]
        forged = (
            JsonSearchIndexGroup(
                group.kind,
                (JsonSearchIndexBucket(one.key, (0, 1, 2)),),
            ),
        )
        self.assertFalse(verify_json_search_index(self._with_groups(forged)))

    def test_concealed_hit_returns_false(self):
        group = self.index.groups[0]
        one, two = group.buckets
        concealed = (
            JsonSearchIndexGroup(
                group.kind,
                (JsonSearchIndexBucket(one.key, (0,)), two),
            ),
        )
        self.assertFalse(
            verify_json_search_index(self._with_groups(concealed))
        )

    def test_misassigned_hit_returns_false(self):
        group = self.index.groups[0]
        one, two = group.buckets
        swapped = (
            JsonSearchIndexGroup(
                group.kind,
                (
                    JsonSearchIndexBucket(one.key, (2,)),
                    JsonSearchIndexBucket(two.key, (0, 1)),
                ),
            ),
        )
        self.assertFalse(verify_json_search_index(self._with_groups(swapped)))

    def test_tampered_payload_returns_false(self):
        index = self.index
        first = index.items[0]
        tampered_payload = first.payload.replace(b"1", b"2", 1)
        items = (
            Entry(
                first.index,
                tampered_payload,
                first.previous_hash,
                first.entry_hash,
            ),
        ) + index.items[1:]
        bad = JsonSearchIndex(
            index.version,
            index.hash_name,
            index.size,
            index.root,
            index.head,
            index.retain_from,
            index.pointer,
            items,
            index.proof,
            index.groups,
        )
        self.assertFalse(verify_json_search_index(bad))

    def test_tampered_root_returns_false(self):
        index = self.index
        bad = JsonSearchIndex(
            index.version,
            index.hash_name,
            index.size,
            bytes(len(index.root)),
            index.head,
            index.retain_from,
            index.pointer,
            index.items,
            index.proof,
            index.groups,
        )
        self.assertFalse(verify_json_search_index(bad))

    def test_hits_outside_coverage_rejected(self):
        group = self.index.groups[0]
        one = group.buckets[0]
        bad_groups = (
            JsonSearchIndexGroup(
                group.kind,
                (JsonSearchIndexBucket(one.key, (0, 1, 99)),),
            ),
        )
        with self.assertRaises(ValueError):
            self._with_groups(bad_groups)

    def test_duplicate_or_unordered_group_kind_rejected(self):
        groups = self.index.groups
        with self.assertRaises(ValueError):
            JsonSearchIndex(
                self.index.version,
                self.index.hash_name,
                self.index.size,
                self.index.root,
                self.index.head,
                self.index.retain_from,
                self.index.pointer,
                self.index.items,
                self.index.proof,
                (groups[0], groups[0]),
            )


class SignedJsonSearchIndexHeadConsistencyTest(unittest.TestCase):
    """The declared chain head must match the authenticated snapshot."""

    def _with_head(self, index, head):
        return JsonSearchIndex(
            index.version,
            index.hash_name,
            index.size,
            index.root,
            head,
            index.retain_from,
            index.pointer,
            index.items,
            index.proof,
            index.groups,
        )

    def _resign(self, index, seed=SEED_A):
        # Sign the tampered index with the trusted key over the documented
        # domain-separated message (D || 0x01 || u64be(len) || blob), so
        # only the content inconsistency itself can fail verification.
        blob = encode_json_search_index(index)
        message = (
            b"auditchain/signed-json-search-index/v1\0"
            + b"\x01"
            + len(blob).to_bytes(8, "big")
            + blob
        )
        signature = Ed25519PrivateKey.from_private_bytes(seed).sign(message)
        return SignedJsonSearchIndex(index, signature)

    def test_wrong_head_fails_unsigned_verification(self):
        index = make_log().signed_json_search_index("/a", SEED_A).index
        bad = self._with_head(index, bytes([0xA5]) * len(index.head))
        self.assertFalse(verify_json_search_index(bad))

    def test_wrong_head_fails_signed_verification_with_valid_signature(self):
        index = make_log().signed_json_search_index("/a", SEED_A).index
        bad = self._with_head(index, bytes([0xA5]) * len(index.head))
        bundle = self._resign(bad)
        # The signature is genuine and from the trusted key, yet the
        # declared head contradicts the authenticated snapshot content.
        self.assertFalse(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )

    def test_wrong_head_still_constructs_and_round_trips(self):
        index = make_log().signed_json_search_index("/a", SEED_A).index
        bad = self._with_head(index, bytes([0xA5]) * len(index.head))
        blob = encode_json_search_index(bad)
        self.assertEqual(decode_json_search_index(blob), bad)
        self.assertEqual(encode_json_search_index(decode_json_search_index(blob)), blob)

    def test_head_type_and_width_errors_unchanged(self):
        index = make_log().signed_json_search_index("/a", SEED_A).index
        with self.assertRaises(TypeError):
            self._with_head(index, "not bytes")
        with self.assertRaises(ValueError):
            self._with_head(index, b"\x00")

    def test_historical_snapshot_head_is_last_covered_entry(self):
        log = make_log()
        bundle = log.signed_json_search_index("/a", SEED_A, size=4)
        index = bundle.index
        # The historical head is entry 3's hash, not the current log head.
        self.assertEqual(index.head, index.items[-1].entry_hash)
        self.assertNotEqual(index.head, log.head)
        # The frozen snapshot still verifies after appends and prunes.
        log.append(j({"a": 99}))
        log.prune(2, log.seal(2))
        public = public_key(SEED_A)
        self.assertTrue(verify_json_search_index(index))
        self.assertTrue(verify_signed_json_search_index(bundle, public))
        # A head naming the wrong record fails offline.
        bad = self._with_head(index, bytes([0xA5]) * len(index.head))
        self.assertFalse(verify_json_search_index(bad))
        self.assertFalse(
            verify_signed_json_search_index(self._resign(bad), public)
        )

    def test_pruned_log_with_retained_entries_checks_head(self):
        log = make_log()
        log.prune(2, log.seal(2))
        index = log.signed_json_search_index("/a", SEED_A).index
        self.assertEqual(index.retain_from, 2)
        self.assertEqual(index.head, index.items[-1].entry_hash)
        self.assertTrue(verify_json_search_index(index))
        bad = self._with_head(index, bytes([0xA5]) * len(index.head))
        self.assertFalse(verify_json_search_index(bad))

    def test_empty_coverage_keeps_accepting_structure(self):
        log = make_log()
        log.prune(len(log), log.seal(len(log)))
        bundle = log.signed_json_search_index("/a", SEED_A)
        index = bundle.index
        self.assertEqual(index.items, ())
        self.assertGreater(index.size, 0)
        self.assertEqual(index.retain_from, index.size)
        # No last-entry evidence remains; the empty coverage attests no
        # content and is still accepted without a head check.
        self.assertTrue(verify_json_search_index(index))
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )

    def test_empty_snapshot_requires_zero_head(self):
        bundle = AuditLog().signed_json_search_index("/a", SEED_A)
        index = bundle.index
        self.assertEqual(index.size, 0)
        self.assertEqual(index.head, bytes(len(index.head)))
        self.assertTrue(verify_json_search_index(index))
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )
        bad = self._with_head(index, bytes([0xA5]) * len(index.head))
        self.assertFalse(verify_json_search_index(bad))
        self.assertFalse(
            verify_signed_json_search_index(
                self._resign(bad), public_key(SEED_A)
            )
        )

    def test_head_consistency_other_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for value in (1, 2, 3):
            log.append(j({"a": value}))
        bundle = log.signed_json_search_index("/a", SEED_A)
        index = bundle.index
        self.assertTrue(verify_json_search_index(index))
        self.assertTrue(
            verify_signed_json_search_index(bundle, public_key(SEED_A))
        )
        bad = self._with_head(index, bytes([0xA5]) * len(index.head))
        self.assertFalse(verify_json_search_index(bad))
        self.assertFalse(
            verify_signed_json_search_index(
                self._resign(bad), public_key(SEED_A)
            )
        )
        # An empty sha512 snapshot likewise only accepts the zero head.
        empty = AuditLog(hash_name="sha512").signed_json_search_index(
            "/a", SEED_A
        ).index
        self.assertTrue(verify_json_search_index(empty))
        self.assertFalse(
            verify_json_search_index(
                self._with_head(empty, bytes([0xA5]) * len(empty.head))
            )
        )


class SignedJsonSearchIndexDeterminismTest(unittest.TestCase):
    def test_same_state_and_seed_yield_identical_bytes(self):
        log = make_log()
        first = log.signed_json_search_index("/a", SEED_A)
        second = log.signed_json_search_index("/a", SEED_A)
        self.assertEqual(
            encode_signed_json_search_index(first),
            encode_signed_json_search_index(second),
        )

    def test_decode_reencode_is_byte_identical(self):
        bundle = make_log().signed_json_search_index("/a", SEED_A)
        blob = encode_signed_json_search_index(bundle)
        decoded = decode_signed_json_search_index(blob)
        self.assertEqual(encode_signed_json_search_index(decoded), blob)
        self.assertEqual(decoded, bundle)

    def test_failed_calls_are_read_only(self):
        log = make_log()
        head = log.head
        root = log.merkle_root()
        length = len(log)
        entries = tuple(log)
        for call in (
            lambda: log.signed_json_search_index(b"/a", SEED_A),
            lambda: log.signed_json_search_index("bad", SEED_A),
            lambda: log.signed_json_search_index("/a", b"short"),
            lambda: log.signed_json_search_index("/a", SEED_A, size=99),
        ):
            with self.assertRaises((TypeError, ValueError)):
                call()
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(len(log), length)
        self.assertEqual(tuple(log), entries)


if __name__ == "__main__":
    unittest.main()
