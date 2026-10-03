"""Head-vs-snapshot consistency for the two JSON retrieval index verifiers.

The unsigned ``verify_json_search_index`` / ``verify_json_multi_index``
must bind the declared chain head to the authenticated snapshot: for a
non-empty coverage the last covered entry is the snapshot's last record
(absolute index ``size - 1``), an empty snapshot only fits the
digest-width zero head, while an empty coverage of a non-empty snapshot
(``retain_from == size`` after a prune) has no last-entry evidence and
keeps its structural acceptance. The two signed public verifiers
delegate to the same checks, so a genuine signature over an
internally-contradictory head still verifies False.
"""

import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    JsonMultiIndex,
    JsonSearchIndex,
    SignedJsonMultiIndex,
    SignedJsonSearchIndex,
    _signed_json_multi_index_message,
    _signed_json_search_index_message,
    decode_json_multi_index,
    decode_json_search_index,
    encode_json_multi_index,
    encode_json_search_index,
    verify_json_multi_index,
    verify_json_search_index,
    verify_signed_json_multi_index,
    verify_signed_json_search_index,
)

SEED_A = bytes(range(1, 33))
POINTERS = ("/a", "/b/c")


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def public_key(seed):
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def sign_search(index):
    signing_key = Ed25519PrivateKey.from_private_bytes(SEED_A)
    message = _signed_json_search_index_message(
        encode_json_search_index(index)
    )
    return SignedJsonSearchIndex(index, signing_key.sign(message))


def sign_multi(index):
    signing_key = Ed25519PrivateKey.from_private_bytes(SEED_A)
    message = _signed_json_multi_index_message(
        encode_json_multi_index(index)
    )
    return SignedJsonMultiIndex(index, signing_key.sign(message))


def make_log():
    log = AuditLog()
    for value in (1, 1, 2, 3, 1):
        log.append(j({"a": value, "b": {"c": value * 10}}))
    return log


def with_head(index, head):
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


def multi_with_head(index, head):
    return JsonMultiIndex(
        index.version,
        index.hash_name,
        index.size,
        index.root,
        head,
        index.retain_from,
        index.pointers,
        index.items,
        index.proof,
        index.groups,
    )


class JsonSearchIndexHeadConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.index = self.log.signed_json_search_index("/a", SEED_A).index
        self.public = public_key(SEED_A)

    def test_genuine_head_is_last_entry_digest(self):
        self.assertEqual(
            self.index.head,
            self.log.entry(len(self.log) - 1).entry_hash,
        )
        self.assertTrue(verify_json_search_index(self.index))

    def test_equal_width_wrong_head_returns_false(self):
        bad = with_head(self.index, b"\xff" * len(self.index.head))
        self.assertFalse(verify_json_search_index(bad))

    def test_wrong_head_keeps_everything_else_authentic(self):
        # Everything but the head is the genuine artifact: the entry
        # digests, the shared proof and the hit partition all still check.
        flipped = self.index.head[:-1] + bytes([self.index.head[-1] ^ 0x01])
        bad = with_head(self.index, flipped)
        self.assertFalse(verify_json_search_index(bad))

    def test_trusted_signature_over_wrong_head_still_returns_false(self):
        bad = with_head(self.index, b"\xaa" * len(self.index.head))
        bundle = sign_search(bad)
        self.assertFalse(
            verify_signed_json_search_index(bundle, self.public)
        )

    def test_wrong_head_type_is_structure_error(self):
        bypass = object.__new__(JsonSearchIndex)
        object.__setattr__(bypass, "__dict__", dict(self.index.__dict__))
        object.__setattr__(bypass, "head", "not bytes")
        with self.assertRaises(TypeError):
            verify_json_search_index(bypass)

    def test_wrong_head_width_is_structure_error(self):
        with self.assertRaises(ValueError):
            with_head(self.index, self.index.head + b"\x00")

    def test_wrong_head_still_round_trips_and_fails_after_decode(self):
        bad = with_head(self.index, b"\x01" * len(self.index.head))
        blob = encode_json_search_index(bad)
        decoded = decode_json_search_index(blob)
        self.assertEqual(encode_json_search_index(decoded), blob)
        self.assertFalse(verify_json_search_index(decoded))

    def test_verification_is_read_only(self):
        bad = with_head(self.index, b"\x01" * len(self.index.head))
        before = (bad.head, bad.root, bad.items, bad.groups, bad.proof)
        self.assertFalse(verify_json_search_index(bad))
        self.assertEqual(
            (bad.head, bad.root, bad.items, bad.groups, bad.proof), before
        )
        self.assertEqual(len(self.log), len(make_log()))


class JsonMultiIndexHeadConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.index = self.log.signed_json_multi_index(POINTERS, SEED_A).index
        self.public = public_key(SEED_A)

    def test_genuine_head_is_last_entry_digest(self):
        self.assertEqual(
            self.index.head,
            self.log.entry(len(self.log) - 1).entry_hash,
        )
        self.assertTrue(verify_json_multi_index(self.index))

    def test_equal_width_wrong_head_returns_false(self):
        bad = multi_with_head(self.index, b"\xff" * len(self.index.head))
        self.assertFalse(verify_json_multi_index(bad))

    def test_trusted_signature_over_wrong_head_still_returns_false(self):
        bad = multi_with_head(self.index, b"\xaa" * len(self.index.head))
        bundle = sign_multi(bad)
        self.assertFalse(
            verify_signed_json_multi_index(bundle, self.public)
        )

    def test_wrong_head_type_is_structure_error(self):
        bypass = object.__new__(JsonMultiIndex)
        object.__setattr__(bypass, "__dict__", dict(self.index.__dict__))
        object.__setattr__(bypass, "head", 42)
        with self.assertRaises(TypeError):
            verify_json_multi_index(bypass)

    def test_wrong_head_still_round_trips_and_fails_after_decode(self):
        bad = multi_with_head(self.index, b"\x01" * len(self.index.head))
        blob = encode_json_multi_index(bad)
        decoded = decode_json_multi_index(blob)
        self.assertEqual(encode_json_multi_index(decoded), blob)
        self.assertFalse(verify_json_multi_index(decoded))


class HistoricalSnapshotHeadTest(unittest.TestCase):
    def setUp(self):
        self.public = public_key(SEED_A)

    def test_historical_head_is_not_current_head(self):
        log = make_log()
        bundle = log.signed_json_search_index("/a", SEED_A, size=3)
        index = bundle.index
        self.assertEqual(index.size, 3)
        self.assertEqual(index.head, log.entry(2).entry_hash)
        self.assertNotEqual(index.head, log.head)
        self.assertTrue(
            verify_signed_json_search_index(bundle, self.public)
        )

    def test_replacing_historical_head_with_current_head_fails(self):
        log = make_log()
        index = log.signed_json_search_index("/a", SEED_A, size=3).index
        # The current chain head is an equal-width digest, but it is not
        # the head of the frozen historical snapshot.
        bad = with_head(index, log.head)
        self.assertFalse(verify_json_search_index(bad))

    def test_historical_multi_index_head_mismatch_fails(self):
        log = make_log()
        index = log.signed_json_multi_index(POINTERS, SEED_A, size=3).index
        bad = multi_with_head(index, log.head)
        self.assertFalse(verify_json_multi_index(bad))
        self.assertTrue(verify_json_multi_index(index))

    def test_historical_snapshot_verifies_after_later_appends_and_prune(self):
        log = make_log()
        bundle = log.signed_json_search_index("/a", SEED_A, size=3)
        # The log grows beyond the frozen snapshot.
        log.append(j({"a": 9}))
        log.append(j({"a": 9}))
        self.assertTrue(
            verify_signed_json_search_index(bundle, self.public)
        )
        self.assertTrue(verify_json_search_index(bundle.index))
        # A later prune of the issuing log must not affect the artifact:
        # the receiver holds only the sealed index.
        log.prune(5, log.seal(5))
        self.assertEqual(
            bundle.index.head,
            make_log().entry(2).entry_hash,
        )
        self.assertTrue(
            verify_signed_json_search_index(bundle, self.public)
        )
        self.assertEqual(bundle.find(1), (0, 1))


class PrunedRetainedSegmentHeadTest(unittest.TestCase):
    def setUp(self):
        self.public = public_key(SEED_A)

    def _pruned_log(self):
        log = make_log()
        log.prune(2, log.seal(2))
        return log

    def test_retained_segment_head_is_last_retained_entry(self):
        log = self._pruned_log()
        bundle = log.signed_json_search_index("/a", SEED_A)
        index = bundle.index
        self.assertEqual(index.retain_from, 2)
        self.assertEqual(index.size, len(log))
        self.assertTrue(index.items)
        self.assertEqual(
            index.head, index.items[-1].entry_hash
        )
        self.assertEqual(index.head, log.head)
        self.assertTrue(
            verify_signed_json_search_index(bundle, self.public)
        )

    def test_retained_segment_head_tamper_fails(self):
        log = self._pruned_log()
        index = log.signed_json_search_index("/a", SEED_A).index
        bad = with_head(index, b"\x01" * len(index.head))
        self.assertFalse(verify_json_search_index(bad))
        self.assertFalse(
            verify_signed_json_search_index(sign_search(bad), self.public)
        )

    def test_pruned_multi_segment_head_tamper_fails(self):
        log = self._pruned_log()
        index = log.signed_json_multi_index(POINTERS, SEED_A).index
        bad = multi_with_head(index, b"\x02" * len(index.head))
        self.assertFalse(verify_json_multi_index(bad))


class EmptySnapshotHeadTest(unittest.TestCase):
    def setUp(self):
        self.public = public_key(SEED_A)

    def test_empty_snapshot_requires_zero_head(self):
        bundle = AuditLog().signed_json_search_index("/a", SEED_A)
        index = bundle.index
        self.assertEqual(index.size, 0)
        self.assertEqual(index.head, bytes(len(index.head)))
        self.assertTrue(verify_json_search_index(index))
        self.assertTrue(
            verify_signed_json_search_index(bundle, self.public)
        )

    def test_empty_snapshot_nonzero_head_fails(self):
        index = AuditLog().signed_json_search_index("/a", SEED_A).index
        bad = with_head(index, b"\x01" * len(index.head))
        self.assertFalse(verify_json_search_index(bad))
        self.assertFalse(
            verify_signed_json_search_index(sign_search(bad), self.public)
        )

    def test_empty_multi_snapshot_nonzero_head_fails(self):
        index = AuditLog().signed_json_multi_index(POINTERS, SEED_A).index
        bad = multi_with_head(index, b"\x01" * len(index.head))
        self.assertFalse(verify_json_multi_index(bad))
        self.assertFalse(
            verify_signed_json_multi_index(sign_multi(bad), self.public)
        )

    def test_zero_head_with_bad_root_still_fails(self):
        index = AuditLog().signed_json_search_index("/a", SEED_A).index
        bad = JsonSearchIndex(
            index.version,
            index.hash_name,
            index.size,
            b"\x01" * len(index.root),
            bytes(len(index.head)),
            index.retain_from,
            index.pointer,
            index.items,
            index.proof,
            index.groups,
        )
        self.assertFalse(verify_json_search_index(bad))


class EmptyCoverageAfterPruneHeadTest(unittest.TestCase):
    def setUp(self):
        self.public = public_key(SEED_A)
        log = make_log()
        log.prune(2, log.seal(2))
        self.log = log
        # size == retain_from: an empty coverage of a non-empty snapshot;
        # the artifact carries no last-entry evidence.
        self.index = log.signed_json_search_index(
            "/a", SEED_A, size=2
        ).index
        self.multi_index = log.signed_json_multi_index(
            POINTERS, SEED_A, size=2
        ).index

    def test_empty_coverage_is_structurally_accepted_unsigned(self):
        self.assertEqual(self.index.items, ())
        self.assertEqual(self.index.size, 2)
        self.assertEqual(self.index.retain_from, 2)
        self.assertTrue(verify_json_search_index(self.index))
        self.assertTrue(verify_json_multi_index(self.multi_index))

    def test_arbitrary_equal_width_head_is_accepted_without_evidence(self):
        bad = with_head(self.index, b"\xcd" * len(self.index.head))
        self.assertTrue(verify_json_search_index(bad))
        bad_multi = multi_with_head(
            self.multi_index, b"\xcd" * len(self.multi_index.head)
        )
        self.assertTrue(verify_json_multi_index(bad_multi))

    def test_arbitrary_head_signed_by_trusted_key_is_accepted(self):
        # No determinable content contradiction: the released entries
        # cannot be reconstructed, so a genuinely sealed arbitrary head
        # passes exactly like the root-less empty coverage always did.
        bundle = sign_search(
            with_head(self.index, b"\xcd" * len(self.index.head))
        )
        self.assertTrue(
            verify_signed_json_search_index(bundle, self.public)
        )
        multi_bundle = sign_multi(
            multi_with_head(
                self.multi_index, b"\xcd" * len(self.multi_index.head)
            )
        )
        self.assertTrue(
            verify_signed_json_multi_index(multi_bundle, self.public)
        )


class Sha512HeadConsistencyTest(unittest.TestCase):
    def test_fixed_width_algorithms_other_than_sha256(self):
        for hash_name, width in (("sha512", 64), ("sha224", 28), ("sha384", 48)):
            with self.subTest(hash_name=hash_name):
                log = AuditLog(hash_name=hash_name)
                log.append(j({"a": 1}))
                log.append(j({"a": 2}))
                index = log.signed_json_search_index("/a", SEED_A).index
                self.assertEqual(len(index.head), width)
                self.assertEqual(
                    index.head, log.entry(len(log) - 1).entry_hash
                )
                self.assertTrue(verify_json_search_index(index))
                bad = with_head(index, b"\x01" * width)
                self.assertFalse(verify_json_search_index(bad))
                empty = AuditLog(hash_name=hash_name).signed_json_search_index(
                    "/a", SEED_A
                ).index
                self.assertTrue(verify_json_search_index(empty))
                self.assertFalse(
                    verify_json_search_index(with_head(empty, b"\x01" * width))
                )


if __name__ == "__main__":
    unittest.main()
