"""Parse-attempt budget regression for the multi-pointer JSON index.

Building ``AuditLog.signed_json_multi_index`` and offline verification by
``verify_json_multi_index`` / ``verify_signed_json_multi_index`` must
strict-parse each covered *plaintext* entry at most once, no matter how
many pointers are bound. Invalid JSON still costs the one attempt;
encrypted entries never reach the parser.
"""

import json
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    JsonMultiIndex,
    JsonSearchIndexBucket,
    JsonSearchIndexGroup,
    decode_signed_json_multi_index,
    encode_signed_json_multi_index,
    verify_json_multi_index,
    verify_signed_json_multi_index,
)

SEED_A = bytes(range(1, 33))

POINTERS = ("/a", "/b/c", "/z")
# More pointers than the baseline three, still unique and ascending.
MANY_POINTERS = ("", "/a", "/b/c", "/other", "/z")


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def public_key(seed):
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


@contextmanager
def counting_json_loads():
    """Count every json.loads attempt (failures included) while active."""
    import auditchain

    original = json.loads
    attempts = {"count": 0}

    def counting_loads(text, *args, **kwargs):
        attempts["count"] += 1
        return original(text, *args, **kwargs)

    with patch.object(auditchain.json, "loads", counting_loads):
        yield attempts


def make_log():
    log = AuditLog()
    # 0: integer 1 at /a, string x at /b/c
    log.append(j({"a": 1, "b": {"c": "x"}, "arr": [10, 20]}))
    # 1: float 1.0 at /a (same JSON number as 1), y at /b/c
    log.append(j({"a": 1.0, "b": {"c": "y"}}))
    # 2: boolean true is a different kind from the number 1
    log.append(j({"a": True, "z": 3}))
    # 3: the string "1" is a different kind from the number 1
    log.append(j({"a": "1", "b": {"c": "x"}}))
    # 4: explicit null at /a, integer at /z
    log.append(j({"a": None, "z": 5}))
    # 5: payload that is not JSON at all — still one (failed) attempt
    log.append(b"not json")
    # 6: non-scalar object at /a
    log.append(j({"a": {"nested": 1}}))
    # 7: non-scalar array at /a
    log.append(j({"a": [1, 2]}))
    # 8: missing field for every bound pointer
    log.append(j({"other": 1}))
    # 9: top-level scalar document
    log.append(b"42")
    # 10: top-level string document
    log.append(b'"hello"')
    # 11: empty object
    log.append(b"{}")
    return log


class BuildParseCountTest(unittest.TestCase):
    def test_one_parse_per_plaintext_entry_regardless_of_pointers(self):
        log = make_log()
        n = len(log)
        for pointers in (("/a",), POINTERS, MANY_POINTERS):
            with counting_json_loads() as attempts:
                bundle = log.signed_json_multi_index(pointers, SEED_A)
            # Exactly one attempt per covered plaintext entry, including
            # the invalid-JSON one, never one per (entry, pointer) pair.
            self.assertEqual(
                attempts["count"],
                n,
                f"pointers={pointers}",
            )
            self.assertTrue(
                verify_signed_json_multi_index(bundle, public_key(SEED_A))
            )

    def test_encrypted_entries_are_never_parsed(self):
        log = AuditLog()
        log.append(j({"a": 1}))
        log.encrypt(j({"a": 2}), b"k" * 32)
        log.append(j({"a": 3}))
        log.encrypt(j({"a": 4}), b"k" * 32)
        log.encrypt(j({"a": 5}), b"k" * 32)
        with counting_json_loads() as attempts:
            bundle = log.signed_json_multi_index(MANY_POINTERS, SEED_A)
        self.assertEqual(attempts["count"], 2)
        self.assertEqual(bundle.find("/a", 1), (0,))
        self.assertEqual(bundle.find("/a", 3), (2,))
        self.assertTrue(
            verify_signed_json_multi_index(bundle, public_key(SEED_A))
        )

    def test_invalid_json_and_bad_utf8_each_cost_one_attempt(self):
        log = AuditLog()
        log.append(b'{"a": 1}')
        log.append(b"{not valid")
        log.append(b'{"a": 1, "a": 2}')  # repeated member
        log.append(b'{"a": \xff}')  # illegal UTF-8, fails before json.loads
        log.append(b'{"a": 1e999}')  # overflow literal
        n = len(log)
        # Four payloads reach the JSON parser; the illegal-UTF-8 one fails
        # the single UTF-8 decode instead. Either way the budget is one
        # attempt per entry and independent of the pointer count.
        for pointers in (("/a",), ("/a", "/other"), MANY_POINTERS):
            with counting_json_loads() as attempts:
                bundle = log.signed_json_multi_index(pointers, SEED_A)
            self.assertLessEqual(attempts["count"], n)
            self.assertEqual(attempts["count"], 4, f"pointers={pointers}")
            self.assertTrue(
                verify_signed_json_multi_index(bundle, public_key(SEED_A))
            )
        self.assertEqual(bundle.find("/a", 1), (0,))

    def test_empty_and_pruned_coverages_parse_nothing(self):
        log = AuditLog()
        with counting_json_loads() as attempts:
            AuditLog().signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(attempts["count"], 0)

        populated = make_log()
        populated.prune(len(populated), populated.seal(len(populated)))
        with counting_json_loads() as attempts:
            populated.signed_json_multi_index(POINTERS, SEED_A)
        self.assertEqual(attempts["count"], 0)


class VerifyParseCountTest(unittest.TestCase):
    def test_one_parse_per_plaintext_entry_regardless_of_pointers(self):
        log = make_log()
        n = len(log)
        for pointers in (("/a",), POINTERS, MANY_POINTERS):
            bundle = log.signed_json_multi_index(pointers, SEED_A)
            # A decoded artifact must verify with no log available.
            decoded = decode_signed_json_multi_index(
                encode_signed_json_multi_index(bundle)
            )
            with counting_json_loads() as unsigned_attempts:
                self.assertTrue(verify_json_multi_index(decoded.index))
            self.assertEqual(unsigned_attempts["count"], n)
            with counting_json_loads() as signed_attempts:
                self.assertTrue(
                    verify_signed_json_multi_index(
                        decoded, public_key(SEED_A)
                    )
                )
            self.assertEqual(signed_attempts["count"], n)

    def test_failed_verification_still_parses_each_entry_once(self):
        log = AuditLog()
        for value in (1, 1, 2):
            log.append(j({"a": value}))
        n = len(log)
        bundle = log.signed_json_multi_index(("/a", "/other"), SEED_A)
        index = bundle.index
        # Conceal one /a hit: structurally valid, but the recorded
        # partition no longer reproduces from the authenticated entries.
        group = index.groups[0][0]
        concealed_a = (
            JsonSearchIndexGroup(
                group.kind,
                (JsonSearchIndexBucket(group.buckets[0].key, (0,)),)
                + group.buckets[1:],
            ),
        )
        bad = JsonMultiIndex(
            index.version,
            index.hash_name,
            index.size,
            index.root,
            index.head,
            index.retain_from,
            index.pointers,
            index.items,
            index.proof,
            (concealed_a, index.groups[1]),
        )
        with counting_json_loads() as attempts:
            self.assertFalse(verify_json_multi_index(bad))
        self.assertEqual(attempts["count"], n)


class IdenticalArtifactTest(unittest.TestCase):
    def test_multi_pointer_groups_equal_single_pointer_indexes(self):
        log = make_log()
        multi = log.signed_json_multi_index(POINTERS, SEED_A)
        for position, pointer in enumerate(POINTERS):
            single = log.signed_json_search_index(pointer, SEED_A)
            self.assertEqual(
                multi.index.groups[position],
                single.index.groups,
                pointer,
            )

    def test_extra_pointers_do_not_change_shared_fields_or_bytes(self):
        log = make_log()
        three = log.signed_json_multi_index(POINTERS, SEED_A)
        five = log.signed_json_multi_index(MANY_POINTERS, SEED_A)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "head",
            "retain_from",
            "items",
            "proof",
        ):
            self.assertEqual(
                getattr(three.index, name), getattr(five.index, name), name
            )
        # The shared pointers' groups are unaffected by their neighbours.
        for pointer in POINTERS:
            self.assertEqual(
                three.find(pointer, 1), five.find(pointer, 1), pointer
            )
        # Deterministic canonical encoding and signature, twice.
        self.assertEqual(
            encode_signed_json_multi_index(five),
            encode_signed_json_multi_index(
                log.signed_json_multi_index(MANY_POINTERS, SEED_A)
            ),
        )

    def test_each_pointer_is_checked_independently(self):
        log = make_log()
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        index = bundle.index

        # Drop every hit of only the middle pointer (/b/c): signature and
        # every other pointer's groups are untouched, verification must
        # still fail.
        bad_groups = (index.groups[0], (), index.groups[2])
        bad = JsonMultiIndex(
            index.version,
            index.hash_name,
            index.size,
            index.root,
            index.head,
            index.retain_from,
            index.pointers,
            index.items,
            index.proof,
            bad_groups,
        )
        self.assertFalse(verify_json_multi_index(bad))


if __name__ == "__main__":
    unittest.main()
