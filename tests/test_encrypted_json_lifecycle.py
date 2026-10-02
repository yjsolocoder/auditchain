"""Lifecycle regression tests for encrypted JSON search across pruning and
secure-pruned log restoration.

One fixed history is driven through the whole path

    append/encrypt -> seal -> prune -> dump_secure_pruned/load_secure_pruned
    -> append/encrypt -> seal -> prune -> dump_secure_pruned/load_secure_pruned
    -> append/encrypt

and at every stage the absolute-index hit sets of ``find_encrypted_json`` and
the complete encrypted JSON search receipts are checked against predetermined
indices (never against another search function). The history deliberately
mixes plaintext JSON entries, ciphertexts sealed under different keys,
duplicate hits and malformed JSON, and keeps a non-power-of-two entry count.
Logs here never use authentication, matching ``dump_secure_pruned``.
"""

import dataclasses
import json
import unittest

from auditchain import (
    AuditLog,
    decode_full_encrypted_json_search_receipt,
    dump_secure_pruned,
    encode_full_encrypted_json_search_receipt,
    load_secure_pruned,
    verify_full_encrypted_json_search_receipt,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
THIRD_KEY = bytes(reversed(range(32)))
SEED = bytes(range(2, 34))

PUB = (
    Ed25519PrivateKey.from_private_bytes(SEED)
    .public_key()
    .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
)


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def nonce(i):
    """A deterministic, per-absolute-index 12-byte nonce (each value unique)."""
    return bytes([i + 1]) * 12


def build_initial(log):
    """Lay down the fixed 11-entry (non-power-of-two) history.

    Absolute indices are fixed and referenced literally by the tests:

    0: KEY {"a": 1}            hit for /a == 1
    1: KEY {"a": 1.0}          hit, numbers compare by numeric value
    2: KEY {"a": true}         boolean kind, never a hit for 1
    3: plaintext {"a": 1}      plain entry, never an encrypted-search hit
    4: OTHER_KEY {"a": 1}      hit only under OTHER_KEY
    5: KEY b"{not json"        malformed JSON, never a hit
    6: KEY {"a": 1, "b": 2}    duplicate hit under KEY
    7: KEY {"a": "1"}          string kind, never a hit for 1
    8: KEY {"other": 1}        missing field, never a hit
    9: OTHER_KEY {"a": 1.0}    hit only under OTHER_KEY
    10: KEY {"a": 1}           trailing hit
    """
    log.encrypt(j({"a": 1}), KEY, nonce=nonce(0))
    log.encrypt(j({"a": 1.0}), KEY, nonce=nonce(1))
    log.encrypt(j({"a": True}), KEY, nonce=nonce(2))
    log.append(j({"a": 1}))
    log.encrypt(j({"a": 1}), OTHER_KEY, nonce=nonce(3))
    log.encrypt(b"{not json", KEY, nonce=nonce(4))
    log.encrypt(j({"a": 1, "b": 2}), KEY, nonce=nonce(5))
    log.encrypt(j({"a": "1"}), KEY, nonce=nonce(6))
    log.encrypt(j({"other": 1}), KEY, nonce=nonce(7))
    log.encrypt(j({"a": 1.0}), OTHER_KEY, nonce=nonce(8))
    log.encrypt(j({"a": 1}), KEY, nonce=nonce(9))
    return log


def restore(log):
    return load_secure_pruned(dump_secure_pruned(log, SEED), PUB)


def issue(log, *args, **kwargs):
    return log.full_encrypted_json_search_receipt("/a", 1, KEY, *args, **kwargs)


def verify(receipt, key=KEY):
    return verify_full_encrypted_json_search_receipt(receipt, key)


def observable_state(log):
    return (
        len(log),
        log.retain_from,
        log.head,
        log.merkle_root(),
        tuple(log.entries()),
        log.hash_name,
    )


class EncryptedJsonLifecycleTest(unittest.TestCase):
    def _run(self, hash_name):
        log = AuditLog(hash_name=hash_name)
        build_initial(log)

        # ---- Phase A: the full unpruned 11-entry history ------------------
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY), (0, 1, 6, 10))
        # int and float queries match numerically identical JSON numbers...
        self.assertEqual(log.find_encrypted_json("/a", 1.0, KEY), (0, 1, 6, 10))
        # ...while booleans are a separate JSON kind.
        self.assertEqual(log.find_encrypted_json("/a", True, KEY), (2,))
        self.assertEqual(log.find_encrypted_json("/a", False, KEY), ())
        # A different append key isolates its own entries.
        self.assertEqual(log.find_encrypted_json("/a", 1, OTHER_KEY), (4, 9))
        # The plaintext entry at index 3 is visible to plain find_json only.
        self.assertEqual(log.find_json("/a", 1), (3,))
        # Half-open explicit ranges over absolute indices.
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY, 1, 7), (1, 6))
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY, 7, 11), (10,))
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY, 0, 3), (0, 1))
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY, 5, 6), ())
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY, 11, 11), ())

        # A receipt bound to the size-11 snapshot; saved long before its
        # entries are pruned away.
        old_receipt = issue(log, 0, 11)
        self.assertEqual(old_receipt.hits, (0, 1, 6, 10))
        self.assertEqual(
            [entry.index for entry in old_receipt.items], list(range(11))
        )
        self.assertTrue(verify(old_receipt))
        self.assertFalse(verify(old_receipt, OTHER_KEY))
        old_receipt_bytes = encode_full_encrypted_json_search_receipt(old_receipt)

        # ---- Phase B: seal and prune away indices 0..2 --------------------
        log.prune(3, log.seal(3))
        self.assertEqual(log.retain_from, 3)
        # Default range covers only the retained segment; absolute indices of
        # the released hits 0 and 1 never reappear.
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY), (6, 10))
        self.assertEqual(
            log.find_encrypted_json("/a", 1, KEY, 6, 9), (6,)
        )
        self.assertEqual(
            log.find_encrypted_json("/a", 1, KEY, 10, 11), (10,)
        )
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY, 3, 6), ())
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY, 6, 6), ())

        default_before = issue(log)
        self.assertEqual((default_before.start, default_before.stop), (3, 11))
        self.assertEqual(
            [entry.index for entry in default_before.items], list(range(3, 11))
        )
        self.assertEqual(default_before.hits, (6, 10))
        explicit_before = issue(log, 7, 11)
        self.assertEqual(explicit_before.hits, (10,))
        nohits_before = issue(log, 7, 10)
        self.assertEqual(nohits_before.hits, ())
        self.assertTrue(nohits_before.proof)  # items carried, simply no match
        empty_before = issue(log, 6, 6)
        self.assertEqual((empty_before.items, empty_before.proof,
                          empty_before.hits), ((), (), ()))
        third_before = log.full_encrypted_json_search_receipt(
            "/a", 1, THIRD_KEY
        )
        self.assertEqual(third_before.hits, ())
        for receipt, key in (
            (default_before, KEY),
            (explicit_before, KEY),
            (nohits_before, KEY),
            (empty_before, KEY),
            (third_before, THIRD_KEY),
        ):
            self.assertTrue(verify(receipt, key))
        before_bytes = tuple(
            encode_full_encrypted_json_search_receipt(r)
            for r in (default_before, explicit_before, nohits_before,
                      empty_before, third_before)
        )

        # ---- Phase C: restore into an independent log ---------------------
        restored = restore(log)
        self.assertIsInstance(restored, AuditLog)
        self.assertEqual(observable_state(restored), observable_state(log))
        self.assertEqual(restored.find_encrypted_json("/a", 1, KEY), (6, 10))
        self.assertTrue(restored.verify())
        # The nonce history includes nonces of ciphertexts released by the
        # prune (entry 0 used nonce(0)).
        for used in (nonce(0), nonce(9)):
            with self.assertRaises(ValueError):
                restored.encrypt(j({"a": 1}), KEY, nonce=used)

        # Same query, range and snapshot re-issued on either side of the
        # restore compare field-equal with identical encoded bytes.
        default_after = issue(restored)
        explicit_after = issue(restored, 7, 11)
        nohits_after = issue(restored, 7, 10)
        empty_after = issue(restored, 6, 6)
        third_after = restored.full_encrypted_json_search_receipt(
            "/a", 1, THIRD_KEY
        )
        after = (default_after, explicit_after, nohits_after, empty_after,
                 third_after)
        after_bytes = tuple(
            encode_full_encrypted_json_search_receipt(r) for r in after
        )
        before = (default_before, explicit_before, nohits_before,
                  empty_before, third_before)
        for issued_after, issued_before in zip(after, before):
            self.assertEqual(issued_after, issued_before)
        self.assertEqual(after_bytes, before_bytes)
        for blob in after_bytes:
            decoded = decode_full_encrypted_json_search_receipt(blob)
            self.assertEqual(
                encode_full_encrypted_json_search_receipt(decoded), blob
            )
        self.assertTrue(verify(default_after))
        self.assertFalse(verify(default_after, THIRD_KEY))
        self.assertTrue(verify(third_after, THIRD_KEY))
        self.assertFalse(verify(third_after, KEY))

        # ---- Phase D: append to the restored log --------------------------
        restored.encrypt(j({"a": 1}), KEY, nonce=nonce(11))      # 11 hit
        restored.encrypt(j({"a": True}), KEY, nonce=nonce(12))   # 12 boolean
        restored.append(j({"a": 1}))                             # 13 plain
        restored.encrypt(j({"a": 1.0}), KEY, nonce=nonce(14))    # 14 hit
        self.assertEqual(len(restored), 15)
        self.assertTrue(restored.verify())
        self.assertEqual(
            restored.find_encrypted_json("/a", 1, KEY), (6, 10, 11, 14)
        )
        self.assertEqual(restored.find_encrypted_json("/a", True, KEY), (12,))
        # Index 4 (OTHER_KEY) is still in the retained segment 3..14.
        self.assertEqual(restored.find_encrypted_json("/a", 1, OTHER_KEY), (4, 9))
        # Plaintext indices 3 (still retained) and 13 are visible to
        # find_json, never to the encrypted search.
        self.assertEqual(restored.find_json("/a", 1), (3, 13))
        self.assertEqual(
            restored.find_encrypted_json("/a", 1, KEY, 10, 14), (10, 11)
        )
        self.assertEqual(
            restored.find_encrypted_json("/a", 1, KEY, 11, 15), (11, 14)
        )
        self.assertEqual(
            restored.find_encrypted_json("/a", 1, KEY, 14, 15), (14,)
        )
        mid_receipt = issue(restored)
        self.assertEqual((mid_receipt.start, mid_receipt.stop), (3, 15))
        self.assertEqual(mid_receipt.hits, (6, 10, 11, 14))
        self.assertTrue(verify(mid_receipt))
        # The original size-11 snapshot is still rebuildable and still binds
        # the same evidence; later appends change neither fields nor bytes.
        self.assertTrue(verify(old_receipt))
        self.assertEqual(
            encode_full_encrypted_json_search_receipt(old_receipt),
            old_receipt_bytes,
        )
        self.assertEqual(
            decode_full_encrypted_json_search_receipt(old_receipt_bytes),
            old_receipt,
        )

        # ---- Phase E: prune again, past every original ciphertext ---------
        restored.prune(12, restored.seal(12))
        self.assertEqual((len(restored), restored.retain_from), (15, 12))
        self.assertEqual(
            [entry.index for entry in restored.entries()], [12, 13, 14]
        )
        self.assertEqual(restored.find_encrypted_json("/a", 1, KEY), (14,))
        # Absolute indices are never reordered by pruning.
        self.assertEqual(
            restored.find_encrypted_json("/a", 1, KEY, 12, 15), (14,)
        )
        # Receipts saved before this prune remain independently verifiable
        # offline even though their entries are gone from the log.
        self.assertTrue(verify(mid_receipt))
        self.assertTrue(verify(old_receipt))

        tail_before = issue(restored, 12, 15)
        self.assertEqual(tail_before.hits, (14,))
        tail_before_bytes = encode_full_encrypted_json_search_receipt(
            tail_before
        )
        restored2 = restore(restored)
        self.assertEqual(observable_state(restored2), observable_state(restored))
        self.assertEqual(
            restored2.find_encrypted_json("/a", 1, KEY), (14,)
        )
        tail_after = issue(restored2, 12, 15)
        self.assertEqual(tail_after, tail_before)
        self.assertEqual(
            encode_full_encrypted_json_search_receipt(tail_after),
            tail_before_bytes,
        )
        self.assertTrue(verify(tail_after))

        # ---- Phase F: append to the twice-restored log --------------------
        restored2.encrypt(j({"a": 1}), OTHER_KEY, nonce=nonce(15))  # 15
        restored2.encrypt(j({"a": 1}), KEY, nonce=nonce(16))        # 16
        self.assertTrue(restored2.verify())
        self.assertEqual(
            [entry.index for entry in restored2.entries()],
            [12, 13, 14, 15, 16],
        )
        self.assertEqual(
            restored2.find_encrypted_json("/a", 1, KEY), (14, 16)
        )
        self.assertEqual(
            restored2.find_encrypted_json("/a", 1, OTHER_KEY), (15,)
        )
        self.assertEqual(
            restored2.find_encrypted_json("/a", 1, KEY, 12, 17), (14, 16)
        )
        final_receipt = issue(restored2)
        self.assertEqual((final_receipt.start, final_receipt.stop), (12, 17))
        self.assertEqual(
            [entry.index for entry in final_receipt.items],
            [12, 13, 14, 15, 16],
        )
        self.assertEqual(final_receipt.hits, (14, 16))
        self.assertTrue(verify(final_receipt))
        self.assertFalse(verify(final_receipt, OTHER_KEY))
        other_final = restored2.full_encrypted_json_search_receipt(
            "/a", 1, OTHER_KEY
        )
        self.assertEqual(other_final.hits, (15,))
        self.assertTrue(verify(other_final, OTHER_KEY))
        # All earlier evidence survives the whole journey unchanged.
        self.assertTrue(verify(mid_receipt))
        self.assertTrue(verify(old_receipt))
        self.assertEqual(
            encode_full_encrypted_json_search_receipt(old_receipt),
            old_receipt_bytes,
        )

    def test_sha256_lifecycle(self):
        self._run("sha256")

    def test_sha512_lifecycle(self):
        self._run("sha512")


class EncryptedJsonPrunedBoundaryTest(unittest.TestCase):
    """Failure boundaries pinned on a restored log retained from index 3."""

    def setUp(self):
        log = AuditLog()
        build_initial(log)
        log.prune(3, log.seal(3))
        self.log = restore(log)

    def test_range_or_snapshot_before_retain_point_rejected(self):
        with self.assertRaises(ValueError):
            self.log.find_encrypted_json("/a", 1, KEY, 0)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_json("/a", 1, KEY, 2, 4)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_json("/a", 1, KEY, -1)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_json("/a", 1, KEY, 3, 12)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_json("/a", 1, KEY, 5, 4)
        with self.assertRaises(ValueError):
            issue(self.log, 0, 4)
        with self.assertRaises(ValueError):
            issue(self.log, 3, 12)
        with self.assertRaises(ValueError):
            issue(self.log, 5, 4)
        # Snapshot requests at or below the retain point cannot rebuild.
        with self.assertRaises(ValueError):
            issue(self.log, size=2)
        with self.assertRaises(ValueError):
            self.log.seal(2)

    def test_interval_bound_type_errors(self):
        for bad in ("3", 1.5, True, b"3"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.log.find_encrypted_json("/a", 1, KEY, bad)
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.log.find_encrypted_json("/a", 1, KEY, 3, bad)
            with self.assertRaises(TypeError, msg=repr(bad)):
                issue(self.log, bad, 11)
            with self.assertRaises(TypeError, msg=repr(bad)):
                issue(self.log, 3, bad)
            with self.assertRaises(TypeError, msg=repr(bad)):
                issue(self.log, size=bad)

    def test_legal_but_unused_key_finds_nothing(self):
        result = self.log.find_encrypted_json("/a", 1, THIRD_KEY)
        self.assertEqual(result, ())
        self.assertIsInstance(result, tuple)

    def test_wrong_legal_key_fails_hit_zero_hit_and_empty_receipts(self):
        hit_receipt = issue(self.log)
        self.assertEqual(hit_receipt.hits, (6, 10))
        self.assertTrue(verify(hit_receipt))
        self.assertFalse(verify(hit_receipt, OTHER_KEY))
        self.assertFalse(verify(hit_receipt, THIRD_KEY))

        zero_receipt = self.log.full_encrypted_json_search_receipt(
            "/a", 1, THIRD_KEY
        )
        self.assertEqual(zero_receipt.hits, ())
        self.assertTrue(verify(zero_receipt, THIRD_KEY))
        # A legitimate-but-wrong key cannot confirm even an empty result.
        self.assertFalse(verify(zero_receipt, KEY))

        # Range with entries but no matches.
        covered_empty = issue(self.log, 7, 10)
        self.assertEqual(covered_empty.hits, ())
        self.assertTrue(verify(covered_empty, KEY))
        self.assertFalse(verify(covered_empty, OTHER_KEY))

        # Fully empty range.
        empty_receipt = issue(self.log, 6, 6)
        self.assertTrue(verify(empty_receipt, KEY))
        self.assertFalse(verify(empty_receipt, OTHER_KEY))


class EncryptedJsonReceiptTamperTest(unittest.TestCase):
    def test_changed_same_length_confirmation_roundtrips_but_fails(self):
        log = AuditLog()
        build_initial(log)
        log.prune(3, log.seal(3))
        restored = restore(log)
        receipt = issue(restored)
        flipped = bytes(b ^ 0xFF for b in receipt.confirmation)
        self.assertEqual(len(flipped), len(receipt.confirmation))
        self.assertNotEqual(flipped, receipt.confirmation)
        forged = dataclasses.replace(receipt, confirmation=flipped)
        encoded = encode_full_encrypted_json_search_receipt(forged)
        # Codec succeeds: structural validity is independent of verification.
        decoded = decode_full_encrypted_json_search_receipt(encoded)
        self.assertEqual(decoded, forged)
        self.assertEqual(
            encode_full_encrypted_json_search_receipt(decoded), encoded
        )
        self.assertFalse(verify(decoded, KEY))
        self.assertFalse(verify(decoded, THIRD_KEY))
        # The untouched receipt still verifies.
        self.assertTrue(verify(receipt, KEY))


class EncryptedJsonNonceReuseAtomicityTest(unittest.TestCase):
    def test_reused_pruned_nonce_rejected_without_state_change(self):
        log = AuditLog()
        build_initial(log)
        log.prune(3, log.seal(3))
        restored = restore(log)

        before = observable_state(restored)
        hits_before = restored.find_encrypted_json("/a", 1, KEY)
        self.assertEqual(hits_before, (6, 10))

        # nonce(0) sealed the pruned ciphertext at index 0; nonce(5) seals the
        # retained index 6. Both must stay blocked after restoration.
        for reused in (nonce(0), nonce(5)):
            with self.assertRaises(ValueError, msg=reused):
                restored.encrypt(j({"a": 1}), KEY, nonce=reused)
            self.assertEqual(observable_state(restored), before)
            self.assertEqual(
                restored.find_encrypted_json("/a", 1, KEY), hits_before
            )
            self.assertTrue(restored.verify())

        # A genuinely fresh nonce still appends on an independent copy.
        follower = restore(log)
        follower.encrypt(j({"a": 1}), KEY, nonce=b"z" * 12)
        self.assertTrue(follower.verify())
        self.assertEqual(
            follower.find_encrypted_json("/a", 1, KEY), (6, 10, 11)
        )


class EncryptedJsonReadOnlyTest(unittest.TestCase):
    def test_repeated_queries_and_issuance_change_nothing(self):
        log = AuditLog()
        build_initial(log)
        log.prune(3, log.seal(3))
        restored = restore(log)

        def round():
            self.assertEqual(
                restored.find_encrypted_json("/a", 1, KEY), (6, 10)
            )
            self.assertEqual(
                restored.find_encrypted_json("/a", 1, KEY, 7, 11), (10,)
            )
            self.assertEqual(
                restored.find_encrypted_json("/a", 1, THIRD_KEY), ()
            )
            receipt = issue(restored)
            encoded = encode_full_encrypted_json_search_receipt(receipt)
            decoded = decode_full_encrypted_json_search_receipt(encoded)
            self.assertEqual(decoded, receipt)
            self.assertTrue(verify(decoded, KEY))
            # Failing lookups are read-only too.
            with self.assertRaises(ValueError):
                restored.find_encrypted_json("/a", 1, KEY, 0)
            with self.assertRaises(TypeError):
                issue(restored, "3", 11)
            with self.assertRaises(ValueError):
                issue(restored, size=0)
            return encoded

        snapshot = observable_state(restored)
        first_bytes = round()
        self.assertEqual(observable_state(restored), snapshot)
        second_bytes = round()
        self.assertEqual(observable_state(restored), snapshot)
        self.assertEqual(second_bytes, first_bytes)
        self.assertEqual(dump_secure_pruned(restored, SEED),
                         dump_secure_pruned(restore(log), SEED))


class EncryptedJsonRestoreIndependenceTest(unittest.TestCase):
    def test_appends_to_restored_copy_leave_source_untouched(self):
        log = AuditLog()
        build_initial(log)
        log.prune(3, log.seal(3))
        source_state = observable_state(log)
        data = dump_secure_pruned(log, SEED)
        restored = load_secure_pruned(data, PUB)

        restored.encrypt(j({"a": 1}), KEY, nonce=nonce(11))
        restored.encrypt(j({"a": True}), KEY, nonce=nonce(12))
        restored.append(j({"a": 1}))
        restored.encrypt(j({"a": 1.0}), KEY, nonce=nonce(14))
        restored.prune(12, restored.seal(12))
        restored2 = load_secure_pruned(
            dump_secure_pruned(restored, SEED), PUB
        )
        restored2.encrypt(j({"a": 1}), OTHER_KEY, nonce=nonce(15))
        restored2.encrypt(j({"a": 1}), KEY, nonce=nonce(16))

        self.assertEqual(observable_state(log), source_state)
        self.assertEqual(len(log), 11)
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY), (6, 10))
        self.assertEqual(restored2.find_encrypted_json("/a", 1, KEY), (14, 16))
        self.assertEqual(
            restored2.find_encrypted_json("/a", 1, OTHER_KEY), (15,)
        )
        self.assertTrue(log.verify())
        self.assertTrue(restored2.verify())


class FullyPrunedReappendTest(unittest.TestCase):
    def _run(self, hash_name):
        log = AuditLog(hash_name=hash_name)
        log.encrypt(j({"a": 1}), KEY, nonce=b"p0" * 6)       # 0 hit
        log.append(j({"a": 1}))                               # 1 plain
        log.encrypt(j({"a": 1}), OTHER_KEY, nonce=b"p1" * 6)  # 2 other
        log.encrypt(b"{bad", KEY, nonce=b"p2" * 6)            # 3 bad json
        log.encrypt(j({"a": 1}), KEY, nonce=b"p3" * 6)        # 4 hit
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY), (0, 4))
        old_receipt = issue(log, 0, 5)
        self.assertEqual(old_receipt.hits, (0, 4))
        self.assertTrue(verify(old_receipt))
        old_bytes = encode_full_encrypted_json_search_receipt(old_receipt)

        # Retain nothing but the checkpoint.
        log.prune(5, log.seal(5))
        self.assertEqual(log.entries(), [])
        restored = restore(log)
        self.assertEqual((len(restored), restored.retain_from), (5, 5))
        self.assertEqual(restored.entries(), [])
        self.assertEqual(restored.find_encrypted_json("/a", 1, KEY), ())
        empty = issue(restored)
        self.assertEqual((empty.start, empty.stop), (5, 5))
        self.assertEqual((empty.items, empty.proof, empty.hits), ((), (), ()))
        self.assertTrue(verify(empty, KEY))

        # Reusing a nonce of a fully released ciphertext is still rejected,
        # with length, head, root and queries unchanged after the failure.
        before = observable_state(restored)
        with self.assertRaises(ValueError):
            restored.encrypt(j({"a": 1}), KEY, nonce=b"p0" * 6)
        self.assertEqual(observable_state(restored), before)
        self.assertEqual(restored.find_encrypted_json("/a", 1, KEY), ())

        # Re-append after a full prune.
        restored.encrypt(j({"a": 1}), KEY, nonce=b"p4" * 6)  # 5 hit
        restored.append(j({"a": 1}))                          # 6 plain
        self.assertTrue(restored.verify())
        self.assertEqual(restored.find_encrypted_json("/a", 1, KEY), (5,))
        self.assertEqual(restored.find_encrypted_json("/a", 1, OTHER_KEY), ())
        self.assertEqual(restored.find_json("/a", 1), (6,))
        new_receipt = issue(restored)
        self.assertEqual((new_receipt.start, new_receipt.stop), (5, 7))
        self.assertEqual(new_receipt.hits, (5,))
        self.assertTrue(verify(new_receipt, KEY))
        self.assertFalse(verify(new_receipt, OTHER_KEY))
        # Old evidence remains independently valid against the old snapshot.
        self.assertTrue(verify(old_receipt, KEY))
        self.assertEqual(
            encode_full_encrypted_json_search_receipt(old_receipt), old_bytes
        )

    def test_sha256_full_prune_then_reappend(self):
        self._run("sha256")

    def test_sha512_full_prune_then_reappend(self):
        self._run("sha512")


if __name__ == "__main__":
    unittest.main()
