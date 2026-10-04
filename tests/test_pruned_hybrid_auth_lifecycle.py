"""End-to-end authentication lifecycle regression tests across repeated
pruning and encrypted pruned-hybrid state recovery.

One scenario runs per supported hash (sha256, sha512) and drives a single
keyed :class:`AuditLog` holding a mix of plaintext and encrypted entries
through:

* forward-secure authentication with ``auth`` / ``auth_batch`` /
  ``rotate_key`` and delivery-point ``StageVerifier`` exports,
* prefix pruning, including one prune that releases every retained entry,
* ``dump_pruned_hybrid`` / ``load_pruned_hybrid`` round trips (twice),
* failed batch issuances interleaved between the two restorations,

asserting through the public surface only:

* cumulative absolute indexing and the exact stage of every issued tag,
* batch results in ascending absolute-index order and an empty batch
  returning an empty tuple without advancing the stage,
* stage verification material being repeatable/equal and only valid from
  its delivery stage onward, while the original stage-0 ``Verifier``
  continues to verify every legitimate tag, including tags for entries
  whose records have since been pruned,
* failure atomicity: a rejected batch (bool member, duplicate index, or
  pruned index) consumes no evolution, so the next legal issuance produces
  the tag originally expected at that stage,
* restorations not re-requiring historical tags (the export carries none),
* restored objects being independent of the originals,
* authentication and its failures never changing existing entries, the
  chain head, Merkle roots or the retained search results.

The expected tag bytes are recomputed here independently from the
README-documented HMAC construction (``HMAC(K, b"auditchain/auth/v1" ||
u64(stage) || entry_hash)`` with ``K`` evolved per
``H(b"auditchain/key-evolve/v1" || K)``) rather than copied from a second
log, so an implementation shared by both sides cannot make a wrong tag
pass.
"""

import hashlib
import hmac
import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    StageVerifier,
    Verifier,
    decrypt_entry,
    dump_pruned_hybrid,
    load_pruned_hybrid,
    verify_auth,
    verify_auth_batch,
    verify_auth_stage,
)

_CONSTRUCTION_KEY = b"shared-secret-passphrase"
_SEAL_KEY = bytes(range(1, 33))        # 32-byte AES-256-GCM sealing key
_OTHER_SEAL_KEY = bytes(range(33, 65))  # different key, same legal length
_ENC_KEY = bytes(range(65, 97))        # 32-byte entry-encryption key

_AUTH_DOMAIN = b"auditchain/auth/v1"
_EVOLVE_DOMAIN = b"auditchain/key-evolve/v1"


def _evolve(key: bytes, hash_name: str) -> bytes:
    return hashlib.new(hash_name, _EVOLVE_DOMAIN + key).digest()


def _evolved_key(stage: int, hash_name: str) -> bytes:
    key = _CONSTRUCTION_KEY
    for _ in range(stage):
        key = _evolve(key, hash_name)
    return key


def _expected_tag(stage: int, entry_hash: bytes, hash_name: str) -> bytes:
    """Independently recompute the tag the README promises for ``stage``."""
    return hmac.new(
        _evolved_key(stage, hash_name),
        _AUTH_DOMAIN + stage.to_bytes(8, "big") + entry_hash,
        hash_name,
    ).digest()


def _snapshot(log: AuditLog):
    """Publicly observable chain state an auth call must never touch."""
    return (
        len(log),
        log.retain_from,
        log.head,
        log.merkle_root(),
        [e.index for e in log],
        log.entries(),
        log.verify(),
    )


class PrunedHybridAuthLifecycleTest(unittest.TestCase):
    def _run_lifecycle(self, hash_name: str) -> None:
        # ------------------------------------------------------------------
        # Phase 0: a mixed plaintext/ciphertext log; save the stage-0
        # verification material before the first evolution.
        # ------------------------------------------------------------------
        log = AuditLog(key=_CONSTRUCTION_KEY, hash_name=hash_name)
        root_verifier = log.export_verifier()
        self.assertIsInstance(root_verifier, Verifier)
        # The stage-0 material is one-shot and stage material does not exist
        # before the first evolution.
        with self.assertRaises(ValueError):
            log.export_verifier()
        with self.assertRaises(ValueError):
            log.export_stage_verifier()

        entry0 = log.append("plain-0")                           # index 0
        log.encrypt("cipher-1", _ENC_KEY, nonce=b"\x01" * 12)   # index 1
        log.append(b"plain-2")                                  # index 2

        # ------------------------------------------------------------------
        # Phase 1: single auth at stage 0, then an explicit evolution.
        # ------------------------------------------------------------------
        tag0 = log.auth(0)
        self.assertEqual(tag0.stage, 0)
        self.assertEqual(
            tag0.tag, _expected_tag(0, entry0.entry_hash, hash_name)
        )
        self.assertEqual(log.stage, 1)

        log.rotate_key()                                        # stage -> 2
        self.assertEqual(log.stage, 2)

        # First delivery point: stage-2 material is repeatable and equal.
        stage2_a = log.export_stage_verifier()
        stage2_b = log.export_stage_verifier()
        self.assertEqual(stage2_a, stage2_b)
        self.assertEqual(stage2_a.stage, 2)
        self.assertEqual(
            stage2_a.key, _evolved_key(2, hash_name)
        )
        # Delivering stage material is read-only.
        self.assertEqual(log.stage, 2)
        with self.assertRaises(ValueError):
            log.export_verifier()

        # ------------------------------------------------------------------
        # Phase 2: batch of two (indices 1, 2) at stages 2, 3. The result is
        # ordered by ascending absolute index no matter the input order.
        # ------------------------------------------------------------------
        batch_1_2 = log.auth_batch([2, 1])
        self.assertEqual([entry.index for entry, _ in batch_1_2], [1, 2])
        self.assertEqual([tag.stage for _, tag in batch_1_2], [2, 3])
        for position, (entry, tag) in enumerate(batch_1_2):
            self.assertEqual(tag.stage, 2 + position)
            self.assertEqual(
                tag.tag, _expected_tag(tag.stage, entry.entry_hash, hash_name)
            )
            self.assertIsInstance(tag, AuthTag)
        self.assertEqual(log.stage, 4)

        # Stage material at the new stage is independently the evolved key
        # and is itself repeatable/equal.
        stage4 = log.export_stage_verifier()
        self.assertEqual(stage4.stage, 4)
        self.assertEqual(stage4, log.export_stage_verifier())
        self.assertEqual(stage4.key, _evolved_key(4, hash_name))

        # An empty batch returns an empty tuple and leaves the stage alone.
        self.assertEqual(log.auth_batch(()), ())
        self.assertEqual(verify_auth_batch((), root_verifier), ())
        self.assertEqual(log.stage, 4)

        # Stage-2 material verifies tags at stages >= 2, never the stage-0
        # tag that precedes its delivery point.
        self.assertTrue(
            verify_auth_stage(batch_1_2[0][0], batch_1_2[0][1], stage2_a)
        )
        self.assertTrue(
            verify_auth_stage(batch_1_2[1][0], batch_1_2[1][1], stage2_a)
        )
        self.assertFalse(verify_auth_stage(entry0, tag0, stage2_a))
        # The original stage-0 material verifies every legitimate tag.
        self.assertTrue(verify_auth(entry0, tag0, root_verifier))
        self.assertEqual(
            verify_auth_batch(batch_1_2, root_verifier), (True, True)
        )

        # ------------------------------------------------------------------
        # Phase 3: prune a mixed prefix (one plain, one ciphertext), then
        # the first encrypted export / restore.
        # ------------------------------------------------------------------
        log.append(b"plain-3")                                  # index 3
        log.encrypt(b"cipher-4", _ENC_KEY, nonce=b"\x04" * 12)  # index 4

        log.prune(2, log.seal(2))
        self.assertEqual(log.retain_from, 2)
        self.assertEqual([e.index for e in log], [2, 3, 4])
        # Retained search indexes expose only retained absolute indices.
        self.assertEqual(log.find(b"plain-2"), (2,))
        self.assertEqual(log.find(b"plain-0"), ())
        self.assertEqual(log.find_encrypted(b"cipher-4", _ENC_KEY), (4,))
        self.assertEqual(log.find_encrypted(b"cipher-1", _ENC_KEY), ())
        self.assertEqual(
            decrypt_entry(log.entry(4), _ENC_KEY, hash_name=hash_name),
            b"cipher-4",
        )
        self.assertTrue(log.verify())

        data1 = dump_pruned_hybrid(log, _SEAL_KEY, nonce=b"r" * 12)
        r1 = load_pruned_hybrid(data1, _SEAL_KEY)

        # The restored log matches across the full public surface.
        self.assertEqual(r1.hash_name, hash_name)
        self.assertEqual(len(r1), 5)
        self.assertEqual(r1.retain_from, 2)
        self.assertEqual(r1.head, log.head)
        self.assertEqual(r1.merkle_root(), log.merkle_root())
        self.assertEqual(r1.stage, 4)
        self.assertEqual([e.index for e in r1], [2, 3, 4])
        self.assertTrue(r1.verify())
        self.assertEqual(r1.find(b"plain-2"), (2,))
        self.assertEqual(r1.find(b"plain-0"), ())
        self.assertEqual(r1.find_encrypted(b"cipher-4", _ENC_KEY), (4,))
        self.assertEqual(r1.find_encrypted(b"cipher-1", _ENC_KEY), ())
        # The complete nonce history survives, even the released nonce.
        with self.assertRaises(ValueError):
            r1.encrypt("again", _ENC_KEY, nonce=b"\x01" * 12)
        with self.assertRaises(ValueError):
            r1.encrypt("again", _ENC_KEY, nonce=b"\x04" * 12)
        # Pruned records are gone; restoring never asked for their tags.
        with self.assertRaises(IndexError):
            r1.entry(0)

        # ------------------------------------------------------------------
        # Phase 4: failures interleaved between the two restorations. Each
        # must be atomic: no stage/key consumption, so the next legal
        # issuance at stage 4 gets the independently predicted tag.
        # ------------------------------------------------------------------
        entry5 = r1.append("plain-5")                           # index 5
        self.assertEqual(len(r1), 6)

        def expect_unchanged_after_failure(action, error):
            snapshot = _snapshot(r1)
            stage = r1.stage
            with self.assertRaises(error):
                action()
            self.assertEqual(r1.stage, stage)
            self.assertEqual(_snapshot(r1), snapshot)

        expect_unchanged_after_failure(lambda: r1.auth_batch([5, False]), TypeError)
        expect_unchanged_after_failure(lambda: r1.auth_batch(5), TypeError)
        expect_unchanged_after_failure(lambda: r1.auth_batch([5, 3, 5]), ValueError)
        expect_unchanged_after_failure(lambda: r1.auth_batch([0, 5]), IndexError)
        expect_unchanged_after_failure(lambda: r1.auth_batch([1]), IndexError)
        # Single-entry auth shares the retained-range rule and atomicity.
        expect_unchanged_after_failure(lambda: r1.auth(0), IndexError)

        tag5 = r1.auth(5)
        self.assertEqual(tag5.stage, 4)
        self.assertEqual(tag5.tag, _expected_tag(4, entry5.entry_hash, hash_name))
        self.assertEqual(r1.stage, 5)
        self.assertTrue(verify_auth(entry5, tag5, root_verifier))

        # ------------------------------------------------------------------
        # Phase 5: rotate, batch across old and new entries, then a prune
        # releasing ALL currently retained entries. Later appends keep the
        # cumulative absolute indices.
        # ------------------------------------------------------------------
        r1.rotate_key()                                         # stage -> 6
        entry6 = r1.encrypt(b"cipher-6", _ENC_KEY, nonce=b"\x06" * 12)
        batch_2_6 = r1.auth_batch((6, 2))
        self.assertEqual([entry.index for entry, _ in batch_2_6], [2, 6])
        self.assertEqual([tag.stage for _, tag in batch_2_6], [6, 7])
        for entry, tag in batch_2_6:
            self.assertEqual(
                tag.tag, _expected_tag(tag.stage, entry.entry_hash, hash_name)
            )
        self.assertEqual(r1.stage, 8)

        stage8 = r1.export_stage_verifier()
        self.assertEqual(stage8.stage, 8)
        self.assertEqual(stage8, r1.export_stage_verifier())
        self.assertEqual(stage8.key, _evolved_key(8, hash_name))
        # Delivery-point material cannot see tags minted before stage 8.
        for entry, tag in batch_2_6:
            self.assertFalse(verify_auth_stage(entry, tag, stage8))
        # The original material still verifies them.
        self.assertEqual(
            verify_auth_batch(batch_2_6, root_verifier), (True, True)
        )

        # Release every retained entry.
        r1.prune(7, r1.seal(7))
        self.assertEqual(r1.retain_from, 7)
        self.assertEqual(len(r1), 7)
        self.assertEqual(list(r1), [])
        self.assertEqual(r1.find(b"plain-5"), ())
        self.assertEqual(r1.find_encrypted(b"cipher-6", _ENC_KEY), ())
        self.assertTrue(r1.verify())
        self.assertEqual(r1.head, r1.seal(7).chain_hash)

        # Appends after the full prune keep cumulative absolute indices.
        entry7 = r1.append("plain-7")                           # index 7
        entry8 = r1.append(b"plain-8")                          # index 8
        self.assertEqual([e.index for e in r1], [7, 8])
        self.assertEqual(len(r1), 9)
        self.assertEqual(r1.retain_from, 7)
        self.assertTrue(r1.verify())
        self.assertEqual(r1.find("plain-7"), (7,))
        self.assertEqual(r1.find(b"plain-8"), (8,))
        self.assertEqual(r1.find("plain-3"), ())

        # ------------------------------------------------------------------
        # Phase 6: the second encrypted export/restore, then continue
        # authenticating the post-full-prune entries from stage 8.
        # ------------------------------------------------------------------
        data2 = dump_pruned_hybrid(r1, _SEAL_KEY, nonce=b"s" * 12)
        r2 = load_pruned_hybrid(data2, _SEAL_KEY)

        self.assertEqual(len(r2), 9)
        self.assertEqual(r2.retain_from, 7)
        self.assertEqual(r2.head, r1.head)
        self.assertEqual(r2.merkle_root(), r1.merkle_root())
        self.assertEqual(r2.stage, 8)
        self.assertEqual([e.index for e in r2], [7, 8])
        self.assertTrue(r2.verify())
        self.assertEqual(r2.find("plain-7"), (7,))
        self.assertEqual(r2.find("plain-2"), ())
        with self.assertRaises(ValueError):
            r2.encrypt("x", _ENC_KEY, nonce=b"\x06" * 12)

        tag7 = r2.auth(7)
        self.assertEqual(tag7.stage, 8)
        self.assertEqual(tag7.tag, _expected_tag(8, entry7.entry_hash, hash_name))
        batch_8 = r2.auth_batch([8])
        self.assertEqual(batch_8[0][0].index, 8)
        self.assertEqual(batch_8[0][1].stage, 9)
        self.assertEqual(
            batch_8[0][1].tag,
            _expected_tag(9, entry8.entry_hash, hash_name),
        )
        self.assertEqual(r2.stage, 10)
        # Stage-8 material (delivered on r1) verifies stages 8+ after restore.
        self.assertTrue(verify_auth_stage(entry7, tag7, stage8))
        self.assertTrue(verify_auth_stage(*batch_8[0], stage8))
        # The original stage-0 material verifies the newest tags too.
        self.assertTrue(verify_auth(entry7, tag7, root_verifier))
        self.assertTrue(verify_auth(*batch_8[0], root_verifier))

        # ------------------------------------------------------------------
        # Phase 7: tags and records of long-pruned entries still verify
        # fully offline (the verifier kept the Entry records and tags; the
        # export deliberately carried neither).
        # ------------------------------------------------------------------
        # Index 1 was released by the first prune; indices 0, 2 and 6 by the
        # full prune. No log involved in these calls.
        self.assertTrue(verify_auth(entry0, tag0, root_verifier))
        entry1, tag1 = batch_1_2[0]
        entry2, tag2 = batch_1_2[1]
        self.assertTrue(verify_auth(entry1, tag1, root_verifier))
        self.assertTrue(verify_auth(entry2, tag2, root_verifier))
        for entry, tag in batch_2_6:
            self.assertTrue(verify_auth(entry, tag, root_verifier))
        # The delivery-point material keeps its scope on the old records.
        self.assertTrue(verify_auth_stage(entry2, tag2, stage2_a))
        self.assertFalse(verify_auth_stage(entry1, tag1, stage4))
        self.assertFalse(verify_auth_stage(entry2, tag2, stage8))
        # A single flipped tag byte flips the verdict to False (not an
        # exception): the independent expectation is really being checked.
        bad = AuthTag(tag0.stage, bytes([tag0.tag[0] ^ 1]) + tag0.tag[1:])
        self.assertFalse(verify_auth(entry0, bad, root_verifier))

        # ------------------------------------------------------------------
        # Phase 8: consumed initial material cannot be re-exported after a
        # restore, and wrong sealing keys / corrupted data fail the load.
        # ------------------------------------------------------------------
        for restored in (r1, r2):
            with self.assertRaises(ValueError):
                restored.export_verifier()
        self.assertEqual(len(_OTHER_SEAL_KEY), len(_SEAL_KEY))
        with self.assertRaises(ValueError):
            load_pruned_hybrid(data1, _OTHER_SEAL_KEY)
        with self.assertRaises(ValueError):
            load_pruned_hybrid(data2, _OTHER_SEAL_KEY)
        tampered = bytearray(data2)
        tampered[-1] ^= 0x01
        with self.assertRaises(ValueError):
            load_pruned_hybrid(bytes(tampered), _SEAL_KEY)

        # ------------------------------------------------------------------
        # Phase 9: a successful restore yields an independent object.
        # Mutating the restoration changes neither the source log nor the
        # other restoration.
        # ------------------------------------------------------------------
        r1_len, r1_stage, log_len, log_stage = len(r1), r1.stage, len(log), log.stage
        r2.append("forked-9")                                  # index 9
        forked_entry = r2.entry(9)
        forked_tag = r2.auth(9)
        self.assertEqual(len(r2), 10)
        self.assertEqual(r2.stage, 11)
        self.assertEqual(len(r1), r1_len)
        self.assertEqual(r1.stage, r1_stage)
        self.assertEqual(len(log), log_len)
        self.assertEqual(log.stage, log_stage)

        r1.append("other-9")
        own_entry = r1.entry(9)
        self.assertIsNot(r2, r1)
        self.assertNotEqual(forked_entry.entry_hash, own_entry.entry_hash)
        # The fork's tag cannot authenticate the sibling branch's entry.
        self.assertFalse(verify_auth(own_entry, forked_tag, root_verifier))
        self.assertTrue(verify_auth(forked_entry, forked_tag, root_verifier))

        # ------------------------------------------------------------------
        # Phase 10: neither success nor failure of authentication changes
        # existing entries, the chain head, the Merkle root or retrieval.
        # ------------------------------------------------------------------
        r2.append("stable-10")                                 # index 10
        head_before = r2.head
        root_before = r2.merkle_root()
        entries_before = r2.entries()
        finds_before = (
            r2.find("plain-7"),
            r2.find("forked-9"),
            r2.find("stable-10"),
            r2.find_encrypted(b"cipher-4", _ENC_KEY),
        )
        tag10 = r2.auth(10)
        self.assertEqual(
            tag10.tag, _expected_tag(11, r2.entry(10).entry_hash, hash_name)
        )
        # A successful auth changed none of the chain/search observables.
        self.assertEqual(r2.head, head_before)
        self.assertEqual(r2.merkle_root(), root_before)
        self.assertEqual(r2.entries(), entries_before)
        self.assertEqual(
            (
                r2.find("plain-7"),
                r2.find("forked-9"),
                r2.find("stable-10"),
                r2.find_encrypted(b"cipher-4", _ENC_KEY),
            ),
            finds_before,
        )
        # Failed batches change nothing either.
        stage_before = r2.stage
        with self.assertRaises(TypeError):
            r2.auth_batch([9, True])
        with self.assertRaises(ValueError):
            r2.auth_batch([9, 9])
        with self.assertRaises(IndexError):
            r2.auth_batch([2, 9])
        self.assertEqual(r2.stage, stage_before)
        self.assertEqual(r2.head, head_before)
        self.assertEqual(r2.merkle_root(), root_before)
        self.assertEqual(r2.entries(), entries_before)
        self.assertTrue(r2.verify())

    def test_lifecycle_sha256(self):
        self._run_lifecycle("sha256")

    def test_lifecycle_sha512(self):
        self._run_lifecycle("sha512")


class PrunedHybridAuthLifecycleFocusedTest(unittest.TestCase):
    """Focused versions of guarantees the long scenario relies on."""

    def test_restored_log_evolves_identically_to_original(self):
        for hash_name in ("sha256", "sha512"):
            with self.subTest(hash_name=hash_name):
                log = AuditLog(key=_CONSTRUCTION_KEY, hash_name=hash_name)
                log.export_verifier()
                log.append("a")
                log.encrypt("s", _ENC_KEY, nonce=b"\x0a" * 12)
                log.auth(0)
                log.prune(1, log.seal(1))
                restored = load_pruned_hybrid(
                    dump_pruned_hybrid(log, _SEAL_KEY), _SEAL_KEY
                )
                log.append("b")
                restored.append("b")
                self.assertEqual(log.auth(1), restored.auth(1))
                self.assertEqual(log.head, restored.head)
                self.assertEqual(log.merkle_root(), restored.merkle_root())
                self.assertEqual(log.stage, restored.stage)

    def test_empty_batch_after_restore_returns_empty_tuple(self):
        for hash_name in ("sha256", "sha512"):
            with self.subTest(hash_name=hash_name):
                log = AuditLog(key=_CONSTRUCTION_KEY, hash_name=hash_name)
                log.export_verifier()
                log.append("a")
                log.auth(0)
                log.prune(1, log.seal(1))
                restored = load_pruned_hybrid(
                    dump_pruned_hybrid(log, _SEAL_KEY), _SEAL_KEY
                )
                self.assertEqual(restored.auth_batch(()), ())
                self.assertEqual(restored.stage, 1)

    def test_full_prune_round_trip_keeps_root_and_absolute_index(self):
        for hash_name in ("sha256", "sha512"):
            with self.subTest(hash_name=hash_name):
                log = AuditLog(key=_CONSTRUCTION_KEY, hash_name=hash_name)
                verifier = log.export_verifier()
                entry0 = log.append("a")
                tag = log.auth(0)
                log.encrypt("s", _ENC_KEY, nonce=b"\x0b" * 12)
                log.prune(2, log.seal(2))
                self.assertEqual(list(log), [])
                restored = load_pruned_hybrid(
                    dump_pruned_hybrid(log, _SEAL_KEY), _SEAL_KEY
                )
                self.assertEqual(restored.retain_from, 2)
                self.assertEqual(len(restored), 2)
                self.assertEqual(list(restored), [])
                self.assertEqual(restored.head, log.head)
                self.assertEqual(restored.merkle_root(), log.merkle_root())
                self.assertEqual(restored.stage, 1)
                # Appends continue at the cumulative absolute index 2.
                entry2 = restored.append("b")
                self.assertEqual([e.index for e in restored], [2])
                next_tag = restored.auth(2)
                self.assertEqual(next_tag.stage, 1)
                self.assertEqual(
                    next_tag.tag,
                    _expected_tag(1, entry2.entry_hash, hash_name),
                )
                # The fully-pruned entry's tag still verifies offline.
                self.assertTrue(verify_auth(entry0, tag, verifier))

    def test_wrong_length_seal_key_raises_value_error(self):
        log = AuditLog(key=_CONSTRUCTION_KEY)
        log.export_verifier()
        log.append("a")
        log.prune(1, log.seal(1))
        data = dump_pruned_hybrid(log, _SEAL_KEY)
        with self.assertRaises(ValueError):
            load_pruned_hybrid(data, b"k" * 31)
        with self.assertRaises(ValueError):
            load_pruned_hybrid(data, b"k" * 33)

    def test_stage_material_export_is_read_only_across_restore(self):
        for hash_name in ("sha256", "sha512"):
            with self.subTest(hash_name=hash_name):
                log = AuditLog(key=_CONSTRUCTION_KEY, hash_name=hash_name)
                log.export_verifier()
                log.append("a")
                log.auth(0)                                   # stage -> 1
                log.append("b")
                log.prune(1, log.seal(1))
                before = (log.stage, log.head, log.merkle_root(), len(log))
                material = log.export_stage_verifier()
                self.assertEqual(material, log.export_stage_verifier())
                self.assertEqual(
                    (log.stage, log.head, log.merkle_root(), len(log)),
                    before,
                )
                restored = load_pruned_hybrid(
                    dump_pruned_hybrid(log, _SEAL_KEY), _SEAL_KEY
                )
                # The restored log holds the same stage-1 key and can
                # re-deliver equal material without consuming anything.
                self.assertEqual(restored.export_stage_verifier(), material)
                self.assertEqual(restored.stage, 1)


if __name__ == "__main__":
    unittest.main()
