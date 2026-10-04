import hashlib
import hmac
import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    StageVerifier,
    Verifier,
    dump_pruned_hybrid,
    load_pruned_hybrid,
    verify_auth,
    verify_auth_batch,
    verify_auth_stage,
)

KEY = b"lifecycle-master-key"
SEAL_KEY = bytes(range(1, 33))
WRONG_SEAL_KEY = bytes(range(33, 65))
ENC_KEY = bytes(range(65, 97))

N1 = b"\x01" * 12
N2 = b"\x02" * 12
N3 = b"\x03" * 12
N4 = b"\x04" * 12

AUTH_DOMAIN = b"auditchain/auth/v1"
EVOLVE_DOMAIN = b"auditchain/key-evolve/v1"


class AuthOracle:
    """Independent re-implementation of the documented tag schedule.

    Tracks the evolving key and stage purely from the public contract
    (key evolution over EVOLVE_DOMAIN, HMAC over AUTH_DOMAIN || stage ||
    entry_hash), so tag expectations are derived from the specification
    rather than from comparing the pre- and post-restore logs against
    each other.
    """

    def __init__(self, key, hash_name):
        self._key = key
        self.stage = 0
        self._hash_name = hash_name

    @property
    def current_key(self):
        return self._key

    def evolve(self):
        self._key = hashlib.new(
            self._hash_name, EVOLVE_DOMAIN + self._key
        ).digest()
        self.stage += 1

    def expect_auth(self, entry):
        tag = AuthTag(
            stage=self.stage,
            tag=hmac.new(
                self._key,
                AUTH_DOMAIN + self.stage.to_bytes(8, "big") + entry.entry_hash,
                self._hash_name,
            ).digest(),
        )
        self.evolve()
        return tag


def public_state(log):
    """Everything observable through the read-only public entry points."""
    return (
        log.entries(),
        log.head,
        log.merkle_root(),
        log.find("plain-alpha"),
        log.find("plain-beta"),
        log.find("plain-gamma"),
        log.find("plain-delta"),
        log.find("after-full-prune"),
        log.find_encrypted("secret-alpha", ENC_KEY),
        log.find_encrypted("secret-beta", ENC_KEY),
        log.find_encrypted("secret-gamma", ENC_KEY),
    )


class PrunedHybridAuthLifecycleTest(unittest.TestCase):
    """One authentication lifecycle carried across two prunes and two
    dump_pruned_hybrid / load_pruned_hybrid round trips."""

    def test_lifecycle_sha256(self):
        self._run_lifecycle("sha256")

    def test_lifecycle_sha512(self):
        self._run_lifecycle("sha512")

    def _run_lifecycle(self, hash_name):
        oracle = AuthOracle(KEY, hash_name)
        delivered = []  # every (Entry, AuthTag) handed out, in mint order

        # --- Phase 1: hybrid log, alternating auth forms, first delivery.
        log = AuditLog(key=KEY, hash_name=hash_name)
        e0 = log.append("plain-alpha")                      # 0
        e1 = log.encrypt("secret-alpha", ENC_KEY, nonce=N1)  # 1
        e2 = log.append(b"plain-beta")                      # 2

        # Verification material is saved before the first evolution.
        verifier = log.export_verifier()
        self.assertEqual(verifier, Verifier(key=KEY, hash_name=hash_name))
        self.assertEqual(log.stage, 0)

        tag_e1 = log.auth(1)                                # minted at stage 0
        self.assertEqual(tag_e1, oracle.expect_auth(e1))
        self.assertEqual(tag_e1.stage, 0)
        self.assertEqual(log.stage, 1)
        delivered.append((e1, tag_e1))

        batch1 = log.auth_batch([2, 0])                     # stages 1 and 2
        self.assertEqual([entry.index for entry, _ in batch1], [0, 2])
        self.assertEqual(
            batch1,
            (
                (e0, oracle.expect_auth(e0)),
                (e2, oracle.expect_auth(e2)),
            ),
        )
        self.assertEqual([tag.stage for _, tag in batch1], [1, 2])
        self.assertEqual(log.stage, 3)
        delivered.extend(batch1)

        log.rotate_key()                                    # stage -> 4
        oracle.evolve()
        self.assertEqual(log.stage, 4)

        e3 = log.encrypt("secret-beta", ENC_KEY, nonce=N2)  # 3
        e4 = log.append("plain-gamma")                      # 4

        # Authentication and verifier exports are read-only on the log.
        state_before_auth = public_state(log)
        tag_e4 = log.auth(4)                                # minted at stage 4
        self.assertEqual(tag_e4, oracle.expect_auth(e4))
        self.assertEqual(tag_e4.stage, 4)
        self.assertEqual(log.stage, 5)
        delivered.append((e4, tag_e4))

        # First stage-scoped delivery point, at stage 5.
        sv_a = log.export_stage_verifier()
        self.assertEqual(sv_a.stage, 5)
        self.assertEqual(
            sv_a, StageVerifier(stage=5, key=oracle.current_key, hash_name=hash_name)
        )
        self.assertEqual(log.export_stage_verifier(), sv_a)  # repeatable
        self.assertEqual(log.stage, 5)                       # export is read-only

        tag_e3 = log.auth(3)                                # minted at stage 5
        self.assertEqual(tag_e3, oracle.expect_auth(e3))
        self.assertEqual(tag_e3.stage, 5)
        self.assertEqual(log.stage, 6)
        delivered.append((e3, tag_e3))

        # An empty batch mints nothing and does not evolve.
        self.assertEqual(log.auth_batch(()), ())
        self.assertEqual(log.auth_batch([]), ())
        self.assertEqual(log.stage, 6)
        self.assertEqual(public_state(log), state_before_auth)

        # --- Phase 2: prune a mixed prefix, export, restore (#1).
        log.prune(3, log.seal(3))
        self.assertEqual(log.retain_from, 3)
        self.assertEqual(len(log), 5)
        # Search only ever returns retained absolute indices.
        self.assertEqual(log.find("plain-alpha"), ())
        self.assertEqual(log.find("plain-beta"), ())
        self.assertEqual(log.find("plain-gamma"), (4,))
        self.assertEqual(log.find_encrypted("secret-alpha", ENC_KEY), ())
        self.assertEqual(log.find_encrypted("secret-beta", ENC_KEY), (3,))

        # Already-delivered tags still verify offline against the stage-0
        # material even though entries 0..2 have been released.
        for entry, tag in delivered:
            self.assertTrue(verify_auth(entry, tag, verifier))
        self.assertEqual(verify_auth_batch(batch1, verifier), (True, True))
        # The stage-5 material covers its delivery stage and later only.
        self.assertTrue(verify_auth_stage(e3, tag_e3, sv_a))
        self.assertFalse(verify_auth_stage(e4, tag_e4, sv_a))
        self.assertFalse(verify_auth_stage(e1, tag_e1, sv_a))

        data1 = dump_pruned_hybrid(log, SEAL_KEY)
        # The export carries no tags: restoring never asks for them.
        self.assertNotIn(tag_e1.tag, data1)
        self.assertNotIn(tag_e3.tag, data1)
        # A wrong but well-formed (32-byte) sealing key fails the load.
        with self.assertRaises(ValueError):
            load_pruned_hybrid(data1, WRONG_SEAL_KEY)

        original_state = public_state(log)
        original_meta = (len(log), log.retain_from, log.stage)
        restored = load_pruned_hybrid(data1, SEAL_KEY)
        self.assertIsNot(restored, log)
        self.assertEqual(restored.retain_from, 3)
        self.assertEqual(len(restored), 5)
        self.assertEqual(restored.stage, 6)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(public_state(restored), public_state(log))
        # The consumed stage-0 export stays consumed across the restore.
        with self.assertRaises(ValueError):
            restored.export_verifier()
        with self.assertRaises(ValueError):
            log.export_verifier()
        # The restored log keeps evolving from exactly the same point.
        self.assertEqual(
            restored.export_stage_verifier(),
            StageVerifier(stage=6, key=oracle.current_key, hash_name=hash_name),
        )

        # --- Phase 3 (between the two restores): failures are atomic.
        state_before_failures = public_state(restored)
        with self.assertRaises(TypeError):
            restored.auth_batch([3, True])
        with self.assertRaises(ValueError):
            restored.auth_batch([4, 4])
        with self.assertRaises(IndexError):
            restored.auth_batch([3, 0])     # 0 was released by the prune
        with self.assertRaises(IndexError):
            restored.auth(2)                # released by the prune
        # No failure consumed a stage or touched the log.
        self.assertEqual(restored.stage, 6)
        self.assertEqual(public_state(restored), state_before_failures)

        # The next legitimate mint gets exactly the tag the failed
        # requests left behind.
        tag_e4b = restored.auth(4)                          # minted at stage 6
        self.assertEqual(tag_e4b, oracle.expect_auth(restored.entry(4)))
        self.assertEqual(tag_e4b.stage, 6)
        self.assertEqual(restored.stage, 7)
        self.assertEqual(public_state(restored), state_before_failures)
        delivered.append((e4, tag_e4b))

        e5 = restored.append("post-restore-one")            # 5
        self.assertEqual(e5.index, 5)
        e6 = restored.encrypt("secret-gamma", ENC_KEY, nonce=N3)  # 6
        batch2 = restored.auth_batch([6, 5])                # stages 7 and 8
        self.assertEqual([entry.index for entry, _ in batch2], [5, 6])
        self.assertEqual(
            batch2,
            (
                (e5, oracle.expect_auth(e5)),
                (e6, oracle.expect_auth(e6)),
            ),
        )
        self.assertEqual([tag.stage for _, tag in batch2], [7, 8])
        self.assertEqual(restored.stage, 9)
        delivered.extend(batch2)

        e7 = restored.append("plain-delta")                 # 7
        self.assertEqual(e7.index, 7)
        restored.rotate_key()                               # stage -> 10
        oracle.evolve()
        self.assertEqual(restored.stage, 10)

        # Second stage-scoped delivery point, at stage 10.
        sv_b = restored.export_stage_verifier()
        self.assertEqual(
            sv_b, StageVerifier(stage=10, key=oracle.current_key, hash_name=hash_name)
        )
        self.assertEqual(restored.export_stage_verifier(), sv_b)

        e8 = restored.append("plain-epsilon")               # 8
        tag_e8 = restored.auth(8)                           # minted at stage 10
        self.assertEqual(tag_e8, oracle.expect_auth(e8))
        self.assertEqual(tag_e8.stage, 10)
        self.assertEqual(restored.stage, 11)
        delivered.append((e8, tag_e8))

        # The complete nonce history survived the restore.
        with self.assertRaises(ValueError):
            restored.encrypt("replay", ENC_KEY, nonce=N1)

        # --- Phase 4: a prune that releases every retained entry.
        root_before_full_prune = restored.merkle_root()
        head_before_full_prune = restored.head
        self.assertEqual(len(restored), 9)
        restored.prune(9, restored.seal(9))
        self.assertEqual(restored.retain_from, 9)
        self.assertEqual(len(restored), 9)
        self.assertEqual(restored.entries(), [])
        # Chain head and the full-snapshot Merkle root survive the release.
        self.assertEqual(restored.head, head_before_full_prune)
        self.assertEqual(restored.merkle_root(), root_before_full_prune)
        self.assertEqual(restored.find("plain-gamma"), ())
        self.assertEqual(restored.find_encrypted("secret-beta", ENC_KEY), ())

        # Appends after a full prune keep the cumulative absolute index.
        e9 = restored.append("after-full-prune")            # 9
        self.assertEqual(e9.index, 9)
        self.assertEqual(restored.find("after-full-prune"), (9,))
        tag_e9 = restored.auth(9)                           # minted at stage 11
        self.assertEqual(tag_e9, oracle.expect_auth(e9))
        self.assertEqual(tag_e9.stage, 11)
        self.assertEqual(restored.stage, 12)
        delivered.append((e9, tag_e9))

        # Everything delivered so far — including tags of long-released
        # entries — still verifies offline against the stage-0 material.
        for entry, tag in delivered:
            self.assertTrue(verify_auth(entry, tag, verifier))

        # --- Phase 5: second export and restore.
        data2 = dump_pruned_hybrid(restored, SEAL_KEY)
        with self.assertRaises(ValueError):
            load_pruned_hybrid(data2, WRONG_SEAL_KEY)
        restored_state = public_state(restored)
        restored_meta = (len(restored), restored.retain_from, restored.stage)

        restored2 = load_pruned_hybrid(data2, SEAL_KEY)
        self.assertIsNot(restored2, restored)
        self.assertEqual(restored2.retain_from, 9)
        self.assertEqual(len(restored2), 10)
        self.assertEqual(restored2.stage, 12)
        self.assertEqual(restored2.head, restored.head)
        self.assertEqual(restored2.merkle_root(), restored.merkle_root())
        self.assertEqual(restored2.find("after-full-prune"), (9,))
        with self.assertRaises(ValueError):
            restored2.export_verifier()

        # Third stage-scoped delivery point, at stage 12; identical on
        # both copies of the same state.
        sv_c = restored2.export_stage_verifier()
        self.assertEqual(
            sv_c, StageVerifier(stage=12, key=oracle.current_key, hash_name=hash_name)
        )
        self.assertEqual(restored.export_stage_verifier(), sv_c)
        # Stage-12 material cannot reach back to the stage-11 tag.
        self.assertFalse(verify_auth_stage(e9, tag_e9, sv_c))

        e10 = restored2.encrypt("secret-delta", ENC_KEY, nonce=N4)  # 10
        self.assertEqual(e10.index, 10)
        tag_e10 = restored2.auth(10)                        # minted at stage 12
        self.assertEqual(tag_e10, oracle.expect_auth(e10))
        self.assertEqual(tag_e10.stage, 12)
        self.assertEqual(restored2.stage, 13)
        delivered.append((e10, tag_e10))

        # The restored objects are independent: mutating the later ones
        # never leaked back into the earlier ones.
        self.assertEqual(public_state(restored), restored_state)
        self.assertEqual((len(restored), restored.retain_from, restored.stage), restored_meta)
        self.assertEqual(public_state(log), original_state)
        self.assertEqual((len(log), log.retain_from, log.stage), original_meta)

        # --- Final sweep: the whole lifecycle through the public verifiers.
        # The stage-0 material still verifies every legitimate tag.
        for entry, tag in delivered:
            self.assertTrue(verify_auth(entry, tag, verifier))
        self.assertEqual(verify_auth_batch(batch2, verifier), (True, True))
        # Each stage-scoped delivery covers exactly its own stage and later.
        for material, floor in ((sv_a, 5), (sv_b, 10), (sv_c, 12)):
            for entry, tag in delivered:
                self.assertEqual(
                    verify_auth_stage(entry, tag, material),
                    tag.stage >= floor,
                    f"stage verifier at {floor} vs tag at {tag.stage}",
                )


if __name__ == "__main__":
    unittest.main()
