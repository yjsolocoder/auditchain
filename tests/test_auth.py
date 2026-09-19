import hashlib
import hmac
import unittest

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    AuthTag,
    Entry,
    PruneReceipt,
    Verifier,
    entry_digest,
    verify_auth,
)

KEY = b"super-secret-key"
AUTH_DOMAIN = b"auditchain/auth/v1"
EVOLVE_DOMAIN = b"auditchain/key-evolve/v1"


def evolve(key, hash_name="sha256"):
    return hashlib.new(hash_name, EVOLVE_DOMAIN + key).digest()


class KeyedLogSetupTest(unittest.TestCase):
    def test_keyless_construction_still_works(self):
        log = AuditLog()
        entry = log.append("a")
        self.assertIsInstance(entry, Entry)
        self.assertEqual(log.stage, 0)

    def test_key_must_be_bytes(self):
        with self.assertRaises(TypeError):
            AuditLog(key="not-bytes")
        with self.assertRaises(TypeError):
            AuditLog(key=123)

    def test_key_must_be_bytes_not_bytearray_or_memoryview(self):
        with self.assertRaises(TypeError):
            AuditLog(key=bytearray(KEY))
        with self.assertRaises(TypeError):
            AuditLog(key=memoryview(KEY))

    def test_key_must_be_non_empty(self):
        with self.assertRaises(ValueError):
            AuditLog(key=b"")

    def test_unknown_hash_algorithm_rejected_with_key(self):
        with self.assertRaises(ValueError):
            AuditLog(key=KEY, hash_name="not-a-hash")


class AuthTagTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=KEY)
        for record in ("a", "b", "c"):
            self.log.append(record)

    def test_auth_returns_immutable_tag(self):
        tag = self.log.auth(0)
        self.assertIsInstance(tag, AuthTag)
        self.assertEqual(tag.stage, 0)
        self.assertIsInstance(tag.tag, bytes)
        with self.assertRaises(Exception):
            tag.stage = 5

    def test_tag_matches_hmac_composition(self):
        entry = self.log.entry(0)
        tag = self.log.auth(0)
        expected = hmac.new(
            KEY,
            AUTH_DOMAIN + (0).to_bytes(8, "big") + entry.entry_hash,
            "sha256",
        ).digest()
        self.assertEqual(tag.tag, expected)

    def test_auth_advances_stage_and_evolves_key(self):
        self.log.auth(0)
        self.assertEqual(self.log.stage, 1)
        entry1 = self.log.entry(1)
        tag1 = self.log.auth(1)
        self.assertEqual(tag1.stage, 1)
        key1 = evolve(KEY)
        expected = hmac.new(
            key1,
            AUTH_DOMAIN + (1).to_bytes(8, "big") + entry1.entry_hash,
            "sha256",
        ).digest()
        self.assertEqual(tag1.tag, expected)

    def test_auth_does_not_append(self):
        length = len(self.log)
        self.log.auth(0)
        self.assertEqual(len(self.log), length)
        self.assertEqual([e.index for e in self.log], [0, 1, 2])

    def test_auth_rejects_pruned_index(self):
        self.log.prune(1, self.log.seal(1))
        with self.assertRaises(IndexError):
            self.log.auth(0)

    def test_auth_type_and_bounds(self):
        with self.assertRaises(TypeError):
            self.log.auth("0")
        with self.assertRaises(IndexError):
            self.log.auth(3)

    def test_same_entry_can_be_authenticated_at_later_stages(self):
        verifier = self.log.export_verifier()
        tag0 = self.log.auth(0)
        tag1 = self.log.auth(0)
        self.assertEqual((tag0.stage, tag1.stage), (0, 1))
        self.assertNotEqual(tag0.tag, tag1.tag)
        self.assertTrue(verify_auth(self.log.entry(0), tag0, verifier))
        self.assertTrue(verify_auth(self.log.entry(0), tag1, verifier))


class KeylessModeTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("a")

    def test_auth_disabled(self):
        with self.assertRaises(ValueError):
            self.log.auth(0)

    def test_rotate_disabled(self):
        with self.assertRaises(ValueError):
            self.log.rotate_key()

    def test_export_verifier_disabled(self):
        with self.assertRaises(ValueError):
            self.log.export_verifier()


class RotateKeyTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=KEY)
        for record in ("a", "b"):
            self.log.append(record)

    def test_rotate_advances_stage_without_tag_or_append(self):
        length = len(self.log)
        self.log.rotate_key()
        self.assertEqual(self.log.stage, 1)
        self.assertEqual(len(self.log), length)
        self.log.rotate_key()
        self.log.rotate_key()
        self.assertEqual(self.log.stage, 3)

    def test_auth_after_rotate_uses_evolved_key(self):
        verifier = self.log.export_verifier()
        self.log.rotate_key()
        self.log.rotate_key()
        entry = self.log.entry(0)
        tag = self.log.auth(0)
        self.assertEqual(tag.stage, 2)
        key2 = evolve(evolve(KEY))
        expected = hmac.new(
            key2,
            AUTH_DOMAIN + (2).to_bytes(8, "big") + entry.entry_hash,
            "sha256",
        ).digest()
        self.assertEqual(tag.tag, expected)
        self.assertTrue(verify_auth(entry, tag, verifier))


class ExportVerifierTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=KEY)
        self.log.append("a")

    def test_verifier_fields_and_immutability(self):
        verifier = self.log.export_verifier()
        self.assertIsInstance(verifier, Verifier)
        self.assertEqual(verifier.key, KEY)
        self.assertEqual(verifier.hash_name, "sha256")
        with self.assertRaises(Exception):
            verifier.key = b"other"

    def test_only_once(self):
        self.assertIsNotNone(self.log.export_verifier())
        with self.assertRaises(ValueError):
            self.log.export_verifier()

    def test_not_after_auth(self):
        self.log.auth(0)
        with self.assertRaises(ValueError):
            self.log.export_verifier()

    def test_not_after_rotate(self):
        self.log.rotate_key()
        with self.assertRaises(ValueError):
            self.log.export_verifier()

    def test_export_before_evolution_still_verifies_later_tags(self):
        verifier = self.log.export_verifier()
        tags = [self.log.auth(i) for i in range(1)]
        self.log.append("b")
        tags.append(self.log.auth(1))
        self.log.rotate_key()
        self.log.append("c")
        tags.append(self.log.auth(2))
        self.assertEqual([tag.stage for tag in tags], [0, 1, 3])
        for index, tag in enumerate(tags):
            self.assertTrue(verify_auth(self.log.entry(index), tag, verifier))

    def test_verifier_validation(self):
        with self.assertRaises(TypeError):
            Verifier("not-bytes", "sha256")
        with self.assertRaises(TypeError):
            Verifier(bytearray(KEY), "sha256")
        with self.assertRaises(TypeError):
            Verifier(memoryview(KEY), "sha256")
        with self.assertRaises(ValueError):
            Verifier(b"", "sha256")
        with self.assertRaises(TypeError):
            Verifier(KEY, 123)
        with self.assertRaises(ValueError):
            Verifier(KEY, "not-a-hash")


class VerifyAuthTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=KEY)
        for record in ("a", "b", "c", "d"):
            self.log.append(record)
        self.verifier = self.log.export_verifier()
        self.tags = [self.log.auth(i) for i in range(4)]

    def test_every_tag_verifies(self):
        for index, tag in enumerate(self.tags):
            self.assertTrue(verify_auth(self.log.entry(index), tag, self.verifier))

    def test_wrong_tag_returns_false(self):
        self.assertFalse(verify_auth(self.log.entry(0), self.tags[1], self.verifier))
        self.assertFalse(verify_auth(self.log.entry(1), self.tags[0], self.verifier))

    def test_entry_hash_must_match_entry_contents(self):
        entry = self.log.entry(1)
        forged = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        self.assertFalse(verify_auth(forged, self.tags[1], self.verifier))

    def test_entry_hash_rebinding_detected(self):
        entry = self.log.entry(1)
        # Internally consistent for a different payload, but the tag commits to
        # the recorded entry hash of the genuine entry.
        rebound = Entry(
            entry.index,
            b"forged",
            entry.previous_hash,
            entry_digest(entry.index, entry.previous_hash, b"forged"),
        )
        self.assertFalse(verify_auth(rebound, self.tags[1], self.verifier))

    def test_corrupt_tag_digest_returns_false(self):
        tag = self.tags[0]
        bad = AuthTag(tag.stage, b"\x00" * len(tag.tag))
        self.assertFalse(verify_auth(self.log.entry(0), bad, self.verifier))

    def test_wrong_stage_tag_returns_false(self):
        tag = self.tags[2]
        self.assertFalse(verify_auth(self.log.entry(2), AuthTag(0, tag.tag), self.verifier))
        self.assertFalse(verify_auth(self.log.entry(2), AuthTag(3, tag.tag), self.verifier))

    def test_type_errors(self):
        entry = self.log.entry(0)
        tag = self.tags[0]
        with self.assertRaises(TypeError):
            verify_auth(("not", "entry"), tag, self.verifier)
        with self.assertRaises(TypeError):
            verify_auth(entry, ("not", "tag"), self.verifier)
        with self.assertRaises(TypeError):
            verify_auth(entry, tag, ("not", "verifier"))

    def test_negative_index_rejected(self):
        entry = self.log.entry(0)
        bad = Entry(-1, entry.payload, entry.previous_hash, entry.entry_hash)
        with self.assertRaises(ValueError):
            verify_auth(bad, self.tags[0], self.verifier)

    def test_digest_lengths_checked(self):
        entry = self.log.entry(0)
        tag = self.tags[0]
        with self.assertRaises(ValueError):
            verify_auth(
                Entry(entry.index, entry.payload, b"\x00" * 31, entry.entry_hash),
                tag,
                self.verifier,
            )
        with self.assertRaises(ValueError):
            verify_auth(
                Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 31),
                tag,
                self.verifier,
            )
        with self.assertRaises(ValueError):
            verify_auth(entry, AuthTag(0, b"\x00" * 31), self.verifier)

    def test_auth_tag_direct_validation(self):
        with self.assertRaises(TypeError):
            AuthTag("0", b"\x00" * 32)
        with self.assertRaises(TypeError):
            AuthTag(True, b"\x00" * 32)
        with self.assertRaises(ValueError):
            AuthTag(-1, b"\x00" * 32)
        with self.assertRaises(ValueError):
            AuthTag(1 << 64, b"\x00" * 32)
        # The largest encodable stage is still accepted.
        AuthTag((1 << 64) - 1, b"\x00" * 32)
        with self.assertRaises(TypeError):
            AuthTag(0, "not-bytes")
        with self.assertRaises(TypeError):
            AuthTag(0, bytearray(b"\x00" * 32))
        with self.assertRaises(TypeError):
            AuthTag(0, memoryview(b"\x00" * 32))

    def test_verify_auth_validates_stage_first(self):
        entry = self.log.entry(0)
        tag = self.tags[0]
        for bad_stage, error in ((True, TypeError), ("0", TypeError), (-1, ValueError), (1 << 64, ValueError)):
            tampered = AuthTag(0, tag.tag)
            object.__setattr__(tampered, "stage", bad_stage)
            with self.assertRaises(error):
                verify_auth(entry, tampered, self.verifier)

    def test_wrong_verifier_key_returns_false(self):
        other = Verifier(key=b"a-completely-different-key", hash_name="sha256")
        self.assertFalse(verify_auth(self.log.entry(0), self.tags[0], other))


class AlternateHashAuthTest(unittest.TestCase):
    def test_auth_with_sha3(self):
        log = AuditLog(key=KEY, hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        verifier = log.export_verifier()
        self.assertEqual(verifier.hash_name, "sha3-256")
        log.rotate_key()
        tag = log.auth(1)
        self.assertEqual(tag.stage, 1)
        self.assertEqual(len(tag.tag), hashlib.new("sha3-256").digest_size)
        self.assertTrue(verify_auth(log.entry(1), tag, verifier))
        # A sha256 verifier must not accept the sha3-256 tag.
        sha256 = Verifier(key=KEY, hash_name="sha256")
        self.assertFalse(verify_auth(log.entry(1), tag, sha256))

    def test_tag_length_mismatch_under_hash_algorithm(self):
        log = AuditLog(key=KEY, hash_name="sha3-256")
        log.append("a")
        verifier = log.export_verifier()
        tag = log.auth(0)
        bad = AuthTag(tag.stage, tag.tag[:-1])
        with self.assertRaises(ValueError):
            verify_auth(log.entry(0), bad, verifier)


class AuthFailureAtomicityTest(unittest.TestCase):
    """A failing auth/rotate_key/export_verifier must not change any state."""

    def setUp(self):
        self.log = AuditLog(key=KEY)
        for record in ("a", "b", "c"):
            self.log.append(record)

    def snapshot(self):
        return (
            self.log.stage,
            self.log._key,
            dict(self.log._tags),
            self.log.head,
            len(self.log),
            self.log._verifier_exported,
        )

    def test_failed_auth_leaves_state_untouched(self):
        before = self.snapshot()
        with self.assertRaises(TypeError):
            self.log.auth("0")
        with self.assertRaises(IndexError):
            self.log.auth(3)
        self.assertEqual(self.snapshot(), before)
        # The key was not evolved: the next successful auth is still stage 0.
        tag = self.log.auth(0)
        self.assertEqual(tag.stage, 0)
        self.assertEqual(self.log.stage, 1)

    def test_failed_auth_after_prune_leaves_state_untouched(self):
        self.log.auth(0)
        self.log.prune(2, self.log.seal(2))
        before = self.snapshot()
        with self.assertRaises(IndexError):
            self.log.auth(0)
        self.assertEqual(self.snapshot(), before)

    def test_failed_rotate_leaves_state_untouched(self):
        keyless = AuditLog()
        keyless.append("a")
        head = keyless.head
        with self.assertRaises(ValueError):
            keyless.rotate_key()
        self.assertEqual(keyless.stage, 0)
        self.assertEqual(keyless.head, head)

    def test_failed_export_leaves_state_untouched(self):
        verifier = self.log.export_verifier()
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.log.export_verifier()
        self.assertEqual(self.snapshot(), before)
        # A failed export did not consume or evolve anything: tags minted
        # afterwards still verify against the original verifier.
        tag = self.log.auth(0)
        self.assertTrue(verify_auth(self.log.entry(0), tag, verifier))


class PruneAuthTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=KEY)
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.verifier = self.log.export_verifier()

    def test_prune_releases_old_tags_but_keeps_retained(self):
        tags = {i: self.log.auth(i) for i in range(5)}
        released_entry = self.log.entry(0)
        self.log.prune(3, self.log.seal(3))
        # Tags of the released prefix are dropped from the log's state...
        self.assertEqual(sorted(self.log._tags), [3, 4])
        # ...while tags of the retained segment still verify.
        for index in (3, 4):
            self.assertTrue(verify_auth(self.log.entry(index), tags[index], self.verifier))
        # An outsider that still holds a released entry and its tag can verify.
        self.assertTrue(verify_auth(released_entry, tags[0], self.verifier))

    def test_prune_releases_old_tags(self):
        self.log.auth(0)
        self.log.auth(2)
        self.log.prune(3, self.log.seal(3))
        with self.assertRaises(IndexError):
            self.log.auth(0)
        # Old tags can still be verified by an outsider holding the entry,
        # but the log no longer holds the entry to look up.
        self.assertEqual(self.log.stage, 2)

    def test_append_and_auth_continue_after_prune(self):
        self.log.auth(0)
        self.log.prune(2, self.log.seal(2))
        self.log.append("f")
        tag = self.log.auth(5)
        self.assertEqual(tag.stage, 1)
        self.assertTrue(self.log.verify())
        self.assertTrue(verify_auth(self.log.entry(5), tag, self.verifier))

    def test_repeated_prune_keeps_evolution_intact(self):
        tag2 = self.log.auth(2)
        snapshot2 = self.log.entry(2)
        self.log.prune(2, self.log.seal(2))
        self.log.append("f")
        self.log.prune(4, self.log.seal(4))
        tag5 = self.log.auth(5)
        self.assertEqual((tag2.stage, tag5.stage), (0, 1))
        # Entry 2 was released by the second prune; its tag still verifies for
        # an outsider that kept the entry.
        self.assertTrue(verify_auth(snapshot2, tag2, self.verifier))
        self.assertTrue(verify_auth(self.log.entry(5), tag5, self.verifier))


if __name__ == "__main__":
    unittest.main()
