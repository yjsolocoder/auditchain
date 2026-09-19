import hashlib
import hmac
import unittest

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    AuthTag,
    Entry,
    Verifier,
    entry_digest,
    verify_auth,
)

KEY = b"forward-secure seed"
AUTH_DOMAIN = b"auditchain/auth/v1"
EVOLVE_DOMAIN = b"auditchain/key-evolve/v1"


def expected_tag(key, stage, entry_hash, hash_name="sha256"):
    message = AUTH_DOMAIN + stage.to_bytes(8, "big") + entry_hash
    return hmac.new(key, message, hash_name).digest()


def evolve(key, hash_name="sha256"):
    return hashlib.new(hash_name, EVOLVE_DOMAIN + key).digest()


class KeyedLogTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=KEY)
        for record in ("a", "b", "c", "d"):
            self.log.append(record)

    def test_keyless_log_disables_auth(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            log.auth(0)
        with self.assertRaises(ValueError):
            log.rotate_key()
        with self.assertRaises(ValueError):
            log.export_verifier()

    def test_key_must_be_bytes(self):
        with self.assertRaises(TypeError):
            AuditLog(key="secret")
        with self.assertRaises(TypeError):
            AuditLog(key=42)

    def test_key_must_be_non_empty(self):
        with self.assertRaises(ValueError):
            AuditLog(key=b"")

    def test_bytearray_key_accepted(self):
        log = AuditLog(key=bytearray(KEY))
        log.append("a")
        tag = log.auth(0)
        self.assertEqual(tag, AuthTag(0, expected_tag(KEY, 0, log.entry(0).entry_hash)))

    def test_auth_tag_matches_spec(self):
        entry = self.log.entry(1)
        tag = self.log.auth(1)
        self.assertEqual(tag, AuthTag(0, expected_tag(KEY, 0, entry.entry_hash)))
        self.assertIsInstance(tag.tag, bytes)

    def test_each_auth_evolves_the_key(self):
        first = self.log.auth(0)
        second = self.log.auth(1)
        self.assertEqual((first.stage, second.stage), (0, 1))
        self.assertEqual(second.tag, expected_tag(evolve(KEY), 1, self.log.entry(1).entry_hash))

    def test_rotate_key_only_evolves(self):
        self.log.rotate_key()
        self.assertEqual(len(self.log), 4)
        tag = self.log.auth(2)
        self.assertEqual(tag.stage, 1)
        self.assertEqual(tag.tag, expected_tag(evolve(KEY), 1, self.log.entry(2).entry_hash))

    def test_old_key_is_not_kept(self):
        self.log.auth(0)
        self.assertNotEqual(self.log._key, KEY)
        self.assertEqual(self.log._key, evolve(KEY))

    def test_auth_index_validation(self):
        with self.assertRaises(TypeError):
            self.log.auth("0")
        with self.assertRaises(ValueError):
            self.log.auth(-1)
        with self.assertRaises(IndexError):
            self.log.auth(4)

    def test_export_verifier_roundtrip(self):
        verifier = self.log.export_verifier()
        self.assertEqual(verifier, Verifier(KEY, "sha256"))
        entry = self.log.entry(0)
        tag = self.log.auth(0)
        self.assertTrue(verify_auth(entry, tag, verifier))

    def test_export_verifier_only_once(self):
        self.log.export_verifier()
        with self.assertRaises(ValueError):
            self.log.export_verifier()

    def test_export_verifier_only_before_first_evolution(self):
        self.log.auth(0)
        with self.assertRaises(ValueError):
            self.log.export_verifier()
        log = AuditLog(key=KEY)
        log.rotate_key()
        with self.assertRaises(ValueError):
            log.export_verifier()

    def test_verify_auth_after_multiple_evolutions(self):
        verifier = self.log.export_verifier()
        self.log.rotate_key()
        tag = self.log.auth(3)
        self.assertTrue(verify_auth(self.log.entry(3), tag, verifier))

    def test_verify_auth_rejects_wrong_content(self):
        verifier = self.log.export_verifier()
        tag = self.log.auth(1)
        self.assertFalse(verify_auth(self.log.entry(2), tag, verifier))
        forged = AuthTag(tag.stage, bytes(len(tag.tag)))
        self.assertFalse(verify_auth(self.log.entry(1), forged, verifier))
        other = Verifier(b"other key", "sha256")
        self.assertFalse(verify_auth(self.log.entry(1), tag, other))

    def test_verify_auth_detects_tampered_entry(self):
        verifier = self.log.export_verifier()
        entry = self.log.entry(1)
        tag = self.log.auth(1)
        tampered = Entry(entry.index, b"forged", entry.previous_hash, entry.entry_hash)
        self.assertFalse(verify_auth(tampered, tag, verifier))

    def test_verify_auth_type_errors(self):
        verifier = self.log.export_verifier()
        tag = self.log.auth(0)
        with self.assertRaises(TypeError):
            verify_auth("entry", tag, verifier)
        with self.assertRaises(TypeError):
            verify_auth(self.log.entry(0), b"tag", verifier)
        with self.assertRaises(TypeError):
            verify_auth(self.log.entry(0), tag, "verifier")

    def test_verify_auth_tag_length_checked(self):
        verifier = self.log.export_verifier()
        tag = self.log.auth(0)
        short = AuthTag(tag.stage, tag.tag[:-1])
        with self.assertRaises(ValueError):
            verify_auth(self.log.entry(0), short, verifier)

    def test_alternate_hash_name(self):
        log = AuditLog(hash_name="sha3-256", key=KEY)
        verifier = log.export_verifier()
        log.append("a")
        log.append("b")
        tag = log.auth(1)
        self.assertTrue(verify_auth(log.entry(1), tag, verifier))
        expected = expected_tag(KEY, 0, log.entry(1).entry_hash, "sha3-256")
        self.assertEqual(tag.tag, expected)

    def test_prune_drops_old_tags_and_keeps_evolution(self):
        verifier = self.log.export_verifier()
        pruned_entry = self.log.entry(0)
        first = self.log.auth(0)
        retained = self.log.auth(2)
        receipt = self.log.seal(2)
        self.log.prune(2, receipt)
        self.assertNotIn(0, self.log._tags)
        self.assertNotIn(1, self.log._tags)
        self.assertEqual(self.log._tags[2], retained)
        # Retained tags still verify and the key keeps evolving.
        self.assertTrue(verify_auth(self.log.entry(2), retained, verifier))
        self.assertTrue(verify_auth(pruned_entry, first, verifier))
        later = self.log.auth(3)
        self.assertEqual(later.stage, 2)
        self.assertTrue(verify_auth(self.log.entry(3), later, verifier))
        with self.assertRaises(IndexError):
            self.log.auth(0)


class AuthTagTest(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(TypeError):
            AuthTag("0", b"x" * 32)
        with self.assertRaises(TypeError):
            AuthTag(True, b"x" * 32)
        with self.assertRaises(ValueError):
            AuthTag(-1, b"x" * 32)
        with self.assertRaises(TypeError):
            AuthTag(0, "not bytes")

    def test_bytearray_normalized(self):
        tag = AuthTag(0, bytearray(b"x" * 32))
        self.assertIsInstance(tag.tag, bytes)

    def test_immutable(self):
        tag = AuthTag(0, b"x" * 32)
        with self.assertRaises(AttributeError):
            tag.stage = 1


class VerifierTest(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(TypeError):
            Verifier("key", "sha256")
        with self.assertRaises(ValueError):
            Verifier(b"", "sha256")
        with self.assertRaises(TypeError):
            Verifier(b"key", 42)
        with self.assertRaises(ValueError):
            Verifier(b"key", "not-a-hash")

    def test_bytearray_normalized(self):
        verifier = Verifier(bytearray(KEY), "sha256")
        self.assertIsInstance(verifier.key, bytes)

    def test_immutable(self):
        verifier = Verifier(KEY, "sha256")
        with self.assertRaises(AttributeError):
            verifier.key = b"other"


class GenesisReceiptTest(unittest.TestCase):
    def test_empty_receipt_matches_first_entry(self):
        log = AuditLog()
        log.append("a")
        log.append("b")
        receipt = log.seal(0)
        self.assertEqual(receipt.chain_hash, GENESIS_HASH)
        self.assertTrue(receipt.matches(log.entry(0)))
        self.assertFalse(receipt.matches(log.entry(1)))

    def test_empty_receipt_rejects_wrong_predecessor(self):
        log = AuditLog()
        log.append("a")
        forged = Entry(0, b"a", b"\x01" * 32, log.entry(0).entry_hash)
        self.assertFalse(log.seal(0).matches(forged))


if __name__ == "__main__":
    unittest.main()
