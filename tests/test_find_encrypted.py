import hmac
import unittest

from auditchain import AuditLog, Entry, decrypt_entry, verify_auth

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
THIRD_KEY = bytes(reversed(range(32)))
NONCE = b"nonce-12byte"
LOCATE_DOMAIN = b"auditchain/encrypted-locate/v1\0"


def locator(key, payload, hash_name="sha256"):
    return hmac.new(key, LOCATE_DOMAIN + payload, hash_name).digest()


class FindEncryptedBasicTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("plain-a")
        self.log.encrypt("secret", KEY, nonce=b"0" * 12)
        self.log.append(b"secret")
        self.log.encrypt("secret", KEY, nonce=b"1" * 12)
        self.log.encrypt(b"binary\x00", KEY, nonce=b"2" * 12)
        self.log.encrypt("other-key-text", OTHER_KEY, nonce=b"3" * 12)

    def test_single_and_duplicate_matches_ascending(self):
        result = self.log.find_encrypted("secret", KEY)
        self.assertEqual(result, (1, 3))
        self.assertIsInstance(result, tuple)
        self.assertEqual(self.log.find_encrypted(b"binary\x00", KEY), (4,))
        self.assertEqual(self.log.find_encrypted("other-key-text", OTHER_KEY), (5,))

    def test_str_and_bytes_are_equivalent(self):
        self.assertEqual(
            self.log.find_encrypted(b"secret", KEY),
            self.log.find_encrypted("secret", KEY),
        )

    def test_str_is_utf8_normalized(self):
        log = AuditLog()
        log.encrypt("héllo 位置", KEY, nonce=NONCE)
        self.assertEqual(log.find_encrypted("héllo 位置", KEY), (0,))
        self.assertEqual(log.find_encrypted("héllo 位置".encode("utf-8"), KEY), (0,))

    def test_empty_plaintext(self):
        log = AuditLog()
        log.encrypt(b"", KEY, nonce=b"a" * 12)
        log.encrypt("", KEY, nonce=b"b" * 12)
        self.assertEqual(log.find_encrypted("", KEY), (0, 1))
        self.assertEqual(log.find_encrypted(b"", KEY), (0, 1))

    def test_no_match_returns_empty_tuple(self):
        self.assertEqual(self.log.find_encrypted("missing", KEY), ())
        self.assertEqual(AuditLog().find_encrypted("x", KEY), ())

    def test_plain_entries_never_match(self):
        # Index 0 is a plain entry whose payload happens to equal the
        # plaintext; find_encrypted must not report it, and neither must a
        # plaintext-only value at index 2.
        self.assertEqual(self.log.find_encrypted("plain-a", KEY), ())
        self.assertEqual(self.log.find_encrypted("secret", KEY), (1, 3))

    def test_find_still_matches_only_envelopes(self):
        self.assertEqual(self.log.find(b"secret"), (2,))
        self.assertEqual(self.log.find("secret"), (2,))
        self.assertEqual(self.log.find(self.log.entry(1).payload), (1,))

    def test_locator_digest_has_the_specified_form(self):
        log = AuditLog()
        log.encrypt("secret", KEY, nonce=NONCE)
        digest = locator(KEY, b"secret")
        self.assertIn(digest, log._encrypted_index)
        self.assertEqual(log._encrypted_index[digest], [0])

    def test_neither_plaintext_nor_key_is_stored(self):
        log = AuditLog()
        log.encrypt("TOPSECRET-PLAINTEXT", KEY, nonce=NONCE)
        state = repr(log.__dict__).encode("utf-8")
        self.assertNotIn(b"TOPSECRET-PLAINTEXT", state)
        self.assertFalse(
            any(value == KEY for value in vars(log).values())
        )


class FindEncryptedKeyTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.encrypt("secret", KEY, nonce=b"0" * 12)
        self.log.encrypt("secret", OTHER_KEY, nonce=b"1" * 12)

    def test_wrong_but_valid_key_returns_empty_without_raising(self):
        self.assertEqual(self.log.find_encrypted("secret", OTHER_KEY), (1,))
        self.assertEqual(self.log.find_encrypted("secret", KEY), (0,))
        self.assertEqual(self.log.find_encrypted("secret", THIRD_KEY), ())

    def test_same_plaintext_under_other_keys_is_distinguished(self):
        self.assertEqual(self.log.find_encrypted(b"secret", KEY), (0,))
        self.assertEqual(self.log.find_encrypted(b"secret", OTHER_KEY), (1,))

    def test_key_type_errors(self):
        for bad_key in ("k" * 32, 123, None, bytearray(KEY), memoryview(KEY)):
            with self.assertRaises(TypeError):
                self.log.find_encrypted("secret", bad_key)

    def test_key_length_errors(self):
        for bad_key in (b"", b"k" * 31, b"k" * 33):
            with self.assertRaises(ValueError):
                self.log.find_encrypted("secret", bad_key)

    def test_payload_type_errors(self):
        for bad_payload in (123, None, bytearray(b"secret"), memoryview(b"secret"), ["s"]):
            with self.assertRaises(TypeError):
                self.log.find_encrypted(bad_payload, KEY)


class FindEncryptedRangeTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for nonce_byte in range(5):
            self.log.encrypt(
                "secret" if nonce_byte % 2 == 0 else "other",
                KEY,
                nonce=bytes([nonce_byte]) * 12,
            )

    def test_default_range_is_whole_retained_segment(self):
        self.assertEqual(self.log.find_encrypted("secret", KEY), (0, 2, 4))

    def test_half_open_explicit_range(self):
        self.assertEqual(self.log.find_encrypted("secret", KEY, 1, 4), (2,))
        self.assertEqual(self.log.find_encrypted("secret", KEY, 2, 5), (2, 4))
        self.assertEqual(self.log.find_encrypted("secret", KEY, 0, 2), (0,))
        self.assertEqual(self.log.find_encrypted("secret", KEY, 4), (4,))
        self.assertEqual(self.log.find_encrypted("secret", KEY, None, 2), (0,))

    def test_empty_range(self):
        self.assertEqual(self.log.find_encrypted("secret", KEY, 2, 2), ())
        self.assertEqual(self.log.find_encrypted("secret", KEY, 5, 5), ())

    def test_bound_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.find_encrypted("secret", KEY, bad)
            with self.assertRaises(TypeError):
                self.log.find_encrypted("secret", KEY, 0, bad)

    def test_bound_range_errors(self):
        with self.assertRaises(ValueError):
            self.log.find_encrypted("secret", KEY, -1)
        with self.assertRaises(ValueError):
            self.log.find_encrypted("secret", KEY, 0, 6)
        with self.assertRaises(ValueError):
            self.log.find_encrypted("secret", KEY, 3, 2)
        with self.assertRaises(ValueError):
            self.log.find_encrypted("secret", KEY, 6)
        # Boundary values themselves are accepted.
        self.assertEqual(self.log.find_encrypted("secret", KEY, 0, 5), (0, 2, 4))


class FindEncryptedPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        # 0 plain, 1 enc "a", 2 enc "b", 3 enc "a", 4 plain, 5 enc "a"
        self.log.append("a")
        self.log.encrypt("a", KEY, nonce=b"a0" * 6)
        self.log.encrypt("b", KEY, nonce=b"b0" * 6)
        self.log.encrypt("a", KEY, nonce=b"a1" * 6)
        self.log.append("b")
        self.log.encrypt("a", KEY, nonce=b"a2" * 6)

    def test_prune_drops_released_prefix_from_encrypted_index(self):
        self.log.prune(2, self.log.seal(2))
        self.assertEqual(self.log.find_encrypted("a", KEY), (3, 5))
        self.assertEqual(self.log.find_encrypted("b", KEY), (2,))
        # Explicit ranges may not reach into the released prefix either.
        with self.assertRaises(ValueError):
            self.log.find_encrypted("a", KEY, 0, 4)
        self.assertEqual(self.log.find_encrypted("a", KEY, 2, 4), (3,))

    def test_released_plain_and_encrypted_entries_in_one_prune(self):
        self.log.prune(4, self.log.seal(4))
        self.assertEqual(self.log.find_encrypted("a", KEY), (5,))
        self.assertEqual(self.log.find_encrypted("b", KEY), ())

    def test_failed_prune_leaves_encrypted_index_untouched(self):
        receipt = self.log.seal(3)
        with self.assertRaises(ValueError):
            self.log.prune(2, receipt)  # retain_from != receipt.size
        with self.assertRaises(TypeError):
            self.log.prune(2, "not-a-receipt")
        self.assertEqual(self.log.find_encrypted("a", KEY), (1, 3, 5))
        self.assertEqual(self.log.find_encrypted("b", KEY), (2,))

    def test_append_after_prune_is_indexed(self):
        self.log.prune(4, self.log.seal(4))
        self.log.encrypt("a", KEY, nonce=b"a3" * 6)
        self.assertEqual(self.log.find_encrypted("a", KEY), (5, 6))
        self.assertEqual(self.log.find_encrypted("b", KEY), ())

    def test_list_ordering_survives_pruning_duplicate_locators(self):
        # All three share the (KEY, "a") locator; pruning the first must
        # remove exactly index 1 (the list prefix), then a new duplicate at 6.
        self.log.prune(2, self.log.seal(2))
        self.log.encrypt("a", KEY, nonce=b"a3" * 6)
        self.assertEqual(self.log.find_encrypted("a", KEY), (3, 5, 6))
        self.log.prune(4, self.log.seal(4))
        self.assertEqual(self.log.find_encrypted("a", KEY), (5, 6))

    def test_repeated_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.log.prune(4, self.log.seal(4))
        self.assertEqual(self.log.find_encrypted("a", KEY), (5,))
        # Pruning to the current retain point is a no-op for the index.
        self.log.prune(4, self.log.seal(4))
        self.assertEqual(self.log.find_encrypted("a", KEY), (5,))

    def test_prune_all_then_find_encrypted(self):
        self.log.prune(6, self.log.seal(6))
        self.assertEqual(self.log.find_encrypted("a", KEY), ())
        self.log.encrypt("a", KEY, nonce=b"a9" * 6)
        self.assertEqual(self.log.find_encrypted("a", KEY), (6,))

    def test_other_key_locator_survives_prune_of_unrelated_entries(self):
        log = AuditLog()
        log.encrypt("mine", KEY, nonce=b"k0" * 6)
        log.encrypt("theirs", OTHER_KEY, nonce=b"o0" * 6)
        log.prune(1, log.seal(1))
        self.assertEqual(log.find_encrypted("theirs", OTHER_KEY), (1,))
        self.assertEqual(log.find_encrypted("mine", KEY), ())


class FindEncryptedCommitTest(unittest.TestCase):
    def test_locator_committed_only_after_successful_append(self):
        log = AuditLog()
        log.encrypt("used", KEY, nonce=NONCE)
        snapshot = (
            len(log),
            log.head,
            list(log.entries()),
            {key: list(hits) for key, hits in log._encrypted_index.items()},
            dict(log._encrypted_locators),
        )
        calls = (
            (42, KEY, b"g" * 12),                       # bad payload type
            ("x", "k" * 32, NONCE),                     # bad key type
            ("x", b"short", NONCE),                     # bad key length
            ("x", KEY, "n" * 12),                       # bad nonce type
            ("x", KEY, b"short"),                       # bad nonce length
            ("x", KEY, NONCE),                          # nonce already used
        )
        for args in calls:
            with self.assertRaises((TypeError, ValueError)):
                log.encrypt(*args)
        current = (
            len(log),
            log.head,
            list(log.entries()),
            {key: list(hits) for key, hits in log._encrypted_index.items()},
            dict(log._encrypted_locators),
        )
        self.assertEqual(current, snapshot)


class FindEncryptedCollisionTest(unittest.TestCase):
    def test_foreign_key_entry_under_locator_cannot_forge_a_hit(self):
        log = AuditLog()
        log.encrypt("secret", KEY, nonce=b"0" * 12)
        log.encrypt("secret", OTHER_KEY, nonce=b"1" * 12)
        # Plant the foreign-key entry (index 1) into the (KEY, "secret")
        # locator list, as a digest collision / corrupt index would.
        digest = locator(KEY, b"secret")
        log._encrypted_index[digest].append(1)
        self.assertEqual(log.find_encrypted("secret", KEY), (0,))

    def test_plain_entry_under_locator_cannot_forge_a_hit(self):
        log = AuditLog()
        log.encrypt("secret", KEY, nonce=NONCE)
        log.append(b"secret")
        digest = locator(KEY, b"secret")
        log._encrypted_index[digest].append(1)
        # Decrypting a plain envelope fails: no false hit.
        self.assertEqual(log.find_encrypted("secret", KEY), (0,))

    def test_tampered_envelope_candidate_is_rejected(self):
        log = AuditLog()
        entry = log.encrypt("secret", KEY, nonce=NONCE)
        raw = entry.payload[:-1] + bytes([entry.payload[-1] ^ 0x01])
        log._entries[0] = Entry(entry.index, raw, entry.previous_hash, entry.entry_hash)
        self.assertEqual(log.find_encrypted("secret", KEY), ())


class FindEncryptedAlternateHashTest(unittest.TestCase):
    def test_find_encrypted_with_sha3(self):
        log = AuditLog(hash_name="sha3-256")
        log.encrypt("secret", KEY, nonce=NONCE)
        log.encrypt("secret", OTHER_KEY, nonce=b"1" * 12)
        self.assertEqual(log.find_encrypted("secret", KEY), (0,))
        self.assertEqual(log.find_encrypted("secret", OTHER_KEY), (1,))
        self.assertEqual(log.find_encrypted("secret", THIRD_KEY), ())
        digest = locator(KEY, b"secret", "sha3-256")
        self.assertEqual(log._encrypted_index[digest], [0])
        log.prune(1, log.seal(1))
        self.assertEqual(log.find_encrypted("secret", OTHER_KEY), (1,))
        self.assertEqual(log.find_encrypted("secret", KEY), ())

    def test_find_encrypted_on_forward_secure_log(self):
        log = AuditLog(key=b"shared-secret", hash_name="sha3-256")
        verifier = log.export_verifier()
        log.encrypt("secret", KEY, nonce=NONCE)
        tag = log.auth(0)
        self.assertEqual(log.find_encrypted("secret", KEY), (0,))
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))


class FindEncryptedReadOnlyTest(unittest.TestCase):
    def test_queries_change_nothing(self):
        log = AuditLog(key=b"shared-secret")
        log.encrypt("secret", KEY, nonce=b"0" * 12)
        log.encrypt("secret", KEY, nonce=b"1" * 12)
        log.encrypt("other", OTHER_KEY, nonce=b"2" * 12)
        verifier = log.export_verifier()
        tag = log.auth(0)

        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        stage = log.stage
        tags = dict(log._tags)
        encrypted_index = {key: list(hits) for key, hits in log._encrypted_index.items()}
        locators = dict(log._encrypted_locators)
        plain_index = {key: list(hits) for key, hits in log._index.items()}

        # Matching query, miss, and wrong-key attempts alike.
        self.assertEqual(log.find_encrypted("secret", KEY), (0, 1))
        self.assertEqual(log.find_encrypted("missing", KEY), ())
        self.assertEqual(log.find_encrypted("secret", OTHER_KEY), ())
        self.assertEqual(log.find_encrypted("secret", KEY, 1, 1), ())
        with self.assertRaises(ValueError):
            log.find_encrypted("secret", KEY, -1)

        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(log.stage, stage)
        self.assertEqual(log._tags, tags)
        self.assertEqual(
            {key: list(hits) for key, hits in log._encrypted_index.items()},
            encrypted_index,
        )
        self.assertEqual(dict(log._encrypted_locators), locators)
        self.assertEqual(
            {key: list(hits) for key, hits in log._index.items()}, plain_index
        )
        self.assertTrue(log.verify())
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))
        # Entries still decrypt exactly as before.
        self.assertEqual(decrypt_entry(log.entry(0), KEY), b"secret")


if __name__ == "__main__":
    unittest.main()
