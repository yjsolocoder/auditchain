import unittest

from auditchain import AuditLog, decrypt_entry, verify_auth

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
THIRD_KEY = bytes(reversed(range(32)))
NONCE = b"nonce-12byte"


class FindEncryptedPrefixBasicTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        # 0 plain, 1 enc "hello world", 2 enc "help", 3 enc empty,
        # 4 enc under another key, 5 plain.
        self.log.append("plain-hello")
        self.log.encrypt("hello world", KEY, nonce=b"0" * 12)
        self.log.encrypt("help", KEY, nonce=b"1" * 12)
        self.log.encrypt(b"", KEY, nonce=b"2" * 12)
        self.log.encrypt("hello foreign", OTHER_KEY, nonce=b"3" * 12)
        self.log.append(b"hello raw")

    def test_prefix_matches_are_strictly_ascending(self):
        result = self.log.find_encrypted_prefix("hel", KEY)
        self.assertEqual(result, (1, 2))
        self.assertIsInstance(result, tuple)

    def test_str_and_bytes_are_equivalent(self):
        self.assertEqual(
            self.log.find_encrypted_prefix(b"hel", KEY),
            self.log.find_encrypted_prefix("hel", KEY),
        )

    def test_str_is_utf8_normalized(self):
        log = AuditLog()
        log.encrypt("héllo 位置", KEY, nonce=NONCE)
        self.assertEqual(log.find_encrypted_prefix("hél", KEY), (0,))
        self.assertEqual(
            log.find_encrypted_prefix("hél".encode("utf-8"), KEY), (0,)
        )
        # A prefix that is not a UTF-8 boundary cannot match.
        self.assertEqual(log.find_encrypted_prefix("hé", KEY), (0,))
        self.assertEqual(log.find_encrypted_prefix("xyz", KEY), ())

    def test_full_plaintext_matches_its_own_prefix(self):
        self.assertEqual(self.log.find_encrypted_prefix("hello world", KEY), (1,))

    def test_empty_prefix_hits_every_successfully_unsealed_entry(self):
        # Indices 1, 2, 3 unseal under KEY (including the empty plaintext);
        # the plain entries (0, 5) and the foreign-key envelope (4) do not.
        self.assertEqual(self.log.find_encrypted_prefix(b"", KEY), (1, 2, 3))
        self.assertEqual(self.log.find_encrypted_prefix("", KEY), (1, 2, 3))

    def test_empty_plaintext_only_matches_empty_prefix(self):
        # The empty plaintext at index 3 starts with b"" but never with a
        # non-empty prefix.
        self.assertIn(3, self.log.find_encrypted_prefix(b"", KEY))
        self.assertEqual(self.log.find_encrypted_prefix("h", KEY), (1, 2))

    def test_no_match_returns_empty_tuple(self):
        self.assertEqual(self.log.find_encrypted_prefix("missing", KEY), ())
        self.assertEqual(AuditLog().find_encrypted_prefix("x", KEY), ())

    def test_plain_entries_never_match(self):
        self.assertEqual(self.log.find_encrypted_prefix("plain", KEY), ())
        # "help" starts with "hel" but not with "hello"; only index 1 hits.
        self.assertEqual(self.log.find_encrypted_prefix("hello", KEY), (1,))
        self.assertEqual(self.log.find_encrypted_prefix(b"", KEY), (1, 2, 3))

    def test_foreign_key_entries_never_match(self):
        # KEY cannot unseal index 4.
        self.assertEqual(self.log.find_encrypted_prefix("hello", KEY), (1,))
        # OTHER_KEY unseals only index 4.
        self.assertEqual(
            self.log.find_encrypted_prefix("hello", OTHER_KEY), (4,)
        )

    def test_wrong_but_valid_key_returns_empty_without_raising(self):
        self.assertEqual(self.log.find_encrypted_prefix("hel", THIRD_KEY), ())
        self.assertEqual(self.log.find_encrypted_prefix(b"", THIRD_KEY), ())

    def test_prefix_is_byte_semantics_case_sensitive(self):
        log = AuditLog()
        log.encrypt("Apple", KEY, nonce=b"a" * 12)
        log.encrypt("apple", KEY, nonce=b"b" * 12)
        self.assertEqual(log.find_encrypted_prefix("App", KEY), (0,))
        self.assertEqual(log.find_encrypted_prefix("app", KEY), (1,))

    def test_query_is_read_only(self):
        log = AuditLog(key=b"shared-secret")
        log.encrypt("hello", KEY, nonce=b"0" * 12)
        verifier = log.export_verifier()
        tag = log.auth(0)
        snapshot = (
            log.head,
            log.merkle_root(),
            log.entries(),
            log.stage,
            dict(log._tags),
            {digest: list(hits) for digest, hits in log._encrypted_index.items()},
            {digest: list(hits) for digest, hits in log._index.items()},
        )
        self.log = log
        self.assertEqual(log.find_encrypted_prefix("hel", KEY), (0,))
        self.assertEqual(log.find_encrypted_prefix("zzz", KEY), ())
        self.assertEqual(log.find_encrypted_prefix(b"", OTHER_KEY), ())
        self.assertEqual(log.find_encrypted_prefix("hel", KEY, 0, 0), ())
        with self.assertRaises(ValueError):
            log.find_encrypted_prefix("hel", KEY, -1)
        self.assertEqual(
            (
                log.head,
                log.merkle_root(),
                log.entries(),
                log.stage,
                dict(log._tags),
                {
                    digest: list(hits)
                    for digest, hits in log._encrypted_index.items()
                },
                {digest: list(hits) for digest, hits in log._index.items()},
            ),
            snapshot,
        )
        self.assertTrue(log.verify())
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))
        self.assertEqual(decrypt_entry(log.entry(0), KEY), b"hello")


class FindEncryptedPrefixKeyTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.encrypt("hello", KEY, nonce=b"0" * 12)

    def test_key_type_errors(self):
        for bad_key in ("k" * 32, 123, None, bytearray(KEY), memoryview(KEY)):
            with self.assertRaises(TypeError):
                self.log.find_encrypted_prefix("hel", bad_key)

    def test_key_length_errors(self):
        for bad_key in (b"", b"k" * 31, b"k" * 33):
            with self.assertRaises(ValueError):
                self.log.find_encrypted_prefix("hel", bad_key)

    def test_prefix_type_errors(self):
        for bad_prefix in (
            123,
            None,
            bytearray(b"hel"),
            memoryview(b"hel"),
            ["h"],
        ):
            with self.assertRaises(TypeError):
                self.log.find_encrypted_prefix(bad_prefix, KEY)


class FindEncryptedPrefixRangeTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for nonce_byte in range(5):
            self.log.encrypt(
                "hello" if nonce_byte % 2 == 0 else "other",
                KEY,
                nonce=bytes([nonce_byte]) * 12,
            )

    def test_default_range_is_whole_retained_segment(self):
        self.assertEqual(self.log.find_encrypted_prefix("hel", KEY), (0, 2, 4))

    def test_half_open_explicit_range(self):
        self.assertEqual(self.log.find_encrypted_prefix("hel", KEY, 1, 4), (2,))
        self.assertEqual(self.log.find_encrypted_prefix("hel", KEY, 2, 5), (2, 4))
        self.assertEqual(self.log.find_encrypted_prefix("hel", KEY, 0, 2), (0,))
        self.assertEqual(self.log.find_encrypted_prefix("hel", KEY, 4), (4,))
        self.assertEqual(self.log.find_encrypted_prefix("hel", KEY, None, 2), (0,))

    def test_empty_range(self):
        self.assertEqual(self.log.find_encrypted_prefix("hel", KEY, 2, 2), ())
        self.assertEqual(self.log.find_encrypted_prefix(b"", KEY, 2, 2), ())
        self.assertEqual(self.log.find_encrypted_prefix("hel", KEY, 5, 5), ())

    def test_bound_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.find_encrypted_prefix("hel", KEY, bad)
            with self.assertRaises(TypeError):
                self.log.find_encrypted_prefix("hel", KEY, 0, bad)

    def test_bound_range_errors(self):
        with self.assertRaises(ValueError):
            self.log.find_encrypted_prefix("hel", KEY, -1)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_prefix("hel", KEY, 0, 6)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_prefix("hel", KEY, 3, 2)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_prefix("hel", KEY, 6)
        # Boundary values themselves are accepted.
        self.assertEqual(
            self.log.find_encrypted_prefix("hel", KEY, 0, 5), (0, 2, 4)
        )


class FindEncryptedPrefixPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        # 0 plain, 1 enc "apple", 2 enc "banana", 3 enc "apricot",
        # 4 plain, 5 enc "apply".
        self.log.append("apple")
        self.log.encrypt("apple", KEY, nonce=b"a0" * 6)
        self.log.encrypt("banana", KEY, nonce=b"b0" * 6)
        self.log.encrypt("apricot", KEY, nonce=b"a1" * 6)
        self.log.append("banana")
        self.log.encrypt("apply", KEY, nonce=b"a2" * 6)

    def test_default_range_follows_retained_segment(self):
        self.log.prune(2, self.log.seal(2))
        # Retained: 2 "banana", 3 "apricot", 4 plain, 5 "apply" — only 5
        # starts with "app".
        self.assertEqual(self.log.find_encrypted_prefix("app", KEY), (5,))
        with self.assertRaises(ValueError):
            self.log.find_encrypted_prefix("app", KEY, 0, 4)
        self.assertEqual(self.log.find_encrypted_prefix("app", KEY, 2, 4), ())
        self.assertEqual(self.log.find_encrypted_prefix("app", KEY, 5, 6), (5,))

    def test_append_after_prune_is_queryable(self):
        self.log.prune(4, self.log.seal(4))
        self.assertEqual(self.log.find_encrypted_prefix("app", KEY), (5,))
        self.log.encrypt("appended", KEY, nonce=b"a3" * 6)
        self.assertEqual(
            self.log.find_encrypted_prefix("app", KEY), (5, 6)
        )

    def test_prune_all_then_find(self):
        self.log.prune(6, self.log.seal(6))
        self.assertEqual(self.log.find_encrypted_prefix("app", KEY), ())
        self.assertEqual(self.log.find_encrypted_prefix(b"", KEY), ())
        self.log.encrypt("apple", KEY, nonce=b"a9" * 6)
        self.assertEqual(self.log.find_encrypted_prefix("app", KEY), (6,))


class FindEncryptedPrefixAlternateHashTest(unittest.TestCase):
    def test_find_with_sha3(self):
        log = AuditLog(hash_name="sha3_256")
        log.encrypt("hello", KEY, nonce=NONCE)
        log.encrypt("hello", OTHER_KEY, nonce=b"1" * 12)
        log.append("hello")
        self.assertEqual(log.find_encrypted_prefix("hel", KEY), (0,))
        self.assertEqual(log.find_encrypted_prefix("hel", OTHER_KEY), (1,))
        self.assertEqual(log.find_encrypted_prefix("hel", THIRD_KEY), ())
        self.assertEqual(log.find_encrypted_prefix(b"", KEY), (0,))


if __name__ == "__main__":
    unittest.main()
