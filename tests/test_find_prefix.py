import unittest

from auditchain import AuditLog, verify_auth

KEY = b"super-secret-key"


class FindPrefixBasicTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "aa", "c", "az", "b", b"a\x00", "apple"):
            self.log.append(record)

    def test_raw_byte_prefix_match(self):
        # Everything starting with b"a": a, aa, az, a\x00, apple — in order.
        self.assertEqual(self.log.find_prefix(b"a"), (0, 2, 4, 6, 7))
        self.assertIsInstance(self.log.find_prefix(b"a"), tuple)
        self.assertEqual(self.log.find_prefix(b"az"), (4,))
        self.assertEqual(self.log.find_prefix(b"apple"), (7,))
        # A prefix that is itself a full payload still matches that payload.
        self.assertEqual(self.log.find_prefix(b"aa"), (2,))

    def test_str_and_bytes_prefix_are_equivalent(self):
        self.assertEqual(
            self.log.find_prefix("a"), self.log.find_prefix(b"a")
        )

    def test_prefix_longer_than_payload_never_matches(self):
        self.assertEqual(self.log.find_prefix(b"aaa"), ())
        self.assertEqual(self.log.find_prefix(b"apples"), ())

    def test_empty_prefix_matches_every_entry(self):
        self.assertEqual(
            self.log.find_prefix(b""), tuple(range(len(self.log)))
        )
        self.assertEqual(
            self.log.find_prefix(""), tuple(range(len(self.log)))
        )

    def test_binary_prefix_uses_raw_bytes(self):
        # Only b"a\x00" starts with b"a\x00" (b"aa" and b"az" do not).
        self.assertEqual(self.log.find_prefix(b"a\x00"), (6,))
        self.assertEqual(self.log.find_prefix(b"\x00"), ())

    def test_unicode_prefix_uses_utf8_bytes(self):
        self.log.append("位置")
        index = len(self.log) - 1
        self.assertEqual(self.log.find_prefix("位"), (index,))
        self.assertEqual(
            self.log.find_prefix("位置".encode("utf-8")), (index,)
        )

    def test_empty_log(self):
        self.assertEqual(AuditLog().find_prefix(b"a"), ())
        self.assertEqual(AuditLog().find_prefix(b""), ())


class FindPrefixErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)

    def test_prefix_type_errors(self):
        for bad in (
            None,
            1,
            1.5,
            bytearray(b"a"),
            memoryview(b"a"),
            ["a"],
            object(),
        ):
            with self.assertRaises(TypeError):
                self.log.find_prefix(bad)

    def test_index_range_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.find_prefix(b"a", bad)
            with self.assertRaises(TypeError):
                self.log.find_prefix(b"a", 0, bad)

    def test_index_range_value_errors_follow_find(self):
        with self.assertRaises(ValueError):
            self.log.find_prefix(b"a", -1)
        with self.assertRaises(ValueError):
            self.log.find_prefix(b"a", 0, 4)
        with self.assertRaises(ValueError):
            self.log.find_prefix(b"a", 2, 1)
        # Boundary values are accepted.
        self.assertEqual(self.log.find_prefix(b"a", 0, 3), (0,))
        self.assertEqual(self.log.find_prefix(b"a", 3, 3), ())

    def test_range_still_validated_for_empty_prefix(self):
        with self.assertRaises(ValueError):
            self.log.find_prefix(b"", 0, 4)
        with self.assertRaises(TypeError):
            self.log.find_prefix(b"", True)


class FindPrefixIndexRangeTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "aa", "c", "az"):
            self.log.append(record)

    def test_default_range_is_whole_retained_segment(self):
        self.assertEqual(self.log.find_prefix(b"a"), (0, 2, 4))

    def test_explicit_half_open_range(self):
        self.assertEqual(self.log.find_prefix(b"a", 1, 5), (2, 4))
        self.assertEqual(self.log.find_prefix(b"a", 2), (2, 4))
        self.assertEqual(self.log.find_prefix(b"a", None, 3), (0, 2))
        self.assertEqual(self.log.find_prefix(b"a", 3, 3), ())
        self.assertEqual(self.log.find_prefix(b"", 1, 4), (1, 2, 3))

    def test_pruned_log_keeps_absolute_indices(self):
        self.log.prune(2, self.log.seal(2))
        # Entries 0 and 1 are gone; absolute indices 2..4 survive.
        self.assertEqual(self.log.find_prefix(b"a"), (2, 4))
        self.assertEqual(self.log.find_prefix(b"a", 2, 3), (2,))
        self.assertEqual(self.log.find_prefix(b"", 2, 5), (2, 3, 4))
        with self.assertRaises(ValueError):
            self.log.find_prefix(b"a", 0, 4)


class FindPrefixEncryptedTest(unittest.TestCase):
    def test_encrypted_entries_compare_envelope_bytes_without_decrypting(self):
        log = AuditLog()
        log.append(b"apple")
        key = b"k" * 32
        log.encrypt(b"apple pie", key)
        log.encrypt(b"apricot", key)
        # The plaintext never occurs as a stored payload; plain entries are
        # still matched normally.
        self.assertEqual(log.find_prefix(b"apple"), (0,))
        envelope_prefix = b"auditchain/encrypted-entry"
        self.assertEqual(log.find_prefix(envelope_prefix), (1, 2))
        # Exact-envelope startswith agrees with direct entry inspection.
        envelope = log.entry(1).payload
        self.assertEqual(
            log.find_prefix(envelope),
            tuple(i for i in range(len(log))
                  if log.entry(i).payload.startswith(envelope)),
        )


class FindPrefixReadOnlyTest(unittest.TestCase):
    def test_find_prefix_changes_nothing(self):
        log = AuditLog(key=KEY)
        for record in ("a", "b", "a"):
            log.append(record)
        verifier = log.export_verifier()
        tag = log.auth(0)
        head = log.head
        root = log.merkle_root()
        proof = log.inclusion_proof(1)
        entries = log.entries()
        find_hits = log.find("a")
        range_hits = log.find_range(b"a", b"b")
        stage = log.stage
        tags = dict(log._tags)

        self.assertEqual(log.find_prefix(b"a"), (0, 2))
        self.assertEqual(log.find_prefix(b"z"), ())
        self.assertEqual(log.find_prefix(b""), (0, 1, 2))
        with self.assertRaises(TypeError):
            log.find_prefix(1)

        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.inclusion_proof(1), proof)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(log.find("a"), find_hits)
        self.assertEqual(log.find_range(b"a", b"b"), range_hits)
        self.assertEqual(log.stage, stage)
        self.assertEqual(log._tags, tags)
        self.assertTrue(log.verify())
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))


if __name__ == "__main__":
    unittest.main()
