import unittest

from auditchain import AuditLog, verify_auth

KEY = b"super-secret-key"


class FindRangeBasicTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "aa", "c", "az", "b", b"a\x00"):
            self.log.append(record)

    def test_half_open_byte_order_interval(self):
        # [b"a", b"b") matches a, aa, az, a\x00 — not b or c — in index order.
        self.assertEqual(self.log.find_range(b"a", b"b"), (0, 2, 4, 6))
        self.assertIsInstance(self.log.find_range(b"a", b"b"), tuple)

    def test_str_and_bytes_bounds_are_equivalent(self):
        self.assertEqual(
            self.log.find_range("a", "b"), self.log.find_range(b"a", b"b")
        )

    def test_left_boundary_is_inclusive_right_is_exclusive(self):
        # Only the two exact b"b" entries: b"b" itself is excluded.
        self.assertEqual(self.log.find_range(b"b", b"c"), (1, 5))
        self.assertEqual(self.log.find_range(b"c", b"d"), (3,))
        # Prefix ordering: b"a" < b"a\x00" < b"aa" < b"az" < b"b".
        self.assertEqual(self.log.find_range(b"a\x00", b"az"), (2, 6))

    def test_empty_bounds(self):
        # Every bytes value is >= b"" and < b"z" here.
        self.assertEqual(
            self.log.find_range(b"", b"z"), tuple(range(len(self.log)))
        )
        self.assertEqual(self.log.find_range(b"", b""), ())

    def test_equal_bounds_return_empty_tuple(self):
        self.assertEqual(self.log.find_range(b"a", b"a"), ())
        self.assertEqual(self.log.find_range("aa", "aa"), ())
        self.assertEqual(self.log.find_range(b"", b""), ())

    def test_unicode_bounds_use_utf8_bytes(self):
        self.log.append("位置")
        index = len(self.log) - 1
        material = "位置".encode("utf-8")
        upper = "位育".encode("utf-8")
        self.assertEqual(self.log.find_range(material, upper), (index,))
        self.assertEqual(self.log.find_range("位置", "位育"), (index,))

    def test_empty_log(self):
        self.assertEqual(AuditLog().find_range(b"a", b"z"), ())


class FindRangeErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)

    def test_left_greater_than_right_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.log.find_range(b"b", b"a")
        with self.assertRaises(ValueError):
            self.log.find_range("z", "a")
        # Prefix-inverted bytes ordering.
        with self.assertRaises(ValueError):
            self.log.find_range(b"ab", b"aa")

    def test_bound_type_errors(self):
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
                self.log.find_range(bad, b"z")
            with self.assertRaises(TypeError):
                self.log.find_range(b"a", bad)

    def test_index_range_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.find_range(b"a", b"z", bad)
            with self.assertRaises(TypeError):
                self.log.find_range(b"a", b"z", 0, bad)

    def test_index_range_value_errors_follow_find(self):
        with self.assertRaises(ValueError):
            self.log.find_range(b"a", b"z", -1)
        with self.assertRaises(ValueError):
            self.log.find_range(b"a", b"z", 0, 4)
        with self.assertRaises(ValueError):
            self.log.find_range(b"a", b"z", 2, 1)
        # Boundary values are accepted.
        self.assertEqual(self.log.find_range(b"a", b"z", 0, 3), (0, 1, 2))
        self.assertEqual(self.log.find_range(b"a", b"z", 3, 3), ())

    def test_range_still_validated_for_equal_bounds(self):
        with self.assertRaises(ValueError):
            self.log.find_range(b"a", b"a", 0, 4)
        with self.assertRaises(TypeError):
            self.log.find_range(b"a", b"a", True)


class FindRangeIndexRangeTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "aa", "c", "az"):
            self.log.append(record)

    def test_default_range_is_whole_retained_segment(self):
        # [a, c) covers a, b, aa, az but not c.
        self.assertEqual(self.log.find_range(b"a", b"c"), (0, 1, 2, 4))

    def test_explicit_half_open_range(self):
        self.assertEqual(self.log.find_range(b"a", b"c", 1, 5), (1, 2, 4))
        self.assertEqual(self.log.find_range(b"a", b"c", 2), (2, 4))
        self.assertEqual(self.log.find_range(b"a", b"c", None, 3), (0, 1, 2))
        self.assertEqual(self.log.find_range(b"a", b"c", 3, 3), ())

    def test_pruned_log_keeps_absolute_indices(self):
        self.log.prune(2, self.log.seal(2))
        # Entries 0 and 1 are gone; absolute indices 2..4 survive.
        self.assertEqual(self.log.find_range(b"a", b"c"), (2, 4))
        self.assertEqual(self.log.find_range(b"a", b"c", 2, 3), (2,))
        with self.assertRaises(ValueError):
            self.log.find_range(b"a", b"c", 0, 4)


class FindRangeEncryptedTest(unittest.TestCase):
    def test_encrypted_entries_compare_envelope_bytes_without_decrypting(self):
        log = AuditLog()
        log.append(b"m")
        key = b"k" * 32
        log.encrypt(b"m", key)
        log.encrypt(b"n", key)
        # The plaintext b"m"/b"n" never occur as stored payloads; the two
        # sealed envelopes participate as raw bytes instead.
        self.assertEqual(log.find_range(b"m", b"n"), (0,))
        envelopes = [log.entry(i).payload for i in (1, 2)]
        lo = min(envelopes)
        hi = bytes((max(envelopes)[0] + 1,))
        self.assertEqual(
            log.find_range(lo, hi),
            tuple(i for i in (1, 2) if lo <= log.entry(i).payload < hi),
        )
        # A direct exact-content find over the envelope agrees with a
        # degenerate interval only when bounds are strictly ordered.
        envelope = log.entry(1).payload
        self.assertEqual(log.find(envelope), (1,))
        self.assertEqual(
            log.find_range(b"", envelope + b"\xff"),
            tuple(i for i in range(len(log)) if log.entry(i).payload < envelope + b"\xff"),
        )


class FindRangeReadOnlyTest(unittest.TestCase):
    def test_find_range_changes_nothing(self):
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
        stage = log.stage
        tags = dict(log._tags)

        self.assertEqual(log.find_range(b"a", b"b"), (0, 2))
        self.assertEqual(log.find_range(b"z", b"zz"), ())
        with self.assertRaises(ValueError):
            log.find_range(b"b", b"a")
        with self.assertRaises(TypeError):
            log.find_range(1, b"z")

        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.inclusion_proof(1), proof)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(log.find("a"), find_hits)
        self.assertEqual(log.stage, stage)
        self.assertEqual(log._tags, tags)
        self.assertTrue(log.verify())
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))


if __name__ == "__main__":
    unittest.main()
