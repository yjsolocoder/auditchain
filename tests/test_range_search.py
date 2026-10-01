import unittest

from auditchain import AuditLog, verify_auth

KEY = b"super-secret-key"
ENC_KEY = b"k" * 32


def make_log(records=("a", "b", "aa", "c", "a", "b")):
    log = AuditLog()
    for record in records:
        log.append(record)
    return log


class RangeSearchBasicTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_left_closed_right_open(self):
        self.assertEqual(self.log.range_search(b"a", b"c"), (0, 1, 2, 4, 5))
        self.assertEqual(self.log.range_search(b"b", b"c"), (1, 5))
        # The right boundary itself is excluded.
        self.assertEqual(self.log.range_search(b"c", b"d"), (3,))
        self.assertEqual(self.log.range_search(b"d", b"e"), ())
        # The left boundary itself is included.
        self.assertEqual(self.log.range_search(b"aa", b"b"), (2,))

    def test_result_is_ascending_tuple(self):
        result = self.log.range_search(b"a", b"c")
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, tuple(sorted(result)))

    def test_bytes_and_str_are_equivalent(self):
        self.assertEqual(
            self.log.range_search(b"a", b"c"), self.log.range_search("a", "c")
        )

    def test_unicode_bounds(self):
        log = make_log(())
        log.append("位置")
        log.append("位置主张")
        upper = "位置" + "￿"  # U+FFFF -> EF BF BF, greater than any continuation
        self.assertEqual(log.range_search("位置", upper), (0, 1))
        self.assertEqual(log.range_search("位置", "位置主张"), (0,))
        self.assertEqual(log.range_search("位置主张", upper), (1,))

    def test_raw_byte_order_including_zero_bytes(self):
        log = AuditLog()
        log.append(b"a")
        log.append(b"a\x00")
        log.append(b"a\x00\x01")
        log.append(b"a\x01")
        self.assertEqual(log.range_search(b"a\x00", b"a\x01"), (1, 2))
        self.assertEqual(log.range_search(b"", b"a\x00\xff"), (0, 1, 2))

    def test_equal_bounds_return_empty(self):
        for bound in (b"a", b"", b"zzz", "位置"):
            self.assertEqual(self.log.range_search(bound, bound), ())

    def test_inverted_bounds_raise_value_error(self):
        with self.assertRaises(ValueError):
            self.log.range_search(b"c", b"a")
        # UTF-8 normalization happens before the comparison.
        with self.assertRaises(ValueError):
            self.log.range_search("b", "a")

    def test_bound_type_errors(self):
        for bad in (bytearray(b"a"), memoryview(b"a"), 123, None, ["a"], 1.5):
            with self.assertRaises(TypeError):
                self.log.range_search(bad, b"a")
            with self.assertRaises(TypeError):
                self.log.range_search(b"a", bad)

    def test_empty_log(self):
        log = AuditLog()
        self.assertEqual(log.range_search(b"a", b"z"), ())
        # Equal bounds stay empty on an empty log, inverted still raise.
        self.assertEqual(log.range_search(b"a", b"a"), ())
        with self.assertRaises(ValueError):
            log.range_search(b"z", b"a")

    def test_encrypted_entries_compare_by_envelope_bytes_only(self):
        log = AuditLog()
        log.append("plain")
        entry = log.encrypt("secret", ENC_KEY)
        magic = b"auditchain/encrypted-entry/v1\0"
        # The sealed envelope falls in a raw-byte interval covering the
        # magic prefix, and the plaintext "secret" is never compared.
        self.assertEqual(
            log.range_search(magic, magic + b"\xff"),
            (entry.index,),
        )
        self.assertEqual(log.range_search(b"secret", b"secret\xff"), ())
        self.assertEqual(log.range_search(b"plain", b"plao"), (0,))


class RangeSearchIndexRangeTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_default_range_is_whole_retained_segment(self):
        self.assertEqual(self.log.range_search(b"a", b"z"), (0, 1, 2, 3, 4, 5))

    def test_half_open_explicit_range(self):
        self.assertEqual(self.log.range_search(b"a", b"z", 1, 4), (1, 2, 3))
        self.assertEqual(self.log.range_search(b"a", b"z", 0, 2), (0, 1))
        self.assertEqual(self.log.range_search(b"a", b"z", 4), (4, 5))
        self.assertEqual(self.log.range_search(b"a", b"z", None, 2), (0, 1))

    def test_empty_index_range(self):
        self.assertEqual(self.log.range_search(b"a", b"z", 2, 2), ())
        self.assertEqual(self.log.range_search(b"a", b"z", 6, 6), ())

    def test_bound_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.range_search(b"a", b"z", bad)
            with self.assertRaises(TypeError):
                self.log.range_search(b"a", b"z", 0, bad)

    def test_bound_range_errors(self):
        with self.assertRaises(ValueError):
            self.log.range_search(b"a", b"z", -1)
        with self.assertRaises(ValueError):
            self.log.range_search(b"a", b"z", 0, 7)
        with self.assertRaises(ValueError):
            self.log.range_search(b"a", b"z", 3, 2)
        with self.assertRaises(ValueError):
            self.log.range_search(b"a", b"z", 7)
        # Boundary values themselves are accepted.
        self.assertEqual(
            self.log.range_search(b"a", b"z", 0, 6), (0, 1, 2, 3, 4, 5)
        )

    def test_content_check_runs_before_index_range_check(self):
        # Inverted content bounds and bad bound types surface regardless of
        # the index range.
        with self.assertRaises(ValueError):
            self.log.range_search(b"z", b"a", 0, 1)
        with self.assertRaises(TypeError):
            self.log.range_search(1, b"a", 0, 1)


class RangeSearchPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a", "b"):
            self.log.append(record)

    def test_default_range_is_retained_segment(self):
        self.log.prune(2, self.log.seal(2))
        self.assertEqual(self.log.range_search(b"a", b"z"), (2, 3, 4, 5))

    def test_explicit_range_may_not_reach_released_prefix(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(ValueError):
            self.log.range_search(b"a", b"z", 0, 4)
        self.assertEqual(self.log.range_search(b"a", b"z", 2, 4), (2, 3))

    def test_prune_all_then_search(self):
        self.log.prune(6, self.log.seal(6))
        self.assertEqual(self.log.range_search(b"a", b"z"), ())
        self.log.append("a")
        self.assertEqual(self.log.range_search(b"a", b"z"), (6,))


class RangeSearchReadOnlyTest(unittest.TestCase):
    def test_range_search_does_not_change_log_or_auth_state(self):
        log = AuditLog(key=KEY)
        for record in ("a", "b", "a"):
            log.append(record)
        verifier = log.export_verifier()
        tag = log.auth(0)
        head = log.head
        root = log.merkle_root()
        proof = log.inclusion_proof(1)
        entries = log.entries()
        stage = log.stage
        tags = dict(log._tags)

        log.range_search(b"a", b"c")
        log.range_search(b"missing", b"n")
        log.range_search(b"a", b"c", 0, 2)
        # Failures leave state unchanged as well.
        for bad in ((1, b"a"), (b"a", 1), (b"b", b"a")):
            try:
                log.range_search(*bad)
            except (TypeError, ValueError):
                pass

        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.inclusion_proof(1), proof)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(log.stage, stage)
        self.assertEqual(log._tags, tags)
        self.assertTrue(log.verify())
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))

    def test_existing_find_results_unchanged(self):
        log = AuditLog()
        for record in ("a", "b", "a"):
            log.append(record)
        before = {p: log.find(p) for p in ("a", "b", "missing")}
        log.range_search(b"a", b"z")
        after = {p: log.find(p) for p in ("a", "b", "missing")}
        self.assertEqual(before, after)


class RangeSearchAlternateHashTest(unittest.TestCase):
    def test_sha3_256(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "a"):
            log.append(record)
        self.assertEqual(log.range_search(b"a", b"c"), (0, 1, 2))
        self.assertEqual(log.range_search(b"c", b"d"), ())
        log.prune(1, log.seal(1))
        self.assertEqual(log.range_search(b"a", b"z"), (1, 2))


if __name__ == "__main__":
    unittest.main()
