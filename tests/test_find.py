import unittest

from auditchain import AuditLog, verify_auth

KEY = b"super-secret-key"


class FindBasicTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a"):
            self.log.append(record)

    def test_no_match_returns_empty_tuple(self):
        self.assertEqual(self.log.find("missing"), ())
        self.assertEqual(AuditLog().find("a"), ())

    def test_single_and_duplicate_matches_ascending(self):
        self.assertEqual(self.log.find("b"), (1,))
        self.assertEqual(self.log.find("a"), (0, 2, 4))
        self.assertIsInstance(self.log.find("a"), tuple)

    def test_bytes_and_str_are_equivalent(self):
        self.assertEqual(self.log.find(b"a"), self.log.find("a"))

    def test_empty_payload(self):
        self.log.append("")
        self.log.append(b"")
        self.assertEqual(self.log.find(""), (5, 6))
        self.assertEqual(self.log.find(b""), (5, 6))

    def test_unicode_payload(self):
        self.log.append("位置主张")
        self.log.append("位置主张")
        self.assertEqual(self.log.find("位置主张"), (5, 6))
        self.assertEqual(self.log.find("位置主张".encode("utf-8")), (5, 6))

    def test_payload_type_errors(self):
        for bad in (bytearray(b"a"), memoryview(b"a"), 123, None, ["a"]):
            with self.assertRaises(TypeError):
                self.log.find(bad)


class FindRangeTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a"):
            self.log.append(record)

    def test_default_range_is_whole_retained_segment(self):
        self.assertEqual(self.log.find("a"), (0, 2, 4))

    def test_half_open_explicit_range(self):
        self.assertEqual(self.log.find("a", 1, 4), (2,))
        self.assertEqual(self.log.find("a", 2, 5), (2, 4))
        self.assertEqual(self.log.find("a", 0, 2), (0,))
        self.assertEqual(self.log.find("a", 4), (4,))
        self.assertEqual(self.log.find("a", None, 2), (0,))

    def test_empty_range(self):
        self.assertEqual(self.log.find("a", 2, 2), ())
        self.assertEqual(self.log.find("a", 5, 5), ())

    def test_bound_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.find("a", bad)
            with self.assertRaises(TypeError):
                self.log.find("a", 0, bad)

    def test_bound_range_errors(self):
        with self.assertRaises(ValueError):
            self.log.find("a", -1)
        with self.assertRaises(ValueError):
            self.log.find("a", 0, 6)
        with self.assertRaises(ValueError):
            self.log.find("a", 3, 2)
        with self.assertRaises(ValueError):
            self.log.find("a", 6)
        # Boundary values themselves are accepted.
        self.assertEqual(self.log.find("a", 0, 5), (0, 2, 4))


class FindPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a", "b"):
            self.log.append(record)

    def test_prune_drops_released_prefix_from_index(self):
        self.log.prune(2, self.log.seal(2))
        self.assertEqual(self.log.find("a"), (2, 4))
        self.assertEqual(self.log.find("b"), (5,))
        # Explicit ranges may not reach into the released prefix either.
        with self.assertRaises(ValueError):
            self.log.find("a", 0, 4)
        self.assertEqual(self.log.find("a", 2, 4), (2,))

    def test_failed_prune_leaves_index_untouched(self):
        receipt = self.log.seal(3)
        with self.assertRaises(ValueError):
            self.log.prune(2, receipt)  # retain_from != receipt.size
        with self.assertRaises(TypeError):
            self.log.prune(2, "not-a-receipt")
        self.assertEqual(self.log.find("a"), (0, 2, 4))
        self.assertEqual(self.log.find("b"), (1, 5))

    def test_append_after_prune_is_indexed(self):
        self.log.prune(4, self.log.seal(4))
        self.log.append("a")
        self.assertEqual(self.log.find("a"), (4, 6))
        self.assertEqual(self.log.find("c"), ())

    def test_repeated_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.log.append("b")
        self.log.prune(4, self.log.seal(4))
        self.assertEqual(self.log.find("a"), (4,))
        self.assertEqual(self.log.find("b"), (5, 6))
        # Pruning to the current retain point is a no-op for the index.
        self.log.prune(4, self.log.seal(4))
        self.assertEqual(self.log.find("a"), (4,))

    def test_prune_all_then_find(self):
        self.log.prune(6, self.log.seal(6))
        self.assertEqual(self.log.find("a"), ())
        self.log.append("a")
        self.assertEqual(self.log.find("a"), (6,))


class FindReadOnlyTest(unittest.TestCase):
    def test_find_does_not_change_log_or_auth_state(self):
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

        self.assertEqual(log.find("a"), (0, 2))
        self.assertEqual(log.find("missing"), ())

        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.inclusion_proof(1), proof)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(log.stage, stage)
        self.assertEqual(log._tags, tags)
        self.assertTrue(log.verify())
        self.assertTrue(verify_auth(log.entry(0), tag, verifier))


class FindCollisionTest(unittest.TestCase):
    def test_digest_collision_cannot_forge_a_hit(self):
        log = AuditLog()
        log.append(b"a")
        log.append(b"b")
        # Inject a false candidate: index 0 under the digest of b"b".
        # The locator digest may only narrow the search; find() must
        # re-compare the stored payload and reject the impostor.
        (digest_b,) = [key for key, hits in log._index.items() if hits == [1]]
        log._index[digest_b].insert(0, 0)
        self.assertEqual(log.find(b"b"), (1,))
        self.assertEqual(log.find(b"a"), (0,))


class FindAlternateHashTest(unittest.TestCase):
    def test_find_with_sha3(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "a"):
            log.append(record)
        self.assertEqual(log.find("a"), (0, 2))
        self.assertEqual(log.find("b"), (1,))
        self.assertEqual(log.find("c"), ())
        log.prune(1, log.seal(1))
        self.assertEqual(log.find("a"), (2,))

    def test_find_on_keyed_log(self):
        log = AuditLog(key=KEY, hash_name="sha3-256")
        for record in ("x", "y", "x"):
            log.append(record)
        verifier = log.export_verifier()
        tag = log.auth(2)
        self.assertEqual(log.find("x"), (0, 2))
        self.assertTrue(verify_auth(log.entry(2), tag, verifier))


if __name__ == "__main__":
    unittest.main()
