import unittest

from auditchain import AuditLog


class FindBasicTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("alpha", "beta", "alpha", "gamma", "beta", "alpha"):
            self.log.append(record)

    def test_find_returns_ascending_tuple_of_absolute_indices(self):
        self.assertEqual(self.log.find("alpha"), (0, 2, 5))
        self.assertEqual(self.log.find(b"beta"), (1, 4))
        self.assertIsInstance(self.log.find("alpha"), tuple)

    def test_str_and_bytes_payloads_are_equivalent(self):
        self.assertEqual(self.log.find("alpha"), self.log.find(b"alpha"))

    def test_no_match_returns_empty_tuple(self):
        self.assertEqual(self.log.find("delta"), ())
        self.assertEqual(self.log.find(b""), ())

    def test_empty_payload_supported(self):
        log = AuditLog()
        log.append("")
        log.append("x")
        log.append(b"")
        self.assertEqual(log.find(b""), (0, 2))
        self.assertEqual(log.find(""), (0, 2))

    def test_unicode_payload_supported(self):
        log = AuditLog()
        log.append("位置声明：北纬40°")
        log.append("other")
        log.append("位置声明：北纬40°")
        self.assertEqual(log.find("位置声明：北纬40°"), (0, 2))
        self.assertEqual(log.find("位置声明：北纬40°".encode("utf-8")), (0, 2))
        self.assertEqual(log.find("位置声明：北纬41°"), ())

    def test_payload_type_restricted_to_bytes_and_str(self):
        for bad in (bytearray(b"alpha"), memoryview(b"alpha"), 123, None, ("alpha",)):
            with self.assertRaises(TypeError):
                self.log.find(bad)


class FindRangeTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a", "b", "a"):
            self.log.append(record)

    def test_explicit_half_open_range(self):
        self.assertEqual(self.log.find("a", 1, 5), (2, 4))
        self.assertEqual(self.log.find("a", 0, 7), (0, 2, 4, 6))
        self.assertEqual(self.log.find("a", 3, 4), ())

    def test_start_only_and_stop_only(self):
        self.assertEqual(self.log.find("a", 4), (4, 6))
        self.assertEqual(self.log.find("a", None, 3), (0, 2))

    def test_empty_range_is_empty_result(self):
        self.assertEqual(self.log.find("a", 3, 3), ())
        self.assertEqual(self.log.find("a", 7, 7), ())

    def test_bounds_must_be_non_bool_integers(self):
        for bad in (True, "1", 1.5, b"1"):
            with self.assertRaises(TypeError):
                self.log.find("a", bad)
            with self.assertRaises(TypeError):
                self.log.find("a", 0, bad)

    def test_bounds_out_of_range(self):
        with self.assertRaises(ValueError):
            self.log.find("a", -1)
        with self.assertRaises(ValueError):
            self.log.find("a", 0, 8)
        with self.assertRaises(ValueError):
            self.log.find("a", 5, 4)


class FindPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "a", "c", "a", "b", "a"):
            self.log.append(record)

    def test_default_range_starts_at_retain_from(self):
        self.log.prune(3, self.log.seal(3))
        self.assertEqual(self.log.find("a"), (4, 6))
        self.assertEqual(self.log.find("b"), (5,))
        self.assertEqual(self.log.find("c"), (3,))

    def test_explicit_start_below_retain_from_rejected(self):
        self.log.prune(3, self.log.seal(3))
        with self.assertRaises(ValueError):
            self.log.find("a", 0)
        with self.assertRaises(ValueError):
            self.log.find("a", 2, 5)
        self.assertEqual(self.log.find("a", 3, 7), (4, 6))

    def test_append_after_prune_is_indexed(self):
        self.log.prune(4, self.log.seal(4))
        self.log.append("a")
        self.log.append("d")
        self.assertEqual(self.log.find("a"), (4, 6, 7))
        self.assertEqual(self.log.find("d"), (8,))

    def test_repeated_prune_keeps_index_consistent(self):
        self.log.prune(2, self.log.seal(2))
        self.assertEqual(self.log.find("a"), (2, 4, 6))
        self.log.append("b")
        self.log.prune(5, self.log.seal(5))
        self.assertEqual(self.log.find("a"), (6,))
        self.assertEqual(self.log.find("b"), (5, 7))
        self.assertEqual(self.log.find("c"), ())

    def test_noop_prune_keeps_index(self):
        self.log.prune(3, self.log.seal(3))
        self.log.prune(3, self.log.seal(3))
        self.assertEqual(self.log.find("a"), (4, 6))

    def test_failed_prune_leaves_index_untouched(self):
        receipt = self.log.seal(3)
        other = AuditLog()
        for record in ("x", "y", "z"):
            other.append(record)
        wrong = other.seal(3)
        with self.assertRaises(ValueError):
            self.log.prune(3, wrong)
        with self.assertRaises(ValueError):
            self.log.prune(2, receipt)
        with self.assertRaises(TypeError):
            self.log.prune("3", receipt)
        self.assertEqual(self.log.find("a"), (0, 2, 4, 6))
        self.assertEqual(self.log.find("b"), (1, 5))


class FindPurityTest(unittest.TestCase):
    def test_find_does_not_mutate_log_or_auth_state(self):
        log = AuditLog(key=b"super-secret-key")
        for record in ("a", "b", "a"):
            log.append(record)
        verifier = log.export_verifier()
        tag = log.auth(0)
        before = (
            log.head,
            len(log),
            log.stage,
            log.entries(),
            dict(log._tags),
            log.merkle_root(),
            log.inclusion_proof(1),
            log.consistency_proof(1, 3),
        )
        self.assertEqual(log.find("a"), (0, 2))
        self.assertEqual(log.find("missing"), ())
        after = (
            log.head,
            len(log),
            log.stage,
            log.entries(),
            dict(log._tags),
            log.merkle_root(),
            log.inclusion_proof(1),
            log.consistency_proof(1, 3),
        )
        self.assertEqual(before, after)
        from auditchain import verify_auth

        self.assertTrue(verify_auth(log.entry(0), tag, verifier))

    def test_find_matches_linear_scan(self):
        log = AuditLog()
        records = ["x", "yy", "x", "", "yy", "x", "z", ""]
        for record in records:
            log.append(record)
        for target in ("x", "yy", "", "absent"):
            expected = tuple(
                index for index, record in enumerate(records) if record == target
            )
            self.assertEqual(log.find(target), expected)

    def test_digest_collision_cannot_forge_a_match(self):
        log = AuditLog()
        log.append("real")
        log.append("decoy")
        # Inject the decoy's index into the bucket of "real"'s digest: the
        # locator points at an entry whose payload differs, and find must
        # confirm against the stored payload instead of trusting the digest.
        from auditchain import _find_digest

        bucket = log._locator[_find_digest(b"real", log.hash_name)]
        bucket.append(1)
        self.assertEqual(log.find("real"), (0,))
        self.assertEqual(log.find("decoy"), (1,))


class FindAlternateHashTest(unittest.TestCase):
    def test_find_with_sha3(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "a", "c", "a"):
            log.append(record)
        self.assertEqual(log.find("a"), (0, 2, 4))
        self.assertEqual(log.find("b"), (1,))
        self.assertEqual(log.find("zz"), ())
        log.prune(2, log.seal(2))
        self.assertEqual(log.find("a"), (2, 4))
        log.append("a")
        self.assertEqual(log.find("a"), (2, 4, 5))


if __name__ == "__main__":
    unittest.main()
