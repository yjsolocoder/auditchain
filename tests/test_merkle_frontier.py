import unittest

from auditchain import (
    AuditLog,
    MerkleFrontier,
    rebuild_merkle_root,
)


def filled_log(count, hash_name="sha256"):
    log = AuditLog(hash_name=hash_name)
    for index in range(count):
        log.append(f"entry-{index}")
    return log


class MerkleFrontierConstructorTest(unittest.TestCase):
    def setUp(self):
        self.log = filled_log(7)
        self.credential = self.log.merkle_frontier()

    def test_fields_in_order_and_positional_construction(self):
        self.assertEqual(
            tuple(MerkleFrontier.__dataclass_fields__),
            ("hash_name", "size", "subtrees"),
        )
        credential = MerkleFrontier(
            "sha256", self.credential.size, self.credential.subtrees
        )
        self.assertEqual(credential, self.credential)
        self.assertEqual(credential.hash_name, "sha256")
        self.assertEqual(credential.size, 7)
        self.assertEqual(
            tuple(height for height, _ in credential.subtrees), (0, 1, 2)
        )

    def test_equality_by_all_fields(self):
        again = MerkleFrontier(
            self.credential.hash_name,
            self.credential.size,
            self.credential.subtrees,
        )
        self.assertEqual(self.credential, again)
        self.assertNotEqual(
            self.credential,
            MerkleFrontier("sha256", 6, self.log.merkle_frontier(6).subtrees),
        )
        self.assertNotEqual(self.credential, "not a frontier")

    def test_frozen(self):
        with self.assertRaises(Exception):
            self.credential.size = 1

    def test_hash_name_checked(self):
        base = self.credential
        with self.assertRaises(TypeError):
            MerkleFrontier(1, base.size, base.subtrees)
        with self.assertRaises(ValueError):
            MerkleFrontier("not-a-hash", base.size, base.subtrees)
        with self.assertRaises(ValueError):
            MerkleFrontier("shake_128", base.size, base.subtrees)

    def test_size_checked(self):
        base = self.credential
        for bad, exc in (
            ("7", TypeError),
            (True, TypeError),
            (7.0, TypeError),
            (-1, ValueError),
            (1 << 64, ValueError),
        ):
            with self.assertRaises(exc):
                MerkleFrontier("sha256", bad, base.subtrees)

    def test_empty_size_requires_no_subtrees(self):
        credential = MerkleFrontier("sha256", 0, ())
        self.assertEqual(credential.subtrees, ())
        with self.assertRaises(ValueError):
            MerkleFrontier("sha256", 0, ((0, b"\x00" * 32),))

    def test_subtrees_container_checked(self):
        base = self.credential
        with self.assertRaises(TypeError):
            MerkleFrontier("sha256", base.size, list(base.subtrees))
        with self.assertRaises(TypeError):
            MerkleFrontier("sha256", base.size, (list(base.subtrees[0]),) + base.subtrees[1:])
        with self.assertRaises(TypeError):
            MerkleFrontier("sha256", base.size, ((0,),) + base.subtrees[1:])

    def test_height_type_and_value_checked(self):
        base = self.credential
        digest = b"\x00" * 32
        with self.assertRaises(TypeError):
            MerkleFrontier("sha256", 1, (("0", digest),))
        with self.assertRaises(TypeError):
            MerkleFrontier("sha256", 1, ((True, digest),))
        with self.assertRaises(ValueError):
            MerkleFrontier("sha256", 1, ((-1, digest),))

    def test_digest_type_and_width_checked(self):
        with self.assertRaises(TypeError):
            MerkleFrontier("sha256", 1, ((0, bytearray(32)),))
        with self.assertRaises(TypeError):
            MerkleFrontier("sha256", 1, ((0, memoryview(b"\x00" * 32)),))
        with self.assertRaises(ValueError):
            MerkleFrontier("sha256", 1, ((0, b"\x00" * 31),))
        with self.assertRaises(ValueError):
            MerkleFrontier("sha256", 1, ((0, b""),))

    def test_heights_must_be_strictly_ascending(self):
        digest = b"\x00" * 32
        with self.assertRaises(ValueError):
            MerkleFrontier("sha256", 3, ((1, digest), (0, digest)))
        with self.assertRaises(ValueError):
            MerkleFrontier("sha256", 3, ((0, digest), (0, digest)))

    def test_heights_must_be_exactly_the_set_bits_of_size(self):
        digest = b"\x00" * 32
        # 6 == 0b110: heights must be exactly (1, 2).
        MerkleFrontier("sha256", 6, ((1, digest), (2, digest)))
        with self.assertRaises(ValueError):
            MerkleFrontier("sha256", 6, ((1, digest),))
        with self.assertRaises(ValueError):
            MerkleFrontier("sha256", 6, ((0, digest), (1, digest), (2, digest)))
        with self.assertRaises(ValueError):
            MerkleFrontier("sha256", 6, ((1, digest), (3, digest)))

    def test_alternate_hash_algorithm(self):
        log = filled_log(5, hash_name="sha3-256")
        credential = log.merkle_frontier()
        self.assertEqual(credential.hash_name, "sha3-256")
        self.assertEqual(
            tuple(height for height, _ in credential.subtrees), (0, 2)
        )
        for _, digest in credential.subtrees:
            self.assertEqual(len(digest), 32)


class MerkleFrontierCaptureTest(unittest.TestCase):
    def test_default_size_is_full_log(self):
        log = filled_log(7)
        self.assertEqual(log.merkle_frontier(), log.merkle_frontier(len(log)))

    def test_subtrees_cover_prefix(self):
        log = filled_log(11)
        for size in range(12):
            credential = log.merkle_frontier(size)
            self.assertEqual(credential.size, size)
            heights = tuple(height for height, _ in credential.subtrees)
            expected = tuple(h for h in range(64) if (size >> h) & 1)
            self.assertEqual(heights, expected)
            self.assertEqual(sum(1 << h for h in heights), size)

    def test_capture_is_read_only(self):
        log = filled_log(5)
        before = (len(log), log.head, log.merkle_root())
        log.merkle_frontier()
        self.assertEqual((len(log), log.head, log.merkle_root()), before)

    def test_size_type_and_range(self):
        log = filled_log(4)
        with self.assertRaises(TypeError):
            log.merkle_frontier("3")
        with self.assertRaises(ValueError):
            log.merkle_frontier(-1)
        with self.assertRaises(ValueError):
            log.merkle_frontier(5)

    def test_pruned_prefix_not_capturable(self):
        log = filled_log(8)
        receipt = log.seal(5)
        log.prune(5, receipt)
        with self.assertRaises(ValueError):
            log.merkle_frontier(4)
        # The retain point itself and later snapshots stay capturable.
        self.assertEqual(log.merkle_frontier(5).size, 5)
        self.assertEqual(log.merkle_frontier().size, 8)

    def test_empty_prefix_capturable(self):
        log = filled_log(3)
        credential = log.merkle_frontier(0)
        self.assertEqual(credential, MerkleFrontier("sha256", 0, ()))

    def test_appends_do_not_change_captured_frontier(self):
        log = filled_log(6)
        before = log.merkle_frontier()
        log.append("more")
        self.assertEqual(log.merkle_frontier(6), before)


class RebuildMerkleRootTest(unittest.TestCase):
    def test_rebuilds_full_snapshot_root(self):
        log = filled_log(11)
        receipt = log.seal(6)
        log.prune(6, receipt)
        frontier = log.merkle_frontier(6)
        retained = tuple(entry.entry_hash for entry in log)
        self.assertEqual(
            rebuild_merkle_root(frontier, retained), log.merkle_root()
        )

    def test_rebuilds_every_prefix(self):
        log = filled_log(13)
        for size in range(14):
            frontier = log.merkle_frontier(size)
            retained = tuple(
                log.entry(index).entry_hash for index in range(size, len(log))
            )
            self.assertEqual(
                rebuild_merkle_root(frontier, retained), log.merkle_root()
            )

    def test_empty_frontier_and_segment_gives_empty_root(self):
        frontier = MerkleFrontier("sha256", 0, ())
        self.assertEqual(
            rebuild_merkle_root(frontier, ()),
            AuditLog().merkle_root(),
        )

    def test_rebuild_from_genesis(self):
        log = filled_log(5)
        frontier = log.merkle_frontier(0)
        retained = tuple(entry.entry_hash for entry in log)
        self.assertEqual(
            rebuild_merkle_root(frontier, retained), log.merkle_root()
        )

    def test_frontier_type_checked(self):
        for bad in (None, "x", b"b", 1, object()):
            with self.assertRaises(TypeError):
                rebuild_merkle_root(bad, ())

    def test_frontier_fields_revalidated(self):
        log = filled_log(3)
        frontier = log.merkle_frontier()
        forged = MerkleFrontier("sha256", 3, frontier.subtrees)
        object.__setattr__(forged, "size", -1)
        with self.assertRaises(ValueError):
            rebuild_merkle_root(forged, ())
        forged2 = MerkleFrontier("sha256", 3, frontier.subtrees)
        object.__setattr__(forged2, "subtrees", ((0, b"\x00" * 31),))
        with self.assertRaises(ValueError):
            rebuild_merkle_root(forged2, ())

    def test_retained_hashes_container_checked(self):
        log = filled_log(3)
        frontier = log.merkle_frontier()
        for bad in (None, "x", b"b", 1, [b"\x00" * 32]):
            with self.assertRaises(TypeError):
                rebuild_merkle_root(frontier, bad)

    def test_retained_hash_type_checked(self):
        log = filled_log(3)
        frontier = log.merkle_frontier()
        with self.assertRaises(TypeError):
            rebuild_merkle_root(frontier, (bytearray(32),))
        with self.assertRaises(TypeError):
            rebuild_merkle_root(frontier, (memoryview(b"\x00" * 32),))
        with self.assertRaises(TypeError):
            rebuild_merkle_root(frontier, ("x" * 32,))

    def test_retained_hash_empty_or_wrong_width(self):
        log = filled_log(3)
        frontier = log.merkle_frontier()
        with self.assertRaises(ValueError):
            rebuild_merkle_root(frontier, (b"",))
        with self.assertRaises(ValueError):
            rebuild_merkle_root(frontier, (b"\x00" * 31,))
        with self.assertRaises(ValueError):
            rebuild_merkle_root(frontier, (b"\x00" * 33,))

    def test_rebuild_is_read_only(self):
        log = filled_log(6)
        frontier = log.merkle_frontier()
        snapshot = (frontier.hash_name, frontier.size, frontier.subtrees)
        retained = tuple(entry.entry_hash for entry in log)
        rebuild_merkle_root(frontier, retained)
        self.assertEqual(
            (frontier.hash_name, frontier.size, frontier.subtrees), snapshot
        )

    def test_alternate_hash_algorithm(self):
        log = filled_log(9, hash_name="sha3-256")
        frontier = log.merkle_frontier(4)
        retained = tuple(log.entry(index).entry_hash for index in range(4, 9))
        self.assertEqual(rebuild_merkle_root(frontier, retained), log.merkle_root())


if __name__ == "__main__":
    unittest.main()
