import itertools
import unittest

from auditchain import (
    AuditLog,
    MerkleFrontier,
    decode_merkle_frontier,
    encode_merkle_frontier,
    rebuild_merkle_root,
)

MAGIC = b"auditchain/frontier/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    if isinstance(material, str):
        material = material.encode("utf-8")
    return u64(len(material)) + material


def build(hash_name, size, pairs, *, magic=MAGIC, version=1):
    """Hand-build a frontier encoding with arbitrary bytes/order/content."""
    raw_name = hash_name if isinstance(hash_name, bytes) else hash_name.encode("utf-8")
    out = magic + u64(version) + blob(raw_name) + u64(size)
    out += u64(len(pairs))
    for height, digest in pairs:
        out += u64(height) + blob(digest)
    return out


def expected_heights(size):
    return tuple(h for h in range(64) if (size >> h) & 1)


def full_log(n, *, hash_name="sha256"):
    log = AuditLog(hash_name=hash_name)
    for index in range(n):
        log.append(f"record-{index}")
    return log


class MerkleFrontierConstructorTest(unittest.TestCase):
    def test_positional_fields_and_equality(self):
        log = full_log(13)
        occupied = log.merkle_frontier(13).subtrees
        credential = MerkleFrontier("sha256", 13, occupied)
        self.assertEqual(credential.hash_name, "sha256")
        self.assertEqual(credential.size, 13)
        self.assertEqual([h for h, _ in credential.subtrees], [0, 2, 3])
        self.assertEqual(credential, MerkleFrontier("sha256", 13, occupied))
        # Different content compares unequal.
        other = full_log(13)
        other.append("extra")
        self.assertNotEqual(credential, other.merkle_frontier())
        # A different algorithm or size is a different credential.
        self.assertNotEqual(credential, MerkleFrontier("sha256", 0, ()))
        self.assertNotEqual(
            credential, MerkleFrontier("sha512", 0, ())
        )
        # Frozen and hashable (all fields are immutable).
        with self.assertRaises(Exception):
            credential.size = 4
        self.assertEqual(hash(credential), hash(MerkleFrontier("sha256", 13, occupied)))

    def test_empty_prefix_has_no_subtrees(self):
        credential = MerkleFrontier("sha256", 0, ())
        self.assertEqual(credential.subtrees, ())

    def test_heights_are_exactly_set_bits(self):
        log = full_log(64)
        for size in range(65):
            credential = log.merkle_frontier(size)
            self.assertEqual(
                tuple(h for h, _ in credential.subtrees), expected_heights(size)
            )
            self.assertEqual(len(credential.subtrees), size.bit_count())

    def test_alternate_hash_algorithms(self):
        for hash_name in ("sha224", "sha384", "sha512"):
            log = full_log(11, hash_name=hash_name)
            credential = log.merkle_frontier(11)
            self.assertEqual(credential, MerkleFrontier(hash_name, 11, credential.subtrees))
            for _height, digest in credential.subtrees:
                self.assertEqual(
                    len(digest), AuditLog(hash_name=hash_name)._digest_size
                )

    def test_type_errors(self):
        digest = b"\x01" * 32
        cases = [
            lambda: MerkleFrontier(1, 0, ()),                    # hash_name
            lambda: MerkleFrontier(b"sha256", 0, ()),
            lambda: MerkleFrontier("sha256", "0", ()),          # size
            lambda: MerkleFrontier("sha256", True, ()),
            lambda: MerkleFrontier("sha256", 1.0, ()),
            lambda: MerkleFrontier("sha256", 0, []),            # subtrees
            lambda: MerkleFrontier("sha256", 0, [(0, digest)]),
            lambda: MerkleFrontier("sha256", 1, ((0,),)),       # pair shape
            lambda: MerkleFrontier("sha256", 1, (("0", digest),)),
            lambda: MerkleFrontier("sha256", 1, ((0.0, digest),)),
            lambda: MerkleFrontier("sha256", 1, ((False, digest),)),
            lambda: MerkleFrontier("sha256", 1, ((0, False),)),
            lambda: MerkleFrontier("sha256", 1, ((0, bytearray(32)),)),
            lambda: MerkleFrontier("sha256", 1, ((0, memoryview(b"0" * 32)),)),
        ]
        for build_credential in cases:
            with self.assertRaises(TypeError):
                build_credential()

    def test_value_errors(self):
        digest = b"\x02" * 32
        cases = [
            lambda: MerkleFrontier("no-such-hash", 0, ()),
            lambda: MerkleFrontier("sha256", -1, ()),
            lambda: MerkleFrontier("sha256", 1 << 64, ()),
            lambda: MerkleFrontier("sha256", 1, ((-1, digest),)),
            lambda: MerkleFrontier("sha256", 1, ((1, digest),)),    # bit mismatch
            lambda: MerkleFrontier("sha256", 1, ()),                # missing bit
            lambda: MerkleFrontier("sha256", 0, ((0, digest),)),    # extra bit
            lambda: MerkleFrontier(
                "sha256", 3, ((1, digest), (0, digest))
            ),                                                     # descending
            lambda: MerkleFrontier(
                "sha256", 3, ((0, digest), (0, digest))
            ),                                                     # duplicate
            lambda: MerkleFrontier("sha256", 1, ((0, b"\x03" * 31),)),
            lambda: MerkleFrontier("sha256", 1, ((0, b""),)),
        ]
        for build_credential in cases:
            with self.assertRaises(ValueError):
                build_credential()

    def test_height_64_rejected(self):
        # A u64-sized height is structurally encodable but never a set bit of
        # any u64 size; the constructor must reject it.
        with self.assertRaises(ValueError):
            MerkleFrontier("sha256", 0, ((64, b"\x04" * 32),))


class CaptureMerkleFrontierTest(unittest.TestCase):
    def setUp(self):
        self.log = full_log(21)

    def test_defaults_to_current_length(self):
        credential = self.log.merkle_frontier()
        self.assertEqual(credential.size, len(self.log))
        self.assertEqual(credential, self.log.merkle_frontier(len(self.log)))

    def test_folding_frontier_gives_prefix_root(self):
        # rebuild with an empty retained segment is exactly the prefix root.
        for size in (0, 1, 2, 3, 5, 8, 13, 21):
            credential = self.log.merkle_frontier(size)
            self.assertEqual(
                rebuild_merkle_root(credential, ()),
                self.log.merkle_root(size),
            )

    def test_capture_is_read_only(self):
        before = (
            self.log.retain_from,
            self.log.head,
            tuple(self.log),
            self.log.merkle_root(),
        )
        captured = self.log.merkle_frontier(7)
        self.assertEqual(
            (
                self.log.retain_from,
                self.log.head,
                tuple(self.log),
                self.log.merkle_root(),
            ),
            before,
        )
        # Repeated captures are equal and byte-identical once encoded.
        again = self.log.merkle_frontier(7)
        self.assertEqual(captured, again)
        self.assertEqual(
            encode_merkle_frontier(captured), encode_merkle_frontier(again)
        )

    def test_capture_after_prune(self):
        captured = self.log.merkle_frontier(9)
        self.log.prune(9, self.log.seal(9))
        # The frontier at the retain point is exactly the checkpoint captured
        # before releasing the prefix; request it explicitly.
        at_retain = self.log.merkle_frontier(self.log.retain_from)
        self.assertEqual(at_retain, captured)
        # A size inside the released prefix cannot be captured.
        with self.assertRaises(ValueError):
            self.log.merkle_frontier(8)
        # A later rebuildable size still captures normally.
        later = self.log.merkle_frontier(len(self.log))
        self.assertEqual(
            tuple(h for h, _ in later.subtrees), expected_heights(len(self.log))
        )

    def test_size_type_errors(self):
        for bad in (True, False, "7", 1.0, object()):
            with self.assertRaises(TypeError):
                self.log.merkle_frontier(bad)

    def test_size_value_errors(self):
        with self.assertRaises(ValueError):
            self.log.merkle_frontier(-1)
        with self.assertRaises(ValueError):
            self.log.merkle_frontier(len(self.log) + 1)


class RebuildMerkleRootTest(unittest.TestCase):
    def test_rebuild_matches_full_snapshot_root(self):
        for total, retain in itertools.product((0, 1, 2, 3, 7, 8, 13, 16), repeat=2):
            if retain > total:
                continue
            with self.subTest(total=total, retain=retain):
                reference = full_log(total)
                log = full_log(total)
                frontier = log.merkle_frontier(retain)
                if retain:
                    log.prune(retain, log.seal(retain))
                retained = tuple(entry.entry_hash for entry in log)
                root = rebuild_merkle_root(frontier, retained)
                self.assertEqual(root, reference.merkle_root())

    def test_rebuild_after_further_appends(self):
        log = full_log(10)
        frontier = log.merkle_frontier(4)
        log.prune(4, log.seal(4))
        log.append("after prune 1")
        log.append("after prune 2")
        reference = full_log(10)
        reference.append("after prune 1")
        reference.append("after prune 2")
        retained = tuple(entry.entry_hash for entry in log)
        self.assertEqual(
            rebuild_merkle_root(frontier, retained), reference.merkle_root()
        )

    def test_compare_against_signed_checkpoint_root(self):
        seed = b"\xab" * 32
        log = full_log(13)
        checkpoint = log.sign_root(seed, 13)
        frontier = log.merkle_frontier(5)
        log.prune(5, log.seal(5))
        retained = tuple(entry.entry_hash for entry in log)
        rebuilt = rebuild_merkle_root(frontier, retained)
        # The caller confirms the retained segment follows the released
        # prefix by comparing the rebuilt root with the signed checkpoint.
        self.assertEqual(rebuilt, checkpoint.root)
        # A different retained segment does not match the checkpoint root.
        other = full_log(13)
        other.append("unrelated")
        self.assertNotEqual(
            rebuild_merkle_root(frontier, tuple(e.entry_hash for e in other)),
            checkpoint.root,
        )

    def test_type_errors(self):
        credential = self.log.merkle_frontier(5)
        retained = tuple(entry.entry_hash for entry in self.log)[5:]
        with self.assertRaises(TypeError):
            rebuild_merkle_root("not a frontier", retained)
        with self.assertRaises(TypeError):
            rebuild_merkle_root(None, retained)
        with self.assertRaises(TypeError):
            rebuild_merkle_root(credential, list(retained))
        with self.assertRaises(TypeError):
            rebuild_merkle_root(credential, retained[:-1] + ("not bytes",))
        with self.assertRaises(TypeError):
            rebuild_merkle_root(
                credential, retained[:-1] + (bytearray(retained[-1]),)
            )
        with self.assertRaises(TypeError):
            rebuild_merkle_root(
                credential, retained[:-1] + (memoryview(retained[-1]),)
            )

    def test_value_errors(self):
        credential = self.log.merkle_frontier(5)
        retained = tuple(entry.entry_hash for entry in self.log)[5:]
        with self.assertRaises(ValueError):
            rebuild_merkle_root(credential, retained[:-1] + (b"",))
        with self.assertRaises(ValueError):
            rebuild_merkle_root(credential, retained[:-1] + (b"\x05" * 31,))
        # A frontier corrupted past the frozen constructor is re-validated:
        # emulate a field overwritten via object.__setattr__.
        bypassed = object.__new__(MerkleFrontier)
        object.__setattr__(bypassed, "hash_name", "nope")
        object.__setattr__(bypassed, "size", 5)
        object.__setattr__(bypassed, "subtrees", credential.subtrees)
        with self.assertRaises(ValueError):
            rebuild_merkle_root(bypassed, retained)

    def setUp(self):
        self.log = full_log(13)


class EncodeMerkleFrontierTest(unittest.TestCase):
    def setUp(self):
        self.log = full_log(13)
        self.credential = self.log.merkle_frontier(13)

    def test_magic_prefix_and_layout(self):
        data = encode_merkle_frontier(self.credential)
        self.assertTrue(data.startswith(MAGIC))
        expected = build("sha256", 13, self.credential.subtrees)
        self.assertEqual(data, expected)
        # Magic itself ends in exactly one NUL.
        self.assertEqual(MAGIC, b"auditchain/frontier/v1" + b"\0")

    def test_deterministic_and_read_only(self):
        first = encode_merkle_frontier(self.credential)
        second = encode_merkle_frontier(self.credential)
        self.assertEqual(first, second)
        self.assertEqual(self.credential, self.log.merkle_frontier(13))

    def test_only_accepts_credential(self):
        with self.assertRaises(TypeError):
            encode_merkle_frontier(object())
        with self.assertRaises(TypeError):
            encode_merkle_frontier(("sha256", 0, ()))

    def test_revalidates_corrupted_fields(self):
        bypassed = object.__new__(MerkleFrontier)
        object.__setattr__(bypassed, "hash_name", 7)
        object.__setattr__(bypassed, "size", 0)
        object.__setattr__(bypassed, "subtrees", ())
        with self.assertRaises(TypeError):
            encode_merkle_frontier(bypassed)


class DecodeMerkleFrontierTest(unittest.TestCase):
    def setUp(self):
        self.log = full_log(13)

    def test_roundtrip_all_sizes_and_algorithms(self):
        for hash_name in ("sha256", "sha384", "sha512"):
            log = full_log(33, hash_name=hash_name)
            for size in (0, 1, 2, 3, 5, 8, 13, 21, 32, 33):
                credential = log.merkle_frontier(size)
                data = encode_merkle_frontier(credential)
                restored = decode_merkle_frontier(data)
                self.assertEqual(restored, credential)
                self.assertEqual(encode_merkle_frontier(restored), data)
                # The decoded object is frozen.
                with self.assertRaises(Exception):
                    restored.size = 1
                retained = tuple(entry.entry_hash for entry in log)[size:]
                self.assertEqual(
                    rebuild_merkle_root(restored, retained), log.merkle_root()
                )

    def test_only_accepts_exact_bytes(self):
        data = encode_merkle_frontier(self.log.merkle_frontier(13))
        for bad in (bytearray(data), memoryview(data), data.decode("latin1"), 4, None):
            with self.assertRaises(TypeError):
                decode_merkle_frontier(bad)

    def test_bad_magic_and_version(self):
        credential = self.log.merkle_frontier(13)
        with self.assertRaises(ValueError):
            decode_merkle_frontier(b"auditchain/frontier/v2\0" + b"\0" * 32)
        with self.assertRaises(ValueError):
            decode_merkle_frontier(b"")
        with self.assertRaises(ValueError):
            decode_merkle_frontier(
                build("sha256", 13, credential.subtrees, version=2)
            )

    def test_truncation_at_every_field(self):
        credential = self.log.merkle_frontier(13)
        data = encode_merkle_frontier(credential)
        # Any strict prefix of a valid encoding must be rejected.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_merkle_frontier(data[:cut])

    def test_trailing_bytes_rejected(self):
        data = encode_merkle_frontier(self.log.merkle_frontier(0))
        with self.assertRaises(ValueError):
            decode_merkle_frontier(data + b"\0")

    def test_invalid_utf8(self):
        pairs = self.log.merkle_frontier(1).subtrees
        data = build(b"sha256\xff\xfe", 1, pairs)
        with self.assertRaises(ValueError):
            decode_merkle_frontier(data)

    def test_unknown_algorithm(self):
        digest = b"\x06" * 32
        data = build("no-such-hash", 1, ((0, digest),))
        with self.assertRaises(ValueError):
            decode_merkle_frontier(data)

    def test_digest_width_mismatch(self):
        data = build("sha256", 1, ((0, b"\x07" * 31),))
        with self.assertRaises(ValueError):
            decode_merkle_frontier(data)
        data = build("sha256", 1, ((0, b"\x08" * 64),))
        with self.assertRaises(ValueError):
            decode_merkle_frontier(data)

    def test_illegal_heights(self):
        digest = b"\x09" * 32
        # Descending order.
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build("sha256", 3, ((1, digest), (0, digest))))
        # Heights not the set bits of size.
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build("sha256", 1, ((1, digest),)))
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build("sha256", 1, ()))
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build("sha256", 0, ((0, digest),)))
        # Height 64 is outside the u64 bit range.
        with self.assertRaises(ValueError):
            decode_merkle_frontier(build("sha256", 0, ((64, digest),)))
        # Duplicate heights.
        with self.assertRaises(ValueError):
            decode_merkle_frontier(
                build("sha256", 3, ((0, digest), (0, digest)))
            )

    def test_declared_count_beyond_stream(self):
        # size 0 claims one subtree pair but none follow -> truncated.
        data = MAGIC + u64(1) + blob("sha256") + u64(0) + u64(1)
        with self.assertRaises(ValueError):
            decode_merkle_frontier(data)

    def test_size_u64_limit_handled(self):
        # size == 2**64 cannot be produced by the encoder; a hand-built stream
        # carrying it must be rejected (its set bits never fit the pairs too).
        digest = b"\x0a" * 32
        data = MAGIC + u64(1) + blob("sha256") + u64((1 << 64) - 1) + u64(0)
        with self.assertRaises(ValueError):
            decode_merkle_frontier(data)


if __name__ == "__main__":
    unittest.main()
