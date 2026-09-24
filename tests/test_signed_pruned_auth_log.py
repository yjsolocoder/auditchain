import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    dump_signed_pruned_auth,
    load_signed_pruned_auth,
    verify_auth,
)

MAGIC = b"auditchain/signed-pruned-auth/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _public_key(seed):
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _sign(seed, body):
    return Ed25519PrivateKey.from_private_bytes(seed).sign(body)


PUBLIC_A = _public_key(_SEED_A)
PUBLIC_B = _public_key(_SEED_B)


def _frame(log, root, head):
    parts = [
        blob(log.hash_name.encode("utf-8")),
        u64(len(log)),
        u64(log.retain_from),
        blob(log._checkpoint_head),
        u64(len(log._frontier)),
    ]
    for height in sorted(log._frontier):
        parts.append(u64(height))
        parts.append(blob(log._frontier[height]))
    parts.append(u64(len(log._entries)))
    for entry in log._entries:
        parts.append(u64(entry.index))
        parts.append(blob(entry.payload))
        parts.append(blob(entry.previous_hash))
        parts.append(blob(entry.entry_hash))
    parts.append(blob(root))
    parts.append(blob(head))
    parts.append(u64(log.stage))
    parts.append(blob(log._key))
    parts.append(u64(1 if log._verifier_exported else 0))
    return b"".join(parts)


def _encode(log, seed=_SEED_A):
    root = log.merkle_root()
    head = log.head
    body = MAGIC + u64(1) + _frame(log, root, head)
    return body + _sign(seed, body)


def _make_pruned_keyed_log(retain_from=3):
    log = AuditLog(key=b"shared-secret")
    verifier = log.export_verifier()
    for record in ("a", b"b", b"c" * 100, "d", "e"):
        log.append(record)
    log.auth(1)            # stage -> 1; tag released by the prune
    log.prune(retain_from, log.seal(retain_from))
    tag4 = log.auth(4)     # retained tag, stage -> 2
    log.rotate_key()       # stage -> 3
    return log, tag4, verifier


class DumpSignedPrunedAuthTest(unittest.TestCase):
    def setUp(self):
        self.log, self.tag4, self.verifier = _make_pruned_keyed_log()

    def test_wire_layout(self):
        data = dump_signed_pruned_auth(self.log, _SEED_A)
        self.assertTrue(data.startswith(MAGIC + u64(1)))
        self.assertEqual(data, _encode(self.log))
        # The trailing 64 bytes are an Ed25519 signature over the body.
        body, signature = data[:-64], data[-64:]
        Ed25519PrivateKey.from_private_bytes(_SEED_A).public_key().verify(
            signature, body
        )
        # The frame is plaintext: the live evolution key is visible.
        self.assertIn(self.log._key, data)

    def test_deterministic_and_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"d"),
            self.log._key,
        )
        first = dump_signed_pruned_auth(self.log, _SEED_A)
        second = dump_signed_pruned_auth(self.log, _SEED_A)
        self.assertEqual(first, second)
        after = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"d"),
            self.log._key,
        )
        self.assertEqual(before, after)

    def test_distinct_seeds_differ_only_in_signature(self):
        first = dump_signed_pruned_auth(self.log, _SEED_A)
        second = dump_signed_pruned_auth(self.log, _SEED_B)
        self.assertEqual(first[:-64], second[:-64])
        self.assertNotEqual(first[-64:], second[-64:])

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            dump_signed_pruned_auth("not a log", _SEED_A)
        with self.assertRaises(TypeError):
            dump_signed_pruned_auth(self.log, "not bytes")
        with self.assertRaises(TypeError):
            dump_signed_pruned_auth(self.log, bytearray(_SEED_A))

    def test_seed_length(self):
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(self.log, b"short")
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(self.log, b"s" * 33)

    def test_unpruned_log_rejected(self):
        log = AuditLog(key=b"k")
        log.append("x")
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(log, _SEED_A)

    def test_keyless_pruned_log_rejected(self):
        log = AuditLog()
        for i in range(3):
            log.append(f"r{i}")
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(log, _SEED_A)

    def test_encrypt_history_rejected(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.encrypt("secret", b"e" * 32)
        log.append("b")
        log.prune(2, log.seal(2))  # even with the ciphertext released
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(log, _SEED_A)

    def test_fully_pruned_round_trip_dump(self):
        log = AuditLog(key=b"k")
        for record in ("a", "b", "c"):
            log.append(record)
        log.auth(0)
        log.prune(3, log.seal(3))
        data = dump_signed_pruned_auth(log, _SEED_A)
        restored = load_signed_pruned_auth(data, PUBLIC_A)
        self.assertEqual(len(restored), 3)
        self.assertEqual(restored.retain_from, 3)
        self.assertEqual(restored.entries(), [])
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())

    def test_stage_zero_keyed_log(self):
        # A pruned keyed log that never evolved still carries the arbitrary
        # non-digest-width construction key.
        log = AuditLog(key=b"shared-secret")
        for record in ("a", "b", "c", "d"):
            log.append(record)
        log.prune(2, log.seal(2))
        restored = load_signed_pruned_auth(
            dump_signed_pruned_auth(log, _SEED_A), PUBLIC_A
        )
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored._key, b"shared-secret")
        self.assertEqual(restored.head, log.head)


class LoadSignedPrunedAuthRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log, self.tag4, self.verifier = _make_pruned_keyed_log()
        self.data = dump_signed_pruned_auth(self.log, _SEED_A)

    def _restore(self):
        return load_signed_pruned_auth(self.data, PUBLIC_A)

    def test_state_matches(self):
        restored = self._restore()
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, self.log.retain_from)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(restored.stage, self.log.stage)
        self.assertEqual(restored.hash_name, self.log.hash_name)
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertEqual(list(restored), list(self.log))
        self.assertTrue(restored.verify())

    def test_proofs_match(self):
        restored = self._restore()
        for index in range(3, 5):
            self.assertEqual(
                restored.inclusion_proof(index),
                self.log.inclusion_proof(index),
            )
        self.assertEqual(
            restored.consistency_proof(3, 5),
            self.log.consistency_proof(3, 5),
        )

    def test_find_index_matches(self):
        restored = self._restore()
        self.assertEqual(restored.find(b"d"), self.log.find(b"d"))
        self.assertEqual(restored.find(b"e"), self.log.find(b"e"))
        self.assertEqual(restored.find(b"c" * 100), ())  # released by prune
        self.assertEqual(restored.find(b"missing"), ())

    def test_old_tag_still_verifies(self):
        restored = self._restore()
        self.assertTrue(
            verify_auth(restored.entry(4), self.tag4, self.verifier)
        )

    def test_verifier_exported_flag_restored(self):
        self.assertTrue(self._restore()._verifier_exported)
        with self.assertRaises(ValueError):
            self._restore().export_verifier()

    def test_unexported_flag_restored(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        restored = load_signed_pruned_auth(
            dump_signed_pruned_auth(log, _SEED_A), PUBLIC_A
        )
        verifier = restored.export_verifier()
        self.assertEqual(verifier.key, log.export_verifier().key)

    def test_evolution_continues_identically(self):
        restored = self._restore()
        self.log.append("f")
        restored.append("f")
        tag_orig = self.log.auth(5)
        tag_rest = restored.auth(5)
        self.assertEqual(tag_orig, tag_rest)
        self.assertEqual(self.log.stage, restored.stage)
        self.assertTrue(verify_auth(restored.entry(5), tag_orig, self.verifier))

    def test_independent_and_mutable(self):
        restored = self._restore()
        restored.append("separate")
        restored.encrypt(b"hidden", b"k" * 32, nonce=b"0" * 12)
        restored.rotate_key()
        self.assertEqual(len(self.log), 5)
        self.assertEqual(len(restored), 7)
        self.assertEqual(restored.stage, self.log.stage + 1)
        for entry in self.log:
            self.assertEqual(restored.entry(entry.index), entry)

    def test_can_be_pruned_again(self):
        restored = self._restore()
        restored.prune(4, restored.seal(4))
        self.assertEqual(restored.retain_from, 4)
        self.assertEqual(restored.head, self.log.head)
        # A further prune round-trips through the signed export too.
        again = load_signed_pruned_auth(
            dump_signed_pruned_auth(restored, _SEED_A), PUBLIC_A
        )
        self.assertEqual(again.retain_from, 4)
        self.assertEqual(again.head, restored.head)
        self.assertEqual(again.merkle_root(), restored.merkle_root())

    def test_non_default_hash(self):
        log = AuditLog(key=b"k", hash_name="sha512")
        for i in range(3):
            log.append(f"r{i}")
        log.auth(0)
        log.prune(1, log.seal(1))
        restored = load_signed_pruned_auth(
            dump_signed_pruned_auth(log, _SEED_A), PUBLIC_A
        )
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        log.append("r3")
        restored.append("r3")
        self.assertEqual(log.auth(3), restored.auth(3))


class LoadSignedPrunedAuthErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log, _, _ = _make_pruned_keyed_log()
        self.data = dump_signed_pruned_auth(self.log, _SEED_A)

    def test_data_type(self):
        for bad in (bytearray(self.data), memoryview(self.data), "x", 42):
            with self.assertRaises(TypeError):
                load_signed_pruned_auth(bad, PUBLIC_A)

    def test_public_key_type(self):
        for bad in ("k" * 32, bytearray(32), memoryview(bytes(32)), None):
            with self.assertRaises(TypeError):
                load_signed_pruned_auth(self.data, bad)

    def test_public_key_length(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self.data, b"short")
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self.data, b"p" * 33)

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(
                b"auditchain/signed-pruned-auth/v2\0" + self.data[len(MAGIC):],
                PUBLIC_A,
            )
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(b"", PUBLIC_A)
        # A first-byte flip is caught before any signature work.
        broken = bytearray(self.data)
        broken[0] ^= 0x01
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(bytes(broken), PUBLIC_A)

    def test_bad_version(self):
        body = MAGIC + u64(2) + self.data[len(MAGIC) + 8:-64]
        data = body + _sign(_SEED_A, body)
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(data, PUBLIC_A)

    def test_truncation(self):
        for cut in (
            len(MAGIC),
            len(self.data) - 65,
            len(self.data) - 64,
            len(self.data) - 1,
        ):
            with self.assertRaises(ValueError):
                load_signed_pruned_auth(self.data[:cut], PUBLIC_A)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self.data + b"x", PUBLIC_A)

    def test_signature_failure(self):
        # Wrong public key.
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self.data, PUBLIC_B)
        # A flipped body byte invalidates the signature.
        flipped = bytearray(self.data)
        flipped[len(MAGIC) + 12] ^= 1
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(bytes(flipped), PUBLIC_A)
        # A flipped signature byte.
        flipped = bytearray(self.data)
        flipped[-1] ^= 1
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(bytes(flipped), PUBLIC_A)

    def test_foreign_formats_rejected(self):
        from auditchain import dump_signed_auth, dump_pruned_auth

        # The unpruned signed-auth stream must not parse here.
        full = AuditLog(key=b"k")
        full.append("a")
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(dump_signed_auth(full, _SEED_A), PUBLIC_A)
        # The AES-GCM pruned-auth stream must not parse here either.
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(
                dump_pruned_auth(self.log, b"k" * 32, nonce=b"N" * 12),
                PUBLIC_A,
            )

    def test_load_is_read_only(self):
        view = bytes(self.data)
        load_signed_pruned_auth(view, PUBLIC_A)
        self.assertEqual(view, self.data)


class LoadSignedPrunedAuthFrameValidationTest(unittest.TestCase):
    """Valid signatures over frames that violate the pruned-auth framing."""

    def setUp(self):
        self.log, _, _ = _make_pruned_keyed_log()
        self.good_frame = _frame(self.log, self.log.merkle_root(), self.log.head)
        self.fields = self._parse(self.good_frame)

    @staticmethod
    def _parse(data):
        cursor = 0

        def take_u64():
            nonlocal cursor
            value = int.from_bytes(data[cursor:cursor + 8], "big")
            cursor += 8
            return value

        def take_blob():
            nonlocal cursor
            length = take_u64()
            value = data[cursor:cursor + length]
            cursor += length
            return value

        name = take_blob()
        size = take_u64()
        retain_from = take_u64()
        checkpoint = take_blob()
        frontier = []
        for _ in range(take_u64()):
            frontier.append((take_u64(), take_blob()))
        entries = []
        for _ in range(take_u64()):
            entries.append((take_u64(), take_blob(), take_blob(), take_blob()))
        tail = (take_blob(), take_blob(), take_u64(), take_blob(), take_u64())
        assert cursor == len(data)
        return name, size, retain_from, checkpoint, frontier, entries, tail

    @staticmethod
    def _build(name, size, retain_from, checkpoint, frontier, entries, tail):
        parts = [
            blob(name),
            u64(size),
            u64(retain_from),
            blob(checkpoint),
            u64(len(frontier)),
        ]
        for height, digest in frontier:
            parts += [u64(height), blob(digest)]
        parts.append(u64(len(entries)))
        for index, payload, previous_hash, entry_hash in entries:
            parts += [u64(index), blob(payload), blob(previous_hash), blob(entry_hash)]
        root, head, stage, key_material, exported = tail
        parts += [blob(root), blob(head), u64(stage), blob(key_material), u64(exported)]
        return b"".join(parts)

    def _forge(self, *, version=1, seed=_SEED_A, **overrides):
        (name, size, retain_from, checkpoint,
         frontier, entries, tail) = self.fields
        frame = self._build(
            overrides.get("name", name),
            overrides.get("size", size),
            overrides.get("retain_from", retain_from),
            overrides.get("checkpoint", checkpoint),
            overrides.get("frontier", frontier),
            overrides.get("entries", entries),
            overrides.get("tail", tail),
        )
        body = MAGIC + u64(version) + frame
        return body + _sign(seed, body)

    def _assert_rejected(self, data):
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(data, PUBLIC_A)

    def test_baseline_loads(self):
        self.assertEqual(
            load_signed_pruned_auth(self._forge(), PUBLIC_A).head,
            self.log.head,
        )

    def test_trailing_bytes_in_body(self):
        frame = self._build(*self.fields)
        body = MAGIC + u64(1) + frame + b"x"
        self._assert_rejected(body + _sign(_SEED_A, body))

    def test_truncated_frame(self):
        frame = self._build(*self.fields)
        body = MAGIC + u64(1) + frame[:-1]
        self._assert_rejected(body + _sign(_SEED_A, body))

    def test_bad_utf8_hash_name(self):
        self._assert_rejected(self._forge(name=b"\xff\xff"))

    def test_unknown_hash(self):
        self._assert_rejected(self._forge(name=b"nonesuch"))

    def test_retain_point_zero_rejected(self):
        self._assert_rejected(self._forge(retain_from=0))

    def test_retain_point_beyond_count_rejected(self):
        self._assert_rejected(self._forge(retain_from=7, size=6))

    def test_bad_checkpoint_width(self):
        self._assert_rejected(self._forge(checkpoint=b"\x00" * 31))

    def test_frontier_must_be_set_bits(self):
        _, _, _, _, frontier, _, _ = self.fields
        self._assert_rejected(self._forge(frontier=frontier[1:]))

    def test_frontier_heights_must_be_ascending(self):
        _, _, _, _, frontier, _, _ = self.fields
        self._assert_rejected(self._forge(frontier=list(reversed(frontier))))

    def test_bad_retained_count(self):
        (name, size, retain_from, checkpoint,
         frontier, entries, tail) = self.fields
        # Build a frame declaring one more retained entry than n - r without
        # supplying the record; the parser must run off the end / desync.
        parts = [
            blob(name),
            u64(size),
            u64(retain_from),
            blob(checkpoint),
            u64(len(frontier)),
        ]
        for height, digest in frontier:
            parts += [u64(height), blob(digest)]
        parts.append(u64(len(entries) + 1))
        for index, payload, previous_hash, entry_hash in entries:
            parts += [u64(index), blob(payload), blob(previous_hash), blob(entry_hash)]
        root, head, stage, key_material, exported = tail
        parts += [blob(root), blob(head), u64(stage), blob(key_material), u64(exported)]
        body = MAGIC + u64(1) + b"".join(parts)
        self._assert_rejected(body + _sign(_SEED_A, body))

    def test_bad_entry_index(self):
        _, _, _, _, _, entries, _ = self.fields
        index, payload, previous_hash, entry_hash = entries[0]
        bad_entries = [(index + 1, payload, previous_hash, entry_hash)] + entries[1:]
        self._assert_rejected(self._forge(entries=bad_entries))

    def test_bad_entry_digest_width(self):
        _, _, _, _, _, entries, _ = self.fields
        index, payload, previous_hash, entry_hash = entries[0]
        bad_entries = [(index, payload, previous_hash, entry_hash[:-1])] + entries[1:]
        self._assert_rejected(self._forge(entries=bad_entries))

    def test_bad_root_width(self):
        root, head, stage, key_material, exported = self.fields[6]
        self._assert_rejected(
            self._forge(tail=(root[:-1], head, stage, key_material, exported))
        )

    def test_bad_head_width(self):
        root, head, stage, key_material, exported = self.fields[6]
        self._assert_rejected(
            self._forge(tail=(root, head + b"\x00", stage, key_material, exported))
        )

    def test_bad_flag(self):
        root, head, stage, key_material, _exported = self.fields[6]
        self._assert_rejected(
            self._forge(tail=(root, head, stage, key_material, 2))
        )

    def test_empty_evolution_key(self):
        root, head, stage, _key_material, exported = self.fields[6]
        self._assert_rejected(
            self._forge(tail=(root, head, stage, b"", exported))
        )

    def test_wrong_width_evolution_key_after_evolution(self):
        # stage == 3 here, so K must be the 32-byte digest width.
        root, head, stage, _key_material, exported = self.fields[6]
        self._assert_rejected(
            self._forge(tail=(root, head, stage, b"too-short", exported))
        )

    def test_wrong_root_rejected(self):
        root, head, stage, key_material, exported = self.fields[6]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(root))
        self._assert_rejected(
            self._forge(tail=(wrong, head, stage, key_material, exported))
        )

    def test_wrong_head_rejected(self):
        root, head, stage, key_material, exported = self.fields[6]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(head))
        self._assert_rejected(
            self._forge(tail=(root, wrong, stage, key_material, exported))
        )

    def test_broken_chain_rejected(self):
        _, _, _, _, _, entries, tail = self.fields
        index, payload, previous_hash, entry_hash = entries[0]
        broken_previous = bytes(d ^ 0x01 for d in previous_hash)
        bad_entries = [(index, payload, broken_previous, entry_hash)] + entries[1:]
        self._assert_rejected(self._forge(entries=bad_entries))

    def test_corrupted_payload_rejected(self):
        _, _, _, _, _, entries, tail = self.fields
        index, _payload, previous_hash, entry_hash = entries[0]
        bad_entries = [(index, b"zzz", previous_hash, entry_hash)] + entries[1:]
        self._assert_rejected(self._forge(entries=bad_entries))

    def test_frame_signed_by_other_seed_fails_signature(self):
        # A structurally perfect frame re-signed by the wrong seed must still
        # be rejected at verification, before parsing.
        self._assert_rejected(self._forge(seed=_SEED_B))


if __name__ == "__main__":
    unittest.main()
