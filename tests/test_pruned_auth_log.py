import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from auditchain import (
    AuditLog,
    Verifier,
    dump_pruned_auth,
    load_pruned_auth,
    verify_auth,
)

MAGIC = b"auditchain/pruned-auth/v1\0"
_VERSION = b"\x01"

_KEY = bytes(range(1, 33))
_OTHER_KEY = bytes(range(33, 65))


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _encode(plaintext, nonce=b"N" * 12):
    aad = MAGIC + _VERSION + nonce
    sealed = AESGCM(_KEY).encrypt(nonce, plaintext, aad)
    return MAGIC + _VERSION + nonce + sealed


def _make_pruned_keyed_log(retain_from=3):
    log = AuditLog(key=b"shared-secret")
    verifier = log.export_verifier()
    for record in ("a", b"b", b"c" * 100, "d", "e"):
        log.append(record)
    log.auth(1)            # stage -> 1; tag released by the prune
    log.prune(retain_from, log.seal(retain_from))
    tag4 = log.auth(4)     # retained tag, stage -> 2
    return log, tag4, verifier


class DumpPrunedAuthTest(unittest.TestCase):
    def setUp(self):
        self.log, self.tag4, self.verifier = _make_pruned_keyed_log()

    def test_wire_layout(self):
        data = dump_pruned_auth(self.log, _KEY, nonce=b"N" * 12)
        self.assertTrue(data.startswith(MAGIC + _VERSION + b"N" * 12))
        self.assertGreaterEqual(len(data) - (len(MAGIC) + 1 + 12), 16)
        # Plaintext never leaks a payload or the evolution key.
        self.assertNotIn(b"c" * 100, data)
        self.assertNotIn(b"shared-secret", data)

    def test_random_nonce_default_differs(self):
        first = dump_pruned_auth(self.log, _KEY)
        second = dump_pruned_auth(self.log, _KEY)
        self.assertNotEqual(first, second)
        self.assertEqual(
            load_pruned_auth(first, _KEY).head,
            load_pruned_auth(second, _KEY).head,
        )

    def test_explicit_nonce_is_caller_controlled(self):
        data = dump_pruned_auth(self.log, _KEY, nonce=b"0" * 12)
        self.assertEqual(data[len(MAGIC) + 1:len(MAGIC) + 13], b"0" * 12)

    def test_export_is_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"d"),
        )
        dump_pruned_auth(self.log, _KEY)
        dump_pruned_auth(self.log, _KEY, nonce=b"X" * 12)
        after = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"d"),
        )
        self.assertEqual(before, after)

    def test_dump_type_errors(self):
        with self.assertRaises(TypeError):
            dump_pruned_auth("not a log", _KEY)
        for bad_key in ("k" * 32, bytearray(32), memoryview(bytes(32)), 32):
            with self.assertRaises(TypeError):
                dump_pruned_auth(self.log, bad_key)
        with self.assertRaises(TypeError):
            dump_pruned_auth(self.log, _KEY, nonce="N" * 12)
        with self.assertRaises(TypeError):
            dump_pruned_auth(self.log, _KEY, nonce=bytearray(12))

    def test_dump_value_errors(self):
        with self.assertRaises(ValueError):
            dump_pruned_auth(self.log, bytes(31))
        with self.assertRaises(ValueError):
            dump_pruned_auth(self.log, bytes(33))
        with self.assertRaises(ValueError):
            dump_pruned_auth(self.log, _KEY, nonce=b"short")
        with self.assertRaises(ValueError):
            dump_pruned_auth(self.log, _KEY, nonce=b"x" * 11)

    def test_rejects_unpruned_keyed_log(self):
        log = AuditLog(key=b"k")
        log.append("a")
        with self.assertRaises(ValueError):
            dump_pruned_auth(log, _KEY)

    def test_rejects_keyless_pruned_log(self):
        log = AuditLog()
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_pruned_auth(log, _KEY)

    def test_rejects_encrypted_history(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.encrypt("secret", _KEY)
        log.append("b")
        log.prune(2, log.seal(2))  # even with the ciphertext released
        with self.assertRaises(ValueError):
            dump_pruned_auth(log, _KEY)

    def test_failure_is_atomic(self):
        with self.assertRaises(ValueError):
            dump_pruned_auth(self.log, bytes(31))
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(self.log.stage, 2)
        # The log still dumps fine after the failed attempt.
        load_pruned_auth(dump_pruned_auth(self.log, _KEY), _KEY)


class LoadPrunedAuthRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log, self.tag4, self.verifier = _make_pruned_keyed_log()
        self.data = dump_pruned_auth(self.log, _KEY, nonce=b"N" * 12)

    def _restore(self):
        return load_pruned_auth(self.data, _KEY)

    def test_state_matches(self):
        restored = self._restore()
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, self.log.retain_from)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
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
        self.assertEqual(restored.find(b"c" * 100), ())  # released by the prune
        self.assertEqual(restored.find(b"missing"), ())

    def test_stage_restored(self):
        self.assertEqual(self.log.stage, 2)
        self.assertEqual(self._restore().stage, 2)

    def test_verifier_flag_restored(self):
        self.assertTrue(self._restore()._verifier_exported)
        with self.assertRaises(ValueError):
            self._restore().export_verifier()

    def test_verifier_flag_zero_allows_export(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        restored = load_pruned_auth(dump_pruned_auth(log, _KEY), _KEY)
        verifier = restored.export_verifier()
        self.assertIsInstance(verifier, Verifier)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_old_tag_still_verifies(self):
        restored = self._restore()
        self.assertTrue(
            verify_auth(restored.entry(4), self.tag4, self.verifier)
        )

    def test_forward_security_continues(self):
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
        self.assertEqual(len(restored), len(self.log) + 1)
        self.assertEqual(len(self.log), 5)
        restored.rotate_key()
        self.assertEqual(restored.stage, self.log.stage + 1)
        # Can be pruned again like any live log.
        restored.prune(5, restored.seal(5))
        self.assertEqual(restored.retain_from, 5)

    def test_fully_pruned_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        for record in ("a", "b", "c"):
            log.append(record)
        log.auth(0)
        log.prune(3, log.seal(3))
        self.assertEqual(log.entries(), [])
        restored = load_pruned_auth(dump_pruned_auth(log, _KEY), _KEY)
        self.assertEqual(len(restored), 3)
        self.assertEqual(restored.retain_from, 3)
        self.assertEqual(restored.entries(), [])
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        restored.append("d")
        self.assertEqual(restored.entry(3).index, 3)

    def test_non_default_hash(self):
        log = AuditLog(key=b"shared-secret", hash_name="sha512")
        log.append("a")
        log.append("b")
        log.auth(0)
        log.prune(1, log.seal(1))
        restored = load_pruned_auth(dump_pruned_auth(log, _KEY), _KEY)
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        self.assertEqual(len(restored.head), 64)


class LoadPrunedAuthErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log, _, _ = _make_pruned_keyed_log()
        self.data = dump_pruned_auth(self.log, _KEY, nonce=b"N" * 12)

    def test_data_type(self):
        for bad in (bytearray(self.data), memoryview(self.data), "x", 42):
            with self.assertRaises(TypeError):
                load_pruned_auth(bad, _KEY)

    def test_key_type(self):
        for bad in ("k" * 32, bytearray(32), memoryview(bytes(32)), None):
            with self.assertRaises(TypeError):
                load_pruned_auth(self.data, bad)

    def test_key_length(self):
        with self.assertRaises(ValueError):
            load_pruned_auth(self.data, bytes(31))
        with self.assertRaises(ValueError):
            load_pruned_auth(self.data, bytes(33))

    def test_bad_magic(self):
        broken = b"x" + self.data[1:]
        with self.assertRaises(ValueError):
            load_pruned_auth(broken, _KEY)

    def test_bad_version(self):
        broken = MAGIC + b"\x02" + self.data[len(MAGIC) + 1:]
        with self.assertRaises(ValueError):
            load_pruned_auth(broken, _KEY)

    def test_truncated(self):
        for cut in (
            len(MAGIC),
            len(MAGIC) + 1,
            len(MAGIC) + 1 + 12,
            len(self.data) - 1,
        ):
            with self.assertRaises(ValueError):
                load_pruned_auth(self.data[:cut], _KEY)

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            load_pruned_auth(self.data, _OTHER_KEY)

    def test_ciphertext_tamper_fails(self):
        broken = bytearray(self.data)
        broken[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            load_pruned_auth(bytes(broken), _KEY)

    def test_nonce_tamper_fails_aad(self):
        broken = bytearray(self.data)
        broken[len(MAGIC) + 1] ^= 0x01
        with self.assertRaises(ValueError):
            load_pruned_auth(bytes(broken), _KEY)

    def test_magic_tamper_fails_aad(self):
        broken = bytearray(self.data)
        broken[0] ^= 0x01
        with self.assertRaises(ValueError):
            load_pruned_auth(bytes(broken), _KEY)

    def test_auth_log_frame_rejected(self):
        # An auth-log (unpruned variant) frame must not parse here.
        from auditchain import dump_auth

        log = AuditLog(key=b"shared-secret")
        log.append("a")
        foreign = dump_auth(log, _KEY, nonce=b"N" * 12)
        with self.assertRaises(ValueError):
            load_pruned_auth(foreign, _KEY)

    def test_load_is_read_only(self):
        view = bytes(self.data)
        load_pruned_auth(view, _KEY)
        self.assertEqual(view, self.data)


class LoadPrunedAuthPlaintextValidationTest(unittest.TestCase):
    """Valid AEAD frames whose decrypted plaintext violates the framing."""

    def setUp(self):
        self.log, _, _ = _make_pruned_keyed_log()
        self.nonce = b"N" * 12
        self.good = dump_pruned_auth(self.log, _KEY, nonce=self.nonce)
        aad = MAGIC + _VERSION + self.nonce
        sealed = self.good[len(MAGIC) + 1 + 12:]
        plaintext = AESGCM(_KEY).decrypt(self.nonce, sealed, aad)
        self.fields = self._parse(plaintext)

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

    def _forge(self, **overrides):
        (name, size, retain_from, checkpoint,
         frontier, entries, tail) = self.fields
        return _encode(self._build(
            overrides.get("name", name),
            overrides.get("size", size),
            overrides.get("retain_from", retain_from),
            overrides.get("checkpoint", checkpoint),
            overrides.get("frontier", frontier),
            overrides.get("entries", entries),
            overrides.get("tail", tail),
        ), nonce=self.nonce)

    def test_baseline_plaintext_loads(self):
        self.assertEqual(load_pruned_auth(self.good, _KEY).head, self.log.head)

    def test_trailing_bytes(self):
        plaintext = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_pruned_auth(_encode(plaintext + b"\x00", nonce=self.nonce), _KEY)

    def test_truncated_plaintext(self):
        plaintext = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_pruned_auth(_encode(plaintext[:-1], nonce=self.nonce), _KEY)

    def test_bad_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(name=b"\xff\xff"), _KEY)

    def test_unknown_hash(self):
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(name=b"nonesuch"), _KEY)

    def test_retain_point_zero_rejected(self):
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(retain_from=0), _KEY)

    def test_retain_point_beyond_count_rejected(self):
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(retain_from=7, size=6), _KEY)

    def test_bad_checkpoint_width(self):
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(checkpoint=b"\x00" * 31), _KEY)

    def test_frontier_must_be_set_bits(self):
        # r == 3 requires heights 0 and 1; dropping height 0 leaves a gap.
        _, _, _, _, frontier, _, _ = self.fields
        with self.assertRaises(ValueError):
            load_pruned_auth(
                self._forge(frontier=frontier[1:]), _KEY
            )

    def test_frontier_heights_must_be_ascending(self):
        _, _, _, _, frontier, _, _ = self.fields
        with self.assertRaises(ValueError):
            load_pruned_auth(
                self._forge(frontier=list(reversed(frontier))), _KEY
            )

    def test_bad_retained_count(self):
        # Claim one more retained entry than n - r, but keep n/r unchanged;
        # the parser runs off the end or desyncs and must reject the frame.
        (name, size, retain_from, checkpoint,
         frontier, entries, tail) = self.fields
        plaintext = self._build(
            name, size, retain_from, checkpoint, frontier, entries, tail
        )
        # Locate the retained-count field: it follows the last frontier blob.
        cursor = len(blob(name)) + 16 + len(blob(checkpoint)) + 8
        for height, digest in frontier:
            cursor += 8 + len(blob(digest))
        declared = int.from_bytes(plaintext[cursor:cursor + 8], "big")
        tampered = (
            plaintext[:cursor] + u64(declared + 1) + plaintext[cursor + 8:]
        )
        with self.assertRaises(ValueError):
            load_pruned_auth(_encode(tampered, nonce=self.nonce), _KEY)

    def test_bad_entry_index(self):
        _, _, _, _, _, entries, _ = self.fields
        bad_entries = [
            (index + 1, payload, previous_hash, entry_hash)
            if i == 0
            else (index, payload, previous_hash, entry_hash)
            for i, (index, payload, previous_hash, entry_hash) in enumerate(entries)
        ]
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(entries=bad_entries), _KEY)

    def test_bad_entry_digest_width(self):
        _, _, _, _, _, entries, _ = self.fields
        index, payload, previous_hash, entry_hash = entries[0]
        bad_entries = [(index, payload, previous_hash, entry_hash[:-1])] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(entries=bad_entries), _KEY)

    def test_bad_root_width(self):
        root, head, stage, key_material, exported = self.fields[6]
        with self.assertRaises(ValueError):
            load_pruned_auth(
                self._forge(tail=(root[:-1], head, stage, key_material, exported)),
                _KEY,
            )

    def test_bad_head_width(self):
        root, head, stage, key_material, exported = self.fields[6]
        with self.assertRaises(ValueError):
            load_pruned_auth(
                self._forge(tail=(root, head + b"\x00", stage, key_material, exported)),
                _KEY,
            )

    def test_bad_flag(self):
        root, head, stage, key_material, _exported = self.fields[6]
        with self.assertRaises(ValueError):
            load_pruned_auth(
                self._forge(tail=(root, head, stage, key_material, 2)), _KEY
            )

    def test_empty_evolution_key(self):
        root, head, stage, _key_material, exported = self.fields[6]
        with self.assertRaises(ValueError):
            load_pruned_auth(
                self._forge(tail=(root, head, stage, b"", exported)), _KEY
            )

    def test_wrong_width_evolution_key_after_evolution(self):
        # stage == 2 here, so K must be the 32-byte digest width.
        root, head, stage, _key_material, exported = self.fields[6]
        with self.assertRaises(ValueError):
            load_pruned_auth(
                self._forge(tail=(root, head, stage, b"too-short", exported)),
                _KEY,
            )

    def test_wrong_root_rejected(self):
        root, head, stage, key_material, exported = self.fields[6]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(root))
        with self.assertRaises(ValueError):
            load_pruned_auth(
                self._forge(tail=(wrong, head, stage, key_material, exported)), _KEY
            )

    def test_wrong_head_rejected(self):
        root, head, stage, key_material, exported = self.fields[6]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(head))
        with self.assertRaises(ValueError):
            load_pruned_auth(
                self._forge(tail=(root, wrong, stage, key_material, exported)), _KEY
            )

    def test_broken_chain_rejected(self):
        name, size, retain_from, cp, frontier, entries, tail = self.fields
        index, payload, previous_hash, entry_hash = entries[0]
        broken_previous = bytes(d ^ 0x01 for d in previous_hash)
        bad_entries = [(index, payload, broken_previous, entry_hash)] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(entries=bad_entries), _KEY)


if __name__ == "__main__":
    unittest.main()
