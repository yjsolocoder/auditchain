import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from auditchain import (
    AuditLog,
    Verifier,
    dump_pruned_auth,
    load_pruned_auth,
    verify_auth,
    verify_inclusion,
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


def make_log():
    log = AuditLog(key=b"shared-secret")
    verifier = log.export_verifier()
    for record in ("a", "b", "c", "d", "e", b"f" * 100, "g"):
        log.append(record)
    log.prune(3, log.seal(3))
    tag4 = log.auth(4)
    log.rotate_key()
    # stage: auth(4) -> 1, rotate -> 2
    return log, verifier, tag4


class DumpPrunedAuthTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag4 = make_log()

    def test_wire_layout(self):
        data = dump_pruned_auth(self.log, _KEY, nonce=b"N" * 12)
        self.assertTrue(data.startswith(MAGIC + _VERSION + b"N" * 12))
        # Everything after D || 0x01 || N is ciphertext||tag (>=16 bytes).
        self.assertGreaterEqual(len(data) - (len(MAGIC) + 1 + 12), 16)
        # Plaintext never leaks a payload or the evolution key.
        self.assertNotIn(b"f" * 100, data)
        self.assertNotIn(b"shared-secret", data)

    def test_random_nonce_default_differs(self):
        first = dump_pruned_auth(self.log, _KEY)
        second = dump_pruned_auth(self.log, _KEY)
        self.assertNotEqual(first, second)
        # Both load to the same state.
        self.assertEqual(
            load_pruned_auth(first, _KEY).head,
            load_pruned_auth(second, _KEY).head,
        )

    def test_explicit_nonce_is_caller_controlled(self):
        data = dump_pruned_auth(self.log, _KEY, nonce=b"0" * 12)
        self.assertEqual(data[len(MAGIC) + 1:len(MAGIC) + 13], b"0" * 12)
        # Deterministic under an explicit nonce.
        self.assertEqual(
            data, dump_pruned_auth(self.log, _KEY, nonce=b"0" * 12)
        )

    def test_export_is_read_only(self):
        before = (
            len(self.log),
            self.log.retain_from,
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"d"),
        )
        dump_pruned_auth(self.log, _KEY)
        dump_pruned_auth(self.log, _KEY)
        after = (
            len(self.log),
            self.log.retain_from,
            self.log.head,
            self.log.stage,
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

    def test_requires_pruned_log(self):
        log = AuditLog(key=b"k")
        log.append("a")
        with self.assertRaises(ValueError):
            dump_pruned_auth(log, _KEY)

    def test_requires_keyed_log(self):
        plain = AuditLog()
        plain.append("a")
        plain.append("b")
        plain.prune(1, plain.seal(1))
        with self.assertRaises(ValueError):
            dump_pruned_auth(plain, _KEY)

    def test_rejects_encrypted_history(self):
        log = AuditLog(key=b"k")
        log.encrypt("secret", _KEY)
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_pruned_auth(log, _KEY)

    def test_rejects_released_encrypted_history(self):
        # The ciphertext itself was released by the prune, but the nonce
        # history remains and still disqualifies the log.
        log = AuditLog(key=b"k")
        log.encrypt("secret", _KEY)
        log.append("b")
        log.append("c")
        log.prune(2, log.seal(2))
        self.assertFalse(log._encrypted_index)
        with self.assertRaises(ValueError):
            dump_pruned_auth(log, _KEY)

    def test_failure_is_atomic(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_pruned_auth(log, bytes(31))
        self.assertEqual(len(log), 2)
        self.assertEqual(log.retain_from, 1)
        self.assertEqual(log.stage, 0)
        # The log still dumps fine after the failed attempt.
        load_pruned_auth(dump_pruned_auth(log, _KEY), _KEY)


class LoadPrunedAuthRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag4 = make_log()
        self.data = dump_pruned_auth(self.log, _KEY, nonce=b"N" * 12)

    def _restore(self):
        return load_pruned_auth(self.data, _KEY)

    def test_state_matches(self):
        restored = self._restore()
        self.assertIsInstance(restored, AuditLog)
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, 3)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.hash_name, self.log.hash_name)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(restored._checkpoint_head, self.log._checkpoint_head)
        self.assertEqual(restored._frontier, self.log._frontier)
        self.assertTrue(restored.verify())

    def test_entries_and_find_index_match(self):
        restored = self._restore()
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertEqual(list(restored), list(self.log))
        self.assertEqual(restored.find(b"d"), (3,))
        self.assertEqual(restored.find(b"f" * 100), (5,))
        # Released payloads are gone from the index.
        self.assertEqual(restored.find(b"a"), ())
        self.assertEqual(restored.find(b"missing"), ())

    def test_proofs_match(self):
        restored = self._restore()
        for index in range(3, len(self.log)):
            proof = restored.inclusion_proof(index)
            self.assertEqual(proof, self.log.inclusion_proof(index))
            self.assertTrue(
                verify_inclusion(
                    restored.entry(index).entry_hash,
                    index,
                    len(restored),
                    restored.merkle_root(),
                    proof,
                )
            )

    def test_stage_and_flag_restored(self):
        restored = self._restore()
        self.assertEqual(restored.stage, 2)
        self.assertTrue(restored._verifier_exported)
        with self.assertRaises(ValueError):
            restored.export_verifier()

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

    def test_forward_security_continues(self):
        # A tag minted after the dump continues evolution identically in both.
        restored = self._restore()
        self.log.append("h")
        restored.append("h")
        tag_orig = self.log.auth(7)
        tag_rest = restored.auth(7)
        self.assertEqual(tag_orig, tag_rest)
        self.assertEqual(self.log.stage, restored.stage)
        # Old verifier material still verifies tags from both processes.
        self.assertTrue(verify_auth(restored.entry(4), self.tag4, self.verifier))
        self.assertTrue(verify_auth(restored.entry(7), tag_orig, self.verifier))

    def test_independent_and_mutable(self):
        restored = self._restore()
        restored.append("separate")
        self.assertEqual(len(restored), len(self.log) + 1)
        restored.rotate_key()
        self.assertEqual(restored.stage, self.log.stage + 1)
        # The original log is untouched.
        self.assertEqual(len(self.log), 7)
        self.assertEqual(self.log.stage, 2)

    def test_further_prune_after_restore(self):
        restored = self._restore()
        receipt = restored.seal(5)
        restored.prune(5, receipt)
        self.assertEqual(restored.retain_from, 5)
        self.assertEqual(len(restored), 7)
        self.assertTrue(restored.verify())
        # And the twice-pruned log still round-trips.
        again = load_pruned_auth(dump_pruned_auth(restored, _KEY), _KEY)
        self.assertEqual(again.retain_from, 5)
        self.assertEqual(again.head, restored.head)
        self.assertEqual(again.merkle_root(), restored.merkle_root())

    def test_stage_zero_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        restored = load_pruned_auth(dump_pruned_auth(log, _KEY), _KEY)
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored.retain_from, 1)
        self.assertEqual(restored.head, log.head)

    def test_prune_to_end_round_trip(self):
        # retain_from == n: no retained entries at all.
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.append("b")
        log.auth(0)
        log.prune(2, log.seal(2))
        restored = load_pruned_auth(dump_pruned_auth(log, _KEY), _KEY)
        self.assertEqual(len(restored), 2)
        self.assertEqual(restored.retain_from, 2)
        self.assertEqual(restored.entries(), [])
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)

    def test_non_default_hash(self):
        log = AuditLog(key=b"shared-secret", hash_name="sha512")
        for record in ("a", "b", "c", "d"):
            log.append(record)
        log.auth(1)
        log.prune(2, log.seal(2))
        restored = load_pruned_auth(dump_pruned_auth(log, _KEY), _KEY)
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        self.assertEqual(len(restored.head), 64)


class LoadPrunedAuthErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log, _, _ = make_log()
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
        for cut in (len(MAGIC), len(MAGIC) + 1, len(self.data) - 1):
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
        # Flipping a magic byte breaks the AAD even though parsing still
        # starts at the same offsets.
        broken = bytearray(self.data)
        broken[0] ^= 0x01
        with self.assertRaises(ValueError):
            load_pruned_auth(bytes(broken), _KEY)

    def test_load_is_read_only(self):
        view = bytes(self.data)
        load_pruned_auth(view, _KEY)
        self.assertEqual(view, self.data)


class LoadPrunedAuthPlaintextValidationTest(unittest.TestCase):
    """Valid AEAD frames whose decrypted plaintext violates the framing."""

    def setUp(self):
        self.log, _, _ = make_log()
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
        frontier = [(take_u64(), take_blob()) for _ in range(take_u64())]
        entries = [
            (take_u64(), take_blob(), take_blob(), take_blob())
            for _ in range(take_u64())
        ]
        tail = (take_blob(), take_blob(), take_u64(), take_blob(), take_u64())
        assert cursor == len(data)
        return name, size, retain_from, checkpoint, frontier, entries, tail

    @staticmethod
    def _build(name, size, retain_from, checkpoint, frontier, entries, tail):
        parts = [blob(name), u64(size), u64(retain_from), blob(checkpoint)]
        parts.append(u64(len(frontier)))
        for height, digest in frontier:
            parts += [u64(height), blob(digest)]
        parts.append(u64(len(entries)))
        for index, payload, previous_hash, entry_hash in entries:
            parts += [u64(index), blob(payload), blob(previous_hash), blob(entry_hash)]
        root, head, stage, key_material, exported = tail
        parts += [blob(root), blob(head), u64(stage), blob(key_material), u64(exported)]
        return b"".join(parts)

    def _forge(self, **overrides):
        fields = list(self.fields)
        names = (
            "name", "size", "retain_from", "checkpoint",
            "frontier", "entries", "tail",
        )
        for key, value in overrides.items():
            fields[names.index(key)] = value
        return _encode(self._build(*fields), nonce=self.nonce)

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

    def test_zero_retain_from(self):
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(retain_from=0), _KEY)

    def test_retain_from_beyond_size(self):
        _, size, _, _, _, _, _ = self.fields
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(retain_from=size + 1), _KEY)

    def test_bad_checkpoint_width(self):
        _, _, _, checkpoint, _, _, _ = self.fields
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(checkpoint=checkpoint[:-1]), _KEY)

    def test_frontier_heights_not_ascending(self):
        log = AuditLog(key=b"k")
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            log.append(record)
        log.prune(3, log.seal(3))  # frontier heights {0, 1}
        nonce = b"M" * 12
        good = dump_pruned_auth(log, _KEY, nonce=nonce)
        sealed = good[len(MAGIC) + 1 + 12:]
        plaintext = AESGCM(_KEY).decrypt(nonce, sealed, MAGIC + _VERSION + nonce)
        name, size, retain_from, checkpoint, frontier, entries, tail = self._parse(
            plaintext
        )
        self.assertEqual([height for height, _ in frontier], [0, 1])
        broken = self._build(
            name, size, retain_from, checkpoint,
            [frontier[1], frontier[0]], entries, tail,
        )
        with self.assertRaises(ValueError):
            load_pruned_auth(_encode(broken, nonce=nonce), _KEY)

    def test_frontier_not_set_bits(self):
        _, _, _, _, frontier, _, _ = self.fields
        # Drop one subtree: the heights no longer cover the set bits of r.
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(frontier=frontier[1:]), _KEY)

    def test_bad_frontier_digest_width(self):
        _, _, _, _, frontier, _, _ = self.fields
        height, digest = frontier[0]
        broken = [(height, digest[:-1])] + frontier[1:]
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(frontier=broken), _KEY)

    def test_retained_count_mismatch(self):
        name, size, retain_from, checkpoint, frontier, entries, tail = self.fields
        parts = [blob(name), u64(size), u64(retain_from), blob(checkpoint)]
        parts.append(u64(len(frontier)))
        for height, digest in frontier:
            parts += [u64(height), blob(digest)]
        parts.append(u64(len(entries) + 1))  # one entry too many
        for index, payload, previous_hash, entry_hash in entries:
            parts += [u64(index), blob(payload), blob(previous_hash), blob(entry_hash)]
        root, head, stage, key_material, exported = tail
        parts += [blob(root), blob(head), u64(stage), blob(key_material), u64(exported)]
        with self.assertRaises(ValueError):
            load_pruned_auth(
                _encode(b"".join(parts), nonce=self.nonce), _KEY
            )

    def test_bad_entry_index(self):
        _, _, retain_from, _, _, entries, _ = self.fields
        index, payload, previous_hash, entry_hash = entries[0]
        broken = [(retain_from + 1, payload, previous_hash, entry_hash)] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(entries=broken), _KEY)

    def test_bad_entry_digest_width(self):
        _, _, _, _, _, entries, _ = self.fields
        index, payload, previous_hash, entry_hash = entries[0]
        broken = [(index, payload, previous_hash, entry_hash[:-1])] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(entries=broken), _KEY)

    def test_broken_chain_link(self):
        _, _, _, _, _, entries, _ = self.fields
        index, payload, _, entry_hash = entries[1]
        broken = entries[:1] + [(index, payload, bytes(32), entry_hash)] + entries[2:]
        with self.assertRaises(ValueError):
            load_pruned_auth(self._forge(entries=broken), _KEY)

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
                self._forge(tail=(wrong, head, stage, key_material, exported)),
                _KEY,
            )

    def test_wrong_head_rejected(self):
        root, head, stage, key_material, exported = self.fields[6]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(head))
        with self.assertRaises(ValueError):
            load_pruned_auth(
                self._forge(tail=(root, wrong, stage, key_material, exported)),
                _KEY,
            )


if __name__ == "__main__":
    unittest.main()
