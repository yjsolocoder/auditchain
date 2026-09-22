import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from auditchain import (
    AuditLog,
    Verifier,
    decrypt_entry,
    dump_auth,
    dump_hybrid,
    load_hybrid,
    verify_auth,
)

MAGIC = b"auditchain/hybrid/v1\0"
_VERSION = b"\x01"

_KEY = bytes(range(1, 33))
_OTHER_KEY = bytes(range(33, 65))
_ENTRY_KEY = b"e" * 32
_OTHER_ENTRY_KEY = b"f" * 32


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _encode(plaintext, nonce=b"N" * 12, key=_KEY):
    aad = MAGIC + _VERSION + nonce
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return MAGIC + _VERSION + nonce + sealed


class DumpHybridTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        self.verifier = self.log.export_verifier()
        self.log.append("a")
        self.log.encrypt("secret-a", _ENTRY_KEY, nonce=b"0" * 12)
        self.log.append(b"b" * 50)
        self.log.encrypt("secret-b", _OTHER_ENTRY_KEY, nonce=b"1" * 12)
        self.tag1 = self.log.auth(1)
        self.log.rotate_key()
        # stage: auth(1) -> 1, rotate_key -> 2

    def test_wire_layout(self):
        data = dump_hybrid(self.log, _KEY, nonce=b"N" * 12)
        self.assertTrue(data.startswith(MAGIC + _VERSION + b"N" * 12))
        self.assertGreaterEqual(len(data) - (len(MAGIC) + 1 + 12), 16)
        # Plaintext material never appears in the sealed stream.
        self.assertNotIn(b"b" * 50, data)
        self.assertNotIn(b"shared-secret", data)
        self.assertNotIn(b"secret-a", data)

    def test_random_nonce_default_differs(self):
        first = dump_hybrid(self.log, _KEY)
        second = dump_hybrid(self.log, _KEY)
        self.assertNotEqual(first, second)
        self.assertEqual(
            load_hybrid(first, _KEY).head, load_hybrid(second, _KEY).head
        )

    def test_explicit_nonce_is_caller_controlled(self):
        data = dump_hybrid(self.log, _KEY, nonce=b"0" * 12)
        self.assertEqual(data[len(MAGIC) + 1:len(MAGIC) + 13], b"0" * 12)

    def test_fixed_nonce_is_deterministic(self):
        self.assertEqual(
            dump_hybrid(self.log, _KEY, nonce=b"N" * 12),
            dump_hybrid(self.log, _KEY, nonce=b"N" * 12),
        )

    def test_export_is_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"a"),
            self.log.find_encrypted("secret-a", _ENTRY_KEY),
            [e.payload for e in self.log.entries()],
        )
        dump_hybrid(self.log, _KEY)
        dump_hybrid(self.log, _KEY)
        after = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"a"),
            self.log.find_encrypted("secret-a", _ENTRY_KEY),
            [e.payload for e in self.log.entries()],
        )
        self.assertEqual(before, after)

    def test_dump_type_errors(self):
        with self.assertRaises(TypeError):
            dump_hybrid("not a log", _KEY)
        for bad_key in ("k" * 32, bytearray(32), memoryview(bytes(32)), 32):
            with self.assertRaises(TypeError):
                dump_hybrid(self.log, bad_key)
        with self.assertRaises(TypeError):
            dump_hybrid(self.log, _KEY, nonce="N" * 12)
        with self.assertRaises(TypeError):
            dump_hybrid(self.log, _KEY, nonce=bytearray(12))

    def test_dump_value_errors(self):
        with self.assertRaises(ValueError):
            dump_hybrid(self.log, bytes(31))
        with self.assertRaises(ValueError):
            dump_hybrid(self.log, bytes(33))
        with self.assertRaises(ValueError):
            dump_hybrid(self.log, _KEY, nonce=b"short")
        with self.assertRaises(ValueError):
            dump_hybrid(self.log, _KEY, nonce=b"x" * 11)

    def test_requires_keyed_log(self):
        plain = AuditLog()
        plain.append("a")
        plain.encrypt("s", _ENTRY_KEY, nonce=b"0" * 12)
        with self.assertRaises(ValueError):
            dump_hybrid(plain, _KEY)

    def test_rejects_pruned_log(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_hybrid(log, _KEY)

    def test_failure_is_atomic(self):
        with self.assertRaises(ValueError):
            dump_hybrid(self.log, bytes(31))
        self.assertEqual(len(self.log), 4)
        self.assertEqual(self.log.stage, 2)
        load_hybrid(dump_hybrid(self.log, _KEY), _KEY)


class LoadHybridRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        self.verifier = self.log.export_verifier()
        self.log.append("a")
        self.log.encrypt("secret-a", _ENTRY_KEY, nonce=b"0" * 12)
        self.log.append(b"b" * 50)
        self.log.encrypt("secret-b", _OTHER_ENTRY_KEY, nonce=b"1" * 12)
        self.log.encrypt(b"", _ENTRY_KEY, nonce=b"2" * 12)
        self.tag1 = self.log.auth(1)
        self.log.rotate_key()
        # stage: auth(1) -> 1, rotate_key -> 2
        self.data = dump_hybrid(self.log, _KEY, nonce=b"N" * 12)

    def _restore(self):
        return load_hybrid(self.data, _KEY)

    def test_length_head_root_match(self):
        restored = self._restore()
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, 0)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertTrue(restored.verify())

    def test_entries_match_byte_for_byte(self):
        restored = self._restore()
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertEqual(list(restored), list(self.log))

    def test_find_index_matches(self):
        restored = self._restore()
        self.assertEqual(restored.find(b"a"), (0,))
        self.assertEqual(restored.find(b"b" * 50), (2,))
        self.assertEqual(restored.find(b"missing"), ())

    def test_encrypted_locator_index_matches(self):
        restored = self._restore()
        self.assertEqual(restored.find_encrypted("secret-a", _ENTRY_KEY), (1,))
        self.assertEqual(restored.find_encrypted("secret-b", _OTHER_ENTRY_KEY), (3,))
        self.assertEqual(restored.find_encrypted(b"", _ENTRY_KEY), (4,))
        # A foreign key and plaintext queries never hit.
        self.assertEqual(restored.find_encrypted("secret-a", _OTHER_ENTRY_KEY), ())
        self.assertEqual(restored.find_encrypted(b"a", _ENTRY_KEY), ())
        self.assertEqual(
            decrypt_entry(restored.entry(1), _ENTRY_KEY), b"secret-a"
        )

    def test_nonce_history_restored(self):
        restored = self._restore()
        # Every nonce used before the dump is now spent in the restored log.
        for spent in (b"0" * 12, b"1" * 12, b"2" * 12):
            with self.assertRaises(ValueError):
                restored.encrypt("x", _ENTRY_KEY, nonce=spent)
        # A random fresh nonce keeps working and enters the history.
        restored.encrypt("new-secret", _ENTRY_KEY)
        self.assertEqual(len(restored), 6)
        self.assertEqual(restored.find_encrypted("new-secret", _ENTRY_KEY), (5,))

    def test_stage_and_flag_restored(self):
        restored = self._restore()
        self.assertEqual(restored.stage, 2)
        self.assertTrue(restored._verifier_exported)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_flag_zero_allows_export(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.encrypt("s", _ENTRY_KEY, nonce=b"0" * 12)
        restored = load_hybrid(dump_hybrid(log, _KEY), _KEY)
        verifier = restored.export_verifier()
        self.assertIsInstance(verifier, Verifier)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_forward_security_continues(self):
        restored = self._restore()
        self.log.append("f")
        restored.append("f")
        tag_orig = self.log.auth(0)
        tag_rest = restored.auth(0)
        self.assertEqual(tag_orig, tag_rest)
        self.assertEqual(self.log.stage, restored.stage)
        # Old verifier material still verifies tags from the restored log.
        self.assertTrue(verify_auth(restored.entry(1), self.tag1, self.verifier))
        self.assertTrue(verify_auth(restored.entry(0), tag_orig, self.verifier))

    def test_independent_and_mutable(self):
        restored = self._restore()
        restored.append("separate")
        restored.encrypt("separate-secret", _ENTRY_KEY)
        restored.rotate_key()
        self.assertEqual(len(self.log), 5)
        self.assertEqual(len(restored), 7)
        self.assertEqual(restored.stage, self.log.stage + 1)
        self.assertTrue(restored.verify())

    def test_plain_only_keyed_log_round_trips(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.rotate_key()
        restored = load_hybrid(dump_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        self.assertEqual(restored.find(b"a"), (0,))

    def test_empty_log_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        restored = load_hybrid(dump_hybrid(log, _KEY), _KEY)
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        restored.append("x")
        self.assertEqual(len(restored), 1)

    def test_non_default_hash(self):
        log = AuditLog(key=b"shared-secret", hash_name="sha512")
        log.append("a")
        log.encrypt("s", _ENTRY_KEY, nonce=b"0" * 12)
        log.auth(0)
        restored = load_hybrid(dump_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(len(restored.head), 64)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        self.assertEqual(restored.find_encrypted("s", _ENTRY_KEY), (1,))


class LoadHybridErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        self.log.append("a")
        self.log.encrypt("s", _ENTRY_KEY, nonce=b"0" * 12)
        self.data = dump_hybrid(self.log, _KEY, nonce=b"N" * 12)
        # Canonical GCM-valid plaintext, for rebuilding structurally-bad but
        # authenticated streams.
        aad = MAGIC + _VERSION + b"N" * 12
        self.plaintext = AESGCM(_KEY).decrypt(
            b"N" * 12, self.data[len(MAGIC) + 13:], aad
        )

    def _rebuild(self, plaintext):
        return load_hybrid(_encode(plaintext), _KEY)

    def test_data_type(self):
        for bad in (bytearray(self.data), memoryview(self.data), "x", 42):
            with self.assertRaises(TypeError):
                load_hybrid(bad, _KEY)

    def test_key_type(self):
        for bad in ("k" * 32, bytearray(32), memoryview(bytes(32)), None):
            with self.assertRaises(TypeError):
                load_hybrid(self.data, bad)

    def test_key_length(self):
        with self.assertRaises(ValueError):
            load_hybrid(self.data, bytes(31))
        with self.assertRaises(ValueError):
            load_hybrid(self.data, bytes(33))

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_hybrid(b"x" + self.data[1:], _KEY)

    def test_bad_version_byte(self):
        broken = self.data[:len(MAGIC)] + b"\x02" + self.data[len(MAGIC) + 1:]
        with self.assertRaises(ValueError):
            load_hybrid(broken, _KEY)

    def test_truncated_outer_framing(self):
        for size in (0, len(MAGIC), len(MAGIC) + 1, len(self.data) - 1):
            with self.assertRaises(ValueError):
                load_hybrid(self.data[:size], _KEY)

    def test_wrong_key_fails_gcm(self):
        with self.assertRaises(ValueError):
            load_hybrid(self.data, _OTHER_KEY)

    def test_ciphertext_tamper_fails_gcm(self):
        broken = bytearray(self.data)
        broken[-1] ^= 0x01
        with self.assertRaises(ValueError):
            load_hybrid(bytes(broken), _KEY)

    def test_aad_tamper_fails_gcm(self):
        # Flipping the nonce makes AAD disagree with the sealed framing.
        broken = bytearray(self.data)
        broken[len(MAGIC) + 1] ^= 0xFF
        with self.assertRaises(ValueError):
            load_hybrid(bytes(broken), _KEY)

    # Structural checks on GCM-valid (re-sealed) plaintexts.

    def _parse_canonical(self):
        pt = self.plaintext
        cursor = 0

        def take_blob():
            nonlocal cursor
            length = int.from_bytes(pt[cursor:cursor + 8], "big")
            cursor += 8
            value = pt[cursor:cursor + length]
            cursor += length
            return value

        hash_name = take_blob()
        count = int.from_bytes(pt[cursor:cursor + 8], "big")
        cursor += 8
        nonces = [take_blob() for _ in range(count)]
        n = int.from_bytes(pt[cursor:cursor + 8], "big")
        cursor += 8
        entries = []
        for _ in range(n):
            index = int.from_bytes(pt[cursor:cursor + 8], "big")
            cursor += 8
            payload = take_blob()
            previous = take_blob()
            entry_hash = take_blob()
            locator = take_blob()
            entries.append([index, payload, previous, entry_hash, locator])
        root = take_blob()
        head = take_blob()
        stage = int.from_bytes(pt[cursor:cursor + 8], "big")
        cursor += 8
        evolution_key = take_blob()
        exported = int.from_bytes(pt[cursor:cursor + 8], "big")
        cursor += 8
        self.assertEqual(cursor, len(pt))
        return hash_name, nonces, entries, root, head, stage, evolution_key, exported

    def _build(
        self, *, hash_name=None, nonces=None, entries=None, root=None,
        head=None, stage=None, evolution_key=None, exported=None,
    ):
        h, h_nonces, h_entries, h_root, h_head, h_stage, h_key, h_x = (
            self._parse_canonical()
        )
        hash_name = h if hash_name is None else hash_name
        nonces = h_nonces if nonces is None else nonces
        entries = h_entries if entries is None else entries
        root = h_root if root is None else root
        head = h_head if head is None else head
        stage = h_stage if stage is None else stage
        evolution_key = h_key if evolution_key is None else evolution_key
        exported = h_x if exported is None else exported
        parts = [blob(hash_name), u64(len(nonces))]
        for value in nonces:
            parts.append(blob(value))
        parts.append(u64(len(entries)))
        for index, payload, previous, entry_hash, locator in entries:
            parts += [
                u64(index), blob(payload), blob(previous),
                blob(entry_hash), blob(locator),
            ]
        parts += [
            blob(root), blob(head), u64(stage),
            blob(evolution_key), u64(exported),
        ]
        return b"".join(parts)

    def test_trailing_plaintext_bytes(self):
        with self.assertRaises(ValueError):
            self._rebuild(self.plaintext + b"\x00")

    def test_truncated_plaintext(self):
        with self.assertRaises(ValueError):
            self._rebuild(self.plaintext[:-1])

    def test_bad_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            self._rebuild(self._build(hash_name=b"\xff\xfe"))

    def test_unknown_hash_name(self):
        with self.assertRaises(ValueError):
            self._rebuild(self._build(hash_name=b"no-such-hash"))

    def test_history_nonce_wrong_width(self):
        with self.assertRaises(ValueError):
            self._rebuild(self._build(nonces=[b"x" * 11]))

    def test_duplicate_history_nonce(self):
        with self.assertRaises(ValueError):
            self._rebuild(self._build(nonces=[b"0" * 12, b"0" * 12]))

    def test_unsorted_history_nonces(self):
        log = AuditLog(key=b"shared-secret")
        log.encrypt("s0", _ENTRY_KEY, nonce=b"a" * 12)
        log.encrypt("s1", _ENTRY_KEY, nonce=b"b" * 12)
        data = dump_hybrid(log, _KEY, nonce=b"N" * 12)
        plaintext = AESGCM(_KEY).decrypt(
            b"N" * 12, data[len(MAGIC) + 13:], MAGIC + _VERSION + b"N" * 12
        )
        # Swap the two 12-byte B(nonce) blobs after B(hash_name) || U(2).
        prefix_len = 8 + len(b"sha256") + 8
        blob_len = 8 + 12
        first = plaintext[prefix_len:prefix_len + blob_len]
        second = plaintext[prefix_len + blob_len:prefix_len + 2 * blob_len]
        swapped = (
            plaintext[:prefix_len] + second + first
            + plaintext[prefix_len + 2 * blob_len:]
        )
        with self.assertRaises(ValueError):
            load_hybrid(_encode(swapped), _KEY)

    def test_ciphertext_nonce_missing_from_history(self):
        with self.assertRaises(ValueError):
            self._rebuild(self._build(nonces=[]))

    def test_dangling_history_nonce(self):
        with self.assertRaises(ValueError):
            self._rebuild(self._build(nonces=[b"0" * 12, b"9" * 12]))

    def test_duplicate_entry_nonce(self):
        entries = [list(entry) for entry in self._parse_canonical()[2]]
        # Copy the encrypted record's locator and envelope onto the plain
        # entry so two records recover the same history nonce.
        entries[0][4] = entries[1][4]
        entries[0][1] = entries[1][1]
        with self.assertRaises(ValueError):
            self._rebuild(self._build(entries=entries))

    def test_locator_wrong_width(self):
        entries = [list(entry) for entry in self._parse_canonical()[2]]
        entries[1][4] = b"\x01\x02"
        with self.assertRaises(ValueError):
            self._rebuild(self._build(entries=entries))

    def test_bad_envelope_with_locator(self):
        entries = [list(entry) for entry in self._parse_canonical()[2]]
        entries[1][1] = b"not-an-envelope"
        with self.assertRaises(ValueError):
            self._rebuild(self._build(entries=entries))

    def test_index_out_of_order(self):
        entries = [list(entry) for entry in self._parse_canonical()[2]]
        entries[0][0], entries[1][0] = 1, 0
        with self.assertRaises(ValueError):
            self._rebuild(self._build(entries=entries))

    def test_root_and_head_widths(self):
        with self.assertRaises(ValueError):
            self._rebuild(self._build(root=b"\x00" * 31))
        with self.assertRaises(ValueError):
            self._rebuild(self._build(head=b"\x00" * 33))

    def test_root_and_head_mismatch(self):
        _, _, _, root, _, _, _, _ = self._parse_canonical()
        with self.assertRaises(ValueError):
            self._rebuild(self._build(root=bytes(len(root))))
        with self.assertRaises(ValueError):
            self._rebuild(self._build(head=bytes(len(root))))

    def test_bad_exported_flag(self):
        with self.assertRaises(ValueError):
            self._rebuild(self._build(exported=2))

    def test_empty_evolution_key(self):
        with self.assertRaises(ValueError):
            self._rebuild(self._build(evolution_key=b""))

    def test_evolution_key_width_after_evolution(self):
        with self.assertRaises(ValueError):
            self._rebuild(self._build(stage=1, evolution_key=b"short"))

    def test_chain_digest_mismatch(self):
        entries = [list(entry) for entry in self._parse_canonical()[2]]
        entries[0][1] = b"tampered"
        with self.assertRaises(ValueError):
            self._rebuild(self._build(entries=entries))

    def test_auth_log_framing_not_hybrid(self):
        # A dump_auth stream shares the outer envelope shape but seals with a
        # different AAD domain: swapping the magic makes GCM fail, so the
        # foreign framing can never be parsed as a hybrid.
        plain_keyed = AuditLog(key=b"shared-secret")
        plain_keyed.append("a")
        data = dump_auth(plain_keyed, _KEY, nonce=b"N" * 12)
        forged = MAGIC + data[len(b"auditchain/auth-log/v1\0"):]
        with self.assertRaises(ValueError):
            load_hybrid(forged, _KEY)


if __name__ == "__main__":
    unittest.main()
