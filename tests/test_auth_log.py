import os
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from auditchain import (
    AuditLog,
    Verifier,
    dump_auth,
    load_auth,
    verify_auth,
)

MAGIC = b"auditchain/auth-log/v1\0"
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


class DumpAuthTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        self.verifier = self.log.export_verifier()
        for record in ("a", b"b", b"c" * 100):
            self.log.append(record)
        self.tag0 = self.log.auth(0)
        self.log.append("d")
        self.log.rotate_key()
        self.tag3 = self.log.auth(3)
        # stage: auth(0) -> 1, rotate -> 2, auth(3) -> 3

    def test_wire_layout(self):
        data = dump_auth(self.log, _KEY, nonce=b"N" * 12)
        self.assertTrue(data.startswith(MAGIC + _VERSION + b"N" * 12))
        # Everything after D || 0x01 || N is ciphertext||tag (>=16 bytes).
        self.assertGreaterEqual(len(data) - (len(MAGIC) + 1 + 12), 16)
        # Plaintext never leaks a payload in the ciphertext.
        self.assertNotIn(b"c" * 100, data)
        self.assertNotIn(b"shared-secret", data)

    def test_random_nonce_default_differs(self):
        first = dump_auth(self.log, _KEY)
        second = dump_auth(self.log, _KEY)
        self.assertNotEqual(first, second)
        # Both load to the same state.
        self.assertEqual(load_auth(first, _KEY).head, load_auth(second, _KEY).head)

    def test_explicit_nonce_is_caller_controlled(self):
        data = dump_auth(self.log, _KEY, nonce=b"0" * 12)
        self.assertEqual(
            data[len(MAGIC) + 1:len(MAGIC) + 13], b"0" * 12
        )

    def test_export_is_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"a"),
        )
        dump_auth(self.log, _KEY)
        dump_auth(self.log, _KEY)
        after = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"a"),
        )
        self.assertEqual(before, after)

    def test_dump_type_errors(self):
        with self.assertRaises(TypeError):
            dump_auth("not a log", _KEY)
        for bad_key in ("k" * 32, bytearray(32), memoryview(bytes(32)), 32):
            with self.assertRaises(TypeError):
                dump_auth(self.log, bad_key)
        with self.assertRaises(TypeError):
            dump_auth(self.log, _KEY, nonce="N" * 12)
        with self.assertRaises(TypeError):
            dump_auth(self.log, _KEY, nonce=bytearray(12))

    def test_dump_value_errors(self):
        with self.assertRaises(ValueError):
            dump_auth(self.log, bytes(31))
        with self.assertRaises(ValueError):
            dump_auth(self.log, bytes(33))
        with self.assertRaises(ValueError):
            dump_auth(self.log, _KEY, nonce=b"short")
        with self.assertRaises(ValueError):
            dump_auth(self.log, _KEY, nonce=b"x" * 11)

    def test_requires_keyed_log(self):
        plain = AuditLog()
        plain.append("a")
        with self.assertRaises(ValueError):
            dump_auth(plain, _KEY)

    def test_rejects_encrypted_history(self):
        log = AuditLog(key=b"k")
        log.encrypt("secret", _KEY)
        with self.assertRaises(ValueError):
            dump_auth(log, _KEY)

    def test_rejects_pruned_log(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_auth(log, _KEY)

    def test_failure_is_atomic(self):
        log = AuditLog(key=b"k")
        log.append("a")
        with self.assertRaises(ValueError):
            dump_auth(log, bytes(31))
        self.assertEqual(len(log), 1)
        self.assertEqual(log.stage, 0)
        # The log still dumps fine after the failed attempt.
        load_auth(dump_auth(log, _KEY), _KEY)


class LoadAuthRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        self.verifier = self.log.export_verifier()
        for record in ("a", b"b", b"c" * 100, "d"):
            self.log.append(record)
        self.tag1 = self.log.auth(1)
        self.log.append("e")
        self.data = dump_auth(self.log, _KEY, nonce=b"N" * 12)

    def _restore(self):
        return load_auth(self.data, _KEY)

    def test_length_head_root_match(self):
        restored = self._restore()
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertTrue(restored.verify())

    def test_find_index_matches(self):
        restored = self._restore()
        self.assertEqual(restored.find(b"a"), self.log.find(b"a"))
        self.assertEqual(restored.find(b"c" * 100), self.log.find(b"c" * 100))
        self.assertEqual(restored.find(b"missing"), ())

    def test_entries_match(self):
        restored = self._restore()
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertEqual(list(restored), list(self.log))

    def test_stage_restored(self):
        self.assertEqual(self.log.stage, 1)
        self.assertEqual(self._restore().stage, 1)

    def test_verifier_flag_restored(self):
        self.assertTrue(self._restore()._verifier_exported)
        with self.assertRaises(ValueError):
            self._restore().export_verifier()

    def test_verifier_flag_zero_allows_export(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        restored = load_auth(dump_auth(log, _KEY), _KEY)
        verifier = restored.export_verifier()
        self.assertIsInstance(verifier, Verifier)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_forward_security_continues(self):
        # A tag minted after the dump continues evolution identically in both.
        restored = self._restore()
        self.log.append("f")
        restored.append("f")
        tag_orig = self.log.auth(5)
        tag_rest = restored.auth(5)
        self.assertEqual(tag_orig, tag_rest)
        self.assertEqual(self.log.stage, restored.stage)
        # Old verifier material still verifies tags from both processes.
        self.assertTrue(verify_auth(restored.entry(1), self.tag1, self.verifier))
        self.assertTrue(verify_auth(restored.entry(5), tag_orig, self.verifier))

    def test_independent_and_mutable(self):
        restored = self._restore()
        restored.append("separate")
        self.assertEqual(len(restored), len(self.log) + 1)
        restored.rotate_key()
        self.assertEqual(restored.stage, self.log.stage + 1)

    def test_stage_zero_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        restored = load_auth(dump_auth(log, _KEY), _KEY)
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored.head, log.head)

    def test_empty_log_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        restored = load_auth(dump_auth(log, _KEY), _KEY)
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())

    def test_non_default_hash(self):
        log = AuditLog(key=b"shared-secret", hash_name="sha512")
        log.append("a")
        log.auth(0)
        restored = load_auth(dump_auth(log, _KEY), _KEY)
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        self.assertEqual(len(restored.head), 64)


class LoadAuthErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        self.log.append("a")
        self.data = dump_auth(self.log, _KEY, nonce=b"N" * 12)

    def test_data_type(self):
        for bad in (bytearray(self.data), memoryview(self.data), "x", 42):
            with self.assertRaises(TypeError):
                load_auth(bad, _KEY)

    def test_key_type(self):
        for bad in ("k" * 32, bytearray(32), memoryview(bytes(32)), None):
            with self.assertRaises(TypeError):
                load_auth(self.data, bad)

    def test_key_length(self):
        with self.assertRaises(ValueError):
            load_auth(self.data, bytes(31))
        with self.assertRaises(ValueError):
            load_auth(self.data, bytes(33))

    def test_bad_magic(self):
        broken = b"x" + self.data[1:]
        with self.assertRaises(ValueError):
            load_auth(broken, _KEY)

    def test_bad_version(self):
        broken = MAGIC + b"\x02" + self.data[len(MAGIC) + 1:]
        with self.assertRaises(ValueError):
            load_auth(broken, _KEY)

    def test_truncated(self):
        for cut in (len(MAGIC), len(MAGIC) + 1, len(self.data) - 1):
            with self.assertRaises(ValueError):
                load_auth(self.data[:cut], _KEY)

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            load_auth(self.data, _OTHER_KEY)

    def test_ciphertext_tamper_fails(self):
        broken = bytearray(self.data)
        broken[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            load_auth(bytes(broken), _KEY)

    def test_nonce_tamper_fails_aad(self):
        broken = bytearray(self.data)
        broken[len(MAGIC) + 1] ^= 0x01
        with self.assertRaises(ValueError):
            load_auth(bytes(broken), _KEY)

    def test_magic_tamper_fails_aad(self):
        # Flipping a magic byte breaks the AAD even though parsing still
        # starts at the same offsets.
        broken = bytearray(self.data)
        broken[0] ^= 0x01
        with self.assertRaises(ValueError):
            load_auth(bytes(broken), _KEY)

    def test_load_is_read_only(self):
        view = bytes(self.data)
        load_auth(view, _KEY)
        self.assertEqual(view, self.data)


class LoadAuthPlaintextValidationTest(unittest.TestCase):
    """Valid AEAD frames whose decrypted plaintext violates the framing."""

    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        for record in ("a", b"b"):
            self.log.append(record)
        self.log.auth(0)
        self.nonce = b"N" * 12
        self.good = dump_auth(self.log, _KEY, nonce=self.nonce)
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
        count = take_u64()
        entries = []
        for _ in range(count):
            entries.append((take_u64(), take_blob(), take_blob(), take_blob()))
        tail = (take_blob(), take_blob(), take_u64(), take_blob(), take_u64())
        assert cursor == len(data)
        return name, entries, tail

    @staticmethod
    def _build(name, entries, tail):
        parts = [blob(name), u64(len(entries))]
        for index, payload, previous_hash, entry_hash in entries:
            parts += [u64(index), blob(payload), blob(previous_hash), blob(entry_hash)]
        root, head, stage, key_material, exported = tail
        parts += [blob(root), blob(head), u64(stage), blob(key_material), u64(exported)]
        return b"".join(parts)

    def _forge(self, name=None, entries=None, tail=None):
        old_name, old_entries, old_tail = self.fields
        plaintext = self._build(
            name if name is not None else old_name,
            entries if entries is not None else old_entries,
            tail if tail is not None else old_tail,
        )
        return _encode(plaintext, nonce=self.nonce)

    def test_baseline_plaintext_loads(self):
        self.assertEqual(load_auth(self.good, _KEY).head, self.log.head)

    def test_trailing_bytes(self):
        plaintext = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_auth(_encode(plaintext + b"\x00", nonce=self.nonce), _KEY)

    def test_truncated_plaintext(self):
        plaintext = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_auth(_encode(plaintext[:-1], nonce=self.nonce), _KEY)

    def test_bad_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            load_auth(self._forge(name=b"\xff\xff"), _KEY)

    def test_unknown_hash(self):
        with self.assertRaises(ValueError):
            load_auth(self._forge(name=b"nonesuch"), _KEY)

    def test_bad_entry_index(self):
        entries = [
            (1, payload, previous_hash, entry_hash)
            if i == 0
            else (index, payload, previous_hash, entry_hash)
            for i, (index, payload, previous_hash, entry_hash) in enumerate(self.fields[1])
        ]
        with self.assertRaises(ValueError):
            load_auth(self._forge(entries=entries), _KEY)

    def test_bad_entry_digest_width(self):
        index, payload, previous_hash, entry_hash = self.fields[1][0]
        entries = [(index, payload, previous_hash, entry_hash[:-1])] + self.fields[1][1:]
        with self.assertRaises(ValueError):
            load_auth(self._forge(entries=entries), _KEY)

    def test_bad_root_width(self):
        root, head, stage, key_material, exported = self.fields[2]
        with self.assertRaises(ValueError):
            load_auth(self._forge(tail=(root[:-1], head, stage, key_material, exported)), _KEY)

    def test_bad_head_width(self):
        root, head, stage, key_material, exported = self.fields[2]
        with self.assertRaises(ValueError):
            load_auth(self._forge(tail=(root, head + b"\x00", stage, key_material, exported)), _KEY)

    def test_bad_flag(self):
        root, head, stage, key_material, _exported = self.fields[2]
        with self.assertRaises(ValueError):
            load_auth(self._forge(tail=(root, head, stage, key_material, 2)), _KEY)

    def test_empty_evolution_key(self):
        root, head, stage, _key_material, exported = self.fields[2]
        with self.assertRaises(ValueError):
            load_auth(self._forge(tail=(root, head, stage, b"", exported)), _KEY)

    def test_wrong_width_evolution_key_after_evolution(self):
        # stage == 1 here, so K must be the 32-byte digest width.
        root, head, stage, _key_material, exported = self.fields[2]
        with self.assertRaises(ValueError):
            load_auth(
                self._forge(tail=(root, head, stage, b"too-short", exported)), _KEY
            )

    def test_wrong_root_rejected(self):
        root, head, stage, key_material, exported = self.fields[2]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(root))
        with self.assertRaises(ValueError):
            load_auth(self._forge(tail=(wrong, head, stage, key_material, exported)), _KEY)

    def test_wrong_head_rejected(self):
        root, head, stage, key_material, exported = self.fields[2]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(head))
        with self.assertRaises(ValueError):
            load_auth(self._forge(tail=(root, wrong, stage, key_material, exported)), _KEY)


if __name__ == "__main__":
    unittest.main()
