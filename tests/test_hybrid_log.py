import os
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from auditchain import (
    AuditLog,
    Verifier,
    decrypt_entry,
    dump_hybrid,
    load_hybrid,
    verify_auth,
)

MAGIC = b"auditchain/hybrid/v1\0"
_VERSION = b"\x01"

_KEY = bytes(range(1, 33))
_OTHER_KEY = bytes(range(33, 65))
_ENC_KEY = bytes(range(65, 97))


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _encode(plaintext, nonce=b"N" * 12):
    aad = MAGIC + _VERSION + nonce
    sealed = AESGCM(_KEY).encrypt(nonce, plaintext, aad)
    return MAGIC + _VERSION + nonce + sealed


def _make_log():
    log = AuditLog(key=b"shared-secret")
    verifier = log.export_verifier()
    log.append("plain one")
    log.encrypt("secret one", _ENC_KEY)
    tag1 = log.auth(1)
    log.append(b"plain two")
    log.rotate_key()
    log.encrypt(b"secret two", _ENC_KEY, nonce=b"\x07" * 12)
    tag3 = log.auth(3)
    # stage: auth(1) -> 1, rotate -> 2, auth(3) -> 3
    return log, verifier, tag1, tag3


class DumpHybridTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag1, self.tag3 = _make_log()

    def test_wire_layout(self):
        data = dump_hybrid(self.log, _KEY, nonce=b"N" * 12)
        self.assertTrue(data.startswith(MAGIC + _VERSION + b"N" * 12))
        # Everything after D || 0x01 || N is ciphertext||tag (>=16 bytes).
        self.assertGreaterEqual(len(data) - (len(MAGIC) + 1 + 12), 16)
        # Plaintext never leaks a payload or a key in the ciphertext.
        self.assertNotIn(b"plain one", data)
        self.assertNotIn(b"secret one", data)
        self.assertNotIn(b"shared-secret", data)
        self.assertNotIn(_KEY, data)

    def test_random_nonce_default_differs(self):
        first = dump_hybrid(self.log, _KEY)
        second = dump_hybrid(self.log, _KEY)
        self.assertNotEqual(first, second)
        # Both load to the same state.
        self.assertEqual(load_hybrid(first, _KEY).head, load_hybrid(second, _KEY).head)

    def test_explicit_nonce_is_caller_controlled(self):
        data = dump_hybrid(self.log, _KEY, nonce=b"0" * 12)
        self.assertEqual(
            data[len(MAGIC) + 1:len(MAGIC) + 13], b"0" * 12
        )

    def test_export_is_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"plain one"),
            self.log.find_encrypted(b"secret one", _ENC_KEY),
            set(self.log._used_nonces),
        )
        dump_hybrid(self.log, _KEY)
        dump_hybrid(self.log, _KEY)
        after = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"plain one"),
            self.log.find_encrypted(b"secret one", _ENC_KEY),
            set(self.log._used_nonces),
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
        with self.assertRaises(ValueError):
            dump_hybrid(plain, _KEY)

    def test_allows_encrypted_history(self):
        # Unlike dump_auth, a log with encrypt history qualifies.
        log = AuditLog(key=b"k")
        log.encrypt("secret", _ENC_KEY)
        data = dump_hybrid(log, _KEY)
        self.assertEqual(load_hybrid(data, _KEY).head, log.head)

    def test_rejects_pruned_log(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_hybrid(log, _KEY)

    def test_failure_is_atomic(self):
        log = AuditLog(key=b"k")
        log.append("a")
        with self.assertRaises(ValueError):
            dump_hybrid(log, bytes(31))
        self.assertEqual(len(log), 1)
        self.assertEqual(log.stage, 0)
        # The log still dumps fine after the failed attempt.
        load_hybrid(dump_hybrid(log, _KEY), _KEY)


class LoadHybridRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag1, self.tag3 = _make_log()
        self.data = dump_hybrid(self.log, _KEY, nonce=b"N" * 12)

    def _restore(self):
        return load_hybrid(self.data, _KEY)

    def test_length_head_root_match(self):
        restored = self._restore()
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertTrue(restored.verify())

    def test_find_index_matches(self):
        restored = self._restore()
        self.assertEqual(restored.find(b"plain one"), (0,))
        self.assertEqual(restored.find(b"plain two"), (2,))
        self.assertEqual(restored.find(b"missing"), ())

    def test_encrypted_locator_index_matches(self):
        restored = self._restore()
        self.assertEqual(restored.find_encrypted("secret one", _ENC_KEY), (1,))
        self.assertEqual(restored.find_encrypted(b"secret two", _ENC_KEY), (3,))
        self.assertEqual(restored.find_encrypted(b"nonesuch", _ENC_KEY), ())

    def test_encrypted_entries_still_decrypt(self):
        restored = self._restore()
        self.assertEqual(decrypt_entry(restored.entry(1), _ENC_KEY), b"secret one")
        self.assertEqual(decrypt_entry(restored.entry(3), _ENC_KEY), b"secret two")

    def test_entries_match(self):
        restored = self._restore()
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertEqual(list(restored), list(self.log))

    def test_stage_restored(self):
        self.assertEqual(self.log.stage, 3)
        self.assertEqual(self._restore().stage, 3)

    def test_verifier_flag_restored(self):
        self.assertTrue(self._restore()._verifier_exported)
        with self.assertRaises(ValueError):
            self._restore().export_verifier()

    def test_verifier_flag_zero_allows_export(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.encrypt("s", _ENC_KEY)
        restored = load_hybrid(dump_hybrid(log, _KEY), _KEY)
        verifier = restored.export_verifier()
        self.assertIsInstance(verifier, Verifier)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_nonce_history_restored(self):
        restored = self._restore()
        self.assertEqual(restored._used_nonces, self.log._used_nonces)
        # A nonce the original log used is still rejected after the restore.
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=b"\x07" * 12)
        # A fresh nonce works.
        restored.encrypt("again", _ENC_KEY, nonce=b"\x08" * 12)
        self.assertEqual(restored.find_encrypted(b"again", _ENC_KEY), (4,))

    def test_forward_security_continues(self):
        # A tag minted after the dump continues evolution identically in both.
        restored = self._restore()
        self.log.append("f")
        restored.append("f")
        tag_orig = self.log.auth(4)
        tag_rest = restored.auth(4)
        self.assertEqual(tag_orig, tag_rest)
        self.assertEqual(self.log.stage, restored.stage)
        # Old verifier material still verifies tags from both processes.
        self.assertTrue(verify_auth(restored.entry(1), self.tag1, self.verifier))
        self.assertTrue(verify_auth(restored.entry(3), self.tag3, self.verifier))
        self.assertTrue(verify_auth(restored.entry(4), tag_orig, self.verifier))

    def test_independent_and_mutable(self):
        restored = self._restore()
        restored.append("separate")
        self.assertEqual(len(restored), len(self.log) + 1)
        restored.rotate_key()
        self.assertEqual(restored.stage, self.log.stage + 1)

    def test_stage_zero_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.encrypt("s", _ENC_KEY)
        restored = load_hybrid(dump_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored.head, log.head)

    def test_empty_log_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        restored = load_hybrid(dump_hybrid(log, _KEY), _KEY)
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored._used_nonces, set())

    def test_encrypt_only_log_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        log.encrypt("one", _ENC_KEY)
        log.encrypt("two", _ENC_KEY)
        restored = load_hybrid(dump_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.find_encrypted(b"one", _ENC_KEY), (0,))
        self.assertEqual(restored.find_encrypted(b"two", _ENC_KEY), (1,))
        self.assertEqual(restored._used_nonces, log._used_nonces)

    def test_non_default_hash(self):
        log = AuditLog(key=b"shared-secret", hash_name="sha512")
        log.append("a")
        log.encrypt("s", _ENC_KEY)
        log.auth(0)
        restored = load_hybrid(dump_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        self.assertEqual(len(restored.head), 64)
        self.assertEqual(restored.find_encrypted(b"s", _ENC_KEY), (1,))


class LoadHybridErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log, _verifier, _tag1, _tag3 = _make_log()
        self.data = dump_hybrid(self.log, _KEY, nonce=b"N" * 12)

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
        broken = b"x" + self.data[1:]
        with self.assertRaises(ValueError):
            load_hybrid(broken, _KEY)

    def test_bad_version(self):
        broken = MAGIC + b"\x02" + self.data[len(MAGIC) + 1:]
        with self.assertRaises(ValueError):
            load_hybrid(broken, _KEY)

    def test_truncated(self):
        for cut in (len(MAGIC), len(MAGIC) + 1, len(self.data) - 1):
            with self.assertRaises(ValueError):
                load_hybrid(self.data[:cut], _KEY)

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            load_hybrid(self.data, _OTHER_KEY)

    def test_ciphertext_tamper_fails(self):
        broken = bytearray(self.data)
        broken[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            load_hybrid(bytes(broken), _KEY)

    def test_nonce_tamper_fails_aad(self):
        broken = bytearray(self.data)
        broken[len(MAGIC) + 1] ^= 0x01
        with self.assertRaises(ValueError):
            load_hybrid(bytes(broken), _KEY)

    def test_magic_tamper_fails_aad(self):
        # Flipping a magic byte breaks the AAD even though parsing still
        # starts at the same offsets.
        broken = bytearray(self.data)
        broken[0] ^= 0x01
        with self.assertRaises(ValueError):
            load_hybrid(bytes(broken), _KEY)

    def test_load_is_read_only(self):
        view = bytes(self.data)
        load_hybrid(view, _KEY)
        self.assertEqual(view, self.data)


class LoadHybridPlaintextValidationTest(unittest.TestCase):
    """Valid AEAD frames whose decrypted plaintext violates the framing."""

    def setUp(self):
        self.log, _verifier, _tag1, _tag3 = _make_log()
        self.nonce = b"N" * 12
        self.good = dump_hybrid(self.log, _KEY, nonce=self.nonce)
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
        nonce_count = take_u64()
        nonces = [take_blob() for _ in range(nonce_count)]
        count = take_u64()
        entries = []
        for _ in range(count):
            entries.append(
                (take_u64(), take_blob(), take_blob(), take_blob(), take_blob())
            )
        tail = (take_blob(), take_blob(), take_u64(), take_blob(), take_u64())
        assert cursor == len(data)
        return name, nonces, entries, tail

    @staticmethod
    def _build(name, nonces, entries, tail):
        parts = [blob(name), u64(len(nonces))]
        for used_nonce in nonces:
            parts.append(blob(used_nonce))
        parts.append(u64(len(entries)))
        for index, payload, previous_hash, entry_hash, locator in entries:
            parts += [
                u64(index),
                blob(payload),
                blob(previous_hash),
                blob(entry_hash),
                blob(locator),
            ]
        root, head, stage, key_material, exported = tail
        parts += [blob(root), blob(head), u64(stage), blob(key_material), u64(exported)]
        return b"".join(parts)

    def _forge(self, name=None, nonces=None, entries=None, tail=None):
        old_name, old_nonces, old_entries, old_tail = self.fields
        plaintext = self._build(
            name if name is not None else old_name,
            nonces if nonces is not None else old_nonces,
            entries if entries is not None else old_entries,
            tail if tail is not None else old_tail,
        )
        return _encode(plaintext, nonce=self.nonce)

    def test_baseline_plaintext_loads(self):
        self.assertEqual(load_hybrid(self.good, _KEY).head, self.log.head)

    def test_nonce_history_is_lexicographic(self):
        _name, nonces, _entries, _tail = self.fields
        self.assertEqual(len(nonces), 2)
        self.assertEqual(nonces, sorted(nonces))
        self.assertTrue(all(len(used) == 12 for used in nonces))

    def test_trailing_bytes(self):
        plaintext = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_hybrid(_encode(plaintext + b"\x00", nonce=self.nonce), _KEY)

    def test_truncated_plaintext(self):
        plaintext = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_hybrid(_encode(plaintext[:-1], nonce=self.nonce), _KEY)

    def test_bad_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(name=b"\xff\xff"), _KEY)

    def test_unknown_hash(self):
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(name=b"nonesuch"), _KEY)

    def test_nonce_wrong_width(self):
        _name, nonces, _entries, _tail = self.fields
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(nonces=[nonces[0][:-1]] + nonces[1:]), _KEY)

    def test_nonces_out_of_order(self):
        _name, nonces, _entries, _tail = self.fields
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(nonces=list(reversed(nonces))), _KEY)

    def test_nonce_duplicated_in_history(self):
        _name, nonces, _entries, _tail = self.fields
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(nonces=[nonces[0], nonces[0]] + nonces[1:]), _KEY)

    def test_nonce_history_missing_entry_nonce(self):
        _name, nonces, _entries, _tail = self.fields
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(nonces=nonces[:1]), _KEY)

    def test_nonce_history_with_extra_nonce(self):
        _name, nonces, _entries, _tail = self.fields
        extra = sorted(nonces + [b"\xff" * 12])
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(nonces=extra), _KEY)

    def test_bad_entry_index(self):
        entries = [
            (1, payload, previous_hash, entry_hash, locator)
            if i == 0
            else (index, payload, previous_hash, entry_hash, locator)
            for i, (index, payload, previous_hash, entry_hash, locator) in enumerate(
                self.fields[2]
            )
        ]
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(entries=entries), _KEY)

    def test_bad_entry_digest_width(self):
        index, payload, previous_hash, entry_hash, locator = self.fields[2][0]
        entries = [
            (index, payload, previous_hash, entry_hash[:-1], locator)
        ] + self.fields[2][1:]
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(entries=entries), _KEY)

    def test_bad_previous_hash_width(self):
        index, payload, previous_hash, entry_hash, locator = self.fields[2][0]
        entries = [
            (index, payload, previous_hash + b"\x00", entry_hash, locator)
        ] + self.fields[2][1:]
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(entries=entries), _KEY)

    def test_broken_chain_rejected(self):
        # Swapping two payloads keeps widths intact but breaks the chain.
        entries = list(self.fields[2])
        first, second = entries[0], entries[1]
        entries[0] = (first[0], second[1], first[2], first[3], first[4])
        entries[1] = (second[0], first[1], second[2], second[3], second[4])
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(entries=entries), _KEY)

    def test_locator_wrong_width(self):
        # Entry 1 is encrypted; a non-empty locator of the wrong width fails.
        index, payload, previous_hash, entry_hash, locator = self.fields[2][1]
        self.assertTrue(locator)
        entries = list(self.fields[2])
        entries[1] = (index, payload, previous_hash, entry_hash, locator[:-1])
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(entries=entries), _KEY)

    def test_locator_on_plain_payload_rejected(self):
        # A non-empty locator whose payload is not an encrypted envelope.
        index, payload, previous_hash, entry_hash, _locator = self.fields[2][0]
        entries = list(self.fields[2])
        entries[0] = (index, payload, previous_hash, entry_hash, bytes(32))
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(entries=entries), _KEY)

    def test_dropped_locator_rejected(self):
        # Emptying an encrypted entry's locator desynchronizes the nonce
        # history from the entries.
        index, payload, previous_hash, entry_hash, _locator = self.fields[2][1]
        entries = list(self.fields[2])
        entries[1] = (index, payload, previous_hash, entry_hash, b"")
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(entries=entries), _KEY)

    def test_duplicate_envelope_nonce_rejected(self):
        # Two encrypted entries carrying the same envelope nonce, in an
        # otherwise fully consistent chain (digests, root and head all
        # recomputed to match), so only the duplicate-nonce check can fail.
        from auditchain import entry_digest

        shared_nonce = b"\x05" * 12
        aad_domain = b"auditchain/aead/v1\0"
        enc_magic = b"auditchain/encrypted-entry/v1\0"

        def seal(index, previous_hash, plaintext):
            aad = aad_domain + b"\x01" + u64(index) + previous_hash
            sealed = AESGCM(_ENC_KEY).encrypt(shared_nonce, plaintext, aad)
            return enc_magic + b"\x01" + shared_nonce + sealed

        genesis = bytes(32)
        env1 = seal(1, entry_digest(0, genesis, b"a"), b"first")
        hash0 = entry_digest(0, genesis, b"a")
        hash1 = entry_digest(1, hash0, env1)
        env2 = seal(2, hash1, b"second")
        hash2 = entry_digest(2, hash1, env2)
        # A plain log over the same payloads yields the matching root/head.
        mirror = AuditLog(key=b"k")
        mirror.append(b"a")
        mirror.append(env1)
        mirror.append(env2)
        entries = [
            (0, b"a", genesis, hash0, b""),
            (1, env1, hash0, hash1, bytes(32)),
            (2, env2, hash1, hash2, bytes(32)),
        ]
        tail = (mirror.merkle_root(), mirror.head, 0, b"k", 0)
        forged = self._forge(
            nonces=[shared_nonce], entries=entries, tail=tail
        )
        with self.assertRaises(ValueError):
            load_hybrid(forged, _KEY)

    def test_plain_payload_with_envelope_magic_loads(self):
        # Classification is driven by the locator: a plain entry whose payload
        # merely starts with the envelope magic stays a plain entry.
        log = AuditLog(key=b"shared-secret")
        log.append(b"auditchain/encrypted-entry/v1\0" + b"\x01" + b"x" * 40)
        log.encrypt("real secret", _ENC_KEY)
        restored = load_hybrid(dump_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.find(b"auditchain/encrypted-entry/v1\0" + b"\x01" + b"x" * 40), (0,))
        self.assertEqual(restored.find_encrypted(b"real secret", _ENC_KEY), (1,))

    def test_bad_root_width(self):
        root, head, stage, key_material, exported = self.fields[3]
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(tail=(root[:-1], head, stage, key_material, exported)), _KEY)

    def test_bad_head_width(self):
        root, head, stage, key_material, exported = self.fields[3]
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(tail=(root, head + b"\x00", stage, key_material, exported)), _KEY)

    def test_bad_flag(self):
        root, head, stage, key_material, _exported = self.fields[3]
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(tail=(root, head, stage, key_material, 2)), _KEY)

    def test_empty_evolution_key(self):
        root, head, stage, _key_material, exported = self.fields[3]
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(tail=(root, head, stage, b"", exported)), _KEY)

    def test_wrong_width_evolution_key_after_evolution(self):
        # stage == 3 here, so K must be the 32-byte digest width.
        root, head, stage, _key_material, exported = self.fields[3]
        with self.assertRaises(ValueError):
            load_hybrid(
                self._forge(tail=(root, head, stage, b"too-short", exported)), _KEY
            )

    def test_wrong_root_rejected(self):
        root, head, stage, key_material, exported = self.fields[3]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(root))
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(tail=(wrong, head, stage, key_material, exported)), _KEY)

    def test_wrong_head_rejected(self):
        root, head, stage, key_material, exported = self.fields[3]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(head))
        with self.assertRaises(ValueError):
            load_hybrid(self._forge(tail=(root, wrong, stage, key_material, exported)), _KEY)


if __name__ == "__main__":
    unittest.main()
