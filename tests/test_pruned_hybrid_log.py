import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from auditchain import (
    AuditLog,
    Verifier,
    decrypt_entry,
    dump_pruned_hybrid,
    entry_digest,
    load_pruned_hybrid,
    verify_auth,
)

MAGIC = b"auditchain/pruned-hybrid/v1\0"
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


def _make_pruned_keyed_log(retain_from=3):
    """n=5, retain_from=3.

    Prefix 0..2 holds a plain entry, an encrypted entry (released) and a
    plain entry; tag at 1 is minted before the prune (stage -> 1) and then
    released. Retained range 3..4 holds an encrypted entry (nonce 0x07*12)
    and a plain entry; auth(4) pushes the stage to 2 and rotate_key() to 3.
    """
    log = AuditLog(key=b"shared-secret")
    verifier = log.export_verifier()
    log.append("a")
    log.encrypt("secret-pruned", _ENC_KEY)
    log.append(b"c" * 100)
    log.auth(1)
    log.prune(retain_from, log.seal(retain_from))
    log.encrypt(b"secret-kept", _ENC_KEY, nonce=b"\x07" * 12)
    log.append("e")
    tag4 = log.auth(4)
    log.rotate_key()
    return log, tag4, verifier


class DumpPrunedHybridTest(unittest.TestCase):
    def setUp(self):
        self.log, self.tag4, self.verifier = _make_pruned_keyed_log()

    def test_wire_layout(self):
        data = dump_pruned_hybrid(self.log, _KEY, nonce=b"N" * 12)
        self.assertTrue(data.startswith(MAGIC + _VERSION + b"N" * 12))
        self.assertGreaterEqual(len(data) - (len(MAGIC) + 1 + 12), 16)
        # Plaintext never leaks a payload, the evolution key or the enc key.
        self.assertNotIn(b"secret-kept", data)
        self.assertNotIn(b"c" * 100, data)
        self.assertNotIn(b"shared-secret", data)
        self.assertNotIn(_KEY, data)
        self.assertNotIn(_ENC_KEY, data)

    def test_random_nonce_default_differs(self):
        first = dump_pruned_hybrid(self.log, _KEY)
        second = dump_pruned_hybrid(self.log, _KEY)
        self.assertNotEqual(first, second)
        self.assertEqual(
            load_pruned_hybrid(first, _KEY).head,
            load_pruned_hybrid(second, _KEY).head,
        )

    def test_explicit_nonce_is_caller_controlled(self):
        data = dump_pruned_hybrid(self.log, _KEY, nonce=b"0" * 12)
        self.assertEqual(data[len(MAGIC) + 1:len(MAGIC) + 13], b"0" * 12)

    def test_export_is_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"e"),
            self.log.find_encrypted(b"secret-kept", _ENC_KEY),
            tuple(sorted(self.log._used_nonces)),
        )
        dump_pruned_hybrid(self.log, _KEY)
        dump_pruned_hybrid(self.log, _KEY, nonce=b"X" * 12)
        after = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"e"),
            self.log.find_encrypted(b"secret-kept", _ENC_KEY),
            tuple(sorted(self.log._used_nonces)),
        )
        self.assertEqual(before, after)

    def test_dump_type_errors(self):
        with self.assertRaises(TypeError):
            dump_pruned_hybrid("not a log", _KEY)
        for bad_key in ("k" * 32, bytearray(32), memoryview(bytes(32)), 32):
            with self.assertRaises(TypeError):
                dump_pruned_hybrid(self.log, bad_key)
        with self.assertRaises(TypeError):
            dump_pruned_hybrid(self.log, _KEY, nonce="N" * 12)
        with self.assertRaises(TypeError):
            dump_pruned_hybrid(self.log, _KEY, nonce=bytearray(12))

    def test_dump_value_errors(self):
        with self.assertRaises(ValueError):
            dump_pruned_hybrid(self.log, bytes(31))
        with self.assertRaises(ValueError):
            dump_pruned_hybrid(self.log, bytes(33))
        with self.assertRaises(ValueError):
            dump_pruned_hybrid(self.log, _KEY, nonce=b"short")
        with self.assertRaises(ValueError):
            dump_pruned_hybrid(self.log, _KEY, nonce=b"x" * 11)

    def test_rejects_unpruned_keyed_log(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.encrypt("s", _ENC_KEY)
        with self.assertRaises(ValueError):
            dump_pruned_hybrid(log, _KEY)

    def test_rejects_keyless_pruned_log(self):
        log = AuditLog()
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_pruned_hybrid(log, _KEY)

    def test_allows_encrypted_history(self):
        # Unlike dump_pruned_auth, a pruned log with encrypt history
        # qualifies, even when the only ciphertexts were released.
        data = dump_pruned_hybrid(self.log, _KEY)
        self.assertEqual(load_pruned_hybrid(data, _KEY).head, self.log.head)

    def test_allows_history_with_only_released_ciphertexts(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.encrypt("released-secret", _ENC_KEY)
        log.append("b")
        log.prune(3, log.seal(3))
        log.append("c")
        data = dump_pruned_hybrid(log, _KEY)
        restored = load_pruned_hybrid(data, _KEY)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored._used_nonces, log._used_nonces)
        self.assertEqual(restored.find(b"c"), (3,))

    def test_failure_is_atomic(self):
        with self.assertRaises(ValueError):
            dump_pruned_hybrid(self.log, bytes(31))
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(self.log.stage, 3)
        # The log still dumps fine after the failed attempt.
        load_pruned_hybrid(dump_pruned_hybrid(self.log, _KEY), _KEY)


class LoadPrunedHybridRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log, self.tag4, self.verifier = _make_pruned_keyed_log()
        self.data = dump_pruned_hybrid(self.log, _KEY, nonce=b"N" * 12)

    def _restore(self):
        return load_pruned_hybrid(self.data, _KEY)

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

    def test_pruned_snapshots_still_unavailable(self):
        restored = self._restore()
        with self.assertRaises(ValueError):
            restored.merkle_root(1)
        with self.assertRaises(IndexError):
            restored.entry(0)

    def test_find_index_matches(self):
        restored = self._restore()
        self.assertEqual(restored.find(b"e"), self.log.find(b"e"))
        self.assertEqual(restored.find(b"a"), ())            # released
        self.assertEqual(restored.find(b"c" * 100), ())     # released
        self.assertEqual(restored.find(b"missing"), ())

    def test_encrypted_locator_index_matches(self):
        restored = self._restore()
        self.assertEqual(restored.find_encrypted("secret-kept", _ENC_KEY), (3,))
        self.assertEqual(restored.find_encrypted(b"secret-pruned", _ENC_KEY), ())
        self.assertEqual(restored.find_encrypted(b"nonesuch", _ENC_KEY), ())

    def test_encrypted_entries_still_decrypt(self):
        restored = self._restore()
        self.assertEqual(decrypt_entry(restored.entry(3), _ENC_KEY), b"secret-kept")

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
        log.prune(2, log.seal(2))
        log.append("b")
        restored = load_pruned_hybrid(dump_pruned_hybrid(log, _KEY), _KEY)
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
        self.assertTrue(verify_auth(restored.entry(4), self.tag4, self.verifier))

    def test_nonce_history_restored(self):
        restored = self._restore()
        self.assertEqual(restored._used_nonces, self.log._used_nonces)
        # The retained ciphertext nonce is still rejected.
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=b"\x07" * 12)
        # The released ciphertext nonce is remembered too; find its concrete
        # value in the original log's lifetime history.
        (released_nonce,) = self.log._used_nonces - {b"\x07" * 12}
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=released_nonce)
        # A genuinely fresh nonce works.
        restored.encrypt("again", _ENC_KEY, nonce=b"\x08" * 12)
        self.assertEqual(restored.find_encrypted(b"again", _ENC_KEY), (5,))

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
        log.append("a")
        log.encrypt("s", _ENC_KEY)
        log.auth(0)
        log.prune(2, log.seal(2))
        self.assertEqual(log.entries(), [])
        restored = load_pruned_hybrid(dump_pruned_hybrid(log, _KEY), _KEY)
        self.assertEqual(len(restored), 2)
        self.assertEqual(restored.retain_from, 2)
        self.assertEqual(restored.entries(), [])
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        self.assertEqual(restored._used_nonces, log._used_nonces)
        restored.append("d")
        self.assertEqual(restored.entry(2).index, 2)

    def test_non_default_hash(self):
        log = AuditLog(key=b"shared-secret", hash_name="sha512")
        log.append("a")
        log.encrypt("released", _ENC_KEY)
        log.append("b")
        log.auth(2)
        log.prune(3, log.seal(3))
        log.encrypt(b"kept", _ENC_KEY, nonce=b"\x02" * 12)
        restored = load_pruned_hybrid(dump_pruned_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        self.assertEqual(len(restored.head), 64)
        self.assertEqual(restored.find_encrypted(b"kept", _ENC_KEY), (3,))
        self.assertEqual(restored._used_nonces, log._used_nonces)


class LoadPrunedHybridErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log, _tag4, _verifier = _make_pruned_keyed_log()
        self.data = dump_pruned_hybrid(self.log, _KEY, nonce=b"N" * 12)

    def test_data_type(self):
        for bad in (bytearray(self.data), memoryview(self.data), "x", 42):
            with self.assertRaises(TypeError):
                load_pruned_hybrid(bad, _KEY)

    def test_key_type(self):
        for bad in ("k" * 32, bytearray(32), memoryview(bytes(32)), None):
            with self.assertRaises(TypeError):
                load_pruned_hybrid(self.data, bad)

    def test_key_length(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self.data, bytes(31))
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self.data, bytes(33))

    def test_bad_magic(self):
        broken = b"x" + self.data[1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(broken, _KEY)

    def test_bad_version(self):
        broken = MAGIC + b"\x02" + self.data[len(MAGIC) + 1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(broken, _KEY)

    def test_truncated(self):
        for cut in (len(MAGIC), len(MAGIC) + 1, len(self.data) - 1):
            with self.assertRaises(ValueError):
                load_pruned_hybrid(self.data[:cut], _KEY)

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self.data, _OTHER_KEY)

    def test_ciphertext_tamper_fails(self):
        broken = bytearray(self.data)
        broken[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            load_pruned_hybrid(bytes(broken), _KEY)

    def test_nonce_tamper_fails_aad(self):
        broken = bytearray(self.data)
        broken[len(MAGIC) + 1] ^= 0x01
        with self.assertRaises(ValueError):
            load_pruned_hybrid(bytes(broken), _KEY)

    def test_magic_tamper_fails_aad(self):
        broken = bytearray(self.data)
        broken[0] ^= 0x01
        with self.assertRaises(ValueError):
            load_pruned_hybrid(bytes(broken), _KEY)

    def test_load_is_read_only(self):
        view = bytes(self.data)
        load_pruned_hybrid(view, _KEY)
        self.assertEqual(view, self.data)


class LoadPrunedHybridPlaintextValidationTest(unittest.TestCase):
    """Valid AEAD frames whose decrypted plaintext violates the framing."""

    def setUp(self):
        self.log, _tag4, _verifier = _make_pruned_keyed_log()
        self.nonce = b"N" * 12
        self.good = dump_pruned_hybrid(self.log, _KEY, nonce=self.nonce)
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
        retain = take_u64()
        checkpoint = take_blob()
        frontier_count = take_u64()
        frontier = [(take_u64(), take_blob()) for _ in range(frontier_count)]
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
        return name, size, retain, checkpoint, frontier, nonces, entries, tail

    @staticmethod
    def _build(name, size, retain, checkpoint, frontier, nonces, entries, tail):
        parts = [
            blob(name),
            u64(size),
            u64(retain),
            blob(checkpoint),
            u64(len(frontier)),
        ]
        for height, digest in frontier:
            parts += [u64(height), blob(digest)]
        parts.append(u64(len(nonces)))
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

    def _forge(self, **changes):
        keys = (
            "name",
            "size",
            "retain",
            "checkpoint",
            "frontier",
            "nonces",
            "entries",
            "tail",
        )
        values = [
            changes[key] if key in changes else old
            for key, old in zip(keys, self.fields)
        ]
        plaintext = self._build(*values)
        return _encode(plaintext, nonce=self.nonce)

    def test_baseline_plaintext_loads(self):
        self.assertEqual(
            load_pruned_hybrid(self.good, _KEY).head, self.log.head
        )

    def test_framing_values(self):
        _name, size, retain, _checkpoint, frontier, nonces, entries, _tail = self.fields
        self.assertEqual((size, retain), (5, 3))
        self.assertEqual(len(entries), 2)
        self.assertEqual([entry[0] for entry in entries], [3, 4])
        self.assertEqual([height for height, _digest in frontier], [0, 1])
        self.assertEqual(len(nonces), 2)
        self.assertEqual(nonces, sorted(nonces))
        self.assertTrue(all(len(used) == 12 for used in nonces))

    def test_trailing_bytes(self):
        plaintext = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                _encode(plaintext + b"\x00", nonce=self.nonce), _KEY
            )

    def test_truncated_plaintext(self):
        plaintext = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                _encode(plaintext[:-1], nonce=self.nonce), _KEY
            )

    def test_bad_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(name=b"\xff\xff"), _KEY)

    def test_unknown_hash(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(name=b"nonesuch"), _KEY)

    def test_retain_zero(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(retain=0), _KEY)

    def test_retain_past_size(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(retain=6), _KEY)

    def test_bad_checkpoint_width(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(checkpoint=b"\x00" * 31), _KEY)

    def test_frontier_out_of_order(self):
        _n, _s, _r, _c, frontier, _q, _e, _t = self.fields
        broken = list(reversed(frontier))
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(frontier=broken), _KEY)

    def test_frontier_wrong_digest_width(self):
        _n, _s, _r, _c, frontier, _q, _e, _t = self.fields
        broken = [(height, digest[:-1]) for height, digest in frontier]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(frontier=broken), _KEY)

    def test_frontier_not_set_bits(self):
        # retain_from == 3 sets bits {0, 1}; swap in height 2 instead.
        _n, _s, _r, _c, frontier, _q, _e, _t = self.fields
        broken = [(0, frontier[0][1]), (2, frontier[1][1])]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(frontier=broken), _KEY)

    def test_nonce_wrong_width(self):
        _n, _s, _r, _c, _f, nonces, _e, _t = self.fields
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(nonces=[nonces[0][:-1]] + nonces[1:]), _KEY)

    def test_nonces_out_of_order(self):
        _n, _s, _r, _c, _f, nonces, _e, _t = self.fields
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(nonces=list(reversed(nonces))), _KEY)

    def test_nonce_duplicated_in_history(self):
        _n, _s, _r, _c, _f, nonces, _e, _t = self.fields
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                self._forge(nonces=[nonces[0], nonces[0]] + nonces[1:]), _KEY
            )

    def test_retained_ciphertext_nonce_missing_from_history(self):
        # Q keeps only the released ciphertext's nonce, dropping 0x07*12.
        _n, _s, _r, _c, _f, nonces, entries, _t = self.fields
        kept = [used for used in nonces if used != b"\x07" * 12]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(nonces=kept), _KEY)

    def test_extra_history_nonce_is_the_pruned_case(self):
        # An extra history nonce is legitimate (a released ciphertext), and
        # the baseline itself already carries one: the retained range uses
        # only 0x07*12 while Q carries two nonces.
        _n, _s, _r, _c, _f, nonces, _e, _t = self.fields
        self.assertIn(b"\x07" * 12, nonces)
        self.assertEqual(len(nonces), 2)

    def test_entries_count_mismatch(self):
        # Declare one more retained record than n - r; parsing then runs out
        # of tail bytes (truncation), which is still a ValueError.
        _n, _s, _r, _c, _f, _q, entries, _t = self.fields
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=[entries[0]]), _KEY)

    def test_bad_entry_index(self):
        _n, _s, _r, _c, _f, _q, entries, _t = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[0]
        broken = [(index + 1, payload, previous_hash, entry_hash, locator)] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_bad_entry_digest_width(self):
        _n, _s, _r, _c, _f, _q, entries, _t = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[0]
        broken = [(index, payload, previous_hash, entry_hash[:-1], locator)] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_bad_previous_hash_width(self):
        _n, _s, _r, _c, _f, _q, entries, _t = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[0]
        broken = [(index, payload, previous_hash + b"\x00", entry_hash, locator)] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_broken_chain_rejected(self):
        # Reversing the two retained records keeps widths but breaks links.
        _n, _s, _r, _c, _f, _q, entries, _t = self.fields
        first, second = entries
        broken = [
            (first[0], second[1], first[2], first[3], first[4]),
            (second[0], first[1], second[2], second[3], second[4]),
        ]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_locator_wrong_width(self):
        # Entry 3 is the retained ciphertext.
        _n, _s, _r, _c, _f, _q, entries, _t = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[0]
        self.assertTrue(locator)
        broken = [(index, payload, previous_hash, entry_hash, locator[:-1])] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_locator_on_plain_payload_rejected(self):
        _n, _s, _r, _c, _f, _q, entries, _t = self.fields
        index, payload, previous_hash, entry_hash, _locator = entries[1]
        self.assertFalse(entries[1][4])
        broken = entries[:1] + [(index, payload, previous_hash, entry_hash, bytes(32))]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_dropped_locator_is_treated_as_released_ciphertext(self):
        # In a pruned format a retained record loses its locator on purpose:
        # it then classifies as plain (locator-driven, never payload-driven)
        # and its envelope nonce reads as the nonce of a ciphertext released
        # by the prune, exactly as in load_secure_pruned. Recompute the chain
        # as a plain chain so only that interpretation is exercised.
        _name, _size, retain, checkpoint, frontier, _nonces, entries, _tail = self.fields
        index3, env3, _prev3, _hash3, _locator3 = entries[0]
        index4, payload4, _prev4, _hash4, locator4 = entries[1]
        hash3 = entry_digest(3, checkpoint, env3)
        hash4 = entry_digest(4, hash3, payload4)
        mirror = AuditLog(key=b"shared-secret")
        mirror._retain_from = retain
        mirror._checkpoint_head = checkpoint
        mirror._frontier = dict(frontier)
        mirror._head = checkpoint
        mirror.append(env3)
        mirror.append(payload4)
        broken_entries = [
            (index3, env3, checkpoint, hash3, b""),
            (index4, payload4, hash3, hash4, locator4),
        ]
        tail = (mirror.merkle_root(), mirror.head, 0, b"shared-secret", 0)
        restored = load_pruned_hybrid(
            self._forge(entries=broken_entries, tail=tail), _KEY
        )
        self.assertEqual(restored.head, mirror.head)
        self.assertNotIn(3, restored._encrypted_locators)

    def test_duplicate_retained_envelope_nonce_rejected(self):
        # Turn retained entry 4 into a second ciphertext carrying entry 3's
        # nonce, recomputing every digest/root/head through a mirror log with
        # the same checkpoint/frontier, so only the duplicate-nonce rule fails.
        _name, _size, retain, checkpoint, frontier, _nonces, entries, _tail = self.fields
        index3, env3, prev3, hash3, locator3 = entries[0]
        aad_domain = b"auditchain/aead/v1\0"
        enc_magic = b"auditchain/encrypted-entry/v1\0"
        # Recover the 12-byte nonce of entry 3's envelope.
        shared_nonce = env3[len(enc_magic) + 1:len(enc_magic) + 13]
        aad4 = aad_domain + b"\x01" + u64(4) + hash3
        env4 = enc_magic + b"\x01" + shared_nonce + AESGCM(_ENC_KEY).encrypt(
            shared_nonce, b"second", aad4
        )
        hash4 = entry_digest(4, hash3, env4)
        mirror = AuditLog(key=b"shared-secret")
        mirror._retain_from = retain
        mirror._checkpoint_head = checkpoint
        mirror._frontier = dict(frontier)
        mirror._head = checkpoint
        mirror.append(env3)
        mirror.append(env4)
        root = mirror.merkle_root()
        head = mirror.head
        # The locator HMAC value is irrelevant to the duplicate-nonce check;
        # any digest-width locator classifies both records as ciphertexts.
        broken_entries = [
            (index3, env3, prev3, hash3, locator3),
            (4, env4, hash3, hash4, bytes(range(32))),
        ]
        tail = (root, head, 0, b"shared-secret", 0)
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken_entries, tail=tail), _KEY)

    def test_plain_payload_with_envelope_magic_loads(self):
        # Classification is driven by the locator: a plain retained entry
        # whose payload merely starts with the envelope magic stays plain.
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.encrypt("released", _ENC_KEY)
        log.prune(2, log.seal(2))
        log.append(b"auditchain/encrypted-entry/v1\0" + b"\x01" + b"x" * 40)
        log.encrypt("real secret", _ENC_KEY, nonce=b"\x04" * 12)
        restored = load_pruned_hybrid(dump_pruned_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(
            restored.find(b"auditchain/encrypted-entry/v1\0" + b"\x01" + b"x" * 40),
            (2,),
        )
        self.assertEqual(restored.find_encrypted(b"real secret", _ENC_KEY), (3,))

    def test_bad_root_width(self):
        root, head, stage, key_material, exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                self._forge(tail=(root[:-1], head, stage, key_material, exported)), _KEY
            )

    def test_bad_head_width(self):
        root, head, stage, key_material, exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                self._forge(tail=(root, head + b"\x00", stage, key_material, exported)), _KEY
            )

    def test_bad_flag(self):
        root, head, stage, key_material, _exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                self._forge(tail=(root, head, stage, key_material, 2)), _KEY
            )

    def test_empty_evolution_key(self):
        root, head, stage, _key_material, exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                self._forge(tail=(root, head, stage, b"", exported)), _KEY
            )

    def test_wrong_width_evolution_key_after_evolution(self):
        # stage == 3 here, so K must be the 32-byte digest width.
        root, head, stage, _key_material, exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                self._forge(tail=(root, head, stage, b"too-short", exported)), _KEY
            )

    def test_wrong_root_rejected(self):
        root, head, stage, key_material, exported = self.fields[7]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(root))
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                self._forge(tail=(wrong, head, stage, key_material, exported)), _KEY
            )

    def test_wrong_head_rejected(self):
        root, head, stage, key_material, exported = self.fields[7]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(head))
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                self._forge(tail=(root, wrong, stage, key_material, exported)), _KEY
            )


if __name__ == "__main__":
    unittest.main()
