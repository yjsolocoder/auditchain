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

_ENC_MAGIC = b"auditchain/encrypted-entry/v1\0"
_AAD_DOMAIN = b"auditchain/aead/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _encode(plaintext, nonce=b"N" * 12):
    aad = MAGIC + _VERSION + nonce
    sealed = AESGCM(_KEY).encrypt(nonce, plaintext, aad)
    return MAGIC + _VERSION + nonce + sealed


def _make_log(retain_from=2):
    log = AuditLog(key=b"shared-secret")
    verifier = log.export_verifier()
    log.append("plain one")                      # 0: released by the prune
    log.encrypt("released secret", _ENC_KEY)     # 1: released ciphertext
    tag1 = log.auth(1)                           # stage -> 1; tag released
    log.append(b"plain two")                     # 2: retained plain
    log.rotate_key()                             # stage -> 2
    log.encrypt(b"kept secret", _ENC_KEY, nonce=b"\x07" * 12)  # 3: retained
    tag3 = log.auth(3)                           # stage -> 3
    log.prune(retain_from, log.seal(retain_from))
    return log, verifier, tag1, tag3


class DumpPrunedHybridTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag1, self.tag3 = _make_log()

    def test_wire_layout(self):
        data = dump_pruned_hybrid(self.log, _KEY, nonce=b"N" * 12)
        self.assertTrue(data.startswith(MAGIC + _VERSION + b"N" * 12))
        # Everything after D || 0x01 || N is ciphertext||tag (>=16 bytes).
        self.assertGreaterEqual(len(data) - (len(MAGIC) + 1 + 12), 16)
        # Plaintext never leaks a payload, a key or the evolution key.
        self.assertNotIn(b"plain one", data)
        self.assertNotIn(b"plain two", data)
        self.assertNotIn(b"released secret", data)
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
            self.log.find(b"plain two"),
            self.log.find_encrypted(b"kept secret", _ENC_KEY),
            dict(self.log._frontier),
            self.log._checkpoint_head,
            set(self.log._used_nonces),
        )
        dump_pruned_hybrid(self.log, _KEY)
        dump_pruned_hybrid(self.log, _KEY, nonce=b"X" * 12)
        after = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"plain two"),
            self.log.find_encrypted(b"kept secret", _ENC_KEY),
            dict(self.log._frontier),
            self.log._checkpoint_head,
            set(self.log._used_nonces),
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
        # Unlike dump_pruned_auth, a pruned log with encrypt history —
        # including ciphertexts released by the prune — qualifies.
        data = dump_pruned_hybrid(self.log, _KEY)
        self.assertEqual(load_pruned_hybrid(data, _KEY).head, self.log.head)

    def test_allows_plain_only_pruned_log(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        log.auth(0)
        log.prune(1, log.seal(1))
        data = dump_pruned_hybrid(log, _KEY)
        restored = load_pruned_hybrid(data, _KEY)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored._used_nonces, set())

    def test_failure_is_atomic(self):
        with self.assertRaises(ValueError):
            dump_pruned_hybrid(self.log, bytes(31))
        self.assertEqual(len(self.log), 4)
        self.assertEqual(self.log.stage, 3)
        # The log still dumps fine after the failed attempt.
        load_pruned_hybrid(dump_pruned_hybrid(self.log, _KEY), _KEY)


class LoadPrunedHybridRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag1, self.tag3 = _make_log()
        self.data = dump_pruned_hybrid(self.log, _KEY, nonce=b"N" * 12)

    def _restore(self):
        return load_pruned_hybrid(self.data, _KEY)

    def test_length_retain_point_head_root_match(self):
        restored = self._restore()
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, 2)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertTrue(restored.verify())

    def test_checkpoint_and_frontier_match(self):
        restored = self._restore()
        self.assertEqual(restored._checkpoint_head, self.log._checkpoint_head)
        self.assertEqual(restored._frontier, self.log._frontier)

    def test_retained_entries_match(self):
        restored = self._restore()
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertEqual([e.index for e in restored], [2, 3])
        # Released indices stay inaccessible.
        with self.assertRaises(IndexError):
            restored.entry(0)
        with self.assertRaises(IndexError):
            restored.entry(1)

    def test_find_index_covers_only_retained(self):
        restored = self._restore()
        self.assertEqual(restored.find(b"plain two"), (2,))
        self.assertEqual(restored.find(b"missing"), ())
        # The released plain entry is not in the find index.
        self.assertEqual(restored.find(b"plain one"), ())

    def test_encrypted_locator_index_covers_only_retained(self):
        restored = self._restore()
        self.assertEqual(restored.find_encrypted(b"kept secret", _ENC_KEY), (3,))
        self.assertEqual(restored.find_encrypted(b"nonesuch", _ENC_KEY), ())
        # The released ciphertext is not locatable.
        self.assertEqual(restored.find_encrypted(b"released secret", _ENC_KEY), ())

    def test_retained_ciphertext_still_decrypts(self):
        restored = self._restore()
        self.assertEqual(decrypt_entry(restored.entry(3), _ENC_KEY), b"kept secret")

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
        log.prune(1, log.seal(1))
        restored = load_pruned_hybrid(dump_pruned_hybrid(log, _KEY), _KEY)
        verifier = restored.export_verifier()
        self.assertIsInstance(verifier, Verifier)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_complete_nonce_history_restored(self):
        restored = self._restore()
        self.assertEqual(restored._used_nonces, self.log._used_nonces)
        # The history covers two nonces: one retained, one released.
        self.assertEqual(len(restored._used_nonces), 2)
        # The retained ciphertext's nonce is still rejected after restore.
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=b"\x07" * 12)
        # A nonce belonging to the released ciphertext is rejected too.
        released_nonce = next(
            iter(self.log._used_nonces - {b"\x07" * 12})
        )
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=released_nonce)
        # A genuinely fresh nonce works.
        restored.encrypt("again", _ENC_KEY, nonce=b"\x08" * 12)
        self.assertEqual(restored.find_encrypted(b"again", _ENC_KEY), (4,))

    def test_forward_security_continues(self):
        restored = self._restore()
        self.log.append("f")
        restored.append("f")
        tag_orig = self.log.auth(4)
        tag_rest = restored.auth(4)
        self.assertEqual(tag_orig, tag_rest)
        self.assertEqual(self.log.stage, restored.stage)
        # Old verifier material still verifies tags from both processes.
        self.assertTrue(verify_auth(restored.entry(3), self.tag3, self.verifier))
        self.assertTrue(verify_auth(restored.entry(4), tag_orig, self.verifier))

    def test_independent_and_mutable(self):
        restored = self._restore()
        restored.append("separate")
        self.assertEqual(len(restored), len(self.log) + 1)
        restored.rotate_key()
        self.assertEqual(restored.stage, self.log.stage + 1)

    def test_snapshots_and_proofs_match_original(self):
        restored = self._restore()
        for size in (2, 3, 4):
            self.assertEqual(
                restored.merkle_root(size), self.log.merkle_root(size)
            )
        self.assertEqual(
            restored.inclusion_proof(3, 4), self.log.inclusion_proof(3, 4)
        )
        self.assertEqual(
            restored.consistency_proof(2, 4),
            self.log.consistency_proof(2, 4),
        )
        # Snapshot size 0 stays the content-free constant.
        self.assertEqual(restored.merkle_root(0), self.log.merkle_root(0))

    def test_supports_further_pruning(self):
        restored = self._restore()
        restored.prune(3, restored.seal(3))
        self.assertEqual(restored.retain_from, 3)
        self.assertEqual([e.index for e in restored], [3])
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        # The fully re-pruned log dumps and loads again.
        again = load_pruned_hybrid(dump_pruned_hybrid(restored, _KEY), _KEY)
        self.assertEqual(again.head, self.log.head)
        self.assertEqual(again.retain_from, 3)

    def test_fully_pruned_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.encrypt("s", _ENC_KEY)
        log.prune(2, log.seal(2))
        restored = load_pruned_hybrid(dump_pruned_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.retain_from, 2)
        self.assertEqual(len(restored), 2)
        self.assertEqual(list(restored), [])
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored._used_nonces, log._used_nonces)

    def test_non_default_hash(self):
        log = AuditLog(key=b"shared-secret", hash_name="sha512")
        log.append("a")
        log.encrypt("released", _ENC_KEY)
        log.append("b")
        log.encrypt("kept", _ENC_KEY, nonce=b"\x09" * 12)
        log.auth(0)
        log.prune(2, log.seal(2))
        restored = load_pruned_hybrid(dump_pruned_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(len(restored.head), 64)
        self.assertEqual(restored.find_encrypted(b"kept", _ENC_KEY), (3,))


class LoadPrunedHybridWireErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log, _v, _t1, _t3 = _make_log()
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
        with self.assertRaises(ValueError):
            load_pruned_hybrid(b"x" + self.data[1:], _KEY)

    def test_bad_version(self):
        broken = MAGIC + b"\x02" + self.data[len(MAGIC) + 1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(broken, _KEY)

    def test_truncated(self):
        for cut in (
            len(MAGIC),
            len(MAGIC) + 1,
            len(MAGIC) + 1 + 12,
            len(self.data) - 1,
        ):
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
        self.log, _v, _t1, _t3 = _make_log()
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
        total = take_u64()
        retain_from = take_u64()
        checkpoint = take_blob()
        frontier_count = take_u64()
        frontier = [(take_u64(), take_blob()) for _ in range(frontier_count)]
        nonce_count = take_u64()
        nonces = [take_blob() for _ in range(nonce_count)]
        entry_count = take_u64()
        entries = []
        for _ in range(entry_count):
            entries.append(
                (take_u64(), take_blob(), take_blob(), take_blob(), take_blob())
            )
        tail = (take_blob(), take_blob(), take_u64(), take_blob(), take_u64())
        assert cursor == len(data)
        return name, total, retain_from, checkpoint, frontier, nonces, entries, tail

    @staticmethod
    def _build(name, total, retain_from, checkpoint, frontier, nonces, entries, tail):
        parts = [
            blob(name),
            u64(total),
            u64(retain_from),
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

    def _forge(self, **overrides):
        (
            name,
            total,
            retain_from,
            checkpoint,
            frontier,
            nonces,
            entries,
            tail,
        ) = self.fields
        return _encode(
            self._build(
                overrides.get("name", name),
                overrides.get("total", total),
                overrides.get("retain_from", retain_from),
                overrides.get("checkpoint", checkpoint),
                overrides.get("frontier", frontier),
                overrides.get("nonces", nonces),
                overrides.get("entries", entries),
                overrides.get("tail", tail),
            ),
            nonce=self.nonce,
        )

    def test_baseline_plaintext_loads(self):
        self.assertEqual(load_pruned_hybrid(self.good, _KEY).head, self.log.head)

    def test_layout(self):
        _n, total, retain_from, _c, frontier, nonces, entries, _t = self.fields
        self.assertEqual((total, retain_from), (4, 2))
        self.assertEqual([h for h, _d in frontier], [1])
        self.assertEqual(len(nonces), 2)
        self.assertEqual(nonces, sorted(nonces))
        self.assertTrue(all(len(used) == 12 for used in nonces))
        self.assertEqual([e[0] for e in entries], [2, 3])

    def test_trailing_bytes(self):
        plaintext = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_pruned_hybrid(_encode(plaintext + b"\x00", nonce=self.nonce), _KEY)

    def test_truncated_plaintext(self):
        plaintext = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_pruned_hybrid(_encode(plaintext[:-1], nonce=self.nonce), _KEY)

    def test_bad_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(name=b"\xff\xff"), _KEY)

    def test_unknown_hash(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(name=b"nonesuch"), _KEY)

    def test_retain_zero(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(retain_from=0), _KEY)

    def test_retain_past_total(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(total=4, retain_from=5), _KEY)

    def test_retain_count_mismatch_total(self):
        # r == 3 but the entry section still holds two records (n - r = 1).
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(retain_from=3), _KEY)

    def test_checkpoint_wrong_width(self):
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(checkpoint=b"\x00" * 31), _KEY)

    def test_frontier_wrong_width(self):
        _n, _t, r, _c, frontier, _no, _e, _ta = self.fields
        broken = [(frontier[0][0], frontier[0][1][:-1])]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(frontier=broken), _KEY)

    def test_frontier_not_set_bits(self):
        _n, _t, r, _c, frontier, _no, _e, _ta = self.fields
        # r == 2 has only bit 1 set; claim height 0 instead.
        broken = [(0, frontier[0][1])]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(frontier=broken), _KEY)

    def test_frontier_duplicate_height(self):
        _n, _t, r, _c, frontier, _no, _e, _ta = self.fields
        digest = frontier[0][1]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(frontier=[(1, digest), (1, digest)]), _KEY)

    def test_nonce_wrong_width(self):
        _n, _t, _r, _c, _f, nonces, _e, _ta = self.fields
        broken = [nonces[0][:-1]] + nonces[1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(nonces=broken), _KEY)

    def test_nonces_out_of_order(self):
        _n, _t, _r, _c, _f, nonces, _e, _ta = self.fields
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(nonces=list(reversed(nonces))), _KEY)

    def test_nonce_duplicated_in_history(self):
        _n, _t, _r, _c, _f, nonces, _e, _ta = self.fields
        with self.assertRaises(ValueError):
            load_pruned_hybrid(
                self._forge(nonces=[nonces[0], nonces[0]] + nonces[1:]), _KEY
            )

    def test_extra_history_nonce_is_allowed(self):
        # An extra history nonce is the normal "released ciphertext" case:
        # here both retained and released nonces are already present, so add
        # a third one that no visible entry uses; it must still load.
        _n, _t, _r, _c, _f, nonces, _e, _ta = self.fields
        extra = sorted(nonces + [b"\xfe" * 12])
        restored = load_pruned_hybrid(self._forge(nonces=extra), _KEY)
        self.assertEqual(restored.head, self.log.head)
        self.assertIn(b"\xfe" * 12, restored._used_nonces)

    def test_retained_nonce_missing_from_history(self):
        _n, _t, _r, _c, _f, nonces, entries, _ta = self.fields
        # Entry 3 carries nonce 0x07*12; drop every other nonce (the
        # released one), then drop 0x07*12 too and keep only an unrelated
        # released-style nonce.
        kept_nonce = b"\x07" * 12
        unrelated = sorted(set(nonces) - {kept_nonce})
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(nonces=unrelated), _KEY)

    def test_bad_entry_index(self):
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[0]
        broken = [(index + 1, payload, previous_hash, entry_hash, locator)] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_bad_entry_digest_width(self):
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[0]
        broken = [(index, payload, previous_hash, entry_hash[:-1], locator)] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_bad_previous_hash_width(self):
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[0]
        broken = [(index, payload, previous_hash + b"\x00", entry_hash, locator)] + entries[1:]
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_broken_chain_rejected(self):
        # Swap the two retained payloads: widths stay intact but the chain
        # from the checkpoint breaks.
        entries = list(self.fields[6])
        first, second = entries[0], entries[1]
        entries[0] = (first[0], second[1], first[2], first[3], first[4])
        entries[1] = (second[0], first[1], second[2], second[3], second[4])
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=entries), _KEY)

    def test_locator_wrong_width(self):
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        # Entry 3 is the retained ciphertext.
        index, payload, previous_hash, entry_hash, locator = entries[1]
        self.assertTrue(locator)
        broken = list(entries)
        broken[1] = (index, payload, previous_hash, entry_hash, locator[:-1])
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_locator_on_plain_payload_rejected(self):
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        index, payload, previous_hash, entry_hash, _locator = entries[0]
        broken = list(entries)
        broken[0] = (index, payload, previous_hash, entry_hash, bytes(32))
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(entries=broken), _KEY)

    def test_plain_payload_with_envelope_magic_loads(self):
        # Classification is driven by the locator: a retained plain entry
        # whose payload merely starts with the envelope magic stays plain.
        log = AuditLog(key=b"shared-secret")
        log.append(b"released")
        log.append(b"auditchain/encrypted-entry/v1\0" + b"\x01" + b"x" * 40)
        log.prune(1, log.seal(1))
        restored = load_pruned_hybrid(dump_pruned_hybrid(log, _KEY), _KEY)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(
            restored.find(b"auditchain/encrypted-entry/v1\0" + b"\x01" + b"x" * 40),
            (1,),
        )

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

    def test_wrong_checkpoint_rejected(self):
        _n, _t, _r, checkpoint, _f, _no, _e, _ta = self.fields
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(checkpoint))
        with self.assertRaises(ValueError):
            load_pruned_hybrid(self._forge(checkpoint=wrong), _KEY)


class LoadPrunedHybridDuplicateRetainedNonceTest(unittest.TestCase):
    """Two retained ciphertexts sharing one envelope nonce in a consistent
    chain: only the duplicate-nonce check can fail."""

    def test_duplicate_envelope_nonce_rejected(self):
        shared_nonce = b"\x05" * 12

        def seal(index, previous_hash, plaintext):
            aad = _AAD_DOMAIN + b"\x01" + u64(index) + previous_hash
            sealed = AESGCM(_ENC_KEY).encrypt(shared_nonce, plaintext, aad)
            return _ENC_MAGIC + b"\x01" + shared_nonce + sealed

        genesis = bytes(32)
        hash0 = entry_digest(0, genesis, b"a")
        env1 = seal(1, hash0, b"first")
        hash1 = entry_digest(1, hash0, env1)
        env2 = seal(2, hash1, b"second")
        hash2 = entry_digest(2, hash1, env2)
        # A plain keyed log over the same records, pruned at r == 1, yields
        # the matching checkpoint, frontier, root and head.
        mirror = AuditLog(key=b"k")
        mirror.append(b"a")
        mirror.append(env1)
        mirror.append(env2)
        mirror.prune(1, mirror.seal(1))
        entries = [
            (1, env1, hash0, hash1, bytes(32)),
            (2, env2, hash1, hash2, bytes(32)),
        ]
        parts = [
            blob(b"sha256"),
            u64(3),
            u64(1),
            blob(mirror._checkpoint_head),
            u64(1),
            u64(0),
            blob(mirror._frontier[0]),
            u64(1),
            blob(shared_nonce),
            u64(2),
        ]
        for index, payload, previous_hash, entry_hash, locator in entries:
            parts += [
                u64(index),
                blob(payload),
                blob(previous_hash),
                blob(entry_hash),
                blob(locator),
            ]
        parts += [blob(mirror.merkle_root()), blob(mirror.head), u64(0), blob(b"k"), u64(0)]
        forged = _encode(b"".join(parts))
        with self.assertRaises(ValueError):
            load_pruned_hybrid(forged, _KEY)


if __name__ == "__main__":
    unittest.main()
