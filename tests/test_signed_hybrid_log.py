import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    Verifier,
    decrypt_entry,
    dump_signed_hybrid,
    load_signed_hybrid,
    verify_auth,
)

MAGIC = b"auditchain/signed-hybrid/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_ENC_KEY = bytes(range(65, 97))


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


def _frame(log, root, head):
    parts = [blob(log.hash_name.encode("utf-8"))]
    parts.append(u64(len(log._used_nonces)))
    for used_nonce in sorted(log._used_nonces):
        parts.append(blob(used_nonce))
    parts.append(u64(len(log)))
    for entry in log:
        locator = log._encrypted_locators.get(entry.index, b"")
        parts.append(u64(entry.index))
        parts.append(blob(entry.payload))
        parts.append(blob(entry.previous_hash))
        parts.append(blob(entry.entry_hash))
        parts.append(blob(locator))
    parts.append(blob(root))
    parts.append(blob(head))
    parts.append(u64(log.stage))
    parts.append(blob(log._key))
    parts.append(u64(1 if log._verifier_exported else 0))
    return b"".join(parts)


def _encode(log, seed=_SEED_A, version=1, frame=None):
    root = log.merkle_root()
    head = log.head
    body = MAGIC + u64(version) + (
        frame if frame is not None else _frame(log, root, head)
    )
    return body + _sign(seed, body)


class DumpSignedHybridTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag1, self.tag3 = _make_log()

    def test_wire_layout(self):
        data = dump_signed_hybrid(self.log, _SEED_A)
        self.assertTrue(data.startswith(MAGIC + u64(1)))
        self.assertEqual(data, _encode(self.log))
        # The trailing 64 bytes are an Ed25519 signature over the body.
        body, signature = data[:-64], data[-64:]
        Ed25519PrivateKey.from_private_bytes(_SEED_A).public_key().verify(
            signature, body
        )
        # The frame is plaintext: payloads, nonces and the current evolution
        # key are visible in the stream; the signature only authenticates
        # origin.
        self.assertIn(b"plain one", data)
        self.assertIn(self.log._key, data)
        self.assertIn(b"\x07" * 12, data)

    def test_deterministic_and_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"plain one"),
            self.log.find_encrypted(b"secret one", _ENC_KEY),
            set(self.log._used_nonces),
            self.log._key,
        )
        first = dump_signed_hybrid(self.log, _SEED_A)
        second = dump_signed_hybrid(self.log, _SEED_A)
        self.assertEqual(first, second)
        after = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"plain one"),
            self.log.find_encrypted(b"secret one", _ENC_KEY),
            set(self.log._used_nonces),
            self.log._key,
        )
        self.assertEqual(before, after)

    def test_distinct_seeds_differ_only_in_signature(self):
        first = dump_signed_hybrid(self.log, _SEED_A)
        second = dump_signed_hybrid(self.log, _SEED_B)
        self.assertEqual(first[:-64], second[:-64])
        self.assertNotEqual(first[-64:], second[-64:])

    def test_dump_type_errors(self):
        with self.assertRaises(TypeError):
            dump_signed_hybrid("not a log", _SEED_A)
        for bad_seed in ("not bytes", bytearray(_SEED_A), memoryview(_SEED_A), 32):
            with self.assertRaises(TypeError):
                dump_signed_hybrid(self.log, bad_seed)

    def test_seed_length(self):
        with self.assertRaises(ValueError):
            dump_signed_hybrid(self.log, b"short")
        with self.assertRaises(ValueError):
            dump_signed_hybrid(self.log, b"s" * 33)

    def test_pruned_log_rejected(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_signed_hybrid(log, _SEED_A)

    def test_keyless_log_rejected(self):
        log = AuditLog()
        log.append("x")
        with self.assertRaises(ValueError):
            dump_signed_hybrid(log, _SEED_A)

    def test_allows_encrypted_history(self):
        # Unlike dump_signed_auth, a log with encrypt history qualifies.
        data = dump_signed_hybrid(self.log, _SEED_A)
        self.assertEqual(load_signed_hybrid(data, PUBLIC_A).head, self.log.head)

    def test_empty_keyed_log(self):
        log = AuditLog(key=b"k")
        data = dump_signed_hybrid(log, _SEED_A)
        restored = load_signed_hybrid(data, PUBLIC_A)
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())

    def test_failure_is_atomic(self):
        log = AuditLog(key=b"k")
        log.append("a")
        with self.assertRaises(ValueError):
            dump_signed_hybrid(log, b"short")
        self.assertEqual(len(log), 1)
        self.assertEqual(log.stage, 0)
        load_signed_hybrid(dump_signed_hybrid(log, _SEED_A), PUBLIC_A)


class LoadSignedHybridRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag1, self.tag3 = _make_log()
        self.data = dump_signed_hybrid(self.log, _SEED_A)

    def _restore(self):
        return load_signed_hybrid(self.data, PUBLIC_A)

    def test_length_head_root_match(self):
        restored = self._restore()
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertTrue(restored.verify())

    def test_absolute_indices_and_entries_match(self):
        restored = self._restore()
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertEqual(list(restored), list(self.log))
        self.assertEqual(tuple(entry.index for entry in restored), (0, 1, 2, 3))

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
        restored = load_signed_hybrid(
            dump_signed_hybrid(log, _SEED_A), PUBLIC_A
        )
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

    def test_forward_security_continues_identically(self):
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
        restored.encrypt(b"hidden", b"k" * 32, nonce=b"0" * 12)
        restored.rotate_key()
        self.assertEqual(len(self.log), 4)
        self.assertEqual(self.log.stage, 3)
        self.assertEqual(len(restored), 6)
        self.assertEqual(restored.stage, 4)

    def test_stage_zero_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.encrypt("s", _ENC_KEY)
        restored = load_signed_hybrid(
            dump_signed_hybrid(log, _SEED_A), PUBLIC_A
        )
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored.head, log.head)

    def test_encrypt_only_log_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        log.encrypt("one", _ENC_KEY)
        log.encrypt("two", _ENC_KEY)
        restored = load_signed_hybrid(
            dump_signed_hybrid(log, _SEED_A), PUBLIC_A
        )
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.find_encrypted(b"one", _ENC_KEY), (0,))
        self.assertEqual(restored.find_encrypted(b"two", _ENC_KEY), (1,))
        self.assertEqual(restored._used_nonces, log._used_nonces)

    def test_non_default_hash(self):
        log = AuditLog(key=b"shared-secret", hash_name="sha512")
        log.append("a")
        log.encrypt("s", _ENC_KEY)
        log.auth(0)
        restored = load_signed_hybrid(
            dump_signed_hybrid(log, _SEED_A), PUBLIC_A
        )
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        self.assertEqual(len(restored.head), 64)
        self.assertEqual(restored.find_encrypted(b"s", _ENC_KEY), (1,))

    def test_load_is_read_only(self):
        view = bytes(self.data)
        load_signed_hybrid(view, PUBLIC_A)
        self.assertEqual(view, self.data)


class LoadSignedHybridErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log, _verifier, _tag1, _tag3 = _make_log()
        self.data = dump_signed_hybrid(self.log, _SEED_A)

    def test_data_type(self):
        for bad in (bytearray(self.data), memoryview(self.data), "x", 42):
            with self.assertRaises(TypeError):
                load_signed_hybrid(bad, PUBLIC_A)

    def test_public_key_type(self):
        for bad in ("k" * 32, bytearray(32), memoryview(bytes(32)), None):
            with self.assertRaises(TypeError):
                load_signed_hybrid(self.data, bad)

    def test_public_key_length(self):
        with self.assertRaises(ValueError):
            load_signed_hybrid(self.data, b"short")
        with self.assertRaises(ValueError):
            load_signed_hybrid(self.data, b"p" * 33)

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_signed_hybrid(b"x" + self.data[1:], PUBLIC_A)
        with self.assertRaises(ValueError):
            load_signed_hybrid(b"", PUBLIC_A)
        # The signed-auth magic must not be accepted here.
        other = b"auditchain/signed-auth/v1\0" + self.data[len(MAGIC):]
        with self.assertRaises(ValueError):
            load_signed_hybrid(other, PUBLIC_A)

    def test_bad_version(self):
        with self.assertRaises(ValueError):
            load_signed_hybrid(_encode(self.log, version=2), PUBLIC_A)

    def test_truncation(self):
        for cut in (
            len(MAGIC),
            len(self.data) - 65,
            len(self.data) - 64,
            len(self.data) - 1,
        ):
            with self.assertRaises(ValueError):
                load_signed_hybrid(self.data[:cut], PUBLIC_A)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            load_signed_hybrid(self.data + b"x", PUBLIC_A)

    def test_signature_failure(self):
        # Wrong public key.
        with self.assertRaises(ValueError):
            load_signed_hybrid(self.data, PUBLIC_B)
        # A flipped body byte invalidates the signature.
        flipped = bytearray(self.data)
        flipped[len(MAGIC) + 12] ^= 1
        with self.assertRaises(ValueError):
            load_signed_hybrid(bytes(flipped), PUBLIC_A)
        # A flipped signature byte.
        flipped = bytearray(self.data)
        flipped[-1] ^= 1
        with self.assertRaises(ValueError):
            load_signed_hybrid(bytes(flipped), PUBLIC_A)

    def test_signature_checked_before_parsing(self):
        # Garbage after a valid magic with a bad signature must fail as a
        # signature failure, never as a frame parse error.
        body = MAGIC + u64(1) + b"not a frame at all"
        data = body + _sign(_SEED_B, body)
        with self.assertRaises(ValueError):
            load_signed_hybrid(data, PUBLIC_A)


class LoadSignedHybridFrameValidationTest(unittest.TestCase):
    """Valid signatures whose signed framing violates the hybrid layout."""

    def setUp(self):
        self.log, _verifier, _tag1, _tag3 = _make_log()
        self.fields = self._parse(_frame(self.log, self.log.merkle_root(), self.log.head))

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

    def _forge(self, name=None, nonces=None, entries=None, tail=None, seed=_SEED_A):
        old_name, old_nonces, old_entries, old_tail = self.fields
        frame = self._build(
            name if name is not None else old_name,
            nonces if nonces is not None else old_nonces,
            entries if entries is not None else old_entries,
            tail if tail is not None else old_tail,
        )
        return _encode(self.log, seed=seed, frame=frame)

    def test_baseline_loads(self):
        self.assertEqual(
            load_signed_hybrid(
                dump_signed_hybrid(self.log, _SEED_A), PUBLIC_A
            ).head,
            self.log.head,
        )

    def test_trailing_bytes_inside_body(self):
        frame = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_signed_hybrid(_encode(self.log, frame=frame + b"\x00"), PUBLIC_A)

    def test_truncated_frame(self):
        frame = self._build(*self.fields)
        with self.assertRaises(ValueError):
            load_signed_hybrid(_encode(self.log, frame=frame[:-1]), PUBLIC_A)

    def test_bad_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            load_signed_hybrid(self._forge(name=b"\xff\xff"), PUBLIC_A)

    def test_unknown_hash(self):
        with self.assertRaises(ValueError):
            load_signed_hybrid(self._forge(name=b"nonesuch"), PUBLIC_A)

    def test_nonce_wrong_width(self):
        _name, nonces, _entries, _tail = self.fields
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(nonces=[nonces[0][:-1]] + nonces[1:]), PUBLIC_A
            )

    def test_nonces_out_of_order(self):
        _name, nonces, _entries, _tail = self.fields
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(nonces=list(reversed(nonces))), PUBLIC_A
            )

    def test_nonce_duplicated(self):
        _name, nonces, _entries, _tail = self.fields
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(nonces=[nonces[0], nonces[0]] + nonces[1:]),
                PUBLIC_A,
            )

    def test_nonce_history_missing_entry_nonce(self):
        _name, nonces, _entries, _tail = self.fields
        with self.assertRaises(ValueError):
            load_signed_hybrid(self._forge(nonces=nonces[:1]), PUBLIC_A)

    def test_nonce_history_with_extra_nonce(self):
        _name, nonces, _entries, _tail = self.fields
        extra = sorted(nonces + [b"\xff" * 12])
        with self.assertRaises(ValueError):
            load_signed_hybrid(self._forge(nonces=extra), PUBLIC_A)

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
            load_signed_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_bad_entry_digest_width(self):
        index, payload, previous_hash, entry_hash, locator = self.fields[2][0]
        entries = [
            (index, payload, previous_hash, entry_hash[:-1], locator)
        ] + self.fields[2][1:]
        with self.assertRaises(ValueError):
            load_signed_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_bad_previous_hash_width(self):
        index, payload, previous_hash, entry_hash, locator = self.fields[2][0]
        entries = [
            (index, payload, previous_hash + b"\x00", entry_hash, locator)
        ] + self.fields[2][1:]
        with self.assertRaises(ValueError):
            load_signed_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_broken_chain_rejected(self):
        # Swapping two payloads keeps widths intact but breaks the chain.
        entries = list(self.fields[2])
        first, second = entries[0], entries[1]
        entries[0] = (first[0], second[1], first[2], first[3], first[4])
        entries[1] = (second[0], first[1], second[2], second[3], second[4])
        with self.assertRaises(ValueError):
            load_signed_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_locator_wrong_width(self):
        index, payload, previous_hash, entry_hash, locator = self.fields[2][1]
        self.assertTrue(locator)
        entries = list(self.fields[2])
        entries[1] = (index, payload, previous_hash, entry_hash, locator[:-1])
        with self.assertRaises(ValueError):
            load_signed_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_locator_on_plain_payload_rejected(self):
        index, payload, previous_hash, entry_hash, _locator = self.fields[2][0]
        entries = list(self.fields[2])
        entries[0] = (index, payload, previous_hash, entry_hash, bytes(32))
        with self.assertRaises(ValueError):
            load_signed_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_dropped_locator_rejected(self):
        index, payload, previous_hash, entry_hash, _locator = self.fields[2][1]
        entries = list(self.fields[2])
        entries[1] = (index, payload, previous_hash, entry_hash, b"")
        with self.assertRaises(ValueError):
            load_signed_hybrid(self._forge(entries=entries), PUBLIC_A)

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
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(nonces=[shared_nonce], entries=entries, tail=tail),
                PUBLIC_A,
            )

    def test_plain_payload_with_envelope_magic_loads(self):
        # Classification is driven by the locator: a plain entry whose
        # payload merely starts with the envelope magic stays a plain entry.
        log = AuditLog(key=b"shared-secret")
        log.append(b"auditchain/encrypted-entry/v1\0" + b"\x01" + b"x" * 40)
        log.encrypt("real secret", _ENC_KEY)
        restored = load_signed_hybrid(
            dump_signed_hybrid(log, _SEED_A), PUBLIC_A
        )
        self.assertEqual(restored.head, log.head)
        self.assertEqual(
            restored.find(
                b"auditchain/encrypted-entry/v1\0" + b"\x01" + b"x" * 40
            ),
            (0,),
        )
        self.assertEqual(restored.find_encrypted(b"real secret", _ENC_KEY), (1,))

    def test_bad_root_width(self):
        root, head, stage, key_material, exported = self.fields[3]
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(tail=(root[:-1], head, stage, key_material, exported)),
                PUBLIC_A,
            )

    def test_bad_head_width(self):
        root, head, stage, key_material, exported = self.fields[3]
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(tail=(root, head + b"\x00", stage, key_material, exported)),
                PUBLIC_A,
            )

    def test_bad_flag(self):
        root, head, stage, key_material, _exported = self.fields[3]
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(tail=(root, head, stage, key_material, 2)),
                PUBLIC_A,
            )

    def test_empty_evolution_key(self):
        root, head, stage, _key_material, exported = self.fields[3]
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(tail=(root, head, stage, b"", exported)),
                PUBLIC_A,
            )

    def test_wrong_width_evolution_key_after_evolution(self):
        # stage == 3 here, so K must be the 32-byte digest width.
        root, head, stage, _key_material, exported = self.fields[3]
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(tail=(root, head, stage, b"too-short", exported)),
                PUBLIC_A,
            )

    def test_wrong_root_rejected(self):
        root, head, stage, key_material, exported = self.fields[3]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(root))
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(tail=(wrong, head, stage, key_material, exported)),
                PUBLIC_A,
            )

    def test_wrong_head_rejected(self):
        root, head, stage, key_material, exported = self.fields[3]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(head))
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                self._forge(tail=(root, wrong, stage, key_material, exported)),
                PUBLIC_A,
            )


if __name__ == "__main__":
    unittest.main()
