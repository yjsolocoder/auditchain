import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
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
    log.encrypt("secret one", _ENC_KEY, nonce=b"1" * 12)
    tag1 = log.auth(1)
    log.append(b"plain two")
    log.rotate_key()
    log.encrypt(b"secret two", _ENC_KEY, nonce=b"\x07" * 12)
    tag3 = log.auth(3)
    # stage: auth(1) -> 1, rotate -> 2, auth(3) -> 3
    return log, verifier, tag1, tag3


def _frame(log, root, head):
    parts = [blob(log.hash_name.encode("utf-8")), u64(len(log._used_nonces))]
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


def _encode(log, seed=_SEED_A):
    root = log.merkle_root()
    head = log.head
    body = MAGIC + u64(1) + _frame(log, root, head)
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
        # The frame is plaintext: the evolution key is visible in the stream.
        self.assertIn(self.log._key, data)
        # No symmetric envelope of the hybrid wire format is used here.
        self.assertFalse(data.startswith(b"auditchain/hybrid/v1\0"))

    def test_deterministic_and_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"plain one"),
            self.log.find_encrypted(b"secret one", _ENC_KEY),
            frozenset(self.log._used_nonces),
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
            frozenset(self.log._used_nonces),
            self.log._key,
        )
        self.assertEqual(before, after)

    def test_distinct_seeds_differ_only_in_signature(self):
        first = dump_signed_hybrid(self.log, _SEED_A)
        second = dump_signed_hybrid(self.log, _SEED_B)
        self.assertEqual(first[:-64], second[:-64])
        self.assertNotEqual(first[-64:], second[-64:])

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            dump_signed_hybrid("not a log", _SEED_A)
        with self.assertRaises(TypeError):
            dump_signed_hybrid(self.log, "not bytes")
        with self.assertRaises(TypeError):
            dump_signed_hybrid(self.log, bytearray(_SEED_A))

    def test_seed_length(self):
        with self.assertRaises(ValueError):
            dump_signed_hybrid(self.log, b"short")
        with self.assertRaises(ValueError):
            dump_signed_hybrid(self.log, b"s" * 33)

    def test_pruned_log_rejected(self):
        log = AuditLog(key=b"k")
        for i in range(4):
            log.append(f"r{i}")
        log.encrypt(b"secret", _ENC_KEY)
        receipt = log.seal(2)
        log.prune(2, receipt)
        with self.assertRaises(ValueError):
            dump_signed_hybrid(log, _SEED_A)

    def test_keyless_log_rejected_even_plain(self):
        log = AuditLog()
        log.append("x")
        with self.assertRaises(ValueError):
            dump_signed_hybrid(log, _SEED_A)

    def test_keyless_log_rejected_with_ciphertext(self):
        log = AuditLog()
        log.encrypt(b"secret", _ENC_KEY)
        with self.assertRaises(ValueError):
            dump_signed_hybrid(log, _SEED_A)

    def test_allows_encrypted_history(self):
        # The main point of the hybrid variant: ciphertext history is fine.
        data = dump_signed_hybrid(self.log, _SEED_A)
        self.assertTrue(load_signed_hybrid(data, PUBLIC_A).verify())


class LoadSignedHybridTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag1, self.tag3 = _make_log()
        self.data = dump_signed_hybrid(self.log, _SEED_A)

    def test_round_trip_state(self):
        restored = load_signed_hybrid(self.data, PUBLIC_A)
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.stage, self.log.stage)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(restored.retain_from, 0)
        self.assertEqual(restored.hash_name, self.log.hash_name)
        for entry in self.log:
            self.assertEqual(restored.entry(entry.index), entry)
        self.assertEqual(restored.find(b"plain one"), self.log.find(b"plain one"))
        self.assertEqual(restored.find(b"plain two"), self.log.find(b"plain two"))
        self.assertEqual(
            restored.find_encrypted(b"secret one", _ENC_KEY),
            self.log.find_encrypted(b"secret one", _ENC_KEY),
        )
        self.assertEqual(
            restored.find_encrypted(b"secret two", _ENC_KEY),
            self.log.find_encrypted(b"secret two", _ENC_KEY),
        )
        self.assertEqual(restored._used_nonces, self.log._used_nonces)
        self.assertTrue(restored.verify())

    def test_round_trip_empty_log(self):
        log = AuditLog(key=b"k")
        data = dump_signed_hybrid(log, _SEED_A)
        restored = load_signed_hybrid(data, PUBLIC_A)
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())

    def test_encrypt_only_round_trip(self):
        log = AuditLog(key=b"k")
        log.encrypt(b"only secret", _ENC_KEY, nonce=b"n" * 12)
        restored = load_signed_hybrid(
            dump_signed_hybrid(log, _SEED_A), PUBLIC_A
        )
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.find_encrypted(b"only secret", _ENC_KEY), (0,))
        self.assertEqual(restored._used_nonces, {b"n" * 12})

    def test_no_encrypt_history_round_trip(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        restored = load_signed_hybrid(
            dump_signed_hybrid(log, _SEED_A), PUBLIC_A
        )
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.find(b"a"), (0,))
        self.assertEqual(restored._used_nonces, set())

    def test_evolution_continues_identically(self):
        restored = load_signed_hybrid(self.data, PUBLIC_A)
        # Continue both logs identically: the freshly minted tags must match
        # byte-for-byte and verify against the exported stage-0 verifier.
        self.log.append("more")
        restored.append("more")
        original_tag = self.log.auth(4)
        restored_tag = restored.auth(4)
        self.assertEqual(restored_tag, original_tag)
        self.assertEqual(restored.stage, self.log.stage)
        self.assertTrue(
            verify_auth(self.log.entry(4), original_tag, self.verifier)
        )
        self.assertTrue(
            verify_auth(restored.entry(4), restored_tag, self.verifier)
        )
        # The carried historical tags also still verify.
        self.assertTrue(verify_auth(restored.entry(1), self.tag1, self.verifier))
        self.assertTrue(verify_auth(restored.entry(3), self.tag3, self.verifier))

    def test_verifier_exported_flag_restored(self):
        restored = load_signed_hybrid(self.data, PUBLIC_A)
        # The source already exported its stage-0 verifier; the restore must
        # not allow a second export.
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_unexported_flag_restored(self):
        log = AuditLog(key=b"k")
        log.append("x")
        restored = load_signed_hybrid(
            dump_signed_hybrid(log, _SEED_A), PUBLIC_A
        )
        verifier = restored.export_verifier()
        self.assertEqual(verifier.key, b"k")

    def test_nonce_history_restored_and_enforced(self):
        restored = load_signed_hybrid(self.data, PUBLIC_A)
        self.assertEqual(restored._used_nonces, {b"1" * 12, b"\x07" * 12})
        # An old nonce is still rejected after the restore.
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=b"1" * 12)
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=b"\x07" * 12)
        # A fresh nonce is accepted.
        restored.encrypt("again", _ENC_KEY, nonce=b"2" * 12)

    def test_restored_log_is_independent_and_mutable(self):
        restored = load_signed_hybrid(self.data, PUBLIC_A)
        restored.append("e")
        restored.encrypt(b"hidden", b"k" * 32, nonce=b"0" * 12)
        restored.rotate_key()
        self.assertEqual(len(self.log), 4)
        self.assertEqual(self.log.stage, 3)
        self.assertEqual(len(restored), 6)
        self.assertEqual(restored.stage, 4)
        # The shared prefix is untouched on the original.
        for entry in self.log:
            self.assertEqual(restored.entry(entry.index), entry)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            load_signed_hybrid(bytearray(self.data), PUBLIC_A)
        with self.assertRaises(TypeError):
            load_signed_hybrid(memoryview(self.data), PUBLIC_A)
        with self.assertRaises(TypeError):
            load_signed_hybrid(self.data, "not bytes")
        with self.assertRaises(TypeError):
            load_signed_hybrid(self.data, bytearray(PUBLIC_A))

    def test_public_key_length(self):
        with self.assertRaises(ValueError):
            load_signed_hybrid(self.data, b"short")
        with self.assertRaises(ValueError):
            load_signed_hybrid(self.data, b"p" * 33)

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_signed_hybrid(
                b"auditchain/signed-hybrid/v2\0" + self.data[len(MAGIC):],
                PUBLIC_A,
            )
        with self.assertRaises(ValueError):
            load_signed_hybrid(b"", PUBLIC_A)

    def test_bad_version(self):
        body = MAGIC + u64(2) + self.data[len(MAGIC) + 8:-64]
        data = body + _sign(_SEED_A, body)
        with self.assertRaises(ValueError):
            load_signed_hybrid(data, PUBLIC_A)

    def test_truncation(self):
        for cut in (len(MAGIC), len(self.data) - 65, len(self.data) - 1, 0):
            with self.assertRaises(ValueError):
                load_signed_hybrid(self.data[:cut], PUBLIC_A)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            load_signed_hybrid(self.data + b"x", PUBLIC_A)

    def test_signature_failure(self):
        # Wrong public key.
        with self.assertRaises(ValueError):
            load_signed_hybrid(self.data, PUBLIC_B)
        # A flipped body byte invalidates the signature (verification first).
        flipped = bytearray(self.data)
        flipped[len(MAGIC) + 12] ^= 1
        with self.assertRaises(ValueError):
            load_signed_hybrid(bytes(flipped), PUBLIC_A)
        # A flipped signature byte.
        flipped = bytearray(self.data)
        flipped[-1] ^= 1
        with self.assertRaises(ValueError):
            load_signed_hybrid(bytes(flipped), PUBLIC_A)

    def test_other_hash_algorithms(self):
        for hash_name in ("sha512", "sha3-256"):
            log = AuditLog(key=b"k", hash_name=hash_name)
            log.append("plain")
            log.encrypt(b"secret", _ENC_KEY, nonce=b"n" * 12)
            log.auth(0)
            data = dump_signed_hybrid(log, _SEED_A)
            restored = load_signed_hybrid(data, PUBLIC_A)
            self.assertEqual(restored.hash_name, hash_name)
            self.assertEqual(restored.head, log.head)
            self.assertEqual(restored.merkle_root(), log.merkle_root())
            self.assertEqual(restored.stage, log.stage)
            self.assertEqual(
                restored.find_encrypted(b"secret", _ENC_KEY), (1,)
            )
            log.append("next")
            restored.append("next")
            self.assertEqual(restored.auth(1), log.auth(1))


class LoadSignedHybridFrameValidationTest(unittest.TestCase):
    """Valid signatures whose signed frame violates the framing."""

    def setUp(self):
        self.log, _verifier, _tag1, _tag3 = _make_log()
        self.good = dump_signed_hybrid(self.log, _SEED_A)
        self.fields = self._parse(self.good[:-64][len(MAGIC) + 8:])

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
        parts += [
            blob(root),
            blob(head),
            u64(stage),
            blob(key_material),
            u64(exported),
        ]
        return b"".join(parts)

    def _forge(self, name=None, nonces=None, entries=None, tail=None, seed=_SEED_A):
        old_name, old_nonces, old_entries, old_tail = self.fields
        frame = self._build(
            name if name is not None else old_name,
            nonces if nonces is not None else old_nonces,
            entries if entries is not None else old_entries,
            tail if tail is not None else old_tail,
        )
        body = MAGIC + u64(1) + frame
        return body + _sign(seed, body)

    def test_baseline_loads(self):
        self.assertEqual(
            load_signed_hybrid(self.good, PUBLIC_A).head, self.log.head
        )

    def test_trailing_bytes(self):
        frame = self._build(*self.fields)
        body = MAGIC + u64(1) + frame + b"\x00"
        data = body + _sign(_SEED_A, body)
        with self.assertRaises(ValueError):
            load_signed_hybrid(data, PUBLIC_A)

    def test_truncated_frame(self):
        frame = self._build(*self.fields)
        body = MAGIC + u64(1) + frame[:-1]
        data = body + _sign(_SEED_A, body)
        with self.assertRaises(ValueError):
            load_signed_hybrid(data, PUBLIC_A)

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

    def test_nonce_duplicated_in_history(self):
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
            (
                1 if i == 0 else index,
                payload,
                previous_hash,
                entry_hash,
                locator,
            )
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
        # Two encrypted entries carrying the same envelope nonce in a
        # fully consistent chain, so only the duplicate-nonce check fails.
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
        # Classification is driven by the locator, not the payload.
        log = AuditLog(key=b"shared-secret")
        log.append(b"auditchain/encrypted-entry/v1\0" + b"\x01" + b"x" * 40)
        log.encrypt("real secret", _ENC_KEY)
        data = dump_signed_hybrid(log, _SEED_A)
        restored = load_signed_hybrid(data, PUBLIC_A)
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

    def test_signature_checked_before_frame(self):
        # A frame with invalid UTF-8 signed by the wrong seed must fail as a
        # signature error, never parse: sign with seed B, verify with A.
        data = self._forge(name=b"\xff\xff", seed=_SEED_B)
        with self.assertRaises(ValueError):
            load_signed_hybrid(data, PUBLIC_A)


if __name__ == "__main__":
    unittest.main()
