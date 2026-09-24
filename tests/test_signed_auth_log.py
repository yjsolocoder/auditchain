import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    Verifier,
    dump_auth,
    dump_signed_auth,
    load_signed_auth,
    verify_auth,
)

MAGIC = b"auditchain/signed-auth/v1\0"

_SEED = bytes(range(32))
_ENC_KEY = bytes(range(1, 33))
_OTHER_PUB = bytes(range(32, 64))


def _public(seed):
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _sign_body(seed, body):
    return Ed25519PrivateKey.from_private_bytes(seed).sign(body)


def _signed(seed, frame, *, version=1, magic=MAGIC):
    body = magic + u64(version) + frame
    return body + _sign_body(seed, body)


class DumpSignedAuthTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        self.verifier = self.log.export_verifier()
        for record in ("a", b"b", b"c" * 100, "d"):
            self.log.append(record)
        self.tag1 = self.log.auth(1)
        self.log.append("e")

    def test_wire_layout(self):
        data = dump_signed_auth(self.log, _SEED)
        self.assertTrue(data.startswith(MAGIC))
        self.assertEqual(data[len(MAGIC):len(MAGIC) + 8], u64(1))
        # The stream closes with exactly a 64-byte signature.
        self.assertGreaterEqual(len(data), 64)

    def test_frame_is_plaintext_not_encrypted(self):
        # Payloads and the evolving key are readable; the signature
        # authenticates the source but encrypts nothing.
        self.assertIn(b"c" * 100, dump_signed_auth(self.log, _SEED))
        stage_zero = AuditLog(key=b"shared-secret")
        stage_zero.append("a")
        self.assertIn(b"shared-secret", dump_signed_auth(stage_zero, _SEED))

    def test_deterministic(self):
        first = dump_signed_auth(self.log, _SEED)
        second = dump_signed_auth(self.log, _SEED)
        self.assertEqual(first, second)

    def test_signature_covers_everything_before_it(self):
        data = dump_signed_auth(self.log, _SEED)
        body, signature = data[:-64], data[-64:]
        self.assertEqual(_sign_body(_SEED, body), signature)

    def test_frame_matches_auth_plaintext_frame(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        wire = dump_auth(self.log, _ENC_KEY, nonce=b"N" * 12)
        aad = b"auditchain/auth-log/v1\0" + b"\x01" + b"N" * 12
        plaintext = AESGCM(_ENC_KEY).decrypt(b"N" * 12, wire[len(aad):], aad)
        signed = dump_signed_auth(self.log, _SEED)
        self.assertEqual(signed[len(MAGIC) + 8:-64], plaintext)

    def test_export_is_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.merkle_root(),
            self.log.find(b"a"),
        )
        dump_signed_auth(self.log, _SEED)
        dump_signed_auth(self.log, _SEED)
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
            dump_signed_auth("not a log", _SEED)
        for bad_seed in ("s" * 32, bytearray(32), memoryview(bytes(32)), 32):
            with self.assertRaises(TypeError):
                dump_signed_auth(self.log, bad_seed)

    def test_seed_length(self):
        with self.assertRaises(ValueError):
            dump_signed_auth(self.log, bytes(31))
        with self.assertRaises(ValueError):
            dump_signed_auth(self.log, bytes(33))

    def test_requires_keyed_log(self):
        plain = AuditLog()
        plain.append("a")
        with self.assertRaises(ValueError):
            dump_signed_auth(plain, _SEED)

    def test_rejects_encrypted_history(self):
        log = AuditLog(key=b"k")
        log.encrypt("secret", _ENC_KEY)
        with self.assertRaises(ValueError):
            dump_signed_auth(log, _SEED)

    def test_rejects_pruned_log(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_signed_auth(log, _SEED)

    def test_failure_is_atomic(self):
        with self.assertRaises(ValueError):
            dump_signed_auth(self.log, bytes(31))
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.stage, 1)
        load_signed_auth(dump_signed_auth(self.log, _SEED), _public(_SEED))


class LoadSignedAuthRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        self.verifier = self.log.export_verifier()
        for record in ("a", b"b", b"c" * 100, "d"):
            self.log.append(record)
        self.tag1 = self.log.auth(1)
        self.log.append("e")
        self.data = dump_signed_auth(self.log, _SEED)

    def _restore(self):
        return load_signed_auth(self.data, _public(_SEED))

    def test_length_head_root_match(self):
        restored = self._restore()
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertTrue(restored.verify())

    def test_absolute_indices_match(self):
        self.assertEqual(
            [entry.index for entry in self._restore()],
            [entry.index for entry in self.log],
        )

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
        restored = self._restore()
        self.assertTrue(restored._verifier_exported)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_verifier_flag_zero_allows_export(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        restored = load_signed_auth(dump_signed_auth(log, _SEED), _public(_SEED))
        self.assertIsInstance(restored.export_verifier(), Verifier)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_evolution_continuity(self):
        restored = self._restore()
        self.log.append("f")
        restored.append("f")
        tag_orig = self.log.auth(5)
        tag_rest = restored.auth(5)
        self.assertEqual(tag_orig, tag_rest)
        self.assertEqual(self.log.stage, restored.stage)
        # The original stage-0 verifier verifies tags from both processes.
        self.assertTrue(verify_auth(restored.entry(1), self.tag1, self.verifier))
        self.assertTrue(verify_auth(restored.entry(5), tag_orig, self.verifier))

    def test_independent_and_mutable(self):
        restored = self._restore()
        restored.append("separate")
        self.assertEqual(len(restored), len(self.log) + 1)
        restored.rotate_key()
        self.assertEqual(restored.stage, self.log.stage + 1)

    def test_restored_can_encrypt(self):
        restored = self._restore()
        restored.encrypt("secret", _ENC_KEY)
        self.assertEqual(len(self.log), 5)
        self.assertEqual(len(restored), 6)

    def test_empty_log_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        restored = load_signed_auth(dump_signed_auth(log, _SEED), _public(_SEED))
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())

    def test_non_default_hash(self):
        log = AuditLog(key=b"shared-secret", hash_name="sha512")
        log.append("a")
        log.auth(0)
        restored = load_signed_auth(dump_signed_auth(log, _SEED), _public(_SEED))
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        self.assertEqual(len(restored.head), 64)


class LoadSignedAuthErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        self.log.append("a")
        self.data = dump_signed_auth(self.log, _SEED)

    def test_data_type(self):
        for bad in (bytearray(self.data), memoryview(self.data), "x", 42, None):
            with self.assertRaises(TypeError):
                load_signed_auth(bad, _public(_SEED))

    def test_public_key_type(self):
        for bad in ("k" * 32, bytearray(32), memoryview(bytes(32)), None):
            with self.assertRaises(TypeError):
                load_signed_auth(self.data, bad)

    def test_public_key_length(self):
        with self.assertRaises(ValueError):
            load_signed_auth(self.data, bytes(31))
        with self.assertRaises(ValueError):
            load_signed_auth(self.data, bytes(33))

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_signed_auth(b"x" + self.data[1:], _public(_SEED))

    def test_bad_version(self):
        broken = bytearray(self.data)
        broken[len(MAGIC) + 7] = 2
        with self.assertRaises(ValueError):
            load_signed_auth(bytes(broken), _public(_SEED))

    def test_truncated(self):
        for cut in (
            0,
            10,
            len(MAGIC),
            len(MAGIC) + 8,
            63,
            len(self.data) - 1,
            len(self.data) - 63,
        ):
            with self.assertRaises(ValueError):
                load_signed_auth(self.data[:cut], _public(_SEED))

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            load_signed_auth(self.data + b"\x00", _public(_SEED))

    def test_wrong_public_key(self):
        with self.assertRaises(ValueError):
            load_signed_auth(self.data, _OTHER_PUB)

    def test_signature_tamper_fails(self):
        broken = bytearray(self.data)
        broken[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            load_signed_auth(bytes(broken), _public(_SEED))

    def test_frame_tamper_fails(self):
        broken = bytearray(self.data)
        broken[len(MAGIC) + 8] ^= 0x01
        with self.assertRaises(ValueError):
            load_signed_auth(bytes(broken), _public(_SEED))

    def test_magic_tamper_fails(self):
        broken = bytearray(self.data)
        broken[0] ^= 0x01
        with self.assertRaises(ValueError):
            load_signed_auth(bytes(broken), _public(_SEED))

    def test_load_is_read_only(self):
        view = bytes(self.data)
        load_signed_auth(view, _public(_SEED))
        self.assertEqual(view, self.data)


class LoadSignedAuthFrameValidationTest(unittest.TestCase):
    """Valid signatures over frames that violate the in-frame rules."""

    def setUp(self):
        self.log = AuditLog(key=b"shared-secret")
        self.log.export_verifier()
        self.log.append("a")
        self.log.append("b")
        self.log.auth(0)
        good = dump_signed_auth(self.log, _SEED)
        self.frame = good[len(MAGIC) + 8:-64]
        self.name, self.entries, self.tail = self._parse(self.frame)

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
            parts += [
                u64(index),
                blob(payload),
                blob(previous_hash),
                blob(entry_hash),
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

    def _forge(self, name=None, entries=None, tail=None, *, version=1):
        frame = self._build(
            self.name if name is None else name,
            self.entries if entries is None else entries,
            self.tail if tail is None else tail,
        )
        return load_signed_auth(_signed(_SEED, frame, version=version), _public(_SEED))

    def test_baseline_loads(self):
        self.assertEqual(self._forge().head, self.log.head)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            load_signed_auth(_signed(_SEED, self.frame + b"\x00"), _public(_SEED))

    def test_truncated_frame(self):
        with self.assertRaises(ValueError):
            load_signed_auth(_signed(_SEED, self.frame[:-1]), _public(_SEED))

    def test_bad_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            self._forge(name=b"\xff\xff")

    def test_unknown_hash(self):
        with self.assertRaises(ValueError):
            self._forge(name=b"nonesuch")

    def test_bad_entry_index(self):
        entries = [
            (1, payload, previous_hash, entry_hash)
            if i == 0
            else (index, payload, previous_hash, entry_hash)
            for i, (index, payload, previous_hash, entry_hash) in enumerate(
                self.entries
            )
        ]
        with self.assertRaises(ValueError):
            self._forge(entries=entries)

    def test_bad_entry_digest_widths(self):
        index, payload, previous_hash, entry_hash = self.entries[0]
        with self.assertRaises(ValueError):
            self._forge(entries=[(index, payload, previous_hash, entry_hash[:-1])])
        with self.assertRaises(ValueError):
            self._forge(entries=[(index, payload, previous_hash[:-1], entry_hash)])

    def test_bad_root_and_head_widths(self):
        root, head, stage, key_material, exported = self.tail
        with self.assertRaises(ValueError):
            self._forge(tail=(root[:-1], head, stage, key_material, exported))
        with self.assertRaises(ValueError):
            self._forge(tail=(root, head + b"\x00", stage, key_material, exported))

    def test_bad_flag(self):
        root, head, stage, key_material, _exported = self.tail
        with self.assertRaises(ValueError):
            self._forge(tail=(root, head, stage, key_material, 2))

    def test_empty_evolution_key(self):
        root, head, stage, _key_material, exported = self.tail
        with self.assertRaises(ValueError):
            self._forge(tail=(root, head, stage, b"", exported))

    def test_wrong_width_evolution_key_after_evolution(self):
        root, head, stage, _key_material, exported = self.tail
        self.assertEqual(stage, 1)
        with self.assertRaises(ValueError):
            self._forge(tail=(root, head, stage, b"too-short", exported))

    def test_stage_zero_allows_construction_key_width(self):
        root, head, _stage, _key_material, exported = self.tail
        restored = self._forge(tail=(root, head, 0, b"shared-secret", exported))
        self.assertEqual(restored.stage, 0)

    def test_wrong_root_rejected(self):
        root, head, stage, key_material, exported = self.tail
        wrong = bytes(d ^ 0x01 if (i + 1) % 7 == 0 else d for i, d in enumerate(root))
        with self.assertRaises(ValueError):
            self._forge(tail=(wrong, head, stage, key_material, exported))

    def test_wrong_head_rejected(self):
        root, head, stage, key_material, exported = self.tail
        wrong = bytes(d ^ 0x01 if (i + 1) % 7 == 0 else d for i, d in enumerate(head))
        with self.assertRaises(ValueError):
            self._forge(tail=(root, wrong, stage, key_material, exported))

    def test_payload_tamper_rejected(self):
        index, payload, previous_hash, entry_hash = self.entries[0]
        with self.assertRaises(ValueError):
            self._forge(
                entries=[(index, payload + b"x", previous_hash, entry_hash)]
                + self.entries[1:]
            )

    def test_unsupported_version(self):
        with self.assertRaises(ValueError):
            self._forge(version=2)


if __name__ == "__main__":
    unittest.main()
