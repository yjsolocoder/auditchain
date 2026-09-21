import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from auditchain import (
    AuditLog,
    dump_auth,
    load_auth,
    verify_auth,
)

D = b"auditchain/auth-log/v1\0"
VERSION = b"\x01"
KEY = b"k" * 32
OTHER_KEY = b"x" * 32
NONCE = b"n" * 12


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def entry_bytes(entry):
    return b"".join((
        u64(entry.index),
        blob(entry.payload),
        blob(entry.previous_hash),
        blob(entry.entry_hash),
    ))


def seal(key, nonce, plaintext, *, version=VERSION):
    aad = D + version + nonce
    return aad + AESGCM(key).encrypt(nonce, plaintext, aad)


def plaintext_for(log, *, key_state=None, stage=None, flag=None):
    """Build the dump_auth plaintext for ``log`` with optional state tweaks."""
    parts = [
        blob(log.hash_name.encode("utf-8")),
        u64(len(log)),
    ]
    for entry in log.entries():
        parts.append(entry_bytes(entry))
    parts.append(blob(log.merkle_root()))
    parts.append(blob(log.head))
    parts.append(u64(log.stage if stage is None else stage))
    evolving = log._key if key_state is None else key_state
    parts.append(blob(evolving))
    exported = log._verifier_exported if flag is None else flag
    parts.append(u64(1 if exported else 0))
    return b"".join(parts)


def reseal(log, key, nonce, *, mutate=None, **kwargs):
    plaintext = plaintext_for(log, **kwargs)
    if mutate is not None:
        plaintext = mutate(plaintext)
    return seal(key, nonce, plaintext)


class DumpAuthRoundTripTests(unittest.TestCase):
    def test_empty_keyed_log(self):
        log = AuditLog(key=KEY)
        restored = load_auth(dump_auth(log, KEY, NONCE), KEY)
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.retain_from, 0)
        self.assertEqual(restored.stage, 0)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        entry = restored.append("after restart")
        self.assertEqual(entry.index, 0)
        self.assertEqual(restored.entry(0).payload, b"after restart")

    def test_length_head_root_find_stage_match(self):
        log = AuditLog(key=KEY)
        log.append("agent started")
        log.append("position claim: -73.9857,40.7484")
        log.append("agent started")
        log.export_verifier()
        log.auth(0)
        log.rotate_key()
        data = dump_auth(log, KEY, NONCE)
        restored = load_auth(data, KEY)
        self.assertEqual(len(restored), len(log))
        self.assertEqual(restored.retain_from, 0)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, log.stage)
        self.assertEqual(restored.find(b"agent started"), (0, 2))
        self.assertEqual(restored.find(b"position claim: -73.9857,40.7484"), (1,))
        self.assertEqual(restored.find(b"missing"), ())
        self.assertEqual(
            [e.payload for e in restored],
            [e.payload for e in log],
        )
        self.assertTrue(restored.verify())

    def test_wire_layout(self):
        log = AuditLog(key=KEY)
        log.append("hello")
        data = dump_auth(log, KEY, NONCE)
        self.assertTrue(data.startswith(D + VERSION))
        self.assertEqual(data[len(D) + 1:len(D) + 13], NONCE)
        # C decrypts under AES-256-GCM with AAD D||0x01||N.
        aad = D + VERSION + NONCE
        plaintext = AESGCM(KEY).decrypt(NONCE, data[len(D) + 13:], aad)
        expected = plaintext_for(log)
        self.assertEqual(plaintext, expected)

    def test_explicit_nonce_and_random_default(self):
        log = AuditLog(key=KEY)
        log.append("hello")
        first = dump_auth(log, KEY, NONCE)
        second = dump_auth(log, KEY, NONCE)
        # Deterministic with a fixed nonce; no log state changes between calls.
        self.assertEqual(first, second)
        self.assertEqual(log.stage, 0)
        random_one = dump_auth(log, KEY)
        random_two = dump_auth(log, KEY)
        self.assertNotEqual(random_one, random_two)
        # Both random exports carry a usable 12-byte nonce.
        for data in (random_one, random_two):
            restored = load_auth(data, KEY)
            self.assertEqual(restored.head, log.head)

    def test_non_default_hash_algorithm(self):
        for hash_name in ("sha512", "sha3_256"):
            with self.subTest(hash_name=hash_name):
                log = AuditLog(key=KEY, hash_name=hash_name)
                log.append("a")
                log.append("b")
                verifier = log.export_verifier()
                tag = log.auth(0)
                restored = load_auth(dump_auth(log, KEY, NONCE), KEY)
                self.assertEqual(restored.hash_name, hash_name)
                self.assertEqual(restored.stage, 1)
                self.assertEqual(restored.head, log.head)
                self.assertEqual(restored.merkle_root(), log.merkle_root())
                self.assertTrue(verify_auth(restored.entry(0), tag, verifier))

    def test_sealing_key_is_independent_of_construction_key(self):
        # The dump sealing key only protects the export; the carried evolving
        # key K (derived from the construction key) is what resumes forward
        # security, so a different sealing key still restores the same lineage.
        construction_key = b"a" * 32
        sealing_key = b"b" * 32
        log = AuditLog(key=construction_key)
        log.append("e0")
        verifier = log.export_verifier()
        log.auth(0)
        data = dump_auth(log, sealing_key, NONCE)
        restored = load_auth(data, sealing_key)
        self.assertEqual(restored.stage, 1)
        log.append("e1")
        restored.append("e1")
        tag1 = log.auth(1)
        restored_tag1 = restored.auth(1)
        self.assertEqual(tag1, restored_tag1)
        # The pre-evolution verifier (from the construction key) still verifies
        # tags minted after the independently-sealed restore.
        self.assertTrue(verify_auth(restored.entry(1), restored_tag1, verifier))

    def test_empty_log_with_rotation_only(self):
        log = AuditLog(key=KEY)
        log.rotate_key()
        log.rotate_key()
        restored = load_auth(dump_auth(log, KEY, NONCE), KEY)
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.stage, 2)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        restored.append("first")
        self.assertEqual(restored.auth(0).stage, 2)

    def test_short_construction_key_round_trip_at_stage_zero(self):
        # The construction key need not be 32 or digest-width bytes; at stage 0
        # the carried K is exactly that key, and evolution still resumes.
        construction_key = b"shared-secret"
        sealing_key = KEY
        log = AuditLog(key=construction_key)
        log.append("e0")
        verifier = log.export_verifier()
        restored = load_auth(
            dump_auth(log, sealing_key, NONCE), sealing_key
        )
        self.assertEqual(restored.stage, 0)
        tag = restored.auth(0)
        self.assertEqual(tag, log.auth(0))
        self.assertTrue(verify_auth(restored.entry(0), tag, verifier))
        self.assertEqual(restored.stage, 1)

class ForwardSecurityContinuationTests(unittest.TestCase):
    def test_evolution_continues_after_restart(self):
        log = AuditLog(key=KEY)
        log.append("e0")
        log.append("e1")
        verifier = log.export_verifier()
        tag0 = log.auth(0)
        log.rotate_key()
        tag1 = log.auth(1)
        self.assertEqual(log.stage, 3)

        restored = load_auth(dump_auth(log, KEY, NONCE), KEY)
        self.assertEqual(restored.stage, 3)
        # Old tags verify offline against the pre-evolution verifier.
        self.assertTrue(verify_auth(restored.entry(0), tag0, verifier))
        self.assertTrue(verify_auth(restored.entry(1), tag1, verifier))
        # The next tag minted in the restored log equals one minted in the
        # original: the evolving key and stage resumed identically.
        log.append("e2")
        restored.append("e2")
        self.assertEqual(log.auth(2), restored.auth(2))
        log.append("e3")
        restored.append("e3")
        self.assertEqual(log.auth_batch([3]), restored.auth_batch([3]))
        # Mint one more tag in each log and verify the restored one offline
        # against the verifier exported before any evolution.
        log.append("e4")
        restored.append("e4")
        log_items = log.auth_batch([4])
        restored_items = restored.auth_batch([4])
        self.assertEqual(log_items, restored_items)
        self.assertTrue(
            verify_auth(restored.entry(4), restored_items[0][1], verifier)
        )

    def test_exported_verifier_flag_is_restored(self):
        log = AuditLog(key=KEY)
        log.append("e0")
        log.export_verifier()
        log.auth(0)
        restored = load_auth(dump_auth(log, KEY, NONCE), KEY)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_evolution_without_export_keeps_verifier_forbidden(self):
        # Evolution happened without an export; restoring the stage verbatim
        # must not re-open the one-shot export window.
        log = AuditLog(key=KEY)
        log.append("e0")
        log.rotate_key()
        restored = load_auth(dump_auth(log, KEY, NONCE), KEY)
        self.assertEqual(restored.stage, log.stage)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_unevolved_log_allows_verifier_export_after_restore(self):
        log = AuditLog(key=KEY)
        log.append("e0")
        restored = load_auth(dump_auth(log, KEY, NONCE), KEY)
        verifier = restored.export_verifier()
        tag = restored.auth(0)
        self.assertTrue(verify_auth(restored.entry(0), tag, verifier))

    def test_dump_is_read_only(self):
        log = AuditLog(key=KEY)
        log.append("e0")
        log.export_verifier()
        log.auth(0)
        snapshot = (log.head, log.stage, log.merkle_root(), len(log), log._key)
        dump_auth(log, KEY, NONCE)
        dump_auth(log, KEY)
        self.assertEqual(
            (log.head, log.stage, log.merkle_root(), len(log), log._key),
            snapshot,
        )


class IndependenceTests(unittest.TestCase):
    def test_restored_log_is_independent_and_mutable(self):
        log = AuditLog(key=KEY)
        log.append("e0")
        restored = load_auth(dump_auth(log, KEY, NONCE), KEY)
        restored.append("e1")
        restored.rotate_key()
        self.assertEqual(len(log), 1)
        self.assertEqual(len(restored), 2)
        self.assertEqual(log.stage, 0)
        self.assertEqual(restored.stage, 1)
        # Mutating a caller buffer that fed the dump cannot affect the restore.
        payload = bytearray(b"e0")
        other = AuditLog(key=KEY)
        other.append(bytes(payload))
        data = dump_auth(other, KEY, NONCE)
        restored_other = load_auth(data, KEY)
        payload[0] = ord("X")
        other.append(b"more")
        self.assertEqual(restored_other.entry(0).payload, b"e0")


class EligibilityTests(unittest.TestCase):
    def test_keyless_log_rejected(self):
        log = AuditLog()
        log.append("plain")
        with self.assertRaises(ValueError):
            dump_auth(log, KEY, NONCE)

    def test_pruned_log_rejected(self):
        log = AuditLog(key=KEY)
        log.append("e0")
        log.append("e1")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_auth(log, KEY, NONCE)

    def test_encrypted_history_rejected(self):
        log = AuditLog(key=KEY)
        log.encrypt("secret", b"a" * 32, nonce=b"0" * 12)
        with self.assertRaises(ValueError):
            dump_auth(log, KEY, NONCE)
        # Even a plain entry after the encrypted one cannot rescue the log.
        log.append("plain")
        with self.assertRaises(ValueError):
            dump_auth(log, KEY, NONCE)

    def test_keyless_log_is_not_treated_as_auth_log(self):
        # A keyless dump must never be loadable through the auth framing by
        # accident; its magic differs.
        from auditchain import dump_log
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        log = AuditLog()
        log.append("plain")
        seed = bytes(range(1, 33))
        data = dump_log(log, seed)
        with self.assertRaises(ValueError):
            load_auth(data, KEY)


class TypeAndValueTests(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=KEY)
        self.log.append("e0")

    def test_dump_log_type(self):
        for bad in (None, object(), b"not a log", 42):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    dump_auth(bad, KEY, NONCE)

    def test_key_types_and_length(self):
        with self.assertRaises(TypeError):
            dump_auth(self.log, "k" * 32, NONCE)
        with self.assertRaises(TypeError):
            dump_auth(self.log, bytearray(KEY), NONCE)
        with self.assertRaises(TypeError):
            dump_auth(self.log, memoryview(KEY), NONCE)
        with self.assertRaises(ValueError):
            dump_auth(self.log, b"short", NONCE)
        with self.assertRaises(TypeError):
            load_auth(dump_auth(self.log, KEY, NONCE), "k" * 32)
        with self.assertRaises(TypeError):
            load_auth(dump_auth(self.log, KEY, NONCE), bytearray(KEY))
        with self.assertRaises(ValueError):
            load_auth(dump_auth(self.log, KEY, NONCE), b"short")

    def test_nonce_types_and_length(self):
        with self.assertRaises(TypeError):
            dump_auth(self.log, KEY, "n" * 12)
        with self.assertRaises(TypeError):
            dump_auth(self.log, KEY, bytearray(12))
        with self.assertRaises(ValueError):
            dump_auth(self.log, KEY, b"short")
        with self.assertRaises(ValueError):
            dump_auth(self.log, KEY, b"x" * 13)

    def test_data_must_be_bytes(self):
        data = dump_auth(self.log, KEY, NONCE)
        with self.assertRaises(TypeError):
            load_auth(bytearray(data), KEY)
        with self.assertRaises(TypeError):
            load_auth(memoryview(data), KEY)
        with self.assertRaises(TypeError):
            load_auth(None, KEY)

    def test_wrong_key_fails_to_decrypt(self):
        data = dump_auth(self.log, KEY, NONCE)
        with self.assertRaises(ValueError):
            load_auth(data, OTHER_KEY)

    def test_bad_magic_and_version(self):
        data = dump_auth(self.log, KEY, NONCE)
        with self.assertRaises(ValueError):
            load_auth(b"auditchain/other/v1\0" + data[len(D):], KEY)
        with self.assertRaises(ValueError):
            load_auth(data[:len(D)] + b"\x02" + data[len(D) + 1:], KEY)

    def test_truncation(self):
        data = dump_auth(self.log, KEY, NONCE)
        for length in range(0, len(data)):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    load_auth(data[:length], KEY)

    def test_ciphertext_tampering(self):
        data = bytearray(dump_auth(self.log, KEY, NONCE))
        data[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            load_auth(bytes(data), KEY)
        # Tampering with the nonce changes both the AAD and the GCM nonce.
        data = bytearray(dump_auth(self.log, KEY, NONCE))
        data[len(D) + 1] ^= 0x01
        with self.assertRaises(ValueError):
            load_auth(bytes(data), KEY)
        # Tampering with the AAD-side magic/version header fails auth.
        data = bytearray(dump_auth(self.log, KEY, NONCE))
        data[0] = ord("b") if data[0] != ord("b") else ord("c")
        with self.assertRaises(ValueError):
            load_auth(bytes(data), KEY)


class PlaintextValidationTests(unittest.TestCase):
    """Re-seal mutated plaintexts under the real key to exercise the
    post-AEAD structural validation (the GCM layer itself is valid)."""

    def setUp(self):
        self.log = AuditLog(key=KEY)
        self.log.append("e0")
        self.log.append("e1")
        self.log.auth(0)

    def _load(self, **kwargs):
        return load_auth(reseal(self.log, KEY, NONCE, **kwargs), KEY)

    def test_trailing_plaintext_bytes(self):
        with self.assertRaises(ValueError):
            self._load(mutate=lambda p: p + b"\x00")

    def test_truncated_plaintext(self):
        with self.assertRaises(ValueError):
            self._load(mutate=lambda p: p[:-1])

    def test_bad_utf8_hash_name(self):
        def mutate(plaintext):
            # Replace the first blob's content with invalid UTF-8 while
            # preserving its u64 length prefix.
            bad_name = b"\xff\xfe"
            return u64(len(bad_name)) + bad_name + plaintext[len(blob(b"sha256")):]
        with self.assertRaises(ValueError):
            self._load(mutate=mutate)

    def test_unknown_hash_algorithm(self):
        def mutate(plaintext):
            bad_name = b"not-a-real-algorithm"
            return u64(len(bad_name)) + bad_name + plaintext[len(blob(b"sha256")):]
        with self.assertRaises(ValueError):
            self._load(mutate=mutate)

    def test_entry_indices_must_be_zero_based(self):
        # Declare the first entry's index as 1; it must equal position 0.
        # Layout: B("sha256")=14, U(n)=8, then U(index) at offset 22.
        def mutate(plaintext):
            return plaintext[:22] + u64(1) + plaintext[30:]
        with self.assertRaises(ValueError):
            self._load(mutate=mutate)

    def test_stage_must_fit_u64_semantics(self):
        # stage = 2**64 - 1 is structurally valid but evolution must be
        # exhausted afterwards.
        restored = self._load(stage=(1 << 64) - 1)
        self.assertEqual(restored.stage, (1 << 64) - 1)
        with self.assertRaises(ValueError):
            restored.rotate_key()

    def test_bad_exported_flag(self):
        def mutate(plaintext):
            return plaintext[:-8] + u64(2)
        with self.assertRaises(ValueError):
            self._load(mutate=mutate)

    def test_evolving_key_width_mismatch(self):
        # Rebuild the plaintext manually with a wrong-width key blob.
        parts = [
            blob(b"sha256"),
            u64(2),
        ]
        for entry in self.log.entries():
            parts.append(entry_bytes(entry))
        parts.append(blob(self.log.merkle_root()))
        parts.append(blob(self.log.head))
        parts.append(u64(self.log.stage))
        parts.append(blob(b"too-short"))
        parts.append(u64(0))
        data = seal(KEY, NONCE, b"".join(parts))
        with self.assertRaises(ValueError):
            load_auth(data, KEY)

    def test_empty_evolving_key_rejected_even_at_stage_zero(self):
        # An empty B(K) is never valid even at stage 0, since the constructor
        # itself rejects an empty key.
        parts = [
            blob(b"sha256"),
            u64(0),
            blob(self.log.merkle_root()),
            blob(self.log.head),
            u64(0),
            blob(b""),
            u64(0),
        ]
        with self.assertRaises(ValueError):
            load_auth(seal(KEY, NONCE, b"".join(parts)), KEY)

    def test_wrong_root_rejected(self):
        parts = [
            blob(b"sha256"),
            u64(2),
        ]
        for entry in self.log.entries():
            parts.append(entry_bytes(entry))
        parts.append(blob(b"\x00" * 32))
        parts.append(blob(self.log.head))
        parts.append(u64(self.log.stage))
        parts.append(blob(self.log._key))
        parts.append(u64(0))
        with self.assertRaises(ValueError):
            load_auth(seal(KEY, NONCE, b"".join(parts)), KEY)

    def test_wrong_head_rejected(self):
        parts = [
            blob(b"sha256"),
            u64(2),
        ]
        for entry in self.log.entries():
            parts.append(entry_bytes(entry))
        parts.append(blob(self.log.merkle_root()))
        parts.append(blob(b"\x00" * 32))
        parts.append(u64(self.log.stage))
        parts.append(blob(self.log._key))
        parts.append(u64(0))
        with self.assertRaises(ValueError):
            load_auth(seal(KEY, NONCE, b"".join(parts)), KEY)

    def test_tampered_entry_rejected(self):
        # Flip a payload byte inside an entry blob; the recomputed digest
        # diverges from the recorded entry_hash. Layout: B("sha256")=14,
        # U(n)=8, U(index)=8, then the first B(payload) length prefix; the
        # payload content starts at offset 38.
        payload = bytearray(plaintext_for(self.log))
        payload[38] ^= 0x01
        with self.assertRaises(ValueError):
            load_auth(seal(KEY, NONCE, bytes(payload)), KEY)

    def test_wrong_aad_rejected(self):
        # A valid ciphertext sealed under a different header (different AAD)
        # must not authenticate under the required AAD.
        plaintext = plaintext_for(self.log)
        rogue = seal(KEY, NONCE, plaintext, version=b"\x02")
        with self.assertRaises(ValueError):
            load_auth(rogue, KEY)


if __name__ == "__main__":
    unittest.main()
