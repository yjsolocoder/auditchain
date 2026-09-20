import os
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    Entry,
    decrypt_entry,
    encode_audit_receipt,
    decode_audit_receipt,
    entry_digest,
    verify_audit_receipt,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
NONCE = b"nonce-12byte"
MAGIC = b"auditchain/encrypted-entry/v1\0"
AAD_DOMAIN = b"auditchain/aead/v1\0"
ALG = b"\x01"


def aad(index, previous_hash):
    return AAD_DOMAIN + ALG + index.to_bytes(8, "big") + previous_hash


class EncryptFormatTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()

    def test_entry_is_chained_like_a_plain_append(self):
        plain = self.log.append("before")
        entry = self.log.encrypt("secret", KEY, nonce=NONCE)
        self.assertEqual(entry.index, 1)
        self.assertEqual(entry.previous_hash, plain.entry_hash)
        self.assertEqual(self.log.head, entry.entry_hash)
        self.assertEqual(len(self.log), 2)

    def test_envelope_layout(self):
        entry = self.log.encrypt(b"plaintext", KEY, nonce=NONCE)
        prefix = MAGIC + ALG + NONCE
        self.assertTrue(entry.payload.startswith(prefix))
        # magic + algorithm byte + 12-byte nonce + ciphertext + 16-byte tag.
        self.assertEqual(len(entry.payload), len(prefix) + len(b"plaintext") + 16)

    def test_ciphertext_matches_aesgcm_with_positional_aad(self):
        entry = self.log.encrypt(b"plaintext", KEY, nonce=NONCE)
        sealed = entry.payload[len(MAGIC) + 1 + 12:]
        expected = AESGCM(KEY).encrypt(NONCE, b"plaintext", aad(0, GENESIS_HASH))
        self.assertEqual(sealed, expected)
        self.assertEqual(
            AESGCM(KEY).decrypt(NONCE, sealed, aad(0, GENESIS_HASH)), b"plaintext"
        )

    def test_aad_binds_index_and_previous_hash(self):
        first = self.log.encrypt("a", KEY, nonce=b"0" * 12)
        second = self.log.encrypt("b", KEY, nonce=b"1" * 12)
        sealed = second.payload[len(MAGIC) + 1 + 12:]
        with self.assertRaises(InvalidTag):
            AESGCM(KEY).decrypt(b"1" * 12, sealed, aad(first.index, first.previous_hash))
        with self.assertRaises(InvalidTag):
            AESGCM(KEY).decrypt(b"1" * 12, sealed, aad(second.index + 1, second.previous_hash))
        with self.assertRaises(InvalidTag):
            AESGCM(KEY).decrypt(b"1" * 12, sealed, aad(second.index, b"\x01" * 32))

    def test_envelope_is_what_the_entry_digest_covers(self):
        entry = self.log.encrypt("secret", KEY, nonce=NONCE)
        self.assertEqual(
            entry.entry_hash,
            entry_digest(0, GENESIS_HASH, entry.payload),
        )

    def test_random_nonce_when_omitted(self):
        first = self.log.encrypt("a", KEY)
        second = self.log.encrypt("b", KEY)
        offset = len(MAGIC) + 1
        self.assertEqual(len(first.payload[offset:offset + 12]), 12)
        self.assertNotEqual(
            first.payload[offset:offset + 12], second.payload[offset:offset + 12]
        )

    def test_key_is_not_stored_on_the_log(self):
        self.log.encrypt("secret", KEY, nonce=NONCE)
        self.assertFalse(any(KEY == value for value in vars(self.log).values() if isinstance(value, bytes)))


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()

    def test_str_is_utf8_encoded_like_append(self):
        entry = self.log.encrypt("héllo", KEY, nonce=NONCE)
        self.assertEqual(decrypt_entry(entry, KEY), "héllo".encode("utf-8"))

    def test_bytes_and_empty_payload(self):
        entry = self.log.encrypt(b"\x00\x01\x02", KEY, nonce=b"a" * 12)
        self.assertEqual(decrypt_entry(entry, KEY), b"\x00\x01\x02")
        empty = self.log.encrypt(b"", KEY, nonce=b"b" * 12)
        self.assertEqual(decrypt_entry(empty, KEY), b"")
        self.assertEqual(len(empty.payload), len(MAGIC) + 1 + 12 + 16)

    def test_mixed_plain_and_encrypted_chain_verifies(self):
        entries = [
            self.log.append("plain-0"),
            self.log.encrypt("secret-1", KEY, nonce=b"c" * 12),
            self.log.append(b"plain-2"),
            self.log.encrypt(b"secret-3", KEY, nonce=b"d" * 12),
        ]
        self.assertTrue(self.log.verify())
        self.assertEqual([e.index for e in entries], [0, 1, 2, 3])
        self.assertEqual(entries[1].previous_hash, entries[0].entry_hash)
        self.assertEqual(entries[3].previous_hash, entries[2].entry_hash)
        self.assertEqual(decrypt_entry(self.log.entry(1), KEY), b"secret-1")
        self.assertEqual(decrypt_entry(self.log.entry(3), KEY), b"secret-3")

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha3-256")
        entry = log.encrypt("secret", KEY, nonce=NONCE)
        self.assertTrue(log.verify())
        self.assertEqual(decrypt_entry(entry, KEY, hash_name="sha3-256"), b"secret")
        with self.assertRaises(ValueError):
            decrypt_entry(entry, KEY)


class EncryptValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("before")

    def test_key_must_be_32_bytes(self):
        for bad_key in ("k" * 32, 123, bytearray(KEY), memoryview(KEY), None):
            with self.assertRaises(TypeError):
                self.log.encrypt("x", bad_key, nonce=NONCE)
        for bad_key in (b"", b"k" * 31, b"k" * 33):
            with self.assertRaises(ValueError):
                self.log.encrypt("x", bad_key, nonce=NONCE)

    def test_nonce_must_be_12_bytes(self):
        for bad_nonce in ("n" * 12, 12, bytearray(NONCE), memoryview(NONCE)):
            with self.assertRaises(TypeError):
                self.log.encrypt("x", KEY, nonce=bad_nonce)
        for bad_nonce in (b"", b"n" * 11, b"n" * 13):
            with self.assertRaises(ValueError):
                self.log.encrypt("x", KEY, nonce=bad_nonce)

    def test_payload_type_rules_match_append(self):
        with self.assertRaises(TypeError):
            self.log.encrypt(42, KEY, nonce=NONCE)
        entry = self.log.encrypt(bytearray(b"ba"), KEY, nonce=b"e" * 12)
        self.assertEqual(decrypt_entry(entry, KEY), b"ba")

    def test_nonce_must_not_repeat(self):
        self.log.encrypt("first", KEY, nonce=NONCE)
        with self.assertRaises(ValueError):
            self.log.encrypt("second", KEY, nonce=NONCE)

    def test_nonce_history_survives_prune(self):
        entry = self.log.encrypt("released", KEY, nonce=NONCE)
        size = len(self.log)
        self.log.prune(size, self.log.seal(size))
        self.assertNotIn(entry, self.log.entries())
        with self.assertRaises(ValueError):
            self.log.encrypt("again", KEY, nonce=NONCE)

    def test_failed_encrypt_changes_no_state(self):
        self.log.encrypt("used", KEY, nonce=NONCE)
        snapshot = (len(self.log), self.log.head, list(self.log.entries()))
        calls = (
            (42, KEY, b"g" * 12),
            ("x", "k" * 32, NONCE),
            ("x", b"short", NONCE),
            ("x", KEY, "n" * 12),
            ("x", KEY, b"short"),
            ("x", KEY, NONCE),  # already used in this log
        )
        for args in calls:
            with self.assertRaises((TypeError, ValueError)):
                self.log.encrypt(*args)
            self.assertEqual((len(self.log), self.log.head, list(self.log.entries())), snapshot)

    def test_rejected_nonce_is_not_consumed(self):
        fresh = b"f" * 12
        with self.assertRaises(TypeError):
            self.log.encrypt("x", "k" * 32, nonce=fresh)
        entry = self.log.encrypt("ok", KEY, nonce=fresh)
        self.assertEqual(decrypt_entry(entry, KEY), b"ok")


class DecryptValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.entry = self.log.encrypt("secret", KEY, nonce=NONCE)

    def test_entry_must_be_an_entry(self):
        with self.assertRaises(TypeError):
            decrypt_entry(self.entry.payload, KEY)

    def test_key_must_be_32_bytes(self):
        for bad_key in ("k" * 32, 123, bytearray(KEY), memoryview(KEY)):
            with self.assertRaises(TypeError):
                decrypt_entry(self.entry, bad_key)
        for bad_key in (b"", b"k" * 31, b"k" * 33):
            with self.assertRaises(ValueError):
                decrypt_entry(self.entry, bad_key)

    def test_hash_name_must_be_a_known_string(self):
        with self.assertRaises(TypeError):
            decrypt_entry(self.entry, KEY, hash_name=b"sha256")
        with self.assertRaises(ValueError):
            decrypt_entry(self.entry, KEY, hash_name="not-a-hash")

    def test_plain_payload_is_not_an_envelope(self):
        plain = self.log.append("plain")
        with self.assertRaises(ValueError):
            decrypt_entry(plain, KEY)

    def test_wrong_key_fails_authentication(self):
        with self.assertRaises(ValueError):
            decrypt_entry(self.entry, OTHER_KEY)

    def test_tampered_envelope_fails_authentication(self):
        raw = bytearray(self.entry.payload)
        raw[-1] ^= 0x01
        forged = Entry(self.entry.index, bytes(raw), self.entry.previous_hash, self.entry.entry_hash)
        with self.assertRaises(ValueError):
            decrypt_entry(forged, KEY)

    def test_entry_hash_mismatch_is_rejected(self):
        forged = Entry(self.entry.index, self.entry.payload, self.entry.previous_hash, b"\x01" * 32)
        with self.assertRaises(ValueError):
            decrypt_entry(forged, KEY)

    def test_previous_hash_binding_is_enforced_via_aad(self):
        # Keep the recorded digest consistent with the envelope so only the
        # AAD position binding can fail.
        moved = Entry(
            self.entry.index,
            self.entry.payload,
            b"\x09" * 32,
            entry_digest(self.entry.index, b"\x09" * 32, self.entry.payload),
        )
        with self.assertRaises(ValueError):
            decrypt_entry(moved, KEY)

    def test_index_binding_is_enforced_via_aad(self):
        moved = Entry(
            self.entry.index + 1,
            self.entry.payload,
            self.entry.previous_hash,
            entry_digest(self.entry.index + 1, self.entry.previous_hash, self.entry.payload),
        )
        with self.assertRaises(ValueError):
            decrypt_entry(moved, KEY)

    def test_malformed_envelopes_are_rejected(self):
        cases = {
            "missing algorithm byte": MAGIC,
            "unknown algorithm": MAGIC + b"\x02" + b"n" * 12 + b"c" * 20,
            "truncated nonce": MAGIC + ALG + b"n",
            "shorter than tag": MAGIC + ALG + b"n" * 12 + b"x" * 15,
        }
        for name, payload in cases.items():
            with self.subTest(name=name):
                bad = Entry(0, payload, GENESIS_HASH, entry_digest(0, GENESIS_HASH, payload))
                with self.assertRaises(ValueError):
                    decrypt_entry(bad, KEY)

    def test_decrypt_is_read_only(self):
        decrypt_entry(self.entry, KEY)
        self.assertIs(self.log.entry(0), self.entry)


class FindReceiptPruneTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.plain = self.log.append("plaintext")
        self.encrypted = self.log.encrypt(b"plaintext", KEY, nonce=NONCE)

    def test_find_matches_only_the_envelope(self):
        self.assertEqual(self.log.find(b"plaintext"), (0,))
        self.assertEqual(self.log.find(self.encrypted.payload), (1,))
        self.assertEqual(self.log.find("plaintext"), (0,))
        self.assertEqual(self.log.find(MAGIC), ())

    def test_audit_receipt_preserves_ciphertext_and_decrypts_offline(self):
        receipt = self.log.audit_receipt([1])
        self.assertTrue(verify_audit_receipt(receipt))
        (stored_entry, proof) = receipt.items[0]
        self.assertEqual(stored_entry.payload, self.encrypted.payload)
        self.assertEqual(decrypt_entry(stored_entry, KEY), b"plaintext")
        encoded = encode_audit_receipt(receipt)
        restored = decode_audit_receipt(encoded)
        self.assertEqual(encode_audit_receipt(restored), encoded)
        self.assertTrue(verify_audit_receipt(restored))
        restored_entry = restored.items[0][0]
        self.assertEqual(decrypt_entry(restored_entry, KEY), b"plaintext")

    def test_pruning_keeps_ciphertext_of_retained_entries(self):
        self.log.prune(1, self.log.seal(1))
        self.assertTrue(self.log.verify())
        retained = self.log.entry(1)
        self.assertEqual(retained.payload, self.encrypted.payload)
        self.assertEqual(decrypt_entry(retained, KEY), b"plaintext")
        receipt = self.log.audit_receipt([1])
        self.assertTrue(verify_audit_receipt(receipt))
        appended = self.log.encrypt("after prune", KEY, nonce=b"z" * 12)
        self.assertEqual(appended.index, 2)
        self.assertTrue(self.log.verify())
        self.assertEqual(decrypt_entry(appended, KEY), b"after prune")

    def test_random_nonce_path_round_trip(self):
        log = AuditLog()
        for i in range(5):
            entry = log.encrypt(f"record-{i}", KEY)
            self.assertEqual(decrypt_entry(entry, KEY), f"record-{i}".encode())
        self.assertTrue(log.verify())


if __name__ == "__main__":
    unittest.main()
