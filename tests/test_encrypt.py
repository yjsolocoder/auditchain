import unittest

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

MAGIC = b"auditchain/encrypted-entry/v1\0"
KEY = bytes(range(32))
OTHER_KEY = bytes(range(32, 64))
NONCE = b"\x01" * 12


def envelope_of(entry):
    return entry.payload


class EncryptTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()

    def test_roundtrip_bytes(self):
        entry = self.log.encrypt(b"secret", KEY)
        self.assertEqual(decrypt_entry(entry, KEY), b"secret")

    def test_roundtrip_str_and_bytearray(self):
        entry = self.log.encrypt("机密", KEY)
        self.assertEqual(decrypt_entry(entry, KEY), "机密".encode("utf-8"))
        entry = self.log.encrypt(bytearray(b"mutable"), KEY)
        self.assertEqual(decrypt_entry(entry, KEY), b"mutable")

    def test_payload_is_self_describing_envelope(self):
        entry = self.log.encrypt(b"secret", KEY, NONCE)
        envelope = envelope_of(entry)
        self.assertTrue(envelope.startswith(MAGIC))
        self.assertEqual(envelope[len(MAGIC)], 0x01)
        self.assertEqual(envelope[len(MAGIC) + 1 : len(MAGIC) + 13], NONCE)
        # ciphertext || 16-byte tag follows the 12-byte nonce.
        self.assertEqual(len(envelope), len(MAGIC) + 1 + 12 + len(b"secret") + 16)

    def test_explicit_nonce_is_used(self):
        entry = self.log.encrypt(b"x", KEY, NONCE)
        self.assertEqual(envelope_of(entry)[len(MAGIC) + 1 : len(MAGIC) + 13], NONCE)

    def test_default_nonce_is_random_and_distinct(self):
        first = self.log.encrypt(b"a", KEY)
        second = self.log.encrypt(b"b", KEY)
        nonce_a = envelope_of(first)[len(MAGIC) + 1 : len(MAGIC) + 13]
        nonce_b = envelope_of(second)[len(MAGIC) + 1 : len(MAGIC) + 13]
        self.assertEqual(len(nonce_a), 12)
        self.assertNotEqual(nonce_a, nonce_b)

    def test_envelope_matches_reference_aead(self):
        self.log.append(b"plain")
        head = self.log.head
        entry = self.log.encrypt(b"secret", KEY, NONCE)
        aad = b"auditchain/aead/v1\0" + b"\x01" + (1).to_bytes(8, "big") + head
        expected = AESGCM(KEY).encrypt(NONCE, b"secret", aad)
        self.assertEqual(envelope_of(entry), MAGIC + b"\x01" + NONCE + expected)

    def test_envelope_participates_in_entry_digest(self):
        entry = self.log.encrypt(b"secret", KEY)
        self.assertEqual(
            entry.entry_hash,
            entry_digest(entry.index, entry.previous_hash, entry.payload),
        )
        self.assertTrue(self.log.verify())
        self.assertTrue(self.log.verify_entry(entry.index))

    def test_key_not_stored_on_log(self):
        self.log.encrypt(b"secret", KEY)
        for value in vars(self.log).values():
            self.assertNotEqual(value, KEY)

    def test_mixed_with_plain_appends(self):
        self.log.append(b"plain-0")
        encrypted = self.log.encrypt(b"secret", KEY)
        self.log.append(b"plain-2")
        self.assertEqual(len(self.log), 3)
        self.assertEqual(self.log.entry(0).payload, b"plain-0")
        self.assertEqual(self.log.entry(2).payload, b"plain-2")
        self.assertEqual(decrypt_entry(encrypted, KEY), b"secret")
        self.assertTrue(self.log.verify())

    def test_key_type_and_length(self):
        with self.assertRaises(TypeError):
            self.log.encrypt(b"x", "not-bytes")
        with self.assertRaises(TypeError):
            self.log.encrypt(b"x", bytearray(KEY))
        with self.assertRaises(ValueError):
            self.log.encrypt(b"x", KEY[:31])
        with self.assertRaises(ValueError):
            self.log.encrypt(b"x", KEY + b"\x00")

    def test_nonce_type_and_length(self):
        with self.assertRaises(TypeError):
            self.log.encrypt(b"x", KEY, "not-bytes")
        with self.assertRaises(ValueError):
            self.log.encrypt(b"x", KEY, NONCE[:11])
        with self.assertRaises(ValueError):
            self.log.encrypt(b"x", KEY, NONCE + b"\x00")

    def test_payload_type_error(self):
        with self.assertRaises(TypeError):
            self.log.encrypt(123, KEY)

    def test_nonce_reuse_rejected(self):
        self.log.encrypt(b"a", KEY, NONCE)
        with self.assertRaises(ValueError):
            self.log.encrypt(b"b", KEY, NONCE)

    def test_nonce_reuse_rejected_after_prune(self):
        self.log.encrypt(b"a", KEY, NONCE)
        self.log.append(b"b")
        receipt = self.log.seal(1)
        self.log.prune(1, receipt)
        with self.assertRaises(ValueError):
            self.log.encrypt(b"c", KEY, NONCE)

    def test_nonce_history_is_per_log(self):
        self.log.encrypt(b"a", KEY, NONCE)
        other = AuditLog()
        other.encrypt(b"b", KEY, NONCE)  # same nonce, different log: fine

    def test_failure_leaves_state_unchanged(self):
        self.log.append(b"plain")
        head = self.log.head
        for bad_call in (
            lambda: self.log.encrypt(b"x", KEY[:16]),
            lambda: self.log.encrypt(b"x", KEY, NONCE[:8]),
            lambda: self.log.encrypt(123, KEY),
        ):
            with self.assertRaises((TypeError, ValueError)):
                bad_call()
        self.log.encrypt(b"a", KEY, NONCE)
        with self.assertRaises(ValueError):
            self.log.encrypt(b"b", KEY, NONCE)
        self.assertEqual(len(self.log), 2)
        self.assertEqual(self.log.head, self.log.entry(1).entry_hash)
        self.assertNotEqual(self.log.head, head)
        self.assertTrue(self.log.verify())

    def test_find_matches_envelope_not_plaintext(self):
        entry = self.log.encrypt(b"secret", KEY)
        self.assertEqual(self.log.find(b"secret"), ())
        self.assertEqual(self.log.find(entry.payload), (entry.index,))

    def test_prune_keeps_ciphertext(self):
        first = self.log.encrypt(b"a", KEY)
        self.log.encrypt(b"b", KEY)
        receipt = self.log.seal(1)
        self.log.prune(1, receipt)
        self.assertEqual(self.log.retain_from, 1)
        self.assertTrue(self.log.entry(1).payload.startswith(MAGIC))
        self.assertTrue(self.log.verify())
        self.assertTrue(receipt.matches(self.log.entry(1)))
        self.assertEqual(decrypt_entry(self.log.entry(1), KEY), b"b")
        self.assertEqual(first.index, 0)

    def test_audit_receipt_keeps_ciphertext(self):
        self.log.append(b"plain")
        self.log.encrypt(b"secret", KEY)
        receipt = self.log.audit_receipt([1])
        self.assertTrue(verify_audit_receipt(receipt))
        entry, _proof = receipt.items[0]
        self.assertTrue(entry.payload.startswith(MAGIC))
        self.assertEqual(decrypt_entry(entry, KEY), b"secret")
        restored = decode_audit_receipt(encode_audit_receipt(receipt))
        self.assertTrue(verify_audit_receipt(restored))
        self.assertEqual(decrypt_entry(restored.items[0][0], KEY), b"secret")


class DecryptEntryTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append(b"plain")
        self.entry = self.log.encrypt(b"secret", KEY, NONCE)

    def test_entry_must_be_entry(self):
        with self.assertRaises(TypeError):
            decrypt_entry("not-an-entry", KEY)

    def test_key_type_and_length(self):
        with self.assertRaises(TypeError):
            decrypt_entry(self.entry, "not-bytes")
        with self.assertRaises(ValueError):
            decrypt_entry(self.entry, KEY[:31])

    def test_unknown_hash_algorithm(self):
        with self.assertRaises(ValueError):
            decrypt_entry(self.entry, KEY, hash_name="not-a-hash")
        with self.assertRaises(TypeError):
            decrypt_entry(self.entry, KEY, hash_name=123)

    def test_wrong_key_fails_authentication(self):
        with self.assertRaises(ValueError):
            decrypt_entry(self.entry, OTHER_KEY)

    def test_wrong_hash_name_fails_digest_check(self):
        with self.assertRaises(ValueError):
            decrypt_entry(self.entry, KEY, hash_name="sha512")

    def test_tampered_ciphertext_rejected(self):
        envelope = bytearray(self.entry.payload)
        envelope[-1] ^= 1
        forged = Entry(self.entry.index, bytes(envelope), self.entry.previous_hash,
                       entry_digest(self.entry.index, self.entry.previous_hash, bytes(envelope)))
        with self.assertRaises(ValueError):
            decrypt_entry(forged, KEY)

    def test_tampered_index_rejected(self):
        forged = Entry(self.entry.index + 1, self.entry.payload,
                       self.entry.previous_hash, self.entry.entry_hash)
        with self.assertRaises(ValueError):
            decrypt_entry(forged, KEY)

    def test_tampered_previous_hash_rejected(self):
        forged = Entry(self.entry.index, self.entry.payload,
                       GENESIS_HASH, self.entry.entry_hash)
        with self.assertRaises(ValueError):
            decrypt_entry(forged, KEY)

    def test_digest_mismatch_rejected(self):
        forged = Entry(self.entry.index, self.entry.payload,
                       self.entry.previous_hash, bytes(32))
        with self.assertRaises(ValueError):
            decrypt_entry(forged, KEY)

    def test_plain_payload_is_not_an_envelope(self):
        plain = self.log.entry(0)
        with self.assertRaises(ValueError):
            decrypt_entry(plain, KEY)

    def test_bad_algorithm_byte_rejected(self):
        envelope = bytearray(self.entry.payload)
        envelope[len(MAGIC)] = 0x02
        forged = Entry(self.entry.index, bytes(envelope), self.entry.previous_hash,
                       entry_digest(self.entry.index, self.entry.previous_hash, bytes(envelope)))
        with self.assertRaises(ValueError):
            decrypt_entry(forged, KEY)

    def test_truncated_envelope_rejected(self):
        envelope = self.entry.payload[: len(MAGIC) + 1 + 12 + 8]
        forged = Entry(self.entry.index, envelope, self.entry.previous_hash,
                       entry_digest(self.entry.index, self.entry.previous_hash, envelope))
        with self.assertRaises(ValueError):
            decrypt_entry(forged, KEY)

    def test_field_type_errors(self):
        with self.assertRaises(TypeError):
            decrypt_entry(
                Entry("0", self.entry.payload, self.entry.previous_hash, self.entry.entry_hash),
                KEY,
            )
        with self.assertRaises(TypeError):
            decrypt_entry(
                Entry(self.entry.index, "payload", self.entry.previous_hash, self.entry.entry_hash),
                KEY,
            )

    def test_hash_length_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            decrypt_entry(
                Entry(self.entry.index, self.entry.payload, b"\x00" * 16, self.entry.entry_hash),
                KEY,
            )

    def test_genesis_entry_decrypts(self):
        log = AuditLog()
        entry = log.encrypt(b"first", KEY, NONCE)
        self.assertEqual(entry.previous_hash, GENESIS_HASH)
        self.assertEqual(decrypt_entry(entry, KEY), b"first")

    def test_other_hash_algorithm_roundtrip(self):
        log = AuditLog(hash_name="sha3_256")
        log.append(b"plain")
        entry = log.encrypt(b"secret", KEY)
        self.assertEqual(
            decrypt_entry(entry, KEY, hash_name="sha3_256"), b"secret"
        )


if __name__ == "__main__":
    unittest.main()
