import unittest

from auditchain import (
    AuditLog,
    decrypt_entry,
    dump_secure_pruned,
    load_secure_pruned,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAGIC = b"auditchain/pruned-secure/v1\0"
NONCE_BYTES = 12

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


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


def _mixed_log(retain_from=4):
    """Pruned log whose released prefix and retained tail mix plain/ciphertext."""
    log = AuditLog()
    key = b"k" * 32
    log.append(b"plain-0")
    log.encrypt(b"secret-1", key, b"\x01" + b"\x00" * 11)
    log.append(b"plain-2")
    log.encrypt(b"secret-3", key, b"\x02" + b"\x00" * 11)
    log.append(b"plain-4")
    log.encrypt(b"secret-5", key, b"\x03" + b"\x00" * 11)
    log.prune(retain_from, log.seal(retain_from))
    log.append(b"plain-6")
    log.encrypt(b"secret-7", key, b"\x04" + b"\x00" * 11)
    return log, key


class DumpSecurePrunedLayoutTest(unittest.TestCase):
    def setUp(self):
        self.log, self.key = _mixed_log()
        self.data = dump_secure_pruned(self.log, _SEED_A)

    def test_magic_and_field_layout(self):
        data = self.data
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        # B(hash_name)
        width = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(data[offset:offset + width], b"sha256")
        offset += width
        # U(n), U(r)
        self.assertEqual(data[offset:offset + 8], u64(len(self.log)))
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(self.log.retain_from))
        offset += 8
        # B(checkpoint)
        width = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(width, 32)
        self.assertEqual(data[offset:offset + width], self.log._checkpoint_head)
        offset += width
        # Frontier: count, then U(height) || B(digest) ascending (set bits of r).
        count = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        heights = sorted(self.log._frontier)
        self.assertEqual(count, len(heights))
        previous = -1
        for height in heights:
            self.assertGreater(height, previous)
            previous = height
            self.assertEqual(data[offset:offset + 8], u64(height))
            offset += 8
            width = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            self.assertEqual(data[offset:offset + width],
                             self.log._frontier[height])
            offset += width
        # Nonce history: U(count), then raw 12-byte nonces in ascending order.
        count = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        expected_nonces = sorted(self.log._used_nonces)
        self.assertEqual(count, len(expected_nonces))
        for nonce in expected_nonces:
            self.assertEqual(data[offset:offset + NONCE_BYTES], nonce)
            offset += NONCE_BYTES
        # Retained entries r..n-1 in dump_secure_log E framing, with B(locator).
        count = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(count, len(self.log) - self.log.retain_from)
        for entry in self.log.entries():
            self.assertEqual(data[offset:offset + 8], u64(entry.index))
            offset += 8
            locator = self.log._encrypted_locators.get(entry.index, b"")
            for value in (entry.payload, entry.previous_hash,
                          entry.entry_hash, locator):
                width = int.from_bytes(data[offset:offset + 8], "big")
                offset += 8
                self.assertEqual(data[offset:offset + width], value)
                offset += width
        # B(root), B(head), then the 64-byte trailing signature.
        for expected in (self.log.merkle_root(), self.log.head):
            width = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            self.assertEqual(data[offset:offset + width], expected)
            offset += width
        self.assertEqual(offset + 64, len(data))

    def test_nonce_history_includes_released_and_retained(self):
        # Nonces of ciphertext pruned away (indices 1, 3) and kept (5, 7).
        self.assertEqual(
            self.log._used_nonces,
            {b"\x01" + b"\x00" * 11, b"\x02" + b"\x00" * 11,
             b"\x03" + b"\x00" * 11, b"\x04" + b"\x00" * 11},
        )

    def test_deterministic_same_state_same_seed(self):
        self.assertEqual(
            dump_secure_pruned(self.log, _SEED_A),
            dump_secure_pruned(self.log, _SEED_A),
        )

    def test_read_only(self):
        before = (self.log.retain_from, len(self.log), self.log.head,
                  self.log.merkle_root(),
                  tuple(e.index for e in self.log.entries()),
                  frozenset(self.log._used_nonces))
        dump_secure_pruned(self.log, _SEED_A)
        after = (self.log.retain_from, len(self.log), self.log.head,
                 self.log.merkle_root(),
                 tuple(e.index for e in self.log.entries()),
                 frozenset(self.log._used_nonces))
        self.assertEqual(before, after)

    def test_distinct_magic_from_pruned_log(self):
        from auditchain import dump_pruned_log

        plain = AuditLog()
        for record in (b"a", b"b", b"c", b"d"):
            plain.append(record)
        plain.prune(2, plain.seal(2))
        self.assertTrue(
            dump_secure_pruned(plain, _SEED_A).startswith(MAGIC)
        )
        self.assertFalse(
            dump_pruned_log(plain, _SEED_A).startswith(MAGIC)
        )


class LoadSecurePrunedRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_restores_mixed_pruned_log(self):
        log, key = _mixed_log()
        restored = load_secure_pruned(
            dump_secure_pruned(log, _SEED_A), self.public_key
        )
        self.assertIsNot(restored, log)
        self.assertEqual(restored.retain_from, log.retain_from)
        self.assertEqual(len(restored), len(log))
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.hash_name, log.hash_name)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(
            [e.index for e in restored],
            [e.index for e in log],
        )
        for original in log.entries():
            got = restored.entry(original.index)
            self.assertEqual(got.payload, original.payload)
            self.assertEqual(got.previous_hash, original.previous_hash)
            self.assertEqual(got.entry_hash, original.entry_hash)

    def test_retention_proofs_and_search_indexes_match(self):
        log, key = _mixed_log()
        restored = load_secure_pruned(
            dump_secure_pruned(log, _SEED_A), self.public_key
        )
        for index in range(log.retain_from, len(log)):
            self.assertEqual(
                restored.inclusion_proof(index),
                log.inclusion_proof(index),
            )
        self.assertEqual(restored.find(b"plain-4"), log.find(b"plain-4"))
        self.assertEqual(restored.find(b"plain-6"), (6,))
        self.assertEqual(
            restored.find_encrypted(b"secret-5", key),
            log.find_encrypted(b"secret-5", key),
        )
        self.assertEqual(restored.find_encrypted(b"secret-7", key), (7,))
        # A plaintext whose ciphertext was pruned is no longer locatable.
        self.assertEqual(restored.find_encrypted(b"secret-1", key), ())
        self.assertEqual(restored.find_encrypted(b"secret-3", key), ())
        # The retained ciphertext decrypts offline with the original key.
        self.assertEqual(
            decrypt_entry(restored.entry(7), key), b"secret-7"
        )

    def test_nonce_history_fully_restored(self):
        log, key = _mixed_log()
        restored = load_secure_pruned(
            dump_secure_pruned(log, _SEED_A), self.public_key
        )
        self.assertEqual(restored._used_nonces, log._used_nonces)
        # A released nonce can never be reused after restore.
        with self.assertRaises(ValueError):
            restored.encrypt(b"x", key, b"\x01" + b"\x00" * 11)
        with self.assertRaises(ValueError):
            restored.encrypt(b"x", key, b"\x02" + b"\x00" * 11)
        # A fresh nonce still works and participates in the restored log.
        entry = restored.encrypt(b"secret-8", key)
        self.assertEqual(entry.index, len(log))
        self.assertEqual(decrypt_entry(entry, key), b"secret-8")

    def test_restored_log_is_fully_mutable(self):
        log, _ = _mixed_log()
        restored = load_secure_pruned(
            dump_secure_pruned(log, _SEED_A), self.public_key
        )
        restored.append(b"plain-after")
        receipt = restored.seal(restored.retain_from + 1)
        restored.prune(restored.retain_from + 1, receipt)
        restored.append(b"plain-after-2")
        self.assertTrue(restored.verify())

    def test_plain_only_pruned_log_roundtrips(self):
        log = AuditLog()
        for record in (b"a", b"b", b"c", b"d", b"e"):
            log.append(record)
        log.prune(2, log.seal(2))
        data = dump_secure_pruned(log, _SEED_A)
        restored = load_secure_pruned(data, self.public_key)
        self.assertEqual(restored.retain_from, 2)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored._used_nonces, set())
        self.assertEqual(restored.find(b"c"), (2,))

    def test_fully_pruned_log_keeps_nonce_history(self):
        log = AuditLog()
        key = b"k" * 32
        released_nonce = b"\xaa" + b"\x00" * 11
        log.encrypt(b"secret-only", key, released_nonce)
        log.prune(1, log.seal(1))
        self.assertEqual(list(log), [])
        restored = load_secure_pruned(
            dump_secure_pruned(log, _SEED_A), self.public_key
        )
        self.assertEqual(restored.retain_from, 1)
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored._used_nonces, {released_nonce})
        with self.assertRaises(ValueError):
            restored.encrypt(b"x", key, released_nonce)

    def test_alternate_hash_name(self):
        log = AuditLog(hash_name="sha512")
        key = b"k" * 32
        log.encrypt(b"secret-0", key, b"\x00" * 12)
        log.append(b"plain-1")
        log.prune(1, log.seal(1))
        restored = load_secure_pruned(
            dump_secure_pruned(log, _SEED_A), self.public_key
        )
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.head, log.head)


class EligibilityTest(unittest.TestCase):
    def test_unpruned_log_rejected(self):
        log = AuditLog()
        log.append(b"a")
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, _SEED_A)

    def test_keyed_log_rejected(self):
        log = AuditLog(key=b"auth" * 8)
        log.append(b"a")
        log.append(b"b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, _SEED_A)

    def test_authenticated_history_rejected(self):
        log = AuditLog(key=b"auth" * 8)
        log.append(b"a")
        log.auth(0)
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, _SEED_A)

    def test_verifier_exported_rejected(self):
        log = AuditLog(key=b"auth" * 8)
        log.append(b"a")
        log.export_verifier()
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, _SEED_A)


class TypeAndValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.log, _ = _mixed_log()
        self.data = dump_secure_pruned(self.log, _SEED_A)
        self.public_key = _public_key(_SEED_A)

    def test_dump_type_errors(self):
        with self.assertRaises(TypeError):
            dump_secure_pruned("not a log", _SEED_A)
        with self.assertRaises(TypeError):
            dump_secure_pruned(self.log, "not bytes")
        with self.assertRaises(TypeError):
            dump_secure_pruned(self.log, bytearray(_SEED_A))

    def test_load_type_errors(self):
        with self.assertRaises(TypeError):
            load_secure_pruned(bytearray(self.data), self.public_key)
        with self.assertRaises(TypeError):
            load_secure_pruned(memoryview(self.data), self.public_key)
        with self.assertRaises(TypeError):
            load_secure_pruned("not bytes", self.public_key)
        with self.assertRaises(TypeError):
            load_secure_pruned(self.data, "not bytes")
        with self.assertRaises(TypeError):
            load_secure_pruned(self.data, bytearray(self.public_key))

    def test_key_length_errors(self):
        with self.assertRaises(ValueError):
            dump_secure_pruned(self.log, _SEED_A[:-1])
        with self.assertRaises(ValueError):
            load_secure_pruned(self.data, self.public_key[:-1])

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(b"x" * 100, self.public_key)

    def test_wrong_verification_key(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(self.data, _public_key(_SEED_B))

    def test_tampered_body_fails_signature(self):
        tampered = bytearray(self.data)
        tampered[len(MAGIC)] ^= 0x01
        with self.assertRaises(ValueError):
            load_secure_pruned(bytes(tampered), self.public_key)

    def test_truncated_signature(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(self.data[:-1], self.public_key)


class SignedMalformedBodyTest(unittest.TestCase):
    """Parse-time failures need a valid signature, so each body is re-signed."""

    def setUp(self):
        self.signing_key = Ed25519PrivateKey.from_private_bytes(_SEED_A)
        self.public_key = _public_key(_SEED_A)
        log, _ = _mixed_log()
        self.data = dump_secure_pruned(log, _SEED_A)
        self.body = self.data[:-64]

    def _resign(self, body):
        return body + self.signing_key.sign(body)

    def _section_offsets(self):
        offset = len(MAGIC) + 8  # version
        offset += 8 + len(b"sha256")  # B(hash_name)
        offset += 8  # n
        offset += 8  # r
        checkpoint_width = int.from_bytes(
            self.body[offset:offset + 8], "big"
        )
        offset += 8 + checkpoint_width
        frontier_count = int.from_bytes(
            self.body[offset:offset + 8], "big"
        )
        offset += 8
        for _ in range(frontier_count):
            offset += 8
            width = int.from_bytes(self.body[offset:offset + 8], "big")
            offset += 8 + width
        nonce_count_pos = offset
        nonce_count = int.from_bytes(self.body[offset:offset + 8], "big")
        offset += 8
        nonce_start = offset
        offset += nonce_count * NONCE_BYTES
        retained_count_pos = offset
        return nonce_count_pos, nonce_start, retained_count_pos

    def test_unsupported_version(self):
        body = (
            self.body[:len(MAGIC)] + u64(2) + self.body[len(MAGIC) + 8:]
        )
        with self.assertRaises(ValueError):
            load_secure_pruned(self._resign(body), self.public_key)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._resign(self.body + b"\x00"), self.public_key
            )

    def test_duplicate_nonce(self):
        ncp, nonce_start, _ = self._section_offsets()
        nonce = self.body[nonce_start:nonce_start + NONCE_BYTES]
        body = (
            self.body[:ncp] + u64(2) + nonce + nonce
            + self.body[nonce_start + NONCE_BYTES:]
        )
        with self.assertRaises(ValueError):
            load_secure_pruned(self._resign(body), self.public_key)

    def test_non_ascending_nonces(self):
        ncp, nonce_start, _ = self._section_offsets()
        low = b"\x11" + b"\x00" * 11
        high = b"\xee" + b"\x00" * 11
        body = (
            self.body[:ncp] + u64(2) + high + low
            + self.body[nonce_start + NONCE_BYTES:]
        )
        with self.assertRaises(ValueError):
            load_secure_pruned(self._resign(body), self.public_key)

    def test_truncated_nonce_section(self):
        ncp, nonce_start, _ = self._section_offsets()
        body = self.body[:ncp] + u64(1) + b"\x00" * 5
        with self.assertRaises(ValueError):
            load_secure_pruned(self._resign(body), self.public_key)

    def test_retained_ciphertext_nonce_missing_from_history(self):
        # Build a log whose only nonce belongs to a retained ciphertext, then
        # re-sign the same body with an empty nonce history.
        log = AuditLog()
        key = b"k" * 32
        log.append(b"plain-0")
        log.prune(1, log.seal(1))
        nonce = b"\x07" + b"\x00" * 11
        log.encrypt(b"retained-secret", key, nonce)
        data = dump_secure_pruned(log, _SEED_A)
        body = data[:-64]
        # The nonce section is u64(1) + the one 12-byte nonce; locate it and
        # replace it with an empty history (the retained ciphertext's nonce
        # then goes unacknowledged).
        needle = u64(1) + nonce
        position = body.find(needle)
        self.assertGreater(position, 0)
        self.assertEqual(body.rfind(needle), position)
        rebuilt = body[:position] + u64(0) + body[position + len(needle):]
        with self.assertRaises(ValueError):
            load_secure_pruned(self._resign(rebuilt), self.public_key)


if __name__ == "__main__":
    unittest.main()
