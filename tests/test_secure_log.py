import unittest

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    Entry,
    decrypt_entry,
    dump_secure_log,
    entry_digest,
    load_secure_log,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAGIC = b"auditchain/secure-log/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"k" * 32
_KEY2 = b"K" * 32


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


def _signing_key(seed):
    return Ed25519PrivateKey.from_private_bytes(seed)


def _entry_bytes(entry, locator=b""):
    return b"".join((
        u64(entry.index),
        blob(entry.payload),
        blob(entry.previous_hash),
        blob(entry.entry_hash),
        blob(locator),
    ))


def _body(log, entries_locators, *, magic=MAGIC, version=1):
    return b"".join((
        magic,
        u64(version),
        blob(log.hash_name.encode("utf-8")),
        u64(len(entries_locators)),
        blob(log.merkle_root()),
        blob(log.head),
        *(_entry_bytes(entry, locator) for entry, locator in entries_locators),
    ))


def _signed(body, seed=_SEED_A):
    return body + _signing_key(seed).sign(body)


class DumpSecureLogTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("a")
        self.log.encrypt("secret one", _KEY, nonce=b"\x01" * 12)
        self.log.append(b"b" * 40)
        self.log.encrypt("secret two", _KEY2, nonce=b"\x02" * 12)
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        data = dump_secure_log(self.log, _SEED_A)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        width = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(data[offset:offset + width], b"sha256")
        offset += width
        self.assertEqual(data[offset:offset + 8], u64(4))  # entry count
        offset += 8
        for value in (self.log.merkle_root(), self.log.head):
            width = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            self.assertEqual(data[offset:offset + width], value)
            offset += width
        for position, entry in enumerate(self.log.entries()):
            self.assertEqual(data[offset:offset + 8], u64(position))
            offset += 8
            for value in (entry.payload, entry.previous_hash, entry.entry_hash):
                width = int.from_bytes(data[offset:offset + 8], "big")
                offset += 8
                self.assertEqual(data[offset:offset + width], value)
                offset += width
            width = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            locator = data[offset:offset + width]
            offset += width
            if position in (1, 3):
                self.assertEqual(len(locator), 32)
            else:
                self.assertEqual(locator, b"")
        # Exactly the 64-byte Ed25519 signature over every preceding byte.
        self.assertEqual(len(data) - offset, 64)
        _public = _signing_key(_SEED_A).public_key()
        _public.verify(data[-64:], data[:-64])  # raises if invalid

    def test_deterministic_same_state_same_seed(self):
        self.assertEqual(
            dump_secure_log(self.log, _SEED_A), dump_secure_log(self.log, _SEED_A)
        )
        twin = AuditLog()
        twin.append("a")
        twin.encrypt("secret one", _KEY, nonce=b"\x01" * 12)
        twin.append(b"b" * 40)
        twin.encrypt("secret two", _KEY2, nonce=b"\x02" * 12)
        self.assertEqual(dump_secure_log(twin, _SEED_A), dump_secure_log(self.log, _SEED_A))

    def test_seed_changes_only_signature(self):
        data_a = dump_secure_log(self.log, _SEED_A)
        data_b = dump_secure_log(self.log, _SEED_B)
        self.assertNotEqual(data_a, data_b)
        self.assertEqual(data_a[:-64], data_b[:-64])
        self.assertEqual(load_secure_log(data_b, _public_key(_SEED_B)).head, self.log.head)

    def test_empty_log(self):
        data = dump_secure_log(AuditLog(), _SEED_A)
        restored = load_secure_log(data, self.public_key)
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.head, GENESIS_HASH)
        self.assertEqual(restored.retain_from, 0)
        self.assertTrue(restored.verify())
        self.assertEqual(restored.merkle_root(), AuditLog().merkle_root())

    def test_alternate_hash_algorithms(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            log.append("a")
            log.encrypt("secret", _KEY, nonce=b"\x03" * 12)
            restored = load_secure_log(dump_secure_log(log, _SEED_A), self.public_key)
            self.assertEqual(restored.hash_name, hash_name)
            self.assertEqual(len(restored), 2)
            self.assertEqual(restored.head, log.head)
            self.assertEqual(restored.merkle_root(), log.merkle_root())
            self.assertTrue(restored.verify())
            self.assertEqual(restored.find_encrypted("secret", _KEY), (1,))

    def test_dump_is_read_only(self):
        before = dump_secure_log(self.log, _SEED_A)
        dump_secure_log(self.log, _SEED_A)
        self.assertEqual(len(self.log), 4)
        self.assertTrue(self.log.verify())
        self.assertEqual(self.log.find_encrypted("secret one", _KEY), (1,))
        self.assertEqual(dump_secure_log(self.log, _SEED_A), before)

    def test_seed_is_not_stored(self):
        dump_secure_log(self.log, _SEED_A)
        self.assertEqual(self.log.stage, 0)
        with self.assertRaises(ValueError):
            self.log.export_verifier()


class LoadSecureLogRoundtripTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("a")
        self.log.encrypt("secret one", _KEY, nonce=b"\x01" * 12)
        self.log.append("b")
        self.log.encrypt("secret two", _KEY, nonce=b"\x02" * 12)
        self.log.encrypt("other key", _KEY2, nonce=b"\x03" * 12)
        self.public_key = _public_key(_SEED_A)
        self.data = dump_secure_log(self.log, _SEED_A)

    def test_restored_fields_match(self):
        restored = load_secure_log(self.data, self.public_key)
        self.assertIsInstance(restored, AuditLog)
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, 0)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.hash_name, self.log.hash_name)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertTrue(restored.verify())

    def test_find_and_find_encrypted_rebuilt(self):
        restored = load_secure_log(self.data, self.public_key)
        self.assertEqual(restored.find(b"a"), (0,))
        self.assertEqual(restored.find_encrypted("secret one", _KEY), (1,))
        self.assertEqual(restored.find_encrypted("secret two", _KEY), (3,))
        self.assertEqual(restored.find_encrypted("other key", _KEY2), (4,))
        self.assertEqual(restored.find_encrypted("secret one", _KEY2), ())
        # The ciphertext itself decrypts with the original key.
        self.assertEqual(
            decrypt_entry(restored.entry(1), _KEY), b"secret one"
        )

    def test_restored_log_is_independent_and_mutable(self):
        restored = load_secure_log(self.data, self.public_key)
        restored.append("new event")
        restored.encrypt("fresh secret", _KEY)
        self.assertEqual(len(restored), 7)
        self.assertEqual(restored.find(b"new event"), (5,))
        self.assertEqual(restored.find_encrypted("fresh secret", _KEY), (6,))
        self.assertTrue(restored.verify())
        # The source log is untouched and shares no state.
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.head, restored.entry(4).entry_hash)

    def test_restored_log_rejects_reused_nonce(self):
        restored = load_secure_log(self.data, self.public_key)
        with self.assertRaises(ValueError):
            restored.encrypt("again", _KEY, nonce=b"\x01" * 12)
        restored.encrypt("again", _KEY, nonce=b"\x09" * 12)
        self.assertEqual(restored.find_encrypted("again", _KEY), (5,))

    def test_restored_log_supports_prune(self):
        restored = load_secure_log(self.data, self.public_key)
        receipt = restored.seal(2)
        restored.prune(2, receipt)
        self.assertEqual(restored.retain_from, 2)
        self.assertEqual(restored.find_encrypted("secret two", _KEY), (3,))
        self.assertEqual(restored.find_encrypted("secret one", _KEY), ())
        restored.append("after prune")
        self.assertTrue(restored.verify())

    def test_restored_log_is_keyless(self):
        restored = load_secure_log(self.data, self.public_key)
        self.assertEqual(restored.stage, 0)
        with self.assertRaises(ValueError):
            restored.auth(0)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_old_interfaces_still_work(self):
        from auditchain import verify_audit_receipt, verify_signed_root

        restored = load_secure_log(self.data, self.public_key)
        self.assertTrue(verify_audit_receipt(restored.audit_receipt([0, 2])))
        self.assertTrue(
            verify_signed_root(restored.sign_root(_SEED_A, 3), self.public_key)
        )
        self.assertEqual(
            restored.consistency_proof(2), self.log.consistency_proof(2)
        )


class DumpSecureLogQualificationTest(unittest.TestCase):
    def test_pruned_log_rejected(self):
        log = AuditLog()
        log.append("a")
        log.encrypt("secret", _KEY)
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A)

    def test_keyed_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A)

    def test_authenticated_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.auth(0)
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A)

    def test_rotated_key_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.rotate_key()
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A)

    def test_verifier_exported_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.export_verifier()
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A)

    def test_plain_log_after_rejected_dump_is_unharmed(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            dump_secure_log(log, b"short")
        self.assertEqual(len(log), 1)
        self.assertTrue(log.verify())


class DumpSecureLogTypeErrorTest(unittest.TestCase):
    def test_log_must_be_audit_log(self):
        for bad in (None, "log", b"bytes", 1, (), object(), Entry(0, b"", b"", b"")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dump_secure_log(bad, _SEED_A)

    def test_private_key_must_be_bytes(self):
        log = AuditLog()
        for bad in (None, "seed", bytearray(_SEED_A), memoryview(_SEED_A), 1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dump_secure_log(log, bad)

    def test_private_key_length(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            dump_secure_log(log, b"short")
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A + b"\x00")


class LoadSecureLogFramingTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("a")
        self.log.encrypt("secret", _KEY, nonce=b"\x01" * 12)
        self.log.append("c")
        self.public_key = _public_key(_SEED_A)
        self.data = dump_secure_log(self.log, _SEED_A)
        self.entries = tuple(self.log.entries())
        self.locators = (b"", self.log._encrypted_locators[1], b"")

    def test_only_bytes_accepted(self):
        for bad in (
            bytearray(self.data),
            memoryview(self.data),
            "text",
            None,
            1,
            (),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                load_secure_log(bad, self.public_key)

    def test_public_key_must_be_bytes(self):
        for bad in (None, "key", bytearray(self.public_key), memoryview(self.public_key), 1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                load_secure_log(self.data, bad)

    def test_public_key_length(self):
        with self.assertRaises(ValueError):
            load_secure_log(self.data, b"short")
        with self.assertRaises(ValueError):
            load_secure_log(self.data, self.public_key + b"\x00")

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_secure_log(b"x" + self.data[1:], self.public_key)
        with self.assertRaises(ValueError):
            load_secure_log(b"", self.public_key)
        with self.assertRaises(ValueError):
            load_secure_log(MAGIC[:-1], self.public_key)
        with self.assertRaises(ValueError):
            load_secure_log(
                b"auditchain/log-state/v1\0" + self.data[len(MAGIC):],
                self.public_key,
            )

    def test_bad_version(self):
        bad = _signed(MAGIC + u64(2) + self.data[len(MAGIC) + 8:-64])
        with self.assertRaises(ValueError):
            load_secure_log(bad, self.public_key)

    def test_truncation(self):
        for cut in range(len(MAGIC), len(self.data)):
            with self.assertRaises(ValueError, msg=cut):
                load_secure_log(self.data[:cut], self.public_key)

    def test_trailing_bytes(self):
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                load_secure_log(self.data + extra, self.public_key)

    def test_oversized_blob_length(self):
        bad = _signed(MAGIC + u64(1) + u64(1 << 63) + b"rest")
        with self.assertRaises(ValueError):
            load_secure_log(bad, self.public_key)

    def test_bad_utf8_hash_name(self):
        body = b"".join((
            MAGIC,
            u64(1),
            blob(b"\xff\xfe"),
            u64(0),
            blob(self.log.merkle_root(0)),
            blob(GENESIS_HASH),
        ))
        with self.assertRaises(ValueError):
            load_secure_log(_signed(body), self.public_key)

    def test_unknown_hash_algorithm(self):
        body = b"".join((
            MAGIC,
            u64(1),
            blob(b"not-a-hash"),
            u64(0),
            blob(b"\x00" * 32),
            blob(b"\x00" * 32),
        ))
        with self.assertRaises(ValueError):
            load_secure_log(_signed(body), self.public_key)

    def test_root_and_head_width(self):
        for field in ("root", "head"):
            good = self.log.merkle_root() if field == "root" else self.log.head
            bad_value = good[:-1]
            parts = [MAGIC, u64(1), blob(b"sha256"), u64(0)]
            parts.append(blob(bad_value) if field == "root" else blob(self.log.merkle_root()))
            parts.append(blob(bad_value) if field == "head" else blob(self.log.head))
            with self.assertRaises(ValueError, msg=field):
                load_secure_log(_signed(b"".join(parts)), self.public_key)


class LoadSecureLogVerificationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("a")
        self.log.encrypt("secret", _KEY, nonce=b"\x01" * 12)
        self.log.append("c")
        self.public_key = _public_key(_SEED_A)
        self.data = dump_secure_log(self.log, _SEED_A)
        self.entries = tuple(self.log.entries())
        self.locators = (b"", self.log._encrypted_locators[1], b"")

    def _stream(self, entries_locators, log=None):
        return _signed(_body(log or self.log, entries_locators))

    def test_wrong_public_key(self):
        with self.assertRaises(ValueError):
            load_secure_log(self.data, _public_key(_SEED_B))

    def test_forged_signature(self):
        forged = self.data[:-64] + b"\x00" * 64
        with self.assertRaises(ValueError):
            load_secure_log(forged, self.public_key)

    def test_tampered_body_breaks_signature(self):
        tampered = bytearray(self.data)
        tampered[len(MAGIC) + 8] ^= 0xFF
        with self.assertRaises(ValueError):
            load_secure_log(bytes(tampered), self.public_key)

    def test_indices_must_be_zero_based_in_order(self):
        reordered = [
            (Entry(1, e.payload, e.previous_hash, e.entry_hash) if i == 0 else e, loc)
            for i, (e, loc) in enumerate(zip(self.entries, self.locators))
        ]
        with self.assertRaises(ValueError):
            load_secure_log(self._stream(reordered), self.public_key)

    def test_digest_width_must_match_algorithm(self):
        bad_entry = Entry(
            0,
            self.entries[0].payload,
            self.entries[0].previous_hash,
            b"\x00" * 31,
        )
        items = [(bad_entry, b"")] + list(zip(self.entries[1:], self.locators[1:]))
        with self.assertRaises(ValueError):
            load_secure_log(self._stream(items), self.public_key)

    def test_locator_width_must_match_algorithm(self):
        items = list(zip(self.entries, self.locators))
        items[1] = (self.entries[1], b"\x00" * 31)
        with self.assertRaises(ValueError):
            load_secure_log(self._stream(items), self.public_key)

    def test_broken_chain_rejected(self):
        bad_entry = Entry(
            1,
            self.entries[1].payload,
            b"\x00" * 32,
            self.entries[1].entry_hash,
        )
        items = list(zip(self.entries, self.locators))
        items[1] = (bad_entry, self.locators[1])
        with self.assertRaises(ValueError):
            load_secure_log(self._stream(items), self.public_key)

    def test_entry_digest_mismatch_rejected(self):
        bad_entry = Entry(
            0,
            self.entries[0].payload,
            self.entries[0].previous_hash,
            entry_digest(0, self.entries[0].previous_hash, b"different"),
        )
        items = [(bad_entry, b"")] + list(zip(self.entries[1:], self.locators[1:]))
        with self.assertRaises(ValueError):
            load_secure_log(self._stream(items), self.public_key)

    def test_head_mismatch_rejected(self):
        # Sign a body whose head field belongs to a different log.
        other = AuditLog()
        other.append("a")
        other.encrypt("secret", _KEY, nonce=b"\x01" * 12)
        other.append("different")
        items = list(zip(self.entries, self.locators))
        body = b"".join((
            MAGIC,
            u64(1),
            blob(b"sha256"),
            u64(3),
            blob(self.log.merkle_root()),
            blob(other.head),
            *(_entry_bytes(entry, locator) for entry, locator in items),
        ))
        with self.assertRaises(ValueError):
            load_secure_log(_signed(body), self.public_key)

    def test_root_mismatch_rejected(self):
        other = AuditLog()
        other.append("a")
        other.encrypt("secret", _KEY, nonce=b"\x01" * 12)
        other.append("different")
        items = list(zip(self.entries, self.locators))
        body = b"".join((
            MAGIC,
            u64(1),
            blob(b"sha256"),
            u64(3),
            blob(other.merkle_root()),
            blob(self.log.head),
            *(_entry_bytes(entry, locator) for entry, locator in items),
        ))
        with self.assertRaises(ValueError):
            load_secure_log(_signed(body), self.public_key)

    def test_malformed_envelope_rejected(self):
        # A non-empty locator on an entry whose payload is not a well-formed
        # encrypted-entry envelope. The envelope check fires while the chain
        # is recomputed, before the head/root comparison.
        forged = Entry(0, b"plain", bytes(32), entry_digest(0, bytes(32), b"plain"))
        single = [(forged, b"\x00" * 32)]
        with self.assertRaises(ValueError):
            load_secure_log(self._stream(single), self.public_key)

    def test_duplicate_nonce_rejected(self):
        # Two encrypted entries sealed under the same nonce: encrypt() refuses
        # this in-process, so hand-build a stream whose second encrypted entry
        # reuses the first entry's envelope (and therefore its nonce), with
        # the chain, head and root repaired so only the nonce check can fire.
        log = AuditLog()
        log.append("a")
        first = log.encrypt("secret", _KEY, nonce=b"\x01" * 12)
        forged = Entry(
            2,
            first.payload,
            first.entry_hash,
            entry_digest(2, first.entry_hash, first.payload),
        )
        locator = log._encrypted_locators[1]
        items = [(log.entry(0), b""), (first, locator), (forged, locator)]
        probe = AuditLog()
        for entry, _ in items:
            probe.append(entry.payload)
        body = b"".join((
            MAGIC,
            u64(1),
            blob(b"sha256"),
            u64(3),
            blob(probe.merkle_root()),
            blob(forged.entry_hash),
            *(_entry_bytes(entry, loc) for entry, loc in items),
        ))
        with self.assertRaises(ValueError):
            load_secure_log(_signed(body), self.public_key)


if __name__ == "__main__":
    unittest.main()
