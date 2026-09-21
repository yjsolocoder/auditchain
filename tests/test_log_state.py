import os
import unittest

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    Entry,
    SignedRoot,
    decode_signed_root,
    dump_log,
    encode_signed_root,
    entry_digest,
    load_log,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAGIC = b"auditchain/log-state/v1\0"

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


def _signing_key(seed):
    return Ed25519PrivateKey.from_private_bytes(seed)


def _entry_bytes(entry):
    return b"".join((
        u64(entry.index),
        blob(entry.payload),
        blob(entry.previous_hash),
        blob(entry.entry_hash),
    ))


def _state_bytes(checkpoint, entries, *, magic=MAGIC, version=1):
    return b"".join((
        magic,
        u64(version),
        blob(encode_signed_root(checkpoint)),
        u64(len(entries)),
        *(_entry_bytes(entry) for entry in entries),
    ))


class DumpLogTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", b"b", b"c" * 100, "d"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        data = dump_log(self.log, _SEED_A)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        # One length-prefixed blob holding the complete signed-root encoding.
        length = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        checkpoint_bytes = data[offset:offset + length]
        offset += length
        self.assertEqual(
            decode_signed_root(checkpoint_bytes), self.log.sign_root(_SEED_A)
        )
        # Then the entry count and the entries in index order.
        count = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(count, len(self.log))
        for position, entry in enumerate(self.log.entries()):
            self.assertEqual(data[offset:offset + 8], u64(position))
            offset += 8
            for value in (entry.payload, entry.previous_hash, entry.entry_hash):
                width = int.from_bytes(data[offset:offset + 8], "big")
                offset += 8
                self.assertEqual(data[offset:offset + width], value)
                offset += width
        self.assertEqual(offset, len(data))

    def test_blob_is_complete_signed_root_encoding(self):
        data = dump_log(self.log, _SEED_A)
        offset = len(MAGIC) + 8
        length = int.from_bytes(data[offset:offset + 8], "big")
        checkpoint_bytes = data[offset + 8:offset + 8 + length]
        self.assertTrue(
            checkpoint_bytes.startswith(b"auditchain/signed-root/v1\0")
        )

    def test_deterministic_same_state_same_seed(self):
        # Same state, same seed: byte-for-byte identical, repeated calls and
        # across independently built logs.
        self.assertEqual(
            dump_log(self.log, _SEED_A), dump_log(self.log, _SEED_A)
        )
        twin = AuditLog()
        for record in ("a", b"b", b"c" * 100, "d"):
            twin.append(record)
        self.assertEqual(dump_log(twin, _SEED_A), dump_log(self.log, _SEED_A))

    def test_seed_changes_only_checkpoint_signature(self):
        # A different seed changes bytes but the state still loads under its
        # own public key.
        data_a = dump_log(self.log, _SEED_A)
        data_b = dump_log(self.log, _SEED_B)
        self.assertNotEqual(data_a, data_b)
        self.assertEqual(load_log(data_b, _public_key(_SEED_B)).head, self.log.head)

    def test_empty_log(self):
        data = dump_log(AuditLog(), _SEED_A)
        restored = load_log(data, self.public_key)
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.head, GENESIS_HASH)
        self.assertEqual(restored.retain_from, 0)
        self.assertTrue(restored.verify())
        self.assertEqual(restored.merkle_root(), AuditLog().merkle_root())

    def test_alternate_hash_algorithms(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            for record in ("a", "b", "c"):
                log.append(record)
            restored = load_log(dump_log(log, _SEED_A), self.public_key)
            self.assertEqual(restored.hash_name, hash_name)
            self.assertEqual(len(restored), 3)
            self.assertEqual(restored.head, log.head)
            self.assertEqual(restored.merkle_root(), log.merkle_root())
            self.assertTrue(restored.verify())

    def test_dump_is_read_only(self):
        before = dump_log(self.log, _SEED_A)
        dump_log(self.log, _SEED_A)
        self.assertEqual(len(self.log), 4)
        self.assertEqual(self.log.retain_from, 0)
        self.assertTrue(self.log.verify())
        self.assertEqual(dump_log(self.log, _SEED_A), before)

    def test_seed_is_not_stored(self):
        dump_log(self.log, _SEED_A)
        self.assertEqual(self.log.stage, 0)
        with self.assertRaises(ValueError):
            self.log.export_verifier()


class LoadLogRoundtripTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", b"b", b"c" * 50, "d", "e"):
            self.log.append(record)
        self.seed = _SEED_A
        self.public_key = _public_key(_SEED_A)
        self.data = dump_log(self.log, self.seed)

    def test_restored_fields_match(self):
        restored = load_log(bytes(self.data), self.public_key)
        self.assertIsInstance(restored, AuditLog)
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, 0)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.hash_name, self.log.hash_name)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertTrue(restored.verify())

    def test_find_index_is_rebuilt(self):
        restored = load_log(self.data, self.public_key)
        self.assertEqual(restored.find(b"b"), (1,))
        self.assertEqual(restored.find(b"c" * 50), (2,))
        self.assertEqual(restored.find("missing"), ())

    def test_restored_log_is_independent_and_mutable(self):
        restored = load_log(self.data, self.public_key)
        restored.append("new event")
        restored.encrypt("secret", b"k" * 32)
        self.assertEqual(len(restored), 7)
        self.assertEqual(restored.find(b"new event"), (5,))
        self.assertEqual(restored.find_encrypted("secret", b"k" * 32), (6,))
        self.assertTrue(restored.verify())
        # The source log is untouched and shares no state.
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.head, restored.entry(4).entry_hash)

    def test_restored_log_supports_prune(self):
        restored = load_log(self.data, self.public_key)
        receipt = restored.seal(2)
        restored.prune(2, receipt)
        self.assertEqual(restored.retain_from, 2)
        restored.append("after prune")
        self.assertTrue(restored.verify())
        self.assertEqual(len(restored), 6)
        self.assertEqual(restored.head[:0], b"")

    def test_restored_log_is_keyless(self):
        restored = load_log(self.data, self.public_key)
        self.assertEqual(restored.stage, 0)
        with self.assertRaises(ValueError):
            restored.auth(0)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_old_interfaces_still_work(self):
        restored = load_log(self.data, self.public_key)
        receipt = restored.audit_receipt([0, 2])
        from auditchain import verify_audit_receipt

        self.assertTrue(verify_audit_receipt(receipt))
        signed = restored.sign_root(self.seed, 3)
        from auditchain import verify_signed_root

        self.assertTrue(verify_signed_root(signed, self.public_key))
        self.assertEqual(
            restored.consistency_proof(2),
            self.log.consistency_proof(2),
        )


class DumpLogQualificationTest(unittest.TestCase):
    def test_pruned_log_rejected(self):
        log = AuditLog()
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A)

    def test_keyed_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A)

    def test_authenticated_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.auth(0)
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A)

    def test_rotated_key_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.rotate_key()
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A)

    def test_verifier_exported_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.export_verifier()
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A)

    def test_encrypted_history_rejected(self):
        log = AuditLog()
        log.append("a")
        log.encrypt("secret", b"k" * 32)
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A)

    def test_plain_log_after_rejected_dump_is_unharmed(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            dump_log(log, b"short")
        self.assertEqual(len(log), 1)
        self.assertTrue(log.verify())


class DumpLogTypeErrorTest(unittest.TestCase):
    def test_log_must_be_audit_log(self):
        for bad in (None, "log", b"bytes", 1, (), object(), Entry(0, b"", b"", b"")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dump_log(bad, _SEED_A)

    def test_private_key_must_be_bytes(self):
        log = AuditLog()
        for bad in (None, "seed", bytearray(_SEED_A), memoryview(_SEED_A), 1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dump_log(log, bad)

    def test_private_key_length(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            dump_log(log, b"short")
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A + b"\x00")


class LoadLogFramingTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.data = dump_log(self.log, _SEED_A)

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
                load_log(bad, self.public_key)

    def test_public_key_must_be_bytes(self):
        for bad in (None, "key", bytearray(self.public_key), memoryview(self.public_key), 1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                load_log(self.data, bad)

    def test_public_key_length(self):
        with self.assertRaises(ValueError):
            load_log(self.data, b"short")
        with self.assertRaises(ValueError):
            load_log(self.data, self.public_key + b"\x00")

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_log(b"x" + self.data[1:], self.public_key)
        with self.assertRaises(ValueError):
            load_log(b"", self.public_key)
        with self.assertRaises(ValueError):
            load_log(MAGIC[:-1], self.public_key)
        with self.assertRaises(ValueError):
            load_log(
                b"auditchain/signed-prune/v1\0" + self.data[len(MAGIC):],
                self.public_key,
            )

    def test_bad_version(self):
        bad = MAGIC + u64(2) + self.data[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            load_log(bad, self.public_key)

    def test_truncation(self):
        for cut in range(len(MAGIC), len(self.data)):
            with self.assertRaises(ValueError, msg=cut):
                load_log(self.data[:cut], self.public_key)

    def test_trailing_bytes(self):
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                load_log(self.data + extra, self.public_key)

    def test_oversized_blob_length(self):
        bad = MAGIC + u64(1) + u64(1 << 63) + b"rest"
        with self.assertRaises(ValueError):
            load_log(bad, self.public_key)

    def test_nested_checkpoint_must_be_signed_root_encoding(self):
        # An inner signed-root blob with version 2 must be rejected by the
        # nested decode, even though the outer envelope is well formed.
        signed_magic = b"auditchain/signed-root/v1\0"
        inner = b"".join((
            signed_magic,
            u64(2),
            blob(b"sha256"),
            u64(3),
            blob(b"\x00" * 32),
            blob(b"\x00" * 32),
            blob(b"\x00" * 64),
        ))
        bad = b"".join((
            MAGIC,
            u64(1),
            blob(inner),
            u64(3),
            *(_entry_bytes(entry) for entry in self.log.entries()),
        ))
        with self.assertRaises(ValueError):
            load_log(bad, self.public_key)


class LoadLogVerificationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c"):
            self.log.append(record)
        self.public_key = _public_key(_SEED_A)
        self.data = dump_log(self.log, _SEED_A)
        self.checkpoint = self.log.sign_root(_SEED_A)
        self.entries = tuple(self.log.entries())

    def test_wrong_public_key(self):
        with self.assertRaises(ValueError):
            load_log(self.data, _public_key(_SEED_B))

    def test_forged_signature(self):
        forged = SignedRoot(
            version=self.checkpoint.version,
            hash_name=self.checkpoint.hash_name,
            size=self.checkpoint.size,
            root=self.checkpoint.root,
            head=self.checkpoint.head,
            signature=b"\x00" * 64,
        )
        with self.assertRaises(ValueError):
            load_log(_state_bytes(forged, self.entries), self.public_key)

    def test_entry_count_must_match_checkpoint_size(self):
        # count u64 smaller than the signed size, with the extra entry removed
        # so framing still ends exactly: a pure count/size disagreement.
        offset = len(MAGIC) + 8
        blob_len = int.from_bytes(self.data[offset:offset + 8], "big")
        count_off = offset + 8 + blob_len
        truncated = self.data[: count_off] + u64(2) + _entry_bytes(self.entries[0]) + _entry_bytes(self.entries[1])
        self.assertNotEqual(len(truncated), len(self.data))
        with self.assertRaises(ValueError):
            load_log(truncated, self.public_key)

    def test_indices_must_be_zero_based_in_order(self):
        reordered = (
            Entry(1, e.payload, e.previous_hash, e.entry_hash)
            if i == 0
            else e
            for i, e in enumerate(self.entries)
        )
        with self.assertRaises(ValueError):
            load_log(
                _state_bytes(self.checkpoint, tuple(reordered)),
                self.public_key,
            )

    def test_digest_width_must_match_algorithm(self):
        bad_entry = Entry(
            0,
            self.entries[0].payload,
            self.entries[0].previous_hash,
            b"\x00" * 31,
        )
        with self.assertRaises(ValueError):
            load_log(
                _state_bytes(self.checkpoint, (bad_entry,) + self.entries[1:]),
                self.public_key,
            )

    def test_broken_chain_rejected(self):
        # Skip the count and the first entry's index u64 plus its payload
        # length prefix, then flip its single payload byte; framing stays
        # intact but the recomputed entry digest no longer matches.
        payload_byte_off = len(MAGIC) + 8
        blob_len = int.from_bytes(self.data[payload_byte_off:payload_byte_off + 8], "big")
        payload_byte_off += 8 + blob_len + 8 + 8 + 8
        tampered = bytearray(self.data)
        tampered[payload_byte_off] ^= 0xFF
        with self.assertRaises(ValueError):
            load_log(bytes(tampered), self.public_key)

    def test_chain_head_must_match_checkpoint(self):
        # Same size and a genuine signature from the trusted seed, but the
        # checkpoint describes a different log: recomputed head must mismatch.
        other = AuditLog()
        other.append("a")
        other.append("different")
        foreign = other.sign_root(_SEED_A)
        with self.assertRaises(ValueError):
            load_log(_state_bytes(foreign, self.entries), self.public_key)

    def test_merkle_root_must_match_checkpoint(self):
        # A genuine signature over a checkpoint whose root alone is wrong
        # (head, size and algorithm unchanged) must be rejected when the root
        # is rebuilt from the entries. Sign the documented sign_root message
        # verbatim: D || 0x01 || B(hash_name) || U(size) || B(root) || B(head).
        domain = b"auditchain/signed-root/v1\0"
        wrong_root = entry_digest(9, b"\x00" * 32, b"not the root")
        message = (
            domain
            + b"\x01"
            + blob(b"sha256")
            + u64(self.checkpoint.size)
            + blob(wrong_root)
            + blob(self.checkpoint.head)
        )
        signature = _signing_key(_SEED_A).sign(message)
        forged = SignedRoot(
            version=1,
            hash_name=self.checkpoint.hash_name,
            size=self.checkpoint.size,
            root=wrong_root,
            head=self.checkpoint.head,
            signature=signature,
        )
        with self.assertRaises(ValueError):
            load_log(_state_bytes(forged, self.entries), self.public_key)

    def test_unknown_hash_algorithm_in_checkpoint_rejected(self):
        # Hand-craft an inner signed-root blob naming an unknown algorithm but
        # with structurally valid widths, then wrap it in a valid envelope; the
        # nested decode must surface ValueError.
        signed_magic = b"auditchain/signed-root/v1\0"
        inner = b"".join((
            signed_magic,
            u64(1),
            blob(b"not-a-hash"),
            u64(len(self.entries)),
            blob(b"\x00" * 32),
            blob(b"\x00" * 32),
            blob(b"\x00" * 64),
        ))
        outer = b"".join((
            MAGIC,
            u64(1),
            blob(inner),
            u64(len(self.entries)),
            *(_entry_bytes(entry) for entry in self.entries),
        ))
        with self.assertRaises(ValueError):
            load_log(outer, self.public_key)


if __name__ == "__main__":
    unittest.main()
