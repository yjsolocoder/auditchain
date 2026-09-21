import unittest

from auditchain import (
    AuditLog,
    Entry,
    dump_pruned_log,
    load_pruned_log,
    verify_inclusion,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAGIC = b"auditchain/pruned-log/v1\0"

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


def _entry_bytes(entry):
    return b"".join((
        u64(entry.index),
        blob(entry.payload),
        blob(entry.previous_hash),
        blob(entry.entry_hash),
    ))


def _pruned_log(records=("a", "b", "c", "d", "e", "f", "g"), retain_from=3,
                hash_name="sha256"):
    log = AuditLog(hash_name=hash_name)
    for record in records:
        log.append(record)
    log.prune(retain_from, log.seal(retain_from))
    return log


class DumpPrunedLogTest(unittest.TestCase):
    def setUp(self):
        self.log = _pruned_log()
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        data = dump_pruned_log(self.log, _SEED_A)
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
        # B(checkpoint): chain digest of the last of the first r entries.
        width = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(width, 32)
        checkpoint = data[offset:offset + width]
        offset += width
        self.assertEqual(checkpoint, self.log._checkpoint_head)
        # Frontier: count, then U(height) || B(digest) ascending; the heights
        # are exactly the set bits of r (r == 3 -> heights 0 and 1).
        count = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(count, 2)
        for height in (0, 1):
            self.assertEqual(data[offset:offset + 8], u64(height))
            offset += 8
            width = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            self.assertEqual(data[offset:offset + width],
                             self.log._frontier[height])
            offset += width
        # Retained entries r..n-1 in dump_log entry framing.
        count = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(count, len(self.log) - self.log.retain_from)
        for entry in self.log.entries():
            self.assertEqual(data[offset:offset + 8], u64(entry.index))
            offset += 8
            for value in (entry.payload, entry.previous_hash, entry.entry_hash):
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

    def test_deterministic_same_state_same_seed(self):
        self.assertEqual(
            dump_pruned_log(self.log, _SEED_A),
            dump_pruned_log(self.log, _SEED_A),
        )
        twin = _pruned_log()
        self.assertEqual(
            dump_pruned_log(twin, _SEED_A), dump_pruned_log(self.log, _SEED_A)
        )

    def test_seed_changes_only_signature(self):
        data_a = dump_pruned_log(self.log, _SEED_A)
        data_b = dump_pruned_log(self.log, _SEED_B)
        self.assertNotEqual(data_a, data_b)
        self.assertEqual(data_a[:-64], data_b[:-64])
        restored = load_pruned_log(data_b, _public_key(_SEED_B))
        self.assertEqual(restored.head, self.log.head)

    def test_dump_is_read_only(self):
        before = dump_pruned_log(self.log, _SEED_A)
        dump_pruned_log(self.log, _SEED_A)
        self.assertEqual(len(self.log), 7)
        self.assertEqual(self.log.retain_from, 3)
        self.assertTrue(self.log.verify())
        self.assertEqual(dump_pruned_log(self.log, _SEED_A), before)

    def test_seed_is_not_stored(self):
        dump_pruned_log(self.log, _SEED_A)
        self.assertEqual(self.log.stage, 0)
        with self.assertRaises(ValueError):
            self.log.export_verifier()

    def test_fully_pruned_log(self):
        log = _pruned_log(records=("a", "b", "c"), retain_from=3)
        self.assertEqual(len(log.entries()), 0)
        data = dump_pruned_log(log, _SEED_A)
        restored = load_pruned_log(data, self.public_key)
        self.assertEqual(len(restored), 3)
        self.assertEqual(restored.retain_from, 3)
        self.assertEqual(restored.entries(), [])
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertTrue(restored.verify())

    def test_various_retain_points(self):
        for retain_from in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10):
            log = _pruned_log(
                records=tuple(f"r{i}" for i in range(12)),
                retain_from=retain_from,
            )
            restored = load_pruned_log(
                dump_pruned_log(log, _SEED_A), self.public_key
            )
            self.assertEqual(len(restored), 12)
            self.assertEqual(restored.retain_from, retain_from)
            self.assertEqual(restored.head, log.head)
            self.assertEqual(restored.merkle_root(), log.merkle_root())
            self.assertEqual(restored.entries(), log.entries())
            self.assertTrue(restored.verify())


class DumpPrunedLogQualificationTest(unittest.TestCase):
    def test_unpruned_log_rejected(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            dump_pruned_log(log, _SEED_A)

    def test_empty_log_rejected(self):
        with self.assertRaises(ValueError):
            dump_pruned_log(AuditLog(), _SEED_A)

    def test_keyed_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_pruned_log(log, _SEED_A)

    def test_authenticated_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.append("b")
        log.auth(1)
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_pruned_log(log, _SEED_A)

    def test_rotated_key_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.append("b")
        log.rotate_key()
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_pruned_log(log, _SEED_A)

    def test_verifier_exported_log_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.append("b")
        log.export_verifier()
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_pruned_log(log, _SEED_A)

    def test_encrypted_history_rejected(self):
        log = AuditLog()
        log.append("a")
        log.encrypt("secret", b"k" * 32)
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_pruned_log(log, _SEED_A)

    def test_pruned_away_encryption_history_rejected(self):
        # The encrypted entry itself is released by the prune, but the nonce
        # history remains: the log still has encryption history.
        log = AuditLog()
        log.encrypt("secret", b"k" * 32)
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        self.assertEqual(log._encrypted_index, {})
        with self.assertRaises(ValueError):
            dump_pruned_log(log, _SEED_A)

    def test_failed_dump_leaves_log_unharmed(self):
        log = _pruned_log()
        with self.assertRaises(ValueError):
            dump_pruned_log(log, b"short")
        self.assertEqual(len(log), 7)
        self.assertEqual(log.retain_from, 3)
        self.assertTrue(log.verify())

    def test_log_must_be_audit_log(self):
        for bad in (None, "log", b"bytes", 1, (), object(), Entry(0, b"", b"", b"")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dump_pruned_log(bad, _SEED_A)

    def test_private_key_must_be_bytes(self):
        log = _pruned_log()
        for bad in (None, "seed", bytearray(_SEED_A), memoryview(_SEED_A), 1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dump_pruned_log(log, bad)

    def test_private_key_length(self):
        log = _pruned_log()
        with self.assertRaises(ValueError):
            dump_pruned_log(log, b"short")
        with self.assertRaises(ValueError):
            dump_pruned_log(log, _SEED_A + b"\x00")


class LoadPrunedLogRoundtripTest(unittest.TestCase):
    def setUp(self):
        self.log = _pruned_log()
        self.public_key = _public_key(_SEED_A)
        self.data = dump_pruned_log(self.log, _SEED_A)

    def test_restored_fields_match(self):
        restored = load_pruned_log(self.data, self.public_key)
        self.assertIsInstance(restored, AuditLog)
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, self.log.retain_from)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.hash_name, self.log.hash_name)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertEqual(restored._checkpoint_head, self.log._checkpoint_head)
        self.assertEqual(restored._frontier, self.log._frontier)
        self.assertTrue(restored.verify())

    def test_proofs_match_original(self):
        restored = load_pruned_log(self.data, self.public_key)
        for index in range(self.log.retain_from, len(self.log)):
            proof = restored.inclusion_proof(index)
            self.assertEqual(proof, self.log.inclusion_proof(index))
            self.assertTrue(
                verify_inclusion(
                    restored.entry(index).entry_hash,
                    index,
                    len(restored),
                    restored.merkle_root(),
                    proof,
                )
            )

    def test_find_index_is_rebuilt(self):
        restored = load_pruned_log(self.data, self.public_key)
        self.assertEqual(restored.find(b"e"), (4,))
        self.assertEqual(restored.find("missing"), ())

    def test_restored_log_is_independent_and_mutable(self):
        restored = load_pruned_log(self.data, self.public_key)
        restored.append("new event")
        restored.encrypt("secret", b"k" * 32)
        self.assertEqual(len(restored), 9)
        self.assertEqual(restored.find(b"new event"), (7,))
        self.assertEqual(restored.find_encrypted("secret", b"k" * 32), (8,))
        self.assertTrue(restored.verify())
        # The source log is untouched and shares no state.
        self.assertEqual(len(self.log), 7)
        self.assertEqual(self.log.head, restored.entry(6).entry_hash)

    def test_restored_log_prunes_further(self):
        restored = load_pruned_log(self.data, self.public_key)
        receipt = restored.seal(5)
        restored.prune(5, receipt)
        self.assertEqual(restored.retain_from, 5)
        restored.append("after prune")
        self.assertTrue(restored.verify())
        self.assertEqual(len(restored), 8)

    def test_restored_log_is_keyless(self):
        restored = load_pruned_log(self.data, self.public_key)
        self.assertEqual(restored.stage, 0)
        with self.assertRaises(ValueError):
            restored.auth(3)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_restored_log_redumps_identically(self):
        restored = load_pruned_log(self.data, self.public_key)
        self.assertEqual(dump_pruned_log(restored, _SEED_A), self.data)

    def test_alternate_hash_algorithms(self):
        for hash_name in ("sha512", "sha3_256"):
            log = _pruned_log(records=("a", "b", "c", "d"), retain_from=2,
                              hash_name=hash_name)
            restored = load_pruned_log(
                dump_pruned_log(log, _SEED_A), self.public_key
            )
            self.assertEqual(restored.hash_name, hash_name)
            self.assertEqual(restored.retain_from, 2)
            self.assertEqual(restored.head, log.head)
            self.assertEqual(restored.merkle_root(), log.merkle_root())
            self.assertTrue(restored.verify())


class LoadPrunedLogFramingTest(unittest.TestCase):
    def setUp(self):
        self.log = _pruned_log()
        self.public_key = _public_key(_SEED_A)
        self.data = dump_pruned_log(self.log, _SEED_A)

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
                load_pruned_log(bad, self.public_key)

    def test_public_key_must_be_bytes(self):
        for bad in (None, "key", bytearray(self.public_key),
                    memoryview(self.public_key), 1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                load_pruned_log(self.data, bad)

    def test_public_key_length(self):
        with self.assertRaises(ValueError):
            load_pruned_log(self.data, b"short")
        with self.assertRaises(ValueError):
            load_pruned_log(self.data, self.public_key + b"\x00")

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_pruned_log(b"x" + self.data[1:], self.public_key)
        with self.assertRaises(ValueError):
            load_pruned_log(b"", self.public_key)
        with self.assertRaises(ValueError):
            load_pruned_log(MAGIC[:-1], self.public_key)
        with self.assertRaises(ValueError):
            load_pruned_log(
                b"auditchain/secure-log/v1\0" + self.data[len(MAGIC):],
                self.public_key,
            )

    def test_bad_version(self):
        bad = bytearray(self.data)
        bad[len(MAGIC):len(MAGIC) + 8] = u64(2)
        # Re-signing is impossible, so the signature check rejects it; the
        # version rule is exercised separately below with a signed stream.
        with self.assertRaises(ValueError):
            load_pruned_log(bytes(bad), self.public_key)

    def test_truncation(self):
        for cut in range(len(MAGIC), len(self.data)):
            with self.assertRaises(ValueError, msg=cut):
                load_pruned_log(self.data[:cut], self.public_key)

    def test_trailing_bytes(self):
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                load_pruned_log(self.data + extra, self.public_key)

    def test_wrong_public_key(self):
        with self.assertRaises(ValueError):
            load_pruned_log(self.data, _public_key(_SEED_B))

    def test_tampered_body_rejected(self):
        # Flip one byte in the middle of the body: the trailing signature no
        # longer covers it.
        tampered = bytearray(self.data)
        tampered[len(self.data) // 2] ^= 0xFF
        with self.assertRaises(ValueError):
            load_pruned_log(bytes(tampered), self.public_key)


class LoadPrunedLogStructureTest(unittest.TestCase):
    """Structural re-checks after the signature: craft streams and sign them
    with the trusted seed, exactly as a genuine dump would be framed."""

    def setUp(self):
        self.log = _pruned_log()
        self.public_key = _public_key(_SEED_A)
        self.key = Ed25519PrivateKey.from_private_bytes(_SEED_A)

    def _signed(self, body):
        return body + self.key.sign(body)

    def _body(self, *, version=1, hash_name=b"sha256", n=7, r=3,
              checkpoint=None, frontier=None, entries=None,
              root=None, head=None):
        if checkpoint is None:
            checkpoint = self.log._checkpoint_head
        if frontier is None:
            frontier = self.log._frontier
        if entries is None:
            entries = self.log.entries()
        if root is None:
            root = self.log.merkle_root()
        if head is None:
            head = self.log.head
        parts = [
            MAGIC,
            u64(version),
            blob(hash_name),
            u64(n),
            u64(r),
            blob(checkpoint),
            u64(len(frontier)),
        ]
        for height in sorted(frontier):
            parts.append(u64(height))
            parts.append(blob(frontier[height]))
        parts.append(u64(len(entries)))
        for entry in entries:
            parts.append(_entry_bytes(entry))
        parts.append(blob(root))
        parts.append(blob(head))
        return b"".join(parts)

    def test_bad_signed_version(self):
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(version=2)), self.public_key
            )

    def test_bad_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(hash_name=b"\xff")), self.public_key
            )

    def test_unknown_hash_algorithm(self):
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(hash_name=b"not-a-hash")),
                self.public_key,
            )

    def test_zero_retain_from_rejected(self):
        with self.assertRaises(ValueError):
            load_pruned_log(self._signed(self._body(r=0)), self.public_key)

    def test_retain_from_beyond_size_rejected(self):
        with self.assertRaises(ValueError):
            load_pruned_log(self._signed(self._body(r=8)), self.public_key)

    def test_checkpoint_width(self):
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(checkpoint=b"\x00" * 31)),
                self.public_key,
            )

    def test_frontier_heights_must_be_set_bits(self):
        # r == 3 has set bits 0 and 1; a frontier missing height 0 is illegal.
        frontier = {1: self.log._frontier[1]}
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(frontier=frontier)), self.public_key
            )

    def test_frontier_digest_width(self):
        frontier = {0: b"\x00" * 31, 1: self.log._frontier[1]}
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(frontier=frontier)), self.public_key
            )

    def test_entry_count_must_match(self):
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(entries=self.log.entries()[:-1])),
                self.public_key,
            )

    def test_indices_must_be_r_to_n_in_order(self):
        entries = [
            Entry(2, e.payload, e.previous_hash, e.entry_hash)
            if i == 0 else e
            for i, e in enumerate(self.log.entries())
        ]
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(entries=entries)), self.public_key
            )

    def test_broken_chain_rejected(self):
        entries = list(self.log.entries())
        first = entries[0]
        entries[0] = Entry(
            first.index, b"X" + first.payload[1:],
            first.previous_hash, first.entry_hash,
        )
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(entries=entries)), self.public_key
            )

    def test_entry_digest_width(self):
        entries = list(self.log.entries())
        first = entries[0]
        entries[0] = Entry(
            first.index, first.payload, first.previous_hash, b"\x00" * 31
        )
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(entries=entries)), self.public_key
            )

    def test_head_must_match_recomputed_chain(self):
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(head=b"\x00" * 32)), self.public_key
            )

    def test_root_must_match_rebuilt_tree(self):
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(root=b"\x00" * 32)), self.public_key
            )

    def test_frontier_digest_must_match_root(self):
        # A structurally valid frontier whose digest is wrong fails the root
        # cross-check even though the stream is genuinely signed.
        frontier = dict(self.log._frontier)
        frontier[0] = b"\x00" * 32
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(frontier=frontier)), self.public_key
            )

    def test_root_width(self):
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(root=b"\x00" * 31)), self.public_key
            )

    def test_head_width(self):
        with self.assertRaises(ValueError):
            load_pruned_log(
                self._signed(self._body(head=b"\x00" * 33)), self.public_key
            )


if __name__ == "__main__":
    unittest.main()
