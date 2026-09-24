import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    dump_signed_pruned_auth,
    load_signed_pruned_auth,
    verify_auth,
)

MAGIC = b"auditchain/signed-pruned-auth/v1\0"

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


def _sign(seed, body):
    return Ed25519PrivateKey.from_private_bytes(seed).sign(body)


PUBLIC_A = _public_key(_SEED_A)
PUBLIC_B = _public_key(_SEED_B)


def _frame(log, root, head):
    parts = [
        blob(log.hash_name.encode("utf-8")),
        u64(len(log)),
        u64(log.retain_from),
        blob(log._checkpoint_head),
        u64(len(log._frontier)),
    ]
    for height in sorted(log._frontier):
        parts.append(u64(height))
        parts.append(blob(log._frontier[height]))
    retained = list(log)
    parts.append(u64(len(retained)))
    for entry in retained:
        parts.append(u64(entry.index))
        parts.append(blob(entry.payload))
        parts.append(blob(entry.previous_hash))
        parts.append(blob(entry.entry_hash))
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


def _make_pruned_keyed_log(retain_from=3):
    log = AuditLog(key=b"shared-secret")
    verifier = log.export_verifier()
    for record in ("a", b"b", b"c" * 100, "d", "e"):
        log.append(record)
    log.auth(1)            # stage -> 1; tag released by the prune
    log.prune(retain_from, log.seal(retain_from))
    tag4 = log.auth(4)     # retained tag, stage -> 2
    return log, tag4, verifier


class DumpSignedPrunedAuthTest(unittest.TestCase):
    def setUp(self):
        self.log, self.tag4, self.verifier = _make_pruned_keyed_log()

    def test_wire_layout(self):
        data = dump_signed_pruned_auth(self.log, _SEED_A)
        self.assertTrue(data.startswith(MAGIC + u64(1)))
        expected = _encode(self.log)
        self.assertEqual(data, expected)
        # The trailing 64 bytes are an Ed25519 signature over the body.
        body, signature = data[:-64], data[-64:]
        Ed25519PrivateKey.from_private_bytes(_SEED_A).public_key().verify(
            signature, body
        )
        # The frame is plaintext: the evolution key is visible in the stream.
        self.assertIn(self.log._key, data)

    def test_deterministic_and_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"d"),
            self.log._key,
        )
        first = dump_signed_pruned_auth(self.log, _SEED_A)
        second = dump_signed_pruned_auth(self.log, _SEED_A)
        self.assertEqual(first, second)
        after = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"d"),
            self.log._key,
        )
        self.assertEqual(before, after)

    def test_distinct_seeds_differ_only_in_signature(self):
        first = dump_signed_pruned_auth(self.log, _SEED_A)
        second = dump_signed_pruned_auth(self.log, _SEED_B)
        self.assertEqual(first[:-64], second[:-64])
        self.assertNotEqual(first[-64:], second[-64:])

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            dump_signed_pruned_auth("not a log", _SEED_A)
        with self.assertRaises(TypeError):
            dump_signed_pruned_auth(self.log, "not bytes")
        with self.assertRaises(TypeError):
            dump_signed_pruned_auth(self.log, bytearray(_SEED_A))

    def test_seed_length(self):
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(self.log, b"short")
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(self.log, b"s" * 33)

    def test_unpruned_log_rejected(self):
        log = AuditLog(key=b"k")
        log.append("a")
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(log, _SEED_A)

    def test_keyless_log_rejected(self):
        log = AuditLog()
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(log, _SEED_A)

    def test_encrypt_history_rejected(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.encrypt(b"secret", b"e" * 32, nonce=b"n" * 12)
        log.append("b")
        log.prune(2, log.seal(2))  # even with the ciphertext released
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(log, _SEED_A)

    def test_failure_is_atomic(self):
        with self.assertRaises(ValueError):
            dump_signed_pruned_auth(self.log, bytes(31))
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.retain_from, 3)
        self.assertEqual(self.log.stage, 2)
        # The log still dumps fine after the failed attempt.
        load_signed_pruned_auth(dump_signed_pruned_auth(self.log, _SEED_A), PUBLIC_A)


class LoadSignedPrunedAuthTest(unittest.TestCase):
    def setUp(self):
        self.log, self.tag4, self.verifier = _make_pruned_keyed_log()
        self.data = dump_signed_pruned_auth(self.log, _SEED_A)

    def test_round_trip_state(self):
        restored = load_signed_pruned_auth(self.data, PUBLIC_A)
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, self.log.retain_from)
        self.assertEqual(restored.stage, self.log.stage)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(restored.hash_name, self.log.hash_name)
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertEqual(list(restored), list(self.log))
        self.assertTrue(restored.verify())
        for record in (b"d", b"e"):
            self.assertEqual(restored.find(record), self.log.find(record))
        self.assertEqual(restored.find(b"c" * 100), ())  # released by the prune

    def test_proofs_match(self):
        restored = load_signed_pruned_auth(self.data, PUBLIC_A)
        for index in range(3, 5):
            self.assertEqual(
                restored.inclusion_proof(index),
                self.log.inclusion_proof(index),
            )
        self.assertEqual(
            restored.consistency_proof(3, 5),
            self.log.consistency_proof(3, 5),
        )

    def test_evolution_continues_identically(self):
        restored = load_signed_pruned_auth(self.data, PUBLIC_A)
        self.log.append("f")
        restored.append("f")
        original_tag = self.log.auth(5)
        restored_tag = restored.auth(5)
        self.assertEqual(restored_tag, original_tag)
        self.assertEqual(restored.stage, self.log.stage)
        self.assertTrue(verify_auth(restored.entry(5), original_tag, self.verifier))
        # The retained tag minted before the dump still verifies.
        self.assertTrue(verify_auth(restored.entry(4), self.tag4, self.verifier))

    def test_verifier_exported_flag_restored(self):
        restored = load_signed_pruned_auth(self.data, PUBLIC_A)
        # The source already exported its stage-0 verifier; the restore must
        # not allow a second export.
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_unexported_flag_restored(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        restored = load_signed_pruned_auth(
            dump_signed_pruned_auth(log, _SEED_A), PUBLIC_A
        )
        verifier = restored.export_verifier()
        self.assertEqual(verifier.key, log.export_verifier().key)

    def test_restored_log_is_independent_and_mutable(self):
        restored = load_signed_pruned_auth(self.data, PUBLIC_A)
        restored.append("f")
        restored.rotate_key()
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.stage, 2)
        self.assertEqual(len(restored), 6)
        self.assertEqual(restored.stage, 3)
        # The shared retained prefix is untouched.
        for entry in self.log:
            self.assertEqual(restored.entry(entry.index), entry)
        # Can be pruned again like any live log.
        restored.prune(5, restored.seal(5))
        self.assertEqual(restored.retain_from, 5)

    def test_fully_pruned_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        for record in ("a", "b", "c"):
            log.append(record)
        log.auth(0)
        log.prune(3, log.seal(3))
        self.assertEqual(log.entries(), [])
        restored = load_signed_pruned_auth(
            dump_signed_pruned_auth(log, _SEED_A), PUBLIC_A
        )
        self.assertEqual(len(restored), 3)
        self.assertEqual(restored.retain_from, 3)
        self.assertEqual(restored.entries(), [])
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.stage, 1)
        restored.append("d")
        self.assertEqual(restored.entry(3).index, 3)

    def test_other_hash_algorithms(self):
        for hash_name in ("sha512", "sha3-256"):
            log = AuditLog(key=b"k", hash_name=hash_name)
            for i in range(4):
                log.append(f"r{i}")
            log.auth(0)
            log.prune(2, log.seal(2))
            data = dump_signed_pruned_auth(log, _SEED_A)
            restored = load_signed_pruned_auth(data, PUBLIC_A)
            self.assertEqual(restored.hash_name, hash_name)
            self.assertEqual(restored.retain_from, 2)
            self.assertEqual(restored.head, log.head)
            self.assertEqual(restored.merkle_root(), log.merkle_root())
            self.assertEqual(restored.stage, log.stage)
            self.assertEqual(restored.auth(3), log.auth(3))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            load_signed_pruned_auth(bytearray(self.data), PUBLIC_A)
        with self.assertRaises(TypeError):
            load_signed_pruned_auth(self.data, "not bytes")
        with self.assertRaises(TypeError):
            load_signed_pruned_auth(self.data, bytearray(PUBLIC_A))

    def test_public_key_length(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self.data, b"short")
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self.data, b"p" * 33)

    def test_bad_magic(self):
        broken = b"auditchain/signed-pruned-auth/v2\0" + self.data[len(MAGIC):]
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(broken, PUBLIC_A)
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(b"", PUBLIC_A)

    def test_bad_version(self):
        body = MAGIC + u64(2) + self.data[len(MAGIC) + 8:-64]
        data = body + _sign(_SEED_A, body)
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(data, PUBLIC_A)

    def test_truncation(self):
        for cut in (len(MAGIC), len(self.data) - 65, len(self.data) - 1):
            with self.assertRaises(ValueError):
                load_signed_pruned_auth(self.data[:cut], PUBLIC_A)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self.data + b"x", PUBLIC_A)

    def test_signature_failure(self):
        # Wrong public key.
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self.data, PUBLIC_B)
        # A flipped body byte invalidates the signature.
        flipped = bytearray(self.data)
        flipped[len(MAGIC) + 12] ^= 1
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(bytes(flipped), PUBLIC_A)
        # A flipped signature byte.
        flipped = bytearray(self.data)
        flipped[-1] ^= 1
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(bytes(flipped), PUBLIC_A)

    def _load_frame(self, frame, **overrides):
        body = MAGIC + u64(overrides.get("version", 1)) + frame
        return body + _sign(overrides.get("seed", _SEED_A), body)

    def test_tampered_frame_values(self):
        root = self.log.merkle_root()
        head = self.log.head
        good = _frame(self.log, root, head)

        def load(frame):
            with self.assertRaises(ValueError):
                load_signed_pruned_auth(self._load_frame(frame), PUBLIC_A)

        # A root that does not match the recomputed Merkle root.
        load(good.replace(blob(root), blob(bytes(32)), 1))
        # A head that does not match the recomputed chain head.
        load(good.replace(blob(head), blob(bytes(32)), 1))
        # A wrong-width root.
        load(good.replace(blob(root), blob(b"\x00" * 31), 1))
        # An out-of-range exported flag.
        load(good[:-8] + u64(2))
        # An empty evolution key.
        key_blob = blob(self.log._key)
        load(good.replace(key_blob, blob(b""), 1))
        # A wrong-width evolution key at a non-zero stage.
        load(good.replace(key_blob, blob(b"\x00" * 31), 1))
        # Trailing bytes inside the signed body.
        load(good + b"x")

    def test_tampered_prune_fields(self):
        good = _frame(self.log, self.log.merkle_root(), self.log.head)

        def load(frame):
            with self.assertRaises(ValueError):
                load_signed_pruned_auth(self._load_frame(frame), PUBLIC_A)

        # A retain point of zero or beyond the entry count.
        load(good.replace(u64(3), u64(0), 1))
        load(good.replace(u64(3), u64(6), 1))
        # A wrong-width checkpoint.
        checkpoint_blob = blob(self.log._checkpoint_head)
        load(good.replace(checkpoint_blob, blob(b"\x00" * 31), 1))
        # A frontier that is not exactly the set bits of retain_from.
        height_pair = u64(0) + blob(self.log._frontier[0])
        load(good.replace(u64(2) + height_pair, u64(0), 1))
        # A retained-entry count that disagrees with n - r.
        load(good.replace(u64(2), u64(1), 1))

    def test_tampered_entries(self):
        good = _frame(self.log, self.log.merkle_root(), self.log.head)

        # A corrupted payload breaks the recomputed chain.
        bad = good.replace(blob(b"d"), blob(b"z"), 1)
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self._load_frame(bad), PUBLIC_A)
        # A corrupted recorded entry_hash.
        entry3 = self.log.entry(3)
        bad = good.replace(blob(entry3.entry_hash), blob(bytes(32)), 1)
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self._load_frame(bad), PUBLIC_A)

    def test_unknown_hash_name(self):
        frame = blob(b"no-such-hash") + _frame(
            self.log, self.log.merkle_root(), self.log.head
        )[len(blob(b"sha256")):]
        with self.assertRaises(ValueError):
            load_signed_pruned_auth(self._load_frame(frame), PUBLIC_A)

    def test_load_is_read_only(self):
        view = bytes(self.data)
        load_signed_pruned_auth(view, PUBLIC_A)
        self.assertEqual(view, self.data)


if __name__ == "__main__":
    unittest.main()
