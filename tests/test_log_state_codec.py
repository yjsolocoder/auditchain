import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    decode_signed_root,
    dump_log,
    encode_signed_root,
    load_log,
)

MAGIC = b"auditchain/log-state/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


_PUB_A = _public_key(_SEED_A)
_PUB_B = _public_key(_SEED_B)


def _sample_log() -> AuditLog:
    log = AuditLog()
    log.append(b"alpha")
    log.append("beta")
    log.append(b"alpha")
    return log


def _framing(log: AuditLog, seed: bytes = _SEED_A) -> bytes:
    """Independently rebuilt expected framing for ``log``."""
    checkpoint = encode_signed_root(log.sign_root(seed))
    parts = [MAGIC, u64(1), blob(checkpoint), u64(len(log))]
    for entry in log:
        parts.append(u64(entry.index))
        parts.append(blob(entry.payload))
        parts.append(blob(entry.previous_hash))
        parts.append(blob(entry.entry_hash))
    return b"".join(parts)


class DumpLogTests(unittest.TestCase):
    def test_round_trip_preserves_state(self):
        log = _sample_log()
        restored = load_log(dump_log(log, _SEED_A), _PUB_A)
        self.assertEqual(restored.entries(), log.entries())
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.hash_name, log.hash_name)
        self.assertEqual(restored.retain_from, 0)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertTrue(restored.verify())

    def test_round_trip_empty_log(self):
        log = AuditLog()
        restored = load_log(dump_log(log, _SEED_A), _PUB_A)
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertTrue(restored.verify())

    def test_round_trip_other_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for value in (b"x", b"y", b"z"):
            log.append(value)
        restored = load_log(dump_log(log, _SEED_A), _PUB_A)
        self.assertEqual(restored.hash_name, "sha512")
        self.assertEqual(restored.entries(), log.entries())
        self.assertEqual(restored.head, log.head)

    def test_restored_log_rebuilds_find_index(self):
        log = _sample_log()
        restored = load_log(dump_log(log, _SEED_A), _PUB_A)
        self.assertEqual(restored.find(b"alpha"), (0, 2))
        self.assertEqual(restored.find("beta"), (1,))
        self.assertEqual(restored.find(b"missing"), ())

    def test_restored_log_is_independent_and_mutable(self):
        log = _sample_log()
        restored = load_log(dump_log(log, _SEED_A), _PUB_A)
        restored.append(b"gamma")
        self.assertEqual(len(restored), 4)
        self.assertEqual(len(log), 3)
        self.assertTrue(restored.verify())
        log.append(b"delta")
        self.assertEqual(len(restored), 4)
        self.assertEqual(len(log), 4)
        self.assertNotEqual(restored.head, log.head)

    def test_dump_is_deterministic(self):
        self.assertEqual(
            dump_log(_sample_log(), _SEED_A), dump_log(_sample_log(), _SEED_A)
        )

    def test_dump_matches_independent_framing(self):
        log = _sample_log()
        self.assertEqual(dump_log(log, _SEED_A), _framing(log))

    def test_dump_is_read_only(self):
        log = _sample_log()
        before = (log.entries(), log.head, log.merkle_root())
        dump_log(log, _SEED_A)
        self.assertEqual((log.entries(), log.head, log.merkle_root()), before)

    def test_dump_does_not_store_the_key(self):
        data = dump_log(_sample_log(), _SEED_A)
        self.assertNotIn(_SEED_A, data)

    def test_dump_type_errors(self):
        log = _sample_log()
        with self.assertRaises(TypeError):
            dump_log("not a log", _SEED_A)
        with self.assertRaises(TypeError):
            dump_log(log, "not bytes")
        with self.assertRaises(TypeError):
            dump_log(log, bytearray(_SEED_A))

    def test_dump_seed_length(self):
        with self.assertRaises(ValueError):
            dump_log(_sample_log(), b"\x01" * 31)
        with self.assertRaises(ValueError):
            dump_log(_sample_log(), b"\x01" * 33)

    def test_dump_rejects_pruned_log(self):
        log = _sample_log()
        receipt = log.seal(1)
        log.prune(1, receipt)
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A)

    def test_dump_rejects_keyed_log(self):
        log = AuditLog(key=b"k" * 16)
        log.append(b"alpha")
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A)

    def test_dump_rejects_log_with_auth_history(self):
        log = AuditLog(key=b"k" * 16)
        log.append(b"alpha")
        log.auth(0)
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A)

    def test_dump_rejects_log_with_encryption_history(self):
        log = AuditLog()
        log.encrypt(b"secret", b"\x07" * 32, nonce=b"\x00" * 12)
        with self.assertRaises(ValueError):
            dump_log(log, _SEED_A)


class LoadLogTests(unittest.TestCase):
    def setUp(self):
        self.log = _sample_log()
        self.data = dump_log(self.log, _SEED_A)

    def test_load_type_errors(self):
        with self.assertRaises(TypeError):
            load_log(bytearray(self.data), _PUB_A)
        with self.assertRaises(TypeError):
            load_log(self.data, "not bytes")

    def test_load_public_key_length(self):
        with self.assertRaises(ValueError):
            load_log(self.data, b"\x01" * 31)

    def test_load_bad_magic(self):
        with self.assertRaises(ValueError):
            load_log(b"auditchain/log-state/v2\0" + self.data[len(MAGIC):], _PUB_A)

    def test_load_bad_version(self):
        offset = len(MAGIC)
        bad = self.data[:offset] + u64(2) + self.data[offset + 8:]
        with self.assertRaises(ValueError):
            load_log(bad, _PUB_A)

    def test_load_truncation(self):
        for cut in (len(MAGIC) + 3, len(self.data) // 2, len(self.data) - 1):
            with self.assertRaises(ValueError):
                load_log(self.data[:cut], _PUB_A)

    def test_load_trailing_bytes(self):
        with self.assertRaises(ValueError):
            load_log(self.data + b"\x00", _PUB_A)

    def test_load_wrong_public_key(self):
        with self.assertRaises(ValueError):
            load_log(self.data, _PUB_B)

    def test_load_tampered_checkpoint(self):
        # Re-sign the same state with another key: structurally sound, but
        # the signature no longer verifies under the trusted public key.
        checkpoint = encode_signed_root(self.log.sign_root(_SEED_B))
        offset = len(MAGIC) + 8
        length = int.from_bytes(self.data[offset:offset + 8], "big")
        tampered = (
            self.data[:offset] + blob(checkpoint) + self.data[offset + 8 + length:]
        )
        with self.assertRaises(ValueError):
            load_log(tampered, _PUB_A)

    def test_load_tampered_payload(self):
        # Flip one payload byte of the first entry; the recomputed entry
        # digest no longer matches the recorded one.
        marker = blob(b"alpha")
        at = self.data.index(marker)
        tampered = self.data[:at + 8] + b"A" + self.data[at + 9:]
        with self.assertRaises(ValueError):
            load_log(tampered, _PUB_A)

    def test_load_out_of_order_index(self):
        # Rewrite the second entry's index to 7 (keeping the framing valid).
        log = _sample_log()
        checkpoint = encode_signed_root(log.sign_root(_SEED_A))
        parts = [MAGIC, u64(1), blob(checkpoint), u64(3)]
        for position, entry in enumerate(log):
            parts.append(u64(7 if position == 1 else entry.index))
            parts.append(blob(entry.payload))
            parts.append(blob(entry.previous_hash))
            parts.append(blob(entry.entry_hash))
        with self.assertRaises(ValueError):
            load_log(b"".join(parts), _PUB_A)

    def test_load_count_disagrees_with_checkpoint(self):
        # Drop the last entry but keep the checkpoint attesting size 3.
        log = _sample_log()
        checkpoint = encode_signed_root(log.sign_root(_SEED_A))
        entries = list(log)
        parts = [MAGIC, u64(1), blob(checkpoint), u64(2)]
        for entry in entries[:2]:
            parts.append(u64(entry.index))
            parts.append(blob(entry.payload))
            parts.append(blob(entry.previous_hash))
            parts.append(blob(entry.entry_hash))
        with self.assertRaises(ValueError):
            load_log(b"".join(parts), _PUB_A)

    def test_load_wrong_digest_width(self):
        # Widen one recorded entry_hash; the width check fires before any
        # state is built.
        log = _sample_log()
        checkpoint = encode_signed_root(log.sign_root(_SEED_A))
        parts = [MAGIC, u64(1), blob(checkpoint), u64(3)]
        for position, entry in enumerate(log):
            parts.append(u64(entry.index))
            parts.append(blob(entry.payload))
            parts.append(blob(entry.previous_hash))
            parts.append(blob(entry.entry_hash + (b"\x00" if position == 0 else b"")))
        with self.assertRaises(ValueError):
            load_log(b"".join(parts), _PUB_A)

    def test_load_unknown_hash_algorithm(self):
        # Hand-build a checkpoint blob naming an unknown algorithm.
        checkpoint = decode_signed_root(
            encode_signed_root(self.log.sign_root(_SEED_A))
        )
        self.assertEqual(checkpoint.hash_name, "sha256")
        bad_inner = (
            b"auditchain/signed-root/v1\0"
            + u64(1)
            + blob(b"no-such-hash")
            + u64(checkpoint.size)
            + blob(checkpoint.root)
            + blob(checkpoint.head)
            + blob(checkpoint.signature)
        )
        data = MAGIC + u64(1) + blob(bad_inner) + u64(0)
        with self.assertRaises(ValueError):
            load_log(data, _PUB_A)

    def test_load_accepts_only_bytes_data(self):
        restored = load_log(bytes(self.data), _PUB_A)
        self.assertEqual(restored.entries(), self.log.entries())


if __name__ == "__main__":
    unittest.main()
