import os
import unittest

from auditchain import (
    AuditLog,
    Entry,
    decrypt_entry,
    dump_secure_pruned,
    load_secure_pruned,
    verify_inclusion,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MAGIC = b"auditchain/pruned-secure/v1\0"
KEY = bytes(range(1, 33))
KEY2 = bytes(range(33, 65))
SEED_A = bytes(range(2, 34))
SEED_B = bytes(range(34, 66))
N0 = b"n" * 12
N1 = b"m" * 12
N2 = b"a" * 12


def pub(seed):
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


PUB_A = pub(SEED_A)


def u64(v):
    return v.to_bytes(8, "big")


def blob(b):
    return u64(len(b)) + b


def make_log(retain_from=3, records=7, hash_name="sha256"):
    log = AuditLog(hash_name=hash_name)
    # Released prefix when retain_from == 3:
    log.encrypt("enc-released", KEY, nonce=N0)      # 0 encrypted, released
    log.append("plain-1")                            # 1 plain, released
    log.append("plain-2")                            # 2 plain, released
    # Retained suffix:
    log.encrypt("enc-retained-a", KEY, nonce=N1)     # 3 encrypted, retained
    log.encrypt("enc-retained-b", KEY, nonce=N2)     # 4 encrypted, retained
    log.append("plain-5")                            # 5 plain, retained
    log.append(b"auditchain/encrypted-entry/v1\0fake")  # 6 magic-prefix plain
    log.prune(retain_from, log.seal(retain_from))
    return log


class RoundtripTest(unittest.TestCase):
    def test_basic_roundtrip(self):
        log = make_log()
        data = dump_secure_pruned(log, SEED_A)
        self.assertTrue(data.startswith(MAGIC))
        restored = load_secure_pruned(data, PUB_A)
        self.assertIsInstance(restored, AuditLog)
        self.assertEqual(len(restored), len(log))
        self.assertEqual(restored.retain_from, 3)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.hash_name, log.hash_name)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.entries(), log.entries())
        self.assertEqual(restored._checkpoint_head, log._checkpoint_head)
        self.assertEqual(restored._frontier, log._frontier)
        self.assertEqual(restored._used_nonces, log._used_nonces)
        self.assertTrue(restored.verify())

    def test_nonce_history_includes_released_ciphertexts(self):
        log = make_log()
        # Entry 0's nonce N0 belongs to a ciphertext released by the prune;
        # the history must still contain all three nonces (N0, N1, N2).
        self.assertEqual(log._used_nonces, {N0, N1, N2})
        restored = load_secure_pruned(dump_secure_pruned(log, SEED_A), PUB_A)
        for nonce in (N0, N1, N2):
            with self.assertRaises(ValueError):
                restored.encrypt("x", KEY, nonce=nonce)
        # A fresh nonce works
        restored.encrypt("new", KEY, nonce=b"f" * 12)
        self.assertTrue(restored.verify())
        # And the new nonce is now blocked too
        with self.assertRaises(ValueError):
            restored.encrypt("y", KEY2, nonce=b"f" * 12)

    def test_indexes_restored(self):
        log = make_log()
        restored = load_secure_pruned(dump_secure_pruned(log, SEED_A), PUB_A)
        self.assertEqual(restored.find(b"plain-5"), (5,))
        self.assertEqual(restored.find_encrypted("enc-retained-a", KEY), (3,))
        self.assertEqual(restored.find_encrypted("enc-retained-b", KEY), (4,))
        # Released entries are gone from both indexes
        self.assertEqual(restored.find(b"plain-1"), ())
        self.assertEqual(restored.find_encrypted("enc-released", KEY), ())
        # Magic-prefixed payload with empty locator is still a plain entry
        self.assertEqual(
            restored.find(b"auditchain/encrypted-entry/v1\0fake"), (6,)
        )
        # Decryptability of retained ciphertexts preserved
        self.assertEqual(
            decrypt_entry(restored.entry(3), KEY), b"enc-retained-a"
        )
        # Wrong key -> no hit, no raise
        self.assertEqual(restored.find_encrypted("enc-retained-a", KEY2), ())

    def test_proofs_match(self):
        log = make_log()
        restored = load_secure_pruned(dump_secure_pruned(log, SEED_A), PUB_A)
        for index in range(3, len(log)):
            proof = restored.inclusion_proof(index)
            self.assertEqual(proof, log.inclusion_proof(index))
            self.assertTrue(
                verify_inclusion(
                    restored.entry(index).entry_hash,
                    index,
                    len(restored),
                    restored.merkle_root(),
                    proof,
                )
            )

    def test_fully_pruned(self):
        log = AuditLog()
        log.encrypt("a", KEY, nonce=N0)
        log.append("b")
        log.encrypt("c", KEY, nonce=N1)
        log.prune(3, log.seal(3))
        self.assertEqual(log.entries(), [])
        restored = load_secure_pruned(dump_secure_pruned(log, SEED_A), PUB_A)
        self.assertEqual(len(restored), 3)
        self.assertEqual(restored.retain_from, 3)
        self.assertEqual(restored.entries(), [])
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored._used_nonces, {N0, N1})
        with self.assertRaises(ValueError):
            restored.encrypt("x", KEY, nonce=N0)
        self.assertTrue(restored.verify())
        restored.append("after")
        self.assertTrue(restored.verify())

    def test_various_retain_points_and_hashes(self):
        for hash_name in ("sha256", "sha512", "sha3_256"):
            for r in range(1, 8):
                log = make_log(retain_from=r, hash_name=hash_name)
                restored = load_secure_pruned(
                    dump_secure_pruned(log, SEED_A), PUB_A
                )
                self.assertEqual(restored.retain_from, r)
                self.assertEqual(restored.head, log.head, (hash_name, r))
                self.assertEqual(restored.merkle_root(), log.merkle_root())
                self.assertEqual(restored.entries(), log.entries())
                self.assertEqual(restored._used_nonces, log._used_nonces)
                self.assertTrue(restored.verify())

    def test_all_plain_pruned_log_roundtrips_too(self):
        # No encrypted entries at all: empty nonce history section
        log = AuditLog()
        for p in ("a", "b", "c", "d"):
            log.append(p)
        log.prune(2, log.seal(2))
        restored = load_secure_pruned(dump_secure_pruned(log, SEED_A), PUB_A)
        self.assertEqual(restored.entries(), log.entries())
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored._used_nonces, set())
        self.assertTrue(restored.verify())

    def test_deterministic_and_redump(self):
        log = make_log()
        d1 = dump_secure_pruned(log, SEED_A)
        d2 = dump_secure_pruned(log, SEED_A)
        self.assertEqual(d1, d2)
        restored = load_secure_pruned(d1, PUB_A)
        self.assertEqual(dump_secure_pruned(restored, SEED_A), d1)
        # Different seed changes only the signature
        db = dump_secure_pruned(log, SEED_B)
        self.assertEqual(db[:-64], d1[:-64])
        self.assertNotEqual(db, d1)
        self.assertEqual(load_secure_pruned(db, pub(SEED_B)).head, log.head)

    def test_read_only(self):
        log = make_log()
        before = dump_secure_pruned(log, SEED_A)
        dump_secure_pruned(log, SEED_A)
        self.assertEqual(len(log), 7)
        self.assertEqual(log.retain_from, 3)
        self.assertTrue(log.verify())
        self.assertEqual(dump_secure_pruned(log, SEED_A), before)

    def test_mutability_and_independence(self):
        log = make_log()
        restored = load_secure_pruned(dump_secure_pruned(log, SEED_A), PUB_A)
        restored.append("new")
        restored.encrypt("newenc", KEY2, nonce=b"q" * 12)
        restored.prune(4, restored.seal(4))
        self.assertTrue(restored.verify())
        self.assertEqual(len(log), 7)  # source untouched

    def test_non_released_nonce_in_history(self):
        # random nonces in encrypted retained entries; dump must include them
        log = AuditLog()
        log.append("a")
        rn = os.urandom(12)
        log.encrypt("s", KEY, nonce=rn)
        log.prune(1, log.seal(1))
        restored = load_secure_pruned(dump_secure_pruned(log, SEED_A), PUB_A)
        with self.assertRaises(ValueError):
            restored.encrypt("t", KEY, nonce=rn)


class ByteLayoutTest(unittest.TestCase):
    def test_layout(self):
        log = make_log()
        data = dump_secure_pruned(log, SEED_A)
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        width = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(data[offset:offset + width], b"sha256")
        offset += width
        self.assertEqual(data[offset:offset + 8], u64(7))  # n
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(3))  # r
        offset += 8
        width = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8 + width  # checkpoint (32)
        fcount = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(fcount, 2)  # bits 0,1 of r==3
        for height in (0, 1):
            self.assertEqual(data[offset:offset + 8], u64(height))
            offset += 8
            w = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8 + w
        # nonce history: count then B(nonce) blobs, sorted
        ncount = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(ncount, 3)
        expected_nonces = sorted([N0, N1, N2])
        for nonce in expected_nonces:
            w = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            self.assertEqual(w, 12)
            self.assertEqual(data[offset:offset + 12], nonce)
            offset += 12
        # retained entries: count then E records
        ecount = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(ecount, 4)  # retained entries 3..6
        for entry in log.entries():
            self.assertEqual(data[offset:offset + 8], u64(entry.index))
            offset += 8
            for value in (
                entry.payload,
                entry.previous_hash,
                entry.entry_hash,
                log._encrypted_locators.get(entry.index, b""),
            ):
                w = int.from_bytes(data[offset:offset + 8], "big")
                offset += 8
                self.assertEqual(data[offset:offset + w], value)
                offset += w
        # B(root), B(head), signature
        for expected in (log.merkle_root(), log.head):
            w = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            self.assertEqual(data[offset:offset + w], expected)
            offset += w
        self.assertEqual(offset + 64, len(data))

    def test_magic_distinct_from_siblings(self):
        log = make_log()
        data = dump_secure_pruned(log, SEED_A)
        self.assertFalse(data.startswith(b"auditchain/pruned-log/v1\0"))
        self.assertFalse(data.startswith(b"auditchain/secure-log/v1\0"))


class EligibilityTest(unittest.TestCase):
    def test_unpruned_rejected(self):
        log = AuditLog()
        log.append("a")
        log.encrypt("s", KEY, nonce=N0)
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, SEED_A)

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            dump_secure_pruned(AuditLog(), SEED_A)

    def test_keyed_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, SEED_A)

    def test_auth_history_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.auth(0)
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, SEED_A)

    def test_rotated_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.append("a")
        log.rotate_key()
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, SEED_A)

    def test_verifier_exported_rejected(self):
        log = AuditLog(key=b"k" * 32)
        log.export_verifier()
        log.append("a")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, SEED_A)

    def test_released_ciphertext_is_allowed(self):
        log = AuditLog()
        log.encrypt("gone", KEY, nonce=N0)
        log.append("keep")
        log.append("keep2")
        log.prune(2, log.seal(2))
        self.assertEqual(log._encrypted_index, {})
        # Must NOT raise: unlike dump_pruned_log, encryption history is fine
        data = dump_secure_pruned(log, SEED_A)
        restored = load_secure_pruned(data, PUB_A)
        with self.assertRaises(ValueError):
            restored.encrypt("x", KEY, nonce=N0)

    def test_not_audit_log(self):
        for bad in (None, "x", b"x", 1, (), object(), Entry(0, b"", b"", b"")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dump_secure_pruned(bad, SEED_A)

    def test_seed_type(self):
        log = make_log()
        for bad in (None, "s", bytearray(SEED_A), memoryview(SEED_A), 1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dump_secure_pruned(log, bad)

    def test_seed_length(self):
        log = make_log()
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, b"short")
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, SEED_A + b"\0")

    def test_failed_dump_atomic(self):
        log = make_log()
        with self.assertRaises(ValueError):
            dump_secure_pruned(log, b"short")
        self.assertEqual(len(log), 7)
        self.assertTrue(log.verify())
        self.assertEqual(
            dump_secure_pruned(log, SEED_A),
            dump_secure_pruned(make_log(), SEED_A),
        )


class FramingTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.data = dump_secure_pruned(self.log, SEED_A)
        self.key = Ed25519PrivateKey.from_private_bytes(SEED_A)

    def test_data_must_be_bytes(self):
        for bad in (bytearray(self.data), memoryview(self.data), "s", None, 1, ()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                load_secure_pruned(bad, PUB_A)

    def test_pubkey_type(self):
        for bad in (None, "k", bytearray(PUB_A), memoryview(PUB_A), 1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                load_secure_pruned(self.data, bad)

    def test_pubkey_length(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(self.data, b"short")
        with self.assertRaises(ValueError):
            load_secure_pruned(self.data, PUB_A + b"\0")

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(b"x" + self.data[1:], PUB_A)
        with self.assertRaises(ValueError):
            load_secure_pruned(b"", PUB_A)
        # Sibling magics rejected
        with self.assertRaises(ValueError):
            load_secure_pruned(
                b"auditchain/pruned-log/v1\0" + self.data[len(MAGIC):], PUB_A
            )

    def test_truncation(self):
        for cut in range(len(MAGIC), len(self.data)):
            with self.assertRaises(ValueError, msg=cut):
                load_secure_pruned(self.data[:cut], PUB_A)

    def test_trailing(self):
        for extra in (b"\0", b"trailing"):
            with self.assertRaises(ValueError):
                load_secure_pruned(self.data + extra, PUB_A)

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(self.data, pub(SEED_B))

    def test_tamper(self):
        bad = bytearray(self.data)
        bad[len(self.data) // 2] ^= 0xFF
        with self.assertRaises(ValueError):
            load_secure_pruned(bytes(bad), PUB_A)

    def _signed(self, body):
        return body + self.key.sign(body)

    def _body_parts(self, *, version=1, hash_name=b"sha256", n=7, r=3,
                    checkpoint=None, frontier=None, nonces=None,
                    entries=None, locators=None, root=None, head=None):
        if checkpoint is None:
            checkpoint = self.log._checkpoint_head
        if frontier is None:
            frontier = self.log._frontier
        if nonces is None:
            nonces = sorted(self.log._used_nonces)
        if entries is None:
            entries = self.log.entries()
        if locators is None:
            locators = [
                self.log._encrypted_locators.get(e.index, b"") for e in entries
            ]
        if root is None:
            root = self.log.merkle_root()
        if head is None:
            head = self.log.head
        parts = [
            MAGIC, u64(version), blob(hash_name), u64(n), u64(r),
            blob(checkpoint), u64(len(frontier)),
        ]
        for h in sorted(frontier):
            parts.append(u64(h))
            parts.append(blob(frontier[h]))
        parts.append(u64(len(nonces)))
        for nonce in nonces:
            parts.append(blob(nonce))
        parts.append(u64(len(entries)))
        for entry, locator in zip(entries, locators):
            parts.extend((
                u64(entry.index), blob(entry.payload),
                blob(entry.previous_hash), blob(entry.entry_hash),
                blob(locator),
            ))
        parts.append(blob(root))
        parts.append(blob(head))
        return b"".join(parts)

    def test_bad_version(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(self._signed(self._body_parts(version=2)), PUB_A)

    def test_bad_utf8(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(hash_name=b"\xff")), PUB_A
            )

    def test_unknown_hash(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(hash_name=b"nope")), PUB_A
            )

    def test_r_zero_and_beyond_n(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(self._signed(self._body_parts(r=0)), PUB_A)
        with self.assertRaises(ValueError):
            load_secure_pruned(self._signed(self._body_parts(r=7)), PUB_A)

    def test_frontier_must_be_set_bits(self):
        frontier = {1: self.log._frontier[1]}  # missing bit 0
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(frontier=frontier)), PUB_A
            )

    def test_nonce_wrong_width(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(nonces=[b"11" * 6 + b"\x00"])),
                PUB_A,
            )

    def test_nonce_unsorted(self):
        nonces = sorted(self.log._used_nonces)
        nonces[0], nonces[1] = nonces[1], nonces[0]
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(nonces=nonces)), PUB_A
            )

    def test_nonce_duplicate(self):
        nonces = sorted(self.log._used_nonces)
        nonces.append(nonces[-1])
        # equal adjacent -> ordering check rejects
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(nonces=nonces)), PUB_A
            )

    def test_extra_history_nonce_is_fine(self):
        # History may contain a nonce of a fully-released ciphertext; an extra
        # unknown nonce in history is not contradicted by anything retained.
        extra = b"\xff" * 12
        nonces = sorted(self.log._used_nonces | {extra})
        restored = load_secure_pruned(
            self._signed(self._body_parts(nonces=nonces)), PUB_A
        )
        with self.assertRaises(ValueError):
            restored.encrypt("x", KEY, nonce=extra)

    def test_missing_retained_nonce_rejected(self):
        # Drop N1 (nonce of retained entry 2): entry still carries locator
        nonces = [n for n in sorted(self.log._used_nonces) if n != N1]
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(nonces=nonces)), PUB_A
            )

    def test_locator_width(self):
        entries = self.log.entries()
        locators = [b"\x00" * 31 if e.index == 3
                    else self.log._encrypted_locators.get(e.index, b"")
                    for e in entries]
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(locators=locators)), PUB_A
            )

    def test_bad_envelope_with_locator(self):
        entries = list(self.log.entries())
        i = next(i for i, e in enumerate(entries) if e.index == 3)
        entries[i] = Entry(
            entries[i].index, b"not-an-envelope",
            entries[i].previous_hash, entries[i].entry_hash,
        )
        # entry_hash now mismatches the chain too; envelope parsing/chain
        # either way must reject
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(entries=entries)), PUB_A
            )

    def test_entry_count_mismatch(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(
                    self._body_parts(entries=self.log.entries()[:-1])
                ),
                PUB_A,
            )

    def test_bad_chain_root_head(self):
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(head=b"\0" * 32)), PUB_A
            )
        with self.assertRaises(ValueError):
            load_secure_pruned(
                self._signed(self._body_parts(root=b"\0" * 32)), PUB_A
            )


class CrossMagicTest(unittest.TestCase):
    def test_secure_pruned_bytes_rejected_by_sibling_loaders(self):
        from auditchain import load_pruned_log, load_secure_log
        log = make_log()
        data = dump_secure_pruned(log, SEED_A)
        with self.assertRaises(ValueError):
            load_pruned_log(data, PUB_A)
        with self.assertRaises(ValueError):
            load_secure_log(data, PUB_A)


if __name__ == "__main__":
    unittest.main()
