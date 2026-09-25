import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    dump_signed_pruned_hybrid,
    load_signed_pruned_hybrid,
    verify_auth,
)

MAGIC = b"auditchain/signed-pruned-hybrid/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_ENC_KEY = bytes(range(65, 97))


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


def _make_log(retain_from=2):
    log = AuditLog(key=b"shared-secret")
    verifier = log.export_verifier()
    log.append("plain one")                                # 0: released
    log.encrypt("released secret", _ENC_KEY, nonce=b"1" * 12)  # 1: released
    tag1 = log.auth(1)                                     # stage -> 1
    log.append(b"plain two")                               # 2: retained plain
    log.rotate_key()                                       # stage -> 2
    log.encrypt(b"kept secret", _ENC_KEY, nonce=b"\x07" * 12)  # 3: retained
    tag3 = log.auth(3)                                     # stage -> 3
    log.prune(retain_from, log.seal(retain_from))
    return log, verifier, tag1, tag3


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
    parts.append(u64(len(log._used_nonces)))
    for used_nonce in sorted(log._used_nonces):
        parts.append(blob(used_nonce))
    parts.append(u64(len(log._entries)))
    for entry in log._entries:
        locator = log._encrypted_locators.get(entry.index, b"")
        parts.append(u64(entry.index))
        parts.append(blob(entry.payload))
        parts.append(blob(entry.previous_hash))
        parts.append(blob(entry.entry_hash))
        parts.append(blob(locator))
    parts.append(blob(root))
    parts.append(blob(head))
    parts.append(u64(log.stage))
    parts.append(blob(log._key))
    parts.append(u64(1 if log._verifier_exported else 0))
    return b"".join(parts)


def _encode(log, seed=_SEED_A):
    body = MAGIC + u64(1) + _frame(log, log.merkle_root(), log.head)
    return body + _sign(seed, body)


class DumpSignedPrunedHybridTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag1, self.tag3 = _make_log()

    def test_wire_layout(self):
        data = dump_signed_pruned_hybrid(self.log, _SEED_A)
        self.assertTrue(data.startswith(MAGIC + u64(1)))
        self.assertEqual(data, _encode(self.log))
        # The trailing 64 bytes are an Ed25519 signature over the body.
        body, signature = data[:-64], data[-64:]
        Ed25519PrivateKey.from_private_bytes(_SEED_A).public_key().verify(
            signature, body
        )
        # The frame is plaintext: the evolution key is visible in the stream.
        self.assertIn(self.log._key, data)
        # No symmetric envelope of the pruned-hybrid wire format is used here.
        self.assertFalse(data.startswith(b"auditchain/pruned-hybrid/v1\0"))

    def test_deterministic_and_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"plain two"),
            self.log.find_encrypted(b"kept secret", _ENC_KEY),
            dict(self.log._frontier),
            self.log._checkpoint_head,
            frozenset(self.log._used_nonces),
            self.log._key,
        )
        first = dump_signed_pruned_hybrid(self.log, _SEED_A)
        second = dump_signed_pruned_hybrid(self.log, _SEED_A)
        self.assertEqual(first, second)
        after = (
            len(self.log),
            self.log.head,
            self.log.stage,
            self.log.retain_from,
            self.log.merkle_root(),
            self.log.find(b"plain two"),
            self.log.find_encrypted(b"kept secret", _ENC_KEY),
            dict(self.log._frontier),
            self.log._checkpoint_head,
            frozenset(self.log._used_nonces),
            self.log._key,
        )
        self.assertEqual(before, after)

    def test_distinct_seeds_differ_only_in_signature(self):
        first = dump_signed_pruned_hybrid(self.log, _SEED_A)
        second = dump_signed_pruned_hybrid(self.log, _SEED_B)
        self.assertEqual(first[:-64], second[:-64])
        self.assertNotEqual(first[-64:], second[-64:])

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            dump_signed_pruned_hybrid("not a log", _SEED_A)
        with self.assertRaises(TypeError):
            dump_signed_pruned_hybrid(self.log, "not bytes")
        with self.assertRaises(TypeError):
            dump_signed_pruned_hybrid(self.log, bytearray(_SEED_A))

    def test_seed_length(self):
        with self.assertRaises(ValueError):
            dump_signed_pruned_hybrid(self.log, b"short")
        with self.assertRaises(ValueError):
            dump_signed_pruned_hybrid(self.log, b"s" * 33)

    def test_unpruned_log_rejected(self):
        log = AuditLog(key=b"k")
        log.append("x")
        log.encrypt(b"secret", _ENC_KEY)
        with self.assertRaises(ValueError):
            dump_signed_pruned_hybrid(log, _SEED_A)

    def test_keyless_log_rejected_even_pruned(self):
        log = AuditLog()
        for i in range(4):
            log.append(f"r{i}")
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            dump_signed_pruned_hybrid(log, _SEED_A)

    def test_allows_released_ciphertext_history(self):
        # The released ciphertext's nonce survives in the complete history.
        self.assertEqual(self.log._used_nonces, {b"1" * 12, b"\x07" * 12})
        data = dump_signed_pruned_hybrid(self.log, _SEED_A)
        restored = load_signed_pruned_hybrid(data, PUBLIC_A)
        self.assertTrue(restored.verify())


class LoadSignedPrunedHybridTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag1, self.tag3 = _make_log()
        self.data = dump_signed_pruned_hybrid(self.log, _SEED_A)

    def test_round_trip_state(self):
        restored = load_signed_pruned_hybrid(self.data, PUBLIC_A)
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.stage, self.log.stage)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(restored.retain_from, self.log.retain_from)
        self.assertEqual(restored._checkpoint_head, self.log._checkpoint_head)
        self.assertEqual(restored._frontier, self.log._frontier)
        self.assertEqual(restored.hash_name, self.log.hash_name)
        for entry in self.log:
            self.assertEqual(restored.entry(entry.index), entry)
        self.assertEqual(restored.find(b"plain two"), self.log.find(b"plain two"))
        self.assertEqual(
            restored.find_encrypted(b"kept secret", _ENC_KEY),
            self.log.find_encrypted(b"kept secret", _ENC_KEY),
        )
        # The complete lifetime nonce history, including the released
        # ciphertext's nonce, is restored.
        self.assertEqual(restored._used_nonces, self.log._used_nonces)
        self.assertTrue(restored.verify())

    def test_evolution_continues_identically(self):
        restored = load_signed_pruned_hybrid(self.data, PUBLIC_A)
        # Continue both logs identically: the freshly minted tags must match
        # byte-for-byte and verify against the exported stage-0 verifier.
        self.log.append("more")
        restored.append("more")
        original_tag = self.log.auth(4)
        restored_tag = restored.auth(4)
        self.assertEqual(restored_tag, original_tag)
        self.assertEqual(restored.stage, self.log.stage)
        self.assertTrue(
            verify_auth(self.log.entry(4), original_tag, self.verifier)
        )
        self.assertTrue(
            verify_auth(restored.entry(4), restored_tag, self.verifier)
        )
        # The carried historical tag of a retained entry still verifies.
        self.assertTrue(verify_auth(restored.entry(3), self.tag3, self.verifier))

    def test_verifier_exported_flag_restored(self):
        restored = load_signed_pruned_hybrid(self.data, PUBLIC_A)
        # The source already exported its stage-0 verifier; the restore must
        # not allow a second export.
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_unexported_flag_restored(self):
        log = AuditLog(key=b"k")
        for i in range(3):
            log.append(f"x{i}")
        log.prune(1, log.seal(1))
        restored = load_signed_pruned_hybrid(
            dump_signed_pruned_hybrid(log, _SEED_A), PUBLIC_A
        )
        verifier = restored.export_verifier()
        self.assertEqual(verifier.key, b"k")

    def test_nonce_history_restored_and_enforced(self):
        restored = load_signed_pruned_hybrid(self.data, PUBLIC_A)
        self.assertEqual(restored._used_nonces, {b"1" * 12, b"\x07" * 12})
        # Old nonces are still rejected after the restore — both the retained
        # ciphertext's and the released ciphertext's.
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=b"\x07" * 12)
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=b"1" * 12)
        # A fresh nonce is accepted.
        restored.encrypt("again", _ENC_KEY, nonce=b"2" * 12)

    def test_restored_log_is_independent_and_mutable(self):
        restored = load_signed_pruned_hybrid(self.data, PUBLIC_A)
        restored.append("e")
        restored.encrypt(b"hidden", b"k" * 32, nonce=b"0" * 12)
        restored.rotate_key()
        self.assertEqual(len(self.log), 4)
        self.assertEqual(self.log.stage, 3)
        self.assertEqual(len(restored), 6)
        self.assertEqual(restored.stage, 4)
        # The shared retained prefix is untouched on the original.
        for entry in self.log:
            self.assertEqual(restored.entry(entry.index), entry)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            load_signed_pruned_hybrid(bytearray(self.data), PUBLIC_A)
        with self.assertRaises(TypeError):
            load_signed_pruned_hybrid(memoryview(self.data), PUBLIC_A)
        with self.assertRaises(TypeError):
            load_signed_pruned_hybrid(self.data, "not bytes")
        with self.assertRaises(TypeError):
            load_signed_pruned_hybrid(self.data, bytearray(PUBLIC_A))

    def test_public_key_length(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self.data, b"short")
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self.data, b"p" * 33)

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                b"auditchain/signed-pruned-hybrid/v2\0"
                + self.data[len(MAGIC):],
                PUBLIC_A,
            )
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(b"", PUBLIC_A)

    def test_bad_version(self):
        body = MAGIC + u64(2) + self.data[len(MAGIC) + 8:-64]
        data = body + _sign(_SEED_A, body)
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(data, PUBLIC_A)

    def test_truncation(self):
        for cut in (len(MAGIC), len(self.data) - 65, len(self.data) - 1, 0):
            with self.assertRaises(ValueError):
                load_signed_pruned_hybrid(self.data[:cut], PUBLIC_A)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self.data + b"x", PUBLIC_A)

    def test_signature_failure(self):
        # Wrong public key.
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self.data, PUBLIC_B)
        # A flipped body byte invalidates the signature (verification first).
        flipped = bytearray(self.data)
        flipped[len(MAGIC) + 12] ^= 1
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(bytes(flipped), PUBLIC_A)
        # A flipped signature byte.
        flipped = bytearray(self.data)
        flipped[-1] ^= 1
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(bytes(flipped), PUBLIC_A)

    def test_other_hash_algorithms(self):
        for hash_name in ("sha512", "sha3-256"):
            log = AuditLog(key=b"k", hash_name=hash_name)
            log.append("plain")
            log.encrypt(b"secret", _ENC_KEY, nonce=b"n" * 12)
            log.append("kept")
            log.auth(2)
            log.prune(1, log.seal(1))
            data = dump_signed_pruned_hybrid(log, _SEED_A)
            restored = load_signed_pruned_hybrid(data, PUBLIC_A)
            self.assertEqual(restored.hash_name, hash_name)
            self.assertEqual(restored.head, log.head)
            self.assertEqual(restored.merkle_root(), log.merkle_root())
            self.assertEqual(restored.stage, log.stage)
            self.assertEqual(restored.retain_from, 1)
            self.assertEqual(
                restored.find_encrypted(b"secret", _ENC_KEY), (1,)
            )
            log.append("next")
            restored.append("next")
            self.assertEqual(restored.auth(3), log.auth(3))


class LoadSignedPrunedHybridFrameValidationTest(unittest.TestCase):
    """Valid signatures whose signed frame violates the framing."""

    def setUp(self):
        self.log, _verifier, _tag1, _tag3 = _make_log()
        self.good = dump_signed_pruned_hybrid(self.log, _SEED_A)
        self.fields = self._parse(self.good[:-64][len(MAGIC) + 8:])

    @staticmethod
    def _parse(data):
        cursor = 0

        def take_u64():
            nonlocal cursor
            value = int.from_bytes(data[cursor:cursor + 8], "big")
            cursor += 8
            return value

        def take_blob():
            nonlocal cursor
            length = take_u64()
            value = data[cursor:cursor + length]
            cursor += length
            return value

        name = take_blob()
        size = take_u64()
        retain_from = take_u64()
        checkpoint = take_blob()
        frontier_count = take_u64()
        frontier = [(take_u64(), take_blob()) for _ in range(frontier_count)]
        nonce_count = take_u64()
        nonces = [take_blob() for _ in range(nonce_count)]
        count = take_u64()
        entries = []
        for _ in range(count):
            entries.append(
                (take_u64(), take_blob(), take_blob(), take_blob(), take_blob())
            )
        tail = (take_blob(), take_blob(), take_u64(), take_blob(), take_u64())
        assert cursor == len(data)
        return name, size, retain_from, checkpoint, frontier, nonces, entries, tail

    @staticmethod
    def _build(name, size, retain_from, checkpoint, frontier, nonces, entries, tail):
        parts = [blob(name), u64(size), u64(retain_from), blob(checkpoint)]
        parts.append(u64(len(frontier)))
        for height, digest in frontier:
            parts.append(u64(height))
            parts.append(blob(digest))
        parts.append(u64(len(nonces)))
        for used_nonce in nonces:
            parts.append(blob(used_nonce))
        parts.append(u64(len(entries)))
        for index, payload, previous_hash, entry_hash, locator in entries:
            parts += [
                u64(index),
                blob(payload),
                blob(previous_hash),
                blob(entry_hash),
                blob(locator),
            ]
        root, head, stage, key_material, exported = tail
        parts += [
            blob(root),
            blob(head),
            u64(stage),
            blob(key_material),
            u64(exported),
        ]
        return b"".join(parts)

    def _forge(self, seed=_SEED_A, **overrides):
        fields = list(self.fields)
        names = (
            "name", "size", "retain_from", "checkpoint",
            "frontier", "nonces", "entries", "tail",
        )
        for key, value in overrides.items():
            fields[names.index(key)] = value
        frame = self._build(*fields)
        body = MAGIC + u64(1) + frame
        return body + _sign(seed, body)

    def test_baseline_loads(self):
        self.assertEqual(
            load_signed_pruned_hybrid(self.good, PUBLIC_A).head, self.log.head
        )

    def test_trailing_bytes_in_frame(self):
        frame = self._build(*self.fields)
        body = MAGIC + u64(1) + frame + b"\x00"
        data = body + _sign(_SEED_A, body)
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(data, PUBLIC_A)

    def test_truncated_frame(self):
        frame = self._build(*self.fields)
        body = MAGIC + u64(1) + frame[:-1]
        data = body + _sign(_SEED_A, body)
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(data, PUBLIC_A)

    def test_bad_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(name=b"\xff\xff"), PUBLIC_A)

    def test_unknown_hash(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(name=b"nonesuch"), PUBLIC_A)

    def test_retain_from_out_of_range(self):
        _n, size, _r, _c, _f, _q, _e, _t = self.fields
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(retain_from=0), PUBLIC_A)
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(retain_from=size + 1), PUBLIC_A
            )

    def test_checkpoint_wrong_width(self):
        _n, _s, _r, checkpoint, _f, _q, _e, _t = self.fields
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(checkpoint=checkpoint[:-1]), PUBLIC_A
            )

    def test_frontier_not_set_bits_of_retain_from(self):
        _n, _s, _r, _c, frontier, _q, _e, _t = self.fields
        digest_size = len(frontier[0][1])
        forged = [(0, bytes(digest_size))] + frontier
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(frontier=forged), PUBLIC_A)

    def test_frontier_heights_out_of_order(self):
        _n, _s, retain_from, _c, frontier, _q, _e, _t = self.fields
        # retain_from = 2 has a single set bit; a log pruned at 3 has two.
        log = AuditLog(key=b"k")
        for i in range(5):
            log.append(f"x{i}")
        log.prune(3, log.seal(3))
        data = dump_signed_pruned_hybrid(log, _SEED_A)
        fields = self._parse(data[:-64][len(MAGIC) + 8:])
        frontier = list(reversed(fields[4]))
        frame = self._build(
            fields[0], fields[1], fields[2], fields[3],
            frontier, fields[5], fields[6], fields[7],
        )
        body = MAGIC + u64(1) + frame
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(body + _sign(_SEED_A, body), PUBLIC_A)

    def test_nonce_wrong_width(self):
        _n, _s, _r, _c, _f, nonces, _e, _t = self.fields
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(nonces=[nonces[0][:-1]] + nonces[1:]), PUBLIC_A
            )

    def test_nonces_out_of_order(self):
        _n, _s, _r, _c, _f, nonces, _e, _t = self.fields
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(nonces=list(reversed(nonces))), PUBLIC_A
            )

    def test_nonce_duplicated_in_history(self):
        _n, _s, _r, _c, _f, nonces, _e, _t = self.fields
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(nonces=[nonces[0]] + nonces), PUBLIC_A
            )

    def test_retained_count_disagrees_with_size(self):
        _n, size, retain_from, _c, _f, _q, _e, _t = self.fields
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(size=size + 1), PUBLIC_A)

    def test_bad_entry_index(self):
        entries = [
            (
                index + 1 if i == 0 else index,
                payload,
                previous_hash,
                entry_hash,
                locator,
            )
            for i, (index, payload, previous_hash, entry_hash, locator) in enumerate(
                self.fields[6]
            )
        ]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_bad_entry_digest_width(self):
        index, payload, previous_hash, entry_hash, locator = self.fields[6][0]
        entries = [
            (index, payload, previous_hash, entry_hash[:-1], locator)
        ] + self.fields[6][1:]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_broken_chain_rejected(self):
        # Swapping two payloads keeps widths intact but breaks the chain.
        entries = list(self.fields[6])
        first, second = entries[0], entries[1]
        entries[0] = (first[0], second[1], first[2], first[3], first[4])
        entries[1] = (second[0], first[1], second[2], second[3], second[4])
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_locator_wrong_width(self):
        entries = list(self.fields[6])
        index, payload, previous_hash, entry_hash, locator = entries[1]
        entries[1] = (index, payload, previous_hash, entry_hash, locator[:-1])
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_retained_nonce_missing_from_history(self):
        # Drop the retained ciphertext's nonce from the declared history.
        _n, _s, _r, _c, _f, nonces, _e, _t = self.fields
        kept = [nonce for nonce in nonces if nonce != b"\x07" * 12]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(nonces=kept), PUBLIC_A)

    def test_unparseable_ciphertext_envelope(self):
        # A non-empty locator whose payload is not an encrypted-entry envelope.
        entries = list(self.fields[6])
        index, _payload, previous_hash, entry_hash, locator = entries[1]
        entries[1] = (index, b"not an envelope", previous_hash, entry_hash, locator)
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=entries), PUBLIC_A)

    def test_exported_flag_out_of_range(self):
        root, head, stage, key_material, _exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(root, head, stage, key_material, 2)),
                PUBLIC_A,
            )

    def test_evolution_key_empty(self):
        root, head, stage, _key_material, exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(root, head, stage, b"", exported)),
                PUBLIC_A,
            )

    def test_evolution_key_wrong_width_after_evolution(self):
        # stage is 3 here, so K must be exactly one digest wide.
        root, head, stage, key_material, exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(root, head, stage, key_material + b"\x00", exported)),
                PUBLIC_A,
            )

    def test_recomputed_head_mismatch(self):
        root, head, stage, key_material, exported = self.fields[7]
        wrong = bytes(b ^ 1 for b in head)
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(root, wrong, stage, key_material, exported)),
                PUBLIC_A,
            )

    def test_recomputed_root_mismatch(self):
        root, head, stage, key_material, exported = self.fields[7]
        wrong = bytes(b ^ 1 for b in root)
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(wrong, head, stage, key_material, exported)),
                PUBLIC_A,
            )


if __name__ == "__main__":
    unittest.main()
