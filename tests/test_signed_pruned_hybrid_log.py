import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    Verifier,
    decrypt_entry,
    dump_signed_pruned_hybrid,
    dump_pruned_hybrid,
    entry_digest,
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
    log.append("plain one")                                   # 0: released
    log.encrypt("released secret", _ENC_KEY, nonce=b"1" * 12)  # 1: released
    tag1 = log.auth(1)                           # stage -> 1; tag released
    log.append(b"plain two")                                  # 2: retained
    log.rotate_key()                                          # stage -> 2
    log.encrypt(b"kept secret", _ENC_KEY, nonce=b"\x07" * 12)  # 3: retained
    tag3 = log.auth(3)                                        # stage -> 3
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
    for entry in log:
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
    root = log.merkle_root()
    head = log.head
    body = MAGIC + u64(1) + _frame(log, root, head)
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
        # No symmetric envelope of the pruned-hybrid wire format is used.
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
        log.append("r0")
        log.encrypt("secret", _ENC_KEY)
        with self.assertRaises(ValueError):
            dump_signed_pruned_hybrid(log, _SEED_A)

    def test_keyless_pruned_log_rejected(self):
        log = AuditLog()
        for i in range(4):
            log.append(f"r{i}")
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            dump_signed_pruned_hybrid(log, _SEED_A)

    def test_allows_encrypted_history(self):
        # The main point of this variant: pruned history, including the
        # ciphertext released by the prune, is fine.
        data = dump_signed_pruned_hybrid(self.log, _SEED_A)
        self.assertTrue(load_signed_pruned_hybrid(data, PUBLIC_A).verify())

    def test_allows_plain_only_pruned_log(self):
        log = AuditLog(key=b"k")
        log.append("a")
        log.append("b")
        log.auth(0)
        log.prune(1, log.seal(1))
        data = dump_signed_pruned_hybrid(log, _SEED_A)
        restored = load_signed_pruned_hybrid(data, PUBLIC_A)
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored._used_nonces, set())

    def test_failure_is_atomic(self):
        with self.assertRaises(ValueError):
            dump_signed_pruned_hybrid(self.log, b"short")
        self.assertEqual(len(self.log), 4)
        self.assertEqual(self.log.stage, 3)
        # The log still dumps fine after the failed attempt.
        load_signed_pruned_hybrid(
            dump_signed_pruned_hybrid(self.log, _SEED_A), PUBLIC_A
        )


class LoadSignedPrunedHybridRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.log, self.verifier, self.tag1, self.tag3 = _make_log()
        self.data = dump_signed_pruned_hybrid(self.log, _SEED_A)

    def _restore(self):
        return load_signed_pruned_hybrid(self.data, PUBLIC_A)

    def test_length_retain_point_head_root_match(self):
        restored = self._restore()
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, 2)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(restored.stage, self.log.stage)
        self.assertEqual(restored.hash_name, self.log.hash_name)
        self.assertTrue(restored.verify())

    def test_checkpoint_and_frontier_match(self):
        restored = self._restore()
        self.assertEqual(restored._checkpoint_head, self.log._checkpoint_head)
        self.assertEqual(restored._frontier, self.log._frontier)

    def test_absolute_indices_and_retained_entries(self):
        restored = self._restore()
        # Absolute indices survive: retained entries stay at 2..n-1.
        self.assertEqual([e.index for e in restored], [2, 3])
        self.assertEqual(restored.entries(), self.log.entries())
        with self.assertRaises(IndexError):
            restored.entry(0)
        with self.assertRaises(IndexError):
            restored.entry(1)

    def test_find_index_covers_only_retained(self):
        restored = self._restore()
        self.assertEqual(restored.find(b"plain two"), (2,))
        self.assertEqual(restored.find(b"missing"), ())
        # The released plain entry is not in the find index.
        self.assertEqual(restored.find(b"plain one"), ())

    def test_encrypted_locator_index_covers_only_retained(self):
        restored = self._restore()
        self.assertEqual(restored.find_encrypted(b"kept secret", _ENC_KEY), (3,))
        self.assertEqual(restored.find_encrypted(b"nonesuch", _ENC_KEY), ())
        # The released ciphertext is not locatable.
        self.assertEqual(
            restored.find_encrypted(b"released secret", _ENC_KEY), ()
        )

    def test_retained_ciphertext_still_decrypts(self):
        restored = self._restore()
        self.assertEqual(decrypt_entry(restored.entry(3), _ENC_KEY), b"kept secret")

    def test_verifier_flag_restored(self):
        self.assertTrue(self._restore()._verifier_exported)
        with self.assertRaises(ValueError):
            self._restore().export_verifier()

    def test_verifier_flag_zero_allows_export(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.encrypt("s", _ENC_KEY)
        log.prune(1, log.seal(1))
        restored = load_signed_pruned_hybrid(
            dump_signed_pruned_hybrid(log, _SEED_A), PUBLIC_A
        )
        verifier = restored.export_verifier()
        self.assertIsInstance(verifier, Verifier)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_complete_nonce_history_restored(self):
        restored = self._restore()
        self.assertEqual(restored._used_nonces, self.log._used_nonces)
        # The history covers two nonces: one retained, one released.
        self.assertEqual(restored._used_nonces, {b"1" * 12, b"\x07" * 12})
        # The retained ciphertext's nonce is still rejected after restore.
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=b"\x07" * 12)
        # The released ciphertext's nonce is rejected too.
        with self.assertRaises(ValueError):
            restored.encrypt("again", _ENC_KEY, nonce=b"1" * 12)
        # A genuinely fresh nonce works.
        restored.encrypt("again", _ENC_KEY, nonce=b"\x08" * 12)
        self.assertEqual(restored.find_encrypted(b"again", _ENC_KEY), (4,))

    def test_forward_security_continues_identically(self):
        restored = self._restore()
        self.log.append("f")
        restored.append("f")
        tag_orig = self.log.auth(4)
        tag_rest = restored.auth(4)
        self.assertEqual(tag_orig, tag_rest)
        self.assertEqual(self.log.stage, restored.stage)
        # Old verifier material still verifies tags from both processes.
        self.assertTrue(verify_auth(restored.entry(3), self.tag3, self.verifier))
        self.assertTrue(verify_auth(restored.entry(4), tag_orig, self.verifier))

    def test_encrypted_append_continues_identically(self):
        restored = self._restore()
        self.log.encrypt(b"later secret", _ENC_KEY, nonce=b"\x55" * 12)
        restored.encrypt(b"later secret", _ENC_KEY, nonce=b"\x55" * 12)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(self.log.auth(4), restored.auth(4))

    def test_independent_and_mutable(self):
        restored = self._restore()
        restored.append("separate")
        self.assertEqual(len(restored), len(self.log) + 1)
        restored.rotate_key()
        self.assertEqual(restored.stage, self.log.stage + 1)
        self.assertEqual(len(self.log), 4)

    def test_snapshots_and_proofs_match_original(self):
        restored = self._restore()
        for size in (2, 3, 4):
            self.assertEqual(
                restored.merkle_root(size), self.log.merkle_root(size)
            )
        self.assertEqual(
            restored.inclusion_proof(3, 4), self.log.inclusion_proof(3, 4)
        )
        self.assertEqual(
            restored.consistency_proof(2, 4),
            self.log.consistency_proof(2, 4),
        )
        self.assertEqual(restored.merkle_root(0), self.log.merkle_root(0))

    def test_supports_further_pruning(self):
        restored = self._restore()
        restored.prune(3, restored.seal(3))
        self.assertEqual(restored.retain_from, 3)
        self.assertEqual([e.index for e in restored], [3])
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        # The fully re-pruned log dumps and loads again.
        again = load_signed_pruned_hybrid(
            dump_signed_pruned_hybrid(restored, _SEED_A), PUBLIC_A
        )
        self.assertEqual(again.head, self.log.head)
        self.assertEqual(again.retain_from, 3)

    def test_fully_pruned_round_trip(self):
        log = AuditLog(key=b"shared-secret")
        log.append("a")
        log.encrypt("s", _ENC_KEY)
        log.prune(2, log.seal(2))
        restored = load_signed_pruned_hybrid(
            dump_signed_pruned_hybrid(log, _SEED_A), PUBLIC_A
        )
        self.assertEqual(restored.retain_from, 2)
        self.assertEqual(len(restored), 2)
        self.assertEqual(list(restored), [])
        self.assertEqual(restored.head, log.head)
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored._used_nonces, log._used_nonces)

    def test_non_default_hash(self):
        for hash_name in ("sha512", "sha3-256"):
            log = AuditLog(key=b"shared-secret", hash_name=hash_name)
            log.append("a")
            log.encrypt("released", _ENC_KEY, nonce=b"n" * 12)
            log.auth(1)
            log.append("b")
            log.encrypt("kept", _ENC_KEY, nonce=b"\x09" * 12)
            log.prune(2, log.seal(2))
            restored = load_signed_pruned_hybrid(
                dump_signed_pruned_hybrid(log, _SEED_A), PUBLIC_A
            )
            self.assertEqual(restored.hash_name, hash_name)
            self.assertEqual(restored.head, log.head)
            self.assertEqual(restored.merkle_root(), log.merkle_root())
            self.assertEqual(
                restored.find_encrypted(b"kept", _ENC_KEY), (3,)
            )
            log.append("c")
            restored.append("c")
            self.assertEqual(log.auth(2), restored.auth(2))


class LoadSignedPrunedHybridWireErrorsTest(unittest.TestCase):
    def setUp(self):
        self.log, _v, _t1, _t3 = _make_log()
        self.data = dump_signed_pruned_hybrid(self.log, _SEED_A)

    def test_data_type(self):
        for bad in (bytearray(self.data), memoryview(self.data), "x", 42):
            with self.assertRaises(TypeError):
                load_signed_pruned_hybrid(bad, PUBLIC_A)

    def test_public_key_type(self):
        for bad in ("p" * 32, bytearray(32), memoryview(bytes(32)), None):
            with self.assertRaises(TypeError):
                load_signed_pruned_hybrid(self.data, bad)

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

    def test_truncated(self):
        for cut in (
            0,
            len(MAGIC),
            len(self.data) - 65,
            len(self.data) - 1,
        ):
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

    def test_signature_checked_before_frame(self):
        # A frame with invalid UTF-8 signed by the wrong seed must fail as a
        # signature error, never parse: sign with seed B, verify with A.
        body = MAGIC + u64(1) + b"\xff" * 40
        data = body + _sign(_SEED_B, body)
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(data, PUBLIC_A)

    def test_symmetric_dump_does_not_load(self):
        symmetric = dump_pruned_hybrid(self.log, bytes(range(1, 33)))
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(symmetric, PUBLIC_A)

    def test_load_is_read_only(self):
        view = bytes(self.data)
        load_signed_pruned_hybrid(view, PUBLIC_A)
        self.assertEqual(view, self.data)


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
        total = take_u64()
        retain_from = take_u64()
        checkpoint = take_blob()
        frontier_count = take_u64()
        frontier = []
        for _ in range(frontier_count):
            frontier.append((take_u64(), take_blob()))
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
        return name, total, retain_from, checkpoint, frontier, nonces, entries, tail

    @staticmethod
    def _build(name, total, retain_from, checkpoint, frontier, nonces, entries, tail):
        parts = [
            blob(name),
            u64(total),
            u64(retain_from),
            blob(checkpoint),
            u64(len(frontier)),
        ]
        for height, digest in frontier:
            parts += [u64(height), blob(digest)]
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
        (name, total, retain_from, checkpoint, frontier,
         nonces, entries, tail) = self.fields
        frame = self._build(
            overrides.get("name", name),
            overrides.get("total", total),
            overrides.get("retain_from", retain_from),
            overrides.get("checkpoint", checkpoint),
            overrides.get("frontier", frontier),
            overrides.get("nonces", nonces),
            overrides.get("entries", entries),
            overrides.get("tail", tail),
        )
        body = MAGIC + u64(1) + frame
        return body + _sign(seed, body)

    def test_baseline_loads(self):
        self.assertEqual(
            load_signed_pruned_hybrid(self.good, PUBLIC_A).head, self.log.head
        )

    def test_extra_history_nonce_loads(self):
        # A nonce history beyond the retained ciphertexts is expected: it
        # accounts for ciphertexts released by the prune.
        _n, _t, _r, _c, _f, nonces, _e, _tail = self.fields
        extra = sorted(nonces + [b"\xee" * 12])
        restored = load_signed_pruned_hybrid(self._forge(nonces=extra), PUBLIC_A)
        self.assertEqual(restored.head, self.log.head)
        self.assertIn(b"\xee" * 12, restored._used_nonces)
        with self.assertRaises(ValueError):
            restored.encrypt("x", _ENC_KEY, nonce=b"\xee" * 12)

    def test_trailing_bytes(self):
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

    def test_retain_zero(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(retain_from=0), PUBLIC_A)

    def test_retain_above_total(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(retain_from=5), PUBLIC_A)

    def test_bad_checkpoint_width(self):
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(checkpoint=b"x" * 31), PUBLIC_A
            )

    def test_frontier_digest_wrong_width(self):
        _n, _t, _r, _c, frontier, _no, _e, _ta = self.fields
        height, digest = frontier[0]
        broken = [(height, digest[:-1])] + frontier[1:]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(frontier=broken), PUBLIC_A)

    def test_frontier_not_set_bits(self):
        _n, _t, _r, _c, frontier, _no, _e, _ta = self.fields
        height, digest = frontier[0]
        broken = [(height + 1, digest)] + frontier[1:]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(frontier=broken), PUBLIC_A)

    def test_nonce_wrong_width(self):
        _n, _t, _r, _c, _f, nonces, _e, _ta = self.fields
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(nonces=[n[:-1] for n in nonces]), PUBLIC_A
            )

    def test_nonces_out_of_order(self):
        _n, _t, _r, _c, _f, nonces, _e, _ta = self.fields
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(nonces=list(reversed(nonces))), PUBLIC_A
            )

    def test_nonce_duplicated_in_history(self):
        _n, _t, _r, _c, _f, nonces, _e, _ta = self.fields
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(nonces=[nonces[0], nonces[0]]), PUBLIC_A
            )

    def test_retained_nonce_missing_from_history(self):
        # Drop the retained ciphertext's nonce (keep the released one).
        _n, _t, _r, _c, _f, nonces, _e, _ta = self.fields
        kept = [n for n in nonces if n != b"\x07" * 12]
        self.assertEqual(kept, [b"1" * 12])
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(nonces=kept), PUBLIC_A)

    def test_entry_count_mismatch(self):
        # Lie that one entry is retained while two records remain in the
        # stream: the parse desyncs and the tail fields must fail validation.
        (name, total, retain_from, checkpoint, frontier,
         nonces, entries, tail) = self.fields
        prefix_parts = [
            blob(name), u64(total), u64(retain_from), blob(checkpoint),
            u64(len(frontier)),
        ]
        for height, digest in frontier:
            prefix_parts += [u64(height), blob(digest)]
        prefix_parts.append(u64(len(nonces)))
        for used_nonce in nonces:
            prefix_parts.append(blob(used_nonce))
        count_offset = len(b"".join(prefix_parts))
        raw = bytearray(self._build(*self.fields))
        raw[count_offset:count_offset + 8] = u64(1)
        body = MAGIC + u64(1) + bytes(raw)
        data = body + _sign(_SEED_A, body)
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(data, PUBLIC_A)

    def test_bad_entry_index(self):
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[0]
        broken = [(index + 1, payload, previous_hash, entry_hash, locator)] + entries[1:]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=broken), PUBLIC_A)

    def test_bad_entry_digest_width(self):
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[0]
        broken = [(index, payload, previous_hash, entry_hash[:-1], locator)] + entries[1:]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=broken), PUBLIC_A)

    def test_bad_previous_hash_width(self):
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[0]
        broken = [(index, payload, previous_hash + b"\x00", entry_hash, locator)] + entries[1:]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=broken), PUBLIC_A)

    def test_broken_chain_rejected(self):
        # Swapping the two retained payloads keeps widths but breaks the
        # chain starting at index 2.
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        first, second = entries[0], entries[1]
        broken = [
            (first[0], second[1], first[2], first[3], first[4]),
            (second[0], first[1], second[2], second[3], second[4]),
        ]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=broken), PUBLIC_A)

    def test_locator_wrong_width(self):
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        index, payload, previous_hash, entry_hash, locator = entries[1]
        self.assertTrue(locator)
        broken = list(entries)
        broken[1] = (index, payload, previous_hash, entry_hash, locator[:-1])
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=broken), PUBLIC_A)

    def test_locator_on_plain_payload_rejected(self):
        _n, _t, _r, _c, _f, _no, entries, _ta = self.fields
        index, payload, previous_hash, entry_hash, _locator = entries[0]
        broken = list(entries)
        broken[0] = (index, payload, previous_hash, entry_hash, bytes(32))
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(self._forge(entries=broken), PUBLIC_A)

    def test_duplicate_envelope_nonce_among_retained(self):
        # Two retained encrypted entries carrying the same envelope nonce in
        # a fully consistent chain, so only the duplicate-nonce check fails.
        shared_nonce = b"\x05" * 12
        aad_domain = b"auditchain/aead/v1\0"
        enc_magic = b"auditchain/encrypted-entry/v1\0"

        def seal(index, previous_hash, plaintext):
            aad = aad_domain + b"\x01" + u64(index) + previous_hash
            sealed = AESGCM(_ENC_KEY).encrypt(shared_nonce, plaintext, aad)
            return enc_magic + b"\x01" + shared_nonce + sealed

        genesis = bytes(32)
        env1 = seal(1, entry_digest(0, genesis, b"a"), b"first")
        hash0 = entry_digest(0, genesis, b"a")
        hash1 = entry_digest(1, hash0, env1)
        env2 = seal(2, hash1, b"second")
        hash2 = entry_digest(2, hash1, env2)
        mirror = AuditLog(key=b"k")
        mirror.append(b"a")
        mirror.append(env1)
        mirror.append(env2)
        receipt = mirror.seal(1)
        mirror.prune(1, receipt)
        checkpoint = hash0
        frontier = [(0, mirror._frontier[0])]
        entries = [
            (1, env1, hash0, hash1, bytes(32)),
            (2, env2, hash1, hash2, bytes(32)),
        ]
        tail = (mirror.merkle_root(), mirror.head, 0, b"k", 0)
        name = b"sha256"
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(
                    name=name, total=3, retain_from=1, checkpoint=checkpoint,
                    frontier=frontier, nonces=[shared_nonce], entries=entries,
                    tail=tail,
                ),
                PUBLIC_A,
            )

    def test_bad_root_width(self):
        root, head, stage, key_material, exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(root[:-1], head, stage, key_material, exported)),
                PUBLIC_A,
            )

    def test_bad_head_width(self):
        root, head, stage, key_material, exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(root, head + b"\x00", stage, key_material, exported)),
                PUBLIC_A,
            )

    def test_bad_flag(self):
        root, head, stage, key_material, _exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(root, head, stage, key_material, 2)),
                PUBLIC_A,
            )

    def test_empty_evolution_key(self):
        root, head, stage, _key_material, exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(root, head, stage, b"", exported)),
                PUBLIC_A,
            )

    def test_wrong_width_evolution_key_after_evolution(self):
        # stage == 3 here, so K must be the 32-byte digest width.
        root, head, stage, _key_material, exported = self.fields[7]
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(root, head, stage, b"too-short", exported)),
                PUBLIC_A,
            )

    def test_wrong_root_rejected(self):
        root, head, stage, key_material, exported = self.fields[7]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(root))
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(wrong, head, stage, key_material, exported)),
                PUBLIC_A,
            )

    def test_wrong_head_rejected(self):
        root, head, stage, key_material, exported = self.fields[7]
        wrong = bytes(d if (i + 1) % 7 else d ^ 0x01 for i, d in enumerate(head))
        with self.assertRaises(ValueError):
            load_signed_pruned_hybrid(
                self._forge(tail=(root, wrong, stage, key_material, exported)),
                PUBLIC_A,
            )


if __name__ == "__main__":
    unittest.main()
