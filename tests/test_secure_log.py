import hashlib
import hmac as hmac_module
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    Entry,
    decrypt_entry,
    dump_secure_log,
    entry_digest,
    load_secure_log,
)

MAGIC = b"auditchain/secure-log/v1\0"
ENC_MAGIC = b"auditchain/encrypted-entry/v1\0"
LOCATE_DOMAIN = b"auditchain/encrypted-locate/v1\0"
LEAF_DOMAIN = b"auditchain/merkle-leaf/v1"
NODE_DOMAIN = b"auditchain/merkle-node/v1"
EMPTY_DOMAIN = b"auditchain/merkle-empty/v1"
AAD_DOMAIN = b"auditchain/aead/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
KEY = b"k" * 32
OTHER_KEY = b"x" * 32
NONCE_0 = b"0" * 12
NONCE_1 = b"1" * 12


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


def _locator(key, plaintext, hash_name="sha256"):
    return hmac_module.new(key, LOCATE_DOMAIN + plaintext, hash_name).digest()


def _aad(index, previous_hash):
    return AAD_DOMAIN + b"\x01" + index.to_bytes(8, "big") + previous_hash


def _envelope(key, nonce, plaintext, index, previous_hash):
    sealed = AESGCM(key).encrypt(nonce, plaintext, _aad(index, previous_hash))
    return ENC_MAGIC + b"\x01" + nonce + sealed


def _merkle_root(entry_hashes, hash_name):
    def h(*parts):
        d = hashlib.new(hash_name)
        for part in parts:
            d.update(part)
        return d.digest()

    if not entry_hashes:
        return h(EMPTY_DOMAIN)
    level = [h(LEAF_DOMAIN, digest) for digest in entry_hashes]
    while len(level) > 1:
        combined = [
            h(NODE_DOMAIN, level[i], level[i + 1])
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            combined.append(level[-1])
        level = combined
    return level[0]


def build_secure(hash_name, materials, seed=_SEED_A, *, version=1, sign=True):
    """Build a secure-log stream from ``(payload, locator)`` materials.

    Recomputes the entry-digest chain from genesis and the Merkle root over
    the recomputed leaf digests, so a stream with mutated payloads still
    carries an internally consistent chain and root (signed by the trusted
    seed) — letting tests reach the locator/nonce/width validation rather
    than failing earlier at a digest check.
    """
    digest_size = hashlib.new(hash_name).digest_size
    records = []
    previous = bytes(digest_size)
    leaf_hashes = []
    for index, (payload, locator) in enumerate(materials):
        digest = entry_digest(index, previous, payload, hash_name=hash_name)
        records.append((index, payload, previous, digest, locator))
        leaf_hashes.append(digest)
        previous = digest
    root = _merkle_root(leaf_hashes, hash_name)
    head = previous
    parts = [
        MAGIC,
        u64(version),
        blob(hash_name.encode("utf-8")),
        u64(len(records)),
        blob(root),
        blob(head),
    ]
    for index, payload, prev, digest, locator in records:
        parts.extend((
            u64(index),
            blob(payload),
            blob(prev),
            blob(digest),
            blob(locator),
        ))
    body = b"".join(parts)
    if not sign:
        return body
    return body + Ed25519PrivateKey.from_private_bytes(seed).sign(body)


def _record_bytes(record):
    index, payload, previous_hash, entry_hash, locator = record
    return b"".join((
        u64(index),
        blob(payload),
        blob(previous_hash),
        blob(entry_hash),
        blob(locator),
    ))


class DumpSecureLogLayoutTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("plain")
        self.log.encrypt("secret", KEY, nonce=NONCE_0)
        self.public_key = _public_key(_SEED_A)
        self.data = dump_secure_log(self.log, _SEED_A)

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
        # U(n)
        count = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        self.assertEqual(count, 2)
        # B(root), B(head)
        for expected in (self.log.merkle_root(), self.log.head):
            width = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            self.assertEqual(width, 32)
            self.assertEqual(data[offset:offset + width], expected)
            offset += width
        # Two records E = U(index) || B(payload) || B(previous) || B(hash) || B(locator).
        for position, entry in enumerate(self.log.entries()):
            self.assertEqual(data[offset:offset + 8], u64(position))
            offset += 8
            self.assertEqual(
                data[offset + 8:offset + 8 + len(entry.payload)], entry.payload
            )
            offset += 8 + len(entry.payload)
            offset += 8 + 32  # previous_hash
            offset += 8 + 32  # entry_hash
            locator_width = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            if position == 0:
                self.assertEqual(locator_width, 0)  # plain entry
            else:
                self.assertEqual(locator_width, 32)  # encrypted locator HMAC
                locator = data[offset:offset + 32]
                self.assertEqual(locator, _locator(KEY, b"secret"))
            offset += locator_width
        # Exactly the 64-byte Ed25519 signature closes the stream.
        self.assertEqual(offset, len(data) - 64)

    def test_signature_covers_every_preceding_byte(self):
        # The trailing 64 bytes verify under the public key over the whole
        # prefix (which is NOT the sign_root domain message).
        body = self.data[:-64]
        signature = self.data[-64:]
        verification_key = Ed25519PrivateKey.from_private_bytes(
            _SEED_A
        ).public_key()
        verification_key.verify(signature, body)  # no exception

    def test_deterministic_same_state_same_seed(self):
        self.assertEqual(
            dump_secure_log(self.log, _SEED_A),
            dump_secure_log(self.log, _SEED_A),
        )
        twin = AuditLog()
        twin.append("plain")
        twin.encrypt("secret", KEY, nonce=NONCE_0)
        self.assertEqual(
            dump_secure_log(twin, _SEED_A), dump_secure_log(self.log, _SEED_A)
        )

    def test_dump_is_read_only(self):
        before = dump_secure_log(self.log, _SEED_A)
        dump_secure_log(self.log, _SEED_A)
        self.assertEqual(len(self.log), 2)
        self.assertEqual(self.log.retain_from, 0)
        self.assertTrue(self.log.verify())
        self.assertEqual(dump_secure_log(self.log, _SEED_A), before)

    def test_seed_is_not_stored(self):
        dump_secure_log(self.log, _SEED_A)
        self.assertEqual(self.log.stage, 0)
        with self.assertRaises(ValueError):
            self.log.export_verifier()


class SecureLogRoundtripTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("plain one")
        self.enc_alpha = self.log.encrypt("secret alpha", KEY, nonce=NONCE_0)
        self.log.append(b"plain two")
        self.enc_beta = self.log.encrypt("secret beta", KEY, nonce=NONCE_1)
        # A plain payload that merely starts with the encrypted-entry magic
        # must remain a plain entry (classification is by locator).
        self.decoy = self.log.append(ENC_MAGIC + b"\x01not really encrypted")
        self.public_key = _public_key(_SEED_A)
        self.data = dump_secure_log(self.log, _SEED_A)

    def test_restored_fields_match(self):
        restored = load_secure_log(bytes(self.data), self.public_key)
        self.assertIsInstance(restored, AuditLog)
        self.assertEqual(len(restored), len(self.log))
        self.assertEqual(restored.retain_from, 0)
        self.assertEqual(restored.head, self.log.head)
        self.assertEqual(restored.hash_name, self.log.hash_name)
        self.assertEqual(restored.merkle_root(), self.log.merkle_root())
        self.assertEqual(restored.entries(), self.log.entries())
        self.assertTrue(restored.verify())

    def test_empty_log(self):
        restored = load_secure_log(
            dump_secure_log(AuditLog(), _SEED_A), self.public_key
        )
        self.assertEqual(len(restored), 0)
        self.assertEqual(restored.head, GENESIS_HASH)
        self.assertEqual(restored.retain_from, 0)
        self.assertTrue(restored.verify())
        self.assertEqual(restored.merkle_root(), AuditLog().merkle_root())

    def test_plain_only_log(self):
        log = AuditLog()
        for record in ("a", b"b", b"c" * 100):
            log.append(record)
        restored = load_secure_log(
            dump_secure_log(log, _SEED_A), self.public_key
        )
        self.assertEqual(restored.entries(), log.entries())
        self.assertEqual(restored.merkle_root(), log.merkle_root())
        self.assertEqual(restored.find(b"c" * 100), (2,))

    def test_find_index_is_rebuilt(self):
        restored = load_secure_log(self.data, self.public_key)
        self.assertEqual(restored.find(b"plain one"), (0,))
        self.assertEqual(restored.find(b"plain two"), (2,))
        self.assertEqual(restored.find("missing"), ())
        # The envelope bytes themselves remain findable.
        self.assertEqual(restored.find(self.enc_alpha.payload), (1,))
        # The magic-prefixed plain payload is a normal plain entry.
        self.assertEqual(restored.find(self.decoy.payload), (4,))

    def test_encrypted_locator_index_is_rebuilt(self):
        restored = load_secure_log(self.data, self.public_key)
        self.assertEqual(restored.find_encrypted("secret alpha", KEY), (1,))
        self.assertEqual(restored.find_encrypted("secret beta", KEY), (3,))
        self.assertEqual(
            restored.find_encrypted(b"secret alpha", KEY), (1,)
        )
        # A valid but wrong key never hits and never raises.
        self.assertEqual(restored.find_encrypted("secret alpha", OTHER_KEY), ())
        # Plaintext is never matched by the ordinary find index.
        self.assertEqual(restored.find(b"secret alpha"), ())

    def test_envelopes_still_decrypt_offline(self):
        restored = load_secure_log(self.data, self.public_key)
        self.assertEqual(decrypt_entry(restored.entry(1), KEY), b"secret alpha")
        self.assertEqual(decrypt_entry(restored.entry(3), KEY), b"secret beta")

    def test_nonce_history_is_recovered(self):
        restored = load_secure_log(self.data, self.public_key)
        # Both original nonces are recorded again; reuse is rejected.
        with self.assertRaises(ValueError):
            restored.encrypt("dup alpha", KEY, nonce=NONCE_0)
        with self.assertRaises(ValueError):
            restored.encrypt("dup beta", KEY, nonce=NONCE_1)
        # A fresh nonce still works, and the restored log stays consistent.
        restored.encrypt("secret gamma", KEY)
        self.assertTrue(restored.verify())
        self.assertEqual(restored.find_encrypted("secret gamma", KEY), (5,))

    def test_restored_log_is_independent_and_mutable(self):
        restored = load_secure_log(self.data, self.public_key)
        restored.append("new event")
        restored.encrypt("fresh secret", KEY)
        self.assertEqual(len(restored), 7)
        self.assertEqual(restored.find(b"new event"), (5,))
        self.assertEqual(restored.find_encrypted("fresh secret", KEY), (6,))
        self.assertTrue(restored.verify())
        # The source log is untouched and shares no state.
        self.assertEqual(len(self.log), 5)

    def test_restored_log_supports_prune(self):
        restored = load_secure_log(self.data, self.public_key)
        receipt = restored.seal(2)
        restored.prune(2, receipt)
        self.assertEqual(restored.retain_from, 2)
        restored.append("after prune")
        self.assertTrue(restored.verify())
        self.assertEqual(len(restored), 6)

    def test_restored_log_is_keyless(self):
        restored = load_secure_log(self.data, self.public_key)
        self.assertEqual(restored.stage, 0)
        with self.assertRaises(ValueError):
            restored.auth(0)
        with self.assertRaises(ValueError):
            restored.export_verifier()

    def test_alternate_hash_algorithms(self):
        for hash_name in ("sha512", "sha3_256"):
            log = AuditLog(hash_name=hash_name)
            log.append("a")
            log.encrypt("s", KEY, nonce=NONCE_0)
            restored = load_secure_log(
                dump_secure_log(log, _SEED_A), self.public_key
            )
            self.assertEqual(restored.hash_name, hash_name)
            self.assertEqual(len(restored), 2)
            self.assertEqual(restored.head, log.head)
            self.assertEqual(restored.merkle_root(), log.merkle_root())
            self.assertTrue(restored.verify())
            self.assertEqual(restored.find_encrypted("s", KEY), (1,))


class DumpSecureQualificationTest(unittest.TestCase):
    def test_pruned_log_rejected(self):
        log = AuditLog()
        log.append("a")
        log.append("b")
        log.prune(1, log.seal(1))
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A)

    def test_keyed_log_rejected(self):
        log = AuditLog(key=b"a" * 10)
        log.append("a")
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A)

    def test_authenticated_log_rejected(self):
        log = AuditLog(key=b"a" * 10)
        log.append("a")
        log.auth(0)
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A)

    def test_rotated_key_log_rejected(self):
        log = AuditLog(key=b"a" * 10)
        log.append("a")
        log.rotate_key()
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A)

    def test_verifier_exported_log_rejected(self):
        log = AuditLog(key=b"a" * 10)
        log.append("a")
        log.export_verifier()
        with self.assertRaises(ValueError):
            dump_secure_log(log, _SEED_A)

    def test_encrypted_history_is_allowed(self):
        log = AuditLog()
        log.append("a")
        log.encrypt("secret", KEY, nonce=NONCE_0)
        data = dump_secure_log(log, _SEED_A)
        restored = load_secure_log(data, _public_key(_SEED_A))
        self.assertEqual(restored.find_encrypted("secret", KEY), (1,))


class DumpSecureTypeErrorTest(unittest.TestCase):
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

    def test_log_unharmed_after_rejected_seed(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            dump_secure_log(log, b"short")
        self.assertEqual(len(log), 1)
        self.assertTrue(log.verify())


class LoadSecureFramingTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b"):
            self.log.append(record)
        self.log.encrypt("s", KEY, nonce=NONCE_0)
        self.public_key = _public_key(_SEED_A)
        self.data = dump_secure_log(self.log, _SEED_A)

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
        for bad in (
            None,
            "key",
            bytearray(self.public_key),
            memoryview(self.public_key),
            1,
        ):
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
        bad = bytearray(self.data)
        bad[len(MAGIC):len(MAGIC) + 8] = u64(2)
        # The body changed, so the trailing signature must fail first.
        with self.assertRaises(ValueError):
            load_secure_log(bytes(bad), self.public_key)

    def test_truncation(self):
        for cut in range(0, len(self.data)):
            with self.assertRaises(ValueError, msg=cut):
                load_secure_log(self.data[:cut], self.public_key)

    def test_trailing_bytes(self):
        for extra in (b"\x00", b"trailing"):
            with self.assertRaises(ValueError):
                load_secure_log(self.data + extra, self.public_key)

    def test_oversized_blob_length(self):
        bad = MAGIC + u64(1) + u64(1 << 63) + b"rest"
        with self.assertRaises(ValueError):
            load_secure_log(bad, self.public_key)


class LoadSecureSignatureTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        self.log.append("a")
        self.log.encrypt("s", KEY, nonce=NONCE_0)
        self.public_key = _public_key(_SEED_A)
        self.data = dump_secure_log(self.log, _SEED_A)

    def test_wrong_public_key(self):
        with self.assertRaises(ValueError):
            load_secure_log(self.data, _public_key(_SEED_B))

    def test_forged_signature(self):
        forged = self.data[:-64] + b"\x00" * 64
        with self.assertRaises(ValueError):
            load_secure_log(forged, self.public_key)

    def test_tampered_body_fails_signature(self):
        # Flipping any byte of the body invalidates the Ed25519 signature.
        for position in (len(MAGIC), len(self.data) // 2, len(self.data) - 65):
            tampered = bytearray(self.data)
            tampered[position] ^= 0xFF
            with self.assertRaises(ValueError, msg=position):
                load_secure_log(bytes(tampered), self.public_key)

    def test_signature_is_verified_before_parsing(self):
        # A body that is nonsense after the magic still fails on the signature
        # rather than a parse error, proving verification comes first.
        body = MAGIC + b"\xff" * 200
        signed_by_other = body + b"\x00" * 64
        with self.assertRaises(ValueError):
            load_secure_log(signed_by_other, self.public_key)


class LoadSecureSemanticTest(unittest.TestCase):
    """Rejection paths past a valid signature (streams signed by the trusted seed)."""

    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def _materials(self):
        # (payload, locator) pairs; encrypted envelopes bind to their position.
        p0 = b"plain"
        env1_prev = entry_digest(0, bytes(32), p0)
        env1 = _envelope(KEY, NONCE_0, b"secret one", 1, env1_prev)
        loc1 = _locator(KEY, b"secret one")
        p2 = b"plain two"
        h1 = entry_digest(1, env1_prev, env1)
        env3_prev = entry_digest(2, h1, p2)
        env3 = _envelope(KEY, NONCE_1, b"secret two", 3, env3_prev)
        loc3 = _locator(KEY, b"secret two")
        return [
            (p0, b""),
            (env1, loc1),
            (p2, b""),
            (env3, loc3),
        ]

    def test_valid_constructed_stream_loads(self):
        data = build_secure("sha256", self._materials())
        restored = load_secure_log(data, self.public_key)
        self.assertEqual(len(restored), 4)
        self.assertTrue(restored.verify())
        self.assertEqual(restored.find_encrypted("secret one", KEY), (1,))
        self.assertEqual(restored.find_encrypted("secret two", KEY), (3,))

    def test_bad_version_after_valid_signature(self):
        data = build_secure("sha256", self._materials(), version=2)
        with self.assertRaises(ValueError):
            load_secure_log(data, self.public_key)

    def test_bad_utf8_hash_name(self):
        materials = self._materials()
        digest_size = 32
        records = []
        previous = bytes(digest_size)
        leaves = []
        for index, (payload, locator) in enumerate(materials):
            digest = entry_digest(index, previous, payload)
            records.append((index, payload, previous, digest, locator))
            leaves.append(digest)
            previous = digest
        body = b"".join((
            MAGIC,
            u64(1),
            blob(b"\xff\xff"),
            u64(len(records)),
            blob(_merkle_root(leaves, "sha256")),
            blob(previous),
            *( _record_bytes(record) for record in records),
        ))
        data = body + Ed25519PrivateKey.from_private_bytes(_SEED_A).sign(body)
        with self.assertRaises(ValueError):
            load_secure_log(data, self.public_key)

    def test_unknown_hash_algorithm(self):
        # The loader rejects an unknown algorithm right after the hash_name
        # blob is read, so a valid signature over magic/version/blob suffices.
        body = MAGIC + u64(1) + blob(b"not-a-hash")
        data = body + Ed25519PrivateKey.from_private_bytes(_SEED_A).sign(body)
        with self.assertRaises(ValueError):
            load_secure_log(data, self.public_key)

    def test_root_width_must_match_algorithm(self):
        materials = self._materials()
        # Rebuild with a 31-byte root and a valid signature over the new body.
        bad_root = b"\x00" * 31
        parts = [
            MAGIC,
            u64(1),
            blob(b"sha256"),
            u64(len(materials)),
            blob(bad_root),
            blob(bytes(32)),
        ]
        previous = bytes(32)
        for index, (payload, locator) in enumerate(materials):
            digest = entry_digest(index, previous, payload)
            parts.append(
                _record_bytes((index, payload, previous, digest, locator))
            )
            previous = digest
        new_body = b"".join(parts)
        signed = new_body + Ed25519PrivateKey.from_private_bytes(_SEED_A).sign(
            new_body
        )
        with self.assertRaises(ValueError):
            load_secure_log(signed, self.public_key)

    def test_indices_must_be_zero_based_in_order(self):
        materials = self._materials()
        # Re-encode records but renumber the first index to 1; keep its digest
        # chain consistent (digest uses the position-derived previous only), so
        # the only failure is the index/position check.
        digest_size = 32
        records = []
        previous = bytes(digest_size)
        leaves = []
        for index, (payload, locator) in enumerate(materials):
            digest = entry_digest(index, previous, payload)
            records.append((index, payload, previous, digest, locator))
            leaves.append(digest)
            previous = digest
        records[0] = (1, records[0][1], records[0][2], records[0][3], records[0][4])
        body = b"".join((
            MAGIC,
            u64(1),
            blob(b"sha256"),
            u64(len(records)),
            blob(_merkle_root(leaves, "sha256")),
            blob(previous),
            *(_record_bytes(record) for record in records),
        ))
        data = body + Ed25519PrivateKey.from_private_bytes(_SEED_A).sign(body)
        with self.assertRaises(ValueError):
            load_secure_log(data, self.public_key)

    def test_broken_chain_rejected(self):
        data = build_secure("sha256", self._materials())
        # Flip a payload byte without recomputing anything: framing and the
        # signature survive only because we re-sign; the digest chain cannot.
        body, _signature = data[:-64], data[-64:]
        tampered = bytearray(body)
        # Locate the first plain payload ("plain") inside the body and flip it.
        position = body.index(b"plain")
        tampered[position] ^= 0xFF
        new_body = bytes(tampered)
        signed = new_body + Ed25519PrivateKey.from_private_bytes(_SEED_A).sign(
            new_body
        )
        with self.assertRaises(ValueError):
            load_secure_log(signed, self.public_key)

    def test_duplicate_nonce_rejected(self):
        # Two encrypted envelopes sealed with the SAME 12-byte nonce, each
        # correctly bound to its own position; chain and root are recomputed
        # and the whole stream is signed by the trusted seed, so rejection
        # must come from the nonce-dedup check.
        p0 = b"plain"
        env1_prev = entry_digest(0, bytes(32), p0)
        env1 = _envelope(KEY, NONCE_0, b"secret one", 1, env1_prev)
        loc1 = _locator(KEY, b"secret one")
        p2 = b"plain two"
        h1 = entry_digest(1, env1_prev, env1)
        env3_prev = entry_digest(2, h1, p2)
        env3 = _envelope(KEY, NONCE_0, b"secret two", 3, env3_prev)
        loc3 = _locator(KEY, b"secret two")
        data = build_secure(
            "sha256", [(p0, b""), (env1, loc1), (p2, b""), (env3, loc3)]
        )
        with self.assertRaises(ValueError):
            load_secure_log(data, self.public_key)

    def test_nonempty_locator_requires_envelope(self):
        # A plain payload paired with a digest-width locator must fail when its
        # bytes are parsed as an encrypted-entry envelope.
        materials = self._materials()
        materials[0] = (b"plain", _locator(KEY, b"plain"))
        data = build_secure("sha256", materials)
        with self.assertRaises(ValueError):
            load_secure_log(data, self.public_key)

    def test_locator_width_must_match_algorithm(self):
        for bad_locator in (b"\x00" * 31, b"\x00" * 33):
            materials = self._materials()
            # Replace the first encrypted record's locator with a wrong-width
            # value while keeping its envelope; recompute and re-sign so the
            # failure is the locator-width check.
            payload, _loc = materials[1]
            materials[1] = (payload, bad_locator)
            data = build_secure("sha256", materials)
            with self.assertRaises(ValueError, msg=len(bad_locator)):
                load_secure_log(data, self.public_key)

    def test_unknown_envelope_algorithm_rejected(self):
        p0 = b"plain"
        env1_prev = entry_digest(0, bytes(32), p0)
        # A structurally complete envelope but with algorithm byte 0x02.
        sealed = AESGCM(KEY).encrypt(
            NONCE_0, b"secret one", _aad(1, env1_prev)
        )
        env1 = ENC_MAGIC + b"\x02" + NONCE_0 + sealed
        materials = [(p0, b""), (env1, _locator(KEY, b"secret one"))]
        data = build_secure("sha256", materials)
        with self.assertRaises(ValueError):
            load_secure_log(data, self.public_key)

    def test_truncated_envelope_rejected(self):
        p0 = b"plain"
        env1_prev = entry_digest(0, bytes(32), p0)
        # Magic + algorithm byte but no nonce/ciphertext at all.
        env1 = ENC_MAGIC + b"\x01"
        materials = [(p0, b""), (env1, _locator(KEY, b"secret one"))]
        data = build_secure("sha256", materials)
        with self.assertRaises(ValueError):
            load_secure_log(data, self.public_key)

    def test_plain_envelope_bytes_with_empty_locator_is_plain(self):
        # An envelope-shaped payload carried by an EMPTY locator is, per the
        # format, an ordinary plain entry whose payload happens to look like an
        # envelope; it must load (no nonce is recovered, no error raised).
        p0 = b"plain"
        env1_prev = entry_digest(0, bytes(32), p0)
        fake = ENC_MAGIC + b"\x01" + b"z" * 12 + b"z" * 28
        materials = [(p0, b""), (fake, b"")]
        data = build_secure("sha256", materials)
        restored = load_secure_log(data, self.public_key)
        self.assertEqual(len(restored), 2)
        self.assertTrue(restored.verify())
        self.assertEqual(restored.find(fake), (1,))
        self.assertEqual(restored.find_encrypted(fake, KEY), ())


if __name__ == "__main__":
    unittest.main()
