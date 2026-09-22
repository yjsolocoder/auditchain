"""auditchain - an append-only hash-chained audit log.

Public API: Entry / AuditLog / PruneReceipt / AuditReceipt / AuthTag /
Verifier / SignedRoot / SignedAuditBatch / SignedConsistency /
SignedPrune / IntegrityIssue / IntegrityReport / entry_digest /
decrypt_entry / verify_inclusion / verify_batch_inclusion /
verify_consistency / verify_auth / verify_auth_batch / verify_audit_receipt /
verify_audit_batch / verify_signed_root / verify_signed_audit_batch /
verify_signed_consistency / verify_signed_prune /
encode_audit_receipt / decode_audit_receipt /
encode_prune_receipt / decode_prune_receipt /
encode_audit_batch / decode_audit_batch /
encode_auth_batch / decode_auth_batch /
encode_signed_root / decode_signed_root /
encode_signed_audit_batch / decode_signed_audit_batch /
encode_signed_consistency / decode_signed_consistency /
encode_signed_prune / decode_signed_prune /
dump_log / load_log /
dump_secure_log / load_secure_log /
dump_pruned_log / load_pruned_log /
dump_secure_pruned / load_secure_pruned /
dump_auth / load_auth /
dump_pruned_auth / load_pruned_auth /
dump_hybrid / load_hybrid.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Sequence

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

__all__ = [
    "AuditLog",
    "AuditReceipt",
    "AuthTag",
    "Entry",
    "IntegrityIssue",
    "IntegrityReport",
    "PruneReceipt",
    "SignedAuditBatch",
    "SignedConsistency",
    "SignedPrune",
    "SignedRoot",
    "Verifier",
    "GENESIS_HASH",
    "decode_audit_batch",
    "decode_audit_receipt",
    "decode_auth_batch",
    "decode_prune_receipt",
    "decode_signed_audit_batch",
    "decode_signed_consistency",
    "decode_signed_prune",
    "decode_signed_root",
    "decrypt_entry",
    "dump_auth",
    "dump_hybrid",
    "dump_log",
    "dump_pruned_auth",
    "dump_pruned_hybrid",
    "dump_pruned_log",
    "dump_secure_log",
    "dump_secure_pruned",
    "encode_audit_batch",
    "encode_audit_receipt",
    "encode_auth_batch",
    "encode_prune_receipt",
    "encode_signed_audit_batch",
    "encode_signed_consistency",
    "encode_signed_prune",
    "encode_signed_root",
    "entry_digest",
    "load_auth",
    "load_hybrid",
    "load_log",
    "load_pruned_auth",
    "load_pruned_hybrid",
    "load_pruned_log",
    "load_secure_log",
    "load_secure_pruned",
    "verify_audit_receipt",
    "verify_audit_batch",
    "verify_auth",
    "verify_auth_batch",
    "verify_batch_inclusion",
    "verify_consistency",
    "verify_inclusion",
    "verify_signed_audit_batch",
    "verify_signed_consistency",
    "verify_signed_prune",
    "verify_signed_root",
]

GENESIS_HASH = bytes(32)
_DOMAIN = b"auditchain/entry/v1"
_INDEX_BYTES = 8

# Self-describing envelope of AuditLog.encrypt / decrypt_entry:
# magic, one-byte algorithm id (0x01 == AES-256-GCM), 12-byte nonce, then the
# AESGCM output (ciphertext || 16-byte authentication tag).
_ENC_MAGIC = b"auditchain/encrypted-entry/v1\0"
_AAD_DOMAIN = b"auditchain/aead/v1\0"
_ALG_AES256_GCM = 0x01
_KEY_BYTES = 32
_NONCE_BYTES = 12
_GCM_TAG_BYTES = 16

_LEAF_DOMAIN = b"auditchain/merkle-leaf/v1"
_NODE_DOMAIN = b"auditchain/merkle-node/v1"
_EMPTY_DOMAIN = b"auditchain/merkle-empty/v1"

_AUTH_DOMAIN = b"auditchain/auth/v1"
_EVOLVE_DOMAIN = b"auditchain/key-evolve/v1"
_LOCATE_DOMAIN = b"auditchain/locate/v1"
# HMAC keyed by the caller-supplied encryption key, locating encrypted
# entries by their original plaintext. HMAC (rather than a plain hash) keeps
# the locator unguessable without the key; the index stores only these
# digests, never the plaintext or the key.
_ENC_LOCATE_DOMAIN = b"auditchain/encrypted-locate/v1\0"

# Binary framing of encode_audit_receipt / decode_audit_receipt: a fixed
# magic, then unsigned 8-byte big-endian integers and length-prefixed blobs.
_RECEIPT_MAGIC = b"auditchain/audit-receipt/v1\0"
# Binary framing of encode_prune_receipt / decode_prune_receipt: same u64/blob
# rules; a sealed prefix checkpoint with no per-entry payload.
_PRUNE_RECEIPT_MAGIC = b"auditchain/prune-receipt/v1\0"
_PRUNE_RECEIPT_VERSION = 1
# Binary framing of encode_audit_batch / decode_audit_batch: same u64/blob
# rules, one shared proof at the end instead of one proof per item.
_BATCH_MAGIC = b"auditchain/batch/v1\0"
_BATCH_VERSION = 1
# Binary framing of encode_auth_batch / decode_auth_batch: same u64/blob
# rules, persisting the (Entry, AuthTag) item tuple minted by
# AuditLog.auth_batch together with the hash algorithm verify_auth_batch
# needs, with no verifier material of any kind.
_AUTH_BATCH_MAGIC = b"auditchain/auth-batch/v1\0"
_AUTH_BATCH_VERSION = 1
_U64_BYTES = 8
_U64_LIMIT = 1 << 64

# Signed snapshot-root checkpoint of AuditLog.sign_root / verify_signed_root.
# An Ed25519 signature over the hash algorithm, snapshot size, Merkle root and
# chain head; the signing seed is supplied per call and never stored.
_SIGNED_ROOT_DOMAIN = b"auditchain/signed-root/v1\0"
_SIGNED_ROOT_VERSION = 1
_ED25519_KEY_BYTES = 32
_ED25519_SIGNATURE_BYTES = 64

# Binary framing of encode_signed_audit_batch / decode_signed_audit_batch:
# a fixed magic, then the envelope version as a u64 and two u64-length-prefixed
# blobs holding the complete canonical encode_audit_batch and
# encode_signed_root bytes, in that order and with nothing else.
_SIGNED_AUDIT_BATCH_MAGIC = b"auditchain/signed-audit-batch/v1\0"
_SIGNED_AUDIT_BATCH_VERSION = 1

# Binary framing of encode_signed_consistency / decode_signed_consistency:
# a fixed magic, then the envelope version as a u64, two u64-length-prefixed
# blobs holding the complete canonical encode_signed_root bytes of the old
# and new checkpoints in that order, a u64 proof-node count and one
# length-prefixed blob per proof node in tuple order, with nothing else.
_SIGNED_CONSISTENCY_MAGIC = b"auditchain/signed-consistency/v1\0"
_SIGNED_CONSISTENCY_VERSION = 1

# Binary framing of encode_signed_prune / decode_signed_prune: a fixed magic,
# then the envelope version as a u64 and two u64-length-prefixed blobs holding
# the complete canonical encode_prune_receipt and encode_signed_root bytes, in
# that order and with nothing else.
_SIGNED_PRUNE_MAGIC = b"auditchain/signed-prune/v1\0"
_SIGNED_PRUNE_VERSION = 1

# Binary framing of dump_log / load_log: a fixed magic, then the envelope
# version as a u64, one u64-length-prefixed blob holding the complete
# canonical encode_signed_root checkpoint, the entry count as a u64 and one
# encoded Entry per record (index u64, then payload / previous_hash /
# entry_hash blobs), in that order and with nothing else.
_LOG_STATE_MAGIC = b"auditchain/log-state/v1\0"
_LOG_STATE_VERSION = 1

# Binary framing of dump_secure_log / load_secure_log. Like the log-state
# framing (same u64/blob rules, same eligibility), but the signed snapshot is
# inlined as version/hash_name/root/head fields with a trailing 64-byte
# Ed25519 signature over every preceding byte (no nested signed-root blob),
# and each entry record additionally carries B(locator): an empty blob marks
# a plain entry, otherwise the digest-width encrypted-locator HMAC. The
# 12-byte AEAD nonce of every encrypted entry is recovered from its envelope
# on load and must never repeat.
_SECURE_LOG_MAGIC = b"auditchain/secure-log/v1\0"
_SECURE_LOG_VERSION = 1

# Binary framing of dump_pruned_log / load_pruned_log. Like the secure-log
# framing (same u64/blob rules, inline snapshot fields and a trailing 64-byte
# Ed25519 signature over every preceding byte), but for a pruned plain log:
# after the version, hash name, total length n and retain point r the stream
# carries the sealed checkpoint (the chain head of the released prefix
# [0, r)) and the perfect-subtree frontier covering that prefix — one
# U(height) || B(digest) pair per set bit of r, in ascending height order —
# then the retained entries r..n-1 in the dump_log entry framing, and finally
# B(root) and B(head) of the full size-n snapshot. No prune receipts,
# authentication material or encryption state is carried.
_PRUNED_LOG_MAGIC = b"auditchain/pruned-log/v1\0"
_PRUNED_LOG_VERSION = 1

# Binary framing of dump_secure_pruned / load_secure_pruned. Like the
# pruned-log framing (same u64/blob rules, inline checkpoint/frontier fields,
# retained entries in the secure-log E record order and a trailing 64-byte
# Ed25519 signature over every preceding byte), but for a pruned log whose
# history may contain encrypted entries: after the frontier the stream carries
# the nonce history — a u64 count followed by one length-prefixed B(nonce)
# blob per used nonce in lexicographic order, each carrying exactly 12 bytes;
# every nonce used by the pre-prune log is included, not just the nonces of
# retained ciphertexts — and the retained entries carry B(locator)
# exactly as in dump_secure_log (an empty blob marks a plain entry, otherwise
# the digest-width encrypted-locator HMAC). No prune receipts, authentication
# material or encryption keys are carried.
_PRUNED_SECURE_MAGIC = b"auditchain/pruned-secure/v1\0"
_PRUNED_SECURE_VERSION = 1

# Binary framing of dump_auth / load_auth: an authenticated, forward-secure
# keyed log (unpruned, no encrypt history) exported under a symmetric 32-byte
# key with AES-256-GCM rather than an Ed25519 signature. The wire form is
# D || 0x01 || N || C: D is the magic, 0x01 the one-byte algorithm id
# (AES-256-GCM), N the 12-byte nonce and C the AESGCM output (ciphertext ||
# 16-byte tag) over the plaintext framing P, authenticated with the AAD
# D || 0x01 || N. P carries the hash name, entry count and entries, the
# snapshot Merkle root and chain head, the current evolution key and stage,
# and a one-byte exported flag so forward-secure evolution can continue in a
# fresh process.
_AUTH_LOG_MAGIC = b"auditchain/auth-log/v1\0"
_AUTH_LOG_VERSION = 1

# Binary framing of dump_pruned_auth / load_pruned_auth: the pruned
# counterpart of the auth-log framing — the same symmetric AES-256-GCM wire
# form D || 0x01 || N || C with AAD D || 0x01 || N, but the plaintext
# describes a pruned keyed log (retain_from > 0, no encrypt history): after
# B(hash_name), U(n) and U(r) it carries B(checkpoint), the pruned-log
# frontier F, the retained entries r..n-1, and then the same auth-state tail
# B(root) || B(head) || U(stage) || B(K) || U(x) as dump_auth.
_PRUNED_AUTH_MAGIC = b"auditchain/pruned-auth/v1\0"
_PRUNED_AUTH_VERSION = 1

# Binary framing of dump_hybrid / load_hybrid: the hybrid of the auth-log and
# secure-log export formats — an unpruned, keyed, forward-secure log whose
# history may contain encrypted entries, exported under a symmetric 32-byte
# key with AES-256-GCM. The wire form is D || 0x01 || N || C: D is the magic,
# 0x01 the one-byte algorithm id (AES-256-GCM), N the 12-byte nonce and C the
# AESGCM output (ciphertext || 16-byte tag) over the plaintext framing P,
# authenticated with the AAD D || 0x01 || N. P carries the hash name, the
# complete encrypt nonce history (a u64 count followed by one 12-byte B(nonce)
# blob per used nonce in lexicographic order), the entry count and entries in
# the secure-log E record order (with B(locator)), and then the same
# auth-state tail B(root) || B(head) || U(stage) || B(K) || U(x) as dump_auth.
_HYBRID_MAGIC = b"auditchain/hybrid/v1\0"
_HYBRID_VERSION = 1

# Binary framing of dump_pruned_hybrid / load_pruned_hybrid: the pruned
# counterpart of the hybrid framing — the same symmetric AES-256-GCM wire
# form D || 0x01 || N || C with AAD D || 0x01 || N, but the plaintext
# describes a pruned keyed log (retain_from > 0) whose history may contain
# encrypted entries. It combines the dump_pruned_auth prefix (B(hash_name),
# U(n), U(r), B(checkpoint), the pruned-log frontier F) with the hybrid
# material: the complete encrypt nonce history Q, the retained entries
# r..n-1 in the secure-log record order (with B(locator)), and then the same
# auth-state tail B(root) || B(head) || U(stage) || B(K) || U(x).
_PRUNED_HYBRID_MAGIC = b"auditchain/pruned-hybrid/v1\0"
_PRUNED_HYBRID_VERSION = 1

# Stages are encoded as 8-byte big-endian integers inside tags.
_MAX_STAGE = 1 << 64


def _digest_size(hash_name: Any) -> int:
    """Fixed digest width of ``hash_name`` in bytes.

    Only hashlib algorithms with a fixed-length digest are accepted: a
    non-str name raises TypeError, an unknown algorithm or one without a
    fixed-length output (e.g. the SHAKE XOFs, whose ``digest_size`` is 0)
    raises ValueError.
    """
    if not isinstance(hash_name, str):
        raise TypeError("hash_name must be a string")
    try:
        digest_size = hashlib.new(hash_name).digest_size
    except ValueError as error:
        raise ValueError(f"unknown hash algorithm: {hash_name}") from error
    if digest_size == 0:
        raise ValueError(
            f"hash algorithm {hash_name!r} has no fixed-length digest"
        )
    return digest_size


def _as_bytes(payload: Any) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, bytearray):
        return bytes(payload)
    if isinstance(payload, str):
        return payload.encode("utf-8")
    raise TypeError("payload must be bytes, bytearray or str")


def _check_key(key: Any) -> bytes:
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) != _KEY_BYTES:
        raise ValueError(f"key must be {_KEY_BYTES} bytes")
    return key


def _check_nonce(nonce: Any) -> bytes:
    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes")
    if len(nonce) != _NONCE_BYTES:
        raise ValueError(f"nonce must be {_NONCE_BYTES} bytes")
    return nonce


def _load_ed25519_seed(private_key: Any) -> Ed25519PrivateKey:
    """Load a 32-byte Ed25519 private key seed; the seed is never stored."""
    if not isinstance(private_key, bytes):
        raise TypeError("private_key must be a 32-byte Ed25519 seed")
    if len(private_key) != _ED25519_KEY_BYTES:
        raise ValueError(
            f"private_key must be {_ED25519_KEY_BYTES} bytes (an Ed25519 seed)"
        )
    return Ed25519PrivateKey.from_private_bytes(private_key)


def _load_ed25519_public(public_key: Any) -> Ed25519PublicKey:
    if not isinstance(public_key, bytes):
        raise TypeError("public_key must be a 32-byte Ed25519 public key")
    if len(public_key) != _ED25519_KEY_BYTES:
        raise ValueError(
            f"public_key must be {_ED25519_KEY_BYTES} bytes (an Ed25519 public key)"
        )
    return Ed25519PublicKey.from_public_bytes(public_key)


def _signed_root_message(hash_name: str, size: int, root: bytes, head: bytes) -> bytes:
    """M of sign_root / verify_signed_root.

    ``D || 0x01 || B(UTF-8(hash_name)) || U(size) || B(root) || B(head)``
    with ``D = b"auditchain/signed-root/v1\\0"``, ``U`` an unsigned 8-byte
    big-endian integer and ``B(x) = U(len(x)) || x``.
    """
    return (
        _SIGNED_ROOT_DOMAIN
        + bytes((0x01,))
        + _encode_blob(hash_name.encode("utf-8"))
        + _encode_u64(size, "size")
        + _encode_blob(root)
        + _encode_blob(head)
    )


def _seal_aad(index: int, previous_hash: bytes) -> bytes:
    return (
        _AAD_DOMAIN
        + bytes((_ALG_AES256_GCM,))
        + index.to_bytes(_INDEX_BYTES, "big")
        + previous_hash
    )


def _seal_envelope(nonce: bytes, sealed: bytes) -> bytes:
    return _ENC_MAGIC + bytes((_ALG_AES256_GCM,)) + nonce + sealed


def _parse_envelope(payload: Any) -> tuple[int, bytes, bytes]:
    """Split an encrypted-entry envelope into ``(algorithm, nonce, sealed)``."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("entry.payload must be bytes")
    material = bytes(payload)
    if not material.startswith(_ENC_MAGIC):
        raise ValueError("payload is not an auditchain encrypted-entry envelope")
    offset = len(_ENC_MAGIC)
    try:
        algorithm = material[offset]
    except IndexError:
        raise ValueError("truncated envelope: missing algorithm byte") from None
    offset += 1
    if algorithm != _ALG_AES256_GCM:
        raise ValueError(f"unsupported encryption algorithm: {algorithm:#04x}")
    nonce_end = offset + _NONCE_BYTES
    if len(material) < nonce_end:
        raise ValueError("truncated envelope: missing nonce")
    nonce = material[offset:nonce_end]
    sealed = material[nonce_end:]
    if len(sealed) < _GCM_TAG_BYTES:
        raise ValueError("truncated envelope: ciphertext must include a 16-byte tag")
    return algorithm, nonce, sealed


def entry_digest(index: int, previous_hash: bytes, payload: bytes, *, hash_name: str = "sha256") -> bytes:
    """Digest binding an entry to its position and predecessor."""
    if not isinstance(index, int) or index < 0:
        raise ValueError("index must be a non-negative integer")
    digest_size = _digest_size(hash_name)
    previous = bytes(previous_hash)
    if len(previous) != digest_size:
        raise ValueError(f"previous_hash must be {digest_size} bytes")
    digest = hashlib.new(hash_name)
    digest.update(_DOMAIN)
    digest.update(index.to_bytes(_INDEX_BYTES, "big"))
    digest.update(previous)
    digest.update(bytes(payload))
    return digest.digest()


def decrypt_entry(entry: Any, key: Any, *, hash_name: str = "sha256") -> bytes:
    """Decrypt an entry produced by :meth:`AuditLog.encrypt`.

    Validates, in order, that ``entry`` is an :class:`Entry` with a
    well-formed encrypted-entry envelope, that ``key`` is 32 ``bytes``, that
    ``entry.entry_hash`` equals :func:`entry_digest` over the envelope at the
    entry's position, and finally the AES-256-GCM authentication tag with the
    same AAD used when sealing (``b"auditchain/aead/v1\\0" || 0x01 || index
    (u64 big-endian) || previous_hash``). Only then is the plaintext
    returned; plaintext encoding rules are the same as for :meth:`AuditLog.append`
    — callers receive exactly the bytes appended (a ``str`` comes back as its
    UTF-8 encoding). Type errors raise TypeError; a bad key length, a plain
    or malformed envelope, an unknown algorithm, an entry-digest mismatch or
    failed AEAD authentication raise ValueError. The call is read-only and
    never mutates the entry or a log.
    """
    if not isinstance(entry, Entry):
        raise TypeError("entry must be an Entry")
    if not isinstance(hash_name, str):
        raise TypeError("hash_name must be a string")
    _check_key(key)
    if not isinstance(entry.index, int) or isinstance(entry.index, bool):
        raise TypeError("entry.index must be an integer")
    if entry.index < 0 or entry.index >= (1 << 64):
        raise ValueError("entry.index is out of range for the entry framing")
    if not isinstance(entry.previous_hash, (bytes, bytearray)):
        raise TypeError("entry.previous_hash must be bytes")
    if not isinstance(entry.entry_hash, (bytes, bytearray)):
        raise TypeError("entry.entry_hash must be bytes")
    _, nonce, sealed = _parse_envelope(entry.payload)
    digest_size = _digest_size(hash_name)
    previous_hash = bytes(entry.previous_hash)
    if len(previous_hash) != digest_size:
        raise ValueError(f"entry.previous_hash must be {digest_size} bytes")
    expected_hash = entry_digest(
        entry.index,
        previous_hash,
        bytes(entry.payload),
        hash_name=hash_name,
    )
    if not hmac.compare_digest(expected_hash, bytes(entry.entry_hash)):
        raise ValueError("entry.entry_hash does not match the envelope digest")
    aad = _seal_aad(entry.index, previous_hash)
    try:
        return AESGCM(key).decrypt(nonce, sealed, aad)
    except InvalidTag as error:
        raise ValueError("AEAD authentication failed: wrong key or corrupted entry") from error


def _hash_parts(hash_name: str, *parts: bytes) -> bytes:
    digest = hashlib.new(hash_name)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _evolve_key(key: bytes, hash_name: str) -> bytes:
    """Derive the next-stage key; the predecessor key is discarded."""
    return _hash_parts(hash_name, _EVOLVE_DOMAIN, key)


def _locator_digest(payload: bytes, hash_name: str) -> bytes:
    """Content digest used only to locate candidate entries in the index."""
    return _hash_parts(hash_name, _LOCATE_DOMAIN, payload)


def _encrypted_locator_digest(key: bytes, payload: bytes, hash_name: str) -> bytes:
    """Keyed locator digest of an encrypted entry's original plaintext.

    ``HMAC(key, b"auditchain/encrypted-locate/v1\\0" || payload)``: only a
    holder of the append-time key can compute a candidate, and neither the
    plaintext nor the key is stored in the index.
    """
    return hmac.new(key, _ENC_LOCATE_DOMAIN + payload, hash_name).digest()


def _auth_tag(stage: int, entry_hash: bytes, key: bytes, hash_name: str) -> bytes:
    return hmac.new(
        key,
        _AUTH_DOMAIN + stage.to_bytes(_INDEX_BYTES, "big") + entry_hash,
        hash_name,
    ).digest()


def _leaf_hash(entry_hash: bytes, hash_name: str) -> bytes:
    return _hash_parts(hash_name, _LEAF_DOMAIN, entry_hash)


def _node_hash(left: bytes, right: bytes, hash_name: str) -> bytes:
    return _hash_parts(hash_name, _NODE_DOMAIN, left, right)


def _next_level(level: list[bytes], hash_name: str) -> list[bytes]:
    """Combine adjacent pairs; an odd trailing node is promoted unchanged."""
    combined = [
        _node_hash(level[index], level[index + 1], hash_name)
        for index in range(0, len(level) - 1, 2)
    ]
    if len(level) % 2:
        combined.append(level[-1])
    return combined


def _root_of(leaves: list[bytes], hash_name: str) -> bytes:
    if not leaves:
        return _hash_parts(hash_name, _EMPTY_DOMAIN)
    level = leaves
    while len(level) > 1:
        level = _next_level(level, hash_name)
    return level[0]


def _split_point(n: int) -> int:
    """Largest power of two strictly smaller than ``n`` (n >= 2)."""
    k = 1 << (n.bit_length() - 1)
    return k >> 1 if k == n else k


def _subproof(m: int, leaves: list[bytes], complete: bool, hash_name: str) -> list[bytes]:
    """RFC 6962 section 2.1.2 SUBPROOF over ``leaves`` (length n >= m >= 1).

    ``complete`` marks whether the root of the first ``m`` leaves is already
    known to the verifier of the enclosing proof.
    """
    n = len(leaves)
    if m == n:
        return [] if complete else [_root_of(leaves, hash_name)]
    k = _split_point(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete, hash_name) + [_root_of(leaves[k:], hash_name)]
    return _subproof(m - k, leaves[k:], False, hash_name) + [_root_of(leaves[:k], hash_name)]


def _subproof_length(m: int, n: int, complete: bool) -> int:
    """Node count of ``_subproof`` for sizes only (0 < m <= n)."""
    if m == n:
        return 0 if complete else 1
    k = _split_point(n)
    if m <= k:
        return _subproof_length(m, k, complete) + 1
    return _subproof_length(m - k, n - k, False) + 1


@dataclass(frozen=True)
class Entry:
    """One immutable log record."""

    index: int
    payload: bytes
    previous_hash: bytes
    entry_hash: bytes


@dataclass(frozen=True)
class PruneReceipt:
    """Sealed checkpoint for a verifiable prefix prune.

    Captures everything a later :meth:`AuditLog.prune` must agree with before
    the payloads of the first ``size`` entries may be released:

    - ``hash_name``: hash algorithm of the log that sealed the prefix,
    - ``size``: number of entries in the sealed prefix,
    - ``merkle_root``: Merkle root of the prefix,
    - ``chain_hash``: entry hash of the last prefix entry (the predecessor
      digest the first retained entry must carry); a digest-width zero
      predecessor for an empty prefix (``GENESIS_HASH`` under sha256).
    """

    hash_name: str
    size: int
    merkle_root: bytes
    chain_hash: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        if not isinstance(self.size, int) or isinstance(self.size, bool):
            raise TypeError("size must be an integer")
        if self.size < 0:
            raise ValueError("size must be non-negative")
        digest_size = _digest_size(self.hash_name)
        for name in ("merkle_root", "chain_hash"):
            value = getattr(self, name)
            if not isinstance(value, (bytes, bytearray)):
                raise TypeError(f"{name} must be bytes")
            if len(value) != digest_size:
                raise ValueError(f"{name} must be {digest_size} bytes")
            if not isinstance(value, bytes):
                object.__setattr__(self, name, bytes(value))

    def matches(self, entry: Any) -> bool:
        """Whether ``entry`` is the first record retained after this prefix.

        Its absolute index must equal ``size`` and its predecessor digest must
        equal ``chain_hash``. A receipt for the empty prefix matches the
        genesis record: an entry at index 0 whose predecessor is the
        digest-width zero value (``GENESIS_HASH`` under sha256).
        """
        if not isinstance(entry, Entry):
            raise TypeError("entry must be an Entry")
        return entry.index == self.size and entry.previous_hash == self.chain_hash


@dataclass(frozen=True)
class AuditReceipt:
    """Offline receipt for selected entries of a snapshot.

    Issued by :meth:`AuditLog.audit_receipt` and verified entirely offline
    by :func:`verify_audit_receipt`:

    - ``version``: receipt format version, always ``1``,
    - ``hash_name``: hash algorithm of the log that issued the receipt,
    - ``size``: number of entries in the snapshot the receipt refers to,
    - ``root``: Merkle root of that snapshot,
    - ``items``: ``(Entry, proof)`` pairs in ascending absolute index order,
      where ``proof`` is the tuple of sibling digests of the entry's
      inclusion proof within the snapshot. Every receipt for a non-empty
      snapshot carries its last entry (index ``size - 1``) with its inclusion
      proof; only an empty snapshot (``size == 0``) carries ``items == ()``,
      and an empty snapshot never carries any items.
    """

    version: int
    hash_name: str
    size: int
    root: bytes
    items: tuple

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or isinstance(self.version, bool):
            raise TypeError("version must be an integer")
        if self.version != 1:
            raise ValueError("version must be 1")
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        digest_size = _digest_size(self.hash_name)
        if not isinstance(self.size, int) or isinstance(self.size, bool):
            raise TypeError("size must be an integer")
        if self.size < 0:
            raise ValueError("size must be non-negative")
        if not isinstance(self.root, (bytes, bytearray)):
            raise TypeError("root must be bytes")
        if len(self.root) != digest_size:
            raise ValueError(f"root must be {digest_size} bytes")
        if not isinstance(self.root, bytes):
            object.__setattr__(self, "root", bytes(self.root))
        if not isinstance(self.items, tuple):
            raise TypeError("items must be a tuple of (Entry, proof) pairs")
        previous_index = -1
        for item in self.items:
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError("each item must be an (Entry, proof) tuple")
            entry, proof = item
            if not isinstance(entry, Entry):
                raise TypeError("item entry must be an Entry")
            if not isinstance(entry.index, int) or isinstance(entry.index, bool):
                raise TypeError("entry.index must be an integer")
            if entry.index < 0:
                raise ValueError("entry.index must be non-negative")
            for name in ("payload", "previous_hash", "entry_hash"):
                if not isinstance(getattr(entry, name), (bytes, bytearray)):
                    raise TypeError(f"entry.{name} must be bytes")
            if len(entry.previous_hash) != digest_size:
                raise ValueError(f"entry.previous_hash must be {digest_size} bytes")
            if len(entry.entry_hash) != digest_size:
                raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
            if entry.index <= previous_index:
                raise ValueError("item indices must be in strictly ascending order")
            previous_index = entry.index
            if not isinstance(proof, tuple):
                raise TypeError("item proof must be a tuple of digests")
            for sibling in proof:
                if not isinstance(sibling, (bytes, bytearray)):
                    raise TypeError("proof element must be bytes")
                if len(sibling) != digest_size:
                    raise ValueError(f"proof element must be {digest_size} bytes")
        if self.size == 0:
            if self.items:
                raise ValueError("an empty snapshot receipt must carry no items")
        elif not self.items or self.items[-1][0].index != self.size - 1:
            # A non-empty snapshot receipt must carry the entry at
            # index size - 1 with its inclusion proof; an items==() receipt
            # for size > 0 would attest to an arbitrary root with no
            # evidence at all and must never be constructible.
            raise ValueError(
                "a receipt for a non-empty snapshot must include the entry "
                "at index size - 1"
            )


@dataclass(frozen=True)
class SignedRoot:
    """Ed25519-signed snapshot-root checkpoint.

    Issued by :meth:`AuditLog.sign_root` and verified entirely offline by
    :func:`verify_signed_root` against a pre-trusted 32-byte Ed25519 public
    key, so a receipt can cross processes and storage media without anyone
    re-holding the log:

    - ``version``: format version, always ``1``,
    - ``hash_name``: hash algorithm of the signing log,
    - ``size``: number of entries in the attested prefix,
    - ``root``: Merkle root of that prefix,
    - ``head``: chain head at that prefix (the entry hash of its last record,
      the digest-width zero value for an empty prefix),
    - ``signature``: the 64-byte Ed25519 signature over the fields.

    Instances are immutable, may be built positionally and compare by all six
    fields.
    """

    version: int
    hash_name: str
    size: int
    root: bytes
    head: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or isinstance(self.version, bool):
            raise TypeError("version must be an integer")
        if self.version != _SIGNED_ROOT_VERSION:
            raise ValueError("version must be 1")
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        digest_size = _digest_size(self.hash_name)
        if not isinstance(self.size, int) or isinstance(self.size, bool):
            raise TypeError("size must be an integer")
        if not 0 <= self.size < _U64_LIMIT:
            raise ValueError("size must satisfy 0 <= size < 2**64")
        # root, head and signature must be exact bytes: bytearray and
        # memoryview are rejected rather than copied, so a received receipt
        # never silently aliases a mutable caller buffer.
        for name in ("root", "head", "signature"):
            value = getattr(self, name)
            if not isinstance(value, bytes):
                raise TypeError(f"{name} must be bytes")
        if len(self.root) != digest_size:
            raise ValueError(f"root must be {digest_size} bytes")
        if len(self.head) != digest_size:
            raise ValueError(f"head must be {digest_size} bytes")
        if len(self.signature) != _ED25519_SIGNATURE_BYTES:
            raise ValueError(
                f"signature must be {_ED25519_SIGNATURE_BYTES} bytes"
            )


@dataclass(frozen=True)
class SignedAuditBatch:
    """Compact batch audit receipt sealed by a pre-trusted Ed25519 key.

    Bundles the five-tuple of :meth:`AuditLog.audit_batch` with the
    :class:`SignedRoot` checkpoint of :meth:`AuditLog.sign_root`, so an
    offline receiver holding only a pre-trusted 32-byte Ed25519 public key
    can confirm in one artifact that the selected entries, the snapshot
    Merkle root and the chain head were all issued by the log holder —
    without holding the :class:`AuditLog`:

    - ``batch``: the ``(hash_name, size, root, entries, proof)`` five-tuple
      produced by :meth:`AuditLog.audit_batch`,
    - ``checkpoint``: the :class:`SignedRoot` produced by
      :meth:`AuditLog.sign_root` for the same snapshot.

    Instances are immutable, may be built positionally and compare by both
    fields. Only the container shape is validated here: ``batch`` must be a
    tuple and ``checkpoint`` a :class:`SignedRoot`; the batch tuple's own
    structural contract is left to :func:`verify_audit_batch`, so a field of
    the wrong type raises TypeError.
    """

    batch: tuple
    checkpoint: SignedRoot

    def __post_init__(self) -> None:
        if not isinstance(self.batch, tuple):
            raise TypeError("batch must be the audit_batch five-tuple")
        if not isinstance(self.checkpoint, SignedRoot):
            raise TypeError("checkpoint must be a SignedRoot")


@dataclass(frozen=True)
class SignedConsistency:
    """Ed25519-sealed proof that one signed snapshot extends another.

    Issued by :meth:`AuditLog.signed_consistency` and verified entirely
    offline by :func:`verify_signed_consistency` against a pre-trusted
    32-byte Ed25519 public key, so a receiver holding neither the log nor
    any checkpoint history can confirm that both snapshots were signed by
    the log holder and that the newer one is the older one extended by
    appends only:

    - ``old``: the :class:`SignedRoot` checkpoint of the earlier prefix,
    - ``new``: the :class:`SignedRoot` checkpoint of the later prefix,
    - ``proof``: the tuple of Merkle consistency-proof digests linking the
      two snapshot roots, byte-for-byte the output of
      :meth:`AuditLog.consistency_proof` for the two sizes.

    Instances are immutable, may be built positionally and compare by all
    three fields. Only the container shape is validated here: ``old`` and
    ``new`` must be :class:`SignedRoot` instances and ``proof`` a tuple of
    ``bytes``; a field of the wrong type raises TypeError.
    """

    old: SignedRoot
    new: SignedRoot
    proof: tuple

    def __post_init__(self) -> None:
        if not isinstance(self.old, SignedRoot):
            raise TypeError("old must be a SignedRoot")
        if not isinstance(self.new, SignedRoot):
            raise TypeError("new must be a SignedRoot")
        if not isinstance(self.proof, tuple):
            raise TypeError("proof must be a tuple of digests")
        for node in self.proof:
            if not isinstance(node, bytes):
                raise TypeError("proof element must be bytes")


@dataclass(frozen=True)
class SignedPrune:
    """Ed25519-authorized prune: a sealed prefix receipt plus its signed checkpoint.

    Bundles the :class:`PruneReceipt` of :meth:`AuditLog.seal` with the
    :class:`SignedRoot` checkpoint of :meth:`AuditLog.sign_root` for the very
    same prefix, so an offline receiver holding only a pre-trusted 32-byte
    Ed25519 public key can confirm that the prune authorization — the prefix
    hash algorithm, size, Merkle root and chain head — was issued by the log
    holder before the prefix payloads are released:

    - ``receipt``: the :class:`PruneReceipt` produced by
      :meth:`AuditLog.seal` for the prefix,
    - ``checkpoint``: the :class:`SignedRoot` produced by
      :meth:`AuditLog.sign_root` for that same prefix.

    Instances are immutable, may be built positionally and compare by both
    fields. Only the container shape is validated here: ``receipt`` must be a
    :class:`PruneReceipt` and ``checkpoint`` a :class:`SignedRoot`; whether the
    two describe the same prefix and whether the signature verifies is left to
    :func:`verify_signed_prune`, so a field of the wrong type raises TypeError.
    """

    receipt: PruneReceipt
    checkpoint: SignedRoot

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, PruneReceipt):
            raise TypeError("receipt must be a PruneReceipt")
        if not isinstance(self.checkpoint, SignedRoot):
            raise TypeError("checkpoint must be a SignedRoot")


@dataclass(frozen=True)
class AuthTag:
    """Immutable forward-secure authentication tag for one entry.

    - ``stage``: key-evolution stage the tag was minted at (0 before the first
      evolution); tags at different stages never verify against one another.
    - ``tag``: HMAC digest over the entry hash at that stage.
    """

    stage: int
    tag: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.stage, int) or isinstance(self.stage, bool):
            raise TypeError("stage must be an integer")
        if self.stage < 0:
            raise ValueError("stage must be non-negative")
        if self.stage >= _MAX_STAGE:
            raise ValueError("stage must be less than 2**64")
        if not isinstance(self.tag, bytes):
            raise TypeError("tag must be bytes")


@dataclass(frozen=True)
class Verifier:
    """Immutable verification state exported before the first key evolution.

    Holds the stage-0 key and the hash algorithm; :func:`verify_auth` evolves
    this key forward to the tag's stage without needing the log.
    """

    key: bytes
    hash_name: str

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes):
            raise TypeError("key must be bytes")
        if len(self.key) == 0:
            raise ValueError("key must be non-empty")
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        _digest_size(self.hash_name)


# Issue codes reported by AuditLog.verify_report(). The first three pinpoint a
# mismatch at a retained entry's absolute index; "head" pinpoints no entry,
# only that the recomputed chain head does not equal the recorded log head.
_ISSUE_INDEX = "index"
_ISSUE_PREVIOUS_HASH = "previous_hash"
_ISSUE_ENTRY_HASH = "entry_hash"
_ISSUE_HEAD = "head"
_ISSUE_CODES = frozenset(
    {_ISSUE_INDEX, _ISSUE_PREVIOUS_HASH, _ISSUE_ENTRY_HASH, _ISSUE_HEAD}
)


@dataclass(frozen=True)
class IntegrityIssue:
    """One locateable integrity problem found by :meth:`AuditLog.verify_report`.

    - ``code``: one of ``"index"``, ``"previous_hash"``, ``"entry_hash"``
      (a mismatch at the retained entry given by ``index``) or ``"head"``
      (the recomputed chain head does not match the recorded log head);
    - ``index``: the absolute index of the offending entry, or ``None`` for
      the entry-independent trailing ``"head"`` issue (and only for it).

    Issues compare and hash by their two fields and may be built positionally.
    """

    code: str
    index: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.code, str):
            raise TypeError("code must be a string")
        if self.code not in _ISSUE_CODES:
            raise ValueError(
                f"unknown issue code {self.code!r}; expected one of "
                f"'index', 'previous_hash', 'entry_hash', 'head'"
            )
        if self.code == _ISSUE_HEAD:
            if self.index is not None:
                raise ValueError("a 'head' issue must carry index None")
        elif not isinstance(self.index, int) or isinstance(self.index, bool):
            raise TypeError("index must be an integer or None")
        elif self.index < 0:
            raise ValueError("index must be non-negative")


@dataclass(frozen=True)
class IntegrityReport:
    """Result of :meth:`AuditLog.verify_report`.

    ``issues`` holds :class:`IntegrityIssue` values in ascending absolute
    index order; the entry-independent ``("head", None)`` issue, when present,
    is the trailing element. ``ok`` is the single source of truth and is
    ``True`` exactly when ``issues`` is empty. Reports compare by their fields
    (``ok`` and ``issues`` only) and may be built positionally.
    """

    ok: bool
    issues: tuple

    def __post_init__(self) -> None:
        if not isinstance(self.ok, bool):
            raise TypeError("ok must be a bool")
        if not isinstance(self.issues, tuple):
            raise TypeError("issues must be a tuple")
        for issue in self.issues:
            if not isinstance(issue, IntegrityIssue):
                raise TypeError("each issue must be an IntegrityIssue")
        rank = {
            _ISSUE_INDEX: 0,
            _ISSUE_PREVIOUS_HASH: 1,
            _ISSUE_ENTRY_HASH: 2,
            _ISSUE_HEAD: 3,
        }

        def order_key(issue: IntegrityIssue) -> tuple[int, int, int]:
            # The index-less "head" issue sorts after every indexed position.
            if issue.code == _ISSUE_HEAD:
                return (1, 0, rank[_ISSUE_HEAD])
            return (0, issue.index, rank[issue.code])  # type: ignore[arg-type]

        previous_key: tuple[int, int, int] | None = None
        for position, issue in enumerate(self.issues):
            if issue.code == _ISSUE_HEAD and position != len(self.issues) - 1:
                raise ValueError("a 'head' issue may only be the final issue")
            key = order_key(issue)
            if previous_key is not None and key <= previous_key:
                raise ValueError(
                    "issues must be in ascending index order, with codes "
                    "'index', 'previous_hash', 'entry_hash' at one position"
                )
            previous_key = key
        if self.ok != (len(self.issues) == 0):
            raise ValueError("ok must be True exactly when issues is empty")


class AuditLog:
    """Append-only hash chain held in memory.

    A pruned log keeps only entries from ``retain_from`` onward. Absolute
    indices, the chain head and every rebuildable Merkle snapshot stay
    identical to an unpruned log holding the same records; snapshots wholly
    inside a pruned prefix can no longer be produced.
    """

    def __init__(self, *, key: bytes | None = None, hash_name: str = "sha256") -> None:
        digest_size = _digest_size(hash_name)
        genesis = bytes(digest_size)
        if key is not None:
            if not isinstance(key, bytes):
                raise TypeError("key must be bytes")
            if len(key) == 0:
                raise ValueError("key must be non-empty")
        self._hash_name = hash_name
        self._digest_size = digest_size
        self._entries: list[Entry] = []
        self._retain_from = 0
        self._head: bytes = genesis
        # Locator index for find(): payload digest -> ascending absolute
        # indices of the retained entries carrying that digest. Digests only
        # narrow the candidates; find() always re-compares the stored payload.
        self._index: dict[bytes, list[int]] = {}
        # Keyed locator index for find_encrypted(): HMAC over the original
        # plaintext -> ascending absolute indices of retained encrypted
        # entries. Holds neither plaintext nor keys; a hit is always confirmed
        # by decrypting with the query key and byte-comparing the plaintext.
        self._encrypted_index: dict[bytes, list[int]] = {}
        # Reverse map (absolute index -> its locator digest) so a prune can
        # drop released encrypted entries from _encrypted_index without the
        # append-time key; only retained entries are present.
        self._encrypted_locators: dict[int, bytes] = {}
        # Chain hash of the last pruned entry (the digest_size-byte zero
        # predecessor before any prune).
        self._checkpoint_head: bytes = genesis
        # Roots of the maximal perfect subtrees covering [0, retain_from),
        # keyed by subtree height (a subtree of height h holds 2**h leaves).
        self._frontier: dict[int, bytes] = {}
        # Forward-secure authentication state. ``key is None`` is keyless
        # mode: the authentication interface is disabled.
        self._key: bytes | None = key
        self._stage = 0
        self._verifier_exported = False
        # Tags of retained entries, keyed by absolute index.
        self._tags: dict[int, AuthTag] = {}
        # Nonces already used by encrypt(); retained for the log's whole
        # lifetime, including across prunes, so a nonce can never repeat
        # under the same log even after its envelope has been released.
        self._used_nonces: set[bytes] = set()

    @property
    def hash_name(self) -> str:
        return self._hash_name

    @property
    def retain_from(self) -> int:
        """Absolute index of the first entry still held after the last prune."""
        return self._retain_from

    def __len__(self) -> int:
        return self._retain_from + len(self._entries)

    def __iter__(self) -> Iterator[Entry]:
        return iter(self._entries)

    @property
    def head(self) -> bytes:
        return self._head

    def append(self, payload: Any) -> Entry:
        material = _as_bytes(payload)
        index = len(self)
        entry = Entry(
            index=index,
            payload=material,
            previous_hash=self._head,
            entry_hash=entry_digest(index, self._head, material, hash_name=self._hash_name),
        )
        self._entries.append(entry)
        self._index.setdefault(_locator_digest(material, self._hash_name), []).append(index)
        self._head = entry.entry_hash
        return entry

    def encrypt(self, payload: Any, key: Any, nonce: Any = None) -> Entry:
        """Append an AES-256-GCM-encrypted entry.

        Behaves exactly like :meth:`append` structurally — the next absolute
        index, predecessor link and entry digest follow the same rules — but
        the stored ``Entry.payload`` is a self-describing envelope rather than
        the plaintext:

        ``b"auditchain/encrypted-entry/v1\\0" || 0x01 || nonce (12) ||
        ciphertext || tag (16)``.

        The GCM additional authenticated data binds the ciphertext to its
        chain position:

        ``b"auditchain/aead/v1\\0" || 0x01 || index (u64 big-endian) ||
        previous_hash``.

        ``key`` must be 32 ``bytes`` and is never stored; ``nonce`` must be
        12 ``bytes`` and must never repeat within this log (history is kept
        for the log's lifetime, including after prunes). When ``nonce`` is
        ``None`` a fresh ``os.urandom(12)`` nonce is generated. The envelope
        itself is what participates in :func:`entry_digest`; use the
        top-level :func:`decrypt_entry` to recover the plaintext. Any failure
        raises before the log is touched, leaving all state unchanged.
        """
        material = _as_bytes(payload)
        _check_key(key)
        if nonce is None:
            nonce = os.urandom(_NONCE_BYTES)
        else:
            _check_nonce(nonce)
            if nonce in self._used_nonces:
                raise ValueError("nonce has already been used in this log")
        # Also defend against the astronomically unlikely random collision.
        while nonce in self._used_nonces:
            nonce = os.urandom(_NONCE_BYTES)
        index = len(self)
        previous_hash = self._head
        aad = _seal_aad(index, previous_hash)
        sealed = AESGCM(key).encrypt(nonce, material, aad)
        envelope = _seal_envelope(nonce, sealed)
        # The plaintext locator is keyed with this append's key. Compute it
        # before committing while the plaintext is at hand; the digest leaks
        # neither the plaintext nor the key.
        encrypted_locator = _encrypted_locator_digest(
            key, material, self._hash_name
        )
        # Encryption succeeded; commit exactly as append() does, plus the
        # plaintext locator entry. Nothing before this point mutates the log,
        # so a failed encrypt leaves both indexes untouched.
        entry = Entry(
            index=index,
            payload=envelope,
            previous_hash=previous_hash,
            entry_hash=entry_digest(index, previous_hash, envelope, hash_name=self._hash_name),
        )
        self._entries.append(entry)
        self._index.setdefault(_locator_digest(envelope, self._hash_name), []).append(index)
        self._encrypted_index.setdefault(encrypted_locator, []).append(index)
        self._encrypted_locators[index] = encrypted_locator
        self._used_nonces.add(nonce)
        self._head = entry.entry_hash
        return entry

    @property
    def stage(self) -> int:
        """Current key-evolution stage (0 before the first evolution)."""
        return self._stage

    def _require_key(self) -> bytes:
        if self._key is None:
            raise ValueError(
                "authentication is disabled: construct AuditLog with a non-empty key"
            )
        return self._key

    def auth(self, index: int) -> AuthTag:
        """Mint a forward-secure tag for the retained entry at ``index``.

        The tag is an HMAC over the entry hash at the current stage. Right
        after minting, the key is replaced by its one-way evolution and the
        stage advances, so a later compromise cannot forge tags for entries
        authenticated earlier. The log itself is not modified.
        """
        key = self._require_key()
        entry = self.entry(index)
        # Compute everything before mutating: a failure leaves the
        # authentication and log state untouched.
        tag = AuthTag(
            stage=self._stage,
            tag=_auth_tag(self._stage, entry.entry_hash, key, self._hash_name),
        )
        new_key = _evolve_key(key, self._hash_name)
        self._tags[index] = tag
        self._key = new_key
        self._stage += 1
        return tag

    def auth_batch(
        self, indices: Iterable[int]
    ) -> tuple[tuple[Entry, AuthTag], ...]:
        """Mint forward-secure tags for many retained entries in one call.

        The batch equivalent of :meth:`auth`: ``indices`` is an iterable of
        distinct non-bool integers; the selected entries are issued in
        ascending absolute index order and returned as ``(Entry, AuthTag)``
        pairs in that order, an empty selection yielding ``()``. The j-th tag
        (j from 0) is minted at the initial stage plus j, reusing exactly the
        HMAC domain, 8-byte big-endian stage encoding and key-evolution of
        :meth:`auth`, so each item is byte-for-byte what j consecutive
        ascending :meth:`auth` calls would have produced; on success the key
        has evolved and the stage advanced exactly once per selected entry.

        Every index and the retained range, and the requirement that
        ``stage + count < 2**64``, are validated before any tag is computed:
        a failure leaves the key, stage, stored tags and log untouched. The
        call never appends an entry and never changes the hash chain, Merkle
        roots, search indexes or any other public object. Wrong index types
        raise TypeError; duplicate or out-of-range indices or exhausting the
        u64 stage space raise ValueError (a non-retained index raises
        IndexError, exactly as :meth:`auth`); keyless mode raises ValueError.
        """
        key = self._require_key()
        try:
            iterator = iter(indices)
        except TypeError:
            raise TypeError("indices must be an iterable of integers") from None
        selected: set[int] = set()
        ordered: list[int] = []
        for index in iterator:
            if not isinstance(index, int) or isinstance(index, bool):
                raise TypeError("indices must be non-bool integers")
            if index in selected:
                raise ValueError(f"duplicate index {index}")
            # entry() also type- and range-checks, but resolve every entry up
            # front so a bad index aborts before the key evolves even once.
            if not self._retain_from <= index < len(self):
                raise IndexError(f"no retained entry at index {index}")
            selected.add(index)
            ordered.append(index)
        ordered.sort()
        count = len(ordered)
        if self._stage + count >= _MAX_STAGE:
            raise ValueError("stage limit reached; cannot evolve the key that far")
        # All validation passed; compute tags against the current key and
        # commit the whole batch in one step, so the only mutation below is
        # the final state swap.
        current_key = key
        items: list[tuple[Entry, AuthTag]] = []
        new_tags: dict[int, AuthTag] = {}
        for position, index in enumerate(ordered):
            stage = self._stage + position
            entry = self._entries[index - self._retain_from]
            tag = AuthTag(
                stage=stage,
                tag=_auth_tag(stage, entry.entry_hash, current_key, self._hash_name),
            )
            items.append((entry, tag))
            new_tags[index] = tag
            current_key = _evolve_key(current_key, self._hash_name)
        self._tags.update(new_tags)
        self._key = current_key
        self._stage += count
        return tuple(items)

    def rotate_key(self) -> None:
        """Evolve the authentication key once without minting a tag."""
        key = self._require_key()
        if self._stage >= _MAX_STAGE - 1:
            raise ValueError("stage limit reached; cannot evolve the key further")
        self._key = _evolve_key(key, self._hash_name)
        self._stage += 1

    def export_verifier(self) -> Verifier:
        """Export the stage-0 verification material exactly once.

        Only callable before the first key evolution (no :meth:`auth` or
        :meth:`rotate_key` yet) and only once. The returned :class:`Verifier`
        lets anyone verify tags at any later stage without the evolving key.
        """
        self._require_key()
        if self._stage != 0 or self._verifier_exported:
            raise ValueError(
                "verifier can only be exported once and before the first key evolution"
            )
        verifier = Verifier(key=self._key, hash_name=self._hash_name)  # type: ignore[arg-type]
        self._verifier_exported = True
        return verifier

    def entries(self) -> list[Entry]:
        return list(self._entries)

    def entry(self, index: int) -> Entry:
        if not isinstance(index, int):
            raise TypeError("index must be an integer")
        if not self._retain_from <= index < len(self):
            raise IndexError(f"no retained entry at index {index}")
        return self._entries[index - self._retain_from]

    def find(
        self, payload: Any, start: int | None = None, stop: int | None = None
    ) -> tuple[int, ...]:
        """Absolute indices of retained entries whose payload equals ``payload``.

        ``payload`` accepts ``bytes`` or ``str`` (UTF-8 encoded); anything
        else raises TypeError. The search covers the half-open range
        ``[start, stop)`` of absolute indices, defaulting to
        ``[retain_from, len(log))``. Explicit bounds must be non-bool
        integers satisfying ``retain_from <= start <= stop <= len(log)``;
        wrong types raise TypeError, out-of-range values ValueError. Matches
        come back as a tuple in ascending order, ``()`` when nothing
        matches. Lookups go through the incrementally maintained digest
        index, but every candidate's stored payload is re-compared, so a
        digest collision can never produce a false hit. The query is
        read-only: entries, head, authentication state, Merkle roots and
        proofs are all left untouched.
        """
        if isinstance(payload, str):
            material = payload.encode("utf-8")
        elif isinstance(payload, bytes):
            material = payload
        else:
            raise TypeError("payload must be bytes or str")
        start, stop = self._resolve_find_range(start, stop)
        candidates = self._index.get(_locator_digest(material, self._hash_name), ())
        return tuple(
            index
            for index in candidates
            if start <= index < stop
            and self._entries[index - self._retain_from].payload == material
        )

    def _resolve_find_range(
        self, start: int | None, stop: int | None
    ) -> tuple[int, int]:
        """Validate the half-open ``[start, stop)`` range shared by find and
        find_encrypted, applying the same defaults and bounds as ``find``.

        Defaults are ``[retain_from, len(log))``; explicit bounds must be
        non-bool integers satisfying
        ``retain_from <= start <= stop <= len(log)``. Wrong types raise
        TypeError and out-of-range values ValueError.
        """
        first = self._retain_from
        last = len(self)
        if start is None:
            start = first
        elif not isinstance(start, int) or isinstance(start, bool):
            raise TypeError("start must be an integer")
        if stop is None:
            stop = last
        elif not isinstance(stop, int) or isinstance(stop, bool):
            raise TypeError("stop must be an integer")
        if not first <= start <= stop <= last:
            raise ValueError(
                f"range must satisfy retain_from ({first}) <= start <= stop <= len ({last})"
            )
        return start, stop

    def find_encrypted(
        self, payload: Any, key: Any, start: int | None = None, stop: int | None = None
    ) -> tuple[int, ...]:
        """Locate retained encrypted entries whose original plaintext equals
        ``payload``, using the key supplied when they were appended.

        ``payload`` accepts ``bytes`` or ``str`` (normalized to ``P``; a
        ``str`` is UTF-8 encoded); anything else raises TypeError. ``key``
        must be exactly 32 ``bytes`` — a non-bytes value raises TypeError and
        a wrong length raises ValueError. The range defaults and half-open
        ``[start, stop)`` bounds are exactly those of :meth:`find`. Candidates
        come from a keyed locator index storing only
        ``HMAC(key, b"auditchain/encrypted-locate/v1\\0" || P, hash_name)``
        against absolute indices; the index holds neither plaintext nor keys
        and never changes the ciphertext envelope, entry digests, the chain
        or Merkle results.

        Every candidate is confirmed by decrypting the stored envelope with
        the query key and comparing the recovered plaintext byte-for-byte
        against ``P``, so an authentication failure or a digest collision can
        never produce a false hit. A valid 32-byte key that simply was not the
        append key yields ``()`` rather than raising. Plain entries and
        entries sealed under other keys never match. The query is read-only
        and never stores the plaintext, the key or the locator digest.
        """
        if isinstance(payload, str):
            material = payload.encode("utf-8")
        elif isinstance(payload, bytes):
            material = payload
        else:
            raise TypeError("payload must be bytes or str")
        _check_key(key)
        start, stop = self._resolve_find_range(start, stop)
        locator = _encrypted_locator_digest(key, material, self._hash_name)
        matches: list[int] = []
        for index in self._encrypted_index.get(locator, ()):
            if not start <= index < stop:
                continue
            entry = self._entries[index - self._retain_from]
            try:
                plaintext = decrypt_entry(entry, key, hash_name=self._hash_name)
            except ValueError:
                # A candidate under the locator digest that does not
                # authenticate with this key (a collision or a foreign key)
                # is simply not a hit.
                continue
            if plaintext == material:
                matches.append(index)
        return tuple(matches)

    def verify_entry(self, index: int) -> bool:
        """Check that one retained entry links correctly to its predecessor."""
        entry = self.entry(index)
        if entry.index != index:
            return False
        if index == 0:
            previous = bytes(self._digest_size)
        elif index == self._retain_from:
            previous = self._checkpoint_head
        else:
            previous = self._entries[index - self._retain_from - 1].entry_hash
        if entry.previous_hash != previous:
            return False
        return entry.entry_hash == entry_digest(
            entry.index, entry.previous_hash, entry.payload, hash_name=self._hash_name
        )

    def verify(self) -> bool:
        """Whether the retained chain is intact (``verify_report().ok``)."""
        return self.verify_report().ok

    def verify_report(self) -> IntegrityReport:
        """Verify the retained chain, locating every mismatch in the result.

        Walks the retained entries forward from the prune checkpoint — the
        digest-width zero predecessor for an unpruned or empty log, the sealed
        checkpoint after a prune. At each expected absolute index the entry
        digest is recomputed as
        ``H(b"auditchain/entry/v1" || index (u64 big-endian) ||
        previous_recomputed || payload)`` with the log's own hash algorithm
        and digest width, and compared against the recorded index,
        predecessor and entry digest. After the walk the final recomputed
        digest must equal the recorded :attr:`head`.

        Structurally valid data that simply does not match is collected as
        :class:`IntegrityIssue` records with ``ok=False`` rather than raised:
        at one position the codes appear in the order ``"index"``,
        ``"previous_hash"``, ``"entry_hash"``; a head mismatch appends the
        trailing ``("head", None)``. Issues are listed in ascending absolute
        index order. Walking always continues with the *expected* index and
        the *recomputed* predecessor, so later damage is diagnosed even after
        an earlier mismatch. Illegal fields still raise TypeError or
        ValueError exactly as elsewhere (a non-``Entry`` record, an index that
        is not a non-bool non-negative integer, a non-bytes field, or a
        predecessor/entry digest of the wrong width); such structural
        corruption is reported as an exception, never as an issue. The call is
        read-only.
        """
        issues: list[IntegrityIssue] = []
        previous = self._checkpoint_head
        for offset, entry in enumerate(self._entries):
            index = self._retain_from + offset
            if not isinstance(entry, Entry):
                raise TypeError("entry must be an Entry")
            if not isinstance(entry.index, int) or isinstance(entry.index, bool):
                raise TypeError("entry.index must be an integer")
            if entry.index < 0:
                raise ValueError("entry.index must be non-negative")
            for name in ("payload", "previous_hash", "entry_hash"):
                if not isinstance(getattr(entry, name), (bytes, bytearray)):
                    raise TypeError(f"entry.{name} must be bytes")
            if len(entry.previous_hash) != self._digest_size:
                raise ValueError(
                    f"entry.previous_hash must be {self._digest_size} bytes"
                )
            if len(entry.entry_hash) != self._digest_size:
                raise ValueError(
                    f"entry.entry_hash must be {self._digest_size} bytes"
                )
            if entry.index != index:
                issues.append(IntegrityIssue(_ISSUE_INDEX, index))
            if entry.previous_hash != previous:
                issues.append(IntegrityIssue(_ISSUE_PREVIOUS_HASH, index))
            recomputed = entry_digest(
                index, previous, bytes(entry.payload), hash_name=self._hash_name
            )
            if entry.entry_hash != recomputed:
                issues.append(IntegrityIssue(_ISSUE_ENTRY_HASH, index))
            previous = recomputed
        if previous != self._head:
            issues.append(IntegrityIssue(_ISSUE_HEAD, None))
        return IntegrityReport(ok=not issues, issues=tuple(issues))

    def _resolve_size(self, size: int | None) -> int:
        if size is None:
            return len(self)
        if not isinstance(size, int):
            raise TypeError("size must be an integer")
        if not 0 <= size <= len(self):
            raise ValueError(f"size must be within 0..{len(self)}")
        return size

    def _require_retained_snapshot(self, size: int) -> None:
        if size < self._retain_from:
            raise ValueError(
                f"snapshot at size {size} was pruned (entries are retained from {self._retain_from})"
            )

    def _chain_head_at(self, size: int) -> bytes:
        """Entry hash of the last entry of the prefix (zero predecessor at 0)."""
        if size == 0:
            return bytes(self._digest_size)
        if size == self._retain_from:
            return self._checkpoint_head
        return self._entries[size - self._retain_from - 1].entry_hash

    def _occupied_at(self, size: int) -> dict[int, bytes]:
        """Perfect-subtree stack (height -> root) covering the first ``size`` leaves."""
        occupied = dict(self._frontier)
        for entry in self._entries[: size - self._retain_from]:
            node = _leaf_hash(entry.entry_hash, self._hash_name)
            height = 0
            while height in occupied:
                node = _node_hash(occupied.pop(height), node, self._hash_name)
                height += 1
            occupied[height] = node
        return occupied

    def _fold_occupied(self, occupied: dict[int, bytes]) -> bytes:
        if not occupied:
            return _hash_parts(self._hash_name, _EMPTY_DOMAIN)
        root: bytes | None = None
        # Low blocks are the rightmost subtrees; fold them in from the right.
        for height in sorted(occupied):
            node = occupied[height]
            root = node if root is None else _node_hash(node, root, self._hash_name)
        return root  # type: ignore[return-value]

    def merkle_root(self, size: int | None = None) -> bytes:
        """Root of the Merkle tree over the first ``size`` entries.

        Defaults to the whole log. Appending later entries never changes
        the root of an earlier prefix. A prefix already released by
        :meth:`prune` cannot be rebuilt and raises ValueError.
        """
        size = self._resolve_size(size)
        if size == 0:
            return _hash_parts(self._hash_name, _EMPTY_DOMAIN)
        self._require_retained_snapshot(size)
        return self._fold_occupied(self._occupied_at(size))

    def _frontier_blocks(self) -> dict[tuple[int, int], bytes]:
        """Checkpoint subtrees as ``(height, level node index)`` nodes."""
        blocks: dict[tuple[int, int], bytes] = {}
        start = 0
        for height in sorted(self._frontier, reverse=True):
            blocks[(height, start >> height)] = self._frontier[height]
            start += 1 << height
        return blocks

    def _perfect_node(self, height: int, index: int, blocks: dict[tuple[int, int], bytes]) -> bytes:
        """Root of the aligned perfect subtree ``[index*2**height, (index+1)*2**height)``."""
        cached = blocks.get((height, index))
        if cached is not None:
            return cached
        if height == 0:
            absolute = index
            if absolute < self._retain_from:
                raise ValueError(
                    f"snapshot data at index {absolute} was pruned "
                    f"(entries are retained from {self._retain_from})"
                )
            entry = self._entries[absolute - self._retain_from]
            return _leaf_hash(entry.entry_hash, self._hash_name)
        left = self._perfect_node(height - 1, index * 2, blocks)
        right = self._perfect_node(height - 1, index * 2 + 1, blocks)
        return _node_hash(left, right, self._hash_name)

    def _level_node(
        self, height: int, index: int, size: int, blocks: dict[tuple[int, int], bytes]
    ) -> bytes:
        """Node at ``index`` of tree level ``height`` under the promotion rule.

        Levels combine adjacent pairs and promote the odd trailing node
        unchanged. A level node is promoted only when it is the trailing index
        while its parent level had an odd node count; otherwise it is the hash
        of its two children.
        """
        start = index << height
        if start + (1 << height) <= size:
            return self._perfect_node(height, index, blocks)
        if height == 0:
            return self._perfect_node(0, index, blocks)
        lower_count = (size + (1 << (height - 1)) - 1) >> (height - 1)
        if index * 2 + 1 >= lower_count:
            # Trailing node promoted unchanged from the lower level.
            return self._level_node(height - 1, index * 2, size, blocks)
        return _node_hash(
            self._level_node(height - 1, index * 2, size, blocks),
            self._level_node(height - 1, index * 2 + 1, size, blocks),
            self._hash_name,
        )

    def _range_root(self, start: int, length: int, blocks: dict[tuple[int, int], bytes]) -> bytes:
        """Merkle root of ``length`` leaves beginning at the aligned ``start``."""
        if length & (length - 1) == 0:
            return self._perfect_node(length.bit_length() - 1, start >> (length.bit_length() - 1), blocks)
        k = _split_point(length)
        return _node_hash(
            self._range_root(start, k, blocks),
            self._range_root(start + k, length - k, blocks),
            self._hash_name,
        )

    def _virtual_subproof(
        self, m: int, n: int, base: int, complete: bool, blocks: dict[tuple[int, int], bytes]
    ) -> list[bytes]:
        """RFC 6962 SUBPROOF over the virtual leaf range ``[base, base+n)``."""
        if m == n:
            return [] if complete else [self._range_root(base, n, blocks)]
        k = _split_point(n)
        if m <= k:
            return self._virtual_subproof(m, k, base, complete, blocks) + [
                self._range_root(base + k, n - k, blocks)
            ]
        return self._virtual_subproof(m - k, n - k, base + k, False, blocks) + [
            self._range_root(base, k, blocks)
        ]

    def inclusion_proof(self, index: int, size: int | None = None) -> tuple[bytes, ...]:
        """Sibling digests from leaf to root for ``index`` within the first ``size`` entries."""
        size = self._resolve_size(size)
        if not isinstance(index, int):
            raise TypeError("index must be an integer")
        if not 0 <= index < size:
            raise ValueError(f"index must satisfy 0 <= index < {size}")
        if size < self._retain_from or index < self._retain_from:
            raise ValueError(
                f"index {index} is inside the pruned prefix (entries retained from {self._retain_from})"
            )
        blocks = self._frontier_blocks()
        proof: list[bytes] = []
        position = index
        width = size
        height = 0
        while width > 1:
            sibling = position ^ 1
            if sibling < width:
                proof.append(self._level_node(height, sibling, size, blocks))
            position //= 2
            width = (width + 1) // 2
            height += 1
        return tuple(proof)

    def batch_inclusion_proof(
        self, indices: Iterable[int], size: int | None = None
    ) -> tuple[tuple[int, ...], tuple[bytes, ...]]:
        """Compact combined inclusion proof for many entries at once.

        Returns ``(sorted_indices, proof)``: ``sorted_indices`` is the
        strictly ascending, deduplicated tuple of the requested indices and
        ``proof`` is a single tuple of Merkle nodes that covers the whole
        ``[0, size)`` snapshot. The proof walks the tree recursively — when a
        subtree spans ``n > 1`` leaves it splits at the largest power of two
        ``k < n`` into left ``[0, k)`` and right ``[k, n)`` halves, in that
        order; a half containing no selected index contributes just its
        Merkle root, a half containing selected indices is recursed into, and
        a selected single leaf contributes nothing (its digest is supplied to
        the verifier). Subtrees shared by several selected leaves therefore
        appear only once, unlike a bundle of individual inclusion proofs.

        ``indices`` must be an iterable of distinct non-bool integers
        satisfying ``retain_from <= index < size``; an empty selection is
        rejected. ``size`` defaults to the current log length and the snapshot
        must still be rebuildable. The call is read-only: it never changes
        entries, head, authentication state, Merkle roots or proofs. Wrong
        index types raise TypeError; an empty selection, out-of-range or
        duplicate indices or an unrebuildable snapshot raise ValueError.
        """
        size = self._resolve_size(size)
        if isinstance(size, bool):
            raise TypeError("size must be an integer")
        try:
            iterator = iter(indices)
        except TypeError:
            raise TypeError("indices must be an iterable of integers") from None
        selected: set[int] = set()
        for index in iterator:
            if not isinstance(index, int) or isinstance(index, bool):
                raise TypeError("indices must be non-bool integers")
            if index in selected:
                raise ValueError(f"duplicate index {index}")
            if not self._retain_from <= index < size:
                raise ValueError(
                    f"index {index} must satisfy retain_from ({self._retain_from}) "
                    f"<= index < size ({size})"
                )
            selected.add(index)
        if not selected:
            raise ValueError("indices must select at least one entry")
        ordered = tuple(sorted(selected))
        self._require_retained_snapshot(size)
        blocks = self._frontier_blocks()
        nodes: list[bytes] = []

        def build(start: int, length: int, chosen: tuple[int, ...]) -> None:
            if length == 1:
                # A chosen leaf is supplied by the verifier; an unchosen leaf
                # never reaches this branch of the recursion.
                return
            k = _split_point(length)
            cut = 0
            while cut < len(chosen) and chosen[cut] < start + k:
                cut += 1
            left = chosen[:cut]
            right = chosen[cut:]
            if not left:
                nodes.append(self._range_root(start, k, blocks))
            else:
                build(start, k, left)
            if not right:
                nodes.append(self._range_root(start + k, length - k, blocks))
            else:
                build(start + k, length - k, right)

        build(0, size, ordered)
        return ordered, tuple(nodes)

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> tuple[bytes, ...]:
        """Proof that the first ``old_size`` entries are a prefix of the first ``new_size``.

        ``new_size`` defaults to the current log length. The digests follow the
        RFC 6962 section 2.1.2 SUBPROOF order; appending later entries never
        changes the proof for an existing pair of prefix sizes. After a prune,
        proofs from the retain point to any later prefix remain available;
        proofs rooted inside a released prefix raise ValueError.
        """
        new_size = self._resolve_size(new_size)
        if not isinstance(old_size, int):
            raise TypeError("old_size must be an integer")
        if not 0 <= old_size <= new_size:
            raise ValueError(f"old_size must satisfy 0 <= old_size <= {new_size}")
        if old_size == 0 or old_size == new_size:
            return ()
        if old_size < self._retain_from:
            raise ValueError(
                f"snapshot at size {old_size} was pruned (entries are retained from {self._retain_from})"
            )
        blocks = self._frontier_blocks()
        return tuple(self._virtual_subproof(old_size, new_size, 0, True, blocks))

    def seal(self, size: int | None = None) -> PruneReceipt:
        """Issue a :class:`PruneReceipt` for the prefix of the first ``size`` entries.

        Defaults to the current log length. The receipt records the prefix
        Merkle root and the entry hash of its last record; the empty prefix
        records the digest-width zero predecessor as its chain hash
        (``GENESIS_HASH`` under sha256).
        """
        size = self._resolve_size(size)
        if size == 0:
            root = _hash_parts(self._hash_name, _EMPTY_DOMAIN)
        else:
            self._require_retained_snapshot(size)
            root = self._fold_occupied(self._occupied_at(size))
        return PruneReceipt(
            hash_name=self._hash_name,
            size=size,
            merkle_root=root,
            chain_hash=self._chain_head_at(size),
        )

    def sign_root(self, private_key: Any, size: int | None = None) -> SignedRoot:
        """Sign a snapshot root and chain head with an Ed25519 seed.

        Produces a :class:`SignedRoot` over the first ``size`` entries
        (defaulting to the current log length): ``root`` is the prefix Merkle
        root and ``head`` is the entry hash of the last prefix entry — the
        digest-width zero chain head for an empty prefix — so a receiver with
        only a pre-trusted public key can authenticate a snapshot checkpoint
        offline and across storage media.

        ``private_key`` is a 32-byte Ed25519 private key seed; it is used for
        this one signature and is never stored, copied into log state or
        returned. The signed message is
        ``D || 0x01 || B(UTF-8(hash_name)) || U(size) || B(root) || B(head)``
        with ``D = b"auditchain/signed-root/v1\\0"``, ``U`` an unsigned 8-byte
        big-endian integer and ``B(x) = U(len(x)) || x``; ``signature`` is the
        64-byte Ed25519 signature over it and ``version`` is always 1. The call
        is read-only: entries, head, authentication state, Merkle roots and
        proofs are all left untouched. A non-``bytes`` seed raises TypeError;
        a seed that is not 32 bytes, an out-of-range ``size`` or a pruned,
        unrebuildable snapshot raises ValueError.
        """
        signing_key = _load_ed25519_seed(private_key)
        size = self._resolve_size(size)
        if size == 0:
            root = _hash_parts(self._hash_name, _EMPTY_DOMAIN)
        else:
            self._require_retained_snapshot(size)
            root = self._fold_occupied(self._occupied_at(size))
        head = self._chain_head_at(size)
        message = _signed_root_message(self._hash_name, size, root, head)
        signature = signing_key.sign(message)
        return SignedRoot(
            version=_SIGNED_ROOT_VERSION,
            hash_name=self._hash_name,
            size=size,
            root=root,
            head=head,
            signature=signature,
        )

    def audit_receipt(self, indices: Iterable[int], size: int | None = None) -> AuditReceipt:
        """Issue an offline :class:`AuditReceipt` for entries of a snapshot.

        ``indices`` is an iterable of distinct non-bool absolute indices,
        each satisfying ``retain_from <= index < size``; ``size`` defaults to
        the current log length and the snapshot must still be rebuildable.
        Any receipt for a non-empty snapshot automatically also includes the
        last entry of the snapshot (index ``size - 1``) with its inclusion
        proof, even when ``indices`` is empty; only an empty snapshot yields
        ``items == ()``. Items are stored in ascending absolute index order,
        each paired with its inclusion proof within the snapshot. The call is
        read-only: entries, head, authentication state, Merkle roots and
        proofs are left untouched.
        """
        size = self._resolve_size(size)
        try:
            iterator = iter(indices)
        except TypeError:
            raise TypeError("indices must be an iterable of integers") from None
        selected: set[int] = set()
        for index in iterator:
            if not isinstance(index, int) or isinstance(index, bool):
                raise TypeError("indices must be non-bool integers")
            if index in selected:
                raise ValueError(f"duplicate index {index}")
            if not self._retain_from <= index < size:
                raise ValueError(
                    f"index {index} must satisfy retain_from ({self._retain_from}) "
                    f"<= index < size ({size})"
                )
            selected.add(index)
        if size > 0:
            # A non-empty snapshot receipt always carries the last entry and
            # its inclusion proof, so an empty selection can never attest to a
            # root without evidence.
            selected.add(size - 1)
        root = self.merkle_root(size)
        items = tuple(
            (self.entry(index), self.inclusion_proof(index, size))
            for index in sorted(selected)
        )
        return AuditReceipt(
            version=1,
            hash_name=self._hash_name,
            size=size,
            root=root,
            items=items,
        )

    def audit_batch(
        self, indices: Iterable[int], size: int | None = None
    ) -> tuple[str, int, bytes, tuple[Entry, ...], tuple[bytes, ...]]:
        """Issue a compact offline batch audit receipt.

        Returns ``(hash_name, size, root, entries, proof)``: ``root`` is the
        Merkle root of the snapshot over the first ``size`` entries,
        ``entries`` is the strictly ascending tuple of the selected
        :class:`Entry` records and ``proof`` is the single shared
        :meth:`batch_inclusion_proof` node tuple covering them all, so several
        selected records share one compact batch inclusion proof rather than
        carrying one inclusion proof each.

        ``indices`` is an iterable of distinct non-bool absolute indices, each
        satisfying ``retain_from <= index < size``; ``size`` defaults to the
        current log length and the snapshot must still be rebuildable. As with
        :meth:`audit_receipt`, every receipt for a non-empty snapshot also
        carries the last snapshot entry (index ``size - 1``) so an empty
        selection can never attest to a root without evidence; only an empty
        snapshot (``size == 0``) accepts an empty selection, yielding the
        canonical empty-tree root, ``entries == ()`` and ``proof == ()``.

        The returned proof is byte-for-byte the one
        :meth:`batch_inclusion_proof` produces for the same ordered indices and
        ``size``; the leaf digests are recomputed by
        :func:`verify_audit_batch` offline. The call is read-only: entries,
        head, authentication state, Merkle roots and proofs are left untouched.
        Wrong index or size types raise TypeError; duplicate or out-of-range
        indices or an unrebuildable snapshot raise ValueError, in all cases
        before any state change.
        """
        size = self._resolve_size(size)
        try:
            iterator = iter(indices)
        except TypeError:
            raise TypeError("indices must be an iterable of integers") from None
        selected: set[int] = set()
        for index in iterator:
            if not isinstance(index, int) or isinstance(index, bool):
                raise TypeError("indices must be non-bool integers")
            if index in selected:
                raise ValueError(f"duplicate index {index}")
            if not self._retain_from <= index < size:
                raise ValueError(
                    f"index {index} must satisfy retain_from ({self._retain_from}) "
                    f"<= index < size ({size})"
                )
            selected.add(index)
        if size == 0:
            # The empty snapshot is a content-free constant: validation above
            # only admits an empty selection (no index satisfies
            # retain_from <= index < 0), so it carries the canonical empty
            # root with no entries and no proof.
            return (
                self._hash_name,
                0,
                _hash_parts(self._hash_name, _EMPTY_DOMAIN),
                (),
                (),
            )
        # A non-empty snapshot receipt always carries the last entry in the
        # shared batch proof, so an empty selection still attests the root with
        # real evidence.
        selected.add(size - 1)
        ordered, proof = self.batch_inclusion_proof(tuple(sorted(selected)), size)
        entries = tuple(self.entry(index) for index in ordered)
        return self._hash_name, size, self.merkle_root(size), entries, proof

    def signed_audit_batch(
        self,
        indices: Iterable[int],
        private_key: Any,
        size: int | None = None,
    ) -> SignedAuditBatch:
        """Issue a :class:`SignedAuditBatch`: a batch receipt sealed by a
        pre-trusted Ed25519 key.

        Convenience for the read-only sequence ``batch =
        audit_batch(indices, size)`` followed by ``checkpoint =
        sign_root(private_key, size)`` (``size`` defaulting to the current
        log length), bundled as one :class:`SignedAuditBatch`. The batch
        five-tuple lets an offline receiver verify the selected entries
        against the snapshot Merkle root, and the checkpoint lets the same
        receiver confirm — using only a pre-trusted 32-byte Ed25519 public
        key — that the root and chain head were issued by the log holder;
        no new signing message is introduced, the checkpoint signs exactly
        the :meth:`sign_root` message. The call is read-only: it never
        changes entries, head, authentication state, Merkle roots or proofs,
        and a failure (an invalid selection, seed or size) raises before the
        bundle is constructed, leaving all state unchanged.
        """
        # Validate and build the batch first, exactly as the public method
        # does; sign_root() is read-only as well, so either failure leaves the
        # log untouched and nothing new is ever signed.
        batch = self.audit_batch(indices, size)
        checkpoint = self.sign_root(private_key, size)
        return SignedAuditBatch(batch=batch, checkpoint=checkpoint)

    def signed_consistency(
        self,
        old_size: int,
        private_key: Any,
        new_size: int | None = None,
    ) -> SignedConsistency:
        """Issue a :class:`SignedConsistency`: two signed snapshot roots plus
        the Merkle consistency proof linking them.

        Convenience for the read-only sequence ``old = sign_root(private_key,
        old_size)``, ``new = sign_root(private_key, new_size)`` and ``proof =
        consistency_proof(old_size, new_size)`` (``new_size`` defaulting to
        the current log length), bundled as one :class:`SignedConsistency`.
        An offline receiver holding only a pre-trusted 32-byte Ed25519 public
        key can then confirm that both snapshots were signed by the log holder
        and that the ``new_size`` snapshot is the ``old_size`` snapshot
        extended by appends only — without holding the :class:`AuditLog`. No
        new signing message is introduced: both checkpoints sign exactly the
        :meth:`sign_root` message, and ``proof`` is byte-for-byte the
        :meth:`consistency_proof` output for the same pair of sizes.

        The sizes must satisfy ``0 <= old_size <= new_size <= len(log)`` and
        both snapshots must still be rebuildable (a pruned-away prefix raises
        ValueError). ``private_key`` is a 32-byte Ed25519 private key seed,
        used for these two signatures and never stored. The call is read-only:
        it never changes entries, head, authentication state, Merkle roots or
        proofs, and a failure (an invalid size or seed) raises before the
        bundle is constructed, leaving all state unchanged. Type and value
        errors are exactly those of :meth:`consistency_proof` and
        :meth:`sign_root`.
        """
        # consistency_proof validates both sizes and the rebuildability of
        # the old snapshot first, exactly as the public method does; both
        # sign_root calls are read-only, so any failure leaves the log
        # untouched and nothing is ever signed half-way.
        proof = self.consistency_proof(old_size, new_size)
        old = self.sign_root(private_key, old_size)
        new = self.sign_root(private_key, new_size)
        return SignedConsistency(old=old, new=new, proof=proof)

    def sign_prune(self, private_key: Any, size: int | None = None) -> SignedPrune:
        """Issue a :class:`SignedPrune`: a sealed receipt authorized by a
        pre-trusted Ed25519 key.

        Convenience for the read-only sequence ``receipt = seal(size)``
        followed by ``checkpoint = sign_root(private_key, size)`` (``size``
        defaulting to the current log length), bundled as one
        :class:`SignedPrune`. The receipt names the prefix Merkle root and the
        last prefix entry's chain hash, and the checkpoint lets an offline
        receiver confirm — using only a pre-trusted 32-byte Ed25519 public key
        — that exactly those fields were signed by the log holder; no new
        signing message is introduced, the checkpoint signs exactly the
        :meth:`sign_root` message. The call is read-only: it never changes
        entries, head, authentication state, Merkle roots or proofs, and a
        failure (an invalid seed or size) raises before the bundle is
        constructed, leaving all state unchanged.
        """
        # Build and validate the receipt first, exactly as the public method
        # does; sign_root() is read-only as well, so either failure leaves the
        # log untouched and nothing new is ever signed.
        receipt = self.seal(size)
        checkpoint = self.sign_root(private_key, size)
        return SignedPrune(receipt=receipt, checkpoint=checkpoint)

    def prune(self, retain_from: int, receipt: PruneReceipt) -> None:
        """Release payloads of the sealed prefix, retaining entries from ``retain_from``.

        ``retain_from`` must equal ``receipt.size`` and the receipt's hash
        algorithm, prefix Merkle root and last-entry chain hash must match the
        log. The retain point can only move forward and never past the log
        end. On success the prefix payloads are dropped; indices, head,
        appends and all rebuildable snapshots stay consistent with an unpruned
        log.
        """
        if not isinstance(receipt, PruneReceipt):
            raise TypeError("receipt must be a PruneReceipt")
        if not isinstance(retain_from, int) or isinstance(retain_from, bool):
            raise TypeError("retain_from must be an integer")
        if retain_from != receipt.size:
            raise ValueError(f"retain_from ({retain_from}) must equal receipt.size ({receipt.size})")
        if not 0 <= retain_from <= len(self):
            raise ValueError(f"retain_from must be within 0..{len(self)}")
        if retain_from < self._retain_from:
            raise ValueError(
                f"retain_from cannot move backwards "
                f"({self._retain_from} -> {retain_from})"
            )
        if receipt.hash_name != self._hash_name:
            raise ValueError(
                f"receipt hash_name {receipt.hash_name!r} does not match log {self._hash_name!r}"
            )
        expected_root = self._fold_occupied(self._occupied_at(retain_from))
        if not hmac.compare_digest(receipt.merkle_root, expected_root):
            raise ValueError("receipt merkle_root does not match the log prefix")
        expected_chain = self._chain_head_at(retain_from)
        if not hmac.compare_digest(receipt.chain_hash, expected_chain):
            raise ValueError("receipt chain_hash does not match the last prefix entry")

        if retain_from == self._retain_from:
            self._checkpoint_head = expected_chain
            return
        self._frontier = self._occupied_at(retain_from)
        released = self._entries[: retain_from - self._retain_from]
        del self._entries[: retain_from - self._retain_from]
        for entry in released:
            # Released indices are the ascending prefix of each digest list.
            digest = _locator_digest(entry.payload, self._hash_name)
            hits = self._index[digest]
            del hits[0]
            if not hits:
                del self._index[digest]
            # Drop the keyed plaintext locator of a released encrypted entry;
            # the reverse map supplies its locator without the append key.
            encrypted_locator = self._encrypted_locators.pop(entry.index, None)
            if encrypted_locator is not None:
                encrypted_hits = self._encrypted_index[encrypted_locator]
                del encrypted_hits[0]
                if not encrypted_hits:
                    del self._encrypted_index[encrypted_locator]
        for released_index in range(self._retain_from, retain_from):
            self._tags.pop(released_index, None)
        self._retain_from = retain_from
        self._checkpoint_head = expected_chain

    def prune_signed(self, retain_from: int, item: Any, public_key: Any) -> None:
        """Release a sealed prefix only when its signed authorization holds.

        Exactly the state-changing half of :meth:`prune`, gated by
        :func:`verify_signed_prune`: the bundle's :class:`SignedRoot`
        checkpoint must verify against the 32-byte ``public_key`` and its
        :class:`PruneReceipt` must agree with the checkpoint on the prefix
        hash algorithm, size, Merkle root and chain head (``root`` / ``head``
        respectively). Only then is the log pruned exactly as
        ``prune(retain_from, item.receipt)`` would — which re-checks
        ``retain_from == receipt.size`` and re-derives the prefix root and
        chain hash from the log itself. A bundle that is structurally sound but
        not authorized (an untrusted key, disagreeing fields, an altered
        signature) raises ValueError and leaves every entry, authentication
        tag/stage/key, locator index, frontier checkpoint and nonce history
        exactly as it was; type and structural errors are exactly those of
        :func:`verify_signed_prune` and :meth:`prune`.
        """
        if not isinstance(retain_from, int) or isinstance(retain_from, bool):
            raise TypeError("retain_from must be an integer")
        if not verify_signed_prune(item, public_key):
            raise ValueError("signed prune authorization does not verify")
        self.prune(retain_from, item.receipt)

    def apply_retention(self, value: int, *, mode: str = "retain_from") -> PruneReceipt:
        """Seal and prune atomically at a retention point derived from ``value``.

        With ``mode="retain_from"`` the target retain point is exactly
        ``value``; with ``mode="keep_last"`` it is
        ``max(retain_from, len(log) - value)``, so at most the newest
        ``value`` entries are kept without ever moving the retain point
        backwards.

        ``value`` must be a non-bool integer. In ``retain_from`` mode it must
        satisfy ``retain_from <= value <= len(log)``; in ``keep_last`` mode it
        must be non-negative. ``mode`` must be one of the two known strings.
        On success the call is exactly ``receipt = seal(target);
        prune(target, receipt)`` and the receipt is returned. A type error in
        ``value`` or ``mode`` raises TypeError; an unknown mode or an
        out-of-range value raises ValueError before anything is touched, so on
        failure every entry, authentication tag/stage/key, locator index,
        frontier checkpoint and nonce history stays exactly as it was.
        """
        if not isinstance(mode, str):
            raise TypeError("mode must be a string")
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("value must be an integer")
        length = len(self)
        if mode == "retain_from":
            target = value
            if not self._retain_from <= target <= length:
                raise ValueError(
                    f"value must satisfy retain_from ({self._retain_from}) "
                    f"<= value <= len ({length})"
                )
        elif mode == "keep_last":
            if value < 0:
                raise ValueError("value must be non-negative")
            target = max(self._retain_from, length - value)
        else:
            raise ValueError(f"unknown mode {mode!r}; expected 'retain_from' or 'keep_last'")
        receipt = self.seal(target)
        self.prune(target, receipt)
        return receipt


def _check_digest(value: Any, name: str, digest_size: int) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    material = bytes(value)
    if len(material) != digest_size:
        raise ValueError(f"{name} must be {digest_size} bytes")
    return material


def verify_inclusion(
    entry_hash: bytes,
    index: int,
    size: int,
    root: bytes,
    proof: Sequence[bytes],
    *,
    hash_name: str = "sha256",
) -> bool:
    """Verify a Merkle inclusion proof without holding the log.

    Rebuilds the root from ``entry_hash`` at ``index`` within a snapshot of
    ``size`` entries, following the sibling digests in ``proof``. Structurally
    valid inputs that do not match return False; malformed inputs raise
    TypeError or ValueError.
    """
    if not isinstance(hash_name, str):
        raise TypeError("hash_name must be a string")
    digest_size = _digest_size(hash_name)

    entry_hash = _check_digest(entry_hash, "entry_hash", digest_size)
    root = _check_digest(root, "root", digest_size)

    if not isinstance(index, int):
        raise TypeError("index must be an integer")
    if not isinstance(size, int):
        raise TypeError("size must be an integer")
    if index < 0 or size < 0:
        raise ValueError("index and size must be non-negative")
    if index >= size:
        raise ValueError("index must satisfy 0 <= index < size")

    if not isinstance(proof, (tuple, list)):
        raise TypeError("proof must be a tuple or list of digests")
    siblings = [_check_digest(sibling, "proof element", digest_size) for sibling in proof]

    node = _leaf_hash(entry_hash, hash_name)
    position = index
    width = size
    consumed = 0
    while width > 1:
        if position % 2 == 1:
            if consumed >= len(siblings):
                raise ValueError("proof has too few levels")
            node = _node_hash(siblings[consumed], node, hash_name)
            consumed += 1
        elif position + 1 < width:
            if consumed >= len(siblings):
                raise ValueError("proof has too few levels")
            node = _node_hash(node, siblings[consumed], hash_name)
            consumed += 1
        # An odd trailing node is promoted without consuming a sibling.
        position //= 2
        width = (width + 1) // 2
    if consumed != len(siblings):
        raise ValueError("proof has too many levels")
    return hmac.compare_digest(node, root)


def _batch_split_counts(indices: tuple[int, ...], lo: int, hi: int, start: int, length: int) -> tuple[int, int]:
    """Partition the chosen indices in ``[start, start+length)`` at the split.

    Returns ``(left_count, right_count)`` where the boundary is the largest
    power of two ``k < length`` at offset ``start + k``. ``indices`` is sorted
    and the slice ``[lo, hi)`` is exactly the chosen indices of this subtree.
    """
    boundary = start + _split_point(length)
    cut = lo
    while cut < hi and indices[cut] < boundary:
        cut += 1
    return cut - lo, hi - cut


def _batch_proof_length(indices: tuple[int, ...], lo: int, hi: int, start: int, length: int) -> int:
    """Canonical node count of a batch inclusion proof for this subtree."""
    if length == 1:
        # A chosen single leaf contributes nothing.
        return 0
    left_count, right_count = _batch_split_counts(indices, lo, hi, start, length)
    k = _split_point(length)
    total = 0
    cut = lo + left_count
    total += 1 if left_count == 0 else _batch_proof_length(indices, lo, cut, start, k)
    total += (
        1
        if right_count == 0
        else _batch_proof_length(indices, cut, hi, start + k, length - k)
    )
    return total


def verify_batch_inclusion(
    indices: Any,
    entry_hashes: Any,
    size: int,
    root: Any,
    proof: Any,
    *,
    hash_name: str = "sha256",
) -> bool:
    """Verify a compact batch inclusion proof without holding the log.

    Checks that the given ``entry_hashes`` are exactly the leaf digests at the
    ascending ``indices`` within a snapshot of ``size`` entries whose Merkle
    root is ``root``, rebuilding it from the single shared ``proof`` produced
    by :meth:`AuditLog.batch_inclusion_proof`. The same recursive split is
    followed (largest power of two below the current length, left half before
    right): an unchosen half contributes its supplied subtree root, a chosen
    half is rebuilt from its leaves and the remaining proof nodes, and odd
    trailing nodes are promoted exactly as for the regular Merkle tree.

    The three sequences must be: a non-empty tuple of strictly ascending
    non-bool integer indices, a tuple of ``bytes`` entry digests of exactly the
    same length and digest width, and a tuple of ``bytes`` proof nodes. Type
    problems raise TypeError; out-of-range or non-ascending indices, mismatched
    sequence or digest widths, a wrong snapshot size or a proof node count that
    does not fit ``(indices, size)`` raise ValueError. Structurally valid
    inputs whose digests, proof or root simply do not match return False.
    """
    if not isinstance(hash_name, str):
        raise TypeError("hash_name must be a string")
    digest_size = _digest_size(hash_name)
    root = _check_digest(root, "root", digest_size)

    if not isinstance(size, int) or isinstance(size, bool):
        raise TypeError("size must be an integer")
    if size < 0:
        raise ValueError("size must be non-negative")

    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple of integers")
    if not indices:
        raise ValueError("indices must be non-empty")
    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("indices must be non-bool integers")
        if index <= previous:
            raise ValueError("indices must be strictly ascending with no duplicates")
        if index < 0 or index >= size:
            raise ValueError(f"index {index} must satisfy 0 <= index < size ({size})")
        previous = index

    if not isinstance(entry_hashes, tuple):
        raise TypeError("entry_hashes must be a tuple of digests")
    if len(entry_hashes) != len(indices):
        raise ValueError("entry_hashes must have the same length as indices")
    leaves: list[bytes] = []
    for entry_hash in entry_hashes:
        if not isinstance(entry_hash, bytes):
            raise TypeError("entry_hashes elements must be bytes")
        if len(entry_hash) != digest_size:
            raise ValueError(f"entry_hash must be {digest_size} bytes")
        leaves.append(_leaf_hash(entry_hash, hash_name))

    if not isinstance(proof, tuple):
        raise TypeError("proof must be a tuple of digests")
    nodes: list[bytes] = []
    for node in proof:
        if not isinstance(node, bytes):
            raise TypeError("proof elements must be bytes")
        if len(node) != digest_size:
            raise ValueError(f"proof element must be {digest_size} bytes")
        nodes.append(node)

    expected = _batch_proof_length(indices, 0, len(indices), 0, size)
    if len(nodes) != expected:
        raise ValueError(
            f"proof must have {expected} nodes for these indices and size, got {len(nodes)}"
        )

    cursor = 0

    def rebuild(lo: int, hi: int, start: int, length: int) -> bytes:
        nonlocal cursor
        if length == 1:
            return leaves[lo]
        left_count, _ = _batch_split_counts(indices, lo, hi, start, length)
        k = _split_point(length)
        cut = lo + left_count
        if left_count == 0:
            left = nodes[cursor]
            cursor += 1
        else:
            left = rebuild(lo, cut, start, k)
        if hi - cut == 0:
            right = nodes[cursor]
            cursor += 1
        else:
            right = rebuild(cut, hi, start + k, length - k)
        return _node_hash(left, right, hash_name)

    rebuilt = rebuild(0, len(indices), 0, size)
    return hmac.compare_digest(rebuilt, root)


def verify_consistency(
    old_size: int,
    old_root: bytes,
    new_size: int,
    new_root: bytes,
    proof: tuple[bytes, ...],
    *,
    hash_name: str = "sha256",
) -> bool:
    """Verify a Merkle consistency proof without holding the log.

    Checks that the snapshot of ``old_size`` entries with ``old_root`` is a
    prefix of the snapshot of ``new_size`` entries with ``new_root``, following
    the RFC 6962 section 2.1.2 verification procedure. Equal sizes only accept
    an empty proof and equal roots; ``old_size == 0`` only accepts an empty
    proof and the canonical empty-tree old root. Structurally valid inputs
    that do not match return False; malformed inputs raise TypeError or
    ValueError.
    """
    if not isinstance(hash_name, str):
        raise TypeError("hash_name must be a string")
    digest_size = _digest_size(hash_name)

    old_root = _check_digest(old_root, "old_root", digest_size)
    new_root = _check_digest(new_root, "new_root", digest_size)

    if not isinstance(old_size, int):
        raise TypeError("old_size must be an integer")
    if not isinstance(new_size, int):
        raise TypeError("new_size must be an integer")
    if old_size < 0 or new_size < 0:
        raise ValueError("sizes must be non-negative")
    if old_size > new_size:
        raise ValueError("old_size must not exceed new_size")

    if not isinstance(proof, tuple):
        raise TypeError("proof must be a tuple of digests")
    nodes = [_check_digest(node, "proof element", digest_size) for node in proof]

    if old_size == new_size:
        if nodes:
            raise ValueError("proof must be empty when sizes are equal")
        return hmac.compare_digest(old_root, new_root)
    if old_size == 0:
        if nodes:
            raise ValueError("proof must be empty when old_size is 0")
        return hmac.compare_digest(old_root, _root_of([], hash_name))

    expected = _subproof_length(old_size, new_size, True)
    if len(nodes) != expected:
        raise ValueError(f"proof must have {expected} nodes for these sizes")

    path = list(nodes)
    if old_size & (old_size - 1) == 0:
        # An exact-power-of-two old root is its own first proof node.
        path.insert(0, old_root)
    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for node in path[1:]:
        if sn == 0:
            raise ValueError("proof has too many nodes")
        if fn & 1 or fn == sn:
            fr = _node_hash(node, fr, hash_name)
            sr = _node_hash(node, sr, hash_name)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = _node_hash(sr, node, hash_name)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("proof has too few nodes")
    return hmac.compare_digest(fr, old_root) and hmac.compare_digest(sr, new_root)


def verify_audit_receipt(receipt: Any) -> bool:
    """Verify an :class:`AuditReceipt` without holding the log.

    Recomputes every item's entry digest from the entry's fields and
    re-verifies every inclusion proof against the receipt's snapshot root;
    the last snapshot entry (index ``size - 1``) must be carried with a valid
    inclusion proof, so a non-empty snapshot can never be attested with zero
    evidence. An empty snapshot only accepts the canonical empty-tree root.
    A structurally valid receipt whose entry content, proofs or root do not
    match — including a size > 0 receipt whose items omit the last entry —
    returns False; malformed input raises TypeError or ValueError
    (see :class:`AuditReceipt` for the structural rules).
    """
    if not isinstance(receipt, AuditReceipt):
        raise TypeError("receipt must be an AuditReceipt")
    if receipt.size == 0:
        if receipt.items:
            return False
        return hmac.compare_digest(
            receipt.root, _hash_parts(receipt.hash_name, _EMPTY_DOMAIN)
        )
    if not receipt.items or receipt.items[-1][0].index != receipt.size - 1:
        # A receipt built bypassing the constructor (size > 0, items missing
        # the last entry) attests nothing; reject it rather than accepting an
        # arbitrary root on zero evidence.
        return False
    for entry, proof in receipt.items:
        recomputed = entry_digest(
            entry.index,
            entry.previous_hash,
            entry.payload,
            hash_name=receipt.hash_name,
        )
        if not hmac.compare_digest(recomputed, entry.entry_hash):
            return False
        if not verify_inclusion(
            entry.entry_hash,
            entry.index,
            receipt.size,
            receipt.root,
            proof,
            hash_name=receipt.hash_name,
        ):
            return False
    return True


def _unpack_audit_batch(
    receipt: Any,
) -> tuple[str, int, bytes, tuple[Entry, ...], tuple[bytes, ...]]:
    """Validate the five-tuple shape shared by :func:`verify_audit_batch` and
    :func:`decode_audit_batch`.

    Returns the canonicalized fields (bytearray fields copied to bytes). Only
    structural properties are checked; entry content, proof and root are left
    to :func:`verify_audit_batch`, so a structurally sound receipt that simply
    does not match still unpacks.
    """
    if not isinstance(receipt, tuple) or len(receipt) != 5:
        raise TypeError(
            "receipt must be a 5-tuple (hash_name, size, root, entries, proof)"
        )
    hash_name, size, root, entries, proof = receipt

    if not isinstance(hash_name, str):
        raise TypeError("hash_name must be a string")
    digest_size = _digest_size(hash_name)
    if not isinstance(size, int) or isinstance(size, bool):
        raise TypeError("size must be an integer")
    if size < 0:
        raise ValueError("size must be non-negative")
    root = _check_digest(root, "root", digest_size)

    if not isinstance(entries, tuple):
        raise TypeError("entries must be a tuple of Entry")
    if not isinstance(proof, tuple):
        raise TypeError("proof must be a tuple of digests")
    nodes: list[bytes] = []
    for node in proof:
        if not isinstance(node, bytes):
            raise TypeError("proof elements must be bytes")
        if len(node) != digest_size:
            raise ValueError(f"proof element must be {digest_size} bytes")
        nodes.append(node)

    if size == 0:
        if entries:
            raise ValueError("an empty snapshot receipt must carry no entries")
        if nodes:
            raise ValueError("an empty snapshot receipt must carry an empty proof")
        return hash_name, size, root, (), ()

    if not entries:
        # Zero evidence must never attest a non-empty snapshot's root.
        raise ValueError(
            "a receipt for a non-empty snapshot must include the entry at index size - 1"
        )

    # First pass: validate the structure of every entry so a malformed receipt
    # raises even when some entry's content would also fail to match.
    checked_entries: list[Entry] = []
    indices: list[int] = []
    previous_index = -1
    for entry in entries:
        if not isinstance(entry, Entry):
            raise TypeError("each entry must be an Entry")
        if not isinstance(entry.index, int) or isinstance(entry.index, bool):
            raise TypeError("entry.index must be an integer")
        if entry.index < 0:
            raise ValueError("entry.index must be non-negative")
        if entry.index <= previous_index:
            raise ValueError(
                "entries must be in strictly ascending order with no duplicates"
            )
        if entry.index >= size:
            raise ValueError(
                f"entry.index {entry.index} must satisfy 0 <= index < size ({size})"
            )
        for name in ("payload", "previous_hash", "entry_hash"):
            if not isinstance(getattr(entry, name), (bytes, bytearray)):
                raise TypeError(f"entry.{name} must be bytes")
        if len(entry.previous_hash) != digest_size:
            raise ValueError(f"entry.previous_hash must be {digest_size} bytes")
        if len(entry.entry_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        previous_index = entry.index
        indices.append(entry.index)
        checked_entries.append(
            Entry(
                entry.index,
                bytes(entry.payload),
                bytes(entry.previous_hash),
                bytes(entry.entry_hash),
            )
        )

    if indices[-1] != size - 1:
        raise ValueError(
            "a receipt for a non-empty snapshot must include the entry at index size - 1"
        )
    # verify_batch_inclusion expects exactly this node count; check it up front
    # so a structurally wrong proof raises rather than mismatches.
    expected_nodes = _batch_proof_length(tuple(indices), 0, len(indices), 0, size)
    if len(nodes) != expected_nodes:
        raise ValueError(
            f"proof must have {expected_nodes} nodes for these entries and size, "
            f"got {len(nodes)}"
        )

    return hash_name, size, root, tuple(checked_entries), tuple(nodes)


def verify_audit_batch(receipt: Any) -> bool:
    """Verify a compact batch audit receipt without holding the log.

    The receipt is the five-tuple
    ``(hash_name, size, root, entries, proof)`` returned by
    :meth:`AuditLog.audit_batch`: the hash algorithm, the snapshot size, the
    snapshot Merkle root, a strictly ascending tuple of :class:`Entry` records
    and the single shared :meth:`AuditLog.batch_inclusion_proof` node tuple
    covering them. Verification recomputes each :func:`entry_digest` from the
    entry fields, then rebuilds the snapshot root from those leaf digests and
    the shared proof via :func:`verify_batch_inclusion`, requiring the entries
    to include the non-empty snapshot's last record (index ``size - 1``); an
    empty snapshot (``size == 0``) must carry no entries and only the canonical
    empty-tree root.

    Anything that is not a five-tuple, or whose element types are wrong
    (``hash_name``/``root``/``entries``/``proof`` or an entry's fields), raises
    TypeError. An unknown hash algorithm, a negative size, an entry index out
    of range, a digest of the wrong width, entries that are not strictly
    ascending or repeat an index, a non-empty snapshot missing its last entry
    (including the zero-evidence ``size > 0`` with no entries case), an empty
    snapshot that carries entries, or a proof node count that does not fit the
    indices and size raises ValueError. A structurally valid receipt whose
    entry content, proof or root simply do not match returns False; a genuine
    receipt returns True.
    """
    hash_name, size, root, entries, nodes = _unpack_audit_batch(receipt)

    if size == 0:
        return hmac.compare_digest(root, _hash_parts(hash_name, _EMPTY_DOMAIN))

    # Second pass: the structure is sound; recompute every leaf digest. Any
    # content mismatch (and only a content mismatch) now yields False.
    entry_hashes: list[bytes] = []
    for entry in entries:
        recomputed = entry_digest(
            entry.index,
            entry.previous_hash,
            entry.payload,
            hash_name=hash_name,
        )
        if not hmac.compare_digest(recomputed, entry.entry_hash):
            return False
        entry_hashes.append(entry.entry_hash)

    # Rebuild the snapshot root from the leaf digests and the single shared
    # proof; a wrong proof or root is a mismatch, not a structural error.
    return verify_batch_inclusion(
        tuple(entry.index for entry in entries),
        tuple(entry_hashes),
        size,
        root,
        nodes,
        hash_name=hash_name,
    )


def _encode_u64(value: int, name: str) -> bytes:
    if not 0 <= value < _U64_LIMIT:
        raise ValueError(f"{name} must satisfy 0 <= {name} < 2**64")
    return value.to_bytes(_U64_BYTES, "big")


def _encode_blob(material: bytes) -> bytes:
    return _encode_u64(len(material), "blob length") + material


def _proof_level_count(index: int, size: int) -> int:
    """Sibling count an inclusion proof for ``index`` within ``size`` entries needs."""
    count = 0
    position = index
    width = size
    while width > 1:
        if position % 2 == 1 or position + 1 < width:
            count += 1
        position //= 2
        width = (width + 1) // 2
    return count


def _check_receipt_proofs(receipt: AuditReceipt) -> None:
    if receipt.size == 0:
        if receipt.items:
            raise ValueError("an empty snapshot receipt must carry no items")
    elif not receipt.items or receipt.items[-1][0].index != receipt.size - 1:
        raise ValueError(
            "a receipt for a non-empty snapshot must include the entry at index size - 1"
        )
    for entry, proof in receipt.items:
        expected = _proof_level_count(entry.index, receipt.size)
        if len(proof) != expected:
            raise ValueError(
                f"proof for index {entry.index} must have {expected} levels, "
                f"got {len(proof)}"
            )


def encode_audit_receipt(receipt: Any) -> bytes:
    """Encode an :class:`AuditReceipt` into its canonical binary form.

    The encoding starts with the magic ``b"auditchain/audit-receipt/v1\\0"``;
    every integer is an unsigned 8-byte big-endian value and every blob is a
    u64 byte length followed by the raw bytes (a zero length is an all-zero
    u64). Fields appear in the order ``version``, ``hash_name`` (UTF-8 blob),
    ``size``, ``root`` blob and item count; each item is ``Entry.index``,
    ``payload`` blob, ``previous_hash`` blob, ``entry_hash`` blob, proof
    count and one blob per proof digest. ``receipt`` must be an
    :class:`AuditReceipt` (anything else raises TypeError); its structure is
    validated by the class itself, and integers that do not fit the u64
    framing raise ValueError. Encoding is deterministic: re-encoding a
    decoded receipt reproduces the original bytes exactly.
    """
    if not isinstance(receipt, AuditReceipt):
        raise TypeError("receipt must be an AuditReceipt")
    _check_receipt_proofs(receipt)
    parts = [
        _RECEIPT_MAGIC,
        _encode_u64(receipt.version, "version"),
        _encode_blob(receipt.hash_name.encode("utf-8")),
        _encode_u64(receipt.size, "size"),
        _encode_blob(bytes(receipt.root)),
        _encode_u64(len(receipt.items), "items count"),
    ]
    for entry, proof in receipt.items:
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(bytes(entry.payload)))
        parts.append(_encode_blob(bytes(entry.previous_hash)))
        parts.append(_encode_blob(bytes(entry.entry_hash)))
        parts.append(_encode_u64(len(proof), "proof count"))
        for digest in proof:
            parts.append(_encode_blob(bytes(digest)))
    return b"".join(parts)


def decode_audit_receipt(data: Any) -> AuditReceipt:
    """Decode bytes produced by :func:`encode_audit_receipt`.

    ``data`` must be ``bytes`` (anything else raises TypeError). A bad magic,
    an unsupported version or hash algorithm, invalid UTF-8 in ``hash_name``,
    truncation, trailing bytes, digest-length mismatches, non-ascending or
    duplicate item indices, a missing last entry — including ``items == ()``
    for a size > 0 snapshot — and structurally invalid proofs all raise
    ValueError. The decoded receipt's fields equal the originally encoded
    ones and satisfy :func:`verify_audit_receipt` whenever the original did.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_RECEIPT_MAGIC):
        raise ValueError("not an auditchain audit-receipt encoding")
    offset = len(_RECEIPT_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(data):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(data[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(data):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = data[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    size = read_u64("size")
    root = read_blob("root")
    item_count = read_u64("items count")
    items = []
    for _ in range(item_count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        proof_count = read_u64("proof count")
        proof = tuple(read_blob("proof element") for _ in range(proof_count))
        items.append((Entry(index, payload, previous_hash, entry_hash), proof))
    if offset != len(data):
        raise ValueError("trailing bytes after the receipt")
    receipt = AuditReceipt(
        version=version,
        hash_name=hash_name,
        size=size,
        root=root,
        items=tuple(items),
    )
    _check_receipt_proofs(receipt)
    return receipt


def encode_prune_receipt(receipt: Any) -> bytes:
    """Encode a :class:`PruneReceipt` into its canonical binary form.

    The encoding starts with the magic ``b"auditchain/prune-receipt/v1\\0"``;
    every integer is an unsigned 8-byte big-endian value and every blob is a
    u64 byte length followed by the raw bytes (a zero length is an all-zero
    u64). Fields appear strictly in the order ``version`` (always 1),
    ``hash_name`` (UTF-8 blob), ``size``, ``merkle_root`` blob and
    ``chain_hash`` blob, with nothing omitted, reordered or appended.
    ``receipt`` must be a :class:`PruneReceipt` — anything else, or a receipt
    whose fields have been bypassed to wrong types, raises TypeError; a size
    outside the u64 range, a non-fixed-output hash algorithm, or digests whose
    width does not match the named algorithm (so the two digests cannot differ
    in width) raise ValueError. The call is read-only and deterministic: it
    never mutates the receipt, and re-encoding a decoded one reproduces the
    original bytes exactly, so a receipt can be persisted and restored in
    another process and handed straight to :meth:`AuditLog.prune`.
    """
    if not isinstance(receipt, PruneReceipt):
        raise TypeError("receipt must be a PruneReceipt")
    # Re-validate every field even for a receipt built with object.__setattr__
    # bypassing the frozen constructor, so structural corruption raises
    # exactly as the constructor would.
    checked = PruneReceipt(
        receipt.hash_name,
        receipt.size,
        receipt.merkle_root,
        receipt.chain_hash,
    )
    return b"".join((
        _PRUNE_RECEIPT_MAGIC,
        _encode_u64(_PRUNE_RECEIPT_VERSION, "version"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_u64(checked.size, "size"),
        _encode_blob(checked.merkle_root),
        _encode_blob(checked.chain_hash),
    ))


def decode_prune_receipt(data: Any) -> PruneReceipt:
    """Decode bytes produced by :func:`encode_prune_receipt`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown or non-fixed-output hash
    algorithm, truncation, trailing bytes, an oversized blob length, a size
    outside the u64 range, or a ``merkle_root`` / ``chain_hash`` whose width
    does not match the named digest raises ValueError. The returned receipt is
    a frozen :class:`PruneReceipt` whose fields equal the originally encoded
    ones; re-encoding it reproduces the original bytes exactly, and a receipt
    sealed by a log using the same hash algorithm can be passed to
    :meth:`AuditLog.prune` on a log in another process exactly as the original
    could.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_PRUNE_RECEIPT_MAGIC):
        raise ValueError("not an auditchain prune-receipt encoding")
    offset = len(_PRUNE_RECEIPT_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(data):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(data[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(data):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = data[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    if version != _PRUNE_RECEIPT_VERSION:
        raise ValueError("unsupported prune-receipt version")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    size = read_u64("size")
    merkle_root = read_blob("merkle_root")
    chain_hash = read_blob("chain_hash")
    if offset != len(data):
        raise ValueError("trailing bytes after the prune receipt")
    return PruneReceipt(
        hash_name=hash_name,
        size=size,
        merkle_root=merkle_root,
        chain_hash=chain_hash,
    )


def encode_audit_batch(receipt: Any) -> bytes:
    """Encode an :meth:`AuditLog.audit_batch` five-tuple into canonical bytes.

    The encoding starts with the magic ``b"auditchain/batch/v1\\0"``; every
    integer is an unsigned 8-byte big-endian value and every blob is a u64
    byte length followed by the raw bytes (a zero length is an all-zero u64).
    Fields appear in the order ``version`` (1), ``hash_name`` (UTF-8 blob),
    ``size``, ``root`` blob and entry count; each :class:`Entry` is written as
    ``index`` (u64), ``payload`` blob, ``previous_hash`` blob and
    ``entry_hash`` blob, and the single shared proof follows as a node count
    plus one blob per digest.

    ``receipt`` must be the five-tuple
    ``(hash_name, size, root, entries, proof)`` accepted by
    :func:`verify_audit_batch` — anything else, or a field of the wrong type,
    raises TypeError and structural violations (an unknown hash algorithm,
    out-of-range or non-ascending indices, a missing last snapshot entry,
    wrong digest widths or proof node count, ...) raise ValueError. Encoding is
    read-only and deterministic: re-encoding a decoded tuple reproduces the
    original bytes exactly, and integers outside the u64 range raise
    ValueError. A structurally valid receipt whose content, root or proof does
    not match encodes just as well; :func:`verify_audit_batch` reports False.
    """
    hash_name, size, root, entries, proof = _unpack_audit_batch(receipt)
    parts = [
        _BATCH_MAGIC,
        _encode_u64(_BATCH_VERSION, "version"),
        _encode_blob(hash_name.encode("utf-8")),
        _encode_u64(size, "size"),
        _encode_blob(root),
        _encode_u64(len(entries), "entries count"),
    ]
    for entry in entries:
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(entry.payload))
        parts.append(_encode_blob(entry.previous_hash))
        parts.append(_encode_blob(entry.entry_hash))
    parts.append(_encode_u64(len(proof), "proof count"))
    for node in proof:
        parts.append(_encode_blob(node))
    return b"".join(parts)


def decode_audit_batch(data: Any) -> tuple[str, int, bytes, tuple[Entry, ...], tuple[bytes, ...]]:
    """Decode bytes produced by :func:`encode_audit_batch`.

    ``data`` must be ``bytes`` (anything else raises TypeError). A bad magic,
    an unsupported version or hash algorithm, invalid UTF-8 in ``hash_name``,
    truncation, trailing bytes, digest-length/width mismatches, entry indices
    out of range, non-ascending or duplicate entries, a missing last entry —
    including an entry count of 0 for a ``size > 0`` snapshot — an empty
    snapshot carrying entries or proof nodes, or a proof node count that does
    not fit the entries and size all raise ValueError. The decoded tuple has
    the same ``(hash_name, size, root, entries, proof)`` shape as
    :meth:`AuditLog.audit_batch` output and satisfies
    :func:`verify_audit_batch` whenever the original did; a structurally sound
    encoding whose entry content, root or proof does not match decodes fine,
    and verification of the result returns False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_BATCH_MAGIC):
        raise ValueError("not an auditchain batch-receipt encoding")
    offset = len(_BATCH_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(data):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(data[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(data):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = data[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    if version != _BATCH_VERSION:
        raise ValueError(f"unsupported batch receipt version {version}")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    size = read_u64("size")
    root = read_blob("root")
    entry_count = read_u64("entries count")
    entries = []
    for _ in range(entry_count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        entries.append(Entry(index, payload, previous_hash, entry_hash))
    proof_count = read_u64("proof count")
    proof = tuple(read_blob("proof element") for _ in range(proof_count))
    if offset != len(data):
        raise ValueError("trailing bytes after the batch receipt")
    receipt = (hash_name, size, root, tuple(entries), proof)
    # Apply the same structural contract as audit_batch / verify_audit_batch:
    # algorithm, ranges, digest widths, ordering, last entry and node count.
    _unpack_audit_batch(receipt)
    return receipt


def _unpack_auth_batch(
    items: Any, hash_name: str
) -> tuple[tuple[Entry, AuthTag], ...]:
    """Validate the ``(Entry, AuthTag)`` item shape shared by
    :func:`encode_auth_batch`, :func:`decode_auth_batch` and
    :func:`verify_auth_batch`.

    ``items`` must be a tuple of exactly-two-element ``(Entry, AuthTag)``
    pairs with strictly ascending, non-bool, u64-range entry indices, fields
    whose digest width matches ``hash_name`` and consecutive (not merely
    ascending) tag stages starting at any value — the output of
    :meth:`AuditLog.auth_batch`. Returns the canonicalized items
    (``bytes``/``bytearray`` entry fields copied to ``bytes``); the verifier
    tuple of :func:`verify_auth_batch` applies the same checks itself. Only
    structural properties are checked: whether a tag authenticates is left to
    :func:`verify_auth_batch`.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple of (Entry, AuthTag) pairs")
    digest_size = _digest_size(hash_name)
    checked_items: list[tuple[Entry, AuthTag]] = []
    previous_index: int | None = None
    previous_stage: int | None = None
    for item in items:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("each item must be an (Entry, AuthTag) tuple")
        entry, tag = item
        if not isinstance(entry, Entry):
            raise TypeError("item entry must be an Entry")
        if not isinstance(tag, AuthTag):
            raise TypeError("item tag must be an AuthTag")
        if not isinstance(entry.index, int) or isinstance(entry.index, bool):
            raise TypeError("entry.index must be an integer")
        if not 0 <= entry.index < _MAX_STAGE:
            raise ValueError("entry.index must satisfy 0 <= index < 2**64")
        if previous_index is not None and entry.index <= previous_index:
            raise ValueError(
                "item entries must be in strictly ascending index order with no duplicates"
            )
        for name in ("payload", "previous_hash", "entry_hash"):
            if not isinstance(getattr(entry, name), (bytes, bytearray)):
                raise TypeError(f"entry.{name} must be bytes")
        if len(entry.previous_hash) != digest_size:
            raise ValueError(f"entry.previous_hash must be {digest_size} bytes")
        if len(entry.entry_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        # Re-validate even against a tag built with object.__setattr__, the
        # same defensive ordering verify_auth_batch uses.
        if not isinstance(tag.stage, int) or isinstance(tag.stage, bool):
            raise TypeError("tag.stage must be an integer")
        if not 0 <= tag.stage < _MAX_STAGE:
            raise ValueError("tag.stage must satisfy 0 <= stage < 2**64")
        if not isinstance(tag.tag, bytes):
            raise TypeError("tag.tag must be bytes")
        if len(tag.tag) != digest_size:
            raise ValueError(f"tag.tag must be {digest_size} bytes")
        if previous_stage is not None and tag.stage != previous_stage + 1:
            raise ValueError("item tag stages must be consecutive")
        previous_index = entry.index
        previous_stage = tag.stage
        checked_items.append(
            (
                Entry(
                    entry.index,
                    bytes(entry.payload),
                    bytes(entry.previous_hash),
                    bytes(entry.entry_hash),
                ),
                AuthTag(tag.stage, tag.tag),
            )
        )
    return tuple(checked_items)


def encode_auth_batch(items: Any, *, hash_name: str = "sha256") -> bytes:
    """Encode an :meth:`AuditLog.auth_batch` result into canonical bytes.

    Persists the forward-secure authentication material so it can be written
    to disk and restored in another process, then checked entirely offline by
    :func:`verify_auth_batch` — the verifier (stage-0 key) is never part of
    the encoding and must travel through a separate trust channel.

    The encoding starts with the magic ``b"auditchain/auth-batch/v1\\0"``;
    every integer is an unsigned 8-byte big-endian value and every blob is a
    u64 byte length followed by the raw bytes (a zero length is an all-zero
    u64). Fields appear in the order ``version`` (1), ``hash_name`` (UTF-8
    blob) and item count; each item is written exactly as
    ``index`` (u64), ``payload`` blob, ``previous_hash`` blob,
    ``entry_hash`` blob, ``stage`` (u64), ``tag`` blob — the entry first, then
    the tag — with nothing omitted, reordered or appended.

    ``items`` must be the ``(Entry, AuthTag)`` tuple produced by
    :meth:`AuditLog.auth_batch` and accepted by :func:`verify_auth_batch` —
    anything else, or a field of the wrong type, raises TypeError; an unknown
    or non-fixed-output ``hash_name``, an index or stage outside the u64
    range, non-ascending or duplicate entry indices, non-consecutive tag
    stages or digest/tag widths that do not match the named algorithm raise
    ValueError. Encoding is read-only and deterministic: it never mutates an
    item, and re-encoding the decoded items reproduces the original bytes
    exactly. A structurally valid item whose tag does not authenticate
    encodes just as well; :func:`verify_auth_batch` reports False per item.
    """
    checked = _unpack_auth_batch(items, hash_name)
    parts = [
        _AUTH_BATCH_MAGIC,
        _encode_u64(_AUTH_BATCH_VERSION, "version"),
        _encode_blob(hash_name.encode("utf-8")),
        _encode_u64(len(checked), "items count"),
    ]
    for entry, tag in checked:
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(entry.payload))
        parts.append(_encode_blob(entry.previous_hash))
        parts.append(_encode_blob(entry.entry_hash))
        parts.append(_encode_u64(tag.stage, "tag.stage"))
        parts.append(_encode_blob(tag.tag))
    return b"".join(parts)


def decode_auth_batch(data: Any) -> tuple[str, tuple[tuple[Entry, AuthTag], ...]]:
    """Decode bytes produced by :func:`encode_auth_batch`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown or non-fixed-output hash
    algorithm, truncation, trailing bytes, an oversized blob length, an item
    count or integer outside the u64 range, ``previous_hash`` /
    ``entry_hash`` / ``tag`` widths that do not match the named digest,
    non-ascending or duplicate entry indices, or non-consecutive tag stages
    raise ValueError. Returns ``(hash_name, items)`` where ``items`` is the
    immutable tuple of frozen ``(Entry, AuthTag)`` pairs in their original
    order — ``()`` for an empty batch — and re-encoding it with the same
    ``hash_name`` reproduces the original bytes exactly. A structurally sound
    encoding whose entries or tags simply do not authenticate decodes fine;
    :func:`verify_auth_batch` then returns False per item rather than
    raising.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_AUTH_BATCH_MAGIC):
        raise ValueError("not an auditchain auth-batch encoding")
    offset = len(_AUTH_BATCH_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(data):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(data[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(data):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = data[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    if version != _AUTH_BATCH_VERSION:
        raise ValueError(f"unsupported auth-batch version {version}")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    # Resolve the algorithm and its digest width before reading any item so a
    # non-fixed-output or unknown hash_name reports ValueError up front.
    _digest_size(hash_name)
    item_count = read_u64("items count")
    items = []
    for _ in range(item_count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        stage = read_u64("tag.stage")
        tag_bytes = read_blob("tag.tag")
        items.append(
            (
                Entry(index, payload, previous_hash, entry_hash),
                AuthTag(stage, tag_bytes),
            )
        )
    if offset != len(data):
        raise ValueError("trailing bytes after the auth batch")
    # Apply the same structural contract as auth_batch / verify_auth_batch:
    # ranges, digest widths, ascending indices and consecutive stages. The
    # Entry/AuthTag constructors cover field types and u64 ranges; the shared
    # check covers ordering, continuity and widths for the named algorithm.
    items = _unpack_auth_batch(tuple(items), hash_name)
    return hash_name, items


def verify_auth(entry: Any, tag: Any, verifier: Any) -> bool:
    """Verify a forward-secure authentication tag without holding the log.

    First recomputes the entry digest from ``entry``'s fields and checks it
    against ``entry.entry_hash``; a structurally valid entry whose recorded
    hash does not match returns False. Then evolves the verifier's stage-0 key
    forward to ``tag.stage`` and checks the HMAC over the entry hash.

    Structural/type problems raise TypeError; negative values, wrong digest
    lengths, an unknown hash algorithm or an invalid state raise ValueError.
    A well-formed entry and tag whose content simply does not authenticate
    return False.
    """
    if not isinstance(entry, Entry):
        raise TypeError("entry must be an Entry")
    if not isinstance(tag, AuthTag):
        raise TypeError("tag must be an AuthTag")
    if not isinstance(verifier, Verifier):
        raise TypeError("verifier must be a Verifier")

    # The stage bounds the key-evolution loop below, so validate it first.
    if not isinstance(tag.stage, int) or isinstance(tag.stage, bool):
        raise TypeError("tag.stage must be an integer")
    if not 0 <= tag.stage < _MAX_STAGE:
        raise ValueError("tag.stage must satisfy 0 <= stage < 2**64")

    digest_size = _digest_size(verifier.hash_name)
    for name in ("previous_hash", "entry_hash", "payload"):
        value = getattr(entry, name)
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"entry.{name} must be bytes")
    if len(entry.previous_hash) != digest_size:
        raise ValueError(f"entry.previous_hash must be {digest_size} bytes")
    if len(entry.entry_hash) != digest_size:
        raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
    if not isinstance(entry.index, int) or isinstance(entry.index, bool):
        raise TypeError("entry.index must be an integer")
    if entry.index < 0:
        raise ValueError("entry.index must be non-negative")

    if len(tag.tag) != digest_size:
        raise ValueError(f"tag.tag must be {digest_size} bytes")

    recomputed = entry_digest(
        entry.index,
        entry.previous_hash,
        entry.payload,
        hash_name=verifier.hash_name,
    )
    if not hmac.compare_digest(recomputed, entry.entry_hash):
        return False

    key = verifier.key
    for _ in range(tag.stage):
        key = _evolve_key(key, verifier.hash_name)
    expected = _auth_tag(tag.stage, entry.entry_hash, key, verifier.hash_name)
    return hmac.compare_digest(expected, tag.tag)


def verify_auth_batch(items: Any, verifier: Any) -> tuple[bool, ...]:
    """Verify many ``(Entry, AuthTag)`` pairs without holding the log.

    The batch counterpart of :func:`verify_auth`: every pair is checked with
    exactly that routine and the results come back as a tuple of booleans in
    the same order, ``()`` for an empty tuple. Before any per-item
    verification the whole batch is validated structurally: ``items`` must be
    a tuple of ``(Entry, AuthTag)`` pairs, the entry indices must be strictly
    ascending (distinct and ordered) and the tag stages must be consecutive,
    matching the output of :meth:`AuditLog.auth_batch`.

    A wrong container or element type raises TypeError; duplicate,
    out-of-range or out-of-order entry indices, non-consecutive stages, a
    stage/index at or beyond ``2**64`` or a wrong digest width raise
    ValueError. Such structural failures abort the call before anything is
    verified; a structurally valid pair whose content simply does not
    authenticate contributes only ``False`` at its position, never an
    exception.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple of (Entry, AuthTag) pairs")
    if not isinstance(verifier, Verifier):
        raise TypeError("verifier must be a Verifier")
    digest_size = _digest_size(verifier.hash_name)

    # One structural pass over the whole batch first: any malformed pair (or a
    # broken ordering/continuity relationship) must raise before per-item
    # verification, exactly as a malformed single argument raises in
    # verify_auth before its content checks.
    previous_index: int | None = None
    for position, item in enumerate(items):
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("each item must be an (Entry, AuthTag) tuple")
        entry, tag = item
        if not isinstance(entry, Entry):
            raise TypeError("item entry must be an Entry")
        if not isinstance(tag, AuthTag):
            raise TypeError("item tag must be an AuthTag")
        if not isinstance(entry.index, int) or isinstance(entry.index, bool):
            raise TypeError("entry.index must be an integer")
        if not 0 <= entry.index < _MAX_STAGE:
            raise ValueError("entry.index must satisfy 0 <= index < 2**64")
        if previous_index is not None and entry.index <= previous_index:
            raise ValueError(
                "item entries must be in strictly ascending index order with no duplicates"
            )
        previous_index = entry.index
        for name in ("payload", "previous_hash", "entry_hash"):
            if not isinstance(getattr(entry, name), (bytes, bytearray)):
                raise TypeError(f"entry.{name} must be bytes")
        if len(entry.previous_hash) != digest_size:
            raise ValueError(f"entry.previous_hash must be {digest_size} bytes")
        if len(entry.entry_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        # Re-validate even against a tag built with object.__setattr__, the
        # same defensive ordering verify_auth uses.
        if not isinstance(tag.stage, int) or isinstance(tag.stage, bool):
            raise TypeError("tag.stage must be an integer")
        if not 0 <= tag.stage < _MAX_STAGE:
            raise ValueError("tag.stage must satisfy 0 <= stage < 2**64")
        if not isinstance(tag.tag, bytes):
            raise TypeError("tag.tag must be bytes")
        if len(tag.tag) != digest_size:
            raise ValueError(f"tag.tag must be {digest_size} bytes")
        if position > 0 and tag.stage != items[position - 1][1].stage + 1:
            raise ValueError("item tag stages must be consecutive")

    return tuple(
        verify_auth(entry, tag, verifier) for entry, tag in items  # type: ignore[misc]
    )


def verify_signed_root(receipt: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedRoot` against a pre-trusted Ed25519 public key.

    Rebuilds the exact message :meth:`AuditLog.sign_root` signed —
    ``D || 0x01 || B(UTF-8(hash_name)) || U(size) || B(root) || B(head)``
    with ``D = b"auditchain/signed-root/v1\\0"``, ``U`` an unsigned 8-byte
    big-endian integer and ``B(x) = U(len(x)) || x`` — and checks the
    receipt's 64-byte Ed25519 signature with the 32-byte ``public_key``,
    entirely without holding the log. A genuine receipt from that key returns
    True; a structurally valid receipt signed by another key, or whose root,
    chain head or signature has been altered, returns False. Input that is not
    a :class:`SignedRoot` or whose key is not ``bytes`` raises TypeError; an
    unsupported version, an unknown hash algorithm, a size outside the u64
    range, a root/head of the wrong digest width, a signature that is not 64
    bytes or a public key that is not 32 bytes raises ValueError. The call is
    read-only and never mutates the receipt.
    """
    if not isinstance(receipt, SignedRoot):
        raise TypeError("receipt must be a SignedRoot")
    # Re-validate every field even for a receipt built with object.__setattr__
    # bypassing the frozen constructor, so structural corruption raises
    # exactly as the constructor would and only genuine mismatches return
    # False below.
    checked = SignedRoot(
        receipt.version,
        receipt.hash_name,
        receipt.size,
        receipt.root,
        receipt.head,
        receipt.signature,
    )
    verification_key = _load_ed25519_public(public_key)
    message = _signed_root_message(
        checked.hash_name,
        checked.size,
        checked.root,
        checked.head,
    )
    try:
        verification_key.verify(checked.signature, message)
    except InvalidSignature:
        return False
    return True


def verify_signed_audit_batch(receipt: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedAuditBatch` against a pre-trusted Ed25519 key.

    Confirms both parts of the sealed bundle without holding the log:
    :func:`verify_audit_batch` re-verifies the selected entries and their
    shared proof against the batch's snapshot root, and
    :func:`verify_signed_root` verifies the checkpoint signature with the
    32-byte ``public_key``. The two parts are then required to describe the
    same snapshot — equal ``hash_name``, ``size`` and ``root`` — and the
    checkpoint chain head must equal the batch's last entry's
    ``entry_hash``; for an empty snapshot the head must be the digest-width
    zero value. A genuine sealed bundle from the trusted key returns True;
    a structurally valid bundle signed by another key, whose parts disagree,
    or whose entries, proof, root, head or signature have been altered
    returns False. Input that is not a :class:`SignedAuditBatch` (or whose
    container fields have been bypassed to wrong types) raises TypeError;
    nested structural violations raise exactly the exceptions of
    :func:`verify_audit_batch` and :func:`verify_signed_root` (TypeError or
    ValueError), and a public key that is not 32 ``bytes`` raises
    ValueError (a non-``bytes`` key TypeError). The call is read-only.
    """
    if not isinstance(receipt, SignedAuditBatch):
        raise TypeError("receipt must be a SignedAuditBatch")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedAuditBatch(receipt.batch, receipt.checkpoint)
    # The batch's own structural contract (field types, ranges, widths,
    # ordering, last entry, proof node count) raises as in verify_audit_batch.
    hash_name, size, root, entries, _proof = _unpack_audit_batch(checked.batch)
    digest_size = _digest_size(hash_name)

    if not verify_audit_batch(checked.batch):
        return False
    if not verify_signed_root(checked.checkpoint, public_key):
        return False

    checkpoint = checked.checkpoint
    # The signed checkpoint must attest exactly the batch's snapshot.
    if (
        checkpoint.hash_name != hash_name
        or checkpoint.size != size
        or checkpoint.root != root
    ):
        return False
    if size == 0:
        expected_head = bytes(digest_size)
    else:
        # verify_audit_batch guarantees the final carried entry is the last
        # snapshot entry (index size - 1); its entry hash is the chain head.
        expected_head = entries[-1].entry_hash
    return hmac.compare_digest(checkpoint.head, expected_head)


def verify_signed_consistency(receipt: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedConsistency` against a pre-trusted Ed25519 key.

    Confirms the sealed cross-snapshot claim entirely offline, without
    holding the log: :func:`verify_signed_root` verifies the ``old`` and
    ``new`` checkpoint signatures with the 32-byte ``public_key``, the two
    checkpoints must name the same hash algorithm, and finally
    :func:`verify_consistency` — called with the shared ``hash_name`` —
    re-verifies that the snapshot of ``old.size`` entries with root
    ``old.root`` is a prefix of the snapshot of ``new.size`` entries with
    root ``new.root`` via ``proof``. A genuine receipt from the trusted key
    returns True; a structurally valid receipt signed by another key, whose
    checkpoints disagree on the hash algorithm, or whose roots, sizes,
    signatures or proof have been altered returns False.

    Input that is not a :class:`SignedConsistency` (or whose container
    fields have been bypassed to wrong types) raises TypeError; nested
    structural violations raise exactly the exceptions of
    :func:`verify_signed_root` and :func:`verify_consistency` (TypeError or
    ValueError), and a public key that is not 32 ``bytes`` raises
    ValueError (a non-``bytes`` key TypeError). The call is read-only and
    never mutates the receipt.
    """
    if not isinstance(receipt, SignedConsistency):
        raise TypeError("receipt must be a SignedConsistency")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedConsistency(receipt.old, receipt.new, receipt.proof)
    if not verify_signed_root(checked.old, public_key):
        return False
    if not verify_signed_root(checked.new, public_key):
        return False
    old = checked.old
    new = checked.new
    # Both checkpoints must describe snapshots of the same log, hence the
    # same hash algorithm; a mismatch is a linkage failure, not a
    # structural error.
    if old.hash_name != new.hash_name:
        return False
    return verify_consistency(
        old.size,
        old.root,
        new.size,
        new.root,
        checked.proof,
        hash_name=old.hash_name,
    )


def verify_signed_prune(item: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedPrune` prune authorization against a pre-trusted key.

    Confirms the signed authorization entirely offline, without holding the
    log: :func:`verify_signed_root` verifies the checkpoint signature with the
    32-byte ``public_key``, and the bundled :class:`PruneReceipt` must agree
    with that checkpoint on the prefix it seals — equal ``hash_name`` and
    ``size``, ``merkle_root == root`` and ``chain_hash == head``. A genuine
    authorization from the trusted key whose two parts describe the same
    prefix returns True; a structurally valid bundle signed by another key,
    whose parts disagree, or whose signature has been altered returns False.

    Input that is not a :class:`SignedPrune` (or whose container fields have
    been bypassed to wrong types) raises TypeError; nested structural
    violations raise exactly the exceptions of :class:`PruneReceipt`,
    :class:`SignedRoot` and :func:`verify_signed_root` (TypeError or
    ValueError), and a public key that is not 32 ``bytes`` raises
    ValueError (a non-``bytes`` key TypeError). The call is read-only and
    never mutates the item.
    """
    if not isinstance(item, SignedPrune):
        raise TypeError("item must be a SignedPrune")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedPrune(item.receipt, item.checkpoint)
    # Re-validate the receipt's fields as well (verify_signed_root below does
    # the same for the checkpoint), so bypassed nested corruption raises
    # exactly as the PruneReceipt constructor would and only a genuine
    # mismatch returns False.
    receipt = PruneReceipt(
        checked.receipt.hash_name,
        checked.receipt.size,
        checked.receipt.merkle_root,
        checked.receipt.chain_hash,
    )
    checkpoint = checked.checkpoint
    if not verify_signed_root(checkpoint, public_key):
        return False
    # The signed checkpoint must attest exactly the sealed prefix the receipt
    # names: same algorithm and size, and its root/head are the receipt's
    # Merkle root and last-entry chain hash.
    return (
        receipt.hash_name == checkpoint.hash_name
        and receipt.size == checkpoint.size
        and hmac.compare_digest(receipt.merkle_root, checkpoint.root)
        and hmac.compare_digest(receipt.chain_hash, checkpoint.head)
    )


def encode_signed_root(receipt: Any) -> bytes:
    """Encode a :class:`SignedRoot` into its canonical binary form.

    The encoding starts with the magic ``b"auditchain/signed-root/v1\\0"``;
    every integer is an unsigned 8-byte big-endian value and every blob is a
    u64 byte length followed by the raw bytes (a zero length is an all-zero
    u64). Fields appear in the order ``version`` (always 1), ``hash_name``
    (UTF-8 blob), ``size``, ``root`` blob, ``head`` blob and ``signature``
    blob. ``receipt`` must be a :class:`SignedRoot` — anything else, or a
    receipt whose fields have been bypassed to wrong types, raises TypeError;
    a version other than 1, a size outside the u64 range, an unknown hash
    algorithm, a root/head of the wrong digest width or a signature that is
    not 64 bytes raises ValueError. The call is read-only and deterministic:
    it never mutates the receipt, and re-encoding a decoded one reproduces the
    original bytes exactly.
    """
    if not isinstance(receipt, SignedRoot):
        raise TypeError("receipt must be a SignedRoot")
    # Re-validate every field even for a receipt built with object.__setattr__
    # bypassing the frozen constructor, so structural corruption raises
    # exactly as the constructor would.
    checked = SignedRoot(
        receipt.version,
        receipt.hash_name,
        receipt.size,
        receipt.root,
        receipt.head,
        receipt.signature,
    )
    return b"".join((
        _SIGNED_ROOT_DOMAIN,
        _encode_u64(checked.version, "version"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_u64(checked.size, "size"),
        _encode_blob(checked.root),
        _encode_blob(checked.head),
        _encode_blob(checked.signature),
    ))


def decode_signed_root(data: Any) -> SignedRoot:
    """Decode bytes produced by :func:`encode_signed_root`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown hash algorithm, truncation,
    trailing bytes, an oversized blob length, a size outside the u64 range, a
    root/head whose width does not match the named digest, or a signature
    that is not 64 bytes raises ValueError. The decoded receipt's fields
    equal the originally encoded ones, re-encoding reproduces the original
    bytes exactly, and it verifies under :func:`verify_signed_root` whenever
    the original did; a structurally sound encoding whose signature does not
    match the claimed fields still decodes, and verification returns False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_ROOT_DOMAIN):
        raise ValueError("not an auditchain signed-root encoding")
    offset = len(_SIGNED_ROOT_DOMAIN)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(data):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(data[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(data):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = data[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    size = read_u64("size")
    root = read_blob("root")
    head = read_blob("head")
    signature = read_blob("signature")
    if offset != len(data):
        raise ValueError("trailing bytes after the signed root")
    return SignedRoot(
        version=version,
        hash_name=hash_name,
        size=size,
        root=root,
        head=head,
        signature=signature,
    )


def encode_signed_audit_batch(receipt: Any) -> bytes:
    """Encode a :class:`SignedAuditBatch` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/signed-audit-batch/v1\\0"``; it then writes, strictly in
    order, the envelope ``version`` (always 1) as an unsigned 8-byte
    big-endian integer, the batch blob and the checkpoint blob — nothing may
    be omitted, reordered or appended. Each blob is a u64 byte length followed
    by the raw bytes: the batch blob is the complete canonical output of
    :func:`encode_audit_batch` over ``receipt.batch`` and the checkpoint blob
    is the complete canonical output of :func:`encode_signed_root` over
    ``receipt.checkpoint``. No new signing message is introduced: encoding is
    read-only and only re-uses the existing canonical encodings.

    ``receipt`` must be a :class:`SignedAuditBatch` — anything else raises
    TypeError; nested structural problems raise exactly the exceptions of
    :func:`encode_audit_batch` and :func:`encode_signed_root` (TypeError or
    ValueError). Encoding is deterministic: re-encoding a decoded bundle
    reproduces the original bytes exactly, and a structurally valid bundle
    whose signature does not match encodes just as well.
    """
    if not isinstance(receipt, SignedAuditBatch):
        raise TypeError("receipt must be a SignedAuditBatch")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedAuditBatch(receipt.batch, receipt.checkpoint)
    batch_blob = encode_audit_batch(checked.batch)
    checkpoint_blob = encode_signed_root(checked.checkpoint)
    return b"".join((
        _SIGNED_AUDIT_BATCH_MAGIC,
        _encode_u64(_SIGNED_AUDIT_BATCH_VERSION, "version"),
        _encode_blob(batch_blob),
        _encode_blob(checkpoint_blob),
    ))


def decode_signed_audit_batch(data: Any) -> SignedAuditBatch:
    """Decode bytes produced by :func:`encode_signed_audit_batch`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signed-audit-batch/v1\\0"`` it must contain, strictly in
    order, the u64 envelope version (only ``1`` is supported), one
    length-prefixed batch blob and one length-prefixed checkpoint blob, with
    no trailing bytes. Each blob is handed whole to the existing decoder —
    :func:`decode_audit_batch` and :func:`decode_signed_root` respectively —
    so every nested framing and structural rule is theirs. A bad magic or
    version, truncation, an oversized blob length, trailing bytes or an
    illegal nested encoding raises ValueError.

    The returned object is a frozen :class:`SignedAuditBatch` whose fields
    equal the originally encoded ones, and re-encoding reproduces the
    original bytes exactly. A structurally sound encoding whose batch or
    checkpoint signature simply does not verify still decodes;
    :func:`verify_signed_audit_batch` reports False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_AUDIT_BATCH_MAGIC):
        raise ValueError("not an auditchain signed-audit-batch encoding")
    offset = len(_SIGNED_AUDIT_BATCH_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(data):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(data[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(data):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = data[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    if version != _SIGNED_AUDIT_BATCH_VERSION:
        raise ValueError(
            f"unsupported signed-audit-batch version {version}"
        )
    batch_blob = read_blob("batch")
    checkpoint_blob = read_blob("checkpoint")
    if offset != len(data):
        raise ValueError("trailing bytes after the signed audit batch")
    # Decode both nested blobs with their existing decoders; their own magic,
    # version, truncation/trailing-byte and structural checks apply verbatim.
    batch = decode_audit_batch(batch_blob)
    checkpoint = decode_signed_root(checkpoint_blob)
    return SignedAuditBatch(batch=batch, checkpoint=checkpoint)


def encode_signed_consistency(receipt: Any) -> bytes:
    """Encode a :class:`SignedConsistency` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/signed-consistency/v1\\0"``; it then writes, strictly in
    order, the envelope ``version`` (always 1) as an unsigned 8-byte
    big-endian integer, the old-checkpoint blob, the new-checkpoint blob,
    the proof-node count as a u64 and one blob per proof digest in tuple
    order — nothing may be omitted, reordered or appended. Each blob is a
    u64 byte length followed by the raw bytes: the two checkpoint blobs are
    the complete canonical output of :func:`encode_signed_root` over
    ``receipt.old`` and ``receipt.new``, and every proof node is written as
    one raw digest blob. No new signing message is introduced: encoding is
    read-only and only re-uses the existing canonical checkpoint encoding.

    ``receipt`` must be a :class:`SignedConsistency` — anything else, or a
    receipt whose fields have been bypassed to wrong types, raises
    TypeError; nested checkpoint problems raise exactly the exceptions of
    :func:`encode_signed_root` (TypeError or ValueError), and a proof node
    whose width is not the digest size named by the old checkpoint's hash
    algorithm raises ValueError. The proof's *content* — node count versus
    the two sizes, linkage to the roots — is not judged here. Encoding is
    deterministic: re-encoding a decoded receipt reproduces the original
    bytes exactly, and a structurally valid receipt whose signatures do not
    match encodes just as well.
    """
    if not isinstance(receipt, SignedConsistency):
        raise TypeError("receipt must be a SignedConsistency")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedConsistency(receipt.old, receipt.new, receipt.proof)
    old_blob = encode_signed_root(checked.old)
    new_blob = encode_signed_root(checked.new)
    # Structural width only: verify_consistency hashes the proof under the
    # old checkpoint's algorithm, so every node must be that digest wide.
    # Node count versus the sizes and the actual linkage are proof content
    # and stay deferred to verify_signed_consistency.
    digest_size = _digest_size(checked.old.hash_name)
    parts = [
        _SIGNED_CONSISTENCY_MAGIC,
        _encode_u64(_SIGNED_CONSISTENCY_VERSION, "version"),
        _encode_blob(old_blob),
        _encode_blob(new_blob),
        _encode_u64(len(checked.proof), "proof count"),
    ]
    for node in checked.proof:
        if len(node) != digest_size:
            raise ValueError(f"proof element must be {digest_size} bytes")
        parts.append(_encode_blob(node))
    return b"".join(parts)


def decode_signed_consistency(data: Any) -> SignedConsistency:
    """Decode bytes produced by :func:`encode_signed_consistency`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signed-consistency/v1\\0"`` it must contain, strictly in
    order, the u64 envelope version (only ``1`` is supported), one
    length-prefixed old-checkpoint blob, one length-prefixed new-checkpoint
    blob, a u64 proof-node count and exactly that many length-prefixed node
    blobs in tuple order, with no trailing bytes. Each checkpoint blob is
    handed whole to :func:`decode_signed_root`, so every nested framing and
    structural rule is theirs; each proof node must be exactly the digest
    width named by the decoded old checkpoint's hash algorithm. A bad magic
    or version, truncation, an oversized blob length, trailing bytes, an
    illegal nested checkpoint encoding or an illegal proof width raises
    ValueError.

    Signatures, the association between the two checkpoints and the proof
    content are not checked here. The returned object is a frozen
    :class:`SignedConsistency` whose fields equal the originally encoded
    ones (positionally constructed, compared by all three fields), and
    re-encoding reproduces the original bytes exactly. A structurally sound
    encoding whose signatures simply do not verify, whose checkpoints name
    different hash algorithms, or whose proof does not link the roots still
    decodes; :func:`verify_signed_consistency` reports False (or raises as
    its own contract specifies).
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_CONSISTENCY_MAGIC):
        raise ValueError("not an auditchain signed-consistency encoding")
    offset = len(_SIGNED_CONSISTENCY_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(data):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(data[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(data):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = data[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    if version != _SIGNED_CONSISTENCY_VERSION:
        raise ValueError(
            f"unsupported signed-consistency version {version}"
        )
    old_blob = read_blob("old checkpoint")
    new_blob = read_blob("new checkpoint")
    proof_count = read_u64("proof count")
    proof = tuple(
        read_blob("proof element") for _ in range(proof_count)
    )
    if offset != len(data):
        raise ValueError("trailing bytes after the signed consistency receipt")
    # Decode both nested blobs with the existing decoder; its own magic,
    # version, truncation/trailing-byte and structural checks apply verbatim.
    old = decode_signed_root(old_blob)
    new = decode_signed_root(new_blob)
    # Structural width only, under the old checkpoint's algorithm; whether
    # the nodes actually link the two roots is left to verification.
    digest_size = _digest_size(old.hash_name)
    for node in proof:
        if len(node) != digest_size:
            raise ValueError(f"proof element must be {digest_size} bytes")
    return SignedConsistency(old=old, new=new, proof=proof)


def encode_signed_prune(item: Any) -> bytes:
    """Encode a :class:`SignedPrune` into its canonical binary form.

    The encoding starts with the magic ``b"auditchain/signed-prune/v1\\0"``;
    it then writes, strictly in order, the envelope ``version`` (always 1) as
    an unsigned 8-byte big-endian integer, the receipt blob and the
    checkpoint blob — nothing may be omitted, reordered or appended. Each
    blob is a u64 byte length followed by the raw bytes: the receipt blob is
    the complete canonical output of :func:`encode_prune_receipt` over
    ``item.receipt`` and the checkpoint blob is the complete canonical output
    of :func:`encode_signed_root` over ``item.checkpoint``. No new signing
    message is introduced: encoding is read-only and only re-uses the
    existing canonical encodings.

    ``item`` must be a :class:`SignedPrune` — anything else raises
    TypeError; nested structural problems raise exactly the exceptions of
    :func:`encode_prune_receipt` and :func:`encode_signed_root` (TypeError or
    ValueError). Encoding is deterministic: re-encoding a decoded bundle
    reproduces the original bytes exactly, and a structurally valid bundle
    whose signature does not match encodes just as well.
    """
    if not isinstance(item, SignedPrune):
        raise TypeError("item must be a SignedPrune")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedPrune(item.receipt, item.checkpoint)
    receipt_blob = encode_prune_receipt(checked.receipt)
    checkpoint_blob = encode_signed_root(checked.checkpoint)
    return b"".join((
        _SIGNED_PRUNE_MAGIC,
        _encode_u64(_SIGNED_PRUNE_VERSION, "version"),
        _encode_blob(receipt_blob),
        _encode_blob(checkpoint_blob),
    ))


def decode_signed_prune(data: Any) -> SignedPrune:
    """Decode bytes produced by :func:`encode_signed_prune`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signed-prune/v1\\0"`` it must contain, strictly in order,
    the u64 envelope version (only ``1`` is supported), one
    length-prefixed receipt blob and one length-prefixed checkpoint blob,
    with no trailing bytes. Each blob is handed whole to the existing decoder
    — :func:`decode_prune_receipt` and :func:`decode_signed_root`
    respectively — so every nested framing and structural rule is theirs. A
    bad magic or version, truncation, an oversized blob length, trailing
    bytes or an illegal nested encoding raises ValueError.

    The returned object is a frozen :class:`SignedPrune` whose fields equal
    the originally encoded ones, and re-encoding reproduces the original
    bytes exactly. A structurally sound encoding whose receipt and checkpoint
    disagree or whose checkpoint signature simply does not verify still
    decodes; :func:`verify_signed_prune` reports False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_PRUNE_MAGIC):
        raise ValueError("not an auditchain signed-prune encoding")
    offset = len(_SIGNED_PRUNE_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(data):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(data[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(data):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = data[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    if version != _SIGNED_PRUNE_VERSION:
        raise ValueError(f"unsupported signed-prune version {version}")
    receipt_blob = read_blob("receipt")
    checkpoint_blob = read_blob("checkpoint")
    if offset != len(data):
        raise ValueError("trailing bytes after the signed prune")
    # Decode both nested blobs with their existing decoders; their own magic,
    # version, truncation/trailing-byte and structural checks apply verbatim.
    receipt = decode_prune_receipt(receipt_blob)
    checkpoint = decode_signed_root(checkpoint_blob)
    return SignedPrune(receipt=receipt, checkpoint=checkpoint)


def dump_log(log: Any, private_key: Any) -> bytes:
    """Export a complete, qualified log as one self-certifying byte string.

    Only accepts an :class:`AuditLog` that holds its **complete, unpruned**
    history (``retain_from == 0``), was constructed without an authentication
    key and has never held encrypted entries: the dump carries no prune
    checkpoints, no authentication tags or key-evolution state, no encryption
    keys or nonce history and no plaintext locators beyond what ordinary
    appended payloads already imply. The snapshot — hash algorithm, entry
    count, Merkle root and chain head — is signed exactly as
    :meth:`AuditLog.sign_root` signs it with the 32-byte Ed25519 seed
    ``private_key``; the seed is used for that one signature and is never
    stored, copied into the dump or added as a separate signing input.

    The encoding starts with the magic ``b"auditchain/log-state/v1\\0"`` and
    then writes, strictly in order, the envelope version (always ``1``) as an
    unsigned 8-byte big-endian integer, one blob ``C`` holding the complete
    canonical output of :func:`encode_signed_root` over
    ``log.sign_root(private_key)``, the entry count ``n`` as a u64 and the
    ``n`` entries; entry ``Ei`` is encoded as ``U(index)``, ``B(payload)``,
    ``B(previous_hash)`` and ``B(entry_hash)`` in that order, where ``U`` is an
    unsigned 8-byte big-endian integer and ``B(x) = U(len(x)) || x``. Nothing
    is omitted, reordered or appended.

    The call is read-only and deterministic: it never mutates the log, and two
    dumps of logs in the same state signed with the same seed are byte-for-byte
    identical (Ed25519 signatures are deterministic). A non-:class:`AuditLog`
    value or a non-``bytes`` seed raises TypeError; a seed that is not 32 bytes
    or a log that is pruned, keyed/authenticated or has encrypted history
    raises ValueError.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    # Validate the seed before any eligibility check, so type/value errors
    # surface in the same order as sign_root (which loads the seed first).
    # The loaded key is used only for the one signature below and never
    # stored on the log.
    signing_key = _load_ed25519_seed(private_key)
    # The format restores an independent keyless log and carries no prune,
    # authentication or encryption material, so only a complete, plain
    # append-only history is eligible.
    if log._retain_from != 0:
        raise ValueError(
            "only an unpruned log holding its complete history can be dumped"
        )
    if log._key is not None or log._stage != 0 or log._tags or log._verifier_exported:
        raise ValueError("a log with authentication state or history cannot be dumped")
    if log._encrypted_index or log._encrypted_locators:
        raise ValueError("a log with encrypted entries cannot be dumped")
    # Sign the current snapshot with the same message and artifact as
    # sign_root (re-using its framing introduces no new signing input).
    size = len(log)
    root = log._fold_occupied(log._occupied_at(size))
    head = log._chain_head_at(size)
    signature = signing_key.sign(
        _signed_root_message(log._hash_name, size, root, head)
    )
    checkpoint = SignedRoot(
        version=_SIGNED_ROOT_VERSION,
        hash_name=log._hash_name,
        size=size,
        root=root,
        head=head,
        signature=signature,
    )
    parts = [
        _LOG_STATE_MAGIC,
        _encode_u64(_LOG_STATE_VERSION, "version"),
        _encode_blob(encode_signed_root(checkpoint)),
        _encode_u64(len(log), "entries count"),
    ]
    for entry in log._entries:
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(entry.payload))
        parts.append(_encode_blob(entry.previous_hash))
        parts.append(_encode_blob(entry.entry_hash))
    return b"".join(parts)


def load_log(data: Any, public_key: Any) -> AuditLog:
    """Restore an independent, mutable :class:`AuditLog` from :func:`dump_log`.

    ``data`` must be ``bytes`` (anything else raises TypeError). After the
    magic ``b"auditchain/log-state/v1\\0"`` it must contain, strictly in order,
    the u64 envelope version (only ``1`` is supported), one length-prefixed
    blob holding a complete :func:`encode_signed_root` checkpoint, a u64 entry
    count and exactly that many entries encoded as ``U(index)``,
    ``B(payload)``, ``B(previous_hash)`` and ``B(entry_hash)``, with no
    trailing bytes.

    Verification is entirely offline against the 32-byte ``public_key``: the
    embedded checkpoint is decoded and its Ed25519 signature verified exactly
    as :func:`verify_signed_root` does; the entry count must equal
    ``checkpoint.size``; the entries must occupy indices ``0..n-1`` in order;
    and, using the checkpoint's own ``hash_name`` and digest width, every
    :func:`entry_digest` and predecessor link is recomputed from genesis and
    the resulting chain head and Merkle root must match the signed checkpoint.
    Only then is a fresh keyless :class:`AuditLog` built by replaying the
    payloads through the normal append path, so its find index, Merkle
    frontier, head, length and retain point are exactly those of a log built
    from the same records in this process — it is fully mutable and supports
    every existing operation (append, encrypt with a fresh key, prune, ...),
    sharing no state with the caller's buffers.

    A non-``bytes`` ``data`` or ``public_key`` raises TypeError; a public key
    that is not 32 bytes, a bad magic, version, nested encoding, hash
    algorithm, digest width, entry order, truncation, trailing bytes, an entry
    count that disagrees with the checkpoint, a signature that does not verify
    or any recomputed chain/root inconsistency raises ValueError.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_LOG_STATE_MAGIC):
        raise ValueError("not an auditchain log-state encoding")
    offset = len(_LOG_STATE_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(data):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(data[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(data):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = data[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    if version != _LOG_STATE_VERSION:
        raise ValueError(f"unsupported log-state version {version}")
    # The nested blob is a complete signed-root encoding; every one of its
    # framing, version, algorithm and width rules applies verbatim.
    checkpoint = decode_signed_root(read_blob("signed root checkpoint"))
    count = read_u64("entries count")
    raw_entries: list[tuple[int, bytes, bytes, bytes]] = []
    for _ in range(count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        raw_entries.append((index, payload, previous_hash, entry_hash))
    if offset != len(data):
        raise ValueError("trailing bytes after the log state")

    digest_size = _digest_size(checkpoint.hash_name)
    if count != checkpoint.size:
        raise ValueError(
            "entry count does not match the signed checkpoint size"
        )
    # verify_signed_root raises TypeError/ValueError for a malformed key and
    # returns False for a structurally fine checkpoint that does not verify;
    # load_log treats the latter as a fatal format error.
    if not verify_signed_root(checkpoint, public_key):
        raise ValueError("log-state checkpoint signature does not verify")

    # Re-derive the whole chain from genesis under the checkpoint's own hash
    # algorithm, and simultaneously replay the payloads into a fresh keyless
    # log so the find index, frontier and every other auxiliary structure are
    # rebuilt exactly as the normal append path builds them.
    log = AuditLog(hash_name=checkpoint.hash_name)
    previous = bytes(digest_size)
    for position, (index, payload, recorded_previous, recorded_hash) in enumerate(
        raw_entries
    ):
        if index != position:
            raise ValueError("entries must occupy indices 0..n-1 in order")
        if len(recorded_previous) != digest_size:
            raise ValueError(
                f"entry.previous_hash must be {digest_size} bytes"
            )
        if len(recorded_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        if recorded_previous != previous:
            raise ValueError(f"entry chain is broken at index {position}")
        recomputed = entry_digest(
            position,
            previous,
            payload,
            hash_name=checkpoint.hash_name,
        )
        if not hmac.compare_digest(recomputed, recorded_hash):
            raise ValueError(f"entry digest mismatch at index {position}")
        replayed = log.append(payload)
        if (
            replayed.index != index
            or replayed.previous_hash != recorded_previous
            or not hmac.compare_digest(replayed.entry_hash, recorded_hash)
        ):
            raise ValueError(f"entry chain is inconsistent at index {position}")
        previous = recomputed
    if not hmac.compare_digest(previous, checkpoint.head):
        raise ValueError(
            "recomputed chain head does not match the signed checkpoint"
        )
    if not hmac.compare_digest(log.merkle_root(), checkpoint.root):
        raise ValueError(
            "recomputed Merkle root does not match the signed checkpoint"
        )
    return log


def dump_secure_log(log: Any, private_key: Any) -> bytes:
    """Export a complete keyless log (plain and/or encrypted entries) as bytes.

    Like :func:`dump_log`, but the exported history may contain entries
    appended with :meth:`AuditLog.encrypt`; the byte stream additionally
    carries, per entry, the information needed to restore the log's encrypted
    support structures without any encryption key:

    - an empty locator blob marks an ordinary entry;
    - a non-empty locator blob is the entry's encrypted-location HMAC, the
      digest-width value ``HMAC(key,
      b"auditchain/encrypted-locate/v1\\0" || plaintext, hash_name)`` (the
      value the live log stores in its reverse locator map);
    - each encrypted entry's 12-byte AEAD nonce is recovered from its
      self-describing envelope on load and re-entered into the nonce history,
      so a restored log rejects a reused nonce exactly as the original did.

    Only an :class:`AuditLog` that is complete and unpruned
    (``retain_from == 0``), was constructed without an authentication key and
    has never held any authentication state or history is accepted; a log that
    has only ever been appended to (plain and/or encrypted) qualifies, so the
    keyless restore target matches the source mode and no prune,
    authentication, key-evolution or verifier state needs to be carried.

    The encoding starts with the magic ``b"auditchain/secure-log/v1\\0"`` and
    then writes, strictly in order, the envelope version (always ``1``) as an
    unsigned 8-byte big-endian integer, ``B(UTF-8(hash_name))``, the entry
    count ``n`` as a u64, ``B(root)``, ``B(head)`` and the ``n`` entry
    records; record ``Ei`` is ``U(index)``, ``B(payload)``,
    ``B(previous_hash)``, ``B(entry_hash)`` and ``B(locator)`` in that order.
    ``U`` is an unsigned 8-byte big-endian integer and
    ``B(x) = U(len(x)) || x``. A 64-byte Ed25519 signature over every byte
    preceding it — the same snapshot message shape as :meth:`AuditLog.sign_root`
    apart from the trailing signature's placement at the very end — closes the
    stream. Nothing is omitted, reordered or appended.

    The call is read-only and deterministic: it never mutates the log, and two
    dumps of logs in the same state signed with the same seed are byte-for-byte
    identical (Ed25519 signatures are deterministic). A non-:class:`AuditLog`
    value or a non-``bytes`` seed raises TypeError; a seed that is not 32 bytes
    or a log that is pruned or carries authentication state/history raises
    ValueError.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    # Validate the seed first, mirroring dump_log / sign_root; the key is used
    # only for the one signature below and is never stored on the log.
    signing_key = _load_ed25519_seed(private_key)
    # The format restores an independent keyless log and carries no prune or
    # authentication material; unlike dump_log, encrypted entries are allowed.
    if log._retain_from != 0:
        raise ValueError(
            "only an unpruned log holding its complete history can be dumped"
        )
    if log._key is not None or log._stage != 0 or log._tags or log._verifier_exported:
        raise ValueError("a log with authentication state or history cannot be dumped")
    hash_name = log._hash_name
    digest_size = log._digest_size
    size = len(log)
    root = log._fold_occupied(log._occupied_at(size))
    head = log._chain_head_at(size)
    parts = [
        _SECURE_LOG_MAGIC,
        _encode_u64(_SECURE_LOG_VERSION, "version"),
        _encode_blob(hash_name.encode("utf-8")),
        _encode_u64(size, "entries count"),
        _encode_blob(root),
        _encode_blob(head),
    ]
    for entry in log._entries:
        locator = log._encrypted_locators.get(entry.index, b"")
        if locator:
            if len(locator) != digest_size:
                raise ValueError(
                    f"encrypted locator must be {digest_size} bytes"
                )
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(entry.payload))
        parts.append(_encode_blob(entry.previous_hash))
        parts.append(_encode_blob(entry.entry_hash))
        parts.append(_encode_blob(locator))
    body = b"".join(parts)
    # Sign every byte written so far; the signature is the trailing field, so
    # the wire format verifies without knowing any inner framing offset.
    signature = signing_key.sign(body)
    if len(signature) != _ED25519_SIGNATURE_BYTES:
        raise ValueError(
            f"signature must be {_ED25519_SIGNATURE_BYTES} bytes"
        )
    return body + signature


def load_secure_log(data: Any, public_key: Any) -> AuditLog:
    """Restore an independent, mutable keyless :class:`AuditLog` from
    :func:`dump_secure_log`, verifying entirely offline.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/secure-log/v1\\0"`` it must contain, strictly in order, the
    u64 envelope version (only ``1`` is supported), ``B(UTF-8(hash_name))``,
    the entry count ``n`` as a u64, ``B(root)``, ``B(head)`` and exactly ``n``
    records ``E = U(index) || B(payload) || B(previous_hash) ||
    B(entry_hash) || B(locator)``, followed by a final 64-byte Ed25519
    signature, with no truncation or trailing bytes.

    Verification happens before any state is built: the trailing signature is
    checked against every preceding byte with the 32-byte ``public_key``; only
    then is the stream parsed. Under the named ``hash_name`` every
    :func:`entry_digest` and predecessor link is recomputed from genesis and
    the resulting chain head and Merkle root must match ``head`` / ``root``.
    Classification is driven by the locator, never the payload: an empty
    locator blob marks an ordinary entry, while a non-empty locator must be
    exactly the digest width and its payload must parse as an encrypted-entry
    envelope, whose 12-byte nonce is recovered and must not repeat (a repeat,
    an unparseable envelope, or a wrong-width locator raises ValueError); a
    plain payload that merely starts with the envelope magic is still a plain
    entry when its locator is empty. Only then is a fresh keyless
    :class:`AuditLog` built by replaying the payloads through the normal
    append / encrypted-entry recovery path, so the find index, encrypted
    locator index, nonce history, Merkle frontier, head, length and retain
    point are exactly those of a log built from the same records; the result
    is fully mutable and shares no state with the caller's buffers.

    A non-``bytes`` ``data`` or ``public_key`` raises TypeError; a public key
    that is not 32 bytes, or a bad magic, version, UTF-8, hash algorithm,
    truncation, trailing bytes, index ordering, digest/locator width,
    ciphertext envelope, duplicate nonce, recomputed chain/root mismatch or a
    signature that does not verify raises ValueError.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    verification_key = _load_ed25519_public(public_key)
    if not data.startswith(_SECURE_LOG_MAGIC):
        raise ValueError("not an auditchain secure-log encoding")
    if len(data) < _ED25519_SIGNATURE_BYTES:
        raise ValueError("truncated encoding: missing signature")
    body = data[:-_ED25519_SIGNATURE_BYTES]
    signature = data[-_ED25519_SIGNATURE_BYTES:]
    # Verify the signature over the entire body before parsing any of it, so a
    # forged or corrupted stream never reaches the chain-replay logic.
    try:
        verification_key.verify(signature, body)
    except InvalidSignature as error:
        raise ValueError("secure-log signature does not verify") from error
    offset = len(_SECURE_LOG_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(body):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(body[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(body):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = body[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    if version != _SECURE_LOG_VERSION:
        raise ValueError(f"unsupported secure-log version {version}")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    digest_size = _digest_size(hash_name)
    count = read_u64("entries count")
    root = read_blob("root")
    head = read_blob("head")
    if len(root) != digest_size:
        raise ValueError(f"root must be {digest_size} bytes")
    if len(head) != digest_size:
        raise ValueError(f"head must be {digest_size} bytes")
    raw_entries: list[tuple[int, bytes, bytes, bytes, bytes]] = []
    for _ in range(count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        locator = read_blob("entry.locator")
        raw_entries.append((index, payload, previous_hash, entry_hash, locator))
    if offset != len(body):
        raise ValueError("trailing bytes before the secure-log signature")

    # Re-derive the whole chain from genesis under the named hash algorithm,
    # validate each record's locator/nonce, and simultaneously replay the
    # payloads into a fresh keyless log so every auxiliary structure (find
    # index, encrypted locator index, nonce history, frontier) is rebuilt
    # exactly as the normal append / encrypt paths build them.
    log = AuditLog(hash_name=hash_name)
    previous = bytes(digest_size)
    used_nonces: set[bytes] = set()
    for position, (index, payload, recorded_previous, recorded_hash, locator) in enumerate(
        raw_entries
    ):
        if index != position:
            raise ValueError("entries must occupy indices 0..n-1 in order")
        if len(recorded_previous) != digest_size:
            raise ValueError(
                f"entry.previous_hash must be {digest_size} bytes"
            )
        if len(recorded_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        if recorded_previous != previous:
            raise ValueError(f"entry chain is broken at index {position}")
        recomputed = entry_digest(
            position,
            previous,
            payload,
            hash_name=hash_name,
        )
        if not hmac.compare_digest(recomputed, recorded_hash):
            raise ValueError(f"entry digest mismatch at index {position}")
        # Classification is driven by the locator, never by the payload: a
        # plain append() may legitimately store bytes beginning with the
        # envelope magic, while an encrypted entry always carries a
        # digest-width locator HMAC.
        if locator:
            if len(locator) != digest_size:
                raise ValueError(
                    f"encrypted locator must be {digest_size} bytes"
                )
            # _parse_envelope validates the envelope magic, algorithm and
            # truncation and returns the embedded 12-byte nonce.
            _algorithm, nonce, _sealed = _parse_envelope(payload)
            if len(nonce) != _NONCE_BYTES:
                raise ValueError(
                    f"encrypted nonce must be {_NONCE_BYTES} bytes"
                )
            if nonce in used_nonces:
                raise ValueError("duplicate encrypted nonce in secure log")
            used_nonces.add(nonce)
            # Replay the same commit encrypt() performs, seeding the nonce
            # history and encrypted locator index without any encryption key.
            entry = Entry(
                index=position,
                payload=payload,
                previous_hash=previous,
                entry_hash=recomputed,
            )
            log._entries.append(entry)
            log._index.setdefault(
                _locator_digest(payload, hash_name), []
            ).append(position)
            log._encrypted_index.setdefault(locator, []).append(position)
            log._encrypted_locators[position] = locator
            log._used_nonces.add(nonce)
            log._head = recomputed
        else:
            # Ordinary entry: replay through the normal append path so the
            # find index and every other structure match a live append.
            replayed = log.append(payload)
            if (
                replayed.index != index
                or replayed.previous_hash != recorded_previous
                or not hmac.compare_digest(replayed.entry_hash, recorded_hash)
            ):
                raise ValueError(
                    f"entry chain is inconsistent at index {position}"
                )
        previous = recomputed
    if not hmac.compare_digest(previous, head):
        raise ValueError(
            "recomputed chain head does not match the signed snapshot"
        )
    if not hmac.compare_digest(log.merkle_root(), root):
        raise ValueError(
            "recomputed Merkle root does not match the signed snapshot"
        )
    return log


def dump_pruned_log(log: Any, private_key: Any) -> bytes:
    """Export a pruned, plain log (``retain_from > 0``) as one self-certifying
    byte string.

    The pruned counterpart of :func:`dump_log`: only an :class:`AuditLog`
    that has been pruned (``retain_from > 0``), was constructed without an
    authentication key and has never held authentication or encryption state
    or history is accepted. The byte stream carries everything needed to
    restore the log offline without any pruned payload: the retain point
    ``r``, the sealed checkpoint (the chain head of the released prefix
    ``[0, r)``), the perfect-subtree frontier covering that prefix and the
    retained entries ``r..n-1`` — no prune receipts, authentication tags or
    key-evolution state, encryption keys, nonces or locators.

    The encoding starts with the magic ``b"auditchain/pruned-log/v1\\0"`` and
    then writes, strictly in order, the envelope version (always ``1``) as an
    unsigned 8-byte big-endian integer, ``B(UTF-8(hash_name))``, the total
    entry count ``n`` as a u64, the retain point ``r`` as a u64,
    ``B(checkpoint)`` where ``checkpoint`` is the chain digest of the last of
    the first ``r`` entries (exactly the hash algorithm's digest width), the
    frontier subtree count as a u64, one ``U(height) || B(digest)`` pair per
    frontier subtree in ascending height order (the heights are exactly the
    set bits of ``r`` and the subtrees cover ``[0, r)``), the retained entry
    count as a u64 and the retained entries; entry ``Ei`` is encoded as
    ``U(index)``, ``B(payload)``, ``B(previous_hash)`` and ``B(entry_hash)``
    in that order, exactly as in :func:`dump_log`. Then come ``B(root)`` and
    ``B(head)`` of the full size-``n`` snapshot, and a 64-byte Ed25519
    signature over every preceding byte closes the stream. ``U`` is an
    unsigned 8-byte big-endian integer and ``B(x) = U(len(x)) || x``. Nothing
    is omitted, reordered or appended.

    ``private_key`` is a 32-byte Ed25519 private key seed; it is used for the
    one signature and is never stored, copied into the dump or added as a
    separate signing input. The call is read-only and deterministic: it never
    mutates the log, and two dumps of logs in the same state signed with the
    same seed are byte-for-byte identical (Ed25519 signatures are
    deterministic). A non-:class:`AuditLog` value or a non-``bytes`` seed
    raises TypeError; a seed that is not 32 bytes, or a log that is unpruned
    (``retain_from == 0``), keyed/authenticated or has encryption history
    raises ValueError.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    # Validate the seed before any eligibility check, mirroring dump_log /
    # dump_secure_log; the key is used only for the one signature below and
    # is never stored on the log.
    signing_key = _load_ed25519_seed(private_key)
    # The format restores an independent keyless log from the prune
    # checkpoint, the frontier and the retained entries only, so a pruned,
    # plain, append-only history is required.
    if log._retain_from == 0:
        raise ValueError(
            "only a pruned log (retain_from > 0) can be dumped as a pruned log"
        )
    if log._key is not None or log._stage != 0 or log._tags or log._verifier_exported:
        raise ValueError("a log with authentication state or history cannot be dumped")
    if log._encrypted_index or log._encrypted_locators or log._used_nonces:
        raise ValueError("a log with encrypted entries cannot be dumped")
    hash_name = log._hash_name
    size = len(log)
    retain_from = log._retain_from
    root = log._fold_occupied(log._occupied_at(size))
    head = log._chain_head_at(size)
    parts = [
        _PRUNED_LOG_MAGIC,
        _encode_u64(_PRUNED_LOG_VERSION, "version"),
        _encode_blob(hash_name.encode("utf-8")),
        _encode_u64(size, "entries count"),
        _encode_u64(retain_from, "retain_from"),
        _encode_blob(log._checkpoint_head),
        _encode_u64(len(log._frontier), "frontier count"),
    ]
    for height in sorted(log._frontier):
        parts.append(_encode_u64(height, "frontier height"))
        parts.append(_encode_blob(log._frontier[height]))
    parts.append(_encode_u64(len(log._entries), "retained entries count"))
    for entry in log._entries:
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(entry.payload))
        parts.append(_encode_blob(entry.previous_hash))
        parts.append(_encode_blob(entry.entry_hash))
    parts.append(_encode_blob(root))
    parts.append(_encode_blob(head))
    body = b"".join(parts)
    # Sign every byte written so far; the signature is the trailing field, so
    # the wire format verifies without knowing any inner framing offset.
    signature = signing_key.sign(body)
    if len(signature) != _ED25519_SIGNATURE_BYTES:
        raise ValueError(
            f"signature must be {_ED25519_SIGNATURE_BYTES} bytes"
        )
    return body + signature


def load_pruned_log(data: Any, public_key: Any) -> AuditLog:
    """Restore an independent, mutable :class:`AuditLog` from
    :func:`dump_pruned_log`, verifying entirely offline.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/pruned-log/v1\\0"`` it must contain, strictly in order,
    the u64 envelope version (only ``1`` is supported),
    ``B(UTF-8(hash_name))``, the total entry count ``n`` as a u64, the retain
    point ``r`` as a u64 (with ``0 < r <= n``), ``B(checkpoint)`` (the chain
    digest of the last of the first ``r`` entries, exactly the digest width),
    the u64 frontier subtree count, one ``U(height) || B(digest)`` pair per
    subtree in strictly ascending height order (the heights must be exactly
    the set bits of ``r``, covering ``[0, r)``), the u64 retained entry count
    (exactly ``n - r``), that many entries encoded as ``U(index)``,
    ``B(payload)``, ``B(previous_hash)`` and ``B(entry_hash)``, and finally
    ``B(root)`` and ``B(head)``, followed by a closing 64-byte Ed25519
    signature, with no truncation or trailing bytes.

    Verification happens before any state is built: the trailing signature is
    checked against every preceding byte with the 32-byte ``public_key``;
    only then is the stream parsed and re-checked. Under the named
    ``hash_name`` the retained entries must occupy indices ``r..n-1`` in
    order, and every :func:`entry_digest` and predecessor link is recomputed
    starting from the signed checkpoint; the resulting chain head must equal
    ``head`` and the Merkle root rebuilt from the frontier and the retained
    entries must equal ``root``. Only then is a fresh keyless
    :class:`AuditLog` materialized with ``retain_from == r``, the checkpoint
    and frontier installed and the payloads replayed through the normal
    append path, so its find index, Merkle frontier, head, length, retain
    point, Merkle roots and inclusion proofs are exactly those of the
    original pruned log — it is fully mutable and supports every existing
    operation (append, encrypt with a fresh key, further pruning, ...),
    sharing no state with the caller's buffers.

    A non-``bytes`` ``data`` or ``public_key`` raises TypeError; a public key
    that is not 32 bytes, a bad magic, version, UTF-8, hash algorithm,
    truncation, trailing bytes, an out-of-range retain point, a
    checkpoint/frontier/digest width mismatch, a frontier that is not exactly
    the set bits of ``r``, an entry count that disagrees with ``n - r``, an
    index ordering violation, a broken recomputed chain, a root/head mismatch
    or a signature that does not verify raises ValueError.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    verification_key = _load_ed25519_public(public_key)
    if not data.startswith(_PRUNED_LOG_MAGIC):
        raise ValueError("not an auditchain pruned-log encoding")
    if len(data) < _ED25519_SIGNATURE_BYTES:
        raise ValueError("truncated encoding: missing signature")
    body = data[:-_ED25519_SIGNATURE_BYTES]
    signature = data[-_ED25519_SIGNATURE_BYTES:]
    # Verify the signature over the entire body before parsing any of it, so
    # a forged or corrupted stream never reaches the chain-replay logic.
    try:
        verification_key.verify(signature, body)
    except InvalidSignature as error:
        raise ValueError("pruned-log signature does not verify") from error
    offset = len(_PRUNED_LOG_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(body):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(body[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(body):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = body[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    if version != _PRUNED_LOG_VERSION:
        raise ValueError(f"unsupported pruned-log version {version}")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    digest_size = _digest_size(hash_name)
    size = read_u64("entries count")
    retain_from = read_u64("retain_from")
    checkpoint = read_blob("checkpoint")
    if not 0 < retain_from <= size:
        raise ValueError(
            "retain_from must satisfy 0 < retain_from <= entries count"
        )
    if len(checkpoint) != digest_size:
        raise ValueError(f"checkpoint must be {digest_size} bytes")
    frontier_count = read_u64("frontier count")
    frontier: dict[int, bytes] = {}
    previous_height = -1
    for _ in range(frontier_count):
        height = read_u64("frontier height")
        digest = read_blob("frontier digest")
        if height <= previous_height:
            raise ValueError("frontier heights must be in strictly ascending order")
        if len(digest) != digest_size:
            raise ValueError(f"frontier digest must be {digest_size} bytes")
        frontier[height] = digest
        previous_height = height
    # The frontier is exactly the set of maximal perfect subtrees covering
    # [0, retain_from): one subtree of height h per set bit h of retain_from.
    expected_heights = [
        height for height in range(64) if (retain_from >> height) & 1
    ]
    if sorted(frontier) != expected_heights:
        raise ValueError(
            "frontier heights must be exactly the set bits of retain_from"
        )
    count = read_u64("retained entries count")
    if count != size - retain_from:
        raise ValueError(
            "retained entries count must equal entries count minus retain_from"
        )
    raw_entries: list[tuple[int, bytes, bytes, bytes]] = []
    for _ in range(count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        raw_entries.append((index, payload, previous_hash, entry_hash))
    root = read_blob("root")
    head = read_blob("head")
    if offset != len(body):
        raise ValueError("trailing bytes before the pruned-log signature")
    if len(root) != digest_size:
        raise ValueError(f"root must be {digest_size} bytes")
    if len(head) != digest_size:
        raise ValueError(f"head must be {digest_size} bytes")

    # Re-derive the retained chain from the signed checkpoint under the named
    # hash algorithm, and simultaneously replay the payloads into a fresh
    # keyless log with the checkpoint, frontier and retain point installed,
    # so the find index and every other auxiliary structure are rebuilt
    # exactly as the normal append path builds them. Seeding the head with
    # the checkpoint makes the first retained append link to it exactly as
    # the live log did.
    log = AuditLog(hash_name=hash_name)
    log._retain_from = retain_from
    log._checkpoint_head = checkpoint
    log._frontier = dict(frontier)
    log._head = checkpoint
    previous = checkpoint
    for position, (index, payload, recorded_previous, recorded_hash) in enumerate(
        raw_entries
    ):
        expected_index = retain_from + position
        if index != expected_index:
            raise ValueError("entries must occupy indices r..n-1 in order")
        if len(recorded_previous) != digest_size:
            raise ValueError(
                f"entry.previous_hash must be {digest_size} bytes"
            )
        if len(recorded_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        if recorded_previous != previous:
            raise ValueError(f"entry chain is broken at index {expected_index}")
        recomputed = entry_digest(
            expected_index,
            previous,
            payload,
            hash_name=hash_name,
        )
        if not hmac.compare_digest(recomputed, recorded_hash):
            raise ValueError(f"entry digest mismatch at index {expected_index}")
        replayed = log.append(payload)
        if (
            replayed.index != index
            or replayed.previous_hash != recorded_previous
            or not hmac.compare_digest(replayed.entry_hash, recorded_hash)
        ):
            raise ValueError(
                f"entry chain is inconsistent at index {expected_index}"
            )
        previous = recomputed
    if not hmac.compare_digest(previous, head):
        raise ValueError(
            "recomputed chain head does not match the signed snapshot"
        )
    if not hmac.compare_digest(log.merkle_root(), root):
        raise ValueError(
            "recomputed Merkle root does not match the signed snapshot"
        )
    return log


def dump_secure_pruned(log: Any, private_key: Any) -> bytes:
    """Export a pruned log that may contain ciphertext as one self-certifying
    byte string.

    The encrypted counterpart of :func:`dump_pruned_log`: only an
    :class:`AuditLog` that has been pruned (``retain_from > 0``), was
    constructed without an authentication key and has never held
    authentication state or history is accepted. Unlike
    :func:`dump_pruned_log`, the log's lifetime history may contain entries
    appended with :meth:`AuditLog.encrypt`, including ciphertexts released by
    the prune themselves: the stream carries the retained entries with the
    secure-log locator records and the complete nonce history, so the restored
    log rejects a reused nonce exactly as the original did. No prune receipts,
    authentication tags or key-evolution state, and no AES encryption keys, are
    carried.

    The encoding starts with the magic
    ``b"auditchain/pruned-secure/v1\\0"`` and then writes, strictly in order,
    the same fields as :func:`dump_pruned_log` up to and including the frontier
    — the envelope version (always ``1``) as an unsigned 8-byte big-endian
    integer, ``B(UTF-8(hash_name))``, the total entry count ``n`` as a u64, the
    retain point ``r`` as a u64, ``B(checkpoint)``, the frontier subtree count
    as a u64 and one ``U(height) || B(digest)`` pair per frontier subtree in
    ascending height order (the heights are exactly the set bits of ``r``).
    Then comes the nonce history: a u64 count followed by one ``B(nonce)``
    blob per used nonce in lexicographic (byte) order, each carrying exactly
    12 bytes — the complete pre-prune nonce history, not just the nonces of
    retained ciphertexts. After it the stream writes the retained entry count
    as a u64 and the retained entries
    ``r..n-1``; each entry uses the secure-log ``E`` encoding of
    :func:`dump_secure_log`: ``U(index)``, ``B(payload)``,
    ``B(previous_hash)``, ``B(entry_hash)`` and ``B(locator)``, where an empty
    locator blob marks an ordinary entry and a non-empty locator is the
    digest-width encrypted-locator HMAC (its ciphertext envelope must recover
    the 12-byte nonce carried in the history). Finally come ``B(root)`` and
    ``B(head)`` of the full size-``n`` snapshot, and a 64-byte Ed25519
    signature over every preceding byte closes the stream. ``U`` is an
    unsigned 8-byte big-endian integer and ``B(x) = U(len(x)) || x``. Nothing
    is omitted, reordered or appended.

    ``private_key`` is a 32-byte Ed25519 private key seed; it is used for the
    one signature and is never stored, copied into the dump or added as a
    separate signing input. The call is read-only and deterministic: it never
    mutates the log, and two dumps of logs in the same state signed with the
    same seed are byte-for-byte identical (Ed25519 signatures are
    deterministic). A non-:class:`AuditLog` value or a non-``bytes`` seed
    raises TypeError; a seed that is not 32 bytes, or a log that is unpruned
    (``retain_from == 0``) or carries authentication state or history raises
    ValueError.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    # Validate the seed before any eligibility check, mirroring the other
    # dump_* functions; the key is used only for the one signature below and
    # is never stored on the log.
    signing_key = _load_ed25519_seed(private_key)
    # The format restores an independent keyless log from the prune
    # checkpoint, the frontier, the retained entries and the nonce history;
    # a pruned, append-only history (plain and/or encrypted) is required, but
    # unlike dump_pruned_log encrypted entries and their nonce history are
    # carried rather than rejected.
    if log._retain_from == 0:
        raise ValueError(
            "only a pruned log (retain_from > 0) can be dumped as a pruned secure log"
        )
    if log._key is not None or log._stage != 0 or log._tags or log._verifier_exported:
        raise ValueError("a log with authentication state or history cannot be dumped")
    hash_name = log._hash_name
    digest_size = log._digest_size
    size = len(log)
    retain_from = log._retain_from
    root = log._fold_occupied(log._occupied_at(size))
    head = log._chain_head_at(size)
    # The complete lifetime nonce history, sorted lexicographically; the set
    # already outlives prunes, so nonces of released ciphertexts survive here.
    nonce_history = sorted(log._used_nonces)
    for nonce in nonce_history:
        if len(nonce) != _NONCE_BYTES:
            raise ValueError(f"encrypted nonce must be {_NONCE_BYTES} bytes")
    history = set(nonce_history)
    # Every retained ciphertext must carry a recoverable 12-byte nonce that
    # the history section accounts for; classification is driven by the
    # locator, exactly as in dump_secure_log.
    for entry in log._entries:
        locator = log._encrypted_locators.get(entry.index, b"")
        if locator:
            if len(locator) != digest_size:
                raise ValueError(
                    f"encrypted locator must be {digest_size} bytes"
                )
            _algorithm, nonce, _sealed = _parse_envelope(entry.payload)
            if len(nonce) != _NONCE_BYTES or nonce not in history:
                raise ValueError(
                    "retained ciphertext nonce is missing from the nonce history"
                )
    parts = [
        _PRUNED_SECURE_MAGIC,
        _encode_u64(_PRUNED_SECURE_VERSION, "version"),
        _encode_blob(hash_name.encode("utf-8")),
        _encode_u64(size, "entries count"),
        _encode_u64(retain_from, "retain_from"),
        _encode_blob(log._checkpoint_head),
        _encode_u64(len(log._frontier), "frontier count"),
    ]
    for height in sorted(log._frontier):
        parts.append(_encode_u64(height, "frontier height"))
        parts.append(_encode_blob(log._frontier[height]))
    parts.append(_encode_u64(len(nonce_history), "nonce history count"))
    # Each nonce is a length-prefixed B(nonce) blob carrying exactly 12
    # bytes, in lexicographic order.
    for nonce in nonce_history:
        parts.append(_encode_blob(nonce))
    parts.append(_encode_u64(len(log._entries), "retained entries count"))
    for entry in log._entries:
        locator = log._encrypted_locators.get(entry.index, b"")
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(entry.payload))
        parts.append(_encode_blob(entry.previous_hash))
        parts.append(_encode_blob(entry.entry_hash))
        parts.append(_encode_blob(locator))
    parts.append(_encode_blob(root))
    parts.append(_encode_blob(head))
    body = b"".join(parts)
    # Sign every byte written so far; the signature is the trailing field, so
    # the wire format verifies without knowing any inner framing offset.
    signature = signing_key.sign(body)
    if len(signature) != _ED25519_SIGNATURE_BYTES:
        raise ValueError(
            f"signature must be {_ED25519_SIGNATURE_BYTES} bytes"
        )
    return body + signature


def load_secure_pruned(data: Any, public_key: Any) -> AuditLog:
    """Restore an independent, mutable keyless :class:`AuditLog` from
    :func:`dump_secure_pruned`, verifying entirely offline.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/pruned-secure/v1\\0"`` it must contain, strictly in order,
    the same header and frontier fields as :func:`load_pruned_log` — the u64
    envelope version (only ``1`` is supported), ``B(UTF-8(hash_name))``, the
    total entry count ``n`` as a u64, the retain point ``r`` as a u64 (with
    ``0 < r <= n``), ``B(checkpoint)`` (exactly the digest width), the u64
    frontier subtree count and one ``U(height) || B(digest)`` pair per subtree
    in strictly ascending height order (the heights must be exactly the set
    bits of ``r``). Then come the nonce history — a u64 count and that many
    length-prefixed ``B(nonce)`` blobs in strictly ascending lexicographic
    order, each carrying exactly 12 bytes and covering the complete pre-prune
    history — the u64 retained entry count (exactly ``n - r``) and that many secure-log records
    ``E = U(index) || B(payload) || B(previous_hash) || B(entry_hash) ||
    B(locator)`` at indices ``r..n-1`` in order, then ``B(root)`` and
    ``B(head)``, followed by a closing 64-byte Ed25519 signature, with no
    truncation or trailing bytes.

    Verification happens before any state is built: the trailing signature is
    checked against every preceding byte with the 32-byte ``public_key``;
    only then is the stream parsed and re-checked. As in
    :func:`load_secure_log`, classification is driven by the locator, never
    the payload: an empty locator blob marks an ordinary entry, while a
    non-empty locator must be exactly the digest width and its payload must
    parse as an encrypted-entry envelope whose 12-byte nonce is recovered;
    that nonce must be present in the serialized history and must not repeat
    among the retained ciphertexts. Under the named ``hash_name`` every
    :func:`entry_digest` and predecessor link is recomputed starting from the
    signed checkpoint; the resulting chain head must equal ``head`` and the
    Merkle root rebuilt from the frontier and the retained entries must equal
    ``root``. Only then is a fresh keyless :class:`AuditLog` materialized with
    ``retain_from == r``, the checkpoint and frontier installed, the full
    nonce history restored and the payloads replayed through the normal append
    / encrypted-entry recovery path, so the find index, encrypted locator
    index, nonce history, Merkle frontier, head, length, retain point, Merkle
    roots and inclusion proofs are exactly those of the original pruned log;
    the result is fully mutable and shares no state with the caller's buffers.

    A non-``bytes`` ``data`` or ``public_key`` raises TypeError; a public key
    that is not 32 bytes, a bad magic, version, UTF-8, hash algorithm,
    truncation, trailing bytes, an out-of-range retain point, a
    checkpoint/frontier/digest width mismatch, a frontier that is not exactly
    the set bits of ``r``, an out-of-order or wrong-width history nonce, a
    retained ciphertext nonce missing from the history, a duplicate retained
    nonce, an entry count that disagrees with ``n - r``, an index ordering
    violation, a wrong-width locator, a bad ciphertext envelope, a broken
    recomputed chain, a root/head mismatch or a signature that does not verify
    raises ValueError.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    verification_key = _load_ed25519_public(public_key)
    if not data.startswith(_PRUNED_SECURE_MAGIC):
        raise ValueError("not an auditchain pruned-secure-log encoding")
    if len(data) < _ED25519_SIGNATURE_BYTES:
        raise ValueError("truncated encoding: missing signature")
    body = data[:-_ED25519_SIGNATURE_BYTES]
    signature = data[-_ED25519_SIGNATURE_BYTES:]
    # Verify the signature over the entire body before parsing any of it, so
    # a forged or corrupted stream never reaches the chain-replay logic.
    try:
        verification_key.verify(signature, body)
    except InvalidSignature as error:
        raise ValueError("pruned-secure-log signature does not verify") from error
    offset = len(_PRUNED_SECURE_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal offset
        end = offset + _U64_BYTES
        if end > len(body):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(body[offset:end], "big")
        offset = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal offset
        length = read_u64(f"{name} length")
        end = offset + length
        if end > len(body):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = body[offset:end]
        offset = end
        return blob

    version = read_u64("version")
    if version != _PRUNED_SECURE_VERSION:
        raise ValueError(f"unsupported pruned-secure-log version {version}")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    digest_size = _digest_size(hash_name)
    size = read_u64("entries count")
    retain_from = read_u64("retain_from")
    checkpoint = read_blob("checkpoint")
    if not 0 < retain_from <= size:
        raise ValueError(
            "retain_from must satisfy 0 < retain_from <= entries count"
        )
    if len(checkpoint) != digest_size:
        raise ValueError(f"checkpoint must be {digest_size} bytes")
    frontier_count = read_u64("frontier count")
    frontier: dict[int, bytes] = {}
    previous_height = -1
    for _ in range(frontier_count):
        height = read_u64("frontier height")
        digest = read_blob("frontier digest")
        if height <= previous_height:
            raise ValueError("frontier heights must be in strictly ascending order")
        if len(digest) != digest_size:
            raise ValueError(f"frontier digest must be {digest_size} bytes")
        frontier[height] = digest
        previous_height = height
    # The frontier is exactly the set of maximal perfect subtrees covering
    # [0, retain_from): one subtree of height h per set bit h of retain_from.
    expected_heights = [
        height for height in range(64) if (retain_from >> height) & 1
    ]
    if sorted(frontier) != expected_heights:
        raise ValueError(
            "frontier heights must be exactly the set bits of retain_from"
        )
    # Nonce history: one B(nonce) length-prefixed blob per nonce, each
    # carrying exactly 12 bytes, in strictly ascending lexicographic order,
    # which also rules out duplicates.
    nonce_count = read_u64("nonce history count")
    nonce_history: list[bytes] = []
    previous_nonce: bytes | None = None
    for _ in range(nonce_count):
        nonce = read_blob("encrypted nonce")
        if len(nonce) != _NONCE_BYTES:
            raise ValueError(f"encrypted nonce must be {_NONCE_BYTES} bytes")
        if previous_nonce is not None and nonce <= previous_nonce:
            raise ValueError(
                "nonce history must be strictly ascending 12-byte nonces without duplicates"
            )
        nonce_history.append(nonce)
        previous_nonce = nonce
    nonce_history_set = set(nonce_history)
    count = read_u64("retained entries count")
    if count != size - retain_from:
        raise ValueError(
            "retained entries count must equal entries count minus retain_from"
        )
    raw_entries: list[tuple[int, bytes, bytes, bytes, bytes]] = []
    for _ in range(count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        locator = read_blob("entry.locator")
        raw_entries.append((index, payload, previous_hash, entry_hash, locator))
    root = read_blob("root")
    head = read_blob("head")
    if offset != len(body):
        raise ValueError("trailing bytes before the pruned-secure-log signature")
    if len(root) != digest_size:
        raise ValueError(f"root must be {digest_size} bytes")
    if len(head) != digest_size:
        raise ValueError(f"head must be {digest_size} bytes")

    # Re-derive the retained chain from the signed checkpoint under the named
    # hash algorithm, and simultaneously replay the payloads into a fresh
    # keyless log with the checkpoint, frontier and retain point installed,
    # so every auxiliary structure (find index, encrypted locator index,
    # nonce history, frontier) is rebuilt exactly as the normal append /
    # encrypt paths build it. Seeding the head with the checkpoint makes the
    # first retained append link to it exactly as the live log did.
    log = AuditLog(hash_name=hash_name)
    log._retain_from = retain_from
    log._checkpoint_head = checkpoint
    log._frontier = dict(frontier)
    log._head = checkpoint
    # Restore the complete lifetime nonce history, including nonces of
    # ciphertexts released by the prune.
    log._used_nonces = set(nonce_history_set)
    previous = checkpoint
    seen_nonces: set[bytes] = set()
    for position, (index, payload, recorded_previous, recorded_hash, locator) in enumerate(
        raw_entries
    ):
        expected_index = retain_from + position
        if index != expected_index:
            raise ValueError("entries must occupy indices r..n-1 in order")
        if len(recorded_previous) != digest_size:
            raise ValueError(
                f"entry.previous_hash must be {digest_size} bytes"
            )
        if len(recorded_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        if recorded_previous != previous:
            raise ValueError(f"entry chain is broken at index {expected_index}")
        recomputed = entry_digest(
            expected_index,
            previous,
            payload,
            hash_name=hash_name,
        )
        if not hmac.compare_digest(recomputed, recorded_hash):
            raise ValueError(f"entry digest mismatch at index {expected_index}")
        # Classification is driven by the locator, never by the payload, with
        # the same rules load_secure_log applies; the recovered nonce must
        # additionally be covered by the serialized history and unique among
        # the retained ciphertexts.
        if locator:
            if len(locator) != digest_size:
                raise ValueError(
                    f"encrypted locator must be {digest_size} bytes"
                )
            _algorithm, nonce, _sealed = _parse_envelope(payload)
            if len(nonce) != _NONCE_BYTES:
                raise ValueError(
                    f"encrypted nonce must be {_NONCE_BYTES} bytes"
                )
            if nonce not in nonce_history_set:
                raise ValueError(
                    "retained ciphertext nonce is missing from the nonce history"
                )
            if nonce in seen_nonces:
                raise ValueError(
                    "duplicate encrypted nonce among retained entries"
                )
            seen_nonces.add(nonce)
            # Replay the same commit encrypt() performs, seeding the nonce
            # history (already restored above) and encrypted locator index
            # without any encryption key.
            entry = Entry(
                index=expected_index,
                payload=payload,
                previous_hash=previous,
                entry_hash=recomputed,
            )
            log._entries.append(entry)
            log._index.setdefault(
                _locator_digest(payload, hash_name), []
            ).append(expected_index)
            log._encrypted_index.setdefault(locator, []).append(expected_index)
            log._encrypted_locators[expected_index] = locator
            log._used_nonces.add(nonce)
            log._head = recomputed
        else:
            # Ordinary entry: replay through the normal append path so the
            # find index and every other structure match a live append.
            replayed = log.append(payload)
            if (
                replayed.index != index
                or replayed.previous_hash != recorded_previous
                or not hmac.compare_digest(replayed.entry_hash, recorded_hash)
            ):
                raise ValueError(
                    f"entry chain is inconsistent at index {expected_index}"
                )
        previous = recomputed
    if not hmac.compare_digest(previous, head):
        raise ValueError(
            "recomputed chain head does not match the signed snapshot"
        )
    if not hmac.compare_digest(log.merkle_root(), root):
        raise ValueError(
            "recomputed Merkle root does not match the signed snapshot"
        )
    return log


def dump_auth(log: Any, key: Any, nonce: Any = None) -> bytes:
    """Export an unpruned, keyed, encrypt-free log as one encrypted byte string.

    Unlike the Ed25519-signed dumps, the export is sealed symmetrically with
    AES-256-GCM under the 32-byte ``key`` (which must be supplied out of band
    to :func:`load_auth`). Only an :class:`AuditLog` that holds its complete,
    unpruned history (``retain_from == 0``), was **constructed with an
    authentication key** and has never held encrypted entries qualifies: the
    plaintext framing carries the current forward-secure evolution key and
    stage, so a fresh process can continue evolving from exactly the same
    point, but it carries no prune checkpoints, encryption keys, nonce history
    or verifier material beyond the u64 verifier-exported flag.

    The wire form is ``D || 0x01 || N || C`` where
    ``D = b"auditchain/auth-log/v1\\0"``, ``0x01`` is the one-byte AES-256-GCM
    algorithm id, ``N`` is the 12-byte nonce and ``C`` is the AESGCM output
    (``ciphertext || 16-byte tag``) over the plaintext framing ``P``, with the
    AEAD additional authenticated data ``D || 0x01 || N``. When ``nonce`` is
    ``None`` a fresh ``os.urandom(12)`` nonce is generated; an explicit nonce
    must be 12 ``bytes`` and the caller is responsible for never reusing it
    under the same key.

    The plaintext framing is
    ``P = B(h) || U(n) || E1…En || B(root) || B(head) || U(stage) ||
    B(K) || U(x)``: ``h`` is the UTF-8 encoding of the hash algorithm name,
    ``n`` the entry count, ``root`` the Merkle root and ``head`` the chain
    head of the size-``n`` snapshot, ``stage`` the current key-evolution
    stage, ``K`` the current evolution key and ``x`` the verifier-exported
    flag, encoded as a u64 with value ``0`` or ``1``. Each ``Ei`` encodes an
    ``Entry(index, payload, previous_hash, entry_hash)`` in field order as
    ``U, B, B, B``. ``U`` is an unsigned 8-byte big-endian integer and
    ``B(v) = U(len(v)) || v``; entry indices must be exactly ``0..n-1``.

    The call is read-only: it never mutates the log. A non-:class:`AuditLog`
    value or a non-``bytes`` key/nonce raises TypeError; a key that is not 32
    bytes, a nonce that is not 12 bytes, or a pruned/keyless log or one with
    encrypted history raises ValueError. Nothing is changed on failure.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    _check_key(key)
    if nonce is None:
        nonce = os.urandom(_NONCE_BYTES)
    else:
        _check_nonce(nonce)
    # Eligibility: the format restores a keyed, forward-secure log carrying
    # the live evolution key, so it requires an unpruned log that was
    # constructed with a key and has no encrypt history of any kind. Tags
    # themselves are not carried (offline verifiers keep their own Verifier).
    if log._retain_from != 0:
        raise ValueError(
            "only an unpruned log holding its complete history can be dumped"
        )
    if log._key is None:
        raise ValueError(
            "only a log constructed with an authentication key can be dumped"
        )
    if log._encrypted_index or log._encrypted_locators or log._used_nonces:
        raise ValueError("a log with encrypted entries cannot be dumped")
    hash_name = log._hash_name
    size = len(log)
    root = log._fold_occupied(log._occupied_at(size))
    head = log._chain_head_at(size)
    parts = [
        _encode_blob(hash_name.encode("utf-8")),
        _encode_u64(size, "entries count"),
    ]
    for entry in log._entries:
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(entry.payload))
        parts.append(_encode_blob(entry.previous_hash))
        parts.append(_encode_blob(entry.entry_hash))
    parts.append(_encode_blob(root))
    parts.append(_encode_blob(head))
    parts.append(_encode_u64(log._stage, "stage"))
    parts.append(_encode_blob(log._key))
    parts.append(_encode_u64(1 if log._verifier_exported else 0, "exported flag"))
    plaintext = b"".join(parts)
    aad = _AUTH_LOG_MAGIC + bytes((_AUTH_LOG_VERSION,)) + nonce
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return (
        _AUTH_LOG_MAGIC
        + bytes((_AUTH_LOG_VERSION,))
        + nonce
        + sealed
    )


def load_auth(data: Any, key: Any) -> AuditLog:
    """Restore an independent, mutable keyed :class:`AuditLog` from
    :func:`dump_auth`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError) and ``key`` must be 32 ``bytes``. The
    stream must start with ``D = b"auditchain/auth-log/v1\\0"`` followed by
    the one-byte algorithm id ``0x01`` (AES-256-GCM), a 12-byte nonce ``N``
    and the AESGCM output ``C`` (``ciphertext || 16-byte tag``); it is
    decrypted with the AEAD additional authenticated data
    ``D || 0x01 || N``. A wrong key or any authentication failure raises
    ValueError.

    The decrypted plaintext must parse, strictly in order and with no trailing
    bytes, as
    ``B(h) || U(n) || E1…En || B(root) || B(head) || U(stage) ||
    B(K) || U(x)``, where each ``Ei`` is an
    ``Entry(index, payload, previous_hash, entry_hash)`` in field order
    (``U, B, B, B``); indices must be exactly ``0..n-1``, every chain digest
    must have the width of the named hash algorithm, ``stage`` must be a u64,
    ``K`` (the current evolution key) must be non-empty — at stage 0 it is
    the construction key, which may have any non-zero length, and after any
    evolution it is one hash-digest wide — and
    ``x`` (the verifier-exported flag) must be ``0`` or ``1``. Under the named
    ``hash_name`` every :func:`entry_digest` and predecessor link is then
    recomputed from genesis, and the resulting chain head and Merkle root must
    match ``head`` / ``root``. Only then is a fresh keyed :class:`AuditLog`
    built by replaying the payloads through the normal append path, with
    ``K`` installed as the current key, ``stage`` and the exported flag
    restored, so its length, head, Merkle root, find index and stage are
    exactly those of the dumped log and forward-secure evolution continues
    from the same point; the result is fully mutable and shares no state with
    the caller's buffers.

    A non-``bytes`` ``data`` or key raises TypeError; a key that is not 32
    bytes, a bad magic/algorithm id, truncation, trailing bytes, a bad UTF-8 or
    unknown hash name, wrong digest widths, an out-of-order index, an
    out-of-range stage or flag, a wrong-width evolution key, an AEAD failure
    or a recomputed chain/root mismatch raises ValueError. The call never
    mutates its inputs; on failure nothing is returned and no partial log
    escapes.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    _check_key(key)
    if not data.startswith(_AUTH_LOG_MAGIC):
        raise ValueError("not an auditchain auth-log encoding")
    offset = len(_AUTH_LOG_MAGIC)
    if len(data) <= offset:
        raise ValueError("truncated encoding: missing algorithm byte")
    version = data[offset]
    offset += 1
    if version != _AUTH_LOG_VERSION:
        raise ValueError(f"unsupported auth-log version {version}")
    nonce_end = offset + _NONCE_BYTES
    if len(data) < nonce_end + _GCM_TAG_BYTES:
        raise ValueError("truncated encoding: missing nonce or ciphertext")
    nonce = data[offset:nonce_end]
    sealed = data[nonce_end:]
    aad = _AUTH_LOG_MAGIC + bytes((_AUTH_LOG_VERSION,)) + nonce
    try:
        plaintext = AESGCM(key).decrypt(nonce, sealed, aad)
    except InvalidTag as error:
        raise ValueError(
            "auth-log authentication failed: wrong key or corrupted export"
        ) from error

    cursor = 0

    def read_u64(name: str) -> int:
        nonlocal cursor
        end = cursor + _U64_BYTES
        if end > len(plaintext):
            raise ValueError(f"truncated plaintext: expected 8 bytes for {name}")
        value = int.from_bytes(plaintext[cursor:end], "big")
        cursor = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal cursor
        length = read_u64(f"{name} length")
        end = cursor + length
        if end > len(plaintext):
            raise ValueError(f"truncated plaintext: {name} is {length} bytes")
        blob = plaintext[cursor:end]
        cursor = end
        return blob

    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    digest_size = _digest_size(hash_name)
    count = read_u64("entries count")
    raw_entries: list[tuple[int, bytes, bytes, bytes]] = []
    for _ in range(count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        raw_entries.append((index, payload, previous_hash, entry_hash))
    root = read_blob("root")
    head = read_blob("head")
    stage = read_u64("stage")
    evolution_key = read_blob("evolution key")
    exported = read_u64("exported flag")
    if cursor != len(plaintext):
        raise ValueError("trailing bytes in the auth-log plaintext")
    if len(root) != digest_size:
        raise ValueError(f"root must be {digest_size} bytes")
    if len(head) != digest_size:
        raise ValueError(f"head must be {digest_size} bytes")
    if not evolution_key:
        raise ValueError("evolution key must be non-empty")
    if stage > 0 and len(evolution_key) != digest_size:
        raise ValueError(
            f"evolution key must be {digest_size} bytes after the first evolution"
        )
    if exported not in (0, 1):
        raise ValueError("exported flag must be 0 or 1")

    # Re-derive the whole chain from genesis under the named hash algorithm,
    # and simultaneously replay the payloads into a fresh keyed log so every
    # auxiliary structure (find index, Merkle frontier, head, length) is
    # rebuilt exactly as the normal append path builds it. The evolution key,
    # stage and verifier-exported flag are only installed after the replay
    # succeeds, so a failure leaves no partially restored log behind.
    log = AuditLog(key=evolution_key, hash_name=hash_name)
    previous = bytes(digest_size)
    for position, (index, payload, recorded_previous, recorded_hash) in enumerate(
        raw_entries
    ):
        if index != position:
            raise ValueError("entries must occupy indices 0..n-1 in order")
        if len(recorded_previous) != digest_size:
            raise ValueError(
                f"entry.previous_hash must be {digest_size} bytes"
            )
        if len(recorded_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        if recorded_previous != previous:
            raise ValueError(f"entry chain is broken at index {position}")
        recomputed = entry_digest(
            position,
            previous,
            payload,
            hash_name=hash_name,
        )
        if not hmac.compare_digest(recomputed, recorded_hash):
            raise ValueError(f"entry digest mismatch at index {position}")
        replayed = log.append(payload)
        if (
            replayed.index != index
            or replayed.previous_hash != recorded_previous
            or not hmac.compare_digest(replayed.entry_hash, recorded_hash)
        ):
            raise ValueError(f"entry chain is inconsistent at index {position}")
        previous = recomputed
    if not hmac.compare_digest(previous, head):
        raise ValueError("recomputed chain head does not match the exported head")
    if not hmac.compare_digest(log.merkle_root(), root):
        raise ValueError("recomputed Merkle root does not match the exported root")
    log._stage = stage
    log._verifier_exported = bool(exported)
    return log


def dump_pruned_auth(log: Any, key: Any, nonce: Any = None) -> bytes:
    """Export a pruned, keyed, encrypt-free log as one encrypted byte string.

    The pruned counterpart of :func:`dump_auth`: unlike the Ed25519-signed
    dumps, the export is sealed symmetrically with AES-256-GCM under the
    32-byte ``key`` (which must be supplied out of band to
    :func:`load_pruned_auth`). Only an :class:`AuditLog` that has been pruned
    (``retain_from > 0``), was **constructed with an authentication key** and
    has never held encrypted entries qualifies: the plaintext framing carries
    the prune checkpoint, the prefix frontier, the retained entries and the
    current forward-secure evolution key and stage, so a fresh process can
    continue evolving from exactly the same point, but it carries no prune
    receipts, tags, encryption keys, nonce history or verifier material
    beyond the u64 verifier-exported flag.

    The wire form is ``D || 0x01 || N || C`` where
    ``D = b"auditchain/pruned-auth/v1\\0"``, ``0x01`` is the one-byte
    AES-256-GCM algorithm id, ``N`` is the 12-byte nonce and ``C`` is the
    AESGCM output (``ciphertext || 16-byte tag``) over the plaintext framing
    ``P``, with the AEAD additional authenticated data
    ``D || 0x01 || N``. When ``nonce`` is ``None`` a fresh
    ``os.urandom(12)`` nonce is generated; an explicit nonce must be 12
    ``bytes`` and the caller is responsible for never reusing it under the
    same key.

    The plaintext framing is, strictly in order,
    ``P = B(hash_name) || U(n) || U(r) || B(checkpoint) || F || E ||
    B(root) || B(head) || U(stage) || B(K) || U(x)``: ``n`` is the total
    entry count, ``r`` the retain point (``0 < r <= n``), ``checkpoint`` the
    chain digest of the last of the first ``r`` entries, and ``F`` the
    frontier — a u64 subtree count followed by one
    ``U(height) || B(digest)`` pair per set bit of ``r`` in ascending height
    order. ``E`` is a u64 count (exactly ``n - r``) followed by the retained
    entries in index order ``r..n-1``, each encoded exactly as in
    :func:`dump_auth` (``U(index) || B(payload) || B(previous_hash) ||
    B(entry_hash)``). ``root`` / ``head`` are the Merkle root and chain head
    of the full size-``n`` snapshot, ``stage`` the current key-evolution
    stage, ``K`` the current evolution key and ``x`` the verifier-exported
    flag, encoded as a u64 with value ``0`` or ``1``. ``U`` is an unsigned
    8-byte big-endian integer and ``B(v) = U(len(v)) || v``.

    The call is read-only: it never mutates the log. A non-:class:`AuditLog`
    value or a non-``bytes`` key/nonce raises TypeError; a key that is not 32
    bytes, a nonce that is not 12 bytes, or an unpruned/keyless log or one
    with encrypted history raises ValueError. Nothing is changed on failure.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    _check_key(key)
    if nonce is None:
        nonce = os.urandom(_NONCE_BYTES)
    else:
        _check_nonce(nonce)
    # Eligibility: the format restores a pruned, keyed, forward-secure log
    # carrying the live evolution key, so it requires retain_from > 0, a
    # construction-time key and no encrypt history of any kind.
    if log._retain_from == 0:
        raise ValueError(
            "only a pruned log (retain_from > 0) can be dumped as a pruned auth log"
        )
    if log._key is None:
        raise ValueError(
            "only a log constructed with an authentication key can be dumped"
        )
    if log._encrypted_index or log._encrypted_locators or log._used_nonces:
        raise ValueError("a log with encrypted entries cannot be dumped")
    hash_name = log._hash_name
    size = len(log)
    retain_from = log._retain_from
    root = log._fold_occupied(log._occupied_at(size))
    head = log._chain_head_at(size)
    parts = [
        _encode_blob(hash_name.encode("utf-8")),
        _encode_u64(size, "entries count"),
        _encode_u64(retain_from, "retain_from"),
        _encode_blob(log._checkpoint_head),
        _encode_u64(len(log._frontier), "frontier count"),
    ]
    for height in sorted(log._frontier):
        parts.append(_encode_u64(height, "frontier height"))
        parts.append(_encode_blob(log._frontier[height]))
    parts.append(_encode_u64(len(log._entries), "retained entries count"))
    for entry in log._entries:
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(entry.payload))
        parts.append(_encode_blob(entry.previous_hash))
        parts.append(_encode_blob(entry.entry_hash))
    parts.append(_encode_blob(root))
    parts.append(_encode_blob(head))
    parts.append(_encode_u64(log._stage, "stage"))
    parts.append(_encode_blob(log._key))
    parts.append(_encode_u64(1 if log._verifier_exported else 0, "exported flag"))
    plaintext = b"".join(parts)
    aad = _PRUNED_AUTH_MAGIC + bytes((_PRUNED_AUTH_VERSION,)) + nonce
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return (
        _PRUNED_AUTH_MAGIC
        + bytes((_PRUNED_AUTH_VERSION,))
        + nonce
        + sealed
    )


def load_pruned_auth(data: Any, key: Any) -> AuditLog:
    """Restore an independent, mutable keyed :class:`AuditLog` from
    :func:`dump_pruned_auth`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError) and ``key`` must be 32 ``bytes``. The
    stream must start with ``D = b"auditchain/pruned-auth/v1\\0"`` followed
    by the one-byte algorithm id ``0x01`` (AES-256-GCM), a 12-byte nonce
    ``N`` and the AESGCM output ``C`` (``ciphertext || 16-byte tag``); it is
    decrypted with the AEAD additional authenticated data
    ``D || 0x01 || N``. A wrong key or any authentication failure raises
    ValueError; GCM authentication always runs before the plaintext is
    parsed.

    The decrypted plaintext must parse, strictly in order and with no trailing
    bytes, as
    ``B(hash_name) || U(n) || U(r) || B(checkpoint) || F || E ||
    B(root) || B(head) || U(stage) || B(K) || U(x)``: ``r`` must satisfy
    ``0 < r <= n``, ``checkpoint`` must have the digest width, ``F`` must
    list one ``U(height) || B(digest)`` pair per set bit of ``r`` in
    strictly ascending order, ``E`` must carry exactly ``n - r`` entries
    occupying indices ``r..n-1`` in order (each as
    ``U(index) || B(payload) || B(previous_hash) || B(entry_hash)``), every
    chain digest must have the width of the named hash algorithm,
    ``stage`` must be a u64, ``K`` (the current evolution key) must be
    non-empty — at stage 0 it is the construction key, which may have any
    non-zero length, and after any evolution it is one hash-digest wide —
    and ``x`` must be the u64 value ``0`` or ``1``. Under the named
    ``hash_name`` every :func:`entry_digest` and predecessor link is then
    recomputed starting from the checkpoint, the resulting chain head must
    match ``head`` and the Merkle root rebuilt from the frontier and the
    retained entries must match ``root``. Only then is a fresh keyed
    :class:`AuditLog` materialized with ``retain_from == r``, the checkpoint
    and frontier installed and the payloads replayed through the normal
    append path, with ``K`` installed as the current key, ``stage`` and the
    exported flag restored; the result is fully mutable, supports every
    existing operation (append, auth, rotate_key, further pruning, ...) and
    shares no state with the caller's buffers.

    A non-``bytes`` ``data`` or key raises TypeError; a key that is not 32
    bytes, a bad magic/algorithm id, truncation, trailing bytes, a bad UTF-8
    or unknown hash name, an out-of-range retain point, wrong digest widths,
    a frontier that is not exactly the set bits of ``r``, an entry count
    that disagrees with ``n - r``, an out-of-order index, a broken
    recomputed chain, a root/head mismatch, an out-of-range stage or flag, a
    wrong-width evolution key, or an AEAD failure raises ValueError. The
    call never mutates its inputs; on failure no partial log escapes.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    _check_key(key)
    if not data.startswith(_PRUNED_AUTH_MAGIC):
        raise ValueError("not an auditchain pruned-auth encoding")
    offset = len(_PRUNED_AUTH_MAGIC)
    if len(data) <= offset:
        raise ValueError("truncated encoding: missing algorithm byte")
    version = data[offset]
    offset += 1
    if version != _PRUNED_AUTH_VERSION:
        raise ValueError(f"unsupported pruned-auth version {version}")
    nonce_end = offset + _NONCE_BYTES
    if len(data) < nonce_end + _GCM_TAG_BYTES:
        raise ValueError("truncated encoding: missing nonce or ciphertext")
    nonce = data[offset:nonce_end]
    sealed = data[nonce_end:]
    aad = _PRUNED_AUTH_MAGIC + bytes((_PRUNED_AUTH_VERSION,)) + nonce
    try:
        plaintext = AESGCM(key).decrypt(nonce, sealed, aad)
    except InvalidTag as error:
        raise ValueError(
            "pruned-auth authentication failed: wrong key or corrupted export"
        ) from error

    cursor = 0

    def read_u64(name: str) -> int:
        nonlocal cursor
        end = cursor + _U64_BYTES
        if end > len(plaintext):
            raise ValueError(f"truncated plaintext: expected 8 bytes for {name}")
        value = int.from_bytes(plaintext[cursor:end], "big")
        cursor = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal cursor
        length = read_u64(f"{name} length")
        end = cursor + length
        if end > len(plaintext):
            raise ValueError(f"truncated plaintext: {name} is {length} bytes")
        blob = plaintext[cursor:end]
        cursor = end
        return blob

    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    digest_size = _digest_size(hash_name)
    size = read_u64("entries count")
    retain_from = read_u64("retain_from")
    checkpoint = read_blob("checkpoint")
    if not 0 < retain_from <= size:
        raise ValueError(
            "retain_from must satisfy 0 < retain_from <= entries count"
        )
    if len(checkpoint) != digest_size:
        raise ValueError(f"checkpoint must be {digest_size} bytes")
    frontier_count = read_u64("frontier count")
    frontier: dict[int, bytes] = {}
    previous_height = -1
    for _ in range(frontier_count):
        height = read_u64("frontier height")
        digest = read_blob("frontier digest")
        if height <= previous_height:
            raise ValueError("frontier heights must be in strictly ascending order")
        if len(digest) != digest_size:
            raise ValueError(f"frontier digest must be {digest_size} bytes")
        frontier[height] = digest
        previous_height = height
    expected_heights = [
        height for height in range(64) if (retain_from >> height) & 1
    ]
    if sorted(frontier) != expected_heights:
        raise ValueError(
            "frontier heights must be exactly the set bits of retain_from"
        )
    count = read_u64("retained entries count")
    if count != size - retain_from:
        raise ValueError(
            "retained entries count must equal entries count minus retain_from"
        )
    raw_entries: list[tuple[int, bytes, bytes, bytes]] = []
    for _ in range(count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        raw_entries.append((index, payload, previous_hash, entry_hash))
    root = read_blob("root")
    head = read_blob("head")
    stage = read_u64("stage")
    evolution_key = read_blob("evolution key")
    exported = read_u64("exported flag")
    if cursor != len(plaintext):
        raise ValueError("trailing bytes in the pruned-auth plaintext")
    if len(root) != digest_size:
        raise ValueError(f"root must be {digest_size} bytes")
    if len(head) != digest_size:
        raise ValueError(f"head must be {digest_size} bytes")
    if not evolution_key:
        raise ValueError("evolution key must be non-empty")
    if stage > 0 and len(evolution_key) != digest_size:
        raise ValueError(
            f"evolution key must be {digest_size} bytes after the first evolution"
        )
    if exported not in (0, 1):
        raise ValueError("exported flag must be 0 or 1")

    # Re-derive the retained chain from the checkpoint under the named hash
    # algorithm, and simultaneously replay the payloads into a fresh keyed
    # log with the checkpoint, frontier and retain point installed, so the
    # find index and every other auxiliary structure are rebuilt exactly as
    # the normal append path builds them. The evolution key, stage and
    # verifier-exported flag are only installed after the replay succeeds,
    # so a failure leaves no partially restored log behind.
    log = AuditLog(key=evolution_key, hash_name=hash_name)
    log._retain_from = retain_from
    log._checkpoint_head = checkpoint
    log._frontier = dict(frontier)
    log._head = checkpoint
    previous = checkpoint
    for position, (index, payload, recorded_previous, recorded_hash) in enumerate(
        raw_entries
    ):
        expected_index = retain_from + position
        if index != expected_index:
            raise ValueError("entries must occupy indices r..n-1 in order")
        if len(recorded_previous) != digest_size:
            raise ValueError(
                f"entry.previous_hash must be {digest_size} bytes"
            )
        if len(recorded_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        if recorded_previous != previous:
            raise ValueError(f"entry chain is broken at index {expected_index}")
        recomputed = entry_digest(
            expected_index,
            previous,
            payload,
            hash_name=hash_name,
        )
        if not hmac.compare_digest(recomputed, recorded_hash):
            raise ValueError(f"entry digest mismatch at index {expected_index}")
        replayed = log.append(payload)
        if (
            replayed.index != index
            or replayed.previous_hash != recorded_previous
            or not hmac.compare_digest(replayed.entry_hash, recorded_hash)
        ):
            raise ValueError(
                f"entry chain is inconsistent at index {expected_index}"
            )
        previous = recomputed
    if not hmac.compare_digest(previous, head):
        raise ValueError("recomputed chain head does not match the exported head")
    if not hmac.compare_digest(log.merkle_root(), root):
        raise ValueError("recomputed Merkle root does not match the exported root")
    log._stage = stage
    log._verifier_exported = bool(exported)
    return log


def dump_hybrid(log: Any, key: Any, nonce: Any = None) -> bytes:
    """Export an unpruned, keyed log (with encrypt history) as encrypted bytes.

    The hybrid of :func:`dump_auth` and :func:`dump_secure_log`: like
    :func:`dump_auth`, the export is sealed symmetrically with AES-256-GCM
    under the 32-byte ``key`` (which must be supplied out of band to
    :func:`load_hybrid`) and carries the current forward-secure evolution key
    and stage, so a fresh process can continue evolving from exactly the same
    point; like :func:`dump_secure_log`, the history may contain entries
    appended with :meth:`AuditLog.encrypt`, and the framing additionally
    carries their encrypted-locator HMACs and the log's complete nonce
    history, so the restored log keeps its encrypted search index and rejects
    a reused nonce exactly as the original did. Only an :class:`AuditLog`
    that holds its complete, unpruned history (``retain_from == 0``) and was
    **constructed with an authentication key** qualifies; tags themselves are
    not carried (offline verifiers keep their own Verifier).

    The wire form is ``D || 0x01 || N || C`` where
    ``D = b"auditchain/hybrid/v1\\0"``, ``0x01`` is the one-byte AES-256-GCM
    algorithm id, ``N`` is the 12-byte nonce and ``C`` is the AESGCM output
    (``ciphertext || 16-byte tag``) over the plaintext framing ``P``, with the
    AEAD additional authenticated data ``D || 0x01 || N``. When ``nonce`` is
    ``None`` a fresh ``os.urandom(12)`` nonce is generated; an explicit nonce
    must be 12 ``bytes`` and the caller is responsible for never reusing it
    under the same key.

    The plaintext framing is
    ``P = B(h) || U(q) || B(nonce1)…B(nonceq) || U(n) || E1…En ||
    B(root) || B(head) || U(stage) || B(K) || U(x)``: ``h`` is the UTF-8
    encoding of the hash algorithm name, ``q`` the number of nonces ever used
    by :meth:`AuditLog.encrypt` in this log, each written as a 12-byte blob
    in lexicographic order, ``n`` the entry count, ``root`` the Merkle root
    and ``head`` the chain head of the size-``n`` snapshot, ``stage`` the
    current key-evolution stage, ``K`` the current evolution key and ``x``
    the verifier-exported flag, encoded as a u64 with value ``0`` or ``1``.
    Each ``Ei`` reuses the :func:`dump_secure_log` record encoding
    ``U(index) || B(payload) || B(previous_hash) || B(entry_hash) ||
    B(locator)``, where an empty locator blob marks a plain entry and a
    non-empty locator is the digest-width encrypted-locator HMAC. ``U`` is an
    unsigned 8-byte big-endian integer and ``B(v) = U(len(v)) || v``; entry
    indices must be exactly ``0..n-1``.

    The call is read-only: it never mutates the log. A non-:class:`AuditLog`
    value or a non-``bytes`` key/nonce raises TypeError; a key that is not 32
    bytes, a nonce that is not 12 bytes, or a pruned or keyless log raises
    ValueError. Nothing is changed on failure.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    _check_key(key)
    if nonce is None:
        nonce = os.urandom(_NONCE_BYTES)
    else:
        _check_nonce(nonce)
    # Eligibility: the format restores a keyed, forward-secure log carrying
    # the live evolution key, so it requires an unpruned log that was
    # constructed with a key. Unlike dump_auth, an encrypt history is
    # exactly what the nonce history and per-entry locators preserve.
    if log._retain_from != 0:
        raise ValueError(
            "only an unpruned log holding its complete history can be dumped"
        )
    if log._key is None:
        raise ValueError(
            "only a log constructed with an authentication key can be dumped"
        )
    hash_name = log._hash_name
    digest_size = log._digest_size
    size = len(log)
    root = log._fold_occupied(log._occupied_at(size))
    head = log._chain_head_at(size)
    parts = [
        _encode_blob(hash_name.encode("utf-8")),
        _encode_u64(len(log._used_nonces), "nonce count"),
    ]
    for used_nonce in sorted(log._used_nonces):
        parts.append(_encode_blob(used_nonce))
    parts.append(_encode_u64(size, "entries count"))
    for entry in log._entries:
        locator = log._encrypted_locators.get(entry.index, b"")
        if locator:
            if len(locator) != digest_size:
                raise ValueError(
                    f"encrypted locator must be {digest_size} bytes"
                )
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(entry.payload))
        parts.append(_encode_blob(entry.previous_hash))
        parts.append(_encode_blob(entry.entry_hash))
        parts.append(_encode_blob(locator))
    parts.append(_encode_blob(root))
    parts.append(_encode_blob(head))
    parts.append(_encode_u64(log._stage, "stage"))
    parts.append(_encode_blob(log._key))
    parts.append(_encode_u64(1 if log._verifier_exported else 0, "exported flag"))
    plaintext = b"".join(parts)
    aad = _HYBRID_MAGIC + bytes((_HYBRID_VERSION,)) + nonce
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return (
        _HYBRID_MAGIC
        + bytes((_HYBRID_VERSION,))
        + nonce
        + sealed
    )


def load_hybrid(data: Any, key: Any) -> AuditLog:
    """Restore an independent, mutable keyed :class:`AuditLog` from
    :func:`dump_hybrid`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError) and ``key`` must be 32 ``bytes``. The
    stream must start with ``D = b"auditchain/hybrid/v1\\0"`` followed by the
    one-byte algorithm id ``0x01`` (AES-256-GCM), a 12-byte nonce ``N`` and
    the AESGCM output ``C`` (``ciphertext || 16-byte tag``); it is decrypted
    with the AEAD additional authenticated data ``D || 0x01 || N``. A wrong
    key or any authentication failure raises ValueError; GCM authentication
    always runs before the plaintext is parsed.

    The decrypted plaintext must parse, strictly in order and with no
    trailing bytes, as
    ``B(h) || U(q) || B(nonce1)…B(nonceq) || U(n) || E1…En || B(root) ||
    B(head) || U(stage) || B(K) || U(x)``: every nonce blob must carry
    exactly 12 bytes and the ``q`` nonces must be distinct and in
    lexicographic order; each ``Ei`` is an
    ``Entry(index, payload, previous_hash, entry_hash)`` record in the
    :func:`dump_secure_log` field order (``U, B, B, B, B``) whose trailing
    ``B(locator)`` is empty for a plain entry and the digest-width
    encrypted-locator HMAC for an encrypted one; indices must be exactly
    ``0..n-1``, every chain digest must have the width of the named hash
    algorithm, ``stage`` must be a u64, ``K`` (the current evolution key)
    must be non-empty — at stage 0 it is the construction key, which may
    have any non-zero length, and after any evolution it is one hash-digest
    wide — and ``x`` (the verifier-exported flag) must be ``0`` or ``1``.
    Under the named ``hash_name`` every :func:`entry_digest` and predecessor
    link is then recomputed from genesis, and the resulting chain head and
    Merkle root must match ``head`` / ``root``. Classification is driven by
    the locator, never the payload: a non-empty locator's payload must parse
    as an encrypted-entry envelope, whose 12-byte nonce is recovered and must
    not repeat, and the recovered envelope nonces must together be exactly
    the declared nonce history. Only then is a fresh keyed
    :class:`AuditLog` built by replaying the payloads through the normal
    append / encrypted-entry recovery path, with the nonce history, ``K`` as
    the current key, ``stage`` and the exported flag installed, so its
    length, head, Merkle root, find index, encrypted locator index, nonce
    history and stage are exactly those of the dumped log and forward-secure
    evolution continues from the same point; the result is fully mutable and
    shares no state with the caller's buffers.

    A non-``bytes`` ``data`` or key raises TypeError; a key that is not 32
    bytes, a bad magic/algorithm id, truncation, trailing bytes, a bad UTF-8
    or unknown hash name, a wrong-width, duplicated or misordered nonce, a
    nonce history that disagrees with the encrypted entries, wrong digest or
    locator widths, an unparseable ciphertext envelope, an out-of-order
    index, an out-of-range stage or flag, a wrong-width evolution key, an
    AEAD failure or a recomputed chain/root mismatch raises ValueError. The
    call never mutates its inputs; on failure nothing is returned and no
    partial log escapes.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    _check_key(key)
    if not data.startswith(_HYBRID_MAGIC):
        raise ValueError("not an auditchain hybrid encoding")
    offset = len(_HYBRID_MAGIC)
    if len(data) <= offset:
        raise ValueError("truncated encoding: missing algorithm byte")
    version = data[offset]
    offset += 1
    if version != _HYBRID_VERSION:
        raise ValueError(f"unsupported hybrid version {version}")
    nonce_end = offset + _NONCE_BYTES
    if len(data) < nonce_end + _GCM_TAG_BYTES:
        raise ValueError("truncated encoding: missing nonce or ciphertext")
    nonce = data[offset:nonce_end]
    sealed = data[nonce_end:]
    aad = _HYBRID_MAGIC + bytes((_HYBRID_VERSION,)) + nonce
    try:
        plaintext = AESGCM(key).decrypt(nonce, sealed, aad)
    except InvalidTag as error:
        raise ValueError(
            "hybrid authentication failed: wrong key or corrupted export"
        ) from error

    cursor = 0

    def read_u64(name: str) -> int:
        nonlocal cursor
        end = cursor + _U64_BYTES
        if end > len(plaintext):
            raise ValueError(f"truncated plaintext: expected 8 bytes for {name}")
        value = int.from_bytes(plaintext[cursor:end], "big")
        cursor = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal cursor
        length = read_u64(f"{name} length")
        end = cursor + length
        if end > len(plaintext):
            raise ValueError(f"truncated plaintext: {name} is {length} bytes")
        blob = plaintext[cursor:end]
        cursor = end
        return blob

    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    digest_size = _digest_size(hash_name)
    nonce_count = read_u64("nonce count")
    nonce_history: list[bytes] = []
    previous_nonce: bytes | None = None
    for _ in range(nonce_count):
        used_nonce = read_blob("nonce")
        if len(used_nonce) != _NONCE_BYTES:
            raise ValueError(f"nonce must be {_NONCE_BYTES} bytes")
        if previous_nonce is not None and used_nonce <= previous_nonce:
            raise ValueError(
                "nonces must be distinct and in lexicographic order"
            )
        nonce_history.append(used_nonce)
        previous_nonce = used_nonce
    count = read_u64("entries count")
    raw_entries: list[tuple[int, bytes, bytes, bytes, bytes]] = []
    for _ in range(count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        locator = read_blob("entry.locator")
        raw_entries.append((index, payload, previous_hash, entry_hash, locator))
    root = read_blob("root")
    head = read_blob("head")
    stage = read_u64("stage")
    evolution_key = read_blob("evolution key")
    exported = read_u64("exported flag")
    if cursor != len(plaintext):
        raise ValueError("trailing bytes in the hybrid plaintext")
    if len(root) != digest_size:
        raise ValueError(f"root must be {digest_size} bytes")
    if len(head) != digest_size:
        raise ValueError(f"head must be {digest_size} bytes")
    if not evolution_key:
        raise ValueError("evolution key must be non-empty")
    if stage > 0 and len(evolution_key) != digest_size:
        raise ValueError(
            f"evolution key must be {digest_size} bytes after the first evolution"
        )
    if exported not in (0, 1):
        raise ValueError("exported flag must be 0 or 1")

    # Re-derive the whole chain from genesis under the named hash algorithm,
    # validate each record's locator/nonce, and simultaneously replay the
    # payloads into a fresh keyed log so every auxiliary structure (find
    # index, encrypted locator index, nonce history, frontier) is rebuilt
    # exactly as the normal append / encrypt paths build them. The nonce
    # history, evolution key, stage and verifier-exported flag are only
    # installed after the replay succeeds, so a failure leaves no partially
    # restored log behind.
    log = AuditLog(key=evolution_key, hash_name=hash_name)
    previous = bytes(digest_size)
    for position, (index, payload, recorded_previous, recorded_hash, locator) in enumerate(
        raw_entries
    ):
        if index != position:
            raise ValueError("entries must occupy indices 0..n-1 in order")
        if len(recorded_previous) != digest_size:
            raise ValueError(
                f"entry.previous_hash must be {digest_size} bytes"
            )
        if len(recorded_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        if recorded_previous != previous:
            raise ValueError(f"entry chain is broken at index {position}")
        recomputed = entry_digest(
            position,
            previous,
            payload,
            hash_name=hash_name,
        )
        if not hmac.compare_digest(recomputed, recorded_hash):
            raise ValueError(f"entry digest mismatch at index {position}")
        # Classification is driven by the locator, never by the payload: a
        # plain append() may legitimately store bytes beginning with the
        # envelope magic, while an encrypted entry always carries a
        # digest-width locator HMAC.
        if locator:
            if len(locator) != digest_size:
                raise ValueError(
                    f"encrypted locator must be {digest_size} bytes"
                )
            # _parse_envelope validates the envelope magic, algorithm and
            # truncation and returns the embedded 12-byte nonce.
            _algorithm, entry_nonce, _sealed = _parse_envelope(payload)
            if len(entry_nonce) != _NONCE_BYTES:
                raise ValueError(
                    f"encrypted nonce must be {_NONCE_BYTES} bytes"
                )
            if entry_nonce in log._used_nonces:
                raise ValueError("duplicate encrypted nonce in hybrid log")
            # Replay the same commit encrypt() performs, seeding the nonce
            # history and encrypted locator index without any encryption key.
            entry = Entry(
                index=position,
                payload=payload,
                previous_hash=previous,
                entry_hash=recomputed,
            )
            log._entries.append(entry)
            log._index.setdefault(
                _locator_digest(payload, hash_name), []
            ).append(position)
            log._encrypted_index.setdefault(locator, []).append(position)
            log._encrypted_locators[position] = locator
            log._used_nonces.add(entry_nonce)
            log._head = recomputed
        else:
            # Ordinary entry: replay through the normal append path so the
            # find index and every other structure match a live append.
            replayed = log.append(payload)
            if (
                replayed.index != index
                or replayed.previous_hash != recorded_previous
                or not hmac.compare_digest(replayed.entry_hash, recorded_hash)
            ):
                raise ValueError(
                    f"entry chain is inconsistent at index {position}"
                )
        previous = recomputed
    if not hmac.compare_digest(previous, head):
        raise ValueError("recomputed chain head does not match the exported head")
    if not hmac.compare_digest(log.merkle_root(), root):
        raise ValueError("recomputed Merkle root does not match the exported root")
    # The declared nonce history must be exactly the nonces of the encrypted
    # entries: an unpruned log releases no envelope, so anything more or less
    # is inconsistent state.
    if log._used_nonces != set(nonce_history):
        raise ValueError(
            "nonce history does not match the encrypted entries"
        )
    log._stage = stage
    log._verifier_exported = bool(exported)
    return log


def dump_pruned_hybrid(log: Any, key: Any, nonce: Any = None) -> bytes:
    """Export a pruned, keyed log (with encrypt history) as encrypted bytes.

    The pruned counterpart of :func:`dump_hybrid` and the encrypt-tolerant
    counterpart of :func:`dump_pruned_auth`: like both, the export is sealed
    symmetrically with AES-256-GCM under the 32-byte ``key`` (which must be
    supplied out of band to :func:`load_pruned_hybrid`) and carries the
    current forward-secure evolution key and stage, so a fresh process can
    continue evolving from exactly the same point. Only an :class:`AuditLog`
    that has been pruned (``retain_from > 0``) and was **constructed with an
    authentication key** qualifies; unlike :func:`dump_pruned_auth`, the
    history may contain entries appended with :meth:`AuditLog.encrypt`,
    including ciphertexts released by the prune. The framing carries the
    prune checkpoint, the prefix frontier, the retained entries, the
    log's complete nonce history (covering every encrypt nonce ever used,
    even those of released ciphertexts) and the encrypted-locator HMACs of
    the retained ciphertexts, so the restored log keeps its find index,
    encrypted search index, Merkle frontier and nonce-reuse rejection
    exactly as the original did. Tags themselves are not carried (offline
    verifiers keep their own Verifier).

    The wire form is ``D || 0x01 || N || C`` where
    ``D = b"auditchain/pruned-hybrid/v1\\0"``, ``0x01`` is the one-byte
    AES-256-GCM algorithm id, ``N`` is the 12-byte nonce and ``C`` is the
    AESGCM output (``ciphertext || 16-byte tag``) over the plaintext framing
    ``P``, with the AEAD additional authenticated data ``D || 0x01 || N``.
    When ``nonce`` is ``None`` a fresh ``os.urandom(12)`` nonce is generated;
    an explicit nonce must be 12 ``bytes`` and the caller is responsible for
    never reusing it under the same key.

    The plaintext framing is, strictly in order,
    ``P = B(h) || U(n) || U(r) || B(checkpoint) || F || Q || E ||
    B(root) || B(head) || U(stage) || B(K) || U(x)``: ``h`` is the UTF-8
    encoding of the hash algorithm name, ``n`` the total entry count, ``r``
    the retain point (``0 < r <= n``), ``checkpoint`` the chain digest of
    the last of the first ``r`` entries, and ``F`` the frontier exactly as
    encoded by :func:`dump_pruned_auth` — a u64 subtree count followed by
    one ``U(height) || B(digest)`` pair per set bit of ``r`` in ascending
    height order. ``Q`` is the complete nonce history exactly as in
    :func:`dump_hybrid`: a u64 count followed by one 12-byte
    ``B(used_nonce)`` blob per nonce ever used by :meth:`AuditLog.encrypt`,
    in lexicographic order. ``E`` is a u64 count (exactly ``n - r``)
    followed by the retained entries in index order ``r..n-1``, each
    encoded exactly as in :func:`dump_secure_log` (``U(index) ||
    B(payload) || B(previous_hash) || B(entry_hash) || B(locator)``, with
    an empty locator marking a plain entry and a non-empty locator carrying
    the digest-width encrypted-locator HMAC). ``root`` / ``head`` are the
    Merkle root and chain head of the full size-``n`` snapshot, ``stage``
    the current key-evolution stage, ``K`` the current evolution key and
    ``x`` the verifier-exported flag, encoded as a u64 with value ``0`` or
    ``1``. ``U`` is an unsigned 8-byte big-endian integer and
    ``B(v) = U(len(v)) || v``.

    The call is read-only: it never mutates the log. A non-:class:`AuditLog`
    value or a non-``bytes`` key/nonce raises TypeError; a key that is not 32
    bytes, a nonce that is not 12 bytes, or an unpruned or keyless log
    raises ValueError. Nothing is changed on failure.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    _check_key(key)
    if nonce is None:
        nonce = os.urandom(_NONCE_BYTES)
    else:
        _check_nonce(nonce)
    # Eligibility: the format restores a pruned, keyed, forward-secure log
    # carrying the live evolution key, so it requires retain_from > 0 and a
    # construction-time key. Unlike dump_pruned_auth, an encrypt history —
    # including ciphertexts released by the prune — is exactly what the
    # complete nonce history and the retained locators preserve.
    if log._retain_from == 0:
        raise ValueError(
            "only a pruned log (retain_from > 0) can be dumped as a pruned hybrid log"
        )
    if log._key is None:
        raise ValueError(
            "only a log constructed with an authentication key can be dumped"
        )
    hash_name = log._hash_name
    digest_size = log._digest_size
    size = len(log)
    retain_from = log._retain_from
    root = log._fold_occupied(log._occupied_at(size))
    head = log._chain_head_at(size)
    parts = [
        _encode_blob(hash_name.encode("utf-8")),
        _encode_u64(size, "entries count"),
        _encode_u64(retain_from, "retain_from"),
        _encode_blob(log._checkpoint_head),
        _encode_u64(len(log._frontier), "frontier count"),
    ]
    for height in sorted(log._frontier):
        parts.append(_encode_u64(height, "frontier height"))
        parts.append(_encode_blob(log._frontier[height]))
    parts.append(_encode_u64(len(log._used_nonces), "nonce count"))
    for used_nonce in sorted(log._used_nonces):
        parts.append(_encode_blob(used_nonce))
    parts.append(_encode_u64(len(log._entries), "retained entries count"))
    for entry in log._entries:
        locator = log._encrypted_locators.get(entry.index, b"")
        if locator:
            if len(locator) != digest_size:
                raise ValueError(
                    f"encrypted locator must be {digest_size} bytes"
                )
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(entry.payload))
        parts.append(_encode_blob(entry.previous_hash))
        parts.append(_encode_blob(entry.entry_hash))
        parts.append(_encode_blob(locator))
    parts.append(_encode_blob(root))
    parts.append(_encode_blob(head))
    parts.append(_encode_u64(log._stage, "stage"))
    parts.append(_encode_blob(log._key))
    parts.append(_encode_u64(1 if log._verifier_exported else 0, "exported flag"))
    plaintext = b"".join(parts)
    aad = _PRUNED_HYBRID_MAGIC + bytes((_PRUNED_HYBRID_VERSION,)) + nonce
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return (
        _PRUNED_HYBRID_MAGIC
        + bytes((_PRUNED_HYBRID_VERSION,))
        + nonce
        + sealed
    )


def load_pruned_hybrid(data: Any, key: Any) -> AuditLog:
    """Restore an independent, mutable keyed :class:`AuditLog` from
    :func:`dump_pruned_hybrid`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError) and ``key`` must be 32 ``bytes``. The
    stream must start with ``D = b"auditchain/pruned-hybrid/v1\\0"``
    followed by the one-byte algorithm id ``0x01`` (AES-256-GCM), a 12-byte
    nonce ``N`` and the AESGCM output ``C`` (``ciphertext || 16-byte tag``);
    it is decrypted with the AEAD additional authenticated data
    ``D || 0x01 || N``. A wrong key or any authentication failure raises
    ValueError; GCM authentication always runs before the plaintext is
    parsed.

    The decrypted plaintext must parse, strictly in order and with no
    trailing bytes, as
    ``B(h) || U(n) || U(r) || B(checkpoint) || F || Q || E || B(root) ||
    B(head) || U(stage) || B(K) || U(x)``: ``r`` must satisfy
    ``0 < r <= n``, ``checkpoint`` must have the digest width, ``F`` must
    list one ``U(height) || B(digest)`` pair per set bit of ``r`` in
    strictly ascending order. ``Q`` must carry the complete lifetime nonce
    history: every blob is exactly 12 bytes, the nonces are distinct and in
    lexicographic order. ``E`` must carry exactly ``n - r`` records at
    indices ``r..n-1`` in order, each in the :func:`dump_secure_log` field
    order (``U, B, B, B, B``) whose trailing ``B(locator)`` is empty for a
    plain entry and the digest-width encrypted-locator HMAC for an encrypted
    one; every chain digest must have the width of the named hash algorithm,
    ``stage`` must be a u64, ``K`` (the current evolution key) must be
    non-empty — at stage 0 it is the construction key, which may have any
    non-zero length, and after any evolution it is one hash-digest wide —
    and ``x`` (the verifier-exported flag) must be ``0`` or ``1``. Under
    the named ``hash_name`` every :func:`entry_digest` and predecessor link
    is then recomputed starting from the checkpoint, and the resulting chain
    head and the Merkle root rebuilt from the frontier and the retained
    entries must match ``head`` / ``root``. Classification is driven by the
    locator, never the payload: a non-empty locator's payload must parse as
    an encrypted-entry envelope, whose 12-byte nonce is recovered, must not
    repeat among the retained ciphertexts and must be covered by the
    complete nonce history, which may additionally hold nonces of
    ciphertexts released by the prune. Only then is a fresh keyed
    :class:`AuditLog` built with ``retain_from == r``, the checkpoint and
    frontier installed, the complete nonce history restored and the
    retained payloads replayed through the normal append / encrypted-entry
    recovery path, with ``K`` as the current key, ``stage`` and the
    exported flag installed, so its length, retain point, head, Merkle
    roots and proofs, find index, encrypted locator index, nonce history
    and stage are exactly those of the dumped log and forward-secure
    evolution continues from the same point; the result is fully mutable
    and shares no state with the caller's buffers.

    A non-``bytes`` ``data`` or key raises TypeError; a key that is not 32
    bytes, a bad magic/algorithm id, truncation, trailing bytes, a bad
    UTF-8 or unknown hash name, an out-of-range retain point, wrong digest
    or locator widths, a frontier that is not exactly the set bits of ``r``,
    a wrong-width, duplicated or misordered history nonce, an entry count
    that disagrees with ``n - r``, an out-of-order index, an unparseable
    ciphertext envelope, a duplicate retained ciphertext nonce, a retained
    ciphertext nonce missing from the history, an out-of-range stage or
    flag, a wrong-width evolution key, an AEAD failure or a recomputed
    chain/root mismatch raises ValueError. The call never mutates its
    inputs; on failure nothing is returned and no partial log escapes.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    _check_key(key)
    if not data.startswith(_PRUNED_HYBRID_MAGIC):
        raise ValueError("not an auditchain pruned-hybrid encoding")
    offset = len(_PRUNED_HYBRID_MAGIC)
    if len(data) <= offset:
        raise ValueError("truncated encoding: missing algorithm byte")
    version = data[offset]
    offset += 1
    if version != _PRUNED_HYBRID_VERSION:
        raise ValueError(f"unsupported pruned-hybrid version {version}")
    nonce_end = offset + _NONCE_BYTES
    if len(data) < nonce_end + _GCM_TAG_BYTES:
        raise ValueError("truncated encoding: missing nonce or ciphertext")
    frame_nonce = data[offset:nonce_end]
    sealed = data[nonce_end:]
    aad = _PRUNED_HYBRID_MAGIC + bytes((_PRUNED_HYBRID_VERSION,)) + frame_nonce
    try:
        plaintext = AESGCM(key).decrypt(frame_nonce, sealed, aad)
    except InvalidTag as error:
        raise ValueError(
            "pruned-hybrid authentication failed: wrong key or corrupted export"
        ) from error

    cursor = 0

    def read_u64(name: str) -> int:
        nonlocal cursor
        end = cursor + _U64_BYTES
        if end > len(plaintext):
            raise ValueError(f"truncated plaintext: expected 8 bytes for {name}")
        value = int.from_bytes(plaintext[cursor:end], "big")
        cursor = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal cursor
        length = read_u64(f"{name} length")
        end = cursor + length
        if end > len(plaintext):
            raise ValueError(f"truncated plaintext: {name} is {length} bytes")
        blob = plaintext[cursor:end]
        cursor = end
        return blob

    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    digest_size = _digest_size(hash_name)
    size = read_u64("entries count")
    retain_from = read_u64("retain_from")
    checkpoint = read_blob("checkpoint")
    if not 0 < retain_from <= size:
        raise ValueError(
            "retain_from must satisfy 0 < retain_from <= entries count"
        )
    if len(checkpoint) != digest_size:
        raise ValueError(f"checkpoint must be {digest_size} bytes")
    frontier_count = read_u64("frontier count")
    frontier: dict[int, bytes] = {}
    previous_height = -1
    for _ in range(frontier_count):
        height = read_u64("frontier height")
        digest = read_blob("frontier digest")
        if height <= previous_height:
            raise ValueError("frontier heights must be in strictly ascending order")
        if len(digest) != digest_size:
            raise ValueError(f"frontier digest must be {digest_size} bytes")
        frontier[height] = digest
        previous_height = height
    expected_heights = [
        height for height in range(64) if (retain_from >> height) & 1
    ]
    if sorted(frontier) != expected_heights:
        raise ValueError(
            "frontier heights must be exactly the set bits of retain_from"
        )
    # Complete lifetime nonce history: one B(nonce) length-prefixed blob per
    # nonce, each carrying exactly 12 bytes, in strictly ascending
    # lexicographic order, which also rules out duplicates.
    nonce_count = read_u64("nonce count")
    nonce_history: list[bytes] = []
    previous_nonce: bytes | None = None
    for _ in range(nonce_count):
        used_nonce = read_blob("nonce")
        if len(used_nonce) != _NONCE_BYTES:
            raise ValueError(f"nonce must be {_NONCE_BYTES} bytes")
        if previous_nonce is not None and used_nonce <= previous_nonce:
            raise ValueError(
                "nonces must be distinct and in lexicographic order"
            )
        nonce_history.append(used_nonce)
        previous_nonce = used_nonce
    nonce_history_set = set(nonce_history)
    count = read_u64("retained entries count")
    if count != size - retain_from:
        raise ValueError(
            "retained entries count must equal entries count minus retain_from"
        )
    raw_entries: list[tuple[int, bytes, bytes, bytes, bytes]] = []
    for _ in range(count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        locator = read_blob("entry.locator")
        raw_entries.append((index, payload, previous_hash, entry_hash, locator))
    root = read_blob("root")
    head = read_blob("head")
    stage = read_u64("stage")
    evolution_key = read_blob("evolution key")
    exported = read_u64("exported flag")
    if cursor != len(plaintext):
        raise ValueError("trailing bytes in the pruned-hybrid plaintext")
    if len(root) != digest_size:
        raise ValueError(f"root must be {digest_size} bytes")
    if len(head) != digest_size:
        raise ValueError(f"head must be {digest_size} bytes")
    if not evolution_key:
        raise ValueError("evolution key must be non-empty")
    if stage > 0 and len(evolution_key) != digest_size:
        raise ValueError(
            f"evolution key must be {digest_size} bytes after the first evolution"
        )
    if exported not in (0, 1):
        raise ValueError("exported flag must be 0 or 1")

    # Re-derive the retained chain from the checkpoint under the named hash
    # algorithm, and simultaneously replay the payloads into a fresh keyed
    # log with the checkpoint, frontier and retain point installed, so every
    # auxiliary structure (find index, encrypted locator index, nonce
    # history, frontier) is rebuilt exactly as the normal append / encrypt
    # paths build it. The complete nonce history is seeded before the replay
    # (covering nonces of ciphertexts released by the prune); the evolution
    # key, stage and verifier-exported flag are only installed after the
    # replay succeeds, so a failure leaves no partially restored log behind.
    log = AuditLog(key=evolution_key, hash_name=hash_name)
    log._retain_from = retain_from
    log._checkpoint_head = checkpoint
    log._frontier = dict(frontier)
    log._head = checkpoint
    log._used_nonces = set(nonce_history_set)
    previous = checkpoint
    seen_nonces: set[bytes] = set()
    for position, (index, payload, recorded_previous, recorded_hash, locator) in enumerate(
        raw_entries
    ):
        expected_index = retain_from + position
        if index != expected_index:
            raise ValueError("entries must occupy indices r..n-1 in order")
        if len(recorded_previous) != digest_size:
            raise ValueError(
                f"entry.previous_hash must be {digest_size} bytes"
            )
        if len(recorded_hash) != digest_size:
            raise ValueError(f"entry.entry_hash must be {digest_size} bytes")
        if recorded_previous != previous:
            raise ValueError(f"entry chain is broken at index {expected_index}")
        recomputed = entry_digest(
            expected_index,
            previous,
            payload,
            hash_name=hash_name,
        )
        if not hmac.compare_digest(recomputed, recorded_hash):
            raise ValueError(f"entry digest mismatch at index {expected_index}")
        # Classification is driven by the locator, never by the payload; the
        # recovered envelope nonce must be covered by the complete lifetime
        # history and unique among the retained ciphertexts.
        if locator:
            if len(locator) != digest_size:
                raise ValueError(
                    f"encrypted locator must be {digest_size} bytes"
                )
            _algorithm, entry_nonce, _sealed = _parse_envelope(payload)
            if len(entry_nonce) != _NONCE_BYTES:
                raise ValueError(
                    f"encrypted nonce must be {_NONCE_BYTES} bytes"
                )
            if entry_nonce not in nonce_history_set:
                raise ValueError(
                    "retained ciphertext nonce is missing from the nonce history"
                )
            if entry_nonce in seen_nonces:
                raise ValueError(
                    "duplicate encrypted nonce among retained entries"
                )
            seen_nonces.add(entry_nonce)
            # Replay the same commit encrypt() performs, seeding the
            # encrypted locator index without any encryption key.
            entry = Entry(
                index=expected_index,
                payload=payload,
                previous_hash=previous,
                entry_hash=recomputed,
            )
            log._entries.append(entry)
            log._index.setdefault(
                _locator_digest(payload, hash_name), []
            ).append(expected_index)
            log._encrypted_index.setdefault(locator, []).append(expected_index)
            log._encrypted_locators[expected_index] = locator
            log._used_nonces.add(entry_nonce)
            log._head = recomputed
        else:
            # Ordinary entry: replay through the normal append path so the
            # find index and every other structure match a live append.
            replayed = log.append(payload)
            if (
                replayed.index != index
                or replayed.previous_hash != recorded_previous
                or not hmac.compare_digest(replayed.entry_hash, recorded_hash)
            ):
                raise ValueError(
                    f"entry chain is inconsistent at index {expected_index}"
                )
        previous = recomputed
    if not hmac.compare_digest(previous, head):
        raise ValueError("recomputed chain head does not match the exported head")
    if not hmac.compare_digest(log.merkle_root(), root):
        raise ValueError("recomputed Merkle root does not match the exported root")
    log._stage = stage
    log._verifier_exported = bool(exported)
    return log
