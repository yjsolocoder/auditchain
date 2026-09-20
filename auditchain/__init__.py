"""auditchain - an append-only hash-chained audit log.

Public API: Entry / AuditLog / PruneReceipt / AuditReceipt / AuthTag /
Verifier / SignedRoot / IntegrityIssue / IntegrityReport / entry_digest /
decrypt_entry / verify_inclusion / verify_batch_inclusion /
verify_consistency / verify_auth / verify_audit_receipt / verify_audit_batch /
verify_signed_root / encode_audit_receipt / decode_audit_receipt /
encode_audit_batch / decode_audit_batch /
encode_signed_root / decode_signed_root.
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
    "SignedRoot",
    "Verifier",
    "GENESIS_HASH",
    "decode_audit_batch",
    "decode_audit_receipt",
    "decode_signed_root",
    "decrypt_entry",
    "encode_audit_batch",
    "encode_audit_receipt",
    "encode_signed_root",
    "entry_digest",
    "verify_audit_receipt",
    "verify_audit_batch",
    "verify_auth",
    "verify_batch_inclusion",
    "verify_consistency",
    "verify_inclusion",
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
# Binary framing of encode_audit_batch / decode_audit_batch: same u64/blob
# rules, one shared proof at the end instead of one proof per item.
_BATCH_MAGIC = b"auditchain/batch/v1\0"
_BATCH_VERSION = 1
_U64_BYTES = 8
_U64_LIMIT = 1 << 64

# Signed snapshot-root checkpoint of AuditLog.sign_root / verify_signed_root.
# An Ed25519 signature over the hash algorithm, snapshot size, Merkle root and
# chain head; the signing seed is supplied per call and never stored.
_SIGNED_ROOT_DOMAIN = b"auditchain/signed-root/v1\0"
_SIGNED_ROOT_VERSION = 1
_ED25519_KEY_BYTES = 32
_ED25519_SIGNATURE_BYTES = 64

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
