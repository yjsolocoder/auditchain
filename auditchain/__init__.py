"""auditchain - an append-only hash-chained audit log.

Public API: Entry / AuditLog / PruneReceipt / AuditReceipt / AuthTag /
Verifier / entry_digest / decrypt_entry / verify_inclusion /
verify_consistency / verify_auth / verify_audit_receipt /
encode_audit_receipt / decode_audit_receipt.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "AuditLog",
    "AuditReceipt",
    "AuthTag",
    "Entry",
    "PruneReceipt",
    "Verifier",
    "GENESIS_HASH",
    "decode_audit_receipt",
    "decrypt_entry",
    "encode_audit_receipt",
    "entry_digest",
    "verify_audit_receipt",
    "verify_auth",
    "verify_consistency",
    "verify_inclusion",
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

# Binary framing of encode_audit_receipt / decode_audit_receipt: a fixed
# magic, then unsigned 8-byte big-endian integers and length-prefixed blobs.
_RECEIPT_MAGIC = b"auditchain/audit-receipt/v1\0"
_U64_BYTES = 8
_U64_LIMIT = 1 << 64

# Stages are encoded as 8-byte big-endian integers inside tags.
_MAX_STAGE = 1 << 64


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
    previous = bytes(previous_hash)
    if len(previous) != 32:
        raise ValueError("previous_hash must be 32 bytes")
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
    try:
        digest_size = hashlib.new(hash_name).digest_size
    except ValueError as error:
        raise ValueError(f"unknown hash algorithm: {hash_name}") from error
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
      digest the first retained entry must carry); ``GENESIS_HASH`` for an
      empty prefix.
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
        try:
            digest_size = hashlib.new(self.hash_name).digest_size
        except ValueError as error:
            raise ValueError(f"unknown hash algorithm: {self.hash_name}") from error
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
        genesis record: an entry at index 0 whose predecessor is
        ``GENESIS_HASH``.
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
      inclusion proof within the snapshot. A non-empty receipt always
      carries the last entry of the snapshot (index ``size - 1``); an empty
      snapshot carries ``items == ()``.
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
        try:
            digest_size = hashlib.new(self.hash_name).digest_size
        except ValueError as error:
            raise ValueError(f"unknown hash algorithm: {self.hash_name}") from error
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
        if self.items and self.items[-1][0].index != self.size - 1:
            raise ValueError(
                "a non-empty receipt must include the entry at index size - 1"
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
        try:
            hashlib.new(self.hash_name)
        except ValueError as error:
            raise ValueError(f"unknown hash algorithm: {self.hash_name}") from error


class AuditLog:
    """Append-only hash chain held in memory.

    A pruned log keeps only entries from ``retain_from`` onward. Absolute
    indices, the chain head and every rebuildable Merkle snapshot stay
    identical to an unpruned log holding the same records; snapshots wholly
    inside a pruned prefix can no longer be produced.
    """

    def __init__(self, *, key: bytes | None = None, hash_name: str = "sha256") -> None:
        try:
            hashlib.new(hash_name)
        except ValueError as error:
            raise ValueError(f"unknown hash algorithm: {hash_name}") from error
        if key is not None:
            if not isinstance(key, bytes):
                raise TypeError("key must be bytes")
            if len(key) == 0:
                raise ValueError("key must be non-empty")
        self._hash_name = hash_name
        self._entries: list[Entry] = []
        self._retain_from = 0
        self._head: bytes = GENESIS_HASH
        # Locator index for find(): payload digest -> ascending absolute
        # indices of the retained entries carrying that digest. Digests only
        # narrow the candidates; find() always re-compares the stored payload.
        self._index: dict[bytes, list[int]] = {}
        # Chain hash of the last pruned entry (GENESIS_HASH before any prune).
        self._checkpoint_head: bytes = GENESIS_HASH
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
        # Encryption succeeded; commit exactly as append() does.
        entry = Entry(
            index=index,
            payload=envelope,
            previous_hash=previous_hash,
            entry_hash=entry_digest(index, previous_hash, envelope, hash_name=self._hash_name),
        )
        self._entries.append(entry)
        self._index.setdefault(_locator_digest(envelope, self._hash_name), []).append(index)
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
        candidates = self._index.get(_locator_digest(material, self._hash_name), ())
        return tuple(
            index
            for index in candidates
            if start <= index < stop
            and self._entries[index - self._retain_from].payload == material
        )

    def verify_entry(self, index: int) -> bool:
        """Check that one retained entry links correctly to its predecessor."""
        entry = self.entry(index)
        if entry.index != index:
            return False
        if index == 0:
            previous = GENESIS_HASH
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
        """Walk the retained chain forward from the prune checkpoint."""
        previous = self._checkpoint_head
        for offset, entry in enumerate(self._entries):
            index = self._retain_from + offset
            if entry.index != index or entry.previous_hash != previous:
                return False
            if entry.entry_hash != entry_digest(
                index, previous, entry.payload, hash_name=self._hash_name
            ):
                return False
            previous = entry.entry_hash
        return True

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
        """Entry hash of the last entry of the prefix (GENESIS_HASH at 0)."""
        if size == 0:
            return GENESIS_HASH
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
        records ``GENESIS_HASH`` as its chain hash.
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

    def audit_receipt(self, indices: Iterable[int], size: int | None = None) -> AuditReceipt:
        """Issue an offline :class:`AuditReceipt` for entries of a snapshot.

        ``indices`` is an iterable of distinct non-bool absolute indices,
        each satisfying ``retain_from <= index < size``; ``size`` defaults to
        the current log length and the snapshot must still be rebuildable. A
        non-empty selection automatically also includes the last entry of the
        snapshot (index ``size - 1``); an empty selection — and always an
        empty snapshot — yields ``items == ()``. Items are stored in
        ascending absolute index order, each paired with its inclusion proof
        within the snapshot. The call is read-only: entries, head,
        authentication state, Merkle roots and proofs are left untouched.
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
        if selected:
            # A non-empty receipt always carries the last snapshot entry.
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
            hits = self._index[_locator_digest(entry.payload, self._hash_name)]
            del hits[0]
            if not hits:
                del self._index[_locator_digest(entry.payload, self._hash_name)]
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
    try:
        digest_size = hashlib.new(hash_name).digest_size
    except ValueError as error:
        raise ValueError(f"unknown hash algorithm: {hash_name}") from error

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
    try:
        digest_size = hashlib.new(hash_name).digest_size
    except ValueError as error:
        raise ValueError(f"unknown hash algorithm: {hash_name}") from error

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
    an empty snapshot only accepts the canonical empty-tree root. A
    structurally valid receipt whose entry content, proofs or root do not
    match returns False; malformed input raises TypeError or ValueError
    (see :class:`AuditReceipt` for the structural rules).
    """
    if not isinstance(receipt, AuditReceipt):
        raise TypeError("receipt must be an AuditReceipt")
    if receipt.size == 0:
        return hmac.compare_digest(
            receipt.root, _hash_parts(receipt.hash_name, _EMPTY_DOMAIN)
        )
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
    duplicate item indices, a missing last entry and structurally invalid
    proofs all raise ValueError. The decoded receipt's fields equal the
    originally encoded ones and satisfy :func:`verify_audit_receipt` whenever
    the original did.
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

    digest_size = hashlib.new(verifier.hash_name).digest_size
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
