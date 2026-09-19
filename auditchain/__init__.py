"""auditchain - an append-only hash-chained audit log.

Public API: Entry / AuditLog / entry_digest / verify_inclusion /
verify_consistency.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Iterator, Sequence

__all__ = [
    "AuditLog",
    "Entry",
    "GENESIS_HASH",
    "entry_digest",
    "verify_consistency",
    "verify_inclusion",
]

GENESIS_HASH = bytes(32)
_DOMAIN = b"auditchain/entry/v1"
_INDEX_BYTES = 8

_LEAF_DOMAIN = b"auditchain/merkle-leaf/v1"
_NODE_DOMAIN = b"auditchain/merkle-node/v1"
_EMPTY_DOMAIN = b"auditchain/merkle-empty/v1"


def _as_bytes(payload: Any) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, bytearray):
        return bytes(payload)
    if isinstance(payload, str):
        return payload.encode("utf-8")
    raise TypeError("payload must be bytes, bytearray or str")


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


def _hash_parts(hash_name: str, *parts: bytes) -> bytes:
    digest = hashlib.new(hash_name)
    for part in parts:
        digest.update(part)
    return digest.digest()


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


def _split(n: int) -> int:
    """Largest power of two strictly below ``n`` (requires n > 1)."""
    return 1 << ((n - 1).bit_length() - 1)


def _subproof(leaves: list[bytes], m: int, hash_name: str, complete: bool) -> list[bytes]:
    """RFC 6962 §2.1.2 SUBPROOF(m, leaves, complete) in node order."""
    n = len(leaves)
    if m == n:
        return [] if complete else [_root_of(leaves, hash_name)]
    k = _split(n)
    if m <= k:
        return _subproof(leaves[:k], m, hash_name, complete) + [_root_of(leaves[k:], hash_name)]
    return _subproof(leaves[k:], m - k, hash_name, False) + [_root_of(leaves[:k], hash_name)]


@dataclass(frozen=True)
class Entry:
    """One immutable log record."""

    index: int
    payload: bytes
    previous_hash: bytes
    entry_hash: bytes


class AuditLog:
    """Append-only hash chain held in memory."""

    def __init__(self, *, hash_name: str = "sha256") -> None:
        try:
            hashlib.new(hash_name)
        except ValueError as error:
            raise ValueError(f"unknown hash algorithm: {hash_name}") from error
        self._hash_name = hash_name
        self._entries: list[Entry] = []

    @property
    def hash_name(self) -> str:
        return self._hash_name

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[Entry]:
        return iter(self._entries)

    @property
    def head(self) -> bytes:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def append(self, payload: Any) -> Entry:
        material = _as_bytes(payload)
        previous = self.head
        index = len(self._entries)
        entry = Entry(
            index=index,
            payload=material,
            previous_hash=previous,
            entry_hash=entry_digest(index, previous, material, hash_name=self._hash_name),
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> list[Entry]:
        return list(self._entries)

    def entry(self, index: int) -> Entry:
        if not isinstance(index, int):
            raise TypeError("index must be an integer")
        if not 0 <= index < len(self._entries):
            raise IndexError(f"no entry at index {index}")
        return self._entries[index]

    def verify_entry(self, index: int) -> bool:
        """Check that one entry links correctly to its predecessor."""
        entry = self.entry(index)
        previous = GENESIS_HASH if index == 0 else self._entries[index - 1].entry_hash
        if entry.previous_hash != previous:
            return False
        return entry.entry_hash == entry_digest(
            entry.index, entry.previous_hash, entry.payload, hash_name=self._hash_name
        )

    def verify(self) -> bool:
        """Walk the whole chain from the genesis digest."""
        for index in range(len(self._entries)):
            entry = self._entries[index]
            if entry.index != index:
                return False
            if not self.verify_entry(index):
                return False
        return True

    def _resolve_size(self, size: int | None) -> int:
        if size is None:
            return len(self._entries)
        if not isinstance(size, int):
            raise TypeError("size must be an integer")
        if not 0 <= size <= len(self._entries):
            raise ValueError(f"size must be within 0..{len(self._entries)}")
        return size

    def merkle_root(self, size: int | None = None) -> bytes:
        """Root of the Merkle tree over the first ``size`` entries.

        Defaults to the whole log. Appending later entries never changes
        the root of an earlier prefix.
        """
        size = self._resolve_size(size)
        leaves = [_leaf_hash(entry.entry_hash, self._hash_name) for entry in self._entries[:size]]
        return _root_of(leaves, self._hash_name)

    def inclusion_proof(self, index: int, size: int | None = None) -> tuple[bytes, ...]:
        """Sibling digests from leaf to root for ``index`` within the first ``size`` entries."""
        size = self._resolve_size(size)
        if not isinstance(index, int):
            raise TypeError("index must be an integer")
        if not 0 <= index < size:
            raise ValueError(f"index must satisfy 0 <= index < {size}")
        level = [_leaf_hash(entry.entry_hash, self._hash_name) for entry in self._entries[:size]]
        proof: list[bytes] = []
        position = index
        while len(level) > 1:
            sibling = position ^ 1
            if sibling < len(level):
                proof.append(level[sibling])
            level = _next_level(level, self._hash_name)
            position //= 2
        return tuple(proof)

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> tuple[bytes, ...]:
        """Proof that the first ``old_size`` entries are a prefix of the first ``new_size``.

        Defaults ``new_size`` to the whole log. Nodes follow the RFC 6962
        §2.1.2 SUBPROOF ordering over the promotion-based tree; appending
        later entries never changes the proof for a given pair of sizes.
        """
        new_size = self._resolve_size(new_size)
        if not isinstance(old_size, int):
            raise TypeError("old_size must be an integer")
        if not 0 <= old_size <= new_size:
            raise ValueError(f"old_size must satisfy 0 <= old_size <= {new_size}")
        if old_size == 0 or old_size == new_size:
            return ()
        leaves = [_leaf_hash(entry.entry_hash, self._hash_name) for entry in self._entries[:new_size]]
        return tuple(_subproof(leaves, old_size, self._hash_name, True))


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


def _fold_subproof(
    m: int,
    n: int,
    known: bytes | None,
    nodes: list[bytes],
    pos: int,
    hash_name: str,
) -> tuple[bytes, bytes, int]:
    """Rebuild the old and new subtree roots from consistency proof nodes.

    Mirrors ``_subproof``, consuming nodes in SUBPROOF order from ``pos``.
    ``known`` is the already-known root of a complete subtree on the
    leftmost spine (the ``complete=True`` case of RFC 6962 §2.1.2, where
    the proof carries no node); it is None elsewhere. Returns
    ``(old_root, new_root, next_pos)``.
    """
    if m == n:
        if known is not None:
            return known, known, pos
        if pos >= len(nodes):
            raise ValueError("proof has too few nodes")
        return nodes[pos], nodes[pos], pos + 1
    k = _split(n)
    if m <= k:
        first, second, pos = _fold_subproof(m, k, known, nodes, pos, hash_name)
        if pos >= len(nodes):
            raise ValueError("proof has too few nodes")
        return first, _node_hash(second, nodes[pos], hash_name), pos + 1
    first, second, pos = _fold_subproof(m - k, n - k, None, nodes, pos, hash_name)
    if pos >= len(nodes):
        raise ValueError("proof has too few nodes")
    sibling = nodes[pos]
    return (
        _node_hash(sibling, first, hash_name),
        _node_hash(sibling, second, hash_name),
        pos + 1,
    )


def verify_consistency(
    old_size: int,
    old_root: bytes,
    new_size: int,
    new_root: bytes,
    proof: Sequence[bytes],
    *,
    hash_name: str = "sha256",
) -> bool:
    """Verify a Merkle consistency proof without holding the log.

    Confirms that the snapshot of ``old_size`` entries with ``old_root``
    is a prefix of the snapshot of ``new_size`` entries with ``new_root``,
    following the digests in ``proof``. Structurally valid inputs that do
    not match return False; malformed inputs raise TypeError or ValueError.
    """
    if not isinstance(hash_name, str):
        raise TypeError("hash_name must be a string")
    try:
        digest_size = hashlib.new(hash_name).digest_size
    except ValueError as error:
        raise ValueError(f"unknown hash algorithm: {hash_name}") from error

    if not isinstance(old_size, int):
        raise TypeError("old_size must be an integer")
    if not isinstance(new_size, int):
        raise TypeError("new_size must be an integer")
    if old_size < 0 or new_size < 0:
        raise ValueError("sizes must be non-negative")
    if old_size > new_size:
        raise ValueError("old_size must not exceed new_size")

    old_root = _check_digest(old_root, "old_root", digest_size)
    new_root = _check_digest(new_root, "new_root", digest_size)

    if not isinstance(proof, (tuple, list)):
        raise TypeError("proof must be a tuple or list of digests")
    nodes = [_check_digest(node, "proof element", digest_size) for node in proof]

    if old_size == new_size:
        if nodes:
            raise ValueError("proof must be empty when sizes are equal")
        return hmac.compare_digest(old_root, new_root)
    if old_size == 0:
        if nodes:
            raise ValueError("proof must be empty when old_size is 0")
        return hmac.compare_digest(old_root, _hash_parts(hash_name, _EMPTY_DOMAIN))

    first, second, consumed = _fold_subproof(old_size, new_size, old_root, nodes, 0, hash_name)
    if consumed != len(nodes):
        raise ValueError("proof has too many nodes")
    return hmac.compare_digest(first, old_root) and hmac.compare_digest(second, new_root)
