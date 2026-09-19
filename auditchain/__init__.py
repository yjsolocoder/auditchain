"""auditchain - an append-only hash-chained audit log.

Public API: Entry / PruneReceipt / AuditLog / entry_digest / verify_inclusion /
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
    "PruneReceipt",
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
    """Immutable receipt sealing a pruned prefix of a log.

    ``size`` is the number of entries the receipt covers, ``merkle_root`` the
    root of that prefix's Merkle tree and ``chain_hash`` the entry hash of its
    last record (``GENESIS_HASH`` for an empty prefix).
    """

    hash_name: str
    size: int
    merkle_root: bytes
    chain_hash: bytes

    def matches(self, entry: Entry) -> bool:
        """Check that ``entry`` is the first record retained after this prefix.

        The first retained record must sit at index ``size`` and link back to
        ``chain_hash`` as its predecessor.
        """
        if not isinstance(entry, Entry):
            raise TypeError("entry must be an Entry")
        return entry.index == self.size and entry.previous_hash == self.chain_hash


def _check_bytes(value: Any, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    return bytes(value)


class AuditLog:
    """Append-only hash chain held in memory.

    Entries before the retention point may be pruned with :meth:`prune` after
    sealing them with :meth:`seal`; indices stay absolute and the chain keeps
    appending and verifying as if nothing had been dropped.
    """

    def __init__(self, *, hash_name: str = "sha256") -> None:
        try:
            hashlib.new(hash_name)
        except ValueError as error:
            raise ValueError(f"unknown hash algorithm: {hash_name}") from error
        self._hash_name = hash_name
        self._entries: list[Entry] = []
        # Number of pruned entries; indices stay absolute, so entry i lives at
        # position i - _offset in _entries.
        self._offset = 0
        # Chain hash at the retention point (GENESIS_HASH when nothing pruned).
        self._base_hash = GENESIS_HASH
        # Frontier of the pruned prefix: the binary decomposition of [0, _offset)
        # into (start, height, root) subtrees, heights strictly decreasing.
        self._frontier: list[tuple[int, int, bytes]] = []

    @property
    def hash_name(self) -> str:
        return self._hash_name

    def __len__(self) -> int:
        return self._offset + len(self._entries)

    def __iter__(self) -> Iterator[Entry]:
        return iter(self._entries)

    @property
    def head(self) -> bytes:
        return self._entries[-1].entry_hash if self._entries else self._base_hash

    def append(self, payload: Any) -> Entry:
        material = _as_bytes(payload)
        previous = self.head
        index = len(self)
        entry = Entry(
            index=index,
            payload=material,
            previous_hash=previous,
            entry_hash=entry_digest(index, previous, material, hash_name=self._hash_name),
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> list[Entry]:
        """The retained segment; pruned entries are no longer listed."""
        return list(self._entries)

    def entry(self, index: int) -> Entry:
        if not isinstance(index, int):
            raise TypeError("index must be an integer")
        if not self._offset <= index < len(self):
            raise IndexError(f"no entry at index {index}")
        return self._entries[index - self._offset]

    def verify_entry(self, index: int) -> bool:
        """Check that one entry links correctly to its predecessor."""
        entry = self.entry(index)
        if index == 0:
            previous = GENESIS_HASH
        elif index == self._offset:
            previous = self._base_hash
        else:
            previous = self._entries[index - self._offset - 1].entry_hash
        if entry.previous_hash != previous:
            return False
        return entry.entry_hash == entry_digest(
            entry.index, entry.previous_hash, entry.payload, hash_name=self._hash_name
        )

    def verify(self) -> bool:
        """Walk the chain from the checkpoint at the retention point."""
        for position, entry in enumerate(self._entries):
            index = self._offset + position
            if entry.index != index:
                return False
            if not self.verify_entry(index):
                return False
        return True

    def _resolve_size(self, size: int | None) -> int:
        if size is None:
            return len(self)
        if not isinstance(size, int):
            raise TypeError("size must be an integer")
        if not 0 <= size <= len(self):
            raise ValueError(f"size must be within 0..{len(self)}")
        return size

    def _frontier_map(self) -> dict[tuple[int, int], bytes]:
        return {(start, height): root for start, height, root in self._frontier}

    def _frontier_push(self, index: int, leaf: bytes) -> None:
        """Fold one more leaf into the pruned-prefix frontier."""
        start, height, root = index, 0, leaf
        while self._frontier and self._frontier[-1][1] == height:
            start, _, left = self._frontier.pop()
            root = _node_hash(left, root, self._hash_name)
            height += 1
        self._frontier.append((start, height, root))

    def _subtree_root(self, start: int, length: int, memo: dict[tuple[int, int], bytes]) -> bytes:
        """Root of the Merkle tree over leaves ``[start, start + length)``.

        Leaves below the retention point are recovered from the frontier; a
        range that can no longer be rebuilt raises ValueError.
        """
        if length == 0:
            return _hash_parts(self._hash_name, _EMPTY_DOMAIN)
        if length & (length - 1) == 0:
            cached = memo.get((start, length.bit_length() - 1))
            if cached is not None:
                return cached
        if start >= self._offset:
            stop = start - self._offset + length
            leaves = [
                _leaf_hash(entry.entry_hash, self._hash_name)
                for entry in self._entries[start - self._offset : stop]
            ]
            return _root_of(leaves, self._hash_name)
        if length == 1:
            raise ValueError(f"snapshot of the first {start + 1} entries has been pruned")
        k = _split_point(length)
        return _node_hash(
            self._subtree_root(start, k, memo),
            self._subtree_root(start + k, length - k, memo),
            self._hash_name,
        )

    def _chain_hash_at(self, size: int) -> bytes:
        """Entry hash of the last record within the first ``size`` entries."""
        if size == 0:
            return GENESIS_HASH
        if size < self._offset:
            raise ValueError(f"snapshot of the first {size} entries has been pruned")
        if size == self._offset:
            return self._base_hash
        return self._entries[size - self._offset - 1].entry_hash

    def merkle_root(self, size: int | None = None) -> bytes:
        """Root of the Merkle tree over the first ``size`` entries.

        Defaults to the whole log. Appending later entries never changes
        the root of an earlier prefix. Prefixes at or beyond the retention
        point rebuild to the same root as an unpruned log; snapshots that
        have been pruned raise ValueError.
        """
        size = self._resolve_size(size)
        if size < self._offset:
            raise ValueError(f"snapshot of the first {size} entries has been pruned")
        return self._subtree_root(0, size, self._frontier_map())

    def inclusion_proof(self, index: int, size: int | None = None) -> tuple[bytes, ...]:
        """Sibling digests from leaf to root for ``index`` within the first ``size`` entries."""
        size = self._resolve_size(size)
        if not isinstance(index, int):
            raise TypeError("index must be an integer")
        if size < self._offset:
            raise ValueError(f"snapshot of the first {size} entries has been pruned")
        if index < self._offset:
            raise ValueError(f"entry at index {index} has been pruned")
        if not 0 <= index < size:
            raise ValueError(f"index must satisfy 0 <= index < {size}")
        memo = self._frontier_map()
        proof: list[bytes] = []
        position = index
        height = 0
        width = size
        while width > 1:
            sibling = position ^ 1
            if sibling < width:
                start = sibling << height
                proof.append(self._subtree_root(start, min(1 << height, size - start), memo))
            position //= 2
            width = (width + 1) // 2
            height += 1
        return tuple(proof)

    def _subproof(
        self, m: int, start: int, n: int, complete: bool, memo: dict[tuple[int, int], bytes]
    ) -> list[bytes]:
        """RFC 6962 section 2.1.2 SUBPROOF over leaves ``[start, start + n)``."""
        if m == n:
            return [] if complete else [self._subtree_root(start, n, memo)]
        k = _split_point(n)
        if m <= k:
            return self._subproof(m, start, k, complete, memo) + [
                self._subtree_root(start + k, n - k, memo)
            ]
        return self._subproof(m - k, start + k, n - k, False, memo) + [
            self._subtree_root(start, k, memo)
        ]

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> tuple[bytes, ...]:
        """Proof that the first ``old_size`` entries are a prefix of the first ``new_size``.

        ``new_size`` defaults to the current log length. The digests follow the
        RFC 6962 section 2.1.2 SUBPROOF order; appending later entries never
        changes the proof for an existing pair of prefix sizes. Pairs at or
        beyond the retention point rebuild to the same proof as an unpruned
        log; snapshots that have been pruned raise ValueError.
        """
        new_size = self._resolve_size(new_size)
        if not isinstance(old_size, int):
            raise TypeError("old_size must be an integer")
        if not 0 <= old_size <= new_size:
            raise ValueError(f"old_size must satisfy 0 <= old_size <= {new_size}")
        if old_size < self._offset:
            raise ValueError(f"snapshot of the first {old_size} entries has been pruned")
        if old_size == 0 or old_size == new_size:
            return ()
        return tuple(self._subproof(old_size, 0, new_size, True, self._frontier_map()))

    def seal(self, size: int | None = None) -> PruneReceipt:
        """Seal the first ``size`` entries (default: the whole log) into a receipt.

        The receipt records the prefix's Merkle root and the chain hash of its
        last record (``GENESIS_HASH`` for an empty prefix), and is required to
        later :meth:`prune` that prefix.
        """
        size = self._resolve_size(size)
        return PruneReceipt(
            hash_name=self._hash_name,
            size=size,
            merkle_root=self.merkle_root(size),
            chain_hash=self._chain_hash_at(size),
        )

    def prune(self, retain_from: int, receipt: PruneReceipt) -> None:
        """Drop the payloads of the entries before ``retain_from``.

        ``retain_from`` must equal ``receipt.size`` and the receipt's hash
        algorithm, Merkle root and chain hash must match this log. The
        retention point only moves forward and never beyond the current
        length. After pruning, indices stay absolute: ``len`` keeps counting
        from genesis, ``head``/``append``/``verify`` behave as on an unpruned
        log, and Merkle snapshots at or beyond the retention point remain
        rebuildable.
        """
        if not isinstance(retain_from, int):
            raise TypeError("retain_from must be an integer")
        if not isinstance(receipt, PruneReceipt):
            raise TypeError("receipt must be a PruneReceipt")
        if not isinstance(receipt.hash_name, str):
            raise TypeError("receipt hash_name must be a string")
        if not isinstance(receipt.size, int):
            raise TypeError("receipt size must be an integer")
        merkle_root = _check_bytes(receipt.merkle_root, "receipt merkle_root")
        chain_hash = _check_bytes(receipt.chain_hash, "receipt chain_hash")
        if retain_from != receipt.size:
            raise ValueError("retain_from must equal the receipt size")
        if receipt.hash_name != self._hash_name:
            raise ValueError("receipt hash algorithm does not match the log")
        if not 0 <= retain_from <= len(self):
            raise ValueError(f"retain_from must be within 0..{len(self)}")
        if retain_from < self._offset:
            raise ValueError("retention point cannot move backwards")
        if not hmac.compare_digest(merkle_root, self.merkle_root(retain_from)):
            raise ValueError("receipt merkle_root does not match the log")
        if not hmac.compare_digest(chain_hash, self._chain_hash_at(retain_from)):
            raise ValueError("receipt chain_hash does not match the log")
        count = retain_from - self._offset
        for entry in self._entries[:count]:
            self._frontier_push(entry.index, _leaf_hash(entry.entry_hash, self._hash_name))
        del self._entries[:count]
        self._offset = retain_from
        self._base_hash = chain_hash


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
