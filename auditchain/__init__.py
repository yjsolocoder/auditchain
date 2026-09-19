"""auditchain - an append-only hash-chained audit log.

Public API: Entry / AuditLog / entry_digest / verify_inclusion.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterator, Optional, Tuple

from . import merkle as _merkle
from .merkle import verify_inclusion

__all__ = ["AuditLog", "Entry", "GENESIS_HASH", "entry_digest", "verify_inclusion"]

GENESIS_HASH = bytes(32)
_DOMAIN = b"auditchain/entry/v1"
_INDEX_BYTES = 8


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

    def _resolve_size(self, size: Optional[int]) -> int:
        if size is None:
            return len(self._entries)
        if not isinstance(size, int):
            raise TypeError("size must be an integer")
        if not 0 <= size <= len(self._entries):
            raise ValueError("size must satisfy 0 <= size <= len(log)")
        return size

    def merkle_root(self, size: Optional[int] = None) -> bytes:
        """Root of the Merkle tree over the first ``size`` entries."""
        size = self._resolve_size(size)
        hashes = [entry.entry_hash for entry in self._entries[:size]]
        return _merkle.merkle_root(hashes, self._hash_name)

    def inclusion_proof(self, index: int, size: Optional[int] = None) -> Tuple[bytes, ...]:
        """Sibling digests proving entry ``index`` against merkle_root(size)."""
        size = self._resolve_size(size)
        if not isinstance(index, int):
            raise TypeError("index must be an integer")
        if not 0 <= index < size:
            raise ValueError("index must satisfy 0 <= index < size")
        hashes = [entry.entry_hash for entry in self._entries[:size]]
        return _merkle.inclusion_proof(hashes, index, self._hash_name)

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
