"""Prefix Merkle trees over the audit log.

Leaves are domain-separated hashes of entry hashes; interior nodes are
domain-separated hashes of their children. When a level has an odd number
of nodes the last one is promoted unchanged, so appending entries never
changes the root or the proofs of any shorter prefix.
"""

from __future__ import annotations

import hashlib
from typing import Sequence, Tuple

__all__ = ["verify_inclusion"]

_LEAF_DOMAIN = b"auditchain/merkle-leaf/v1"
_NODE_DOMAIN = b"auditchain/merkle-node/v1"
_EMPTY_DOMAIN = b"auditchain/merkle-empty/v1"


def _hash(hash_name: str, *parts: bytes) -> bytes:
    digest = hashlib.new(hash_name)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _digest_size(hash_name: str) -> int:
    if not isinstance(hash_name, str):
        raise TypeError("hash_name must be a string")
    try:
        return hashlib.new(hash_name).digest_size
    except ValueError as error:
        raise ValueError(f"unknown hash algorithm: {hash_name}") from error


def _leaf_hash(entry_hash: bytes, hash_name: str) -> bytes:
    return _hash(hash_name, _LEAF_DOMAIN, entry_hash)


def _empty_root(hash_name: str) -> bytes:
    return _hash(hash_name, _EMPTY_DOMAIN)


def _next_level(level: Sequence[bytes], hash_name: str) -> list[bytes]:
    parents = [
        _hash(hash_name, _NODE_DOMAIN, level[i], level[i + 1])
        for i in range(0, len(level) - 1, 2)
    ]
    if len(level) % 2:
        parents.append(level[-1])
    return parents


def _root_from_leaves(leaves: Sequence[bytes], hash_name: str) -> bytes:
    if not leaves:
        return _empty_root(hash_name)
    level = list(leaves)
    while len(level) > 1:
        level = _next_level(level, hash_name)
    return level[0]


def merkle_root(entry_hashes: Sequence[bytes], hash_name: str) -> bytes:
    """Root of the Merkle tree over a prefix of entry hashes."""
    return _root_from_leaves([_leaf_hash(h, hash_name) for h in entry_hashes], hash_name)


def inclusion_proof(entry_hashes: Sequence[bytes], index: int, hash_name: str) -> Tuple[bytes, ...]:
    """Sibling digests from the leaf at ``index`` up to the root."""
    level = [_leaf_hash(h, hash_name) for h in entry_hashes]
    proof: list[bytes] = []
    while len(level) > 1:
        width = len(level)
        if not (index == width - 1 and width % 2):
            proof.append(level[index + 1] if index % 2 == 0 else level[index - 1])
        level = _next_level(level, hash_name)
        index //= 2
    return tuple(proof)


def _expected_proof_length(index: int, size: int) -> int:
    length = 0
    width = size
    while width > 1:
        if not (index == width - 1 and width % 2):
            length += 1
        index //= 2
        width = (width + 1) // 2
    return length


def _check_digest(name: str, value: bytes, digest_size: int) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    if len(value) != digest_size:
        raise ValueError(f"{name} must be {digest_size} bytes for this hash algorithm")
    return bytes(value)


def _check_position(name: str, value: int) -> int:
    if not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def verify_inclusion(
    entry_hash: bytes,
    index: int,
    size: int,
    root: bytes,
    proof: Sequence[bytes],
    *,
    hash_name: str = "sha256",
) -> bool:
    """Rebuild the Merkle root from one entry hash and its proof.

    ``index`` and ``size`` locate the entry within the snapshot the root
    commits to; ``proof`` holds the sibling digests from leaf to root.
    """
    digest_size = _digest_size(hash_name)
    entry_hash = _check_digest("entry_hash", entry_hash, digest_size)
    root = _check_digest("root", root, digest_size)
    index = _check_position("index", index)
    size = _check_position("size", size)
    if size == 0:
        raise ValueError("size must be at least 1")
    if index >= size:
        raise ValueError("index must satisfy 0 <= index < size")
    if not isinstance(proof, (tuple, list)):
        raise TypeError("proof must be a tuple of sibling digests")
    siblings = [_check_digest("proof element", element, digest_size) for element in proof]
    if len(siblings) != _expected_proof_length(index, size):
        raise ValueError("proof has the wrong number of levels for index and size")

    node = _leaf_hash(entry_hash, hash_name)
    width = size
    position = index
    consumed = 0
    while width > 1:
        if not (position == width - 1 and width % 2):
            sibling = siblings[consumed]
            consumed += 1
            if position % 2 == 0:
                node = _hash(hash_name, _NODE_DOMAIN, node, sibling)
            else:
                node = _hash(hash_name, _NODE_DOMAIN, sibling, node)
        position //= 2
        width = (width + 1) // 2
    return node == root
