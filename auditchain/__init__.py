"""auditchain - an append-only hash-chained audit log.

Public API: Entry / AuditLog / PruneReceipt / AuditReceipt / AuthTag /
BatchInclusionProof / InclusionProof / ConsistencyProof / MerkleFrontier /
Verifier / StageVerifier / SignedRoot / SignedStageVerifier / SignedVerifier /
SignedStageAuthBundle /
SignedStageAuthAuditBundle /
SignedAuditBatch /
SignedAuditReceipt /
EncryptedSearchReceipt /
FullSearchReceipt /
SignedSearchReceipt /
SignedFullSearchReceipt /
SignedAuthAuditBundle /
SignedConsistency / SignedPrune / IntegrityIssue / IntegrityReport /
ContinuationChainReport / AnchoredContinuationChain /
AnchorSet /
RotatedChain /
RotatedAnchorSet /
entry_digest / decrypt_entry / verify_inclusion / verify_batch_inclusion /
verify_consistency / verify_auth / verify_auth_batch / verify_auth_stage /
verify_audit_receipt /
verify_audit_batch / verify_full_search_receipt /
inspect_continuation_chain / inspect_anchors /
inspect_rotated_chain /
inspect_rotated_anchors /
inspect_anchored_continuations / inspect_anchor_set / merge_anchor_set /
inspect_rotated_anchor_set / merge_rotated_anchor_set /
verify_signed_verifier / verify_signed_root /
verify_signed_stage_verifier / verify_signed_stage_auth_bundle /
verify_signed_audit_batch / verify_signed_audit_receipt /
verify_signed_search_receipt /
verify_signed_full_search_receipt /
verify_signed_consistency / verify_signed_prune /
verify_rotation /
verify_rotation_chain /
encode_audit_receipt / decode_audit_receipt /
encode_full_search_receipt / decode_full_search_receipt /
encode_prune_receipt / decode_prune_receipt /
encode_audit_batch / decode_audit_batch /
encode_batch_inclusion_proof / decode_batch_inclusion_proof /
encode_inclusion_proof / decode_inclusion_proof /
encode_consistency_proof / decode_consistency_proof /
encode_merkle_frontier / decode_merkle_frontier /
rebuild_merkle_root /
encode_auth_batch / decode_auth_batch /
encode_signed_root / decode_signed_root /
encode_signed_verifier / decode_signed_verifier /
encode_signed_stage_auth_bundle / decode_signed_stage_auth_bundle /
encode_signed_stage_auth_audit_bundle /
decode_signed_stage_auth_audit_bundle /
encode_signed_audit_batch / decode_signed_audit_batch /
encode_signed_audit_receipt / decode_signed_audit_receipt /
encode_signed_search_receipt / decode_signed_search_receipt /
encode_signed_full_search_receipt / decode_signed_full_search_receipt /
encode_signed_auth_audit_continuation /
decode_signed_auth_audit_continuation /
encode_continuations / decode_continuations /
encode_continuation_chain_report / decode_continuation_chain_report /
encode_integrity_report / decode_integrity_report /
encode_rotation / decode_rotation /
encode_rotations / decode_rotations /
encode_anchored_continuations / decode_anchored_continuations /
encode_anchor_set / decode_anchor_set /
encode_rotated_anchor / decode_rotated_anchor /
encode_rotated_anchor_set / decode_rotated_anchor_set /
encode_signed_consistency / decode_signed_consistency /
encode_signed_prune / decode_signed_prune /
dump_log / load_log /
dump_secure_log / load_secure_log /
dump_pruned_log / load_pruned_log /
dump_secure_pruned / load_secure_pruned /
dump_auth / load_auth /
dump_pruned_auth / load_pruned_auth /
dump_signed_pruned_auth / load_signed_pruned_auth /
dump_signed_hybrid / load_signed_hybrid /
dump_signed_pruned_hybrid / load_signed_pruned_hybrid /
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
    "AnchoredContinuationChain",
    "AnchorSet",
    "AuditLog",
    "AuditReceipt",
    "AuthTag",
    "BatchInclusionProof",
    "ConsistencyProof",
    "ContinuationChainReport",
    "EncryptedSearchReceipt",
    "Entry",
    "FullSearchReceipt",
    "InclusionProof",
    "IntegrityIssue",
    "IntegrityReport",
    "MerkleFrontier",
    "PruneReceipt",
    "RotatedAnchorSet",
    "RotatedChain",
    "SearchReceipt",
    "SignedAuditBatch",
    "SignedAuditReceipt",
    "SignedAuthAuditBundle",
    "SignedAuthAuditContinuation",
    "SignedAuthBundle",
    "SignedConsistency",
    "SignedEncryptedSearchReceipt",
    "SignedFullSearchReceipt",
    "SignedPrune",
    "SignedRoot",
    "SignedSearchReceipt",
    "SignedStageAuthBundle",
    "SignedStageAuthAuditBundle",
    "SignedStageVerifier",
    "SignedVerifier",
    "StageVerifier",
    "Verifier",
    "GENESIS_HASH",
    "decode_anchored_continuations",
    "decode_anchor_set",
    "decode_audit_batch",
    "decode_audit_receipt",
    "decode_auth_batch",
    "decode_batch_inclusion_proof",
    "decode_consistency_proof",
    "decode_continuations",
    "decode_continuation_chain_report",
    "decode_encrypted_search_receipt",
    "decode_full_search_receipt",
    "decode_inclusion_proof",
    "decode_integrity_report",
    "decode_merkle_frontier",
    "decode_prune_receipt",
    "decode_rotation",
    "decode_rotated_anchor",
    "decode_rotated_anchor_set",
    "decode_rotations",
    "decode_search_receipt",
    "decode_signed_audit_batch",
    "decode_signed_audit_receipt",
    "decode_signed_auth_audit_bundle",
    "decode_signed_auth_audit_continuation",
    "decode_signed_auth_bundle",
    "decode_signed_consistency",
    "decode_signed_encrypted_search_receipt",
    "decode_signed_full_search_receipt",
    "decode_signed_prune",
    "decode_signed_root",
    "decode_signed_search_receipt",
    "decode_signed_stage_auth_audit_bundle",
    "decode_signed_stage_auth_bundle",
    "decode_signed_stage_verifier",
    "decode_signed_verifier",
    "decode_stage_verifier",
    "decode_verifier",
    "decrypt_entry",
    "dump_auth",
    "dump_hybrid",
    "dump_log",
    "dump_pruned_auth",
    "dump_pruned_hybrid",
    "dump_pruned_log",
    "dump_secure_log",
    "dump_secure_pruned",
    "dump_signed_auth",
    "dump_signed_hybrid",
    "dump_signed_pruned_auth",
    "dump_signed_pruned_hybrid",
    "encode_anchored_continuations",
    "encode_anchor_set",
    "encode_audit_batch",
    "encode_audit_receipt",
    "encode_auth_batch",
    "encode_batch_inclusion_proof",
    "encode_consistency_proof",
    "encode_continuations",
    "encode_continuation_chain_report",
    "encode_encrypted_search_receipt",
    "encode_full_search_receipt",
    "encode_inclusion_proof",
    "encode_integrity_report",
    "encode_merkle_frontier",
    "encode_prune_receipt",
    "encode_rotation",
    "encode_rotated_anchor",
    "encode_rotated_anchor_set",
    "encode_rotations",
    "encode_search_receipt",
    "encode_signed_audit_batch",
    "encode_signed_audit_receipt",
    "encode_signed_auth_audit_bundle",
    "encode_signed_auth_audit_continuation",
    "encode_signed_auth_bundle",
    "encode_signed_consistency",
    "encode_signed_encrypted_search_receipt",
    "encode_signed_full_search_receipt",
    "encode_signed_prune",
    "encode_signed_root",
    "encode_signed_search_receipt",
    "encode_signed_stage_auth_audit_bundle",
    "encode_signed_stage_auth_bundle",
    "encode_signed_stage_verifier",
    "encode_signed_verifier",
    "encode_stage_verifier",
    "encode_verifier",
    "entry_digest",
    "inspect_anchor_set",
    "inspect_anchored_continuations",
    "inspect_anchors",
    "inspect_continuation_chain",
    "inspect_rotated_anchors",
    "inspect_rotated_chain",
    "inspect_rotated_anchor_set",
    "load_auth",
    "load_hybrid",
    "load_log",
    "load_pruned_auth",
    "load_pruned_hybrid",
    "load_pruned_log",
    "load_secure_log",
    "load_secure_pruned",
    "load_signed_auth",
    "load_signed_hybrid",
    "load_signed_pruned_auth",
    "load_signed_pruned_hybrid",
    "merge_anchor_set",
    "merge_rotated_anchor_set",
    "rebuild_merkle_root",
    "verify_audit_receipt",
    "verify_audit_batch",
    "verify_auth",
    "verify_auth_batch",
    "verify_auth_stage",
    "verify_batch_inclusion",
    "verify_consistency",
    "verify_continuation_chain",
    "verify_encrypted_search_receipt",
    "verify_full_search_receipt",
    "verify_inclusion",
    "verify_rotated_chain",
    "verify_rotation",
    "verify_rotation_chain",
    "verify_search_receipt",
    "verify_signed_audit_batch",
    "verify_signed_audit_receipt",
    "verify_signed_auth_audit_bundle",
    "verify_signed_auth_audit_continuation",
    "verify_signed_auth_bundle",
    "verify_signed_consistency",
    "verify_signed_encrypted_search_receipt",
    "verify_signed_full_search_receipt",
    "verify_signed_prune",
    "verify_signed_root",
    "verify_signed_search_receipt",
    "verify_signed_stage_auth_bundle",
    "verify_signed_stage_auth_audit_bundle",
    "verify_signed_stage_verifier",
    "verify_signed_verifier",
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
# Binary framing of encode_search_receipt / decode_search_receipt: same
# u64/blob rules; a content-search receipt binding the normalized query, the
# searched half-open range and the snapshot context to one inclusion proof
# per hit.
_SEARCH_RECEIPT_MAGIC = b"auditchain/search-receipt/v1\0"
_SEARCH_RECEIPT_VERSION = 1
# Binary framing of encode_encrypted_search_receipt /
# decode_encrypted_search_receipt: same u64/blob rules as the plain search
# receipt, persisting the outcome of find_encrypted: each listed hit carries
# its still-sealed encrypted envelope and is checked offline by decrypting it
# with the caller-supplied key; no key or plaintext is recorded.
_ENCRYPTED_SEARCH_MAGIC = b"auditchain/encrypted-search/v1\0"
_ENCRYPTED_SEARCH_VERSION = 1
# Binary framing of encode_full_search_receipt / decode_full_search_receipt:
# same u64/blob rules; a completeness search receipt listing every entry of
# the searched half-open range, one per absolute index, with a single shared
# compact batch inclusion proof covering all of them at the end instead of
# one inclusion proof per listed hit.
_FULL_SEARCH_MAGIC = b"auditchain/full-search/v1\0"
_FULL_SEARCH_VERSION = 1
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
# Binary framing of encode_batch_inclusion_proof / decode_batch_inclusion_proof:
# same u64/blob rules, binding the verify_batch_inclusion context (algorithm,
# indices, entry digests, snapshot size and root) to the shared proof nodes.
_BATCH_INCLUSION_MAGIC = b"auditchain/batch-inclusion/v1\0"
_BATCH_INCLUSION_VERSION = 1
_INCLUSION_MAGIC = b"auditchain/inclusion/v1\0"
_INCLUSION_VERSION = 1
_CONSISTENCY_MAGIC = b"auditchain/consistency/v1\0"
_CONSISTENCY_VERSION = 1
# Binary framing of encode_merkle_frontier / decode_merkle_frontier: same
# u64/blob rules, binding the Merkle frontier of a covered prefix (algorithm,
# covered size and the perfect-subtree (height, digest) pairs, one per set bit
# of the size, in ascending height order) into a persistable credential.
_FRONTIER_MAGIC = b"auditchain/frontier/v1\0"
_FRONTIER_VERSION = 1
_U64_BYTES = 8
_U64_LIMIT = 1 << 64

# Signed snapshot-root checkpoint of AuditLog.sign_root / verify_signed_root.
# An Ed25519 signature over the hash algorithm, snapshot size, Merkle root and
# chain head; the signing seed is supplied per call and never stored.
_SIGNED_ROOT_DOMAIN = b"auditchain/signed-root/v1\0"
_SIGNED_ROOT_VERSION = 1
_ED25519_KEY_BYTES = 32
_ED25519_SIGNATURE_BYTES = 64

# Old-signer authorization of an Ed25519 signer rotation
# (AuditLog.rotate_signer / verify_rotation). The old seed signs a message
# binding its own snapshot signature, the new signer's 32-byte public key and
# the new seed's signature over the very same snapshot; no new snapshot
# signature domain is introduced.
_ROTATION_DOMAIN = b"auditchain/signer-rotation/v1\0"
_ROTATION_VERSION = 0x01

# Binary framing of encode_rotation / decode_rotation: a fixed magic, then
# the envelope version as a u64 and four u64-length-prefixed blobs holding,
# strictly in rotate_signer tuple order, the complete canonical
# encode_signed_root bytes of the old checkpoint, the new signer's 32-byte
# raw public key, the complete canonical encode_signed_root bytes of the new
# checkpoint and the 64-byte old-key authorization — with nothing else.
_ROTATION_RECORD_MAGIC = b"auditchain/signer-rotation-record/v1\0"
_ROTATION_RECORD_VERSION = 1

# Binary framing of encode_rotations / decode_rotations: a fixed magic, then
# the envelope version as a u64, the non-zero record count as a u64 and one
# u64-length-prefixed blob per rotate_signer four-tuple, each blob holding the
# complete canonical encode_rotation bytes — with nothing else.
_ROTATION_CHAIN_MAGIC = b"auditchain/rotation-chain/v1\0"
_ROTATION_CHAIN_VERSION = 1

# Signed stage-0 verifier of AuditLog.export_signed_verifier /
# verify_signed_verifier. An Ed25519 signature over the verifier's hash
# algorithm and stage-0 key; the signature authenticates the source only, it
# does not encrypt the key it carries.
_SIGNED_VERIFIER_DOMAIN = b"auditchain/signed-verifier/v1\0"
_SIGNED_VERIFIER_VERSION = 1

# Signed stage verifier of AuditLog.export_signed_stage_verifier /
# verify_signed_stage_verifier. An Ed25519 signature over the delivery stage,
# the hash algorithm and that stage's key; the signature authenticates the
# source only, it does not encrypt the key it carries. The domain is distinct
# from the stage-0 signed-verifier domain above.
_SIGNED_STAGE_DOMAIN = b"auditchain/signed-stage/v1\0"
_SIGNED_STAGE_VERSION = 1

# Binary framing of encode_verifier / decode_verifier: a fixed magic, then
# the format version as a u64 (always 1) and u64-length-prefixed blobs
# holding the hash_name UTF-8 bytes and the stage-0 key, strictly in
# Verifier field order — there is no stage field and nothing else.
_VERIFIER_MAGIC = b"auditchain/verifier/v1\0"
_VERIFIER_VERSION = 1

# Binary framing of encode_stage_verifier / decode_stage_verifier: a fixed
# magic, then the format version as a u64 (always 1), the delivery stage as a
# u64 and u64-length-prefixed blobs holding the hash_name UTF-8 bytes and the
# key, strictly in StageVerifier field order after stage — with nothing else.
_STAGE_VERIFIER_MAGIC = b"auditchain/stage-verifier/v1\0"
_STAGE_VERIFIER_VERSION = 1

# Binary framing of encode_signed_audit_batch / decode_signed_audit_batch:
# a fixed magic, then the envelope version as a u64 and two u64-length-prefixed
# blobs holding the complete canonical encode_audit_batch and
# encode_signed_root bytes, in that order and with nothing else.
_SIGNED_AUDIT_BATCH_MAGIC = b"auditchain/signed-audit-batch/v1\0"
_SIGNED_AUDIT_BATCH_VERSION = 1

# Binary framing of encode_signed_audit_receipt / decode_signed_audit_receipt:
# a fixed magic, then the envelope version as a u64 and two u64-length-prefixed
# blobs holding the complete canonical encode_audit_receipt and
# encode_signed_root bytes, in that order and with nothing else.
_SIGNED_AUDIT_RECEIPT_MAGIC = b"auditchain/signed-audit-receipt/v1\0"
_SIGNED_AUDIT_RECEIPT_VERSION = 1

# Binary framing of encode_signed_search_receipt /
# decode_signed_search_receipt: a fixed magic, then the envelope version as a
# u64 and two u64-length-prefixed blobs holding the complete canonical
# encode_search_receipt and encode_signed_root bytes, in that order and with
# nothing else.
_SIGNED_SEARCH_RECEIPT_MAGIC = b"auditchain/signed-search-receipt/v1\0"
_SIGNED_SEARCH_RECEIPT_VERSION = 1

# Binary framing of encode_signed_encrypted_search_receipt /
# decode_signed_encrypted_search_receipt: a fixed magic, then the envelope
# version as a u64 and two u64-length-prefixed blobs holding the complete
# canonical encode_encrypted_search_receipt and encode_signed_root bytes, in
# that order and with nothing else.
_SIGNED_ENCRYPTED_SEARCH_MAGIC = b"auditchain/signed-encrypted-search/v1\0"
_SIGNED_ENCRYPTED_SEARCH_VERSION = 1

# Binary framing of encode_signed_full_search_receipt /
# decode_signed_full_search_receipt: a fixed magic, then the envelope version
# as a u64 and two u64-length-prefixed blobs holding the complete canonical
# encode_full_search_receipt and encode_signed_root bytes, in that order and
# with nothing else.
_SIGNED_FULL_SEARCH_MAGIC = b"auditchain/signed-full-search/v1\0"
_SIGNED_FULL_SEARCH_VERSION = 1

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

# Binary framing of encode_signed_auth_bundle / decode_signed_auth_bundle:
# a fixed magic, then the envelope version as a u64 and two u64-length-prefixed
# blobs holding the complete canonical encode_signed_verifier and
# encode_auth_batch bytes, in that order and with nothing else.
_SIGNED_AUTH_BUNDLE_MAGIC = b"auditchain/signed-auth-bundle/v1\0"
_SIGNED_AUTH_BUNDLE_VERSION = 1

# Binary framing of encode_signed_stage_auth_bundle /
# decode_signed_stage_auth_bundle: a fixed magic, then the envelope version as
# a u64 and two u64-length-prefixed blobs holding the complete canonical
# encode_signed_stage_verifier and encode_auth_batch bytes, in that order and
# with nothing else. As in the signed-auth-bundle framing the decoder
# additionally requires the batch's hash algorithm to equal the signed stage
# verifier's algorithm.
_SIGNED_STAGE_AUTH_BUNDLE_MAGIC = (
    b"auditchain/signed-stage-auth-bundle/v1\0"
)
_SIGNED_STAGE_AUTH_BUNDLE_VERSION = 1

# Binary framing of encode_signed_auth_audit_bundle /
# decode_signed_auth_audit_bundle: a fixed magic, then the envelope version as
# a u64 and two u64-length-prefixed blobs holding the complete canonical
# encode_signed_auth_bundle and encode_signed_audit_batch bytes, in that order
# and with nothing else. Unlike the signed-auth-bundle framing the two nested
# packages do not name a common algorithm themselves: the audit side signs its
# own snapshot, so the decoder additionally requires the auth bundle's hash
# algorithm to equal the signed audit batch's algorithm.
_SIGNED_AUTH_AUDIT_MAGIC = b"auditchain/auth-audit/v1\0"
_SIGNED_AUTH_AUDIT_VERSION = 1

# Binary framing of encode_signed_stage_auth_audit_bundle /
# decode_signed_stage_auth_audit_bundle: a fixed magic, then the envelope
# version as a u64 and two u64-length-prefixed blobs holding the complete
# canonical encode_signed_stage_auth_bundle and
# encode_signed_audit_batch bytes, in that order and with nothing else. The
# signed-stage-auth-bundle decoder already pins its batch algorithm to the
# signed stage verifier's algorithm; this envelope additionally requires the
# signed audit batch's algorithm to equal that one algorithm.
_SIGNED_STAGE_AUTH_AUDIT_MAGIC = (
    b"auditchain/signed-stage-auth-audit/v1\0"
)
_SIGNED_STAGE_AUTH_AUDIT_VERSION = 1

# Binary framing of encode_signed_auth_audit_continuation /
# decode_signed_auth_audit_continuation: a fixed magic, then the envelope
# version as a u64 and two u64-length-prefixed blobs holding the complete
# canonical encode_signed_auth_audit_bundle and
# encode_signed_consistency bytes, in that order and with nothing else. The
# continuation introduces no framing of its own beyond that envelope.
_SIGNED_AUTH_AUDIT_CONTINUATION_MAGIC = (
    b"auditchain/auth-audit-continuation/v1\0"
)
_SIGNED_AUTH_AUDIT_CONTINUATION_VERSION = 1

# Binary framing of encode_continuations / decode_continuations: a fixed
# magic, then the envelope version as a u64, the receipt count as a u64 and
# one u64-length-prefixed blob per frozen SignedAuthAuditContinuation in
# tuple order, each blob the complete canonical
# encode_signed_auth_audit_continuation output, with nothing else.
_CONTINUATION_CHAIN_MAGIC = b"auditchain/cont-chain/v1\0"
_CONTINUATION_CHAIN_VERSION = 1

# Binary framing of encode_continuation_chain_report /
# decode_continuation_chain_report: a fixed magic, then the envelope version
# as a u64 (always 1), the verdict as a u64 (0 success, 1 failure), the
# absolute segment position as a u64 (0 for success) and the issue code as a
# u64-length-prefixed UTF-8 blob (empty for success), in that strict order and
# with nothing else. It carries no signatures or receipts, only the frozen
# diagnosis, and introduces no new signing message.
_CHAIN_REPORT_MAGIC = b"auditchain/chain-report/v1\0"
_CHAIN_REPORT_VERSION = 1

# Binary framing of encode_integrity_report / decode_integrity_report: a
# fixed magic, then the envelope version as a u64 (always 1), the verdict
# as a u64 (0 success, 1 failure), the issue count as a u64 and, per issue
# in report order, the issue code as a u64-length-prefixed UTF-8 blob and
# the absolute position as a u64 (0 for the index-less "head" issue), in
# that strict order and with nothing else. It carries no signatures, only
# the frozen chain-verification diagnosis, and introduces no new signing
# message.
_INTEGRITY_REPORT_MAGIC = b"auditchain/integrity-report/v1\0"
_INTEGRITY_REPORT_VERSION = 1

# Binary framing of encode_anchored_continuations /
# decode_anchored_continuations: a fixed magic, then the envelope version as
# a u64 and three u64-length-prefixed blobs holding the complete canonical
# encode_continuations chain bytes and the encode_signed_root bytes of the
# start and end anchors, in that order and with nothing else.
_ANCHORED_CONTINUATION_MAGIC = b"auditchain/anchor/v1\0"
_ANCHORED_CONTINUATION_VERSION = 1

# Binary framing of encode_anchor_set / decode_anchor_set: a fixed magic,
# then the envelope version as a u64 (always 1), the package count as a u64
# and one u64-length-prefixed blob per AnchoredContinuationChain package in
# tuple order (each the complete canonical encode_anchored_continuations
# output), in that order and with nothing else.
_ANCHOR_SET_MAGIC = b"auditchain/anchor-set/v1\0"
_ANCHOR_SET_VERSION = 1

# Binary framing of encode_rotated_anchor / decode_rotated_anchor: a fixed
# magic, then the envelope version as a u64 and four u64-length-prefixed
# blobs holding the complete canonical encode_continuations chain bytes, the
# encode_rotations rotation bytes and the encode_signed_root bytes of the
# start and end anchors, in that order and with nothing else.
_ROTATED_ANCHOR_MAGIC = b"auditchain/ra/v1\0"
_ROTATED_ANCHOR_VERSION = 1

# Binary framing of encode_rotated_anchor_set /
# decode_rotated_anchor_set: a fixed magic, then the envelope version as a
# u64, the package count as a u64 and one u64-length-prefixed blob per
# RotatedChain package in tuple order (each the complete canonical
# encode_rotated_anchor output), then the bridge count as a u64 and one blob
# per cross-package rotation bridge in tuple order (each the complete
# canonical encode_rotation output), with nothing else.
_ROTATED_ANCHOR_SET_MAGIC = b"auditchain/rotated-anchor-set/v1\0"
_ROTATED_ANCHOR_SET_VERSION = 1

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

# Binary framing of dump_signed_auth / load_signed_auth: an authenticated,
# forward-secure keyed log (unpruned, no encrypt history) exported as one
# self-certifying byte string — the Ed25519-signed counterpart of dump_auth.
# The wire form is D || U(version) || P || S: D is the magic, version the u64
# envelope version (always 1), P exactly the plaintext framing of dump_auth
# (B(hash_name) || U(n) || E1…En || B(root) || B(head) || U(stage) || B(K) ||
# U(x), each Ei an Entry in field order U, B, B, B) and S the 64-byte Ed25519
# signature over every preceding byte; no further signing domain is
# introduced. The signature authenticates the export's origin but does not
# encrypt P, which carries the live evolution key, so the byte string must be
# protected like key material.
_SIGNED_AUTH_MAGIC = b"auditchain/signed-auth/v1\0"
_SIGNED_AUTH_VERSION = 1

# Binary framing of dump_pruned_auth / load_pruned_auth: the pruned
# counterpart of the auth-log framing — the same symmetric AES-256-GCM wire
# form D || 0x01 || N || C with AAD D || 0x01 || N, but the plaintext
# describes a pruned keyed log (retain_from > 0, no encrypt history): after
# B(hash_name), U(n) and U(r) it carries B(checkpoint), the pruned-log
# frontier F, the retained entries r..n-1, and then the same auth-state tail
# B(root) || B(head) || U(stage) || B(K) || U(x) as dump_auth.
_PRUNED_AUTH_MAGIC = b"auditchain/pruned-auth/v1\0"
_PRUNED_AUTH_VERSION = 1

# Binary framing of dump_signed_pruned_auth / load_signed_pruned_auth: the
# Ed25519-signed counterpart of dump_pruned_auth, mirroring dump_signed_auth
# exactly — the wire form is D || U(version) || P || S: D is the magic,
# version the u64 envelope version (always 1), P field-by-field the plaintext
# framing of dump_pruned_auth
# (B(hash_name) || U(n) || U(r) || B(checkpoint) || F || E || B(root) ||
# B(head) || U(stage) || B(K) || U(x)) and S the 64-byte Ed25519 signature
# over every preceding byte; no further signing domain is introduced and no
# key is encrypted. As with dump_signed_auth the signature authenticates the
# export's origin but not its confidentiality — P carries the live evolution
# key — so the byte string must be protected like key material.
_SIGNED_PRUNED_AUTH_MAGIC = b"auditchain/signed-pruned-auth/v1\0"
_SIGNED_PRUNED_AUTH_VERSION = 1

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

# Binary framing of dump_signed_hybrid / load_signed_hybrid: the
# Ed25519-signed counterpart of the hybrid framing — the same unpruned, keyed,
# forward-secure log whose history may contain encrypted entries, but exported
# as one self-certifying byte string instead of being sealed symmetrically.
# The wire form is D || U(version) || P || S: D is the magic, version the u64
# envelope version (always 1), P field-by-field the plaintext framing of
# dump_hybrid
# (B(h) || U(q) || B(nonce1)…B(nonceq) || U(n) || E1…En || B(root) ||
# B(head) || U(stage) || B(K) || U(x), each Ei a secure-log record with
# B(locator)) and S the 64-byte Ed25519 signature over every preceding byte;
# no further signing domain is introduced and no key is encrypted. As with
# dump_signed_auth the signature authenticates the export's origin but not its
# confidentiality — P carries the live evolution key — so the byte string must
# be protected like key material.
_SIGNED_HYBRID_MAGIC = b"auditchain/signed-hybrid/v1\0"
_SIGNED_HYBRID_VERSION = 1

# Binary framing of dump_signed_pruned_hybrid / load_signed_pruned_hybrid: the
# Ed25519-signed counterpart of the pruned-hybrid framing — the same pruned,
# keyed, forward-secure log whose history may contain encrypted entries,
# including ciphertexts released by the prune, but exported as one
# self-certifying byte string instead of being sealed symmetrically. The wire
# form is D || U(version) || P || S: D is the magic, version the u64 envelope
# version (always 1), P field-by-field the plaintext framing of
# dump_pruned_hybrid
# (B(h) || U(n) || U(r) || B(checkpoint) || F || Q || E || B(root) ||
# B(head) || U(stage) || B(K) || U(x), each Ei a secure-log record with
# B(locator)) and S the 64-byte Ed25519 signature over every preceding byte;
# no further signing domain is introduced and no key is encrypted. As with
# dump_signed_hybrid the signature authenticates the export's origin but not
# its confidentiality — P carries the live evolution key — so the byte string
# must be protected like key material.
_SIGNED_PRUNED_HYBRID_MAGIC = b"auditchain/signed-pruned-hybrid/v1\0"
_SIGNED_PRUNED_HYBRID_VERSION = 1

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


def _signed_verifier_message(hash_name: str, key: bytes) -> bytes:
    """M of export_signed_verifier / verify_signed_verifier.

    ``D || 0x01 || B(UTF-8(hash_name)) || B(key)``
    with ``D = b"auditchain/signed-verifier/v1\\0"``, ``U`` an unsigned
    8-byte big-endian integer and ``B(x) = U(len(x)) || x``.
    """
    return (
        _SIGNED_VERIFIER_DOMAIN
        + bytes((0x01,))
        + _encode_blob(hash_name.encode("utf-8"))
        + _encode_blob(key)
    )


def _signed_stage_verifier_message(stage: int, hash_name: str, key: bytes) -> bytes:
    """M of export_signed_stage_verifier / verify_signed_stage_verifier.

    ``D || 0x01 || U(stage) || B(UTF-8(hash_name)) || B(key)``
    with ``D = b"auditchain/signed-stage/v1\\0"``, ``U`` an unsigned
    8-byte big-endian integer and ``B(x) = U(len(x)) || x``.
    """
    return (
        _SIGNED_STAGE_DOMAIN
        + bytes((0x01,))
        + _encode_u64(stage, "stage")
        + _encode_blob(hash_name.encode("utf-8"))
        + _encode_blob(key)
    )


def _rotation_message(old_signature: bytes, new_key: bytes, new_signature: bytes) -> bytes:
    """M of AuditLog.rotate_signer / verify_rotation's ``auth`` signature.

    ``D || 0x01 || B(old.signature) || B(new_key) || B(new.signature)``
    with ``D = b"auditchain/signer-rotation/v1\\0"``, ``U`` an unsigned
    8-byte big-endian integer and ``B(x) = U(len(x)) || x``.
    """
    return (
        _ROTATION_DOMAIN
        + bytes((_ROTATION_VERSION,))
        + _encode_blob(old_signature)
        + _encode_blob(new_key)
        + _encode_blob(new_signature)
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
class SearchReceipt:
    """Offline receipt for a content search over a snapshot.

    Issued by :meth:`AuditLog.search_receipt` and verified entirely offline
    by :func:`verify_search_receipt`:

    - ``version``: receipt format version, always ``1``,
    - ``hash_name``: hash algorithm of the log that issued the receipt,
    - ``size``: number of entries in the snapshot the receipt refers to,
    - ``root``: Merkle root of that snapshot,
    - ``query``: the normalized query value (a ``str`` query is UTF-8
      encoded at construction; the stored value is always ``bytes``),
    - ``start`` / ``stop``: the half-open absolute-index range the search
      covered, satisfying ``0 <= start <= stop <= size``,
    - ``items``: ``(Entry, proof)`` pairs in strictly ascending absolute
      index order, one per listed hit, where ``proof`` is the tuple of
      sibling digests of the entry's inclusion proof within the snapshot.
      Every listed entry must satisfy ``start <= entry.index < stop``.
      Duplicate payloads are listed once per occurrence; a search with no
      hits (and any empty snapshot) carries ``items == ()``.

    Instances are immutable, may be built positionally and compare by all
    eight fields. Verification only attests that the listed hits are
    genuine; it makes no claim about the completeness of the result set.
    """

    version: int
    hash_name: str
    size: int
    root: bytes
    query: bytes
    start: int
    stop: int
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
        if self.size >= _U64_LIMIT:
            raise ValueError("size must satisfy size < 2**64")
        if not isinstance(self.root, (bytes, bytearray)):
            raise TypeError("root must be bytes")
        if len(self.root) != digest_size:
            raise ValueError(f"root must be {digest_size} bytes")
        if not isinstance(self.root, bytes):
            object.__setattr__(self, "root", bytes(self.root))
        if isinstance(self.query, str):
            object.__setattr__(self, "query", self.query.encode("utf-8"))
        elif not isinstance(self.query, bytes):
            raise TypeError("query must be bytes or str")
        for name in ("start", "stop"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")
        if not 0 <= self.start <= self.stop <= self.size:
            raise ValueError(
                f"range must satisfy 0 <= start <= stop <= size ({self.size})"
            )
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
            if not self.start <= entry.index < self.stop:
                raise ValueError(
                    f"entry.index {entry.index} must satisfy "
                    f"start ({self.start}) <= index < stop ({self.stop})"
                )
            previous_index = entry.index
            if not isinstance(proof, tuple):
                raise TypeError("item proof must be a tuple of digests")
            for sibling in proof:
                if not isinstance(sibling, (bytes, bytearray)):
                    raise TypeError("proof element must be bytes")
                if len(sibling) != digest_size:
                    raise ValueError(f"proof element must be {digest_size} bytes")


@dataclass(frozen=True)
class EncryptedSearchReceipt:
    """Offline receipt for a keyed search over encrypted entries.

    Issued by :meth:`AuditLog.encrypted_search_receipt` and verified entirely
    offline by :func:`verify_encrypted_search_receipt`:

    - ``version``: receipt format version, always ``1``,
    - ``hash_name``: hash algorithm of the log that issued the receipt,
    - ``size``: number of entries in the snapshot the receipt refers to,
    - ``root``: Merkle root of that snapshot,
    - ``query``: the normalized query value (a ``str`` query is UTF-8
      encoded at construction; the stored value is always ``bytes``),
    - ``start`` / ``stop``: the half-open absolute-index range the search
      covered, satisfying ``0 <= start <= stop <= size``,
    - ``items``: ``(Entry, proof)`` pairs in strictly ascending absolute
      index order, one per listed hit, exactly as for :class:`SearchReceipt`.
      Each entry's payload is the still-sealed encrypted-entry envelope;
      verification decrypts it with the caller-supplied key and compares the
      recovered plaintext against the normalized query. Duplicate plaintexts
      are listed once per occurrence; a search with no hits (and any empty
      snapshot) carries ``items == ()``.

    The receipt records neither the key nor any plaintext. Instances are
    immutable, may be built positionally and compare by all eight fields.
    As with :class:`SearchReceipt`, verification only attests that the listed
    hits are genuine; it makes no claim about the completeness of the result
    set. The constructor fixes only types, widths, ordering and ranges —
    whether an entry's envelope actually decrypts to the query is left to
    :func:`verify_encrypted_search_receipt`, so a tampered receipt is still
    constructible and round-trips.
    """

    version: int
    hash_name: str
    size: int
    root: bytes
    query: bytes
    start: int
    stop: int
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
        if self.size >= _U64_LIMIT:
            raise ValueError("size must satisfy size < 2**64")
        if not isinstance(self.root, (bytes, bytearray)):
            raise TypeError("root must be bytes")
        if len(self.root) != digest_size:
            raise ValueError(f"root must be {digest_size} bytes")
        if not isinstance(self.root, bytes):
            object.__setattr__(self, "root", bytes(self.root))
        if isinstance(self.query, str):
            object.__setattr__(self, "query", self.query.encode("utf-8"))
        elif not isinstance(self.query, bytes):
            raise TypeError("query must be bytes or str")
        for name in ("start", "stop"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")
        if not 0 <= self.start <= self.stop <= self.size:
            raise ValueError(
                f"range must satisfy 0 <= start <= stop <= size ({self.size})"
            )
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
            if not self.start <= entry.index < self.stop:
                raise ValueError(
                    f"entry.index {entry.index} must satisfy "
                    f"start ({self.start}) <= index < stop ({self.stop})"
                )
            previous_index = entry.index
            if not isinstance(proof, tuple):
                raise TypeError("item proof must be a tuple of digests")
            for sibling in proof:
                if not isinstance(sibling, (bytes, bytearray)):
                    raise TypeError("proof element must be bytes")
                if len(sibling) != digest_size:
                    raise ValueError(f"proof element must be {digest_size} bytes")


@dataclass(frozen=True)
class FullSearchReceipt:
    """Offline completeness receipt for a content search over a snapshot.

    Issued by :meth:`AuditLog.full_search_receipt` and verified entirely
    offline by :func:`verify_full_search_receipt`:

    - ``version``: receipt format version, always ``1``,
    - ``hash_name``: hash algorithm of the log that issued the receipt,
    - ``size``: number of entries in the snapshot the receipt refers to,
    - ``root``: Merkle root of that snapshot,
    - ``query``: the normalized query value (a ``str`` query is UTF-8
      encoded at construction; the stored value is always ``bytes``),
    - ``start`` / ``stop``: the half-open absolute-index range the search
      covered, satisfying ``0 <= start <= stop <= size``,
    - ``items``: every :class:`Entry` of the searched range, one per
      absolute index in strictly ascending order — exactly the indices
      ``start, start + 1, ..., stop - 1``, so an incomplete coverage, a
      duplicate or an out-of-order entry is rejected at construction,
    - ``proof``: the single shared compact batch inclusion proof (as
      produced by :meth:`AuditLog.batch_inclusion_proof`) covering all of
      ``items`` within the snapshot, instead of one proof per entry.

    Unlike :class:`SearchReceipt`, which only attests that the listed hits
    are genuine, this receipt carries the whole searched range: once the
    entries are authenticated against the snapshot root, the verifier's own
    comparison of each payload against ``query`` yields the complete hit
    set, so a missing hit cannot be concealed. An empty range (and any
    empty snapshot) carries ``items == ()`` and ``proof == ()``.

    Instances are immutable, may be built positionally and compare by all
    nine fields. The constructor fixes only types, widths, ordering,
    coverage and ranges — whether the entry digests and the shared proof
    actually rebuild ``root`` is left to :func:`verify_full_search_receipt`,
    so a tampered receipt is still constructible and round-trips.
    """

    version: int
    hash_name: str
    size: int
    root: bytes
    query: bytes
    start: int
    stop: int
    items: tuple
    proof: tuple

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
        if self.size >= _U64_LIMIT:
            raise ValueError("size must satisfy size < 2**64")
        if not isinstance(self.root, (bytes, bytearray)):
            raise TypeError("root must be bytes")
        if len(self.root) != digest_size:
            raise ValueError(f"root must be {digest_size} bytes")
        if not isinstance(self.root, bytes):
            object.__setattr__(self, "root", bytes(self.root))
        if isinstance(self.query, str):
            object.__setattr__(self, "query", self.query.encode("utf-8"))
        elif not isinstance(self.query, bytes):
            raise TypeError("query must be bytes or str")
        for name in ("start", "stop"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")
        if not 0 <= self.start <= self.stop <= self.size:
            raise ValueError(
                f"range must satisfy 0 <= start <= stop <= size ({self.size})"
            )
        if not isinstance(self.items, tuple):
            raise TypeError("items must be a tuple of Entry records")
        previous_index = -1
        for entry in self.items:
            if not isinstance(entry, Entry):
                raise TypeError("item must be an Entry")
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
            if not self.start <= entry.index < self.stop:
                raise ValueError(
                    f"entry.index {entry.index} must satisfy "
                    f"start ({self.start}) <= index < stop ({self.stop})"
                )
            previous_index = entry.index
        if len(self.items) != self.stop - self.start:
            # Strictly ascending in-range indices only cover the range when
            # there is exactly one entry per absolute index.
            raise ValueError(
                f"items must carry every entry of the range "
                f"[{self.start}, {self.stop})"
            )
        if not isinstance(self.proof, tuple):
            raise TypeError("proof must be a tuple of digests")
        for node in self.proof:
            if not isinstance(node, (bytes, bytearray)):
                raise TypeError("proof element must be bytes")
            if len(node) != digest_size:
                raise ValueError(f"proof element must be {digest_size} bytes")
        if not self.items and self.proof:
            raise ValueError("an empty range receipt must carry an empty proof")


@dataclass(frozen=True)
class BatchInclusionProof:
    """Offline credential binding a compact batch inclusion proof to its context.

    Ties everything :func:`verify_batch_inclusion` needs into one artifact, so
    a proof minted by :meth:`AuditLog.batch_inclusion_proof` can be persisted
    and restored in another process without re-holding the log:

    - ``hash_name``: hash algorithm of the log the proof came from,
    - ``indices``: strictly ascending tuple of the selected absolute indices,
    - ``entry_hashes``: tuple of the selected entries' digests, exactly as
      long as ``indices``,
    - ``size``: number of entries in the snapshot the proof refers to,
    - ``root``: Merkle root of that snapshot,
    - ``proof``: the shared proof node tuple, in generation order.

    Instances are immutable, may be built positionally and compare by all six
    fields. Whether the proof node count fits the selected leaves and whether
    the nodes rebuild ``root`` is left to :func:`verify_batch_inclusion`: a
    wrong node count raises ValueError there and a mere content mismatch
    returns False; the constructor only fixes the shape, widths and ordering.
    """

    hash_name: str
    indices: tuple[int, ...]
    entry_hashes: tuple[bytes, ...]
    size: int
    root: bytes
    proof: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        digest_size = _digest_size(self.hash_name)

        if not isinstance(self.indices, tuple):
            raise TypeError("indices must be a tuple of integers")
        if not self.indices:
            raise ValueError("indices must be non-empty")
        previous = -1
        for index in self.indices:
            if not isinstance(index, int) or isinstance(index, bool):
                raise TypeError("indices must be non-bool integers")
            if index < 0:
                raise ValueError("indices must be non-negative")
            if index <= previous:
                raise ValueError(
                    "indices must be strictly ascending with no duplicates"
                )
            previous = index

        if not isinstance(self.entry_hashes, tuple):
            raise TypeError("entry_hashes must be a tuple of digests")
        if len(self.entry_hashes) != len(self.indices):
            raise ValueError("entry_hashes must have the same length as indices")
        for entry_hash in self.entry_hashes:
            if not isinstance(entry_hash, bytes):
                raise TypeError("entry_hashes elements must be bytes")
            if len(entry_hash) != digest_size:
                raise ValueError(f"entry_hash must be {digest_size} bytes")

        if not isinstance(self.size, int) or isinstance(self.size, bool):
            raise TypeError("size must be a non-bool integer")
        if self.size <= 0:
            raise ValueError("size must be positive")
        if self.size >= _U64_LIMIT:
            raise ValueError("size must satisfy size < 2**64")
        if self.indices[-1] >= self.size:
            raise ValueError(
                f"index {self.indices[-1]} must satisfy "
                f"0 <= index < size ({self.size})"
            )

        # root and every proof node must be exact bytes: bytearray and
        # memoryview are rejected rather than copied, so a received credential
        # never silently aliases a mutable caller buffer.
        if not isinstance(self.root, bytes):
            raise TypeError("root must be bytes")
        if len(self.root) != digest_size:
            raise ValueError(f"root must be {digest_size} bytes")

        if not isinstance(self.proof, tuple):
            raise TypeError("proof must be a tuple of digests")
        for node in self.proof:
            if not isinstance(node, bytes):
                raise TypeError("proof elements must be bytes")
            if len(node) != digest_size:
                raise ValueError(f"proof element must be {digest_size} bytes")


@dataclass(frozen=True)
class InclusionProof:
    """Offline credential binding a single-entry inclusion proof to its context.

    Ties everything :func:`verify_inclusion` needs into one artifact, so a
    proof minted by :meth:`AuditLog.inclusion_proof` can be persisted and
    restored in another process without re-holding the log:

    - ``hash_name``: hash algorithm of the log the proof came from,
    - ``index``: absolute index of the proven entry within the snapshot,
    - ``size``: number of entries in the snapshot the proof refers to,
    - ``entry_hash``: digest of the proven entry,
    - ``root``: Merkle root of that snapshot,
    - ``proof``: the sibling-node tuple, in generation order.

    Instances are immutable, may be built positionally and compare by all six
    fields. Whether the proof node count fits the leaf and whether the nodes
    rebuild ``root`` is left to :func:`verify_inclusion`: a wrong node count
    raises ValueError there and a mere content mismatch returns False; the
    constructor only fixes the types, widths and ranges.
    """

    hash_name: str
    index: int
    size: int
    entry_hash: bytes
    root: bytes
    proof: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        digest_size = _digest_size(self.hash_name)

        if not isinstance(self.index, int) or isinstance(self.index, bool):
            raise TypeError("index must be a non-bool integer")
        if self.index < 0:
            raise ValueError("index must be non-negative")

        if not isinstance(self.size, int) or isinstance(self.size, bool):
            raise TypeError("size must be a non-bool integer")
        if self.size <= 0:
            raise ValueError("size must be positive")
        if self.size >= _U64_LIMIT:
            raise ValueError("size must satisfy size < 2**64")
        if self.index >= self.size:
            raise ValueError(
                f"index {self.index} must satisfy "
                f"0 <= index < size ({self.size})"
            )

        # entry_hash, root and every proof node must be exact bytes: bytearray
        # and memoryview are rejected rather than copied, so a received
        # credential never silently aliases a mutable caller buffer.
        if not isinstance(self.entry_hash, bytes):
            raise TypeError("entry_hash must be bytes")
        if len(self.entry_hash) != digest_size:
            raise ValueError(f"entry_hash must be {digest_size} bytes")

        if not isinstance(self.root, bytes):
            raise TypeError("root must be bytes")
        if len(self.root) != digest_size:
            raise ValueError(f"root must be {digest_size} bytes")

        if not isinstance(self.proof, tuple):
            raise TypeError("proof must be a tuple of digests")
        for node in self.proof:
            if not isinstance(node, bytes):
                raise TypeError("proof elements must be bytes")
            if len(node) != digest_size:
                raise ValueError(f"proof element must be {digest_size} bytes")


@dataclass(frozen=True)
class ConsistencyProof:
    """Offline credential binding a cross-snapshot consistency proof to context.

    Ties everything :func:`verify_consistency` needs into one artifact, so a
    proof minted by :meth:`AuditLog.consistency_proof` can be persisted and
    restored in another process without re-holding the log:

    - ``hash_name``: hash algorithm of the log the proof came from,
    - ``old_size``: number of entries in the earlier snapshot,
    - ``old_root``: Merkle root of the earlier snapshot,
    - ``new_size``: number of entries in the later snapshot,
    - ``new_root``: Merkle root of the later snapshot,
    - ``proof``: the proof node tuple, in generation (RFC 6962 SUBPROOF)
      order.

    Instances are immutable, may be built positionally and compare by all six
    fields. Whether the proof node count fits the two sizes and whether the
    nodes connect the two roots is left to :func:`verify_consistency`: a wrong
    node count raises ValueError there and a mere content mismatch returns
    False; the constructor only fixes the types, widths, ordering and ranges.
    """

    hash_name: str
    old_size: int
    old_root: bytes
    new_size: int
    new_root: bytes
    proof: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        digest_size = _digest_size(self.hash_name)

        if not isinstance(self.old_size, int) or isinstance(self.old_size, bool):
            raise TypeError("old_size must be a non-bool integer")
        if not isinstance(self.new_size, int) or isinstance(self.new_size, bool):
            raise TypeError("new_size must be a non-bool integer")
        if self.old_size < 0 or self.new_size < 0:
            raise ValueError("sizes must be non-negative")
        if self.old_size > self.new_size:
            raise ValueError("old_size must not exceed new_size")
        if self.new_size >= _U64_LIMIT:
            raise ValueError("sizes must satisfy size < 2**64")

        # old_root, new_root and every proof node must be exact bytes:
        # bytearray and memoryview are rejected rather than copied, so a
        # received credential never silently aliases a mutable caller buffer.
        if not isinstance(self.old_root, bytes):
            raise TypeError("old_root must be bytes")
        if len(self.old_root) != digest_size:
            raise ValueError(f"old_root must be {digest_size} bytes")

        if not isinstance(self.new_root, bytes):
            raise TypeError("new_root must be bytes")
        if len(self.new_root) != digest_size:
            raise ValueError(f"new_root must be {digest_size} bytes")

        if not isinstance(self.proof, tuple):
            raise TypeError("proof must be a tuple of digests")
        for node in self.proof:
            if not isinstance(node, bytes):
                raise TypeError("proof elements must be bytes")
            if len(node) != digest_size:
                raise ValueError(f"proof element must be {digest_size} bytes")


@dataclass(frozen=True)
class MerkleFrontier:
    """Offline credential freezing the Merkle frontier of a covered prefix.

    Captures the perfect-subtree stack a pruned log keeps for its released
    prefix as a public, persistable artifact, so the subtree digests can be
    written to disk and restored in another process without re-holding the
    log:

    - ``hash_name``: hash algorithm of the log the frontier came from,
    - ``size``: number of entries in the covered prefix ``[0, size)``,
    - ``subtrees``: the ``(height, digest)`` pairs of the maximal perfect
      subtrees covering that prefix — one pair per set bit of ``size``, in
      ascending height order, each digest the root of the subtree of height
      ``height`` (holding ``2**height`` leaves).

    Instances are immutable, may be built positionally and compare by all
    three fields. The constructor fixes the types, widths, ranges and the
    exact set-bit coverage; folding the subtrees together with the retained
    entries' hashes into the full snapshot root is :func:`rebuild_merkle_root`.
    """

    hash_name: str
    size: int
    subtrees: tuple[tuple[int, bytes], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        digest_size = _digest_size(self.hash_name)

        if not isinstance(self.size, int) or isinstance(self.size, bool):
            raise TypeError("size must be a non-bool integer")
        if self.size < 0:
            raise ValueError("size must be non-negative")
        if self.size >= _U64_LIMIT:
            raise ValueError("size must satisfy size < 2**64")

        if not isinstance(self.subtrees, tuple):
            raise TypeError("subtrees must be a tuple of (height, digest) pairs")
        previous_height = -1
        for pair in self.subtrees:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise TypeError("subtrees elements must be (height, digest) pairs")
            height, digest = pair
            if not isinstance(height, int) or isinstance(height, bool):
                raise TypeError("subtree height must be a non-bool integer")
            if height < 0:
                raise ValueError("subtree height must be non-negative")
            if height <= previous_height:
                raise ValueError("subtree heights must be in strictly ascending order")
            previous_height = height
            # Each digest must be exact bytes: bytearray and memoryview are
            # rejected rather than copied, so a received credential never
            # silently aliases a mutable caller buffer.
            if not isinstance(digest, bytes):
                raise TypeError("subtree digest must be bytes")
            if len(digest) != digest_size:
                raise ValueError(f"subtree digest must be {digest_size} bytes")
        # The frontier is exactly the set of maximal perfect subtrees covering
        # [0, size): one subtree of height h per set bit h of size.
        expected = tuple(
            height for height in range(64) if (self.size >> height) & 1
        )
        if tuple(height for height, _ in self.subtrees) != expected:
            raise ValueError(
                "subtree heights must be exactly the set bits of size"
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
class SignedAuditReceipt:
    """Per-entry audit receipt sealed by a pre-trusted Ed25519 key.

    Bundles the :class:`AuditReceipt` of :meth:`AuditLog.audit_receipt` with
    the :class:`SignedRoot` checkpoint of :meth:`AuditLog.sign_root`, so an
    offline receiver holding only a pre-trusted 32-byte Ed25519 public key
    can confirm in one artifact that the selected entries with their
    per-entry inclusion proofs, the snapshot Merkle root and the chain head
    were all issued by the log holder — without holding the :class:`AuditLog`:

    - ``receipt``: the :class:`AuditReceipt` produced by
      :meth:`AuditLog.audit_receipt`,
    - ``checkpoint``: the :class:`SignedRoot` produced by
      :meth:`AuditLog.sign_root` for the same rebuildable snapshot.

    Instances are immutable, may be built positionally and compare by both
    fields. ``receipt`` must be an :class:`AuditReceipt` and ``checkpoint`` a
    :class:`SignedRoot` — a field of the wrong type raises TypeError — and the
    two must describe the same snapshot: equal ``hash_name``, ``size`` and
    ``root``, or the bundle could never attest one rebuildable snapshot; a
    mismatch raises ValueError. The receipt's own structural contract is left
    to :class:`AuditReceipt`, and whether the checkpoint signature is genuine
    is left to :func:`verify_signed_audit_receipt`.
    """

    receipt: AuditReceipt
    checkpoint: SignedRoot

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, AuditReceipt):
            raise TypeError("receipt must be an AuditReceipt")
        if not isinstance(self.checkpoint, SignedRoot):
            raise TypeError("checkpoint must be a SignedRoot")
        if (
            self.receipt.hash_name != self.checkpoint.hash_name
            or self.receipt.size != self.checkpoint.size
            or self.receipt.root != self.checkpoint.root
        ):
            raise ValueError(
                "receipt and checkpoint must describe the same snapshot "
                "(hash_name, size and root must be equal)"
            )


@dataclass(frozen=True)
class SignedSearchReceipt:
    """Content-search receipt sealed by a pre-trusted Ed25519 key.

    Bundles the :class:`SearchReceipt` of :meth:`AuditLog.search_receipt`
    with the :class:`SignedRoot` checkpoint of :meth:`AuditLog.sign_root`,
    so an offline receiver holding only a pre-trusted 32-byte Ed25519 public
    key can confirm in one artifact that the listed search hits with their
    inclusion proofs, the snapshot Merkle root and the chain head were all
    issued by the log holder — without holding the :class:`AuditLog`:

    - ``receipt``: the :class:`SearchReceipt` produced by
      :meth:`AuditLog.search_receipt`,
    - ``checkpoint``: the :class:`SignedRoot` produced by
      :meth:`AuditLog.sign_root` for the same rebuildable snapshot.

    Instances are immutable, may be built positionally and compare by both
    fields. ``receipt`` must be a :class:`SearchReceipt` and ``checkpoint`` a
    :class:`SignedRoot` — a field of the wrong type raises TypeError — and
    the two must describe the same snapshot: equal ``hash_name``, ``size``
    and ``root``, or the bundle could never attest one rebuildable snapshot;
    a mismatch raises ValueError. The receipt's own structural contract is
    left to :class:`SearchReceipt`, and whether the checkpoint signature is
    genuine is left to :func:`verify_signed_search_receipt`.
    """

    receipt: SearchReceipt
    checkpoint: SignedRoot

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, SearchReceipt):
            raise TypeError("receipt must be a SearchReceipt")
        if not isinstance(self.checkpoint, SignedRoot):
            raise TypeError("checkpoint must be a SignedRoot")
        if (
            self.receipt.hash_name != self.checkpoint.hash_name
            or self.receipt.size != self.checkpoint.size
            or self.receipt.root != self.checkpoint.root
        ):
            raise ValueError(
                "receipt and checkpoint must describe the same snapshot "
                "(hash_name, size and root must be equal)"
            )


@dataclass(frozen=True)
class SignedEncryptedSearchReceipt:
    """Keyed-search receipt sealed by a pre-trusted Ed25519 key.

    Bundles the :class:`EncryptedSearchReceipt` of
    :meth:`AuditLog.encrypted_search_receipt` with the :class:`SignedRoot`
    checkpoint of :meth:`AuditLog.sign_root`, so an offline receiver holding
    only the append key and a pre-trusted 32-byte Ed25519 public key can
    confirm in one artifact that the listed encrypted-search hits with their
    inclusion proofs, the snapshot Merkle root and the chain head were all
    issued by the log holder — without holding the :class:`AuditLog`:

    - ``receipt``: the :class:`EncryptedSearchReceipt` produced by
      :meth:`AuditLog.encrypted_search_receipt`,
    - ``checkpoint``: the :class:`SignedRoot` produced by
      :meth:`AuditLog.sign_root` for the same rebuildable snapshot.

    Instances are immutable, may be built positionally and compare by both
    fields. ``receipt`` must be an :class:`EncryptedSearchReceipt` and
    ``checkpoint`` a :class:`SignedRoot` — a field of the wrong type raises
    TypeError — and the two must describe the same snapshot: equal
    ``hash_name``, ``size`` and ``root``, or the bundle could never attest
    one rebuildable snapshot; a mismatch raises ValueError. The receipt's own
    structural contract is left to :class:`EncryptedSearchReceipt`, and
    whether the checkpoint signature is genuine is left to
    :func:`verify_signed_encrypted_search_receipt`.
    """

    receipt: EncryptedSearchReceipt
    checkpoint: SignedRoot

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, EncryptedSearchReceipt):
            raise TypeError("receipt must be an EncryptedSearchReceipt")
        if not isinstance(self.checkpoint, SignedRoot):
            raise TypeError("checkpoint must be a SignedRoot")
        if (
            self.receipt.hash_name != self.checkpoint.hash_name
            or self.receipt.size != self.checkpoint.size
            or self.receipt.root != self.checkpoint.root
        ):
            raise ValueError(
                "receipt and checkpoint must describe the same snapshot "
                "(hash_name, size and root must be equal)"
            )


@dataclass(frozen=True)
class SignedFullSearchReceipt:
    """Full-coverage search receipt sealed by a pre-trusted Ed25519 key.

    Bundles the :class:`FullSearchReceipt` of
    :meth:`AuditLog.full_search_receipt` with the :class:`SignedRoot`
    checkpoint of :meth:`AuditLog.sign_root`, so an offline receiver holding
    only a pre-trusted 32-byte Ed25519 public key can confirm in one artifact
    that the complete searched range with its shared inclusion proof, the
    snapshot Merkle root and the chain head were all issued by the log
    holder — without holding the :class:`AuditLog`:

    - ``receipt``: the :class:`FullSearchReceipt` produced by
      :meth:`AuditLog.full_search_receipt`,
    - ``checkpoint``: the :class:`SignedRoot` produced by
      :meth:`AuditLog.sign_root` for the same rebuildable snapshot.

    Instances are immutable, may be built positionally and compare by both
    fields. ``receipt`` must be a :class:`FullSearchReceipt` and
    ``checkpoint`` a :class:`SignedRoot` — a field of the wrong type raises
    TypeError — and the two must describe the same snapshot: equal
    ``hash_name``, ``size`` and ``root``, or the bundle could never attest
    one rebuildable snapshot; a mismatch raises ValueError. The receipt's own
    structural contract is left to :class:`FullSearchReceipt`, and whether
    the checkpoint signature is genuine is left to
    :func:`verify_signed_full_search_receipt`.
    """

    receipt: FullSearchReceipt
    checkpoint: SignedRoot

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, FullSearchReceipt):
            raise TypeError("receipt must be a FullSearchReceipt")
        if not isinstance(self.checkpoint, SignedRoot):
            raise TypeError("checkpoint must be a SignedRoot")
        if (
            self.receipt.hash_name != self.checkpoint.hash_name
            or self.receipt.size != self.checkpoint.size
            or self.receipt.root != self.checkpoint.root
        ):
            raise ValueError(
                "receipt and checkpoint must describe the same snapshot "
                "(hash_name, size and root must be equal)"
            )


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


@dataclass(frozen=True)
class StageVerifier:
    """Immutable verification material delivered at a post-evolution stage.

    The stage-scoped counterpart of :class:`Verifier`: it freezes the
    evolution stage at which it was delivered together with that stage's
    current key and the hash algorithm, and :func:`verify_auth_stage`
    evolves this key forward to a tag's stage without needing the log.
    Unlike the stage-0 :class:`Verifier`, delivery at a positive stage can
    only authenticate tags minted at that stage or later: a tag whose stage
    precedes delivery never verifies, even when its entry and tag are
    otherwise genuine.

    - ``stage``: key-evolution stage the material was delivered at,
    - ``key``: the evolving key at exactly that stage,
    - ``hash_name``: hash algorithm of the issuing log.

    Instances are immutable, may be built positionally and compare by all
    three fields. ``stage`` must be a non-bool integer satisfying
    ``0 <= stage < 2**64`` and ``key`` must be non-empty ``bytes``; a
    positive stage additionally requires ``key`` to be exactly one digest
    wide under ``hash_name`` (at stage 0 the construction key may have any
    non-empty length, exactly as the log accepts it). A wrong field type
    raises TypeError; an out-of-range stage, an empty or wrong-width key, or
    an unknown hash algorithm raises ValueError.
    """

    stage: int
    key: bytes
    hash_name: str

    def __post_init__(self) -> None:
        if not isinstance(self.stage, int) or isinstance(self.stage, bool):
            raise TypeError("stage must be an integer")
        if self.stage < 0:
            raise ValueError("stage must be non-negative")
        if self.stage >= _MAX_STAGE:
            raise ValueError("stage must be less than 2**64")
        if not isinstance(self.key, bytes):
            raise TypeError("key must be bytes")
        if len(self.key) == 0:
            raise ValueError("key must be non-empty")
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        digest_size = _digest_size(self.hash_name)
        if self.stage > 0 and len(self.key) != digest_size:
            raise ValueError(f"key must be {digest_size} bytes at a positive stage")


@dataclass(frozen=True)
class SignedStageVerifier:
    """Ed25519-signed stage :class:`StageVerifier` for trusted delivery.

    Issued by :meth:`AuditLog.export_signed_stage_verifier` and verified
    entirely offline by :func:`verify_signed_stage_verifier` against a
    pre-trusted 32-byte Ed25519 public key, so a receiver can confirm where
    the stage verification material came from without holding the log:

    - ``version``: format version, always ``1``,
    - ``verifier``: the delivered :class:`StageVerifier` (delivery stage,
      that stage's key and the hash algorithm),
    - ``signature``: the 64-byte Ed25519 signature over the verifier fields.

    The signature authenticates provenance only; it does not encrypt the
    verifier's key, so callers must still protect the material carried here
    exactly as they would protect a bare :class:`StageVerifier`.

    Instances are immutable, may be built positionally and compare by all
    three fields.
    """

    version: int
    verifier: StageVerifier
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or isinstance(self.version, bool):
            raise TypeError("version must be an integer")
        if self.version != _SIGNED_STAGE_VERSION:
            raise ValueError("version must be 1")
        if not isinstance(self.verifier, StageVerifier):
            raise TypeError("verifier must be a StageVerifier")
        # Re-validate the nested verifier even for an instance whose fields
        # were set bypassing the frozen constructor, so corruption raises
        # exactly as the StageVerifier constructor would.
        StageVerifier(
            self.verifier.stage, self.verifier.key, self.verifier.hash_name
        )
        if not isinstance(self.signature, bytes):
            raise TypeError("signature must be bytes")
        if len(self.signature) != _ED25519_SIGNATURE_BYTES:
            raise ValueError(
                f"signature must be {_ED25519_SIGNATURE_BYTES} bytes"
            )


@dataclass(frozen=True)
class SignedVerifier:
    """Ed25519-signed stage-0 :class:`Verifier` for trusted delivery.

    Issued by :meth:`AuditLog.export_signed_verifier` and verified entirely
    offline by :func:`verify_signed_verifier` against a pre-trusted 32-byte
    Ed25519 public key, so a receiver can confirm where the stage-0
    verification material came from without holding the log:

    - ``version``: format version, always ``1``,
    - ``verifier``: the stage-0 :class:`Verifier` (key and hash algorithm),
    - ``signature``: the 64-byte Ed25519 signature over the verifier fields.

    The signature authenticates provenance only; it does not encrypt the
    verifier's key, so callers must still protect the material carried here
    exactly as they would protect a bare :class:`Verifier`.

    Instances are immutable, may be built positionally and compare by all
    three fields.
    """

    version: int
    verifier: Verifier
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or isinstance(self.version, bool):
            raise TypeError("version must be an integer")
        if self.version != _SIGNED_VERIFIER_VERSION:
            raise ValueError("version must be 1")
        if not isinstance(self.verifier, Verifier):
            raise TypeError("verifier must be a Verifier")
        # Re-validate the nested verifier even for an instance whose fields
        # were set bypassing the frozen constructor, so corruption raises
        # exactly as the Verifier constructor would.
        Verifier(self.verifier.key, self.verifier.hash_name)
        if not isinstance(self.signature, bytes):
            raise TypeError("signature must be bytes")
        if len(self.signature) != _ED25519_SIGNATURE_BYTES:
            raise ValueError(
                f"signature must be {_ED25519_SIGNATURE_BYTES} bytes"
            )


@dataclass(frozen=True)
class SignedAuthBundle:
    """Trusted delivery bundle of signed stage-0 material and an auth batch.

    Merges the :class:`SignedVerifier` of
    :meth:`AuditLog.export_signed_verifier` with the ``(Entry, AuthTag)``
    item tuple of :meth:`AuditLog.auth_batch`, so an offline receiver
    holding only a pre-trusted 32-byte Ed25519 public key can confirm where
    the stage-0 verification material came from and then check every tag
    against it — one artifact, no new signing message:

    - ``verifier``: the :class:`SignedVerifier` carrying the signed stage-0
      :class:`Verifier`,
    - ``hash_name``: the hash algorithm the auth batch was minted under
      (must agree with the nested verifier's algorithm for verification to
      succeed),
    - ``items``: the ``((Entry, AuthTag), ...)`` tuple produced by
      :meth:`AuditLog.auth_batch`.

    Instances are immutable, may be built positionally and compare by all
    three fields. Only the container shape is validated here: ``verifier``
    must be a :class:`SignedVerifier`, ``hash_name`` a known hash algorithm
    name and ``items`` a tuple; the items' own structural contract is left
    to :func:`verify_auth_batch`, so a field of the wrong type raises
    TypeError. The signature authenticates provenance only; the verifier
    key travels in the clear.
    """

    verifier: SignedVerifier
    hash_name: str
    items: tuple

    def __post_init__(self) -> None:
        if not isinstance(self.verifier, SignedVerifier):
            raise TypeError("verifier must be a SignedVerifier")
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        _digest_size(self.hash_name)
        if not isinstance(self.items, tuple):
            raise TypeError("items must be a tuple of (Entry, AuthTag) pairs")


@dataclass(frozen=True)
class SignedStageAuthBundle:
    """Trusted delivery bundle of signed stage material and an auth batch.

    The stage-scoped counterpart of :class:`SignedAuthBundle`: it merges the
    :class:`SignedStageVerifier` of
    :meth:`AuditLog.export_signed_stage_verifier` with the ``(Entry,
    AuthTag)`` item tuple of :meth:`AuditLog.auth_batch`, so an offline
    receiver holding only a pre-trusted 32-byte Ed25519 public key can
    confirm where the post-evolution stage verification material came from
    and then check every tag against it — one artifact, no new signing
    message:

    - ``verifier``: the :class:`SignedStageVerifier` carrying the signed
      :class:`StageVerifier` (delivery stage, that stage's key and the hash
      algorithm),
    - ``hash_name``: the hash algorithm the auth batch was minted under
      (must agree with the nested verifier's algorithm for verification to
      succeed),
    - ``items``: the ``((Entry, AuthTag), ...)`` tuple produced by
      :meth:`AuditLog.auth_batch`, whose first tag sits at the delivery
      stage.

    Instances are immutable, may be built positionally and compare by all
    three fields. Only the container shape is validated here: ``verifier``
    must be a :class:`SignedStageVerifier`, ``hash_name`` a known hash
    algorithm name and ``items`` a tuple; the items' own structural contract
    is left to :func:`verify_signed_stage_auth_bundle`, so a field of the
    wrong type raises TypeError. The signature authenticates provenance
    only; the verifier key travels in the clear.
    """

    verifier: SignedStageVerifier
    hash_name: str
    items: tuple

    def __post_init__(self) -> None:
        if not isinstance(self.verifier, SignedStageVerifier):
            raise TypeError("verifier must be a SignedStageVerifier")
        if not isinstance(self.hash_name, str):
            raise TypeError("hash_name must be a string")
        _digest_size(self.hash_name)
        if not isinstance(self.items, tuple):
            raise TypeError("items must be a tuple of (Entry, AuthTag) pairs")


@dataclass(frozen=True)
class SignedStageAuthAuditBundle:
    """Trusted delivery bundle of a signed-stage auth bundle and a batch audit.

    The stage-scoped counterpart of :class:`SignedAuthAuditBundle`: it merges
    the :class:`SignedStageAuthBundle` of
    :meth:`AuditLog.signed_stage_auth_bundle` — the signed post-evolution
    :class:`SignedStageVerifier` together with the selected entries'
    forward-secure tags — with the :class:`SignedAuditBatch` of
    :meth:`AuditLog.signed_audit_batch`, so an offline receiver holding only a
    pre-trusted 32-byte Ed25519 public key gets — in one artifact — both
    authentication against the signed current-stage material and the signed
    evidence that the selected entries belong to one snapshot:

    - ``auth``: the :class:`SignedStageAuthBundle` carrying the signed
      :class:`StageVerifier` (delivery stage, that stage's key and the hash
      algorithm) and the selected ``(Entry, AuthTag)`` items,
    - ``audit``: the :class:`SignedAuditBatch` carrying the selected
      entries' batch inclusion proof and the signed snapshot checkpoint.

    The two packages must be minted under one hash algorithm, and every
    entry the auth package authenticates must be the very record the audit
    package carries at the same absolute index; the audit package
    additionally carries the snapshot's last entry (as every non-empty
    batch receipt does). Whether all of that holds, and whether either
    Ed25519 signature verifies, is left to
    :func:`verify_signed_stage_auth_audit_bundle`.

    Instances are immutable, may be built positionally and compare by both
    fields. Only the container shape is validated here: ``auth`` must be a
    :class:`SignedStageAuthBundle` and ``audit`` a :class:`SignedAuditBatch`,
    so a field of the wrong type raises TypeError; neither half's internal
    structure is validated by the constructor. The signature authenticates
    provenance only; the stage key travels in the clear.
    """

    auth: SignedStageAuthBundle
    audit: SignedAuditBatch

    def __post_init__(self) -> None:
        if not isinstance(self.auth, SignedStageAuthBundle):
            raise TypeError("auth must be a SignedStageAuthBundle")
        if not isinstance(self.audit, SignedAuditBatch):
            raise TypeError("audit must be a SignedAuditBatch")


@dataclass(frozen=True)
class SignedAuthAuditBundle:
    """Trusted delivery bundle of an auth bundle and a signed batch audit.

    Merges the :class:`SignedAuthBundle` of
    :meth:`AuditLog.signed_auth_bundle` with the :class:`SignedAuditBatch`
    of :meth:`AuditLog.signed_audit_batch`, so an offline receiver holding
    only a pre-trusted 32-byte Ed25519 public key gets — in one artifact —
    both the forward-secure authentication of the selected entries and the
    signed evidence that they belong to one snapshot:

    - ``auth``: the :class:`SignedAuthBundle` carrying the signed stage-0
      :class:`Verifier` and the selected ``(Entry, AuthTag)`` items,
    - ``audit``: the :class:`SignedAuditBatch` carrying the selected
      entries' batch inclusion proof and the signed snapshot checkpoint.

    The two packages must be minted under one hash algorithm, and every
    entry the auth package authenticates must be the very record the audit
    package carries at the same absolute index; the audit package
    additionally carries the snapshot's last entry (as every non-empty
    batch receipt does). Whether all of that holds, and whether either
    Ed25519 signature verifies, is left to
    :func:`verify_signed_auth_audit_bundle`.

    Instances are immutable, may be built positionally and compare by both
    fields. Only the container shape is validated here: ``auth`` must be a
    :class:`SignedAuthBundle` and ``audit`` a :class:`SignedAuditBatch`, so
    a field of the wrong type raises TypeError.
    """

    auth: SignedAuthBundle
    audit: SignedAuditBatch

    def __post_init__(self) -> None:
        if not isinstance(self.auth, SignedAuthBundle):
            raise TypeError("auth must be a SignedAuthBundle")
        if not isinstance(self.audit, SignedAuditBatch):
            raise TypeError("audit must be a SignedAuditBatch")


@dataclass(frozen=True)
class SignedAuthAuditContinuation:
    """Cross-snapshot continuation of a signed auth audit, with no new domain.

    Merges the :class:`SignedAuthAuditBundle` of
    :meth:`AuditLog.signed_auth_audit_bundle` — selected entries'
    forward-secure tags and signed audit against one snapshot — with the
    :class:`SignedConsistency` of :meth:`AuditLog.signed_consistency` linking
    an earlier prefix to that very snapshot, so an offline receiver holding
    only a pre-trusted 32-byte Ed25519 public key can authenticate the
    selected entries, confirm the snapshot they belong to, and confirm that
    the audit continues an earlier signed snapshot by appends only — all in
    one artifact, without holding the :class:`AuditLog` and without any new
    signing message:

    - ``bundle``: the :class:`SignedAuthAuditBundle` carrying the signed
      stage-0 :class:`Verifier`, the selected ``(Entry, AuthTag)`` items and
      the selected entries' batch inclusion proof plus the new snapshot's
      signed checkpoint,
    - ``consistency``: the :class:`SignedConsistency` whose ``new``
      checkpoint attests exactly that new snapshot (all fields equal to the
      bundle's audit checkpoint) and whose ``old`` checkpoint attests the
      earlier prefix, joined by the Merkle consistency proof between them.

    Both packages must be minted under one hash algorithm, and the
    consistency proof's ``new`` checkpoint must be byte-for-byte the audit
    package's checkpoint. Whether all of that holds, and whether any of the
    embedded Ed25519 signatures verify, is left to
    :func:`verify_signed_auth_audit_continuation`.

    Instances are immutable, may be built positionally and compare by both
    fields. Only the container shape is validated here: ``bundle`` must be a
    :class:`SignedAuthAuditBundle` and ``consistency`` a
    :class:`SignedConsistency`, so a field of the wrong type raises
    TypeError.
    """

    bundle: SignedAuthAuditBundle
    consistency: SignedConsistency

    def __post_init__(self) -> None:
        if not isinstance(self.bundle, SignedAuthAuditBundle):
            raise TypeError("bundle must be a SignedAuthAuditBundle")
        if not isinstance(self.consistency, SignedConsistency):
            raise TypeError("consistency must be a SignedConsistency")


@dataclass(frozen=True)
class AnchoredContinuationChain:
    """A continuation chain persisted together with its two anchor checkpoints.

    Bundles the non-empty tuple of chained
    :class:`SignedAuthAuditContinuation` receipts with the two
    :class:`SignedRoot` checkpoints the chain is expected to span — the
    ``start`` checkpoint the first segment's ``consistency.old`` must equal
    and the ``end`` checkpoint the last segment's ``consistency.new`` must
    equal — so the continuation credentials and both endpoint anchors can be
    saved, transferred and restored across processes as one artifact:

    - ``receipts``: the non-empty tuple of
      :class:`SignedAuthAuditContinuation` receipts, in chain order,
    - ``start``: the :class:`SignedRoot` checkpoint the chain must start at,
    - ``end``: the :class:`SignedRoot` checkpoint the chain must end at.

    Instances are immutable, may be built positionally and compare by all
    three fields. Only the container shape is validated here: ``receipts``
    must be a non-empty ``tuple`` of :class:`SignedAuthAuditContinuation`
    objects and ``start``/``end`` must be :class:`SignedRoot` — a non-tuple
    or a wrongly typed field raises TypeError, an empty tuple raises
    ValueError. Whether the chain is internally continuous and actually
    spans the two anchors is left to :func:`inspect_anchored_continuations`.
    """

    receipts: tuple
    start: SignedRoot
    end: SignedRoot

    def __post_init__(self) -> None:
        if not isinstance(self.receipts, tuple):
            raise TypeError("receipts must be a non-empty tuple")
        if len(self.receipts) == 0:
            raise ValueError("receipts must be a non-empty tuple")
        for receipt in self.receipts:
            if not isinstance(receipt, SignedAuthAuditContinuation):
                raise TypeError(
                    "each receipt must be a SignedAuthAuditContinuation"
                )
        if not isinstance(self.start, SignedRoot):
            raise TypeError("start must be a SignedRoot")
        if not isinstance(self.end, SignedRoot):
            raise TypeError("end must be a SignedRoot")


@dataclass(frozen=True)
class AnchorSet:
    """Several :class:`AnchoredContinuationChain` packages as one artifact.

    Bundles the non-empty tuple of :class:`AnchoredContinuationChain`
    packages — one continuation chain landed in several separate batches,
    each batch persisted on its own — so the whole set can be saved,
    transferred and restored across processes as a single self-contained
    artifact and later diagnosed with :func:`inspect_anchor_set` or merged
    with :func:`merge_anchor_set`:

    - ``items``: the non-empty tuple of :class:`AnchoredContinuationChain`
      packages, in chain order.

    Instances are immutable, may be built positionally and compare by the
    field (and are hashable). Only the container shape is validated here:
    ``items`` must be a non-empty ``tuple`` holding only
    :class:`AnchoredContinuationChain` objects — a non-tuple or a wrongly
    typed element raises TypeError, an empty tuple raises ValueError.
    Whether the packages verify, join at equal anchors and splice into one
    chain is left to :func:`inspect_anchor_set`.
    """

    items: tuple

    def __post_init__(self) -> None:
        if not isinstance(self.items, tuple):
            raise TypeError("items must be a non-empty tuple")
        if len(self.items) == 0:
            raise ValueError("items must be a non-empty tuple")
        for item in self.items:
            if not isinstance(item, AnchoredContinuationChain):
                raise TypeError(
                    "each item must be an AnchoredContinuationChain"
                )


@dataclass(frozen=True)
class RotatedChain:
    """A cross-key continuation chain persisted with its rotations and anchors.

    Bundles a continuation chain whose segments may be signed by different
    keys — the non-empty tuple of chained
    :class:`SignedAuthAuditContinuation` receipts and the one-per-boundary
    signer rotations that authorize the hops — together with the two
    :class:`SignedRoot` checkpoints the whole chain is expected to span, so
    the continuation credentials, every :meth:`AuditLog.rotate_signer`
    handoff and both endpoint anchors can be saved, transferred and restored
    across processes as one artifact:

    - ``receipts``: the tuple of :class:`SignedAuthAuditContinuation`
      receipts (the segments), in chain order, at least two of them;
    - ``rotations``: the tuple of ``(old, new_key, new, auth)`` rotation
      four-tuples, exactly one fewer than the receipts — ``rotations[i]``
      connects segment ``i`` to segment ``i + 1``;
    - ``start``: the :class:`SignedRoot` checkpoint the first segment's
      ``consistency.old`` must equal;
    - ``end``: the :class:`SignedRoot` checkpoint the last segment's
      ``consistency.new`` must equal.

    Instances are immutable, may be built positionally and compare by all
    four fields. Only the container shape is validated here: ``receipts``
    and ``rotations`` must be tuples, there must be at least two receipts,
    the rotation count must be exactly ``len(receipts) - 1``, every receipt
    must be a :class:`SignedAuthAuditContinuation`, every rotation must be a
    ``tuple`` and ``start``/``end`` must be :class:`SignedRoot` — a non-tuple
    or a wrongly typed field raises TypeError, while fewer than two receipts
    or a rotation count other than one per boundary raises ValueError.
    Whether the rotations are genuine, the segments verify under the hopped
    keys and the chain actually spans the two anchors is left to
    :func:`inspect_rotated_anchors`.
    """

    receipts: tuple
    rotations: tuple
    start: SignedRoot
    end: SignedRoot

    def __post_init__(self) -> None:
        if not isinstance(self.receipts, tuple):
            raise TypeError("receipts must be a tuple")
        if not isinstance(self.rotations, tuple):
            raise TypeError("rotations must be a tuple of rotation records")
        if len(self.receipts) < 2:
            raise ValueError(
                "a rotated chain must contain at least two continuation "
                "receipts"
            )
        if len(self.rotations) != len(self.receipts) - 1:
            raise ValueError(
                "rotations must contain exactly one record per segment "
                "boundary "
                f"({len(self.rotations)} given for {len(self.receipts)} "
                "segments)"
            )
        for receipt in self.receipts:
            if not isinstance(receipt, SignedAuthAuditContinuation):
                raise TypeError(
                    "each receipt must be a SignedAuthAuditContinuation"
                )
        for rotation in self.rotations:
            if not isinstance(rotation, tuple):
                raise TypeError(
                    "each rotation must be a (old, new_key, new, auth) tuple"
                )
        if not isinstance(self.start, SignedRoot):
            raise TypeError("start must be a SignedRoot")
        if not isinstance(self.end, SignedRoot):
            raise TypeError("end must be a SignedRoot")


@dataclass(frozen=True)
class RotatedAnchorSet:
    """Several :class:`RotatedChain` packages and their bridges as one artifact.

    Bundles a non-empty tuple of :class:`RotatedChain` packages with the
    cross-package rotation bridges that hop between them, so the packages
    and bridges can be saved, transferred and restored across processes as a
    single self-contained artifact and later diagnosed with
    :func:`inspect_rotated_anchor_set` or merged with
    :func:`merge_rotated_anchor_set`:

    - ``items``: the non-empty tuple of :class:`RotatedChain` packages, in
      traversal order;
    - ``bridges``: the tuple of ``(old, new_key, new, auth)`` rotation
      four-tuples, exactly one fewer than the packages — ``bridges[i]``
      connects package ``i`` to package ``i + 1``.

    Instances are immutable, may be built positionally and compare by both
    fields (and are hashable). Only the container shape is validated here:
    both fields must be tuples, ``items`` must be non-empty and hold only
    :class:`RotatedChain` objects, ``bridges`` must hold only tuples, and
    the bridge count must be exactly ``len(items) - 1`` — a non-tuple
    field, a wrongly typed item or a non-tuple bridge raises TypeError,
    while an empty ``items`` tuple or a bridge count other than one per
    package boundary raises ValueError. Whether the bridges are genuine,
    join the package anchors and authorize one cross-signer chain is left
    to :func:`inspect_rotated_anchor_set`.
    """

    items: tuple
    bridges: tuple

    def __post_init__(self) -> None:
        if not isinstance(self.items, tuple):
            raise TypeError("items must be a non-empty tuple")
        if len(self.items) == 0:
            raise ValueError("items must be a non-empty tuple")
        for item in self.items:
            if not isinstance(item, RotatedChain):
                raise TypeError("each item must be a RotatedChain")
        if not isinstance(self.bridges, tuple):
            raise TypeError("bridges must be a tuple of rotation records")
        if len(self.bridges) != len(self.items) - 1:
            raise ValueError(
                "bridges must contain exactly one record per package "
                "boundary "
                f"({len(self.bridges)} given for {len(self.items)} "
                "packages)"
            )
        # The raw four-tuples returned by rotate_signer have no dedicated
        # class; check only their container type here, leaving length and
        # element validation to encode_rotation / verify_rotation, exactly
        # as inspect_rotated_anchor_set does.
        for bridge in self.bridges:
            if not isinstance(bridge, tuple):
                raise TypeError(
                    "each bridge must be a (old, new_key, new, auth) tuple"
                )


# Diagnostic codes of inspect_continuation_chain and inspect_anchors, each
# pinpointing the first segment or boundary at which the receipts fail to
# describe one chain: "verify" — a segment itself fails
# verify_signed_auth_audit_continuation; "growth" — a segment's old checkpoint
# is not strictly smaller than its new; "duplicate" — a segment repeats an
# earlier receipt; "link" — adjacent segments do not join at equal
# checkpoints; "start" — the first segment's old checkpoint is not the
# expected anchor; "end" — the last segment's new checkpoint is not the
# expected anchor. "link" names only the boundary between segments, it does
# not blame either one. "start" and "end" are reported by inspect_anchors
# only, never by inspect_continuation_chain. "anchor_link" is reported by
# inspect_anchor_set only: the end anchor of one persisted package does not
# equal the following package's start anchor, so the separately landed
# packages cannot be spliced into one chain; its index is the global
# position, across every package, of the later package's first receipt.
# "rotation_duplicate", "rotation" and "rotation_link" are reported by
# inspect_rotated_chain and inspect_rotated_anchor_set: a rotation equal to
# an earlier one, a rotation that fails verify_rotation, and a rotation whose
# checkpoints do not join the two segments on every field; within a single
# chain each is indexed at the later segment, and across separately landed
# packages at the global position of the later package's first segment.
_CHAIN_CODE_VERIFY = "verify"
_CHAIN_CODE_GROWTH = "growth"
_CHAIN_CODE_DUPLICATE = "duplicate"
_CHAIN_CODE_LINK = "link"
_CHAIN_CODE_START = "start"
_CHAIN_CODE_END = "end"
_CHAIN_CODE_ANCHOR_LINK = "anchor_link"
_CHAIN_CODE_ROTATION_DUPLICATE = "rotation_duplicate"
_CHAIN_CODE_ROTATION = "rotation"
_CHAIN_CODE_ROTATION_LINK = "rotation_link"
_CHAIN_CODES = frozenset(
    {
        _CHAIN_CODE_VERIFY,
        _CHAIN_CODE_GROWTH,
        _CHAIN_CODE_DUPLICATE,
        _CHAIN_CODE_LINK,
        _CHAIN_CODE_START,
        _CHAIN_CODE_END,
        _CHAIN_CODE_ANCHOR_LINK,
        _CHAIN_CODE_ROTATION_DUPLICATE,
        _CHAIN_CODE_ROTATION,
        _CHAIN_CODE_ROTATION_LINK,
    }
)


@dataclass(frozen=True)
class ContinuationChainReport:
    """Result of :func:`inspect_continuation_chain` and :func:`inspect_anchors`.

    A read-only diagnosis of a non-empty tuple of chained
    :class:`SignedAuthAuditContinuation` receipts, locating the **first**
    failed segment or broken boundary — only the earliest problem is ever
    reported:

    - ``ok``: the single source of truth, ``True`` exactly for a chain whose
      every segment verifies against the pre-trusted key, whose segments all
      grow strictly, which repeats no receipt and whose adjacent segments join
      on equal checkpoints — and, for :func:`inspect_anchors`, which
      additionally starts and ends exactly at the expected anchor
      checkpoints;
    - ``index``: the tuple position of the failing segment for ``"verify"``,
      ``"growth"`` and ``"duplicate"``, or the position of the segment whose
      ``old`` boundary does not join its predecessor's ``new`` for
      ``"link"``; for the anchor codes of :func:`inspect_anchors` it is ``0``
      for ``"start"`` and the last segment's position for ``"end"``;
      ``None`` exactly when ``ok`` is ``True``;
    - ``code``: one of ``"verify"``, ``"growth"``, ``"duplicate"``,
      ``"link"``, ``"start"``, ``"end"``, ``"anchor_link"``,
      ``"rotation_duplicate"``, ``"rotation"`` or ``"rotation_link"``
      describing that first failure; ``None`` exactly when ``ok`` is
      ``True``. A ``"link"`` code identifies the boundary only and blames
      neither segment. ``"start"`` and ``"end"`` are reported by
      :func:`inspect_anchors` only, and ``"anchor_link"`` — a boundary at
      which two separately persisted packages fail to join, its ``index``
      the global receipt position of the later package's first receipt — by
      :func:`inspect_anchor_set` only. ``"rotation_duplicate"``,
      ``"rotation"`` and ``"rotation_link"`` — a repeated rotation, a
      rotation that fails :func:`verify_rotation`, and a rotation whose two
      checkpoints fail to join the surrounding segments — are reported by
      :func:`inspect_rotated_chain`, indexed at the later segment's
      position, and by :func:`inspect_rotated_anchor_set`, where a repeated
      rotation means a bridge equal to an earlier cross-package bridge and
      every such code is indexed at the global position of the later
      package's first segment.

    Reports are immutable, may be built positionally and compare by all three
    fields. The success report is ``ContinuationChainReport(True, None, None)``.
    A non-bool ``ok`` or a non-integer, negative or bool ``index`` raises
    TypeError/ValueError like the other frozen reports; an unknown code string
    raises ValueError, and a failed report must carry both a code and an index.
    """

    ok: bool
    index: int | None
    code: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.ok, bool):
            raise TypeError("ok must be a bool")
        if self.ok:
            if self.index is not None or self.code is not None:
                raise ValueError(
                    "a successful report must carry index None and code None"
                )
            return
        if not isinstance(self.code, str):
            raise TypeError("code must be a string")
        if self.code not in _CHAIN_CODES:
            raise ValueError(
                f"unknown chain code {self.code!r}; expected one of "
                "'verify', 'growth', 'duplicate', 'link', 'start', 'end', "
                "'anchor_link', 'rotation_duplicate', 'rotation', "
                "'rotation_link'"
            )
        if not isinstance(self.index, int) or isinstance(self.index, bool):
            raise TypeError("index must be an integer or None")
        if self.index < 0:
            raise ValueError("index must be non-negative")


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

    def _resolve_auth_indices(self, indices: Any) -> list[int]:
        """Validate an :meth:`auth_batch` selection: distinct non-bool ints.

        Returns the indices sorted ascending; every index is also checked
        against the retained range up front, so a bad index aborts before the
        key evolves even once. Wrong index types raise TypeError; a non-
        iterable argument raises TypeError; duplicates raise ValueError; a
        non-retained index raises IndexError, exactly as :meth:`entry`.
        """
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
            if not self._retain_from <= index < len(self):
                raise IndexError(f"no retained entry at index {index}")
            selected.add(index)
            ordered.append(index)
        ordered.sort()
        return ordered

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
        ordered = self._resolve_auth_indices(indices)
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

    def export_signed_verifier(self, private_key: Any) -> SignedVerifier:
        """Export the stage-0 verification material once, Ed25519-signed.

        The signed-delivery counterpart of :meth:`export_verifier`: it shares
        the exact same eligibility — a keyed log, still at ``stage == 0`` and
        with the verifier not yet exported — and a successful call consumes
        that one export, so neither method can run again (and a prior
        :meth:`export_verifier` disqualifies this call). The returned
        :class:`SignedVerifier` bundles the stage-0 :class:`Verifier` with a
        64-byte Ed25519 signature a receiver checks against a pre-trusted
        public key via :func:`verify_signed_verifier`.

        ``private_key`` is a 32-byte Ed25519 seed; it is used for this one
        signature and is never stored, copied into log state or returned. The
        signed message is
        ``D || 0x01 || B(UTF-8(hash_name)) || B(key)`` with
        ``D = b"auditchain/signed-verifier/v1\\0"``, ``U`` an unsigned 8-byte
        big-endian integer and ``B(x) = U(len(x)) || x``; ``version`` is
        always 1. The signature authenticates the source only — it does not
        encrypt the stage-0 key — so callers must still protect the returned
        material. Every check (key mode, stage, one-shot eligibility and the
        seed) runs before the signature is made and the eligibility consumed:
        a failure leaves the key, stage and export eligibility untouched. A
        non-``bytes`` seed raises TypeError; a seed that is not 32 bytes,
        keyless mode, a non-zero stage or a repeat export raises ValueError.
        """
        key = self._require_key()
        signing_key = _load_ed25519_seed(private_key)
        if self._stage != 0 or self._verifier_exported:
            raise ValueError(
                "verifier can only be exported once and before the first key evolution"
            )
        verifier = Verifier(key=key, hash_name=self._hash_name)
        message = _signed_verifier_message(self._hash_name, key)
        signature = signing_key.sign(message)
        self._verifier_exported = True
        return SignedVerifier(
            version=_SIGNED_VERIFIER_VERSION,
            verifier=verifier,
            signature=signature,
        )

    def export_stage_verifier(self) -> StageVerifier:
        """Export the current stage's verification material, repeatably.

        Unlike the one-shot stage-0 :meth:`export_verifier`, this entry is
        available only *after* the log has evolved at least once
        (``stage > 0``); it is then read-only and may be called any number
        of times, always returning an equal :class:`StageVerifier` for the
        current stage (the material changes only as the log keeps
        evolving). It neither consumes the stage-0 export eligibility nor
        advances the stage, mints a tag or changes any log state. The
        returned material verifies tags minted at the current stage or
        later via :func:`verify_auth_stage`; a tag from an earlier stage —
        including every tag before the delivery point — never verifies.
        Calling it in keyless mode, or while still at the initial stage,
        raises ValueError and leaves the log untouched.
        """
        self._require_key()
        if self._stage == 0:
            raise ValueError(
                "stage verifier can only be exported after at least one key evolution"
            )
        key = self._key
        if key is None:  # a keyed log past stage 0 always holds a key
            raise ValueError(
                "authentication is disabled: construct AuditLog with a non-empty key"
            )
        return StageVerifier(
            stage=self._stage,
            key=key,
            hash_name=self._hash_name,
        )

    def export_signed_stage_verifier(self, private_key: Any) -> SignedStageVerifier:
        """Export the current stage's verification material, Ed25519-signed.

        The signed-delivery counterpart of :meth:`export_stage_verifier`: it
        shares the exact same eligibility — a keyed log that has evolved at
        least once (``stage > 0``) — and is likewise read-only and repeatable:
        it neither consumes the stage-0 export eligibility nor advances the
        stage, mints a tag or changes any log state, and repeated calls from
        the same state with the same seed return byte-identical
        :class:`SignedStageVerifier` values (Ed25519 signing is
        deterministic). The returned receipt bundles the current
        :class:`StageVerifier` with a 64-byte Ed25519 signature a receiver
        checks against a pre-trusted public key via
        :func:`verify_signed_stage_verifier`.

        ``private_key`` is a 32-byte Ed25519 seed; it is used for this one
        signature and is never stored, copied into log state or returned. The
        signed message is
        ``D || 0x01 || U(stage) || B(UTF-8(hash_name)) || B(key)`` with
        ``D = b"auditchain/signed-stage/v1\\0"``, ``U`` an unsigned 8-byte
        big-endian integer and ``B(x) = U(len(x)) || x``; ``version`` is
        always 1. The signature authenticates the source only — it does not
        encrypt the stage key — so callers must still protect the returned
        material. Every check (key mode, the seed and the stage) runs before
        the signature is made: a failure leaves the log untouched. A
        non-``bytes`` seed raises TypeError; a seed that is not 32 bytes,
        keyless mode or the initial stage raises ValueError.
        """
        key = self._require_key()
        signing_key = _load_ed25519_seed(private_key)
        if self._stage == 0:
            raise ValueError(
                "stage verifier can only be exported after at least one key evolution"
            )
        verifier = StageVerifier(
            stage=self._stage,
            key=key,
            hash_name=self._hash_name,
        )
        message = _signed_stage_verifier_message(self._stage, self._hash_name, key)
        signature = signing_key.sign(message)
        return SignedStageVerifier(
            version=_SIGNED_STAGE_VERSION,
            verifier=verifier,
            signature=signature,
        )

    def signed_auth_bundle(
        self,
        indices: Iterable[int],
        private_key: Any,
    ) -> SignedAuthBundle:
        """Atomically issue a :class:`SignedAuthBundle`.

        The one-call fusion of :meth:`export_signed_verifier` and
        :meth:`auth_batch`: it delivers the signed stage-0
        :class:`SignedVerifier` together with the forward-secure tags of the
        selected entries in ascending absolute-index order, so a caller never
        observes the half-committed states a separate export-then-batch
        sequence can leave (a consumed export with no tags, or an evolved key
        with no signed material). No new signing message is introduced: the
        embedded signature is byte-for-byte the Ed25519 signature
        :meth:`export_signed_verifier` makes over
        ``D || 0x01 || B(UTF-8(hash_name)) || B(key)`` with
        ``D = b"auditchain/signed-verifier/v1\\0"``, and the j-th tag reuses
        exactly :meth:`auth_batch`'s HMAC, 8-byte big-endian stage encoding
        and key evolution — the items are byte-for-byte what j consecutive
        ascending :meth:`auth` calls from the initial key produce, with the
        j-th tag at ``stage == j``.

        The same one-shot export eligibility as :meth:`export_signed_verifier`
        applies: a keyed log still at ``stage == 0`` with the verifier not yet
        exported. ``private_key`` is a 32-byte Ed25519 seed used for this one
        signature and never stored. Every check — key mode, seed, indices,
        duplicates, retained range, stage capacity and export eligibility —
        runs before the signature is made or any state changes: a failure
        consumes no export eligibility, never evolves the key and leaves
        stored tags, entries and every other log object untouched. An empty
        selection still delivers the signed stage-0 material (consuming the
        export) while the stage does not advance; a non-empty selection
        advances the stage exactly once per selected entry, exactly like
        :meth:`auth_batch`. A non-``bytes`` seed, a non-iterable
        ``indices`` or a non-integer/``bool`` index raises TypeError; a seed
        that is not 32 bytes, duplicate indices, stage-capacity exhaustion,
        keyless mode, a non-zero stage or a repeat export raises ValueError;
        a non-retained index raises IndexError, exactly as
        :meth:`auth_batch`.
        """
        key = self._require_key()
        signing_key = _load_ed25519_seed(private_key)
        ordered = self._resolve_auth_indices(indices)
        count = len(ordered)
        if self._stage + count >= _MAX_STAGE:
            raise ValueError("stage limit reached; cannot evolve the key that far")
        if self._stage != 0 or self._verifier_exported:
            raise ValueError(
                "verifier can only be exported once and before the first key evolution"
            )
        # All validation passed. Build the signature and every tag against
        # local variables first, so nothing below mutates the log until the
        # single commit at the end: a failure here cannot leave a consumed
        # export or a half-evolved key.
        verifier = Verifier(key=key, hash_name=self._hash_name)
        message = _signed_verifier_message(self._hash_name, key)
        receipt = SignedVerifier(
            version=_SIGNED_VERIFIER_VERSION,
            verifier=verifier,
            signature=signing_key.sign(message),
        )
        current_key = key
        items: list[tuple[Entry, AuthTag]] = []
        new_tags: dict[int, AuthTag] = {}
        for position, index in enumerate(ordered):
            stage = position
            entry = self._entries[index - self._retain_from]
            tag = AuthTag(
                stage=stage,
                tag=_auth_tag(stage, entry.entry_hash, current_key, self._hash_name),
            )
            items.append((entry, tag))
            new_tags[index] = tag
            current_key = _evolve_key(current_key, self._hash_name)
        bundle = SignedAuthBundle(
            verifier=receipt,
            hash_name=self._hash_name,
            items=tuple(items),
        )
        # Commit the export and the whole batch atomically.
        self._verifier_exported = True
        self._tags.update(new_tags)
        self._key = current_key
        self._stage += count
        return bundle

    def signed_stage_auth_bundle(
        self,
        indices: Iterable[int],
        private_key: Any,
    ) -> SignedStageAuthBundle:
        """Atomically issue a :class:`SignedStageAuthBundle`.

        The one-call fusion of :meth:`export_signed_stage_verifier` and
        :meth:`auth_batch`: it delivers the signed current-stage
        :class:`SignedStageVerifier` together with the forward-secure tags
        of the selected entries in ascending absolute-index order, so a
        caller never observes the half-committed states a separate
        export-then-batch sequence can leave. No new signing message is
        introduced: the embedded signature is byte-for-byte the Ed25519
        signature :meth:`export_signed_stage_verifier` makes over
        ``D || 0x01 || U(stage) || B(UTF-8(hash_name)) || B(key)`` with
        ``D = b"auditchain/signed-stage/v1\\0"``, and the j-th tag reuses
        exactly :meth:`auth_batch`'s HMAC, 8-byte big-endian stage encoding
        and key evolution — the items are byte-for-byte what j consecutive
        ascending :meth:`auth` calls from the current state produce, with
        the j-th tag at the delivery stage plus j.

        The same eligibility as :meth:`export_signed_stage_verifier`
        applies: a keyed log that has evolved at least once
        (``stage > 0``); the call is repeatable and consumes no one-shot
        eligibility. ``private_key`` is a 32-byte Ed25519 seed used for this
        one signature and never stored. Every check — key mode, seed,
        indices, duplicates, retained range, stage capacity and the
        post-evolution stage — runs before the signature is made or any
        state changes: a failure never evolves the key and leaves stored
        tags, entries and every other log object untouched. An empty
        selection still delivers the signed stage material while the stage
        does not advance; a non-empty selection advances the stage exactly
        once per selected entry, exactly like :meth:`auth_batch`. A
        non-``bytes`` seed, a non-iterable ``indices`` or a
        non-integer/``bool`` index raises TypeError; a seed that is not 32
        bytes, duplicate indices, stage-capacity exhaustion, keyless mode or
        the initial stage raises ValueError; a non-retained index raises
        IndexError, exactly as :meth:`auth_batch`.
        """
        key = self._require_key()
        signing_key = _load_ed25519_seed(private_key)
        ordered = self._resolve_auth_indices(indices)
        count = len(ordered)
        if self._stage + count >= _MAX_STAGE:
            raise ValueError("stage limit reached; cannot evolve the key that far")
        if self._stage == 0:
            raise ValueError(
                "stage verifier can only be exported after at least one key evolution"
            )
        # All validation passed. Build the signature and every tag against
        # local variables first, so nothing below mutates the log until the
        # single commit at the end: a failure here cannot leave a
        # half-evolved key.
        receipt = SignedStageVerifier(
            version=_SIGNED_STAGE_VERSION,
            verifier=StageVerifier(
                stage=self._stage,
                key=key,
                hash_name=self._hash_name,
            ),
            signature=signing_key.sign(
                _signed_stage_verifier_message(self._stage, self._hash_name, key)
            ),
        )
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
        bundle = SignedStageAuthBundle(
            verifier=receipt,
            hash_name=self._hash_name,
            items=tuple(items),
        )
        # Commit the whole batch atomically.
        self._tags.update(new_tags)
        self._key = current_key
        self._stage += count
        return bundle

    def signed_stage_auth_audit_bundle(
        self,
        indices: Iterable[int],
        private_key: Any,
        size: int | None = None,
    ) -> SignedStageAuthAuditBundle:
        """Atomically issue a :class:`SignedStageAuthAuditBundle`.

        The one-call fusion of :meth:`signed_stage_auth_bundle` and
        :meth:`signed_audit_batch`: it delivers the forward-secure tags and
        signed current-stage :class:`SignedStageVerifier` of the selected
        entries together with the signed batch audit of those same entries
        against one snapshot, so the receiver gets post-evolution
        authentication and snapshot evidence as a single artifact. Both
        halves are built from the same validated selection and the same
        ``size`` (defaulting to the current log length): the auth half is
        exactly what :meth:`signed_stage_auth_bundle` mints — the first tag
        sits at the delivery stage and the items run in ascending absolute-
        index order — and the audit half is exactly what
        :meth:`signed_audit_batch` mints — it shares the snapshot's last
        entry (index ``size - 1``) automatically even when ``indices`` does
        not list it — so the auth half never gains a signing domain for that
        last entry. No new signing message is introduced: the embedded
        Ed25519 signatures are byte-for-byte the ones
        :meth:`signed_stage_auth_bundle` and :meth:`signed_audit_batch`
        make.

        The same eligibility as :meth:`signed_stage_auth_bundle` applies: a
        keyed log that has evolved at least once (``stage > 0``); the call
        is read-only with respect to one-shot eligibility and repeatable,
        consuming no stage-0 export. ``private_key`` is a 32-byte Ed25519
        seed used for the two signatures and never stored. ``indices`` must
        be an iterable of distinct non-bool integers each satisfying
        ``retain_from <= index < size``; as with every batch audit, an empty
        selection is accepted (it still delivers the signed stage material,
        the stage does not advance and no key is evolved, and the audit
        still carries the last snapshot entry) and only the empty snapshot
        (``size == 0``) yields an audit with no entries. On success the
        stage advances exactly once per selected entry; the audit half is
        read-only.

        Every check — the seed, the resolved ``size``, the selection against
        the retained snapshot range, snapshot rebuildability, stage
        capacity and the post-evolution stage — runs before either
        signature is made or any state changes: a failure never evolves the
        key and leaves stored tags, entries and every other log object
        untouched. A non-``bytes`` seed, a non-iterable ``indices`` or a
        non-integer/``bool`` index raises TypeError; a seed that is not 32
        bytes, duplicate indices, a ``size`` outside ``0..len(log)``, an
        unrebuildable snapshot, stage-capacity exhaustion, keyless mode or
        the initial stage raises ValueError; an index outside the retained
        snapshot range raises IndexError.
        """
        # Resolve and validate size exactly as audit_batch does: wrong type
        # is TypeError, an out-of-range size ValueError, before the seed and
        # the selection are touched.
        size = self._resolve_size(size)
        if isinstance(size, bool):
            raise TypeError("size must be an integer")
        key = self._require_key()
        signing_key = _load_ed25519_seed(private_key)
        # Validate the selection against the snapshot range up front. The
        # audit's automatic last entry is added only to the audit selection;
        # the auth indices stay exactly the caller's distinct set, so the
        # auth side never tags an entry the caller did not select.
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
                raise IndexError(
                    f"no retained entry at index {index} in snapshot of size {size}"
                )
            selected.add(index)
        count = len(selected)
        if self._stage + count >= _MAX_STAGE:
            raise ValueError("stage limit reached; cannot evolve the key that far")
        if self._stage == 0:
            raise ValueError(
                "stage verifier can only be exported after at least one key evolution"
            )
        # A non-empty snapshot must still be rebuildable; the empty snapshot
        # is a content-free constant always available, even after a prune.
        if size > 0:
            self._require_retained_snapshot(size)
        # Build the read-only audit half first: it re-checks the seed and
        # adds size - 1 to the audit selection. It mutates nothing, so a
        # failure below cannot leave a half-evolved key — and all validation
        # above ran before either signature was made.
        audit = self.signed_audit_batch(tuple(sorted(selected)), private_key, size)
        # Build the auth half against local variables exactly as
        # signed_stage_auth_bundle does, reusing the loaded seed and the
        # validated selection, then commit the whole batch atomically.
        receipt = SignedStageVerifier(
            version=_SIGNED_STAGE_VERSION,
            verifier=StageVerifier(
                stage=self._stage,
                key=key,
                hash_name=self._hash_name,
            ),
            signature=signing_key.sign(
                _signed_stage_verifier_message(self._stage, self._hash_name, key)
            ),
        )
        current_key = key
        items: list[tuple[Entry, AuthTag]] = []
        new_tags: dict[int, AuthTag] = {}
        for position, index in enumerate(sorted(selected)):
            stage = self._stage + position
            entry = self._entries[index - self._retain_from]
            tag = AuthTag(
                stage=stage,
                tag=_auth_tag(stage, entry.entry_hash, current_key, self._hash_name),
            )
            items.append((entry, tag))
            new_tags[index] = tag
            current_key = _evolve_key(current_key, self._hash_name)
        auth = SignedStageAuthBundle(
            verifier=receipt,
            hash_name=self._hash_name,
            items=tuple(items),
        )
        # Commit the whole batch atomically.
        self._tags.update(new_tags)
        self._key = current_key
        self._stage += count
        return SignedStageAuthAuditBundle(auth=auth, audit=audit)

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

    def search_receipt(
        self,
        query: Any,
        start: int | None = None,
        stop: int | None = None,
        size: int | None = None,
    ) -> SearchReceipt:
        """Issue an offline :class:`SearchReceipt` for a content search.

        Runs the same lookup as :meth:`find` over the half-open range
        ``[start, stop)`` of the snapshot of the first ``size`` entries and
        freezes the outcome into a receipt that :func:`verify_search_receipt`
        can check without holding the log: the receipt records the hash
        algorithm, the snapshot ``size`` and its Merkle ``root``, the
        normalized ``query``, the searched range and one
        ``(Entry, inclusion_proof)`` pair per hit in ascending absolute
        index order, duplicates listed once per occurrence.

        ``query`` accepts ``bytes`` or ``str`` (UTF-8 encoded); anything
        else raises TypeError. ``size`` defaults to the current log length
        and the snapshot must still be rebuildable (a prefix released by
        :meth:`prune` is not). The range defaults to the retained segment
        ``[retain_from, size)``; explicit bounds must be non-bool integers
        satisfying ``retain_from <= start <= stop <= size``. Wrong types
        raise TypeError, out-of-range values or an unrebuildable snapshot
        ValueError. A search with no hits — and any empty snapshot — yields
        ``items == ()``. The call is read-only: entries, head,
        authentication state, Merkle roots and proofs are left untouched.
        """
        if isinstance(query, str):
            material = query.encode("utf-8")
        elif isinstance(query, bytes):
            material = query
        else:
            raise TypeError("query must be bytes or str")
        if size is not None and isinstance(size, bool):
            raise TypeError("size must be an integer")
        size = self._resolve_size(size)
        first = self._retain_from
        if start is None:
            start = first
        elif not isinstance(start, int) or isinstance(start, bool):
            raise TypeError("start must be an integer")
        if stop is None:
            stop = size
        elif not isinstance(stop, int) or isinstance(stop, bool):
            raise TypeError("stop must be an integer")
        if not first <= start <= stop <= size:
            raise ValueError(
                f"range must satisfy retain_from ({first}) <= start <= stop "
                f"<= size ({size})"
            )
        root = self.merkle_root(size)
        items = tuple(
            (self.entry(index), self.inclusion_proof(index, size))
            for index in self.find(material, start, stop)
        )
        return SearchReceipt(
            version=_SEARCH_RECEIPT_VERSION,
            hash_name=self._hash_name,
            size=size,
            root=root,
            query=material,
            start=start,
            stop=stop,
            items=items,
        )

    def encrypted_search_receipt(
        self,
        query: Any,
        key: Any,
        start: int | None = None,
        stop: int | None = None,
        size: int | None = None,
    ) -> EncryptedSearchReceipt:
        """Issue an offline :class:`EncryptedSearchReceipt` for a keyed search.

        Runs the same lookup as :meth:`find_encrypted` over the half-open
        range ``[start, stop)`` of the snapshot of the first ``size`` entries
        and freezes the outcome into a receipt that
        :func:`verify_encrypted_search_receipt` can check without holding the
        log: the receipt records the hash algorithm, the snapshot ``size`` and
        its Merkle ``root``, the normalized ``query``, the searched range and
        one ``(Entry, inclusion_proof)`` pair per hit in ascending absolute
        index order, duplicates listed once per occurrence. Each entry's
        payload remains the sealed encrypted-entry envelope; the key and the
        plaintext are never recorded.

        ``query`` accepts ``bytes`` or ``str`` (UTF-8 encoded); anything
        else raises TypeError. ``key`` must be exactly 32 ``bytes`` — a
        non-bytes value raises TypeError and a wrong length raises ValueError.
        ``size`` defaults to the current log length and the snapshot must
        still be rebuildable (a prefix released by :meth:`prune` is not). The
        range defaults to the retained segment ``[retain_from, size)``;
        explicit bounds must be non-bool integers satisfying
        ``retain_from <= start <= stop <= size``. Wrong types raise TypeError,
        out-of-range values or an unrebuildable snapshot ValueError. Plain
        entries and entries sealed under another key never hit, and a valid
        32-byte key that simply was not an append key yields ``items == ()``.
        A search with no hits — and any empty snapshot — yields ``items == ()``.
        The call is read-only: entries, head, authentication state, the
        encrypted locator index, Merkle roots and proofs are left untouched.
        """
        if isinstance(query, str):
            material = query.encode("utf-8")
        elif isinstance(query, bytes):
            material = query
        else:
            raise TypeError("query must be bytes or str")
        _check_key(key)
        if size is not None and isinstance(size, bool):
            raise TypeError("size must be an integer")
        size = self._resolve_size(size)
        first = self._retain_from
        if start is None:
            start = first
        elif not isinstance(start, int) or isinstance(start, bool):
            raise TypeError("start must be an integer")
        if stop is None:
            stop = size
        elif not isinstance(stop, int) or isinstance(stop, bool):
            raise TypeError("stop must be an integer")
        if not first <= start <= stop <= size:
            raise ValueError(
                f"range must satisfy retain_from ({first}) <= start <= stop "
                f"<= size ({size})"
            )
        root = self.merkle_root(size)
        items = tuple(
            (self.entry(index), self.inclusion_proof(index, size))
            for index in self.find_encrypted(material, key, start, stop)
        )
        return EncryptedSearchReceipt(
            version=_ENCRYPTED_SEARCH_VERSION,
            hash_name=self._hash_name,
            size=size,
            root=root,
            query=material,
            start=start,
            stop=stop,
            items=items,
        )

    def full_search_receipt(
        self,
        query: Any,
        start: int | None = None,
        stop: int | None = None,
        size: int | None = None,
    ) -> FullSearchReceipt:
        """Issue an offline :class:`FullSearchReceipt` proving completeness.

        Unlike :meth:`search_receipt`, whose receipt only attests that the
        listed hits are genuine, this receipt carries *every* entry of the
        half-open range ``[start, stop)`` of the snapshot of the first
        ``size`` entries, together with a single shared compact batch
        inclusion proof covering all of them. :func:`verify_full_search_receipt`
        can therefore check offline — without holding the log — that the
        listed entries are exactly the range's content, and its own
        comparison of each payload against the normalized ``query`` yields
        the complete hit set: no hit inside the range can be concealed or
        forged.

        ``query`` accepts ``bytes`` or ``str`` (UTF-8 encoded); anything
        else raises TypeError. ``size`` defaults to the current log length
        and the snapshot must still be rebuildable (a prefix released by
        :meth:`prune` is not). The range defaults to the retained segment
        ``[retain_from, size)``; explicit bounds must be non-bool integers
        satisfying ``retain_from <= start <= stop <= size``. Wrong types
        raise TypeError, out-of-range values or an unrebuildable snapshot
        ValueError. An empty range — and any empty snapshot — yields
        ``items == ()`` and ``proof == ()``. The call is read-only and may
        be repeated at will: entries, head, authentication state, Merkle
        roots and proofs are left untouched.
        """
        if isinstance(query, str):
            material = query.encode("utf-8")
        elif isinstance(query, bytes):
            material = query
        else:
            raise TypeError("query must be bytes or str")
        if size is not None and isinstance(size, bool):
            raise TypeError("size must be an integer")
        size = self._resolve_size(size)
        first = self._retain_from
        if start is None:
            start = first
        elif not isinstance(start, int) or isinstance(start, bool):
            raise TypeError("start must be an integer")
        if stop is None:
            stop = size
        elif not isinstance(stop, int) or isinstance(stop, bool):
            raise TypeError("stop must be an integer")
        if not first <= start <= stop <= size:
            raise ValueError(
                f"range must satisfy retain_from ({first}) <= start <= stop "
                f"<= size ({size})"
            )
        root = self.merkle_root(size)
        items = tuple(self.entry(index) for index in range(start, stop))
        if items:
            _, proof = self.batch_inclusion_proof(
                tuple(range(start, stop)), size
            )
        else:
            proof = ()
        return FullSearchReceipt(
            version=_FULL_SEARCH_VERSION,
            hash_name=self._hash_name,
            size=size,
            root=root,
            query=material,
            start=start,
            stop=stop,
            items=items,
            proof=proof,
        )

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

    def merkle_frontier(self, size: int | None = None) -> MerkleFrontier:
        """Freeze the public read-only Merkle frontier credential for a prefix.

        Returns a :class:`MerkleFrontier` covering the first ``size`` entries
        (defaulting to the whole log): the perfect-subtree
        ``(height, digest)`` pairs exactly at the set-bit heights of
        ``size``. The call is read-only; at the retain point the captured
        frontier is exactly the checkpoint frontier a prune keeps, and a
        later :func:`rebuild_merkle_root` against the retained entry hashes
        reconstructs the full snapshot root. ``size`` outside ``0..len(log)``
        or pointing into a pruned prefix raises ValueError (TypeError for a
        non-integer, ``bool`` included).
        """
        size = self._resolve_size(size)
        if size == 0:
            return MerkleFrontier(self._hash_name, 0, ())
        self._require_retained_snapshot(size)
        occupied = self._occupied_at(size)
        subtrees = tuple(
            (height, occupied[height]) for height in sorted(occupied)
        )
        return MerkleFrontier(self._hash_name, size, subtrees)

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

    def rotate_signer(
        self, old_seed: Any, new_seed: Any, size: int | None = None
    ) -> tuple[SignedRoot, bytes, SignedRoot, bytes]:
        """Rotate the snapshot signing key, old key authorizing the new one.

        Produces two :class:`SignedRoot` checkpoints over the very same
        snapshot — same ``hash_name``, ``size``, ``root`` and ``head`` — one
        signed by ``old_seed`` and one signed by ``new_seed``, plus an
        Ed25519 authorization by which a verifier holding only the old public
        key learns the new one offline:

        ``(old, new_key, new, auth)`` where ``new_key`` is the 32-byte raw
        public key of ``new_seed`` and ``auth`` is the 64-byte Ed25519
        signature of ``old_seed`` over
        ``D || 0x01 || B(old.signature) || B(new_key) || B(new.signature)``
        with ``D = b"auditchain/signer-rotation/v1\\0"``, ``U`` an unsigned
        8-byte big-endian integer and ``B(x) = U(len(x)) || x``. Verify the
        artifact offline, without holding the log, with
        :func:`verify_rotation`.

        ``size`` defaults to the current log length; it must be a non-bool
        integer in ``0..len(log)`` and the snapshot must still be rebuildable
        (a prefix released by :meth:`prune` is not). Neither seed is stored,
        copied into log state or returned; the :class:`SignedRoot` signature
        domain and interface are unchanged — ``old`` and ``new`` are exactly
        what :meth:`sign_root` produces for each seed and size. The call is
        read-only: entries, head, authentication state, Merkle roots and
        proofs are all left untouched. A non-``bytes`` seed raises TypeError;
        a seed that is not 32 bytes, a bool or otherwise out-of-range
        ``size``, or a pruned, unrebuildable snapshot raises ValueError.
        """
        old_signing_key = _load_ed25519_seed(old_seed)
        new_signing_key = _load_ed25519_seed(new_seed)
        if size is not None and isinstance(size, bool):
            raise TypeError("size must be an integer")
        # _resolve_size rejects the remaining non-integers; validate the seeds
        # first so neither snapshot is built from a bad key.
        size = self._resolve_size(size)
        if size == 0:
            root = _hash_parts(self._hash_name, _EMPTY_DOMAIN)
        else:
            self._require_retained_snapshot(size)
            root = self._fold_occupied(self._occupied_at(size))
        head = self._chain_head_at(size)
        message = _signed_root_message(self._hash_name, size, root, head)
        old_signature = old_signing_key.sign(message)
        new_signature = new_signing_key.sign(message)
        old = SignedRoot(
            version=_SIGNED_ROOT_VERSION,
            hash_name=self._hash_name,
            size=size,
            root=root,
            head=head,
            signature=old_signature,
        )
        new = SignedRoot(
            version=_SIGNED_ROOT_VERSION,
            hash_name=self._hash_name,
            size=size,
            root=root,
            head=head,
            signature=new_signature,
        )
        new_key = new_signing_key.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )
        auth = old_signing_key.sign(
            _rotation_message(old_signature, new_key, new_signature)
        )
        return old, new_key, new, auth

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

    def signed_audit_receipt(
        self,
        indices: Iterable[int],
        private_key: Any,
        size: int | None = None,
    ) -> SignedAuditReceipt:
        """Issue a :class:`SignedAuditReceipt`: a per-entry audit receipt
        sealed by a pre-trusted Ed25519 key.

        Convenience for the read-only sequence ``receipt =
        audit_receipt(indices, size)`` followed by ``checkpoint =
        sign_root(private_key, size)`` (``size`` defaulting to the current
        log length), bundled as one :class:`SignedAuditReceipt`. The receipt
        lets an offline receiver re-verify every selected entry and its
        inclusion proof against the snapshot Merkle root, and the checkpoint
        lets the same receiver confirm — using only a pre-trusted 32-byte
        Ed25519 public key — that the root and chain head were issued by the
        log holder; no new signing message is introduced, the checkpoint
        signs exactly the :meth:`sign_root` message. The call is read-only:
        it never changes entries, head, authentication state, Merkle roots or
        proofs, and a failure (an invalid selection, seed or size) raises
        before the bundle is constructed, leaving all state unchanged and
        never signing anything new.
        """
        # Validate and build the receipt first, exactly as the public method
        # does; sign_root() is read-only as well, so either failure leaves the
        # log untouched and nothing new is ever signed.
        receipt = self.audit_receipt(indices, size)
        checkpoint = self.sign_root(private_key, size)
        return SignedAuditReceipt(receipt=receipt, checkpoint=checkpoint)

    def signed_search_receipt(
        self,
        query: Any,
        private_key: Any,
        start: int | None = None,
        stop: int | None = None,
        size: int | None = None,
    ) -> SignedSearchReceipt:
        """Issue a :class:`SignedSearchReceipt`: a content-search receipt
        sealed by a pre-trusted Ed25519 key.

        Convenience for the read-only sequence ``receipt =
        search_receipt(query, start, stop, size)`` followed by ``checkpoint =
        sign_root(private_key, size)`` (the range defaulting to the retained
        segment and ``size`` to the current log length, exactly as
        :meth:`search_receipt`), bundled as one :class:`SignedSearchReceipt`.
        The receipt lets an offline receiver re-verify every listed hit and
        its inclusion proof against the snapshot Merkle root, and the
        checkpoint lets the same receiver confirm — using only a pre-trusted
        32-byte Ed25519 public key — that the root and chain head were issued
        by the log holder; no new signing message is introduced, the
        checkpoint signs exactly the :meth:`sign_root` message. The call is
        read-only and repeatable: it never changes entries, head,
        authentication state, Merkle roots or proofs, the same log state and
        seed yield byte-for-byte the same bundle, and a failure (an invalid
        query, range, seed or size) raises before the bundle is constructed,
        leaving all state unchanged and never signing anything new.
        """
        # Validate and build the receipt first, exactly as the public method
        # does; sign_root() is read-only as well, so either failure leaves the
        # log untouched and nothing new is ever signed.
        receipt = self.search_receipt(query, start, stop, size)
        checkpoint = self.sign_root(private_key, size)
        return SignedSearchReceipt(receipt=receipt, checkpoint=checkpoint)

    def signed_encrypted_search_receipt(
        self,
        query: Any,
        key: Any,
        private_key: Any,
        start: int | None = None,
        stop: int | None = None,
        size: int | None = None,
    ) -> SignedEncryptedSearchReceipt:
        """Issue a :class:`SignedEncryptedSearchReceipt`: a keyed-search
        receipt sealed by a pre-trusted Ed25519 key.

        Convenience for the read-only sequence ``receipt =
        encrypted_search_receipt(query, key, start, stop, size)`` followed by
        ``checkpoint = sign_root(private_key, size)`` (the range defaulting to
        the retained segment and ``size`` to the current log length, exactly
        as :meth:`encrypted_search_receipt`), bundled as one
        :class:`SignedEncryptedSearchReceipt`. The receipt lets an offline
        receiver holding the append key re-verify every listed hit and its
        inclusion proof against the snapshot Merkle root, and the checkpoint
        lets the same receiver confirm — using only a pre-trusted 32-byte
        Ed25519 public key — that the root and chain head were issued by the
        log holder; no new signing message is introduced, the checkpoint signs
        exactly the :meth:`sign_root` message. The call is read-only and
        repeatable: it never changes entries, head, authentication state, the
        encrypted locator index, Merkle roots or proofs, the same log state
        and seed yield byte-for-byte the same bundle, and a failure (an
        invalid query, key, range, seed or size) raises before the bundle is
        constructed, leaving all state unchanged and never signing anything
        new.
        """
        # Validate and build the receipt first, exactly as the public method
        # does; sign_root() is read-only as well, so either failure leaves the
        # log untouched and nothing new is ever signed.
        receipt = self.encrypted_search_receipt(query, key, start, stop, size)
        checkpoint = self.sign_root(private_key, size)
        return SignedEncryptedSearchReceipt(receipt=receipt, checkpoint=checkpoint)

    def signed_full_search_receipt(
        self,
        query: Any,
        private_key: Any,
        start: int | None = None,
        stop: int | None = None,
        size: int | None = None,
    ) -> SignedFullSearchReceipt:
        """Issue a :class:`SignedFullSearchReceipt`: a full-coverage search
        receipt sealed by a pre-trusted Ed25519 key.

        Convenience for the read-only sequence ``receipt =
        full_search_receipt(query, start, stop, size)`` followed by
        ``checkpoint = sign_root(private_key, size)`` (the range defaulting to
        the retained segment and ``size`` to the current log length, exactly
        as :meth:`full_search_receipt`), bundled as one
        :class:`SignedFullSearchReceipt`. The receipt lets an offline
        receiver authenticate every entry of the searched range against the
        snapshot Merkle root and derive the complete hit set itself, and the
        checkpoint lets the same receiver confirm — using only a pre-trusted
        32-byte Ed25519 public key — that the root and chain head were issued
        by the log holder; no new signing message is introduced, the
        checkpoint signs exactly the :meth:`sign_root` message. The call is
        read-only and repeatable: it never changes entries, head,
        authentication state, Merkle roots or proofs, the same log state and
        seed yield byte-for-byte the same bundle, and a failure (an invalid
        query, range, seed or size) raises before the bundle is constructed,
        leaving all state unchanged and never signing anything new.
        """
        # Validate and build the receipt first, exactly as the public method
        # does; sign_root() is read-only as well, so either failure leaves the
        # log untouched and nothing new is ever signed.
        receipt = self.full_search_receipt(query, start, stop, size)
        checkpoint = self.sign_root(private_key, size)
        return SignedFullSearchReceipt(receipt=receipt, checkpoint=checkpoint)

    def signed_auth_audit_bundle(
        self,
        indices: Iterable[int],
        private_key: Any,
        size: int | None = None,
    ) -> SignedAuthAuditBundle:
        """Atomically issue a :class:`SignedAuthAuditBundle`.

        The one-call fusion of :meth:`signed_auth_bundle` and
        :meth:`signed_audit_batch`: it delivers the forward-secure tags and
        signed stage-0 :class:`Verifier` of the selected entries together
        with the signed batch audit of those same entries against one
        snapshot, so the receiver gets authentication and snapshot evidence
        as a single artifact. Both halves are built from the same validated
        selection and the same ``size`` (defaulting to the current log
        length): the audit half is exactly what
        :meth:`signed_audit_batch` mints — it shares the snapshot's last
        entry (index ``size - 1``) automatically even when ``indices`` does
        not list it — and the auth half tags exactly the selected indices,
        so it never gains a signing domain for that last entry. No new
        signing message is introduced: the two embedded Ed25519 signatures
        are byte-for-byte the ones :meth:`signed_auth_bundle` and
        :meth:`signed_audit_batch` make.

        ``indices`` must be an iterable of distinct non-bool integers each
        satisfying ``retain_from <= index < size``; as with every batch
        audit, an empty selection is accepted (the audit still carries the
        last snapshot entry) and only the empty snapshot (``size == 0``)
        yields an audit with no entries. ``private_key`` is a 32-byte
        Ed25519 seed used for the two signatures and never stored. The
        selection, seed, ``size`` and snapshot rebuildability are all
        checked while building the read-only audit half, before the auth
        half's one-shot signature and commit; the auth half then re-checks
        stage capacity and the one-shot verifier-export eligibility. Either
        way a failure consumes no export eligibility, never evolves the key
        and leaves stored tags, entries and every other log object
        untouched. On success the auth half consumes the one-shot export
        and advances the stage exactly once per selected entry; the audit
        half is read-only. A non-``bytes`` seed, a non-iterable
        ``indices``, a non-integer/``bool`` index or a non-integer/``bool``
        ``size`` raises TypeError; a seed that is not 32 bytes, duplicate
        indices, a ``size`` outside ``0..len(log)``, an unrebuildable
        snapshot, stage-capacity exhaustion, keyless mode, a non-zero stage
        or a repeat export raises ValueError; an index outside the retained
        snapshot range raises IndexError.
        """
        # Resolve and validate size exactly as audit_batch does: wrong type
        # is TypeError, an out-of-range size ValueError, before the seed and
        # the selection are touched.
        size = self._resolve_size(size)
        if isinstance(size, bool):
            raise TypeError("size must be an integer")
        # Validate the selection against the snapshot range up front. The
        # audit's automatic last entry is added only to the audit selection;
        # the auth indices stay exactly the caller's distinct set, so the
        # auth side never tags an entry the caller did not select.
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
                raise IndexError(
                    f"no retained entry at index {index} in snapshot of size {size}"
                )
            selected.add(index)
        # Build the read-only audit half first: it also re-checks the
        # snapshot's rebuildability and adds size - 1 to the audit
        # selection. It mutates nothing, so a failure here leaves the
        # one-shot export and key state untouched.
        audit = self.signed_audit_batch(tuple(sorted(selected)), private_key, size)
        # signed_auth_bundle re-validates its own selection, seed, stage
        # capacity and one-shot eligibility, then commits atomically; feed
        # it exactly the caller's indices (without the audit's appended
        # last entry), in any order — it sorts them itself.
        auth = self.signed_auth_bundle(tuple(selected), private_key)
        return SignedAuthAuditBundle(auth=auth, audit=audit)

    def signed_auth_audit_continuation(
        self,
        old_size: int,
        indices: Iterable[int],
        private_key: Any,
        size: int | None = None,
    ) -> SignedAuthAuditContinuation:
        """Atomically issue a :class:`SignedAuthAuditContinuation`.

        The one-call continuation of :meth:`signed_auth_audit_bundle` across
        snapshots: it delivers that method's :class:`SignedAuthAuditBundle`
        for the selected entries against the ``size`` snapshot together with
        the :class:`SignedConsistency` linking an earlier ``old_size``
        prefix to that very snapshot, so an offline receiver holding only a
        pre-trusted 32-byte Ed25519 public key gets, in one artifact, the
        forward-secure authentication of the selected entries, the signed
        evidence that they belong to the new snapshot, and the signed
        evidence that the new snapshot continues the old one by appends
        only. No new signing message is introduced: the bundle's signatures
        are byte-for-byte the ones :meth:`signed_auth_audit_bundle` mints
        and the consistency's two checkpoints sign exactly the
        :meth:`sign_root` message, with ``proof`` byte-for-byte the
        :meth:`consistency_proof` output; in particular the consistency's
        ``new`` checkpoint is the audit checkpoint itself (all six fields
        equal), so it adds no signing domain.

        ``size`` defaults to the current log length and must be a non-bool
        integer satisfying ``0 <= size <= len(log)``; ``old_size`` must be a
        non-bool integer satisfying ``0 <= old_size <= size`` and both
        snapshots must still be rebuildable (a pruned-away prefix raises
        ValueError). ``indices`` must be an iterable of distinct non-bool
        integers each satisfying ``retain_from <= index < size``; an empty
        selection is allowed (the audit still carries the snapshot's last
        entry, and only the empty snapshot ``size == 0`` yields an audit
        with no entries). ``private_key`` is a 32-byte Ed25519 seed used for
        the signatures and never stored.

        Every check — the size chain, rebuildability of both snapshots, the
        selection, the seed, stage capacity and the one-shot verifier-export
        eligibility — runs before the auth half's one-shot signature and
        commit; the consistency and audit halves are read-only. A failure
        consumes no export eligibility, never evolves the key and leaves
        stored tags, entries and every other log object untouched. On
        success the auth half consumes the one-shot export and advances the
        stage exactly once per selected entry. A non-``bytes`` seed, a
        non-iterable ``indices``, a non-integer/``bool`` index, ``size`` or
        ``old_size`` raises TypeError; a seed that is not 32 bytes,
        duplicate indices, sizes outside ``0 <= old_size <= size <=
        len(log)``, an unrebuildable snapshot, stage-capacity exhaustion,
        keyless mode, a non-zero stage or a repeat export raises
        ValueError; an index outside the retained snapshot range raises
        IndexError.
        """
        # Resolve and validate the whole size chain first, exactly as the
        # two composed methods do: wrong types are TypeError, out-of-range
        # sizes ValueError, before the snapshots, the seed and the selection
        # are touched.
        size = self._resolve_size(size)
        if isinstance(size, bool):
            raise TypeError("size must be an integer")
        if not isinstance(old_size, int) or isinstance(old_size, bool):
            raise TypeError("old_size must be an integer")
        if not 0 <= old_size <= size:
            raise ValueError(f"old_size must satisfy 0 <= old_size <= {size}")
        # Both snapshots must still be rebuildable; the empty snapshot is a
        # content-free constant always available, even after a prune.
        if old_size > 0:
            self._require_retained_snapshot(old_size)
        if size > 0:
            self._require_retained_snapshot(size)
        # Validate the selection against the new snapshot range up front.
        # The audit's automatic last entry is added only to the audit
        # selection; the auth indices stay exactly the caller's distinct
        # set, so the auth side never tags an unselected entry.
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
                raise IndexError(
                    f"no retained entry at index {index} in snapshot of size {size}"
                )
            selected.add(index)
        # Build the read-only consistency half first: it re-checks the sizes,
        # both snapshots' rebuildability and the seed, and signs nothing the
        # composed methods do not sign; its new checkpoint is the very
        # checkpoint the audit half mints. It mutates nothing, so a failure
        # leaves the one-shot export and key state untouched.
        consistency = self.signed_consistency(old_size, private_key, new_size=size)
        # signed_auth_audit_bundle re-validates the selection, seed, snapshot,
        # stage capacity and one-shot eligibility, builds the read-only audit
        # half and only then commits the auth half atomically (feeding it
        # exactly the caller's indices, without the audit's appended last
        # entry); it sorts them itself.
        bundle = self.signed_auth_audit_bundle(
            tuple(sorted(selected)), private_key, size
        )
        return SignedAuthAuditContinuation(
            bundle=bundle, consistency=consistency
        )

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


def verify_search_receipt(receipt: Any) -> bool:
    """Verify a :class:`SearchReceipt` without holding the log.

    Recomputes every listed entry's digest from the entry's fields,
    re-verifies every inclusion proof against the receipt's snapshot root
    and compares every listed payload against the normalized query value; a
    structurally valid receipt whose entry content, proofs, root or listed
    payloads do not match returns False. Verification only attests that the
    listed hits are genuine — it makes no claim about whether the result
    set is complete, so a receipt listing fewer hits than the log would
    have found is not a failure. Malformed input raises TypeError or
    ValueError exactly as :class:`SearchReceipt` construction does (a
    non-:class:`SearchReceipt` argument, or a receipt whose frozen fields
    were bypassed into an illegal shape, raises the same errors).
    """
    if not isinstance(receipt, SearchReceipt):
        raise TypeError("receipt must be a SearchReceipt")
    # Re-validate every field even for a receipt built with
    # object.__setattr__ bypassing the frozen constructor, so structural
    # corruption raises exactly as the constructor would.
    checked = SearchReceipt(
        receipt.version,
        receipt.hash_name,
        receipt.size,
        receipt.root,
        receipt.query,
        receipt.start,
        receipt.stop,
        receipt.items,
    )
    for entry, proof in checked.items:
        recomputed = entry_digest(
            entry.index,
            entry.previous_hash,
            entry.payload,
            hash_name=checked.hash_name,
        )
        if not hmac.compare_digest(recomputed, entry.entry_hash):
            return False
        if entry.payload != checked.query:
            return False
        if not verify_inclusion(
            entry.entry_hash,
            entry.index,
            checked.size,
            checked.root,
            proof,
            hash_name=checked.hash_name,
        ):
            return False
    return True


def verify_encrypted_search_receipt(receipt: Any, key: Any) -> bool:
    """Verify an :class:`EncryptedSearchReceipt` without holding the log.

    Recomputes every listed entry's digest from the entry's fields,
    re-verifies every inclusion proof against the receipt's snapshot root and
    then decrypts each sealed envelope with ``key`` via :func:`decrypt_entry`,
    comparing the recovered plaintext byte-for-byte against the normalized
    query value; a structurally valid receipt whose entry content, proofs,
    root or envelopes do not match, or whose ``key`` is not the append key,
    returns False. Verification only attests that the listed hits are genuine
    — it makes no claim about whether the result set is complete, so a
    receipt listing fewer hits than the log would have found is not a
    failure. Plain entries listed as hits fail to decrypt and therefore fail
    verification.

    ``key`` must be exactly 32 ``bytes`` — a non-bytes value raises TypeError
    and a wrong length raises ValueError. A receipt that is not an
    :class:`EncryptedSearchReceipt` raises TypeError; a receipt whose frozen
    fields were bypassed into an illegal shape (wrong types, an unknown hash
    algorithm, an out-of-range range or size, digest-width mismatches,
    non-ascending items) raises the same TypeError or ValueError construction
    would. Wrong-key or content failures return False rather than raising.
    """
    if not isinstance(receipt, EncryptedSearchReceipt):
        raise TypeError("receipt must be an EncryptedSearchReceipt")
    _check_key(key)
    # Re-validate every field even for a receipt built with
    # object.__setattr__ bypassing the frozen constructor, so structural
    # corruption raises exactly as the constructor would.
    checked = EncryptedSearchReceipt(
        receipt.version,
        receipt.hash_name,
        receipt.size,
        receipt.root,
        receipt.query,
        receipt.start,
        receipt.stop,
        receipt.items,
    )
    for entry, proof in checked.items:
        recomputed = entry_digest(
            entry.index,
            entry.previous_hash,
            entry.payload,
            hash_name=checked.hash_name,
        )
        if not hmac.compare_digest(recomputed, entry.entry_hash):
            return False
        if not verify_inclusion(
            entry.entry_hash,
            entry.index,
            checked.size,
            checked.root,
            proof,
            hash_name=checked.hash_name,
        ):
            return False
        try:
            plaintext = decrypt_entry(entry, key, hash_name=checked.hash_name)
        except ValueError:
            # Wrong key, a plain/non-envelope payload, an entry-digest
            # mismatch or an AEAD authentication failure is a false hit, not
            # an error: verification returns False rather than raising.
            return False
        if not hmac.compare_digest(plaintext, checked.query):
            return False
    return True


def verify_full_search_receipt(receipt: Any) -> bool:
    """Verify a :class:`FullSearchReceipt` without holding the log.

    Recomputes every listed entry's digest from the entry's fields and
    re-verifies the single shared compact batch inclusion proof against the
    receipt's snapshot root via :func:`verify_batch_inclusion`. Because the
    receipt carries every entry of the searched range ``[start, stop)`` —
    the constructor rejects an incomplete coverage, duplicates and
    out-of-order indices — the caller's own comparison of each payload
    against the normalized query (``entry.payload == receipt.query``) then
    yields the complete hit set: unlike :func:`verify_search_receipt`, a
    concealed hit is a structural failure, not a silent omission.

    An empty range (``items == ()`` and ``proof == ()``) attests no
    content; an empty snapshot (``size == 0``) additionally only accepts
    the canonical empty-tree root. A structurally valid receipt whose entry
    content, proof or root does not match returns False. Malformed input
    raises TypeError or ValueError exactly as :class:`FullSearchReceipt`
    construction does (a non-:class:`FullSearchReceipt` argument, or a
    receipt whose frozen fields were bypassed into an illegal shape, raises
    the same errors; a proof node count that does not fit the listed
    indices and ``size`` raises ValueError as in
    :func:`verify_batch_inclusion`). The call is read-only.
    """
    if not isinstance(receipt, FullSearchReceipt):
        raise TypeError("receipt must be a FullSearchReceipt")
    # Re-validate every field even for a receipt built with
    # object.__setattr__ bypassing the frozen constructor, so structural
    # corruption raises exactly as the constructor would.
    checked = FullSearchReceipt(
        receipt.version,
        receipt.hash_name,
        receipt.size,
        receipt.root,
        receipt.query,
        receipt.start,
        receipt.stop,
        receipt.items,
        receipt.proof,
    )
    if not checked.items:
        if checked.size == 0:
            return hmac.compare_digest(
                checked.root, _hash_parts(checked.hash_name, _EMPTY_DOMAIN)
            )
        # An empty range of a non-empty snapshot attests no content; the
        # recorded root cannot be checked without evidence, exactly as for
        # a no-hit SearchReceipt.
        return True
    entry_hashes: list[bytes] = []
    for entry in checked.items:
        recomputed = entry_digest(
            entry.index,
            entry.previous_hash,
            entry.payload,
            hash_name=checked.hash_name,
        )
        if not hmac.compare_digest(recomputed, entry.entry_hash):
            return False
        entry_hashes.append(entry.entry_hash)
    indices = tuple(entry.index for entry in checked.items)
    return verify_batch_inclusion(
        indices,
        tuple(entry_hashes),
        checked.size,
        checked.root,
        checked.proof,
        hash_name=checked.hash_name,
    )


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


def _check_search_receipt_proofs(receipt: SearchReceipt) -> None:
    for entry, proof in receipt.items:
        expected = _proof_level_count(entry.index, receipt.size)
        if len(proof) != expected:
            raise ValueError(
                f"proof for index {entry.index} must have {expected} levels, "
                f"got {len(proof)}"
            )


def encode_search_receipt(receipt: Any) -> bytes:
    """Encode a :class:`SearchReceipt` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/search-receipt/v1\\0"``; every integer is an unsigned
    8-byte big-endian value and every blob is a u64 byte length followed by
    the raw bytes (a zero length is an all-zero u64). Fields appear
    strictly in the order ``version`` (always 1), ``hash_name`` (UTF-8
    blob), ``size``, ``root`` blob, ``query`` blob, ``start``, ``stop`` and
    item count; each item is ``Entry.index``, ``payload`` blob,
    ``previous_hash`` blob, ``entry_hash`` blob, proof count and one blob
    per proof digest, with nothing omitted, reordered or appended.
    ``receipt`` must be a :class:`SearchReceipt` (anything else raises
    TypeError); every field is re-validated exactly as the constructor
    would, so a receipt whose frozen fields were bypassed into an illegal
    shape raises the same TypeError or ValueError, and a proof whose level
    count does not fit its ``(index, size)`` raises ValueError. Encoding is
    read-only and deterministic: re-encoding a decoded receipt reproduces
    the original bytes exactly.
    """
    if not isinstance(receipt, SearchReceipt):
        raise TypeError("receipt must be a SearchReceipt")
    checked = SearchReceipt(
        receipt.version,
        receipt.hash_name,
        receipt.size,
        receipt.root,
        receipt.query,
        receipt.start,
        receipt.stop,
        receipt.items,
    )
    _check_search_receipt_proofs(checked)
    parts = [
        _SEARCH_RECEIPT_MAGIC,
        _encode_u64(checked.version, "version"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_u64(checked.size, "size"),
        _encode_blob(bytes(checked.root)),
        _encode_blob(checked.query),
        _encode_u64(checked.start, "start"),
        _encode_u64(checked.stop, "stop"),
        _encode_u64(len(checked.items), "items count"),
    ]
    for entry, proof in checked.items:
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(bytes(entry.payload)))
        parts.append(_encode_blob(bytes(entry.previous_hash)))
        parts.append(_encode_blob(bytes(entry.entry_hash)))
        parts.append(_encode_u64(len(proof), "proof count"))
        for digest in proof:
            parts.append(_encode_blob(bytes(digest)))
    return b"".join(parts)


def decode_search_receipt(data: Any) -> SearchReceipt:
    """Decode bytes produced by :func:`encode_search_receipt`.

    ``data`` must be ``bytes`` (anything else raises TypeError). A bad
    magic, a version other than 1, invalid UTF-8 in ``hash_name``, an
    unknown hash algorithm, truncation, trailing bytes, an oversized blob
    length, digest-width mismatches, an out-of-range or inverted search
    range, non-ascending or duplicate item indices, an item index outside
    the recorded range, or a proof whose level count does not fit its
    ``(index, size)`` all raise ValueError. The decoded receipt's fields
    equal the originally encoded ones and satisfy
    :func:`verify_search_receipt` whenever the original did; a structurally
    valid receipt whose content does not match still decodes and only fails
    verification. The call is read-only.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SEARCH_RECEIPT_MAGIC):
        raise ValueError("not an auditchain search-receipt encoding")
    offset = len(_SEARCH_RECEIPT_MAGIC)

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
    query = read_blob("query")
    start = read_u64("start")
    stop = read_u64("stop")
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
    receipt = SearchReceipt(
        version=version,
        hash_name=hash_name,
        size=size,
        root=root,
        query=query,
        start=start,
        stop=stop,
        items=tuple(items),
    )
    _check_search_receipt_proofs(receipt)
    return receipt


def encode_encrypted_search_receipt(receipt: Any) -> bytes:
    """Encode an :class:`EncryptedSearchReceipt` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/encrypted-search/v1\\0"``; every integer is an unsigned
    8-byte big-endian value and every blob is a u64 byte length followed by
    the raw bytes (a zero length is an all-zero u64). Fields appear
    strictly in the order ``version`` (always 1), ``hash_name`` (UTF-8
    blob), ``size``, ``root`` blob, ``query`` blob, ``start``, ``stop`` and
    item count; each item is ``Entry.index``, ``payload`` blob (the sealed
    encrypted-entry envelope, written verbatim), ``previous_hash`` blob,
    ``entry_hash`` blob, proof count and one blob per proof digest, with
    nothing omitted, reordered or appended — the layout is identical to
    :func:`encode_search_receipt` apart from the magic. ``receipt`` must be
    an :class:`EncryptedSearchReceipt` (anything else raises TypeError);
    every field is re-validated exactly as the constructor would, so a
    receipt whose frozen fields were bypassed into an illegal shape raises
    the same TypeError or ValueError, and a proof whose level count does not
    fit its ``(index, size)`` raises ValueError. Encoding is read-only and
    deterministic: re-encoding a decoded receipt reproduces the original
    bytes exactly. No signing material is introduced and no wire format of
    the other layers changes.
    """
    if not isinstance(receipt, EncryptedSearchReceipt):
        raise TypeError("receipt must be an EncryptedSearchReceipt")
    checked = EncryptedSearchReceipt(
        receipt.version,
        receipt.hash_name,
        receipt.size,
        receipt.root,
        receipt.query,
        receipt.start,
        receipt.stop,
        receipt.items,
    )
    _check_search_receipt_proofs(checked)
    parts = [
        _ENCRYPTED_SEARCH_MAGIC,
        _encode_u64(checked.version, "version"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_u64(checked.size, "size"),
        _encode_blob(bytes(checked.root)),
        _encode_blob(checked.query),
        _encode_u64(checked.start, "start"),
        _encode_u64(checked.stop, "stop"),
        _encode_u64(len(checked.items), "items count"),
    ]
    for entry, proof in checked.items:
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(bytes(entry.payload)))
        parts.append(_encode_blob(bytes(entry.previous_hash)))
        parts.append(_encode_blob(bytes(entry.entry_hash)))
        parts.append(_encode_u64(len(proof), "proof count"))
        for digest in proof:
            parts.append(_encode_blob(bytes(digest)))
    return b"".join(parts)


def decode_encrypted_search_receipt(data: Any) -> EncryptedSearchReceipt:
    """Decode bytes produced by :func:`encode_encrypted_search_receipt`.

    ``data`` must be ``bytes`` (anything else raises TypeError). A bad
    magic, a version other than 1, invalid UTF-8 in ``hash_name``, an
    unknown hash algorithm, truncation, trailing bytes, an oversized blob
    length, digest-width mismatches, an out-of-range or inverted search
    range, non-ascending or duplicate item indices, an item index outside
    the recorded range, or a proof whose level count does not fit its
    ``(index, size)`` all raise ValueError. The decoded receipt's fields
    equal the originally encoded ones and satisfy
    :func:`verify_encrypted_search_receipt` whenever the original did; a
    structurally valid receipt whose sealed content does not decrypt to the
    query still decodes and only fails verification. The bytes are consumed
    exactly, with no trailing data accepted. The call is read-only.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_ENCRYPTED_SEARCH_MAGIC):
        raise ValueError("not an auditchain encrypted-search encoding")
    offset = len(_ENCRYPTED_SEARCH_MAGIC)

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
    query = read_blob("query")
    start = read_u64("start")
    stop = read_u64("stop")
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
    receipt = EncryptedSearchReceipt(
        version=version,
        hash_name=hash_name,
        size=size,
        root=root,
        query=query,
        start=start,
        stop=stop,
        items=tuple(items),
    )
    _check_search_receipt_proofs(receipt)
    return receipt


def _check_full_search_receipt_proof(receipt: FullSearchReceipt) -> None:
    if not receipt.items:
        if receipt.proof:
            raise ValueError("an empty range receipt must carry an empty proof")
        return
    indices = tuple(entry.index for entry in receipt.items)
    expected = _batch_proof_length(indices, 0, len(indices), 0, receipt.size)
    if len(receipt.proof) != expected:
        raise ValueError(
            f"proof must have {expected} nodes for these indices and size, "
            f"got {len(receipt.proof)}"
        )


def encode_full_search_receipt(receipt: Any) -> bytes:
    """Encode a :class:`FullSearchReceipt` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/full-search/v1\\0"``; every integer is an unsigned
    8-byte big-endian value and every blob is a u64 byte length followed by
    the raw bytes (a zero length is an all-zero u64). Fields appear
    strictly in the order ``version`` (always 1), ``hash_name`` (UTF-8
    blob), ``size``, ``root`` blob, ``query`` blob, ``start``, ``stop``,
    item count, one item per listed entry — ``Entry.index``, ``payload``
    blob, ``previous_hash`` blob, ``entry_hash`` blob, exactly as entries
    are written by :func:`encode_audit_receipt` — and finally the shared
    proof node count followed by one blob per proof digest, with nothing
    omitted, reordered or appended. ``receipt`` must be a
    :class:`FullSearchReceipt` (anything else raises TypeError); every
    field is re-validated exactly as the constructor would, so a receipt
    whose frozen fields were bypassed into an illegal shape raises the same
    TypeError or ValueError, and a shared proof whose node count does not
    fit the listed indices and ``size`` raises ValueError. Encoding is
    read-only and deterministic: re-encoding a decoded receipt reproduces
    the original bytes exactly.
    """
    if not isinstance(receipt, FullSearchReceipt):
        raise TypeError("receipt must be a FullSearchReceipt")
    checked = FullSearchReceipt(
        receipt.version,
        receipt.hash_name,
        receipt.size,
        receipt.root,
        receipt.query,
        receipt.start,
        receipt.stop,
        receipt.items,
        receipt.proof,
    )
    _check_full_search_receipt_proof(checked)
    parts = [
        _FULL_SEARCH_MAGIC,
        _encode_u64(checked.version, "version"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_u64(checked.size, "size"),
        _encode_blob(bytes(checked.root)),
        _encode_blob(checked.query),
        _encode_u64(checked.start, "start"),
        _encode_u64(checked.stop, "stop"),
        _encode_u64(len(checked.items), "items count"),
    ]
    for entry in checked.items:
        parts.append(_encode_u64(entry.index, "entry.index"))
        parts.append(_encode_blob(bytes(entry.payload)))
        parts.append(_encode_blob(bytes(entry.previous_hash)))
        parts.append(_encode_blob(bytes(entry.entry_hash)))
    parts.append(_encode_u64(len(checked.proof), "proof count"))
    for digest in checked.proof:
        parts.append(_encode_blob(bytes(digest)))
    return b"".join(parts)


def decode_full_search_receipt(data: Any) -> FullSearchReceipt:
    """Decode bytes produced by :func:`encode_full_search_receipt`.

    ``data`` must be ``bytes`` (anything else raises TypeError). A bad
    magic, a version other than 1, invalid UTF-8 in ``hash_name``, an
    unknown hash algorithm, truncation, trailing bytes, an oversized blob
    length, digest-width mismatches, an out-of-range or inverted search
    range, non-ascending or duplicate item indices, an item index outside
    the recorded range, an incomplete coverage of the searched range, a
    non-empty proof on an empty range, or a shared proof whose node count
    does not fit the listed indices and ``size`` all raise ValueError. The
    decoded receipt's fields equal the originally encoded ones and satisfy
    :func:`verify_full_search_receipt` whenever the original did; a
    structurally valid receipt whose content does not match still decodes
    and only fails verification. The call is read-only.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_FULL_SEARCH_MAGIC):
        raise ValueError("not an auditchain full-search encoding")
    offset = len(_FULL_SEARCH_MAGIC)

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
    query = read_blob("query")
    start = read_u64("start")
    stop = read_u64("stop")
    item_count = read_u64("items count")
    items = []
    for _ in range(item_count):
        index = read_u64("entry.index")
        payload = read_blob("entry.payload")
        previous_hash = read_blob("entry.previous_hash")
        entry_hash = read_blob("entry.entry_hash")
        items.append(Entry(index, payload, previous_hash, entry_hash))
    proof_count = read_u64("proof count")
    proof = tuple(read_blob("proof element") for _ in range(proof_count))
    if offset != len(data):
        raise ValueError("trailing bytes after the receipt")
    receipt = FullSearchReceipt(
        version=version,
        hash_name=hash_name,
        size=size,
        root=root,
        query=query,
        start=start,
        stop=stop,
        items=tuple(items),
        proof=proof,
    )
    _check_full_search_receipt_proof(receipt)
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


def encode_batch_inclusion_proof(credential: Any) -> bytes:
    """Encode a :class:`BatchInclusionProof` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/batch-inclusion/v1\\0"``; indices and sizes are unsigned
    8-byte big-endian integers and every other field is a u64 byte length
    followed by the raw bytes (a zero length is an all-zero u64). Fields
    appear strictly in credential order, with nothing omitted, reordered or
    appended: ``version`` (always 1), ``hash_name`` (UTF-8 blob), the
    ``indices`` count followed by one u64 per index, the ``entry_hashes``
    count followed by one blob per digest, ``size``, the ``root`` blob, and
    the ``proof`` node count followed by one blob per node in generation
    order.

    ``credential`` must be a :class:`BatchInclusionProof` — anything else, or
    a field of the wrong type (including fields overwritten through
    ``object.__setattr__`` bypassing the frozen constructor), raises
    TypeError; an unknown hash algorithm, a digest of the wrong width,
    non-ascending or out-of-range indices, mismatched ``indices`` /
    ``entry_hashes`` lengths or a ``size`` outside the u64 range raise
    ValueError. The call is read-only and deterministic: it never mutates the
    credential, and re-encoding a decoded one reproduces the original bytes
    exactly, so a proof can be persisted and restored in another process and
    handed straight to :func:`verify_batch_inclusion`.
    """
    if not isinstance(credential, BatchInclusionProof):
        raise TypeError("credential must be a BatchInclusionProof")
    # Re-validate every field even for a credential built with
    # object.__setattr__ bypassing the frozen constructor, so structural
    # corruption raises exactly as the constructor would.
    checked = BatchInclusionProof(
        credential.hash_name,
        credential.indices,
        credential.entry_hashes,
        credential.size,
        credential.root,
        credential.proof,
    )
    parts = [
        _BATCH_INCLUSION_MAGIC,
        _encode_u64(_BATCH_INCLUSION_VERSION, "version"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_u64(len(checked.indices), "indices count"),
    ]
    for index in checked.indices:
        parts.append(_encode_u64(index, "index"))
    parts.append(_encode_u64(len(checked.entry_hashes), "entry_hashes count"))
    for entry_hash in checked.entry_hashes:
        parts.append(_encode_blob(entry_hash))
    parts.append(_encode_u64(checked.size, "size"))
    parts.append(_encode_blob(checked.root))
    parts.append(_encode_u64(len(checked.proof), "proof count"))
    for node in checked.proof:
        parts.append(_encode_blob(node))
    return b"".join(parts)


def decode_batch_inclusion_proof(data: Any) -> BatchInclusionProof:
    """Decode bytes produced by :func:`encode_batch_inclusion_proof`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown or non-fixed-output hash
    algorithm, truncation, trailing bytes, an oversized blob length, a digest
    whose width does not match the named algorithm, empty, non-ascending,
    duplicate or out-of-range indices, mismatched ``indices`` /
    ``entry_hashes`` lengths or a non-positive ``size`` raise ValueError. The
    whole input is consumed exactly; the returned credential is a frozen
    :class:`BatchInclusionProof` whose fields equal the originally encoded
    ones, re-encoding it reproduces the original bytes exactly, and it can be
    passed to :func:`verify_batch_inclusion` in another process exactly as
    the original could.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_BATCH_INCLUSION_MAGIC):
        raise ValueError("not an auditchain batch-inclusion-proof encoding")
    offset = len(_BATCH_INCLUSION_MAGIC)

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
    if version != _BATCH_INCLUSION_VERSION:
        raise ValueError("unsupported batch-inclusion-proof version")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    index_count = read_u64("indices count")
    indices = tuple(read_u64("index") for _ in range(index_count))
    entry_hash_count = read_u64("entry_hashes count")
    entry_hashes = tuple(read_blob("entry_hash") for _ in range(entry_hash_count))
    size = read_u64("size")
    root = read_blob("root")
    proof_count = read_u64("proof count")
    proof = tuple(read_blob("proof element") for _ in range(proof_count))
    if offset != len(data):
        raise ValueError("trailing bytes after the batch inclusion proof")
    return BatchInclusionProof(
        hash_name=hash_name,
        indices=indices,
        entry_hashes=entry_hashes,
        size=size,
        root=root,
        proof=proof,
    )


def encode_inclusion_proof(credential: Any) -> bytes:
    """Encode an :class:`InclusionProof` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/inclusion/v1\\0"``; indices and sizes are unsigned 8-byte
    big-endian integers and every other field is a u64 byte length followed
    by the raw bytes (a zero length is an all-zero u64). Fields appear
    strictly in credential order, with nothing omitted, reordered or
    appended: ``version`` (always 1), ``hash_name`` (UTF-8 blob), ``index``,
    ``size``, the ``entry_hash`` blob, the ``root`` blob, and the ``proof``
    node count followed by one blob per node in generation order.

    ``credential`` must be an :class:`InclusionProof` — anything else, or a
    field of the wrong type (including fields overwritten through
    ``object.__setattr__`` bypassing the frozen constructor), raises
    TypeError; an unknown hash algorithm, a digest of the wrong width, a
    negative or out-of-range ``index``, or a non-positive or oversized
    ``size`` raises ValueError. The call is read-only and deterministic: it
    never mutates the credential, and re-encoding a decoded one reproduces
    the original bytes exactly, so a proof can be persisted and restored in
    another process and handed straight to :func:`verify_inclusion`.
    """
    if not isinstance(credential, InclusionProof):
        raise TypeError("credential must be an InclusionProof")
    # Re-validate every field even for a credential built with
    # object.__setattr__ bypassing the frozen constructor, so structural
    # corruption raises exactly as the constructor would.
    checked = InclusionProof(
        credential.hash_name,
        credential.index,
        credential.size,
        credential.entry_hash,
        credential.root,
        credential.proof,
    )
    parts = [
        _INCLUSION_MAGIC,
        _encode_u64(_INCLUSION_VERSION, "version"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_u64(checked.index, "index"),
        _encode_u64(checked.size, "size"),
        _encode_blob(checked.entry_hash),
        _encode_blob(checked.root),
        _encode_u64(len(checked.proof), "proof count"),
    ]
    for node in checked.proof:
        parts.append(_encode_blob(node))
    return b"".join(parts)


def decode_inclusion_proof(data: Any) -> InclusionProof:
    """Decode bytes produced by :func:`encode_inclusion_proof`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown or non-fixed-output hash
    algorithm, truncation, trailing bytes, an oversized blob length, a
    digest whose width does not match the named algorithm, a negative or
    out-of-range ``index`` or a non-positive ``size`` raise ValueError. The
    whole input is consumed exactly; the returned credential is a frozen
    :class:`InclusionProof` whose fields equal the originally encoded ones,
    re-encoding it reproduces the original bytes exactly, and it can be
    passed to :func:`verify_inclusion` in another process exactly as the
    original could.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_INCLUSION_MAGIC):
        raise ValueError("not an auditchain inclusion-proof encoding")
    offset = len(_INCLUSION_MAGIC)

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
    if version != _INCLUSION_VERSION:
        raise ValueError("unsupported inclusion-proof version")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    index = read_u64("index")
    size = read_u64("size")
    entry_hash = read_blob("entry_hash")
    root = read_blob("root")
    proof_count = read_u64("proof count")
    proof = tuple(read_blob("proof element") for _ in range(proof_count))
    if offset != len(data):
        raise ValueError("trailing bytes after the inclusion proof")
    return InclusionProof(
        hash_name=hash_name,
        index=index,
        size=size,
        entry_hash=entry_hash,
        root=root,
        proof=proof,
    )


def encode_consistency_proof(credential: Any) -> bytes:
    """Encode a :class:`ConsistencyProof` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/consistency/v1\\0"``; sizes are unsigned 8-byte big-endian
    integers and every other field is a u64 byte length followed by the raw
    bytes (a zero length is an all-zero u64). Fields appear strictly in
    credential order, with nothing omitted, reordered or appended:
    ``version`` (always 1), ``hash_name`` (UTF-8 blob), ``old_size``, the
    ``old_root`` blob, ``new_size``, the ``new_root`` blob, and the
    ``proof`` node count followed by one blob per node in generation (RFC
    6962 SUBPROOF) order.

    ``credential`` must be a :class:`ConsistencyProof` — anything else, or a
    field of the wrong type (including fields overwritten through
    ``object.__setattr__`` bypassing the frozen constructor), raises
    TypeError; an unknown hash algorithm, a digest of the wrong width,
    negative or reversed sizes, or a size outside the u64 range raises
    ValueError. The call is read-only and deterministic: it never mutates
    the credential, and re-encoding a decoded one reproduces the original
    bytes exactly, so a proof can be persisted and restored in another
    process and handed straight to :func:`verify_consistency`.
    """
    if not isinstance(credential, ConsistencyProof):
        raise TypeError("credential must be a ConsistencyProof")
    # Re-validate every field even for a credential built with
    # object.__setattr__ bypassing the frozen constructor, so structural
    # corruption raises exactly as the constructor would.
    checked = ConsistencyProof(
        credential.hash_name,
        credential.old_size,
        credential.old_root,
        credential.new_size,
        credential.new_root,
        credential.proof,
    )
    parts = [
        _CONSISTENCY_MAGIC,
        _encode_u64(_CONSISTENCY_VERSION, "version"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_u64(checked.old_size, "old_size"),
        _encode_blob(checked.old_root),
        _encode_u64(checked.new_size, "new_size"),
        _encode_blob(checked.new_root),
        _encode_u64(len(checked.proof), "proof count"),
    ]
    for node in checked.proof:
        parts.append(_encode_blob(node))
    return b"".join(parts)


def decode_consistency_proof(data: Any) -> ConsistencyProof:
    """Decode bytes produced by :func:`encode_consistency_proof`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown or non-fixed-output hash
    algorithm, truncation, trailing bytes, an oversized blob length, a
    digest whose width does not match the named algorithm, a reversed or
    oversized size pair, or a size outside the u64 range raises ValueError.
    The whole input is consumed exactly; the returned credential is a
    frozen :class:`ConsistencyProof` whose fields equal the originally
    encoded ones, re-encoding it reproduces the original bytes exactly, and
    it can be passed to :func:`verify_consistency` in another process
    exactly as the original could.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_CONSISTENCY_MAGIC):
        raise ValueError("not an auditchain consistency-proof encoding")
    offset = len(_CONSISTENCY_MAGIC)

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
    if version != _CONSISTENCY_VERSION:
        raise ValueError("unsupported consistency-proof version")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    old_size = read_u64("old_size")
    old_root = read_blob("old_root")
    new_size = read_u64("new_size")
    new_root = read_blob("new_root")
    proof_count = read_u64("proof count")
    proof = tuple(read_blob("proof element") for _ in range(proof_count))
    if offset != len(data):
        raise ValueError("trailing bytes after the consistency proof")
    return ConsistencyProof(
        hash_name=hash_name,
        old_size=old_size,
        old_root=old_root,
        new_size=new_size,
        new_root=new_root,
        proof=proof,
    )


def rebuild_merkle_root(frontier: Any, retained_entry_hashes: Any) -> bytes:
    """Rebuild a full snapshot root from a frozen frontier and retained hashes.

    Folds the perfect subtrees of ``frontier`` (a :class:`MerkleFrontier`
    covering the released prefix ``[0, frontier.size)``) together with the
    ``entry_hash`` tuple of the retained segment ``[frontier.size, ...)`` in
    order, exactly as the live log would have folded them, and returns the
    Merkle root of the complete snapshot. Comparing that root with a signed
    checkpoint root confirms the retained segment directly follows the
    released prefix — without re-holding any released payload.

    ``frontier`` must be a :class:`MerkleFrontier` (its fields are
    re-validated, so a credential corrupted through
    ``object.__setattr__`` raises exactly as the constructor would) and
    ``retained_entry_hashes`` must be a ``tuple`` of exact ``bytes``
    digests, each non-empty and exactly the digest width of the frontier's
    algorithm (``bytearray`` / ``memoryview`` raise TypeError; an empty or
    wrong-width digest raises ValueError). Every other wrong input type
    raises TypeError. The call is read-only.
    """
    if not isinstance(frontier, MerkleFrontier):
        raise TypeError("frontier must be a MerkleFrontier")
    # Re-validate every field even for a credential tampered with through
    # object.__setattr__ bypassing the frozen constructor.
    checked = MerkleFrontier(
        frontier.hash_name, frontier.size, frontier.subtrees
    )
    if not isinstance(retained_entry_hashes, tuple):
        raise TypeError("retained_entry_hashes must be a tuple of digests")
    digest_size = _digest_size(checked.hash_name)
    occupied = {height: digest for height, digest in checked.subtrees}
    for entry_hash in retained_entry_hashes:
        if not isinstance(entry_hash, bytes):
            raise TypeError("retained entry hashes must be bytes")
        if len(entry_hash) == 0:
            raise ValueError("retained entry hash must not be empty")
        if len(entry_hash) != digest_size:
            raise ValueError(
                f"retained entry hash must be {digest_size} bytes"
            )
        node = _leaf_hash(entry_hash, checked.hash_name)
        height = 0
        while height in occupied:
            node = _node_hash(occupied.pop(height), node, checked.hash_name)
            height += 1
        occupied[height] = node
    if not occupied:
        return _hash_parts(checked.hash_name, _EMPTY_DOMAIN)
    root: bytes | None = None
    # Low blocks are the rightmost subtrees; fold them in from the right.
    for height in sorted(occupied):
        node = occupied[height]
        root = node if root is None else _node_hash(node, root, checked.hash_name)
    return root  # type: ignore[return-value]


def encode_merkle_frontier(credential: Any) -> bytes:
    """Encode a :class:`MerkleFrontier` into its canonical binary form.

    The encoding starts with the magic ``b"auditchain/frontier/v1\\0"``;
    integers are unsigned 8-byte big-endian values and every blob is a u64
    byte length followed by the raw bytes. Fields appear strictly in
    credential order, with nothing omitted, reordered or appended:
    ``version`` (always 1), ``hash_name`` (UTF-8 blob), ``size``, the
    subtree pair count, and per pair the height and the subtree-root digest
    blob, in ascending height order.

    ``credential`` must be a :class:`MerkleFrontier` — anything else, or a
    field of the wrong type (including fields overwritten through
    ``object.__setattr__`` bypassing the frozen constructor), raises
    TypeError; an unknown hash algorithm, a digest of the wrong width, an
    illegal or out-of-order subtree height, a set-bit mismatch with
    ``size``, or a negative or oversized ``size`` raises ValueError. The
    call is read-only and deterministic: it never mutates the credential,
    and re-encoding a decoded one reproduces the original bytes exactly.
    """
    if not isinstance(credential, MerkleFrontier):
        raise TypeError("credential must be a MerkleFrontier")
    # Re-validate every field even for a credential built with
    # object.__setattr__ bypassing the frozen constructor, so structural
    # corruption raises exactly as the constructor would.
    checked = MerkleFrontier(
        credential.hash_name, credential.size, credential.subtrees
    )
    parts = [
        _FRONTIER_MAGIC,
        _encode_u64(_FRONTIER_VERSION, "version"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_u64(checked.size, "size"),
        _encode_u64(len(checked.subtrees), "subtree count"),
    ]
    for height, digest in checked.subtrees:
        parts.append(_encode_u64(height, "subtree height"))
        parts.append(_encode_blob(digest))
    return b"".join(parts)


def decode_merkle_frontier(data: Any) -> MerkleFrontier:
    """Decode bytes produced by :func:`encode_merkle_frontier`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown or non-fixed-output hash
    algorithm, truncation, trailing bytes, an oversized blob length, a
    negative or u64-exceeding size, a subtree digest whose width does not
    match the named algorithm, a negative or non-ascending subtree height,
    or subtree heights that are not exactly the set bits of ``size`` raise
    ValueError. The whole input is consumed exactly; the returned
    credential is a frozen :class:`MerkleFrontier` whose fields equal the
    originally encoded ones and whose re-encoding reproduces the original
    bytes exactly.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_FRONTIER_MAGIC):
        raise ValueError("not an auditchain merkle-frontier encoding")
    offset = len(_FRONTIER_MAGIC)

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
    if version != _FRONTIER_VERSION:
        raise ValueError("unsupported merkle-frontier version")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    size = read_u64("size")
    subtree_count = read_u64("subtree count")
    subtrees = tuple(
        (read_u64("subtree height"), read_blob("subtree digest"))
        for _ in range(subtree_count)
    )
    if offset != len(data):
        raise ValueError("trailing bytes after the merkle frontier")
    return MerkleFrontier(hash_name=hash_name, size=size, subtrees=subtrees)


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


def verify_auth_stage(entry: Any, tag: Any, stage_verifier: Any) -> bool:
    """Verify a forward-secure tag against material delivered at one stage.

    The stage-scoped counterpart of :func:`verify_auth`: it follows exactly
    that routine's checks and ordering — recomputing the entry digest first
    (a structurally valid entry whose recorded hash does not match returns
    False), then evolving the delivered stage key forward to ``tag.stage``
    and checking the HMAC — with one difference: evolution starts at the
    :class:`StageVerifier`'s delivery stage rather than at stage 0. A tag
    minted before that delivery point (``tag.stage < stage_verifier.stage``)
    therefore returns False even when the entry and tag are genuine; only
    tags at the delivery stage or later can authenticate.

    Structural/type problems raise TypeError; negative values, wrong digest
    lengths, an out-of-range or wrong-width field, or an unknown hash
    algorithm raise ValueError. A well-formed entry and tag whose content
    does not authenticate, or whose stage precedes delivery, return False.
    """
    if not isinstance(entry, Entry):
        raise TypeError("entry must be an Entry")
    if not isinstance(tag, AuthTag):
        raise TypeError("tag must be an AuthTag")
    if not isinstance(stage_verifier, StageVerifier):
        raise TypeError("stage_verifier must be a StageVerifier")

    # Exactly as in verify_auth, the tag stage bounds the evolution loop
    # below, so validate it before anything else.
    if not isinstance(tag.stage, int) or isinstance(tag.stage, bool):
        raise TypeError("tag.stage must be an integer")
    if not 0 <= tag.stage < _MAX_STAGE:
        raise ValueError("tag.stage must satisfy 0 <= stage < 2**64")

    # Re-validate the material even for an instance whose fields were set
    # bypassing the frozen constructor: the delivery stage bounds the loop
    # as well, and the starting key must be a non-empty digest-width value.
    delivered = StageVerifier(
        stage=stage_verifier.stage,
        key=stage_verifier.key,
        hash_name=stage_verifier.hash_name,
    )

    digest_size = _digest_size(delivered.hash_name)
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
        hash_name=delivered.hash_name,
    )
    if not hmac.compare_digest(recomputed, entry.entry_hash):
        return False

    # The delivery point is the earliest verifiable stage: material handed
    # over at a positive stage cannot authenticate anything minted earlier.
    if tag.stage < delivered.stage:
        return False

    key = delivered.key
    for _ in range(tag.stage - delivered.stage):
        key = _evolve_key(key, delivered.hash_name)
    expected = _auth_tag(tag.stage, entry.entry_hash, key, delivered.hash_name)
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


def verify_signed_verifier(receipt: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedVerifier` against a pre-trusted Ed25519 key.

    Rebuilds the exact message :meth:`AuditLog.export_signed_verifier` signed
    — ``D || 0x01 || B(UTF-8(hash_name)) || B(key)`` with
    ``D = b"auditchain/signed-verifier/v1\\0"``, ``U`` an unsigned 8-byte
    big-endian integer and ``B(x) = U(len(x)) || x`` — from the nested
    :class:`Verifier` and checks the receipt's 64-byte Ed25519 signature with
    the 32-byte ``public_key``, entirely without holding the log. A genuine
    receipt from that key returns True; a structurally valid receipt signed
    by another key, or whose verifier fields or signature have been altered,
    returns False.

    Input that is not a :class:`SignedVerifier` (or whose fields have been
    bypassed to wrong types) raises TypeError; a version other than 1, an
    unknown hash algorithm, an empty key, a signature that is not 64 bytes or
    a public key that is not 32 bytes raises ValueError (a non-``bytes`` key
    TypeError). The signature authenticates provenance only, not
    confidentiality: the verifier key travels in the clear and must be
    protected by the caller. The call is read-only and never mutates the
    receipt.
    """
    if not isinstance(receipt, SignedVerifier):
        raise TypeError("receipt must be a SignedVerifier")
    # Re-validate every field even for a receipt built with
    # object.__setattr__ bypassing the frozen constructor (the constructor
    # also re-validates the nested Verifier), so structural corruption raises
    # exactly as the constructor would and only genuine mismatches return
    # False below.
    checked = SignedVerifier(
        receipt.version,
        receipt.verifier,
        receipt.signature,
    )
    verification_key = _load_ed25519_public(public_key)
    message = _signed_verifier_message(
        checked.verifier.hash_name, checked.verifier.key
    )
    try:
        verification_key.verify(checked.signature, message)
    except InvalidSignature:
        return False
    return True


def verify_signed_stage_verifier(receipt: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedStageVerifier` against a pre-trusted Ed25519 key.

    Rebuilds the exact message
    :meth:`AuditLog.export_signed_stage_verifier` signed —
    ``D || 0x01 || U(stage) || B(UTF-8(hash_name)) || B(key)`` with
    ``D = b"auditchain/signed-stage/v1\\0"``, ``U`` an unsigned 8-byte
    big-endian integer and ``B(x) = U(len(x)) || x`` — from the nested
    :class:`StageVerifier` and checks the receipt's 64-byte Ed25519
    signature with the 32-byte ``public_key``, entirely without holding the
    log. A genuine receipt from that key returns True; a structurally valid
    receipt signed by another key, or whose version, stage, hash algorithm,
    key or signature has been altered, returns False.

    Input that is not a :class:`SignedStageVerifier` (or whose fields have
    been bypassed to wrong types), or a ``public_key`` that is not
    ``bytes``, raises TypeError; a version other than 1, an out-of-range
    stage, an empty or wrong-width key, an unknown hash algorithm, a
    signature that is not 64 bytes or a public key that is not 32 bytes
    raises ValueError. The signature authenticates provenance only, not
    confidentiality: the stage key travels in the clear and must be
    protected by the caller. The call is read-only and never mutates the
    receipt.
    """
    if not isinstance(receipt, SignedStageVerifier):
        raise TypeError("receipt must be a SignedStageVerifier")
    # Re-validate every field even for a receipt built with
    # object.__setattr__ bypassing the frozen constructor (the constructor
    # also re-validates the nested StageVerifier), so structural
    # corruption raises exactly as the constructor would and only genuine
    # mismatches return False below.
    checked = SignedStageVerifier(
        receipt.version,
        receipt.verifier,
        receipt.signature,
    )
    verification_key = _load_ed25519_public(public_key)
    message = _signed_stage_verifier_message(
        checked.verifier.stage,
        checked.verifier.hash_name,
        checked.verifier.key,
    )
    try:
        verification_key.verify(checked.signature, message)
    except InvalidSignature:
        return False
    return True


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


def verify_rotation(item: Any, key: Any) -> bool:
    """Verify an Ed25519 signer rotation against a pre-trusted old public key.

    ``item`` is the ``(old, new_key, new, auth)`` four-tuple returned by
    :meth:`AuditLog.rotate_signer` and ``key`` is the pre-trusted 32-byte
    Ed25519 public key of the old signer; the new signer's 32-byte public key
    is learned from ``new_key`` in the item itself. The whole claim is
    checked entirely offline, without holding the log: :func:`verify_signed_root`
    verifies the ``old`` checkpoint against ``key`` and the ``new``
    checkpoint against ``new_key``, and ``key`` verifies ``auth`` — the
    64-byte Ed25519 signature over
    ``D || 0x01 || B(old.signature) || B(new_key) || B(new.signature)`` with
    ``D = b"auditchain/signer-rotation/v1\\0"``, ``U`` an unsigned 8-byte
    big-endian integer and ``B(x) = U(len(x)) || x`` — so ``new_key`` is only
    trusted after the old key vouches for it. The two checkpoints must be
    identical except for their signatures (same ``version``, ``hash_name``,
    ``size``, ``root`` and ``head``), since both attest to the very same
    snapshot.

    A genuine rotation returns True; a signature that does not verify, a
    ``new_key`` vouched for by a different old key, or two checkpoints of
    different snapshots returns False. ``item`` that is not a tuple raises
    TypeError; a tuple whose length is not 4 raises ValueError. ``old`` and
    ``new`` must be :class:`SignedRoot` instances and ``new_key`` and
    ``auth`` must be ``bytes`` (wrong element types raise TypeError); a
    ``new_key`` that is not 32 bytes, an ``auth`` that is not 64 bytes, or
    any nested structural violation raises ValueError exactly as
    :func:`verify_signed_root` does. The call is read-only and never
    mutates the item.
    """
    if not isinstance(item, tuple):
        raise TypeError("item must be a tuple (old, new_key, new, auth)")
    if len(item) != 4:
        raise ValueError(
            "item must have exactly 4 elements (old, new_key, new, auth)"
        )
    old, new_key, new, auth = item
    if not isinstance(old, SignedRoot):
        raise TypeError("old must be a SignedRoot")
    if not isinstance(new, SignedRoot):
        raise TypeError("new must be a SignedRoot")
    if not isinstance(auth, bytes):
        raise TypeError("auth must be bytes")
    if len(auth) != _ED25519_SIGNATURE_BYTES:
        raise ValueError(f"auth must be {_ED25519_SIGNATURE_BYTES} bytes")
    # Re-validate every field even for a receipt built with object.__setattr__
    # bypassing the frozen constructor, so structural corruption raises
    # exactly as the constructor would and only genuine mismatches return
    # False below. _load_ed25519_public also pins new_key and key to 32 bytes.
    checked_old = SignedRoot(
        old.version,
        old.hash_name,
        old.size,
        old.root,
        old.head,
        old.signature,
    )
    checked_new = SignedRoot(
        new.version,
        new.hash_name,
        new.size,
        new.root,
        new.head,
        new.signature,
    )
    old_verification_key = _load_ed25519_public(key)
    # Pins new_key to exactly 32 bytes before it is used for the first time:
    # the new signer is trusted only if verify_signed_root and auth pass.
    _load_ed25519_public(new_key)
    # Both SignedRoots must describe the same snapshot; only their signatures
    # are allowed to differ, since each is signed by a different key.
    if (
        checked_old.version,
        checked_old.hash_name,
        checked_old.size,
        checked_old.root,
        checked_old.head,
    ) != (
        checked_new.version,
        checked_new.hash_name,
        checked_new.size,
        checked_new.root,
        checked_new.head,
    ):
        return False
    if not verify_signed_root(checked_old, key):
        return False
    if not verify_signed_root(checked_new, new_key):
        return False
    message = _rotation_message(
        checked_old.signature, new_key, checked_new.signature
    )
    try:
        old_verification_key.verify(auth, message)
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


def verify_signed_audit_receipt(bundle: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedAuditReceipt` against a pre-trusted Ed25519 key.

    Confirms both parts of the sealed bundle without holding the log:
    :func:`verify_audit_receipt` re-verifies every carried entry's digest and
    per-entry inclusion proof against the receipt's snapshot root, and
    :func:`verify_signed_root` verifies the checkpoint signature with the
    32-byte ``public_key``. The two parts are then required to describe the
    same snapshot — equal ``hash_name``, ``size`` and ``root``. A genuine
    sealed bundle from the trusted key returns True; a structurally valid
    bundle signed by another key, whose parts disagree, or whose entries,
    proofs, root or signature have been altered returns False. Input that is
    not a :class:`SignedAuditReceipt` (or whose container fields have been
    bypassed to wrong types) raises TypeError; nested structural violations
    raise exactly the exceptions of :class:`AuditReceipt` and
    :func:`verify_signed_root` (TypeError or ValueError), and a public key
    that is not 32 ``bytes`` raises ValueError (a non-``bytes`` key
    TypeError). The call is read-only and never mutates the bundle.
    """
    if not isinstance(bundle, SignedAuditReceipt):
        raise TypeError("bundle must be a SignedAuditReceipt")
    # Re-validate the container fields even for an instance whose fields were
    # set bypassing the frozen constructor, so container-type corruption
    # raises TypeError exactly as the constructor would.
    if not isinstance(bundle.receipt, AuditReceipt):
        raise TypeError("receipt must be an AuditReceipt")
    if not isinstance(bundle.checkpoint, SignedRoot):
        raise TypeError("checkpoint must be a SignedRoot")
    # Re-validate the nested structures as their own constructors would, so a
    # bypassed field raises exactly the constructor's TypeError or ValueError
    # rather than being reported as False.
    receipt = AuditReceipt(
        version=bundle.receipt.version,
        hash_name=bundle.receipt.hash_name,
        size=bundle.receipt.size,
        root=bundle.receipt.root,
        items=bundle.receipt.items,
    )
    checkpoint = SignedRoot(
        bundle.checkpoint.version,
        bundle.checkpoint.hash_name,
        bundle.checkpoint.size,
        bundle.checkpoint.root,
        bundle.checkpoint.head,
        bundle.checkpoint.signature,
    )
    # The two parts must describe the same snapshot; a bundle whose parts
    # disagree is a mismatch, not a structural error.
    if (
        receipt.hash_name != checkpoint.hash_name
        or receipt.size != checkpoint.size
        or receipt.root != checkpoint.root
    ):
        return False
    if not verify_audit_receipt(receipt):
        return False
    return verify_signed_root(checkpoint, public_key)


def verify_signed_search_receipt(bundle: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedSearchReceipt` against a pre-trusted Ed25519 key.

    Confirms both parts of the sealed bundle without holding the log:
    :func:`verify_search_receipt` re-verifies every listed hit's digest and
    inclusion proof against the receipt's snapshot root, and
    :func:`verify_signed_root` verifies the checkpoint signature with the
    32-byte ``public_key``. The two parts are then required to describe the
    same snapshot — equal ``hash_name``, ``size`` and ``root``. A genuine
    sealed bundle from the trusted key returns True; a structurally valid
    bundle signed by another key, whose parts disagree, or whose entries,
    proofs, root or signature have been altered returns False. Input that is
    not a :class:`SignedSearchReceipt` (or whose container fields have been
    bypassed to wrong types) raises TypeError; nested structural violations
    raise exactly the exceptions of :class:`SearchReceipt` and
    :func:`verify_signed_root` (TypeError or ValueError), and a public key
    that is not 32 ``bytes`` raises ValueError (a non-``bytes`` key
    TypeError). The call is read-only and never mutates the bundle.
    """
    if not isinstance(bundle, SignedSearchReceipt):
        raise TypeError("bundle must be a SignedSearchReceipt")
    # Re-validate the container fields even for an instance whose fields were
    # set bypassing the frozen constructor, so container-type corruption
    # raises TypeError exactly as the constructor would.
    if not isinstance(bundle.receipt, SearchReceipt):
        raise TypeError("receipt must be a SearchReceipt")
    if not isinstance(bundle.checkpoint, SignedRoot):
        raise TypeError("checkpoint must be a SignedRoot")
    # Re-validate the nested structures as their own constructors would, so a
    # bypassed field raises exactly the constructor's TypeError or ValueError
    # rather than being reported as False.
    receipt = SearchReceipt(
        version=bundle.receipt.version,
        hash_name=bundle.receipt.hash_name,
        size=bundle.receipt.size,
        root=bundle.receipt.root,
        query=bundle.receipt.query,
        start=bundle.receipt.start,
        stop=bundle.receipt.stop,
        items=bundle.receipt.items,
    )
    checkpoint = SignedRoot(
        bundle.checkpoint.version,
        bundle.checkpoint.hash_name,
        bundle.checkpoint.size,
        bundle.checkpoint.root,
        bundle.checkpoint.head,
        bundle.checkpoint.signature,
    )
    # The two parts must describe the same snapshot; a bundle whose parts
    # disagree is a mismatch, not a structural error.
    if (
        receipt.hash_name != checkpoint.hash_name
        or receipt.size != checkpoint.size
        or receipt.root != checkpoint.root
    ):
        return False
    if not verify_search_receipt(receipt):
        return False
    return verify_signed_root(checkpoint, public_key)


def verify_signed_encrypted_search_receipt(
    bundle: Any, key: Any, public_key: Any
) -> bool:
    """Verify a :class:`SignedEncryptedSearchReceipt` against the append key
    and a pre-trusted Ed25519 key.

    Confirms both parts of the sealed bundle without holding the log:
    :func:`verify_encrypted_search_receipt` re-verifies every listed hit's
    digest and inclusion proof against the receipt's snapshot root and
    decrypts each sealed envelope with ``key``, and
    :func:`verify_signed_root` verifies the checkpoint signature with the
    32-byte ``public_key``. The two parts are then required to describe the
    same snapshot — equal ``hash_name``, ``size`` and ``root``. A genuine
    sealed bundle from the trusted key returns True; a structurally valid
    bundle signed by another key, whose parts disagree, whose entries,
    proofs, root, envelopes or signature have been altered, or verified with
    a key that is not the append key returns False. As with
    :func:`verify_encrypted_search_receipt`, verification only attests that
    the listed hits are genuine — a bundle listing fewer hits than the log
    would have found is not a failure, and a wrong append key returns False
    rather than raising. Input that is not a
    :class:`SignedEncryptedSearchReceipt` (or whose container fields have
    been bypassed to wrong types) raises TypeError; nested structural
    violations raise exactly the exceptions of :class:`EncryptedSearchReceipt`
    and :func:`verify_signed_root` (TypeError or ValueError), an append key
    or public key that is not ``bytes`` raises TypeError, and one that is not
    32 bytes raises ValueError. The call is read-only and never mutates the
    bundle.
    """
    if not isinstance(bundle, SignedEncryptedSearchReceipt):
        raise TypeError("bundle must be a SignedEncryptedSearchReceipt")
    # Re-validate the container fields even for an instance whose fields were
    # set bypassing the frozen constructor, so container-type corruption
    # raises TypeError exactly as the constructor would.
    if not isinstance(bundle.receipt, EncryptedSearchReceipt):
        raise TypeError("receipt must be an EncryptedSearchReceipt")
    if not isinstance(bundle.checkpoint, SignedRoot):
        raise TypeError("checkpoint must be a SignedRoot")
    _check_key(key)
    # Re-validate the nested structures as their own constructors would, so a
    # bypassed field raises exactly the constructor's TypeError or ValueError
    # rather than being reported as False.
    receipt = EncryptedSearchReceipt(
        version=bundle.receipt.version,
        hash_name=bundle.receipt.hash_name,
        size=bundle.receipt.size,
        root=bundle.receipt.root,
        query=bundle.receipt.query,
        start=bundle.receipt.start,
        stop=bundle.receipt.stop,
        items=bundle.receipt.items,
    )
    checkpoint = SignedRoot(
        bundle.checkpoint.version,
        bundle.checkpoint.hash_name,
        bundle.checkpoint.size,
        bundle.checkpoint.root,
        bundle.checkpoint.head,
        bundle.checkpoint.signature,
    )
    # The two parts must describe the same snapshot; a bundle whose parts
    # disagree is a mismatch, not a structural error.
    if (
        receipt.hash_name != checkpoint.hash_name
        or receipt.size != checkpoint.size
        or receipt.root != checkpoint.root
    ):
        return False
    if not verify_encrypted_search_receipt(receipt, key):
        return False
    return verify_signed_root(checkpoint, public_key)


def verify_signed_full_search_receipt(bundle: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedFullSearchReceipt` against a pre-trusted
    Ed25519 key.

    Confirms both parts of the sealed bundle without holding the log:
    :func:`verify_full_search_receipt` re-verifies every listed entry's
    digest and the shared inclusion proof against the receipt's snapshot
    root, and :func:`verify_signed_root` verifies the checkpoint signature
    with the 32-byte ``public_key``. The two parts are then required to
    describe the same snapshot — equal ``hash_name``, ``size`` and ``root``.
    Only when all three hold — the receipt verifies, the checkpoint signature
    is genuine and the parts describe one snapshot — does the call return
    True; a structurally valid bundle signed by another key, whose parts
    disagree, or whose entries, proof, root or signature have been altered
    returns False and never raises for a mere mismatch. Input that is not a
    :class:`SignedFullSearchReceipt` (or whose container fields have been
    bypassed to wrong types) raises TypeError; nested structural violations
    raise exactly the exceptions of :class:`FullSearchReceipt` and
    :func:`verify_signed_root` (TypeError or ValueError), and a public key
    that is not ``bytes`` raises TypeError while one that is not 32 bytes
    raises ValueError. The call is read-only and never mutates the bundle.
    """
    if not isinstance(bundle, SignedFullSearchReceipt):
        raise TypeError("bundle must be a SignedFullSearchReceipt")
    # Re-validate the container fields even for an instance whose fields were
    # set bypassing the frozen constructor, so container-type corruption
    # raises TypeError exactly as the constructor would.
    if not isinstance(bundle.receipt, FullSearchReceipt):
        raise TypeError("receipt must be a FullSearchReceipt")
    if not isinstance(bundle.checkpoint, SignedRoot):
        raise TypeError("checkpoint must be a SignedRoot")
    # Re-validate the nested structures as their own constructors would, so a
    # bypassed field raises exactly the constructor's TypeError or ValueError
    # rather than being reported as False.
    receipt = FullSearchReceipt(
        version=bundle.receipt.version,
        hash_name=bundle.receipt.hash_name,
        size=bundle.receipt.size,
        root=bundle.receipt.root,
        query=bundle.receipt.query,
        start=bundle.receipt.start,
        stop=bundle.receipt.stop,
        items=bundle.receipt.items,
        proof=bundle.receipt.proof,
    )
    checkpoint = SignedRoot(
        bundle.checkpoint.version,
        bundle.checkpoint.hash_name,
        bundle.checkpoint.size,
        bundle.checkpoint.root,
        bundle.checkpoint.head,
        bundle.checkpoint.signature,
    )
    # The two parts must describe the same snapshot; a bundle whose parts
    # disagree is a mismatch, not a structural error.
    if (
        receipt.hash_name != checkpoint.hash_name
        or receipt.size != checkpoint.size
        or receipt.root != checkpoint.root
    ):
        return False
    if not verify_full_search_receipt(receipt):
        return False
    return verify_signed_root(checkpoint, public_key)


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


def verify_signed_auth_bundle(bundle: Any, public_key: Any) -> tuple[bool, ...]:
    """Verify a :class:`SignedAuthBundle` against a pre-trusted Ed25519 key.

    Confirms the trusted-delivery auth bundle entirely offline, without
    holding the log: :func:`verify_signed_verifier` first checks the nested
    :class:`SignedVerifier` against the pre-trusted 32-byte ``public_key``,
    so the receiver learns the stage-0 verification material genuinely came
    from the log holder. Only when that signature verifies *and* the
    bundle's ``hash_name`` agrees with the signed verifier's algorithm are
    the items checked, by reusing :func:`verify_auth_batch` with the
    verified verifier; the per-item results come back as a tuple of
    booleans in item order, ``()`` for an empty bundle. A signature that
    does not verify, or a bundle whose ``hash_name`` disagrees with the
    signed verifier's algorithm, yields ``False`` at every item position —
    provenance failure is never silently upgraded to per-item detail.

    Input that is not a :class:`SignedAuthBundle` (or whose container
    fields have been bypassed to wrong types) raises TypeError; nested
    structural violations raise exactly the exceptions of
    :func:`verify_signed_verifier` and :func:`verify_auth_batch`
    (TypeError or ValueError), and a public key that is not 32 ``bytes``
    raises ValueError (a non-``bytes`` key TypeError). The signature
    authenticates provenance only, not confidentiality: the verifier key
    travels in the clear and must be protected by the caller. The call is
    read-only and never mutates the bundle.
    """
    if not isinstance(bundle, SignedAuthBundle):
        raise TypeError("bundle must be a SignedAuthBundle")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedAuthBundle(bundle.verifier, bundle.hash_name, bundle.items)
    if not verify_signed_verifier(checked.verifier, public_key):
        return tuple(False for _ in checked.items)
    verifier = checked.verifier.verifier
    if checked.hash_name != verifier.hash_name:
        return tuple(False for _ in checked.items)
    return verify_auth_batch(checked.items, verifier)


def verify_signed_stage_auth_bundle(bundle: Any, public_key: Any) -> tuple[bool, ...]:
    """Verify a :class:`SignedStageAuthBundle` against a pre-trusted Ed25519 key.

    Confirms the trusted-delivery stage auth bundle entirely offline,
    without holding the log: :func:`verify_signed_stage_verifier` first
    checks the nested :class:`SignedStageVerifier` against the pre-trusted
    32-byte ``public_key``, so the receiver learns the stage verification
    material genuinely came from the log holder. Only when that signature
    verifies *and* the bundle's ``hash_name`` agrees with the signed
    verifier's algorithm are the items checked — each ``(Entry, AuthTag)``
    pair with exactly :func:`verify_auth_stage` against the delivered
    :class:`StageVerifier` — and the per-item results come back as a tuple
    of booleans in item order, ``()`` for an empty bundle. A signature that
    does not verify, or a bundle whose ``hash_name`` disagrees with the
    signed verifier's algorithm, yields ``False`` at every item position —
    provenance failure is never silently upgraded to per-item detail.

    As in :func:`verify_auth_batch`, the batch is validated structurally
    before any per-item verification: the entry indices must be strictly
    ascending and the tag stages consecutive (the first tag sits at the
    delivery stage). A wrong container or element type raises TypeError;
    duplicate, out-of-range or out-of-order entry indices, non-consecutive
    stages, a stage/index at or beyond ``2**64`` or a wrong digest width
    raise ValueError; nested structural violations raise exactly the
    exceptions of :func:`verify_signed_stage_verifier` and
    :func:`verify_auth_stage`, and a public key that is not 32 ``bytes``
    raises ValueError (a non-``bytes`` key TypeError). A structurally valid
    pair whose content does not authenticate contributes only ``False`` at
    its position, never an exception. The signature authenticates provenance
    only, not confidentiality: the stage key travels in the clear and must
    be protected by the caller. The call is read-only and never mutates the
    bundle.
    """
    if not isinstance(bundle, SignedStageAuthBundle):
        raise TypeError("bundle must be a SignedStageAuthBundle")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedStageAuthBundle(bundle.verifier, bundle.hash_name, bundle.items)
    if not verify_signed_stage_verifier(checked.verifier, public_key):
        return tuple(False for _ in checked.items)
    verifier = checked.verifier.verifier
    if checked.hash_name != verifier.hash_name:
        return tuple(False for _ in checked.items)
    digest_size = _digest_size(checked.hash_name)

    # One structural pass over the whole batch first, exactly as
    # verify_auth_batch does: any malformed pair (or a broken
    # ordering/continuity relationship) must raise before per-item
    # verification.
    previous_index: int | None = None
    for position, item in enumerate(checked.items):
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
        # same defensive ordering verify_auth_stage uses.
        if not isinstance(tag.stage, int) or isinstance(tag.stage, bool):
            raise TypeError("tag.stage must be an integer")
        if not 0 <= tag.stage < _MAX_STAGE:
            raise ValueError("tag.stage must satisfy 0 <= stage < 2**64")
        if not isinstance(tag.tag, bytes):
            raise TypeError("tag.tag must be bytes")
        if len(tag.tag) != digest_size:
            raise ValueError(f"tag.tag must be {digest_size} bytes")
        if position > 0 and tag.stage != checked.items[position - 1][1].stage + 1:
            raise ValueError("item tag stages must be consecutive")

    return tuple(
        verify_auth_stage(entry, tag, verifier)
        for entry, tag in checked.items  # type: ignore[misc]
    )


def verify_signed_stage_auth_audit_bundle(
    bundle: Any, public_key: Any
) -> bool:
    """Verify a :class:`SignedStageAuthAuditBundle` against a pre-trusted key.

    Confirms the whole trusted-delivery bundle entirely offline, without
    holding the log, in four steps:

    1. :func:`verify_signed_stage_verifier` checks the nested
       :class:`SignedStageVerifier` signature with the 32-byte
       ``public_key`` (explicitly, so even an empty auth selection cannot
       pass vacuously), and
       :func:`verify_signed_stage_auth_bundle` must return ``True`` at
       every item position;
    2. :func:`verify_signed_audit_batch` verifies the signed batch audit —
       its shared inclusion proof, its checkpoint signature and its
       snapshot linkage;
    3. both packages must name one hash algorithm: the auth bundle's
       ``hash_name``, its signed stage verifier's algorithm and the audit
       batch's ``hash_name`` must all agree;
    4. every entry the auth package authenticates must be byte-for-byte
       the :class:`Entry` the audit package carries at the same absolute
       index (the audit package normally also carries the snapshot's last
       entry, which the auth package need not tag).

    A genuine bundle from the trusted key returns True; a structurally
    valid bundle signed by another key, whose two packages disagree on the
    algorithm or snapshot, whose entries differ at a shared index, or whose
    signatures, tags, proof or checkpoint have been altered returns False.
    Input that is not a :class:`SignedStageAuthAuditBundle` (or whose
    container fields have been bypassed to wrong types) raises TypeError;
    nested structural violations raise exactly the exceptions of
    :func:`verify_signed_stage_auth_bundle` and
    :func:`verify_signed_audit_batch` (TypeError or ValueError), and a
    public key that is not 32 ``bytes`` raises ValueError (a non-``bytes``
    key TypeError). The call is read-only and never mutates the bundle.
    """
    if not isinstance(bundle, SignedStageAuthAuditBundle):
        raise TypeError("bundle must be a SignedStageAuthAuditBundle")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedStageAuthAuditBundle(bundle.auth, bundle.audit)

    # Check the signed stage material explicitly as well: with an empty
    # auth selection verify_signed_stage_auth_bundle reports an empty
    # tuple, whose all() would otherwise pass vacuously.
    if not verify_signed_stage_verifier(checked.auth.verifier, public_key):
        return False
    if not all(verify_signed_stage_auth_bundle(checked.auth, public_key)):
        return False
    if not verify_signed_audit_batch(checked.audit, public_key):
        return False

    auth = checked.auth
    audit = checked.audit
    audit_hash_name, _audit_size, _root, audit_entries, _proof = audit.batch
    # The two packages must be minted under one hash algorithm. The
    # verifier/audit equalities also cover the empty-selection cases that
    # never carry per-item evidence.
    if auth.hash_name != auth.verifier.verifier.hash_name:
        return False
    if auth.hash_name != audit_hash_name:
        return False

    # Every authenticated entry must be exactly the record the audit
    # package carries at the same absolute index. verify_audit_batch has
    # already guaranteed the audit entries are distinct and ascending, so a
    # dict loses no correspondence. Entry equality covers the index (the
    # lookup key) and all three byte fields.
    audit_by_index = {entry.index: entry for entry in audit_entries}
    for entry, _tag in auth.items:
        if audit_by_index.get(entry.index) != entry:
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


def encode_rotation(item: Any) -> bytes:
    """Encode a ``rotate_signer`` four-tuple into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/signer-rotation-record/v1\\0"``; it then writes, strictly
    in the ``(old, new_key, new, auth)`` order returned by
    :meth:`AuditLog.rotate_signer`, the envelope ``version`` (always 1) as
    an unsigned 8-byte big-endian integer followed by four length-prefixed
    blobs ``B(O) || B(K) || B(N) || B(A)`` — nothing may be omitted,
    reordered or appended. With ``U`` an unsigned 8-byte big-endian integer
    and ``B(x) = U(len(x)) || x``: ``O`` and ``N`` are byte-for-byte the
    complete canonical output of :func:`encode_signed_root` over the ``old``
    and ``new`` checkpoints, and ``K`` and ``A`` are the raw ``new_key``
    and ``auth`` bytes. No new signing message is introduced: encoding is
    read-only and only re-uses the existing canonical encoding.

    ``item`` must be exactly the four-tuple produced by
    :meth:`AuditLog.rotate_signer` — anything that is not a tuple raises
    TypeError, and a tuple whose length is not 4 raises ValueError. ``old``
    and ``new`` must be :class:`SignedRoot` instances and ``new_key`` and
    ``auth`` must be ``bytes`` (wrong element types raise TypeError); a
    ``new_key`` that is not 32 bytes, an ``auth`` that is not 64 bytes, or
    any nested structural problem raises ValueError exactly as
    :func:`encode_signed_root` does. Encoding is deterministic: re-encoding
    a decoded four-tuple reproduces the original bytes exactly, and a
    structurally valid rotation whose signatures do not verify encodes just
    as well.
    """
    if not isinstance(item, tuple):
        raise TypeError("item must be a tuple (old, new_key, new, auth)")
    if len(item) != 4:
        raise ValueError(
            "item must have exactly 4 elements (old, new_key, new, auth)"
        )
    old, new_key, new, auth = item
    if not isinstance(old, SignedRoot):
        raise TypeError("old must be a SignedRoot")
    if not isinstance(new, SignedRoot):
        raise TypeError("new must be a SignedRoot")
    if not isinstance(new_key, bytes):
        raise TypeError("new_key must be bytes")
    if not isinstance(auth, bytes):
        raise TypeError("auth must be bytes")
    if len(new_key) != _ED25519_KEY_BYTES:
        raise ValueError(f"new_key must be {_ED25519_KEY_BYTES} bytes")
    if len(auth) != _ED25519_SIGNATURE_BYTES:
        raise ValueError(f"auth must be {_ED25519_SIGNATURE_BYTES} bytes")
    old_blob = encode_signed_root(old)
    new_blob = encode_signed_root(new)
    return b"".join((
        _ROTATION_RECORD_MAGIC,
        _encode_u64(_ROTATION_RECORD_VERSION, "version"),
        _encode_blob(old_blob),
        _encode_blob(new_key),
        _encode_blob(new_blob),
        _encode_blob(auth),
    ))


def decode_rotation(data: Any) -> tuple[SignedRoot, bytes, SignedRoot, bytes]:
    """Decode bytes produced by :func:`encode_rotation`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signer-rotation-record/v1\\0"`` it must contain, strictly
    in order, the u64 envelope version (only ``1`` is supported) and exactly
    four length-prefixed blobs — old checkpoint, new key, new checkpoint and
    authorization — with no trailing bytes. The first and third blobs are
    handed whole to :func:`decode_signed_root`, so every nested magic,
    version, framing and structural rule is hers; the second must be the
    32-byte raw ``new_key`` and the fourth the 64-byte ``auth`` signature.
    A bad magic or version, truncation, an oversized blob length, trailing
    bytes, a key blob that is not 32 bytes, an auth blob that is not 64
    bytes, or an illegal nested checkpoint encoding raises ValueError.

    The returned value is the ``(old, new_key, new, auth)`` four-tuple in
    :meth:`AuditLog.rotate_signer` order; its fields equal the originally
    encoded ones and re-encoding reproduces the original bytes exactly. A
    structurally sound encoding whose signatures simply do not verify under
    :func:`verify_rotation` still decodes; verification reports False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_ROTATION_RECORD_MAGIC):
        raise ValueError("not an auditchain signer-rotation-record encoding")
    offset = len(_ROTATION_RECORD_MAGIC)

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
    if version != _ROTATION_RECORD_VERSION:
        raise ValueError(f"unsupported signer-rotation-record version {version}")
    old_blob = read_blob("old checkpoint")
    new_key = read_blob("new_key")
    new_blob = read_blob("new checkpoint")
    auth = read_blob("auth")
    if offset != len(data):
        raise ValueError("trailing bytes after the signer rotation record")
    if len(new_key) != _ED25519_KEY_BYTES:
        raise ValueError(f"new_key must be {_ED25519_KEY_BYTES} bytes")
    if len(auth) != _ED25519_SIGNATURE_BYTES:
        raise ValueError(f"auth must be {_ED25519_SIGNATURE_BYTES} bytes")
    # Decode both checkpoint blobs with the existing decoder; its own magic,
    # version, truncation/trailing-byte and structural checks apply verbatim.
    old = decode_signed_root(old_blob)
    new = decode_signed_root(new_blob)
    return old, new_key, new, auth


def verify_rotation_chain(items: Any, key: Any) -> bool:
    """Verify an ordered, non-empty tuple of signer rotations offline.

    ``items`` must be a non-empty ``tuple`` whose elements are the
    ``(old, new_key, new, auth)`` four-tuples returned by
    :meth:`AuditLog.rotate_signer`, kept in the caller's order, and ``key``
    is the pre-trusted 32-byte Ed25519 public key of the very first signer.
    The records are examined strictly in tuple order with
    :func:`verify_rotation`: the first record is checked against ``key`` and
    every later record against the preceding record's ``new_key`` — the
    signer learned from one record is the only signer trusted to authorize
    the next, so trust hops from key to final ``new_key`` exactly in order.
    No record may be repeated: a four-tuple equal to an earlier one makes
    the result False. Nothing is skipped, reordered or altered.

    The check holds neither the log nor any checkpoint history and
    introduces no new signing message of its own — it only re-uses
    :func:`verify_rotation`, and it never mutates the items or the key. A
    genuine chain returns True; a record that fails
    :func:`verify_rotation` or a repeated record returns False. A non-tuple
    (including a list, a generator or ``None``) or an element of the wrong
    type raises TypeError, an empty tuple or a four-tuple whose length is
    not 4 raises ValueError, and a key that is not 32 ``bytes`` raises
    exactly as :func:`verify_rotation` does (TypeError for non-``bytes``,
    ValueError for another length); every other nested structural
    violation propagates from :func:`verify_rotation` unchanged.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a non-empty tuple of rotation records")
    if len(items) == 0:
        raise ValueError("items must be a non-empty tuple of rotation records")
    # Pin the initial key to 32 bytes before the first use, exactly as
    # verify_rotation pins every learned new_key, so a malformed anchor key
    # raises identically whether or not the chain happens to be examined.
    _load_ed25519_public(key)
    current_key = key
    seen: set[tuple] = set()
    for item in items:
        if item in seen:
            return False
        if not verify_rotation(item, current_key):
            return False
        seen.add(item)
        # The verified record vouches for its new_key; it is the only key
        # trusted to authorize the following record.
        current_key = item[1]
    return True


def encode_rotations(items: Any) -> bytes:
    """Encode a non-empty tuple of rotation four-tuples into canonical bytes.

    The byte stream is ``D || U(1) || U(n) || B(R1) … B(Rn)`` with
    ``D = b"auditchain/rotation-chain/v1\\0"``, ``U`` an unsigned 8-byte
    big-endian integer, ``B(x) = U(len(x)) || x`` and ``n`` the non-zero
    record count: the envelope ``version`` (always 1), then the count, then
    one length-prefixed blob per rotation four-tuple in the tuple's own
    order — nothing may be omitted, reordered or appended. Each ``Ri`` is
    byte-for-byte the complete canonical output of :func:`encode_rotation`
    over ``items[i]``; the framing introduces no new signing message and is
    read-only.

    ``items`` must be a non-empty ``tuple`` — a non-tuple raises TypeError
    and an empty tuple raises ValueError. Element types and widths are
    checked by :func:`encode_rotation`, so a malformed record raises
    exactly its exceptions (TypeError or ValueError). Encoding is
    deterministic: re-encoding a decoded tuple reproduces the original
    bytes exactly, and a structurally valid chain whose signatures do not
    verify encodes just as well.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a non-empty tuple of rotation records")
    if len(items) == 0:
        raise ValueError("items must be a non-empty tuple of rotation records")
    parts = [
        _ROTATION_CHAIN_MAGIC,
        _encode_u64(_ROTATION_CHAIN_VERSION, "version"),
        _encode_u64(len(items), "record count"),
    ]
    for item in items:
        parts.append(_encode_blob(encode_rotation(item)))
    return b"".join(parts)


def decode_rotations(data: Any) -> tuple:
    """Decode bytes produced by :func:`encode_rotations`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/rotation-chain/v1\\0"`` it must contain, strictly in
    order, the u64 envelope version (only ``1`` is supported), the non-zero
    u64 record count ``n`` and exactly ``n`` length-prefixed blobs, each
    consumed whole with no trailing bytes. Every blob is handed whole to
    :func:`decode_rotation`, so its magic, version, key and auth widths,
    truncation/trailing-byte framing and nested signed-root rules all apply
    verbatim. A bad magic or version, a zero count, truncation, an
    oversized blob length, trailing bytes, an illegal key length or an
    illegal nested record encoding raises ValueError.

    Signatures and the cryptographic hop between records are not checked
    here — only :func:`verify_rotation_chain` confirms the records join
    into one authorized key-handoff sequence. The returned tuple
    preserves the encoded order, its elements equal the originally
    encoded four-tuples, and re-encoding reproduces the original bytes
    exactly.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_ROTATION_CHAIN_MAGIC):
        raise ValueError("not an auditchain rotation-chain encoding")
    offset = len(_ROTATION_CHAIN_MAGIC)

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
    if version != _ROTATION_CHAIN_VERSION:
        raise ValueError(f"unsupported rotation-chain version {version}")
    count = read_u64("record count")
    if count == 0:
        raise ValueError("rotation chain must contain at least one record")
    items = []
    for position in range(count):
        blob = read_blob(f"rotation record {position}")
        items.append(decode_rotation(blob))
    if offset != len(data):
        raise ValueError("trailing bytes after the rotation chain")
    return tuple(items)


def encode_signed_verifier(receipt: Any) -> bytes:
    """Encode a :class:`SignedVerifier` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/signed-verifier/v1\\0"``; every integer is an unsigned
    8-byte big-endian value and every blob is a u64 byte length followed by
    the raw bytes (a zero length is an all-zero u64). Fields appear in the
    order ``version`` (always 1), ``hash_name`` (UTF-8 blob), the verifier's
    ``key`` blob and ``signature`` blob. ``receipt`` must be a
    :class:`SignedVerifier` — anything else, or a receipt whose fields have
    been bypassed to wrong types, raises TypeError; a version other than 1,
    an unknown hash algorithm, an empty key or a signature that is not 64
    bytes raises ValueError. The encoding carries the verifier key in the
    clear — it authenticates provenance only, never encrypts — so the bytes
    must be protected exactly like a bare :class:`Verifier`. The call is
    read-only and deterministic: it never mutates the receipt, and
    re-encoding a decoded one reproduces the original bytes exactly.
    """
    if not isinstance(receipt, SignedVerifier):
        raise TypeError("receipt must be a SignedVerifier")
    # Re-validate every field even for a receipt built with
    # object.__setattr__ bypassing the frozen constructor (the constructor
    # also re-validates the nested Verifier), so structural corruption raises
    # exactly as the constructor would.
    checked = SignedVerifier(
        receipt.version,
        receipt.verifier,
        receipt.signature,
    )
    return b"".join((
        _SIGNED_VERIFIER_DOMAIN,
        _encode_u64(checked.version, "version"),
        _encode_blob(checked.verifier.hash_name.encode("utf-8")),
        _encode_blob(checked.verifier.key),
        _encode_blob(checked.signature),
    ))


def decode_signed_verifier(data: Any) -> SignedVerifier:
    """Decode bytes produced by :func:`encode_signed_verifier`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown hash algorithm, truncation,
    trailing bytes, an oversized blob length, an empty key or a signature
    that is not 64 bytes raises ValueError. The decoded receipt's fields
    equal the originally encoded ones, re-encoding reproduces the original
    bytes exactly, and it verifies under :func:`verify_signed_verifier`
    whenever the original did; a structurally sound encoding whose signature
    does not match the claimed verifier still decodes, and verification
    returns False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_VERIFIER_DOMAIN):
        raise ValueError("not an auditchain signed-verifier encoding")
    offset = len(_SIGNED_VERIFIER_DOMAIN)

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
    key = read_blob("key")
    signature = read_blob("signature")
    if offset != len(data):
        raise ValueError("trailing bytes after the signed verifier")
    return SignedVerifier(
        version=version,
        verifier=Verifier(key, hash_name),
        signature=signature,
    )


def encode_verifier(material: Any) -> bytes:
    """Encode a :class:`Verifier` into its canonical binary form.

    The encoding starts with the magic ``b"auditchain/verifier/v1\\0"``;
    every integer is an unsigned 8-byte big-endian value and every blob is a
    u64 byte length followed by the raw bytes (a zero length is an all-zero
    u64). Fields appear strictly in the order ``version`` (always 1),
    ``hash_name`` (UTF-8 blob) and ``key`` blob — there is no stage field,
    and nothing may be omitted, reordered or appended. ``material`` must be
    a :class:`Verifier` — anything else, or a material whose fields have
    been bypassed to wrong types, raises TypeError; an empty key or an
    unknown or non-fixed-output hash algorithm raises ValueError. The
    encoding carries the stage-0 key in the clear and must be protected
    exactly like the in-memory material. The call is read-only and
    deterministic: it never mutates the material, and re-encoding a decoded
    one reproduces the original bytes exactly.
    """
    if not isinstance(material, Verifier):
        raise TypeError("material must be a Verifier")
    # Re-validate every field even for a material built with
    # object.__setattr__ bypassing the frozen constructor, so structural
    # corruption raises exactly as the constructor would.
    checked = Verifier(
        material.key,
        material.hash_name,
    )
    return b"".join((
        _VERIFIER_MAGIC,
        _encode_u64(_VERIFIER_VERSION, "version"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_blob(checked.key),
    ))


def decode_verifier(data: Any) -> Verifier:
    """Decode bytes produced by :func:`encode_verifier`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown or non-fixed-output hash
    algorithm, truncation, trailing bytes, an oversized blob length or an
    empty key raises ValueError. The decoded material's fields equal the
    originally encoded ones, re-encoding reproduces the original bytes
    exactly, and it works unchanged with :func:`verify_auth` and
    :func:`verify_auth_batch`; the material is frozen and compares equal to
    the original on all fields.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_VERIFIER_MAGIC):
        raise ValueError("not an auditchain verifier encoding")
    offset = len(_VERIFIER_MAGIC)

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
    key = read_blob("key")
    if offset != len(data):
        raise ValueError("trailing bytes after the verifier")
    if version != _VERIFIER_VERSION:
        raise ValueError("unsupported verifier encoding version")
    return Verifier(key=key, hash_name=hash_name)


def encode_stage_verifier(material: Any) -> bytes:
    """Encode a :class:`StageVerifier` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/stage-verifier/v1\\0"``; every integer is an unsigned
    8-byte big-endian value and every blob is a u64 byte length followed by
    the raw bytes (a zero length is an all-zero u64). Fields appear strictly
    in the order ``version`` (always 1), ``stage``, ``hash_name`` (UTF-8
    blob) and ``key`` blob — nothing may be omitted, reordered or appended.
    ``material`` must be a :class:`StageVerifier` — anything else, or a
    material whose fields have been bypassed to wrong types, raises
    TypeError; an out-of-range stage, an empty or wrong-width key (at a
    positive stage it must be exactly one digest wide), or an unknown hash
    algorithm raises ValueError. The encoding carries the stage key in the
    clear and must be protected exactly like the in-memory material. The
    call is read-only and deterministic: it never mutates the material, and
    re-encoding a decoded one reproduces the original bytes exactly.
    """
    if not isinstance(material, StageVerifier):
        raise TypeError("material must be a StageVerifier")
    # Re-validate every field even for a material built with
    # object.__setattr__ bypassing the frozen constructor, so structural
    # corruption raises exactly as the constructor would.
    checked = StageVerifier(
        material.stage,
        material.key,
        material.hash_name,
    )
    return b"".join((
        _STAGE_VERIFIER_MAGIC,
        _encode_u64(_STAGE_VERIFIER_VERSION, "version"),
        _encode_u64(checked.stage, "stage"),
        _encode_blob(checked.hash_name.encode("utf-8")),
        _encode_blob(checked.key),
    ))


def decode_stage_verifier(data: Any) -> StageVerifier:
    """Decode bytes produced by :func:`encode_stage_verifier`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown hash algorithm, truncation,
    trailing bytes, an oversized blob length, an out-of-range stage, an
    empty key or a key that is not one digest wide at a positive stage
    raises ValueError. The decoded material's fields equal the originally
    encoded ones, re-encoding reproduces the original bytes exactly, and it
    works unchanged with :func:`verify_auth_stage`; the material is frozen
    and compares equal to the original on all fields.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_STAGE_VERIFIER_MAGIC):
        raise ValueError("not an auditchain stage-verifier encoding")
    offset = len(_STAGE_VERIFIER_MAGIC)

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
    stage = read_u64("stage")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    key = read_blob("key")
    if offset != len(data):
        raise ValueError("trailing bytes after the stage verifier")
    if version != _STAGE_VERIFIER_VERSION:
        raise ValueError("unsupported stage-verifier encoding version")
    return StageVerifier(stage=stage, key=key, hash_name=hash_name)


def encode_signed_stage_verifier(receipt: Any) -> bytes:
    """Encode a :class:`SignedStageVerifier` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/signed-stage/v1\\0"``; every integer is an unsigned
    8-byte big-endian value and every blob is a u64 byte length followed by
    the raw bytes (a zero length is an all-zero u64). Fields appear strictly
    in the order ``version`` (always 1), the nested verifier's ``stage``,
    ``hash_name`` (UTF-8 blob), ``key`` blob and ``signature`` blob —
    nothing may be omitted, reordered or appended. ``receipt`` must be a
    :class:`SignedStageVerifier` — anything else, or a receipt whose fields
    have been bypassed to wrong types, raises TypeError; a version other
    than 1, an out-of-range stage, an empty or wrong-width key, an unknown
    hash algorithm or a signature that is not 64 bytes raises ValueError.
    The encoding carries the stage key in the clear — the signature
    authenticates provenance only, never encrypts — so the bytes must be
    protected exactly like a bare :class:`StageVerifier`. The call is
    read-only and deterministic: it never mutates the receipt, and
    re-encoding a decoded one reproduces the original bytes exactly.
    """
    if not isinstance(receipt, SignedStageVerifier):
        raise TypeError("receipt must be a SignedStageVerifier")
    # Re-validate every field even for a receipt built with
    # object.__setattr__ bypassing the frozen constructor (the constructor
    # also re-validates the nested StageVerifier), so structural corruption
    # raises exactly as the constructor would.
    checked = SignedStageVerifier(
        receipt.version,
        receipt.verifier,
        receipt.signature,
    )
    return b"".join((
        _SIGNED_STAGE_DOMAIN,
        _encode_u64(checked.version, "version"),
        _encode_u64(checked.verifier.stage, "stage"),
        _encode_blob(checked.verifier.hash_name.encode("utf-8")),
        _encode_blob(checked.verifier.key),
        _encode_blob(checked.signature),
    ))


def decode_signed_stage_verifier(data: Any) -> SignedStageVerifier:
    """Decode bytes produced by :func:`encode_signed_stage_verifier`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). A bad magic, a version other than 1,
    invalid UTF-8 in ``hash_name``, an unknown hash algorithm, truncation,
    trailing bytes, an oversized blob length, an out-of-range stage, an
    empty key, a key that is not one digest wide at a positive stage or a
    signature that is not 64 bytes raises ValueError. The decoded receipt's
    fields equal the originally encoded ones, re-encoding reproduces the
    original bytes exactly, and it verifies under
    :func:`verify_signed_stage_verifier` whenever the original did; a
    structurally sound encoding whose signature does not match the claimed
    verifier still decodes, and verification returns False. The nested
    material is usable directly with :func:`verify_auth_stage`.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_STAGE_DOMAIN):
        raise ValueError("not an auditchain signed-stage encoding")
    offset = len(_SIGNED_STAGE_DOMAIN)

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
    stage = read_u64("stage")
    raw_name = read_blob("hash_name")
    try:
        hash_name = raw_name.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("hash_name is not valid UTF-8") from error
    key = read_blob("key")
    signature = read_blob("signature")
    if offset != len(data):
        raise ValueError("trailing bytes after the signed-stage verifier")
    return SignedStageVerifier(
        version=version,
        verifier=StageVerifier(stage, key, hash_name),
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


def encode_signed_audit_receipt(bundle: Any) -> bytes:
    """Encode a :class:`SignedAuditReceipt` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/signed-audit-receipt/v1\\0"``; it then writes, strictly in
    order, the envelope ``version`` (always 1) as an unsigned 8-byte
    big-endian integer, the receipt blob and the checkpoint blob — nothing
    may be omitted, reordered or appended. Each blob is a u64 byte length
    followed by the raw bytes: the receipt blob is the complete canonical
    output of :func:`encode_audit_receipt` over ``bundle.receipt`` and the
    checkpoint blob is the complete canonical output of
    :func:`encode_signed_root` over ``bundle.checkpoint``. No new signing
    message is introduced: encoding is read-only and only re-uses the
    existing canonical encodings.

    ``bundle`` must be a :class:`SignedAuditReceipt` — anything else, or a
    bundle whose container fields have been bypassed to wrong types, raises
    TypeError; nested structural problems raise exactly the exceptions of
    :func:`encode_audit_receipt` and :func:`encode_signed_root` (TypeError or
    ValueError). Encoding is deterministic: re-encoding a decoded bundle
    reproduces the original bytes exactly, and a structurally valid bundle
    whose signature does not match encodes just as well.
    """
    if not isinstance(bundle, SignedAuditReceipt):
        raise TypeError("bundle must be a SignedAuditReceipt")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would and a pair describing two
    # different snapshots raises its ValueError before any bytes are emitted.
    checked = SignedAuditReceipt(bundle.receipt, bundle.checkpoint)
    receipt_blob = encode_audit_receipt(checked.receipt)
    checkpoint_blob = encode_signed_root(checked.checkpoint)
    return b"".join((
        _SIGNED_AUDIT_RECEIPT_MAGIC,
        _encode_u64(_SIGNED_AUDIT_RECEIPT_VERSION, "version"),
        _encode_blob(receipt_blob),
        _encode_blob(checkpoint_blob),
    ))


def decode_signed_audit_receipt(data: Any) -> SignedAuditReceipt:
    """Decode bytes produced by :func:`encode_signed_audit_receipt`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signed-audit-receipt/v1\\0"`` it must contain, strictly in
    order, the u64 envelope version (only ``1`` is supported), one
    length-prefixed receipt blob and one length-prefixed checkpoint blob,
    with no trailing bytes. Each blob is handed whole to the existing
    decoder — :func:`decode_audit_receipt` and :func:`decode_signed_root`
    respectively — so every nested framing and structural rule is theirs. A
    bad magic or version, truncation, an oversized blob length, trailing
    bytes or an illegal nested encoding raises ValueError, as does a decoded
    pair whose receipt and checkpoint do not describe the same snapshot.

    The returned object is a frozen :class:`SignedAuditReceipt` whose fields
    equal the originally encoded ones, and re-encoding reproduces the
    original bytes exactly. A structurally sound encoding whose checkpoint
    signature simply does not verify still decodes;
    :func:`verify_signed_audit_receipt` reports False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_AUDIT_RECEIPT_MAGIC):
        raise ValueError("not an auditchain signed-audit-receipt encoding")
    offset = len(_SIGNED_AUDIT_RECEIPT_MAGIC)

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
    if version != _SIGNED_AUDIT_RECEIPT_VERSION:
        raise ValueError(
            f"unsupported signed-audit-receipt version {version}"
        )
    receipt_blob = read_blob("receipt")
    checkpoint_blob = read_blob("checkpoint")
    if offset != len(data):
        raise ValueError("trailing bytes after the signed audit receipt")
    # Decode both nested blobs with their existing decoders; their own magic,
    # version, truncation/trailing-byte and structural checks apply verbatim.
    receipt = decode_audit_receipt(receipt_blob)
    checkpoint = decode_signed_root(checkpoint_blob)
    return SignedAuditReceipt(receipt=receipt, checkpoint=checkpoint)


def encode_signed_search_receipt(bundle: Any) -> bytes:
    """Encode a :class:`SignedSearchReceipt` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/signed-search-receipt/v1\\0"``; it then writes, strictly in
    order, the envelope ``version`` (always 1) as an unsigned 8-byte
    big-endian integer, the receipt blob and the checkpoint blob — nothing
    may be omitted, reordered or appended. Each blob is a u64 byte length
    followed by the raw bytes: the receipt blob is the complete canonical
    output of :func:`encode_search_receipt` over ``bundle.receipt`` and the
    checkpoint blob is the complete canonical output of
    :func:`encode_signed_root` over ``bundle.checkpoint``. No new signing
    message is introduced: encoding is read-only and only re-uses the
    existing canonical encodings.

    ``bundle`` must be a :class:`SignedSearchReceipt` — anything else, or a
    bundle whose container fields have been bypassed to wrong types, raises
    TypeError; nested structural problems raise exactly the exceptions of
    :func:`encode_search_receipt` and :func:`encode_signed_root` (TypeError or
    ValueError). Encoding is deterministic: re-encoding a decoded bundle
    reproduces the original bytes exactly, and a structurally valid bundle
    whose signature does not match encodes just as well.
    """
    if not isinstance(bundle, SignedSearchReceipt):
        raise TypeError("bundle must be a SignedSearchReceipt")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would and a pair describing two
    # different snapshots raises its ValueError before any bytes are emitted.
    checked = SignedSearchReceipt(bundle.receipt, bundle.checkpoint)
    receipt_blob = encode_search_receipt(checked.receipt)
    checkpoint_blob = encode_signed_root(checked.checkpoint)
    return b"".join((
        _SIGNED_SEARCH_RECEIPT_MAGIC,
        _encode_u64(_SIGNED_SEARCH_RECEIPT_VERSION, "version"),
        _encode_blob(receipt_blob),
        _encode_blob(checkpoint_blob),
    ))


def decode_signed_search_receipt(data: Any) -> SignedSearchReceipt:
    """Decode bytes produced by :func:`encode_signed_search_receipt`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signed-search-receipt/v1\\0"`` it must contain, strictly in
    order, the u64 envelope version (only ``1`` is supported), one
    length-prefixed receipt blob and one length-prefixed checkpoint blob,
    with no trailing bytes. Each blob is handed whole to the existing
    decoder — :func:`decode_search_receipt` and :func:`decode_signed_root`
    respectively — so every nested framing and structural rule is theirs. A
    bad magic or version, truncation, an oversized blob length, trailing
    bytes or an illegal nested encoding raises ValueError, as does a decoded
    pair whose receipt and checkpoint do not describe the same snapshot.

    The returned object is a frozen :class:`SignedSearchReceipt` whose fields
    equal the originally encoded ones, and re-encoding reproduces the
    original bytes exactly. A structurally sound encoding whose checkpoint
    signature simply does not verify still decodes;
    :func:`verify_signed_search_receipt` reports False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_SEARCH_RECEIPT_MAGIC):
        raise ValueError("not an auditchain signed-search-receipt encoding")
    offset = len(_SIGNED_SEARCH_RECEIPT_MAGIC)

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
    if version != _SIGNED_SEARCH_RECEIPT_VERSION:
        raise ValueError(
            f"unsupported signed-search-receipt version {version}"
        )
    receipt_blob = read_blob("receipt")
    checkpoint_blob = read_blob("checkpoint")
    if offset != len(data):
        raise ValueError("trailing bytes after the signed search receipt")
    # Decode both nested blobs with their existing decoders; their own magic,
    # version, truncation/trailing-byte and structural checks apply verbatim.
    receipt = decode_search_receipt(receipt_blob)
    checkpoint = decode_signed_root(checkpoint_blob)
    return SignedSearchReceipt(receipt=receipt, checkpoint=checkpoint)


def encode_signed_encrypted_search_receipt(bundle: Any) -> bytes:
    """Encode a :class:`SignedEncryptedSearchReceipt` into its canonical
    binary form.

    The encoding starts with the magic
    ``b"auditchain/signed-encrypted-search/v1\\0"``; it then writes, strictly
    in order, the envelope ``version`` (always 1) as an unsigned 8-byte
    big-endian integer, the receipt blob and the checkpoint blob — nothing
    may be omitted, reordered or appended. Each blob is a u64 byte length
    followed by the raw bytes: the receipt blob is the complete canonical
    output of :func:`encode_encrypted_search_receipt` over ``bundle.receipt``
    and the checkpoint blob is the complete canonical output of
    :func:`encode_signed_root` over ``bundle.checkpoint``. No new signing
    message is introduced: encoding is read-only and only re-uses the
    existing canonical encodings.

    ``bundle`` must be a :class:`SignedEncryptedSearchReceipt` — anything
    else, or a bundle whose container fields have been bypassed to wrong
    types, raises TypeError; nested structural problems raise exactly the
    exceptions of :func:`encode_encrypted_search_receipt` and
    :func:`encode_signed_root` (TypeError or ValueError). Encoding is
    deterministic: re-encoding a decoded bundle reproduces the original
    bytes exactly, and a structurally valid bundle whose signature does not
    match encodes just as well.
    """
    if not isinstance(bundle, SignedEncryptedSearchReceipt):
        raise TypeError("bundle must be a SignedEncryptedSearchReceipt")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would and a pair describing two
    # different snapshots raises its ValueError before any bytes are emitted.
    checked = SignedEncryptedSearchReceipt(bundle.receipt, bundle.checkpoint)
    receipt_blob = encode_encrypted_search_receipt(checked.receipt)
    checkpoint_blob = encode_signed_root(checked.checkpoint)
    return b"".join((
        _SIGNED_ENCRYPTED_SEARCH_MAGIC,
        _encode_u64(_SIGNED_ENCRYPTED_SEARCH_VERSION, "version"),
        _encode_blob(receipt_blob),
        _encode_blob(checkpoint_blob),
    ))


def decode_signed_encrypted_search_receipt(data: Any) -> SignedEncryptedSearchReceipt:
    """Decode bytes produced by :func:`encode_signed_encrypted_search_receipt`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signed-encrypted-search/v1\\0"`` it must contain, strictly
    in order, the u64 envelope version (only ``1`` is supported), one
    length-prefixed receipt blob and one length-prefixed checkpoint blob,
    with no trailing bytes. Each blob is handed whole to the existing
    decoder — :func:`decode_encrypted_search_receipt` and
    :func:`decode_signed_root` respectively — so every nested framing and
    structural rule is theirs. A bad magic or version, truncation, an
    oversized blob length, trailing bytes or an illegal nested encoding
    raises ValueError, as does a decoded pair whose receipt and checkpoint
    do not describe the same snapshot.

    The returned object is a frozen :class:`SignedEncryptedSearchReceipt`
    whose fields equal the originally encoded ones, and re-encoding
    reproduces the original bytes exactly. A structurally sound encoding
    whose checkpoint signature simply does not verify still decodes;
    :func:`verify_signed_encrypted_search_receipt` reports False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_ENCRYPTED_SEARCH_MAGIC):
        raise ValueError("not an auditchain signed-encrypted-search encoding")
    offset = len(_SIGNED_ENCRYPTED_SEARCH_MAGIC)

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
    if version != _SIGNED_ENCRYPTED_SEARCH_VERSION:
        raise ValueError(
            f"unsupported signed-encrypted-search version {version}"
        )
    receipt_blob = read_blob("receipt")
    checkpoint_blob = read_blob("checkpoint")
    if offset != len(data):
        raise ValueError(
            "trailing bytes after the signed encrypted search receipt"
        )
    # Decode both nested blobs with their existing decoders; their own magic,
    # version, truncation/trailing-byte and structural checks apply verbatim.
    receipt = decode_encrypted_search_receipt(receipt_blob)
    checkpoint = decode_signed_root(checkpoint_blob)
    return SignedEncryptedSearchReceipt(receipt=receipt, checkpoint=checkpoint)


def encode_signed_full_search_receipt(bundle: Any) -> bytes:
    """Encode a :class:`SignedFullSearchReceipt` into its canonical binary
    form.

    The encoding starts with the magic
    ``b"auditchain/signed-full-search/v1\\0"``; it then writes, strictly in
    order, the envelope ``version`` (always 1) as an unsigned 8-byte
    big-endian integer, the receipt blob and the checkpoint blob — nothing
    may be omitted, reordered or appended. Each blob is a u64 byte length
    followed by the raw bytes: the receipt blob is the complete canonical
    output of :func:`encode_full_search_receipt` over ``bundle.receipt`` and
    the checkpoint blob is the complete canonical output of
    :func:`encode_signed_root` over ``bundle.checkpoint``. No new signing
    message is introduced: encoding is read-only and only re-uses the
    existing canonical encodings.

    ``bundle`` must be a :class:`SignedFullSearchReceipt` — anything else, or
    a bundle whose container fields have been bypassed to wrong types, raises
    TypeError; nested structural problems raise exactly the exceptions of
    :func:`encode_full_search_receipt` and :func:`encode_signed_root`
    (TypeError or ValueError). Encoding is deterministic: re-encoding a
    decoded bundle reproduces the original bytes exactly, and a structurally
    valid bundle whose signature does not match encodes just as well.
    """
    if not isinstance(bundle, SignedFullSearchReceipt):
        raise TypeError("bundle must be a SignedFullSearchReceipt")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would and a pair describing two
    # different snapshots raises its ValueError before any bytes are emitted.
    checked = SignedFullSearchReceipt(bundle.receipt, bundle.checkpoint)
    receipt_blob = encode_full_search_receipt(checked.receipt)
    checkpoint_blob = encode_signed_root(checked.checkpoint)
    return b"".join((
        _SIGNED_FULL_SEARCH_MAGIC,
        _encode_u64(_SIGNED_FULL_SEARCH_VERSION, "version"),
        _encode_blob(receipt_blob),
        _encode_blob(checkpoint_blob),
    ))


def decode_signed_full_search_receipt(data: Any) -> SignedFullSearchReceipt:
    """Decode bytes produced by :func:`encode_signed_full_search_receipt`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signed-full-search/v1\\0"`` it must contain, strictly in
    order, the u64 envelope version (only ``1`` is supported), one
    length-prefixed receipt blob and one length-prefixed checkpoint blob,
    with no trailing bytes. Each blob is handed whole to the existing
    decoder — :func:`decode_full_search_receipt` and
    :func:`decode_signed_root` respectively — so every nested framing and
    structural rule is theirs. A bad magic or version, truncation, an
    oversized blob length, trailing bytes or an illegal nested encoding
    raises ValueError, as does a decoded pair whose receipt and checkpoint
    do not describe the same snapshot.

    The returned object is a frozen :class:`SignedFullSearchReceipt` whose
    fields equal the originally encoded ones, and re-encoding reproduces the
    original bytes exactly. A structurally sound encoding whose checkpoint
    signature simply does not verify still decodes;
    :func:`verify_signed_full_search_receipt` reports False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_FULL_SEARCH_MAGIC):
        raise ValueError("not an auditchain signed-full-search encoding")
    offset = len(_SIGNED_FULL_SEARCH_MAGIC)

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
    if version != _SIGNED_FULL_SEARCH_VERSION:
        raise ValueError(
            f"unsupported signed-full-search version {version}"
        )
    receipt_blob = read_blob("receipt")
    checkpoint_blob = read_blob("checkpoint")
    if offset != len(data):
        raise ValueError("trailing bytes after the signed full search receipt")
    # Decode both nested blobs with their existing decoders; their own magic,
    # version, truncation/trailing-byte and structural checks apply verbatim.
    receipt = decode_full_search_receipt(receipt_blob)
    checkpoint = decode_signed_root(checkpoint_blob)
    return SignedFullSearchReceipt(receipt=receipt, checkpoint=checkpoint)


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


def encode_signed_auth_bundle(bundle: Any) -> bytes:
    """Encode a :class:`SignedAuthBundle` into its canonical binary form.

    The byte stream is ``D || U(1) || B(S) || B(A)`` with
    ``D = b"auditchain/signed-auth-bundle/v1\\0"``, ``U`` an unsigned
    8-byte big-endian integer and ``B(x) = U(len(x)) || x``: the envelope
    ``version`` (always 1), then the verifier blob and the auth-batch blob
    — nothing may be omitted, reordered or appended. ``S`` is the complete
    canonical output of :func:`encode_signed_verifier` over
    ``bundle.verifier`` and ``A`` the complete canonical output of
    :func:`encode_auth_batch` over ``bundle.items`` with
    ``hash_name=bundle.hash_name``. No new signing message is introduced:
    encoding is read-only and only re-uses the existing canonical
    encodings.

    ``bundle`` must be a :class:`SignedAuthBundle` — anything else raises
    TypeError; nested structural problems raise exactly the exceptions of
    :func:`encode_signed_verifier` and :func:`encode_auth_batch`
    (TypeError or ValueError). The encoding carries the verifier key in
    the clear — it authenticates provenance only, never encrypts — so the
    bytes must be protected exactly like a bare :class:`Verifier`.
    Encoding is deterministic: re-encoding a decoded bundle reproduces the
    original bytes exactly, and a structurally valid bundle whose
    signature or tags do not match encodes just as well.
    """
    if not isinstance(bundle, SignedAuthBundle):
        raise TypeError("bundle must be a SignedAuthBundle")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedAuthBundle(bundle.verifier, bundle.hash_name, bundle.items)
    verifier_blob = encode_signed_verifier(checked.verifier)
    batch_blob = encode_auth_batch(checked.items, hash_name=checked.hash_name)
    return b"".join((
        _SIGNED_AUTH_BUNDLE_MAGIC,
        _encode_u64(_SIGNED_AUTH_BUNDLE_VERSION, "version"),
        _encode_blob(verifier_blob),
        _encode_blob(batch_blob),
    ))


def decode_signed_auth_bundle(data: Any) -> SignedAuthBundle:
    """Decode bytes produced by :func:`encode_signed_auth_bundle`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signed-auth-bundle/v1\\0"`` it must contain, strictly in
    order, the u64 envelope version (only ``1`` is supported), one
    length-prefixed verifier blob and one length-prefixed auth-batch blob,
    with no trailing bytes. Each blob is handed whole to the existing
    decoder — :func:`decode_signed_verifier` and :func:`decode_auth_batch`
    respectively — so every nested framing and structural rule is theirs,
    and the hash algorithm named by the auth batch must equal the signed
    verifier's algorithm. A bad magic or version, truncation, an oversized
    blob length, trailing bytes, an illegal nested encoding or a hash
    algorithm disagreement between the two parts raises ValueError.

    The returned object is a frozen :class:`SignedAuthBundle` whose fields
    equal the originally encoded ones, and re-encoding reproduces the
    original bytes exactly. A structurally sound encoding whose signature
    or tags simply do not verify still decodes;
    :func:`verify_signed_auth_bundle` reports False per item.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_AUTH_BUNDLE_MAGIC):
        raise ValueError("not an auditchain signed-auth-bundle encoding")
    offset = len(_SIGNED_AUTH_BUNDLE_MAGIC)

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
    if version != _SIGNED_AUTH_BUNDLE_VERSION:
        raise ValueError(
            f"unsupported signed-auth-bundle version {version}"
        )
    verifier_blob = read_blob("verifier")
    batch_blob = read_blob("auth batch")
    if offset != len(data):
        raise ValueError("trailing bytes after the signed auth bundle")
    # Decode both nested blobs with their existing decoders; their own magic,
    # version, truncation/trailing-byte and structural checks apply verbatim.
    verifier = decode_signed_verifier(verifier_blob)
    hash_name, items = decode_auth_batch(batch_blob)
    # The two parts must describe one delivery: the batch's hash algorithm
    # is the one the signed stage-0 verifier mints tags under.
    if hash_name != verifier.verifier.hash_name:
        raise ValueError(
            "auth batch hash_name does not match the signed verifier"
        )
    return SignedAuthBundle(verifier=verifier, hash_name=hash_name, items=items)


def encode_signed_stage_auth_bundle(bundle: Any) -> bytes:
    """Encode a :class:`SignedStageAuthBundle` into its canonical binary form.

    The byte stream is ``D || U(1) || B(S) || B(A)`` with
    ``D = b"auditchain/signed-stage-auth-bundle/v1\\0"``, ``U`` an unsigned
    8-byte big-endian integer and ``B(x) = U(len(x)) || x``: the envelope
    ``version`` (always 1), then the signed stage verifier blob and the
    auth-batch blob — nothing may be omitted, reordered or appended. ``S`` is
    the complete canonical output of :func:`encode_signed_stage_verifier`
    over ``bundle.verifier`` and ``A`` the complete canonical output of
    :func:`encode_auth_batch` over ``bundle.items`` with
    ``hash_name=bundle.hash_name``. No new signing message is introduced:
    encoding is read-only and only re-uses the existing canonical encodings.

    ``bundle`` must be a :class:`SignedStageAuthBundle` — anything else
    raises TypeError; nested structural problems raise exactly the
    exceptions of :func:`encode_signed_stage_verifier` and
    :func:`encode_auth_batch` (TypeError or ValueError), and a bundle whose
    batch hash algorithm disagrees with the algorithm named by the signed
    stage verifier raises ValueError — encoding never leaves a half result.
    The encoding carries the stage key in the clear — it authenticates
    provenance only, never encrypts — so the bytes must be protected
    exactly like a bare :class:`StageVerifier`. Encoding is deterministic:
    re-encoding a decoded bundle reproduces the original bytes exactly, and
    a structurally valid bundle whose signature or tags do not match
    encodes just as well.
    """
    if not isinstance(bundle, SignedStageAuthBundle):
        raise TypeError("bundle must be a SignedStageAuthBundle")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedStageAuthBundle(
        bundle.verifier, bundle.hash_name, bundle.items
    )
    # Encode both nested parts first; their own re-validation classifies
    # every nested type/structure error with its existing TypeError /
    # ValueError discipline. Only once both canonical byte strings exist
    # do we require them to describe one delivery: the batch's hash
    # algorithm is the one the signed delivery-stage verifier mints tags
    # under. A disagreeing bundle raises ValueError without returning any
    # (half) result.
    verifier_blob = encode_signed_stage_verifier(checked.verifier)
    batch_blob = encode_auth_batch(checked.items, hash_name=checked.hash_name)
    if checked.hash_name != checked.verifier.verifier.hash_name:
        raise ValueError(
            "auth batch hash_name does not match the signed stage verifier"
        )
    return b"".join((
        _SIGNED_STAGE_AUTH_BUNDLE_MAGIC,
        _encode_u64(_SIGNED_STAGE_AUTH_BUNDLE_VERSION, "version"),
        _encode_blob(verifier_blob),
        _encode_blob(batch_blob),
    ))


def decode_signed_stage_auth_bundle(data: Any) -> SignedStageAuthBundle:
    """Decode bytes produced by :func:`encode_signed_stage_auth_bundle`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signed-stage-auth-bundle/v1\\0"`` it must contain,
    strictly in order, the u64 envelope version (only ``1`` is supported),
    one length-prefixed signed stage verifier blob and one length-prefixed
    auth-batch blob, with no trailing bytes. Each blob is handed whole to
    the existing decoder — :func:`decode_signed_stage_verifier` and
    :func:`decode_auth_batch` respectively — so every nested framing and
    structural rule is theirs, and the hash algorithm named by the auth
    batch must equal the signed stage verifier's algorithm. A bad magic or
    version, truncation, an oversized blob length, trailing bytes, an
    illegal nested encoding or a hash algorithm disagreement between the
    two parts raises ValueError.

    The returned object is a frozen :class:`SignedStageAuthBundle` whose
    fields equal the originally encoded ones (an empty batch round-trips as
    ``()``), and re-encoding reproduces the original bytes exactly. A
    structurally sound encoding whose signature or tags simply do not
    verify still decodes; :func:`verify_signed_stage_auth_bundle` reports
    False per item.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_STAGE_AUTH_BUNDLE_MAGIC):
        raise ValueError("not an auditchain signed-stage-auth-bundle encoding")
    offset = len(_SIGNED_STAGE_AUTH_BUNDLE_MAGIC)

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
    if version != _SIGNED_STAGE_AUTH_BUNDLE_VERSION:
        raise ValueError(
            f"unsupported signed-stage-auth-bundle version {version}"
        )
    verifier_blob = read_blob("verifier")
    batch_blob = read_blob("auth batch")
    if offset != len(data):
        raise ValueError("trailing bytes after the signed stage auth bundle")
    # Decode both nested blobs with their existing decoders; their own magic,
    # version, truncation/trailing-byte and structural checks apply verbatim.
    verifier = decode_signed_stage_verifier(verifier_blob)
    hash_name, items = decode_auth_batch(batch_blob)
    # The two parts must describe one delivery: the batch's hash algorithm
    # is the one the signed delivery-stage verifier mints tags under.
    if hash_name != verifier.verifier.hash_name:
        raise ValueError(
            "auth batch hash_name does not match the signed stage verifier"
        )
    return SignedStageAuthBundle(
        verifier=verifier, hash_name=hash_name, items=items
    )


def encode_signed_stage_auth_audit_bundle(bundle: Any) -> bytes:
    """Encode a :class:`SignedStageAuthAuditBundle` into canonical bytes.

    The byte stream is ``D || U(1) || B(A) || B(M)`` with
    ``D = b"auditchain/signed-stage-auth-audit/v1\\0"``, ``U`` an unsigned
    8-byte big-endian integer and ``B(x) = U(len(x)) || x``: the envelope
    ``version`` (always 1), then the signed stage auth bundle blob and the
    signed audit batch blob — nothing may be omitted, reordered or appended.
    ``A`` is the complete canonical output of
    :func:`encode_signed_stage_auth_bundle` over ``bundle.auth`` and ``M``
    the complete canonical output of :func:`encode_signed_audit_batch` over
    ``bundle.audit``. No new signing message is introduced: encoding is
    read-only and only re-uses the existing canonical encodings.

    ``bundle`` must be a :class:`SignedStageAuthAuditBundle` — anything else
    raises TypeError; nested structural problems raise exactly the
    exceptions of :func:`encode_signed_stage_auth_bundle` and
    :func:`encode_signed_audit_batch` (TypeError or ValueError), and a
    bundle whose signed audit batch names a hash algorithm other than the
    one the auth half (and its signed delivery-stage verifier) mints under
    raises ValueError — encoding never leaves a half result. The encoding
    carries the stage key in the clear — it authenticates provenance only,
    never encrypts — so the bytes must be protected exactly like a bare
    :class:`StageVerifier`. Encoding is deterministic: re-encoding a decoded
    bundle reproduces the original bytes exactly, and a structurally valid
    bundle whose signatures, tags, proof or checkpoint do not match encodes
    just as well.
    """
    if not isinstance(bundle, SignedStageAuthAuditBundle):
        raise TypeError(
            "bundle must be a SignedStageAuthAuditBundle"
        )
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedStageAuthAuditBundle(bundle.auth, bundle.audit)
    # Encode both nested parts first; their own re-validation classifies
    # every nested type/structure error with its existing TypeError /
    # ValueError discipline (the auth encoder also pins its batch algorithm
    # to the signed stage verifier's). Only once both canonical byte strings
    # exist do we require the audit half to name that same algorithm, so a
    # disagreeing bundle raises ValueError without returning any (half)
    # result.
    auth_blob = encode_signed_stage_auth_bundle(checked.auth)
    audit_blob = encode_signed_audit_batch(checked.audit)
    if checked.auth.hash_name != checked.audit.batch[0]:
        raise ValueError(
            "signed audit batch hash_name does not match the signed stage "
            "auth bundle"
        )
    return b"".join((
        _SIGNED_STAGE_AUTH_AUDIT_MAGIC,
        _encode_u64(_SIGNED_STAGE_AUTH_AUDIT_VERSION, "version"),
        _encode_blob(auth_blob),
        _encode_blob(audit_blob),
    ))


def decode_signed_stage_auth_audit_bundle(
    data: Any,
) -> SignedStageAuthAuditBundle:
    """Decode bytes produced by :func:`encode_signed_stage_auth_audit_bundle`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/signed-stage-auth-audit/v1\\0"`` it must contain,
    strictly in order, the u64 envelope version (only ``1`` is supported),
    one length-prefixed signed stage auth bundle blob and one
    length-prefixed signed audit batch blob, with no trailing bytes. Each
    blob is handed whole to the existing decoder —
    :func:`decode_signed_stage_auth_bundle` and
    :func:`decode_signed_audit_batch` respectively — so every nested framing
    and structural rule is theirs, and the signed audit batch's hash
    algorithm must equal the auth bundle's algorithm (which already equals
    its signed stage verifier's). A bad magic or version, truncation, an
    oversized blob length, trailing bytes, an illegal nested encoding or a
    hash algorithm disagreement between the two parts raises ValueError.

    The returned object is a frozen :class:`SignedStageAuthAuditBundle`
    whose two fields equal the originally encoded ones (an empty auth batch
    round-trips as ``()`` and the zero-item structure is not omitted), and
    re-encoding reproduces the original bytes exactly. A structurally sound
    encoding whose signatures, tags, proof or checkpoint simply do not
    verify still decodes; :func:`verify_signed_stage_auth_audit_bundle`
    reports False without raising.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_STAGE_AUTH_AUDIT_MAGIC):
        raise ValueError(
            "not an auditchain signed-stage-auth-audit encoding"
        )
    offset = len(_SIGNED_STAGE_AUTH_AUDIT_MAGIC)

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
    if version != _SIGNED_STAGE_AUTH_AUDIT_VERSION:
        raise ValueError(
            f"unsupported signed-stage-auth-audit version {version}"
        )
    auth_blob = read_blob("signed stage auth bundle")
    audit_blob = read_blob("signed audit batch")
    if offset != len(data):
        raise ValueError(
            "trailing bytes after the signed stage auth audit bundle"
        )
    # Decode both nested blobs with their existing decoders; their own
    # magic, version, truncation/trailing-byte and structural checks apply
    # verbatim (the auth decoder also pins its batch algorithm to the
    # signed stage verifier's algorithm).
    auth = decode_signed_stage_auth_bundle(auth_blob)
    audit = decode_signed_audit_batch(audit_blob)
    # The two packages must be minted under one hash algorithm.
    if auth.hash_name != audit.batch[0]:
        raise ValueError(
            "signed audit batch hash_name does not match the signed stage "
            "auth bundle"
        )
    return SignedStageAuthAuditBundle(auth=auth, audit=audit)


def verify_signed_auth_audit_bundle(bundle: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedAuthAuditBundle` against a pre-trusted Ed25519 key.

    Confirms the whole trusted-delivery bundle entirely offline, without
    holding the log, in four steps:

    1. :func:`verify_signed_verifier` checks the nested
       :class:`SignedVerifier` signature with the 32-byte
       ``public_key`` (explicitly, so even an empty auth selection cannot
       pass vacuously), and :func:`verify_auth_batch` must return ``True``
       at every item position;
    2. :func:`verify_signed_audit_batch` verifies the signed batch audit —
       its shared inclusion proof, its checkpoint signature and its
       snapshot linkage;
    3. both packages must name one hash algorithm: the auth bundle's
       ``hash_name``, its signed verifier's algorithm and the audit
       batch's ``hash_name`` must all agree;
    4. every entry the auth package authenticates must be byte-for-byte
       the :class:`Entry` the audit package carries at the same absolute
       index (the audit package normally also carries the snapshot's last
       entry, which the auth package need not tag).

    A genuine bundle from the trusted key returns True; a structurally
    valid bundle signed by another key, whose two packages disagree on the
    algorithm or snapshot, whose entries differ at a shared index, or
    whose signatures, tags, proof or entries have been altered returns
    False. Input that is not a :class:`SignedAuthAuditBundle` (or whose
    container fields have been bypassed to wrong types) raises TypeError;
    nested structural violations raise exactly the exceptions of
    :func:`verify_signed_auth_bundle` and
    :func:`verify_signed_audit_batch` (TypeError or ValueError), and a
    public key that is not 32 ``bytes`` raises ValueError (a non-``bytes``
    key TypeError). The call is read-only and never mutates the bundle.
    """
    if not isinstance(bundle, SignedAuthAuditBundle):
        raise TypeError("bundle must be a SignedAuthAuditBundle")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedAuthAuditBundle(bundle.auth, bundle.audit)

    # Check the signed stage-0 verifier explicitly as well: with an empty
    # auth selection verify_signed_auth_bundle reports an empty tuple, whose
    # all() would otherwise pass vacuously.
    if not verify_signed_verifier(checked.auth.verifier, public_key):
        return False
    if not all(verify_signed_auth_bundle(checked.auth, public_key)):
        return False
    if not verify_signed_audit_batch(checked.audit, public_key):
        return False

    auth = checked.auth
    audit = checked.audit
    audit_hash_name, _audit_size, _root, audit_entries, _proof = audit.batch
    # The two packages must be minted under one hash algorithm. The
    # verifier/audit equalities also cover the empty-selection cases that
    # never carry per-item evidence.
    if auth.hash_name != auth.verifier.verifier.hash_name:
        return False
    if auth.hash_name != audit_hash_name:
        return False

    # Every authenticated entry must be exactly the record the audit
    # package carries at the same absolute index. verify_audit_batch has
    # already guaranteed the audit entries are distinct and ascending, so a
    # dict loses no correspondence. Entry equality covers the index (the
    # lookup key) and all three byte fields.
    audit_by_index = {entry.index: entry for entry in audit_entries}
    for entry, _tag in auth.items:
        if audit_by_index.get(entry.index) != entry:
            return False
    return True


def verify_signed_auth_audit_continuation(receipt: Any, public_key: Any) -> bool:
    """Verify a :class:`SignedAuthAuditContinuation` against a pre-trusted key.

    Confirms the whole cross-snapshot continuation entirely offline, without
    holding the log, in three steps:

    1. :func:`verify_signed_auth_audit_bundle` verifies the nested
       :class:`SignedAuthAuditBundle` — the signed stage-0 verifier, the
       per-item forward-secure tags, the batch inclusion proof, the audit
       checkpoint signature and the entry correspondence at shared indices;
    2. :func:`verify_signed_consistency` verifies the nested
       :class:`SignedConsistency` — both checkpoint signatures and the
       Merkle proof linking the old prefix to the new snapshot;
    3. the two packages must describe one chain: they must name one hash
       algorithm, and the consistency's ``new`` checkpoint must be
       byte-for-byte (all six fields, including the signature) the audit
       package's checkpoint, so the consistency proves exactly the snapshot
       the authenticated entries were audited against — it introduces no
       signing domain of its own.

    A genuine continuation from the trusted key returns True; a
    structurally valid continuation signed by another key, whose two
    packages disagree on the algorithm or snapshot, whose ``new``
    checkpoint differs from the audit checkpoint in any field, or whose
    signatures, tags, proof or entries have been altered returns False.
    Input that is not a :class:`SignedAuthAuditContinuation` (or whose
    container fields have been bypassed to wrong types) raises TypeError;
    nested structural violations raise exactly the exceptions of
    :func:`verify_signed_auth_audit_bundle` and
    :func:`verify_signed_consistency` (TypeError or ValueError), and a
    public key that is not 32 ``bytes`` raises ValueError (a non-``bytes``
    key TypeError). The call is read-only and never mutates the receipt.
    """
    if not isinstance(receipt, SignedAuthAuditContinuation):
        raise TypeError("receipt must be a SignedAuthAuditContinuation")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedAuthAuditContinuation(receipt.bundle, receipt.consistency)
    if not verify_signed_auth_audit_bundle(checked.bundle, public_key):
        return False
    if not verify_signed_consistency(checked.consistency, public_key):
        return False
    bundle = checked.bundle
    consistency = checked.consistency
    # The decisive linkage, covering algorithm consistency as well: the
    # bundle verifier already pinned its auth/verifier/audit algorithms and
    # the consistency verifier pinned old to new; requiring the
    # consistency's new checkpoint to equal the audit checkpoint on every
    # field — hash_name, size, root, head and the signature itself — then
    # pins the two packages to one algorithm and proves the consistency
    # extends exactly the snapshot the entries were audited against, with
    # no signing domain of its own.
    return consistency.new == bundle.audit.checkpoint


def encode_signed_auth_audit_bundle(x: Any) -> bytes:
    """Encode a :class:`SignedAuthAuditBundle` into its canonical binary form.

    The byte stream is ``D || U(1) || B(A) || B(M)`` with
    ``D = b"auditchain/auth-audit/v1\\0"``, ``U`` an unsigned 8-byte
    big-endian integer and ``B(x) = U(len(x)) || x``: the envelope
    ``version`` (always 1), then the auth blob and the audit blob — nothing
    may be omitted, reordered or appended. ``A`` is the complete canonical
    output of :func:`encode_signed_auth_bundle` over ``x.auth`` and ``M``
    the complete canonical output of :func:`encode_signed_audit_batch` over
    ``x.audit``. No new signing message is introduced: encoding is
    read-only and only re-uses the existing canonical encodings.

    ``x`` must be a :class:`SignedAuthAuditBundle` — anything else raises
    TypeError; nested structural problems raise exactly the exceptions of
    :func:`encode_signed_auth_bundle` and
    :func:`encode_signed_audit_batch` (TypeError or ValueError). Encoding
    is deterministic: re-encoding a decoded bundle reproduces the original
    bytes exactly, and a structurally valid bundle whose signatures or tags
    do not match encodes just as well.
    """
    if not isinstance(x, SignedAuthAuditBundle):
        raise TypeError("x must be a SignedAuthAuditBundle")
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedAuthAuditBundle(x.auth, x.audit)
    auth_blob = encode_signed_auth_bundle(checked.auth)
    audit_blob = encode_signed_audit_batch(checked.audit)
    return b"".join((
        _SIGNED_AUTH_AUDIT_MAGIC,
        _encode_u64(_SIGNED_AUTH_AUDIT_VERSION, "version"),
        _encode_blob(auth_blob),
        _encode_blob(audit_blob),
    ))


def decode_signed_auth_audit_bundle(data: Any) -> SignedAuthAuditBundle:
    """Decode bytes produced by :func:`encode_signed_auth_audit_bundle`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/auth-audit/v1\\0"`` it must contain, strictly in order,
    the u64 envelope version (only ``1`` is supported), one
    length-prefixed auth blob and one length-prefixed audit blob, with no
    trailing bytes. Each blob is handed whole to the existing decoder —
    :func:`decode_signed_auth_bundle` and
    :func:`decode_signed_audit_batch` respectively — so every nested
    framing and structural rule is theirs, and the auth bundle's hash
    algorithm must equal the audit batch's algorithm. A bad magic or
    version, truncation, an oversized blob length, trailing bytes, an
    illegal nested encoding or a hash algorithm disagreement between the
    two packages raises ValueError.

    The returned object is a frozen :class:`SignedAuthAuditBundle` whose
    fields equal the originally encoded ones, and re-encoding reproduces
    the original bytes exactly. A structurally sound encoding whose
    signatures or tags simply do not verify still decodes;
    :func:`verify_signed_auth_audit_bundle` reports False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_AUTH_AUDIT_MAGIC):
        raise ValueError("not an auditchain auth-audit encoding")
    offset = len(_SIGNED_AUTH_AUDIT_MAGIC)

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
    if version != _SIGNED_AUTH_AUDIT_VERSION:
        raise ValueError(f"unsupported auth-audit version {version}")
    auth_blob = read_blob("auth bundle")
    audit_blob = read_blob("signed audit batch")
    if offset != len(data):
        raise ValueError("trailing bytes after the auth-audit bundle")
    # Decode both nested blobs with their existing decoders; their own
    # magic, version, truncation/trailing-byte and structural checks apply
    # verbatim (the auth decoder also pins its verifier algorithm).
    auth = decode_signed_auth_bundle(auth_blob)
    audit = decode_signed_audit_batch(audit_blob)
    # The two packages must be minted under one hash algorithm.
    if auth.hash_name != audit.batch[0]:
        raise ValueError(
            "signed audit batch hash_name does not match the auth bundle"
        )
    return SignedAuthAuditBundle(auth=auth, audit=audit)


def encode_signed_auth_audit_continuation(receipt: Any) -> bytes:
    """Encode a :class:`SignedAuthAuditContinuation` into canonical bytes.

    The byte stream is ``D || U(1) || B(A) || B(C)`` with
    ``D = b"auditchain/auth-audit-continuation/v1\\0"``, ``U`` an unsigned
    8-byte big-endian integer and ``B(x) = U(len(x)) || x``: the envelope
    ``version`` (always 1), then the bundle blob and the consistency blob —
    nothing may be omitted, reordered or appended. ``A`` is byte-for-byte
    the complete canonical output of
    :func:`encode_signed_auth_audit_bundle` over ``receipt.bundle`` and
    ``C`` the complete canonical output of
    :func:`encode_signed_consistency` over ``receipt.consistency``. No new
    signing message is introduced: encoding is read-only and only re-uses
    the existing canonical encodings.

    ``receipt`` must be a :class:`SignedAuthAuditContinuation` — anything
    else raises TypeError; nested structural problems raise exactly the
    exceptions of :func:`encode_signed_auth_audit_bundle` and
    :func:`encode_signed_consistency` (TypeError or ValueError). Encoding
    is deterministic: re-encoding a decoded receipt reproduces the original
    bytes exactly, and a structurally valid receipt whose signatures, tags,
    proof or checkpoint linkage do not match encodes just as well.
    """
    if not isinstance(receipt, SignedAuthAuditContinuation):
        raise TypeError(
            "receipt must be a SignedAuthAuditContinuation"
        )
    # Re-validate the container even for an instance whose fields were set
    # bypassing the frozen constructor, so container-type corruption raises
    # TypeError exactly as the constructor would.
    checked = SignedAuthAuditContinuation(
        receipt.bundle, receipt.consistency
    )
    bundle_blob = encode_signed_auth_audit_bundle(checked.bundle)
    consistency_blob = encode_signed_consistency(checked.consistency)
    return b"".join((
        _SIGNED_AUTH_AUDIT_CONTINUATION_MAGIC,
        _encode_u64(_SIGNED_AUTH_AUDIT_CONTINUATION_VERSION, "version"),
        _encode_blob(bundle_blob),
        _encode_blob(consistency_blob),
    ))


def decode_signed_auth_audit_continuation(
    data: Any,
) -> SignedAuthAuditContinuation:
    """Decode bytes produced by :func:`encode_signed_auth_audit_continuation`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/auth-audit-continuation/v1\\0"`` it must contain,
    strictly in order, the u64 envelope version (only ``1`` is supported),
    one length-prefixed bundle blob and one length-prefixed consistency
    blob, with no trailing bytes. Each blob is handed whole to the existing
    decoder — :func:`decode_signed_auth_audit_bundle` and
    :func:`decode_signed_consistency` respectively — so every nested
    framing and structural rule is theirs. A bad magic or version,
    truncation, an oversized blob length, trailing bytes or an illegal
    nested encoding raises ValueError.

    Signatures, tags, proof content and the linkage between the
    consistency's ``new`` checkpoint and the audit checkpoint are not
    checked here. The returned object is a frozen
    :class:`SignedAuthAuditContinuation` whose fields equal the originally
    encoded ones, and re-encoding reproduces the original bytes exactly. A
    structurally sound encoding whose verification simply does not pass
    still decodes; :func:`verify_signed_auth_audit_continuation` reports
    False.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_SIGNED_AUTH_AUDIT_CONTINUATION_MAGIC):
        raise ValueError(
            "not an auditchain auth-audit-continuation encoding"
        )
    offset = len(_SIGNED_AUTH_AUDIT_CONTINUATION_MAGIC)

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
    if version != _SIGNED_AUTH_AUDIT_CONTINUATION_VERSION:
        raise ValueError(
            f"unsupported auth-audit-continuation version {version}"
        )
    bundle_blob = read_blob("auth audit bundle")
    consistency_blob = read_blob("signed consistency")
    if offset != len(data):
        raise ValueError(
            "trailing bytes after the auth-audit continuation receipt"
        )
    # Decode both nested blobs with their existing decoders; their own
    # magic, version, truncation/trailing-byte and structural checks apply
    # verbatim (the bundle decoder also pins its nested algorithms).
    bundle = decode_signed_auth_audit_bundle(bundle_blob)
    consistency = decode_signed_consistency(consistency_blob)
    return SignedAuthAuditContinuation(
        bundle=bundle, consistency=consistency
    )


def verify_continuation_chain(receipts: Any, public_key: Any) -> bool:
    """Verify a non-empty tuple of chained continuation receipts offline.

    ``receipts`` must be a non-empty ``tuple`` whose elements are frozen
    :class:`SignedAuthAuditContinuation` objects, kept in the caller's
    order; each element is first verified on its own with
    :func:`verify_signed_auth_audit_continuation` against the pre-trusted
    32-byte Ed25519 ``public_key``, and the receipts must then describe one
    continuous append-only history:

    - every segment must extend a strictly smaller prefix, i.e. its
      ``consistency.old.size`` must be less than its ``consistency.new.size``
      (a zero-length segment never describes an append);
    - adjacent segments must join exactly: the previous segment's
      ``consistency.new`` checkpoint must equal the following segment's
      ``consistency.old`` checkpoint on every field — hash name, size, root,
      head and the Ed25519 signature itself;
    - no segment may be repeated (the tuple must not contain two equal
      receipts).

    Verification introduces no signing domain of its own and holds neither
    the log nor any checkpoint history. A genuine, strictly growing chain
    returns True; an empty chain, a non-tuple or an element of the wrong
    type raises TypeError, and any segment that fails
    :func:`verify_signed_auth_audit_continuation`, any non-growing segment,
    any repeated segment, any adjacent mismatch or a public key that is not
    32 ``bytes`` makes the result False (nested verification exceptions from
    structurally illegal receipts propagate exactly as
    :func:`verify_signed_auth_audit_continuation` raises them). The call is
    read-only and never mutates the receipts.
    """
    if not isinstance(receipts, tuple):
        raise TypeError("receipts must be a non-empty tuple")
    if len(receipts) == 0:
        raise ValueError("receipts must be a non-empty tuple")
    for receipt in receipts:
        if not isinstance(receipt, SignedAuthAuditContinuation):
            raise TypeError(
                "each receipt must be a SignedAuthAuditContinuation"
            )
    seen: set[SignedAuthAuditContinuation] = set()
    previous_new: SignedRoot | None = None
    for receipt in receipts:
        if receipt in seen:
            return False
        seen.add(receipt)
        if not verify_signed_auth_audit_continuation(receipt, public_key):
            return False
        consistency = receipt.consistency
        if not consistency.old.size < consistency.new.size:
            return False
        if previous_new is not None and consistency.old != previous_new:
            return False
        previous_new = consistency.new
    return True


def verify_rotated_chain(receipts: Any, rotations: Any, key: Any) -> bool:
    """Verify a non-empty tuple of continuation receipts across key rotations.

    The rotation-aware extension of :func:`verify_continuation_chain`: an
    offline party holding only one pre-trusted 32-byte Ed25519 public key
    can confirm that the receipts — consecutive segments of one strictly
    growing append-only history — may be signed by a *different* key per
    segment, with each handoff authorized by a signer rotation the previous
    key vouches for. Nothing about the check requires the log or any
    checkpoint history, it introduces no new signing message or wire format,
    and it never mutates the receipts, the rotations or the key.

    ``receipts`` must be a non-empty ``tuple`` of
    :class:`SignedAuthAuditContinuation` objects (the segments, in chain
    order) and ``rotations`` a ``tuple`` whose length is exactly one less
    than the number of segments; ``rotations[i]`` is the
    :meth:`AuditLog.rotate_signer` ``(old, new_key, new, auth)`` four-tuple
    that connects segment ``i`` to segment ``i + 1``. The receipts are then
    examined strictly in tuple order, with trust hopping exactly once per
    boundary:

    - segment 0 is verified on its own with
      :func:`verify_signed_auth_audit_continuation` against the pre-trusted
      ``key``, and every later segment against the ``new_key`` learned from
      the rotation in front of it — a new signer is trusted only after the
      preceding rotation passes :func:`verify_rotation`;
    - before that hop, ``rotations[i]`` must be verified with
      :func:`verify_rotation` against the currently trusted key, and its
      checkpoints must join the two segments on every field: its ``old``
      checkpoint must equal segment ``i``'s ``consistency.new`` and its
      ``new`` checkpoint must equal segment ``i + 1``'s
      ``consistency.old`` — version, hash name, size, root, head and the
      Ed25519 signature itself — so the rotation authorizes exactly the
      boundary between those two signed snapshots;
    - every segment must extend a strictly smaller prefix, i.e. its
      ``consistency.old.size`` must be less than its ``consistency.new.size``
      (a zero-length segment never describes an append);
    - neither a receipt nor a rotation may be repeated: a tuple element
      equal to an earlier one of the same kind makes the result False.

    A genuine, strictly growing chain whose every handoff is authorized by
    the preceding key returns True. A non-tuple ``receipts`` or ``rotations``
    (including a list, a generator or ``None``), a receipt of another type,
    a rotation element of another type, or a ``key`` that is not ``bytes``
    raises TypeError; an empty ``receipts`` tuple, a ``rotations`` tuple
    whose length is not exactly ``len(receipts) - 1`` or a key that is not
    32 bytes raises ValueError. Every other nested structural violation — a
    rotation four-tuple of the wrong length, a wrongly typed or sized
    rotation field, or any structural exception raised by
    :func:`verify_signed_auth_audit_continuation` — propagates unchanged
    from :func:`verify_rotation` /
    :func:`verify_signed_auth_audit_continuation` (TypeError or
    ValueError). Types and shapes being legal, any signature,
    authorization, tag, inclusion proof, consistency proof, growth or
    boundary-link mismatch returns False.
    """
    if not isinstance(receipts, tuple):
        raise TypeError("receipts must be a non-empty tuple")
    if not isinstance(rotations, tuple):
        raise TypeError("rotations must be a tuple of rotation records")
    if len(receipts) == 0:
        raise ValueError("receipts must be a non-empty tuple")
    if len(rotations) != len(receipts) - 1:
        raise ValueError(
            "rotations must contain exactly one record per segment boundary "
            f"({len(rotations)} given for {len(receipts)} segments)"
        )
    for receipt in receipts:
        if not isinstance(receipt, SignedAuthAuditContinuation):
            raise TypeError(
                "each receipt must be a SignedAuthAuditContinuation"
            )
    # The raw four-tuples returned by rotate_signer have no dedicated class;
    # check only their container type here, leaving length and element
    # validation to verify_rotation, exactly as verify_rotation_chain does.
    for rotation in rotations:
        if not isinstance(rotation, tuple):
            raise TypeError(
                "each rotation must be a (old, new_key, new, auth) tuple"
            )
    # Pin the initial key to 32 bytes before the first use, exactly as
    # verify_rotation and verify_rotation_chain pin every learned new_key.
    _load_ed25519_public(key)
    current_key = key
    seen_receipts: set[SignedAuthAuditContinuation] = set()
    seen_rotations: set[tuple] = set()
    previous_new: SignedRoot | None = None
    for index, receipt in enumerate(receipts):
        if index > 0:
            rotation = rotations[index - 1]
            if rotation in seen_rotations:
                return False
            seen_rotations.add(rotation)
            # The boundary rotation must be authorized by the key currently
            # trusted — the pre-trusted key at the first boundary, otherwise
            # the previous rotation's verified new_key — before that key may
            # sign the following segment, and it must join exactly the two
            # checkpoints that meet at this boundary (all six fields).
            if not verify_rotation(rotation, current_key):
                return False
            if rotation[0] != previous_new:
                return False
            if rotation[2] != receipt.consistency.old:
                return False
            # verify_rotation succeeded and pinned new_key to 32 bytes: it is
            # now the only signer trusted for the following segment.
            current_key = rotation[1]
        if receipt in seen_receipts:
            return False
        seen_receipts.add(receipt)
        if not verify_signed_auth_audit_continuation(receipt, current_key):
            return False
        consistency = receipt.consistency
        if not consistency.old.size < consistency.new.size:
            return False
        previous_new = consistency.new
    return True


def inspect_rotated_chain(
    receipts: Any, rotations: Any, key: Any
) -> ContinuationChainReport:
    """Diagnose a non-empty tuple of continuation receipts across key rotations.

    The read-only diagnostic counterpart of :func:`verify_rotated_chain`:
    it holds neither the log nor any checkpoint history, introduces no new
    signing message or wire format and never mutates the receipts, the
    rotations or the key, but instead of a bare bool it returns a frozen
    :class:`ContinuationChainReport` locating the **first** failed segment,
    rotation or boundary — a genuine chain reports
    ``ContinuationChainReport(True, None, None)`` and only the earliest
    problem is ever reported.

    The inputs have exactly the shape of :func:`verify_rotated_chain`:
    ``receipts`` is a non-empty ``tuple`` of
    :class:`SignedAuthAuditContinuation` segments in chain order and
    ``rotations`` a ``tuple`` whose length is exactly one less, with
    ``rotations[i]`` the :meth:`AuditLog.rotate_signer`
    ``(old, new_key, new, auth)`` four-tuple connecting segment ``i`` to
    segment ``i + 1``. They are examined strictly in tuple order, with trust
    hopping at most once per boundary:

    - segment 0 is checked against the pre-trusted ``key``: failure of
      :func:`verify_signed_auth_audit_continuation` reports ``"verify"`` at
      position ``0``, and ``consistency.old.size >= consistency.new.size``
      reports ``"growth"`` (a duplicate check follows, though position ``0``
      can never repeat an earlier segment);
    - at every later position ``i`` the boundary is diagnosed first, in this
      order: ``rotations[i - 1]`` equal to an earlier rotation reports
      ``"rotation_duplicate"``; failure of :func:`verify_rotation` against
      the currently trusted key reports ``"rotation"``; and a rotation whose
      ``old`` checkpoint does not equal segment ``i - 1``'s
      ``consistency.new`` or whose ``new`` checkpoint does not equal segment
      ``i``'s ``consistency.old`` on every field (version, hash name, size,
      root, head and the Ed25519 signature itself) reports
      ``"rotation_link"``. Only a rotation that passes all three checks hops
      trust: its verified ``new_key`` is then the only key trusted for
      segment ``i``, which is checked in the same order as segment 0 —
      ``"verify"``, ``"growth"``, then ``"duplicate"`` for a receipt equal
      to an earlier one.

    Every failure code is indexed at the later segment's position ``i``.
    A non-tuple ``receipts`` or ``rotations`` (including a list, a generator
    or ``None``), a receipt of another type, a rotation element of another
    type, or a ``key`` that is not ``bytes`` raises TypeError; an empty
    ``receipts`` tuple, a ``rotations`` tuple whose length is not exactly
    ``len(receipts) - 1`` or a key that is not 32 bytes raises ValueError.
    Every other nested structural violation — a rotation four-tuple of the
    wrong length, a wrongly typed or sized rotation field, or any structural
    exception raised by
    :func:`verify_signed_auth_audit_continuation` — propagates unchanged
    from :func:`verify_rotation` /
    :func:`verify_signed_auth_audit_continuation` (TypeError or
    ValueError). Types and shapes being legal, any signature, authorization,
    tag, inclusion proof, consistency proof, growth or boundary-link
    mismatch is reported, not raised.
    """
    if not isinstance(receipts, tuple):
        raise TypeError("receipts must be a non-empty tuple")
    if not isinstance(rotations, tuple):
        raise TypeError("rotations must be a tuple of rotation records")
    if len(receipts) == 0:
        raise ValueError("receipts must be a non-empty tuple")
    if len(rotations) != len(receipts) - 1:
        raise ValueError(
            "rotations must contain exactly one record per segment boundary "
            f"({len(rotations)} given for {len(receipts)} segments)"
        )
    for receipt in receipts:
        if not isinstance(receipt, SignedAuthAuditContinuation):
            raise TypeError(
                "each receipt must be a SignedAuthAuditContinuation"
            )
    # The raw four-tuples returned by rotate_signer have no dedicated class;
    # check only their container type here, leaving length and element
    # validation to verify_rotation, exactly as verify_rotated_chain does.
    for rotation in rotations:
        if not isinstance(rotation, tuple):
            raise TypeError(
                "each rotation must be a (old, new_key, new, auth) tuple"
            )
    # Pin the initial key to 32 bytes before the first use, exactly as
    # verify_rotated_chain does, so a malformed anchor key raises identically
    # whether or not the chain happens to be examined.
    _load_ed25519_public(key)
    current_key = key
    seen_receipts: set[SignedAuthAuditContinuation] = set()
    seen_rotations: set[tuple] = set()
    previous_new: SignedRoot | None = None
    for index, receipt in enumerate(receipts):
        if index > 0:
            rotation = rotations[index - 1]
            # The boundary is diagnosed before the segment it leads into: a
            # repeated rotation, then verify_rotation against the key
            # currently trusted, then the all-field join of its two
            # checkpoints with the two sides of the seam.
            if rotation in seen_rotations:
                return ContinuationChainReport(
                    False, index, _CHAIN_CODE_ROTATION_DUPLICATE
                )
            seen_rotations.add(rotation)
            if not verify_rotation(rotation, current_key):
                return ContinuationChainReport(
                    False, index, _CHAIN_CODE_ROTATION
                )
            consistency = receipt.consistency
            if rotation[0] != previous_new or rotation[2] != consistency.old:
                return ContinuationChainReport(
                    False, index, _CHAIN_CODE_ROTATION_LINK
                )
            # verify_rotation succeeded and pinned new_key to 32 bytes: it is
            # now the only signer trusted for the following segment.
            current_key = rotation[1]
        # Exceptions from nested verification propagate: a structurally
        # illegal receipt or rotation is a caller error, not a failed
        # diagnosis. The segment is checked in the same order as segment 0:
        # verify, strict growth, then repetition.
        if not verify_signed_auth_audit_continuation(receipt, current_key):
            return ContinuationChainReport(False, index, _CHAIN_CODE_VERIFY)
        consistency = receipt.consistency
        if consistency.old.size >= consistency.new.size:
            return ContinuationChainReport(False, index, _CHAIN_CODE_GROWTH)
        if receipt in seen_receipts:
            return ContinuationChainReport(
                False, index, _CHAIN_CODE_DUPLICATE
            )
        seen_receipts.add(receipt)
        previous_new = consistency.new
    return ContinuationChainReport(True, None, None)


def inspect_continuation_chain(
    receipts: Any, public_key: Any
) -> ContinuationChainReport:
    """Diagnose a non-empty tuple of chained continuation receipts offline.

    The read-only diagnostic counterpart of :func:`verify_continuation_chain`:
    it holds neither the log nor any checkpoint history, introduces no new
    Ed25519 or HMAC signing domain and never mutates the receipts or the key,
    but instead of a bare bool it returns a frozen
    :class:`ContinuationChainReport` locating the **first** failed segment or
    broken boundary — a valid chain reports
    ``ContinuationChainReport(True, None, None)`` and only the earliest
    problem is ever reported.

    Segments are examined in the caller's tuple order, in two phases:

    1. each segment is verified on its own with
       :func:`verify_signed_auth_audit_continuation` against the pre-trusted
       32-byte Ed25519 ``public_key`` — failure reports ``"verify"`` at that
       segment's position — and must extend a strictly smaller prefix, i.e.
       ``consistency.old.size < consistency.new.size`` (a zero-length segment
       never describes an append) — ``old.size >= new.size`` reports
       ``"growth"``;
    2. only after every segment is individually sound and strictly growing
       are the segments compared with one another: a receipt equal to an
       earlier one reports ``"duplicate"`` at the repeated segment's
       position, and the previous segment's ``consistency.new`` checkpoint
       must equal the following segment's ``consistency.old`` checkpoint on
       every field (hash name, size, root, head and the Ed25519 signature
       itself) — a mismatch reports ``"link"`` at the following segment's
       position. The ``"link"`` code identifies the boundary between the two
       segments and blames neither one.

    ``receipts`` must be a non-empty ``tuple`` of
    :class:`SignedAuthAuditContinuation` objects: a non-tuple (including a
    list, a generator or ``None``) or an element of another type raises
    TypeError, and an empty tuple raises ValueError. ``public_key`` must be a
    32-byte ``bytes`` Ed25519 key: a non-``bytes`` value (including
    ``bytearray``) raises TypeError and a ``bytes`` value of another length
    raises ValueError. Nested structural violations raised by
    :func:`verify_signed_auth_audit_continuation` on a structurally illegal
    receipt propagate unchanged (TypeError or ValueError) rather than
    becoming a ``"verify"`` report; signature, tag or proof mismatches on a
    structurally valid receipt are reported, not raised.
    """
    if not isinstance(receipts, tuple):
        raise TypeError("receipts must be a non-empty tuple")
    if len(receipts) == 0:
        raise ValueError("receipts must be a non-empty tuple")
    for receipt in receipts:
        if not isinstance(receipt, SignedAuthAuditContinuation):
            raise TypeError(
                "each receipt must be a SignedAuthAuditContinuation"
            )
    if not isinstance(public_key, bytes):
        raise TypeError("public_key must be a 32-byte Ed25519 public key")
    if len(public_key) != _ED25519_KEY_BYTES:
        raise ValueError(
            f"public_key must be {_ED25519_KEY_BYTES} bytes "
            "(an Ed25519 public key)"
        )

    # Phase 1: every segment must independently verify and strictly grow.
    # Exceptions from nested verification propagate: a structurally illegal
    # receipt is a caller error, not a failed "verify" diagnosis.
    for index, receipt in enumerate(receipts):
        if not verify_signed_auth_audit_continuation(receipt, public_key):
            return ContinuationChainReport(False, index, _CHAIN_CODE_VERIFY)
        consistency = receipt.consistency
        if consistency.old.size >= consistency.new.size:
            return ContinuationChainReport(False, index, _CHAIN_CODE_GROWTH)

    # Phase 2: relationships between individually sound segments. Repeated
    # receipts and broken joins are located from the current segment's
    # position; "link" marks the boundary itself rather than either segment.
    seen: set[SignedAuthAuditContinuation] = set()
    previous_new: SignedRoot | None = None
    for index, receipt in enumerate(receipts):
        if receipt in seen:
            return ContinuationChainReport(
                False, index, _CHAIN_CODE_DUPLICATE
            )
        seen.add(receipt)
        consistency = receipt.consistency
        if previous_new is not None and consistency.old != previous_new:
            return ContinuationChainReport(False, index, _CHAIN_CODE_LINK)
        previous_new = consistency.new
    return ContinuationChainReport(True, None, None)


def inspect_anchors(
    receipts: Any, key: Any, start: Any, end: Any
) -> ContinuationChainReport:
    """Diagnose whether a chain joins two expected snapshot checkpoints.

    The anchor-aware extension of :func:`inspect_continuation_chain`: an
    offline party holding only the pre-trusted key and two expected
    :class:`SignedRoot` checkpoints can confirm that the receipts not only
    form one internally continuous chain but span **exactly** from the
    expected old snapshot to the expected new one — a valid sub-chain with a
    truncated prefix, a truncated suffix, or a wholesale replacement of the
    expected span is located rather than accepted. It is equally read-only:
    it holds neither the log nor any checkpoint history, introduces no new
    Ed25519 or HMAC signing domain and never mutates the receipts, the key
    or the anchors.

    The chain itself is diagnosed first by delegating to
    :func:`inspect_continuation_chain`; a failing report is returned
    unchanged, so the four internal codes (``"verify"``, ``"growth"``,
    ``"duplicate"``, ``"link"``) keep their first-failure order and an
    internally broken chain is never re-diagnosed as an anchor mismatch.
    Only when the internal report succeeds are the anchors compared, start
    before end:

    - the first segment's ``consistency.old`` checkpoint must equal
      ``start`` — a mismatch reports ``"start"`` at index ``0``;
    - the last segment's ``consistency.new`` checkpoint must equal ``end``
      — a mismatch reports ``"end"`` at the last segment's position.

    Anchor equality is full :class:`SignedRoot` equality over all six
    fields (``version``, ``hash_name``, ``size``, ``root``, ``head`` and
    the Ed25519 ``signature``), so a checkpoint attesting the right size
    over the wrong history — or signed by the wrong key — does not match.
    A chain that is internally continuous and anchored at both ends reports
    ``ContinuationChainReport(True, None, None)``.

    ``receipts``, ``key``, ``start`` and ``end`` are all required
    and validated before the internal diagnosis runs: a non-tuple
    ``receipts`` (including a list, a generator or ``None``), an element
    that is not a :class:`SignedAuthAuditContinuation`, a non-``bytes``
    ``key`` (including ``bytearray``) or a ``start``/``end`` that is
    not a :class:`SignedRoot` raises TypeError, while an empty tuple or a
    ``key`` of another length than 32 bytes raises ValueError.
    Nested structural violations raised on a structurally illegal receipt
    propagate unchanged (TypeError or ValueError) exactly as in
    :func:`inspect_continuation_chain`.
    """
    if not isinstance(receipts, tuple):
        raise TypeError("receipts must be a non-empty tuple")
    if len(receipts) == 0:
        raise ValueError("receipts must be a non-empty tuple")
    for receipt in receipts:
        if not isinstance(receipt, SignedAuthAuditContinuation):
            raise TypeError(
                "each receipt must be a SignedAuthAuditContinuation"
            )
    if not isinstance(key, bytes):
        raise TypeError("key must be a 32-byte Ed25519 public key")
    if len(key) != _ED25519_KEY_BYTES:
        raise ValueError(
            f"key must be {_ED25519_KEY_BYTES} bytes "
            "(an Ed25519 public key)"
        )
    if not isinstance(start, SignedRoot):
        raise TypeError("start must be a SignedRoot")
    if not isinstance(end, SignedRoot):
        raise TypeError("end must be a SignedRoot")

    # The internal chain diagnosis keeps its own first-failure order; only
    # an internally sound chain is ever compared against the anchors, start
    # before end.
    report = inspect_continuation_chain(receipts, key)
    if not report.ok:
        return report
    if receipts[0].consistency.old != start:
        return ContinuationChainReport(False, 0, _CHAIN_CODE_START)
    if receipts[-1].consistency.new != end:
        return ContinuationChainReport(
            False, len(receipts) - 1, _CHAIN_CODE_END
        )
    return report


def encode_continuation_chain_report(report: Any) -> bytes:
    """Encode a :class:`ContinuationChainReport` into its canonical binary form.

    The encoding starts with the magic ``b"auditchain/chain-report/v1\\0"``,
    followed strictly, in this fixed order, by the u64 envelope version
    (always 1), the verdict, the segment position and the issue code —
    nothing may be omitted, reordered or appended, and no signature or
    receipt is carried. Every integer is an unsigned 8-byte big-endian
    value and the code is a u64-length-prefixed UTF-8 blob (a zero length is
    an all-zero u64). The verdict is ``0`` for success and ``1`` for
    failure: a success report writes position ``0`` and an empty code blob,
    while a failure writes the report's absolute segment position and the
    UTF-8 bytes of its code, one of the diagnostic entry's legal codes.

    ``report`` must be a :class:`ContinuationChainReport` — anything else
    raises TypeError; fields written with wrong types by bypassing the
    frozen constructor (``object.__setattr__``) likewise raise TypeError,
    because every field is re-validated through the constructor. A failing
    position outside the u64 range raises ValueError. The call is
    read-only and deterministic: it never mutates the report, and
    re-encoding a decoded report reproduces the original bytes exactly, so
    a diagnosis can be landed on disk and restored in another process with
    the same verdict, position and code.
    """
    if not isinstance(report, ContinuationChainReport):
        raise TypeError("report must be a ContinuationChainReport")
    # Re-validate every field even when the frozen constructor was bypassed
    # with object.__setattr__, so corrupted fields raise exactly as the
    # constructor would: TypeError for wrong types, ValueError for illegal
    # values or an ok/index/code mismatch.
    checked = ContinuationChainReport(report.ok, report.index, report.code)
    if checked.ok:
        return b"".join((
            _CHAIN_REPORT_MAGIC,
            _encode_u64(_CHAIN_REPORT_VERSION, "version"),
            _encode_u64(0, "verdict"),
            _encode_u64(0, "index"),
            _encode_blob(b""),
        ))
    return b"".join((
        _CHAIN_REPORT_MAGIC,
        _encode_u64(_CHAIN_REPORT_VERSION, "version"),
        _encode_u64(1, "verdict"),
        _encode_u64(checked.index, "index"),
        _encode_blob(checked.code.encode("utf-8")),
    ))


def decode_continuation_chain_report(data: Any) -> ContinuationChainReport:
    """Decode bytes produced by :func:`encode_continuation_chain_report`.

    ``data`` must be exactly ``bytes`` (anything else, including
    ``bytearray`` and ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/chain-report/v1\\0"`` it must contain, strictly in
    order, the u64 version (only ``1`` is supported), the u64 verdict
    (``0`` success, ``1`` failure), the u64 segment position and the
    u64-length-prefixed code blob, consumed whole with no trailing bytes.
    A success verdict must carry position ``0`` and an empty code blob; a
    failure verdict must carry a non-empty code whose UTF-8 text is one of
    the legal diagnostic codes (its position may be ``0``, the first
    segment). A bad magic or version, a verdict other than 0/1, truncation,
    trailing bytes, an oversized blob length, invalid UTF-8, an unknown
    code, or any success/failure field mismatch raises ValueError.

    The returned object is a frozen :class:`ContinuationChainReport` whose
    fields equal the originally encoded report's; re-encoding it
    reproduces the original bytes exactly, and its verdict is the same
    before and after the round trip.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_CHAIN_REPORT_MAGIC):
        raise ValueError("not an auditchain chain-report encoding")
    offset = len(_CHAIN_REPORT_MAGIC)

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
    if version != _CHAIN_REPORT_VERSION:
        raise ValueError(f"unsupported chain-report version {version}")
    verdict = read_u64("verdict")
    if verdict not in (0, 1):
        raise ValueError(f"chain-report verdict must be 0 or 1, got {verdict}")
    index = read_u64("index")
    raw_code = read_blob("code")
    if offset != len(data):
        raise ValueError("trailing bytes after the chain report")
    if verdict == 0:
        if index != 0 or raw_code != b"":
            raise ValueError(
                "a successful chain report must carry position 0 and an "
                "empty code"
            )
        return ContinuationChainReport(True, None, None)
    if raw_code == b"":
        raise ValueError("a failed chain report must carry a code")
    try:
        code = raw_code.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("code is not valid UTF-8") from error
    if code not in _CHAIN_CODES:
        raise ValueError(
            f"unknown chain code {code!r}; expected one of "
            "'verify', 'growth', 'duplicate', 'link', 'start', 'end', "
            "'anchor_link', 'rotation_duplicate', 'rotation', "
            "'rotation_link'"
        )
    return ContinuationChainReport(False, index, code)


def encode_integrity_report(report: Any) -> bytes:
    """Encode an :class:`IntegrityReport` into its canonical binary form.

    The encoding starts with the magic
    ``b"auditchain/integrity-report/v1\\0"``, followed strictly, in this
    fixed order, by the u64 envelope version (always 1), the verdict, the
    issue count and one code/position pair per issue — nothing may be
    omitted, reordered or appended, and no signature is carried. Every
    integer is an unsigned 8-byte big-endian value and every code is a
    u64-length-prefixed UTF-8 blob (a zero length is an all-zero u64).
    The verdict is ``0`` for success and ``1`` for failure; each issue
    writes the UTF-8 bytes of its code — one of ``"index"``,
    ``"previous_hash"``, ``"entry_hash"`` and ``"head"`` — followed by
    its absolute position as a u64, the index-less ``"head"`` issue
    writing position ``0``. Issues appear in report order: ascending
    absolute index, the canonical code order at one position and the
    trailing ``"head"`` issue last.

    ``report`` must be an :class:`IntegrityReport` — anything else
    raises TypeError; fields written with wrong types by bypassing the
    frozen constructor (``object.__setattr__``) likewise raise TypeError,
    because every field, including each nested issue, is re-validated
    through the constructor. An illegal issue code, a code/position
    mismatch, a broken issue order or a position outside the u64 range
    raises ValueError. The call is read-only and deterministic: it never
    mutates the report, and re-encoding a decoded report reproduces the
    original bytes exactly, so a chain-verification diagnosis can be
    landed on disk and restored in another process with the same verdict
    and issues.
    """
    if not isinstance(report, IntegrityReport):
        raise TypeError("report must be an IntegrityReport")
    # Re-validate every field even when the frozen constructor was
    # bypassed with object.__setattr__, so corrupted fields raise exactly
    # as the constructor would: TypeError for wrong types, ValueError for
    # illegal values, an ok/issues mismatch or a broken issue order. Each
    # issue is rebuilt as well, so a corrupted IntegrityIssue raises the
    # same way instead of slipping past the container's isinstance check.
    if not isinstance(report.issues, tuple):
        raise TypeError("issues must be a tuple")
    issues = tuple(
        IntegrityIssue(issue.code, issue.index)
        if isinstance(issue, IntegrityIssue)
        else issue
        for issue in report.issues
    )
    checked = IntegrityReport(report.ok, issues)
    parts = [
        _INTEGRITY_REPORT_MAGIC,
        _encode_u64(_INTEGRITY_REPORT_VERSION, "version"),
        _encode_u64(0 if checked.ok else 1, "verdict"),
        _encode_u64(len(checked.issues), "issues count"),
    ]
    for issue in checked.issues:
        parts.append(_encode_blob(issue.code.encode("utf-8")))
        parts.append(
            _encode_u64(
                issue.index if issue.index is not None else 0, "issue index"
            )
        )
    return b"".join(parts)


def decode_integrity_report(data: Any) -> IntegrityReport:
    """Decode bytes produced by :func:`encode_integrity_report`.

    ``data`` must be exactly ``bytes`` (anything else, including
    ``bytearray`` and ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/integrity-report/v1\\0"`` it must contain, strictly in
    order, the u64 version (only ``1`` is supported), the u64 verdict
    (``0`` success, ``1`` failure), the u64 issue count and, per issue,
    the u64-length-prefixed UTF-8 code blob and the u64 position,
    consumed whole with no trailing bytes. A success verdict must carry
    a zero issue count and a failure verdict at least one issue; every
    code must be one of ``"index"``, ``"previous_hash"``,
    ``"entry_hash"`` and ``"head"``, the ``"head"`` issue must carry
    position ``0`` and may only be the final issue, and indexed issues
    must appear in ascending position order with the canonical code
    order at one position. A bad magic or version, a verdict other than
    0/1, a success/failure count mismatch, truncation, trailing bytes,
    an oversized blob length, invalid UTF-8, an unknown code, a
    code/position mismatch or a broken issue order raises ValueError.

    The returned object is a frozen :class:`IntegrityReport` whose
    fields equal the originally encoded report's; re-encoding it
    reproduces the original bytes exactly, and its verdict is the same
    before and after the round trip.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_INTEGRITY_REPORT_MAGIC):
        raise ValueError("not an auditchain integrity-report encoding")
    offset = len(_INTEGRITY_REPORT_MAGIC)

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
    if version != _INTEGRITY_REPORT_VERSION:
        raise ValueError(f"unsupported integrity-report version {version}")
    verdict = read_u64("verdict")
    if verdict not in (0, 1):
        raise ValueError(f"integrity-report verdict must be 0 or 1, got {verdict}")
    count = read_u64("issues count")
    issues = []
    for _ in range(count):
        raw_code = read_blob("issue code")
        try:
            code = raw_code.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("issue code is not valid UTF-8") from error
        if code not in _ISSUE_CODES:
            raise ValueError(
                f"unknown issue code {code!r}; expected one of "
                f"'index', 'previous_hash', 'entry_hash', 'head'"
            )
        position = read_u64("issue index")
        if code == _ISSUE_HEAD:
            if position != 0:
                raise ValueError("a 'head' issue must carry position 0")
            issues.append(IntegrityIssue(code, None))
        else:
            issues.append(IntegrityIssue(code, position))
    if offset != len(data):
        raise ValueError("trailing bytes after the integrity report")
    if verdict == 0 and issues:
        raise ValueError("a successful integrity report must carry no issues")
    if verdict == 1 and not issues:
        raise ValueError("a failed integrity report must carry at least one issue")
    return IntegrityReport(verdict == 0, tuple(issues))


def inspect_anchored_continuations(
    bundle: Any, key: Any
) -> ContinuationChainReport:
    """Diagnose a persisted anchored continuation chain offline.

    The bundle-level counterpart of :func:`inspect_anchors`: an offline
    party holding only the pre-trusted key and an
    :class:`AnchoredContinuationChain` restored from storage — by
    :func:`decode_anchored_continuations` or built directly — confirms in
    one call that the persisted receipts form one internally continuous
    chain spanning exactly from the persisted ``start`` anchor to the
    persisted ``end`` anchor. It is equally read-only: it holds neither the
    log nor any checkpoint history, introduces no new Ed25519 or HMAC
    signing domain and never mutates the bundle or the key.

    The diagnosis is exactly :func:`inspect_anchors` over the bundle's own
    fields — ``inspect_anchors(bundle.receipts, key, bundle.start,
    bundle.end)`` — so the report, its codes and its first-failure order are
    identical: the four internal codes (``"verify"``, ``"growth"``,
    ``"duplicate"``, ``"link"``) surface unchanged and only an internally
    sound chain is ever compared against the anchors, ``"start"`` before
    ``"end"``. A fully anchored chain reports
    ``ContinuationChainReport(True, None, None)``.

    ``bundle`` must be an :class:`AnchoredContinuationChain` — anything else
    raises TypeError. ``key`` and the bundle's fields are validated by
    :func:`inspect_anchors` itself, whose TypeError/ValueError rules and
    nested structural exceptions apply and propagate unchanged.
    """
    if not isinstance(bundle, AnchoredContinuationChain):
        raise TypeError("bundle must be an AnchoredContinuationChain")
    return inspect_anchors(
        bundle.receipts, key, bundle.start, bundle.end
    )


def inspect_rotated_anchors(
    bundle: Any, key: Any
) -> ContinuationChainReport:
    """Diagnose a persisted cross-key, anchor-to-anchor rotated chain offline.

    The bundle-level counterpart of :func:`inspect_rotated_chain`: an
    offline party holding only the pre-trusted key and a
    :class:`RotatedChain` restored from storage — by
    :func:`decode_rotated_anchor` or built directly — confirms in one call
    that the persisted receipts and rotations form one genuine
    cross-signer chain spanning exactly from the persisted ``start`` anchor
    to the persisted ``end`` anchor. It is equally read-only: it holds
    neither the log nor any checkpoint history, introduces no new Ed25519
    or HMAC signing domain and never mutates the bundle or the key.

    The chain itself is diagnosed first, exactly as
    :func:`inspect_rotated_chain` would over the bundle's own fields —
    ``inspect_rotated_chain(bundle.receipts, bundle.rotations, key)`` — and
    a failing report is returned unchanged, so the segment codes
    (``"verify"``, ``"growth"``, ``"duplicate"``) and the boundary codes
    (``"rotation_duplicate"``, ``"rotation"``, ``"rotation_link"``) keep
    their first-failure order and an internally broken chain is never
    re-diagnosed as an anchor mismatch. Only when the internal report
    succeeds are the anchors compared, start before end:

    - the first segment's ``consistency.old`` checkpoint must equal
      ``bundle.start`` on all six :class:`SignedRoot` fields
      (``version``, ``hash_name``, ``size``, ``root``, ``head`` and the
      Ed25519 ``signature``) — a mismatch reports ``"start"`` at index
      ``0``;
    - the last segment's ``consistency.new`` checkpoint must equal
      ``bundle.end`` on the same six fields — a mismatch reports ``"end"``
      at the last segment's position.

    A chain that is internally continuous across every rotation and
    anchored at both ends reports
    ``ContinuationChainReport(True, None, None)``.

    ``bundle`` must be a :class:`RotatedChain` — anything else raises
    TypeError. ``key`` and the bundle's fields are validated by
    :func:`inspect_rotated_chain` itself, whose TypeError/ValueError rules
    and nested structural exceptions apply and propagate unchanged.
    """
    if not isinstance(bundle, RotatedChain):
        raise TypeError("bundle must be a RotatedChain")
    report = inspect_rotated_chain(
        bundle.receipts, bundle.rotations, key
    )
    if not report.ok:
        return report
    # Only an internally sound, rotation-verified chain is ever compared
    # against the anchors, start before end, on all six SignedRoot fields.
    if bundle.receipts[0].consistency.old != bundle.start:
        return ContinuationChainReport(False, 0, _CHAIN_CODE_START)
    if bundle.receipts[-1].consistency.new != bundle.end:
        return ContinuationChainReport(
            False, len(bundle.receipts) - 1, _CHAIN_CODE_END
        )
    return report


def inspect_rotated_anchor_set(
    items: Any, bridges: Any, key: Any
) -> ContinuationChainReport:
    """Diagnose persisted cross-key packages and the bridges that hop between.

    When a cross-signer continuation chain — one whose segments may be
    signed by different keys, each boundary authorized by an
    :meth:`AuditLog.rotate_signer` rotation — has been landed in several
    separate batches, each batch persisted on its own as a
    :class:`RotatedChain` with its own intra-package rotations and its own
    two anchors, this is the offline, read-only diagnosis that the packages
    and the cross-package rotations, taken in the caller's tuple order,
    verify as one genuine cross-signer chain. It holds neither the log nor
    any checkpoint history, introduces no new signing domain or wire
    format and never mutates the packages, the bridges or the key.

    ``items`` is a non-empty ``tuple`` of :class:`RotatedChain` packages and
    ``bridges`` a ``tuple`` whose length is exactly ``len(items) - 1``, with
    ``bridges[i]`` the ``(old, new_key, new, auth)`` four-tuple connecting
    package ``i`` to package ``i + 1``. Trust hops at most once per
    boundary and packages and bridges are examined strictly in traversal
    order, reporting only the first failure:

    - package 0 is diagnosed with :func:`inspect_rotated_anchors` against
      the pre-trusted 32-byte Ed25519 ``key``; once it passes, the key
      trusted onwards is its last intra-package rotation's verified
      ``new_key``;
    - at every later package ``i`` the bridge is diagnosed before the
      package it leads into, in this order: ``bridges[i - 1]`` equal to an
      earlier cross-package bridge reports ``"rotation_duplicate"``;
      failure of :func:`verify_rotation` against the currently trusted key
      reports ``"rotation"``; and a bridge whose ``old`` checkpoint does
      not equal the previous package's ``end`` or whose ``new`` checkpoint
      does not equal this package's ``start`` on all six
      :class:`SignedRoot` fields (``version``, ``hash_name``, ``size``,
      ``root``, ``head`` and the Ed25519 ``signature``) reports
      ``"rotation_link"``. Only a bridge that passes all three checks hops
      trust: its verified ``new_key`` is then the only key trusted while
      package ``i`` is diagnosed, again with
      :func:`inspect_rotated_anchors`;
    - every package-level failure keeps its code unchanged — ``"verify"``,
      ``"growth"``, ``"duplicate"`` (a receipt repeating an earlier
      credential within that package), ``"rotation_duplicate"``,
      ``"rotation"``, ``"rotation_link"``, ``"start"`` or ``"end"`` — and
      its package-local ``index`` is shifted onto the global credential
      position by adding the receipt count of every earlier package. A
      ``"duplicate"`` report is therefore indexed at the repeated
      credential's later global position, and the three bridge codes at
      the global position of the following package's first receipt. An
      internally broken package is never re-diagnosed across its
      boundary: the bridge is examined only after every earlier package
      has passed.

    A set whose packages are sound one by one under the hopped keys and
    whose bridges are genuine and join at every boundary reports
    ``ContinuationChainReport(True, None, None)``.

    A non-tuple ``items`` or ``bridges`` (including a list, a generator or
    ``None``), an element of ``items`` that is not a :class:`RotatedChain`,
    a bridge element that is not a tuple, or a ``key`` that is not
    ``bytes`` raises TypeError; an empty ``items`` tuple, a ``bridges``
    tuple whose length is not exactly ``len(items) - 1`` or a key that is
    not 32 bytes raises ValueError. Every other nested structural
    violation — a bridge four-tuple of the wrong length, a wrongly typed
    or sized bridge field, or any structural exception raised while a
    package is diagnosed — propagates unchanged (TypeError or ValueError)
    from :func:`verify_rotation` / :func:`inspect_rotated_anchors`. Types
    and shapes being legal, any signature, authorization, proof, growth,
    repetition or boundary-link mismatch is reported, not raised.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a non-empty tuple")
    if len(items) == 0:
        raise ValueError("items must be a non-empty tuple")
    for item in items:
        if not isinstance(item, RotatedChain):
            raise TypeError("each item must be a RotatedChain")
    if not isinstance(bridges, tuple):
        raise TypeError("bridges must be a tuple of rotation records")
    if len(bridges) != len(items) - 1:
        raise ValueError(
            "bridges must contain exactly one record per package boundary "
            f"({len(bridges)} given for {len(items)} packages)"
        )
    # The raw four-tuples returned by rotate_signer have no dedicated class;
    # check only their container type here, leaving length and element
    # validation to verify_rotation, exactly as inspect_rotated_chain does.
    for bridge in bridges:
        if not isinstance(bridge, tuple):
            raise TypeError(
                "each bridge must be a (old, new_key, new, auth) tuple"
            )
    if not isinstance(key, bytes):
        raise TypeError("key must be a 32-byte Ed25519 public key")
    if len(key) != _ED25519_KEY_BYTES:
        raise ValueError(
            f"key must be {_ED25519_KEY_BYTES} bytes "
            "(an Ed25519 public key)"
        )

    # Traversal order: diagnose package 0 with the pre-trusted key, then at
    # each boundary diagnose the bridge (repetition, verify_rotation against
    # the key currently trusted, all-field join of the two anchors) before
    # hopping to its verified new_key and diagnosing the following package.
    # Package-local report indices are re-based onto the global credential
    # position by adding the receipt count of all earlier packages; the
    # bridge codes are indexed at the following package's first receipt.
    seen_bridges: set[tuple] = set()
    current_key = key
    offset = 0
    for index, item in enumerate(items):
        if index > 0:
            bridge = bridges[index - 1]
            if bridge in seen_bridges:
                return ContinuationChainReport(
                    False, offset, _CHAIN_CODE_ROTATION_DUPLICATE
                )
            seen_bridges.add(bridge)
            if not verify_rotation(bridge, current_key):
                return ContinuationChainReport(
                    False, offset, _CHAIN_CODE_ROTATION
                )
            # verify_rotation succeeded and pinned new_key to 32 bytes; only
            # then are the two sides of the seam compared on all six
            # SignedRoot fields.
            if bridge[0] != items[index - 1].end or bridge[2] != item.start:
                return ContinuationChainReport(
                    False, offset, _CHAIN_CODE_ROTATION_LINK
                )
            current_key = bridge[1]
        # Exceptions from the nested diagnosis propagate: a structurally
        # illegal package or bridge is a caller error, not a failed report.
        report = inspect_rotated_anchors(item, current_key)
        if not report.ok:
            return ContinuationChainReport(
                False, offset + report.index, report.code
            )
        offset += len(item.receipts)
        # The package passed, so every one of its rotations passed
        # verify_rotation under the hopped keys; trust now rests on its
        # last rotation's verified new_key, against which the next bridge
        # must be authorized. A RotatedChain always carries at least one
        # rotation (it requires at least two receipts).
        current_key = item.rotations[-1][1]
    return ContinuationChainReport(True, None, None)


def merge_rotated_anchor_set(
    items: Any, bridges: Any, key: Any
) -> RotatedChain:
    """Merge in-order persisted rotated packages into one frozen chain.

    The productive counterpart of :func:`inspect_rotated_anchor_set`: it
    diagnoses the packages and bridges exactly as that function does and,
    only when the diagnosis succeeds — every package sound on its own under
    the hopped keys and every bridge genuine and joining at both anchors —
    returns a **new** frozen :class:`RotatedChain` spanning the whole
    cross-signer chain:

    - ``receipts`` are the packages' receipts concatenated in package order
      and in within-package order;
    - ``rotations`` walk the same global credential order: after each
      package's own intra-package rotations the corresponding
      ``bridges[i]`` four-tuple is inserted, followed by the following
      package's own rotations — so one rotation sits at every adjacent
      credential boundary, intra-package and cross-package alike;
    - ``start`` is the first package's ``start`` and ``end`` the last
      package's ``end``.

    The merged artifact encodes through the existing
    :func:`encode_rotated_anchor` with no new signing domain or wire
    format. The call is strictly offline and read-only: none of the input
    packages, bridges or the key is mutated or rebuilt, and the receipts,
    rotations and anchors are reused rather than recopied (tuples and frozen
    dataclasses are immutable), so the inputs still encode exactly as
    before.

    ``items``, ``bridges`` and ``key`` follow
    :func:`inspect_rotated_anchor_set` and have no defaults: a non-tuple
    ``items`` or ``bridges`` (including a list, a generator or ``None``),
    an element of ``items`` that is not a :class:`RotatedChain`, a bridge
    element that is not a tuple, or a ``key`` that is not ``bytes`` raises
    TypeError, while an empty ``items`` tuple, a ``bridges`` tuple whose
    length is not exactly ``len(items) - 1`` or a key that is not 32 bytes
    raises ValueError. Any failure report — a package or bridge that does
    not verify, a repeated bridge, a growth or repetition failure, or a
    seam that does not join — raises ValueError, never a silently partial
    merge. Nested structural violations raised during the diagnosis
    propagate unchanged (TypeError or ValueError).
    """
    report = inspect_rotated_anchor_set(items, bridges, key)
    if not report.ok:
        raise ValueError(
            "rotated anchor set cannot be merged: "
            f"{report.code!r} at receipt index {report.index}"
        )
    receipts = tuple(
        receipt for item in items for receipt in item.receipts
    )
    rotations = tuple(
        rotation
        for index, item in enumerate(items)
        for rotation in (
            item.rotations + (bridges[index],)
            if index < len(bridges)
            else item.rotations
        )
    )
    return RotatedChain(receipts, rotations, items[0].start, items[-1].end)


def _anchor_set_packages(items: Any, key: Any) -> None:
    """Validate the arguments of the anchor-set entry points."""
    if not isinstance(items, tuple):
        raise TypeError("items must be a non-empty tuple")
    if len(items) == 0:
        raise ValueError("items must be a non-empty tuple")
    for item in items:
        if not isinstance(item, AnchoredContinuationChain):
            raise TypeError(
                "each item must be an AnchoredContinuationChain"
            )
    if not isinstance(key, bytes):
        raise TypeError("key must be a 32-byte Ed25519 public key")
    if len(key) != _ED25519_KEY_BYTES:
        raise ValueError(
            f"key must be {_ED25519_KEY_BYTES} bytes "
            "(an Ed25519 public key)"
        )


def inspect_anchor_set(items: Any, key: Any) -> ContinuationChainReport:
    """Diagnose a set of persisted anchor packages for in-order splicing.

    When one continuation chain has been landed in several separate batches
    — each batch persisted on its own as an
    :class:`AnchoredContinuationChain` — this is the offline, read-only
    diagnosis that the packages, taken in the caller's tuple order, verify as
    one chain and can be merged into a single persistable artifact. It holds
    neither the log nor any checkpoint history and introduces no new Ed25519
    or HMAC signing domain; the inputs are never mutated.

    The packages are examined in two phases, reporting only the first
    failure:

    1. each package is diagnosed in tuple order with
       :func:`inspect_anchored_continuations` against the pre-trusted
       32-byte Ed25519 ``key``. A failing report is returned with its code
       unchanged (``"verify"``, ``"growth"``, ``"duplicate"``, ``"link"``,
       ``"start"`` or ``"end"``) and its ``index`` shifted onto the global
       receipt position — the package-local index plus the number of receipts
       in all earlier packages — so every index addresses a receipt in the
       would-be concatenation, never merely a position inside one package;
    2. only after every package is individually sound are adjacent packages
       compared in package order: the previous package's ``end`` anchor must
       equal the following package's ``start`` anchor on all six
       :class:`SignedRoot` fields (``version``, ``hash_name``, ``size``,
       ``root``, ``head`` and the Ed25519 ``signature``). A mismatch reports
       ``"anchor_link"`` at the global position of the later package's first
       receipt. The code identifies the boundary between the two packages
       and blames neither one; equality of the anchor checkpoints (not just
       their sizes) is what lets the receipts splice without a gap, overlap
       or change of history.

    A set that is sound package by package and joins at every boundary
    reports ``ContinuationChainReport(True, None, None)``.

    ``items`` must be a non-empty ``tuple`` of
    :class:`AnchoredContinuationChain` objects: a non-tuple (including a
    list, a generator or ``None``) or an element of another type raises
    TypeError, and an empty tuple raises ValueError. ``key`` must be a
    32-byte ``bytes`` Ed25519 key: a non-``bytes`` value (including
    ``bytearray``) raises TypeError and a ``bytes`` value of another length
    raises ValueError. Nested structural violations raised while a package
    is diagnosed propagate unchanged (TypeError or ValueError) rather than
    becoming a failed report.
    """
    _anchor_set_packages(items, key)

    # Phase 1: every package must be sound on its own. Package-local report
    # indices are re-based onto the global receipt position by adding the
    # receipt count of all earlier packages; exceptions from the nested
    # diagnosis propagate unchanged.
    offset = 0
    for item in items:
        report = inspect_anchored_continuations(item, key)
        if not report.ok:
            return ContinuationChainReport(
                False, offset + report.index, report.code
            )
        offset += len(item.receipts)

    # Phase 2: adjacent packages must join at equal anchors. The index marks
    # the global position of the later package's first receipt.
    offset = 0
    previous = None
    for item in items:
        if previous is not None and previous.end != item.start:
            return ContinuationChainReport(
                False, offset, _CHAIN_CODE_ANCHOR_LINK
            )
        previous = item
        offset += len(item.receipts)
    return ContinuationChainReport(True, None, None)


def merge_anchor_set(items: Any, key: Any) -> AnchoredContinuationChain:
    """Merge in-order persisted anchor packages into one frozen chain.

    The productive counterpart of :func:`inspect_anchor_set`: it diagnoses
    the packages exactly as that function does and, only when the diagnosis
    succeeds — every package sound on its own and every adjacent pair
    joining at equal :class:`SignedRoot` anchors — returns a **new** frozen
    :class:`AnchoredContinuationChain` whose receipts are the packages'
    receipts concatenated in package order and in within-package order,
    whose ``start`` is the first package's ``start`` and whose ``end`` is the
    last package's ``end``. The merged artifact encodes through the existing
    :func:`encode_anchored_continuations` with no new format or signing
    domain.

    The call is strictly read-only: none of the input packages is mutated
    or rebuilt, and the receipts themselves are reused rather than recopied
    (tuples are immutable), so the inputs still encode exactly as before.

    ``items`` and ``key`` follow :func:`inspect_anchor_set`: a non-tuple
    ``items`` (including a list, a generator or ``None``) or an element that
    is not an :class:`AnchoredContinuationChain` raises TypeError, while an
    empty tuple or a non-32-byte ``key`` raises ValueError. A set that fails
    the diagnosis — a package that does not verify or anchor internally, or
    two packages whose adjacent anchors differ — raises ValueError, never a
    silently partial merge. Nested structural violations raised during the
    diagnosis propagate unchanged (TypeError or ValueError).
    """
    report = inspect_anchor_set(items, key)
    if not report.ok:
        raise ValueError(
            f"anchor set cannot be merged: {report.code!r} at receipt "
            f"index {report.index}"
        )
    receipts = tuple(
        receipt for item in items for receipt in item.receipts
    )
    return AnchoredContinuationChain(receipts, items[0].start, items[-1].end)


def encode_continuations(receipts: Any) -> bytes:
    """Encode a non-empty tuple of continuation receipts into canonical bytes.

    The byte stream is ``D || U(1) || U(n) || B(R1) … B(Rn)`` with
    ``D = b"auditchain/cont-chain/v1\\0"``, ``U`` an unsigned 8-byte
    big-endian integer, ``B(x) = U(len(x)) || x`` and ``n`` the non-zero
    receipt count: the envelope ``version`` (always 1), then the count, then
    one length-prefixed blob per :class:`SignedAuthAuditContinuation` in the
    tuple's own order — nothing may be omitted, reordered or appended. Each
    ``Ri`` is byte-for-byte the complete canonical output of
    :func:`encode_signed_auth_audit_continuation` over that receipt; the
    framing introduces no new signing message and is read-only.

    ``receipts`` must be a non-empty ``tuple`` of
    :class:`SignedAuthAuditContinuation` objects — a non-tuple, an empty
    tuple or an element of another type raises TypeError; nested structural
    problems raise exactly the exceptions of
    :func:`encode_signed_auth_audit_continuation` (TypeError or ValueError).
    Encoding is deterministic: re-encoding a decoded tuple reproduces the
    original bytes exactly.
    """
    if not isinstance(receipts, tuple):
        raise TypeError("receipts must be a non-empty tuple")
    if len(receipts) == 0:
        raise ValueError("receipts must be a non-empty tuple")
    parts = [
        _CONTINUATION_CHAIN_MAGIC,
        _encode_u64(_CONTINUATION_CHAIN_VERSION, "version"),
        _encode_u64(len(receipts), "receipt count"),
    ]
    for receipt in receipts:
        if not isinstance(receipt, SignedAuthAuditContinuation):
            raise TypeError(
                "each receipt must be a SignedAuthAuditContinuation"
            )
        parts.append(
            _encode_blob(encode_signed_auth_audit_continuation(receipt))
        )
    return b"".join(parts)


def decode_continuations(data: Any) -> tuple:
    """Decode bytes produced by :func:`encode_continuations`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/cont-chain/v1\\0"`` it must contain, strictly in order,
    the u64 envelope version (only ``1`` is supported), the non-zero u64
    receipt count ``n`` and exactly ``n`` length-prefixed blobs, each
    consumed whole with no trailing bytes. Every blob is handed to
    :func:`decode_signed_auth_audit_continuation`, so its framing and
    structural rules apply verbatim. A bad magic or version, a zero or
    oversized count, truncation, an oversized blob length, trailing bytes or
    an illegal nested encoding raises ValueError.

    Signatures, tags, proofs and the adjacency between receipts are not
    checked here — only :func:`verify_continuation_chain` confirms the
    segments join into one append-only history. The returned tuple
    preserves the encoded order, its elements equal the originally encoded
    receipts, and re-encoding reproduces the original bytes exactly.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_CONTINUATION_CHAIN_MAGIC):
        raise ValueError("not an auditchain continuation-chain encoding")
    offset = len(_CONTINUATION_CHAIN_MAGIC)

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
    if version != _CONTINUATION_CHAIN_VERSION:
        raise ValueError(
            f"unsupported continuation-chain version {version}"
        )
    count = read_u64("receipt count")
    if count == 0:
        raise ValueError("continuation chain must contain at least one receipt")
    receipts = []
    for position in range(count):
        blob = read_blob(f"continuation receipt {position}")
        receipts.append(decode_signed_auth_audit_continuation(blob))
    if offset != len(data):
        raise ValueError("trailing bytes after the continuation chain")
    return tuple(receipts)


def encode_anchored_continuations(bundle: Any) -> bytes:
    """Encode an :class:`AnchoredContinuationChain` into canonical bytes.

    The byte stream is ``D || U(1) || B(C) || B(S) || B(E)`` with
    ``D = b"auditchain/anchor/v1\\0"``, ``U`` an unsigned 8-byte big-endian
    integer and ``B(x) = U(len(x)) || x``: the envelope ``version`` (always
    1), then ``C`` holding byte-for-byte the complete canonical output of
    :func:`encode_continuations` over ``bundle.receipts``, then ``S`` and
    ``E`` holding byte-for-byte the complete canonical outputs of
    :func:`encode_signed_root` over ``bundle.start`` and ``bundle.end`` —
    nothing may be omitted, reordered or appended. The framing introduces
    no new signing message and is read-only: it never mutates the bundle.

    ``bundle`` must be an :class:`AnchoredContinuationChain` — anything else
    raises TypeError; nested structural problems raise exactly the
    exceptions of :func:`encode_continuations` and
    :func:`encode_signed_root` (TypeError or ValueError), propagated
    unchanged. Encoding is deterministic: re-encoding a decoded bundle
    reproduces the original bytes exactly.
    """
    if not isinstance(bundle, AnchoredContinuationChain):
        raise TypeError("bundle must be an AnchoredContinuationChain")
    return b"".join((
        _ANCHORED_CONTINUATION_MAGIC,
        _encode_u64(_ANCHORED_CONTINUATION_VERSION, "version"),
        _encode_blob(encode_continuations(bundle.receipts)),
        _encode_blob(encode_signed_root(bundle.start)),
        _encode_blob(encode_signed_root(bundle.end)),
    ))


def decode_anchored_continuations(data: Any) -> AnchoredContinuationChain:
    """Decode bytes produced by :func:`encode_anchored_continuations`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/anchor/v1\\0"`` it must contain, strictly in order, the
    u64 envelope version (only ``1`` is supported) and exactly three
    length-prefixed blobs, each consumed whole with no trailing bytes: the
    chain blob is handed to :func:`decode_continuations` and the start and
    end anchor blobs to :func:`decode_signed_root`, so their framing and
    structural rules apply verbatim and their exceptions propagate
    unchanged. A bad magic or version, truncation, an oversized blob length
    or trailing bytes raises ValueError.

    Signatures, tags, proofs, the adjacency between receipts and the
    anchoring itself are not checked here — only
    :func:`inspect_anchored_continuations` confirms the decoded chain spans
    its anchors. The returned bundle's fields equal the originally encoded
    ones, and re-encoding reproduces the original bytes exactly.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_ANCHORED_CONTINUATION_MAGIC):
        raise ValueError("not an auditchain anchored-continuation encoding")
    offset = len(_ANCHORED_CONTINUATION_MAGIC)

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
    if version != _ANCHORED_CONTINUATION_VERSION:
        raise ValueError(
            f"unsupported anchored-continuation version {version}"
        )
    receipts = decode_continuations(read_blob("continuation chain"))
    start = decode_signed_root(read_blob("start anchor"))
    end = decode_signed_root(read_blob("end anchor"))
    if offset != len(data):
        raise ValueError("trailing bytes after the anchored continuations")
    return AnchoredContinuationChain(receipts, start, end)


def encode_anchor_set(bundle: Any) -> bytes:
    """Encode an :class:`AnchorSet` into canonical bytes.

    The byte stream is ``D || U(1) || U(n) || B(P0) … B(Pn-1)`` with
    ``D = b"auditchain/anchor-set/v1\\0"``, ``U`` an unsigned 8-byte
    big-endian integer and ``B(x) = U(len(x)) || x``: the envelope
    ``version`` (always 1), then the package count ``n`` and one
    length-prefixed blob per package in ``bundle.items`` order — each
    ``Pi`` byte-for-byte the complete canonical output of
    :func:`encode_anchored_continuations` over ``items[i]``. Nothing may
    be omitted, reordered or appended. The framing re-uses the existing
    encoding only, introduces no new signing message and is read-only: it
    never mutates the bundle.

    ``bundle`` must be an :class:`AnchorSet` — anything else raises
    TypeError; nested structural problems raise exactly the exceptions of
    :func:`encode_anchored_continuations` (TypeError or ValueError),
    propagated unchanged. Encoding is deterministic: re-encoding a
    decoded bundle reproduces the original bytes exactly.
    """
    if not isinstance(bundle, AnchorSet):
        raise TypeError("bundle must be an AnchorSet")
    parts = [
        _ANCHOR_SET_MAGIC,
        _encode_u64(_ANCHOR_SET_VERSION, "version"),
        _encode_u64(len(bundle.items), "package count"),
    ]
    for item in bundle.items:
        parts.append(_encode_blob(encode_anchored_continuations(item)))
    return b"".join(parts)


def decode_anchor_set(data: Any) -> AnchorSet:
    """Decode bytes produced by :func:`encode_anchor_set`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray``
    and ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/anchor-set/v1\\0"`` it must contain, strictly in
    order, the u64 envelope version (only ``1`` is supported), the
    non-zero u64 package count ``n`` and exactly ``n`` length-prefixed
    package blobs, each consumed whole with no trailing bytes. Every
    package blob is handed whole to :func:`decode_anchored_continuations`,
    so its framing and structural rules apply verbatim and its exceptions
    propagate unchanged. A bad magic or version, a zero package count,
    truncation, an oversized blob length, trailing bytes or an illegal
    nested encoding raises ValueError.

    Signatures, tags, proofs, the adjacency between receipts and the
    anchoring within or across packages are not checked here — only
    :func:`inspect_anchor_set` confirms the decoded packages verify and
    splice into one chain; a structurally well-formed set whose
    credentials fail to verify still decodes. The returned bundle is a
    frozen :class:`AnchorSet` whose field equals the originally encoded
    one, the tuple preserves the encoded order, and re-encoding
    reproduces the original bytes exactly.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_ANCHOR_SET_MAGIC):
        raise ValueError("not an auditchain anchor-set encoding")
    offset = len(_ANCHOR_SET_MAGIC)

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
    if version != _ANCHOR_SET_VERSION:
        raise ValueError(f"unsupported anchor-set version {version}")
    package_count = read_u64("package count")
    if package_count == 0:
        raise ValueError("anchor set must contain at least one package")
    items = []
    for position in range(package_count):
        items.append(
            decode_anchored_continuations(
                read_blob(f"anchor package {position}")
            )
        )
    if offset != len(data):
        raise ValueError("trailing bytes after the anchor set")
    return AnchorSet(tuple(items))


def encode_rotated_anchor(x: Any) -> bytes:
    """Encode a :class:`RotatedChain` into canonical bytes.

    The byte stream is ``D || U(1) || B(C) || B(R) || B(S) || B(E)`` with
    ``D = b"auditchain/ra/v1\\0"``, ``U`` an unsigned 8-byte big-endian
    integer and ``B(x) = U(len(x)) || x``: the envelope ``version``
    (always 1), then ``C`` holding byte-for-byte the complete canonical
    output of :func:`encode_continuations` over ``x.receipts``, ``R``
    holding byte-for-byte the complete canonical output of
    :func:`encode_rotations` over ``x.rotations``, then ``S`` and ``E``
    holding byte-for-byte the complete canonical outputs of
    :func:`encode_signed_root` over ``x.start`` and ``x.end`` — nothing
    may be omitted, reordered or appended. The framing re-uses the
    existing encodings only, introduces no new signing message and is
    read-only: it never mutates the bundle.

    ``x`` must be a :class:`RotatedChain` — anything else raises
    TypeError; nested structural problems raise exactly the exceptions of
    :func:`encode_continuations`, :func:`encode_rotations` and
    :func:`encode_signed_root` (TypeError or ValueError), propagated
    unchanged. Encoding is deterministic: re-encoding a decoded bundle
    reproduces the original bytes exactly.
    """
    if not isinstance(x, RotatedChain):
        raise TypeError("x must be a RotatedChain")
    return b"".join((
        _ROTATED_ANCHOR_MAGIC,
        _encode_u64(_ROTATED_ANCHOR_VERSION, "version"),
        _encode_blob(encode_continuations(x.receipts)),
        _encode_blob(encode_rotations(x.rotations)),
        _encode_blob(encode_signed_root(x.start)),
        _encode_blob(encode_signed_root(x.end)),
    ))


def decode_rotated_anchor(data: Any) -> RotatedChain:
    """Decode bytes produced by :func:`encode_rotated_anchor`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/ra/v1\\0"`` it must contain, strictly in order, the u64
    envelope version (only ``1`` is supported) and exactly four
    length-prefixed blobs, each consumed whole with no trailing bytes:
    the chain blob is handed to :func:`decode_continuations`, the rotation
    blob to :func:`decode_rotations` and the start and end anchor blobs to
    :func:`decode_signed_root`, so their framing and structural rules
    apply verbatim and their exceptions propagate unchanged. A bad magic
    or version, truncation, an oversized blob length, trailing bytes or an
    illegal nested encoding raises ValueError, as does a restored package
    with fewer than two receipts or a rotation count other than one per
    boundary, which fails the :class:`RotatedChain` shape checks.

    Signatures, authorizations, proofs, the cryptographic hop between
    segments and the anchoring itself are not checked here — only
    :func:`inspect_rotated_anchors` confirms the decoded chain verifies
    across its rotations and spans its anchors. The returned bundle is a
    frozen :class:`RotatedChain` whose fields equal the originally encoded
    ones, its tuples preserve the encoded order, and re-encoding
    reproduces the original bytes exactly.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_ROTATED_ANCHOR_MAGIC):
        raise ValueError("not an auditchain rotated-anchor encoding")
    offset = len(_ROTATED_ANCHOR_MAGIC)

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
    if version != _ROTATED_ANCHOR_VERSION:
        raise ValueError(f"unsupported rotated-anchor version {version}")
    receipts = decode_continuations(read_blob("continuation chain"))
    rotations = decode_rotations(read_blob("rotation chain"))
    start = decode_signed_root(read_blob("start anchor"))
    end = decode_signed_root(read_blob("end anchor"))
    if offset != len(data):
        raise ValueError("trailing bytes after the rotated anchor")
    return RotatedChain(receipts, rotations, start, end)


def encode_rotated_anchor_set(bundle: Any) -> bytes:
    """Encode a :class:`RotatedAnchorSet` into canonical bytes.

    The byte stream is
    ``D || U(1) || U(n) || B(P0) … B(Pn-1) || U(m) || B(R0) … B(Rm-1)``
    with ``D = b"auditchain/rotated-anchor-set/v1\\0"``, ``U`` an unsigned
    8-byte big-endian integer and ``B(x) = U(len(x)) || x``: the envelope
    ``version`` (always 1), then the package count ``n`` and one
    length-prefixed blob per package in ``bundle.items`` order — each ``Pi``
    byte-for-byte the complete canonical output of
    :func:`encode_rotated_anchor` over ``items[i]`` — then the bridge count
    ``m = n - 1`` and one length-prefixed blob per bridge in
    ``bundle.bridges`` order, each ``Ri`` byte-for-byte the complete
    canonical output of :func:`encode_rotation` over ``bridges[i]``. A
    zero-length blob still writes its all-zero u64 length (none occurs here
    — both nested encodings always carry a magic — but the framing rule is
    uniform). Nothing may be omitted, reordered or appended. The framing
    re-uses the existing encodings only, introduces no new signing message
    and is read-only: it never mutates the bundle.

    ``bundle`` must be a :class:`RotatedAnchorSet` — anything else raises
    TypeError; nested structural problems raise exactly the exceptions of
    :func:`encode_rotated_anchor` and :func:`encode_rotation` (TypeError or
    ValueError), propagated unchanged. Encoding is deterministic:
    re-encoding a decoded bundle reproduces the original bytes exactly.
    """
    if not isinstance(bundle, RotatedAnchorSet):
        raise TypeError("bundle must be a RotatedAnchorSet")
    parts = [
        _ROTATED_ANCHOR_SET_MAGIC,
        _encode_u64(_ROTATED_ANCHOR_SET_VERSION, "version"),
        _encode_u64(len(bundle.items), "package count"),
    ]
    for item in bundle.items:
        parts.append(_encode_blob(encode_rotated_anchor(item)))
    parts.append(_encode_u64(len(bundle.bridges), "bridge count"))
    for bridge in bundle.bridges:
        parts.append(_encode_blob(encode_rotation(bridge)))
    return b"".join(parts)


def decode_rotated_anchor_set(data: Any) -> RotatedAnchorSet:
    """Decode bytes produced by :func:`encode_rotated_anchor_set`.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError). After the magic
    ``b"auditchain/rotated-anchor-set/v1\\0"`` it must contain, strictly in
    order, the u64 envelope version (only ``1`` is supported), the
    non-zero u64 package count ``n`` followed by exactly ``n``
    length-prefixed package blobs, and then the u64 bridge count ``m`` —
    which must equal ``n - 1`` — followed by exactly ``m``
    length-prefixed bridge blobs, all consumed whole with no trailing
    bytes. Every package blob is handed whole to
    :func:`decode_rotated_anchor` and every bridge blob to
    :func:`decode_rotation`, so their framing and structural rules apply
    verbatim and their exceptions propagate unchanged. A bad magic or
    version, truncation, an oversized blob length, trailing bytes, a zero
    package count or a bridge count other than ``n - 1`` raises
    ValueError, as does an illegal nested encoding.

    Signatures, authorizations, proofs, the cryptographic hops and the
    anchoring itself are not checked here — only
    :func:`inspect_rotated_anchor_set` confirms the decoded packages verify
    across their bridges as one chain; a structurally well-formed set whose
    credentials fail to verify still decodes. The returned bundle is a
    frozen :class:`RotatedAnchorSet` whose fields equal the originally
    encoded ones, both tuples preserve the encoded order, and re-encoding
    reproduces the original bytes exactly.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data.startswith(_ROTATED_ANCHOR_SET_MAGIC):
        raise ValueError("not an auditchain rotated-anchor-set encoding")
    offset = len(_ROTATED_ANCHOR_SET_MAGIC)

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
    if version != _ROTATED_ANCHOR_SET_VERSION:
        raise ValueError(f"unsupported rotated-anchor-set version {version}")
    package_count = read_u64("package count")
    if package_count == 0:
        raise ValueError("rotated anchor set must contain at least one package")
    items = []
    for position in range(package_count):
        items.append(
            decode_rotated_anchor(read_blob(f"rotated package {position}"))
        )
    bridge_count = read_u64("bridge count")
    if bridge_count != package_count - 1:
        raise ValueError(
            "bridge count must be exactly one fewer than the package count "
            f"({bridge_count} bridges for {package_count} packages)"
        )
    bridges = []
    for position in range(bridge_count):
        bridges.append(decode_rotation(read_blob(f"rotation bridge {position}")))
    if offset != len(data):
        raise ValueError("trailing bytes after the rotated anchor set")
    return RotatedAnchorSet(tuple(items), tuple(bridges))


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


def dump_signed_auth(log: Any, private_key: Any) -> bytes:
    """Export an unpruned, keyed, encrypt-free log as one self-certifying
    byte string.

    The Ed25519-signed counterpart of :func:`dump_auth`: instead of sealing
    the framing symmetrically, the export is signed with the 32-byte Ed25519
    seed ``private_key`` and verified offline by :func:`load_signed_auth`
    against the pre-arranged public key. Only an :class:`AuditLog` that holds
    its complete, unpruned history (``retain_from == 0``), was **constructed
    with an authentication key** and has never held encrypted entries
    qualifies: the framing carries the current forward-secure evolution key
    and stage in the clear, so a fresh process can continue evolving from
    exactly the same point, but it carries no prune checkpoints, encryption
    keys, nonce history or verifier material beyond the u64
    verifier-exported flag.

    The encoding starts with the magic ``b"auditchain/signed-auth/v1\\0"``
    and then writes, strictly in order, the envelope version (always ``1``)
    as an unsigned 8-byte big-endian integer, then exactly the plaintext
    framing of :func:`dump_auth` — ``B(h) || U(n) || E1…En || B(root) ||
    B(head) || U(stage) || B(K) || U(x)``, where ``h`` is the UTF-8 encoding
    of the hash algorithm name, ``n`` the entry count, ``root`` the Merkle
    root and ``head`` the chain head of the size-``n`` snapshot, ``stage``
    the current key-evolution stage, ``K`` the current evolution key and
    ``x`` the verifier-exported flag (``0`` or ``1``), and each ``Ei`` an
    ``Entry(index, payload, previous_hash, entry_hash)`` in field order as
    ``U, B, B, B`` — and finally a 64-byte Ed25519 signature over every
    preceding byte. ``U`` is an unsigned 8-byte big-endian integer and
    ``B(v) = U(len(v)) || v``. No signing domain beyond the signed bytes
    themselves is introduced. The signature authenticates the export's
    origin; it does **not** encrypt the framing, which carries the live
    evolution key, so the byte string must be protected like verification
    key material.

    The call is read-only and deterministic: it never mutates the log, and
    two dumps of logs in the same state signed with the same seed are
    byte-for-byte identical (Ed25519 signatures are deterministic); the seed
    is used for the one signature and is never stored, copied into the dump
    or added as a separate signing input. A non-:class:`AuditLog` value or a
    non-``bytes`` seed raises TypeError; a seed that is not 32 bytes, or a
    log that is pruned, keyless or has encrypted history raises ValueError.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    # Validate the seed before any eligibility check, mirroring dump_log /
    # dump_secure_log; the loaded key signs once below and is never stored.
    signing_key = _load_ed25519_seed(private_key)
    # Same eligibility as dump_auth: the framing carries the live evolution
    # key and stage, so only an unpruned log that was constructed with a key
    # and has no encrypt history of any kind qualifies.
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
        _SIGNED_AUTH_MAGIC,
        _encode_u64(_SIGNED_AUTH_VERSION, "version"),
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
    body = b"".join(parts)
    # Sign every byte written so far; the signature is the trailing field, so
    # the wire format verifies without knowing any inner framing offset.
    signature = signing_key.sign(body)
    if len(signature) != _ED25519_SIGNATURE_BYTES:
        raise ValueError(
            f"signature must be {_ED25519_SIGNATURE_BYTES} bytes"
        )
    return body + signature


def load_signed_auth(data: Any, public_key: Any) -> AuditLog:
    """Restore an independent, mutable keyed :class:`AuditLog` from
    :func:`dump_signed_auth`, verifying entirely offline.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError) and ``public_key`` must be the 32-byte
    Ed25519 public key pre-arranged with the exporter. After the magic
    ``b"auditchain/signed-auth/v1\\0"`` the stream must contain, strictly in
    order, the u64 envelope version (only ``1`` is supported), exactly the
    plaintext framing of :func:`dump_auth` —
    ``B(h) || U(n) || E1…En || B(root) || B(head) || U(stage) || B(K) ||
    U(x)``, where each ``Ei`` is an
    ``Entry(index, payload, previous_hash, entry_hash)`` in field order
    (``U, B, B, B``) — and a final 64-byte Ed25519 signature, with no
    truncation or trailing bytes.

    Verification happens before any state is built: the trailing signature
    is checked against every preceding byte with ``public_key``; only then
    is the stream parsed. Indices must be exactly ``0..n-1``, every chain
    digest must have the width of the named hash algorithm, ``K`` (the
    current evolution key) must be non-empty — at stage 0 it is the
    construction key, which may have any non-zero length, and after any
    evolution it is one hash-digest wide — and ``x`` (the verifier-exported
    flag) must be ``0`` or ``1``. Under the named ``hash_name`` every
    :func:`entry_digest` and predecessor link is then recomputed from
    genesis, and the resulting chain head and Merkle root must match
    ``head`` / ``root``. Only then is a fresh keyed :class:`AuditLog` built
    by replaying the payloads through the normal append path, with ``K``
    installed as the current key, ``stage`` and the exported flag restored,
    so its length, absolute indices, head, Merkle root, find results and
    stage are exactly those of the dumped log — an already-exported log
    cannot export stage-0 verifier material again — and forward-secure
    evolution continues from the same point. The result is fully mutable
    (append, encrypt and evolve keys as usual, minting tags byte-identical
    to the original's in the same state) and shares no state with the
    caller's buffers.

    A non-``bytes`` ``data`` or ``public_key`` raises TypeError; a public
    key that is not 32 bytes, a bad magic, version, UTF-8 or hash algorithm,
    truncation, trailing bytes, an out-of-order index, a wrong digest or
    evolution-key width, an out-of-range flag, a signature that does not
    verify or a recomputed chain-head/root mismatch raises ValueError. The
    call never mutates its inputs; on failure nothing is returned and no
    partial log escapes.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    verification_key = _load_ed25519_public(public_key)
    if not data.startswith(_SIGNED_AUTH_MAGIC):
        raise ValueError("not an auditchain signed-auth encoding")
    if len(data) < _ED25519_SIGNATURE_BYTES:
        raise ValueError("truncated encoding: missing signature")
    body = data[:-_ED25519_SIGNATURE_BYTES]
    signature = data[-_ED25519_SIGNATURE_BYTES:]
    # Verify the signature over the entire body before parsing any of it, so
    # a forged or corrupted stream never reaches the chain-replay logic.
    try:
        verification_key.verify(signature, body)
    except InvalidSignature as error:
        raise ValueError("signed-auth signature does not verify") from error
    offset = len(_SIGNED_AUTH_MAGIC)

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
    if version != _SIGNED_AUTH_VERSION:
        raise ValueError(f"unsupported signed-auth version {version}")
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
    if offset != len(body):
        raise ValueError("trailing bytes before the signed-auth signature")
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


def dump_signed_pruned_auth(log: Any, private_key: Any) -> bytes:
    """Export a pruned, keyed, encrypt-free log as one self-certifying
    byte string.

    The Ed25519-signed counterpart of :func:`dump_pruned_auth`: instead of
    sealing the framing symmetrically, the export is signed with the 32-byte
    Ed25519 seed ``private_key`` and verified offline by
    :func:`load_signed_pruned_auth` against the pre-arranged public key. Only
    an :class:`AuditLog` that has been pruned (``retain_from > 0``), was
    **constructed with an authentication key** and has never held encrypted
    entries qualifies: the framing carries the prune checkpoint, the prefix
    frontier, the retained entries and the current forward-secure evolution
    key and stage in the clear, so a fresh process can continue evolving from
    exactly the same point, but it carries no prune receipts, encryption keys,
    nonce history or verifier material beyond the u64 verifier-exported flag.

    The encoding starts with the magic
    ``b"auditchain/signed-pruned-auth/v1\\0"`` and then writes, strictly in
    order, the envelope version (always ``1``) as an unsigned 8-byte
    big-endian integer, then exactly the plaintext framing of
    :func:`dump_pruned_auth` —
    ``B(hash_name) || U(n) || U(r) || B(checkpoint) || F || E || B(root) ||
    B(head) || U(stage) || B(K) || U(x)`` — and finally a 64-byte Ed25519
    signature over every preceding byte. ``U`` is an unsigned 8-byte big-endian
    integer and ``B(v) = U(len(v)) || v``. No signing domain beyond the signed
    bytes themselves is introduced and nothing is encrypted; the signature
    authenticates the export's origin, while the framing carries the live
    evolution key, so the byte string must be protected like verification key
    material.

    The call is read-only and deterministic: it never mutates the log, and
    two dumps of logs in the same state signed with the same seed are
    byte-for-byte identical (Ed25519 signatures are deterministic); the seed
    is used for the one signature and is never stored, copied into the dump
    or added as a separate signing input. A non-:class:`AuditLog` value or a
    non-``bytes`` seed raises TypeError; a seed that is not 32 bytes, or a log
    that is unpruned, keyless or has encrypted history raises ValueError.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    # Validate the seed before any eligibility check, mirroring
    # dump_signed_auth / dump_pruned_log; the loaded key signs once below and
    # is never stored.
    signing_key = _load_ed25519_seed(private_key)
    # Same eligibility as dump_pruned_auth: the plaintext framing carries the
    # live evolution key and stage, so only a pruned log that was constructed
    # with a key and has no encrypt history of any kind qualifies.
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
    # Field-by-field the plaintext framing of dump_pruned_auth.
    parts = [
        _SIGNED_PRUNED_AUTH_MAGIC,
        _encode_u64(_SIGNED_PRUNED_AUTH_VERSION, "version"),
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
    body = b"".join(parts)
    # Sign every byte written so far; the signature is the trailing field, so
    # the wire format verifies without knowing any inner framing offset.
    signature = signing_key.sign(body)
    if len(signature) != _ED25519_SIGNATURE_BYTES:
        raise ValueError(
            f"signature must be {_ED25519_SIGNATURE_BYTES} bytes"
        )
    return body + signature


def load_signed_pruned_auth(data: Any, public_key: Any) -> AuditLog:
    """Restore an independent, mutable keyed :class:`AuditLog` from
    :func:`dump_signed_pruned_auth`, verifying entirely offline.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError) and ``public_key`` must be the 32-byte
    Ed25519 public key pre-arranged with the exporter. After the magic
    ``b"auditchain/signed-pruned-auth/v1\\0"`` the stream must contain,
    strictly in order, the u64 envelope version (only ``1`` is supported),
    exactly the plaintext framing of :func:`dump_pruned_auth` —
    ``B(hash_name) || U(n) || U(r) || B(checkpoint) || F || E || B(root) ||
    B(head) || U(stage) || B(K) || U(x)`` — and a final 64-byte Ed25519
    signature, with no truncation or trailing bytes.

    Verification happens before any state is built: the trailing signature is
    checked against every preceding byte with ``public_key``; only then is the
    stream parsed and re-checked: ``r`` must satisfy ``0 < r <= n``, the
    checkpoint and every frontier/entry digest must have the width of the
    named hash algorithm, the frontier must list one
    ``U(height) || B(digest)`` pair per set bit of ``r`` in strictly ascending
    order, the retained entries must be exactly ``n - r`` occupying indices
    ``r..n-1`` in order, ``K`` (the current evolution key) must be non-empty —
    at stage 0 it is the construction key, which may have any non-zero length,
    and after any evolution it is one hash-digest wide — and ``x`` (the
    verifier-exported flag) must be ``0`` or ``1``. Under the named
    ``hash_name`` every :func:`entry_digest` and predecessor link is then
    recomputed starting from the checkpoint, the resulting chain head must
    match ``head`` and the Merkle root rebuilt from the frontier and the
    retained entries must match ``root``. Only then is a fresh keyed
    :class:`AuditLog` materialized with ``retain_from == r``, the checkpoint
    and frontier installed and the payloads replayed through the normal append
    path, with ``K`` installed as the current key, ``stage`` and the exported
    flag restored, so its length, absolute indices, retain point, head,
    Merkle root, inclusion proofs, find results and stage are exactly those of
    the dumped log — an already-exported log cannot export stage-0 verifier
    material again — and forward-secure evolution continues from the same
    point. The result is fully mutable (append, prune again, rotate and evolve
    keys as usual, minting tags byte-identical to the original's in the same
    state) and shares no state with the caller's buffers.

    A non-``bytes`` ``data`` or ``public_key`` raises TypeError; a public key
    that is not 32 bytes, a bad magic, version, UTF-8 or hash algorithm,
    truncation, trailing bytes, an out-of-range retain point, a wrong
    checkpoint/frontier/digest/key width or value, a frontier that is not
    exactly the set bits of ``r``, an entry count that disagrees with
    ``n - r``, an out-of-order index, an out-of-range stage or flag, a
    signature that does not verify or a recomputed chain-head/root mismatch
    raises ValueError. The call never mutates its inputs; on failure nothing
    is returned and no partial log escapes.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    verification_key = _load_ed25519_public(public_key)
    if not data.startswith(_SIGNED_PRUNED_AUTH_MAGIC):
        raise ValueError("not an auditchain signed-pruned-auth encoding")
    if len(data) < _ED25519_SIGNATURE_BYTES:
        raise ValueError("truncated encoding: missing signature")
    body = data[:-_ED25519_SIGNATURE_BYTES]
    signature = data[-_ED25519_SIGNATURE_BYTES:]
    # Verify the signature over the entire body before parsing any of it, so
    # a forged or corrupted stream never reaches the chain-replay logic.
    try:
        verification_key.verify(signature, body)
    except InvalidSignature as error:
        raise ValueError(
            "signed-pruned-auth signature does not verify"
        ) from error
    offset = len(_SIGNED_PRUNED_AUTH_MAGIC)

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
    if version != _SIGNED_PRUNED_AUTH_VERSION:
        raise ValueError(f"unsupported signed-pruned-auth version {version}")
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
    if offset != len(body):
        raise ValueError(
            "trailing bytes before the signed-pruned-auth signature"
        )
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

    # Re-derive the retained chain from the signed checkpoint under the named
    # hash algorithm, and simultaneously replay the payloads into a fresh
    # keyed log with the checkpoint, frontier and retain point installed, so
    # the find index and every other auxiliary structure are rebuilt exactly
    # as the normal append path builds them. The evolution key, stage and
    # verifier-exported flag are only installed after the replay succeeds, so
    # a failure leaves no partially restored log behind.
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


def dump_signed_hybrid(log: Any, private_key: Any) -> bytes:
    """Export an unpruned, keyed log (with encrypt history) as one
    self-certifying byte string.

    The Ed25519-signed counterpart of :func:`dump_hybrid`: instead of sealing
    the framing symmetrically, the export is signed with the 32-byte Ed25519
    seed ``private_key`` and verified offline by :func:`load_signed_hybrid`
    against the pre-arranged public key. Only an :class:`AuditLog` that holds
    its complete, unpruned history (``retain_from == 0``) and was **constructed
    with an authentication key** qualifies; unlike :func:`dump_signed_auth`,
    its history may contain entries appended with :meth:`AuditLog.encrypt`.
    The framing carries the complete encrypt nonce history and the
    encrypted-locator HMAC of every ciphertext, and the current
    forward-secure evolution key and stage in the clear, so a fresh process
    can continue evolving from exactly the same point, but it carries no prune
    checkpoints, encryption keys or verifier material beyond the u64
    verifier-exported flag.

    The encoding starts with the magic
    ``b"auditchain/signed-hybrid/v1\\0"`` and then writes, strictly in order,
    the envelope version (always ``1``) as an unsigned 8-byte big-endian
    integer, then field-by-field the plaintext framing of
    :func:`dump_hybrid` —
    ``B(h) || U(q) || B(nonce1)…B(nonceq) || U(n) || E1…En || B(root) ||
    B(head) || U(stage) || B(K) || U(x)`` — and finally a 64-byte Ed25519
    signature over every preceding byte. ``U`` is an unsigned 8-byte
    big-endian integer and ``B(v) = U(len(v)) || v``. No signing domain
    beyond the signed bytes themselves is introduced and no evolution key is
    encrypted. The signature authenticates the export's origin; it does
    **not** encrypt the framing, which carries the live evolution key, so the
    byte string must be protected like verification key material.

    The call is read-only and deterministic: it never mutates the log, and
    two dumps of logs in the same state signed with the same seed are
    byte-for-byte identical (Ed25519 signatures are deterministic); the seed
    is used for the one signature and is never stored, copied into the dump
    or added as a separate signing input. A non-:class:`AuditLog` value or a
    non-``bytes`` seed raises TypeError; a seed that is not 32 bytes, or a
    log that is pruned or keyless raises ValueError.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    # Validate the seed before any eligibility check, mirroring
    # dump_signed_auth / dump_hybrid; the loaded key signs once below and is
    # never stored.
    signing_key = _load_ed25519_seed(private_key)
    # Same eligibility as dump_hybrid, minus the symmetric seal: the framing
    # carries the live evolution key, stage, complete nonce history and
    # per-entry locators, so only an unpruned log that was constructed with a
    # key qualifies; encrypt history is exactly what the nonce/locator fields
    # preserve.
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
        _SIGNED_HYBRID_MAGIC,
        _encode_u64(_SIGNED_HYBRID_VERSION, "version"),
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
    body = b"".join(parts)
    # Sign every byte written so far; the signature is the trailing field, so
    # the wire format verifies without knowing any inner framing offset.
    signature = signing_key.sign(body)
    if len(signature) != _ED25519_SIGNATURE_BYTES:
        raise ValueError(
            f"signature must be {_ED25519_SIGNATURE_BYTES} bytes"
        )
    return body + signature


def load_signed_hybrid(data: Any, public_key: Any) -> AuditLog:
    """Restore an independent, mutable keyed :class:`AuditLog` from
    :func:`dump_signed_hybrid`, verifying entirely offline.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError) and ``public_key`` must be the 32-byte
    Ed25519 public key pre-arranged with the exporter. After the magic
    ``b"auditchain/signed-hybrid/v1\\0"`` the stream must contain, strictly
    in order, the u64 envelope version (only ``1`` is supported), field-by-
    field the plaintext framing of :func:`dump_hybrid` —
    ``B(h) || U(q) || B(nonce1)…B(nonceq) || U(n) || E1…En || B(root) ||
    B(head) || U(stage) || B(K) || U(x)`` — and a final 64-byte Ed25519
    signature, with no truncation or trailing bytes.

    Verification happens before any state is built: the trailing signature is
    checked against every preceding byte with ``public_key``; only then is
    the stream parsed: every nonce blob must carry exactly 12 bytes and the
    ``q`` nonces must be distinct and in lexicographic order; each ``Ei`` is
    an :class:`Entry` record in the :func:`dump_secure_log` field order
    (``U, B, B, B, B``) whose trailing ``B(locator)`` is empty for a plain
    entry and the digest-width encrypted-locator HMAC for an encrypted one;
    indices must be exactly ``0..n-1``, every chain digest must have the
    width of the named hash algorithm, ``K`` (the current evolution key) must
    be non-empty — at stage 0 it is the construction key, which may have any
    non-zero length, and after any evolution it is one hash-digest wide — and
    ``x`` (the verifier-exported flag) must be ``0`` or ``1``. Under the
    named ``hash_name`` every :func:`entry_digest` and predecessor link is
    then recomputed from genesis, and the resulting chain head and Merkle
    root must match ``head`` / ``root``. Classification is driven by the
    locator, never the payload: a non-empty locator's payload must parse as
    an encrypted-entry envelope, whose 12-byte nonce is recovered and must
    not repeat, and the recovered envelope nonces must together be exactly
    the declared nonce history. Only then is a fresh keyed
    :class:`AuditLog` built by replaying the payloads through the normal
    append / encrypted-entry recovery path, with the nonce history, ``K`` as
    the current key, ``stage`` and the exported flag installed, so its
    length, absolute indices, head, Merkle root, find index, encrypted
    locator index, nonce history and stage are exactly those of the dumped
    log — an already-exported log cannot export stage-0 verifier material
    again, a previously used nonce is still rejected and a freshly minted
    tag is byte-identical to the original's in the same state — and
    forward-secure evolution continues from the same point. The result is
    fully mutable and shares no state with the caller's buffers.

    A non-``bytes`` ``data`` or ``public_key`` raises TypeError; a public
    key that is not 32 bytes, a bad magic, version, UTF-8 or hash algorithm,
    truncation, trailing bytes, a wrong-width, duplicated or misordered
    nonce, a nonce history that disagrees with the encrypted entries, wrong
    digest or locator widths, an unparseable ciphertext envelope, an
    out-of-order index, an out-of-range stage or flag, a wrong-width
    evolution key, a signature that does not verify or a recomputed
    chain-head/root mismatch raises ValueError. The call never mutates its
    inputs; on failure nothing is returned and no partial log escapes.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    verification_key = _load_ed25519_public(public_key)
    if not data.startswith(_SIGNED_HYBRID_MAGIC):
        raise ValueError("not an auditchain signed-hybrid encoding")
    if len(data) < _ED25519_SIGNATURE_BYTES:
        raise ValueError("truncated encoding: missing signature")
    body = data[:-_ED25519_SIGNATURE_BYTES]
    signature = data[-_ED25519_SIGNATURE_BYTES:]
    # Verify the signature over the entire body before parsing any of it, so
    # a forged or corrupted stream never reaches the chain-replay logic.
    try:
        verification_key.verify(signature, body)
    except InvalidSignature as error:
        raise ValueError("signed-hybrid signature does not verify") from error
    cursor = len(_SIGNED_HYBRID_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal cursor
        end = cursor + _U64_BYTES
        if end > len(body):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(body[cursor:end], "big")
        cursor = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal cursor
        length = read_u64(f"{name} length")
        end = cursor + length
        if end > len(body):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob = body[cursor:end]
        cursor = end
        return blob

    version = read_u64("version")
    if version != _SIGNED_HYBRID_VERSION:
        raise ValueError(f"unsupported signed-hybrid version {version}")
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
    if cursor != len(body):
        raise ValueError("trailing bytes before the signed-hybrid signature")
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
    # exactly as the normal append / encrypt paths build them. The evolution
    # key, stage and verifier-exported flag are only installed after the
    # replay succeeds, so a failure leaves no partially restored log behind.
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
                raise ValueError("duplicate encrypted nonce in signed-hybrid log")
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


def dump_signed_pruned_hybrid(log: Any, private_key: Any) -> bytes:
    """Export a pruned, keyed log (with encrypt history) as one
    self-certifying byte string.

    The Ed25519-signed counterpart of :func:`dump_pruned_hybrid`: instead of
    sealing the framing symmetrically, the export is signed with the 32-byte
    Ed25519 seed ``private_key`` and verified offline by
    :func:`load_signed_pruned_hybrid` against the pre-arranged public key.
    Only an :class:`AuditLog` that has been pruned (``retain_from > 0``) and
    was **constructed with an authentication key** qualifies; like
    :func:`dump_pruned_hybrid` and unlike :func:`dump_signed_pruned_auth`,
    its history may contain entries appended with :meth:`AuditLog.encrypt`,
    including ciphertexts released by the prune. The framing carries the
    prune checkpoint, the prefix frontier, the retained entries, the log's
    complete nonce history (covering every encrypt nonce ever used, even
    those of released ciphertexts) and the encrypted-locator HMACs of the
    retained ciphertexts, and the current forward-secure evolution key and
    stage in the clear, so a fresh process can continue evolving from
    exactly the same point, but it carries no prune receipts, encryption
    keys or verifier material beyond the u64 verifier-exported flag.

    The encoding starts with the magic
    ``b"auditchain/signed-pruned-hybrid/v1\\0"`` and then writes, strictly in
    order, the envelope version (always ``1``) as an unsigned 8-byte
    big-endian integer, then field-by-field the plaintext framing of
    :func:`dump_pruned_hybrid` —
    ``B(h) || U(n) || U(r) || B(checkpoint) || F || Q || E || B(root) ||
    B(head) || U(stage) || B(K) || U(x)`` — and finally a 64-byte Ed25519
    signature over every preceding byte. ``F`` is the pruned-log frontier
    exactly as encoded by :func:`dump_pruned_auth`, ``Q`` the complete nonce
    history exactly as in :func:`dump_hybrid` and each retained entry of
    ``E`` the :func:`dump_secure_log` record (``U, B, B, B, B`` with the
    locator classification). ``U`` is an unsigned 8-byte big-endian integer
    and ``B(v) = U(len(v)) || v``. No signing domain beyond the signed bytes
    themselves is introduced and no evolution key is encrypted; the
    signature authenticates the export's origin, while the framing carries
    the live evolution key, so the byte string must be protected like
    verification key material.

    The call is read-only and deterministic: it never mutates the log, and
    two dumps of logs in the same state signed with the same seed are
    byte-for-byte identical (Ed25519 signatures are deterministic); the seed
    is used for the one signature and is never stored, copied into the dump
    or added as a separate signing input. A non-:class:`AuditLog` value or a
    non-``bytes`` seed raises TypeError; a seed that is not 32 bytes, or a
    log that is unpruned or keyless raises ValueError.
    """
    if not isinstance(log, AuditLog):
        raise TypeError("log must be an AuditLog")
    # Validate the seed before any eligibility check, mirroring
    # dump_signed_hybrid / dump_signed_pruned_auth; the loaded key signs once
    # below and is never stored.
    signing_key = _load_ed25519_seed(private_key)
    # Same eligibility as dump_pruned_hybrid, minus the symmetric seal: the
    # framing carries the checkpoint, frontier, live evolution key, stage,
    # complete nonce history and per-entry locators, so only a pruned log
    # that was constructed with a key qualifies; encrypt history — including
    # ciphertexts released by the prune — is exactly what the nonce/locator
    # fields preserve.
    if log._retain_from == 0:
        raise ValueError(
            "only a pruned log (retain_from > 0) can be dumped as a signed pruned hybrid log"
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
        _SIGNED_PRUNED_HYBRID_MAGIC,
        _encode_u64(_SIGNED_PRUNED_HYBRID_VERSION, "version"),
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
    body = b"".join(parts)
    # Sign every byte written so far; the signature is the trailing field, so
    # the wire format verifies without knowing any inner framing offset.
    signature = signing_key.sign(body)
    if len(signature) != _ED25519_SIGNATURE_BYTES:
        raise ValueError(
            f"signature must be {_ED25519_SIGNATURE_BYTES} bytes"
        )
    return body + signature


def load_signed_pruned_hybrid(data: Any, public_key: Any) -> AuditLog:
    """Restore an independent, mutable keyed :class:`AuditLog` from
    :func:`dump_signed_pruned_hybrid`, verifying entirely offline.

    ``data`` must be ``bytes`` (anything else, including ``bytearray`` and
    ``memoryview``, raises TypeError) and ``public_key`` must be the 32-byte
    Ed25519 public key pre-arranged with the exporter. After the magic
    ``b"auditchain/signed-pruned-hybrid/v1\\0"`` the stream must contain,
    strictly in order, the u64 envelope version (only ``1`` is supported),
    field-by-field the plaintext framing of :func:`dump_pruned_hybrid` —
    ``B(h) || U(n) || U(r) || B(checkpoint) || F || Q || E || B(root) ||
    B(head) || U(stage) || B(K) || U(x)`` — and a final 64-byte Ed25519
    signature, with no truncation or trailing bytes.

    Verification happens before any state is built: the trailing signature is
    checked against every preceding byte with ``public_key``; only then is
    the stream parsed and re-checked exactly like the decrypted framing of
    :func:`load_pruned_hybrid`: ``r`` must satisfy ``0 < r <= n``,
    ``checkpoint`` must have the digest width, ``F`` must list one
    ``U(height) || B(digest)`` pair per set bit of ``r`` in strictly ascending
    order, ``Q`` must carry the complete lifetime nonce history (every blob
    exactly 12 bytes, the nonces distinct and in lexicographic order), and
    ``E`` must carry exactly ``n - r`` records at indices ``r..n-1`` in order,
    each in the :func:`dump_secure_log` field order (``U, B, B, B, B``) whose
    trailing ``B(locator)`` is empty for a plain entry and the digest-width
    encrypted-locator HMAC for an encrypted one; every chain digest must have
    the width of the named hash algorithm, ``K`` (the current evolution key)
    must be non-empty — at stage 0 it is the construction key, which may have
    any non-zero length, and after any evolution it is one hash-digest wide —
    and ``x`` (the verifier-exported flag) must be ``0`` or ``1``. Under the
    named ``hash_name`` every :func:`entry_digest` and predecessor link is
    then recomputed starting from the checkpoint, and the resulting chain
    head and the Merkle root rebuilt from the frontier and the retained
    entries must match ``head`` / ``root``. Classification is driven by the
    locator, never the payload: a non-empty locator's payload must parse as
    an encrypted-entry envelope, whose 12-byte nonce is recovered, must not
    repeat among the retained ciphertexts and must be covered by the complete
    nonce history, which may additionally hold nonces of ciphertexts released
    by the prune. Only then is a fresh keyed :class:`AuditLog` built with
    ``retain_from == r``, the checkpoint and frontier installed, the complete
    nonce history restored and the retained payloads replayed through the
    normal append / encrypted-entry recovery path, with ``K`` as the current
    key, ``stage`` and the exported flag installed, so its length, absolute
    indices, retain point, head, Merkle roots and proofs, find index,
    encrypted locator index, nonce history and stage are exactly those of the
    dumped log — an already-exported log cannot export stage-0 verifier
    material again, a previously used nonce is still rejected and a freshly
    minted tag is byte-identical to the original's in the same state — and
    forward-secure evolution continues from the same point. The result is
    fully mutable and shares no state with the caller's buffers.

    A non-``bytes`` ``data`` or public key raises TypeError; a public key
    that is not 32 bytes, a bad magic, version, UTF-8 or hash algorithm,
    truncation, trailing bytes, an out-of-range retain point, wrong digest or
    locator widths, a frontier that is not exactly the set bits of ``r``, a
    wrong-width, duplicated or misordered history nonce, an entry count that
    disagrees with ``n - r``, an out-of-order index, an unparseable
    ciphertext envelope, a duplicate retained ciphertext nonce, a retained
    ciphertext nonce missing from the history, an out-of-range stage or flag,
    a wrong-width evolution key, a signature that does not verify or a
    recomputed chain-head/root mismatch raises ValueError. The call never
    mutates its inputs; on failure nothing is returned and no partial log
    escapes.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    verification_key = _load_ed25519_public(public_key)
    if not data.startswith(_SIGNED_PRUNED_HYBRID_MAGIC):
        raise ValueError("not an auditchain signed-pruned-hybrid encoding")
    if len(data) < _ED25519_SIGNATURE_BYTES:
        raise ValueError("truncated encoding: missing signature")
    body = data[:-_ED25519_SIGNATURE_BYTES]
    signature = data[-_ED25519_SIGNATURE_BYTES:]
    # Verify the signature over the entire body before parsing any of it, so
    # a forged or corrupted stream never reaches the chain-replay logic.
    try:
        verification_key.verify(signature, body)
    except InvalidSignature as error:
        raise ValueError(
            "signed-pruned-hybrid signature does not verify"
        ) from error
    cursor = len(_SIGNED_PRUNED_HYBRID_MAGIC)

    def read_u64(name: str) -> int:
        nonlocal cursor
        end = cursor + _U64_BYTES
        if end > len(body):
            raise ValueError(f"truncated encoding: expected 8 bytes for {name}")
        value = int.from_bytes(body[cursor:end], "big")
        cursor = end
        return value

    def read_blob(name: str) -> bytes:
        nonlocal cursor
        length = read_u64(f"{name} length")
        end = cursor + length
        if end > len(body):
            raise ValueError(f"truncated encoding: {name} is {length} bytes")
        blob_value = body[cursor:end]
        cursor = end
        return blob_value

    version = read_u64("version")
    if version != _SIGNED_PRUNED_HYBRID_VERSION:
        raise ValueError(
            f"unsupported signed-pruned-hybrid version {version}"
        )
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
    if cursor != len(body):
        raise ValueError(
            "trailing bytes before the signed-pruned-hybrid signature"
        )
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
        # history (which may also hold nonces of released ciphertexts) and
        # unique among the retained ciphertexts.
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
