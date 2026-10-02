"""Compatibility regression for the shared proof-codec parsing rules.

Exercises the public encode/decode entry points of InclusionProof,
BatchInclusionProof, ConsistencyProof and MerkleFrontier after the decoder
refactor that centralized integer, blob and input-boundary handling, pinning
the byte-exact format, the TypeError/ValueError split and the boundary with
the verify/rebuild entry points.
"""

import copy
import unittest

from auditchain import (
    AuditLog,
    BatchInclusionProof,
    ConsistencyProof,
    InclusionProof,
    MerkleFrontier,
    decode_batch_inclusion_proof,
    decode_consistency_proof,
    decode_inclusion_proof,
    decode_merkle_frontier,
    encode_batch_inclusion_proof,
    encode_consistency_proof,
    encode_inclusion_proof,
    encode_merkle_frontier,
    rebuild_merkle_root,
    verify_batch_inclusion,
    verify_consistency,
    verify_inclusion,
)

HASH_NAMES = ("sha256", "sha512")


def filled_log(hash_name, count):
    log = AuditLog(hash_name=hash_name)
    for index in range(count):
        log.append(f"record-{index}")
    return log


def make_inclusion(log, index, size=None):
    size = len(log) if size is None else size
    return InclusionProof(
        log.hash_name,
        index,
        size,
        log.entry(index).entry_hash,
        log.merkle_root(size),
        log.inclusion_proof(index, size),
    )


def make_batch(log, indices, size=None):
    size = len(log) if size is None else size
    indices, proof = log.batch_inclusion_proof(indices, size)
    return BatchInclusionProof(
        log.hash_name,
        indices,
        tuple(log.entry(index).entry_hash for index in indices),
        size,
        log.merkle_root(size),
        proof,
    )


def make_consistency(log, old_size, new_size=None):
    new_size = len(log) if new_size is None else new_size
    return ConsistencyProof(
        log.hash_name,
        old_size,
        log.merkle_root(old_size),
        new_size,
        log.merkle_root(new_size),
        log.consistency_proof(old_size, new_size),
    )


def check_inclusion(credential):
    return verify_inclusion(
        credential.entry_hash,
        credential.index,
        credential.size,
        credential.root,
        credential.proof,
        hash_name=credential.hash_name,
    )


def check_batch(credential):
    return verify_batch_inclusion(
        credential.indices,
        credential.entry_hashes,
        credential.size,
        credential.root,
        credential.proof,
        hash_name=credential.hash_name,
    )


def check_consistency(credential):
    return verify_consistency(
        credential.old_size,
        credential.old_root,
        credential.new_size,
        credential.new_root,
        credential.proof,
        hash_name=credential.hash_name,
    )


class RoundtripCompatTest(unittest.TestCase):
    """Byte-exact roundtrips through the public codec entry points."""

    def assert_roundtrip(self, credential, encode, decode, check=None):
        data = encode(credential)
        self.assertIsInstance(data, bytes)
        decoded = decode(data)
        self.assertEqual(decoded, credential)
        # Decoding and re-encoding restores the input byte for byte.
        self.assertEqual(encode(decoded), data)
        if check is not None:
            self.assertTrue(check(decoded))
        return decoded

    def test_inclusion_roundtrip_both_hashes(self):
        for hash_name in HASH_NAMES:
            # Single-leaf and non-power-of-two snapshots, first/last/inner leaf.
            for count, index in ((1, 0), (7, 0), (7, 3), (7, 6)):
                log = filled_log(hash_name, count)
                self.assert_roundtrip(
                    make_inclusion(log, index),
                    encode_inclusion_proof,
                    decode_inclusion_proof,
                    check_inclusion,
                )

    def test_batch_roundtrip_both_hashes(self):
        for hash_name in HASH_NAMES:
            log = filled_log(hash_name, 7)
            for indices in ((0,), (3,), (0, 3, 6), (0, 1, 2, 3, 4, 5, 6)):
                self.assert_roundtrip(
                    make_batch(log, indices),
                    encode_batch_inclusion_proof,
                    decode_batch_inclusion_proof,
                    check_batch,
                )

    def test_consistency_roundtrip_both_hashes(self):
        for hash_name in HASH_NAMES:
            log = filled_log(hash_name, 7)
            # Zero old size, equal sizes and ordinary growing pairs.
            for old_size, new_size in ((0, 7), (7, 7), (1, 1), (3, 7), (0, 0)):
                self.assert_roundtrip(
                    make_consistency(log, old_size, new_size),
                    encode_consistency_proof,
                    decode_consistency_proof,
                    check_consistency,
                )

    def test_frontier_roundtrip_both_hashes(self):
        for hash_name in HASH_NAMES:
            log = filled_log(hash_name, 7)
            # Empty prefix, single leaf and non-power-of-two prefixes.
            for size in range(8):
                frontier = log.merkle_frontier(size)
                decoded = self.assert_roundtrip(
                    frontier, encode_merkle_frontier, decode_merkle_frontier
                )
                retained = tuple(
                    log.entry(index).entry_hash for index in range(size, len(log))
                )
                self.assertEqual(
                    rebuild_merkle_root(decoded, retained), log.merkle_root()
                )

    def test_pruned_frontier_export_rebuilds_root(self):
        for hash_name in HASH_NAMES:
            log = filled_log(hash_name, 11)
            receipt = log.seal(6)
            log.prune(6, receipt)
            data = encode_merkle_frontier(log.merkle_frontier(6))
            decoded = decode_merkle_frontier(data)
            retained = tuple(entry.entry_hash for entry in log)
            self.assertEqual(
                rebuild_merkle_root(decoded, retained), log.merkle_root()
            )


class StructuralConstraintTest(unittest.TestCase):
    """The structural contract stays enforced at encode and decode time."""

    def test_batch_indices_strictly_ascending(self):
        log = filled_log("sha256", 4)
        base = make_batch(log, (1, 2))
        for bad_indices in ((2, 1), (1, 1), (2, 0)):
            with self.assertRaises(ValueError):
                BatchInclusionProof(
                    base.hash_name,
                    bad_indices,
                    (base.entry_hashes[0],) * 2,
                    base.size,
                    base.root,
                    base.proof,
                )

    def test_batch_indices_and_hashes_equal_length(self):
        log = filled_log("sha256", 4)
        base = make_batch(log, (1, 2))
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                base.hash_name,
                base.indices,
                base.entry_hashes[:1],
                base.size,
                base.root,
                base.proof,
            )

    def test_frontier_heights_match_prefix_size(self):
        log = filled_log("sha256", 7)
        frontier = log.merkle_frontier(6)
        self.assertEqual(tuple(h for h, _ in frontier.subtrees), (1, 2))
        digest = frontier.subtrees[0][1]
        with self.assertRaises(ValueError):
            MerkleFrontier(frontier.hash_name, 6, ((0, digest), (1, digest)))

    def test_consistency_size_order_enforced(self):
        log = filled_log("sha256", 4)
        with self.assertRaises(ValueError):
            ConsistencyProof(
                log.hash_name,
                3,
                log.merkle_root(3),
                2,
                log.merkle_root(2),
                (),
            )

    def test_encode_revalidates_field_types(self):
        log = filled_log("sha256", 4)
        inclusion = make_inclusion(log, 1)
        with self.assertRaises(TypeError):
            encode_inclusion_proof((inclusion,))
        # A wrong-typed field must fail even when smuggled past the constructor.
        forged = copy.copy(inclusion)
        object.__setattr__(forged, "entry_hash", bytearray(inclusion.entry_hash))
        with self.assertRaises(TypeError):
            encode_inclusion_proof(forged)
        forged = copy.copy(inclusion)
        object.__setattr__(forged, "size", 0)
        with self.assertRaises(ValueError):
            encode_inclusion_proof(forged)


class DecodeBoundaryTest(unittest.TestCase):
    """Input-boundary handling is identical across the four decoders."""

    def samples(self):
        log = filled_log("sha256", 5)
        return (
            (encode_inclusion_proof, decode_inclusion_proof, make_inclusion(log, 2)),
            (encode_batch_inclusion_proof, decode_batch_inclusion_proof, make_batch(log, (1, 3))),
            (encode_consistency_proof, decode_consistency_proof, make_consistency(log, 2, 5)),
            (encode_merkle_frontier, decode_merkle_frontier, log.merkle_frontier(5)),
        )

    def test_non_bytes_input_rejected(self):
        for encode, decode, credential in self.samples():
            data = encode(credential)
            for bad in (bytearray(data), memoryview(data), "text", None, 1):
                with self.assertRaises(TypeError):
                    decode(bad)

    def test_bad_magic_version_truncation_trailing(self):
        for encode, decode, credential in self.samples():
            data = encode(credential)
            with self.assertRaises(ValueError):
                decode(b"x" + data[1:])
            with self.assertRaises(ValueError):
                decode(b"")
            for cut in range(1, len(data)):
                with self.assertRaises(ValueError):
                    decode(data[:cut])
            with self.assertRaises(ValueError):
                decode(data + b"\x00")
            # A bumped version field is rejected before any field is read.
            version_offset = data.index(b"\x00") + 1
            bumped = (
                data[:version_offset]
                + (2).to_bytes(8, "big")
                + data[version_offset + 8:]
            )
            with self.assertRaises(ValueError):
                decode(bumped)

    def test_oversized_declared_length_rejected(self):
        for encode, decode, credential in self.samples():
            data = encode(credential)
            version_offset = data.index(b"\x00") + 1
            # The hash_name blob length follows the version field.
            oversized = (
                data[: version_offset + 8]
                + (1 << 63).to_bytes(8, "big")
                + data[version_offset + 16:]
            )
            with self.assertRaises(ValueError):
                decode(oversized)

    def test_invalid_utf8_and_unknown_algorithm_rejected(self):
        for encode, decode, credential in self.samples():
            data = encode(credential)
            version_offset = data.index(b"\x00") + 1
            name_offset = version_offset + 8 + 8
            for bad_name in (b"\xff\xfe", b"not-a-hash"):
                mutated = (
                    data[:version_offset + 8]
                    + len(bad_name).to_bytes(8, "big")
                    + bad_name
                    + data[name_offset + len(credential.hash_name):]
                )
                with self.assertRaises(ValueError):
                    decode(mutated)

    def test_digest_width_rejected(self):
        log = filled_log("sha256", 4)
        inclusion = make_inclusion(log, 1)
        data = bytearray(encode_inclusion_proof(inclusion))
        # Narrow the entry_hash blob from 32 to 31 bytes.
        version_offset = bytes(data).index(b"\x00") + 1
        name_end = version_offset + 8 + 8 + len(inclusion.hash_name)
        entry_hash_length_offset = name_end + 8 + 8
        data[entry_hash_length_offset:entry_hash_length_offset + 8] = (31).to_bytes(8, "big")
        del data[entry_hash_length_offset + 8 + 31]
        with self.assertRaises(ValueError):
            decode_inclusion_proof(bytes(data))


class VerificationBoundaryTest(unittest.TestCase):
    """Decoding stays structural; cryptographic judgment stays with verify."""

    def test_tampered_digest_roundtrips_and_verifies_false(self):
        log = filled_log("sha512", 6)
        inclusion = make_inclusion(log, 2)
        tampered = InclusionProof(
            inclusion.hash_name,
            inclusion.index,
            inclusion.size,
            inclusion.entry_hash,
            b"\x11" * 64,
            inclusion.proof,
        )
        decoded = decode_inclusion_proof(encode_inclusion_proof(tampered))
        self.assertEqual(decoded, tampered)
        self.assertFalse(check_inclusion(decoded))

    def test_tampered_proof_node_roundtrips_and_verifies_false(self):
        log = filled_log("sha256", 6)
        batch = make_batch(log, (1, 4))
        tampered = BatchInclusionProof(
            batch.hash_name,
            batch.indices,
            batch.entry_hashes,
            batch.size,
            batch.root,
            (b"\x22" * 32,) + batch.proof[1:],
        )
        decoded = decode_batch_inclusion_proof(encode_batch_inclusion_proof(tampered))
        self.assertFalse(check_batch(decoded))

    def test_wrong_node_count_decodes_but_verify_raises(self):
        log = filled_log("sha256", 6)
        inclusion = make_inclusion(log, 2)
        bloated = InclusionProof(
            inclusion.hash_name,
            inclusion.index,
            inclusion.size,
            inclusion.entry_hash,
            inclusion.root,
            inclusion.proof + (b"\x00" * 32,),
        )
        decoded = decode_inclusion_proof(encode_inclusion_proof(bloated))
        with self.assertRaises(ValueError):
            check_inclusion(decoded)

        consistency = make_consistency(log, 2, 6)
        bloated = ConsistencyProof(
            consistency.hash_name,
            consistency.old_size,
            consistency.old_root,
            consistency.new_size,
            consistency.new_root,
            consistency.proof + (b"\x00" * 32,),
        )
        decoded = decode_consistency_proof(encode_consistency_proof(bloated))
        with self.assertRaises(ValueError):
            check_consistency(decoded)


class ImmutabilityTest(unittest.TestCase):
    def test_decoded_credentials_are_frozen(self):
        log = filled_log("sha256", 5)
        decoded = (
            decode_inclusion_proof(encode_inclusion_proof(make_inclusion(log, 1))),
            decode_batch_inclusion_proof(
                encode_batch_inclusion_proof(make_batch(log, (1, 2)))
            ),
            decode_consistency_proof(
                encode_consistency_proof(make_consistency(log, 2, 5))
            ),
            decode_merkle_frontier(encode_merkle_frontier(log.merkle_frontier(5))),
        )
        for credential in decoded:
            field = next(iter(credential.__dataclass_fields__))
            with self.assertRaises(Exception):
                setattr(credential, field, None)

    def test_encode_and_rebuild_are_read_only(self):
        log = filled_log("sha256", 5)
        credentials = (
            (make_inclusion(log, 1), encode_inclusion_proof),
            (make_batch(log, (1, 2)), encode_batch_inclusion_proof),
            (make_consistency(log, 2, 5), encode_consistency_proof),
            (log.merkle_frontier(5), encode_merkle_frontier),
        )
        for credential, encode in credentials:
            names = tuple(credential.__dataclass_fields__)
            snapshot = tuple(getattr(credential, name) for name in names)
            encode(credential)
            self.assertEqual(
                tuple(getattr(credential, name) for name in names), snapshot
            )
        frontier = log.merkle_frontier(2)
        before = frontier.subtrees
        rebuild_merkle_root(
            frontier,
            tuple(log.entry(index).entry_hash for index in range(2, 5)),
        )
        self.assertEqual(frontier.subtrees, before)


if __name__ == "__main__":
    unittest.main()
