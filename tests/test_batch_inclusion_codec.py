import itertools
import unittest

from auditchain import (
    AuditLog,
    BatchInclusionProof,
    decode_batch_inclusion_proof,
    encode_batch_inclusion_proof,
    verify_batch_inclusion,
)

MAGIC = b"auditchain/batch-inclusion/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def build(hash_name, indices, digests, size, root, nodes, version=1):
    """Hand-build a batch-inclusion encoding with arbitrary content."""
    out = MAGIC + u64(version) + blob(hash_name.encode("utf-8"))
    out += u64(len(indices))
    for index in indices:
        out += u64(index)
    out += u64(len(digests))
    for digest in digests:
        out += blob(digest)
    out += u64(size) + blob(root)
    out += u64(len(nodes))
    for node in nodes:
        out += blob(node)
    return out


def make_credential(log, selected, size=None, hash_name="sha256"):
    if size is None:
        size = len(log)
    indices, nodes = log.batch_inclusion_proof(selected, size)
    digests = tuple(log.entry(i).entry_hash for i in indices)
    return BatchInclusionProof(
        hash_name, indices, digests, size, log.merkle_root(size), nodes
    )


class BatchInclusionProofConstructorTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in range(7):
            self.log.append(str(record))

    def test_positional_construction_and_equality(self):
        credential = make_credential(self.log, [1, 3, 5])
        again = BatchInclusionProof(
            credential.hash_name,
            credential.indices,
            credential.entry_digests,
            credential.size,
            credential.snapshot_root,
            credential.proof_nodes,
        )
        self.assertEqual(again, credential)
        self.assertEqual(
            credential,
            BatchInclusionProof(
                "sha256",
                credential.indices,
                credential.entry_digests,
                7,
                credential.snapshot_root,
                credential.proof_nodes,
            ),
        )
        self.assertNotEqual(
            credential,
            BatchInclusionProof(
                "sha256",
                credential.indices,
                credential.entry_digests,
                6,
                credential.snapshot_root,
                credential.proof_nodes,
            ),
        )

    def test_frozen(self):
        credential = make_credential(self.log, [1])
        with self.assertRaises((AttributeError, TypeError)):
            credential.size = 3

    def test_single_leaf_snapshot(self):
        credential = make_credential(self.log, [0], 1)
        self.assertEqual(credential.proof_nodes, ())
        self.assertTrue(
            verify_batch_inclusion(
                credential.indices,
                credential.entry_digests,
                credential.size,
                credential.snapshot_root,
                credential.proof_nodes,
                hash_name=credential.hash_name,
            )
        )

    def test_hash_name_type(self):
        credential = make_credential(self.log, [1])
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                None,
                credential.indices,
                credential.entry_digests,
                credential.size,
                credential.snapshot_root,
                credential.proof_nodes,
            )

    def test_unknown_algorithm(self):
        credential = make_credential(self.log, [1])
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "not-a-hash",
                credential.indices,
                credential.entry_digests,
                credential.size,
                b"\x00" * 16,
                credential.proof_nodes,
            )

    def test_indices_type(self):
        credential = make_credential(self.log, [1])
        for bad in ([1], (1.0,), ("1",)):
            with self.assertRaises(TypeError):
                BatchInclusionProof(
                    "sha256",
                    bad,
                    credential.entry_digests,
                    credential.size,
                    credential.snapshot_root,
                    credential.proof_nodes,
                )
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                "sha256",
                (True,),
                (credential.entry_digests[0],),
                credential.size,
                credential.snapshot_root,
                (),
            )

    def test_indices_empty_or_out_of_order(self):
        credential = make_credential(self.log, [1, 3])
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256",
                (),
                (),
                credential.size,
                credential.snapshot_root,
                (),
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256",
                (3, 1),
                credential.entry_digests[::-1],
                credential.size,
                credential.snapshot_root,
                credential.proof_nodes,
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256",
                (1, 1),
                (credential.entry_digests[0], credential.entry_digests[0]),
                credential.size,
                credential.snapshot_root,
                credential.proof_nodes,
            )

    def test_negative_and_out_of_range_indices(self):
        credential = make_credential(self.log, [1])
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256",
                (-1,),
                credential.entry_digests,
                credential.size,
                credential.snapshot_root,
                (),
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256",
                (7,),
                credential.entry_digests,
                7,
                credential.snapshot_root,
                (),
            )

    def test_digest_tuple_must_match_indices(self):
        credential = make_credential(self.log, [1, 3])
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                "sha256",
                credential.indices,
                list(credential.entry_digests),
                credential.size,
                credential.snapshot_root,
                credential.proof_nodes,
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256",
                credential.indices,
                credential.entry_digests[:1],
                credential.size,
                credential.snapshot_root,
                credential.proof_nodes,
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256",
                credential.indices,
                credential.entry_digests + (credential.entry_digests[0],),
                credential.size,
                credential.snapshot_root,
                credential.proof_nodes,
            )

    def test_digests_exact_bytes_and_width(self):
        credential = make_credential(self.log, [1])
        digest = credential.entry_digests[0]
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                "sha256", (1,), (bytearray(digest),), 7,
                credential.snapshot_root, (),
            )
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                "sha256", (1,), (memoryview(digest),), 7,
                credential.snapshot_root, (),
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256", (1,), (b"\x00" * 31,), 7,
                credential.snapshot_root, (),
            )

    def test_size_validation(self):
        credential = make_credential(self.log, [1])
        kwargs = dict(
            hash_name="sha256",
            indices=credential.indices,
            entry_digests=credential.entry_digests,
            snapshot_root=credential.snapshot_root,
            proof_nodes=(),
        )
        for bad_size in (0, -1):
            with self.assertRaises(ValueError):
                BatchInclusionProof(size=bad_size, **kwargs)
        with self.assertRaises(TypeError):
            BatchInclusionProof(size="7", **kwargs)
        with self.assertRaises(TypeError):
            BatchInclusionProof(size=True, **kwargs)

    def test_root_exact_bytes_and_width(self):
        credential = make_credential(self.log, [1])
        args = (
            "sha256",
            credential.indices,
            credential.entry_digests,
            credential.size,
        )
        with self.assertRaises(TypeError):
            BatchInclusionProof(*args, bytearray(credential.snapshot_root), ())
        with self.assertRaises(TypeError):
            BatchInclusionProof(*args, memoryview(credential.snapshot_root), ())
        with self.assertRaises(ValueError):
            BatchInclusionProof(*args, b"\x00" * 31, ())

    def test_proof_nodes_types_and_width(self):
        credential = make_credential(self.log, [0, 2])
        args = (
            "sha256",
            credential.indices,
            credential.entry_digests,
            credential.size,
            credential.snapshot_root,
        )
        with self.assertRaises(TypeError):
            BatchInclusionProof(*args, list(credential.proof_nodes))
        node = credential.proof_nodes[0]
        with self.assertRaises(TypeError):
            BatchInclusionProof(*args, (bytearray(node),) * len(credential.proof_nodes))
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                *args, credential.proof_nodes[:-1] + (b"\x00" * 31,)
            )

    def test_wrong_node_count_left_for_verifier(self):
        # The credential itself does not judge the node count: a structurally
        # sound credential with one node too many constructs and encodes
        # fine; verify_batch_inclusion raises ValueError.
        credential = make_credential(self.log, [1, 3])
        bloated = BatchInclusionProof(
            credential.hash_name,
            credential.indices,
            credential.entry_digests,
            credential.size,
            credential.snapshot_root,
            credential.proof_nodes + (b"\x22" * 32,),
        )
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                bloated.indices,
                bloated.entry_digests,
                bloated.size,
                bloated.snapshot_root,
                bloated.proof_nodes,
                hash_name=bloated.hash_name,
            )


class EncodeBatchInclusionProofTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_magic_and_field_layout(self):
        credential = make_credential(self.log, [1, 3])
        data = encode_batch_inclusion_proof(credential)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(len(credential.indices)))
        offset += 8
        for index in credential.indices:
            self.assertEqual(data[offset:offset + 8], u64(index))
            offset += 8
        self.assertEqual(
            data[offset:offset + 8], u64(len(credential.entry_digests))
        )
        offset += 8
        for digest in credential.entry_digests:
            self.assertEqual(data[offset:offset + 8], u64(32))
            offset += 8
            self.assertEqual(data[offset:offset + 32], digest)
            offset += 32
        self.assertEqual(data[offset:offset + 8], u64(credential.size))
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(32))
        offset += 8
        self.assertEqual(data[offset:offset + 32], credential.snapshot_root)
        offset += 32
        self.assertEqual(
            data[offset:offset + 8], u64(len(credential.proof_nodes))
        )
        offset += 8
        for node in credential.proof_nodes:
            offset += 8 + len(node)
        self.assertEqual(offset, len(data))

    def test_deterministic_and_read_only(self):
        credential = make_credential(self.log, [0, 2, 4])
        self.assertEqual(
            encode_batch_inclusion_proof(credential),
            encode_batch_inclusion_proof(credential),
        )
        before = (len(self.log), self.log.merkle_root())
        encode_batch_inclusion_proof(credential)
        self.assertEqual((len(self.log), self.log.merkle_root()), before)

    def test_only_credential_accepted(self):
        for bad in (None, "proof", b"bytes", 1, (1, 2), object(), []):
            with self.assertRaises(TypeError):
                encode_batch_inclusion_proof(bad)

    def test_bypassed_field_type_errors(self):
        credential = make_credential(self.log, [1])
        corrupted = object.__new__(BatchInclusionProof)
        object.__setattr__(corrupted, "hash_name", 7)
        object.__setattr__(corrupted, "indices", credential.indices)
        object.__setattr__(corrupted, "entry_digests", credential.entry_digests)
        object.__setattr__(corrupted, "size", credential.size)
        object.__setattr__(corrupted, "snapshot_root", credential.snapshot_root)
        object.__setattr__(corrupted, "proof_nodes", credential.proof_nodes)
        with self.assertRaises(TypeError):
            encode_batch_inclusion_proof(corrupted)

    def test_u64_overflow_rejected(self):
        credential = make_credential(self.log, [1])
        corrupted = object.__new__(BatchInclusionProof)
        object.__setattr__(corrupted, "hash_name", "sha256")
        object.__setattr__(corrupted, "indices", (1 << 64,))
        object.__setattr__(corrupted, "entry_digests", credential.entry_digests)
        object.__setattr__(corrupted, "size", credential.size)
        object.__setattr__(corrupted, "snapshot_root", credential.snapshot_root)
        object.__setattr__(corrupted, "proof_nodes", ())
        with self.assertRaises(ValueError):
            encode_batch_inclusion_proof(corrupted)


class DecodeBatchInclusionProofTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in range(7):
            self.log.append(str(record))

    def roundtrip(self, credential, expected_result=True):
        data = encode_batch_inclusion_proof(credential)
        restored = decode_batch_inclusion_proof(data)
        self.assertIsInstance(restored, BatchInclusionProof)
        self.assertEqual(restored, credential)
        self.assertEqual(restored.hash_name, credential.hash_name)
        self.assertEqual(restored.indices, credential.indices)
        self.assertEqual(restored.entry_digests, credential.entry_digests)
        self.assertEqual(restored.size, credential.size)
        self.assertEqual(restored.snapshot_root, credential.snapshot_root)
        self.assertEqual(restored.proof_nodes, credential.proof_nodes)
        # Deterministic: re-encoding a decoded credential is byte-identical.
        self.assertEqual(encode_batch_inclusion_proof(restored), data)
        result = verify_batch_inclusion(
            restored.indices,
            restored.entry_digests,
            restored.size,
            restored.snapshot_root,
            restored.proof_nodes,
            hash_name=restored.hash_name,
        )
        self.assertIs(result, expected_result)
        return restored

    def test_roundtrip_variants(self):
        for n in range(1, 9):
            log = AuditLog()
            for record in range(n):
                log.append(str(record))
            for size in range(1, n + 1):
                for width in range(1, size + 1):
                    for chosen in itertools.combinations(range(size), width):
                        self.roundtrip(make_credential(log, chosen, size))

    def test_roundtrip_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(make_credential(self.log, [2, 4, 6]))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in range(5):
            log.append(str(record))
        self.roundtrip(make_credential(log, [0, 3, 4], hash_name="sha3-256"))

    def test_only_bytes_accepted(self):
        data = encode_batch_inclusion_proof(make_credential(self.log, [1]))
        for bad in (
            bytearray(data),
            memoryview(data),
            "text",
            None,
            1,
            [data],
        ):
            with self.assertRaises(TypeError):
                decode_batch_inclusion_proof(bad)

    def test_bad_magic(self):
        data = encode_batch_inclusion_proof(make_credential(self.log, [1]))
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(b"")
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(MAGIC[:-1])

    def test_bad_version(self):
        credential = make_credential(self.log, [1])
        data = MAGIC + u64(2) + encode_batch_inclusion_proof(credential)[
            len(MAGIC) + 8:
        ]
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data)

    def test_unknown_hash_algorithm(self):
        data = build(
            "not-a-hash", (1,), (b"\x00" * 16,), 3, b"\x00" * 16, ()
        )
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data)

    def test_invalid_utf8_hash_name(self):
        out = MAGIC + u64(1) + blob(b"\xff\xfe")
        out += u64(0) + u64(0) + u64(1) + blob(b"") + u64(0)
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(out)

    def test_truncation(self):
        data = encode_batch_inclusion_proof(make_credential(self.log, [1, 3]))
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_batch_inclusion_proof(data[:cut])

    def test_trailing_bytes(self):
        data = encode_batch_inclusion_proof(make_credential(self.log, [1]))
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data)

    def test_empty_indices_rejected(self):
        data = build("sha256", (), (), 5, self.log.merkle_root(5), ())
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data)

    def test_zero_size_rejected(self):
        digest = self.log.entry(0).entry_hash
        data = build("sha256", (0,), (digest,), 0, self.log.merkle_root(0), ())
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data)

    def test_non_ascending_and_duplicate_indices(self):
        digests = tuple(self.log.entry(i).entry_hash for i in (1, 3))
        root = self.log.merkle_root(7)
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build("sha256", (3, 1), digests[::-1], 7, root, ())
            )
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build("sha256", (1, 1), digests, 7, root, ())
            )

    def test_index_out_of_range(self):
        digest = self.log.entry(0).entry_hash
        data = build(
            "sha256", (7,), (digest,), 7, self.log.merkle_root(7), ()
        )
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data)

    def test_digest_tuple_length_mismatch(self):
        digests = tuple(self.log.entry(i).entry_hash for i in (1, 3))
        root = self.log.merkle_root(7)
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build("sha256", (1, 3), digests[:1], 7, root, ())
            )

    def test_digest_widths_checked(self):
        credential = make_credential(self.log, [1, 3])
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build(
                    "sha256",
                    credential.indices,
                    (b"\x00" * 31,) * 2,
                    7,
                    credential.snapshot_root,
                    credential.proof_nodes,
                )
            )
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build(
                    "sha256",
                    credential.indices,
                    credential.entry_digests,
                    7,
                    b"\x00" * 33,
                    credential.proof_nodes,
                )
            )
        if credential.proof_nodes:
            with self.assertRaises(ValueError):
                decode_batch_inclusion_proof(
                    build(
                        "sha256",
                        credential.indices,
                        credential.entry_digests,
                        7,
                        credential.snapshot_root,
                        credential.proof_nodes[:-1] + (b"\x00" * 16,),
                    )
                )

    def test_wrong_root_content_still_decodes_but_fails(self):
        # A structurally sound credential whose content does not match
        # round-trips; verification of the restored object returns False.
        credential = make_credential(self.log, [1, 3])
        wrong = BatchInclusionProof(
            credential.hash_name,
            credential.indices,
            credential.entry_digests,
            credential.size,
            b"\x11" * 32,
            credential.proof_nodes,
        )
        self.roundtrip(wrong, expected_result=False)

    def test_wrong_node_count_raises_at_verifier(self):
        # Node count is not a codec concern: the credential decodes, and only
        # verify_batch_inclusion raises ValueError.
        credential = make_credential(self.log, [1, 3])
        bloated = BatchInclusionProof(
            credential.hash_name,
            credential.indices,
            credential.entry_digests,
            credential.size,
            credential.snapshot_root,
            credential.proof_nodes + (b"\x22" * 32,),
        )
        data = encode_batch_inclusion_proof(bloated)
        restored = decode_batch_inclusion_proof(data)
        self.assertEqual(restored, bloated)
        with self.assertRaises(ValueError):
            verify_batch_inclusion(
                restored.indices,
                restored.entry_digests,
                restored.size,
                restored.snapshot_root,
                restored.proof_nodes,
                hash_name=restored.hash_name,
            )

    def test_decoded_proof_is_exact_bytes(self):
        credential = make_credential(self.log, [1])
        restored = decode_batch_inclusion_proof(
            encode_batch_inclusion_proof(credential)
        )
        self.assertIs(type(restored.snapshot_root), bytes)
        for digest in restored.entry_digests:
            self.assertIs(type(digest), bytes)
        for node in restored.proof_nodes:
            self.assertIs(type(node), bytes)


if __name__ == "__main__":
    unittest.main()
