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


def build(hash_name, indices, entry_hashes, size, root, proof, version=1):
    """Hand-build a batch-inclusion encoding with arbitrary content."""
    out = MAGIC + u64(version) + blob(hash_name)
    out += u64(len(indices))
    for index in indices:
        out += u64(index)
    out += u64(len(entry_hashes))
    for entry_hash in entry_hashes:
        out += blob(entry_hash)
    out += u64(size) + blob(root)
    out += u64(len(proof))
    for node in proof:
        out += blob(node)
    return out


def verify(credential):
    return verify_batch_inclusion(
        credential.indices,
        credential.entry_hashes,
        credential.size,
        credential.root,
        credential.proof,
        hash_name=credential.hash_name,
    )


class BatchInclusionProofTestBase(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)

    def make_credential(self, selected=(1, 3, 5), size=None):
        size = len(self.log) if size is None else size
        indices, proof = self.log.batch_inclusion_proof(selected, size)
        entry_hashes = tuple(self.log.entry(i).entry_hash for i in indices)
        return BatchInclusionProof(
            "sha256", indices, entry_hashes, size, self.log.merkle_root(size), proof
        )


class BatchInclusionProofConstructorTest(BatchInclusionProofTestBase):
    def test_fields_in_order_and_positional_construction(self):
        credential = self.make_credential()
        self.assertEqual(
            tuple(credential.__dataclass_fields__),
            ("hash_name", "indices", "entry_hashes", "size", "root", "proof"),
        )
        self.assertEqual(credential.hash_name, "sha256")
        self.assertEqual(credential.indices, (1, 3, 5))
        self.assertEqual(credential.size, 7)
        self.assertEqual(credential.root, self.log.merkle_root())
        indices, proof = self.log.batch_inclusion_proof([1, 3, 5])
        self.assertEqual(credential.proof, proof)

    def test_equality_by_all_fields(self):
        self.assertEqual(self.make_credential(), self.make_credential())
        other = self.make_credential(selected=(0, 2))
        self.assertNotEqual(self.make_credential(), other)

    def test_frozen(self):
        credential = self.make_credential()
        with self.assertRaises(Exception):
            credential.size = 3

    def test_hash_name_checked(self):
        base = self.make_credential()
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                1, base.indices, base.entry_hashes, base.size, base.root, base.proof
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "not-a-hash",
                base.indices,
                base.entry_hashes,
                base.size,
                base.root,
                base.proof,
            )

    def test_indices_checked(self):
        base = self.make_credential()
        hashes = base.entry_hashes
        for bad, exc in (
            ([1, 3, 5], TypeError),
            ((), ValueError),
            ((1, 1), ValueError),
            ((3, 1), ValueError),
            ((True,), TypeError),
            (("1",), TypeError),
        ):
            with self.assertRaises(exc):
                BatchInclusionProof(
                    "sha256", bad, hashes[: len(bad) or 1], 7, base.root, ()
                )

    def test_entry_hashes_checked(self):
        base = self.make_credential()
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                "sha256", base.indices, list(base.entry_hashes), 7, base.root, ()
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256", base.indices, base.entry_hashes[:2], 7, base.root, ()
            )
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                "sha256",
                base.indices,
                tuple(bytearray(h) for h in base.entry_hashes),
                7,
                base.root,
                (),
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256",
                base.indices,
                (b"\x00" * 31,) * 3,
                7,
                base.root,
                (),
            )

    def test_size_checked(self):
        base = self.make_credential()
        for bad, exc in (
            ("7", TypeError),
            (True, TypeError),
            (0, ValueError),
            (-1, ValueError),
            (3, ValueError),  # index 5 out of range
            (1 << 64, ValueError),
        ):
            with self.assertRaises(exc):
                BatchInclusionProof(
                    "sha256", base.indices, base.entry_hashes, bad, base.root, ()
                )

    def test_root_and_proof_checked(self):
        base = self.make_credential()
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                "sha256",
                base.indices,
                base.entry_hashes,
                7,
                bytearray(base.root),
                (),
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256", base.indices, base.entry_hashes, 7, b"\x00" * 31, ()
            )
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                "sha256", base.indices, base.entry_hashes, 7, base.root, [b"\x00" * 32]
            )
        with self.assertRaises(TypeError):
            BatchInclusionProof(
                "sha256",
                base.indices,
                base.entry_hashes,
                7,
                base.root,
                (bytearray(b"\x00" * 32),),
            )
        with self.assertRaises(ValueError):
            BatchInclusionProof(
                "sha256",
                base.indices,
                base.entry_hashes,
                7,
                base.root,
                (b"\x00" * 31,),
            )

    def test_proof_node_count_not_checked_by_constructor(self):
        # Node-count fit and root rebuild belong to verify_batch_inclusion.
        base = self.make_credential()
        credential = BatchInclusionProof(
            "sha256",
            base.indices,
            base.entry_hashes,
            base.size,
            base.root,
            base.proof + (b"\x00" * 32,),
        )
        with self.assertRaises(ValueError):
            verify(credential)

    def test_content_mismatch_verifies_false(self):
        base = self.make_credential()
        credential = BatchInclusionProof(
            "sha256",
            base.indices,
            base.entry_hashes,
            base.size,
            b"\x11" * 32,
            base.proof,
        )
        self.assertFalse(verify(credential))


class EncodeBatchInclusionProofTest(BatchInclusionProofTestBase):
    def test_magic_and_field_layout(self):
        credential = self.make_credential()
        data = encode_batch_inclusion_proof(credential)
        expected = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(3)
            + u64(1)
            + u64(3)
            + u64(5)
            + u64(3)
            + b"".join(blob(h) for h in credential.entry_hashes)
            + u64(7)
            + blob(credential.root)
            + u64(len(credential.proof))
            + b"".join(blob(node) for node in credential.proof)
        )
        self.assertEqual(data, expected)

    def test_encode_is_deterministic(self):
        credential = self.make_credential()
        self.assertEqual(
            encode_batch_inclusion_proof(credential),
            encode_batch_inclusion_proof(credential),
        )

    def test_encoding_is_read_only(self):
        credential = self.make_credential()
        before = tuple(credential.__dataclass_fields__)
        snapshot = tuple(getattr(credential, name) for name in before)
        encode_batch_inclusion_proof(credential)
        self.assertEqual(
            tuple(getattr(credential, name) for name in before), snapshot
        )

    def test_only_credential_accepted(self):
        for bad in (None, "x", b"bytes", 1, (), object()):
            with self.assertRaises(TypeError):
                encode_batch_inclusion_proof(bad)

    def test_bypassed_fields_revalidated(self):
        credential = self.make_credential()
        import copy

        for name, value, exc in (
            ("hash_name", 1, TypeError),
            ("indices", (5, 3, 1), ValueError),
            ("entry_hashes", credential.entry_hashes[:2], ValueError),
            ("size", 0, ValueError),
            ("root", bytearray(credential.root), TypeError),
            ("proof", (b"\x00" * 31,), ValueError),
        ):
            forged = copy.copy(credential)
            object.__setattr__(forged, name, value)
            with self.assertRaises(exc):
                encode_batch_inclusion_proof(forged)


class DecodeBatchInclusionProofTest(BatchInclusionProofTestBase):
    def roundtrip(self, credential):
        data = encode_batch_inclusion_proof(credential)
        decoded = decode_batch_inclusion_proof(data)
        self.assertIsInstance(decoded, BatchInclusionProof)
        self.assertEqual(decoded, credential)
        self.assertEqual(encode_batch_inclusion_proof(decoded), data)
        self.assertTrue(verify(decoded))
        return decoded

    def test_roundtrip_variants(self):
        for selected, size in (
            ([0], None),
            ([1, 3], None),
            ([3], 4),
            ([0, 2, 4, 6], None),
            ([0], 1),
            (range(7), None),
        ):
            self.roundtrip(self.make_credential(tuple(selected), size))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        indices, proof = log.batch_inclusion_proof([0, 2])
        credential = BatchInclusionProof(
            "sha3-256",
            indices,
            tuple(log.entry(i).entry_hash for i in indices),
            len(log),
            log.merkle_root(),
            proof,
        )
        self.roundtrip(credential)

    def test_roundtrip_empty_proof(self):
        self.roundtrip(self.make_credential(range(7)))

    def test_only_exact_bytes_accepted(self):
        data = encode_batch_inclusion_proof(self.make_credential())
        for bad in (bytearray(data), memoryview(data), "text", None, 1, [data]):
            with self.assertRaises(TypeError):
                decode_batch_inclusion_proof(bad)

    def test_bad_magic(self):
        data = encode_batch_inclusion_proof(self.make_credential())
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(b"")
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(MAGIC[:-1])

    def test_bad_version(self):
        data = encode_batch_inclusion_proof(self.make_credential())
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(MAGIC + u64(2) + data[len(MAGIC) + 8:])

    def test_unknown_hash_algorithm(self):
        base = self.make_credential()
        data = build(
            b"not-a-hash", base.indices, base.entry_hashes, 7, base.root, base.proof
        )
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data)

    def test_invalid_utf8_hash_name(self):
        base = self.make_credential()
        data = build(
            b"\xff\xfe", base.indices, base.entry_hashes, 7, base.root, base.proof
        )
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data)

    def test_truncation(self):
        data = encode_batch_inclusion_proof(self.make_credential())
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_batch_inclusion_proof(data[:cut])

    def test_trailing_bytes(self):
        data = encode_batch_inclusion_proof(self.make_credential())
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(data)

    def test_digest_widths_checked(self):
        base = self.make_credential()
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build(b"sha256", base.indices, base.entry_hashes, 7, b"\x00" * 31, base.proof)
            )
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build(
                    b"sha256",
                    base.indices,
                    (b"\x00" * 31,) * 3,
                    7,
                    base.root,
                    base.proof,
                )
            )
        if base.proof:
            with self.assertRaises(ValueError):
                decode_batch_inclusion_proof(
                    build(
                        b"sha256",
                        base.indices,
                        base.entry_hashes,
                        7,
                        base.root,
                        base.proof[:-1] + (b"\x00" * 31,),
                    )
                )

    def test_index_order_duplicates_and_range(self):
        base = self.make_credential()
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build(
                    b"sha256",
                    (5, 1, 3),
                    base.entry_hashes,
                    7,
                    base.root,
                    base.proof,
                )
            )
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build(
                    b"sha256",
                    (1, 1, 3),
                    base.entry_hashes,
                    7,
                    base.root,
                    base.proof,
                )
            )
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build(
                    b"sha256",
                    (1, 3, 7),
                    base.entry_hashes,
                    7,
                    base.root,
                    base.proof,
                )
            )

    def test_empty_indices_rejected(self):
        base = self.make_credential()
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build(b"sha256", (), (), 7, base.root, ())
            )

    def test_length_mismatch_rejected(self):
        base = self.make_credential()
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build(
                    b"sha256",
                    base.indices,
                    base.entry_hashes[:2],
                    7,
                    base.root,
                    base.proof,
                )
            )

    def test_non_positive_size_rejected(self):
        base = self.make_credential()
        with self.assertRaises(ValueError):
            decode_batch_inclusion_proof(
                build(b"sha256", base.indices, base.entry_hashes, 0, base.root, base.proof)
            )

    def test_extra_proof_node_decodes_but_verify_raises(self):
        base = self.make_credential()
        data = build(
            b"sha256",
            base.indices,
            base.entry_hashes,
            7,
            base.root,
            base.proof + (b"\x00" * 32,),
        )
        decoded = decode_batch_inclusion_proof(data)
        with self.assertRaises(ValueError):
            verify(decoded)

    def test_wrong_root_decodes_but_verifies_false(self):
        base = self.make_credential()
        data = build(
            b"sha256", base.indices, base.entry_hashes, 7, b"\x11" * 32, base.proof
        )
        decoded = decode_batch_inclusion_proof(data)
        self.assertEqual(decoded.root, b"\x11" * 32)
        self.assertFalse(verify(decoded))

    def test_wrong_proof_node_decodes_but_verifies_false(self):
        base = self.make_credential()
        if not base.proof:
            self.skipTest("credential has an empty proof")
        data = build(
            b"sha256",
            base.indices,
            base.entry_hashes,
            7,
            base.root,
            (b"\x22" * 32,) + base.proof[1:],
        )
        decoded = decode_batch_inclusion_proof(data)
        self.assertFalse(verify(decoded))


if __name__ == "__main__":
    unittest.main()
