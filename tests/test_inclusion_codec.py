import unittest

from auditchain import (
    AuditLog,
    InclusionProof,
    decode_inclusion_proof,
    encode_inclusion_proof,
    verify_inclusion,
)

MAGIC = b"auditchain/inclusion/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def build(hash_name, index, size, entry_hash, root, proof, version=1):
    """Hand-build an inclusion-proof encoding with arbitrary content."""
    out = MAGIC + u64(version) + blob(hash_name)
    out += u64(index) + u64(size) + blob(entry_hash) + blob(root)
    out += u64(len(proof))
    for node in proof:
        out += blob(node)
    return out


def verify(credential):
    return verify_inclusion(
        credential.entry_hash,
        credential.index,
        credential.size,
        credential.root,
        credential.proof,
        hash_name=credential.hash_name,
    )


class InclusionProofTestBase(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)

    def make_credential(self, index=3, size=None):
        size = len(self.log) if size is None else size
        proof = self.log.inclusion_proof(index, size)
        return InclusionProof(
            "sha256",
            index,
            size,
            self.log.entry(index).entry_hash,
            self.log.merkle_root(size),
            proof,
        )


class InclusionProofConstructorTest(InclusionProofTestBase):
    def test_fields_in_order_and_positional_construction(self):
        credential = self.make_credential()
        self.assertEqual(
            tuple(credential.__dataclass_fields__),
            ("hash_name", "index", "size", "entry_hash", "root", "proof"),
        )
        self.assertEqual(credential.hash_name, "sha256")
        self.assertEqual(credential.index, 3)
        self.assertEqual(credential.size, 7)
        self.assertEqual(credential.entry_hash, self.log.entry(3).entry_hash)
        self.assertEqual(credential.root, self.log.merkle_root())
        self.assertEqual(credential.proof, self.log.inclusion_proof(3))

    def test_equality_by_all_fields(self):
        self.assertEqual(self.make_credential(), self.make_credential())
        self.assertNotEqual(self.make_credential(3), self.make_credential(4))

    def test_frozen(self):
        credential = self.make_credential()
        with self.assertRaises(Exception):
            credential.size = 3

    def test_hash_name_checked(self):
        base = self.make_credential()
        with self.assertRaises(TypeError):
            InclusionProof(
                1, base.index, base.size, base.entry_hash, base.root, base.proof
            )
        with self.assertRaises(ValueError):
            InclusionProof(
                "not-a-hash",
                base.index,
                base.size,
                base.entry_hash,
                base.root,
                base.proof,
            )

    def test_index_checked(self):
        base = self.make_credential()
        for bad, exc in (
            ("3", TypeError),
            (True, TypeError),
            (-1, ValueError),
            (7, ValueError),
        ):
            with self.assertRaises(exc):
                InclusionProof(
                    "sha256", bad, base.size, base.entry_hash, base.root, base.proof
                )

    def test_size_checked(self):
        base = self.make_credential()
        for bad, exc in (
            ("7", TypeError),
            (True, TypeError),
            (-1, ValueError),
            (3, ValueError),  # index 3 out of range
            (1 << 64, ValueError),
        ):
            with self.assertRaises(exc):
                InclusionProof(
                    "sha256", base.index, bad, base.entry_hash, base.root, base.proof
                )

    def test_digests_checked(self):
        base = self.make_credential()
        with self.assertRaises(TypeError):
            InclusionProof(
                "sha256", 3, 7, bytearray(base.entry_hash), base.root, base.proof
            )
        with self.assertRaises(ValueError):
            InclusionProof("sha256", 3, 7, b"\x00" * 31, base.root, base.proof)
        with self.assertRaises(TypeError):
            InclusionProof(
                "sha256", 3, 7, base.entry_hash, bytearray(base.root), base.proof
            )
        with self.assertRaises(ValueError):
            InclusionProof("sha256", 3, 7, base.entry_hash, b"\x00" * 31, base.proof)

    def test_proof_checked(self):
        base = self.make_credential()
        with self.assertRaises(TypeError):
            InclusionProof(
                "sha256", 3, 7, base.entry_hash, base.root, list(base.proof)
            )
        with self.assertRaises(TypeError):
            InclusionProof(
                "sha256",
                3,
                7,
                base.entry_hash,
                base.root,
                (bytearray(b"\x00" * 32),),
            )
        with self.assertRaises(ValueError):
            InclusionProof(
                "sha256", 3, 7, base.entry_hash, base.root, (b"\x00" * 31,)
            )

    def test_proof_node_count_not_checked_by_constructor(self):
        # Node-count fit and root rebuild belong to verify_inclusion.
        base = self.make_credential()
        credential = InclusionProof(
            "sha256",
            base.index,
            base.size,
            base.entry_hash,
            base.root,
            base.proof + (b"\x00" * 32,),
        )
        with self.assertRaises(ValueError):
            verify(credential)

    def test_content_mismatch_verifies_false(self):
        base = self.make_credential()
        credential = InclusionProof(
            "sha256",
            base.index,
            base.size,
            base.entry_hash,
            b"\x11" * 32,
            base.proof,
        )
        self.assertFalse(verify(credential))


class EncodeInclusionProofTest(InclusionProofTestBase):
    def test_magic_and_field_layout(self):
        credential = self.make_credential()
        data = encode_inclusion_proof(credential)
        expected = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(3)
            + u64(7)
            + blob(credential.entry_hash)
            + blob(credential.root)
            + u64(len(credential.proof))
            + b"".join(blob(node) for node in credential.proof)
        )
        self.assertEqual(data, expected)

    def test_encode_is_deterministic(self):
        credential = self.make_credential()
        self.assertEqual(
            encode_inclusion_proof(credential),
            encode_inclusion_proof(credential),
        )

    def test_encoding_is_read_only(self):
        credential = self.make_credential()
        before = tuple(credential.__dataclass_fields__)
        snapshot = tuple(getattr(credential, name) for name in before)
        encode_inclusion_proof(credential)
        self.assertEqual(
            tuple(getattr(credential, name) for name in before), snapshot
        )

    def test_only_credential_accepted(self):
        for bad in (None, "x", b"bytes", 1, (), object()):
            with self.assertRaises(TypeError):
                encode_inclusion_proof(bad)

    def test_bypassed_fields_revalidated(self):
        credential = self.make_credential()
        import copy

        for name, value, exc in (
            ("hash_name", 1, TypeError),
            ("index", -1, ValueError),
            ("size", 0, ValueError),
            ("entry_hash", bytearray(credential.entry_hash), TypeError),
            ("root", b"\x00" * 31, ValueError),
            ("proof", (b"\x00" * 31,), ValueError),
        ):
            forged = copy.copy(credential)
            object.__setattr__(forged, name, value)
            with self.assertRaises(exc):
                encode_inclusion_proof(forged)


class DecodeInclusionProofTest(InclusionProofTestBase):
    def roundtrip(self, credential):
        data = encode_inclusion_proof(credential)
        decoded = decode_inclusion_proof(data)
        self.assertIsInstance(decoded, InclusionProof)
        self.assertEqual(decoded, credential)
        self.assertEqual(encode_inclusion_proof(decoded), data)
        self.assertTrue(verify(decoded))
        return decoded

    def test_roundtrip_variants(self):
        for index, size in (
            (0, None),
            (3, None),
            (6, None),
            (3, 4),
            (0, 1),
            (5, 6),
        ):
            self.roundtrip(self.make_credential(index, size))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        credential = InclusionProof(
            "sha3-256",
            1,
            len(log),
            log.entry(1).entry_hash,
            log.merkle_root(),
            log.inclusion_proof(1),
        )
        self.roundtrip(credential)

    def test_roundtrip_empty_proof(self):
        self.roundtrip(self.make_credential(0, 1))

    def test_only_exact_bytes_accepted(self):
        data = encode_inclusion_proof(self.make_credential())
        for bad in (bytearray(data), memoryview(data), "text", None, 1, [data]):
            with self.assertRaises(TypeError):
                decode_inclusion_proof(bad)

    def test_bad_magic(self):
        data = encode_inclusion_proof(self.make_credential())
        with self.assertRaises(ValueError):
            decode_inclusion_proof(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_inclusion_proof(b"")
        with self.assertRaises(ValueError):
            decode_inclusion_proof(MAGIC[:-1])

    def test_bad_version(self):
        data = encode_inclusion_proof(self.make_credential())
        with self.assertRaises(ValueError):
            decode_inclusion_proof(MAGIC + u64(2) + data[len(MAGIC) + 8:])

    def test_unknown_hash_algorithm(self):
        base = self.make_credential()
        data = build(
            b"not-a-hash", base.index, base.size, base.entry_hash, base.root, base.proof
        )
        with self.assertRaises(ValueError):
            decode_inclusion_proof(data)

    def test_invalid_utf8_hash_name(self):
        base = self.make_credential()
        data = build(
            b"\xff\xfe", base.index, base.size, base.entry_hash, base.root, base.proof
        )
        with self.assertRaises(ValueError):
            decode_inclusion_proof(data)

    def test_truncation(self):
        data = encode_inclusion_proof(self.make_credential())
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_inclusion_proof(data[:cut])

    def test_trailing_bytes(self):
        data = encode_inclusion_proof(self.make_credential())
        with self.assertRaises(ValueError):
            decode_inclusion_proof(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_inclusion_proof(data)

    def test_digest_widths_checked(self):
        base = self.make_credential()
        with self.assertRaises(ValueError):
            decode_inclusion_proof(
                build(b"sha256", base.index, base.size, b"\x00" * 31, base.root, base.proof)
            )
        with self.assertRaises(ValueError):
            decode_inclusion_proof(
                build(b"sha256", base.index, base.size, base.entry_hash, b"\x00" * 31, base.proof)
            )
        if base.proof:
            with self.assertRaises(ValueError):
                decode_inclusion_proof(
                    build(
                        b"sha256",
                        base.index,
                        base.size,
                        base.entry_hash,
                        base.root,
                        base.proof[:-1] + (b"\x00" * 31,),
                    )
                )

    def test_index_out_of_range_rejected(self):
        base = self.make_credential()
        with self.assertRaises(ValueError):
            decode_inclusion_proof(
                build(b"sha256", 7, base.size, base.entry_hash, base.root, base.proof)
            )
        with self.assertRaises(ValueError):
            decode_inclusion_proof(
                build(b"sha256", base.index, 3, base.entry_hash, base.root, base.proof)
            )

    def test_extra_proof_node_decodes_but_verify_raises(self):
        base = self.make_credential()
        data = build(
            b"sha256",
            base.index,
            base.size,
            base.entry_hash,
            base.root,
            base.proof + (b"\x00" * 32,),
        )
        decoded = decode_inclusion_proof(data)
        with self.assertRaises(ValueError):
            verify(decoded)

    def test_wrong_root_decodes_but_verifies_false(self):
        base = self.make_credential()
        data = build(
            b"sha256", base.index, base.size, base.entry_hash, b"\x11" * 32, base.proof
        )
        decoded = decode_inclusion_proof(data)
        self.assertEqual(decoded.root, b"\x11" * 32)
        self.assertFalse(verify(decoded))

    def test_wrong_proof_node_decodes_but_verifies_false(self):
        base = self.make_credential()
        if not base.proof:
            self.skipTest("credential has an empty proof")
        data = build(
            b"sha256",
            base.index,
            base.size,
            base.entry_hash,
            base.root,
            (b"\x22" * 32,) + base.proof[1:],
        )
        decoded = decode_inclusion_proof(data)
        self.assertFalse(verify(decoded))


if __name__ == "__main__":
    unittest.main()
