import copy
import unittest

from auditchain import (
    AuditLog,
    ConsistencyProof,
    decode_consistency_proof,
    encode_consistency_proof,
    verify_consistency,
)

MAGIC = b"auditchain/consistency/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def build(hash_name, old_size, old_root, new_size, new_root, proof, version=1):
    """Hand-build a consistency-proof encoding with arbitrary content."""
    out = MAGIC + u64(version) + blob(hash_name)
    out += u64(old_size) + blob(old_root)
    out += u64(new_size) + blob(new_root)
    out += u64(len(proof))
    for node in proof:
        out += blob(node)
    return out


def verify(credential):
    return verify_consistency(
        credential.old_size,
        credential.old_root,
        credential.new_size,
        credential.new_root,
        credential.proof,
        hash_name=credential.hash_name,
    )


class ConsistencyProofTestBase(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e", "f", "g"):
            self.log.append(record)

    def make_credential(self, old_size=3, new_size=6):
        return ConsistencyProof(
            "sha256",
            old_size,
            self.log.merkle_root(old_size),
            new_size,
            self.log.merkle_root(new_size),
            self.log.consistency_proof(old_size, new_size),
        )


class ConsistencyProofConstructorTest(ConsistencyProofTestBase):
    def test_fields_in_order_and_positional_construction(self):
        credential = self.make_credential()
        self.assertEqual(
            tuple(credential.__dataclass_fields__),
            ("hash_name", "old_size", "old_root", "new_size", "new_root", "proof"),
        )
        self.assertEqual(credential.hash_name, "sha256")
        self.assertEqual(credential.old_size, 3)
        self.assertEqual(credential.old_root, self.log.merkle_root(3))
        self.assertEqual(credential.new_size, 6)
        self.assertEqual(credential.new_root, self.log.merkle_root(6))
        self.assertEqual(credential.proof, self.log.consistency_proof(3, 6))

    def test_equality_by_all_fields(self):
        self.assertEqual(self.make_credential(), self.make_credential())
        self.assertNotEqual(self.make_credential(), self.make_credential(2, 6))

    def test_frozen(self):
        credential = self.make_credential()
        with self.assertRaises(Exception):
            credential.old_size = 0

    def test_hash_name_checked(self):
        base = self.make_credential()
        with self.assertRaises(TypeError):
            ConsistencyProof(
                1,
                base.old_size,
                base.old_root,
                base.new_size,
                base.new_root,
                base.proof,
            )
        with self.assertRaises(ValueError):
            ConsistencyProof(
                "not-a-hash",
                base.old_size,
                base.old_root,
                base.new_size,
                base.new_root,
                base.proof,
            )

    def test_sizes_checked(self):
        base = self.make_credential()
        for old, new, exc in (
            ("3", 6, TypeError),
            (3, "6", TypeError),
            (True, 6, TypeError),
            (3, False, TypeError),
            (-1, 6, ValueError),
            (3, -1, ValueError),
            (6, 3, ValueError),
            (3, 1 << 64, ValueError),
        ):
            with self.assertRaises(exc):
                ConsistencyProof(
                    "sha256", old, base.old_root, new, base.new_root, base.proof
                )

    def test_zero_and_equal_sizes_accepted(self):
        empty_root = self.log.merkle_root(0)
        zero = ConsistencyProof("sha256", 0, empty_root, 0, empty_root, ())
        self.assertEqual(zero.old_size, 0)
        equal = self.make_credential(4, 4)
        self.assertEqual(equal.proof, ())

    def test_roots_checked(self):
        base = self.make_credential()
        with self.assertRaises(TypeError):
            ConsistencyProof(
                "sha256",
                base.old_size,
                bytearray(base.old_root),
                base.new_size,
                base.new_root,
                base.proof,
            )
        with self.assertRaises(ValueError):
            ConsistencyProof(
                "sha256",
                base.old_size,
                b"\x00" * 31,
                base.new_size,
                base.new_root,
                base.proof,
            )
        with self.assertRaises(TypeError):
            ConsistencyProof(
                "sha256",
                base.old_size,
                base.old_root,
                base.new_size,
                bytearray(base.new_root),
                base.proof,
            )
        with self.assertRaises(ValueError):
            ConsistencyProof(
                "sha256",
                base.old_size,
                base.old_root,
                base.new_size,
                b"\x00" * 31,
                base.proof,
            )

    def test_proof_checked(self):
        base = self.make_credential()
        with self.assertRaises(TypeError):
            ConsistencyProof(
                "sha256",
                base.old_size,
                base.old_root,
                base.new_size,
                base.new_root,
                list(base.proof),
            )
        with self.assertRaises(TypeError):
            ConsistencyProof(
                "sha256",
                base.old_size,
                base.old_root,
                base.new_size,
                base.new_root,
                (bytearray(b"\x00" * 32),),
            )
        with self.assertRaises(ValueError):
            ConsistencyProof(
                "sha256",
                base.old_size,
                base.old_root,
                base.new_size,
                base.new_root,
                (b"\x00" * 31,),
            )

    def test_proof_node_count_not_checked_by_constructor(self):
        # Node-count fit and connecting the roots belong to verify_consistency.
        base = self.make_credential()
        credential = ConsistencyProof(
            "sha256",
            base.old_size,
            base.old_root,
            base.new_size,
            base.new_root,
            base.proof + (b"\x00" * 32,),
        )
        with self.assertRaises(ValueError):
            verify(credential)

    def test_content_mismatch_verifies_false(self):
        base = self.make_credential()
        credential = ConsistencyProof(
            "sha256",
            base.old_size,
            base.old_root,
            base.new_size,
            b"\x11" * 32,
            base.proof,
        )
        self.assertFalse(verify(credential))


class EncodeConsistencyProofTest(ConsistencyProofTestBase):
    def test_magic_and_field_layout(self):
        credential = self.make_credential()
        data = encode_consistency_proof(credential)
        expected = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(credential.old_size)
            + blob(credential.old_root)
            + u64(credential.new_size)
            + blob(credential.new_root)
            + u64(len(credential.proof))
            + b"".join(blob(node) for node in credential.proof)
        )
        self.assertEqual(data, expected)

    def test_encode_is_deterministic(self):
        credential = self.make_credential()
        self.assertEqual(
            encode_consistency_proof(credential),
            encode_consistency_proof(credential),
        )

    def test_encoding_is_read_only(self):
        credential = self.make_credential()
        names = tuple(credential.__dataclass_fields__)
        snapshot = tuple(getattr(credential, name) for name in names)
        encode_consistency_proof(credential)
        self.assertEqual(
            tuple(getattr(credential, name) for name in names), snapshot
        )

    def test_only_credential_accepted(self):
        for bad in (None, "x", b"bytes", 1, (), object()):
            with self.assertRaises(TypeError):
                encode_consistency_proof(bad)

    def test_bypassed_fields_revalidated(self):
        credential = self.make_credential()
        for name, value, exc in (
            ("hash_name", 1, TypeError),
            ("old_size", -1, ValueError),
            ("old_size", True, TypeError),
            ("new_size", 1 << 64, ValueError),
            ("old_root", bytearray(credential.old_root), TypeError),
            ("new_root", b"\x00" * 31, ValueError),
            ("proof", (b"\x00" * 31,), ValueError),
        ):
            forged = copy.copy(credential)
            object.__setattr__(forged, name, value)
            with self.assertRaises(exc):
                encode_consistency_proof(forged)


class DecodeConsistencyProofTest(ConsistencyProofTestBase):
    def roundtrip(self, credential):
        data = encode_consistency_proof(credential)
        decoded = decode_consistency_proof(data)
        self.assertIsInstance(decoded, ConsistencyProof)
        self.assertEqual(decoded, credential)
        self.assertEqual(encode_consistency_proof(decoded), data)
        return decoded

    def test_roundtrip_variants(self):
        for old, new in (
            (1, 7),
            (3, 6),
            (4, 4),
            (0, 0),
            (2, 5),
            (6, 7),
        ):
            credential = self.make_credential(old, new)
            decoded = self.roundtrip(credential)
            self.assertTrue(verify(decoded))

    def test_roundtrip_power_of_two_boundaries(self):
        for old, new in ((1, 2), (2, 4), (4, 7), (1, 4)):
            credential = self.make_credential(old, new)
            decoded = self.roundtrip(credential)
            self.assertTrue(verify(decoded))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        credential = ConsistencyProof(
            "sha3-256",
            1,
            log.merkle_root(1),
            3,
            log.merkle_root(),
            log.consistency_proof(1, 3),
        )
        decoded = self.roundtrip(credential)
        self.assertTrue(verify(decoded))

    def test_roundtrip_empty_proof_cases(self):
        self.roundtrip(self.make_credential(4, 4))
        empty_root = self.log.merkle_root(0)
        self.roundtrip(ConsistencyProof("sha256", 0, empty_root, 0, empty_root, ()))

    def test_only_exact_bytes_accepted(self):
        data = encode_consistency_proof(self.make_credential())
        for bad in (bytearray(data), memoryview(data), "text", None, 1, [data]):
            with self.assertRaises(TypeError):
                decode_consistency_proof(bad)

    def test_bad_magic(self):
        data = encode_consistency_proof(self.make_credential())
        with self.assertRaises(ValueError):
            decode_consistency_proof(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_consistency_proof(b"")
        with self.assertRaises(ValueError):
            decode_consistency_proof(MAGIC[:-1])

    def test_bad_version(self):
        data = encode_consistency_proof(self.make_credential())
        with self.assertRaises(ValueError):
            decode_consistency_proof(MAGIC + u64(2) + data[len(MAGIC) + 8:])

    def test_unknown_hash_algorithm(self):
        base = self.make_credential()
        data = build(
            b"not-a-hash",
            base.old_size,
            base.old_root,
            base.new_size,
            base.new_root,
            base.proof,
        )
        with self.assertRaises(ValueError):
            decode_consistency_proof(data)

    def test_invalid_utf8_hash_name(self):
        base = self.make_credential()
        data = build(
            b"\xff\xfe",
            base.old_size,
            base.old_root,
            base.new_size,
            base.new_root,
            base.proof,
        )
        with self.assertRaises(ValueError):
            decode_consistency_proof(data)

    def test_truncation(self):
        data = encode_consistency_proof(self.make_credential())
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_consistency_proof(data[:cut])

    def test_trailing_bytes(self):
        data = encode_consistency_proof(self.make_credential())
        with self.assertRaises(ValueError):
            decode_consistency_proof(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_consistency_proof(data)

    def test_digest_widths_checked(self):
        base = self.make_credential()
        with self.assertRaises(ValueError):
            decode_consistency_proof(
                build(
                    b"sha256",
                    base.old_size,
                    b"\x00" * 31,
                    base.new_size,
                    base.new_root,
                    base.proof,
                )
            )
        with self.assertRaises(ValueError):
            decode_consistency_proof(
                build(
                    b"sha256",
                    base.old_size,
                    base.old_root,
                    base.new_size,
                    b"\x00" * 31,
                    base.proof,
                )
            )
        if base.proof:
            with self.assertRaises(ValueError):
                decode_consistency_proof(
                    build(
                        b"sha256",
                        base.old_size,
                        base.old_root,
                        base.new_size,
                        base.new_root,
                        base.proof[:-1] + (b"\x00" * 31,),
                    )
                )

    def test_reversed_sizes_rejected(self):
        base = self.make_credential()
        with self.assertRaises(ValueError):
            decode_consistency_proof(
                build(
                    b"sha256",
                    base.new_size,
                    base.old_root,
                    base.old_size,
                    base.new_root,
                    base.proof,
                )
            )

    def test_extra_proof_node_decodes_but_verify_raises(self):
        base = self.make_credential()
        data = build(
            b"sha256",
            base.old_size,
            base.old_root,
            base.new_size,
            base.new_root,
            base.proof + (b"\x00" * 32,),
        )
        decoded = decode_consistency_proof(data)
        with self.assertRaises(ValueError):
            verify(decoded)

    def test_wrong_root_decodes_but_verifies_false(self):
        base = self.make_credential()
        data = build(
            b"sha256",
            base.old_size,
            base.old_root,
            base.new_size,
            b"\x11" * 32,
            base.proof,
        )
        decoded = decode_consistency_proof(data)
        self.assertEqual(decoded.new_root, b"\x11" * 32)
        self.assertFalse(verify(decoded))

    def test_wrong_proof_node_decodes_but_verifies_false(self):
        base = self.make_credential()
        if not base.proof:
            self.skipTest("credential has an empty proof")
        data = build(
            b"sha256",
            base.old_size,
            base.old_root,
            base.new_size,
            base.new_root,
            (b"\x22" * 32,) + base.proof[1:],
        )
        decoded = decode_consistency_proof(data)
        self.assertFalse(verify(decoded))


if __name__ == "__main__":
    unittest.main()
