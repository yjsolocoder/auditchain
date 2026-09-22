import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedAuthAuditContinuation,
    SignedConsistency,
    encode_rotation,
    encode_signed_auth_audit_continuation,
    verify_rotated_chain,
    verify_signed_auth_audit_continuation,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(3, 35))
_KEY = b"super-secret-verifier-key"


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(n=8, key=_KEY, hash_name="sha256", prefix="record"):
    # Each continuation consumes the log holder's one-shot verifier export,
    # so every artifact is minted from a fresh log over identical content.
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _segment(old_size, new_size, seed, **kwargs):
    return _log(**kwargs).signed_auth_audit_continuation(
        old_size, (), seed, size=new_size
    )


def _rotation(old_seed, new_seed, size, **kwargs):
    return _log(**kwargs).rotate_signer(old_seed, new_seed, size)


class VerifyRotatedChainTest(unittest.TestCase):
    def setUp(self):
        # Two handoffs over distinct prefixes: segment (0,3) under A,
        # rotation A->B at size 3, segment (3,6) under B, rotation B->C at
        # size 6, segment (6,8) under C. Every artifact comes from a fresh
        # log over the same eight records.
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.r1 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.receipts = (self.s0, self.s1, self.s2)
        self.rotations = (self.r0, self.r1)
        self.key_a = _public_key(_SEED_A)
        self.key_b = _public_key(_SEED_B)
        self.key_d = _public_key(_SEED_D)

    def test_single_segment_empty_rotations_verifies(self):
        self.assertTrue(
            verify_rotated_chain((self.s0,), (), self.key_a)
        )

    def test_multi_hop_rotated_chain_verifies_with_only_first_key(self):
        self.assertTrue(
            verify_rotated_chain(
                self.receipts, self.rotations, self.key_a
            )
        )

    def test_two_segments_one_hop_verifies(self):
        self.assertTrue(
            verify_rotated_chain(
                (self.s0, self.s1), (self.r0,), self.key_a
            )
        )

    def test_boundary_checkpoints_join_on_every_field(self):
        self.assertEqual(self.r0[0], self.s0.consistency.new)
        self.assertEqual(self.r0[2], self.s1.consistency.old)
        self.assertEqual(self.r1[0], self.s1.consistency.new)
        self.assertEqual(self.r1[2], self.s2.consistency.old)

    def test_trust_lands_on_final_signer(self):
        # The last segment must not verify under the initial key, but does
        # under the final learned key; the chain bridges exactly that gap.
        self.assertFalse(
            verify_signed_auth_audit_continuation(self.s2, self.key_a)
        )
        final_key = self.r1[1]
        self.assertTrue(
            verify_signed_auth_audit_continuation(self.s2, final_key)
        )
        self.assertTrue(
            verify_rotated_chain(
                self.receipts, self.rotations, self.key_a
            )
        )

    def test_wrong_initial_key_returns_false(self):
        self.assertFalse(
            verify_rotated_chain(
                self.receipts, self.rotations, self.key_d
            )
        )

    def test_reordered_rotations_return_false(self):
        # r1 (B->C) presented at the A|B boundary cannot verify against A.
        self.assertFalse(
            verify_rotated_chain(
                self.receipts, (self.r1, self.r0), self.key_a
            )
        )

    def test_skipping_a_hop_returns_false(self):
        # Only the B->C rotation is supplied, verified directly against A.
        self.assertFalse(
            verify_rotated_chain(
                (self.s0, self.s2), (self.r1,), self.key_a
            )
        )

    def test_second_segment_signed_by_unauthorized_key_returns_false(self):
        # The rotation authorizes B, but segment s1 was actually signed by D:
        # verifying it against the learned new_key fails.
        s1_other = _segment(3, 6, _SEED_D)
        self.assertEqual(
            s1_other.consistency.old.size, self.s1.consistency.old.size
        )
        self.assertNotEqual(
            s1_other.consistency.old, self.s1.consistency.old
        )
        self.assertFalse(
            verify_rotated_chain(
                (self.s0, s1_other), (self.r0,), self.key_a
            )
        )

    def test_rotation_wrong_new_key_returns_false_when_auth_mismatches(self):
        # Rotation claiming another new_key: its auth cannot be replayed over
        # the substituted key, so verify_rotation fails.
        old, _new_key, new, _auth = self.r0
        claimed = (old, self.key_d, new, _auth)
        self.assertFalse(
            verify_rotated_chain(
                (self.s0, self.s1), (claimed,), self.key_a
            )
        )

    def test_tampered_rotation_auth_returns_false(self):
        old, new_key, new, _auth = self.r0
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertFalse(
            verify_rotated_chain(
                (self.s0, self.s1), (forged,), self.key_a
            )
        )

    def test_rotation_at_other_size_fails_boundary_link(self):
        # A genuine A->B rotation, but over the size-2 snapshot rather than
        # the size-3 boundary where the two segments meet.
        other = _rotation(_SEED_A, _SEED_B, 2)
        self.assertFalse(
            verify_rotated_chain(
                (self.s0, self.s1), (other,), self.key_a
            )
        )

    def test_rotation_old_must_equal_previous_segment_new(self):
        # Same sizes but different histories: rotation.old no longer equals
        # the first segment's consistency.new checkpoint.
        s0_other = _log(prefix="other").signed_auth_audit_continuation(
            0, (), _SEED_A, size=3
        )
        self.assertFalse(
            verify_rotated_chain(
                (s0_other, self.s1), (self.r0,), self.key_a
            )
        )

    def test_rotation_new_must_equal_following_segment_old(self):
        # Following segment signed by another key D: even an otherwise valid
        # A->B rotation cannot link into its boundary checkpoint.
        s1_other = _segment(3, 6, _SEED_D)
        self.assertFalse(
            verify_rotated_chain(
                (self.s0, s1_other), (self.r0,), self.key_a
            )
        )

    def test_zero_length_segment_returns_false(self):
        equal = _log(6).signed_auth_audit_continuation(
            3, (), _SEED_B, size=3
        )
        self.assertFalse(
            verify_rotated_chain(
                (self.s0, equal), (self.r0,), self.key_a
            )
        )

    def test_duplicate_receipt_returns_false(self):
        self.assertFalse(
            verify_rotated_chain(
                (self.s0, self.s0), (self.r0,), self.key_a
            )
        )

    def test_duplicate_non_adjacent_receipt_returns_false(self):
        self.assertFalse(
            verify_rotated_chain(
                (self.s0, self.s1, self.s0),
                (self.r0, self.r1),
                self.key_a,
            )
        )

    def test_duplicate_rotation_returns_false(self):
        self.assertFalse(
            verify_rotated_chain(
                self.receipts, (self.r0, self.r0), self.key_a
            )
        )

    def test_tampered_segment_returns_false(self):
        old = self.s1.consistency.old
        forged_old = type(old)(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        forged_consistency = SignedConsistency(
            forged_old,
            self.s1.consistency.new,
            self.s1.consistency.proof,
        )
        forged = SignedAuthAuditContinuation(
            self.s1.bundle, forged_consistency
        )
        self.assertFalse(
            verify_rotated_chain(
                (self.s0, forged), (self.r0,), self.key_a
            )
        )

    def test_empty_receipts_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_rotated_chain((), (), self.key_a)

    def test_rotation_count_must_be_segments_minus_one(self):
        with self.assertRaises(ValueError):
            verify_rotated_chain(
                (self.s0,), (self.r0,), self.key_a
            )
        with self.assertRaises(ValueError):
            verify_rotated_chain(
                self.receipts, (), self.key_a
            )
        with self.assertRaises(ValueError):
            verify_rotated_chain(
                self.receipts, (self.r0,), self.key_a
            )
        with self.assertRaises(ValueError):
            verify_rotated_chain(
                self.receipts,
                (self.r0, self.r1, self.r0),
                self.key_a,
            )

    def test_non_tuple_receipts_raises_type_error(self):
        for bad in (
            [self.s0],
            {self.s0},
            None,
            self.s0,
            "receipts",
            1,
        ):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    verify_rotated_chain(bad, (), self.key_a)

    def test_non_tuple_rotations_raises_type_error(self):
        for bad in ([], None, "rotations", 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    verify_rotated_chain((self.s0,), bad, self.key_a)

    def test_generator_arguments_raise_type_error(self):
        with self.assertRaises(TypeError):
            verify_rotated_chain(
                (r for r in self.receipts), (), self.key_a
            )
        with self.assertRaises(TypeError):
            verify_rotated_chain(
                (self.s0,), (r for r in ()), self.key_a
            )

    def test_wrong_receipt_element_type_raises_type_error(self):
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    verify_rotated_chain(
                        (bad,), (), self.key_a
                    )
                with self.assertRaises(TypeError):
                    verify_rotated_chain(
                        (self.s0, bad), (self.r0,), self.key_a
                    )

    def test_wrong_rotation_element_type_raises_type_error(self):
        for bad in (b"bytes", "rotation", None, 1, object(), [self.r0]):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    verify_rotated_chain(
                        (self.s0, self.s1), (bad,), self.key_a
                    )

    def test_inner_three_tuple_raises_value_error(self):
        # A tuple element of the wrong arity is verify_rotation's nested
        # ValueError and must propagate unchanged.
        with self.assertRaises(ValueError):
            verify_rotated_chain(
                (self.s0, self.s1), (self.r0[:3],), self.key_a
            )

    def test_nested_receipt_structural_error_propagates(self):
        # An instance whose container fields were bypassed to wrong types
        # passes the outer isinstance element check but makes the nested
        # verify_signed_auth_audit_continuation raise TypeError unchanged.
        bypassed = object.__new__(SignedAuthAuditContinuation)
        object.__setattr__(bypassed, "bundle", "not-a-bundle")
        object.__setattr__(
            bypassed, "consistency", self.s0.consistency
        )
        with self.assertRaises(TypeError):
            verify_rotated_chain((bypassed,), (), self.key_a)

    def test_key_type_raises_type_error(self):
        for bad in ("k", bytearray(self.key_a), None, 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    verify_rotated_chain(
                        (self.s0,), (), bad
                    )

    def test_key_length_raises_value_error(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    verify_rotated_chain(
                        (self.s0,), (), bad
                    )

    def test_call_is_read_only(self):
        receipt_bytes_before = tuple(
            encode_signed_auth_audit_continuation(r)
            for r in self.receipts
        )
        rotation_bytes_before = tuple(
            encode_rotation(r) for r in self.rotations
        )
        self.assertTrue(
            verify_rotated_chain(
                self.receipts, self.rotations, self.key_a
            )
        )
        self.assertEqual(
            tuple(
                encode_signed_auth_audit_continuation(r)
                for r in self.receipts
            ),
            receipt_bytes_before,
        )
        self.assertEqual(
            tuple(encode_rotation(r) for r in self.rotations),
            rotation_bytes_before,
        )

    def test_no_new_container_or_key_material_trusted(self):
        # The bundle nesting inside a segment is untouched: swapping in an
        # unrelated auth bundle is exactly the same failure the single
        # receipt verifier reports (False, not a new exception type).
        other = _segment(0, 3, _SEED_B)
        merged = SignedAuthAuditContinuation(
            other.bundle, self.s0.consistency
        )
        self.assertFalse(
            verify_rotated_chain((merged,), (), self.key_a)
        )


if __name__ == "__main__":
    unittest.main()
