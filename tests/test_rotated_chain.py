import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedAuthAuditContinuation,
    verify_rotated_chain,
    verify_signed_auth_audit_continuation,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(2, 34))
_KEY = b"super-secret-verifier-key"


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(n=8, key=_KEY, hash_name="sha256", prefix="record"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


class VerifyRotatedChainTest(unittest.TestCase):
    def setUp(self):
        # Three segments over sizes 0 -> 2 -> 5 -> 8, signed by A, B and C
        # respectively; rotations A->B at size 2 and B->C at size 5 join them.
        # Every artifact is minted on a fresh log of identical content, so
        # deterministic Ed25519 signatures make the boundary checkpoints
        # byte-identical across the segments and rotations.
        self.r1 = _log().signed_auth_audit_continuation(
            0, (), _SEED_A, size=2
        )
        self.rot1 = _log().rotate_signer(_SEED_A, _SEED_B, 2)
        self.r2 = _log().signed_auth_audit_continuation(
            2, (), _SEED_B, size=5
        )
        self.rot2 = _log().rotate_signer(_SEED_B, _SEED_C, 5)
        self.r3 = _log().signed_auth_audit_continuation(
            5, (), _SEED_C, size=8
        )
        self.receipts = (self.r1, self.r2, self.r3)
        self.rotations = (self.rot1, self.rot2)
        self.initial_key = _public_key(_SEED_A)

    def test_single_segment_without_rotations_verifies(self):
        self.assertTrue(
            verify_rotated_chain((self.r1,), (), self.initial_key)
        )

    def test_cross_key_multi_segment_chain_verifies(self):
        self.assertTrue(
            verify_rotated_chain(
                self.receipts, self.rotations, self.initial_key
            )
        )

    def test_each_segment_only_verifies_under_its_own_key(self):
        # The first segment fails under B; the later segments only verify once
        # trust has hopped through the rotation at their boundary.
        self.assertTrue(
            verify_signed_auth_audit_continuation(self.r1, _public_key(_SEED_A))
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(self.r1, _public_key(_SEED_B))
        )
        self.assertTrue(
            verify_signed_auth_audit_continuation(self.r2, _public_key(_SEED_B))
        )
        self.assertFalse(
            verify_signed_auth_audit_continuation(self.r2, _public_key(_SEED_A))
        )
        self.assertTrue(
            verify_signed_auth_audit_continuation(self.r3, _public_key(_SEED_C))
        )

    def test_wrong_initial_key_returns_false(self):
        self.assertFalse(
            verify_rotated_chain(
                self.receipts, self.rotations, _public_key(_SEED_D)
            )
        )

    def test_segment_signed_by_unknown_key_returns_false(self):
        # The B-signed second segment cannot pass if only A is trusted and
        # no rotation precedes it.
        self.assertFalse(
            verify_rotated_chain((self.r2,), (), self.initial_key)
        )

    def test_reordered_rotations_return_false(self):
        # The B->C rotation is presented at the first boundary, where only
        # verify_rotation against A could authorize it.
        self.assertFalse(
            verify_rotated_chain(
                self.receipts, (self.rot2, self.rot1), self.initial_key
            )
        )

    def test_skipping_a_hop_returns_false(self):
        # A directly authorizes C at the first boundary, so the B-signed
        # segment 2 is neither vouched for nor verifies under the learned key.
        jump = _log().rotate_signer(_SEED_A, _SEED_C, 2)
        self.assertFalse(
            verify_rotated_chain(
                (self.r1, self.r2, self.r3),
                (jump, self.rot2),
                self.initial_key,
            )
        )

    def test_rotation_at_wrong_snapshot_returns_false(self):
        # The rotation attests a size-3 checkpoint while both adjacent
        # segments name size 2 at the boundary.
        bad = _log().rotate_signer(_SEED_A, _SEED_B, 3)
        self.assertFalse(
            verify_rotated_chain(
                self.receipts, (bad, self.rot2), self.initial_key
            )
        )

    def test_rotation_authorized_by_wrong_old_key_returns_false(self):
        forged = _log().rotate_signer(_SEED_C, _SEED_B, 2)
        self.assertFalse(
            verify_rotated_chain(
                self.receipts, (forged, self.rot2), self.initial_key
            )
        )

    def test_rotation_to_wrong_new_key_returns_false(self):
        # The rotation is genuine but vouches for D; segment 2 is signed by B.
        forged = _log().rotate_signer(_SEED_A, _SEED_D, 2)
        self.assertFalse(
            verify_rotated_chain(
                self.receipts, (forged, self.rot2), self.initial_key
            )
        )

    def test_tampered_rotation_auth_returns_false(self):
        old, new_key, new, _auth = self.rot1
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertFalse(
            verify_rotated_chain(
                self.receipts, (forged, self.rot2), self.initial_key
            )
        )

    def test_non_growing_segment_returns_false(self):
        # old == new describes no append at all.
        flat = _log().signed_auth_audit_continuation(
            2, (), _SEED_A, size=2
        )
        self.assertFalse(
            verify_rotated_chain((flat,), (), self.initial_key)
        )

    def test_repeated_receipt_returns_false(self):
        self.assertFalse(
            verify_rotated_chain(
                (self.r1, self.r1), (self.rot1,), self.initial_key
            )
        )
        self.assertFalse(
            verify_rotated_chain(
                (self.r1, self.r2, self.r1),
                (self.rot1, self.rot1),
                self.initial_key,
            )
        )

    def test_repeated_rotation_returns_false(self):
        self.assertFalse(
            verify_rotated_chain(
                (self.r1, self.r2, self.r3),
                (self.rot1, self.rot1),
                self.initial_key,
            )
        )

    def test_tampered_segment_returns_false(self):
        # A segment whose consistency new checkpoint no longer matches its
        # audit checkpoint fails verify_signed_auth_audit_continuation.
        tampered = SignedAuthAuditContinuation(
            self.r1.bundle, self.r2.consistency
        )
        self.assertFalse(
            verify_rotated_chain(
                (tampered, self.r2, self.r3),
                (self.rot1, self.rot2),
                self.initial_key,
            )
        )

    def test_empty_receipts_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_rotated_chain((), (), self.initial_key)

    def test_rotation_count_mismatch_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_rotated_chain(self.receipts, (), self.initial_key)
        with self.assertRaises(ValueError):
            verify_rotated_chain(
                self.receipts, self.rotations[:1], self.initial_key
            )
        with self.assertRaises(ValueError):
            verify_rotated_chain(
                (self.r1, self.r2), self.rotations, self.initial_key
            )

    def test_non_tuple_receipts_raises_type_error(self):
        for bad in ([self.r1], {self.r1}, None, self.r1, "receipts", 1):
            with self.assertRaises(TypeError, msg=bad):
                verify_rotated_chain(bad, (), self.initial_key)

    def test_non_tuple_rotations_raises_type_error(self):
        for bad in ([self.rot1], {self.rot1}, None, "rotations", 1):
            with self.assertRaises(TypeError, msg=bad):
                verify_rotated_chain(self.receipts, bad, self.initial_key)

    def test_wrong_receipt_element_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_rotated_chain(
                (self.r1, "not a receipt"),
                (self.rot1,),
                self.initial_key,
            )

    def test_wrong_rotation_element_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_rotated_chain(
                self.receipts, (b"not a tuple", self.rot2), self.initial_key
            )

    def test_non_bytes_key_raises_type_error(self):
        for bad in ("key", bytearray(32), memoryview(bytes(32)), None, 32):
            with self.assertRaises(TypeError, msg=bad):
                verify_rotated_chain(
                    (self.r1,), (), bad
                )

    def test_wrong_length_key_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_rotated_chain((self.r1,), (), b"short")
        with self.assertRaises(ValueError):
            verify_rotated_chain((self.r1,), (), bytes(31))
        with self.assertRaises(ValueError):
            verify_rotated_chain((self.r1,), (), bytes(33))

    def test_malformed_rotation_record_propagates(self):
        # Tuple-typed but structurally illegal: verify_rotation's own
        # ValueError (wrong arity) propagates unchanged rather than becoming
        # False.
        with self.assertRaises(ValueError):
            verify_rotated_chain(
                self.receipts,
                ((1, 2, 3), self.rot2),
                self.initial_key,
            )

    def test_read_only_does_not_mutate_inputs(self):
        receipts = self.receipts
        rotations = self.rotations
        self.assertTrue(
            verify_rotated_chain(receipts, rotations, self.initial_key)
        )
        self.assertEqual(receipts, self.receipts)
        self.assertEqual(rotations, self.rotations)
        self.assertTrue(
            verify_rotated_chain(
                self.receipts, self.rotations, self.initial_key
            )
        )


if __name__ == "__main__":
    unittest.main()
