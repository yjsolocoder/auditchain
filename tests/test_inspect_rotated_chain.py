import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    ContinuationChainReport,
    SignedAuthAuditContinuation,
    SignedConsistency,
    encode_rotation,
    encode_signed_auth_audit_continuation,
    inspect_rotated_chain,
    verify_rotated_chain,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(3, 35))
_KEY = b"super-secret-verifier-key"

_OK = ContinuationChainReport(True, None, None)


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


class InspectRotatedChainTest(unittest.TestCase):
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

    def _assert_bool_and_report_agree(self, receipts, rotations, key):
        # For structurally legal inputs the report's ok flag is exactly the
        # bool verifier's conclusion.
        expected = verify_rotated_chain(receipts, rotations, key)
        report = inspect_rotated_chain(receipts, rotations, key)
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertIs(report.ok, expected)

    def test_single_segment_empty_rotations_reports_ok(self):
        self.assertEqual(
            inspect_rotated_chain((self.s0,), (), self.key_a), _OK
        )

    def test_multi_hop_chain_reports_ok_with_only_first_key(self):
        self.assertEqual(
            inspect_rotated_chain(
                self.receipts, self.rotations, self.key_a
            ),
            _OK,
        )

    def test_two_segments_one_hop_reports_ok(self):
        self.assertEqual(
            inspect_rotated_chain(
                (self.s0, self.s1), (self.r0,), self.key_a
            ),
            _OK,
        )

    def test_success_report_fields(self):
        report = inspect_rotated_chain(
            self.receipts, self.rotations, self.key_a
        )
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)
        self.assertEqual((report.ok, report.index, report.code),
                         (True, None, None))

    def test_wrong_initial_key_reports_verify_at_zero(self):
        self.assertEqual(
            inspect_rotated_chain(
                self.receipts, self.rotations, self.key_d
            ),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_wrong_initial_key_single_segment_reports_verify_at_zero(self):
        self.assertEqual(
            inspect_rotated_chain((self.s0,), (), self.key_d),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_reordered_rotations_report_rotation_at_following_index(self):
        # r1 (B->C) presented at the A|B boundary cannot verify against A.
        self.assertEqual(
            inspect_rotated_chain(
                self.receipts, (self.r1, self.r0), self.key_a
            ),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_skipping_a_hop_reports_rotation(self):
        # Only the B->C rotation is supplied, verified directly against A.
        self.assertEqual(
            inspect_rotated_chain(
                (self.s0, self.s2), (self.r1,), self.key_a
            ),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_rotation_wrong_new_key_reports_rotation(self):
        old, _new_key, new, _auth = self.r0
        claimed = (old, self.key_d, new, _auth)
        self.assertEqual(
            inspect_rotated_chain(
                (self.s0, self.s1), (claimed,), self.key_a
            ),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_tampered_rotation_auth_reports_rotation(self):
        old, new_key, new, _auth = self.r0
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotated_chain(
                (self.s0, self.s1), (forged,), self.key_a
            ),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_rotation_checked_before_its_seam(self):
        # Both invalid: the A->B rotation over the size-2 snapshot fails its
        # seam, and forging its auth also makes verify_rotation fail; the
        # rotation verdict has precedence over the link verdict.
        old, new_key, new, _auth = _rotation(_SEED_A, _SEED_B, 2)
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotated_chain(
                (self.s0, self.s1), (forged,), self.key_a
            ),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_rotation_at_other_size_reports_rotation_link(self):
        # A genuine A->B rotation, but over the size-2 snapshot rather than
        # the size-3 boundary where the two segments meet.
        other = _rotation(_SEED_A, _SEED_B, 2)
        self.assertEqual(
            inspect_rotated_chain(
                (self.s0, self.s1), (other,), self.key_a
            ),
            ContinuationChainReport(False, 1, "rotation_link"),
        )

    def test_rotation_old_must_equal_previous_segment_new(self):
        # Same sizes but different histories: rotation.old no longer equals
        # the first segment's consistency.new checkpoint.
        s0_other = _log(prefix="other").signed_auth_audit_continuation(
            0, (), _SEED_A, size=3
        )
        self.assertEqual(
            inspect_rotated_chain(
                (s0_other, self.s1), (self.r0,), self.key_a
            ),
            ContinuationChainReport(False, 1, "rotation_link"),
        )

    def test_rotation_new_must_equal_following_segment_old(self):
        # Following segment signed by another key D: even an otherwise valid
        # A->B rotation cannot link into its boundary checkpoint, and that
        # seam mismatch (rotation_link) is reached before the segment's own
        # verify because the seam is examined first.
        s1_other = _segment(3, 6, _SEED_D)
        self.assertEqual(
            inspect_rotated_chain(
                (self.s0, s1_other), (self.r0,), self.key_a
            ),
            ContinuationChainReport(False, 1, "rotation_link"),
        )

    def test_segment_signed_by_unauthorized_key_reports_verify(self):
        # The rotation authorizes B and both seams hold, but the following
        # segment's bundle was actually sealed by D while keeping s1's
        # consistency checkpoints: verifying the segment against the learned
        # new_key B fails with "verify".
        s1_other = _segment(3, 6, _SEED_D)
        merged = SignedAuthAuditContinuation(
            s1_other.bundle, self.s1.consistency
        )
        self.assertEqual(
            inspect_rotated_chain(
                (self.s0, merged), (self.r0,), self.key_a
            ),
            ContinuationChainReport(False, 1, "verify"),
        )

    def test_tampered_first_segment_reports_verify_at_zero(self):
        old = self.s0.consistency.old
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
            self.s0.consistency.new,
            self.s0.consistency.proof,
        )
        forged = SignedAuthAuditContinuation(
            self.s0.bundle, forged_consistency
        )
        self.assertEqual(
            inspect_rotated_chain((forged,), (), self.key_a),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_zero_length_first_segment_reports_growth_at_zero(self):
        equal = _log(6).signed_auth_audit_continuation(
            3, (), _SEED_B, size=3
        )
        self.assertEqual(
            inspect_rotated_chain((equal,), (), self.key_b),
            ContinuationChainReport(False, 0, "growth"),
        )

    def test_zero_length_following_segment_reports_growth_at_its_index(self):
        # The boundary is genuine and links on every field; the equal-size
        # segment itself verifies under B but does not grow.
        equal = _log(6).signed_auth_audit_continuation(
            3, (), _SEED_B, size=3
        )
        self.assertEqual(
            inspect_rotated_chain(
                (self.s0, equal), (self.r0,), self.key_a
            ),
            ContinuationChainReport(False, 1, "growth"),
        )

    def test_duplicate_rotation_reports_rotation_duplicate(self):
        # At the second boundary r0 is presented again; even though it would
        # neither verify against B nor link s1 to s2, the repetition check
        # comes first and pins the code.
        self.assertEqual(
            inspect_rotated_chain(
                self.receipts, (self.r0, self.r0), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_duplicate"),
        )

    def test_duplicate_rotation_takes_precedence_over_rotation(self):
        # Repeating the genuine r0 at boundary 2 would also fail
        # verify_rotation against B (A->B cannot be authorized by B) and fail
        # both seams; the repetition check runs first and wins.
        self.assertEqual(
            inspect_rotated_chain(
                self.receipts, (self.r0, self.r0), self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation_duplicate"),
        )

    def test_rotation_failure_takes_precedence_over_rotation_link(self):
        # At boundary 1 the rotation both fails verify_rotation and fails its
        # seam; "rotation" is the earlier check.
        self.assertEqual(
            inspect_rotated_chain(
                self.receipts, (self.r1, self.r0), self.key_a
            ),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_reports_agree_with_bool_verifier_on_cases(self):
        cases = [
            ((self.s0,), (), self.key_a),
            (self.receipts, self.rotations, self.key_a),
            ((self.s0, self.s1), (self.r0,), self.key_a),
            (self.receipts, self.rotations, self.key_d),
            (self.receipts, (self.r1, self.r0), self.key_a),
            ((self.s0, self.s2), (self.r1,), self.key_a),
            ((self.s0, _segment(3, 6, _SEED_D)), (self.r0,), self.key_a),
        ]
        old, _new_key, new, _auth = self.r0
        cases.append((
            (self.s0, self.s1),
            ((old, self.key_d, new, _auth),),
            self.key_a,
        ))
        cases.append((
            (self.s0, self.s1),
            (_rotation(_SEED_A, _SEED_B, 2),),
            self.key_a,
        ))
        equal = _log(6).signed_auth_audit_continuation(
            3, (), _SEED_B, size=3
        )
        cases.append(((self.s0, equal), (self.r0,), self.key_a))
        cases.append((self.receipts, (self.r0, self.r0), self.key_a))
        for receipts, rotations, key in cases:
            with self.subTest():
                self._assert_bool_and_report_agree(
                    receipts, rotations, key
                )

    def test_empty_receipts_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            inspect_rotated_chain((), (), self.key_a)

    def test_rotation_count_must_be_segments_minus_one(self):
        with self.assertRaises(ValueError):
            inspect_rotated_chain((self.s0,), (self.r0,), self.key_a)
        with self.assertRaises(ValueError):
            inspect_rotated_chain(self.receipts, (), self.key_a)
        with self.assertRaises(ValueError):
            inspect_rotated_chain(self.receipts, (self.r0,), self.key_a)
        with self.assertRaises(ValueError):
            inspect_rotated_chain(
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
                    inspect_rotated_chain(bad, (), self.key_a)

    def test_non_tuple_rotations_raises_type_error(self):
        for bad in ([], None, "rotations", 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_chain((self.s0,), bad, self.key_a)

    def test_generator_arguments_raise_type_error(self):
        with self.assertRaises(TypeError):
            inspect_rotated_chain(
                (r for r in self.receipts), (), self.key_a
            )
        with self.assertRaises(TypeError):
            inspect_rotated_chain(
                (self.s0,), (r for r in ()), self.key_a
            )

    def test_wrong_receipt_element_type_raises_type_error(self):
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_chain((bad,), (), self.key_a)
                with self.assertRaises(TypeError):
                    inspect_rotated_chain(
                        (self.s0, bad), (self.r0,), self.key_a
                    )

    def test_wrong_rotation_element_type_raises_type_error(self):
        for bad in (b"bytes", "rotation", None, 1, object(), [self.r0]):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_chain(
                        (self.s0, self.s1), (bad,), self.key_a
                    )

    def test_inner_three_tuple_raises_value_error(self):
        # A tuple element of the wrong arity is verify_rotation's nested
        # ValueError and must propagate unchanged.
        with self.assertRaises(ValueError):
            inspect_rotated_chain(
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
            inspect_rotated_chain((bypassed,), (), self.key_a)

    def test_key_type_raises_type_error(self):
        for bad in ("k", bytearray(self.key_a), None, 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotated_chain(
                        (self.s0,), (), bad
                    )

    def test_key_length_raises_value_error(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    inspect_rotated_chain(
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
        report = inspect_rotated_chain(
            self.receipts, self.rotations, self.key_a
        )
        self.assertEqual(report, _OK)
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

    def test_read_only_also_on_failing_path(self):
        other = _rotation(_SEED_A, _SEED_B, 2)
        rotations = (other,)
        rotation_bytes_before = tuple(encode_rotation(r) for r in rotations)
        self.assertEqual(
            inspect_rotated_chain(
                (self.s0, self.s1), rotations, self.key_a
            ),
            ContinuationChainReport(False, 1, "rotation_link"),
        )
        self.assertEqual(
            tuple(encode_rotation(r) for r in rotations),
            rotation_bytes_before,
        )

    def test_three_parameters_have_no_defaults(self):
        with self.assertRaises(TypeError):
            inspect_rotated_chain((self.s0,), ())  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            inspect_rotated_chain((self.s0,))  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            inspect_rotated_chain()  # type: ignore[call-arg]


if __name__ == "__main__":
    unittest.main()
