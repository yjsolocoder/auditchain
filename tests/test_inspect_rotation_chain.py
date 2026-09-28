import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    ContinuationChainReport,
    SignedRoot,
    encode_rotations,
    inspect_rotation_chain,
    verify_rotation_chain,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(2, 34))
_SEED_E = bytes(range(3, 35))


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log():
    log = AuditLog()
    for record in ("a", "b", "c", "d", "e"):
        log.append(record)
    return log


class InspectRotationChainTest(unittest.TestCase):
    def setUp(self):
        self.log = _log()
        # Three hops over distinct prefixes: A->B, B->C, C->D.
        self.r1 = self.log.rotate_signer(_SEED_A, _SEED_B, 2)
        self.r2 = self.log.rotate_signer(_SEED_B, _SEED_C, 3)
        self.r3 = self.log.rotate_signer(_SEED_C, _SEED_D, 5)
        self.items = (self.r1, self.r2, self.r3)
        self.initial_key = _public_key(_SEED_A)
        self.other_key = _public_key(_SEED_E)

    def _forged_auth(self, item):
        old, new_key, new, _ = item
        return old, new_key, new, b"\x00" * 64

    def test_success_report_shape(self):
        report = inspect_rotation_chain(self.items, self.initial_key)
        self.assertEqual(report, ContinuationChainReport(True, None, None))
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)
        self.assertEqual((report.ok, report.index, report.code), (True, None, None))

    def test_single_record_chain_reports_ok(self):
        self.assertEqual(
            inspect_rotation_chain((self.r1,), self.initial_key),
            ContinuationChainReport(True, None, None),
        )

    def test_multi_hop_chain_reports_ok(self):
        self.assertEqual(
            inspect_rotation_chain(self.items, self.initial_key),
            ContinuationChainReport(True, None, None),
        )

    def test_success_agrees_with_bool_verifier(self):
        self.assertTrue(verify_rotation_chain(self.items, self.initial_key))
        self.assertEqual(
            inspect_rotation_chain(self.items, self.initial_key),
            ContinuationChainReport(True, None, None),
        )

    def test_wrong_initial_key_reports_rotation_at_zero(self):
        self.assertEqual(
            inspect_rotation_chain(self.items, self.other_key),
            ContinuationChainReport(False, 0, "rotation"),
        )

    def test_reordered_records_report_rotation_at_first(self):
        # The second hop is presented first and cannot verify against A.
        self.assertEqual(
            inspect_rotation_chain((self.r2, self.r1, self.r3), self.initial_key),
            ContinuationChainReport(False, 0, "rotation"),
        )
        self.assertEqual(
            inspect_rotation_chain((self.r3, self.r2, self.r1), self.initial_key),
            ContinuationChainReport(False, 0, "rotation"),
        )

    def test_skipping_a_hop_reports_rotation_at_its_index(self):
        # r3 is C->D; without the B->C hop it is presented against B and
        # fails at its own position, not at the genuine first record.
        self.assertEqual(
            inspect_rotation_chain((self.r1, self.r3), self.initial_key),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_duplicate_adjacent_record_reports_rotation_duplicate(self):
        self.assertEqual(
            inspect_rotation_chain((self.r1, self.r1), self.initial_key),
            ContinuationChainReport(False, 1, "rotation_duplicate"),
        )

    def test_duplicate_non_adjacent_record_reports_rotation_duplicate(self):
        self.assertEqual(
            inspect_rotation_chain(
                (self.r1, self.r2, self.r1), self.initial_key
            ),
            ContinuationChainReport(False, 2, "rotation_duplicate"),
        )
        self.assertEqual(
            inspect_rotation_chain(
                (self.r1, self.r2, self.r3, self.r2), self.initial_key
            ),
            ContinuationChainReport(False, 3, "rotation_duplicate"),
        )

    def test_tampered_first_auth_reports_rotation_at_zero(self):
        forged = self._forged_auth(self.r1)
        self.assertEqual(
            inspect_rotation_chain((forged, self.r2, self.r3), self.initial_key),
            ContinuationChainReport(False, 0, "rotation"),
        )

    def test_tampered_later_record_reports_rotation_at_its_index(self):
        forged = self._forged_auth(self.r2)
        self.assertEqual(
            inspect_rotation_chain((self.r1, forged, self.r3), self.initial_key),
            ContinuationChainReport(False, 1, "rotation"),
        )
        forged = self._forged_auth(self.r3)
        self.assertEqual(
            inspect_rotation_chain((self.r1, self.r2, forged), self.initial_key),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_duplicate_checked_before_rotation_at_same_record(self):
        # At index 2 the repeated r1 is both a duplicate of an earlier record
        # and unverifiable against the key currently trusted (C); the
        # duplicate check fires first, so the code is "rotation_duplicate".
        self.assertEqual(
            inspect_rotation_chain(
                (self.r1, self.r2, self.r1), self.initial_key
            ),
            ContinuationChainReport(False, 2, "rotation_duplicate"),
        )

    def test_only_earliest_problem_is_reported(self):
        # A broken record at index 1 masks a duplicate at index 2.
        forged = self._forged_auth(self.r2)
        self.assertEqual(
            inspect_rotation_chain(
                (self.r1, forged, self.r1), self.initial_key
            ),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_first_failure_masks_every_later_record(self):
        # The first record fails under the wrong key; the duplicate that the
        # genuine r1 would show at index 1 is never reached.
        forged = self._forged_auth(self.r1)
        self.assertEqual(
            inspect_rotation_chain((forged, self.r1), self.initial_key),
            ContinuationChainReport(False, 0, "rotation"),
        )
        self.assertEqual(
            inspect_rotation_chain((self.r2, self.r1, self.r1), self.initial_key),
            ContinuationChainReport(False, 0, "rotation"),
        )

    def test_report_ok_iff_bool_verifier_is_true(self):
        chains = [
            (self.r1,),
            self.items,
            (self.r2, self.r1, self.r3),
            (self.r3, self.r2, self.r1),
            (self.r1, self.r3),
            (self.r1, self.r1),
            (self.r1, self.r2, self.r1),
            (self.r1, self.r2, self.r3, self.r2),
            (self._forged_auth(self.r1), self.r2, self.r3),
            (self.r1, self._forged_auth(self.r2), self.r3),
            (self.r1, self.r2, self._forged_auth(self.r3)),
        ]
        for chain in chains:
            with self.subTest(length=len(chain)):
                report = inspect_rotation_chain(chain, self.initial_key)
                self.assertIs(
                    report.ok,
                    verify_rotation_chain(chain, self.initial_key),
                )
        # And under the untrusted anchor every chain fails at index 0.
        for chain in ((self.r1,), self.items):
            with self.subTest(length=len(chain)):
                self.assertEqual(
                    inspect_rotation_chain(chain, self.other_key),
                    ContinuationChainReport(False, 0, "rotation"),
                )
                self.assertFalse(
                    verify_rotation_chain(chain, self.other_key)
                )

    def test_diagnosis_is_deterministic(self):
        self.assertEqual(
            inspect_rotation_chain(self.items, self.initial_key),
            inspect_rotation_chain(self.items, self.initial_key),
        )
        failing = (self.r1, self._forged_auth(self.r2), self.r1)
        self.assertEqual(
            inspect_rotation_chain(failing, self.initial_key),
            inspect_rotation_chain(failing, self.initial_key),
        )

    def test_non_tuple_raises_type_error(self):
        for bad in ([], None, "x", object(), [self.r1]):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotation_chain(bad, self.initial_key)

    def test_generator_raises_type_error(self):
        gen = (item for item in self.items)
        with self.assertRaises(TypeError):
            inspect_rotation_chain(gen, self.initial_key)

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            inspect_rotation_chain((), self.initial_key)

    def test_wrong_element_type_raises_type_error(self):
        for bad in ("x", b"bytes", None, 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotation_chain((bad,), self.initial_key)
                # The element container types are checked up front, so a bad
                # element later in the chain raises even after genuine records.
                with self.assertRaises(TypeError):
                    inspect_rotation_chain(
                        (self.r1, bad), self.initial_key
                    )

    def test_wrong_tuple_length_raises_value_error(self):
        for bad in (
            self.r1[:3],
            self.r1[:2],
            self.r1 + (b"extra",),
        ):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    inspect_rotation_chain((bad,), self.initial_key)
        with self.assertRaises(ValueError):
            inspect_rotation_chain(
                (self.r1, self.r2[:3]), self.initial_key
            )

    def test_wrong_field_type_raises_type_error(self):
        old, new_key, new, auth = self.r1
        with self.assertRaises(TypeError):
            inspect_rotation_chain(
                ((old, bytearray(new_key), new, auth),), self.initial_key
            )
        with self.assertRaises(TypeError):
            inspect_rotation_chain(
                ((old, new_key, new, bytearray(auth)),), self.initial_key
            )

    def test_key_validation(self):
        with self.assertRaises(TypeError):
            inspect_rotation_chain(self.items, "0" * 32)
        with self.assertRaises(TypeError):
            inspect_rotation_chain(self.items, bytearray(self.initial_key))
        with self.assertRaises(ValueError):
            inspect_rotation_chain(self.items, self.initial_key[:-1])
        with self.assertRaises(ValueError):
            inspect_rotation_chain(self.items, self.initial_key + b"\x00")

    def test_nested_structural_violation_propagates(self):
        # Bypassing the frozen constructor leaves a structurally corrupt
        # SignedRoot; the nested verifier raises ValueError, which must
        # propagate rather than become a "rotation" report.
        old, new_key, new, auth = self.r1
        corrupted = object.__new__(SignedRoot)
        object.__setattr__(corrupted, "version", 1)
        object.__setattr__(corrupted, "hash_name", "sha256")
        object.__setattr__(corrupted, "size", new.size)
        object.__setattr__(corrupted, "root", new.root)
        object.__setattr__(corrupted, "head", new.head)
        object.__setattr__(corrupted, "signature", b"\x00" * 32)
        with self.assertRaises(ValueError):
            inspect_rotation_chain(
                ((old, new_key, corrupted, auth),), self.initial_key
            )

    def test_call_is_read_only(self):
        failing = (self.r1, self._forged_auth(self.r2), self.r3)
        before_good = encode_rotations(self.items)
        before_bad = encode_rotations(failing)
        inspect_rotation_chain(self.items, self.initial_key)
        inspect_rotation_chain(failing, self.initial_key)
        inspect_rotation_chain(self.items, self.other_key)
        self.assertEqual(encode_rotations(self.items), before_good)
        self.assertEqual(encode_rotations(failing), before_bad)
        self.assertEqual(self.items, (self.r1, self.r2, self.r3))
        self.assertEqual(failing, (self.r1, self._forged_auth(self.r2), self.r3))

    def test_bool_verifier_unchanged(self):
        # The existing entry point still returns a plain bool on every case.
        self.assertIs(
            verify_rotation_chain(self.items, self.initial_key), True
        )
        self.assertIs(
            verify_rotation_chain(self.items, self.other_key), False
        )
        self.assertIs(
            verify_rotation_chain((self.r1, self.r1), self.initial_key), False
        )


if __name__ == "__main__":
    unittest.main()
