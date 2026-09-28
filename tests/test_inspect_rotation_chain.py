import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    ContinuationChainReport,
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

    def test_success_report_shape(self):
        report = inspect_rotation_chain(self.items, self.initial_key)
        self.assertEqual(report, ContinuationChainReport(True, None, None))
        self.assertIsInstance(report, ContinuationChainReport)
        self.assertTrue(report.ok)
        self.assertIsNone(report.index)
        self.assertIsNone(report.code)
        self.assertEqual((report.ok, report.index, report.code), (True, None, None))

    def test_single_record_chain_reports_ok(self):
        # A one-record chain is diagnosed record by record like any chain.
        self.assertEqual(
            inspect_rotation_chain((self.r1,), self.initial_key),
            ContinuationChainReport(True, None, None),
        )

    def test_multi_hop_chain_reports_ok(self):
        self.assertEqual(
            inspect_rotation_chain(self.items, self.initial_key),
            ContinuationChainReport(True, None, None),
        )

    def test_empty_prefix_first_hop_reports_ok(self):
        first = AuditLog().rotate_signer(_SEED_A, _SEED_B)
        self.assertEqual(
            inspect_rotation_chain((first, self.r2, self.r3), self.initial_key),
            ContinuationChainReport(True, None, None),
        )

    def test_success_iff_bool_verifier_true(self):
        chains = [
            (self.r1,),
            (self.r1, self.r2),
            self.items,
        ]
        for chain in chains:
            report = inspect_rotation_chain(chain, self.initial_key)
            self.assertEqual(report, ContinuationChainReport(True, None, None))
            self.assertIs(verify_rotation_chain(chain, self.initial_key), True)

    def test_wrong_initial_key_reports_rotation_at_zero(self):
        self.assertEqual(
            inspect_rotation_chain(self.items, self.other_key),
            ContinuationChainReport(False, 0, "rotation"),
        )

    def test_single_bad_record_reports_rotation_at_zero(self):
        old, new_key, new, _ = self.r1
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotation_chain((forged,), self.initial_key),
            ContinuationChainReport(False, 0, "rotation"),
        )

    def test_reordered_records_report_rotation_at_first_record(self):
        # The second hop is presented first and cannot verify against A; the
        # later genuine records are never reached.
        self.assertEqual(
            inspect_rotation_chain(
                (self.r2, self.r1, self.r3), self.initial_key
            ),
            ContinuationChainReport(False, 0, "rotation"),
        )
        self.assertEqual(
            inspect_rotation_chain(
                (self.r3, self.r2, self.r1), self.initial_key
            ),
            ContinuationChainReport(False, 0, "rotation"),
        )

    def test_skipping_a_hop_reports_rotation_at_its_index(self):
        # r3 is C->D; without the B->C hop it is presented against B and
        # fails verify_rotation at position 1.
        self.assertEqual(
            inspect_rotation_chain((self.r1, self.r3), self.initial_key),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_tampered_first_auth_reports_rotation_at_zero(self):
        old, new_key, new, _ = self.r1
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotation_chain(
                (forged, self.r2, self.r3), self.initial_key
            ),
            ContinuationChainReport(False, 0, "rotation"),
        )

    def test_tampered_later_record_reports_rotation_at_its_index(self):
        old, new_key, new, _ = self.r2
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotation_chain((self.r1, forged, self.r3), self.initial_key),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_failed_record_stops_all_later_checks(self):
        # Position 1 fails "rotation"; the repeated record at position 2 is
        # never examined, so "rotation_duplicate" at 2 is not reported.
        old, new_key, new, _ = self.r2
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotation_chain(
                (self.r1, forged, self.r1), self.initial_key
            ),
            ContinuationChainReport(False, 1, "rotation"),
        )

    def test_duplicate_adjacent_record_reports_duplicate(self):
        self.assertEqual(
            inspect_rotation_chain((self.r1, self.r1), self.initial_key),
            ContinuationChainReport(False, 1, "rotation_duplicate"),
        )

    def test_duplicate_non_adjacent_record_reports_duplicate(self):
        self.assertEqual(
            inspect_rotation_chain(
                (self.r1, self.r2, self.r1), self.initial_key
            ),
            ContinuationChainReport(False, 2, "rotation_duplicate"),
        )

    def test_duplicate_index_is_record_tuple_position(self):
        self.assertEqual(
            inspect_rotation_chain(
                (self.r1, self.r2, self.r3, self.r2), self.initial_key
            ),
            ContinuationChainReport(False, 3, "rotation_duplicate"),
        )

    def test_duplicate_checked_before_rotation_at_same_record(self):
        # At position 2 the record repeats r1 and also fails verify_rotation
        # against the key currently trusted (r2's new_key); the duplicate
        # comparison comes first, exactly as in verify_rotation_chain.
        self.assertEqual(
            inspect_rotation_chain(
                (self.r1, self.r2, self.r1), self.initial_key
            ),
            ContinuationChainReport(False, 2, "rotation_duplicate"),
        )

    def test_only_earliest_problem_is_reported(self):
        # Position 0 already fails under the wrong key; a later duplicate and
        # a later tampered record are both masked.
        old, new_key, new, _ = self.r3
        forged = (old, new_key, new, b"\x00" * 64)
        self.assertEqual(
            inspect_rotation_chain(
                (self.r1, self.r2, forged, self.r1), self.other_key
            ),
            ContinuationChainReport(False, 0, "rotation"),
        )

    def test_repeated_diagnostics_are_equal(self):
        first = inspect_rotation_chain(self.items, self.initial_key)
        second = inspect_rotation_chain(self.items, self.initial_key)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        bad = inspect_rotation_chain(
            (self.r1, self.r2, self.r1), self.initial_key
        )
        self.assertEqual(
            bad,
            inspect_rotation_chain(
                (self.r1, self.r2, self.r1), self.initial_key
            ),
        )

    def test_reports_agree_with_bool_verifier_on_every_input(self):
        old2, new_key2, new2, _ = self.r2
        forged2 = (old2, new_key2, new2, b"\x00" * 64)
        chains = [
            (self.r1,),
            (self.r2,),
            self.items,
            (self.r1, self.r1),
            (self.r1, self.r2, self.r1),
            (self.r1, self.r2, self.r3, self.r2),
            (self.r1, forged2, self.r3),
            (self.r2, self.r1),
            (self.r1, self.r3),
            (forged2,),
        ]
        keys = (self.initial_key, self.other_key)
        for chain in chains:
            for key in keys:
                report = inspect_rotation_chain(chain, key)
                self.assertIs(
                    report.ok,
                    verify_rotation_chain(chain, key),
                    msg=(chain, key),
                )
                if report.ok:
                    self.assertIsNone(report.index)
                    self.assertIsNone(report.code)
                else:
                    self.assertIsNotNone(report.index)
                    self.assertGreaterEqual(report.index, 0)
                    self.assertIn(
                        report.code, ("rotation", "rotation_duplicate")
                    )

    def test_non_tuple_raises_type_error(self):
        for bad in ([], None, "x", object(), [self.r1], (x for x in (self.r1,))):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotation_chain(bad, self.initial_key)

    def test_empty_tuple_raises_value_error(self):
        with self.assertRaises(ValueError):
            inspect_rotation_chain((), self.initial_key)

    def test_wrong_element_type_raises_type_error(self):
        for bad in (b"bytes", "record", None, 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotation_chain((bad,), self.initial_key)
                with self.assertRaises(TypeError):
                    inspect_rotation_chain((self.r1, bad), self.initial_key)

    def test_element_wrong_length_raises_value_error(self):
        with self.assertRaises(ValueError):
            inspect_rotation_chain((self.r1[:3],), self.initial_key)
        with self.assertRaises(ValueError):
            inspect_rotation_chain((self.r1 + ("extra",),), self.initial_key)

    def test_key_type_raises_type_error(self):
        for bad in ("0" * 32, bytearray(self.initial_key), None, 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    inspect_rotation_chain(self.items, bad)

    def test_key_length_raises_value_error(self):
        for bad in (b"", self.initial_key[:-1], self.initial_key + b"\x00"):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    inspect_rotation_chain(self.items, bad)

    def test_nested_shape_errors_propagate_from_verify_rotation(self):
        old, new_key, new, auth = self.r1
        # verify_rotation's own TypeError: old is not a SignedRoot.
        with self.assertRaises(TypeError):
            inspect_rotation_chain(
                ((b"old", new_key, new, auth),), self.initial_key
            )
        # verify_rotation's own TypeError: auth is not bytes.
        with self.assertRaises(TypeError):
            inspect_rotation_chain(
                ((old, new_key, new, "auth"),), self.initial_key
            )
        # verify_rotation's own ValueError: new_key is not 32 bytes.
        with self.assertRaises(ValueError):
            inspect_rotation_chain(
                ((old, new_key[:-1], new, auth),), self.initial_key
            )
        # verify_rotation's own ValueError: auth is not 64 bytes.
        with self.assertRaises(ValueError):
            inspect_rotation_chain(
                ((old, new_key, new, auth[:-1]),), self.initial_key
            )

    def test_nested_structural_violation_does_not_become_report(self):
        # A bypassed frozen field of the wrong kind must surface
        # verify_rotation / verify_signed_root's own exception rather than a
        # "rotation" failure report.
        old, new_key, new, auth = self.r1
        broken_old = type(old)(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            old.signature,
        )
        object.__setattr__(broken_old, "signature", "not-bytes")
        with self.assertRaises(TypeError):
            inspect_rotation_chain(
                ((broken_old, new_key, new, auth),), self.initial_key
            )

    def test_call_is_read_only(self):
        before = encode_rotations(self.items)
        inspect_rotation_chain(self.items, self.initial_key)
        inspect_rotation_chain(self.items, self.other_key)
        inspect_rotation_chain(
            (self.r1, self.r2, self.r1), self.initial_key
        )
        self.assertEqual(encode_rotations(self.items), before)
        self.assertEqual(self.items, (self.r1, self.r2, self.r3))

    def test_bool_verifier_unchanged(self):
        # The existing entry point still returns a plain bool on every case.
        self.assertIs(
            verify_rotation_chain(self.items, self.initial_key), True
        )
        self.assertIs(
            verify_rotation_chain(self.items, self.other_key), False
        )
        self.assertIs(
            verify_rotation_chain(
                (self.r1, self.r1), self.initial_key
            ),
            False,
        )


if __name__ == "__main__":
    unittest.main()
