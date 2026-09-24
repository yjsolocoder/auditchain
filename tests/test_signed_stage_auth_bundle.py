import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    Entry,
    SignedStageAuthBundle,
    SignedStageVerifier,
    StageVerifier,
    verify_auth_stage,
    verify_signed_stage_auth_bundle,
    verify_signed_stage_verifier,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(records=5, key=_KEY, hash_name="sha256", evolve=1):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(records):
        log.append(f"record-{record}")
    for _ in range(evolve):
        log.rotate_key()
    return log


def _bundle(seed=_SEED_A, key=_KEY, hash_name="sha256", indices=(0, 2, 4), records=5, evolve=1):
    log = _log(records=records, key=key, hash_name=hash_name, evolve=evolve)
    receipt = log.export_signed_stage_verifier(seed)
    items = log.auth_batch(indices)
    return SignedStageAuthBundle(receipt, hash_name, items)


class SignedStageAuthBundleTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        bundle = _bundle()
        again = SignedStageAuthBundle(bundle.verifier, bundle.hash_name, bundle.items)
        self.assertEqual(bundle, again)
        self.assertEqual(bundle.verifier, again.verifier)
        self.assertEqual(bundle.hash_name, "sha256")
        self.assertIsInstance(bundle.items, tuple)
        self.assertNotEqual(bundle, _bundle(indices=(1,)))

    def test_frozen(self):
        bundle = _bundle()
        for field in ("verifier", "hash_name", "items"):
            with self.assertRaises(Exception):
                setattr(bundle, field, None)

    def test_container_type_errors(self):
        bundle = _bundle()
        with self.assertRaises(TypeError):
            SignedStageAuthBundle("not-a-verifier", bundle.hash_name, bundle.items)
        with self.assertRaises(TypeError):
            SignedStageAuthBundle(bundle.verifier, 1, bundle.items)
        with self.assertRaises(TypeError):
            SignedStageAuthBundle(bundle.verifier, bundle.hash_name, list(bundle.items))

    def test_unknown_hash_name_raises_value_error(self):
        bundle = _bundle()
        with self.assertRaises(ValueError):
            SignedStageAuthBundle(bundle.verifier, "not-a-hash", bundle.items)


class VerifySignedStageAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_genuine_bundle_verifies_per_item(self):
        bundle = _bundle()
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.public_key),
            (True, True, True),
        )

    def test_empty_bundle(self):
        bundle = _bundle(indices=())
        self.assertEqual(verify_signed_stage_auth_bundle(bundle, self.public_key), ())
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.other_public_key), ()
        )

    def test_untrusted_public_key_fails_per_item(self):
        bundle = _bundle()
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.other_public_key),
            (False, False, False),
        )

    def test_tampered_signature_fails_per_item(self):
        bundle = _bundle()
        forged = SignedStageAuthBundle(
            SignedStageVerifier(1, bundle.verifier.verifier, b"\x00" * 64),
            bundle.hash_name,
            bundle.items,
        )
        self.assertEqual(
            verify_signed_stage_auth_bundle(forged, self.public_key),
            (False, False, False),
        )

    def test_tampered_tag_fails_at_its_position(self):
        bundle = _bundle()
        entry, tag = bundle.items[1]
        bad_tag = AuthTag(tag.stage, bytes([tag.tag[0] ^ 1]) + tag.tag[1:])
        items = bundle.items[:1] + ((entry, bad_tag),) + bundle.items[2:]
        forged = SignedStageAuthBundle(bundle.verifier, bundle.hash_name, items)
        self.assertEqual(
            verify_signed_stage_auth_bundle(forged, self.public_key),
            (True, False, True),
        )

    def test_tampered_entry_fails_at_its_position(self):
        bundle = _bundle()
        entry, tag = bundle.items[0]
        bad_entry = Entry(
            entry.index, b"forged", entry.previous_hash, entry.entry_hash
        )
        items = ((bad_entry, tag),) + bundle.items[1:]
        forged = SignedStageAuthBundle(bundle.verifier, bundle.hash_name, items)
        results = verify_signed_stage_auth_bundle(forged, self.public_key)
        self.assertEqual(results[0], False)
        self.assertEqual(results[1:], (True, True))

    def test_tag_before_delivery_stage_fails_at_its_position(self):
        # A genuine tag minted before the delivery stage never verifies
        # against the later material, exactly as verify_auth_stage rules.
        log = _log(evolve=0)
        tag = log.auth(0)  # minted at stage 0
        receipt = log.export_signed_stage_verifier(_SEED_A)  # delivered at stage 1
        bundle = SignedStageAuthBundle(receipt, "sha256", ((log.entry(0), tag),))
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.public_key), (False,)
        )

    def test_hash_name_mismatch_fails_per_item(self):
        # A bundle whose batch algorithm disagrees with the signed verifier's
        # algorithm can only be built by hand; every item fails rather than
        # raising.
        bundle = _bundle()
        forged = SignedStageAuthBundle(bundle.verifier, "sha512", bundle.items)
        self.assertEqual(
            verify_signed_stage_auth_bundle(forged, self.public_key),
            (False, False, False),
        )

    def test_type_errors(self):
        for bad in (None, "bundle", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                verify_signed_stage_auth_bundle(bad, self.public_key)
        bundle = _bundle()
        for bad_key in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError):
                verify_signed_stage_auth_bundle(bundle, bad_key)

    def test_public_key_length_raises_value_error(self):
        bundle = _bundle()
        for bad_key in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                verify_signed_stage_auth_bundle(bundle, bad_key)

    def test_bypassed_container_fields_raise_type_error(self):
        bundle = _bundle()
        for field, value in (
            ("verifier", "not-a-verifier"),
            ("hash_name", 1),
            ("items", list(bundle.items)),
        ):
            forged = SignedStageAuthBundle.__new__(SignedStageAuthBundle)
            object.__setattr__(forged, "verifier", bundle.verifier)
            object.__setattr__(forged, "hash_name", bundle.hash_name)
            object.__setattr__(forged, "items", bundle.items)
            object.__setattr__(forged, field, value)
            with self.assertRaises(TypeError, msg=field):
                verify_signed_stage_auth_bundle(forged, self.public_key)

    def test_structurally_invalid_items_raise(self):
        bundle = _bundle()
        entry, tag = bundle.items[0]
        # Wrong digest width.
        bad_tag = AuthTag(tag.stage, tag.tag[:-1])
        forged = SignedStageAuthBundle(
            bundle.verifier,
            bundle.hash_name,
            ((entry, bad_tag),) + bundle.items[1:],
        )
        with self.assertRaises(ValueError):
            verify_signed_stage_auth_bundle(forged, self.public_key)
        # Non-tuple item.
        forged = SignedStageAuthBundle(
            bundle.verifier,
            bundle.hash_name,
            (["not-a-pair"],) + bundle.items[1:],
        )
        with self.assertRaises(TypeError):
            verify_signed_stage_auth_bundle(forged, self.public_key)

    def test_non_ascending_indices_raise_value_error(self):
        bundle = _bundle()
        forged = SignedStageAuthBundle(
            bundle.verifier,
            bundle.hash_name,
            (bundle.items[1], bundle.items[0]) + bundle.items[2:],
        )
        with self.assertRaises(ValueError):
            verify_signed_stage_auth_bundle(forged, self.public_key)

    def test_non_consecutive_stages_raise_value_error(self):
        bundle = _bundle()
        forged = SignedStageAuthBundle(
            bundle.verifier,
            bundle.hash_name,
            (bundle.items[0], bundle.items[2]),
        )
        with self.assertRaises(ValueError):
            verify_signed_stage_auth_bundle(forged, self.public_key)

    def test_call_is_read_only(self):
        bundle = _bundle()
        snapshot = (bundle.verifier, bundle.hash_name, bundle.items)
        verify_signed_stage_auth_bundle(bundle, self.public_key)
        self.assertEqual((bundle.verifier, bundle.hash_name, bundle.items), snapshot)


class SignedStageAuthBundleIssuanceTest(unittest.TestCase):
    def _snapshot(self, log):
        return (
            log.stage,
            log._key,
            dict(log._tags),
            log.head,
            len(log),
            log._verifier_exported,
        )

    def test_returns_frozen_bundle_equal_to_two_step_issuance(self):
        bundle = _log().signed_stage_auth_bundle((4, 0, 2), _SEED_A)
        self.assertIsInstance(bundle, SignedStageAuthBundle)
        self.assertEqual(bundle, _bundle(indices=(0, 2, 4)))
        self.assertEqual(bundle.hash_name, "sha256")
        self.assertIsInstance(bundle.items, tuple)
        self.assertEqual([entry.index for entry, _ in bundle.items], [0, 2, 4])

    def test_verifier_is_signed_current_stage_material(self):
        log = _log(evolve=2)
        bundle = log.signed_stage_auth_bundle((0, 2, 4), _SEED_A)
        self.assertIsInstance(bundle.verifier, SignedStageVerifier)
        self.assertEqual(bundle.verifier.version, 1)
        self.assertIsInstance(bundle.verifier.verifier, StageVerifier)
        self.assertEqual(bundle.verifier.verifier.stage, 2)
        self.assertEqual(bundle.verifier.verifier.hash_name, "sha256")
        self.assertEqual(len(bundle.verifier.signature), 64)
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, _public_key(_SEED_A)),
            (True, True, True),
        )

    def test_signature_reuses_signed_stage_verifier_domain(self):
        # The embedded signature is byte-for-byte the one
        # export_signed_stage_verifier makes from the same state; no new
        # signing message exists.
        bundle = _log().signed_stage_auth_bundle((0, 2, 4), _SEED_A)
        self.assertEqual(bundle.verifier, _bundle().verifier)
        self.assertTrue(
            verify_signed_stage_verifier(bundle.verifier, _public_key(_SEED_A))
        )

    def test_stages_run_from_delivery_and_items_equal_consecutive_auth(self):
        log = _log(evolve=2)
        delivery_stage = log.stage
        bundle = log.signed_stage_auth_bundle((4, 0, 2), _SEED_A)
        self.assertEqual(
            [tag.stage for _, tag in bundle.items],
            [delivery_stage, delivery_stage + 1, delivery_stage + 2],
        )
        # Byte-for-byte what consecutive ascending auth() calls produce from
        # the same starting state.
        reference = _log(evolve=2)
        reference.export_signed_stage_verifier(_SEED_A)
        expected = tuple(
            (reference.entry(i), reference.auth(i)) for i in (0, 2, 4)
        )
        self.assertEqual(bundle.items, expected)
        self.assertEqual(log.stage, delivery_stage + 3)
        self.assertEqual(reference.stage, delivery_stage + 3)
        self.assertEqual(sorted(log._tags), [0, 2, 4])
        for index, (_, tag) in zip((0, 2, 4), bundle.items):
            self.assertEqual(log._tags[index], tag)

    def test_items_verify_offline_against_delivered_verifier(self):
        bundle = _log().signed_stage_auth_bundle((4, 1, 3), _SEED_A)
        self.assertEqual(
            tuple(
                verify_auth_stage(entry, tag, bundle.verifier.verifier)
                for entry, tag in bundle.items
            ),
            (True, True, True),
        )

    def test_accepts_a_generator_and_sorts_ascending(self):
        bundle = _log().signed_stage_auth_bundle((i for i in (4, 0)), _SEED_A)
        self.assertEqual([entry.index for entry, _ in bundle.items], [0, 4])

    def test_empty_selection_delivers_material_without_advancing_stage(self):
        log = _log()
        stage = log.stage
        bundle = log.signed_stage_auth_bundle((), _SEED_A)
        self.assertEqual(bundle.items, ())
        self.assertEqual(log.stage, stage)
        self.assertTrue(
            verify_signed_stage_verifier(bundle.verifier, _public_key(_SEED_A))
        )
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, _public_key(_SEED_A)), ()
        )

    def test_issuance_is_repeatable(self):
        # Unlike the stage-0 bundle, no one-shot eligibility is consumed.
        log = _log()
        first = log.signed_stage_auth_bundle((1,), _SEED_A)
        second = log.signed_stage_auth_bundle((2,), _SEED_A)
        self.assertEqual(first.verifier.verifier.stage, 1)
        self.assertEqual(second.verifier.verifier.stage, 2)
        self.assertEqual(second.items[0][1].stage, 2)
        self.assertEqual(log.stage, 3)
        self.assertEqual(
            verify_signed_stage_auth_bundle(second, _public_key(_SEED_A)), (True,)
        )

    def test_initial_stage_raises_value_error(self):
        log = _log(evolve=0)
        before = self._snapshot(log)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle((0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle((), _SEED_A)
        self.assertEqual(self._snapshot(log), before)

    def test_keyless_mode_raises_value_error(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle((0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle((), _SEED_A)

    def test_private_key_type_errors(self):
        log = _log()
        for bad in ("0" * 32, bytearray(_SEED_A), memoryview(_SEED_A), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                log.signed_stage_auth_bundle((0,), bad)

    def test_private_key_length_raises_value_error(self):
        log = _log()
        for bad in (b"", _SEED_A[:-1], _SEED_A + b"\x00"):
            with self.assertRaises(ValueError):
                log.signed_stage_auth_bundle((0,), bad)

    def test_indices_type_errors(self):
        log = _log()
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle(5, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle(None, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle(["0"], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle([1.0], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle([True], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle([0, False], _SEED_A)

    def test_duplicate_index_raises_value_error(self):
        with self.assertRaises(ValueError):
            _log().signed_stage_auth_bundle([1, 2, 1], _SEED_A)

    def test_non_retained_index_raises_index_error(self):
        log = _log(records=5)
        with self.assertRaises(IndexError):
            log.signed_stage_auth_bundle([5], _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_stage_auth_bundle([-1], _SEED_A)
        log.prune(2, log.seal(2))
        with self.assertRaises(IndexError):
            log.signed_stage_auth_bundle([1, 3], _SEED_A)

    def test_pruned_log_selection_starts_at_delivery_stage(self):
        log = _log(records=6, evolve=1)
        log.prune(2, log.seal(2))
        bundle = log.signed_stage_auth_bundle((5, 2), _SEED_A)
        self.assertEqual([entry.index for entry, _ in bundle.items], [2, 5])
        self.assertEqual([tag.stage for _, tag in bundle.items], [1, 2])
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, _public_key(_SEED_A)),
            (True, True),
        )

    def test_stage_capacity_checked_before_signing(self):
        log = _log(records=3)
        log._stage = (1 << 64) - 1
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle((0,), _SEED_A)

    def test_failure_is_atomic(self):
        for call, error in (
            (lambda log: log.signed_stage_auth_bundle(["0"], _SEED_A), TypeError),
            (lambda log: log.signed_stage_auth_bundle([True], _SEED_A), TypeError),
            (lambda log: log.signed_stage_auth_bundle(5, _SEED_A), TypeError),
            (lambda log: log.signed_stage_auth_bundle([0, 0], _SEED_A), ValueError),
            (lambda log: log.signed_stage_auth_bundle([9], _SEED_A), IndexError),
            (lambda log: log.signed_stage_auth_bundle([-1], _SEED_A), IndexError),
            (lambda log: log.signed_stage_auth_bundle([0], "0" * 32), TypeError),
            (lambda log: log.signed_stage_auth_bundle([0], b"short"), ValueError),
        ):
            log = _log()
            before = self._snapshot(log)
            with self.assertRaises(error):
                call(log)
            self.assertEqual(self._snapshot(log), before)
            # No key evolution happened: the retry with the same selection
            # delivers a bundle starting at the same delivery stage.
            bundle = log.signed_stage_auth_bundle((0, 2, 4), _SEED_A)
            self.assertEqual([tag.stage for _, tag in bundle.items], [1, 2, 3])
            self.assertEqual(
                verify_signed_stage_auth_bundle(bundle, _public_key(_SEED_A)),
                (True, True, True),
            )

    def test_failure_does_not_touch_chain_state(self):
        log = _log()
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        for call, error in (
            (lambda: log.signed_stage_auth_bundle([9], _SEED_A), IndexError),
            (lambda: log.signed_stage_auth_bundle([0, 0], _SEED_A), ValueError),
            (lambda: log.signed_stage_auth_bundle([0], b"bad"), ValueError),
        ):
            with self.assertRaises(error):
                call()
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(len(log), 5)
        self.assertTrue(log.verify())

    def test_success_does_not_change_chain_state(self):
        log = _log()
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        log.signed_stage_auth_bundle((0, 2, 4), _SEED_A)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(len(log), 5)
        self.assertTrue(log.verify())

    def test_success_consumes_no_one_shot_eligibility(self):
        # The stage bundle is repeatable and never touches the stage-0
        # one-shot export flag.
        log = _log()
        log.signed_stage_auth_bundle((1,), _SEED_A)
        self.assertFalse(log._verifier_exported)
        log.signed_stage_auth_bundle((2,), _SEED_A)
        self.assertFalse(log._verifier_exported)

    def test_alternate_hash_algorithm(self):
        log = _log(records=3, hash_name="sha512")
        bundle = log.signed_stage_auth_bundle((2, 0), _SEED_A)
        self.assertEqual(bundle.hash_name, "sha512")
        self.assertEqual(bundle.verifier.verifier.hash_name, "sha512")
        self.assertEqual([tag.stage for _, tag in bundle.items], [1, 2])
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, _public_key(_SEED_A)),
            (True, True),
        )


if __name__ == "__main__":
    unittest.main()
