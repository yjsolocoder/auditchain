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


def _evolved_log(evolutions=3, records=6, key=_KEY, hash_name="sha256"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(records):
        log.append(f"record-{record}")
    for index in range(evolutions):
        log.auth(index)
    return log


def _bundle(
    seed=_SEED_A,
    key=_KEY,
    hash_name="sha256",
    evolutions=3,
    records=6,
    indices=(3, 5),
):
    # export_signed_stage_verifier is repeatable and read-only, so the
    # two-step reference can share a log with auth_batch.
    log = _evolved_log(evolutions, records, key=key, hash_name=hash_name)
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
        self.assertNotEqual(bundle, _bundle(indices=(4,)))

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


class IssuedSignedStageAuthBundleTest(unittest.TestCase):
    def _snapshot(self, log):
        return (
            log.stage,
            log._key,
            dict(log._tags),
            log.head,
            len(log),
            log._verifier_exported,
            log._retain_from,
        )

    def test_returns_frozen_bundle_equal_to_two_step_issuance(self):
        log = _evolved_log()
        bundle = log.signed_stage_auth_bundle((5, 3), _SEED_A)
        self.assertIsInstance(bundle, SignedStageAuthBundle)
        self.assertEqual(bundle, _bundle(indices=(3, 5)))
        self.assertEqual(bundle.hash_name, "sha256")
        self.assertIsInstance(bundle.items, tuple)
        self.assertEqual([entry.index for entry, _ in bundle.items], [3, 5])

    def test_verifier_is_signed_current_stage_material(self):
        log = _evolved_log(evolutions=3)
        bundle = log.signed_stage_auth_bundle((3, 5), _SEED_A)
        self.assertIsInstance(bundle.verifier, SignedStageVerifier)
        self.assertEqual(bundle.verifier.version, 1)
        self.assertEqual(bundle.verifier.verifier.stage, 3)
        self.assertEqual(bundle.verifier.verifier.hash_name, "sha256")
        self.assertEqual(len(bundle.verifier.signature), 64)
        self.assertEqual(
            bundle.verifier,
            _evolved_log(evolutions=3).export_signed_stage_verifier(_SEED_A),
        )
        self.assertTrue(
            verify_signed_stage_verifier(bundle.verifier, _public_key(_SEED_A))
        )

    def test_tags_run_from_delivery_stage_in_ascending_index_order(self):
        log = _evolved_log(evolutions=3)
        bundle = log.signed_stage_auth_bundle((5, 3), _SEED_A)
        self.assertEqual([tag.stage for _, tag in bundle.items], [3, 4])
        self.assertEqual(log.stage, 5)
        self.assertEqual(sorted(log._tags)[-2:], [3, 5])
        for index, (_, tag) in zip((3, 5), bundle.items):
            self.assertEqual(log._tags[index], tag)

    def test_items_equal_consecutive_auth_from_current_state(self):
        log = _evolved_log(evolutions=2)
        bundle = log.signed_stage_auth_bundle((4, 2, 3), _SEED_A)
        # Byte-for-byte what consecutive ascending auth() calls produce from
        # the same current state on a twin log.
        reference = _evolved_log(evolutions=2)
        expected = tuple(
            (reference.entry(i), reference.auth(i)) for i in (2, 3, 4)
        )
        self.assertEqual(bundle.items, expected)
        self.assertEqual(log.stage, 5)
        self.assertEqual(reference.stage, 5)

    def test_items_verify_offline_against_delivered_material(self):
        log = _evolved_log(evolutions=2)
        bundle = log.signed_stage_auth_bundle((4, 2, 3), _SEED_A)
        self.assertEqual(
            tuple(
                verify_auth_stage(entry, tag, bundle.verifier.verifier)
                for entry, tag in bundle.items
            ),
            (True, True, True),
        )

    def test_accepts_a_generator_and_sorts_ascending(self):
        log = _evolved_log()
        bundle = log.signed_stage_auth_bundle(
            (i for i in (5, 3)), _SEED_A
        )
        self.assertEqual([entry.index for entry, _ in bundle.items], [3, 5])

    def test_empty_selection_delivers_material_without_advancing_stage(self):
        log = _evolved_log(evolutions=3)
        bundle = log.signed_stage_auth_bundle((), _SEED_A)
        self.assertEqual(bundle.items, ())
        self.assertEqual(log.stage, 3)
        self.assertEqual(bundle.verifier.verifier.stage, 3)
        self.assertTrue(
            verify_signed_stage_verifier(bundle.verifier, _public_key(_SEED_A))
        )
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, _public_key(_SEED_A)), ()
        )
        # A later batch starts at the unchanged delivery stage, and the
        # stage-0 one-shot export eligibility was never touched.
        self.assertFalse(log._verifier_exported)
        items = log.auth_batch((3,))
        self.assertEqual(items[0][1].stage, 3)
        self.assertEqual(log.stage, 4)

    def test_repeatable_delivery_from_the_same_state(self):
        log = _evolved_log(evolutions=2)
        first = log.signed_stage_auth_bundle((), _SEED_A)
        self.assertEqual(log.stage, 2)
        second = log.signed_stage_auth_bundle((), _SEED_A)
        self.assertEqual(log.stage, 2)
        self.assertEqual(first, second)
        first_batch = log.signed_stage_auth_bundle((2,), _SEED_A)
        self.assertEqual(log.stage, 3)
        second_batch = log.signed_stage_auth_bundle((3,), _SEED_A)
        self.assertEqual(log.stage, 4)
        self.assertEqual(
            [tag.stage for _, tag in first_batch.items]
            + [tag.stage for _, tag in second_batch.items],
            [2, 3],
        )

    def test_initial_stage_raises_value_error(self):
        log = AuditLog(key=_KEY)
        for record in range(3):
            log.append(f"record-{record}")
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle((0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle((), _SEED_A)

    def test_keyless_mode_raises_value_error(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle((0,), _SEED_A)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle((), _SEED_A)

    def test_private_key_type_errors(self):
        log = _evolved_log()
        for bad in ("0" * 32, bytearray(_SEED_A), memoryview(_SEED_A), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                log.signed_stage_auth_bundle((3,), bad)

    def test_private_key_length_raises_value_error(self):
        log = _evolved_log()
        for bad in (b"", _SEED_A[:-1], _SEED_A + b"\x00"):
            with self.assertRaises(ValueError):
                log.signed_stage_auth_bundle((3,), bad)

    def test_indices_type_errors(self):
        log = _evolved_log()
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle(5, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle(None, _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle(["3"], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle([3.0], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle([True], _SEED_A)
        with self.assertRaises(TypeError):
            log.signed_stage_auth_bundle([3, False], _SEED_A)

    def test_duplicate_index_raises_value_error(self):
        with self.assertRaises(ValueError):
            _evolved_log().signed_stage_auth_bundle([3, 4, 3], _SEED_A)

    def test_non_retained_index_raises_index_error(self):
        log = _evolved_log(records=5)
        with self.assertRaises(IndexError):
            log.signed_stage_auth_bundle([5], _SEED_A)
        with self.assertRaises(IndexError):
            log.signed_stage_auth_bundle([-1], _SEED_A)
        log.prune(2, log.seal(2))
        with self.assertRaises(IndexError):
            log.signed_stage_auth_bundle([1, 3], _SEED_A)

    def test_pruned_log_selection_anchors_at_current_stage(self):
        log = _evolved_log(evolutions=2, records=6)
        log.prune(2, log.seal(2))
        self.assertEqual(log._retain_from, 2)
        bundle = log.signed_stage_auth_bundle((5, 2), _SEED_A)
        self.assertEqual([entry.index for entry, _ in bundle.items], [2, 5])
        self.assertEqual([tag.stage for _, tag in bundle.items], [2, 3])
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, _public_key(_SEED_A)),
            (True, True),
        )

    def test_stage_capacity_raises_value_error(self):
        log = _evolved_log(evolutions=3, records=3)
        log._stage = (1 << 64) - 1
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle([2], _SEED_A)
        # At the last slot an empty selection still fits (stage does not
        # move), but even one more tag does not.
        empty = log.signed_stage_auth_bundle((), _SEED_A)
        self.assertEqual(empty.items, ())
        self.assertEqual(log.stage, (1 << 64) - 1)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle([2], _SEED_A)

    def test_failure_is_atomic(self):
        for call, error in (
            (lambda log: log.signed_stage_auth_bundle(["3"], _SEED_A), TypeError),
            (lambda log: log.signed_stage_auth_bundle([True], _SEED_A), TypeError),
            (lambda log: log.signed_stage_auth_bundle(5, _SEED_A), TypeError),
            (lambda log: log.signed_stage_auth_bundle([3, 3], _SEED_A), ValueError),
            (lambda log: log.signed_stage_auth_bundle([9], _SEED_A), IndexError),
            (lambda log: log.signed_stage_auth_bundle([-1], _SEED_A), IndexError),
            (lambda log: log.signed_stage_auth_bundle([3], "0" * 32), TypeError),
            (lambda log: log.signed_stage_auth_bundle([3], b"short"), ValueError),
        ):
            log = _evolved_log()
            before = self._snapshot(log)
            with self.assertRaises(error):
                call(log)
            self.assertEqual(self._snapshot(log), before)
            # No key evolution and no tags stored: the retry with the same
            # selection delivers a batch anchored at the original stage.
            bundle = log.signed_stage_auth_bundle((3, 5), _SEED_A)
            self.assertEqual([tag.stage for _, tag in bundle.items], [3, 4])
            self.assertEqual(
                verify_signed_stage_auth_bundle(bundle, _public_key(_SEED_A)),
                (True, True),
            )

    def test_initial_stage_failure_is_atomic(self):
        log = AuditLog(key=_KEY)
        log.append("a")
        before = self._snapshot(log)
        with self.assertRaises(ValueError):
            log.signed_stage_auth_bundle([0], _SEED_A)
        self.assertEqual(self._snapshot(log), before)

    def test_failure_does_not_touch_chain_state(self):
        log = _evolved_log()
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        for call, error in (
            (lambda: log.signed_stage_auth_bundle([9], _SEED_A), IndexError),
            (lambda: log.signed_stage_auth_bundle([3, 3], _SEED_A), ValueError),
            (lambda: log.signed_stage_auth_bundle([3], b"bad"), ValueError),
        ):
            with self.assertRaises(error):
                call()
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(len(log), 6)
        self.assertTrue(log.verify())

    def test_success_does_not_change_chain_state(self):
        log = _evolved_log()
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        log.signed_stage_auth_bundle((3, 5), _SEED_A)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)
        self.assertEqual(len(log), 6)
        self.assertTrue(log.verify())

    def test_alternate_hash_algorithm(self):
        log = _evolved_log(records=4, hash_name="sha512")
        bundle = log.signed_stage_auth_bundle((3, 2), _SEED_A)
        self.assertEqual(bundle.hash_name, "sha512")
        self.assertEqual(bundle.verifier.verifier.hash_name, "sha512")
        self.assertEqual([tag.stage for _, tag in bundle.items], [3, 4])
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, _public_key(_SEED_A)),
            (True, True),
        )


class VerifySignedStageAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_genuine_bundle_verifies_per_item(self):
        bundle = _bundle(indices=(3, 5))
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.public_key),
            (True, True),
        )

    def test_empty_bundle(self):
        bundle = _bundle(indices=())
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.public_key), ()
        )
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.other_public_key), ()
        )

    def test_untrusted_public_key_fails_per_item(self):
        bundle = _bundle()
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.other_public_key),
            (False, False),
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
            (False, False),
        )

    def test_tampered_material_fails_per_item(self):
        bundle = _bundle()
        material = bundle.verifier.verifier
        # A structurally valid StageVerifier at a different delivery stage
        # makes the signed message differ: signature verification fails
        # before any item is examined.
        shifted = StageVerifier(material.stage + 1, material.key, material.hash_name)
        forged = SignedStageAuthBundle(
            SignedStageVerifier(1, shifted, bundle.verifier.signature),
            bundle.hash_name,
            bundle.items,
        )
        self.assertEqual(
            verify_signed_stage_auth_bundle(forged, self.public_key),
            (False, False),
        )

    def test_tampered_tag_fails_at_its_position(self):
        bundle = _bundle(indices=(3, 4, 5))
        entry, tag = bundle.items[1]
        bad_tag = AuthTag(tag.stage, bytes([tag.tag[0] ^ 1]) + tag.tag[1:])
        items = bundle.items[:1] + ((entry, bad_tag),) + bundle.items[2:]
        forged = SignedStageAuthBundle(bundle.verifier, bundle.hash_name, items)
        self.assertEqual(
            verify_signed_stage_auth_bundle(forged, self.public_key),
            (True, False, True),
        )

    def test_tampered_entry_fails_at_its_position(self):
        bundle = _bundle(indices=(3, 4, 5))
        entry, tag = bundle.items[0]
        bad_entry = Entry(
            entry.index, b"forged", entry.previous_hash, entry.entry_hash
        )
        items = ((bad_entry, tag),) + bundle.items[1:]
        forged = SignedStageAuthBundle(bundle.verifier, bundle.hash_name, items)
        results = verify_signed_stage_auth_bundle(forged, self.public_key)
        self.assertEqual(results[0], False)
        self.assertEqual(results[1:], (True, True))

    def test_hash_name_mismatch_fails_per_item(self):
        bundle = _bundle()
        forged = SignedStageAuthBundle(bundle.verifier, "sha512", bundle.items)
        self.assertEqual(
            verify_signed_stage_auth_bundle(forged, self.public_key),
            (False, False),
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

    def test_malformed_item_shapes_raise_type_error(self):
        bundle = _bundle(indices=(3, 4, 5))
        entry, tag = bundle.items[0]
        # Replace the inner pair with a malformed item: the container itself
        # does not validate items, so the bypass is needed to reach the
        # verifier's structural pass.
        for bad_item in ((entry,), (entry, tag, None), [entry, tag]):
            hacked = SignedStageAuthBundle.__new__(SignedStageAuthBundle)
            object.__setattr__(hacked, "verifier", bundle.verifier)
            object.__setattr__(hacked, "hash_name", bundle.hash_name)
            object.__setattr__(hacked, "items", (bad_item,) + bundle.items[1:])
            with self.assertRaises(TypeError, msg=repr(bad_item)):
                verify_signed_stage_auth_bundle(hacked, self.public_key)
        # Wrong element types inside the pair.
        for bad_item in (("entry", tag), (entry, "tag")):
            hacked = SignedStageAuthBundle.__new__(SignedStageAuthBundle)
            object.__setattr__(hacked, "verifier", bundle.verifier)
            object.__setattr__(hacked, "hash_name", bundle.hash_name)
            object.__setattr__(hacked, "items", (bad_item,) + bundle.items[1:])
            with self.assertRaises(TypeError):
                verify_signed_stage_auth_bundle(hacked, self.public_key)

    def test_structurally_invalid_items_raise_value_error(self):
        bundle = _bundle(indices=(3, 4, 5))
        entry, tag = bundle.items[0]
        bad_tag = AuthTag(tag.stage, tag.tag[:-1])  # wrong digest width
        forged = SignedStageAuthBundle(
            bundle.verifier,
            bundle.hash_name,
            ((entry, bad_tag),) + bundle.items[1:],
        )
        with self.assertRaises(ValueError):
            verify_signed_stage_auth_bundle(forged, self.public_key)

    def test_non_ascending_indices_raise_value_error(self):
        bundle = _bundle(indices=(3, 4, 5))
        reversed_items = tuple(reversed(bundle.items))
        forged = SignedStageAuthBundle(
            bundle.verifier, bundle.hash_name, reversed_items
        )
        with self.assertRaises(ValueError):
            verify_signed_stage_auth_bundle(forged, self.public_key)

    def test_non_consecutive_stages_raise_value_error(self):
        bundle = _bundle(indices=(3, 4, 5))
        entry0, tag0 = bundle.items[0]
        entry1, tag1 = bundle.items[1]
        # Skip a stage: genuine signature over delivery stage 3, but the
        # second tag sits two stages above the first.
        skipped_tag = AuthTag(tag1.stage + 1, tag1.tag)
        forged = SignedStageAuthBundle(
            bundle.verifier,
            bundle.hash_name,
            ((entry0, tag0), (entry1, skipped_tag)),
        )
        with self.assertRaises(ValueError):
            verify_signed_stage_auth_bundle(forged, self.public_key)

    def test_stage_run_not_anchored_at_delivery_stage_raises_value_error(self):
        # Genuinely signed material at delivery stage 3, paired with a
        # structurally valid batch anchored two stages later.
        bundle = _bundle(evolutions=3, indices=(3, 5))
        later = _bundle(evolutions=5, indices=(3, 5))
        forged = SignedStageAuthBundle(
            bundle.verifier, bundle.hash_name, later.items
        )
        self.assertEqual(
            [tag.stage for _, tag in later.items], [5, 6]
        )
        with self.assertRaises(ValueError):
            verify_signed_stage_auth_bundle(forged, self.public_key)

    def test_tag_predating_delivery_stage_raises_value_error(self):
        # A stage-0-style batch paired with post-evolution material: the
        # first tag stage precedes the signed delivery stage.
        bundle = _bundle(evolutions=3, indices=(3, 5))
        fresh = AuditLog(key=_KEY)
        for record in range(6):
            fresh.append(f"record-{record}")
        early_items = tuple(
            (fresh.entry(i), fresh.auth(i)) for i in (3, 5)
        )
        self.assertEqual([tag.stage for _, tag in early_items], [0, 1])
        forged = SignedStageAuthBundle(
            bundle.verifier, bundle.hash_name, early_items
        )
        with self.assertRaises(ValueError):
            verify_signed_stage_auth_bundle(forged, self.public_key)

    def test_call_is_read_only(self):
        bundle = _bundle(indices=(3, 4, 5))
        before = (bundle.verifier, bundle.hash_name, bundle.items)
        verify_signed_stage_auth_bundle(bundle, self.public_key)
        verify_signed_stage_auth_bundle(bundle, self.other_public_key)
        self.assertEqual((bundle.verifier, bundle.hash_name, bundle.items), before)

    def test_results_match_per_item_stage_verification(self):
        bundle = _bundle(indices=(3, 4, 5))
        expected = tuple(
            verify_auth_stage(entry, tag, bundle.verifier.verifier)
            for entry, tag in bundle.items
        )
        self.assertEqual(
            verify_signed_stage_auth_bundle(bundle, self.public_key), expected
        )


if __name__ == "__main__":
    unittest.main()
