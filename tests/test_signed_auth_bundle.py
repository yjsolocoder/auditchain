import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    AuthTag,
    Entry,
    SignedAuthBundle,
    SignedVerifier,
    Verifier,
    verify_auth,
    verify_auth_batch,
    verify_signed_auth_bundle,
    verify_signed_verifier,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"
_OTHER_KEY = b"a-completely-different-stage-zero"


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _make_bundle(indices=(1, 3), *, key=_KEY, seed=_SEED_A, hash_name="sha256"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in ("a", "b", "c", "d", "e"):
        log.append(record)
    receipt = log.export_signed_verifier(seed)
    items = log.auth_batch(list(indices))
    bundle = SignedAuthBundle(receipt, hash_name, items)
    return log, receipt, items, bundle


class SignedAuthBundleConstructionTest(unittest.TestCase):
    def test_positional_and_keyword_fields(self):
        _, receipt, items, bundle = _make_bundle()
        positional = SignedAuthBundle(receipt, "sha256", items)
        keyword = SignedAuthBundle(
            verifier=receipt, hash_name="sha256", items=items
        )
        self.assertEqual(positional, bundle)
        self.assertEqual(keyword, bundle)
        self.assertIs(bundle.verifier, receipt)
        self.assertEqual(bundle.hash_name, "sha256")
        self.assertIs(bundle.items, items)

    def test_frozen(self):
        _, _, _, bundle = _make_bundle()
        with self.assertRaises(FrozenInstanceError):
            bundle.verifier = bundle.verifier
        with self.assertRaises(FrozenInstanceError):
            bundle.hash_name = "sha512"
        with self.assertRaises(FrozenInstanceError):
            bundle.items = ()

    def test_equality_by_all_fields(self):
        _, receipt, items, bundle = _make_bundle()
        self.assertEqual(bundle, SignedAuthBundle(receipt, "sha256", items))
        self.assertNotEqual(
            bundle, SignedAuthBundle(receipt, "sha256", items[:1])
        )
        other_log = AuditLog(key=_OTHER_KEY)
        other_receipt = other_log.export_signed_verifier(_SEED_A)
        self.assertNotEqual(
            bundle, SignedAuthBundle(other_receipt, "sha256", items)
        )
        self.assertNotEqual(
            bundle, SignedAuthBundle(receipt, "sha256", ())
        )

    def test_empty_items(self):
        _, receipt, _, _ = _make_bundle(())
        bundle = SignedAuthBundle(receipt, "sha256", ())
        self.assertEqual(bundle.items, ())

    def test_verifier_must_be_signed_verifier(self):
        verifier = Verifier(_KEY, "sha256")
        for bad in (None, 1, "sha256", verifier, (), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SignedAuthBundle(bad, "sha256", ())

    def test_bypassed_verifier_field_type_raises_type_error(self):
        _, receipt, items, _ = _make_bundle()
        forged = SignedAuthBundle.__new__(SignedAuthBundle)
        object.__setattr__(forged, "verifier", None)
        object.__setattr__(forged, "hash_name", "sha256")
        object.__setattr__(forged, "items", items)
        with self.assertRaises(TypeError):
            SignedAuthBundle(forged.verifier, forged.hash_name, forged.items)

    def test_hash_name_must_be_known_string(self):
        _, receipt, _, _ = _make_bundle(())
        for bad in (None, 1, b"sha256"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SignedAuthBundle(receipt, bad, ())
        with self.assertRaises(ValueError):
            SignedAuthBundle(receipt, "not-a-real-hash", ())

    def test_hash_name_must_match_verifier_algorithm(self):
        _, receipt, _, _ = _make_bundle(())
        log512 = AuditLog(key=_KEY, hash_name="sha512")
        receipt512 = log512.export_signed_verifier(_SEED_A)
        with self.assertRaises(ValueError):
            SignedAuthBundle(receipt, "sha512", ())
        with self.assertRaises(ValueError):
            SignedAuthBundle(receipt512, "sha256", ())
        # The matching name constructs fine.
        self.assertEqual(
            SignedAuthBundle(receipt512, "sha512", ()).hash_name, "sha512"
        )

    def test_items_must_be_a_tuple(self):
        _, receipt, items, _ = _make_bundle()
        for bad in (None, 1, list(items), [items[0]]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SignedAuthBundle(receipt, "sha256", bad)

    def test_item_structure_deferred_to_verification(self):
        # The container only requires a tuple; per-item structural rules are
        # owned by verify_auth_batch (and checked there / at encode time).
        _, receipt, _, _ = _make_bundle()
        bundle = SignedAuthBundle(receipt, "sha256", (1, 2, 3))
        self.assertEqual(bundle.items, (1, 2, 3))

    def test_verifier_key_carried_in_cleartext(self):
        _, receipt, _, bundle = _make_bundle()
        self.assertEqual(bundle.verifier.verifier.key, _KEY)
        self.assertEqual(receipt.verifier.key, _KEY)


class VerifySignedAuthBundleTest(unittest.TestCase):
    def setUp(self):
        self.log, self.receipt, self.items, self.bundle = _make_bundle(
            (1, 3, 4)
        )
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_genuine_bundle_verifies_every_item(self):
        self.assertEqual(
            verify_signed_auth_bundle(self.bundle, self.public_key),
            (True, True, True),
        )

    def test_empty_bundle_returns_empty_tuple(self):
        bundle = SignedAuthBundle(self.receipt, "sha256", ())
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key), ()
        )

    def test_result_is_tuple_of_bool_in_item_order(self):
        result = verify_signed_auth_bundle(self.bundle, self.public_key)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)
        self.assertTrue(all(type(value) is bool for value in result))

    def test_untrusted_public_key_fails_every_item(self):
        self.assertEqual(
            verify_signed_auth_bundle(self.bundle, self.other_public_key),
            (False, False, False),
        )

    def test_bad_signature_fails_every_item(self):
        bogus = SignedVerifier(
            self.receipt.version,
            self.receipt.verifier,
            b"\x00" * 64,
        )
        bundle = SignedAuthBundle(bogus, "sha256", self.items)
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key),
            (False, False, False),
        )

    def test_bad_signature_empty_bundle_stays_empty(self):
        bogus = SignedVerifier(
            self.receipt.version,
            self.receipt.verifier,
            b"\x00" * 64,
        )
        bundle = SignedAuthBundle(bogus, "sha256", ())
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key), ()
        )

    def test_valid_signature_but_wrong_stage0_key_fails_items(self):
        # A second log whose SignedVerifier is genuinely signed by seed A,
        # but whose stage-0 key does not match the first log's tags:
        # provenance passes, then every tag fails on its merits.
        _, other_receipt, _, _ = _make_bundle(
            (0, 1), key=_OTHER_KEY, seed=_SEED_A
        )
        bundle = SignedAuthBundle(other_receipt, "sha256", self.items[:2])
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key),
            (False, False),
        )

    def test_one_tampered_tag_fails_only_that_position(self):
        entry, tag = self.items[0]
        replacement = b"\x00" * len(tag.tag)
        if replacement == tag.tag:
            replacement = b"\x01" * len(tag.tag)
        forged_tag = AuthTag(tag.stage, replacement)
        items = ((entry, forged_tag),) + self.items[1:]
        bundle = SignedAuthBundle(self.receipt, "sha256", items)
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key),
            (False, True, True),
        )

    def test_one_tampered_entry_fails_only_that_position(self):
        entry, tag = self.items[1]
        bogus_hash = bytes(len(entry.entry_hash))
        if bogus_hash == entry.entry_hash:
            bogus_hash = b"\x01" * len(entry.entry_hash)
        forged_entry = Entry(
            entry.index, entry.payload, entry.previous_hash, bogus_hash
        )
        items = (
            self.items[0],
            (forged_entry, tag),
            self.items[2],
        )
        bundle = SignedAuthBundle(self.receipt, "sha256", items)
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key),
            (True, False, True),
        )

    def test_matches_verify_auth_batch_with_delivered_verifier(self):
        expected = verify_auth_batch(self.items, self.receipt.verifier)
        self.assertEqual(
            verify_signed_auth_bundle(self.bundle, self.public_key),
            expected,
        )
        for (entry, tag), value in zip(self.items, expected):
            self.assertEqual(
                verify_auth(entry, tag, self.receipt.verifier), value
            )

    def test_alternate_hash_algorithm(self):
        log = AuditLog(key=_KEY, hash_name="sha512")
        for record in ("a", "b"):
            log.append(record)
        receipt = log.export_signed_verifier(_SEED_A)
        items = log.auth_batch([0, 1])
        bundle = SignedAuthBundle(receipt, "sha512", items)
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key), (True, True)
        )

    def test_single_item(self):
        _, receipt, items, bundle = _make_bundle((2,))
        self.assertEqual(len(items), 1)
        self.assertEqual(
            verify_signed_auth_bundle(bundle, self.public_key), (True,)
        )

    def test_nested_signed_verifier_still_verifies_on_its_own(self):
        self.assertTrue(
            verify_signed_verifier(self.receipt, self.public_key)
        )

    def test_bundle_must_be_signed_auth_bundle(self):
        for bad in (
            None,
            1,
            "bundle",
            b"bytes",
            (),
            (self.receipt, "sha256", self.items),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_signed_auth_bundle(bad, self.public_key)

    def test_bypassed_container_fields_raise_type_error(self):
        for field, value in (
            ("verifier", None),
            ("hash_name", 1),
            ("items", None),
        ):
            forged = SignedAuthBundle.__new__(SignedAuthBundle)
            object.__setattr__(
                forged,
                "verifier",
                self.receipt if field != "verifier" else value,
            )
            object.__setattr__(
                forged,
                "hash_name",
                "sha256" if field != "hash_name" else value,
            )
            object.__setattr__(
                forged,
                "items",
                self.items if field != "items" else value,
            )
            with self.assertRaises(TypeError, msg=field):
                verify_signed_auth_bundle(forged, self.public_key)

    def test_bypassed_items_not_a_tuple_raises_type_error(self):
        forged = SignedAuthBundle.__new__(SignedAuthBundle)
        object.__setattr__(forged, "verifier", self.receipt)
        object.__setattr__(forged, "hash_name", "sha256")
        object.__setattr__(forged, "items", [self.items[0]])
        with self.assertRaises(TypeError):
            verify_signed_auth_bundle(forged, self.public_key)

    def test_structural_item_problem_raises_value_error(self):
        # Non-consecutive tag stages are structurally invalid for
        # verify_auth_batch; provenance cannot mask that.
        entry, tag = self.items[0]
        bad_items = (
            (entry, AuthTag(0, tag.tag)),
            (self.items[1][0], AuthTag(9, self.items[1][1].tag)),
        )
        bundle = SignedAuthBundle(self.receipt, "sha256", bad_items)
        with self.assertRaises(ValueError):
            verify_signed_auth_bundle(bundle, self.public_key)

    def test_public_key_type_error(self):
        for bad in (None, 1, "0" * 32, bytearray(self.public_key)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_signed_auth_bundle(self.bundle, bad)

    def test_public_key_length_value_error(self):
        for bad in (b"", b"\x00", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                verify_signed_auth_bundle(self.bundle, bad)

    def test_call_is_read_only(self):
        before = (self.bundle, self.items, self.receipt)
        verify_signed_auth_bundle(self.bundle, self.public_key)
        verify_signed_auth_bundle(self.bundle, self.other_public_key)
        self.assertEqual(
            (self.bundle, self.items, self.receipt), before
        )
        self.assertEqual(self.log.stage, 3)


if __name__ == "__main__":
    unittest.main()
