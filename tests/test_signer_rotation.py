import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    SignedRoot,
    verify_rotation,
    verify_signed_root,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _blob(material: bytes) -> bytes:
    return _u64(len(material)) + material


class RotateSignerTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.old_public = _public_key(_SEED_A)
        self.new_public = _public_key(_SEED_B)

    def _rotate(self, **kwargs):
        return self.log.rotate_signer(_SEED_A, _SEED_B, **kwargs)

    def test_returns_four_tuple(self):
        item = self._rotate()
        self.assertIsInstance(item, tuple)
        self.assertEqual(len(item), 4)
        old, new_key, new, auth = item
        self.assertIsInstance(old, SignedRoot)
        self.assertIsInstance(new, SignedRoot)
        self.assertIsInstance(new_key, bytes)
        self.assertIsInstance(auth, bytes)

    def test_new_key_is_new_seed_public_key(self):
        _, new_key, _, _ = self._rotate()
        self.assertEqual(len(new_key), 32)
        self.assertEqual(new_key, self.new_public)
        self.assertNotEqual(new_key, self.old_public)

    def test_auth_is_64_bytes(self):
        self.assertEqual(len(self._rotate()[3]), 64)

    def test_both_checkpoints_attest_to_same_snapshot(self):
        old, _, new, _ = self._rotate()
        self.assertEqual(old.version, 1)
        self.assertEqual(new.version, 1)
        self.assertEqual(old.hash_name, new.hash_name)
        self.assertEqual(old.size, new.size)
        self.assertEqual(old.root, new.root)
        self.assertEqual(old.head, new.head)
        # Only the signatures differ: different seeds signed one message.
        self.assertNotEqual(old.signature, new.signature)

    def test_checkpoints_match_log_snapshot(self):
        old, _, new, _ = self._rotate()
        self.assertEqual(old.size, len(self.log))
        self.assertEqual(old.root, self.log.merkle_root())
        self.assertEqual(old.head, self.log.head)
        self.assertEqual(new.root, self.log.merkle_root())

    def test_checkpoints_are_what_sign_root_produces(self):
        old, _, new, _ = self._rotate(size=4)
        self.assertEqual(old, self.log.sign_root(_SEED_A, 4))
        self.assertEqual(new, self.log.sign_root(_SEED_B, 4))

    def test_size_prefix(self):
        old, _, new, _ = self._rotate(size=3)
        self.assertEqual(old.size, 3)
        self.assertEqual(old.root, self.log.merkle_root(3))
        self.assertEqual(old.head, self.log.entry(2).entry_hash)

    def test_size_defaults_to_current_length(self):
        self.assertEqual(self._rotate()[0].size, len(self.log))
        self.log.append("f")
        self.assertEqual(self._rotate()[0].size, 6)

    def test_empty_prefix(self):
        log = AuditLog()
        old, new_key, new, auth = log.rotate_signer(_SEED_A, _SEED_B, 0)
        self.assertEqual(old.size, 0)
        self.assertEqual(new.size, 0)
        self.assertEqual(old.root, log.merkle_root(0))
        self.assertEqual(old.head, GENESIS_HASH)
        self.assertTrue(verify_rotation((old, new_key, new, auth), self.old_public))

    def test_empty_log_default_size(self):
        log = AuditLog()
        old, new_key, new, auth = log.rotate_signer(_SEED_A, _SEED_B)
        self.assertEqual((old.size, new.size), (0, 0))
        self.assertTrue(verify_rotation((old, new_key, new, auth), self.old_public))

    def test_auth_is_over_specified_message(self):
        old, new_key, new, auth = self._rotate()
        message = (
            b"auditchain/signer-rotation/v1\0"
            + b"\x01"
            + _blob(old.signature)
            + _blob(new_key)
            + _blob(new.signature)
        )
        # Ed25519 is deterministic: the old seed signing the message again
        # must reproduce exactly the carried auth signature.
        self.assertEqual(
            Ed25519PrivateKey.from_private_bytes(_SEED_A).sign(message),
            auth,
        )

    def test_survives_later_appends(self):
        item = self._rotate(size=4)
        self.log.append("f")
        self.assertTrue(verify_rotation(item, self.old_public))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        old, new_key, new, auth = log.rotate_signer(_SEED_A, _SEED_B)
        self.assertEqual(old.hash_name, "sha512")
        self.assertEqual(len(old.root), 64)
        self.assertTrue(verify_rotation((old, new_key, new, auth), self.old_public))

    def test_pruned_snapshot_rebuildable(self):
        self.log.prune(3, self.log.seal(3))
        old, new_key, new, auth = self._rotate(size=4)
        self.assertEqual(old.root, self.log.merkle_root(4))
        self.assertTrue(verify_rotation((old, new_key, new, auth), self.old_public))

    def test_pruned_snapshot_unrebuildable_raises(self):
        self.log.prune(3, self.log.seal(3))
        with self.assertRaises(ValueError):
            self._rotate(size=2)

    def test_same_seed_as_old_and_new(self):
        old, new_key, new, auth = self.log.rotate_signer(_SEED_A, _SEED_A)
        self.assertEqual(new_key, self.old_public)
        self.assertTrue(verify_rotation((old, new_key, new, auth), self.old_public))

    def test_call_is_read_only(self):
        head = self.log.head
        root = self.log.merkle_root()
        stage_log = AuditLog(key=b"shared-secret")
        stage_log.append("a")
        stage_log.rotate_signer(_SEED_A, _SEED_B)
        stage_log.rotate_signer(_SEED_A, _SEED_B, 0)
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.merkle_root(), root)
        self.assertTrue(self.log.verify())
        self.assertEqual(stage_log.stage, 0)
        self.assertEqual(stage_log.head, stage_log.entry(0).entry_hash)

    def test_seed_validation(self):
        for bad in ("0" * 32, bytearray(_SEED_A), memoryview(_SEED_A), None, 32):
            with self.assertRaises(TypeError):
                self.log.rotate_signer(bad, _SEED_B)
            with self.assertRaises(TypeError):
                self.log.rotate_signer(_SEED_A, bad)
        with self.assertRaises(ValueError):
            self.log.rotate_signer(_SEED_A[:-1], _SEED_B)
        with self.assertRaises(ValueError):
            self.log.rotate_signer(_SEED_A, _SEED_B + b"\x00")

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self._rotate(size=True)
        with self.assertRaises(TypeError):
            self._rotate(size=1.0)
        with self.assertRaises(TypeError):
            self._rotate(size="5")
        with self.assertRaises(ValueError):
            self._rotate(size=-1)
        with self.assertRaises(ValueError):
            self._rotate(size=len(self.log) + 1)

    def test_failure_leaves_log_untouched(self):
        before = (len(self.log), self.log.head)
        with self.assertRaises(TypeError):
            self.log.rotate_signer("0" * 32, _SEED_B)
        with self.assertRaises(ValueError):
            self.log.rotate_signer(_SEED_A, _SEED_B, len(self.log) + 1)
        self.assertEqual((len(self.log), self.log.head), before)


class VerifyRotationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.old_public = _public_key(_SEED_A)
        self.new_public = _public_key(_SEED_B)
        self.item = self.log.rotate_signer(_SEED_A, _SEED_B)

    def test_genuine_rotation_verifies(self):
        self.assertTrue(verify_rotation(self.item, self.old_public))

    def test_individual_checkpoints_verify_offline(self):
        old, new_key, new, _ = self.item
        self.assertTrue(verify_signed_root(old, self.old_public))
        self.assertTrue(verify_signed_root(new, new_key))

    def test_wrong_trusted_key_returns_false(self):
        self.assertFalse(verify_rotation(self.item, _public_key(_SEED_C)))

    def test_tampered_old_signature_returns_false(self):
        old, new_key, new, auth = self.item
        tampered = replace(old, signature=b"\x00" * 64)
        self.assertFalse(
            verify_rotation((tampered, new_key, new, auth), self.old_public)
        )

    def test_tampered_new_signature_returns_false(self):
        old, new_key, new, auth = self.item
        tampered = replace(new, signature=b"\x00" * 64)
        self.assertFalse(
            verify_rotation((old, new_key, tampered, auth), self.old_public)
        )

    def test_tampered_auth_returns_false(self):
        old, new_key, new, _ = self.item
        self.assertFalse(
            verify_rotation((old, new_key, new, b"\x00" * 64), self.old_public)
        )

    def test_wrong_new_key_returns_false(self):
        old, _, new, auth = self.item
        self.assertFalse(
            verify_rotation((old, _public_key(_SEED_C), new, auth), self.old_public)
        )

    def test_different_snapshot_returns_false(self):
        old, new_key, _, auth = self.item
        # A SignedRoot of a different prefix signed by the new seed.
        other = self.log.sign_root(_SEED_B, 2)
        self.assertFalse(
            verify_rotation((old, new_key, other, auth), self.old_public)
        )

    def test_old_checkpoint_signed_by_another_key_returns_false(self):
        _, new_key, new, auth = self.item
        forged_old = self.log.sign_root(_SEED_C)
        self.assertFalse(
            verify_rotation((forged_old, new_key, new, auth), self.old_public)
        )

    def test_auth_by_another_key_returns_false(self):
        old, new_key, new, _ = self.item
        from auditchain import _rotation_message

        forged_auth = Ed25519PrivateKey.from_private_bytes(_SEED_C).sign(
            _rotation_message(old.signature, new_key, new.signature)
        )
        self.assertFalse(
            verify_rotation((old, new_key, new, forged_auth), self.old_public)
        )

    def test_auth_not_binding_new_key_returns_false(self):
        # A structurally valid rotation item where auth binds a different
        # new_key than the one presented cannot verify.
        old, _, new, _ = self.item
        from auditchain import _rotation_message

        other_key = _public_key(_SEED_C)
        auth = Ed25519PrivateKey.from_private_bytes(_SEED_A).sign(
            _rotation_message(old.signature, other_key, new.signature)
        )
        # Presenting the bound-but-unsigned key: old verifies old, new fails
        # against other_key. Presenting the real key: auth message mismatches.
        self.assertFalse(
            verify_rotation((old, other_key, new, auth), self.old_public)
        )
        self.assertFalse(
            verify_rotation((old, self.new_public, new, auth), self.old_public)
        )

    def test_item_shape_validation(self):
        old, new_key, new, auth = self.item
        not_tuples = ([], None, "x", object())
        wrong_shapes = ((), (old,), (old, new_key), (old, new_key, new))
        five_tuple = (old, new_key, new, auth, b"extra")
        # Anything that is not a tuple at all raises TypeError...
        for bad in (*not_tuples, [old, new_key, new, auth]):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    verify_rotation(bad, self.old_public)
        # ...while a tuple of the wrong length raises ValueError.
        for bad in (*wrong_shapes, five_tuple):
            with self.subTest(bad=len(bad)):
                with self.assertRaises(ValueError):
                    verify_rotation(bad, self.old_public)

    def test_element_type_validation(self):
        old, new_key, new, auth = self.item
        with self.assertRaises(TypeError):
            verify_rotation(("old", new_key, new, auth), self.old_public)
        with self.assertRaises(TypeError):
            verify_rotation((old, new_key, "new", auth), self.old_public)
        with self.assertRaises(TypeError):
            verify_rotation((old, bytearray(new_key), new, auth), self.old_public)
        with self.assertRaises(TypeError):
            verify_rotation((old, new_key, new, bytearray(auth)), self.old_public)

    def test_length_validation(self):
        old, new_key, new, auth = self.item
        with self.assertRaises(ValueError):
            verify_rotation((old, new_key[:-1], new, auth), self.old_public)
        with self.assertRaises(ValueError):
            verify_rotation((old, new_key, new, auth[:-1]), self.old_public)
        with self.assertRaises(ValueError):
            verify_rotation(self.item, self.old_public[:-1])
        with self.assertRaises(TypeError):
            verify_rotation(self.item, "0" * 32)

    def test_nested_signed_root_corruption_raises(self):
        old, new_key, new, auth = self.item
        # Bypassing the frozen constructor leaves a structurally corrupt
        # SignedRoot; verification must raise, not return False.
        corrupted = object.__new__(SignedRoot)
        object.__setattr__(corrupted, "version", 1)
        object.__setattr__(corrupted, "hash_name", "sha256")
        object.__setattr__(corrupted, "size", new.size)
        object.__setattr__(corrupted, "root", new.root)
        object.__setattr__(corrupted, "head", new.head)
        object.__setattr__(corrupted, "signature", b"\x00" * 32)
        with self.assertRaises(ValueError):
            verify_rotation((old, new_key, corrupted, auth), self.old_public)

    def test_call_is_read_only(self):
        self.assertTrue(verify_rotation(self.item, self.old_public))
        self.assertTrue(verify_rotation(self.item, self.old_public))
        old, new_key, new, auth = self.item
        self.assertEqual(self.item, (old, new_key, new, auth))


if __name__ == "__main__":
    unittest.main()
