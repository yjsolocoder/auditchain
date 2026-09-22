import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedRoot,
    verify_rotation,
    verify_signed_root,
)

_SEED_OLD = bytes(range(1, 33))
_SEED_NEW = bytes(range(33, 65))
_SEED_OTHER = bytes(range(65, 97))


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
        self.old_public = _public_key(_SEED_OLD)
        self.new_public = _public_key(_SEED_NEW)
        self.other_public = _public_key(_SEED_OTHER)

    def test_returns_old_new_key_new_auth(self):
        old, new_key, new, auth = self.log.rotate_signer(_SEED_OLD, _SEED_NEW)
        self.assertIsInstance(old, SignedRoot)
        self.assertIsInstance(new, SignedRoot)
        self.assertIsInstance(new_key, bytes)
        self.assertIsInstance(auth, bytes)
        self.assertEqual(new_key, self.new_public)
        self.assertEqual(len(new_key), 32)
        self.assertEqual(len(auth), 64)

    def test_checkpoints_share_the_snapshot_and_differ_only_in_signature(self):
        old, _, new, _ = self.log.rotate_signer(_SEED_OLD, _SEED_NEW, 4)
        for field in ("version", "hash_name", "size", "root", "head"):
            self.assertEqual(getattr(old, field), getattr(new, field), field)
        self.assertEqual(old.size, 4)
        self.assertEqual(old.root, self.log.merkle_root(4))
        self.assertEqual(old.head, self.log.entry(3).entry_hash)
        self.assertNotEqual(old.signature, new.signature)

    def test_checkpoints_are_plain_signed_roots(self):
        old, new_key, new, _ = self.log.rotate_signer(_SEED_OLD, _SEED_NEW)
        self.assertEqual(old, self.log.sign_root(_SEED_OLD))
        self.assertEqual(new, self.log.sign_root(_SEED_NEW))
        self.assertTrue(verify_signed_root(old, self.old_public))
        self.assertTrue(verify_signed_root(new, new_key))
        self.assertFalse(verify_signed_root(new, self.old_public))

    def test_auth_signs_the_specified_message(self):
        old, new_key, new, auth = self.log.rotate_signer(_SEED_OLD, _SEED_NEW)
        message = (
            b"auditchain/signer-rotation/v1\0"
            + b"\x01"
            + _blob(old.signature)
            + _blob(new_key)
            + _blob(new.signature)
        )
        # Ed25519 is deterministic: signing the message again must reproduce
        # exactly the authorization signature carried by the tuple.
        self.assertEqual(
            Ed25519PrivateKey.from_private_bytes(_SEED_OLD).sign(message),
            auth,
        )

    def test_size_defaults_to_current_length(self):
        old, _, new, _ = self.log.rotate_signer(_SEED_OLD, _SEED_NEW)
        self.assertEqual(old.size, len(self.log))
        self.log.append("f")
        old, _, new, _ = self.log.rotate_signer(_SEED_OLD, _SEED_NEW)
        self.assertEqual(old.size, 6)
        self.assertEqual(new.size, 6)

    def test_empty_snapshot(self):
        old, new_key, new, auth = AuditLog().rotate_signer(_SEED_OLD, _SEED_NEW)
        self.assertEqual(old.size, 0)
        self.assertEqual(new.size, 0)
        self.assertTrue(verify_rotation((old, new_key, new, auth), self.old_public))

    def test_explicit_size_zero_on_nonempty_log(self):
        old, new_key, new, auth = self.log.rotate_signer(_SEED_OLD, _SEED_NEW, 0)
        self.assertEqual((old.size, new.size), (0, 0))
        self.assertTrue(verify_rotation((old, new_key, new, auth), self.old_public))

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ("a", "b", "c"):
            log.append(record)
        old, new_key, new, auth = log.rotate_signer(_SEED_OLD, _SEED_NEW)
        self.assertEqual(len(old.root), 64)
        self.assertTrue(verify_rotation((old, new_key, new, auth), self.old_public))

    def test_pruned_unrebuildable_snapshot_raises(self):
        self.log.prune(3, self.log.seal(3))
        with self.assertRaises(ValueError):
            self.log.rotate_signer(_SEED_OLD, _SEED_NEW, 2)
        old, new_key, new, auth = self.log.rotate_signer(_SEED_OLD, _SEED_NEW, 4)
        self.assertTrue(verify_rotation((old, new_key, new, auth), self.old_public))

    def test_call_is_read_only(self):
        head = self.log.head
        root = self.log.merkle_root()
        stage_log = AuditLog(key=b"shared-secret")
        stage_log.append("a")
        self.log.rotate_signer(_SEED_OLD, _SEED_NEW)
        self.log.rotate_signer(_SEED_OLD, _SEED_NEW, 3)
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.merkle_root(), root)
        self.assertTrue(self.log.verify())
        self.assertEqual(stage_log.stage, 0)

    def test_seed_validation(self):
        for bad in ("0" * 32, bytearray(_SEED_OLD), memoryview(_SEED_OLD), None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.log.rotate_signer(bad, _SEED_NEW)
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.log.rotate_signer(_SEED_OLD, bad)
        with self.assertRaises(ValueError):
            self.log.rotate_signer(_SEED_OLD[:-1], _SEED_NEW)
        with self.assertRaises(ValueError):
            self.log.rotate_signer(_SEED_OLD, _SEED_NEW + b"\x00")

    def test_size_validation(self):
        with self.assertRaises(TypeError):
            self.log.rotate_signer(_SEED_OLD, _SEED_NEW, "3")
        with self.assertRaises(TypeError):
            self.log.rotate_signer(_SEED_OLD, _SEED_NEW, True)
        with self.assertRaises(TypeError):
            self.log.rotate_signer(_SEED_OLD, _SEED_NEW, 3.0)
        with self.assertRaises(ValueError):
            self.log.rotate_signer(_SEED_OLD, _SEED_NEW, -1)
        with self.assertRaises(ValueError):
            self.log.rotate_signer(_SEED_OLD, _SEED_NEW, 6)


class VerifyRotationTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)
        self.old_public = _public_key(_SEED_OLD)
        self.new_public = _public_key(_SEED_NEW)
        self.other_public = _public_key(_SEED_OTHER)
        self.item = self.log.rotate_signer(_SEED_OLD, _SEED_NEW)

    def bypass(self, **fields):
        old, new_key, new, auth = self.item
        values = {
            "old": old,
            "new_key": new_key,
            "new": new,
            "auth": auth,
        }
        values.update(fields)
        return (values["old"], values["new_key"], values["new"], values["auth"])

    def test_genuine_rotation_verifies(self):
        for size in (None, 0, 1, 3, 5):
            item = self.log.rotate_signer(_SEED_OLD, _SEED_NEW, size)
            self.assertTrue(verify_rotation(item, self.old_public), size)

    def test_rotation_chains_to_successor(self):
        seed_third = bytes(range(97, 129))
        third_public = _public_key(seed_third)
        _, next_key, _, _ = self.item
        second = self.log.rotate_signer(_SEED_NEW, seed_third)
        self.assertEqual(next_key, self.new_public)
        self.assertTrue(verify_rotation(second, next_key))
        # The successor's own authority must not be accepted for a rotation
        # supposedly rooted at the original signer.
        self.assertFalse(verify_rotation(second, self.old_public))
        self.assertFalse(verify_rotation(self.item, third_public))

    def test_wrong_old_public_key_returns_false(self):
        self.assertFalse(verify_rotation(self.item, self.other_public))

    def test_tampered_auth_returns_false(self):
        old, new_key, new, auth = self.item
        forged = (old, new_key, new, bytes([auth[0] ^ 1]) + auth[1:])
        self.assertFalse(verify_rotation(forged, self.old_public))

    def test_auth_zero_signature_returns_false(self):
        old, new_key, new, _ = self.item
        self.assertFalse(
            verify_rotation((old, new_key, new, b"\x00" * 64), self.old_public)
        )

    def test_swapped_successor_key_returns_false(self):
        self.assertFalse(
            verify_rotation(
                self.bypass(new_key=self.other_public), self.old_public
            )
        )

    def test_new_checkpoint_signed_by_another_key_returns_false(self):
        old, _, _, auth = self.item
        foreign_new = self.log.sign_root(_SEED_OTHER)
        item = (old, self.other_public, foreign_new, auth)
        self.assertFalse(verify_rotation(item, self.old_public))

    def test_old_checkpoint_signed_by_another_key_returns_false(self):
        _, new_key, new, auth = self.item
        foreign_old = self.log.sign_root(_SEED_OTHER)
        item = (foreign_old, new_key, new, auth)
        self.assertFalse(verify_rotation(item, self.old_public))

    def test_checkpoint_snapshot_mismatch_returns_false(self):
        old, new_key, _, auth = self.item
        other_new = self.log.sign_root(_SEED_NEW, 3)
        # Even with a self-consistent auth over these three values, differing
        # snapshots are rejected.
        glued_auth = Ed25519PrivateKey.from_private_bytes(_SEED_OLD).sign(
            b"auditchain/signer-rotation/v1\0"
            + b"\x01"
            + _blob(old.signature)
            + _blob(new_key)
            + _blob(other_new.signature)
        )
        item = (old, new_key, other_new, glued_auth)
        self.assertFalse(verify_rotation(item, self.old_public))

    def test_auth_from_a_different_rotation_is_not_reusable(self):
        other = self.log.rotate_signer(_SEED_OLD, _SEED_OTHER, 3)
        old, _, new, _ = self.item
        _, other_key, _, other_auth = other
        self.assertFalse(
            verify_rotation((old, other_key, new, other_auth), self.old_public)
        )

    def test_auth_domains_are_separated(self):
        # A signature over the same three blobs under the signed-root domain
        # must not be accepted as a rotation authorization.
        old, new_key, new, _ = self.item
        wrong_domain = Ed25519PrivateKey.from_private_bytes(_SEED_OLD).sign(
            b"auditchain/signed-root/v1\0"
            + b"\x01"
            + _blob(old.signature)
            + _blob(new_key)
            + _blob(new.signature)
        )
        self.assertFalse(
            verify_rotation((old, new_key, new, wrong_domain), self.old_public)
        )

    def test_bypassed_checkpoint_fields_return_false_when_unsigned(self):
        old, new_key, new, auth = self.item
        forged = SignedRoot.__new__(SignedRoot)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", new.size),
            ("root", new.root),
            ("head", new.head),
            ("signature", b"\x00" * 64),
        ):
            object.__setattr__(forged, name, value)
        self.assertFalse(
            verify_rotation((old, new_key, forged, auth), self.old_public)
        )

    def test_item_shape_validation(self):
        old, new_key, new, auth = self.item
        for bad in (
            None,
            (old, new_key, new),
            (old, new_key, new, auth, 1),
            [old, new_key, new, auth],
            (),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_rotation(bad, self.old_public)
        with self.assertRaises(TypeError):
            verify_rotation(("x", new_key, new, auth), self.old_public)
        with self.assertRaises(TypeError):
            verify_rotation((old, new_key, "x", auth), self.old_public)
        with self.assertRaises(TypeError):
            verify_rotation((old, bytearray(new_key), new, auth), self.old_public)
        with self.assertRaises(TypeError):
            verify_rotation((old, memoryview(new_key), new, auth), self.old_public)
        with self.assertRaises(TypeError):
            verify_rotation((old, new_key, new, "0" * 64), self.old_public)

    def test_key_validation(self):
        with self.assertRaises(TypeError):
            verify_rotation(self.item, "0" * 32)
        with self.assertRaises(TypeError):
            verify_rotation(self.item, bytearray(self.old_public))
        with self.assertRaises(TypeError):
            verify_rotation(self.item, memoryview(self.old_public))
        with self.assertRaises(ValueError):
            verify_rotation(self.item, self.old_public[:-1])
        with self.assertRaises(ValueError):
            verify_rotation(self.item, self.old_public + b"\x00")

    def test_embedded_new_key_validation(self):
        with self.assertRaises(TypeError):
            verify_rotation(
                self.bypass(new_key="0" * 32), self.old_public
            )
        with self.assertRaises(ValueError):
            verify_rotation(
                self.bypass(new_key=self.new_public[:-1]), self.old_public
            )

    def test_auth_length_validation(self):
        with self.assertRaises(ValueError):
            verify_rotation(
                self.bypass(auth=b"\x00" * 63), self.old_public
            )
        with self.assertRaises(ValueError):
            verify_rotation(
                self.bypass(auth=b"\x00" * 65), self.old_public
            )

    def test_malformed_checkpoint_raises(self):
        old, new_key, new, auth = self.item
        forged = SignedRoot.__new__(SignedRoot)
        for name, value in (
            ("version", 2),
            ("hash_name", "sha256"),
            ("size", new.size),
            ("root", new.root),
            ("head", new.head),
            ("signature", new.signature),
        ):
            object.__setattr__(forged, name, value)
        with self.assertRaises(ValueError):
            verify_rotation((old, new_key, forged, auth), self.old_public)

    def test_call_is_read_only(self):
        verify_rotation(self.item, self.other_public)
        self.assertEqual(
            self.item, self.log.rotate_signer(_SEED_OLD, _SEED_NEW)
        )
        head = self.log.head
        verify_rotation(self.item, self.other_public)
        self.assertEqual(self.log.head, head)
        self.assertEqual(len(self.log), 5)


if __name__ == "__main__":
    unittest.main()
