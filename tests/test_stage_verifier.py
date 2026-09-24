import hashlib
import hmac
import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    Entry,
    StageVerifier,
    Verifier,
    entry_digest,
    verify_auth,
    verify_auth_stage,
)

KEY = b"super-secret-key"
AUTH_DOMAIN = b"auditchain/auth/v1"
EVOLVE_DOMAIN = b"auditchain/key-evolve/v1"


def evolve(key, hash_name="sha256"):
    return hashlib.new(hash_name, EVOLVE_DOMAIN + key).digest()


class StageVerifierConstructionTest(unittest.TestCase):
    def test_positional_fields_and_immutability(self):
        material = StageVerifier(3, bytes(32), "sha256")
        self.assertEqual((material.stage, material.key, material.hash_name),
                         (3, bytes(32), "sha256"))
        with self.assertRaises(Exception):
            material.stage = 4

    def test_equality_by_fields(self):
        self.assertEqual(
            StageVerifier(2, b"\x01" * 32, "sha256"),
            StageVerifier(2, b"\x01" * 32, "sha256"),
        )
        self.assertNotEqual(
            StageVerifier(2, b"\x01" * 32, "sha256"),
            StageVerifier(3, b"\x01" * 32, "sha256"),
        )
        self.assertNotEqual(
            StageVerifier(2, b"\x01" * 32, "sha256"),
            StageVerifier(2, b"\x02" * 32, "sha256"),
        )
        self.assertNotEqual(
            StageVerifier(2, b"\x01" * 32, "sha256"),
            StageVerifier(2, b"\x01" * 32, "sha3_256"),
        )

    def test_stage_zero_accepts_any_non_empty_key(self):
        StageVerifier(0, b"k", "sha256")
        StageVerifier(0, b"x" * 100, "sha256")

    def test_positive_stage_requires_digest_width(self):
        StageVerifier(1, bytes(32), "sha256")
        StageVerifier((1 << 64) - 1, bytes(28), "sha3_224")
        with self.assertRaises(ValueError):
            StageVerifier(1, b"short", "sha256")
        with self.assertRaises(ValueError):
            StageVerifier(2, bytes(33), "sha256")

    def test_stage_type_must_be_non_bool_integer(self):
        for bad in (True, False, "1", 1.0, None):
            with self.assertRaises(TypeError):
                StageVerifier(bad, bytes(32), "sha256")

    def test_stage_range(self):
        with self.assertRaises(ValueError):
            StageVerifier(-1, bytes(32), "sha256")
        with self.assertRaises(ValueError):
            StageVerifier(1 << 64, bytes(32), "sha256")

    def test_key_must_be_non_empty_bytes(self):
        with self.assertRaises(TypeError):
            StageVerifier(0, "k", "sha256")
        with self.assertRaises(TypeError):
            StageVerifier(1, bytearray(32), "sha256")
        with self.assertRaises(TypeError):
            StageVerifier(1, memoryview(bytes(32)), "sha256")
        with self.assertRaises(ValueError):
            StageVerifier(0, b"", "sha256")
        with self.assertRaises(ValueError):
            StageVerifier(1, b"", "sha256")

    def test_hash_name_validation(self):
        with self.assertRaises(TypeError):
            StageVerifier(0, b"k", 123)
        with self.assertRaises(ValueError):
            StageVerifier(0, b"k", "not-a-hash")
        with self.assertRaises(ValueError):
            StageVerifier(1, bytes(32), "shake_128")


class ExportStageVerifierTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=KEY)
        for record in ("a", "b", "c"):
            self.log.append(record)

    def test_not_available_at_initial_stage(self):
        self.assertEqual(self.log.stage, 0)
        with self.assertRaises(ValueError):
            self.log.export_stage_verifier()

    def test_keyless_mode_rejected(self):
        log = AuditLog()
        log.append("a")
        with self.assertRaises(ValueError):
            log.export_stage_verifier()

    def test_material_freezes_current_stage(self):
        stage0 = self.log.export_verifier()
        tag0 = self.log.auth(0)
        material = self.log.export_stage_verifier()
        self.assertIsInstance(material, StageVerifier)
        self.assertEqual(material.stage, 1)
        self.assertEqual(material.key, self.log._key)
        self.assertEqual(material.hash_name, "sha256")
        # Stage-0 material still verifies the old tag; stage material does not.
        self.assertTrue(verify_auth(self.log.entry(0), tag0, stage0))
        self.assertFalse(
            verify_auth_stage(self.log.entry(0), tag0, material)
        )

    def test_repeatable_and_equal_while_stage_unchanged(self):
        self.log.auth(0)
        first = self.log.export_stage_verifier()
        second = self.log.export_stage_verifier()
        self.assertIsNot(first, second)
        self.assertEqual(first, second)

    def test_export_is_read_only(self):
        self.log.auth(0)
        self.log.auth(1)
        before = (
            self.log.stage,
            self.log._key,
            self.log.head,
            len(self.log),
            self.log._verifier_exported,
            dict(self.log._tags),
        )
        self.log.export_stage_verifier()
        self.log.export_stage_verifier()
        after = (
            self.log.stage,
            self.log._key,
            self.log.head,
            len(self.log),
            self.log._verifier_exported,
            dict(self.log._tags),
        )
        self.assertEqual(before, after)

    def test_does_not_consume_stage_zero_export(self):
        stage0 = self.log.export_verifier()
        self.assertTrue(stage0.key == KEY)
        self.log.rotate_key()
        material = self.log.export_stage_verifier()
        self.assertEqual(material.stage, 1)
        # The one-shot stage-0 export stays consumed; the stage export keeps
        # working independently.
        with self.assertRaises(ValueError):
            self.log.export_verifier()
        self.assertEqual(self.log.export_stage_verifier(), material)

    def test_later_export_freezes_later_stage(self):
        self.log.auth(0)  # mints at stage 0, advances to stage 1
        material1 = self.log.export_stage_verifier()
        self.assertEqual(material1.stage, 1)
        self.log.append("d")
        tag3 = self.log.auth(3)  # mints at stage 1, advances to stage 2
        self.assertEqual(tag3.stage, 1)
        material2 = self.log.export_stage_verifier()
        self.assertEqual(material2.stage, 2)
        # The stage-1 material still verifies the tag minted at stage 1, even
        # though it was exported before that tag existed...
        self.assertTrue(verify_auth_stage(self.log.entry(3), tag3, material1))
        # ...but material re-exported after the next evolution raises the
        # boundary past that same tag.
        self.assertFalse(verify_auth_stage(self.log.entry(3), tag3, material2))
        # A tag at the new delivery stage verifies under both, provided the
        # older material holds the key that evolves to it.
        self.log.append("e")
        tag4 = self.log.auth(4)  # mints at stage 2
        self.assertEqual(tag4.stage, 2)
        self.assertTrue(verify_auth_stage(self.log.entry(4), tag4, material1))
        self.assertTrue(verify_auth_stage(self.log.entry(4), tag4, material2))
        # Neither material verifies a stage-0 tag from another log.
        fresh = AuditLog(key=KEY)
        fresh.append("a")
        stage0_tag = fresh.auth(0)
        self.assertFalse(
            verify_auth_stage(fresh.entry(0), stage0_tag, material1)
        )
        self.assertFalse(
            verify_auth_stage(fresh.entry(0), stage0_tag, material2)
        )

    def test_available_after_rotate_and_batch(self):
        self.log.rotate_key()
        self.assertEqual(self.log.export_stage_verifier().stage, 1)
        items = self.log.auth_batch([0, 1])
        material = self.log.export_stage_verifier()
        self.assertEqual(material.stage, 3)
        for entry, tag in items:
            # Both batch tags (stages 1 and 2) predate the stage-3 delivery.
            self.assertFalse(verify_auth_stage(entry, tag, material))

    def test_failure_leaves_state_untouched(self):
        keyless = AuditLog()
        keyless.append("a")
        before = (keyless.stage, keyless._key, keyless.head)
        with self.assertRaises(ValueError):
            keyless.export_stage_verifier()
        self.assertEqual((keyless.stage, keyless._key, keyless.head), before)

        fresh = AuditLog(key=KEY)
        fresh.append("a")
        before = (fresh.stage, fresh._key, fresh.head, fresh._verifier_exported)
        with self.assertRaises(ValueError):
            fresh.export_stage_verifier()
        self.assertEqual(
            (fresh.stage, fresh._key, fresh.head, fresh._verifier_exported),
            before,
        )


class VerifyAuthStageTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(key=KEY)
        for record in ("a", "b", "c", "d"):
            self.log.append(record)
        self.stage0 = self.log.export_verifier()
        self.tags = [self.log.auth(i) for i in range(4)]  # stages 0..3
        self.assertEqual(self.log.stage, 4)
        self.material = self.log.export_stage_verifier()
        self.assertEqual(self.material.stage, 4)

    def test_same_tag_under_both_materials(self):
        # The stage-0 material verifies every genuine tag; material delivered
        # at stage 4 verifies none of the tags minted before delivery.
        for index, tag in enumerate(self.tags):
            self.assertTrue(
                verify_auth(self.log.entry(index), tag, self.stage0)
            )
            self.assertFalse(
                verify_auth_stage(self.log.entry(index), tag, self.material)
            )

    def test_tag_at_delivery_stage_verifies(self):
        self.log.append("e")
        tag = self.log.auth(4)
        self.assertEqual(tag.stage, 4)
        self.assertTrue(verify_auth_stage(self.log.entry(4), tag, self.material))

    def test_tag_after_delivery_stage_verifies(self):
        # Export at stage 1 (a bare rotation), then tags at later stages must
        # all verify by evolving the delivered stage-1 key forward.
        log = AuditLog(key=KEY)
        log.append("a")
        log.rotate_key()  # stage 1, no tag minted
        material = log.export_stage_verifier()
        self.assertEqual(material.stage, 1)
        for record in ("b", "c"):
            log.append(record)
        tag1 = log.auth(1)
        tag2 = log.auth(2)
        self.assertEqual((tag1.stage, tag2.stage), (1, 2))
        self.assertTrue(verify_auth_stage(log.entry(1), tag1, material))
        self.assertTrue(verify_auth_stage(log.entry(2), tag2, material))
        # A tag carried over from stage 0 on a parallel log is out of reach.
        fresh = AuditLog(key=KEY)
        fresh.append("a")
        stage0_tag = fresh.auth(0)
        self.assertFalse(
            verify_auth_stage(fresh.entry(0), stage0_tag, material)
        )

    def test_boundary_one_stage_before_is_false(self):
        log = AuditLog(key=KEY)
        log.append("a")
        log.append("b")
        tag1_stage0 = log.auth(0)  # stage 0
        material = log.export_stage_verifier()  # delivery at stage 1
        self.assertEqual(material.stage, 1)
        # The immediately preceding stage (0) never verifies...
        self.assertFalse(
            verify_auth_stage(log.entry(0), tag1_stage0, material)
        )
        # ...the delivery stage itself does.
        tag = log.auth(1)
        self.assertEqual(tag.stage, 1)
        self.assertTrue(verify_auth_stage(log.entry(1), tag, material))

    def test_tampered_entry_returns_false(self):
        self.log.append("e")
        tag = self.log.auth(4)
        entry = self.log.entry(4)
        forged = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        self.assertFalse(verify_auth_stage(forged, tag, self.material))
        rebound = Entry(
            entry.index,
            b"forged",
            entry.previous_hash,
            entry_digest(entry.index, entry.previous_hash, b"forged"),
        )
        self.assertFalse(verify_auth_stage(rebound, tag, self.material))

    def test_corrupt_tag_returns_false(self):
        self.log.append("e")
        tag = self.log.auth(4)
        bad = AuthTag(tag.stage, b"\x00" * len(tag.tag))
        self.assertFalse(verify_auth_stage(self.log.entry(4), bad, self.material))

    def test_wrong_delivery_key_returns_false(self):
        self.log.append("e")
        tag = self.log.auth(4)
        other = StageVerifier(4, b"\x00" * 32, "sha256")
        self.assertFalse(verify_auth_stage(self.log.entry(4), tag, other))
        # A material for the same key but a different delivery stage fails too:
        # it either forbids the tag as "earlier" or evolves from a different
        # starting key.
        shifted = StageVerifier(5, self.material.key, "sha256")
        self.assertFalse(verify_auth_stage(self.log.entry(4), tag, shifted))

    def test_material_under_other_algorithm_fails(self):
        self.log.append("e")
        tag = self.log.auth(4)
        sha3 = StageVerifier(4, bytes(32), "sha3_256")
        self.assertFalse(verify_auth_stage(self.log.entry(4), tag, sha3))

    def test_argument_types(self):
        self.log.append("e")
        tag = self.log.auth(4)
        entry = self.log.entry(4)
        with self.assertRaises(TypeError):
            verify_auth_stage(("not", "entry"), tag, self.material)
        with self.assertRaises(TypeError):
            verify_auth_stage(entry, ("not", "tag"), self.material)
        with self.assertRaises(TypeError):
            verify_auth_stage(entry, tag, ("not", "material"))
        with self.assertRaises(TypeError):
            verify_auth_stage(entry, tag, self.stage0)  # a stage-0 Verifier

    def test_tag_stage_validated_first(self):
        self.log.append("e")
        tag = self.log.auth(4)
        entry = self.log.entry(4)
        for bad_stage, error in (
            (True, TypeError),
            ("0", TypeError),
            (-1, ValueError),
            (1 << 64, ValueError),
        ):
            tampered = AuthTag(0, tag.tag)
            object.__setattr__(tampered, "stage", bad_stage)
            with self.assertRaises(error):
                verify_auth_stage(entry, tampered, self.material)

    def test_material_fields_revalidated_when_bypassed(self):
        self.log.append("e")
        tag = self.log.auth(4)
        entry = self.log.entry(4)

        bad_stage = StageVerifier(4, bytes(32), "sha256")
        object.__setattr__(bad_stage, "stage", True)
        with self.assertRaises(TypeError):
            verify_auth_stage(entry, tag, bad_stage)

        bad_stage2 = StageVerifier(4, bytes(32), "sha256")
        object.__setattr__(bad_stage2, "stage", 1 << 64)
        with self.assertRaises(ValueError):
            verify_auth_stage(entry, tag, bad_stage2)

        bad_key = StageVerifier(4, bytes(32), "sha256")
        object.__setattr__(bad_key, "key", b"short")
        with self.assertRaises(ValueError):
            verify_auth_stage(entry, tag, bad_key)

        bad_key_type = StageVerifier(4, bytes(32), "sha256")
        object.__setattr__(bad_key_type, "key", "not-bytes")
        with self.assertRaises(TypeError):
            verify_auth_stage(entry, tag, bad_key_type)

        bad_hash = StageVerifier(4, bytes(32), "sha256")
        object.__setattr__(bad_hash, "hash_name", "not-a-hash")
        with self.assertRaises(ValueError):
            verify_auth_stage(entry, tag, bad_hash)

    def test_entry_and_tag_width_errors(self):
        self.log.append("e")
        tag = self.log.auth(4)
        entry = self.log.entry(4)
        with self.assertRaises(ValueError):
            verify_auth_stage(
                Entry(entry.index, entry.payload, b"\x00" * 31, entry.entry_hash),
                tag,
                self.material,
            )
        with self.assertRaises(ValueError):
            verify_auth_stage(
                Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 31),
                tag,
                self.material,
            )
        with self.assertRaises(ValueError):
            verify_auth_stage(entry, AuthTag(tag.stage, b"\x00" * 31), self.material)
        bad_index = Entry(-1, entry.payload, entry.previous_hash, entry.entry_hash)
        with self.assertRaises(ValueError):
            verify_auth_stage(bad_index, tag, self.material)


class AlternateHashStageTest(unittest.TestCase):
    def test_sha3_256_roundtrip_and_width(self):
        log = AuditLog(key=b"k", hash_name="sha3_256")
        for record in ("a", "b"):
            log.append(record)
        tag0 = log.auth(0)
        material = log.export_stage_verifier()
        self.assertEqual(material.stage, 1)
        self.assertEqual(len(material.key), hashlib.new("sha3_256").digest_size)
        self.assertFalse(verify_auth_stage(log.entry(0), tag0, material))
        tag1 = log.auth(1)
        self.assertTrue(verify_auth_stage(log.entry(1), tag1, material))
        # The stage-1 key must be exactly the sha3-256 evolution of stage 0.
        expected_key = hashlib.new("sha3_256", EVOLVE_DOMAIN + b"k").digest()
        self.assertEqual(material.key, expected_key)

    def test_stage_zero_material_allows_arbitrary_key(self):
        # A hand-built stage-0 StageVerifier with the construction key behaves
        # exactly like a Verifier over the same fields.
        log = AuditLog(key=b"arbitrary-length", hash_name="sha256")
        log.append("a")
        material = StageVerifier(0, b"arbitrary-length", "sha256")
        tag = log.auth(0)
        self.assertTrue(verify_auth_stage(log.entry(0), tag, material))


if __name__ == "__main__":
    unittest.main()
