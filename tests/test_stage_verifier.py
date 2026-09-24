import hashlib
import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    Entry,
    StageVerifier,
    Verifier,
    verify_auth,
    verify_auth_stage,
)

KEY = b"super-secret-key"


def make_log(count=4, key=KEY, hash_name="sha256"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(count):
        log.append(f"entry-{record}")
    return log


class StageVerifierConstructorTest(unittest.TestCase):
    def test_positional_fields_and_immutability(self):
        material = StageVerifier(3, b"\x11" * 32, "sha256")
        self.assertEqual((material.stage, material.key, material.hash_name),
                         (3, b"\x11" * 32, "sha256"))
        same = StageVerifier(3, b"\x11" * 32, "sha256")
        self.assertEqual(material, same)
        self.assertEqual(hash(material), hash(same))
        self.assertNotEqual(material, StageVerifier(4, b"\x11" * 32, "sha256"))
        self.assertNotEqual(material, StageVerifier(3, b"\x22" * 32, "sha256"))
        self.assertNotEqual(material, StageVerifier(3, b"\x11" * 32, "sha3_256"))
        for name, value in (
            ("stage", 9),
            ("key", b"other"),
            ("hash_name", "sha512"),
        ):
            with self.assertRaises(Exception):
                setattr(material, name, value)

    def test_stage_validation(self):
        StageVerifier(0, b"x", "sha256")
        StageVerifier((1 << 64) - 1, b"\x00" * 32, "sha256")
        with self.assertRaises(TypeError):
            StageVerifier(True, b"\x00" * 32, "sha256")
        with self.assertRaises(TypeError):
            StageVerifier("1", b"\x00" * 32, "sha256")
        with self.assertRaises(ValueError):
            StageVerifier(-1, b"\x00" * 32, "sha256")
        with self.assertRaises(ValueError):
            StageVerifier(1 << 64, b"\x00" * 32, "sha256")

    def test_key_validation(self):
        with self.assertRaises(TypeError):
            StageVerifier(1, "x" * 32, "sha256")
        with self.assertRaises(TypeError):
            StageVerifier(1, bytearray(b"x" * 32), "sha256")
        with self.assertRaises(TypeError):
            StageVerifier(1, memoryview(b"x" * 32), "sha256")
        with self.assertRaises(ValueError):
            StageVerifier(1, b"", "sha256")

    def test_key_width_must_match_digest_for_positive_stage(self):
        # Stage 0 accepts any non-empty key, exactly like the stage-0 Verifier.
        StageVerifier(0, b"a", "sha256")
        StageVerifier(1, b"\x00" * 32, "sha256")
        with self.assertRaises(ValueError):
            StageVerifier(1, b"\x00" * 31, "sha256")
        with self.assertRaises(ValueError):
            StageVerifier(1, b"\x00" * 33, "sha256")
        StageVerifier(2, b"\x00" * 32, "sha3-256")
        with self.assertRaises(ValueError):
            StageVerifier(2, b"\x00" * 28, "sha3-256")
        StageVerifier(5, b"\x00" * 64, "sha512")
        with self.assertRaises(ValueError):
            StageVerifier(5, b"\x00" * 32, "sha512")

    def test_hash_name_validation(self):
        with self.assertRaises(TypeError):
            StageVerifier(1, b"\x00" * 32, 123)
        with self.assertRaises(ValueError):
            StageVerifier(1, b"\x00" * 32, "not-a-hash")


class ExportStageVerifierTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.stage0 = self.log.export_verifier()
        self.tags = [self.log.auth(i) for i in range(4)]

    def test_requires_at_least_one_evolution(self):
        fresh = make_log()
        with self.assertRaises(ValueError):
            fresh.export_stage_verifier()

    def test_keyless_mode_rejected(self):
        keyless = AuditLog()
        keyless.append("a")
        with self.assertRaises(ValueError):
            keyless.export_stage_verifier()

    def test_export_after_auth_records_current_stage_and_key(self):
        # The four auth() calls above left the log at stage 4.
        self.assertEqual(self.log.stage, 4)
        material = self.log.export_stage_verifier()
        self.assertIsInstance(material, StageVerifier)
        self.assertEqual(material.stage, 4)
        self.assertEqual(material.hash_name, "sha256")
        self.assertEqual(len(material.key), hashlib.new("sha256").digest_size)

    def test_export_after_rotate_only(self):
        log = make_log(count=1)
        log.rotate_key()
        material = log.export_stage_verifier()
        self.assertEqual(material.stage, 1)

    def test_export_is_read_only_and_repeatable(self):
        first = self.log.export_stage_verifier()
        stage_before = self.log.stage
        key_before = self.log._key
        second = self.log.export_stage_verifier()
        third = self.log.export_stage_verifier()
        self.assertEqual(first, second)
        self.assertEqual(first, third)
        self.assertEqual(self.log.stage, stage_before)
        self.assertEqual(self.log._key, key_before)

    def test_export_does_not_consume_stage0_export_eligibility(self):
        # The two delivery layers are independent: exporting a stage-0
        # Verifier first does not block the stage material, and vice versa is
        # moot (stage material exists only after evolution).
        log = make_log(count=2)
        stage0 = log.export_verifier()
        self.assertIsInstance(stage0, Verifier)
        log.auth(0)
        material = log.export_stage_verifier()
        self.assertEqual(material.stage, 1)
        # Repeatable despite the earlier stage-0 export.
        self.assertEqual(log.export_stage_verifier(), material)

    def test_failed_export_leaves_state_untouched(self):
        fresh = make_log(count=2)
        stage0 = fresh.export_verifier()
        with self.assertRaises(ValueError):
            fresh.export_stage_verifier()
        # Nothing evolved: the next mint is still a stage-0 tag that the
        # stage-0 material verifies.
        tag = fresh.auth(0)
        self.assertEqual(tag.stage, 0)
        self.assertTrue(verify_auth(fresh.entry(0), tag, stage0))

    def test_failed_export_in_keyless_mode_leaves_state_untouched(self):
        keyless = AuditLog()
        keyless.append("a")
        with self.assertRaises(ValueError):
            keyless.export_stage_verifier()
        self.assertEqual(keyless.stage, 0)


class VerifyAuthStageTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.stage0 = self.log.export_verifier()
        self.tag0 = self.log.auth(0)
        self.tag1 = self.log.auth(1)
        # Delivery point: stage 2.
        self.material = self.log.export_stage_verifier()
        self.assertEqual(self.material.stage, 2)
        self.tag2 = self.log.auth(2)
        self.tag3 = self.log.auth(3)

    def test_delivery_stage_and_later_verify(self):
        self.assertTrue(verify_auth_stage(self.log.entry(2), self.tag2, self.material))
        self.assertTrue(verify_auth_stage(self.log.entry(3), self.tag3, self.material))

    def test_earlier_tags_return_false_while_stage0_material_accepts_them(self):
        # The same tag under the two different materials: stage-0 verifier
        # accepts everything; stage-2 material rejects earlier tags.
        for index, tag in enumerate((self.tag0, self.tag1, self.tag2, self.tag3)):
            entry = self.log.entry(index)
            self.assertTrue(verify_auth(entry, tag, self.stage0))
            expected = index >= 2
            self.assertIs(verify_auth_stage(entry, tag, self.material), expected)

    def test_boundary_is_inclusive_at_delivery_stage(self):
        # A tag minted exactly at the delivery stage verifies.
        self.assertTrue(verify_auth_stage(self.log.entry(2), self.tag2, self.material))
        # One stage earlier is rejected.
        self.assertFalse(verify_auth_stage(self.log.entry(1), self.tag1, self.material))

    def test_future_evolution_still_verifies_against_old_delivery(self):
        # Material delivered at stage 2 still reaches tags minted much later.
        log = make_log(count=7)
        log.export_verifier()
        log.auth(0)
        log.auth(1)
        material = log.export_stage_verifier()
        tags = [log.auth(i) for i in (2, 3, 4, 5)]
        for entry_index, tag in zip((2, 3, 4, 5), tags):
            self.assertTrue(verify_auth_stage(log.entry(entry_index), tag, material))
        # Delivering again at the later stage freezes the new boundary: the
        # earlier tags are now unverifiable, but a tag minted afterwards is.
        later = log.export_stage_verifier()
        self.assertEqual(later.stage, 6)
        self.assertFalse(verify_auth_stage(log.entry(2), tags[0], later))
        self.assertFalse(verify_auth_stage(log.entry(5), tags[3], later))
        tag6 = log.auth(6)
        self.assertTrue(verify_auth_stage(log.entry(6), tag6, later))
        # The first delivery still verifies the tag minted after it.
        self.assertTrue(verify_auth_stage(log.entry(6), tag6, material))

    def test_wrong_tag_returns_false(self):
        self.assertFalse(verify_auth_stage(self.log.entry(2), self.tag3, self.material))
        self.assertFalse(verify_auth_stage(self.log.entry(3), self.tag2, self.material))

    def test_tampered_entry_returns_false(self):
        entry = self.log.entry(2)
        forged = Entry(entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        self.assertFalse(verify_auth_stage(forged, self.tag2, self.material))

    def test_corrupt_tag_digest_returns_false(self):
        bad = AuthTag(self.tag2.stage, b"\x00" * len(self.tag2.tag))
        self.assertFalse(verify_auth_stage(self.log.entry(2), bad, self.material))

    def test_wrong_key_material_returns_false(self):
        other = StageVerifier(2, b"\x00" * 32, "sha256")
        self.assertFalse(verify_auth_stage(self.log.entry(2), self.tag2, other))

    def test_wrong_algorithm_material_returns_false(self):
        # A same-width algorithm name is structurally legal; the HMAC simply
        # does not authenticate.
        other = StageVerifier(2, self.material.key, "sha3-256")
        self.assertFalse(verify_auth_stage(self.log.entry(2), self.tag2, other))

    def test_earlier_stage_with_wrong_tag_is_still_false_not_error(self):
        self.assertFalse(verify_auth_stage(self.log.entry(0), self.tag1, self.material))

    def test_type_errors(self):
        entry, tag = self.log.entry(2), self.tag2
        with self.assertRaises(TypeError):
            verify_auth_stage(("not", "entry"), tag, self.material)
        with self.assertRaises(TypeError):
            verify_auth_stage(entry, ("not", "tag"), self.material)
        with self.assertRaises(TypeError):
            verify_auth_stage(entry, tag, ("not", "material"))

    def test_value_errors(self):
        entry, tag = self.log.entry(2), self.tag2
        with self.assertRaises(ValueError):
            verify_auth_stage(
                Entry(entry.index, entry.payload, b"\x00" * 31, entry.entry_hash),
                tag, self.material,
            )
        with self.assertRaises(ValueError):
            verify_auth_stage(
                Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 31),
                tag, self.material,
            )
        with self.assertRaises(ValueError):
            verify_auth_stage(entry, AuthTag(tag.stage, b"\x00" * 31), self.material)
        bad_index = Entry(-1, entry.payload, entry.previous_hash, entry.entry_hash)
        with self.assertRaises(ValueError):
            verify_auth_stage(bad_index, tag, self.material)

    def test_bypassed_tag_stage_corruption_raises(self):
        entry = self.log.entry(2)
        for bad_stage, error in (
            (True, TypeError),
            ("2", TypeError),
            (-1, ValueError),
            (1 << 64, ValueError),
        ):
            tampered = AuthTag(self.tag2.stage, self.tag2.tag)
            object.__setattr__(tampered, "stage", bad_stage)
            with self.assertRaises(error):
                verify_auth_stage(entry, tampered, self.material)

    def test_bypassed_material_corruption_raises(self):
        entry, tag = self.log.entry(2), self.tag2
        bad_stage = StageVerifier(2, self.material.key, "sha256")
        object.__setattr__(bad_stage, "stage", True)
        with self.assertRaises(TypeError):
            verify_auth_stage(entry, tag, bad_stage)
        bad_stage_value = StageVerifier(2, self.material.key, "sha256")
        object.__setattr__(bad_stage_value, "stage", 1 << 64)
        with self.assertRaises(ValueError):
            verify_auth_stage(entry, tag, bad_stage_value)
        bad_key_type = StageVerifier(2, self.material.key, "sha256")
        object.__setattr__(bad_key_type, "key", "not-bytes")
        with self.assertRaises(TypeError):
            verify_auth_stage(entry, tag, bad_key_type)
        bad_key_width = StageVerifier(2, self.material.key, "sha256")
        object.__setattr__(bad_key_width, "key", b"short")
        with self.assertRaises(ValueError):
            verify_auth_stage(entry, tag, bad_key_width)
        bad_hash = StageVerifier(2, self.material.key, "sha256")
        object.__setattr__(bad_hash, "hash_name", "not-a-hash")
        with self.assertRaises(ValueError):
            verify_auth_stage(entry, tag, bad_hash)

    def test_verification_order_matches_verify_auth(self):
        # tag.stage is validated before entry structure in both routines.
        entry = self.log.entry(2)
        broken_entry = Entry(entry.index, b"x", b"\x00" * 31, entry.entry_hash)
        tampered_tag = AuthTag(self.tag2.stage, self.tag2.tag)
        object.__setattr__(tampered_tag, "stage", -1)
        with self.assertRaises(ValueError):
            verify_auth_stage(broken_entry, tampered_tag, self.material)


class AlternateHashStageTest(unittest.TestCase):
    def test_sha3_256_stage_delivery(self):
        log = AuditLog(key=KEY, hash_name="sha3-256")
        log.append("a")
        log.append("b")
        log.export_verifier()
        tag0 = log.auth(0)
        material = log.export_stage_verifier()
        self.assertEqual((material.stage, len(material.key)), (1, 32))
        tag1 = log.auth(1)
        self.assertFalse(verify_auth_stage(log.entry(0), tag0, material))
        self.assertTrue(verify_auth_stage(log.entry(1), tag1, material))

    def test_wrong_width_material_rejected_before_verify(self):
        log = AuditLog(key=KEY, hash_name="sha3-256")
        log.append("a")
        log.rotate_key()
        material = log.export_stage_verifier()
        tag = log.auth(0)
        self.assertTrue(verify_auth_stage(log.entry(0), tag, material))
        # The constructor rejects a wrong-width positive-stage key outright;
        # bypassing it must still be caught defensively by the verifier.
        bad = StageVerifier(1, material.key, "sha3-256")
        object.__setattr__(bad, "key", b"\x00" * 64)
        with self.assertRaises(ValueError):
            verify_auth_stage(log.entry(0), tag, bad)


class StageDeliveryDoesNotChangeWireBehaviorTest(unittest.TestCase):
    def test_tags_byte_identical_under_both_materials(self):
        log = make_log(count=3)
        stage0 = log.export_verifier()
        tags = [log.auth(i) for i in range(3)]
        material = log.export_stage_verifier()
        self.assertEqual(material.stage, 3)
        # Exporting the stage material changed nothing about issued tags.
        for index, tag in enumerate(tags):
            self.assertTrue(verify_auth(log.entry(index), tag, stage0))
            self.assertFalse(verify_auth_stage(log.entry(index), tag, material))


if __name__ == "__main__":
    unittest.main()
