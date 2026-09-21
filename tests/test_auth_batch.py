import hashlib
import hmac
import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    Entry,
    Verifier,
    verify_auth,
    verify_auth_batch,
)

KEY = b"super-secret-key"
AUTH_DOMAIN = b"auditchain/auth/v1"
EVOLVE_DOMAIN = b"auditchain/key-evolve/v1"


def evolve(key, hash_name="sha256"):
    return hashlib.new(hash_name, EVOLVE_DOMAIN + key).digest()


def make_log(n=5, key=KEY, hash_name="sha256"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"record-{record}")
    return log


class AuthBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(5)
        self.verifier = self.log.export_verifier()

    def test_empty_selection_returns_empty_tuple_and_does_not_evolve(self):
        self.assertEqual(self.log.auth_batch(()), ())
        self.assertEqual(self.log.auth_batch([]), ())
        self.assertEqual(self.log.stage, 0)
        self.assertEqual(len(self.log), 5)

    def test_accepts_a_generator(self):
        items = self.log.auth_batch(i for i in (2, 0))
        self.assertEqual([entry.index for entry, _ in items], [0, 2])

    def test_returns_entry_tag_pairs_in_ascending_index_order(self):
        items = self.log.auth_batch([3, 0, 2])
        self.assertIsInstance(items, tuple)
        self.assertEqual([entry.index for entry, _ in items], [0, 2, 3])
        for entry, tag in items:
            self.assertIsInstance(entry, Entry)
            self.assertIsInstance(tag, AuthTag)

    def test_stages_run_from_initial_stage_consecutively(self):
        self.log.rotate_key()
        items = self.log.auth_batch([3, 1])
        self.assertEqual([tag.stage for _, tag in items], [1, 2])
        self.assertEqual(self.log.stage, 3)

    def test_equals_consecutive_ascending_auth_calls(self):
        reference = make_log(5)
        reference.export_verifier()
        expected = tuple((reference.entry(i), reference.auth(i)) for i in (0, 2, 4))
        items = self.log.auth_batch([4, 2, 0])
        self.assertEqual(len(items), len(expected))
        for (entry, tag), (ref_entry, ref_tag) in zip(items, expected):
            self.assertEqual(entry, ref_entry)
            self.assertEqual(tag, ref_tag)
        self.assertEqual(self.log.stage, reference.stage)

    def test_single_item_matches_auth(self):
        reference = make_log(5)
        ref_tag = reference.auth(3)
        items = self.log.auth_batch([3])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][0], reference.entry(3))
        self.assertEqual(items[0][1], ref_tag)

    def test_tag_bytes_match_hmac_composition(self):
        items = self.log.auth_batch([0, 1])
        key1 = evolve(KEY)
        self.assertEqual(
            items[0][1].tag,
            hmac.new(
                KEY,
                AUTH_DOMAIN + (0).to_bytes(8, "big") + items[0][0].entry_hash,
                "sha256",
            ).digest(),
        )
        self.assertEqual(
            items[1][1].tag,
            hmac.new(
                key1,
                AUTH_DOMAIN + (1).to_bytes(8, "big") + items[1][0].entry_hash,
                "sha256",
            ).digest(),
        )

    def test_every_tag_verifies_offline(self):
        items = self.log.auth_batch([4, 1, 3])
        self.assertEqual(
            tuple(verify_auth(entry, tag, self.verifier) for entry, tag in items),
            (True, True, True),
        )

    def test_tags_are_stored_and_stage_advances_once_per_item(self):
        items = self.log.auth_batch([1, 3])
        self.assertEqual(self.log.stage, 2)
        self.assertEqual(sorted(self.log._tags), [1, 3])
        for index, (_, tag) in zip((1, 3), items):
            self.assertEqual(self.log._tags[index], tag)

    def test_does_not_append_or_change_public_objects(self):
        head = self.log.head
        root = self.log.merkle_root()
        entries = self.log.entries()
        self.log.auth_batch([0, 2, 4])
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log.head, head)
        self.assertEqual(self.log.merkle_root(), root)
        self.assertEqual(self.log.entries(), entries)
        self.assertEqual(self.log.find(b"record-1"), (1,))

    def test_same_entry_can_be_authenticated_in_a_later_batch(self):
        first = self.log.auth_batch([0])
        second = self.log.auth_batch([0])
        self.assertEqual((first[0][1].stage, second[0][1].stage), (0, 1))
        self.assertNotEqual(first[0][1].tag, second[0][1].tag)
        self.assertTrue(verify_auth(self.log.entry(0), second[0][1], self.verifier))

    def test_bool_indices_rejected(self):
        with self.assertRaises(TypeError):
            self.log.auth_batch([True])
        with self.assertRaises(TypeError):
            self.log.auth_batch([0, False])

    def test_non_integer_indices_rejected(self):
        with self.assertRaises(TypeError):
            self.log.auth_batch(["0"])
        with self.assertRaises(TypeError):
            self.log.auth_batch([1.0])

    def test_non_iterable_rejected(self):
        with self.assertRaises(TypeError):
            self.log.auth_batch(5)
        with self.assertRaises(TypeError):
            self.log.auth_batch(None)

    def test_duplicate_index_rejected(self):
        with self.assertRaises(ValueError):
            self.log.auth_batch([1, 2, 1])

    def test_out_of_range_index_rejected(self):
        with self.assertRaises(IndexError):
            self.log.auth_batch([5])
        with self.assertRaises(IndexError):
            self.log.auth_batch([-1])

    def test_pruned_index_rejected(self):
        self.log.prune(2, self.log.seal(2))
        with self.assertRaises(IndexError):
            self.log.auth_batch([1, 3])
        items = self.log.auth_batch([2, 3, 4])
        self.assertEqual([entry.index for entry, _ in items], [2, 3, 4])

    def test_stage_capacity_enforced_before_commit(self):
        self.log._stage = (1 << 64) - 3
        with self.assertRaises(ValueError):
            self.log.auth_batch([0, 1, 2])
        # Exactly the remaining two stages still fit.
        items = self.log.auth_batch([1, 0])
        self.assertEqual([tag.stage for _, tag in items], [(1 << 64) - 3, (1 << 64) - 2])
        self.assertEqual(self.log.stage, (1 << 64) - 1)
        # The batch rule requires stage + count < 2**64, so no further batch
        # fits even though a single auth() could still mint the last stage.
        with self.assertRaises(ValueError):
            self.log.auth_batch([2])
        single = self.log.auth(2)
        self.assertEqual(single.stage, (1 << 64) - 1)

    def test_keyless_mode_raises_valueerror(self):
        keyless = AuditLog()
        keyless.append("a")
        with self.assertRaises(ValueError):
            keyless.auth_batch([0])
        with self.assertRaises(ValueError):
            keyless.auth_batch(())

    def test_failure_is_atomic(self):
        before = (
            self.log.stage,
            self.log._key,
            dict(self.log._tags),
            self.log.head,
            len(self.log),
        )
        for call, error in (
            (lambda: self.log.auth_batch(["0"]), TypeError),
            (lambda: self.log.auth_batch([1, 1]), ValueError),
            (lambda: self.log.auth_batch([9]), IndexError),
        ):
            with self.assertRaises(error):
                call()
            self.assertEqual(
                (
                    self.log.stage,
                    self.log._key,
                    dict(self.log._tags),
                    self.log.head,
                    len(self.log),
                ),
                before,
            )
        # Nothing evolved: the next successful batch still starts at stage 0.
        items = self.log.auth_batch([0])
        self.assertEqual(items[0][1].stage, 0)
        self.assertEqual(self.log.stage, 1)

    def test_alternate_hash_algorithm(self):
        log = make_log(3, hash_name="sha3-256")
        verifier = log.export_verifier()
        items = log.auth_batch([2, 0])
        reference = make_log(3, hash_name="sha3-256")
        expected = tuple((reference.entry(i), reference.auth(i)) for i in (0, 2))
        self.assertEqual(items, expected)
        self.assertTrue(all(verify_auth(e, t, verifier) for e, t in items))


class VerifyAuthBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(5)
        self.verifier = self.log.export_verifier()
        self.items = self.log.auth_batch([4, 0, 2])

    def test_genuine_batch_all_true(self):
        self.assertEqual(
            verify_auth_batch(self.items, self.verifier), (True, True, True)
        )

    def test_empty_tuple(self):
        self.assertEqual(verify_auth_batch((), self.verifier), ())

    def test_matches_individual_verify_auth(self):
        expected = tuple(
            verify_auth(entry, tag, self.verifier) for entry, tag in self.items
        )
        self.assertEqual(verify_auth_batch(self.items, self.verifier), expected)

    def test_items_must_be_tuple(self):
        with self.assertRaises(TypeError):
            verify_auth_batch(list(self.items), self.verifier)
        with self.assertRaises(TypeError):
            verify_auth_batch(iter(self.items), self.verifier)

    def test_verifier_must_be_verifier(self):
        with self.assertRaises(TypeError):
            verify_auth_batch(self.items, ("not", "a", "verifier"))

    def test_element_shape_errors(self):
        entry, tag = self.items[0]
        with self.assertRaises(TypeError):
            verify_auth_batch((entry,), self.verifier)
        with self.assertRaises(TypeError):
            verify_auth_batch(((entry, tag, None),), self.verifier)
        with self.assertRaises(TypeError):
            verify_auth_batch((("not-entry", tag),), self.verifier)
        with self.assertRaises(TypeError):
            verify_auth_batch(((entry, "not-tag"),), self.verifier)

    def test_entry_index_type_errors(self):
        entry, tag = self.items[0]
        for bad_index in (True, "0", 1.0):
            tampered = Entry(
                bad_index, entry.payload, entry.previous_hash, entry.entry_hash
            )
            with self.assertRaises(TypeError):
                verify_auth_batch(((tampered, tag),), self.verifier)

    def test_entry_index_range_errors(self):
        entry, tag = self.items[0]
        for bad_index in (-1, 1 << 64):
            tampered = Entry(
                bad_index, entry.payload, entry.previous_hash, entry.entry_hash
            )
            with self.assertRaises(ValueError):
                verify_auth_batch(((tampered, tag),), self.verifier)

    def test_duplicate_and_unordered_indices_rejected(self):
        (e0, t0), (e2, t2), (_e4, _t4) = self.items
        with self.assertRaises(ValueError):
            verify_auth_batch(((e0, t0), (e0, t2)), self.verifier)
        with self.assertRaises(ValueError):
            verify_auth_batch(((e2, t0), (e0, t2)), self.verifier)

    def test_digest_width_errors(self):
        entry, tag = self.items[0]
        with self.assertRaises(ValueError):
            verify_auth_batch(
                (
                    (
                        Entry(entry.index, entry.payload, b"\x00" * 31, entry.entry_hash),
                        tag,
                    ),
                ),
                self.verifier,
            )
        with self.assertRaises(ValueError):
            verify_auth_batch(
                (
                    (
                        Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 31),
                        tag,
                    ),
                ),
                self.verifier,
            )

    def test_entry_field_type_errors(self):
        entry, tag = self.items[0]
        with self.assertRaises(TypeError):
            verify_auth_batch(
                ((Entry(entry.index, "not-bytes", entry.previous_hash, entry.entry_hash), tag),),
                self.verifier,
            )

    def test_non_consecutive_stages_rejected(self):
        (e0, t0), (e2, t2), (e4, t4) = self.items
        with self.assertRaises(ValueError):
            verify_auth_batch(((e0, t0), (e2, t4)), self.verifier)
        # Consecutive but descending.
        with self.assertRaises(ValueError):
            verify_auth_batch(((e0, t2), (e2, t0)), self.verifier)

    def test_tampered_tag_stage_raises(self):
        entry, tag = self.items[0]
        for bad_stage, error in (
            (True, TypeError),
            ("0", TypeError),
            (-1, ValueError),
            (1 << 64, ValueError),
        ):
            tampered = AuthTag(0, tag.tag)
            object.__setattr__(tampered, "stage", bad_stage)
            with self.assertRaises(error):
                verify_auth_batch(((entry, tampered),), self.verifier)

    def test_tampered_tag_bytes_raise_typeerror(self):
        entry, tag = self.items[0]
        tampered = AuthTag(tag.stage, tag.tag)
        object.__setattr__(tampered, "tag", bytearray(tag.tag))
        with self.assertRaises(TypeError):
            verify_auth_batch(((entry, tampered),), self.verifier)

    def test_wrong_tag_width_raises_valueerror(self):
        entry, tag = self.items[0]
        with self.assertRaises(ValueError):
            verify_auth_batch(((entry, AuthTag(tag.stage, tag.tag[:-1])),), self.verifier)

    def test_mismatch_at_one_position_only_yields_false_there(self):
        (e0, t0), (e2, t2), (e4, t4) = self.items
        # Keep the stages consecutive; corrupt only the middle tag's digest.
        bad_middle = AuthTag(t2.stage, b"\x00" * len(t2.tag))
        batch = ((e0, t0), (e2, bad_middle), (e4, t4))
        self.assertEqual(verify_auth_batch(batch, self.verifier), (True, False, True))

    def test_tampered_entry_yields_false(self):
        (e0, t0), (e2, t2), (e4, t4) = self.items
        forged = Entry(e2.index, b"tampered", e2.previous_hash, e2.entry_hash)
        self.assertEqual(
            verify_auth_batch(((e0, t0), (forged, t2), (e4, t4)), self.verifier),
            (True, False, True),
        )

    def test_wrong_verifier_key_all_false_no_exception(self):
        other = Verifier(key=b"a-completely-different-key", hash_name="sha256")
        self.assertEqual(verify_auth_batch(self.items, other), (False, False, False))

    def test_batch_after_rotation_verifies(self):
        log = make_log(4)
        verifier = log.export_verifier()
        log.rotate_key()
        log.rotate_key()
        items = log.auth_batch([1, 3])
        self.assertEqual([tag.stage for _, tag in items], [2, 3])
        self.assertEqual(verify_auth_batch(items, verifier), (True, True))

    def test_single_item_tuple(self):
        one = self.log.auth_batch([3])
        self.assertEqual(verify_auth_batch(one, self.verifier), (True,))


if __name__ == "__main__":
    unittest.main()
