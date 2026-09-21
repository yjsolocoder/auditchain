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


def make_log(n=5, *, key=KEY, hash_name="sha256"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in (f"record-{i}" for i in range(n)):
        log.append(record)
    return log


class AuthBatchShapeTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(5)
        self.verifier = self.log.export_verifier()

    def test_returns_tuple_of_entry_tag_pairs_sorted(self):
        items = self.log.auth_batch([3, 1, 0])
        self.assertIsInstance(items, tuple)
        self.assertEqual(len(items), 3)
        self.assertEqual([entry.index for entry, _ in items], [0, 1, 3])
        for item in items:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)
            self.assertIsInstance(item[0], Entry)
            self.assertIsInstance(item[1], AuthTag)
            self.assertEqual(item[0], self.log.entry(item[0].index))

    def test_stages_are_consecutive_from_initial_stage(self):
        self.log.rotate_key()
        items = self.log.auth_batch([4, 2])
        self.assertEqual([tag.stage for _, tag in items], [1, 2])
        self.assertEqual(self.log.stage, 3)

    def test_empty_selection_returns_empty_tuple_without_evolving(self):
        self.assertEqual(self.log.auth_batch(()), ())
        self.assertEqual(self.log.auth_batch([]), ())
        self.assertEqual(self.log.stage, 0)
        self.assertEqual(self.log._key, KEY)

    def test_accepts_a_generator(self):
        items = self.log.auth_batch(i for i in (2, 0))
        self.assertEqual([entry.index for entry, _ in items], [0, 2])

    def test_does_not_append_or_touch_chain(self):
        length = len(self.log)
        head = self.log.head
        entries = self.log.entries()
        self.log.auth_batch([0, 2, 4])
        self.assertEqual(len(self.log), length)
        self.assertEqual(self.log.head, head)
        self.assertEqual(self.log.entries(), entries)

    def test_records_newest_tag_per_index(self):
        first = self.log.auth(0)
        items = self.log.auth_batch([0, 1])
        self.assertEqual(self.log._tags[0], items[0][1])
        self.assertNotEqual(self.log._tags[0], first)
        self.assertEqual(self.log._tags[1], items[1][1])


class AuthBatchEquivalenceTest(unittest.TestCase):
    def setUp(self):
        self.ref = make_log(6)
        self.verifier = self.ref.export_verifier()

    def test_equals_sequential_auth_calls(self):
        batch_log = make_log(6)
        batch_verifier = batch_log.export_verifier()  # consume the one-time export
        # Rotate both logs the same number of times before minting.
        self.ref.rotate_key()
        batch_log.rotate_key()

        selection = [5, 0, 3, 2]
        batched = batch_log.auth_batch(iter(selection))
        ordered = sorted(selection)
        sequential = tuple(self.ref.auth(i) for i in ordered)

        self.assertEqual([entry.index for entry, _ in batched], ordered)
        self.assertEqual(len(batched), len(sequential))
        for (entry_b, tag_b), index, tag_s in zip(batched, ordered, sequential):
            self.assertEqual(entry_b, self.ref.entry(index))
            self.assertEqual(tag_b, tag_s)
        self.assertEqual(batch_log.stage, self.ref.stage)
        self.assertEqual(batch_log._key, self.ref._key)
        self.assertEqual(
            verify_auth_batch(batched, batch_verifier),
            tuple([True] * len(ordered)),
        )

    def test_tag_bytes_match_direct_hmac_composition(self):
        items = self.log_ref_with_stage0()
        entry0 = self.ref.entry(0)
        entry2 = self.ref.entry(2)
        expected0 = hmac.new(
            KEY, AUTH_DOMAIN + (0).to_bytes(8, "big") + entry0.entry_hash, "sha256"
        ).digest()
        key1 = evolve(KEY)
        expected2 = hmac.new(
            key1, AUTH_DOMAIN + (1).to_bytes(8, "big") + entry2.entry_hash, "sha256"
        ).digest()
        self.assertEqual(items[0][1].tag, expected0)
        self.assertEqual(items[1][1].tag, expected2)

    def log_ref_with_stage0(self):
        return self.ref.auth_batch([0, 2])

    def test_every_batch_tag_verifies_individually_and_together(self):
        items = self.ref.auth_batch([1, 3, 4])
        for entry, tag in items:
            self.assertTrue(verify_auth(entry, tag, self.verifier))
        self.assertEqual(
            verify_auth_batch(items, self.verifier),
            (True, True, True),
        )

    def test_indices_need_not_be_contiguous(self):
        items = self.ref.auth_batch([0, 5])
        self.assertEqual([tag.stage for _, tag in items], [0, 1])
        self.assertEqual(
            verify_auth_batch(items, self.verifier), (True, True)
        )


class AuthBatchValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(4)
        self.log.export_verifier()

    def snapshot(self):
        return (
            self.log.stage,
            self.log._key,
            dict(self.log._tags),
            self.log.head,
            len(self.log),
        )

    def test_keyless_mode_raises_value_error_even_when_empty(self):
        keyless = AuditLog()
        keyless.append("a")
        with self.assertRaises(ValueError):
            keyless.auth_batch([0])
        with self.assertRaises(ValueError):
            keyless.auth_batch(())

    def test_non_iterable_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.log.auth_batch(0)

    def test_non_integer_index_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.log.auth_batch(["0"])
        with self.assertRaises(TypeError):
            self.log.auth_batch([None])

    def test_bool_index_rejected(self):
        with self.assertRaises(TypeError):
            self.log.auth_batch([True])
        with self.assertRaises(TypeError):
            self.log.auth_batch([False])

    def test_duplicate_index_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.log.auth_batch([1, 2, 1])

    def test_out_of_range_index_raises_index_error(self):
        with self.assertRaises(IndexError):
            self.log.auth_batch([4])
        with self.assertRaises(IndexError):
            self.log.auth_batch([-1])

    def test_pruned_index_raises_index_error(self):
        self.log.auth(0)
        self.log.prune(2, self.log.seal(2))
        before = self.snapshot()
        with self.assertRaises(IndexError):
            self.log.auth_batch([1, 2])
        self.assertEqual(self.snapshot(), before)

    def test_failure_leaves_all_state_untouched(self):
        before = self.snapshot()
        for call in (
            lambda: self.log.auth_batch(["0"]),
            lambda: self.log.auth_batch([0, 0]),
            lambda: self.log.auth_batch([9]),
        ):
            with self.assertRaises((TypeError, ValueError, IndexError)):
                call()
            self.assertEqual(self.snapshot(), before)
        # Nothing was evolved: a successful batch afterwards starts at stage 0.
        items = self.log.auth_batch([0, 1])
        self.assertEqual([tag.stage for _, tag in items], [0, 1])

    def test_capacity_overflow_rejected_and_atomic(self):
        self.log._stage = (1 << 64) - 2
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.log.auth_batch([0, 1])
        self.assertEqual(self.snapshot(), before)
        # Exactly filling to stage 2**64-1 works; one more evolution cannot.
        items = self.log.auth_batch([0])
        self.assertEqual(items[0][1].stage, (1 << 64) - 2)
        self.assertEqual(self.log.stage, (1 << 64) - 1)
        with self.assertRaises(ValueError):
            self.log.auth_batch([1])


class AuthBatchPruneTest(unittest.TestCase):
    def test_batch_after_prune_uses_retained_range(self):
        log = make_log(6)
        verifier = log.export_verifier()
        log.auth_batch([0, 1])
        log.prune(3, log.seal(3))
        items = log.auth_batch([3, 5])
        self.assertEqual([tag.stage for _, tag in items], [2, 3])
        self.assertEqual(
            verify_auth_batch(items, verifier), (True, True)
        )
        self.assertEqual(sorted(log._tags), [3, 5])


class AlternateHashAuthBatchTest(unittest.TestCase):
    def test_sha3_256_batch(self):
        log = make_log(3, hash_name="sha3-256")
        verifier = log.export_verifier()
        log.rotate_key()
        items = log.auth_batch([0, 2])
        self.assertEqual([tag.stage for _, tag in items], [1, 2])
        width = hashlib.new("sha3-256").digest_size
        for _, tag in items:
            self.assertEqual(len(tag.tag), width)
        self.assertEqual(verify_auth_batch(items, verifier), (True, True))
        # A verifier with a different digest width sees the width mismatch as
        # a structural error; a same-width foreign hash simply verifies False.
        sha512 = Verifier(key=KEY, hash_name="sha512")
        with self.assertRaises(ValueError):
            verify_auth_batch(items, sha512)
        sha256 = Verifier(key=KEY, hash_name="sha256")
        self.assertEqual(verify_auth_batch(items, sha256), (False, False))


class VerifyAuthBatchShapeTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(5)
        self.verifier = self.log.export_verifier()
        self.items = self.log.auth_batch([0, 2, 4])

    def test_empty_tuple_returns_empty_tuple(self):
        self.assertEqual(verify_auth_batch((), self.verifier), ())

    def test_genuine_batch_all_true_in_order(self):
        self.assertEqual(
            verify_auth_batch(self.items, self.verifier), (True, True, True)
        )

    def test_results_follow_item_order(self):
        # Reordering pairs breaks the strictly-ascending index rule, even when
        # each individual pair is a genuine tag from a fresh log.
        other = make_log(5)
        other.export_verifier()
        t4 = other.auth(4)
        t0 = other.auth(0)
        reordered = ((other.entry(4), t4), (other.entry(0), t0))
        with self.assertRaises(ValueError):
            verify_auth_batch(reordered, self.verifier)

    def test_non_tuple_items_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_auth_batch([self.items[0]], self.verifier)
        with self.assertRaises(TypeError):
            verify_auth_batch(iter(self.items), self.verifier)

    def test_non_verifier_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_auth_batch(self.items, ("not", "verifier"))
        with self.assertRaises(TypeError):
            verify_auth_batch((), ("not", "verifier"))

    def test_bad_item_shape_raises_type_error(self):
        base = self.items
        with self.assertRaises(TypeError):
            verify_auth_batch(base + (("nope",),), self.verifier)
        with self.assertRaises(TypeError):
            verify_auth_batch(base + ((base[0][0], "nope"),), self.verifier)
        with self.assertRaises(TypeError):
            verify_auth_batch(base + (("nope", base[0][1]),), self.verifier)
        with self.assertRaises(TypeError):
            verify_auth_batch(base + ((base[0][0], base[0][1], None),), self.verifier)

    def test_index_type_errors(self):
        entry = self.items[0][0]
        tag = self.items[0][1]
        for bad_index in ("0", True):
            bad_entry = Entry(entry.index, entry.payload, entry.previous_hash, entry.entry_hash)
            object.__setattr__(bad_entry, "index", bad_index)
            with self.assertRaises(TypeError):
                verify_auth_batch(((bad_entry, tag),), self.verifier)

    def test_index_value_errors(self):
        entry = self.items[0][0]
        tag = self.items[0][1]
        for bad_index in (-1, 1 << 64):
            bad_entry = Entry(entry.index, entry.payload, entry.previous_hash, entry.entry_hash)
            object.__setattr__(bad_entry, "index", bad_index)
            with self.assertRaises(ValueError):
                verify_auth_batch(((bad_entry, tag),), self.verifier)

    def test_duplicate_and_unordered_indices_raise_value_error(self):
        e0, t0 = self.items[0]
        e2, t2 = self.items[1]
        with self.assertRaises(ValueError):
            verify_auth_batch(((e0, t0), (e0, t2)), self.verifier)
        with self.assertRaises(ValueError):
            verify_auth_batch(((e2, t0), (e0, t2)), self.verifier)

    def test_stage_type_errors(self):
        entry0, tag0 = self.items[0]
        for bad_stage in ("0", True):
            bad_tag = AuthTag(tag0.stage, tag0.tag)
            object.__setattr__(bad_tag, "stage", bad_stage)
            with self.assertRaises(TypeError):
                verify_auth_batch(((entry0, bad_tag),), self.verifier)

    def test_stage_value_errors(self):
        entry0, tag0 = self.items[0]
        for bad_stage in (-1, 1 << 64):
            bad_tag = AuthTag(tag0.stage, tag0.tag)
            object.__setattr__(bad_tag, "stage", bad_stage)
            with self.assertRaises(ValueError):
                verify_auth_batch(((entry0, bad_tag),), self.verifier)

    def test_nonconsecutive_stages_raise_value_error(self):
        e0, t0 = self.items[0]
        e2, _ = self.items[1]
        t_gap = AuthTag(5, b"\x00" * 32)
        with self.assertRaises(ValueError):
            verify_auth_batch(((e0, t0), (e2, t_gap)), self.verifier)

    def test_digest_width_errors(self):
        entry = self.items[0][0]
        tag = self.items[0][1]
        bad_prev = Entry(entry.index, entry.payload, b"\x00" * 31, entry.entry_hash)
        with self.assertRaises(ValueError):
            verify_auth_batch(((bad_prev, tag),), self.verifier)
        bad_hash = Entry(entry.index, entry.payload, entry.previous_hash, b"\x00" * 31)
        with self.assertRaises(ValueError):
            verify_auth_batch(((bad_hash, tag),), self.verifier)
        with self.assertRaises(ValueError):
            verify_auth_batch(((entry, AuthTag(tag.stage, b"\x00" * 31)),), self.verifier)

    def test_entry_field_type_errors(self):
        entry = self.items[0][0]
        tag = self.items[0][1]
        bad_payload = Entry(entry.index, entry.payload, entry.previous_hash, entry.entry_hash)
        object.__setattr__(bad_payload, "payload", "not-bytes")
        with self.assertRaises(TypeError):
            verify_auth_batch(((bad_payload, tag),), self.verifier)

    def test_tag_must_be_bytes(self):
        entry = self.items[0][0]
        tag = self.items[0][1]
        bad_tag = AuthTag(tag.stage, tag.tag)
        object.__setattr__(bad_tag, "tag", bytearray(tag.tag))
        with self.assertRaises(TypeError):
            verify_auth_batch(((entry, bad_tag),), self.verifier)

    def test_structural_failure_raises_before_any_verification(self):
        # Even though the first pair would mismatch, the malformed second
        # pair must raise rather than return partial results.
        e0, t0 = self.items[0]
        e2, _ = self.items[1]
        wrong_first = (e0, self.items[2][1])
        malformed = (wrong_first, (e2, "not-a-tag"))
        with self.assertRaises(TypeError):
            verify_auth_batch(malformed, self.verifier)


class VerifyAuthBatchMismatchTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(5)
        self.verifier = self.log.export_verifier()
        self.items = self.log.auth_batch([0, 1, 2])

    def test_one_bad_tag_only_flips_its_position(self):
        e1, t1 = self.items[1]
        forged = (e1, AuthTag(t1.stage, b"\x00" * len(t1.tag)))
        items = (self.items[0], forged, self.items[2])
        self.assertEqual(
            verify_auth_batch(items, self.verifier), (True, False, True)
        )

    def test_one_tampered_entry_only_flips_its_position(self):
        e1, t1 = self.items[1]
        tampered = Entry(e1.index, b"tampered", e1.previous_hash, e1.entry_hash)
        items = (self.items[0], (tampered, t1), self.items[2])
        self.assertEqual(
            verify_auth_batch(items, self.verifier), (True, False, True)
        )

    def test_wrong_verifier_key_all_false_no_raise(self):
        other = Verifier(key=b"a-completely-different-key", hash_name="sha256")
        self.assertEqual(
            verify_auth_batch(self.items, other), (False, False, False)
        )

    def test_nonzero_starting_stage_still_verifies(self):
        log = make_log(4)
        verifier = log.export_verifier()
        log.rotate_key()
        log.rotate_key()
        items = log.auth_batch([1, 3])
        self.assertEqual([tag.stage for _, tag in items], [2, 3])
        self.assertEqual(verify_auth_batch(items, verifier), (True, True))

    def test_hand_built_consecutive_stage_tuple_verifies(self):
        # The verifier accepts any structurally legal tuple, not only output
        # straight from auth_batch.
        log = make_log(3)
        verifier = log.export_verifier()
        t0 = log.auth(0)
        t2 = log.auth(2)
        items = ((log.entry(0), t0), (log.entry(2), t2))
        self.assertEqual([tag.stage for _, tag in items], [0, 1])
        self.assertEqual(verify_auth_batch(items, verifier), (True, True))


if __name__ == "__main__":
    unittest.main()
