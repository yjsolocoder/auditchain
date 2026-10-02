import json
import unittest

from auditchain import AuditLog

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def make_log():
    """A mixed log of encrypted and plain entries."""
    log = AuditLog()
    log.encrypt(j({"a": 1, "b": {"c": "x"}, "arr": [10, 20]}), KEY, nonce=b"0" * 12)  # 0
    log.append(j({"a": 1}))  # 1 plain JSON: never a hit
    log.encrypt(j({"a": 1.0}), KEY, nonce=b"1" * 12)  # 2 hit by numeric equality
    log.encrypt(j({"a": True}), KEY, nonce=b"2" * 12)  # 3
    log.encrypt(j({"a": "1"}), KEY, nonce=b"3" * 12)  # 4
    log.encrypt(j({"a": None}), KEY, nonce=b"4" * 12)  # 5
    log.encrypt(b"not json", KEY, nonce=b"5" * 12)  # 6
    log.encrypt(j({"a": {"nested": 1}}), KEY, nonce=b"6" * 12)  # 7 non-scalar
    log.encrypt(j({"a": [1, 2]}), KEY, nonce=b"7" * 12)  # 8 non-scalar
    log.encrypt(j({"other": 1}), KEY, nonce=b"8" * 12)  # 9 missing field
    log.encrypt(j({"a": 1}), OTHER_KEY, nonce=b"9" * 12)  # 10 foreign key
    log.append(b"plain bytes")  # 11 plain non-JSON
    return log


class FindEncryptedJsonTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_basic_hits_strictly_ascending(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY), (0, 2))
        hits = self.log.find_encrypted_json("/a", 1, KEY)
        self.assertEqual(list(hits), sorted(set(hits)))

    def test_plain_json_entries_never_hit(self):
        # Index 1 is the same document appended without encryption.
        self.assertNotIn(1, self.log.find_encrypted_json("/a", 1, KEY))

    def test_foreign_key_entries_never_hit(self):
        self.assertNotIn(10, self.log.find_encrypted_json("/a", 1, KEY))

    def test_valid_wrong_key_yields_empty(self):
        # A well-formed 32-byte key that sealed nothing yields no hits.
        self.assertEqual(self.log.find_encrypted_json("/a", 1, b"z" * 32), ())

    def test_numeric_equality_across_int_and_float(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1.0, KEY), (0, 2))
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY), (0, 2))

    def test_json_kinds_stay_apart(self):
        self.assertEqual(self.log.find_encrypted_json("/a", True, KEY), (3,))
        self.assertEqual(self.log.find_encrypted_json("/a", "1", KEY), (4,))
        self.assertEqual(self.log.find_encrypted_json("/a", None, KEY), (5,))
        # True is not the number 1 and "1" is not the number 1.
        self.assertNotIn(3, self.log.find_encrypted_json("/a", 1, KEY))
        self.assertNotIn(4, self.log.find_encrypted_json("/a", 1, KEY))

    def test_nested_and_array_pointers(self):
        self.assertEqual(self.log.find_encrypted_json("/b/c", "x", KEY), (0,))
        self.assertEqual(self.log.find_encrypted_json("/arr/0", 10, KEY), (0,))
        self.assertEqual(self.log.find_encrypted_json("/arr/1", 20, KEY), (0,))
        self.assertEqual(self.log.find_encrypted_json("/arr/2", 30, KEY), ())

    def test_root_pointer(self):
        log = AuditLog()
        log.encrypt(b"42", KEY, nonce=b"n" * 12)
        log.encrypt(j([1, 2]), KEY, nonce=b"m" * 12)
        self.assertEqual(log.find_encrypted_json("", 42, KEY), (0,))
        # The root of an array document is not a scalar.
        self.assertEqual(log.find_encrypted_json("", 1, KEY), ())

    def test_escaped_pointer_tokens(self):
        log = AuditLog()
        log.encrypt(j({"a/b": 1, "c~d": 2}), KEY, nonce=b"e" * 12)
        self.assertEqual(log.find_encrypted_json("/a~1b", 1, KEY), (0,))
        self.assertEqual(log.find_encrypted_json("/c~0d", 2, KEY), (0,))

    def test_duplicate_members_never_hit(self):
        log = AuditLog()
        log.encrypt(b'{"a": 1, "a": 2}', KEY, nonce=b"d" * 12)
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY), ())
        self.assertEqual(log.find_encrypted_json("/a", 2, KEY), ())

    def test_invalid_utf8_and_non_finite_json_never_hit(self):
        log = AuditLog()
        log.encrypt(b"\xff\xfe", KEY, nonce=b"f" * 12)
        log.encrypt(b'{"a": NaN}', KEY, nonce=b"g" * 12)
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY), ())

    def test_missing_field_and_non_scalar_never_hit(self):
        self.assertEqual(self.log.find_encrypted_json("/missing", 1, KEY), ())
        # Entries 7 and 8 address an object and an array at /a: not scalars.
        self.assertNotIn(7, self.log.find_encrypted_json("/a", 1, KEY))
        self.assertNotIn(8, self.log.find_encrypted_json("/a", 1, KEY))
        # A pointer resolving into a non-scalar's member still resolves.
        self.assertEqual(self.log.find_encrypted_json("/a/nested", 1, KEY), (7,))

    def test_explicit_range(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY, 1, 3), (2,))
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY, 0, 2), (0,))
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY, 3, 3), ())

    def test_pruned_log_defaults_to_retained_segment(self):
        log = make_log()
        receipt = log.seal(4)
        log.prune(4, receipt)
        self.assertEqual(log.find_encrypted_json("/a", None, KEY), (5,))
        with self.assertRaises(ValueError):
            log.find_encrypted_json("/a", 1, KEY, 0, 4)

    def test_type_errors(self):
        for call in (
            lambda: self.log.find_encrypted_json(1, 1, KEY),
            lambda: self.log.find_encrypted_json(None, 1, KEY),
            lambda: self.log.find_encrypted_json(b"/a", 1, KEY),
            lambda: self.log.find_encrypted_json("/a", object(), KEY),
            lambda: self.log.find_encrypted_json("/a", [1], KEY),
            lambda: self.log.find_encrypted_json("/a", {"a": 1}, KEY),
            lambda: self.log.find_encrypted_json("/a", 1, "key"),
            lambda: self.log.find_encrypted_json("/a", 1, bytearray(32)),
            lambda: self.log.find_encrypted_json("/a", 1, KEY, "0"),
            lambda: self.log.find_encrypted_json("/a", 1, KEY, True),
            lambda: self.log.find_encrypted_json("/a", 1, KEY, 0, True),
        ):
            with self.assertRaises(TypeError, msg=call):
                call()

    def test_value_errors(self):
        for call in (
            lambda: self.log.find_encrypted_json("a", 1, KEY),
            lambda: self.log.find_encrypted_json("/a~2", 1, KEY),
            lambda: self.log.find_encrypted_json("/a", float("nan"), KEY),
            lambda: self.log.find_encrypted_json("/a", float("inf"), KEY),
            lambda: self.log.find_encrypted_json("/a", 1, b"short"),
            lambda: self.log.find_encrypted_json("/a", 1, bytes(33)),
            lambda: self.log.find_encrypted_json("/a", 1, KEY, -1),
            lambda: self.log.find_encrypted_json("/a", 1, KEY, 2, 1),
            lambda: self.log.find_encrypted_json("/a", 1, KEY, 0, len(self.log) + 1),
        ):
            with self.assertRaises(ValueError, msg=call):
                call()

    def test_query_is_read_only(self):
        before = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.find_encrypted(b"not json", KEY),
            self.log.find_json("/a", 1),
        )
        self.log.find_encrypted_json("/a", 1, KEY)
        after = (
            len(self.log),
            self.log.head,
            self.log.merkle_root(),
            self.log.find_encrypted(b"not json", KEY),
            self.log.find_json("/a", 1),
        )
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
