import json
import unittest

from auditchain import AuditLog, decrypt_entry

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
THIRD_KEY = bytes(reversed(range(32)))


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def make_log():
    log = AuditLog()
    # 0: integer field and a nested object / array
    log.encrypt(j({"a": 1, "b": {"c": "x"}, "arr": [10, 20]}), KEY, nonce=b"0" * 12)
    # 1: float numerically equal to 1
    log.encrypt(j({"a": 1.0, "b": {"c": "y"}}), KEY, nonce=b"1" * 12)
    # 2: boolean true is a different kind
    log.encrypt(j({"a": True}), KEY, nonce=b"2" * 12)
    # 3: the string "1" is a different kind
    log.encrypt(j({"a": "1"}), KEY, nonce=b"3" * 12)
    # 4: explicit null
    log.encrypt(j({"a": None}), KEY, nonce=b"4" * 12)
    # 5: decrypted plaintext is not JSON at all
    log.encrypt(b"not json", KEY, nonce=b"5" * 12)
    # 6: field present but an object (non-scalar)
    log.encrypt(j({"a": {"nested": 1}}), KEY, nonce=b"6" * 12)
    # 7: field present but an array (non-scalar)
    log.encrypt(j({"a": [1, 2]}), KEY, nonce=b"7" * 12)
    # 8: missing field
    log.encrypt(j({"other": 1}), KEY, nonce=b"8" * 12)
    # 9: escaped member names
    log.encrypt(j({"a/b": {"c~d": 7}}), KEY, nonce=b"9" * 12)
    # 10: top-level scalar
    log.encrypt(b"42", KEY, nonce=b"a" * 12)
    # 11: top-level string
    log.encrypt(b'"hello"', KEY, nonce=b"b" * 12)
    # 12: empty object
    log.encrypt(b"{}", KEY, nonce=b"c" * 12)
    # 13: repeated member name (strict JSON rejects)
    log.encrypt(b'{"a": 1, "a": 2}', KEY, nonce=b"d" * 12)
    # 14: non-finite number is not strict JSON
    log.encrypt(b'{"a": NaN}', KEY, nonce=b"e" * 12)
    # 15: plain JSON entry appended without encryption
    log.append(j({"a": 1}))
    # 16: matching document sealed under a different key
    log.encrypt(j({"a": 1}), OTHER_KEY, nonce=b"f" * 12)
    # 17: non-UTF-8 bytes sealed under KEY
    log.encrypt(b"\xff\xfe", KEY, nonce=b"10"[:1] + b"0" * 11)
    return log


class FindEncryptedJsonBasicTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_integer_matches_int_and_float_number(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY), (0, 1))

    def test_float_query_matches_by_numeric_value(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1.0, KEY), (0, 1))
        self.assertEqual(self.log.find_encrypted_json("/a", 1.5, KEY), ())

    def test_boolean_kind_is_separate_from_numbers(self):
        self.assertEqual(self.log.find_encrypted_json("/a", True, KEY), (2,))
        self.assertEqual(self.log.find_encrypted_json("/a", False, KEY), ())
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY), (0, 1))

    def test_string_kind_is_separate(self):
        self.assertEqual(self.log.find_encrypted_json("/a", "1", KEY), (3,))
        self.assertEqual(self.log.find_encrypted_json("/a", "x", KEY), ())

    def test_null_kind(self):
        self.assertEqual(self.log.find_encrypted_json("/a", None, KEY), (4,))

    def test_nested_pointer_and_escapes(self):
        self.assertEqual(self.log.find_encrypted_json("/b/c", "x", KEY), (0,))
        self.assertEqual(
            self.log.find_encrypted_json("/a~1b/c~0d", 7, KEY), (9,)
        )

    def test_array_index_tokens(self):
        self.assertEqual(self.log.find_encrypted_json("/arr/0", 10, KEY), (0,))
        self.assertEqual(self.log.find_encrypted_json("/arr/1", 20, KEY), (0,))

    def test_array_append_token_never_hits(self):
        self.assertEqual(self.log.find_encrypted_json("/arr/-", 10, KEY), ())

    def test_root_pointer_only_matches_top_level_scalars(self):
        self.assertEqual(self.log.find_encrypted_json("", 42, KEY), (10,))
        self.assertEqual(self.log.find_encrypted_json("", "hello", KEY), (11,))
        # Object/array documents addressed at root are non-scalars.
        self.assertEqual(self.log.find_encrypted_json("", 1, KEY), ())

    def test_missing_field_non_scalar_bad_json_never_hit(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY), (0, 1))
        # Traversing through a scalar is not a hit.
        self.assertEqual(self.log.find_encrypted_json("/a/nested/x", 1, KEY), ())
        # Out-of-range array indices and missing object members do not hit.
        self.assertEqual(self.log.find_encrypted_json("/a/5", 1, KEY), ())
        self.assertEqual(self.log.find_encrypted_json("/missing", 1, KEY), ())
        self.assertEqual(self.log.find_encrypted_json("/a", 2, KEY), ())
        self.assertEqual(self.log.find_encrypted_json("/a", 0, KEY), ())

    def test_plain_entries_never_enter_the_result(self):
        # Index 15 is plain JSON {"a": 1}; only the sealed copies hit.
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY), (0, 1))
        # Plain find_json still sees the plain entry but not the envelopes.
        self.assertEqual(self.log.find_json("/a", 1), (15,))

    def test_foreign_key_entries_never_hit(self):
        # Index 16 matches under OTHER_KEY only.
        self.assertEqual(self.log.find_encrypted_json("/a", 1, OTHER_KEY), (16,))
        self.assertEqual(self.log.find_encrypted_json("/a", 1, THIRD_KEY), ())

    def test_result_is_a_strictly_ascending_tuple(self):
        result = self.log.find_encrypted_json("/a", 1, KEY)
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, tuple(sorted(result)))
        self.assertEqual(len(result), len(set(result)))

    def test_empty_log(self):
        self.assertEqual(AuditLog().find_encrypted_json("/a", 1, KEY), ())


class FindEncryptedJsonStrictJsonTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_repeated_member_document_is_not_a_hit(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY), (0, 1))
        self.assertEqual(self.log.find_encrypted_json("/a", 2, KEY), ())

    def test_non_finite_number_document_is_not_a_hit(self):
        # The sealed {"a": NaN} document is not strict JSON and never hits
        # for any scalar query; a non-finite query itself is rejected like
        # in find_json.
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY), (0, 1))
        with self.assertRaises(ValueError):
            self.log.find_encrypted_json("/a", float("nan"), KEY)

    def test_non_utf8_plaintext_is_not_a_hit(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY), (0, 1))

    def test_index_17_is_authentic_but_not_json(self):
        plaintext = decrypt_entry(self.log.entry(17), KEY)
        self.assertEqual(plaintext, b"\xff\xfe")


class FindEncryptedJsonRangeTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for index in range(6):
            value = 1 if index % 2 == 0 else 2
            self.log.encrypt(
                j({"a": value}), KEY, nonce=bytes([index]) * 12
            )

    def test_default_range_is_whole_retained_segment(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY), (0, 2, 4))

    def test_half_open_explicit_range(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY, 1, 4), (2,))
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY, 2, 5), (2, 4))
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY, 0, 2), (0,))
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY, 4), (4,))
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY, None, 2), (0,))

    def test_empty_range(self):
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY, 2, 2), ())
        self.assertEqual(self.log.find_encrypted_json("/a", 1, KEY, 6, 6), ())

    def test_bound_type_errors(self):
        for bad in (True, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                self.log.find_encrypted_json("/a", 1, KEY, bad)
            with self.assertRaises(TypeError):
                self.log.find_encrypted_json("/a", 1, KEY, 0, bad)

    def test_bound_range_errors(self):
        with self.assertRaises(ValueError):
            self.log.find_encrypted_json("/a", 1, KEY, -1)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_json("/a", 1, KEY, 0, 7)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_json("/a", 1, KEY, 3, 2)
        with self.assertRaises(ValueError):
            self.log.find_encrypted_json("/a", 1, KEY, 7)


class FindEncryptedJsonValidationTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_pointer_type_error(self):
        for bad in (1, b"/a", None, ["/a"]):
            with self.assertRaises(TypeError):
                self.log.find_encrypted_json(bad, 1, KEY)

    def test_malformed_pointer_value_error(self):
        for bad in ("a", "/a~", "/a~2"):
            with self.assertRaises(ValueError):
                self.log.find_encrypted_json(bad, 1, KEY)

    def test_value_type_error(self):
        for bad in ([1], {"a": 1}, (1,), object()):
            with self.assertRaises(TypeError):
                self.log.find_encrypted_json("/a", bad, KEY)

    def test_non_finite_float_query_value_error(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                self.log.find_encrypted_json("/a", bad, KEY)

    def test_key_type_error(self):
        for bad in ("k" * 32, bytearray(KEY), memoryview(KEY), 123, None):
            with self.assertRaises(TypeError):
                self.log.find_encrypted_json("/a", 1, bad)

    def test_key_length_value_error(self):
        for bad in (b"", b"k" * 31, b"k" * 33):
            with self.assertRaises(ValueError):
                self.log.find_encrypted_json("/a", 1, bad)


class FindEncryptedJsonPruneTest(unittest.TestCase):
    def test_search_after_prune(self):
        log = AuditLog()
        for index in range(6):
            log.encrypt(j({"a": index % 2}), KEY, nonce=bytes([index]) * 12)
        log.prune(2, log.seal(2))
        self.assertEqual(log.find_encrypted_json("/a", 0, KEY), (2, 4))
        with self.assertRaises(ValueError):
            log.find_encrypted_json("/a", 0, KEY, 0, 4)
        self.assertEqual(log.find_encrypted_json("/a", 0, KEY, 2, 4), (2,))


class FindEncryptedJsonAlternateHashTest(unittest.TestCase):
    def test_sha3_256(self):
        log = AuditLog(hash_name="sha3-256")
        log.encrypt(j({"a": 1}), KEY, nonce=b"0" * 12)
        log.encrypt(j({"a": 1}), OTHER_KEY, nonce=b"1" * 12)
        log.append(j({"a": 1}))
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY), (0,))
        self.assertEqual(log.find_encrypted_json("/a", 1, OTHER_KEY), (1,))
        self.assertEqual(log.find_encrypted_json("/a", 1, THIRD_KEY), ())


class FindEncryptedJsonReadOnlyTest(unittest.TestCase):
    def test_queries_change_nothing(self):
        log = AuditLog()
        log.encrypt(j({"a": 1}), KEY, nonce=b"0" * 12)
        log.encrypt(j({"a": 2}), KEY, nonce=b"1" * 12)
        log.append(j({"a": 1}))
        snapshot = (
            len(log),
            log.head,
            log.entries(),
            log.merkle_root(),
            {k: list(v) for k, v in log._encrypted_index.items()},
            {k: list(v) for k, v in log._index.items()},
        )
        self.assertEqual(log.find_encrypted_json("/a", 1, KEY), (0,))
        self.assertEqual(log.find_encrypted_json("/a", 9, KEY), ())
        self.assertEqual(log.find_encrypted_json("/a", 1, OTHER_KEY), ())
        with self.assertRaises(ValueError):
            log.find_encrypted_json("/a", 1, b"short")
        with self.assertRaises(TypeError):
            log.find_encrypted_json(1, 1, KEY)
        current = (
            len(log),
            log.head,
            log.entries(),
            log.merkle_root(),
            {k: list(v) for k, v in log._encrypted_index.items()},
            {k: list(v) for k, v in log._index.items()},
        )
        self.assertEqual(current, snapshot)
        self.assertTrue(log.verify())
        self.assertEqual(decrypt_entry(log.entry(0), KEY), j({"a": 1}))


if __name__ == "__main__":
    unittest.main()
