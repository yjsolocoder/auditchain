import json
import unittest

from auditchain import AuditLog


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def make_log():
    log = AuditLog()
    # 0: numbers and a string
    log.append(j({"a": 1, "b": {"c": "x"}, "arr": [10, 20]}))
    # 1: float numerically equal to 1
    log.append(j({"a": 1.0, "b": {"c": "y"}}))
    # 2: boolean true is a different kind
    log.append(j({"a": True}))
    # 3: the string "1" is a different kind
    log.append(j({"a": "1"}))
    # 4: explicit null
    log.append(j({"a": None}))
    # 5: payload that is not JSON at all
    log.append(b"not json")
    # 6: field present but an object (non-scalar)
    log.append(j({"a": {"nested": 1}}))
    # 7: field present but an array (non-scalar)
    log.append(j({"a": [1, 2]}))
    # 8: missing field
    log.append(j({"other": 1}))
    # 9: escaped member names
    log.append(j({"a/b": {"c~d": 7}}))
    # 10: top-level scalar
    log.append(b"42")
    # 11: top-level string
    log.append(b'"hello"')
    # 12: empty object
    log.append(b"{}")
    return log


class FindJsonBasicTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_integer_matches_int_and_float_number(self):
        self.assertEqual(self.log.find_json("/a", 1), (0, 1))

    def test_float_query_matches_by_numeric_value(self):
        self.assertEqual(self.log.find_json("/a", 1.0), (0, 1))

    def test_boolean_kind_is_separate_from_numbers(self):
        self.assertEqual(self.log.find_json("/a", True), (2,))
        self.assertEqual(self.log.find_json("/a", False), ())

    def test_string_kind_is_separate(self):
        self.assertEqual(self.log.find_json("/a", "1"), (3,))
        self.assertEqual(self.log.find_json("/a", "x"), ())

    def test_null_kind(self):
        self.assertEqual(self.log.find_json("/a", None), (4,))

    def test_nested_pointer(self):
        self.assertEqual(self.log.find_json("/b/c", "x"), (0,))
        self.assertEqual(self.log.find_json("/b/c", "y"), (1,))

    def test_array_index(self):
        self.assertEqual(self.log.find_json("/arr/0", 10), (0,))
        self.assertEqual(self.log.find_json("/arr/1", 20), (0,))
        self.assertEqual(self.log.find_json("/arr/2", 1), ())

    def test_escaped_reference_tokens(self):
        self.assertEqual(self.log.find_json("/a~1b/c~0d", 7), (9,))

    def test_root_pointer_scalar_documents(self):
        self.assertEqual(self.log.find_json("", 42), (10,))
        self.assertEqual(self.log.find_json("", "hello"), (11,))

    def test_root_pointer_on_object_documents_does_not_hit_scalar_query(self):
        self.assertEqual(self.log.find_json("", 42), (10,))


class FindJsonNonHitsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_non_json_payload_missing_field_and_non_scalars_do_not_hit(self):
        self.assertEqual(self.log.find_json("/a", 1), (0, 1))

    def test_index_into_non_container(self):
        log = AuditLog()
        log.append(b'"a string"')
        self.assertEqual(log.find_json("/0", "a string"), ())

    def test_array_token_rules(self):
        log = AuditLog()
        log.append(b"[1, 2, 3]")
        self.assertEqual(log.find_json("/0", 1), (0,))
        self.assertEqual(log.find_json("/01", 1), ())
        self.assertEqual(log.find_json("/-", 1), ())
        self.assertEqual(log.find_json("/3", 1), ())
        self.assertEqual(log.find_json("//", 1), ())

    def test_duplicate_member_names_are_not_queryable_anywhere(self):
        log = AuditLog()
        log.append(b'{"a": 1, "a": 2}')
        log.append(b'{"o": {"x": 1, "x": 2}}')
        self.assertEqual(log.find_json("/a", 1), ())
        self.assertEqual(log.find_json("/a", 2), ())
        self.assertEqual(log.find_json("/o/x", 1), ())
        self.assertEqual(log.find_json("/o/x", 2), ())

    def test_non_utf8_payload_does_not_hit(self):
        log = AuditLog()
        log.append(b'{"a": "\xff"}')
        self.assertEqual(log.find_json("/a", 1), ())

    def test_non_finite_number_literals_do_not_parse(self):
        log = AuditLog()
        log.append(b'{"a": NaN}')
        log.append(b'{"a": Infinity}')
        self.assertEqual(log.find_json("/a", 1), ())

    def test_encrypted_entries_never_hit(self):
        log = AuditLog()
        key = b"k" * 32
        log.append(j({"a": 1}))
        log.encrypt(j({"a": 1}), key)
        self.assertEqual(log.find_json("/a", 1), (0,))

    def test_json_like_plaintext_inside_envelope_never_hit(self):
        log = AuditLog()
        log.encrypt(b'{"a": 1}', b"k" * 32)
        self.assertEqual(log.find_json("/a", 1), ())


class FindJsonRangeTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_default_range_covers_retained_segment(self):
        self.assertEqual(
            self.log.find_json("/a", 1),
            tuple(i for i in range(len(self.log)) if i in (0, 1)),
        )

    def test_explicit_half_open_range(self):
        self.assertEqual(self.log.find_json("/a", 1, 0, 1), (0,))
        self.assertEqual(self.log.find_json("/a", 1, 1, 2), (1,))
        self.assertEqual(self.log.find_json("/a", 1, 2, 9), ())

    def test_range_type_and_value_errors_follow_find(self):
        with self.assertRaises(TypeError):
            self.log.find_json("/a", 1, True)
        with self.assertRaises(TypeError):
            self.log.find_json("/a", 1, 0, "2")
        with self.assertRaises(ValueError):
            self.log.find_json("/a", 1, -1)
        with self.assertRaises(ValueError):
            self.log.find_json("/a", 1, 0, len(self.log) + 1)
        with self.assertRaises(ValueError):
            self.log.find_json("/a", 1, 4, 2)

    def test_pruned_entries_do_not_hit(self):
        log = make_log()
        log.prune(2, log.seal(2))
        self.assertEqual(log.find_json("/a", 1), ())
        # Range may start only at the retain point.
        with self.assertRaises(ValueError):
            log.find_json("/a", 1, 0, 3)
        self.assertEqual(log.find_json("/a", True), (2,))


class FindJsonArgumentsTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_pointer_must_be_string(self):
        for bad in (b"/a", 1, None, ["/a"], object()):
            with self.assertRaises(TypeError):
                self.log.find_json(bad, 1)

    def test_value_must_be_scalar_json_type(self):
        for bad in ([1], {"x": 1}, b"1", bytearray(b"1")):
            with self.assertRaises(TypeError):
                self.log.find_json("/a", bad)

    def test_non_finite_float_value_is_value_error(self):
        for bad in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                self.log.find_json("/a", bad)

    def test_malformed_pointer(self):
        for bad in ("a", "/a~", "/a~2", "/a~x"):
            with self.assertRaises(ValueError):
                self.log.find_json(bad, 1)

    def test_empty_and_root_pointer_are_legal(self):
        self.log.find_json("", 1)
        self.log.find_json("/", 1)


class FindJsonLifecycleTest(unittest.TestCase):
    def _records(self):
        return (j({"a": 1}), j({"a": 2}), j({"a": 1}))

    def test_consistent_across_append_encrypt_and_prune(self):
        log = AuditLog()
        for payload in self._records():
            log.append(payload)
        log.encrypt(j({"a": 1}), b"k" * 32)
        self.assertEqual(log.find_json("/a", 1), (0, 2))
        log.prune(1, log.seal(1))
        self.assertEqual(log.find_json("/a", 1), (2,))
        log.append(j({"a": 1}))
        self.assertEqual(log.find_json("/a", 1), (2, 4))

    def test_consistent_across_dump_and_load(self):
        from auditchain import dump_log, load_log
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        log = AuditLog()
        for payload in self._records():
            log.append(payload)
        seed = bytes(range(32))
        blob = dump_log(log, seed)
        public_key = (
            Ed25519PrivateKey.from_private_bytes(seed)
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        restored = load_log(blob, public_key)
        self.assertEqual(restored.find_json("/a", 1), log.find_json("/a", 1))
        self.assertEqual(restored.find_json("/a", 2), log.find_json("/a", 2))

    def test_read_only(self):
        log = make_log()
        head = log.head
        root = log.merkle_root()
        entries = log.entries()
        log.find_json("/a", 1)
        log.find_json("", 42)
        with self.assertRaises(TypeError):
            log.find_json("/a", [1])
        with self.assertRaises(ValueError):
            log.find_json("bad", 1)
        self.assertEqual(log.head, head)
        self.assertEqual(log.merkle_root(), root)
        self.assertEqual(log.entries(), entries)


if __name__ == "__main__":
    unittest.main()
