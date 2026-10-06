import dataclasses
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auditchain import (
    AuditLog,
    SignedWhereReceipt,
    WhereReceipt,
    decode_signed_where_receipt,
    decode_where_receipt,
    encode_signed_where_receipt,
    encode_where_receipt,
    sign_where_receipt,
    verify_signed_where_receipt,
    verify_where_receipt,
)

from tests.test_signed_json_multi_index import SEED_A, SEED_B, j, public_key
from tests.test_where_receipt import make_bundle, make_log

MAGIC = b"auditchain/signed-where-receipt/v1\0"

EXPRESSION = ("and", (("eq", "/b", "x"), ("ge", "/a", 1)))


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def signed_where_message(receipt_blob):
    return MAGIC + b"\x01" + blob(receipt_blob)


def make_receipt(bundle=None, expression=EXPRESSION, start=None, stop=None):
    bundle = bundle if bundle is not None else make_bundle()
    return bundle.where_receipt(expression, start, stop)


def _raw_bundle(receipt, signature):
    """Build a SignedWhereReceipt with frozen-field validation bypassed."""
    bundle = SignedWhereReceipt.__new__(SignedWhereReceipt)
    object.__setattr__(bundle, "receipt", receipt)
    object.__setattr__(bundle, "signature", signature)
    return bundle


class SignWhereReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.receipt = make_receipt(self.bundle)
        self.public = public_key(SEED_A)

    def test_bundle_shape_and_fields(self):
        sealed = sign_where_receipt(self.receipt, SEED_A)
        self.assertIsInstance(sealed, SignedWhereReceipt)
        self.assertEqual(sealed.receipt, self.receipt)
        self.assertEqual(len(sealed.signature), 64)

    def test_signature_is_over_canonical_receipt_message(self):
        sealed = sign_where_receipt(self.receipt, SEED_A)
        expected = Ed25519PrivateKey.from_private_bytes(SEED_A).sign(
            signed_where_message(encode_where_receipt(self.receipt))
        )
        self.assertEqual(sealed.signature, expected)

    def test_deterministic_and_repeatable(self):
        first = sign_where_receipt(self.receipt, SEED_A)
        second = sign_where_receipt(self.receipt, SEED_A)
        self.assertEqual(first, second)
        self.assertEqual(
            encode_signed_where_receipt(first),
            encode_signed_where_receipt(second),
        )

    def test_bundle_is_immutable_and_compares_by_fields(self):
        sealed = sign_where_receipt(self.receipt, SEED_A)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            sealed.signature = b"\x00" * 64
        self.assertEqual(
            sealed, SignedWhereReceipt(sealed.receipt, sealed.signature)
        )
        self.assertNotEqual(
            sealed, sign_where_receipt(self.receipt, SEED_B)
        )

    def test_signs_structurally_valid_false_claim(self):
        # Signing checks structure only: a complete-but-wrong hit tuple
        # signs just as well; verification is what reports False.
        false_receipt = WhereReceipt(
            self.receipt.bundle,
            self.receipt.expression,
            self.receipt.start,
            self.receipt.stop,
            (),
        )
        sealed = sign_where_receipt(false_receipt, SEED_A)
        self.assertFalse(verify_signed_where_receipt(sealed, self.public))

    def test_non_receipt_raises_type_error(self):
        for bad in (None, "receipt", self.bundle, b"\x00" * 64):
            with self.assertRaises(TypeError):
                sign_where_receipt(bad, SEED_A)

    def test_seed_type_and_length(self):
        with self.assertRaises(TypeError):
            sign_where_receipt(self.receipt, "0" * 32)
        with self.assertRaises(TypeError):
            sign_where_receipt(self.receipt, bytearray(32))
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                sign_where_receipt(self.receipt, bad)

    def test_bypassed_receipt_fields_raise_like_the_constructor(self):
        raw = WhereReceipt.__new__(WhereReceipt)
        object.__setattr__(raw, "bundle", self.receipt.bundle)
        object.__setattr__(raw, "expression", ("eq", "/b"))
        object.__setattr__(raw, "start", self.receipt.start)
        object.__setattr__(raw, "stop", self.receipt.stop)
        object.__setattr__(raw, "hits", self.receipt.hits)
        with self.assertRaises(ValueError):
            sign_where_receipt(raw, SEED_A)

    def test_signing_is_read_only(self):
        before = encode_where_receipt(self.receipt)
        sign_where_receipt(self.receipt, SEED_A)
        self.assertEqual(encode_where_receipt(self.receipt), before)
        self.assertTrue(verify_where_receipt(self.receipt, self.public))


class VerifySignedWhereReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.receipt = make_receipt(self.bundle)
        self.sealed = sign_where_receipt(self.receipt, SEED_A)
        self.public = public_key(SEED_A)

    def test_genuine_bundle_verifies(self):
        self.assertTrue(verify_signed_where_receipt(self.sealed, self.public))

    def test_empty_range_empty_snapshot_and_zero_hits(self):
        empty = AuditLog()
        empty_bundle = empty.signed_json_multi_index(("/a",), SEED_A)
        empty_receipt = empty_bundle.where_receipt(("eq", "/a", 1))
        self.assertTrue(
            verify_signed_where_receipt(
                sign_where_receipt(empty_receipt, SEED_A), self.public
            )
        )
        empty_range = self.bundle.where_receipt(EXPRESSION, 2, 2)
        self.assertEqual(empty_range.hits, ())
        self.assertTrue(
            verify_signed_where_receipt(
                sign_where_receipt(empty_range, SEED_A), self.public
            )
        )
        no_match = self.bundle.where_receipt(("eq", "/b", "missing"))
        self.assertEqual(no_match.hits, ())
        self.assertTrue(
            verify_signed_where_receipt(
                sign_where_receipt(no_match, SEED_A), self.public
            )
        )

    def test_all_operators_verify(self):
        expressions = (
            ("eq", "/a", 1),
            ("lt", "/a", 2),
            ("le", "/a", 1),
            ("gt", "/a", 0),
            ("ge", "/a", 1),
            ("prefix", "/b", "x"),
            ("exists", "/z"),
            ("not", ("eq", "/b", "x")),
            ("or", (("eq", "/b", "y"), ("eq", "/z", 9))),
            EXPRESSION,
        )
        for expression in expressions:
            receipt = self.bundle.where_receipt(expression)
            sealed = sign_where_receipt(receipt, SEED_A)
            self.assertTrue(
                verify_signed_where_receipt(sealed, self.public),
                expression,
            )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_where_receipt(self.sealed, public_key(SEED_B))
        )

    def test_outer_signature_from_other_key_returns_false(self):
        other = sign_where_receipt(self.receipt, SEED_B)
        self.assertFalse(verify_signed_where_receipt(other, self.public))

    def test_inner_index_signature_from_other_key_returns_false(self):
        other_bundle = self.log.signed_json_multi_index(
            self.bundle.index.pointers, SEED_B
        )
        receipt = WhereReceipt(
            other_bundle,
            self.receipt.expression,
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        # Seal with SEED_A so only the nested index signature is foreign.
        sealed = sign_where_receipt(receipt, SEED_A)
        self.assertFalse(verify_signed_where_receipt(sealed, self.public))

    def test_tampered_signature_returns_false(self):
        signature = bytearray(self.sealed.signature)
        signature[0] ^= 1
        sealed = SignedWhereReceipt(self.receipt, bytes(signature))
        self.assertFalse(verify_signed_where_receipt(sealed, self.public))

    def test_tampered_index_evidence_returns_false(self):
        index = self.bundle.index
        raw_index = type(index).__new__(type(index))
        for field in dataclasses.fields(index):
            object.__setattr__(
                raw_index, field.name, getattr(index, field.name)
            )
        object.__setattr__(raw_index, "root", b"\x00" * len(index.root))
        raw_bundle = type(self.bundle).__new__(type(self.bundle))
        object.__setattr__(raw_bundle, "index", raw_index)
        object.__setattr__(raw_bundle, "signature", self.bundle.signature)
        receipt = WhereReceipt(
            raw_bundle,
            self.receipt.expression,
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        sealed = sign_where_receipt(receipt, SEED_A)
        self.assertFalse(verify_signed_where_receipt(sealed, self.public))

    def test_under_and_over_reported_hits_return_false(self):
        full = self.receipt.hits
        if full:
            under = WhereReceipt(
                self.receipt.bundle,
                self.receipt.expression,
                self.receipt.start,
                self.receipt.stop,
                full[:-1],
            )
            self.assertFalse(
                verify_signed_where_receipt(
                    sign_where_receipt(under, SEED_A), self.public
                )
            )
        over_claim = tuple(
            index
            for index in range(self.receipt.start, self.receipt.stop)
            if index not in full
        )[:1]
        if over_claim:
            over = WhereReceipt(
                self.receipt.bundle,
                self.receipt.expression,
                self.receipt.start,
                self.receipt.stop,
                tuple(sorted(full + over_claim)),
            )
            self.assertFalse(
                verify_signed_where_receipt(
                    sign_where_receipt(over, SEED_A), self.public
                )
            )

    def test_edited_expression_with_same_hits_returns_false(self):
        # The bare receipt's blind spot: the edited query still yields
        # exactly the declared hits, so verify_where_receipt accepts it —
        # the sealed signature must not.
        edited = WhereReceipt(
            self.receipt.bundle,
            ("and", (("ge", "/a", 1), ("eq", "/b", "x"))),
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        self.assertTrue(verify_where_receipt(edited, self.public))
        reused = SignedWhereReceipt(edited, self.sealed.signature)
        self.assertFalse(verify_signed_where_receipt(reused, self.public))

    def test_swapped_equivalent_branches_return_false(self):
        swapped = WhereReceipt(
            self.receipt.bundle,
            ("and", (("ge", "/a", 1), ("eq", "/b", "x"))),
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        reused = SignedWhereReceipt(swapped, self.sealed.signature)
        self.assertFalse(verify_signed_where_receipt(reused, self.public))

    def test_scalar_type_change_returns_false(self):
        changed = WhereReceipt(
            self.receipt.bundle,
            ("and", (("eq", "/b", "x"), ("ge", "/a", 1.0))),
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        reused = SignedWhereReceipt(changed, self.sealed.signature)
        self.assertFalse(verify_signed_where_receipt(reused, self.public))

    def test_edited_range_with_same_hits_returns_false(self):
        # Only entry 0 matches, so narrowing the range to [0, 1) keeps the
        # declared hits exactly the complete result of the edited query.
        narrow = self.bundle.where_receipt(EXPRESSION, 0, 1)
        self.assertEqual(narrow.hits, self.receipt.hits[:1])
        sealed = sign_where_receipt(narrow, SEED_A)
        widened = WhereReceipt(
            narrow.bundle,
            narrow.expression,
            narrow.start,
            self.receipt.stop,
            narrow.hits,
        )
        self.assertTrue(verify_where_receipt(widened, self.public))
        reused = SignedWhereReceipt(widened, sealed.signature)
        self.assertFalse(verify_signed_where_receipt(reused, self.public))

    def test_non_bundle_raises_type_error(self):
        for bad in (None, "bundle", self.receipt, b"\x00" * 64):
            with self.assertRaises(TypeError):
                verify_signed_where_receipt(bad, self.public)

    def test_public_key_type_and_length(self):
        with self.assertRaises(TypeError):
            verify_signed_where_receipt(self.sealed, "0" * 32)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                verify_signed_where_receipt(self.sealed, bad)

    def test_bypassed_container_fields_raise(self):
        raw = _raw_bundle("receipt", self.sealed.signature)
        with self.assertRaises(TypeError):
            verify_signed_where_receipt(raw, self.public)
        raw = _raw_bundle(self.receipt, bytearray(64))
        with self.assertRaises(TypeError):
            verify_signed_where_receipt(raw, self.public)
        raw = _raw_bundle(self.receipt, b"\x00" * 63)
        with self.assertRaises(ValueError):
            verify_signed_where_receipt(raw, self.public)

    def test_signature_failure_does_not_mask_structural_errors(self):
        raw_receipt = WhereReceipt.__new__(WhereReceipt)
        object.__setattr__(raw_receipt, "bundle", self.receipt.bundle)
        object.__setattr__(raw_receipt, "expression", self.receipt.expression)
        object.__setattr__(raw_receipt, "start", self.receipt.start)
        object.__setattr__(raw_receipt, "stop", self.receipt.stop)
        object.__setattr__(raw_receipt, "hits", (self.receipt.stop + 1,))
        raw = _raw_bundle(raw_receipt, b"\x00" * 64)
        with self.assertRaises(ValueError):
            verify_signed_where_receipt(raw, self.public)

    def test_verifying_is_read_only(self):
        before = encode_signed_where_receipt(self.sealed)
        verify_signed_where_receipt(self.sealed, self.public)
        self.assertEqual(encode_signed_where_receipt(self.sealed), before)


class SignedWhereReceiptCodecTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.receipt = make_receipt(self.bundle)
        self.sealed = sign_where_receipt(self.receipt, SEED_A)
        self.public = public_key(SEED_A)
        self.encoded = encode_signed_where_receipt(self.sealed)

    def test_layout(self):
        receipt_blob = encode_where_receipt(self.receipt)
        expected = (
            MAGIC
            + u64(1)
            + blob(receipt_blob)
            + self.sealed.signature
        )
        self.assertEqual(self.encoded, expected)

    def test_round_trip_restores_equal_bundle_and_identical_bytes(self):
        decoded = decode_signed_where_receipt(self.encoded)
        self.assertEqual(decoded, self.sealed)
        self.assertEqual(encode_signed_where_receipt(decoded), self.encoded)
        self.assertTrue(verify_signed_where_receipt(decoded, self.public))

    def test_unverifiable_but_structural_bundle_still_round_trips(self):
        false_receipt = WhereReceipt(
            self.receipt.bundle,
            self.receipt.expression,
            self.receipt.start,
            self.receipt.stop,
            (),
        )
        sealed = sign_where_receipt(false_receipt, SEED_A)
        encoded = encode_signed_where_receipt(sealed)
        decoded = decode_signed_where_receipt(encoded)
        self.assertEqual(decoded, sealed)
        self.assertFalse(verify_signed_where_receipt(decoded, self.public))

    def test_non_bundle_raises_type_error(self):
        for bad in (None, "bundle", self.receipt):
            with self.assertRaises(TypeError):
                encode_signed_where_receipt(bad)

    def test_bypassed_container_fields_raise(self):
        raw = _raw_bundle("receipt", self.sealed.signature)
        with self.assertRaises(TypeError):
            encode_signed_where_receipt(raw)
        raw = _raw_bundle(self.receipt, b"\x00" * 63)
        with self.assertRaises(ValueError):
            encode_signed_where_receipt(raw)

    def test_non_bytes_decode_input_raises_type_error(self):
        for bad in (bytearray(self.encoded), memoryview(self.encoded), 1):
            with self.assertRaises(TypeError):
                decode_signed_where_receipt(bad)

    def test_bad_magic_and_version_raise_value_error(self):
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(b"\x00" + self.encoded[1:])
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(
                encode_where_receipt(self.receipt)
            )
        bad_version = MAGIC + u64(2) + self.encoded[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(bad_version)

    def test_truncation_raises_value_error(self):
        for cut in (
            len(MAGIC),
            len(MAGIC) + 4,
            len(MAGIC) + 8,
            len(self.encoded) - 65,
            len(self.encoded) - 1,
        ):
            with self.assertRaises(ValueError):
                decode_signed_where_receipt(self.encoded[:cut])

    def test_oversized_blob_length_raises_value_error(self):
        oversized = MAGIC + u64(1) + u64(1 << 40) + self.encoded[len(MAGIC) + 16:]
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(oversized)

    def test_trailing_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(self.encoded + b"\x00")

    def test_nested_receipt_encoding_errors_raise_value_error(self):
        receipt_blob = encode_where_receipt(self.receipt)
        broken = MAGIC + u64(1) + blob(receipt_blob[:-1]) + self.sealed.signature
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(broken)

    def test_old_where_receipt_bytes_keep_decoding(self):
        # The new envelope does not change the bare receipt codec.
        old = encode_where_receipt(self.receipt)
        self.assertEqual(decode_where_receipt(old), self.receipt)


class SignedWhereReceiptSnapshotTest(unittest.TestCase):
    def test_pruned_snapshot(self):
        log = make_log()
        receipt = log.seal(2)
        log.prune(2, receipt)
        bundle = log.signed_json_multi_index(("/a", "/b", "/z"), SEED_A)
        where = bundle.where_receipt(EXPRESSION)
        sealed = sign_where_receipt(where, SEED_A)
        self.assertTrue(
            verify_signed_where_receipt(sealed, public_key(SEED_A))
        )
        decoded = decode_signed_where_receipt(encode_signed_where_receipt(sealed))
        self.assertTrue(
            verify_signed_where_receipt(decoded, public_key(SEED_A))
        )

    def test_other_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        for record in ({"a": 1, "b": "x"}, {"a": 2, "b": "y"}, {"a": 3}):
            log.append(j(record))
        bundle = log.signed_json_multi_index(("/a", "/b"), SEED_A)
        where = bundle.where_receipt(EXPRESSION)
        sealed = sign_where_receipt(where, SEED_A)
        self.assertTrue(
            verify_signed_where_receipt(sealed, public_key(SEED_A))
        )

    def test_works_off_decoded_bundle_without_log_or_key(self):
        bundle = make_bundle()
        sealed = sign_where_receipt(make_receipt(bundle), SEED_A)
        decoded = decode_signed_where_receipt(
            encode_signed_where_receipt(sealed)
        )
        self.assertTrue(
            verify_signed_where_receipt(decoded, public_key(SEED_A))
        )


if __name__ == "__main__":
    unittest.main()
