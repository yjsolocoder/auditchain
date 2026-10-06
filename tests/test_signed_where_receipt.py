import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auditchain import (
    AuditLog,
    Entry,
    JsonMultiIndex,
    SignedJsonMultiIndex,
    SignedWhereReceipt,
    WhereReceipt,
    decode_signed_where_receipt,
    decode_where_receipt,
    encode_json_multi_index,
    encode_signed_where_receipt,
    encode_where_receipt,
    sign_where_receipt,
    verify_json_multi_index,
    verify_signed_where_receipt,
    verify_where_receipt,
)

from tests.test_signed_json_multi_index import SEED_A, SEED_B, j, public_key

POINTERS = ("/a", "/b", "/z")


def _u64(value):
    return value.to_bytes(8, "big")


def _blob(material):
    return _u64(len(material)) + material


def signed_where_message(receipt_blob):
    return (
        b"auditchain/signed-where-receipt/v1\0"
        + b"\x01"
        + _blob(receipt_blob)
    )


def signed_multi_index_message(index_blob):
    return (
        b"auditchain/signed-json-multi-index/v1\0"
        + b"\x01"
        + _blob(index_blob)
    )


def make_log():
    log = AuditLog()
    # 0: integer 1 at /a and string x at /b
    log.append(j({"a": 1, "b": "x"}))
    # 1: float 1.0 at /a (the JSON number 1) and string y at /b
    log.append(j({"a": 1.0, "b": "y"}))
    # 2: boolean true at /a and string x at /b
    log.append(j({"a": True, "b": "x"}))
    # 3: string "1" at /a and string x at /b
    log.append(j({"a": "1", "b": "x"}))
    # 4: a matches the number 1 but /b is missing; /z is 9
    log.append(j({"a": 1, "z": 9}))
    # 5: not JSON
    log.append(b"not json")
    # 6: non-scalar at /a
    log.append(j({"a": [1], "b": "x"}))
    # 7: no queried fields
    log.append(j({"other": 1}))
    return log


def make_bundle(log=None, seed=SEED_A):
    log = log if log is not None else make_log()
    return log.signed_json_multi_index(POINTERS, seed)


def make_receipt(expression=("eq", "/b", "x"), start=None, stop=None, seed=SEED_A):
    return make_bundle(seed=seed).where_receipt(expression, start, stop)


def _raw_receipt(bundle, expression, start, stop, hits):
    """Build a WhereReceipt with frozen-field validation bypassed."""
    receipt = WhereReceipt.__new__(WhereReceipt)
    object.__setattr__(receipt, "bundle", bundle)
    object.__setattr__(receipt, "expression", expression)
    object.__setattr__(receipt, "start", start)
    object.__setattr__(receipt, "stop", stop)
    object.__setattr__(receipt, "hits", hits)
    return receipt


def _raw_signed(receipt, signature):
    """Build a SignedWhereReceipt with frozen-field validation bypassed."""
    item = SignedWhereReceipt.__new__(SignedWhereReceipt)
    object.__setattr__(item, "receipt", receipt)
    object.__setattr__(item, "signature", signature)
    return item


class SignedWhereIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.public = public_key(SEED_A)

    def test_bundle_shape_and_fields(self):
        receipt = self.bundle.where_receipt(("eq", "/b", "x"))
        signed = sign_where_receipt(receipt, SEED_A)
        self.assertIsInstance(signed, SignedWhereReceipt)
        self.assertEqual(signed.receipt, receipt)
        self.assertEqual(len(signed.signature), 64)

    def test_signature_is_over_canonical_receipt_message(self):
        receipt = self.bundle.where_receipt(
            ("and", (("ge", "/a", 1), ("le", "/a", 1))), 0, 5
        )
        signed = sign_where_receipt(receipt, SEED_A)
        expected = Ed25519PrivateKey.from_private_bytes(SEED_A).sign(
            signed_where_message(encode_where_receipt(receipt))
        )
        self.assertEqual(signed.signature, expected)

    def test_deterministic_and_repeatable(self):
        receipt = self.bundle.where_receipt(("eq", "/b", "x"))
        first = sign_where_receipt(receipt, SEED_A)
        second = sign_where_receipt(receipt, SEED_A)
        self.assertEqual(first, second)
        self.assertEqual(
            encode_signed_where_receipt(first),
            encode_signed_where_receipt(second),
        )

    def test_all_operators_sign_and_verify(self):
        expressions = (
            ("eq", "/a", 1),
            ("lt", "/a", 2),
            ("le", "/a", 1),
            ("gt", "/a", 0),
            ("ge", "/a", 1),
            ("prefix", "/b", "x"),
            ("exists", "/z"),
            ("and", (("eq", "/b", "x"), ("not", ("eq", "/a", True)))),
            ("or", (("eq", "/a", True), ("eq", "/b", "y"))),
            ("not", ("eq", "/a", 1)),
        )
        for expression in expressions:
            receipt = self.bundle.where_receipt(expression)
            signed = sign_where_receipt(receipt, SEED_A)
            self.assertTrue(
                verify_signed_where_receipt(signed, self.public),
                expression,
            )

    def test_empty_snapshot_empty_range_and_no_match(self):
        empty = make_bundle(AuditLog()).where_receipt(("and", ()))
        self.assertEqual(empty.hits, ())
        signed = sign_where_receipt(empty, SEED_A)
        self.assertTrue(verify_signed_where_receipt(signed, self.public))
        # An empty range and a query without matches sign and verify too.
        for receipt in (
            self.bundle.where_receipt(("and", ()), 3, 3),
            self.bundle.where_receipt(("eq", "/a", False)),
        ):
            self.assertEqual(receipt.hits, ())
            signed = sign_where_receipt(receipt, SEED_A)
            self.assertTrue(verify_signed_where_receipt(signed, self.public))

    def test_pruned_index_signs_and_verifies(self):
        log = make_log()
        log.prune(2, log.seal(2))
        bundle = log.signed_json_multi_index(POINTERS, SEED_A)
        receipt = bundle.where_receipt(("and", ()))
        self.assertEqual(receipt.hits, tuple(range(2, 8)))
        signed = sign_where_receipt(receipt, SEED_A)
        self.assertTrue(verify_signed_where_receipt(signed, self.public))

    def test_other_hash_algorithm_signs_and_verifies(self):
        log = AuditLog(hash_name="sha512")
        for value in ({"a": 1, "b": "x"}, {"a": 2, "b": "y"}):
            log.append(j(value))
        receipt = log.signed_json_multi_index(POINTERS, SEED_A).where_receipt(
            ("eq", "/b", "x")
        )
        signed = sign_where_receipt(receipt, SEED_A)
        self.assertTrue(verify_signed_where_receipt(signed, self.public))

    def test_signs_structurally_valid_receipt_whose_claim_is_wrong(self):
        # Signing checks structure only: an under-reporting receipt signs
        # just as well; verification is what reports the lie.
        receipt = WhereReceipt(
            self.bundle, ("eq", "/b", "x"), 0, 8, (0, 2)
        )
        signed = sign_where_receipt(receipt, SEED_A)
        self.assertFalse(verify_where_receipt(receipt, self.public))
        self.assertFalse(verify_signed_where_receipt(signed, self.public))

    def test_receipt_type_error(self):
        for bad in (None, "receipt", 1, self.bundle):
            with self.assertRaises(TypeError):
                sign_where_receipt(bad, SEED_A)

    def test_seed_type_and_length_errors(self):
        receipt = self.bundle.where_receipt(("eq", "/b", "x"))
        with self.assertRaises(TypeError):
            sign_where_receipt(receipt, "0" * 32)
        with self.assertRaises(ValueError):
            sign_where_receipt(receipt, b"short")

    def test_structural_error_raises_before_seed_check(self):
        # The bypassed illegal expression raises its own ValueError before
        # the seed is ever looked at.
        receipt = _raw_receipt(self.bundle, ("eq", "/a"), 0, 8, ())
        with self.assertRaises(ValueError):
            sign_where_receipt(receipt, b"short")

    def test_failure_leaves_no_partial_bundle(self):
        receipt = self.bundle.where_receipt(("eq", "/b", "x"))
        before = encode_where_receipt(receipt)
        with self.assertRaises(ValueError):
            sign_where_receipt(receipt, b"short")
        self.assertEqual(encode_where_receipt(receipt), before)


class SignedWhereVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = make_bundle(self.log)
        self.receipt = self.bundle.where_receipt(("eq", "/b", "x"))
        self.signed = sign_where_receipt(self.receipt, SEED_A)
        self.public_a = public_key(SEED_A)
        self.public_b = public_key(SEED_B)

    def test_genuine_bundle_verifies(self):
        self.assertTrue(
            verify_signed_where_receipt(self.signed, self.public_a)
        )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_where_receipt(self.signed, self.public_b)
        )
        self.assertFalse(
            verify_signed_where_receipt(self.signed, bytes(32))
        )

    def test_inner_index_signed_by_other_key_returns_false(self):
        # The outer signature is a genuine SEED_A signature over a receipt
        # whose bundled index was signed by SEED_B: the layers disagree.
        receipt = make_receipt(seed=SEED_B)
        signed = sign_where_receipt(receipt, SEED_A)
        self.assertFalse(verify_signed_where_receipt(signed, self.public_a))
        self.assertFalse(verify_signed_where_receipt(signed, self.public_b))

    def test_altered_signature_returns_false(self):
        tampered = SignedWhereReceipt(self.receipt, bytes(64))
        self.assertFalse(
            verify_signed_where_receipt(tampered, self.public_a)
        )

    def test_edited_expression_same_hits_returns_false(self):
        # ("and", (leaf,)) is a different expression with the same complete
        # result; the bare receipt accepts the swap, the sealed one not.
        edited = WhereReceipt(
            self.receipt.bundle,
            ("and", (("eq", "/b", "x"),)),
            self.receipt.start,
            self.receipt.stop,
            self.receipt.hits,
        )
        self.assertTrue(verify_where_receipt(edited, self.public_a))
        tampered = SignedWhereReceipt(edited, self.signed.signature)
        self.assertFalse(
            verify_signed_where_receipt(tampered, self.public_a)
        )

    def test_swapped_equivalent_branches_returns_false(self):
        expression = ("and", (("eq", "/b", "x"), ("eq", "/a", 1)))
        receipt = self.bundle.where_receipt(expression)
        signed = sign_where_receipt(receipt, SEED_A)
        swapped = WhereReceipt(
            receipt.bundle,
            ("and", (("eq", "/a", 1), ("eq", "/b", "x"))),
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        self.assertTrue(verify_where_receipt(swapped, self.public_a))
        tampered = SignedWhereReceipt(swapped, signed.signature)
        self.assertFalse(
            verify_signed_where_receipt(tampered, self.public_a)
        )

    def test_changed_scalar_type_returns_false(self):
        # 2 and 2.0 are different scalars with the same (empty) result.
        receipt = self.bundle.where_receipt(("eq", "/a", 2))
        self.assertEqual(receipt.hits, ())
        signed = sign_where_receipt(receipt, SEED_A)
        retyped = WhereReceipt(
            receipt.bundle,
            ("eq", "/a", 2.0),
            receipt.start,
            receipt.stop,
            receipt.hits,
        )
        self.assertTrue(verify_where_receipt(retyped, self.public_a))
        tampered = SignedWhereReceipt(retyped, signed.signature)
        self.assertFalse(
            verify_signed_where_receipt(tampered, self.public_a)
        )

    def test_edited_range_same_hits_returns_false(self):
        receipt = self.bundle.where_receipt(("eq", "/a", 1))
        self.assertEqual(receipt.hits, (0, 1, 4))
        signed = sign_where_receipt(receipt, SEED_A)
        narrowed = WhereReceipt(
            receipt.bundle, receipt.expression, 0, 5, receipt.hits
        )
        self.assertTrue(verify_where_receipt(narrowed, self.public_a))
        tampered = SignedWhereReceipt(narrowed, signed.signature)
        self.assertFalse(
            verify_signed_where_receipt(tampered, self.public_a)
        )

    def test_wrong_hits_signed_anyway_returns_false(self):
        # Under-report and over-report both fail even when the false claim
        # is sealed with a genuine signature of the trusted key.
        for hits in ((0, 2), (0, 2, 3, 5, 6)):
            receipt = WhereReceipt(
                self.bundle, ("eq", "/b", "x"), 0, 8, hits
            )
            signed = sign_where_receipt(receipt, SEED_A)
            self.assertFalse(
                verify_signed_where_receipt(signed, self.public_a)
            )

    def test_tampered_index_evidence_returns_false(self):
        # Even correctly signed by the trusted key at both layers, a bundle
        # whose index evidence does not hold against its root fails.
        index = self.bundle.index
        first = index.items[0]
        moved = Entry(
            first.index, b"zz", first.previous_hash, first.entry_hash
        )
        tampered_index = JsonMultiIndex(
            index.version,
            index.hash_name,
            index.size,
            index.root,
            index.head,
            index.retain_from,
            index.pointers,
            (moved,) + index.items[1:],
            index.proof,
            index.groups,
        )
        self.assertFalse(verify_json_multi_index(tampered_index))
        index_signature = Ed25519PrivateKey.from_private_bytes(SEED_A).sign(
            signed_multi_index_message(encode_json_multi_index(tampered_index))
        )
        forged_bundle = SignedJsonMultiIndex(tampered_index, index_signature)
        expression = ("eq", "/b", "x")
        receipt = WhereReceipt(
            forged_bundle,
            expression,
            0,
            8,
            forged_bundle.find_where(expression, 0, 8),
        )
        signed = sign_where_receipt(receipt, SEED_A)
        self.assertFalse(
            verify_signed_where_receipt(signed, self.public_a)
        )

    def test_bad_public_key_errors(self):
        with self.assertRaises(TypeError):
            verify_signed_where_receipt(self.signed, "0" * 32)
        with self.assertRaises(ValueError):
            verify_signed_where_receipt(self.signed, b"short")

    def test_bad_bundle_type(self):
        for bad in (None, "bundle", 1, self.receipt):
            with self.assertRaises(TypeError):
                verify_signed_where_receipt(bad, self.public_a)

    def test_bypassed_container_fields_raise(self):
        with self.assertRaises(TypeError):
            verify_signed_where_receipt(
                _raw_signed("not-a-receipt", self.signed.signature),
                self.public_a,
            )
        with self.assertRaises(TypeError):
            verify_signed_where_receipt(
                _raw_signed(self.receipt, "not-bytes"), self.public_a
            )
        with self.assertRaises(ValueError):
            verify_signed_where_receipt(
                _raw_signed(self.receipt, bytes(63)), self.public_a
            )

    def test_structural_error_not_masked_by_false(self):
        # A bypassed illegal expression raises its ValueError even though
        # the signature over the tampered receipt would not verify anyway.
        receipt = _raw_receipt(self.bundle, ("eq", "/a"), 0, 8, ())
        signed = _raw_signed(receipt, self.signed.signature)
        with self.assertRaises(ValueError):
            verify_signed_where_receipt(signed, self.public_a)
        # An out-of-range hit raises likewise.
        receipt = _raw_receipt(
            self.bundle, ("eq", "/b", "x"), 0, 8, (0, 2, 3, 6, 8)
        )
        signed = _raw_signed(receipt, self.signed.signature)
        with self.assertRaises(ValueError):
            verify_signed_where_receipt(signed, self.public_a)

    def test_verify_is_read_only(self):
        before = encode_signed_where_receipt(self.signed)
        verify_signed_where_receipt(self.signed, self.public_a)
        verify_signed_where_receipt(self.signed, self.public_b)
        self.assertEqual(encode_signed_where_receipt(self.signed), before)


class SignedWhereCodecTest(unittest.TestCase):
    def setUp(self):
        self.bundle = make_bundle()
        self.receipt = self.bundle.where_receipt(
            ("and", (("ge", "/a", 1), ("prefix", "/b", "x")))
        )
        self.signed = sign_where_receipt(self.receipt, SEED_A)
        self.public = public_key(SEED_A)

    def test_round_trip_is_byte_stable(self):
        data = encode_signed_where_receipt(self.signed)
        self.assertTrue(
            data.startswith(b"auditchain/signed-where-receipt/v1\0")
        )
        restored = decode_signed_where_receipt(data)
        self.assertEqual(restored, self.signed)
        self.assertEqual(encode_signed_where_receipt(restored), data)
        self.assertTrue(verify_signed_where_receipt(restored, self.public))

    def test_nested_receipt_blob_is_canonical(self):
        data = encode_signed_where_receipt(self.signed)
        offset = len(b"auditchain/signed-where-receipt/v1\0") + 8
        length = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        blob_ = data[offset:offset + length]
        self.assertEqual(blob_, encode_where_receipt(self.receipt))
        self.assertEqual(decode_where_receipt(blob_), self.receipt)
        # Exactly 64 signature bytes follow, with no trailing data.
        self.assertEqual(offset + length + 64, len(data))

    def test_unverifiable_bundle_still_round_trips(self):
        # A structurally sound bundle whose claim fails verification
        # encodes and decodes just as well.
        receipt = WhereReceipt(self.bundle, ("eq", "/b", "x"), 0, 8, (0,))
        signed = sign_where_receipt(receipt, SEED_A)
        self.assertFalse(verify_signed_where_receipt(signed, self.public))
        data = encode_signed_where_receipt(signed)
        restored = decode_signed_where_receipt(data)
        self.assertEqual(restored, signed)
        self.assertEqual(encode_signed_where_receipt(restored), data)
        self.assertFalse(verify_signed_where_receipt(restored, self.public))

    def test_non_bytes_raises_type_error(self):
        for bad in ("x", bytearray(b"0"), memoryview(b"0"), 1, None):
            with self.assertRaises(TypeError):
                decode_signed_where_receipt(bad)

    def test_bad_magic_and_version(self):
        data = encode_signed_where_receipt(self.signed)
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(b"x" + data[1:])
        magic = b"auditchain/signed-where-receipt/v1\0"
        bad = magic + (2).to_bytes(8, "big") + data[len(magic) + 8:]
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(bad)

    def test_truncation_and_trailing_bytes(self):
        data = encode_signed_where_receipt(self.signed)
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(data[:-1])
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(data + b"\x00")
        # A blob length reaching past the end is a truncation, not a crash.
        magic = b"auditchain/signed-where-receipt/v1\0"
        oversized = magic + _u64(1) + _u64(len(data) * 2) + b"\x00"
        with self.assertRaises(ValueError):
            decode_signed_where_receipt(oversized)

    def test_encode_type_errors(self):
        for bad in (None, "bundle", 1, self.receipt):
            with self.assertRaises(TypeError):
                encode_signed_where_receipt(bad)

    def test_encode_bypassed_container_fields_raise(self):
        with self.assertRaises(TypeError):
            encode_signed_where_receipt(
                _raw_signed(self.receipt, "not-bytes")
            )
        with self.assertRaises(ValueError):
            encode_signed_where_receipt(_raw_signed(self.receipt, bytes(63)))

    def test_constructor_field_validation(self):
        with self.assertRaises(TypeError):
            SignedWhereReceipt("not-a-receipt", bytes(64))
        with self.assertRaises(TypeError):
            SignedWhereReceipt(self.receipt, "not-bytes")
        with self.assertRaises(ValueError):
            SignedWhereReceipt(self.receipt, bytes(63))


if __name__ == "__main__":
    unittest.main()
