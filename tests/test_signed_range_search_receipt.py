import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    RangeSearchReceipt,
    SignedRangeSearchReceipt,
    decode_range_search_receipt,
    decode_signed_range_search_receipt,
    encode_range_search_receipt,
    encode_signed_range_search_receipt,
    verify_range_search_receipt,
    verify_signed_range_search_receipt,
)

SEED_A = bytes(range(1, 33))
SEED_B = bytes(range(33, 65))


def public_key(seed):
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def signed_range_message(receipt_blob):
    def u64(value):
        return value.to_bytes(8, "big")

    def blob(material):
        return u64(len(material)) + material

    return (
        b"auditchain/signed-range-search/v1\0"
        + b"\x01"
        + blob(receipt_blob)
    )


def make_log():
    log = AuditLog()
    for record in ("a", "b", "aa", "c", "az", "b"):
        log.append(record)
    return log


class SignedRangeIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.public = public_key(SEED_A)

    def test_bundle_shape_and_fields(self):
        bundle = self.log.signed_range_search_receipt(b"a", b"c", SEED_A)
        self.assertIsInstance(bundle, SignedRangeSearchReceipt)
        self.assertEqual(
            bundle.receipt, self.log.range_search_receipt(b"a", b"c")
        )
        self.assertEqual(len(bundle.signature), 64)

    def test_signature_is_over_canonical_receipt_message(self):
        bundle = self.log.signed_range_search_receipt(b"a", b"c", SEED_A, 1, 5)
        blob_ = encode_range_search_receipt(bundle.receipt)
        expected = Ed25519PrivateKey.from_private_bytes(SEED_A).sign(
            signed_range_message(blob_)
        )
        self.assertEqual(bundle.signature, expected)

    def test_deterministic_and_repeatable(self):
        first = self.log.signed_range_search_receipt(b"a", b"c", SEED_A)
        second = self.log.signed_range_search_receipt(b"a", b"c", SEED_A)
        self.assertEqual(first, second)
        self.assertEqual(
            encode_signed_range_search_receipt(first),
            encode_signed_range_search_receipt(second),
        )

    def test_explicit_range_and_size(self):
        bundle = self.log.signed_range_search_receipt(
            b"a", b"c", SEED_A, 1, 5, size=5
        )
        self.assertEqual(bundle.receipt.start, 1)
        self.assertEqual(bundle.receipt.stop, 5)
        self.assertEqual(bundle.receipt.size, 5)
        self.assertTrue(
            verify_signed_range_search_receipt(bundle, self.public)
        )

    def test_empty_log_and_empty_range(self):
        empty = AuditLog()
        bundle = empty.signed_range_search_receipt(b"a", b"c", SEED_A)
        self.assertEqual(bundle.receipt.items, ())
        self.assertTrue(
            verify_signed_range_search_receipt(bundle, self.public)
        )
        bundle2 = self.log.signed_range_search_receipt(
            b"a", b"a", SEED_A, 2, 2
        )
        self.assertTrue(
            verify_signed_range_search_receipt(bundle2, self.public)
        )

    def test_failure_leaves_no_partial_bundle(self):
        with self.assertRaises(ValueError):
            self.log.signed_range_search_receipt(b"c", b"a", SEED_A)
        with self.assertRaises(ValueError):
            self.log.signed_range_search_receipt(b"a", b"c", b"short")
        with self.assertRaises(TypeError):
            self.log.signed_range_search_receipt(1, b"c", SEED_A)

    def test_seed_type_error(self):
        with self.assertRaises(TypeError):
            self.log.signed_range_search_receipt(b"a", b"c", "0" * 32)


class SignedRangeVerifyTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_range_search_receipt(b"a", b"c", SEED_A)
        self.public_a = public_key(SEED_A)
        self.public_b = public_key(SEED_B)

    def test_genuine_bundle_verifies(self):
        self.assertTrue(
            verify_signed_range_search_receipt(self.bundle, self.public_a)
        )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_range_search_receipt(self.bundle, self.public_b)
        )
        self.assertFalse(
            verify_signed_range_search_receipt(self.bundle, bytes(32))
        )

    def test_altered_signature_returns_false(self):
        tampered = SignedRangeSearchReceipt(
            self.bundle.receipt, bytes(64)
        )
        self.assertFalse(
            verify_signed_range_search_receipt(tampered, self.public_a)
        )

    def test_altered_bound_breaks_signature(self):
        receipt = self.bundle.receipt
        widened = RangeSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            b"",
            receipt.right,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
        )
        # Still internally authentic, but the old signature no longer binds it.
        self.assertTrue(verify_range_search_receipt(widened))
        tampered = SignedRangeSearchReceipt(widened, self.bundle.signature)
        self.assertFalse(
            verify_signed_range_search_receipt(tampered, self.public_a)
        )

    def test_altered_entry_makes_inner_verification_false(self):
        receipt = self.bundle.receipt
        entry0 = receipt.items[0]
        moved = type(entry0)(
            entry0.index, b"zz", entry0.previous_hash, entry0.entry_hash
        )
        items = (moved,) + receipt.items[1:]
        forged_receipt = RangeSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.left,
            receipt.right,
            receipt.start,
            receipt.stop,
            items,
            receipt.proof,
        )
        bundle = SignedRangeSearchReceipt(
            forged_receipt,
            Ed25519PrivateKey.from_private_bytes(SEED_B).sign(
                signed_range_message(
                    encode_range_search_receipt(forged_receipt)
                )
            ),
        )
        # Even a correctly-signed-by-B forgery fails: the inner receipt is
        # not authentic against its recorded root and proof.
        self.assertFalse(
            verify_signed_range_search_receipt(bundle, self.public_b)
        )

    def test_bad_public_key_errors(self):
        with self.assertRaises(TypeError):
            verify_signed_range_search_receipt(self.bundle, "0" * 32)
        with self.assertRaises(ValueError):
            verify_signed_range_search_receipt(self.bundle, b"short")

    def test_bad_bundle_type(self):
        with self.assertRaises(TypeError):
            verify_signed_range_search_receipt("bundle", self.public_a)


class SignedRangeCodecTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.bundle = self.log.signed_range_search_receipt(b"a", b"c", SEED_A)

    def test_round_trip_is_byte_stable(self):
        data = encode_signed_range_search_receipt(self.bundle)
        self.assertTrue(
            data.startswith(b"auditchain/signed-range-search/v1\0")
        )
        restored = decode_signed_range_search_receipt(data)
        self.assertEqual(restored, self.bundle)
        self.assertEqual(
            encode_signed_range_search_receipt(restored), data
        )

    def test_nested_receipt_blob_is_canonical(self):
        data = encode_signed_range_search_receipt(self.bundle)
        offset = len(b"auditchain/signed-range-search/v1\0") + 8
        length = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        blob_ = data[offset:offset + length]
        self.assertEqual(
            blob_, encode_range_search_receipt(self.bundle.receipt)
        )
        self.assertEqual(
            decode_range_search_receipt(blob_), self.bundle.receipt
        )
        # Exactly 64 signature bytes follow, with no trailing data.
        self.assertEqual(offset + length + 64, len(data))

    def test_non_bytes_raises_type_error(self):
        for bad in ("x", bytearray(b"0"), memoryview(b"0"), 1, None):
            with self.assertRaises(TypeError):
                decode_signed_range_search_receipt(bad)

    def test_bad_magic_and_version(self):
        data = encode_signed_range_search_receipt(self.bundle)
        with self.assertRaises(ValueError):
            decode_signed_range_search_receipt(b"x" + data[1:])
        magic = b"auditchain/signed-range-search/v1\0"
        bad = magic + (2).to_bytes(8, "big") + data[len(magic) + 8:]
        with self.assertRaises(ValueError):
            decode_signed_range_search_receipt(bad)

    def test_truncation_and_trailing_bytes(self):
        data = encode_signed_range_search_receipt(self.bundle)
        with self.assertRaises(ValueError):
            decode_signed_range_search_receipt(data[:-1])
        with self.assertRaises(ValueError):
            decode_signed_range_search_receipt(data + b"\x00")

    def test_signature_wrong_width_rejected(self):
        # Forge an encoding whose signature field holds only 63 bytes.
        data = encode_signed_range_search_receipt(self.bundle)
        with self.assertRaises(ValueError):
            decode_signed_range_search_receipt(data[:-1])

    def test_encode_type_errors(self):
        for bad in (None, "bundle", 1, self.bundle.receipt):
            with self.assertRaises(TypeError):
                encode_signed_range_search_receipt(bad)


if __name__ == "__main__":
    unittest.main()
