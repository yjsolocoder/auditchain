import unittest

from auditchain import (
    AnchoredContinuationChain,
    AuditLog,
    ContinuationChainReport,
    SignedRoot,
    decode_anchored_continuations,
    encode_anchored_continuations,
    encode_continuations,
    encode_signed_root,
    inspect_anchored_continuations,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"
_MAGIC = b"auditchain/anchor/v1\0"


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(n=8, key=_KEY, hash_name="sha256", prefix="record"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _chain(sizes, seed=_SEED_A, n=None, **kwargs):
    if n is None:
        n = sizes[-1]
    receipts = []
    old = sizes[0]
    for new in sizes[1:]:
        receipt = _log(n, **kwargs).signed_auth_audit_continuation(
            old, (), seed, size=new
        )
        receipts.append(receipt)
        old = new
    return tuple(receipts)


def _bundle(sizes=(0, 2, 5), **kwargs):
    receipts = _chain(sizes, **kwargs)
    return AnchoredContinuationChain(
        receipts, receipts[0].consistency.old, receipts[-1].consistency.new
    )


def _u64(value):
    return value.to_bytes(8, "big")


def _blob(material):
    return _u64(len(material)) + material


class AnchoredContinuationChainTest(unittest.TestCase):
    def test_positional_construction_and_field_equality(self):
        bundle = _bundle()
        receipts = bundle.receipts
        again = AnchoredContinuationChain(
            receipts, bundle.start, bundle.end
        )
        self.assertEqual(bundle, again)
        self.assertEqual(hash(bundle), hash(again))
        self.assertIs(bundle.receipts, receipts)
        self.assertIsInstance(bundle.start, SignedRoot)
        self.assertIsInstance(bundle.end, SignedRoot)

    def test_frozen(self):
        bundle = _bundle()
        with self.assertRaises(Exception):
            bundle.start = bundle.end

    def test_non_tuple_receipts_raise_type_error(self):
        bundle = _bundle()
        for bad in ([bundle.receipts[0]], None, "r", 1, bundle.receipts[0]):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(bad, bundle.start, bundle.end)

    def test_empty_receipts_raise_value_error(self):
        bundle = _bundle()
        with self.assertRaises(ValueError):
            AnchoredContinuationChain((), bundle.start, bundle.end)

    def test_wrong_element_type_raises_type_error(self):
        bundle = _bundle()
        for bad in (b"bytes", "receipt", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain((bad,), bundle.start, bundle.end)

    def test_non_signed_root_anchors_raise_type_error(self):
        bundle = _bundle()
        for bad in (b"bytes", "anchor", None, 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(bundle.receipts, bad, bundle.end)
            with self.assertRaises(TypeError, msg=bad):
                AnchoredContinuationChain(bundle.receipts, bundle.start, bad)


class AnchoredContinuationCodecTest(unittest.TestCase):
    def test_canonical_layout(self):
        bundle = _bundle()
        expected = (
            _MAGIC
            + _u64(1)
            + _blob(encode_continuations(bundle.receipts))
            + _blob(encode_signed_root(bundle.start))
            + _blob(encode_signed_root(bundle.end))
        )
        self.assertEqual(encode_anchored_continuations(bundle), expected)

    def test_roundtrip(self):
        for sizes in ((0, 2), (0, 2, 5, 8), (3, 4)):
            bundle = _bundle(sizes)
            data = encode_anchored_continuations(bundle)
            back = decode_anchored_continuations(data)
            self.assertIsInstance(back, AnchoredContinuationChain)
            self.assertEqual(back, bundle)
            self.assertEqual(encode_anchored_continuations(back), data)

    def test_encode_non_bundle_raises_type_error(self):
        bundle = _bundle()
        for bad in (
            bundle.receipts,
            None,
            "b",
            1,
            (bundle.receipts, bundle.start, bundle.end),
        ):
            with self.assertRaises(TypeError, msg=bad):
                encode_anchored_continuations(bad)

    def test_decode_non_bytes_raises_type_error(self):
        data = encode_anchored_continuations(_bundle())
        for bad in (bytearray(data), memoryview(data), None, 1, "d"):
            with self.assertRaises(TypeError, msg=bad):
                decode_anchored_continuations(bad)

    def test_decode_bad_magic_raises_value_error(self):
        data = encode_anchored_continuations(_bundle())
        for bad in (b"", b"\x00" + data[1:], data[: len(_MAGIC) - 1]):
            with self.assertRaises(ValueError):
                decode_anchored_continuations(bad)

    def test_decode_bad_version_raises_value_error(self):
        data = encode_anchored_continuations(_bundle())
        for version in (0, 2, 1 << 40):
            bad = _MAGIC + _u64(version) + data[len(_MAGIC) + 8 :]
            with self.assertRaises(ValueError, msg=version):
                decode_anchored_continuations(bad)

    def test_decode_truncation_raises_value_error(self):
        data = encode_anchored_continuations(_bundle())
        for cut in (len(_MAGIC), len(_MAGIC) + 4, len(data) - 1, len(data) // 2):
            with self.assertRaises(ValueError, msg=cut):
                decode_anchored_continuations(data[:cut])

    def test_decode_oversized_blob_length_raises_value_error(self):
        data = encode_anchored_continuations(_bundle())
        bad = _MAGIC + _u64(1) + _u64(1 << 40) + data[len(_MAGIC) + 16 :]
        with self.assertRaises(ValueError):
            decode_anchored_continuations(bad)

    def test_decode_trailing_bytes_raise_value_error(self):
        data = encode_anchored_continuations(_bundle())
        with self.assertRaises(ValueError):
            decode_anchored_continuations(data + b"\x00")

    def test_decode_illegal_nested_encoding_raises_value_error(self):
        bundle = _bundle()
        good_chain = _blob(encode_continuations(bundle.receipts))
        bad_chain = _blob(b"not a chain")
        for chain in (bad_chain, _blob(encode_continuations(bundle.receipts)[:-1])):
            data = (
                _MAGIC
                + _u64(1)
                + chain
                + _blob(encode_signed_root(bundle.start))
                + _blob(encode_signed_root(bundle.end))
            )
            with self.assertRaises(ValueError):
                decode_anchored_continuations(data)
        bad_anchor = _blob(encode_signed_root(bundle.start)[:-1])
        data = (
            _MAGIC
            + _u64(1)
            + good_chain
            + bad_anchor
            + _blob(encode_signed_root(bundle.end))
        )
        with self.assertRaises(ValueError):
            decode_anchored_continuations(data)


class InspectAnchoredContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_success_report_shape(self):
        bundle = _bundle((0, 2, 5, 8))
        self.assertEqual(
            inspect_anchored_continuations(bundle, self.public_key),
            ContinuationChainReport(True, None, None),
        )

    def test_start_mismatch_reports_start_at_zero(self):
        bundle = _bundle()
        other = _bundle((1, 4, 7))
        report = inspect_anchored_continuations(
            AnchoredContinuationChain(
                bundle.receipts, other.start, bundle.end
            ),
            self.public_key,
        )
        self.assertEqual(report, ContinuationChainReport(False, 0, "start"))

    def test_end_mismatch_reports_end_at_last_index(self):
        bundle = _bundle((0, 2, 5, 8))
        other = _bundle((0, 2, 5, 8), prefix="other")
        report = inspect_anchored_continuations(
            AnchoredContinuationChain(
                bundle.receipts, bundle.start, other.end
            ),
            self.public_key,
        )
        self.assertEqual(report, ContinuationChainReport(False, 2, "end"))

    def test_internal_failure_returned_unchanged(self):
        bundle = _bundle()
        self.assertEqual(
            inspect_anchored_continuations(bundle, self.other_public_key),
            ContinuationChainReport(False, 0, "verify"),
        )

    def test_non_bundle_raises_type_error(self):
        bundle = _bundle()
        for bad in (bundle.receipts, None, "b", 1, object()):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchored_continuations(bad, self.public_key)

    def test_key_type_raises_type_error(self):
        bundle = _bundle()
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=bad):
                inspect_anchored_continuations(bundle, bad)

    def test_key_length_raises_value_error(self):
        bundle = _bundle()
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                inspect_anchored_continuations(bundle, bad)

    def test_call_is_read_only(self):
        bundle = _bundle()
        before = encode_anchored_continuations(bundle)
        inspect_anchored_continuations(bundle, self.public_key)
        self.assertEqual(encode_anchored_continuations(bundle), before)

    def test_decoded_bundle_inspects_like_source(self):
        bundle = _bundle((0, 2, 5))
        back = decode_anchored_continuations(
            encode_anchored_continuations(bundle)
        )
        self.assertEqual(
            inspect_anchored_continuations(back, self.public_key),
            ContinuationChainReport(True, None, None),
        )


if __name__ == "__main__":
    unittest.main()
