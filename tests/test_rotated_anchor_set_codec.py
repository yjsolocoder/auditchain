import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AnchoredContinuationChain,
    AuditLog,
    ContinuationChainReport,
    RotatedAnchorSet,
    RotatedChain,
    decode_rotated_anchor_set,
    encode_rotated_anchor,
    encode_rotated_anchor_set,
    encode_rotation,
    inspect_rotated_anchor_set,
    merge_rotated_anchor_set,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_D = bytes(range(3, 35))
_SEED_E = bytes(range(5, 37))
_SEED_F = bytes(range(7, 39))
_KEY = b"super-secret-verifier-key"
_MAGIC = b"auditchain/rotated-anchor-set/v1\0"

_OK = ContinuationChainReport(True, None, None)


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(n=15, key=_KEY, hash_name="sha256", prefix="record"):
    # Each continuation / rotation consumes the log holder's one-shot
    # verifier export, so every artifact is minted from a fresh log over
    # identical content.
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _segment(old_size, new_size, seed, **kwargs):
    return _log(**kwargs).signed_auth_audit_continuation(
        old_size, (), seed, size=new_size
    )


def _rotation(old_seed, new_seed, size, **kwargs):
    return _log(**kwargs).rotate_signer(old_seed, new_seed, size)


def _package(receipts, rotations):
    return RotatedChain(
        receipts,
        rotations,
        receipts[0].consistency.old,
        receipts[-1].consistency.new,
    )


def _u64(value):
    return value.to_bytes(8, "big")


def _blob(material):
    return _u64(len(material)) + material


def _stream(version, package_blobs, bridge_blobs, *, package_count=None,
            bridge_count=None):
    n = len(package_blobs) if package_count is None else package_count
    m = len(bridge_blobs) if bridge_count is None else bridge_count
    return b"".join(
        (
            _MAGIC,
            _u64(version),
            _u64(n),
            *(_blob(blob) for blob in package_blobs),
            _u64(m),
            *(_blob(blob) for blob in bridge_blobs),
        )
    )


class RotatedAnchorSetTest(unittest.TestCase):
    def setUp(self):
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.b0 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.r2 = _rotation(_SEED_C, _SEED_D, 8)
        self.s3 = _segment(8, 11, _SEED_D)
        self.b1 = _rotation(_SEED_D, _SEED_E, 11)
        self.s4 = _segment(11, 13, _SEED_E)
        self.r4 = _rotation(_SEED_E, _SEED_F, 13)
        self.s5 = _segment(13, 15, _SEED_F)
        self.p0 = _package((self.s0, self.s1), (self.r0,))
        self.p1 = _package((self.s2, self.s3), (self.r2,))
        self.p2 = _package((self.s4, self.s5), (self.r4,))
        self.items = (self.p0, self.p1, self.p2)
        self.bridges = (self.b0, self.b1)
        self.key_a = _public_key(_SEED_A)

    def _set(self, **kwargs):
        fields = dict(items=self.items, bridges=self.bridges)
        fields.update(kwargs)
        return RotatedAnchorSet(**fields)

    # --- construction -------------------------------------------------

    def test_positional_construction_and_equality(self):
        bundle = RotatedAnchorSet(self.items, self.bridges)
        again = RotatedAnchorSet(self.items, self.bridges)
        self.assertEqual(bundle, again)
        self.assertEqual(hash(bundle), hash(again))
        self.assertEqual(
            (bundle.items, bundle.bridges),
            (again.items, again.bridges),
        )
        self.assertEqual((bundle.items, bundle.bridges),
                         (self.items, self.bridges))

    def test_keyword_construction(self):
        self.assertEqual(
            self._set(),
            RotatedAnchorSet(self.items, self.bridges),
        )

    def test_single_package_empty_bridges(self):
        bundle = RotatedAnchorSet((self.p0,), ())
        self.assertEqual(bundle.items, (self.p0,))
        self.assertEqual(bundle.bridges, ())

    def test_equality_follows_fields(self):
        self.assertNotEqual(
            RotatedAnchorSet(self.items, self.bridges),
            RotatedAnchorSet((self.p0, self.p1), (self.b0,)),
        )
        other_bridge = (
            self.b0[0], self.b0[1], self.b0[2], b"\x00" * 64
        )
        self.assertNotEqual(
            RotatedAnchorSet((self.p0, self.p1), (self.b0,)),
            RotatedAnchorSet((self.p0, self.p1), (other_bridge,)),
        )

    def test_frozen(self):
        bundle = self._set()
        with self.assertRaises(AttributeError):
            bundle.items = (self.p0,)
        with self.assertRaises(AttributeError):
            bundle.bridges = ()

    def test_non_tuple_items_raises_type_error(self):
        for bad in ([self.p0], {self.p0}, None, self.p0, "items", 1):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedAnchorSet(bad, self.bridges)

    def test_non_tuple_bridges_raises_type_error(self):
        for bad in ([self.b0], None, "bridges", 1, object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedAnchorSet(self.items, bad)

    def test_empty_items_raises_value_error(self):
        with self.assertRaises(ValueError):
            RotatedAnchorSet((), ())

    def test_wrong_item_element_type_raises_type_error(self):
        anchored = AnchoredContinuationChain(
            self.p0.receipts, self.p0.start, self.p0.end
        )
        for bad in (b"bytes", "package", None, 1, self.s0, anchored):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedAnchorSet((bad,), ())
                with self.assertRaises(TypeError):
                    RotatedAnchorSet((self.p0, bad), (self.b0,))

    def test_bridge_count_must_be_packages_minus_one(self):
        with self.assertRaises(ValueError):
            RotatedAnchorSet((self.p0,), (self.b0,))
        with self.assertRaises(ValueError):
            RotatedAnchorSet((self.p0, self.p1), (), )
        with self.assertRaises(ValueError):
            RotatedAnchorSet(self.items, (self.b0,))
        with self.assertRaises(ValueError):
            RotatedAnchorSet(self.items, (self.b0, self.b1, self.b0))

    def test_wrong_bridge_element_type_raises_type_error(self):
        # Only the container shape is validated here, exactly as for
        # inspect_rotated_anchor_set: a bridge must be a tuple, while its
        # arity and element types are left to encode_rotation.
        for bad in (b"bytes", "bridge", None, 1, object(), [self.b0]):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    RotatedAnchorSet((self.p0, self.p1), (bad,))

    def test_bridge_tuple_arity_is_not_the_constructors_concern(self):
        # A tuple bridge of the wrong arity passes the shape checks; the
        # nested encoder is where its structure is validated.
        bundle = RotatedAnchorSet(
            (self.p0, self.p1), (self.b0[:3],)
        )
        self.assertEqual(bundle.bridges, (self.b0[:3],))
        with self.assertRaises(ValueError):
            encode_rotated_anchor_set(bundle)

    def test_arguments_have_no_defaults(self):
        with self.assertRaises(TypeError):
            RotatedAnchorSet(self.items)  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            RotatedAnchorSet()  # type: ignore[call-arg]


class EncodeRotatedAnchorSetTest(unittest.TestCase):
    def setUp(self):
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.b0 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.r2 = _rotation(_SEED_C, _SEED_D, 8)
        self.s3 = _segment(8, 11, _SEED_D)
        self.b1 = _rotation(_SEED_D, _SEED_E, 11)
        self.s4 = _segment(11, 13, _SEED_E)
        self.r4 = _rotation(_SEED_E, _SEED_F, 13)
        self.s5 = _segment(13, 15, _SEED_F)
        self.p0 = _package((self.s0, self.s1), (self.r0,))
        self.p1 = _package((self.s2, self.s3), (self.r2,))
        self.p2 = _package((self.s4, self.s5), (self.r4,))
        self.bundle = RotatedAnchorSet(
            (self.p0, self.p1, self.p2), (self.b0, self.b1)
        )
        self.key_a = _public_key(_SEED_A)

    def test_canonical_stream_layout(self):
        data = encode_rotated_anchor_set(self.bundle)
        p0 = encode_rotated_anchor(self.p0)
        p1 = encode_rotated_anchor(self.p1)
        p2 = encode_rotated_anchor(self.p2)
        r0 = encode_rotation(self.b0)
        r1 = encode_rotation(self.b1)
        expected = b"".join((
            _MAGIC,
            _u64(1),
            _u64(3),
            _blob(p0),
            _blob(p1),
            _blob(p2),
            _u64(2),
            _blob(r0),
            _blob(r1),
        ))
        self.assertEqual(data, expected)

    def test_magic_is_exactly_specified(self):
        data = encode_rotated_anchor_set(self.bundle)
        self.assertTrue(data.startswith(_MAGIC))
        self.assertEqual(
            _MAGIC, b"auditchain/rotated-anchor-set/v1\0"
        )

    def test_single_package_writes_zero_bridge_count(self):
        bundle = RotatedAnchorSet((self.p0,), ())
        data = encode_rotated_anchor_set(bundle)
        self.assertEqual(
            data,
            b"".join((
                _MAGIC,
                _u64(1),
                _u64(1),
                _blob(encode_rotated_anchor(self.p0)),
                _u64(0),
            )),
        )
        # The zero-length bridge list still writes the all-zero u64 count.
        self.assertEqual(data[-8:], _u64(0))

    def test_inner_blobs_reuse_existing_encodings(self):
        data = encode_rotated_anchor_set(self.bundle)
        offset = len(_MAGIC) + 8  # version
        self.assertEqual(data[offset:offset + 8], _u64(3))
        offset += 8  # package count
        for package in self.bundle.items:
            encoded = encode_rotated_anchor(package)
            self.assertEqual(data[offset:offset + 8], _u64(len(encoded)))
            offset += 8
            self.assertEqual(data[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(data[offset:offset + 8], _u64(2))
        offset += 8  # bridge count
        for bridge in self.bundle.bridges:
            encoded = encode_rotation(bridge)
            self.assertEqual(data[offset:offset + 8], _u64(len(encoded)))
            offset += 8
            self.assertEqual(data[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(offset, len(data))

    def test_non_bundle_raises_type_error(self):
        for bad in (
            None,
            b"bytes",
            "bundle",
            1,
            (self.p0,),
            self.p0,
            RotatedChain(
                self.p0.receipts,
                self.p0.rotations,
                self.p0.start,
                self.p0.end,
            ),
        ):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    encode_rotated_anchor_set(bad)

    def test_nested_encode_exception_propagates(self):
        # A set whose constructor checks were bypassed to hold a non-package
        # item: encode_rotated_anchor's TypeError propagates unchanged.
        bypassed = object.__new__(RotatedAnchorSet)
        object.__setattr__(bypassed, "items", (b"not-a-package",))
        object.__setattr__(bypassed, "bridges", ())
        with self.assertRaises(TypeError):
            encode_rotated_anchor_set(bypassed)

    def test_deterministic_and_order_sensitive(self):
        data = encode_rotated_anchor_set(self.bundle)
        self.assertEqual(encode_rotated_anchor_set(self.bundle), data)
        reordered = RotatedAnchorSet(
            (self.p0, self.p2, self.p1), (self.b0, self.b1)
        )
        self.assertNotEqual(
            encode_rotated_anchor_set(reordered), data
        )

    def test_call_is_read_only(self):
        items_before = tuple(
            encode_rotated_anchor(p) for p in self.bundle.items
        )
        bridges_before = tuple(
            encode_rotation(b) for b in self.bundle.bridges
        )
        encode_rotated_anchor_set(self.bundle)
        self.assertEqual(
            tuple(encode_rotated_anchor(p) for p in self.bundle.items),
            items_before,
        )
        self.assertEqual(
            tuple(encode_rotation(b) for b in self.bundle.bridges),
            bridges_before,
        )


class DecodeRotatedAnchorSetTest(unittest.TestCase):
    def setUp(self):
        self.s0 = _segment(0, 3, _SEED_A)
        self.r0 = _rotation(_SEED_A, _SEED_B, 3)
        self.s1 = _segment(3, 6, _SEED_B)
        self.b0 = _rotation(_SEED_B, _SEED_C, 6)
        self.s2 = _segment(6, 8, _SEED_C)
        self.r2 = _rotation(_SEED_C, _SEED_D, 8)
        self.s3 = _segment(8, 11, _SEED_D)
        self.b1 = _rotation(_SEED_D, _SEED_E, 11)
        self.s4 = _segment(11, 13, _SEED_E)
        self.r4 = _rotation(_SEED_E, _SEED_F, 13)
        self.s5 = _segment(13, 15, _SEED_F)
        self.p0 = _package((self.s0, self.s1), (self.r0,))
        self.p1 = _package((self.s2, self.s3), (self.r2,))
        self.p2 = _package((self.s4, self.s5), (self.r4,))
        self.bundle = RotatedAnchorSet(
            (self.p0, self.p1, self.p2), (self.b0, self.b1)
        )
        self.data = encode_rotated_anchor_set(self.bundle)
        self.key_a = _public_key(_SEED_A)

    def test_round_trip_restores_frozen_equal_bundle(self):
        restored = decode_rotated_anchor_set(self.data)
        self.assertIsInstance(restored, RotatedAnchorSet)
        self.assertEqual(restored, self.bundle)
        self.assertEqual(hash(restored), hash(self.bundle))
        self.assertEqual(restored.items, self.bundle.items)
        self.assertEqual(restored.bridges, self.bundle.bridges)
        with self.assertRaises(AttributeError):
            restored.items = ()

    def test_round_trip_preserves_tuple_order(self):
        restored = decode_rotated_anchor_set(self.data)
        self.assertEqual(
            [p for p in restored.items],
            [self.p0, self.p1, self.p2],
        )
        self.assertEqual(
            list(restored.bridges), [self.b0, self.b1]
        )

    def test_single_package_round_trip(self):
        bundle = RotatedAnchorSet((self.p0,), ())
        restored = decode_rotated_anchor_set(
            encode_rotated_anchor_set(bundle)
        )
        self.assertEqual(restored, bundle)

    def test_reencoding_reproduces_bytes_exactly(self):
        restored = decode_rotated_anchor_set(self.data)
        self.assertEqual(encode_rotated_anchor_set(restored), self.data)

    def test_restored_set_can_keep_being_diagnosed(self):
        # Cross-process recovery: the decoded artifact diagnoses and merges
        # exactly as the original, in a process that never held the logs.
        restored = decode_rotated_anchor_set(self.data)
        self.assertEqual(
            inspect_rotated_anchor_set(
                restored.items, restored.bridges, self.key_a
            ),
            _OK,
        )
        self.assertEqual(
            inspect_rotated_anchor_set(
                restored.items, restored.bridges, self.key_a
            ),
            inspect_rotated_anchor_set(
                self.bundle.items, self.bundle.bridges, self.key_a
            ),
        )
        merged = merge_rotated_anchor_set(
            restored.items, restored.bridges, self.key_a
        )
        self.assertEqual(
            merged,
            merge_rotated_anchor_set(
                self.bundle.items, self.bundle.bridges, self.key_a
            ),
        )

    def test_non_bytes_raises_type_error(self):
        for bad in (bytearray(self.data), memoryview(self.data), None, 1,
                    "data", object()):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    decode_rotated_anchor_set(bad)

    def test_bad_magic_raises_value_error(self):
        bad = b"x" + self.data[1:]
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(bad)

    def test_bad_version_raises_value_error(self):
        bad = _MAGIC + _u64(2) + self.data[len(_MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(bad)

    def test_empty_set_raises_value_error(self):
        # D || U(1) || U(0) || U(0): the zero package count is rejected.
        bad = _MAGIC + _u64(1) + _u64(0) + _u64(0)
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(bad)

    def test_empty_set_claiming_bridges_raises_value_error(self):
        bad = _MAGIC + _u64(1) + _u64(0) + _u64(1)
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(bad)

    def test_wrong_bridge_count_raises_value_error(self):
        # n == 1 with m == 1 (a real bridge blob): framing is complete and
        # every nested blob is legal, but m must be n - 1.
        package = encode_rotated_anchor(self.p0)
        bridge = encode_rotation(self.b0)
        bad = _stream(
            1, (package,), (bridge,), package_count=1, bridge_count=1
        )
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(bad)
        # n == 3 with m == 1: counts parse, all blobs are legal, the count
        # invariant fails.
        bad = _stream(
            1,
            tuple(encode_rotated_anchor(p)
                  for p in (self.p0, self.p1, self.p2)),
            (encode_rotation(self.b0),),
            package_count=3,
            bridge_count=1,
        )
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(bad)

    def test_truncation_raises_value_error(self):
        for cut in (
            len(_MAGIC),
            len(_MAGIC) + 8,
            len(self.data) - 1,
            len(self.data) - 8,
        ):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    decode_rotated_anchor_set(self.data[:cut])

    def test_trailing_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(self.data + b"\x00")
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(self.data + _u64(0))

    def test_oversized_blob_length_raises_value_error(self):
        # Inflate the first package's declared length past the remaining
        # bytes so the stream looks truncated.
        length_at = len(_MAGIC) + 8 + 8
        declared = int.from_bytes(
            self.data[length_at:length_at + 8], "big"
        )
        bad = (
            self.data[:length_at]
            + _u64(declared + 99)
            + self.data[length_at + 8:]
        )
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(bad)

    def test_nested_package_exception_propagates(self):
        # A legal-looking outer frame whose first package blob carries a
        # bad magic: decode_rotated_anchor's ValueError propagates.
        package = encode_rotated_anchor(self.p0)
        bad_package = b"x" + package[1:]
        bad = _stream(1, (bad_package,), ())
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(bad)

    def test_nested_bridge_exception_propagates(self):
        bridge = encode_rotation(self.b0)
        bad_bridge = b"x" + bridge[1:]
        bad = _stream(
            1,
            (encode_rotated_anchor(self.p0),
             encode_rotated_anchor(self.p1)),
            (bad_bridge,),
        )
        with self.assertRaises(ValueError):
            decode_rotated_anchor_set(bad)

    def test_failed_verification_still_decodes(self):
        # Structurally well-formed but cryptographically bogus: the bridge
        # carries a zeroed authorization. Encoding and decoding both
        # succeed; only inspection reports the failure.
        forged_bridge = (
            self.b0[0], self.b0[1], self.b0[2], b"\x00" * 64
        )
        bundle = RotatedAnchorSet(
            (self.p0, self.p1), (forged_bridge,)
        )
        restored = decode_rotated_anchor_set(
            encode_rotated_anchor_set(bundle)
        )
        self.assertEqual(restored, bundle)
        self.assertEqual(
            inspect_rotated_anchor_set(
                restored.items, restored.bridges, self.key_a
            ),
            ContinuationChainReport(False, 2, "rotation"),
        )

    def test_decoding_is_read_only_over_input(self):
        decode_rotated_anchor_set(self.data)
        self.assertEqual(
            self.data, encode_rotated_anchor_set(self.bundle)
        )


if __name__ == "__main__":
    unittest.main()
