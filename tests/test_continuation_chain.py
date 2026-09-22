import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    SignedAuthAuditContinuation,
    SignedConsistency,
    SignedRoot,
    decode_continuations,
    decode_signed_auth_audit_continuation,
    encode_continuations,
    encode_signed_auth_audit_continuation,
    verify_continuation_chain,
    verify_signed_auth_audit_continuation,
)

MAGIC = b"auditchain/cont-chain/v1\0"

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_KEY = b"super-secret-verifier-key"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _log(n=9, key=_KEY, hash_name="sha256", prefix="record"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"{prefix}-{record}")
    return log


def _segment(old_size, indices, size, seed=_SEED_A, n=9, **kwargs):
    # Each continuation consumes its log's one-time export qualification,
    # so every segment is issued from a fresh twin log.
    return _log(n, **kwargs).signed_auth_audit_continuation(
        old_size, indices, seed, size
    )


def _chain(seed=_SEED_A, **kwargs):
    """A genuine three-segment chain 0->3, 3->6, 6->9."""
    return (
        _segment(0, (1,), 3, seed=seed, **kwargs),
        _segment(3, (4,), 6, seed=seed, **kwargs),
        _segment(6, (7, 8), 9, seed=seed, **kwargs),
    )


def _split_envelope(data):
    """Split an envelope into (version, count, receipt_blobs)."""
    assert data.startswith(MAGIC)
    offset = len(MAGIC)
    version = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    count = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    parts = []
    for _ in range(count):
        length = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        parts.append(data[offset:offset + length])
        offset += length
    assert offset == len(data)
    return version, count, parts


class VerifyContinuationChainTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def test_genuine_chain(self):
        self.assertTrue(
            verify_continuation_chain(_chain(), self.public_key)
        )

    def test_single_segment_chain(self):
        receipt = _segment(2, (3, 4), 5)
        self.assertTrue(
            verify_continuation_chain((receipt,), self.public_key)
        )

    def test_two_segment_chain(self):
        chain = _chain()
        self.assertTrue(
            verify_continuation_chain(chain[:2], self.public_key)
        )
        self.assertTrue(
            verify_continuation_chain(chain[1:], self.public_key)
        )

    def test_genesis_anchored_segment(self):
        receipt = _segment(0, (), 4)
        self.assertTrue(
            verify_continuation_chain((receipt,), self.public_key)
        )

    def test_reversed_order_rejected(self):
        chain = _chain()
        self.assertFalse(
            verify_continuation_chain(
                (chain[1], chain[0]), self.public_key
            )
        )

    def test_gap_rejected(self):
        chain = _chain()
        self.assertFalse(
            verify_continuation_chain(
                (chain[0], chain[2]), self.public_key
            )
        )

    def test_duplicate_segment_rejected(self):
        chain = _chain()
        self.assertFalse(
            verify_continuation_chain(
                (chain[0], chain[1], chain[1]), self.public_key
            )
        )
        self.assertFalse(
            verify_continuation_chain(
                (chain[0], chain[1], chain[0]), self.public_key
            )
        )

    def test_non_extending_segment_rejected(self):
        # old.size == new.size is a valid continuation on its own but not
        # a strict append-only extension of the chain.
        stale = _segment(3, (1,), 3)
        extending = _segment(3, (4,), 6)
        self.assertTrue(
            verify_signed_auth_audit_continuation(stale, self.public_key)
        )
        self.assertFalse(
            verify_continuation_chain((stale,), self.public_key)
        )
        self.assertFalse(
            verify_continuation_chain(
                (_segment(0, (1,), 3), stale), self.public_key
            )
        )
        self.assertTrue(
            verify_continuation_chain(
                (_segment(0, (1,), 3), extending), self.public_key
            )
        )

    def test_wrong_key_rejected(self):
        self.assertFalse(
            verify_continuation_chain(_chain(), self.other_public_key)
        )
        self.assertTrue(
            verify_continuation_chain(
                _chain(seed=_SEED_B), self.other_public_key
            )
        )

    def test_tampered_segment_rejected(self):
        chain = _chain()
        old = chain[1].consistency.old
        bogus_old = SignedRoot(
            old.version,
            old.hash_name,
            old.size,
            old.root,
            old.head,
            b"\x00" * 64,
        )
        tampered = SignedAuthAuditContinuation(
            chain[1].bundle,
            SignedConsistency(
                bogus_old,
                chain[1].consistency.new,
                chain[1].consistency.proof,
            ),
        )
        self.assertFalse(
            verify_continuation_chain(
                (chain[0], tampered, chain[2]), self.public_key
            )
        )

    def test_only_tuple_accepted(self):
        chain = _chain()
        for bad in (
            None,
            1,
            "receipts",
            b"bytes",
            list(chain),
            chain[0],
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_continuation_chain(bad, self.public_key)

    def test_empty_tuple_rejected(self):
        with self.assertRaises(ValueError):
            verify_continuation_chain((), self.public_key)

    def test_element_type_error(self):
        chain = _chain()
        for bad in (None, 1, "receipt", b"bytes", (), chain[0].bundle):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_continuation_chain(
                    (chain[0], bad), self.public_key
                )

    def test_public_key_type_and_length(self):
        chain = _chain()
        for bad in ("key", bytearray(self.public_key), None, 1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_continuation_chain(chain, bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=len(bad)):
                verify_continuation_chain(chain, bad)

    def test_call_is_read_only(self):
        chain = _chain()
        before = tuple(
            encode_signed_auth_audit_continuation(receipt)
            for receipt in chain
        )
        self.assertTrue(
            verify_continuation_chain(chain, self.public_key)
        )
        self.assertEqual(
            tuple(
                encode_signed_auth_audit_continuation(receipt)
                for receipt in chain
            ),
            before,
        )


class EncodeContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)

    def test_magic_and_field_layout(self):
        chain = _chain()
        data = encode_continuations(chain)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        # version=1
        self.assertEqual(data[offset:offset + 8], u64(1))
        offset += 8
        # receipt count
        self.assertEqual(data[offset:offset + 8], u64(len(chain)))
        offset += 8
        # One blob per receipt, in tuple order, each the complete
        # encode_signed_auth_audit_continuation output.
        for receipt in chain:
            part = encode_signed_auth_audit_continuation(receipt)
            self.assertEqual(data[offset:offset + 8], u64(len(part)))
            offset += 8
            self.assertEqual(data[offset:offset + len(part)], part)
            offset += len(part)
        self.assertEqual(offset, len(data))

    def test_expected_canonical_bytes(self):
        chain = _chain()
        expected = (
            MAGIC
            + u64(1)
            + u64(len(chain))
            + b"".join(
                blob(encode_signed_auth_audit_continuation(receipt))
                for receipt in chain
            )
        )
        self.assertEqual(encode_continuations(chain), expected)

    def test_blobs_are_exact_existing_encodings(self):
        chain = _chain()
        _, count, parts = _split_envelope(encode_continuations(chain))
        self.assertEqual(count, len(chain))
        for receipt, part in zip(chain, parts):
            self.assertEqual(
                part, encode_signed_auth_audit_continuation(receipt)
            )
            # Each blob is independently decodable by the existing codec.
            self.assertEqual(
                decode_signed_auth_audit_continuation(part), receipt
            )

    def test_encode_is_deterministic(self):
        chain = _chain()
        self.assertEqual(
            encode_continuations(chain), encode_continuations(chain)
        )

    def test_no_new_signing_message(self):
        # The segments ride along verbatim as their existing canonical
        # encodings; the chain introduces no signature of its own.
        chain = _chain()
        _, _, parts = _split_envelope(encode_continuations(chain))
        twin = _chain()
        self.assertEqual(
            parts,
            [
                encode_signed_auth_audit_continuation(receipt)
                for receipt in twin
            ],
        )

    def test_only_non_empty_tuple_accepted(self):
        chain = _chain()
        for bad in (
            None,
            1,
            "receipts",
            b"bytes",
            list(chain),
            chain[0],
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_continuations(bad)
        with self.assertRaises(ValueError):
            encode_continuations(())

    def test_element_type_error(self):
        chain = _chain()
        for bad in (None, 1, "receipt", b"bytes", (), chain[0].bundle):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_continuations((chain[0], bad))

    def test_nested_error_propagates(self):
        chain = _chain()
        old = chain[0].consistency.old
        bad_version = SignedRoot.__new__(SignedRoot)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "head",
            "signature",
        ):
            object.__setattr__(bad_version, name, getattr(old, name))
        object.__setattr__(bad_version, "version", 2)
        forged = SignedAuthAuditContinuation(
            chain[0].bundle,
            SignedConsistency(
                bad_version,
                chain[0].consistency.new,
                chain[0].consistency.proof,
            ),
        )
        with self.assertRaises(ValueError):
            encode_continuations((forged,))

    def test_chain_relations_not_checked(self):
        # Encoding is framing only: a gapped chain encodes and decodes
        # fine; the linkage is left to verify_continuation_chain.
        chain = _chain()
        gapped = (chain[0], chain[2])
        decoded = decode_continuations(encode_continuations(gapped))
        self.assertEqual(decoded, gapped)
        self.assertFalse(
            verify_continuation_chain(decoded, self.public_key)
        )

    def test_call_is_read_only(self):
        chain = _chain()
        before = encode_continuations(chain)
        encode_continuations(chain)
        self.assertEqual(encode_continuations(chain), before)
        self.assertTrue(
            verify_continuation_chain(chain, self.public_key)
        )


class DecodeContinuationsTest(unittest.TestCase):
    def setUp(self):
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)

    def roundtrip(self, chain):
        data = encode_continuations(chain)
        decoded = decode_continuations(data)
        self.assertIsInstance(decoded, tuple)
        self.assertEqual(decoded, chain)
        # Re-encoding reproduces the original bytes byte-for-byte.
        self.assertEqual(encode_continuations(decoded), data)
        self.assertTrue(
            verify_continuation_chain(decoded, self.public_key)
        )
        return decoded

    def test_roundtrip_variants(self):
        self.roundtrip(_chain())
        self.roundtrip(_chain()[:1])
        self.roundtrip(_chain()[:2])
        self.roundtrip((_segment(0, (), 9),))
        self.roundtrip((_segment(4, (4, 7), 8),))

    def test_roundtrip_preserves_order(self):
        chain = _chain()
        decoded = self.roundtrip(chain)
        self.assertEqual(
            [receipt.consistency.old.size for receipt in decoded],
            [0, 3, 6],
        )
        self.assertEqual(
            [receipt.consistency.new.size for receipt in decoded],
            [3, 6, 9],
        )

    def test_roundtrip_after_prune(self):
        log = _log(9)
        log.prune(2, log.seal(2))
        first = log.signed_auth_audit_continuation(2, (3,), _SEED_A, size=5)
        second = _segment(5, (6,), 9)
        self.roundtrip((first, second))

    def test_roundtrip_alternate_hashes(self):
        for hash_name in ("sha512", "sha3_256"):
            self.roundtrip(
                (
                    _segment(0, (1,), 3, hash_name=hash_name),
                    _segment(3, (4,), 6, hash_name=hash_name),
                )
            )

    def test_persistence_across_process_boundary(self):
        chain = _chain()
        data = encode_continuations(chain)
        # A fresh byte sequence, as read back from disk or a socket.
        restored = decode_continuations(bytes(data))
        self.assertEqual(restored, chain)
        self.assertTrue(
            verify_continuation_chain(restored, self.public_key)
        )

    def test_only_bytes_accepted(self):
        data = encode_continuations(_chain())
        for bad in (
            bytearray(data),
            memoryview(data),
            "text",
            None,
            1,
            (),
            [],
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_continuations(bad)

    def test_bad_magic(self):
        data = encode_continuations(_chain())
        for bad in (
            b"",
            b"x" + data[1:],
            MAGIC[:-1],
            b"auditchain/auth-audit-continuation/v1\0"
            + data[len(MAGIC):],
            b"auditchain/signed-consistency/v1\0" + data[len(MAGIC):],
            b"auditchain/signed-auth-bundle/v1\0" + data[len(MAGIC):],
        ):
            with self.assertRaises(ValueError, msg=repr(bad[:40])):
                decode_continuations(bad)

    def test_bad_version(self):
        data = encode_continuations(_chain())
        for version in (0, 2, 255, (1 << 64) - 1):
            bad = MAGIC + u64(version) + data[len(MAGIC) + 8:]
            with self.assertRaises(ValueError, msg=version):
                decode_continuations(bad)

    def test_empty_chain_rejected(self):
        with self.assertRaises(ValueError):
            decode_continuations(MAGIC + u64(1) + u64(0))

    def test_truncation(self):
        data = encode_continuations(_chain())
        for cut in (
            len(MAGIC),
            len(MAGIC) + 3,
            len(MAGIC) + 7,
            len(MAGIC) + 8,
            len(data) - 1,
            len(data) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_continuations(data[:cut])
        # Every cut inside the envelope (after the magic) is malformed.
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError, msg=cut):
                decode_continuations(data[:cut])

    def test_trailing_bytes(self):
        data = encode_continuations(_chain())
        for extra in (b"\x00", b"trailing", b"\x00" * 8):
            with self.assertRaises(ValueError, msg=extra):
                decode_continuations(data + extra)

    def test_oversized_blob_length(self):
        for bad in (
            MAGIC + u64(1) + u64(1) + u64(1 << 63) + b"x",
            MAGIC + u64(1) + u64(2) + u64(1 << 63),
        ):
            with self.assertRaises(ValueError):
                decode_continuations(bad)

    def test_missing_receipt_blob(self):
        chain = _chain()
        data = encode_continuations(chain)
        _, _, parts = _split_envelope(data)
        # The count promises three blobs but only two are present.
        with self.assertRaises(ValueError):
            decode_continuations(
                MAGIC + u64(1) + u64(3) + b"".join(blob(p) for p in parts[:2])
            )

    def test_count_smaller_than_blobs_rejected(self):
        chain = _chain()
        data = encode_continuations(chain)
        _, _, parts = _split_envelope(data)
        # A count of two leaves the third blob as trailing bytes.
        with self.assertRaises(ValueError):
            decode_continuations(
                MAGIC + u64(1) + u64(2) + b"".join(blob(p) for p in parts)
            )

    def test_garbage_receipt_blob_rejected(self):
        chain = _chain()
        _, _, parts = _split_envelope(encode_continuations(chain))
        with self.assertRaises(ValueError):
            decode_continuations(
                MAGIC
                + u64(1)
                + u64(2)
                + blob(parts[0])
                + blob(b"hello")
            )

    def test_nested_framing_error_rejected(self):
        chain = _chain()
        _, _, parts = _split_envelope(encode_continuations(chain))
        tampered = b"x" + parts[1][1:]
        with self.assertRaises(ValueError):
            decode_continuations(
                MAGIC
                + u64(1)
                + u64(3)
                + blob(parts[0])
                + blob(tampered)
                + blob(parts[2])
            )

    def test_unverifiable_chain_still_decodes(self):
        # A genuine segment signed by another key decodes fine; the
        # signature is left to verification.
        chain = _chain(seed=_SEED_B)
        decoded = decode_continuations(encode_continuations(chain))
        self.assertEqual(decoded, chain)
        self.assertFalse(
            verify_continuation_chain(decoded, self.public_key)
        )
        self.assertTrue(
            verify_continuation_chain(decoded, self.other_public_key)
        )

    def test_non_extending_chain_still_decodes(self):
        chain = (_segment(0, (1,), 3), _segment(3, (1,), 3))
        decoded = decode_continuations(encode_continuations(chain))
        self.assertEqual(decoded, chain)
        self.assertFalse(
            verify_continuation_chain(decoded, self.public_key)
        )

    def test_call_is_read_only(self):
        chain = _chain()
        data = encode_continuations(chain)
        self.assertEqual(decode_continuations(data), chain)


if __name__ == "__main__":
    unittest.main()
