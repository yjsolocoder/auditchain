import dataclasses
import json
import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    GENESIS_HASH,
    AuditLog,
    Entry,
    FullEncryptedJsonSearchReceipt,
    SignedFullEncryptedJsonSearchReceipt,
    SignedRoot,
    verify_full_encrypted_json_search_receipt,
    verify_signed_full_encrypted_json_search_receipt,
    verify_signed_root,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
THIRD_KEY = bytes(reversed(range(32)))

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


def j(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def _signed_root_message(hash_name, size, root, head):
    def u64(value):
        return value.to_bytes(8, "big")

    def blob(material):
        return u64(len(material)) + material

    return (
        b"auditchain/signed-root/v1\0"
        + b"\x01"
        + blob(hash_name.encode("utf-8"))
        + u64(size)
        + blob(root)
        + blob(head)
    )


def _sign(seed, hash_name, size, root, head):
    message = _signed_root_message(hash_name, size, root, head)
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def make_log():
    log = AuditLog()
    # 0: match for /a == 1
    log.encrypt(j({"a": 1, "b": "x"}), KEY, nonce=b"0" * 12)
    # 1: float numerically equal
    log.encrypt(j({"a": 1.0, "b": "y"}), KEY, nonce=b"1" * 12)
    # 2: string "1"
    log.encrypt(j({"a": "1"}), KEY, nonce=b"2" * 12)
    # 3: boolean
    log.encrypt(j({"a": True}), KEY, nonce=b"3" * 12)
    # 4: non-scalar target
    log.encrypt(j({"a": [1]}), KEY, nonce=b"4" * 12)
    # 5: plain JSON entry
    log.append(j({"a": 1}))
    # 6: same value under another key
    log.encrypt(j({"a": 1}), OTHER_KEY, nonce=b"6" * 12)
    # 7: malformed JSON under KEY
    log.encrypt(b"{not json", KEY, nonce=b"7" * 12)
    # 8: repeated member name
    log.encrypt(b'{"a": 1, "a": 2}', KEY, nonce=b"8" * 12)
    return log


def rebuild(receipt, **overrides):
    fields = dict(
        version=receipt.version,
        hash_name=receipt.hash_name,
        size=receipt.size,
        root=receipt.root,
        pointer=receipt.pointer,
        value=receipt.value,
        start=receipt.start,
        stop=receipt.stop,
        items=receipt.items,
        proof=receipt.proof,
        hits=receipt.hits,
        confirmation=receipt.confirmation,
    )
    fields.update(overrides)
    return FullEncryptedJsonSearchReceipt(**fields)


class SignedFullEncryptedJsonSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.public_key = _public_key(_SEED_A)

    def test_bundles_genuine_receipt_and_checkpoint(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        self.assertIsInstance(
            bundle, SignedFullEncryptedJsonSearchReceipt
        )
        self.assertEqual(
            bundle.receipt,
            self.log.full_encrypted_json_search_receipt("/a", 1, KEY),
        )
        self.assertEqual(bundle.checkpoint, self.log.sign_root(_SEED_A))

    def test_no_new_signing_message(self):
        # Ed25519 is deterministic: the checkpoint is exactly sign_root's
        # output, signed over exactly the documented message.
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, size=4
        )
        self.assertEqual(bundle.checkpoint, self.log.sign_root(_SEED_A, 4))
        signature = _sign(
            _SEED_A,
            "sha256",
            4,
            self.log.merkle_root(4),
            self.log.entry(3).entry_hash,
        )
        self.assertEqual(bundle.checkpoint.signature, signature)

    def test_explicit_range_and_size(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, 1, 7, size=7
        )
        self.assertEqual(
            bundle.receipt,
            self.log.full_encrypted_json_search_receipt(
                "/a", 1, KEY, 1, 7, 7
            ),
        )
        self.assertEqual(bundle.receipt.size, 7)
        self.assertEqual(bundle.receipt.start, 1)
        self.assertEqual(bundle.receipt.stop, 7)
        self.assertEqual(bundle.checkpoint.size, 7)
        self.assertEqual(bundle.checkpoint.head, self.log.entry(6).entry_hash)
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_defaults_follow_full_encrypted_json_search_receipt(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        self.assertEqual(bundle.receipt.size, len(self.log))
        self.assertEqual(bundle.receipt.start, 0)
        self.assertEqual(bundle.receipt.stop, len(self.log))
        self.assertEqual(bundle.checkpoint.size, len(self.log))
        self.log.encrypt(j({"a": 1}), KEY, nonce=b"9" * 12)
        grown = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        self.assertEqual(grown.checkpoint.size, 10)

    def test_repeat_issue_is_byte_identical(self):
        first = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        second = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        self.assertEqual(first, second)
        self.assertEqual(
            first.checkpoint.signature, second.checkpoint.signature
        )

    def test_records_the_complete_hit_set_and_no_plaintext(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        self.assertEqual(bundle.receipt.hits, (0, 1))
        self.assertEqual(len(bundle.receipt.items), 9)
        self.assertEqual(
            bundle.receipt.hits,
            self.log.find_encrypted_json("/a", 1, KEY),
        )
        # Neither the query key nor any plaintext is embedded.
        encoded = dataclasses.astuple(bundle)
        self.assertNotIn(KEY, encoded)
        self.assertNotIn(j({"a": 1, "b": "x"}), encoded)

    def test_empty_snapshot_uses_canonical_root_and_zero_head(self):
        bundle = AuditLog().signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        self.assertEqual(bundle.receipt.size, 0)
        self.assertEqual(bundle.receipt.items, ())
        self.assertEqual(bundle.receipt.proof, ())
        self.assertEqual(bundle.receipt.hits, ())
        self.assertEqual(bundle.receipt.root, AuditLog().merkle_root(0))
        self.assertEqual(bundle.checkpoint.head, GENESIS_HASH)
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_empty_range_of_non_empty_snapshot(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, 4, 4, size=9
        )
        self.assertEqual(bundle.receipt.items, ())
        self.assertEqual(bundle.receipt.proof, ())
        self.assertEqual(bundle.receipt.hits, ())
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_zero_hits(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/nope/missing", 42, KEY, _SEED_A
        )
        self.assertEqual(bundle.receipt.hits, ())
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_plain_and_foreign_key_entries_never_hit(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        self.assertEqual(bundle.receipt.hits, (0, 1))
        other = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, OTHER_KEY, _SEED_A
        )
        self.assertEqual(other.receipt.hits, (6,))
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                other, OTHER_KEY, self.public_key
            )
        )

    def test_json_kinds_are_separated(self):
        string_bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", "1", KEY, _SEED_A
        )
        self.assertEqual(string_bundle.receipt.hits, (2,))
        bool_bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", True, KEY, _SEED_A
        )
        self.assertEqual(bool_bundle.receipt.hits, (3,))

    def test_survives_later_appends(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, size=4
        )
        self.log.encrypt(j({"a": 1}), KEY, nonce=b"f" * 12)
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_alternate_hash_algorithm(self):
        log = AuditLog(hash_name="sha512")
        log.encrypt(j({"a": 1}), KEY, nonce=b"0" * 12)
        log.encrypt(j({"a": 2}), KEY, nonce=b"1" * 12)
        bundle = log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        self.assertEqual(bundle.receipt.hash_name, "sha512")
        self.assertEqual(bundle.checkpoint.hash_name, "sha512")
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_pruned_log(self):
        log = AuditLog()
        twin = AuditLog()
        for index in range(6):
            payload = j({"a": index})
            nonce = bytes([index]) * 12
            log.encrypt(payload, KEY, nonce=nonce)
            twin.encrypt(payload, KEY, nonce=nonce)
        log.prune(2, log.seal(2))
        bundle = log.signed_full_encrypted_json_search_receipt(
            "/a", 4, KEY, _SEED_A
        )
        self.assertEqual(bundle.receipt.root, twin.merkle_root(6))
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                bundle, KEY, self.public_key
            )
        )
        with self.assertRaises(ValueError):
            log.signed_full_encrypted_json_search_receipt(
                "/a", 0, KEY, _SEED_A, size=1
            )

    def test_positional_construction_and_equality(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        clone = SignedFullEncryptedJsonSearchReceipt(
            bundle.receipt, bundle.checkpoint
        )
        self.assertEqual(bundle, clone)
        other = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, size=3
        )
        self.assertNotEqual(bundle, other)
        self.assertNotEqual(bundle, (bundle.receipt, bundle.checkpoint))

    def test_frozen(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.receipt = bundle.receipt
        with self.assertRaises(FrozenInstanceError):
            bundle.checkpoint = bundle.checkpoint

    def test_constructor_field_types(self):
        receipt = self.log.full_encrypted_json_search_receipt("/a", 1, KEY)
        checkpoint = self.log.sign_root(_SEED_A)
        for bad_receipt, bad_checkpoint in (
            ((receipt.version, receipt.hash_name), checkpoint),
            (None, checkpoint),
            (receipt, (checkpoint.version, checkpoint.hash_name)),
            (receipt, None),
        ):
            with self.assertRaises(TypeError):
                SignedFullEncryptedJsonSearchReceipt(
                    bad_receipt, bad_checkpoint
                )

    def _genuine_parts(self, size=9):
        receipt = self.log.full_encrypted_json_search_receipt(
            "/a", 1, KEY, size=size
        )
        checkpoint = self.log.sign_root(_SEED_A, size)
        return receipt, checkpoint

    def test_constructor_rejects_parts_of_different_snapshots(self):
        receipt, checkpoint = self._genuine_parts()
        other_checkpoint = self.log.sign_root(_SEED_A, 3)
        with self.assertRaises(ValueError):
            SignedFullEncryptedJsonSearchReceipt(
                receipt, other_checkpoint
            )
        other_receipt = self.log.full_encrypted_json_search_receipt(
            "/a", 1, KEY, 0, 4, size=4
        )
        with self.assertRaises(ValueError):
            SignedFullEncryptedJsonSearchReceipt(
                other_receipt, checkpoint
            )

    def test_constructor_rejects_different_hash_algorithm(self):
        receipt, checkpoint = self._genuine_parts()
        other_log = AuditLog(hash_name="sha512")
        other_log.encrypt(j({"a": 1}), KEY, nonce=b"0" * 12)
        foreign = other_log.sign_root(_SEED_A)
        with self.assertRaises(ValueError):
            SignedFullEncryptedJsonSearchReceipt(receipt, foreign)

    def test_call_is_read_only(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )
        self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, size=0
        )
        self.assertEqual(
            (len(self.log), self.log.head, self.log.merkle_root()), before
        )
        self.assertTrue(self.log.verify())

    def test_failure_leaves_state_unchanged(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        with self.assertRaises(TypeError):
            self.log.signed_full_encrypted_json_search_receipt(
                1, 1, KEY, _SEED_A
            )
        with self.assertRaises(ValueError):
            self.log.signed_full_encrypted_json_search_receipt(
                "a", 1, KEY, _SEED_A
            )
        with self.assertRaises(TypeError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", [1], KEY, _SEED_A
            )
        with self.assertRaises(ValueError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", float("inf"), KEY, _SEED_A
            )
        with self.assertRaises(TypeError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, "k" * 32, _SEED_A
            )
        with self.assertRaises(ValueError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, b"short", _SEED_A
            )
        with self.assertRaises(TypeError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, "s" * 32
            )
        with self.assertRaises(ValueError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A[:-1]
            )
        with self.assertRaises(ValueError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A, 4, 1
            )
        with self.assertRaises(ValueError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A, size=99
            )
        with self.assertRaises(TypeError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A, size=True
            )
        with self.assertRaises(TypeError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A, "0"
            )
        self.assertEqual(
            (len(self.log), self.log.head, self.log.merkle_root()), before
        )
        self.assertTrue(self.log.verify())

    def test_key_and_seed_bytearray_and_memoryview_raise_type_error(self):
        with self.assertRaises(TypeError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, bytearray(KEY), _SEED_A
            )
        with self.assertRaises(TypeError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, memoryview(KEY), _SEED_A
            )
        with self.assertRaises(TypeError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, bytearray(_SEED_A)
            )
        with self.assertRaises(TypeError):
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, memoryview(_SEED_A)
            )


class VerifySignedFullEncryptedJsonSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A
        )

    def bypass(self, *, receipt=None, checkpoint=None):
        bundle = SignedFullEncryptedJsonSearchReceipt.__new__(
            SignedFullEncryptedJsonSearchReceipt
        )
        object.__setattr__(
            bundle,
            "receipt",
            self.bundle.receipt if receipt is None else receipt,
        )
        object.__setattr__(
            bundle,
            "checkpoint",
            self.bundle.checkpoint if checkpoint is None else checkpoint,
        )
        return bundle

    def test_genuine_bundles_verify(self):
        for pointer, value, start, stop, size in (
            ("/a", 1, None, None, None),
            ("/a", 1.0, None, None, None),
            ("/a", "1", None, None, None),
            ("/a", True, None, None, None),
            ("/a", 1, 1, 7, 7),
            ("/a", 1, None, None, 4),
            ("/nope", "absent", None, None, None),
            ("/a", 1, 4, 4, 9),
            ("/a", 1, None, None, 0),
        ):
            self.assertTrue(
                verify_signed_full_encrypted_json_search_receipt(
                    self.log.signed_full_encrypted_json_search_receipt(
                        pointer, value, KEY, _SEED_A, start, stop, size
                    ),
                    KEY,
                    self.public_key,
                ),
                (pointer, value, start, stop, size),
            )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, KEY, self.other_public_key
            )
        )

    def test_other_key_signing_returns_false(self):
        foreign = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_B
        )
        self.assertEqual(foreign.receipt, self.bundle.receipt)
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                foreign, KEY, self.public_key
            )
        )
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                foreign, KEY, self.other_public_key
            )
        )

    def test_wrong_query_key_returns_false(self):
        self.assertTrue(self.bundle.receipt.hits)
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, OTHER_KEY, self.public_key
            )
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, THIRD_KEY, self.public_key
            )
        )

    def test_zero_hit_receipt_wrong_query_key_still_returns_false(self):
        # Unlike the plaintext-symmetric receipts, the keyed confirmation
        # means even a zero-hit receipt does not verify under another key.
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/absent", 1, THIRD_KEY, _SEED_A
        )
        self.assertEqual(bundle.receipt.hits, ())
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                bundle, THIRD_KEY, self.public_key
            )
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_concealed_hit_returns_false(self):
        receipt = self.bundle.receipt
        self.assertEqual(receipt.hits, (0, 1))
        forged = self.bypass(receipt=rebuild(receipt, hits=(0,)))
        self.assertTrue(
            verify_full_encrypted_json_search_receipt(receipt, KEY)
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_forged_hit_returns_false(self):
        # Index 5 is in range but a plain JSON entry, never a hit.
        receipt = self.bundle.receipt
        forged = self.bypass(receipt=rebuild(receipt, hits=(0, 1, 5)))
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_tampered_hits_empty_returns_false(self):
        receipt = self.bundle.receipt
        forged = self.bypass(receipt=rebuild(receipt, hits=()))
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_tampered_confirmation_returns_false(self):
        receipt = self.bundle.receipt
        forged = self.bypass(
            receipt=rebuild(receipt, confirmation=b"\x00" * 32)
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_tampered_pointer_returns_false(self):
        receipt = self.bundle.receipt
        forged = self.bypass(receipt=rebuild(receipt, pointer="/b"))
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_tampered_query_value_returns_false(self):
        receipt = self.bundle.receipt
        forged = self.bypass(receipt=rebuild(receipt, value=2))
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )
        forged = self.bypass(receipt=rebuild(receipt, value="1"))
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_tampered_ciphertext_returns_false(self):
        receipt = self.bundle.receipt
        entry = receipt.items[0]
        raw = entry.payload[:-1] + bytes([entry.payload[-1] ^ 0x01])
        tampered_entry = Entry(
            entry.index, raw, entry.previous_hash, entry.entry_hash
        )
        forged = self.bypass(
            receipt=rebuild(
                receipt,
                items=(tampered_entry,) + receipt.items[1:],
                hits=(),
            )
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_tampered_entry_hash_returns_false(self):
        receipt = self.bundle.receipt
        entry = receipt.items[0]
        tampered_entry = Entry(
            entry.index,
            entry.payload,
            entry.previous_hash,
            b"\x00" * len(entry.entry_hash),
        )
        forged = self.bypass(
            receipt=rebuild(
                receipt,
                items=(tampered_entry,) + receipt.items[1:],
            )
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_tampered_proof_returns_false(self):
        bundle = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, 1, 8, size=9
        )
        receipt = bundle.receipt
        self.assertTrue(receipt.proof)
        proof = receipt.proof
        flipped = proof[0][:-1] + bytes([proof[0][-1] ^ 0x01])
        forged = self.bypass(receipt=rebuild(receipt, proof=(flipped,) + proof[1:]))
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_tampered_receipt_root_returns_false(self):
        receipt = self.bundle.receipt
        forged = self.bypass(receipt=rebuild(receipt, root=b"\x11" * 32))
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_tampered_checkpoint_signature_returns_false(self):
        checkpoint = self.bundle.checkpoint
        forged_checkpoint = SignedRoot(
            checkpoint.version,
            checkpoint.hash_name,
            checkpoint.size,
            checkpoint.root,
            checkpoint.head,
            b"\x00" * 64,
        )
        forged = self.bypass(checkpoint=forged_checkpoint)
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_mixed_size_returns_false(self):
        # Both parts are genuine and individually verifiable, but describe
        # different snapshot sizes.
        other = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, size=4
        )
        forged = self.bypass(checkpoint=other.checkpoint)
        self.assertTrue(
            verify_full_encrypted_json_search_receipt(forged.receipt, KEY)
        )
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_mixed_root_returns_false(self):
        other_log = AuditLog()
        for index in range(9):
            other_log.encrypt(
                j({"a": index, "z": "other"}),
                KEY,
                nonce=bytes([index + 100]) * 12,
            )
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass(checkpoint=foreign_checkpoint)
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_mixed_hash_name_returns_false(self):
        other_log = AuditLog(hash_name="sha512")
        for index in range(9):
            other_log.encrypt(
                j({"a": 1}), KEY, nonce=bytes([index]) * 12
            )
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass(checkpoint=foreign_checkpoint)
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_bypassed_freeze_with_different_snapshot_bundle_returns_false(self):
        # The container constructor rejects this; bypassing the frozen
        # restriction must still be caught at verification with False.
        other = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, size=4
        )
        forged = self.bypass(checkpoint=other.checkpoint)
        self.assertFalse(
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_empty_snapshot_pairs_canonical_root(self):
        empty = self.log.signed_full_encrypted_json_search_receipt(
            "/a", 1, KEY, _SEED_A, size=0
        )
        self.assertTrue(
            verify_signed_full_encrypted_json_search_receipt(
                empty, KEY, self.public_key
            )
        )

    def test_not_a_bundle_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle.receipt, KEY, self.public_key
            )
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                None, KEY, self.public_key
            )
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                (self.bundle.receipt, self.bundle.checkpoint),
                KEY,
                self.public_key,
            )

    def test_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, "0" * 32, self.public_key
            )
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, bytearray(KEY), self.public_key
            )
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, memoryview(KEY), self.public_key
            )
        with self.assertRaises(ValueError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, KEY[:-1], self.public_key
            )
        with self.assertRaises(ValueError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, KEY + b"\x00", self.public_key
            )

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, KEY, "0" * 32
            )
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, KEY, bytearray(self.public_key)
            )
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, KEY, memoryview(self.public_key)
            )
        with self.assertRaises(ValueError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, KEY, self.public_key[:-1]
            )
        with self.assertRaises(ValueError):
            verify_signed_full_encrypted_json_search_receipt(
                self.bundle, KEY, self.public_key + b"\x00"
            )

    def test_bypassed_container_field_types_raise_type_error(self):
        broken = self.bypass(receipt="not-a-receipt")
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                broken, KEY, self.public_key
            )
        broken = self.bypass(checkpoint="not-a-checkpoint")
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                broken, KEY, self.public_key
            )

    def test_nested_receipt_type_errors_propagate(self):
        receipt = self.bundle.receipt
        forged_receipt = FullEncryptedJsonSearchReceipt.__new__(
            FullEncryptedJsonSearchReceipt
        )
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "pointer",
            "value",
            "start",
            "stop",
            "items",
            "proof",
            "hits",
            "confirmation",
        ):
            object.__setattr__(
                forged_receipt, name, getattr(receipt, name)
            )
        object.__setattr__(forged_receipt, "version", "1")
        forged = self.bypass(receipt=forged_receipt)
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )

    def test_nested_checkpoint_type_errors_propagate(self):
        checkpoint = self.bundle.checkpoint
        forged_checkpoint = SignedRoot.__new__(SignedRoot)
        for name in (
            "version", "hash_name", "size", "root", "head", "signature"
        ):
            object.__setattr__(
                forged_checkpoint, name, getattr(checkpoint, name)
            )
        object.__setattr__(forged_checkpoint, "version", "1")
        forged = self.bypass(checkpoint=forged_checkpoint)
        with self.assertRaises(TypeError):
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )

    def test_nested_receipt_value_errors_propagate(self):
        receipt = self.bundle.receipt
        forged_receipt = FullEncryptedJsonSearchReceipt.__new__(
            FullEncryptedJsonSearchReceipt
        )
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "pointer",
            "value",
            "start",
            "stop",
            "items",
            "proof",
            "hits",
            "confirmation",
        ):
            object.__setattr__(
                forged_receipt, name, getattr(receipt, name)
            )
        object.__setattr__(forged_receipt, "version", 2)
        forged = self.bypass(receipt=forged_receipt)
        with self.assertRaises(ValueError):
            verify_signed_full_encrypted_json_search_receipt(
                forged, KEY, self.public_key
            )

    def test_call_is_read_only(self):
        verify_signed_full_encrypted_json_search_receipt(
            self.bundle, OTHER_KEY, self.other_public_key
        )
        self.assertEqual(
            self.bundle,
            self.log.signed_full_encrypted_json_search_receipt(
                "/a", 1, KEY, _SEED_A
            ),
        )


if __name__ == "__main__":
    unittest.main()
