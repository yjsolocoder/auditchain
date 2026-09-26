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
    EncryptedSearchReceipt,
    Entry,
    SignedEncryptedSearchReceipt,
    SignedRoot,
    verify_encrypted_search_receipt,
    verify_signed_encrypted_search_receipt,
    verify_signed_root,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(32, 64))

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))


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


def make_log(records=("a", "hit", "b", "hit", "c"), **kwargs):
    log = AuditLog(**kwargs)
    for index, value in enumerate(records):
        log.encrypt(value, KEY, nonce=bytes([index]) * 12)
    return log


class SignedEncryptedSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.public_key = _public_key(_SEED_A)

    def test_bundles_genuine_receipt_and_checkpoint(self):
        bundle = self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        self.assertIsInstance(bundle, SignedEncryptedSearchReceipt)
        self.assertEqual(
            bundle.receipt, self.log.encrypted_search_receipt("hit", KEY)
        )
        self.assertEqual(bundle.checkpoint, self.log.sign_root(_SEED_A))

    def test_no_new_signing_message(self):
        # Ed25519 is deterministic: the checkpoint is exactly sign_root's
        # output, signed over exactly the documented message.
        bundle = self.log.signed_encrypted_search_receipt(
            "hit", KEY, _SEED_A, size=4
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
        bundle = self.log.signed_encrypted_search_receipt(
            "hit", KEY, _SEED_A, 1, 4, size=4
        )
        self.assertEqual(
            bundle.receipt,
            self.log.encrypted_search_receipt("hit", KEY, 1, 4, 4),
        )
        self.assertEqual(bundle.receipt.size, 4)
        self.assertEqual(bundle.receipt.start, 1)
        self.assertEqual(bundle.receipt.stop, 4)
        self.assertEqual(bundle.checkpoint.size, 4)
        self.assertEqual(bundle.checkpoint.head, self.log.entry(3).entry_hash)
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_defaults_follow_encrypted_search_receipt(self):
        bundle = self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        self.assertEqual(bundle.receipt.size, len(self.log))
        self.assertEqual(bundle.receipt.start, 0)
        self.assertEqual(bundle.receipt.stop, len(self.log))
        self.assertEqual(bundle.checkpoint.size, len(self.log))
        self.log.encrypt("hit", KEY, nonce=b"\x05" * 12)
        grown = self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        self.assertEqual(grown.checkpoint.size, 6)

    def test_repeat_issue_is_byte_identical(self):
        first = self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        second = self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        self.assertEqual(first, second)
        self.assertEqual(first.checkpoint.signature, second.checkpoint.signature)

    def test_empty_snapshot_uses_canonical_root_and_zero_head(self):
        bundle = self.log.signed_encrypted_search_receipt(
            "hit", KEY, _SEED_A, size=0
        )
        self.assertEqual(bundle.receipt.size, 0)
        self.assertEqual(bundle.receipt.items, ())
        self.assertEqual(bundle.receipt.root, self.log.merkle_root(0))
        self.assertEqual(bundle.checkpoint.head, GENESIS_HASH)
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_empty_log(self):
        bundle = AuditLog().signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        self.assertEqual(bundle.receipt.size, 0)
        self.assertEqual(bundle.checkpoint.head, GENESIS_HASH)
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_no_hits(self):
        bundle = self.log.signed_encrypted_search_receipt(
            "absent", KEY, _SEED_A
        )
        self.assertEqual(bundle.receipt.items, ())
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_plain_entries_never_hit(self):
        log = AuditLog()
        log.append("hit")
        log.encrypt("hit", KEY, nonce=b"\x01" * 12)
        bundle = log.signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        self.assertEqual(
            [entry.index for entry, _ in bundle.receipt.items], [1]
        )
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_survives_later_appends(self):
        bundle = self.log.signed_encrypted_search_receipt(
            "hit", KEY, _SEED_A, size=4
        )
        self.log.encrypt("f", KEY, nonce=b"\x05" * 12)
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_alternate_hash_algorithm(self):
        log = make_log(("a", "hit", "b"), hash_name="sha512")
        bundle = log.signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        self.assertEqual(bundle.receipt.hash_name, "sha512")
        self.assertEqual(bundle.checkpoint.hash_name, "sha512")
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                bundle, KEY, self.public_key
            )
        )

    def test_pruned_log(self):
        log = AuditLog()
        twin = AuditLog()
        for i in range(6):
            nonce = bytes([i]) * 12
            log.encrypt(f"r{i}", KEY, nonce=nonce)
            twin.encrypt(f"r{i}", KEY, nonce=nonce)
        log.prune(2, log.seal(2))
        bundle = log.signed_encrypted_search_receipt("r4", KEY, _SEED_A)
        self.assertEqual(bundle.receipt.root, twin.merkle_root(6))
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                bundle, KEY, self.public_key
            )
        )
        with self.assertRaises(ValueError):
            log.signed_encrypted_search_receipt("r1", KEY, _SEED_A, size=1)

    def test_positional_construction_and_equality(self):
        bundle = self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        clone = SignedEncryptedSearchReceipt(bundle.receipt, bundle.checkpoint)
        self.assertEqual(bundle, clone)
        other = self.log.signed_encrypted_search_receipt(
            "hit", KEY, _SEED_A, size=3
        )
        self.assertNotEqual(bundle, other)
        self.assertNotEqual(bundle, (bundle.receipt, bundle.checkpoint))

    def test_frozen(self):
        bundle = self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        with self.assertRaises(FrozenInstanceError):
            bundle.receipt = bundle.receipt
        with self.assertRaises(FrozenInstanceError):
            bundle.checkpoint = bundle.checkpoint

    def test_constructor_field_types(self):
        receipt = self.log.encrypted_search_receipt("hit", KEY)
        checkpoint = self.log.sign_root(_SEED_A)
        for bad_receipt, bad_checkpoint in (
            ((receipt.version, receipt.hash_name), checkpoint),
            (None, checkpoint),
            (receipt, (checkpoint.version, checkpoint.hash_name)),
            (receipt, None),
        ):
            with self.assertRaises(TypeError):
                SignedEncryptedSearchReceipt(bad_receipt, bad_checkpoint)

    def _genuine_parts(self, size=5):
        receipt = self.log.encrypted_search_receipt("hit", KEY, size=size)
        checkpoint = self.log.sign_root(_SEED_A, size)
        return receipt, checkpoint

    def test_constructor_rejects_parts_of_different_snapshots(self):
        receipt, checkpoint = self._genuine_parts()
        other_checkpoint = self.log.sign_root(_SEED_A, 3)
        with self.assertRaises(ValueError):
            SignedEncryptedSearchReceipt(receipt, other_checkpoint)
        other_receipt = self.log.encrypted_search_receipt("hit", KEY, size=4)
        with self.assertRaises(ValueError):
            SignedEncryptedSearchReceipt(other_receipt, checkpoint)

    def test_constructor_rejects_different_hash_algorithm(self):
        receipt, checkpoint = self._genuine_parts()
        other_log = make_log(hash_name="sha512")
        foreign = other_log.sign_root(_SEED_A)
        self.assertEqual(foreign.size, checkpoint.size)
        with self.assertRaises(ValueError):
            SignedEncryptedSearchReceipt(receipt, foreign)

    def test_call_is_read_only(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        stage_log = AuditLog(key=b"shared-secret")
        stage_log.append("a")
        self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A)
        self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A, size=0)
        self.assertEqual(
            (len(self.log), self.log.head, self.log.merkle_root()), before
        )
        self.assertTrue(self.log.verify())
        self.assertEqual(stage_log.stage, 0)

    def test_failure_leaves_state_unchanged(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        with self.assertRaises(TypeError):
            self.log.signed_encrypted_search_receipt(123, KEY, _SEED_A)
        with self.assertRaises(TypeError):
            self.log.signed_encrypted_search_receipt("hit", "0" * 32, _SEED_A)
        with self.assertRaises(ValueError):
            self.log.signed_encrypted_search_receipt("hit", KEY[:-1], _SEED_A)
        with self.assertRaises(TypeError):
            self.log.signed_encrypted_search_receipt("hit", KEY, "0" * 32)
        with self.assertRaises(ValueError):
            self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A[:-1])
        with self.assertRaises(ValueError):
            self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A, 4, 1)
        with self.assertRaises(ValueError):
            self.log.signed_encrypted_search_receipt(
                "hit", KEY, _SEED_A, size=99
            )
        with self.assertRaises(TypeError):
            self.log.signed_encrypted_search_receipt(
                "hit", KEY, _SEED_A, size=True
            )
        with self.assertRaises(TypeError):
            self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A, "0")
        self.assertEqual(
            (len(self.log), self.log.head, self.log.merkle_root()), before
        )
        self.assertTrue(self.log.verify())


class VerifySignedEncryptedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(("a", "hit", "b", "hit", "c", "hit", "d"))
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.bundle = self.log.signed_encrypted_search_receipt(
            "hit", KEY, _SEED_A
        )

    def bypass(self, *, receipt=None, checkpoint=None):
        bundle = SignedEncryptedSearchReceipt.__new__(
            SignedEncryptedSearchReceipt
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
        for query, start, stop, size in (
            ("hit", None, None, None),
            (b"hit", None, None, None),
            ("hit", 1, 4, None),
            ("hit", None, None, 4),
            ("absent", None, None, None),
            ("hit", None, None, 0),
            ("a", 0, 1, 3),
        ):
            self.assertTrue(
                verify_signed_encrypted_search_receipt(
                    self.log.signed_encrypted_search_receipt(
                        query, KEY, _SEED_A, start, stop, size
                    ),
                    KEY,
                    self.public_key,
                ),
                (query, start, stop, size),
            )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_encrypted_search_receipt(
                self.bundle, KEY, self.other_public_key
            )
        )

    def test_other_key_signing_returns_false(self):
        foreign = self.log.signed_encrypted_search_receipt(
            "hit", KEY, _SEED_B
        )
        self.assertEqual(foreign.receipt, self.bundle.receipt)
        self.assertFalse(
            verify_signed_encrypted_search_receipt(
                foreign, KEY, self.public_key
            )
        )
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                foreign, KEY, self.other_public_key
            )
        )

    def test_wrong_append_key_returns_false(self):
        self.assertFalse(
            verify_signed_encrypted_search_receipt(
                self.bundle, OTHER_KEY, self.public_key
            )
        )

    def test_fewer_listed_hits_is_not_a_failure(self):
        receipt = self.bundle.receipt
        trimmed = EncryptedSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.query,
            receipt.start,
            receipt.stop,
            receipt.items[:1],
        )
        forged = self.bypass(receipt=trimmed)
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_not_a_bundle_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
                self.bundle.receipt, KEY, self.public_key
            )
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
                None, KEY, self.public_key
            )
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
                (self.bundle.receipt, self.bundle.checkpoint),
                KEY,
                self.public_key,
            )

    def test_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
                self.bundle, "0" * 32, self.public_key
            )
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
                self.bundle, bytearray(KEY), self.public_key
            )
        with self.assertRaises(ValueError):
            verify_signed_encrypted_search_receipt(
                self.bundle, KEY[:-1], self.public_key
            )
        with self.assertRaises(ValueError):
            verify_signed_encrypted_search_receipt(
                self.bundle, KEY + b"\x00", self.public_key
            )

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
                self.bundle, KEY, "0" * 32
            )
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
                self.bundle, KEY, bytearray(self.public_key)
            )
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
                self.bundle, KEY, memoryview(self.public_key)
            )
        with self.assertRaises(ValueError):
            verify_signed_encrypted_search_receipt(
                self.bundle, KEY, self.public_key[:-1]
            )
        with self.assertRaises(ValueError):
            verify_signed_encrypted_search_receipt(
                self.bundle, KEY, self.public_key + b"\x00"
            )

    def test_bypassed_container_field_types_raise_type_error(self):
        broken = self.bypass(receipt="not-a-receipt")
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
                broken, KEY, self.public_key
            )
        broken = self.bypass(checkpoint="not-a-checkpoint")
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
                broken, KEY, self.public_key
            )

    def test_nested_receipt_type_errors_propagate(self):
        receipt = self.bundle.receipt
        forged_receipt = EncryptedSearchReceipt.__new__(EncryptedSearchReceipt)
        for name in (
            "version", "hash_name", "size", "root", "query", "start",
            "stop", "items",
        ):
            object.__setattr__(
                forged_receipt, name, getattr(receipt, name)
            )
        object.__setattr__(forged_receipt, "version", "1")
        forged = self.bypass(receipt=forged_receipt)
        with self.assertRaises(TypeError):
            verify_signed_encrypted_search_receipt(
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
            verify_signed_encrypted_search_receipt(
                forged, KEY, self.public_key
            )

    def test_nested_receipt_value_errors_propagate(self):
        receipt = self.bundle.receipt
        forged_receipt = EncryptedSearchReceipt.__new__(EncryptedSearchReceipt)
        for name in (
            "version", "hash_name", "size", "root", "query", "start",
            "stop", "items",
        ):
            object.__setattr__(
                forged_receipt, name, getattr(receipt, name)
            )
        object.__setattr__(forged_receipt, "version", 2)
        forged = self.bypass(receipt=forged_receipt)
        with self.assertRaises(ValueError):
            verify_signed_encrypted_search_receipt(
                forged, KEY, self.public_key
            )

    def test_tampered_receipt_returns_false(self):
        receipt = self.bundle.receipt
        entry, proof = receipt.items[0]
        tampered_entry = Entry(
            entry.index,
            b"tampered",
            entry.previous_hash,
            entry.entry_hash,
        )
        forged_receipt = EncryptedSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.query,
            receipt.start,
            receipt.stop,
            ((tampered_entry, proof),) + receipt.items[1:],
        )
        forged = self.bypass(receipt=forged_receipt)
        self.assertFalse(
            verify_signed_encrypted_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_tampered_receipt_root_returns_false(self):
        receipt = self.bundle.receipt
        forged_receipt = EncryptedSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            b"\x11" * 32,
            receipt.query,
            receipt.start,
            receipt.stop,
            receipt.items,
        )
        forged = self.bypass(receipt=forged_receipt)
        self.assertFalse(
            verify_signed_encrypted_search_receipt(
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
            verify_signed_encrypted_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_mixed_size_returns_false(self):
        # Both parts are genuine and individually verifiable, but describe
        # different snapshot sizes.
        other = self.log.signed_encrypted_search_receipt(
            "hit", KEY, _SEED_A, size=4
        )
        forged = self.bypass(checkpoint=other.checkpoint)
        self.assertTrue(
            verify_encrypted_search_receipt(forged.receipt, KEY)
        )
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_encrypted_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_mixed_root_returns_false(self):
        # Same size and key, but the checkpoint attests a different log's
        # root (and head): the cross-check must reject it.
        other_log = make_log(("x", "y", "z", "w", "u", "v", "t"))
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass(checkpoint=foreign_checkpoint)
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_encrypted_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_mixed_hash_name_returns_false(self):
        other_log = make_log(
            ("a", "hit", "b", "hit", "c", "hit", "d"), hash_name="sha512"
        )
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass(checkpoint=foreign_checkpoint)
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_encrypted_search_receipt(
                forged, KEY, self.public_key
            )
        )

    def test_empty_snapshot_pairs_canonical_root(self):
        empty = self.log.signed_encrypted_search_receipt(
            "hit", KEY, _SEED_A, size=0
        )
        self.assertTrue(
            verify_signed_encrypted_search_receipt(
                empty, KEY, self.public_key
            )
        )

    def test_call_is_read_only(self):
        verify_signed_encrypted_search_receipt(
            self.bundle, KEY, self.other_public_key
        )
        self.assertEqual(
            self.bundle,
            self.log.signed_encrypted_search_receipt("hit", KEY, _SEED_A),
        )


if __name__ == "__main__":
    unittest.main()
