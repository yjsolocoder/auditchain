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
    SearchReceipt,
    SignedRoot,
    SignedSearchReceipt,
    verify_search_receipt,
    verify_signed_root,
    verify_signed_search_receipt,
)

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))

RECORDS = ("a", "b", "a", "c", "a")


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def make_log(records=RECORDS, **kwargs):
    log = AuditLog(**kwargs)
    for record in records:
        log.append(record)
    return log


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


class SignedSearchReceiptIssueTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.public_key = _public_key(_SEED_A)

    def test_bundles_genuine_receipt_and_checkpoint(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        self.assertIsInstance(package, SignedSearchReceipt)
        self.assertEqual(package.receipt, self.log.search_receipt("a"))
        self.assertEqual(package.checkpoint, self.log.sign_root(_SEED_A))

    def test_no_new_signing_message(self):
        # Ed25519 is deterministic: the checkpoint is exactly sign_root's
        # output, signed over exactly the documented message.
        package = self.log.signed_search_receipt("a", _SEED_A, 0, 4, size=4)
        self.assertEqual(package.checkpoint, self.log.sign_root(_SEED_A, 4))
        signature = _sign(
            _SEED_A,
            "sha256",
            4,
            self.log.merkle_root(4),
            self.log.entry(3).entry_hash,
        )
        self.assertEqual(package.checkpoint.signature, signature)

    def test_bytes_and_str_queries_equivalent(self):
        self.assertEqual(
            self.log.signed_search_receipt("a", _SEED_A),
            self.log.signed_search_receipt(b"a", _SEED_A),
        )

    def test_explicit_range_and_size(self):
        package = self.log.signed_search_receipt("a", _SEED_A, 1, 4, size=4)
        self.assertEqual((package.receipt.start, package.receipt.stop), (1, 4))
        self.assertEqual(package.receipt.size, 4)
        self.assertEqual(package.receipt.root, self.log.merkle_root(4))
        self.assertEqual(package.checkpoint.size, 4)
        self.assertEqual(
            [e.index for e, _ in package.receipt.items], [2]
        )
        self.assertTrue(
            verify_signed_search_receipt(package, self.public_key)
        )

    def test_defaults_match_search_receipt(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        receipt = self.log.search_receipt("a")
        self.assertEqual(package.receipt, receipt)
        self.assertEqual(package.receipt.size, len(self.log))
        self.assertEqual(package.checkpoint.size, len(self.log))
        self.assertEqual(
            [e.index for e, _ in package.receipt.items], [0, 2, 4]
        )

    def test_no_match_carries_no_items(self):
        package = self.log.signed_search_receipt("missing", _SEED_A)
        self.assertEqual(package.receipt.items, ())
        self.assertTrue(
            verify_signed_search_receipt(package, self.public_key)
        )

    def test_empty_snapshot_uses_canonical_root_and_zero_head(self):
        package = AuditLog().signed_search_receipt("a", _SEED_A)
        self.assertEqual(package.receipt.size, 0)
        self.assertEqual(package.receipt.items, ())
        self.assertEqual(package.receipt.root, self.log.merkle_root(0))
        self.assertEqual(package.checkpoint.head, GENESIS_HASH)
        self.assertTrue(
            verify_signed_search_receipt(package, self.public_key)
        )

    def test_explicit_empty_snapshot(self):
        package = self.log.signed_search_receipt("a", _SEED_A, size=0)
        self.assertEqual(package.receipt.size, 0)
        self.assertTrue(
            verify_signed_search_receipt(package, self.public_key)
        )

    def test_per_hit_proofs_match_search_receipt(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        self.assertEqual(package.receipt, self.log.search_receipt("a"))
        for entry, proof in package.receipt.items:
            self.assertEqual(
                proof, self.log.inclusion_proof(entry.index, len(self.log))
            )

    def test_survives_later_appends(self):
        package = self.log.signed_search_receipt("a", _SEED_A, size=4)
        self.log.append("f")
        self.assertTrue(
            verify_signed_search_receipt(package, self.public_key)
        )

    def test_alternate_hash_algorithm(self):
        log = make_log(("a", "b", "a"), hash_name="sha512")
        package = log.signed_search_receipt("a", _SEED_A)
        self.assertEqual(package.receipt.hash_name, "sha512")
        self.assertEqual(package.checkpoint.hash_name, "sha512")
        self.assertTrue(
            verify_signed_search_receipt(package, self.public_key)
        )

    def test_pruned_log_default_range_is_retained_segment(self):
        log = make_log(("a", "b", "a", "c", "a", "b"))
        log.prune(2, log.seal(2))
        package = log.signed_search_receipt("a", _SEED_A)
        self.assertEqual((package.receipt.start, package.receipt.stop), (2, 6))
        self.assertEqual(
            [e.index for e, _ in package.receipt.items], [2, 4]
        )
        self.assertTrue(
            verify_signed_search_receipt(package, self.public_key)
        )
        # A released-prefix snapshot is not rebuildable.
        with self.assertRaises(ValueError):
            log.signed_search_receipt("a", _SEED_A, size=1)

    def test_positional_construction_and_equality(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        clone = SignedSearchReceipt(package.receipt, package.checkpoint)
        self.assertEqual(package, clone)
        other = self.log.signed_search_receipt("b", _SEED_A)
        self.assertNotEqual(package, other)
        self.assertNotEqual(
            package, (package.receipt, package.checkpoint)
        )

    def test_frozen(self):
        package = self.log.signed_search_receipt("a", _SEED_A)
        with self.assertRaises(FrozenInstanceError):
            package.receipt = package.receipt
        with self.assertRaises(FrozenInstanceError):
            package.checkpoint = package.checkpoint

    def test_constructor_field_types(self):
        receipt = self.log.search_receipt("a")
        checkpoint = self.log.sign_root(_SEED_A)
        for bad_receipt, bad_checkpoint in (
            ((receipt.version, receipt.hash_name), checkpoint),
            (None, checkpoint),
            (receipt, (checkpoint.version, checkpoint.hash_name)),
            (receipt, None),
        ):
            with self.assertRaises(TypeError):
                SignedSearchReceipt(bad_receipt, bad_checkpoint)

    def _genuine_parts(self, size=5):
        receipt = self.log.search_receipt("a", size=size)
        checkpoint = self.log.sign_root(_SEED_A, size)
        return receipt, checkpoint

    def test_constructor_rejects_parts_of_different_snapshots(self):
        receipt, checkpoint = self._genuine_parts()
        other_checkpoint = self.log.sign_root(_SEED_A, 3)
        with self.assertRaises(ValueError):
            SignedSearchReceipt(receipt, other_checkpoint)
        other_receipt = self.log.search_receipt("a", size=4)
        with self.assertRaises(ValueError):
            SignedSearchReceipt(other_receipt, checkpoint)

    def test_constructor_rejects_different_hash_algorithm(self):
        receipt, checkpoint = self._genuine_parts()
        other_log = make_log(hash_name="sha512")
        foreign = other_log.sign_root(_SEED_A)
        self.assertEqual(foreign.size, checkpoint.size)
        with self.assertRaises(ValueError):
            SignedSearchReceipt(receipt, foreign)

    def test_issuing_is_deterministic_byte_for_byte(self):
        from auditchain import encode_signed_search_receipt

        first = self.log.signed_search_receipt("a", _SEED_A, 0, 5, size=5)
        second = self.log.signed_search_receipt("a", _SEED_A, 0, 5, size=5)
        self.assertEqual(first, second)
        self.assertEqual(
            encode_signed_search_receipt(first),
            encode_signed_search_receipt(second),
        )

    def test_call_is_read_only(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        stage_log = AuditLog(key=b"shared-secret")
        stage_log.append("a")
        self.log.signed_search_receipt("a", _SEED_A)
        self.log.signed_search_receipt("missing", _SEED_A)
        self.log.signed_search_receipt("a", _SEED_A, size=0)
        self.assertEqual(
            (len(self.log), self.log.head, self.log.merkle_root()), before
        )
        self.assertTrue(self.log.verify())
        self.assertEqual(stage_log.stage, 0)

    def test_failure_leaves_no_half_product_and_state_unchanged(self):
        before = (len(self.log), self.log.head, self.log.merkle_root())
        # Bad query value.
        for bad_query in (123, None, bytearray(b"a"), ["a"]):
            with self.assertRaises(TypeError):
                self.log.signed_search_receipt(bad_query, _SEED_A)
        # Bad range / size types.
        with self.assertRaises(TypeError):
            self.log.signed_search_receipt("a", _SEED_A, True)
        with self.assertRaises(TypeError):
            self.log.signed_search_receipt("a", _SEED_A, 0, True)
        with self.assertRaises(TypeError):
            self.log.signed_search_receipt("a", _SEED_A, size=True)
        # Out-of-range range / size.
        with self.assertRaises(ValueError):
            self.log.signed_search_receipt("a", _SEED_A, 0, 6)
        with self.assertRaises(ValueError):
            self.log.signed_search_receipt("a", _SEED_A, 3, 2)
        with self.assertRaises(ValueError):
            self.log.signed_search_receipt("a", _SEED_A, size=6)
        # Unrebuildable (pruned) snapshot.
        log = make_log(("a", "b", "a"))
        log.prune(2, log.seal(2))
        with self.assertRaises(ValueError):
            log.signed_search_receipt("a", _SEED_A, size=1)
        # Bad seed type and length.
        with self.assertRaises(TypeError):
            self.log.signed_search_receipt("a", "0" * 32)
        with self.assertRaises(ValueError):
            self.log.signed_search_receipt("a", _SEED_A[:-1])
        self.assertEqual(
            (len(self.log), self.log.head, self.log.merkle_root()), before
        )
        self.assertTrue(self.log.verify())


class VerifySignedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()
        self.public_key = _public_key(_SEED_A)
        self.other_public_key = _public_key(_SEED_B)
        self.package = self.log.signed_search_receipt("a", _SEED_A)

    def bypass(self, *, receipt=None, checkpoint=None):
        package = SignedSearchReceipt.__new__(SignedSearchReceipt)
        object.__setattr__(
            package,
            "receipt",
            self.package.receipt if receipt is None else receipt,
        )
        object.__setattr__(
            package,
            "checkpoint",
            self.package.checkpoint if checkpoint is None else checkpoint,
        )
        return package

    def _rebuild_receipt(self, **overrides):
        receipt = self.package.receipt
        fields = dict(
            version=receipt.version,
            hash_name=receipt.hash_name,
            size=receipt.size,
            root=receipt.root,
            query=receipt.query,
            start=receipt.start,
            stop=receipt.stop,
            items=receipt.items,
        )
        fields.update(overrides)
        return SearchReceipt(**fields)

    def test_genuine_packages_verify(self):
        for query, start, stop, size in (
            ("a", None, None, None),
            ("missing", None, None, None),
            ("a", 1, 4, 4),
            ("a", 0, 3, 3),
            ("a", None, None, 0),
        ):
            self.assertTrue(
                verify_signed_search_receipt(
                    self.log.signed_search_receipt(
                        query, _SEED_A, start, stop, size=size
                    ),
                    self.public_key,
                ),
                (query, start, stop, size),
            )

    def test_empty_log_verifies(self):
        package = AuditLog().signed_search_receipt("a", _SEED_A)
        self.assertTrue(
            verify_signed_search_receipt(package, self.public_key)
        )

    def test_wrong_public_key_returns_false(self):
        self.assertFalse(
            verify_signed_search_receipt(self.package, self.other_public_key)
        )

    def test_other_key_signing_returns_false(self):
        foreign = self.log.signed_search_receipt("a", _SEED_B)
        self.assertEqual(foreign.receipt, self.package.receipt)
        self.assertFalse(
            verify_signed_search_receipt(foreign, self.public_key)
        )
        self.assertTrue(
            verify_signed_search_receipt(foreign, self.other_public_key)
        )

    def test_not_a_package_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signed_search_receipt(self.package.receipt, self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_search_receipt(None, self.public_key)
        with self.assertRaises(TypeError):
            verify_signed_search_receipt(
                (self.package.receipt, self.package.checkpoint), self.public_key
            )

    def test_public_key_validation(self):
        with self.assertRaises(TypeError):
            verify_signed_search_receipt(self.package, "0" * 32)
        with self.assertRaises(TypeError):
            verify_signed_search_receipt(
                self.package, bytearray(self.public_key)
            )
        with self.assertRaises(TypeError):
            verify_signed_search_receipt(
                self.package, memoryview(self.public_key)
            )
        with self.assertRaises(ValueError):
            verify_signed_search_receipt(self.package, self.public_key[:-1])
        with self.assertRaises(ValueError):
            verify_signed_search_receipt(
                self.package, self.public_key + b"\x00"
            )

    def test_bypassed_container_field_types_raise_type_error(self):
        broken = self.bypass(receipt="not-a-receipt")
        with self.assertRaises(TypeError):
            verify_signed_search_receipt(broken, self.public_key)
        broken = self.bypass(checkpoint="not-a-checkpoint")
        with self.assertRaises(TypeError):
            verify_signed_search_receipt(broken, self.public_key)

    def test_nested_receipt_type_errors_propagate(self):
        receipt = self.package.receipt
        forged_receipt = SearchReceipt.__new__(SearchReceipt)
        for name in (
            "version", "hash_name", "size", "root", "query",
            "start", "stop", "items",
        ):
            object.__setattr__(
                forged_receipt, name, getattr(receipt, name)
            )
        object.__setattr__(forged_receipt, "query", 123)
        forged = self.bypass(receipt=forged_receipt)
        with self.assertRaises(TypeError):
            verify_signed_search_receipt(forged, self.public_key)

    def test_nested_checkpoint_type_errors_propagate(self):
        checkpoint = self.package.checkpoint
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
            verify_signed_search_receipt(forged, self.public_key)

    def test_nested_receipt_value_errors_propagate(self):
        receipt = self.package.receipt
        # A bypassed receipt whose version field is structurally invalid.
        forged_receipt = SearchReceipt.__new__(SearchReceipt)
        for name in (
            "version", "hash_name", "size", "root", "query",
            "start", "stop", "items",
        ):
            object.__setattr__(
                forged_receipt, name, getattr(receipt, name)
            )
        object.__setattr__(forged_receipt, "version", 2)
        forged = self.bypass(receipt=forged_receipt)
        with self.assertRaises(ValueError):
            verify_signed_search_receipt(forged, self.public_key)

    def test_tampered_payload_returns_false(self):
        receipt = self.package.receipt
        entry, proof = receipt.items[0]
        forged_entry = Entry(
            entry.index, b"tampered", entry.previous_hash, entry.entry_hash
        )
        forged_receipt = self._rebuild_receipt(
            items=((forged_entry, proof),) + receipt.items[1:]
        )
        forged = self.bypass(receipt=forged_receipt)
        self.assertFalse(
            verify_signed_search_receipt(forged, self.public_key)
        )

    def test_tampered_query_returns_false(self):
        # A query that no longer equals the listed hit payloads fails the
        # receipt-level check.
        forged = self.bypass(receipt=self._rebuild_receipt(query=b"zzz"))
        self.assertTrue(verify_search_receipt(self.package.receipt))
        self.assertFalse(verify_search_receipt(forged.receipt))
        self.assertFalse(
            verify_signed_search_receipt(forged, self.public_key)
        )

    def test_tampered_proof_returns_false(self):
        receipt = self.package.receipt
        entry, proof = receipt.items[0]
        bad_proof = (b"\x00" * 32,) + proof[1:]
        forged_receipt = self._rebuild_receipt(
            items=((entry, bad_proof),) + receipt.items[1:]
        )
        forged = self.bypass(receipt=forged_receipt)
        self.assertFalse(
            verify_signed_search_receipt(forged, self.public_key)
        )

    def test_tampered_checkpoint_signature_returns_false(self):
        checkpoint = self.package.checkpoint
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
            verify_signed_search_receipt(forged, self.public_key)
        )

    def test_mixed_size_returns_false(self):
        # Both parts are genuine and individually verifiable, but describe
        # different snapshot sizes.
        other = self.log.signed_search_receipt("a", _SEED_A, size=4)
        forged = self.bypass(checkpoint=other.checkpoint)
        self.assertTrue(verify_search_receipt(forged.receipt))
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_search_receipt(forged, self.public_key)
        )

    def test_mixed_root_returns_false(self):
        # Same size and key, but the checkpoint attests a different log's
        # root (and head): the cross-check must reject it.
        other_log = make_log(("x", "y", "z", "w", "u"))
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass(checkpoint=foreign_checkpoint)
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_search_receipt(forged, self.public_key)
        )

    def test_mixed_hash_name_returns_false(self):
        other_log = make_log(RECORDS, hash_name="sha512")
        foreign_checkpoint = other_log.sign_root(_SEED_A)
        forged = self.bypass(checkpoint=foreign_checkpoint)
        self.assertTrue(
            verify_signed_root(forged.checkpoint, self.public_key)
        )
        self.assertFalse(
            verify_signed_search_receipt(forged, self.public_key)
        )

    def test_incomplete_result_set_still_verifies(self):
        # Verification only attests listed hits, not completeness: a receipt
        # listing fewer hits still verifies as long as the checkpoint signs
        # the same snapshot.
        partial = self._rebuild_receipt(
            items=self.package.receipt.items[:1]
        )
        # The partial receipt and the checkpoint still name the same
        # snapshot, so the package is well formed and verifies.
        package = SignedSearchReceipt(partial, self.package.checkpoint)
        self.assertTrue(
            verify_signed_search_receipt(package, self.public_key)
        )

    def test_call_is_read_only(self):
        verify_signed_search_receipt(self.package, self.other_public_key)
        self.assertEqual(
            self.package,
            self.log.signed_search_receipt("a", _SEED_A),
        )


if __name__ == "__main__":
    unittest.main()
