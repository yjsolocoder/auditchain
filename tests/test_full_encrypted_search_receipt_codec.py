import unittest

from auditchain import (
    AuditLog,
    Entry,
    FullEncryptedSearchReceipt,
    decode_full_encrypted_search_receipt,
    encode_full_encrypted_search_receipt,
    verify_full_encrypted_search_receipt,
)

MAGIC = b"auditchain/full-encrypted-search/v1\0"

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def make_log(records=(("enc", "a"), ("plain", "b"), ("enc", "a"), ("enc", "c"), ("enc", "a"))):
    """Build a mixed log; records are ("enc"|"plain", value)."""
    log = AuditLog()
    nonce_counter = 0
    for kind, value in records:
        if kind == "enc":
            log.encrypt(value, KEY, nonce=bytes([nonce_counter]) * 12)
        else:
            log.append(value)
        nonce_counter += 1
    return log


def encode_entry(entry):
    return (
        u64(entry.index)
        + blob(entry.payload)
        + blob(entry.previous_hash)
        + blob(entry.entry_hash)
    )


class EncodeFullEncryptedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_magic_and_field_layout(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4, size=4)
        data = encode_full_encrypted_search_receipt(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(4))  # size
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(32))  # root length
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.root)
        offset += 32
        self.assertEqual(data[offset:offset + 8], u64(1))  # query length
        offset += 8
        self.assertEqual(data[offset:offset + 1], b"a")
        offset += 1
        self.assertEqual(data[offset:offset + 8], u64(1))  # start
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(4))  # stop
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(3))  # items: 1, 2 and 3
        offset += 8
        for entry in receipt.items:
            self.assertEqual(
                data[offset:offset + len(encode_entry(entry))], encode_entry(entry)
            )
            offset += len(encode_entry(entry))
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.proof)))
        offset += 8
        for node in receipt.proof:
            self.assertEqual(data[offset:offset + 8], u64(32))
            offset += 8
            self.assertEqual(data[offset:offset + 32], node)
            offset += 32
        # The hit segment is a bare count followed by bare u64 indices.
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.hits)))
        offset += 8
        for hit in receipt.hits:
            self.assertEqual(data[offset:offset + 8], u64(hit))
            offset += 8
        self.assertEqual(offset, len(data))

    def test_layout_matches_full_search_receipt_before_hits(self):
        from auditchain import encode_full_search_receipt

        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4, size=4)
        data = encode_full_encrypted_search_receipt(receipt)
        plain_data = encode_full_search_receipt(
            self.log.full_search_receipt("a", 1, 4, size=4)
        )
        hit_tail = u64(len(receipt.hits)) + b"".join(u64(h) for h in receipt.hits)
        # Everything up to and including the shared proof is identical apart
        # from the magic prefix; only the hit segment is appended.
        self.assertEqual(
            data[len(MAGIC):-len(hit_tail)],
            plain_data[len(b"auditchain/full-search/v1\0"):],
        )

    def test_encode_is_deterministic(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4, size=4)
        self.assertEqual(
            encode_full_encrypted_search_receipt(receipt),
            encode_full_encrypted_search_receipt(receipt),
        )

    def test_empty_range_and_empty_snapshot_encode(self):
        empty = self.log.full_encrypted_search_receipt("a", KEY, 2, 2)
        data = encode_full_encrypted_search_receipt(empty)
        # zero items, zero proof, zero hits — none of the three is omitted
        self.assertTrue(data.endswith(u64(0) + u64(0) + u64(0)))
        snapshot = AuditLog().full_encrypted_search_receipt("a", KEY)
        self.assertEqual(
            encode_full_encrypted_search_receipt(snapshot),
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(0)
            + blob(snapshot.root)
            + blob(b"a")
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0),
        )

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2)):
            with self.assertRaises(TypeError):
                encode_full_encrypted_search_receipt(bad)

    def make_bypassed(self, **fields):
        """Receipt with invalid structure, bypassing the frozen constructor."""
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        forged = FullEncryptedSearchReceipt.__new__(FullEncryptedSearchReceipt)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "query",
            "start",
            "stop",
            "items",
            "proof",
            "hits",
        ):
            object.__setattr__(forged, name, fields.get(name, getattr(receipt, name)))
        return forged

    def test_encode_revalidates_bypassed_fields(self):
        with self.assertRaises(ValueError):
            encode_full_encrypted_search_receipt(self.make_bypassed(version=2))
        with self.assertRaises(ValueError):
            encode_full_encrypted_search_receipt(self.make_bypassed(stop=4))
        with self.assertRaises(TypeError):
            encode_full_encrypted_search_receipt(self.make_bypassed(query=123))
        with self.assertRaises(TypeError):
            encode_full_encrypted_search_receipt(self.make_bypassed(items="no"))
        with self.assertRaises(TypeError):
            encode_full_encrypted_search_receipt(self.make_bypassed(hits=[0, 2]))
        with self.assertRaises(ValueError):
            encode_full_encrypted_search_receipt(
                self.make_bypassed(hits=(0, 0, 4))
            )  # duplicate
        with self.assertRaises(ValueError):
            encode_full_encrypted_search_receipt(
                self.make_bypassed(hits=(2, 0, 4))
            )  # order
        with self.assertRaises(ValueError):
            encode_full_encrypted_search_receipt(
                self.make_bypassed(hits=(0, 2, 5))
            )  # range

    def test_proof_node_count_checked(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4, size=4)
        with self.assertRaises(ValueError):
            encode_full_encrypted_search_receipt(
                self.make_bypassed(
                    start=1, stop=4, size=4, items=receipt.items, proof=(),
                    hits=receipt.hits,
                )
            )
        with self.assertRaises(ValueError):
            encode_full_encrypted_search_receipt(
                self.make_bypassed(
                    start=1,
                    stop=4,
                    size=4,
                    items=receipt.items,
                    proof=receipt.proof + (b"\x00" * 32,),
                    hits=receipt.hits,
                )
            )


class DecodeFullEncryptedSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def roundtrip(self, receipt, key=KEY):
        data = encode_full_encrypted_search_receipt(receipt)
        decoded = decode_full_encrypted_search_receipt(data)
        self.assertIsInstance(decoded, FullEncryptedSearchReceipt)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.hash_name, receipt.hash_name)
        self.assertEqual(decoded.size, receipt.size)
        self.assertEqual(decoded.root, receipt.root)
        self.assertEqual(decoded.query, receipt.query)
        self.assertEqual((decoded.start, decoded.stop), (receipt.start, receipt.stop))
        self.assertEqual(decoded.items, receipt.items)
        self.assertEqual(decoded.proof, receipt.proof)
        self.assertEqual(decoded.hits, receipt.hits)
        # Decoding and re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_full_encrypted_search_receipt(decoded), data)
        self.assertTrue(verify_full_encrypted_search_receipt(decoded, key))
        return decoded

    def test_roundtrip_variants(self):
        self.roundtrip(self.log.full_encrypted_search_receipt("a", KEY))
        self.roundtrip(self.log.full_encrypted_search_receipt("missing", KEY))
        self.roundtrip(self.log.full_encrypted_search_receipt("a", KEY, 1, 4))
        self.roundtrip(self.log.full_encrypted_search_receipt("a", KEY, size=3))
        self.roundtrip(self.log.full_encrypted_search_receipt("a", KEY, 0, 3, size=3))

    def test_roundtrip_empty_range_and_empty_snapshot(self):
        self.roundtrip(self.log.full_encrypted_search_receipt("a", KEY, 2, 2))
        self.roundtrip(AuditLog().full_encrypted_search_receipt("a", KEY))

    def test_roundtrip_unicode_query(self):
        log = AuditLog()
        log.encrypt("位置主张", KEY, nonce=b"u" * 12)
        log.encrypt("位置主张", KEY, nonce=b"v" * 12)
        receipt = log.full_encrypted_search_receipt("位置主张", KEY)
        decoded = self.roundtrip(receipt)
        self.assertEqual(decoded.query, "位置主张".encode("utf-8"))
        self.assertEqual(decoded.hits, (0, 1))

    def test_roundtrip_with_foreign_key_and_plain_entries(self):
        log = make_log()
        log.encrypt("a", OTHER_KEY, nonce=b"f" * 12)
        self.roundtrip(log.full_encrypted_search_receipt("a", KEY))

    def test_roundtrip_after_prune(self):
        log = make_log()
        log.prune(2, log.seal(2))
        self.roundtrip(log.full_encrypted_search_receipt("a", KEY))
        self.roundtrip(log.full_encrypted_search_receipt("b", KEY))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        nonce = 0
        for kind, value in (("enc", "a"), ("enc", "b"), ("enc", "a")):
            log.encrypt(value, KEY, nonce=bytes([nonce]) * 12)
            nonce += 1
        self.roundtrip(log.full_encrypted_search_receipt("a", KEY))

    def test_tampered_entry_still_roundtrips_and_fails_verification(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        entry = receipt.items[2]
        forged_entry = Entry(entry.index, b"zz", entry.previous_hash, entry.entry_hash)
        tampered = FullEncryptedSearchReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            receipt.query,
            receipt.start,
            receipt.stop,
            receipt.items[:2] + (forged_entry,) + receipt.items[3:],
            receipt.proof,
            receipt.hits,
        )
        data = encode_full_encrypted_search_receipt(tampered)
        decoded = decode_full_encrypted_search_receipt(data)
        self.assertEqual(decoded, tampered)
        self.assertEqual(encode_full_encrypted_search_receipt(decoded), data)
        self.assertFalse(verify_full_encrypted_search_receipt(decoded, KEY))

    def test_tampered_proof_still_roundtrips_and_fails_verification(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 0, 2)
        self.assertGreaterEqual(len(receipt.proof), 1)
        tampered = FullEncryptedSearchReceipt(
            1,
            "sha256",
            receipt.size,
            receipt.root,
            receipt.query,
            receipt.start,
            receipt.stop,
            receipt.items,
            (b"\x00" * 32,) + receipt.proof[1:],
            receipt.hits,
        )
        data = encode_full_encrypted_search_receipt(tampered)
        decoded = decode_full_encrypted_search_receipt(data)
        self.assertEqual(decoded, tampered)
        self.assertEqual(encode_full_encrypted_search_receipt(decoded), data)
        self.assertFalse(verify_full_encrypted_search_receipt(decoded, KEY))

    def test_tampered_root_still_roundtrips_and_fails_verification(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        tampered = FullEncryptedSearchReceipt(
            1,
            "sha256",
            receipt.size,
            bytes(32),
            receipt.query,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
            receipt.hits,
        )
        data = encode_full_encrypted_search_receipt(tampered)
        decoded = decode_full_encrypted_search_receipt(data)
        self.assertEqual(decoded, tampered)
        self.assertEqual(encode_full_encrypted_search_receipt(decoded), data)
        self.assertFalse(verify_full_encrypted_search_receipt(decoded, KEY))

    def test_tampered_hits_still_roundtrip_and_fail_verification(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        for hits in ((), (0, 2), (1, 2, 4), (0, 1, 2, 4)):
            tampered = FullEncryptedSearchReceipt(
                1,
                "sha256",
                receipt.size,
                receipt.root,
                receipt.query,
                receipt.start,
                receipt.stop,
                receipt.items,
                receipt.proof,
                hits,
            )
            data = encode_full_encrypted_search_receipt(tampered)
            decoded = decode_full_encrypted_search_receipt(data)
            self.assertEqual(decoded, tampered)
            self.assertEqual(encode_full_encrypted_search_receipt(decoded), data)
            self.assertFalse(verify_full_encrypted_search_receipt(decoded, KEY))

    def test_empty_snapshot_tampered_root_fails_verification(self):
        receipt = AuditLog().full_encrypted_search_receipt("a", KEY)
        tampered = FullEncryptedSearchReceipt(
            1,
            "sha256",
            receipt.size,
            bytes(32),
            receipt.query,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
            receipt.hits,
        )
        decoded = decode_full_encrypted_search_receipt(
            encode_full_encrypted_search_receipt(tampered)
        )
        self.assertEqual(decoded, tampered)
        self.assertFalse(verify_full_encrypted_search_receipt(decoded, KEY))

    def test_pure_empty_range_root_is_not_compared(self):
        # An empty range of a non-empty snapshot carries no checkable
        # evidence; the recorded root never participates in verification,
        # before or after a round trip.
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 2, 2)
        tampered = FullEncryptedSearchReceipt(
            1,
            "sha256",
            receipt.size,
            bytes(32),
            receipt.query,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
            receipt.hits,
        )
        self.assertTrue(verify_full_encrypted_search_receipt(tampered, KEY))
        decoded = decode_full_encrypted_search_receipt(
            encode_full_encrypted_search_receipt(tampered)
        )
        self.assertTrue(verify_full_encrypted_search_receipt(decoded, KEY))

    def test_only_bytes_accepted(self):
        data = encode_full_encrypted_search_receipt(
            self.log.full_encrypted_search_receipt("a", KEY)
        )
        for bad in (bytearray(data), memoryview(data), "text", None, 1):
            with self.assertRaises(TypeError):
                decode_full_encrypted_search_receipt(bad)

    def test_bad_magic(self):
        data = encode_full_encrypted_search_receipt(
            self.log.full_encrypted_search_receipt("a", KEY)
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(b"")
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(MAGIC[:-1])
        # The sibling full-search magic is not accepted.
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(
                b"auditchain/full-search/v1\0" + data[len(MAGIC):]
            )

    def test_bad_version(self):
        data = encode_full_encrypted_search_receipt(
            self.log.full_encrypted_search_receipt("a", KEY)
        )
        forged = MAGIC + u64(2) + data[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(forged)

    def test_unknown_hash_algorithm(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"not-a-hash")
            + u64(0)
            + blob(b"")
            + blob(b"")
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(data)

    def test_invalid_utf8_hash_name(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"\xff\xfe")
            + u64(0)
            + blob(b"")
            + blob(b"")
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(data)

    def test_truncation(self):
        data = encode_full_encrypted_search_receipt(
            self.log.full_encrypted_search_receipt("a", KEY)
        )
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_full_encrypted_search_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_full_encrypted_search_receipt(
            self.log.full_encrypted_search_receipt("a", KEY)
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(data)

    def test_digest_length_checked(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(5)
            + blob(b"\x00" * 31)
            + blob(b"a")
            + u64(0)
            + u64(5)
            + u64(0)
            + u64(0)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(data)
        # A proof element of the wrong width is rejected too.
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4, size=4)
        forged = FullEncryptedSearchReceipt.__new__(FullEncryptedSearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", 4),
            ("root", self.log.merkle_root(4)),
            ("query", b"a"),
            ("start", 1),
            ("stop", 4),
            ("items", receipt.items),
            ("proof", (b"\x00" * 16,)),
            ("hits", receipt.hits),
        ):
            object.__setattr__(forged, name, value)
        with self.assertRaises(ValueError):
            encode_full_encrypted_search_receipt(forged)

    def make_bypassed(self, items, proof, hits, size=5, start=0, stop=5):
        forged = FullEncryptedSearchReceipt.__new__(FullEncryptedSearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", size),
            ("root", self.log.merkle_root(size)),
            ("query", b"a"),
            ("start", start),
            ("stop", stop),
            ("items", items),
            ("proof", proof),
            ("hits", hits),
        ):
            object.__setattr__(forged, name, value)
        return forged

    def test_index_order_duplicates_and_coverage(self):
        items = tuple(self.log.entry(i) for i in range(5))
        _, proof = self.log.batch_inclusion_proof((0, 1, 2, 3, 4), 5)
        # Out-of-order and duplicate indices are rejected at decode time.
        for bad_items in (
            (items[1], items[0]) + items[2:],
            (items[0], items[0]) + items[2:],
        ):
            with self.assertRaises(ValueError):
                decode_full_encrypted_search_receipt(
                    encode_full_encrypted_search_receipt(
                        self.make_bypassed(bad_items, proof, (0, 2, 4))
                    )
                )
        # An incomplete coverage of the range is rejected at decode time.
        short = items[:4]
        _, short_proof = self.log.batch_inclusion_proof((0, 1, 2, 3), 5)
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(
                encode_full_encrypted_search_receipt(
                    self.make_bypassed(short, short_proof, (0, 2))
                )
            )

    def test_index_outside_recorded_range(self):
        items = tuple(self.log.entry(i) for i in range(5))
        _, proof = self.log.batch_inclusion_proof((0, 1, 2, 3, 4), 5)
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(
                encode_full_encrypted_search_receipt(
                    self.make_bypassed(items, proof, (0, 2, 4), stop=4)
                )
            )

    def test_empty_range_with_non_empty_proof(self):
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(
                encode_full_encrypted_search_receipt(
                    self.make_bypassed((), (b"\x00" * 32,), (), start=2, stop=2)
                )
            )

    def test_proof_structure_checked(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 1, 4, size=4)
        # One node too few / too many for the listed indices and size.
        for bad_proof in ((), receipt.proof + (b"\x00" * 32,)):
            with self.assertRaises(ValueError):
                decode_full_encrypted_search_receipt(
                    encode_full_encrypted_search_receipt(
                        self.make_bypassed(
                            receipt.items,
                            bad_proof,
                            receipt.hits,
                            size=4,
                            start=1,
                            stop=4,
                        )
                    )
                )

    def _replace_hit_segment(self, data, hits):
        """Splice a new hit segment (count + bare u64 indices) into bytes."""
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        old_tail_len = 8 * (1 + len(receipt.hits))
        new_tail = u64(len(hits)) + b"".join(u64(h) for h in hits)
        return data[:len(data) - old_tail_len] + new_tail

    def test_hits_duplicate_out_of_order_and_out_of_range(self):
        data = encode_full_encrypted_search_receipt(
            self.log.full_encrypted_search_receipt("a", KEY)
        )
        for bad_hits in ((0, 0, 4), (2, 0, 4), (0, 2, 5), (-1 & ((1 << 64) - 1), 2, 4)):
            with self.assertRaises(ValueError):
                decode_full_encrypted_search_receipt(
                    self._replace_hit_segment(data, bad_hits)
                )

    def test_hit_count_mismatch_with_declared_entries(self):
        # A hit count announcing more indices than the bytes hold truncates.
        receipt = self.log.full_encrypted_search_receipt("a", KEY)
        data = encode_full_encrypted_search_receipt(receipt)
        old_tail_len = 8 * (1 + len(receipt.hits))
        forged = data[:len(data) - old_tail_len] + u64(len(receipt.hits) + 1)
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(forged)

    def test_non_empty_hits_on_empty_range_rejected(self):
        receipt = self.log.full_encrypted_search_receipt("a", KEY, 2, 2)
        data = encode_full_encrypted_search_receipt(receipt)
        forged = data[:-8] + u64(1) + u64(2)
        with self.assertRaises(ValueError):
            decode_full_encrypted_search_receipt(forged)


if __name__ == "__main__":
    unittest.main()
