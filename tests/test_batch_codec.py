import itertools
import unittest

from auditchain import (
    AuditLog,
    Entry,
    decode_audit_batch,
    encode_audit_batch,
    verify_audit_batch,
)

MAGIC = b"auditchain/batch/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def raw_entry(index, payload, previous_hash, entry_hash):
    return (
        u64(index)
        + blob(payload)
        + blob(previous_hash)
        + blob(entry_hash)
    )


def raw_batch(hash_name, size, root, raw_entries, proof_nodes, version=1):
    parts = [
        MAGIC,
        u64(version),
        blob(hash_name),
        u64(size),
        blob(root),
        u64(len(raw_entries)),
    ]
    parts.extend(raw_entries)
    parts.append(u64(len(proof_nodes)))
    parts.extend(blob(node) for node in proof_nodes)
    return b"".join(parts)


class EncodeAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_magic_and_field_layout(self):
        receipt = self.log.audit_batch([1])
        data = encode_audit_batch(receipt)
        hash_name, size, root, entries, proof = receipt
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(5))  # size
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(32))  # root length
        offset += 8
        self.assertEqual(data[offset:offset + 32], root)
        offset += 32
        # indices 1 and 4 (last entry auto-added)
        self.assertEqual(data[offset:offset + 8], u64(2))
        offset += 8
        for entry in entries:
            self.assertEqual(data[offset:offset + 8], u64(entry.index))
            offset += 8
            self.assertEqual(data[offset:offset + 8], u64(len(entry.payload)))
            offset += 8 + len(entry.payload)
            offset += 8 + len(entry.previous_hash)
            offset += 8 + len(entry.entry_hash)
        self.assertEqual(data[offset:offset + 8], u64(len(proof)))  # proof count

    def test_entries_then_single_shared_proof_at_end(self):
        # The shared proof is written once, after every entry.
        receipt = self.log.audit_batch([0, 2, 3])
        _, _, _, entries, proof = receipt
        body = b"".join(
            [raw_entry(e.index, e.payload, e.previous_hash, e.entry_hash) for e in entries]
            + [u64(len(proof))]
            + [blob(node) for node in proof]
        )
        data = encode_audit_batch(receipt)
        # Header ends right before the first entry.
        header_end = len(MAGIC) + 8 + 8 + 6 + 8 + 8 + 32 + 8
        self.assertEqual(data[header_end:], body)

    def test_zero_length_blob_is_all_zero_u64(self):
        self.log.append(b"")
        receipt = self.log.audit_batch([5])
        data = encode_audit_batch(receipt)
        decoded = decode_audit_batch(data)
        self.assertEqual(decoded[3][0].payload, b"")
        # The empty payload is framed as an all-zero u64 length.
        self.assertIn(u64(0), data)

    def test_encode_is_deterministic(self):
        receipt = self.log.audit_batch([0, 2, 3])
        self.assertEqual(encode_audit_batch(receipt), encode_audit_batch(receipt))

    def test_empty_snapshot_layout(self):
        receipt = self.log.audit_batch((), 0)
        data = encode_audit_batch(receipt)
        hash_name, size, root, entries, proof = receipt
        self.assertEqual(
            data,
            MAGIC + u64(1) + blob(b"sha256") + u64(0) + blob(root) + u64(0) + u64(0),
        )
        self.assertEqual(entries, ())
        self.assertEqual(proof, ())

    def test_type_errors(self):
        receipt = self.log.audit_batch([1])
        for bad in (None, "receipt", b"bytes", 1, [1, 2], (1, 2, 3, 4)):
            with self.assertRaises(TypeError):
                encode_audit_batch(bad)
        # Wrong arity even with plausible contents stays TypeError.
        with self.assertRaises(TypeError):
            encode_audit_batch(receipt[:4])
        with self.assertRaises(TypeError):
            encode_audit_batch(receipt + (1,))

    def test_field_type_errors_match_verifier(self):
        hash_name, size, root, entries, proof = self.log.audit_batch([1])
        bad_variants = (
            (1, size, root, entries, proof),
            (hash_name, "7", root, entries, proof),
            (hash_name, True, root, entries, proof),
            (hash_name, size, "root", entries, proof),
            (hash_name, size, root, list(entries), proof),
            (hash_name, size, root, entries, list(proof)),
        )
        for bad in bad_variants:
            self.assertRaises(TypeError, verify_audit_batch, bad)
            self.assertRaises(TypeError, encode_audit_batch, bad)

    def test_value_errors_match_verifier(self):
        hash_name, size, root, entries, proof = self.log.audit_batch([0, 2, 4])
        reordered = (entries[1], entries[0]) + entries[2:]
        bad_variants = (
            ("not-a-hash", size, root, entries, proof),
            (hash_name, -1, root, entries, proof),
            (hash_name, size, b"\x00" * 31, entries, proof),
            (hash_name, size, root, reordered, proof),
            (hash_name, size, root, entries[:-1], proof),
            (hash_name, size, root, (), ()),
        )
        for bad in bad_variants:
            self.assertRaises(ValueError, verify_audit_batch, bad)
            self.assertRaises(ValueError, encode_audit_batch, bad)

    def test_content_mismatch_still_encodes(self):
        # Structurally valid but forged content must encode; only verify
        # judges content.
        hash_name, size, root, entries, proof = self.log.audit_batch([0])
        e = entries[0]
        forged_entry = Entry(e.index, b"tampered", e.previous_hash, e.entry_hash)
        forged = (hash_name, size, root, (forged_entry,) + entries[1:], proof)
        data = encode_audit_batch(forged)
        self.assertEqual(decode_audit_batch(data), forged)
        self.assertFalse(verify_audit_batch(decode_audit_batch(data)))

    def test_read_only(self):
        receipt = self.log.audit_batch([1, 3])
        before = (len(self.log), self.log.head, self.log.merkle_root())
        encode_audit_batch(receipt)
        self.assertEqual(before, (len(self.log), self.log.head, self.log.merkle_root()))


class DecodeAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def roundtrip(self, receipt):
        data = encode_audit_batch(receipt)
        decoded = decode_audit_batch(data)
        self.assertIsInstance(decoded, tuple)
        self.assertEqual(len(decoded), 5)
        self.assertEqual(decoded, receipt)
        hash_name, size, root, entries, proof = decoded
        self.assertEqual(hash_name, receipt[0])
        self.assertEqual(size, receipt[1])
        self.assertEqual(root, receipt[2])
        self.assertEqual(entries, receipt[3])
        self.assertEqual(proof, receipt[4])
        self.assertIsInstance(entries, tuple)
        self.assertIsInstance(proof, tuple)
        # Re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_audit_batch(decoded), data)
        self.assertTrue(verify_audit_batch(decoded))
        return decoded

    def test_roundtrip_variants(self):
        for indices, size in (
            ([0], None), ([1, 3], None), ([3], 4), ([], None), ([], 3),
            ([0, 4], None), (range(5), 5),
        ):
            self.roundtrip(self.log.audit_batch(indices, size))

    def test_roundtrip_empty_snapshot(self):
        self.roundtrip(self.log.audit_batch((), 0))

    def test_roundtrip_single_leaf(self):
        self.roundtrip(self.log.audit_batch([0], 1))

    def test_roundtrip_empty_payload(self):
        self.log.append(b"")
        self.roundtrip(self.log.audit_batch([5]))

    def test_roundtrip_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.audit_batch([2, 4]))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        self.roundtrip(log.audit_batch([0, 2]))

    def test_roundtrip_sha512_width(self):
        log = AuditLog(hash_name="sha512")
        for record in range(6):
            log.append(str(record))
        decoded = self.roundtrip(log.audit_batch([1, 3]))
        self.assertEqual(len(decoded[2]), 64)
        self.assertTrue(all(len(node) == 64 for node in decoded[4]))

    def test_exhaustive_roundtrips_verify(self):
        for n in range(1, 8):
            log = AuditLog()
            for record in range(n):
                log.append(str(record))
            for size in range(0, n + 1):
                for width in range(0, size + 1):
                    for chosen in itertools.combinations(range(size), width):
                        receipt = log.audit_batch(chosen, size)
                        data = encode_audit_batch(receipt)
                        decoded = decode_audit_batch(data)
                        self.assertEqual(decoded, receipt, (n, size, chosen))
                        self.assertEqual(encode_audit_batch(decoded), data)
                        self.assertTrue(verify_audit_batch(decoded))

    def test_only_bytes_accepted(self):
        data = encode_audit_batch(self.log.audit_batch([1]))
        for bad in (bytearray(data), memoryview(data), "text", None, 1, []):
            with self.assertRaises(TypeError):
                decode_audit_batch(bad)

    def test_bad_magic(self):
        data = encode_audit_batch(self.log.audit_batch([1]))
        with self.assertRaises(ValueError):
            decode_audit_batch(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_audit_batch(b"")
        with self.assertRaises(ValueError):
            decode_audit_batch(MAGIC[:-1])

    def test_bad_version(self):
        receipt = self.log.audit_batch([1])
        data = MAGIC + u64(2) + encode_audit_batch(receipt)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_audit_batch(data)
        data = MAGIC + u64(0) + encode_audit_batch(receipt)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_unknown_hash_algorithm(self):
        data = raw_batch(b"not-a-hash", 0, b"\x00" * 32, [], [])
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_invalid_utf8_hash_name(self):
        data = raw_batch(b"\xff\xfe", 0, b"\x00" * 32, [], [])
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_truncation(self):
        data = encode_audit_batch(self.log.audit_batch([1, 3]))
        for cut in (len(MAGIC) + 3, len(data) - 1, len(data) // 2):
            with self.assertRaises(ValueError):
                decode_audit_batch(data[:cut])
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_audit_batch(data[:cut])

    def test_trailing_bytes(self):
        data = encode_audit_batch(self.log.audit_batch([1]))
        with self.assertRaises(ValueError):
            decode_audit_batch(data + b"\x00")
        with self.assertRaises(ValueError):
            decode_audit_batch(data + b"trailing")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_root_width_checked(self):
        data = raw_batch(b"sha256", 0, b"\x00" * 31, [], [])
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_entry_digest_widths_checked(self):
        receipt = self.log.audit_batch([0, 2])
        _, size, root, entries, proof = receipt
        e = entries[0]
        for field, bad_bytes in (
            ("previous_hash", b"\x00" * 31),
            ("entry_hash", b"\x00" * 33),
        ):
            if field == "previous_hash":
                bad_entry = raw_entry(e.index, e.payload, bad_bytes, e.entry_hash)
            else:
                bad_entry = raw_entry(e.index, e.payload, e.previous_hash, bad_bytes)
            rest = [
                raw_entry(x.index, x.payload, x.previous_hash, x.entry_hash)
                for x in entries[1:]
            ]
            data = raw_batch(
                b"sha256", size, root, [bad_entry] + rest, list(proof)
            )
            with self.assertRaises(ValueError):
                decode_audit_batch(data)

    def test_index_order_and_duplicates(self):
        receipt = self.log.audit_batch([0, 2])
        _, size, root, entries, proof = receipt
        reversed_entries = [
            raw_entry(e.index, e.payload, e.previous_hash, e.entry_hash)
            for e in (entries[1], entries[0])
        ]
        with self.assertRaises(ValueError):
            decode_audit_batch(raw_batch(
                b"sha256", size, root, reversed_entries, list(proof)
            ))
        first = raw_entry(
            entries[0].index, entries[0].payload,
            entries[0].previous_hash, entries[0].entry_hash,
        )
        with self.assertRaises(ValueError):
            decode_audit_batch(raw_batch(
                b"sha256", size, root, [first, first], list(proof)
            ))

    def test_entry_index_out_of_range(self):
        # Strictly ascending indices [0, 5] in a size-5 snapshot: order is
        # fine, but 5 >= size trips the range check.
        receipt = self.log.audit_batch([0])
        _, size, root, entries, proof = receipt
        e0 = entries[0]
        last = self.log.entry(size - 1)
        # Frame the real last entry's bytes at the out-of-range index 5.
        out_of_range = raw_entry(size, last.payload, last.previous_hash, last.entry_hash)
        first = raw_entry(e0.index, e0.payload, e0.previous_hash, e0.entry_hash)
        data = raw_batch(b"sha256", size, root, [first, out_of_range], list(proof))
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_missing_last_entry_rejected(self):
        # size = 5 but only the entry at index 0: the last-entry rule fails.
        receipt = self.log.audit_batch([0])
        _, size, root, entries, proof = receipt
        e = entries[0]
        only = raw_entry(e.index, e.payload, e.previous_hash, e.entry_hash)
        data = raw_batch(b"sha256", size, root, [only], list(proof))
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_zero_entries_non_empty_snapshot_rejected(self):
        root = self.log.merkle_root(5)
        # Genuine root, zero evidence.
        data = raw_batch(b"sha256", 5, root, [], [])
        with self.assertRaises(ValueError):
            decode_audit_batch(data)
        # Arbitrary root, zero evidence.
        data = raw_batch(b"sha256", 5, b"X" * 32, [], [])
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_empty_snapshot_with_entries_rejected(self):
        e = self.log.entry(0)
        data = raw_batch(
            b"sha256", 0, self.log.merkle_root(0),
            [raw_entry(e.index, e.payload, e.previous_hash, e.entry_hash)],
            [],
        )
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_empty_snapshot_with_proof_nodes_rejected(self):
        data = raw_batch(
            b"sha256", 0, self.log.merkle_root(0), [], [b"\x00" * 32]
        )
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_proof_node_count_checked(self):
        receipt = self.log.audit_batch([0, 2, 4])
        _, size, root, entries, proof = receipt
        encoded_entries = [
            raw_entry(e.index, e.payload, e.previous_hash, e.entry_hash) for e in entries
        ]
        if not proof:
            self.skipTest("selection covers every leaf; proof is empty")
        with self.assertRaises(ValueError):
            decode_audit_batch(raw_batch(
                b"sha256", size, root, encoded_entries, list(proof) + [b"\x00" * 32]
            ))
        with self.assertRaises(ValueError):
            decode_audit_batch(raw_batch(
                b"sha256", size, root, encoded_entries, list(proof[:-1])
            ))

    def test_proof_node_width_checked(self):
        receipt = self.log.audit_batch([0, 2, 4])
        _, size, root, entries, proof = receipt
        if not proof:
            self.skipTest("selection covers every leaf; proof is empty")
        encoded_entries = [
            raw_entry(e.index, e.payload, e.previous_hash, e.entry_hash) for e in entries
        ]
        bad_nodes = [b"\x00" * 31] + list(proof[1:])
        with self.assertRaises(ValueError):
            decode_audit_batch(raw_batch(
                b"sha256", size, root, encoded_entries, bad_nodes
            ))

    def test_wrong_content_decodes_but_verifies_false(self):
        receipt = self.log.audit_batch([0, 2])
        hash_name, size, root, entries, proof = receipt
        e = entries[0]
        tampered = Entry(e.index, b"tampered", e.previous_hash, e.entry_hash)
        forged = (hash_name, size, root, (tampered,) + entries[1:], proof)
        data = encode_audit_batch(forged)
        decoded = decode_audit_batch(data)  # no exception
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_audit_batch(decoded))

    def test_wrong_root_decodes_but_verifies_false(self):
        receipt = self.log.audit_batch([0, 2])
        hash_name, size, root, entries, proof = receipt
        forged = (hash_name, size, b"\x11" * 32, entries, proof)
        decoded = decode_audit_batch(encode_audit_batch(forged))
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_audit_batch(decoded))

    def test_wrong_proof_nodes_decode_but_verify_false(self):
        receipt = self.log.audit_batch([0, 2, 4])
        hash_name, size, root, entries, proof = receipt
        if not proof:
            self.skipTest("selection covers every leaf; proof is empty")
        bogus = (b"\x22" * 32,) + proof[1:]
        forged = (hash_name, size, root, entries, bogus)
        decoded = decode_audit_batch(encode_audit_batch(forged))
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_audit_batch(decoded))

    def test_decoded_receipt_survives_later_appends(self):
        receipt = self.log.audit_batch([1], 4)
        decoded = decode_audit_batch(encode_audit_batch(receipt))
        self.log.append("f")
        self.assertTrue(verify_audit_batch(decoded))


if __name__ == "__main__":
    unittest.main()
