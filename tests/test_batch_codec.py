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


def raw_entries(entries):
    return [
        (entry.index, entry.payload, entry.previous_hash, entry.entry_hash)
        for entry in entries
    ]


def build(hash_name, size, root, entries, proof, version=1):
    """Hand-build a batch encoding with arbitrary (possibly invalid) content."""
    out = MAGIC + u64(version) + blob(hash_name) + u64(size) + blob(root)
    out += u64(len(entries))
    for index, payload, previous_hash, entry_hash in entries:
        out += u64(index) + blob(payload) + blob(previous_hash) + blob(entry_hash)
    out += u64(len(proof))
    for node in proof:
        out += blob(node)
    return out


class EncodeAuditBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()
        for record in ("a", "b", "c", "d", "e"):
            self.log.append(record)

    def test_magic_and_field_layout(self):
        receipt = self.log.audit_batch([1, 3])
        hash_name, size, root, entries, proof = receipt
        data = encode_audit_batch(receipt)
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
        self.assertEqual(data[offset:offset + 8], u64(len(entries)))  # entry count
        # The shared proof count follows every entry; scan to it.
        offset += 8
        for entry in entries:
            offset += 8  # index
            for material in (entry.payload, entry.previous_hash, entry.entry_hash):
                offset += 8 + len(material)
        self.assertEqual(data[offset:offset + 8], u64(len(proof)))
        offset += 8
        for node in proof:
            offset += 8 + len(node)
        self.assertEqual(offset, len(data))

    def test_empty_snapshot_layout(self):
        data = encode_audit_batch(self.log.audit_batch((), 0))
        # magic + version + hash_name blob + size 0 + 32-byte root blob +
        # entry count 0 + proof count 0.
        self.assertEqual(
            data,
            MAGIC + u64(1) + blob(b"sha256") + u64(0)
            + blob(self.log.merkle_root(0)) + u64(0) + u64(0),
        )

    def test_zero_length_payload_blob_is_all_zero_u64(self):
        self.log.append(b"")
        receipt = self.log.audit_batch([5])
        data = encode_audit_batch(receipt)
        decoded = decode_audit_batch(data)
        self.assertEqual(decoded[3][-1].payload, b"")
        self.assertIn(u64(0), data)

    def test_encode_is_deterministic(self):
        receipt = self.log.audit_batch([0, 2, 3])
        self.assertEqual(encode_audit_batch(receipt), encode_audit_batch(receipt))

    def test_encoding_is_read_only(self):
        receipt = self.log.audit_batch([1, 3])
        before = (len(self.log), self.log.merkle_root(5))
        encode_audit_batch(receipt)
        self.assertEqual((len(self.log), self.log.merkle_root(5)), before)

    def test_non_five_tuple_raises_type_error(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2), object()):
            with self.assertRaises(TypeError):
                encode_audit_batch(bad)
        receipt = self.log.audit_batch([1])
        with self.assertRaises(TypeError):
            encode_audit_batch(tuple(receipt) + (1,))
        with self.assertRaises(TypeError):
            encode_audit_batch(tuple(receipt)[:-1])
        with self.assertRaises(TypeError):
            encode_audit_batch(list(receipt))

    def test_field_type_errors(self):
        hash_name, size, root, entries, proof = self.log.audit_batch([1])
        with self.assertRaises(TypeError):
            encode_audit_batch((1, size, root, entries, proof))
        with self.assertRaises(TypeError):
            encode_audit_batch((hash_name, "7", root, entries, proof))
        with self.assertRaises(TypeError):
            encode_audit_batch((hash_name, True, root, entries, proof))
        with self.assertRaises(TypeError):
            encode_audit_batch((hash_name, size, "root", entries, proof))
        with self.assertRaises(TypeError):
            encode_audit_batch((hash_name, size, root, list(entries), proof))
        with self.assertRaises(TypeError):
            encode_audit_batch((hash_name, size, root, ("x",), proof))
        with self.assertRaises(TypeError):
            encode_audit_batch((hash_name, size, root, entries, list(proof)))
        # Proof nodes must be exact bytes, not bytearray.
        with self.assertRaises(TypeError):
            encode_audit_batch(
                (hash_name, size, root, entries,
                 tuple(bytearray(node) for node in proof))
            )

    def test_bytearray_entry_fields_accepted(self):
        hash_name, size, root, entries, proof = self.log.audit_batch([1])
        entry = entries[0]
        copied = Entry(
            entry.index,
            bytearray(entry.payload),
            bytearray(entry.previous_hash),
            bytearray(entry.entry_hash),
        )
        receipt = (hash_name, size, root, (copied,) + entries[1:], proof)
        data = encode_audit_batch(receipt)
        self.assertEqual(decode_audit_batch(data), self.log.audit_batch([1]))

    def test_structural_violations_raise_value_error(self):
        hash_name, size, root, entries, proof = self.log.audit_batch([1, 3])
        with self.assertRaises(ValueError):
            encode_audit_batch((hash_name, -1, root, entries, proof))
        with self.assertRaises(ValueError):
            encode_audit_batch(("not-a-hash", size, root, entries, proof))
        with self.assertRaises(ValueError):
            encode_audit_batch((hash_name, size, b"\x00" * 31, entries, proof))
        with self.assertRaises(ValueError):
            encode_audit_batch((hash_name, size, root, (), ()))
        with self.assertRaises(ValueError):
            encode_audit_batch(
                (hash_name, size, root, entries, proof + (b"\x00" * 32,))
            )


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
        # Deterministic: decoding and re-encoding reproduces the bytes.
        self.assertEqual(encode_audit_batch(decoded), data)
        self.assertTrue(verify_audit_batch(decoded))
        return decoded

    def test_roundtrip_variants(self):
        for indices, size in (
            ([0], None), ([1, 3], None), ([3], 4), ([], None), ([], 3),
            ([0, 4], 5), ([0], 1),
        ):
            self.roundtrip(self.log.audit_batch(indices, size))

    def test_roundtrip_empty_snapshot(self):
        self.roundtrip(self.log.audit_batch((), 0))

    def test_roundtrip_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.audit_batch([2, 4]))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "c"):
            log.append(record)
        self.roundtrip(log.audit_batch([0, 2]))

    def test_only_bytes_accepted(self):
        data = encode_audit_batch(self.log.audit_batch([1]))
        for bad in (bytearray(data), memoryview(data), "text", None, 1, [data]):
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

    def test_unknown_hash_algorithm(self):
        data = build(b"not-a-hash", 0, b"", [], [])
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_invalid_utf8_hash_name(self):
        data = build(b"\xff\xfe", 0, b"", [], [])
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_truncation(self):
        data = encode_audit_batch(self.log.audit_batch([1, 3]))
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_audit_batch(data[:cut])

    def test_trailing_bytes(self):
        data = encode_audit_batch(self.log.audit_batch([1]))
        with self.assertRaises(ValueError):
            decode_audit_batch(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_audit_batch(data)

    def test_digest_widths_checked(self):
        _, size, _, entries, proof = self.log.audit_batch([1, 3])
        with self.assertRaises(ValueError):
            decode_audit_batch(build(b"sha256", size, b"\x00" * 31, raw_entries(entries), proof))
        entry = entries[0]
        bad_entry = (entry.index, entry.payload, entry.previous_hash, b"\x00" * 31)
        with self.assertRaises(ValueError):
            decode_audit_batch(
                build(b"sha256", size, self.log.merkle_root(size),
                      [bad_entry] + raw_entries(entries[1:]), proof)
            )
        if proof:
            with self.assertRaises(ValueError):
                decode_audit_batch(
                    build(b"sha256", size, self.log.merkle_root(size),
                          raw_entries(entries), proof[:-1] + (b"\x00" * 31,))
                )

    def test_index_order_and_duplicates(self):
        _, size, root, entries, proof = self.log.audit_batch([1, 3])
        descending = raw_entries((entries[1], entries[0]))
        with self.assertRaises(ValueError):
            decode_audit_batch(build(b"sha256", size, root, descending, proof))
        duplicated = raw_entries((entries[0],) + entries)
        with self.assertRaises(ValueError):
            decode_audit_batch(build(b"sha256", size, root, duplicated, proof))

    def test_index_out_of_range(self):
        _, size, root, entries, proof = self.log.audit_batch([1, 3])
        entry = entries[0]
        bad = (size, entry.payload, entry.previous_hash, entry.entry_hash)
        with self.assertRaises(ValueError):
            decode_audit_batch(
                build(b"sha256", size, root, [bad] + raw_entries(entries[1:]), proof)
            )

    def test_missing_last_entry(self):
        _, size, _, entries, proof = self.log.audit_batch([1, 3])
        with self.assertRaises(ValueError):
            decode_audit_batch(
                build(b"sha256", size, self.log.merkle_root(size),
                      raw_entries(entries[:-1]), proof)
            )

    def test_zero_entry_non_empty_snapshot_rejected(self):
        header = MAGIC + u64(1) + blob(b"sha256") + u64(5)
        with self.assertRaises(ValueError):
            decode_audit_batch(header + blob(self.log.merkle_root(5)) + u64(0) + u64(0))
        # Arbitrary root, zero evidence.
        with self.assertRaises(ValueError):
            decode_audit_batch(header + blob(b"X" * 32) + u64(0) + u64(0))

    def test_empty_snapshot_with_entries_or_nodes_rejected(self):
        entry = self.log.entry(0)
        with self.assertRaises(ValueError):
            decode_audit_batch(
                build(b"sha256", 0, self.log.merkle_root(0), raw_entries([entry]), [])
            )
        with self.assertRaises(ValueError):
            decode_audit_batch(
                build(b"sha256", 0, self.log.merkle_root(0), [], [b"\x00" * 32])
            )

    def test_proof_node_count_checked(self):
        _, size, root, entries, proof = self.log.audit_batch([1, 3])
        with self.assertRaises(ValueError):
            decode_audit_batch(
                build(b"sha256", size, root, raw_entries(entries),
                      proof + (b"\x00" * 32,))
            )
        if proof:
            with self.assertRaises(ValueError):
                decode_audit_batch(
                    build(b"sha256", size, root, raw_entries(entries), proof[:-1])
                )

    def test_content_mismatch_decodes_but_verifies_false(self):
        hash_name, size, root, entries, proof = self.log.audit_batch([1, 3])
        entry = entries[0]
        forged = (entry.index, b"tampered", entry.previous_hash, entry.entry_hash)
        data = build(
            b"sha256", size, root, [forged] + raw_entries(entries[1:]), proof
        )
        decoded = decode_audit_batch(data)  # structurally sound, decodes
        self.assertFalse(verify_audit_batch(decoded))

    def test_wrong_root_decodes_but_verifies_false(self):
        _, size, _, entries, proof = self.log.audit_batch([1, 3])
        data = build(b"sha256", size, b"\x11" * 32, raw_entries(entries), proof)
        decoded = decode_audit_batch(data)
        self.assertEqual(decoded[2], b"\x11" * 32)
        self.assertFalse(verify_audit_batch(decoded))

    def test_wrong_proof_node_decodes_but_verifies_false(self):
        _, size, root, entries, proof = self.log.audit_batch([1, 3])
        if not proof:
            self.skipTest("receipt has an empty shared proof")
        data = build(
            b"sha256", size, root, raw_entries(entries),
            (b"\x22" * 32,) + proof[1:],
        )
        decoded = decode_audit_batch(data)
        self.assertFalse(verify_audit_batch(decoded))

    def test_non_canonical_empty_root_verifies_false(self):
        # Right digest width, wrong value: decodable, not a valid empty root.
        data = build(b"sha256", 0, b"\x00" * 32, [], [])
        decoded = decode_audit_batch(data)
        self.assertFalse(verify_audit_batch(decoded))


if __name__ == "__main__":
    unittest.main()
