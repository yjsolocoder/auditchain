import unittest

from auditchain import (
    AuditLog,
    Entry,
    RangeSearchReceipt,
    decode_range_search_receipt,
    encode_range_search_receipt,
    verify_range_search_receipt,
)

MAGIC = b"auditchain/range-search/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def make_log(records=("a", "b", "aa", "c", "a", "b")):
    log = AuditLog()
    for record in records:
        log.append(record)
    return log


def encode_entry(entry):
    return (
        u64(entry.index)
        + blob(entry.payload)
        + blob(entry.previous_hash)
        + blob(entry.entry_hash)
    )


class EncodeRangeSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def test_magic_and_field_layout(self):
        receipt = self.log.range_search_receipt(b"a", b"d", 1, 5)
        data = encode_range_search_receipt(receipt)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(6))  # size
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(32))  # root length
        offset += 8
        self.assertEqual(data[offset:offset + 32], receipt.root)
        offset += 32
        self.assertEqual(data[offset:offset + 8], u64(1))  # left length
        offset += 8
        self.assertEqual(data[offset:offset + 1], b"a")
        offset += 1
        self.assertEqual(data[offset:offset + 8], u64(1))  # right length
        offset += 8
        self.assertEqual(data[offset:offset + 1], b"d")
        offset += 1
        self.assertEqual(data[offset:offset + 8], u64(1))  # start
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(5))  # stop
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(4))  # items
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
        self.assertEqual(data[offset:offset + 8], u64(len(receipt.hits)))
        offset += 8
        for hit in receipt.hits:
            self.assertEqual(data[offset:offset + 8], u64(hit))
            offset += 8
        self.assertEqual(offset, len(data))

    def test_encode_is_deterministic(self):
        receipt = self.log.range_search_receipt(b"a", b"d", 1, 5, size=5)
        self.assertEqual(
            encode_range_search_receipt(receipt),
            encode_range_search_receipt(receipt),
        )

    def test_empty_range_and_empty_snapshot_encode(self):
        empty = self.log.range_search_receipt(b"a", b"z", 2, 2)
        data = encode_range_search_receipt(empty)
        # zero items, zero proof, zero hits
        self.assertTrue(data.endswith(u64(0) + u64(0) + u64(0)))
        snapshot = AuditLog().range_search_receipt(b"a", b"z")
        self.assertEqual(
            encode_range_search_receipt(snapshot),
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(0)
            + blob(snapshot.root)
            + blob(b"a")
            + blob(b"z")
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0),
        )

    def test_type_errors(self):
        for bad in (None, "receipt", b"bytes", 1, (1, 2)):
            with self.assertRaises(TypeError):
                encode_range_search_receipt(bad)

    def make_bypassed(self, **fields):
        receipt = self.log.range_search_receipt(b"a", b"d")
        forged = RangeSearchReceipt.__new__(RangeSearchReceipt)
        for name in (
            "version",
            "hash_name",
            "size",
            "root",
            "left",
            "right",
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
            encode_range_search_receipt(self.make_bypassed(version=2))
        with self.assertRaises(ValueError):
            encode_range_search_receipt(self.make_bypassed(stop=4))  # coverage broken
        with self.assertRaises(TypeError):
            encode_range_search_receipt(self.make_bypassed(left=123))
        with self.assertRaises(TypeError):
            encode_range_search_receipt(self.make_bypassed(items="not-a-tuple"))
        with self.assertRaises(TypeError):
            encode_range_search_receipt(self.make_bypassed(hits=[0]))

    def test_proof_node_count_checked(self):
        receipt = self.log.range_search_receipt(b"a", b"z", 1, 4)
        with self.assertRaises(ValueError):
            encode_range_search_receipt(
                self.make_bypassed(start=1, stop=4, items=receipt.items, proof=())
            )
        with self.assertRaises(ValueError):
            encode_range_search_receipt(
                self.make_bypassed(
                    start=1,
                    stop=4,
                    items=receipt.items,
                    proof=receipt.proof + (b"\x00" * 32,),
                )
            )


class DecodeRangeSearchReceiptTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log()

    def roundtrip(self, receipt):
        data = encode_range_search_receipt(receipt)
        decoded = decode_range_search_receipt(data)
        self.assertEqual(decoded, receipt)
        self.assertEqual(decoded.version, receipt.version)
        self.assertEqual(decoded.hash_name, receipt.hash_name)
        self.assertEqual(decoded.size, receipt.size)
        self.assertEqual(decoded.root, receipt.root)
        self.assertEqual(decoded.left, receipt.left)
        self.assertEqual(decoded.right, receipt.right)
        self.assertEqual((decoded.start, decoded.stop), (receipt.start, receipt.stop))
        self.assertEqual(decoded.items, receipt.items)
        self.assertEqual(decoded.proof, receipt.proof)
        self.assertEqual(decoded.hits, receipt.hits)
        # Re-encoding reproduces the original bytes exactly.
        self.assertEqual(encode_range_search_receipt(decoded), data)
        self.assertTrue(verify_range_search_receipt(decoded))
        return decoded

    def test_roundtrip_variants(self):
        self.roundtrip(self.log.range_search_receipt(b"a", b"d"))
        self.roundtrip(self.log.range_search_receipt(b"zz", b"zzz"))
        self.roundtrip(self.log.range_search_receipt(b"a", b"a"))
        self.roundtrip(self.log.range_search_receipt(b"a", b"z", 1, 4))
        self.roundtrip(self.log.range_search_receipt(b"a", b"z", size=3))
        self.roundtrip(self.log.range_search_receipt(b"a", b"z", 0, 3, size=3))

    def test_roundtrip_empty_range_and_empty_snapshot(self):
        self.roundtrip(self.log.range_search_receipt(b"a", b"z", 2, 2))
        self.roundtrip(AuditLog().range_search_receipt(b"a", b"z"))

    def test_roundtrip_unicode_bounds(self):
        self.log.append("位置主张")
        receipt = self.log.range_search_receipt("位置", "位置" + chr(0xFFFF))
        decoded = self.roundtrip(receipt)
        self.assertEqual(decoded.left, "位置".encode("utf-8"))

    def test_roundtrip_after_prune(self):
        self.log.append(b"x")
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.range_search_receipt(b"a", b"z"))
        self.roundtrip(self.log.range_search_receipt(b"b", b"z"))

    def test_roundtrip_alternate_hash(self):
        log = AuditLog(hash_name="sha3-256")
        for record in ("a", "b", "a"):
            log.append(record)
        self.roundtrip(log.range_search_receipt(b"a", b"c"))

    def test_forged_hits_roundtrip_but_fail_verification(self):
        # Same convention as FullEncryptedSearchReceipt: a structurally valid
        # receipt whose recorded hits disagree still round-trips; verification
        # reports False.
        receipt = self.log.range_search_receipt(b"a", b"c")
        tampered = RangeSearchReceipt(
            receipt.version,
            receipt.hash_name,
            receipt.size,
            receipt.root,
            receipt.left,
            receipt.right,
            receipt.start,
            receipt.stop,
            receipt.items,
            receipt.proof,
            (),  # all hits concealed
        )
        data = encode_range_search_receipt(tampered)
        decoded = decode_range_search_receipt(data)
        self.assertEqual(decoded, tampered)
        self.assertEqual(encode_range_search_receipt(decoded), data)
        self.assertFalse(verify_range_search_receipt(decoded))

    def test_only_bytes_accepted(self):
        data = encode_range_search_receipt(self.log.range_search_receipt(b"a", b"z"))
        for bad in (bytearray(data), memoryview(data), "text", None, 1):
            with self.assertRaises(TypeError):
                decode_range_search_receipt(bad)

    def test_bad_magic(self):
        data = encode_range_search_receipt(self.log.range_search_receipt(b"a", b"z"))
        with self.assertRaises(ValueError):
            decode_range_search_receipt(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_range_search_receipt(b"")
        with self.assertRaises(ValueError):
            decode_range_search_receipt(MAGIC[:-1])

    def test_bad_version(self):
        data = encode_range_search_receipt(self.log.range_search_receipt(b"a", b"z"))
        forged = MAGIC + u64(2) + data[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_range_search_receipt(forged)

    def test_unknown_hash_algorithm(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"not-a-hash")
            + u64(0)
            + blob(b"")
            + blob(b"")
            + blob(b"")
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_range_search_receipt(data)

    def test_invalid_utf8_hash_name(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"\xff\xfe")
            + u64(0)
            + blob(b"")
            + blob(b"")
            + blob(b"")
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_range_search_receipt(data)

    def test_truncation(self):
        data = encode_range_search_receipt(self.log.range_search_receipt(b"a", b"d"))
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_range_search_receipt(data[:cut])

    def test_trailing_bytes(self):
        data = encode_range_search_receipt(self.log.range_search_receipt(b"a", b"z"))
        with self.assertRaises(ValueError):
            decode_range_search_receipt(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_range_search_receipt(data)

    def test_digest_length_checked(self):
        data = (
            MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(5)
            + blob(b"\x00" * 31)
            + blob(b"a")
            + blob(b"z")
            + u64(0)
            + u64(5)
            + u64(0)
            + u64(0)
            + u64(0)
        )
        with self.assertRaises(ValueError):
            decode_range_search_receipt(data)

    def make_bypassed(self, items, proof, hits=(), size=6, start=0, stop=6):
        forged = RangeSearchReceipt.__new__(RangeSearchReceipt)
        for name, value in (
            ("version", 1),
            ("hash_name", "sha256"),
            ("size", size),
            ("root", self.log.merkle_root(size)),
            ("left", b"a"),
            ("right", b"z"),
            ("start", start),
            ("stop", stop),
            ("items", items),
            ("proof", proof),
            ("hits", hits),
        ):
            object.__setattr__(forged, name, value)
        return forged

    def test_index_order_duplicates_and_coverage(self):
        items = tuple(self.log.entry(i) for i in range(6))
        _, proof = self.log.batch_inclusion_proof((0, 1, 2, 3, 4, 5), 6)
        for bad_items in (
            (items[1], items[0]) + items[2:],
            (items[0], items[0]) + items[2:],
        ):
            with self.assertRaises(ValueError):
                decode_range_search_receipt(
                    encode_range_search_receipt(self.make_bypassed(bad_items, proof))
                )
        short = items[:5]
        _, short_proof = self.log.batch_inclusion_proof((0, 1, 2, 3, 4), 6)
        with self.assertRaises(ValueError):
            decode_range_search_receipt(
                encode_range_search_receipt(self.make_bypassed(short, short_proof))
            )

    def test_index_outside_recorded_range(self):
        items = tuple(self.log.entry(i) for i in range(6))
        _, proof = self.log.batch_inclusion_proof((0, 1, 2, 3, 4, 5), 6)
        with self.assertRaises(ValueError):
            decode_range_search_receipt(
                encode_range_search_receipt(self.make_bypassed(items, proof, stop=5))
            )

    def test_empty_range_with_non_empty_proof(self):
        with self.assertRaises(ValueError):
            decode_range_search_receipt(
                encode_range_search_receipt(
                    self.make_bypassed((), (b"\x00" * 32,), start=2, stop=2)
                )
            )

    def test_proof_structure_checked(self):
        receipt = self.log.range_search_receipt(b"a", b"z", 1, 4)
        for bad_proof in ((), receipt.proof + (b"\x00" * 32,)):
            with self.assertRaises(ValueError):
                decode_range_search_receipt(
                    encode_range_search_receipt(
                        self.make_bypassed(
                            receipt.items,
                            bad_proof,
                            hits=receipt.hits,
                            start=1,
                            stop=4,
                        )
                    )
                )

    def test_hit_structure_checked(self):
        items = tuple(self.log.entry(i) for i in range(6))
        _, proof = self.log.batch_inclusion_proof((0, 1, 2, 3, 4, 5), 6)
        for bad_hits in ((7,), (6,), (0, 0), (2, 1)):
            with self.assertRaises(ValueError, msg=bad_hits):
                decode_range_search_receipt(
                    encode_range_search_receipt(
                        self.make_bypassed(items, proof, hits=bad_hits)
                    )
                )


if __name__ == "__main__":
    unittest.main()
