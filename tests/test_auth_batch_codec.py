import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    Entry,
    decode_auth_batch,
    encode_auth_batch,
    verify_auth_batch,
)

MAGIC = b"auditchain/auth-batch/v1\0"
KEY = b"super-secret-key"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def raw_items(items):
    return [
        (
            entry.index,
            entry.payload,
            entry.previous_hash,
            entry.entry_hash,
            tag.stage,
            tag.tag,
        )
        for entry, tag in items
    ]


def build(hash_name, raw, version=1):
    """Hand-build an auth-batch encoding with arbitrary (possibly invalid) content."""
    name = hash_name.encode("utf-8") if isinstance(hash_name, str) else hash_name
    out = MAGIC + u64(version) + blob(name) + u64(len(raw))
    for index, payload, previous_hash, entry_hash, stage, tag in raw:
        out += (
            u64(index)
            + blob(payload)
            + blob(previous_hash)
            + blob(entry_hash)
            + u64(stage)
            + blob(tag)
        )
    return out


def make_log(n=5, key=KEY, hash_name="sha256"):
    log = AuditLog(key=key, hash_name=hash_name)
    for record in range(n):
        log.append(f"record-{record}")
    return log


class EncodeAuthBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(5)
        self.verifier = self.log.export_verifier()
        self.items = self.log.auth_batch([4, 0, 2])

    def test_magic_and_field_layout(self):
        data = encode_auth_batch(self.items)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(len(self.items)))  # item count
        offset += 8
        for entry, tag in self.items:
            self.assertEqual(data[offset:offset + 8], u64(entry.index))
            offset += 8
            for material in (entry.payload, entry.previous_hash, entry.entry_hash):
                self.assertEqual(data[offset:offset + 8], u64(len(material)))
                offset += 8 + len(material)
            self.assertEqual(data[offset:offset + 8], u64(tag.stage))
            offset += 8
            self.assertEqual(data[offset:offset + 8], u64(len(tag.tag)))
            offset += 8 + len(tag.tag)
        self.assertEqual(offset, len(data))

    def test_empty_batch_layout(self):
        data = encode_auth_batch(())
        self.assertEqual(
            data,
            MAGIC + u64(1) + blob(b"sha256") + u64(0),
        )

    def test_zero_length_payload_blob_is_all_zero_u64(self):
        self.log.append(b"")
        items = self.log.auth_batch([5])
        data = encode_auth_batch(items)
        _, decoded = decode_auth_batch(data)
        self.assertEqual(decoded[0][0].payload, b"")
        self.assertIn(u64(0), data)

    def test_encode_is_deterministic(self):
        self.assertEqual(
            encode_auth_batch(self.items), encode_auth_batch(self.items)
        )

    def test_encode_is_read_only(self):
        before = (self.log.stage, self.log.head, len(self.log))
        encode_auth_batch(self.items)
        self.assertEqual((self.log.stage, self.log.head, len(self.log)), before)

    def test_hash_name_keyword_selects_algorithm(self):
        log = make_log(3, hash_name="sha3-256")
        items = log.auth_batch([2, 0])
        data = encode_auth_batch(items, hash_name="sha3-256")
        offset = len(MAGIC) + 8
        self.assertEqual(data[offset:offset + 8], u64(8))
        self.assertEqual(data[offset + 8:offset + 16], b"sha3-256")

    def test_non_tuple_raises_type_error(self):
        for bad in (None, "items", b"bytes", 1, [self.items], object()):
            with self.assertRaises(TypeError):
                encode_auth_batch(bad)
        with self.assertRaises(TypeError):
            encode_auth_batch(list(self.items))
        # A bare pair is not a tuple of pairs.
        with self.assertRaises(TypeError):
            encode_auth_batch(self.items[0])

    def test_element_shape_errors(self):
        entry, tag = self.items[0]
        with self.assertRaises(TypeError):
            encode_auth_batch((entry,))
        with self.assertRaises(TypeError):
            encode_auth_batch(((entry, tag, None),))
        with self.assertRaises(TypeError):
            encode_auth_batch((("not-entry", tag),))
        with self.assertRaises(TypeError):
            encode_auth_batch(((entry, "not-tag"),))

    def test_hash_name_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_auth_batch(self.items, hash_name=b"sha256")
        with self.assertRaises(TypeError):
            encode_auth_batch((), hash_name=1)

    def test_entry_field_type_errors(self):
        entry, tag = self.items[0]
        with self.assertRaises(TypeError):
            encode_auth_batch(
                ((Entry(entry.index, "not-bytes", entry.previous_hash, entry.entry_hash), tag),)
            )

    def test_bytearray_entry_fields_accepted(self):
        entry, tag = self.items[0]
        copied = Entry(
            entry.index,
            bytearray(entry.payload),
            bytearray(entry.previous_hash),
            bytearray(entry.entry_hash),
        )
        data = encode_auth_batch(((copied, tag),))
        _, decoded = decode_auth_batch(data)
        self.assertEqual(decoded, ((entry, tag),))

    def test_structural_violations_raise_value_error(self):
        (e0, t0), (e2, t2), (_e4, t4) = self.items
        with self.assertRaises(ValueError):
            encode_auth_batch(self.items, hash_name="not-a-hash")
        with self.assertRaises(ValueError):
            encode_auth_batch(self.items, hash_name="shake_128")
        # sha256 material cannot be encoded under a different-width algorithm.
        with self.assertRaises(ValueError):
            encode_auth_batch(self.items, hash_name="sha512")
        with self.assertRaises(ValueError):
            encode_auth_batch(
                ((Entry(e0.index, e0.payload, b"\x00" * 31, e0.entry_hash), t0),)
            )
        with self.assertRaises(ValueError):
            encode_auth_batch(
                ((e0, AuthTag(t0.stage, t0.tag[:-1])),)
            )
        # Duplicate / unordered indices.
        with self.assertRaises(ValueError):
            encode_auth_batch(((e0, t0), (e0, t2)))
        with self.assertRaises(ValueError):
            encode_auth_batch(((e2, t0), (e0, t2)))
        # Non-consecutive stages.
        with self.assertRaises(ValueError):
            encode_auth_batch(((e0, t0), (e2, t4)))

    def test_out_of_u64_index_and_stage_via_bypass(self):
        entry, tag = self.items[0]
        bad_entry = Entry(entry.index, entry.payload, entry.previous_hash, entry.entry_hash)
        object.__setattr__(bad_entry, "index", 1 << 64)
        with self.assertRaises(ValueError):
            encode_auth_batch(((bad_entry, tag),))
        bad_tag = AuthTag(tag.stage, tag.tag)
        object.__setattr__(bad_tag, "stage", 1 << 64)
        with self.assertRaises(ValueError):
            encode_auth_batch(((entry, bad_tag),))


class DecodeAuthBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(5)
        self.verifier = self.log.export_verifier()

    def roundtrip(self, items, hash_name="sha256"):
        data = encode_auth_batch(items, hash_name=hash_name)
        decoded_name, decoded = decode_auth_batch(data)
        self.assertEqual(decoded_name, hash_name)
        self.assertIsInstance(decoded, tuple)
        self.assertEqual(decoded, items)
        # Every level is immutable: tuple items, frozen Entry/AuthTag.
        for entry, tag in decoded:
            self.assertIsInstance(entry, Entry)
            self.assertIsInstance(tag, AuthTag)
            self.assertIsInstance(entry.payload, bytes)
            self.assertIsInstance(tag.tag, bytes)
        # Deterministic: decoding and re-encoding reproduces the bytes.
        self.assertEqual(encode_auth_batch(decoded, hash_name=hash_name), data)
        if items:
            self.assertEqual(
                verify_auth_batch(decoded, self.verifier),
                tuple(True for _ in items),
            )
        else:
            self.assertEqual(verify_auth_batch(decoded, self.verifier), ())
        return decoded

    def test_roundtrip_variants(self):
        for indices in ([0], [3], [4, 0, 2], [0, 1, 2, 3, 4]):
            self.roundtrip(self.log.auth_batch(indices))

    def test_roundtrip_empty_batch(self):
        self.roundtrip(())

    def test_roundtrip_after_rotation(self):
        self.log.rotate_key()
        self.log.rotate_key()
        items = self.log.auth_batch([1, 3])
        self.assertEqual([tag.stage for _, tag in items], [2, 3])
        self.roundtrip(items)

    def test_roundtrip_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.auth_batch([2, 4]))

    def test_roundtrip_alternate_hash(self):
        log = make_log(3, hash_name="sha3-256")
        verifier = log.export_verifier()
        items = log.auth_batch([2, 0])
        data = encode_auth_batch(items, hash_name="sha3-256")
        decoded_name, decoded = decode_auth_batch(data)
        self.assertEqual(decoded_name, "sha3-256")
        self.assertEqual(decoded, items)
        self.assertEqual(verify_auth_batch(decoded, verifier), (True, True))

    def test_roundtrip_survives_file_like_transport(self):
        import io

        items = self.log.auth_batch([4, 1, 3])
        data = encode_auth_batch(items)
        buffer = io.BytesIO()
        buffer.write(data)
        _, restored = decode_auth_batch(buffer.getvalue())
        self.assertEqual(
            verify_auth_batch(restored, self.verifier), (True, True, True)
        )

    def test_only_bytes_accepted(self):
        data = encode_auth_batch(self.log.auth_batch([1]))
        for bad in (bytearray(data), memoryview(data), "text", None, 1, [data]):
            with self.assertRaises(TypeError):
                decode_auth_batch(bad)

    def test_bad_magic(self):
        data = encode_auth_batch(self.log.auth_batch([1]))
        with self.assertRaises(ValueError):
            decode_auth_batch(b"x" + data[1:])
        with self.assertRaises(ValueError):
            decode_auth_batch(b"")
        with self.assertRaises(ValueError):
            decode_auth_batch(MAGIC[:-1])

    def test_bad_version(self):
        items = self.log.auth_batch([1])
        data = MAGIC + u64(2) + encode_auth_batch(items)[len(MAGIC) + 8:]
        with self.assertRaises(ValueError):
            decode_auth_batch(data)

    def test_unknown_hash_algorithm(self):
        with self.assertRaises(ValueError):
            decode_auth_batch(build("not-a-hash", []))

    def test_non_fixed_output_algorithm(self):
        with self.assertRaises(ValueError):
            decode_auth_batch(build("shake_128", []))

    def test_invalid_utf8_hash_name(self):
        with self.assertRaises(ValueError):
            decode_auth_batch(build(b"\xff\xfe", []))

    def test_truncation(self):
        data = encode_auth_batch(self.log.auth_batch([1, 3]))
        for cut in range(len(MAGIC), len(data)):
            with self.assertRaises(ValueError):
                decode_auth_batch(data[:cut])

    def test_trailing_bytes(self):
        data = encode_auth_batch(self.log.auth_batch([1]))
        with self.assertRaises(ValueError):
            decode_auth_batch(data + b"\x00")

    def test_oversized_blob_length(self):
        data = MAGIC + u64(1) + u64(1 << 63) + b"sha256"
        with self.assertRaises(ValueError):
            decode_auth_batch(data)

    def test_item_count_exceeds_present_items(self):
        entry, tag = self.log.auth_batch([0])[0]
        data = build("sha256", raw_items([(entry, tag)]))
        body = data[len(MAGIC) + 8 + 8 + len(b"sha256"):]
        claimed_two = MAGIC + u64(1) + blob(b"sha256") + u64(2) + body
        with self.assertRaises(ValueError):
            decode_auth_batch(claimed_two)

    def test_digest_widths_checked(self):
        items = self.log.auth_batch([0, 2])
        (e0, t0), (e2, t2) = items
        bad_previous = raw_items(items)
        bad_previous[1] = (e2.index, e2.payload, b"\x00" * 31, e2.entry_hash, t2.stage, t2.tag)
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", bad_previous))
        bad_entry_hash = raw_items(items)
        bad_entry_hash[1] = (e2.index, e2.payload, e2.previous_hash, b"\x00" * 31, t2.stage, t2.tag)
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", bad_entry_hash))
        bad_tag = raw_items(items)
        bad_tag[1] = (e2.index, e2.payload, e2.previous_hash, e2.entry_hash, t2.stage, b"\x00" * 31)
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", bad_tag))

    def test_index_order_and_duplicates(self):
        items = self.log.auth_batch([0, 2])
        (e0, t0), (e2, t2) = items
        descending = [
            (e2.index, e2.payload, e2.previous_hash, e2.entry_hash, t0.stage, t0.tag),
            (e0.index, e0.payload, e0.previous_hash, e0.entry_hash, t2.stage, t2.tag),
        ]
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", descending))
        duplicated = raw_items([items[0]]) + raw_items(items)
        # Re-stage the duplicate so stages stay consecutive; indices still repeat.
        duplicated = [
            (index, payload, previous_hash, entry_hash, position, tag)
            for position, (index, payload, previous_hash, entry_hash, _stage, tag)
            in enumerate(duplicated)
        ]
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", duplicated))

    def test_non_consecutive_stages_rejected(self):
        items = self.log.auth_batch([0, 2, 4])
        (e0, t0), (_e2, _t2), (e4, t4) = items
        gapped = [
            (e0.index, e0.payload, e0.previous_hash, e0.entry_hash, t0.stage, t0.tag),
            (e4.index, e4.payload, e4.previous_hash, e4.entry_hash, t4.stage, t4.tag),
        ]
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", gapped))
        # Consecutive values but descending.
        descending_stages = [
            (e4.index, e4.payload, e4.previous_hash, e4.entry_hash, 0, t0.tag),
            (e0.index, e0.payload, e0.previous_hash, e0.entry_hash, 1, t4.tag),
        ]
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", descending_stages))

    def test_first_stage_need_not_be_zero(self):
        self.log.rotate_key()
        items = self.log.auth_batch([1, 3])
        self.assertEqual([tag.stage for _, tag in items], [1, 2])
        _, decoded = decode_auth_batch(encode_auth_batch(items))
        self.assertEqual(decoded, items)

    def test_content_mismatch_decodes_but_verifies_false(self):
        items = self.log.auth_batch([0, 2])
        (e0, t0), (e2, t2) = items
        forged = [
            (e0.index, e0.payload, e0.previous_hash, e0.entry_hash, t0.stage, t0.tag),
            (e2.index, b"tampered", e2.previous_hash, e2.entry_hash, t2.stage, t2.tag),
        ]
        decoded_name, decoded = decode_auth_batch(build("sha256", forged))
        self.assertEqual(decoded_name, "sha256")
        self.assertEqual(
            verify_auth_batch(decoded, self.verifier), (True, False)
        )

    def test_wrong_key_all_false_no_exception(self):
        items = self.log.auth_batch([0, 2])
        _, decoded = decode_auth_batch(encode_auth_batch(items))
        other = type(self.verifier)(
            key=b"a-completely-different-key", hash_name="sha256"
        )
        self.assertEqual(verify_auth_batch(decoded, other), (False, False))

    def test_encoding_carries_no_verifier_material(self):
        # The bytes contain the hash name and items but never the key itself.
        data = encode_auth_batch(self.log.auth_batch([0]))
        self.assertNotIn(KEY, data)


if __name__ == "__main__":
    unittest.main()
