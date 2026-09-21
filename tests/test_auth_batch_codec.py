import unittest

from auditchain import (
    AuditLog,
    AuthTag,
    Entry,
    Verifier,
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
        (entry.index, entry.payload, entry.previous_hash, entry.entry_hash,
         tag.stage, tag.tag)
        for entry, tag in items
    ]


def build(hash_name, items, version=1):
    """Hand-build an auth-batch encoding with arbitrary (possibly invalid) content."""
    if isinstance(hash_name, str):
        hash_name = hash_name.encode("utf-8")
    out = MAGIC + u64(version) + blob(hash_name) + u64(len(items))
    for index, payload, previous_hash, entry_hash, stage, tag in items:
        out += u64(index) + blob(payload) + blob(previous_hash) + blob(entry_hash)
        out += u64(stage) + blob(tag)
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

    def test_magic_and_field_layout(self):
        items = self.log.auth_batch([1, 3])
        data = encode_auth_batch(items)
        self.assertTrue(data.startswith(MAGIC))
        offset = len(MAGIC)
        self.assertEqual(data[offset:offset + 8], u64(1))  # version
        offset += 8
        self.assertEqual(data[offset:offset + 8], u64(6))  # hash_name length
        offset += 8
        self.assertEqual(data[offset:offset + 6], b"sha256")
        offset += 6
        self.assertEqual(data[offset:offset + 8], u64(2))  # items count
        offset += 8
        for entry, tag in items:
            self.assertEqual(data[offset:offset + 8], u64(entry.index))
            offset += 8
            for material in (entry.payload, entry.previous_hash, entry.entry_hash):
                self.assertEqual(data[offset:offset + 8], u64(len(material)))
                offset += 8
                self.assertEqual(data[offset:offset + len(material)], material)
                offset += len(material)
            self.assertEqual(data[offset:offset + 8], u64(tag.stage))
            offset += 8
            self.assertEqual(data[offset:offset + 8], u64(len(tag.tag)))
            offset += 8
            self.assertEqual(data[offset:offset + len(tag.tag)], tag.tag)
            offset += len(tag.tag)
        self.assertEqual(offset, len(data))

    def test_empty_batch_layout(self):
        data = encode_auth_batch(())
        self.assertEqual(data, MAGIC + u64(1) + blob(b"sha256") + u64(0))

    def test_default_hash_name_is_sha256(self):
        items = self.log.auth_batch([0])
        self.assertEqual(
            encode_auth_batch(items), encode_auth_batch(items, hash_name="sha256")
        )

    def test_zero_length_payload_blob_is_all_zero_u64(self):
        self.log.append(b"")
        items = self.log.auth_batch([5])
        data = encode_auth_batch(items)
        decoded_name, decoded_items = decode_auth_batch(data)
        self.assertEqual(decoded_items[-1][0].payload, b"")
        self.assertIn(u64(0), data)

    def test_encode_is_deterministic(self):
        items = self.log.auth_batch([0, 2, 3])
        self.assertEqual(encode_auth_batch(items), encode_auth_batch(items))

    def test_encoding_is_read_only(self):
        items = self.log.auth_batch([1, 3])
        before = (self.log.stage, len(self.log), self.log.head)
        encode_auth_batch(items)
        self.assertEqual((self.log.stage, len(self.log), self.log.head), before)

    def test_items_must_be_tuple(self):
        items = self.log.auth_batch([1])
        for bad in (None, "items", b"bytes", 1, list(items), iter(items), object()):
            with self.assertRaises(TypeError):
                encode_auth_batch(bad)

    def test_element_shape_errors(self):
        entry, tag = self.log.auth_batch([1])[0]
        with self.assertRaises(TypeError):
            encode_auth_batch((entry,))
        with self.assertRaises(TypeError):
            encode_auth_batch(((entry, tag, None),))
        with self.assertRaises(TypeError):
            encode_auth_batch((("not-entry", tag),))
        with self.assertRaises(TypeError):
            encode_auth_batch(((entry, "not-tag"),))
        with self.assertRaises(TypeError):
            encode_auth_batch(([entry, tag],))

    def test_hash_name_type_and_algorithm_errors(self):
        items = self.log.auth_batch([0])
        for bad in (None, 1, b"sha256"):
            with self.assertRaises(TypeError):
                encode_auth_batch(items, hash_name=bad)
        with self.assertRaises(ValueError):
            encode_auth_batch(items, hash_name="not-a-hash")
        with self.assertRaises(ValueError):
            encode_auth_batch(items, hash_name="shake_128")

    def test_entry_field_type_errors(self):
        entry, tag = self.log.auth_batch([1])[0]
        with self.assertRaises(TypeError):
            encode_auth_batch(
                ((Entry("0", entry.payload, entry.previous_hash, entry.entry_hash), tag),)
            )
        with self.assertRaises(TypeError):
            encode_auth_batch(
                ((Entry(True, entry.payload, entry.previous_hash, entry.entry_hash), tag),)
            )
        with self.assertRaises(TypeError):
            encode_auth_batch(
                ((Entry(entry.index, "not-bytes", entry.previous_hash, entry.entry_hash), tag),)
            )

    def test_bytearray_entry_fields_accepted(self):
        entry, tag = self.log.auth_batch([1])[0]
        copied = Entry(
            entry.index,
            bytearray(entry.payload),
            bytearray(entry.previous_hash),
            bytearray(entry.entry_hash),
        )
        data = encode_auth_batch(((copied, tag),))
        self.assertEqual(decode_auth_batch(data)[1], ((entry, tag),))

    def test_tag_field_type_errors(self):
        entry, tag = self.log.auth_batch([1])[0]
        tampered = AuthTag(tag.stage, tag.tag)
        object.__setattr__(tampered, "stage", True)
        with self.assertRaises(TypeError):
            encode_auth_batch(((entry, tampered),))
        object.__setattr__(tampered, "stage", "0")
        with self.assertRaises(TypeError):
            encode_auth_batch(((entry, tampered),))
        object.__setattr__(tampered, "stage", tag.stage)
        object.__setattr__(tampered, "tag", bytearray(tag.tag))
        with self.assertRaises(TypeError):
            encode_auth_batch(((entry, tampered),))

    def test_structural_violations_raise_value_error(self):
        (e0, t0), (e2, t2) = self.log.auth_batch([0, 2])
        # Out-of-range index / stage.
        with self.assertRaises(ValueError):
            encode_auth_batch(
                ((Entry(-1, e0.payload, e0.previous_hash, e0.entry_hash), t0),)
            )
        with self.assertRaises(ValueError):
            encode_auth_batch(
                ((Entry(1 << 64, e0.payload, e0.previous_hash, e0.entry_hash), t0),)
            )
        tampered = AuthTag(0, t0.tag)
        object.__setattr__(tampered, "stage", -1)
        with self.assertRaises(ValueError):
            encode_auth_batch(((e0, tampered),))
        object.__setattr__(tampered, "stage", 1 << 64)
        with self.assertRaises(ValueError):
            encode_auth_batch(((e0, tampered),))
        # Duplicate and descending indices.
        with self.assertRaises(ValueError):
            encode_auth_batch(((e0, t0), (e0, t2)))
        with self.assertRaises(ValueError):
            encode_auth_batch(((e2, t0), (e0, t2)))
        # Non-consecutive stages.
        with self.assertRaises(ValueError):
            encode_auth_batch(((e0, t0), (e2, AuthTag(t2.stage + 1, t2.tag))))
        # Wrong digest widths.
        with self.assertRaises(ValueError):
            encode_auth_batch(
                ((Entry(e0.index, e0.payload, b"\x00" * 31, e0.entry_hash), t0),)
            )
        with self.assertRaises(ValueError):
            encode_auth_batch(
                ((Entry(e0.index, e0.payload, e0.previous_hash, b"\x00" * 31), t0),)
            )
        with self.assertRaises(ValueError):
            encode_auth_batch(((e0, AuthTag(t0.stage, t0.tag[:-1])),))

    def test_mismatched_hash_name_width_rejected(self):
        # A sha256-minted batch does not fit the sha512 digest width.
        items = self.log.auth_batch([0])
        with self.assertRaises(ValueError):
            encode_auth_batch(items, hash_name="sha512")


class DecodeAuthBatchTest(unittest.TestCase):
    def setUp(self):
        self.log = make_log(5)
        self.verifier = self.log.export_verifier()

    def roundtrip(self, items, hash_name="sha256"):
        data = encode_auth_batch(items, hash_name=hash_name)
        decoded_name, decoded_items = decode_auth_batch(data)
        self.assertEqual(decoded_name, hash_name)
        self.assertIsInstance(decoded_items, tuple)
        self.assertEqual(decoded_items, items)
        for entry, tag in decoded_items:
            self.assertIsInstance(entry, Entry)
            self.assertIsInstance(tag, AuthTag)
        # Deterministic: decoding and re-encoding reproduces the bytes.
        self.assertEqual(encode_auth_batch(decoded_items, hash_name=decoded_name), data)
        verifier = Verifier(key=KEY, hash_name=hash_name)
        self.assertEqual(
            verify_auth_batch(decoded_items, verifier), (True,) * len(items)
        )
        return decoded_items

    def test_roundtrip_variants(self):
        self.roundtrip(self.log.auth_batch([0]))
        self.roundtrip(self.log.auth_batch([1, 3]))
        self.roundtrip(self.log.auth_batch([0, 2, 4]))
        self.roundtrip(self.log.auth_batch(()))

    def test_roundtrip_after_rotation(self):
        self.log.rotate_key()
        self.log.rotate_key()
        self.roundtrip(self.log.auth_batch([1, 3]))

    def test_roundtrip_after_prune(self):
        self.log.prune(2, self.log.seal(2))
        self.roundtrip(self.log.auth_batch([2, 4]))

    def test_roundtrip_alternate_hash(self):
        log = make_log(3, hash_name="sha3-256")
        log.export_verifier()
        self.roundtrip(log.auth_batch([0, 2]), hash_name="sha3-256")

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
            decode_auth_batch(build(b"not-a-hash", []))

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

    def test_declared_count_drives_parsing(self):
        # One fewer item than declared: truncation; one more: trailing bytes.
        items = self.log.auth_batch([1, 3])
        data = encode_auth_batch(items)
        raw = raw_items(items)
        short = build("sha256", raw[:1])
        # Patch the declared count up to 2 while only one item follows.
        patched = short[:len(MAGIC) + 8] + u64(6) + b"sha256" + u64(2) \
            + short[len(MAGIC) + 8 + 8 + 6 + 8:]
        with self.assertRaises(ValueError):
            decode_auth_batch(patched)
        with self.assertRaises(ValueError):
            decode_auth_batch(data + build("sha256", [])[len(MAGIC):])

    def test_digest_widths_checked(self):
        items = self.log.auth_batch([1, 3])
        raw = raw_items(items)
        index, payload, previous_hash, entry_hash, stage, tag = raw[0]
        with self.assertRaises(ValueError):
            decode_auth_batch(
                build("sha256", [(index, payload, b"\x00" * 31, entry_hash, stage, tag)] + raw[1:])
            )
        with self.assertRaises(ValueError):
            decode_auth_batch(
                build("sha256", [(index, payload, previous_hash, b"\x00" * 31, stage, tag)] + raw[1:])
            )
        with self.assertRaises(ValueError):
            decode_auth_batch(
                build("sha256", [(index, payload, previous_hash, entry_hash, stage, b"\x00" * 31)] + raw[1:])
            )

    def test_index_order_and_duplicates(self):
        items = self.log.auth_batch([1, 3])
        raw = raw_items(items)
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", [raw[1], raw[0]]))
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", [raw[0], raw[0]]))

    def test_stage_continuity_checked(self):
        items = self.log.auth_batch([1, 3])
        raw = raw_items(items)
        skipped = [raw[0], raw[1][:4] + (raw[1][4] + 1, raw[1][5])]
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", skipped))
        descending = [raw[0][:4] + (raw[1][4], raw[0][5]),
                      raw[1][:4] + (raw[0][4], raw[1][5])]
        with self.assertRaises(ValueError):
            decode_auth_batch(build("sha256", descending))

    def test_content_mismatch_decodes_but_verifies_false(self):
        items = self.log.auth_batch([0, 2, 4])
        raw = raw_items(items)
        forged = raw[1][:1] + (b"tampered",) + tuple(raw[1][2:])
        decoded_name, decoded_items = decode_auth_batch(
            build("sha256", [raw[0], forged, raw[2]])
        )
        self.assertEqual(decoded_name, "sha256")
        self.assertEqual(
            verify_auth_batch(decoded_items, self.verifier), (True, False, True)
        )

    def test_wrong_tag_decodes_but_verifies_false(self):
        items = self.log.auth_batch([0, 2, 4])
        raw = raw_items(items)
        bad_tag = raw[1][:5] + (b"\x00" * 32,)
        _, decoded_items = decode_auth_batch(build("sha256", [raw[0], bad_tag, raw[2]]))
        self.assertEqual(
            verify_auth_batch(decoded_items, self.verifier), (True, False, True)
        )

    def test_wrong_verifier_key_all_false_no_exception(self):
        items = self.log.auth_batch([1, 3])
        _, decoded_items = decode_auth_batch(encode_auth_batch(items))
        other = Verifier(key=b"a-completely-different-key", hash_name="sha256")
        self.assertEqual(verify_auth_batch(decoded_items, other), (False, False))


if __name__ == "__main__":
    unittest.main()
