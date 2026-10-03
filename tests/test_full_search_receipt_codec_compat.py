"""Regression tests for the shared full-search receipt codec internals.

The binary codecs of :class:`FullSearchReceipt`,
:class:`FullEncryptedSearchReceipt` and
:class:`FullEncryptedJsonSearchReceipt` were refactored to state their
common boundary rules (u64/blob framing, entry segment, shared proof
segment, hit segment, magic/version checks) exactly once. These tests pin
that the refactor preserved the external behavior:

- ``GOLDEN_SAMPLES`` are canonical bytes produced by the *pre-refactor*
  encoder; the current decoder must still accept them, restore equal
  frozen objects, re-encode them byte-for-byte and pass offline
  verification,
- the common boundary rules — input types, magic, version, truncation,
  trailing data, length prefixes, UTF-8 fields, digest widths, hit
  ordering — keep raising exactly TypeError or ValueError as documented,
- a structurally valid but tampered receipt still round-trips and only
  fails offline verification, and signed envelopes over these bytes keep
  verifying unchanged.
"""

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from auditchain import (
    AuditLog,
    Entry,
    FullEncryptedJsonSearchReceipt,
    FullEncryptedSearchReceipt,
    FullSearchReceipt,
    decode_full_encrypted_json_search_receipt,
    decode_full_encrypted_search_receipt,
    decode_full_search_receipt,
    decode_signed_full_encrypted_search_receipt,
    decode_signed_full_search_receipt,
    encode_full_encrypted_json_search_receipt,
    encode_full_encrypted_search_receipt,
    encode_full_search_receipt,
    encode_signed_full_encrypted_search_receipt,
    encode_signed_full_search_receipt,
    verify_full_encrypted_json_search_receipt,
    verify_full_encrypted_search_receipt,
    verify_full_search_receipt,
    verify_signed_full_encrypted_search_receipt,
    verify_signed_full_search_receipt,
)

KEY = bytes(range(32))
SEED = bytes(range(1, 33))

FULL_MAGIC = b"auditchain/full-search/v1\0"
ENC_MAGIC = b"auditchain/full-encrypted-search/v1\0"
JSON_MAGIC = b"auditchain/full-encrypted-json-search/v1\0"


def u64(value):
    return value.to_bytes(8, "big")


def blob(material):
    return u64(len(material)) + material


def public_key(seed):
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


# Canonical bytes produced by the pre-refactor encoders; every sample must
# keep decoding, re-encoding byte-for-byte and verifying offline.
GOLDEN_SAMPLES = {
    "full_basic": (
        "6175646974636861696e2f66756c6c2d7365617263682f76310000000000000000010000000000000006736861323536"
        "00000000000000050000000000000020a9618728554dbe2826bee1b91af3cfa198621fd4785dc370cc82de62a7f07adf"
        "000000000000000161000000000000000100000000000000040000000000000003000000000000000100000000000000"
        "016200000000000000205ab2112582a9ad845515b0f22c9ea144444425016f4ff46c33e6e4771c409fda000000000000"
        "00205e300f4d8c7b335396a1ed609ad4441552b6a60aa79e17ee07ea9ca18a80372d0000000000000002000000000000"
        "00016100000000000000205e300f4d8c7b335396a1ed609ad4441552b6a60aa79e17ee07ea9ca18a80372d0000000000"
        "00002085a7bb3b3b9118403cfba32d9f407003e9117a61ca6b80c89ebb00fc1ec506cb00000000000000030000000000"
        "00000163000000000000002085a7bb3b3b9118403cfba32d9f407003e9117a61ca6b80c89ebb00fc1ec506cb00000000"
        "000000203f8ce946d96b3859414f38d1b0298feb0b64d0b49a6090c0e6c71f9b8b2cb587000000000000000200000000"
        "000000202256484a6e27f12b1f373e0fba60f860222f2cb6870568e78f2ab09ef5d55d4d00000000000000205bf29bac"
        "7104c9263d546413f04b851ede584553f10f0a139409fdb62cc6ed54"
    ),
    "full_empty_snapshot": (
        "6175646974636861696e2f66756c6c2d7365617263682f76310000000000000000010000000000000006736861323536"
        "000000000000000000000000000000202f06f3b99dbe2c86209cdf6eaecd7c00ab3249873c1d311dfd3ce9dbd1be35b7"
        "0000000000000001610000000000000000000000000000000000000000000000000000000000000000"
    ),
    "full_empty_range": (
        "6175646974636861696e2f66756c6c2d7365617263682f76310000000000000000010000000000000006736861323536"
        "00000000000000050000000000000020a9618728554dbe2826bee1b91af3cfa198621fd4785dc370cc82de62a7f07adf"
        "0000000000000001610000000000000002000000000000000200000000000000000000000000000000"
    ),
    "full_pruned": (
        "6175646974636861696e2f66756c6c2d7365617263682f76310000000000000000010000000000000006736861323536"
        "000000000000000600000000000000203ff01d7cbe4d94db8209c474c9a508e733b289ffd016b6868545098e2d25ea97"
        "000000000000000161000000000000000200000000000000060000000000000004000000000000000200000000000000"
        "016200000000000000209f30ea86517aae293b427a2111cf1cc5ab97c727259022019fb14819e28394c3000000000000"
        "0020a14833abeae05bac072ded05f0ec5c86cbbdeea57b4f8c95bf6abf9380e5704c0000000000000003000000000000"
        "0001610000000000000020a14833abeae05bac072ded05f0ec5c86cbbdeea57b4f8c95bf6abf9380e5704c0000000000"
        "000020c908dc4f5df4b5e30f7a3366c6a3a49a8e56fb6354cb737710d3289fa7bd30f200000000000000040000000000"
        "000001630000000000000020c908dc4f5df4b5e30f7a3366c6a3a49a8e56fb6354cb737710d3289fa7bd30f200000000"
        "000000204fc914341fedef67711246f45d06cd35ffddce2039e2e75f70ac216c510bfb1f000000000000000500000000"
        "000000016100000000000000204fc914341fedef67711246f45d06cd35ffddce2039e2e75f70ac216c510bfb1f000000"
        "000000002038ab548f4dd26c2462b319299b72fa35f8a6fab2e4ecc3d0fad0ef8419c0c2170000000000000001000000"
        "0000000020e7fe3051829d1bcc62f37f7378a553fa4e30a530009116c983cb295aa6c74a70"
    ),
    "full_sha512": (
        "6175646974636861696e2f66756c6c2d7365617263682f76310000000000000000010000000000000006736861353132"
        "00000000000000030000000000000040b4051a90903bf37e2c7dbdfa1af1c8b7d932044302068793f66d89d886c4aa21"
        "d80bd5b8892ee191ef44ef8249303ed30fb0abf787174cf4a5be21d4c9a9481600000000000000016100000000000000"
        "000000000000000003000000000000000300000000000000000000000000000001610000000000000040000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000040a361b4cbc6d69834a8b45cf13b294a0158cbd1f3763d22befd4a44603161"
        "f79190d5f1f31dc9f93fe3f61a1844448887c82f04f63eb854516bf592acfed28a060000000000000001000000000000"
        "0001620000000000000040a361b4cbc6d69834a8b45cf13b294a0158cbd1f3763d22befd4a44603161f79190d5f1f31d"
        "c9f93fe3f61a1844448887c82f04f63eb854516bf592acfed28a0600000000000000407ef891692d2801e4046ff1d33c"
        "dd61304c28cf008fc56c4e6a7995845eb829a31c55895742841ba7de98b5eb5b4ebe85d59a9e48138adbd50e64538c47"
        "92d5ca000000000000000200000000000000016100000000000000407ef891692d2801e4046ff1d33cdd61304c28cf00"
        "8fc56c4e6a7995845eb829a31c55895742841ba7de98b5eb5b4ebe85d59a9e48138adbd50e64538c4792d5ca00000000"
        "00000040879fb165ae52ed0f57861323274cd168727f3d331b73c3d603625a788b7304a1be02d0e1b4ae4b3addba1ea2"
        "6f01283afe61cc36aba38705e0e8d53f5999616f0000000000000000"
    ),
    "enc_basic": (
        "6175646974636861696e2f66756c6c2d656e637279707465642d7365617263682f763100000000000000000100000000"
        "000000067368613235360000000000000005000000000000002047ae505c86b0459e053e47324dd4edc68cbafe83cf70"
        "7d74272b3a8ef523ed6a0000000000000001610000000000000000000000000000000500000000000000050000000000"
        "000000000000000000003c6175646974636861696e2f656e637279707465642d656e7472792f76310001000000000000"
        "0000000000006fcd28fdd3ab4e2e2b30511c6ad2a9e1a100000000000000200000000000000000000000000000000000"
        "000000000000000000000000000000000000000000002077444299c4821f61415773e704338d817b221c074c99fbc9b8"
        "7c5c22d81200d30000000000000001000000000000000162000000000000002077444299c4821f61415773e704338d81"
        "7b221c074c99fbc9b87c5c22d81200d300000000000000208d50c90a57dfb3c32073cdb3c18793597d7076ace278a657"
        "58e2972cf6919bfe0000000000000002000000000000003c6175646974636861696e2f656e637279707465642d656e74"
        "72792f76310001020202020202020202020202fa9667c5b00397c4f5fa5712a0dc3b70a100000000000000208d50c90a"
        "57dfb3c32073cdb3c18793597d7076ace278a65758e2972cf6919bfe00000000000000205936fa82a04cd9fad4b4b6b6"
        "7f9bcd19b1d5ac601c5d550760daf5d321e9783f0000000000000003000000000000003c6175646974636861696e2f65"
        "6e637279707465642d656e7472792f763100010303030303030303030303038dcb0510e248b83f13fca7ff2fb2ad950a"
        "00000000000000205936fa82a04cd9fad4b4b6b67f9bcd19b1d5ac601c5d550760daf5d321e9783f0000000000000020"
        "3e6208db406dacd986c794c1508148f799aeeefb18ae38f3618b2a9c6db4c5af0000000000000004000000000000003c"
        "6175646974636861696e2f656e637279707465642d656e7472792f76310001040404040404040404040404057109f494"
        "7df0eb178283bee82de72d7700000000000000203e6208db406dacd986c794c1508148f799aeeefb18ae38f3618b2a9c"
        "6db4c5af00000000000000206ad6743e406d8410851bf2bd10c1b3c78c456203861e7262724316c6158477ee00000000"
        "000000000000000000000003000000000000000000000000000000020000000000000004"
    ),
    "enc_empty_range": (
        "6175646974636861696e2f66756c6c2d656e637279707465642d7365617263682f763100000000000000000100000000"
        "000000067368613235360000000000000005000000000000002047ae505c86b0459e053e47324dd4edc68cbafe83cf70"
        "7d74272b3a8ef523ed6a0000000000000001610000000000000002000000000000000200000000000000000000000000"
        "0000000000000000000000"
    ),
    "enc_sha512": (
        "6175646974636861696e2f66756c6c2d656e637279707465642d7365617263682f763100000000000000000100000000"
        "000000067368613531320000000000000003000000000000004099c3873407aabd7ea3cb8503abba6ec2891c21270ad2"
        "2b7805ff358c71b78cfb07b25d2128aab9e6efb114d107475ff4ec99e28e1df2bbad1d4dc50f281c459a000000000000"
        "0001610000000000000000000000000000000300000000000000030000000000000000000000000000003c6175646974"
        "636861696e2f656e637279707465642d656e7472792f763100010000000000000000000000006fcc9b7b5e0dec713e9f"
        "5497ff4b2cd5640000000000000040000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000040ce13e86a7d0b3b2918"
        "da8982b4b3faccd05ad2b4bcccc1fe58b6a47a66329c65abc45d39042416b013499f865f5a8a20791ee2a2a19fe3f2c9"
        "9ec21e27cd32830000000000000001000000000000003c6175646974636861696e2f656e637279707465642d656e7472"
        "792f7631000101010101010101010101010115f343e15daa52d50d6ab560e6df406de10000000000000040ce13e86a7d"
        "0b3b2918da8982b4b3faccd05ad2b4bcccc1fe58b6a47a66329c65abc45d39042416b013499f865f5a8a20791ee2a2a1"
        "9fe3f2c99ec21e27cd328300000000000000403bd6697dbda413a328ba020b1d88a3d34692dbf0f2d2de6c46ebcd21dd"
        "b6db7e9e4a9df716514f24b04b1e54cc1f405caecadf30664e826e2f53e6562fd6280d00000000000000020000000000"
        "00003c6175646974636861696e2f656e637279707465642d656e7472792f76310001020202020202020202020202fad3"
        "3783c68db1539d0c9d3b5505987f2800000000000000403bd6697dbda413a328ba020b1d88a3d34692dbf0f2d2de6c46"
        "ebcd21ddb6db7e9e4a9df716514f24b04b1e54cc1f405caecadf30664e826e2f53e6562fd6280d0000000000000040e3"
        "a8fa9fa1f9f189e963f2ad9e1a06b4191640a767c5041005209ea280f231ede9c4e579f99f88222ac9074773f51ee255"
        "5236c426c9f11fe48fb1954bbc45830000000000000000000000000000000200000000000000000000000000000002"
    ),
    "json_int": (
        "6175646974636861696e2f66756c6c2d656e637279707465642d6a736f6e2d7365617263682f76310000000000000000"
        "01000000000000000673686132353600000000000000060000000000000020db1f8495dbb31582b49afa5f9c281705b5"
        "85b9f66ebce2db01eda3b65b69e23e00000000000000022f610000000000000001000000000000000131000000000000"
        "000000000000000000060000000000000006000000000000000000000000000000426175646974636861696e2f656e63"
        "7279707465642d656e7472792f763100013030303030303030303030309223b16be87baabe3fc900540accab6b584814"
        "aa322dd40000000000000020000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000020099df89206b147ed37772806c265916657bcb0ba7664617c617bef4b2269d45b000000000000000100000000"
        "000000446175646974636861696e2f656e637279707465642d656e7472792f763100013131313131313131313131315c"
        "5d49a09dea291cad2bc31b0331f463c7f2cd66d0919f7cd90000000000000020099df89206b147ed37772806c2659166"
        "57bcb0ba7664617c617bef4b2269d45b0000000000000020394516382359fc645d6f3266382c14ef51b940c1bc2c6cbd"
        "f49d645084fc47c5000000000000000200000000000000446175646974636861696e2f656e637279707465642d656e74"
        "72792f763100013232323232323232323232321c023c3b172e22f257f8a02c8060eea66b64daca6c1a2859a000000000"
        "00000020394516382359fc645d6f3266382c14ef51b940c1bc2c6cbdf49d645084fc47c50000000000000020b852ce00"
        "eeeed73b1fb63180e2894e052720b8a10302d99bde6eec1062110267000000000000000300000000000000077b226122"
        "3a317d0000000000000020b852ce00eeeed73b1fb63180e2894e052720b8a10302d99bde6eec10621102670000000000"
        "000020780d89e8441f0df0efb2cb689ec5f1fb97a19dcf186dacae98679f6824f522b700000000000000040000000000"
        "00003f6175646974636861696e2f656e637279707465642d656e7472792f763100013333333333333333333333333e72"
        "e18e38501ed97cf5f88986d8c78e45c007f30000000000000020780d89e8441f0df0efb2cb689ec5f1fb97a19dcf186d"
        "acae98679f6824f522b70000000000000020a206bdf9ca0a276fb99de95343c9bf3a6bf160013637c6a93835becb5fcc"
        "cf93000000000000000500000000000000426175646974636861696e2f656e637279707465642d656e7472792f763100"
        "0134343434343434343434343412df85a6dca69357b7177310725ca35bb39acbd2dc22990000000000000020a206bdf9"
        "ca0a276fb99de95343c9bf3a6bf160013637c6a93835becb5fcccf9300000000000000200a7569b32d7071818b25f547"
        "c13c11dfe914bf20af45c754699014d5ddef79f000000000000000000000000000000002000000000000000000000000"
        "000000010000000000000020442d6a3ab8af2379f254c7826dae4485cafa94b75d67df7cb893f5b869a0efea"
    ),
    "json_string": (
        "6175646974636861696e2f66756c6c2d656e637279707465642d6a736f6e2d7365617263682f76310000000000000000"
        "01000000000000000673686132353600000000000000060000000000000020db1f8495dbb31582b49afa5f9c281705b5"
        "85b9f66ebce2db01eda3b65b69e23e00000000000000022f610000000000000000000000000000000131000000000000"
        "000000000000000000060000000000000006000000000000000000000000000000426175646974636861696e2f656e63"
        "7279707465642d656e7472792f763100013030303030303030303030309223b16be87baabe3fc900540accab6b584814"
        "aa322dd40000000000000020000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000020099df89206b147ed37772806c265916657bcb0ba7664617c617bef4b2269d45b000000000000000100000000"
        "000000446175646974636861696e2f656e637279707465642d656e7472792f763100013131313131313131313131315c"
        "5d49a09dea291cad2bc31b0331f463c7f2cd66d0919f7cd90000000000000020099df89206b147ed37772806c2659166"
        "57bcb0ba7664617c617bef4b2269d45b0000000000000020394516382359fc645d6f3266382c14ef51b940c1bc2c6cbd"
        "f49d645084fc47c5000000000000000200000000000000446175646974636861696e2f656e637279707465642d656e74"
        "72792f763100013232323232323232323232321c023c3b172e22f257f8a02c8060eea66b64daca6c1a2859a000000000"
        "00000020394516382359fc645d6f3266382c14ef51b940c1bc2c6cbdf49d645084fc47c50000000000000020b852ce00"
        "eeeed73b1fb63180e2894e052720b8a10302d99bde6eec1062110267000000000000000300000000000000077b226122"
        "3a317d0000000000000020b852ce00eeeed73b1fb63180e2894e052720b8a10302d99bde6eec10621102670000000000"
        "000020780d89e8441f0df0efb2cb689ec5f1fb97a19dcf186dacae98679f6824f522b700000000000000040000000000"
        "00003f6175646974636861696e2f656e637279707465642d656e7472792f763100013333333333333333333333333e72"
        "e18e38501ed97cf5f88986d8c78e45c007f30000000000000020780d89e8441f0df0efb2cb689ec5f1fb97a19dcf186d"
        "acae98679f6824f522b70000000000000020a206bdf9ca0a276fb99de95343c9bf3a6bf160013637c6a93835becb5fcc"
        "cf93000000000000000500000000000000426175646974636861696e2f656e637279707465642d656e7472792f763100"
        "0134343434343434343434343412df85a6dca69357b7177310725ca35bb39acbd2dc22990000000000000020a206bdf9"
        "ca0a276fb99de95343c9bf3a6bf160013637c6a93835becb5fcccf9300000000000000200a7569b32d7071818b25f547"
        "c13c11dfe914bf20af45c754699014d5ddef79f000000000000000000000000000000001000000000000000200000000"
        "00000020f643440fbbfa1e3164e8404a3b44a4e4eee4d766837c156c4aac00f74ea7582e"
    ),
    "json_float": (
        "6175646974636861696e2f66756c6c2d656e637279707465642d6a736f6e2d7365617263682f76310000000000000000"
        "01000000000000000673686132353600000000000000060000000000000020db1f8495dbb31582b49afa5f9c281705b5"
        "85b9f66ebce2db01eda3b65b69e23e00000000000000022f6100000000000000020000000000000003312e3000000000"
        "0000000000000000000000060000000000000006000000000000000000000000000000426175646974636861696e2f65"
        "6e637279707465642d656e7472792f763100013030303030303030303030309223b16be87baabe3fc900540accab6b58"
        "4814aa322dd4000000000000002000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000020099df89206b147ed37772806c265916657bcb0ba7664617c617bef4b2269d45b00000000000000010000"
        "0000000000446175646974636861696e2f656e637279707465642d656e7472792f763100013131313131313131313131"
        "315c5d49a09dea291cad2bc31b0331f463c7f2cd66d0919f7cd90000000000000020099df89206b147ed37772806c265"
        "916657bcb0ba7664617c617bef4b2269d45b0000000000000020394516382359fc645d6f3266382c14ef51b940c1bc2c"
        "6cbdf49d645084fc47c5000000000000000200000000000000446175646974636861696e2f656e637279707465642d65"
        "6e7472792f763100013232323232323232323232321c023c3b172e22f257f8a02c8060eea66b64daca6c1a2859a00000"
        "000000000020394516382359fc645d6f3266382c14ef51b940c1bc2c6cbdf49d645084fc47c50000000000000020b852"
        "ce00eeeed73b1fb63180e2894e052720b8a10302d99bde6eec1062110267000000000000000300000000000000077b22"
        "61223a317d0000000000000020b852ce00eeeed73b1fb63180e2894e052720b8a10302d99bde6eec1062110267000000"
        "0000000020780d89e8441f0df0efb2cb689ec5f1fb97a19dcf186dacae98679f6824f522b70000000000000004000000"
        "000000003f6175646974636861696e2f656e637279707465642d656e7472792f76310001333333333333333333333333"
        "3e72e18e38501ed97cf5f88986d8c78e45c007f30000000000000020780d89e8441f0df0efb2cb689ec5f1fb97a19dcf"
        "186dacae98679f6824f522b70000000000000020a206bdf9ca0a276fb99de95343c9bf3a6bf160013637c6a93835becb"
        "5fcccf93000000000000000500000000000000426175646974636861696e2f656e637279707465642d656e7472792f76"
        "31000134343434343434343434343412df85a6dca69357b7177310725ca35bb39acbd2dc22990000000000000020a206"
        "bdf9ca0a276fb99de95343c9bf3a6bf160013637c6a93835becb5fcccf9300000000000000200a7569b32d7071818b25"
        "f547c13c11dfe914bf20af45c754699014d5ddef79f00000000000000000000000000000000200000000000000000000"
        "00000000000100000000000000208d4856c9694f74305ae4722eadda21f95d6d0ac654328ac8c9e25c9c6d2c1bd4"
    ),
    "json_null": (
        "6175646974636861696e2f66756c6c2d656e637279707465642d6a736f6e2d7365617263682f76310000000000000000"
        "01000000000000000673686132353600000000000000060000000000000020db1f8495dbb31582b49afa5f9c281705b5"
        "85b9f66ebce2db01eda3b65b69e23e00000000000000022f610000000000000004000000000000000000000000000000"
        "0000000000000000060000000000000006000000000000000000000000000000426175646974636861696e2f656e6372"
        "79707465642d656e7472792f763100013030303030303030303030309223b16be87baabe3fc900540accab6b584814aa"
        "322dd4000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000020099df89206b147ed37772806c265916657bcb0ba7664617c617bef4b2269d45b00000000000000010000000000"
        "0000446175646974636861696e2f656e637279707465642d656e7472792f763100013131313131313131313131315c5d"
        "49a09dea291cad2bc31b0331f463c7f2cd66d0919f7cd90000000000000020099df89206b147ed37772806c265916657"
        "bcb0ba7664617c617bef4b2269d45b0000000000000020394516382359fc645d6f3266382c14ef51b940c1bc2c6cbdf4"
        "9d645084fc47c5000000000000000200000000000000446175646974636861696e2f656e637279707465642d656e7472"
        "792f763100013232323232323232323232321c023c3b172e22f257f8a02c8060eea66b64daca6c1a2859a00000000000"
        "000020394516382359fc645d6f3266382c14ef51b940c1bc2c6cbdf49d645084fc47c50000000000000020b852ce00ee"
        "eed73b1fb63180e2894e052720b8a10302d99bde6eec1062110267000000000000000300000000000000077b2261223a"
        "317d0000000000000020b852ce00eeeed73b1fb63180e2894e052720b8a10302d99bde6eec1062110267000000000000"
        "0020780d89e8441f0df0efb2cb689ec5f1fb97a19dcf186dacae98679f6824f522b70000000000000004000000000000"
        "003f6175646974636861696e2f656e637279707465642d656e7472792f763100013333333333333333333333333e72e1"
        "8e38501ed97cf5f88986d8c78e45c007f30000000000000020780d89e8441f0df0efb2cb689ec5f1fb97a19dcf186dac"
        "ae98679f6824f522b70000000000000020a206bdf9ca0a276fb99de95343c9bf3a6bf160013637c6a93835becb5fcccf"
        "93000000000000000500000000000000426175646974636861696e2f656e637279707465642d656e7472792f76310001"
        "34343434343434343434343412df85a6dca69357b7177310725ca35bb39acbd2dc22990000000000000020a206bdf9ca"
        "0a276fb99de95343c9bf3a6bf160013637c6a93835becb5fcccf9300000000000000200a7569b32d7071818b25f547c1"
        "3c11dfe914bf20af45c754699014d5ddef79f0000000000000000000000000000000000000000000000020601069d1ad"
        "a24d3651d941eece4e1c7f6aa6a510b079a9d74ada5608f63db879"
    ),
    "json_true_sha512": (
        "6175646974636861696e2f66756c6c2d656e637279707465642d6a736f6e2d7365617263682f76310000000000000000"
        "01000000000000000673686135313200000000000000020000000000000040acafd137a6c695f5ba60899dbe5c301abf"
        "9261ad62897dc0c326b25f963e74617150639c8528a716802a0eff535985af3896a8e3f20aa6235497a0ebb037782200"
        "000000000000022f61000000000000000300000000000000000000000000000000000000000000000200000000000000"
        "02000000000000000000000000000000456175646974636861696e2f656e637279707465642d656e7472792f76310001"
        "7474747474747474747474746b9efe31dcbb47fbfe0a93ae5be216f55b477516b5f40075745400000000000000400000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000402436155aa4321c3f1d51a8cbc8976d2d4745c05e2d6993ef8a76"
        "0b7704d90376816ff08467a842998422f178f7af9b6da6377f5dce97d33ab8baa5cb2354a9a600000000000000010000"
        "0000000000466175646974636861696e2f656e637279707465642d656e7472792f763100016666666666666666666666"
        "66abf3d4dc889dc5622ea9a7b8510e96fae841ef7859c8cb2d1eef2500000000000000402436155aa4321c3f1d51a8cb"
        "c8976d2d4745c05e2d6993ef8a760b7704d90376816ff08467a842998422f178f7af9b6da6377f5dce97d33ab8baa5cb"
        "2354a9a60000000000000040b2dfa52c325a68759c810861e6eb8d6372a07e6031a298fc060c94d3b4c4bd8202322737"
        "cd662f026c6febb49e65c1a558e98de60499f92ce04d915286e98cec0000000000000000000000000000000100000000"
        "000000000000000000000040c642d642b848ead05d4b8c6dbc63a00142f720ce03781cf7a036a82e0b3b9c56a89864d1"
        "cdca97bc66d44eef8a4076f8ee2106d4e38a1d7171a932e8c011dbeb"
    ),
    "json_false_sha512": (
        "6175646974636861696e2f66756c6c2d656e637279707465642d6a736f6e2d7365617263682f76310000000000000000"
        "01000000000000000673686135313200000000000000020000000000000040acafd137a6c695f5ba60899dbe5c301abf"
        "9261ad62897dc0c326b25f963e74617150639c8528a716802a0eff535985af3896a8e3f20aa6235497a0ebb037782200"
        "000000000000022f61000000000000000500000000000000000000000000000000000000000000000200000000000000"
        "02000000000000000000000000000000456175646974636861696e2f656e637279707465642d656e7472792f76310001"
        "7474747474747474747474746b9efe31dcbb47fbfe0a93ae5be216f55b477516b5f40075745400000000000000400000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000402436155aa4321c3f1d51a8cbc8976d2d4745c05e2d6993ef8a76"
        "0b7704d90376816ff08467a842998422f178f7af9b6da6377f5dce97d33ab8baa5cb2354a9a600000000000000010000"
        "0000000000466175646974636861696e2f656e637279707465642d656e7472792f763100016666666666666666666666"
        "66abf3d4dc889dc5622ea9a7b8510e96fae841ef7859c8cb2d1eef2500000000000000402436155aa4321c3f1d51a8cb"
        "c8976d2d4745c05e2d6993ef8a760b7704d90376816ff08467a842998422f178f7af9b6da6377f5dce97d33ab8baa5cb"
        "2354a9a60000000000000040b2dfa52c325a68759c810861e6eb8d6372a07e6031a298fc060c94d3b4c4bd8202322737"
        "cd662f026c6febb49e65c1a558e98de60499f92ce04d915286e98cec0000000000000000000000000000000100000000"
        "0000000100000000000000401a2ee550c4ed9ef8d409ee647ff973f77f04ade39d91e0d2af62911f94dbd73db23aa17e"
        "182b237d984705163640b5a190a20fa1fd8e4fa37ba1cd60e26d3e67"
    ),
}


def golden(name):
    return bytes.fromhex(GOLDEN_SAMPLES[name])


class GoldenFullSearchSampleTest(unittest.TestCase):
    """Pre-refactor FullSearchReceipt bytes stay accepted and stable."""

    def roundtrip(self, name):
        data = golden(name)
        receipt = decode_full_search_receipt(data)
        self.assertIsInstance(receipt, FullSearchReceipt)
        # Re-encoding the restored object reproduces the sample exactly.
        self.assertEqual(encode_full_search_receipt(receipt), data)
        # Decoding the re-encoding restores an equal frozen object.
        self.assertEqual(decode_full_search_receipt(encode_full_search_receipt(receipt)), receipt)
        self.assertTrue(verify_full_search_receipt(receipt))
        return receipt

    def test_basic_range(self):
        receipt = self.roundtrip("full_basic")
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.hash_name, "sha256")
        self.assertEqual(receipt.size, 5)
        self.assertEqual(receipt.query, b"a")
        self.assertEqual((receipt.start, receipt.stop), (1, 4))
        self.assertEqual(tuple(entry.index for entry in receipt.items), (1, 2, 3))
        self.assertEqual(len(receipt.proof), 2)
        self.assertTrue(all(len(node) == 32 for node in receipt.proof))

    def test_empty_snapshot(self):
        receipt = self.roundtrip("full_empty_snapshot")
        self.assertEqual(receipt.size, 0)
        self.assertEqual((receipt.start, receipt.stop), (0, 0))
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())

    def test_empty_range(self):
        receipt = self.roundtrip("full_empty_range")
        self.assertEqual(receipt.size, 5)
        self.assertEqual((receipt.start, receipt.stop), (2, 2))
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())

    def test_pruned_absolute_indices(self):
        receipt = self.roundtrip("full_pruned")
        # The retained segment keeps absolute indices after pruning.
        self.assertEqual((receipt.start, receipt.stop), (2, 6))
        self.assertEqual(tuple(entry.index for entry in receipt.items), (2, 3, 4, 5))

    def test_sha512_widths(self):
        receipt = self.roundtrip("full_sha512")
        self.assertEqual(receipt.hash_name, "sha512")
        self.assertEqual(len(receipt.root), 64)
        for entry in receipt.items:
            self.assertEqual(len(entry.previous_hash), 64)
            self.assertEqual(len(entry.entry_hash), 64)


class GoldenFullEncryptedSearchSampleTest(unittest.TestCase):
    """Pre-refactor FullEncryptedSearchReceipt bytes stay accepted."""

    def roundtrip(self, name):
        data = golden(name)
        receipt = decode_full_encrypted_search_receipt(data)
        self.assertIsInstance(receipt, FullEncryptedSearchReceipt)
        self.assertEqual(encode_full_encrypted_search_receipt(receipt), data)
        self.assertTrue(verify_full_encrypted_search_receipt(receipt, KEY))
        return receipt

    def test_basic(self):
        receipt = self.roundtrip("enc_basic")
        self.assertEqual(receipt.size, 5)
        self.assertEqual((receipt.start, receipt.stop), (0, 5))
        self.assertEqual(receipt.query, b"a")
        self.assertEqual(receipt.hits, (0, 2, 4))
        # Sealed payloads survive the round trip byte-for-byte.
        self.assertTrue(all(isinstance(entry.payload, bytes) for entry in receipt.items))

    def test_empty_range(self):
        receipt = self.roundtrip("enc_empty_range")
        self.assertEqual(receipt.items, ())
        self.assertEqual(receipt.proof, ())
        self.assertEqual(receipt.hits, ())

    def test_sha512_widths(self):
        receipt = self.roundtrip("enc_sha512")
        self.assertEqual(receipt.hash_name, "sha512")
        self.assertEqual(len(receipt.root), 64)
        self.assertEqual(receipt.hits, (0, 2))


class GoldenFullEncryptedJsonSearchSampleTest(unittest.TestCase):
    """Pre-refactor FullEncryptedJsonSearchReceipt bytes stay accepted."""

    def roundtrip(self, name):
        data = golden(name)
        receipt = decode_full_encrypted_json_search_receipt(data)
        self.assertIsInstance(receipt, FullEncryptedJsonSearchReceipt)
        self.assertEqual(encode_full_encrypted_json_search_receipt(receipt), data)
        self.assertTrue(verify_full_encrypted_json_search_receipt(receipt, KEY))
        return receipt

    def test_integer_value(self):
        receipt = self.roundtrip("json_int")
        self.assertEqual(receipt.pointer, "/a")
        self.assertEqual(receipt.value, 1)
        self.assertIs(type(receipt.value), int)
        self.assertEqual(receipt.hits, (0, 1))
        self.assertEqual(len(receipt.confirmation), 32)

    def test_string_value(self):
        receipt = self.roundtrip("json_string")
        self.assertEqual(receipt.value, "1")
        self.assertIs(type(receipt.value), str)
        self.assertEqual(receipt.hits, (2,))

    def test_float_value(self):
        receipt = self.roundtrip("json_float")
        self.assertEqual(receipt.value, 1.0)
        self.assertIs(type(receipt.value), float)
        self.assertEqual(receipt.hits, (0, 1))

    def test_null_value(self):
        receipt = self.roundtrip("json_null")
        self.assertIsNone(receipt.value)
        self.assertEqual(receipt.hits, ())

    def test_boolean_values_sha512(self):
        receipt = self.roundtrip("json_true_sha512")
        self.assertIs(receipt.value, True)
        self.assertEqual(receipt.hash_name, "sha512")
        self.assertEqual(len(receipt.confirmation), 64)
        self.assertEqual(receipt.hits, (0,))
        receipt = self.roundtrip("json_false_sha512")
        self.assertIs(receipt.value, False)
        self.assertEqual(receipt.hits, (1,))


class CommonBoundaryTest(unittest.TestCase):
    """The shared boundary rules behave identically across the three codecs."""

    # (encode, decode, magic, golden sample name)
    FORMATS = (
        (
            encode_full_search_receipt,
            decode_full_search_receipt,
            FULL_MAGIC,
            "full_basic",
        ),
        (
            encode_full_encrypted_search_receipt,
            decode_full_encrypted_search_receipt,
            ENC_MAGIC,
            "enc_basic",
        ),
        (
            encode_full_encrypted_json_search_receipt,
            decode_full_encrypted_json_search_receipt,
            JSON_MAGIC,
            "json_int",
        ),
    )

    def test_decode_requires_exact_bytes(self):
        for _, decode, _, sample in self.FORMATS:
            data = golden(sample)
            for bad in (bytearray(data), memoryview(data), "text", None, 1):
                with self.assertRaises(TypeError):
                    decode(bad)

    def test_encode_requires_matching_receipt_type(self):
        receipts = (
            decode_full_search_receipt(golden("full_basic")),
            decode_full_encrypted_search_receipt(golden("enc_basic")),
            decode_full_encrypted_json_search_receipt(golden("json_int")),
        )
        for encode, _, _, _ in self.FORMATS:
            for bad in (None, "receipt", b"bytes", 1, (1, 2)):
                with self.assertRaises(TypeError):
                    encode(bad)
            for receipt in receipts:
                expected = encode is not {
                    FullSearchReceipt: encode_full_search_receipt,
                    FullEncryptedSearchReceipt: encode_full_encrypted_search_receipt,
                    FullEncryptedJsonSearchReceipt: encode_full_encrypted_json_search_receipt,
                }[type(receipt)]
                if expected:
                    with self.assertRaises(TypeError):
                        encode(receipt)

    def test_bad_magic(self):
        for _, decode, magic, sample in self.FORMATS:
            data = golden(sample)
            with self.assertRaises(ValueError):
                decode(b"x" + data[1:])
            with self.assertRaises(ValueError):
                decode(b"")
            with self.assertRaises(ValueError):
                decode(magic[:-1])

    def test_cross_magic_rejected(self):
        bodies = {
            FULL_MAGIC: golden("full_basic"),
            ENC_MAGIC: golden("enc_basic"),
            JSON_MAGIC: golden("json_int"),
        }
        for _, decode, magic, _ in self.FORMATS:
            for other_magic, data in bodies.items():
                if other_magic != magic:
                    with self.assertRaises(ValueError):
                        decode(data)

    def test_bad_version(self):
        for _, decode, magic, sample in self.FORMATS:
            data = golden(sample)
            forged = magic + u64(2) + data[len(magic) + 8:]
            with self.assertRaises(ValueError):
                decode(forged)

    def test_truncation_at_every_offset(self):
        for _, decode, magic, sample in self.FORMATS:
            data = golden(sample)
            for cut in range(len(magic), len(data)):
                with self.assertRaises(ValueError):
                    decode(data[:cut])

    def test_trailing_bytes(self):
        for _, decode, _, sample in self.FORMATS:
            with self.assertRaises(ValueError):
                decode(golden(sample) + b"\x00")

    def test_oversized_blob_length(self):
        for _, decode, magic, _ in self.FORMATS:
            data = magic + u64(1) + u64(1 << 63) + b"sha256"
            with self.assertRaises(ValueError):
                decode(data)

    def test_invalid_utf8_hash_name(self):
        for _, decode, magic, _ in self.FORMATS:
            data = magic + u64(1) + blob(b"\xff\xfe")
            with self.assertRaises(ValueError):
                decode(data)

    def test_unknown_hash_algorithm(self):
        for _, decode, magic, _ in self.FORMATS:
            data = magic + u64(1) + blob(b"not-a-hash") + u64(0) + blob(b"")
            with self.assertRaises(ValueError):
                decode(data)

    def test_digest_width_checked(self):
        # A 31-byte root against sha256 is rejected by every decoder.
        for _, decode, magic, _ in self.FORMATS:
            data = magic + u64(1) + blob(b"sha256") + u64(5) + blob(b"\x00" * 31)
            with self.assertRaises(ValueError):
                decode(data)

    def test_invalid_utf8_pointer(self):
        data = (
            JSON_MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(0)
            + blob(bytes(32))
            + blob(b"\xff\xfe")
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data)

    def test_unknown_json_value_tag(self):
        data = (
            JSON_MAGIC
            + u64(1)
            + blob(b"sha256")
            + u64(0)
            + blob(bytes(32))
            + blob(b"/a")
            + u64(99)
            + blob(b"")
        )
        with self.assertRaises(ValueError):
            decode_full_encrypted_json_search_receipt(data)


class HitSegmentBoundaryTest(unittest.TestCase):
    """Duplicate, unordered or out-of-range hit indices stay rejected."""

    def replace_hits(self, data, hit_count_from_end, hits):
        tail = u64(len(hits)) + b"".join(u64(h) for h in hits)
        return data[: len(data) - hit_count_from_end] + tail

    def test_encrypted_hits(self):
        data = golden("enc_basic")  # hits (0, 2, 4): 4 trailing u64s
        for bad_hits in ((0, 0, 4), (2, 0, 4), (0, 2, 5)):
            forged = self.replace_hits(data, 4 * 8, bad_hits)
            with self.assertRaises(ValueError):
                decode_full_encrypted_search_receipt(forged)

    def test_json_hits(self):
        data = golden("json_int")  # hits (0, 1) + confirmation blob
        confirmation = u64(32) + golden("json_int")[-32:]
        for bad_hits in ((0, 0), (1, 0), (0, 6)):
            forged = self.replace_hits(data, 3 * 8 + len(confirmation), bad_hits) + confirmation
            with self.assertRaises(ValueError):
                decode_full_encrypted_json_search_receipt(forged)


class TamperedReceiptTest(unittest.TestCase):
    """Tampered-but-structural receipts round-trip and fail verification."""

    def test_full_search_tampered_root(self):
        receipt = decode_full_search_receipt(golden("full_basic"))
        tampered = FullSearchReceipt(
            1, "sha256", receipt.size, bytes(32), receipt.query,
            receipt.start, receipt.stop, receipt.items, receipt.proof,
        )
        data = encode_full_search_receipt(tampered)
        decoded = decode_full_search_receipt(data)
        self.assertEqual(decoded, tampered)
        self.assertEqual(encode_full_search_receipt(decoded), data)
        self.assertFalse(verify_full_search_receipt(decoded))

    def test_encrypted_tampered_entry(self):
        receipt = decode_full_encrypted_search_receipt(golden("enc_basic"))
        entry = receipt.items[0]
        forged = Entry(entry.index, b"zz", entry.previous_hash, entry.entry_hash)
        tampered = FullEncryptedSearchReceipt(
            1, "sha256", receipt.size, receipt.root, receipt.query,
            receipt.start, receipt.stop,
            (forged,) + receipt.items[1:], receipt.proof, receipt.hits,
        )
        decoded = decode_full_encrypted_search_receipt(
            encode_full_encrypted_search_receipt(tampered)
        )
        self.assertEqual(decoded, tampered)
        self.assertFalse(verify_full_encrypted_search_receipt(decoded, KEY))

    def test_json_tampered_confirmation(self):
        receipt = decode_full_encrypted_json_search_receipt(golden("json_int"))
        tampered = FullEncryptedJsonSearchReceipt(
            1, "sha256", receipt.size, receipt.root, receipt.pointer,
            receipt.value, receipt.start, receipt.stop, receipt.items,
            receipt.proof, receipt.hits, bytes(32),
        )
        decoded = decode_full_encrypted_json_search_receipt(
            encode_full_encrypted_json_search_receipt(tampered)
        )
        self.assertEqual(decoded, tampered)
        self.assertFalse(verify_full_encrypted_json_search_receipt(decoded, KEY))


class SignedEnvelopeStabilityTest(unittest.TestCase):
    """Signed envelopes over these receipt bytes keep verifying unchanged."""

    def test_signed_full_search_receipt(self):
        log = AuditLog()
        for record in ("a", "b", "a"):
            log.append(record)
        bundle = log.signed_full_search_receipt("a", SEED)
        data = encode_signed_full_search_receipt(bundle)
        decoded = decode_signed_full_search_receipt(data)
        self.assertEqual(decoded, bundle)
        self.assertEqual(encode_signed_full_search_receipt(decoded), data)
        self.assertTrue(verify_signed_full_search_receipt(decoded, public_key(SEED)))

    def test_signed_full_encrypted_search_receipt(self):
        log = AuditLog()
        log.encrypt("a", KEY, nonce=b"0" * 12)
        log.encrypt("b", KEY, nonce=b"1" * 12)
        log.encrypt("a", KEY, nonce=b"2" * 12)
        bundle = log.signed_full_encrypted_search_receipt("a", KEY, SEED)
        data = encode_signed_full_encrypted_search_receipt(bundle)
        decoded = decode_signed_full_encrypted_search_receipt(data)
        self.assertEqual(decoded, bundle)
        self.assertEqual(encode_signed_full_encrypted_search_receipt(decoded), data)
        self.assertTrue(
            verify_signed_full_encrypted_search_receipt(decoded, KEY, public_key(SEED))
        )


if __name__ == "__main__":
    unittest.main()
