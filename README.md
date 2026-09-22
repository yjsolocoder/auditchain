# auditchain

只追加的哈希链审计日志。每条条目把自身内容与前一条的摘要绑在一起，任何历史篡改都会让整链校验失败。

## 环境

Python 3.10+。只依赖标准库（`hashlib` / `hmac` / `os`）与
[`cryptography`](https://cryptography.io/)（加密追加使用其中的 `AESGCM`，
可信签名检查点使用其中的 Ed25519）。

### 摘要算法与宽度

所有带 `hash_name` 的构造与函数默认 `"sha256"`，并接受任意 **固定输出长度** 的
`hashlib` 算法（如 `"sha512"`、`"sha3-256"`）。日志的前驱、条目摘要、Merkle
节点、包含/一致性证明、认证标签以及两种回执中的每个摘要均为
`hashlib.new(hash_name).digest_size` 字节（sha256 为 32，sha512 为 64）。日志的
创世前驱是 `digest_size` 个 `0x00`；公开常量 `GENESIS_HASH` 保持 `bytes(32)`
（sha256 的创世前驱）。空前缀回执的 `chain_hash` 用日志自身宽度的零摘要。
`hash_name` 非字符串抛 `TypeError`；未知算法或无固定输出长度的算法（如
`shake_128` / `shake_256`，其 `digest_size` 为 0）以及任何摘要长度不符均抛
`ValueError`。结构合法但摘要/证明/标签互不匹配（含跨算法宽度不匹配）返回
`False`，绝不抛异常。

## 使用

```python
from auditchain import AuditLog

log = AuditLog()
log.append("agent started")
log.append("position claim: -73.9857,40.7484")
print(log.verify())        # True
print(log.head.hex())
```

### 按内容查找

```python
log.append("agent started")
log.find("agent started")   # (0, 2)：绝对索引升序元组，无匹配为 ()
log.find(b"agent", 1, 3)    # 半开区间 [1, 3) 内查找 bytes
```

### 加密追加（AES-256-GCM）

`encrypt(payload, key, nonce=None)` 与 `append` 的链式结构完全相同，但
`Entry.payload` 保存的是自描述密文封装，密钥只按次传入、日志从不保存：

```python
import os
from auditchain import decrypt_entry

key = os.urandom(32)                 # 必须是 32 字节 bytes
entry = log.encrypt("secret event", key)            # nonce=None 时用 os.urandom(12)
entry.payload                        # b"auditchain/encrypted-entry/v1\0" + 0x01 + nonce + 密文||tag
decrypt_entry(entry, key)            # b"secret event"：顶层函数，无需持有日志
log.find(b"secret event")            # ()：find 只匹配封装，不做解密检索
log.find(entry.payload)              # (index,)：按封装本体可以命中
log.find_encrypted("secret event", key)  # (index,)：持密钥按原明文定位，见下节
```

- 封装依次为 `b"auditchain/encrypted-entry/v1\0"`、算法号 `0x01`（AES-256-GCM）、
  12 字节 nonce、AESGCM 输出的 `ciphertext || 16 字节 tag`
- AEAD 的 AAD 依次为 `b"auditchain/aead/v1\0"`、`0x01`、index 的 u64 大端编码、
  `previous_hash`，把密文绑定到链上位置；封装整体作为 payload 参与 `entry_digest`
- 解密返回的明文规则与 `append` 一致：传入 `str` 取回其 UTF-8 字节
- `nonce` 须为 12 字节 `bytes`，且在同一日志内历史不重复——nonce 使用记录在日志
  整个生命期内保留，**裁剪后也不允许复用**旧 nonce
- 普通 `append` 行为不变；裁剪与审计回执原样保留密文（回执中的加密条目同样可用
  `decrypt_entry` 离线解密），不需要密钥即可 `verify()` / 验回执 / 重建 Merkle 根
- `key` 必须是 32 字节 `bytes`（其他类型抛 `TypeError`，长度不符抛 `ValueError`）；
  nonce 类型错抛 `TypeError`、长度或重复抛 `ValueError`；`encrypt` 失败不改变任何
  日志状态（被拒绝的 nonce 不会被记为已使用）
- `decrypt_entry(entry, key, *, hash_name="sha256")` 依次校验封装、摘要与 AEAD 认证：
  非 `Entry`、密钥/字段类型错抛 `TypeError`；封装魔数/截断、算法号、摘要长度、
  `entry_hash` 不符、密钥错误或认证失败抛 `ValueError`；调用为只读

#### 按原明文定位加密条目

持有追加时 AES 密钥的调用方可按原明文精确定位加密条目，日志既不保存明文也不
保存密钥，且不改变现有密文封装、`Entry` 摘要、链与 Merkle 结果：

```python
log.encrypt("secret event", key)
log.find_encrypted("secret event", key)   # (0,)：升序绝对索引 tuple
log.find(b"secret event")                 # ()：find 仍只匹配封装本体
log.find_encrypted("secret event", wrong_key)  # ()：合法但错误的密钥不命中、不抛错
```

- 签名为 `find_encrypted(payload, key, start=None, stop=None) -> tuple[int, ...]`，
  返回半开区间 `[start, stop)` 内的升序绝对索引 tuple，无命中为 `()`；范围参数的
  默认值、半开边界与越界规则与 `find` 完全相同（默认
  `[retain_from, len(log))`，显式边界须满足
  `retain_from <= start <= stop <= len(log)`）
- `payload` 仅为 `bytes` 或 `str`（`str` 按 UTF-8 规范化为 `P`），其他类型抛
  `TypeError`；`key` 仅为 32 字节 `bytes`（其他类型抛 `TypeError`，长度不符抛
  `ValueError`）；范围类型非法抛 `TypeError`、越界抛 `ValueError`；合法但错误的
  密钥返回 `()`，查询只读
- 定位摘要为
  `HMAC(key, b"auditchain/encrypted-locate/v1\0" || P, hash_name)`，只把该摘要
  映射到绝对索引；摘要不含明文、也无法在无密钥时伪造或猜测
- 定位项仅在 `encrypt` **追加成功后**才提交，任何 `encrypt` 失败都不改变索引；
  `prune` 成功时同步删除已释放前缀的定位项（无需追加时的密钥），裁剪失败索引不变
- 候选命中后必须用查询密钥解密对应封装并把明文与 `P` **逐字节比较**：AEAD
  认证失败或定位摘要碰撞都不会误命中。普通条目、不同密钥追加的条目均不命中

### 可验证前缀裁剪

```python
receipt = log.seal(2)          # 封存前 2 条，size 默认当前长度
log.prune(2, receipt)          # 校验回执并释放前 2 条的 payload
receipt.matches(log.entry(2))  # True：首条保留记录的索引与前驱摘要匹配
log.append("new event")        # 照常追加，索引、head 与未裁剪日志完全一致
log.verify()                   # True：从检查点开始校验
log.merkle_root()              # 与持有全部内容的日志重建出的根相同
log.consistency_proof(2, 5)    # 保留点到任意后续前缀的一致性证明
```

空前缀回执（`seal(0)`，`chain_hash` 为日志摘要宽度个 `0x00`；sha256 下即
`GENESIS_HASH`）匹配创世条目：
`receipt.matches(entry)` 当且仅当 `entry.index == 0` 且
`entry.previous_hash == receipt.chain_hash`。

#### 一步封存并裁剪（保留策略）

`apply_retention(value, *, mode="retain_from")` 先按模式计算保留点，再原子地
执行封存与裁剪，成功等价于 `receipt = seal(target); prune(target, receipt)`
并返回 `receipt`：

```python
receipt = log.apply_retention(2)                 # mode="retain_from"：保留点直接取 value
log.retain_from                                  # 2
receipt = log.apply_retention(3, mode="keep_last")  # 保留点 = max(当前保留点, len(log)-3)
```

- `mode="retain_from"`（默认）：目标保留点等于 `value`，要求
  `retain_from <= value <= len(log)`
- `mode="keep_last"`：目标保留点等于 `max(当前保留点, len(log) - value)`，
  即至多保留最新的 `value` 条且保留点绝不回退；要求 `value >= 0`
  （`value` 大于当前条数时保留点保持不动，`value=0` 裁剪全部）
- `value` 必须是非 `bool` 整数；`mode` 只接受 `"retain_from"` / `"keep_last"`
- `value` 或 `mode` 类型非法抛 `TypeError`；未知 `mode` 或 `value` 越界抛
  `ValueError`；任何失败都发生在改动之前，全部日志、认证、索引与证明状态不变
- 已裁剪条目的加密 nonce 仍记录在案，裁剪后依旧不可复用

`PruneReceipt` 可编码为规范字节形式，便于落盘或跨进程恢复后继续用于
`AuditLog.prune`（编解码均为只读，旧裁剪行为不变）：

```python
from auditchain import encode_prune_receipt, decode_prune_receipt

data = encode_prune_receipt(receipt)        # bytes，可写文件/发网络
restored = decode_prune_receipt(data)       # 冻结 PruneReceipt，字段与原回执相等
restored == receipt                         # True
encode_prune_receipt(restored) == data      # True：解码后重编码逐字节相同
log.prune(restored.size, restored)          # 同算法日志可直接据此裁剪
```

编码即 `b"auditchain/prune-receipt/v1\0" || version || hash_name || size ||
merkle_root || chain_hash`：魔数之后依次写 `version`（恒为 `1`）、`hash_name`
的 UTF-8 blob、`size`、`merkle_root` blob、`chain_hash` blob；所有整数为 8
字节无符号大端（`U`），每个 blob 为 `B(x) = U(len(x)) || x`（零长度也是全零
u64）。`encode_prune_receipt` 只接受 `PruneReceipt`，其余类型或绕过冻结写入的
字段类型错抛 `TypeError`；`decode_prune_receipt` 只接受 `bytes`（含拒绝
`bytearray` / `memoryview`）。魔数、版本、非法 UTF-8、非固定输出或未知摘要
算法、截断、尾随字节、blob 长度、`size` 的 u64 范围、两摘要宽度与算法不符（两
摘要等宽）均抛 `ValueError`。

### 离线审计回执

```python
receipt = log.audit_receipt([1, 3])     # 自动并入末条；size 默认当前长度
receipt.items                           # ((Entry, proof), ...) 按绝对索引升序
verify_audit_receipt(receipt)           # True：无需持有日志即可离线核验
```

回执为冻结的 `AuditReceipt(version=1, hash_name, size, root, items)`，记录快照
Merkle 根与所选条目的包含证明；`verify_audit_receipt` 重算每条 `entry_digest`
并核验全部包含证明、根与末条摘要。**任何 `size > 0` 的回执都必须携带末条
（`index == size - 1`）及其包含证明**——即使 `indices` 为空选择，也会自动并入
末条；因此非空快照不可能出现“零证据 + 任意 root”的回执。只有空快照
（`size=0`）才得到 `items == ()`，且只接受规范空树根。签发是只读的，不影响日志
任何状态。

回执可编码为规范字节形式，便于落盘或传输后离线核验：

```python
data = encode_audit_receipt(receipt)      # bytes：魔数 + u64 大端整数 + 长度前缀 blob
restored = decode_audit_receipt(data)     # 字段与原回执相等
encode_audit_receipt(restored) == data    # True：重复编码字节相同
verify_audit_receipt(restored)            # True
```

编码以魔数 `b"auditchain/audit-receipt/v1\0"` 开头；整数均为 8 字节无符号大端，
blob 为 u64 字节长度后接原始字节（零长度也是全零 u64）。字段顺序为 version、
hash_name（UTF-8 blob）、size、root blob、items 计数；每个 item 依次为
Entry.index、payload blob、previous_hash blob、entry_hash blob、proof 计数及各
摘要 blob。`encode_audit_receipt` 只接受 `AuditReceipt`（其他类型抛 `TypeError`），
整数超出 u64 范围抛 `ValueError`；`decode_audit_receipt` 只接受 `bytes`，魔数、
版本、算法、非法 UTF-8、截断、尾随字节、长度溢出、摘要长度、索引顺序/重复、
末条缺失或证明结构非法均抛 `ValueError`。

### 紧凑离线批量审计回执

`audit_batch` 与 `audit_receipt` 一样可离线核验快照根与末条，但多条所选记录共享
**一份** Merkle 批量包含证明（`batch_inclusion_proof` 的紧凑形式），比每条各带一份
包含证明更短小；返回的不是具名回执对象，而是纯五元组，字段即验证所需的全部材料：

```python
receipt = log.audit_batch([1, 3])      # 自动并入末条；size 默认当前长度
hash_name, size, root, entries, proof = receipt
entries                                # 严格升序的 Entry 元组
verify_audit_batch(receipt)            # True：无需持有日志即可离线核验
```

五元组依次为 `(hash_name: str, size: int, root: bytes, entries, proof)`：`root` 为
`[0, size)` 快照的 Merkle 根，`entries` 为按绝对索引严格升序的 `Entry` 元组（每个
索引满足 `retain_from <= i < size`），`proof` 为一份覆盖整个快照的 `bytes` 节点元组，
**逐字节等于** 以相同（去重排序并并入末条后的）索引与 `size` 调用
`batch_inclusion_proof` 的结果；叶摘要由验证方用 `entry_digest` 重算。与
`audit_receipt` 相同：非空快照（`size > 0`）即使 `indices` 为空选择也自动并入末条
（`index == size - 1`），故非空快照不可能出现“零证据 + 任意 root”的回执；空快照
（`size=0`）只接受空选择，返回规范空树根 `H("auditchain/merkle-empty/v1")`、空
`entries` 与空 `proof`。签发是只读的，不改变日志任何状态。

- `indices` 须为可迭代的互异非 `bool` 整数；`size` 默认当前长度，快照须可重建
- 类型非法抛 `TypeError`；重复、越界（`retain_from <= index < size` 不满足）或快照
  不可重建抛 `ValueError`；任何失败均发生在改动之前，日志状态不变
- `verify_audit_batch(receipt)` 只凭五元组离线核验：非五元组或字段类型错抛
  `TypeError`；未知算法、`size` 为负、条目索引越界、摘要宽度不符、`entries` 非严格
  升序或重复、非空快照缺末条（含 `size>0 且 entries==()` 的零证据情形）、空快照携带
  条目或证明节点数与 `(indices, size)` 不符抛 `ValueError`；结构合法但条目内容
  （重算 `entry_digest`）、证明或根不匹配返回 `False`，匹配返回 `True`

五元组同样可持久化为规范字节形式，落盘或传输后恢复为同一五元组并继续离线核验：

```python
data = encode_audit_batch(receipt)      # bytes：魔数 + u64 大端整数 + 长度前缀 blob
restored = decode_audit_batch(data)     # (hash_name, size, root, entries, proof)
restored == receipt                     # True：字段与原五元组相等
encode_audit_batch(restored) == data    # True：重复编码字节相同
verify_audit_batch(restored)            # True
```

字节流以魔数 `b"auditchain/batch/v1\0"` 开头，后接 `version=1`（u64）、`hash_name`
的 UTF-8 blob、`size`（u64）、`root` blob、entries 计数（u64）；整数均为 u64 大端，
blob 均为 u64 字节长度后接原始字节（零长度也是全零 u64）。随后逐个 Entry 依次写
`index`（u64）、`payload` blob、`previous_hash` blob、`entry_hash` blob，末尾写共享
`proof` 的节点计数（u64）及各节点 blob。`encode_audit_batch` 只接受满足
`verify_audit_batch` 结构契约的五元组（非五元组或字段类型错抛 `TypeError`；算法、
范围、宽度、顺序、缺末条或节点数等结构问题抛 `ValueError`）；`decode_audit_batch`
只接受 `bytes`（其他类型抛 `TypeError`），魔数、版本、算法、非法 UTF-8、截断、尾随
字节、长度溢出、范围、宽度、顺序、缺末条或节点数不符均抛 `ValueError`。内容、根或
证明不匹配的结构合法回执仍可正常编解码，仅 `verify_audit_batch` 返回 `False`。
编解码均为只读，不改变五元组与日志的任何状态。

### 可信签名快照检查点（Ed25519）

`sign_root` 用日志持有者按次提供的 Ed25519 私钥种子为某个快照（Merkle 根
与链头）签发一个不可变 `SignedRoot`；接收方凭**预先信任**的 32 字节 Ed25519
公钥即可离线核验该快照根与链头确由日志持有者签发，回执因此可以跨进程、跨
存储介质传递与验真，私钥从不落盘：

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from auditchain import verify_signed_root

seed = bytes(range(1, 33))               # 32 字节 Ed25519 私钥种子
public_key = (
    Ed25519PrivateKey.from_private_bytes(seed)
    .public_key()
    .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
)  # 32 字节公钥，预先交给验证方

receipt = log.sign_root(seed)            # size 默认 len(log)
receipt.root == log.merkle_root()        # True：快照 Merkle 根
receipt.head == log.head                 # True：快照链头（末条摘要）
verify_signed_root(receipt, public_key)  # True：无需持有日志
verify_signed_root(receipt, other_key)   # False：未信任的公钥
log.sign_root(seed, 0)                   # 空前缀：规范空树根 + 同宽零链头
```

- 回执为冻结的
  `SignedRoot(version, hash_name, size, root, head, signature)`，支持位置构造、
  按全部字段相等；`version` 恒为 `1`，`root` 为前 `size` 条的 Merkle 根，
  `head` 为该前缀末条摘要（空前缀为日志摘要宽度的零链头，sha256 下即
  `GENESIS_HASH`），`signature` 为 64 字节 Ed25519 签名
- 签名原文依次为
  `D || 0x01 || B(hash_name 的 UTF-8) || U(size) || B(root) || B(head)`，
  其中 `D = b"auditchain/signed-root/v1\0"`，`U` 为 8 字节无符号大端整数，
  `B(x) = U(len(x)) || x`；Ed25519 对该消息确定性签名
- `sign_root(private_key, size=None)` 的 `size` 默认 `len(log)`，须满足
  `0 <= size <= len(log)` 且快照仍可重建（已裁剪前缀抛 `ValueError`，空快照
  `size=0` 是内容无关常量，始终可签）；`private_key` 仅用于这一次签名，日志
  从不保存、返回或写入它；签发为只读，不改变条目、`head`、认证状态、Merkle
  根或证明
- `verify_signed_root(receipt, public_key)` 只凭回执与预信任公钥离线验真：
  重建同一签名原文并用公钥校验 64 字节签名。公钥不是对应签发方，或结构合法但
  `root` / `head` / `signature` / `size` / `hash_name` 任一字段被改，均返回
  `False`（绝不抛异常）
- 类型边界只接受 `bytes`：私钥种子、公钥以及回执的 `root` / `head` /
  `signature` 传入 `str` / `bytearray` / `memoryview` 等抛 `TypeError`
  （二进制字段不做静默拷贝，回执绝不别名调用方的可变缓冲区）；私钥种子或公钥
  不是 32 字节、`version` 非 `1`、未知摘要算法、`size` 超出
  `0 <= size < 2**64`、`root` / `head` 宽度与算法不符、`signature` 不是
  64 字节抛 `ValueError`；各入口均为只读
- `encode_signed_root(receipt)` / `decode_signed_root(data)` 把检查点序列化为
  规范二进制并原样还原，使其可落盘、跨进程传输后继续由 `verify_signed_root`
  验真：

```python
from auditchain import encode_signed_root, decode_signed_root

data = encode_signed_root(receipt)         # bytes，可写文件/发网络
restored = decode_signed_root(data)        # SignedRoot，字段与原回执相等
restored == receipt                        # True
encode_signed_root(restored) == data       # True：重编码逐字节相同
verify_signed_root(restored, public_key)   # True：无需持有日志
```

  编码以魔数 `b"auditchain/signed-root/v1\0"` 开头，依次写 `version`（恒为
  `1`）、`hash_name` 的 UTF-8 blob、`size`、`root` blob、`head` blob、
  `signature` blob；所有整数为 8 字节无符号大端，每个 blob 为 u64 字节长度
  前缀加原始字节（零长度也是全零 u64）。`encode_signed_root` 只接受
  `SignedRoot`、`decode_signed_root` 只接受 `bytes`（含拒绝 `bytearray` /
  `memoryview`），非对应类型或绕过构造器写入的字段类型错抛 `TypeError`；魔数、
  版本、UTF-8、未知算法、截断、尾随、blob 长度、`size` 范围、摘要宽度或签名
  宽度非法抛 `ValueError`；结构合法但签名与字段不匹配仍可解码，
  `verify_signed_root` 返回 `False`。两个入口均为只读

### Ed25519 签名钥轮换（旧钥授新钥）

`rotate_signer` 在**同一快照**上分别用旧、新两个 32 字节 Ed25519 种子各签一个
`SignedRoot`，再由旧种子对一份授权消息签名，使只持有旧公钥的验证方可以离线学会并
信任新公钥；`SignedRoot` 的签名域与接口完全不变，轮换不引入日志状态、不产生任何日志：

```python
from auditchain import verify_rotation

# 返回 (old, new_key, new, auth)
old, new_key, new, auth = log.rotate_signer(old_seed, new_seed)  # size 默认 len(log)
old.version == new.version          # True
old.hash_name == new.hash_name    # True：同一日志
old.size == new.size             # True：同一快照
old.root == new.root              # True：同一 Merkle 根
old.head == new.head              # True：同一链头
old.signature != new.signature    # True：仅签名不同（两把种子签同一消息）
len(new_key) == 32                 # True：新种子的原始 32 字节公钥
len(auth) == 64                   # True：旧种子的 Ed25519 授权签名
verify_rotation((old, new_key, new, auth), old_public)  # True：无需持有日志
verify_rotation((old, new_key, new, auth), other_key)    # False：未信任的旧公钥
```

- 授权原文为
  `D || 0x01 || B(old.signature) || B(new_key) || B(new.signature)`，
  其中 `D = b"auditchain/signer-rotation/v1\0"`，`U` 为 8 字节无符号大端整数，
  `B(x) = U(len(x)) || x`；`auth` 为旧种子对该消息的确定性 64 字节 Ed25519 签名。
  新旧两个检查点各自签的仍是 `sign_root` 的原文，签名域和 `SignedRoot` 接口不变
- `rotate_signer(old_seed, new_seed, size=None)` 的 `size` 默认当前日志长度，须为非
  `bool` 整数且满足 `0 <= size <= len(log)`、快照仍可重建（已裁剪前缀抛
  `ValueError`，空快照 `size=0` 始终可签）；两个种子参数都只接受 32 字节
  `bytes`（`str` / `bytearray` / `memoryview` 等抛 `TypeError`，长度非 32 抛
  `ValueError`），种子从不保存、返回或写入日志。调用只读，不改变条目、`head`、
  认证状态、Merkle 根或证明
- `verify_rotation(item, key)` 完全离线、只读核验：用预信任的旧公钥 `key` 验证
  `old` 与 `auth`，从 `item` 中取出 `new_key` 验证 `new`（新钥只有经旧钥授权后才
  被信任），并要求 `old` / `new` 除 `signature` 外逐字段全等——两者必须描述同一
  快照。结构合法但任一签名不符、`new_key` 与授权不匹配或两个检查点不是同一快照，均
  返回 `False`（绝不抛异常）
- `item` 必须是 `(old, new_key, new, auth)` 四元组：`old` / `new` 必须是
  `SignedRoot`，`new_key` / `auth` 必须是 `bytes`，否则抛 `TypeError`；`new_key`
  非 32 字节、`auth` 非 64 字节、信任公钥非 32 字节抛 `ValueError`，嵌套
  `SignedRoot` 的结构非法沿用 `verify_signed_root` 的既有异常（`TypeError` /
  `ValueError`）

### 可信紧凑批量审计包（Ed25519）

`signed_audit_batch` 在一个不可变 `SignedAuditBatch` 中同时打包
`audit_batch` 的紧凑批量回执五元组与 `sign_root` 对同一快照签发的
`SignedRoot` 检查点；离线接收方仅凭**预置信任**的 32 字节 Ed25519 公钥，
即可一次确认所选条目、共享批量包含证明、快照 Merkle 根与链头均由日志持有者
签发，无需持有 `AuditLog`，也不引入任何新的签名原文：

```python
from auditchain import verify_signed_audit_batch

receipt = log.signed_audit_batch([0, 2], seed)         # size 默认 len(log)
receipt.batch == log.audit_batch([0, 2])               # True：批量五元组
receipt.checkpoint == log.sign_root(seed)             # True：同一签名检查点
verify_signed_audit_batch(receipt, public_key)        # True：无需持有日志
verify_signed_audit_batch(receipt, other_key)         # False：未信任的公钥
AuditLog().signed_audit_batch((), seed)               # 空快照：规范空树根 + 零链头
```

- 包为冻结的 `SignedAuditBatch(batch:tuple, checkpoint:SignedRoot)`，字段顺序
  即签名顺序，支持位置构造、按两个字段相等；`batch` 必须是元组、`checkpoint`
  必须是 `SignedRoot`，字段类型错抛 `TypeError`（批量五元组内部的结构契约仍由
  `verify_audit_batch` 校验）
- `AuditLog.signed_audit_batch(indices, private_key, size=None)` 是只读签发
  入口，`size` 默认当前长度：先调用 `audit_batch(indices, size)`，再调用
  `sign_root(private_key, size)`，据其结果构造 `SignedAuditBatch`；任何失败
  都在构造前抛出，不改变日志状态，也不新增签名原文（检查点签的仍是
  `sign_root` 的原文）
- `verify_signed_audit_batch(receipt, public_key)` 完全离线核验：依次调用
  `verify_audit_batch` 与 `verify_signed_root`，并要求两部分描述同一快照——
  `hash_name`、`size`、`root` 一致，且非空快照的检查点 `head` 等于批量回执
  末条（索引 `size - 1`）的 `entry_hash`；空快照的 `head` 必须为同宽零摘要
  （sha256 下即 `GENESIS_HASH`）。公钥不受信任、两部分不一致，或条目 / 证明 /
  根 / 链头 / 签名被改，均返回 `False`（绝不抛异常）
- 入参不是 `SignedAuditBatch`（含绕过冻结构造器写入的容器字段类型错）抛
  `TypeError`；嵌套的批量五元组或检查点结构非法时沿用 `verify_audit_batch` /
  `verify_signed_root` 的既有异常（`TypeError` / `ValueError`）；公钥不是
  `bytes` 抛 `TypeError`、不是 32 字节抛 `ValueError`；核验为只读
- `encode_signed_audit_batch(receipt)` / `decode_signed_audit_batch(data)`
  把整个可信紧凑批量审计包序列化为规范二进制并原样还原，使其可落盘、跨进程
  传输后继续凭预置信任的 Ed25519 公钥离线验真，且不引入任何新的签名原文：

```python
from auditchain import encode_signed_audit_batch, decode_signed_audit_batch

data = encode_signed_audit_batch(receipt)          # bytes，可写文件/发网络
restored = decode_signed_audit_batch(data)         # 冻结 SignedAuditBatch
restored == receipt                                # True：字段相等
encode_signed_audit_batch(restored) == data        # True：重编码逐字节相同
verify_signed_audit_batch(restored, public_key)    # True：无需持有日志
```

  字节流以魔数 `b"auditchain/signed-audit-batch/v1\0"` 开头，随后**严格依次**
  写 `version`（恒为 `1`，8 字节无符号大端）、batch blob、checkpoint blob，
  不允许省略、换序或附加字段；两个 blob 均为 u64 字节长度前缀加原始字节，
  内容依次就是既有 `encode_audit_batch` 与 `encode_signed_root` 输出的完整
  规范字节。解码精确消费两个 blob，分别原样交给 `decode_audit_batch` 与
  `decode_signed_root`。`encode_signed_audit_batch` 只接受
  `SignedAuditBatch`（其余类型抛 `TypeError`，嵌套错误沿用既有编码器的
  `TypeError` / `ValueError`），`decode_signed_audit_batch` 只接受 `bytes`
  （含拒绝 `bytearray` / `memoryview`）；魔数、版本、截断、尾随、blob 长度
  或任一嵌套格式非法抛 `ValueError`；结构合法但验真不匹配仍可解码，
  `verify_signed_audit_batch` 返回 `False`。两个入口均为只读且确定

### 可信跨快照一致性凭据（Ed25519）

`signed_consistency` 在一个不可变 `SignedConsistency` 中打包同一日志两个
前缀快照的 `SignedRoot` 检查点与连接两根的 Merkle 一致性证明；离线接收方
仅凭**预置信任**的 32 字节 Ed25519 公钥，即可确认两个快照均由日志持有者
签发、且后者由前者只追加形成，无需持有 `AuditLog`，也不引入任何新的签名
原文：

```python
from auditchain import verify_signed_consistency

receipt = log.signed_consistency(3, seed)            # new_size 默认 len(log)
receipt.old == log.sign_root(seed, 3)                # True：旧快照检查点
receipt.new == log.sign_root(seed)                   # True：新快照检查点
receipt.proof == log.consistency_proof(3, len(log))  # True：逐字节相同
verify_signed_consistency(receipt, public_key)       # True：无需持有日志
verify_signed_consistency(receipt, other_key)        # False：未信任的公钥
```

- 凭据为冻结的 `SignedConsistency(old:SignedRoot, new:SignedRoot,
  proof:tuple[bytes, ...])`，支持位置构造、按三个字段相等；`old` / `new`
  必须是 `SignedRoot`、`proof` 必须是 `bytes` 元组，字段类型错抛
  `TypeError`
- `AuditLog.signed_consistency(old_size, private_key, new_size=None)` 是只读
  签发入口，`new_size` 默认当前长度：两端分别调用 `sign_root`，`proof`
  逐字节等于 `consistency_proof(old_size, new_size)`；尺寸须满足
  `0 <= old_size <= new_size <= len(log)` 且两快照均可重建（已剪枝的前缀
  抛 `ValueError`），类型与取值错误沿用 `consistency_proof` / `sign_root`
  的既有接口，任何失败都在构造前抛出，不改变日志状态
- `verify_signed_consistency(receipt, public_key)` 完全离线核验：先用
  `verify_signed_root` 分别验证 `old`、`new` 并要求两者 `hash_name` 相同，
  再以 `old.hash_name` 调用 `verify_consistency` 核验两端尺寸、根与
  `proof`；任一签名、快照关联或证明不匹配返回 `False`（绝不抛异常）
- 入参不是 `SignedConsistency`（含绕过冻结构造器写入的容器字段类型错）抛
  `TypeError`；嵌套检查点或一致性证明结构非法时沿用
  `verify_signed_root` / `verify_consistency` 的既有异常（`TypeError` /
  `ValueError`）；公钥不是 `bytes` 抛 `TypeError`、不是 32 字节抛
  `ValueError`；核验为只读
- `encode_signed_consistency(receipt)` / `decode_signed_consistency(data)`
  把整个可信跨快照一致性凭据序列化为规范二进制并原样还原，使其可落盘、跨进程
  恢复后继续凭预置信任的 Ed25519 公钥离线验真，且不引入任何新的签名原文：

```python
from auditchain import encode_signed_consistency, decode_signed_consistency

data = encode_signed_consistency(receipt)          # bytes，可写文件/发网络
restored = decode_signed_consistency(data)         # 冻结 SignedConsistency
restored == receipt                                # True：字段相等
encode_signed_consistency(restored) == data        # True：重编码逐字节相同
verify_signed_consistency(restored, public_key)    # True：无需持有日志
```

  字节流以魔数 `b"auditchain/signed-consistency/v1\0"` 开头，随后**严格依次**
  写 `version`（恒为 `1`，8 字节无符号大端）、old blob、new blob、proof
  节点计数（u64 大端）以及按元组顺序排列的节点 blob，不允许省略、换序或附加
  字段；所有 blob 均为 u64 字节长度前缀加原始字节（零长度也写全零 u64），
  old 与 new blob 的内容分别就是既有 `encode_signed_root` 输出的完整规范字节，
  解码时精确消费并分别原样交给 `decode_signed_root`。
  `encode_signed_consistency` 只接受 `SignedConsistency`（其余类型抛
  `TypeError`，含绕过冻结构造器写入的字段类型错；嵌套检查点错误沿用
  `encode_signed_root` 的 `TypeError` / `ValueError`），
  `decode_signed_consistency` 只接受 `bytes`（含拒绝 `bytearray` /
  `memoryview`）；魔数、版本、截断、尾随、blob 长度、嵌套检查点格式或 proof
  节点宽度（须等于 old 检查点所命名算法的摘要宽度）非法抛 `ValueError`；编解码
  均不校验签名、两端关联及证明内容（节点计数与尺寸是否相称、是否连接两根留给
  恢复后的既有验真契约判定），结构合法但验真不匹配仍可解码，
  `verify_signed_consistency` 返回 `False`；两个入口均为只读且确定。

### 可信签名裁剪授权（Ed25519）

`sign_prune` 在一个不可变 `SignedPrune` 中同时打包 `seal` 的前缀裁剪回执
`PruneReceipt` 与 `sign_root` 对**同一前缀**签发的 `SignedRoot` 检查点；持有
**预置信任** 32 字节 Ed25519 公钥的一方可先离线确认裁剪授权（摘要算法、`size`、
Merkle 根、链头）确由日志持有者签发，核验通过后才真正释放前缀负载，核验失败
绝不改变日志状态：

```python
from auditchain import verify_signed_prune

item = log.sign_prune(seed, 2)             # size 默认 len(log)
item.receipt == log.seal(2)                # True：前缀裁剪回执
item.checkpoint == log.sign_root(seed, 2)  # True：同一前缀的签名检查点
verify_signed_prune(item, public_key)      # True：无需持有日志
verify_signed_prune(item, other_key)       # False：未信任的公钥
log.prune_signed(2, item, public_key)      # 核验通过才裁剪，等价于 prune(2, item.receipt)
```

- 包为冻结的 `SignedPrune(receipt:PruneReceipt, checkpoint:SignedRoot)`，字段
  顺序即签名顺序，支持位置构造、按两个字段相等；`receipt` 必须是
  `PruneReceipt`、`checkpoint` 必须是 `SignedRoot`，字段类型错抛 `TypeError`
  （两部分是否描述同一前缀、签名是否有效由 `verify_signed_prune` 判定）
- `AuditLog.sign_prune(seed, size=None)` 是只读签发入口，`size` 默认当前日志
  长度：先调用 `seal(size)`，再调用 `sign_root(seed, size)`，据其结果构造
  `SignedPrune`；两部分天然同 `hash_name`、同 `size`，且
  `merkle_root == root`、`chain_hash == head`。任何失败都在构造前抛出，不改变
  日志状态，也不新增签名原文（检查点签的仍是 `sign_root` 的原文）
- `verify_signed_prune(item, key)` 完全离线核验：用 `verify_signed_root` 以
  32 字节公钥校验检查点签名，并要求回执与检查点字段一致——`hash_name` 相等、
  `size` 相等、`merkle_root == checkpoint.root`、
  `chain_hash == checkpoint.head`。公钥不受信任、两部分描述不同前缀，或回执 /
  根 / 链头 / 签名被改，均返回 `False`（绝不抛异常）。入参不是 `SignedPrune`
  （含绕过冻结构造器写入的容器字段类型错）抛 `TypeError`；嵌套结构非法沿用
  `PruneReceipt` / `SignedRoot` / `verify_signed_root` 的既有异常
  （`TypeError` / `ValueError`）；公钥不是 `bytes` 抛 `TypeError`、不是 32
  字节抛 `ValueError`；核验为只读
- `AuditLog.prune_signed(n, item, key) -> None` 先经
  `verify_signed_prune(item, key)` 核验，通过后等价于 `prune(n, item.receipt)`
  （后者仍重新核对 `n == receipt.size` 并自行从日志重算前缀根与链摘要）。
  `n` 必须是非 `bool` 整数（类型错抛 `TypeError`）；授权不匹配（未信任公钥、
  字段不一致、签名被改）或 `prune` 的既有校验失败（越界、保留点回退、回执与
  日志不一致等）均抛 `ValueError`，且失败不改变任何日志、认证、索引、nonce
  历史、frontier 检查点状态；其余异常沿用各既有入口
- `encode_signed_prune(x)` / `decode_signed_prune(y)` 把整个签名裁剪授权序列化
  为规范二进制并原样还原，使其可落盘、跨进程传输后继续凭预置信任的 Ed25519
  公钥验真并用于裁剪，且不引入任何新的签名原文：

```python
from auditchain import encode_signed_prune, decode_signed_prune

data = encode_signed_prune(item)          # bytes，可写文件/发网络
restored = decode_signed_prune(data)      # 冻结 SignedPrune
restored == item                          # True：字段相等
encode_signed_prune(restored) == data     # True：重编码逐字节相同
verify_signed_prune(restored, public_key) # True
fresh_log.prune_signed(2, restored, public_key)  # 跨进程恢复后直接授权裁剪
```

  字节流为 `D || U(1) || B(P) || B(R)`，其中
  `D = b"auditchain/signed-prune/v1\0"`，`U` 为 8 字节无符号大端整数，
  `B(x) = U(len(x)) || x`（沿用 u64 大端与既有 blob 规则）；`P` 与 `R` 分别是
  既有 `encode_prune_receipt(receipt)` 与
  `encode_signed_root(checkpoint)` 输出的完整规范字节，顺序固定为回执在前、
  检查点在后，解码精确消费两个 blob 且**禁止尾随字节**。`encode_signed_prune`
  只接受 `SignedPrune`（其余类型抛 `TypeError`，嵌套错误沿用既有编码器的
  `TypeError` / `ValueError`），`decode_signed_prune` 只接受 `bytes`（含拒绝
  `bytearray` / `memoryview`）；魔数、版本、截断、尾随、blob 长度或任一嵌套
  格式非法抛 `ValueError`；结构合法但两部分不一致或签名不匹配仍可解码，
  `verify_signed_prune` 返回 `False`；两个入口均为只读且确定

### 完整日志状态的签名导出与恢复（Ed25519）

`dump_log(log, private_key)` 把一份**完整、未裁剪、无认证、无加密历史**的
日志导出为自证其真的字节流：状态快照（摘要算法、条目数、Merkle 根、链头）
以 `sign_root(private_key)` 同一签名原文、同一 Ed25519 种子按次签发，私钥
从不保存、不写入字节流，也不新增任何签名原文。`load_log(data, public_key)`
仅凭**预置信任**的 32 字节 Ed25519 公钥离线验真后，重放全部条目，恢复出一条
**独立、可变**的普通无密钥日志——`find` 索引、Merkle frontier、链头、长度与
保留点都与同进程逐条 `append` 构建完全一致，可继续追加、`encrypt`、`prune`
并使用全部既有接口，与调用方缓冲区不共享任何状态：

```python
from auditchain import dump_log, load_log

data = dump_log(log, seed)                   # bytes，可落盘/跨进程/跨介质传递
restored = load_log(data, public_key)        # 全新、独立、可变的 AuditLog
restored.head == log.head                    # True：链头一致
restored.merkle_root() == log.merkle_root()  # True：Merkle 根一致
restored.find(b"agent started")              # find 索引已重建
restored.append("new event")                 # 恢复后照常追加与加密
restored.encrypt("secret", key)
len(restored) == len(log) + 2                # 原日志不受影响
```

- 导出**只读**且确定：不改变日志任何状态；同状态、同种子的两次导出逐字节
  相同（Ed25519 确定性签名）
- 仅接受完整的普通追加日志：`retain_from == 0`（未裁剪）、构造时未传
  `key` 且没有任何认证历史（未 `auth` / `auth_batch` / `rotate_key` /
  `export_verifier`，无残留标签）、从未 `encrypt` 过条目（无密文与 nonce
  历史）。字节流不携带任何裁剪检查点、认证 / 演进状态、密钥或 nonce
- 字节流以魔数 `b"auditchain/log-state/v1\0"` 开头，随后**严格依次**写
  `version`（恒为 `1`，u64）、一个 blob `C`、条目数 `n`（u64）与 `E1…En`；
  `C` 是既有 `encode_signed_root(log.sign_root(private_key))` 输出的**完整**
  规范字节，按 `B(C)` 编码；每个 `Ei` 依次为 `U(index)`、`B(payload)`、
  `B(previous_hash)`、`B(entry_hash)`。整数均为 8 字节无符号大端（`U`），
  blob 均为 `B(x) = U(len(x)) || x`，不允许省略、换序或附加字节
- `load_log` 先把 `C` 交给既有 `decode_signed_root` 并以公钥验签（沿用
  `verify_signed_root` 的全部规则），再要求条目索引恰为 `0..n-1` 且
  `C.size == n`；然后按 `C.hash_name` 指定的算法与摘要宽度，从创世零摘要起
  逐条重算 `entry_digest` 链头并重建 Merkle 根，二者必须与 `C` 匹配，最后
  通过正常 `append` 路径重放重建并返回新日志
- `dump_log` 入参不是 `AuditLog` 或私钥不是 `bytes` 抛 `TypeError`；私钥不是
  32 字节，或日志已裁剪 / 带认证状态 / 含加密历史抛 `ValueError`
- `load_log` 的 `data` 只接受 `bytes`（拒绝 `bytearray` / `memoryview`），
  公钥类型错抛 `TypeError`；公钥长度非 32、魔数 / 版本 / 嵌套检查点算法与
  宽度 / 条目宽度 / 索引顺序 / `C.size` 不符、截断、尾随字节、blob 长度溢出、
  验签失败或重算的链头 / Merkle 根与检查点不一致均抛 `ValueError`；恢复为
  只读校验，不改变入参

### 含加密历史日志的签名导出与恢复（Ed25519）

`dump_secure_log(log, private_key)` 与 `load_secure_log(data, public_key)`
是 `dump_log` / `load_log` 的加密历史版本：同样把一份**完整、未裁剪、无
认证**的日志导出为自证其真的字节流并离线恢复为**独立、可变的无密钥**
`AuditLog`，但允许历史中含有 `encrypt` 追加的密文条目。字节流不携带任何
AES 密钥；每条密文条目的定位 HMAC 与 12 字节 nonce 足以在无密钥情况下重建
`find_encrypted` 定位索引与 nonce 历史，恢复后的日志可继续 `append`、
`encrypt`、`prune` 并使用全部既有接口，与调用方缓冲区不共享任何状态：

```python
from auditchain import dump_secure_log, load_secure_log

key = os.urandom(32)
log.append("plain event")
log.encrypt("secret event", key, nonce=b"0" * 12)
data = dump_secure_log(log, seed)                # bytes，可落盘/跨进程传递
restored = load_secure_log(data, public_key)     # 全新、独立、可变的无密钥 AuditLog
restored.head == log.head                        # True：链头一致
restored.merkle_root() == log.merkle_root()      # True：Merkle 根一致
restored.find_encrypted("secret event", key)     # (1,)：定位索引已恢复
restored.encrypt("again", key, nonce=b"0" * 12)  # ValueError：nonce 历史已恢复
```

- 仅接受 `retain_from == 0`（未裁剪）、构造时未传 `key` 且无任何认证状态或
  历史（未 `auth` / `auth_batch` / `rotate_key` / `export_verifier`，无残留
  标签）的日志；与 `dump_log` 不同，**允许** `encrypt` 历史（密文封装、
  nonce 历史与定位索引都会被恢复）。字节流不携带任何裁剪检查点、认证 / 演进
  状态或 AES 密钥
- 字节流以魔数 `b"auditchain/secure-log/v1\0"` 开头，随后**严格依次**写
  `version`（恒为 `1`，u64）、`B(hash_name 的 UTF-8)`、条目数 `n`（u64）、
  `B(root)`、`B(head)` 与 `n` 个 `E`；末尾再追加 **64 字节 Ed25519 签名**，
  覆盖签名之前的全部字节（不是 `sign_root` 的域分离签名原文）。整数均为 8
  字节无符号大端（`U`），blob 均为 `B(x) = U(len(x)) || x`
- 每个 `E = U(index) || B(payload) || B(previous_hash) || B(entry_hash) ||
  B(locator)`：**`locator` 为空 blob 表示普通条目**；否则它必须是与
  `hash_name` 同宽的既有加密定位 HMAC
  （`HMAC(key, b"auditchain/encrypted-locate/v1\0" || P, hash_name)`，即日志
  内部反向定位表中保存的值）。条目类型由 locator 判定而非 payload——普通
  `append` 的内容即使恰好以密文封装魔数开头，locator 为空时仍是普通条目
- 加载时对每个非空 locator，从其密文封装中恢复 12 字节 nonce 并**拒绝
  重复**；同时校验封装魔数 / 算法号 / 截断（沿用 `decrypt_entry` 的封装
  规则）
- `load_secure_log` **先验签**（对签名之前的全部字节用预置信任的 32 字节
  公钥校验末尾 64 字节签名），通过后才解析；随后按 `hash_name` 从创世零摘要
  逐条重算 `entry_digest` 链、`head` 与 Merkle 根并逐项匹配，再以正常
  `append` / 加密条目恢复路径重放，重建 `find` 索引、加密定位索引、nonce
  历史、Merkle frontier、链头、长度与保留点
- 导出**只读且确定**：不改变日志任何状态；同状态、同种子的两次导出逐字节
  相同（Ed25519 确定性签名），私钥从不保存、不写入字节流
- `dump_secure_log` 入参不是 `AuditLog` 或私钥不是 `bytes` 抛 `TypeError`；
  私钥不是 32 字节，或日志已裁剪 / 带认证状态或历史抛 `ValueError`
- `load_secure_log` 的 `data` 只接受 `bytes`（拒绝 `bytearray` /
  `memoryview`），公钥类型错抛 `TypeError`；公钥非 32 字节，或魔数、版本、
  非法 UTF-8、未知 / 非固定输出算法、截断、尾随、索引非 `0..n-1`、
  摘要 / locator 宽度不符、密文封装非法、nonce 重复、重算链 / 根不符、签名
  不符均抛 `ValueError`；恢复为只读校验，不改变入参

### 已裁剪日志的签名导出与恢复（Ed25519）

`dump_pruned_log(log, private_key)` 与 `load_pruned_log(data, public_key)`
是 `dump_log` / `load_log` 的已裁剪版本：把一份 **`retain_from > 0`（已裁剪）、
构造时未传 `key` 且从无认证与加密历史** 的日志导出为自证其真的字节流，仅凭
**预置信任** 的 32 字节 Ed25519 公钥离线验真后，恢复出一条**独立、可变**的无
密钥 `AuditLog`——长度、绝对索引、`retain_from`、Merkle 根与包含证明都与原
日志完全一致。字节流携带裁剪检查点（被释放前缀的链头）与覆盖 `[0, r)` 的
frontier 完美子树，因此无需任何已释放的 payload 即可重建全部可重建快照：

```python
from auditchain import dump_pruned_log, load_pruned_log

log.prune(3, log.seal(3))                    # 释放前 3 条，retain_from == 3
data = dump_pruned_log(log, seed)            # bytes，可落盘/跨进程/跨介质传递
restored = load_pruned_log(data, public_key) # 全新、独立、可变的 AuditLog
restored.retain_from == 3                    # True：保留点一致
restored.head == log.head                    # True：链头一致
restored.merkle_root() == log.merkle_root()  # True：Merkle 根一致
restored.inclusion_proof(4) == log.inclusion_proof(4)  # True：证明一致
restored.append("new event")                 # 恢复后照常追加、加密、再裁剪
```

- 导出**只读**且确定：不改变日志任何状态；同状态、同种子的两次导出逐字节
  相同（Ed25519 确定性签名），私钥从不保存、不写入字节流
- 仅接受 `retain_from > 0` 的已裁剪日志，且构造时未传 `key`、没有任何认证
  历史（未 `auth` / `auth_batch` / `rotate_key` / `export_verifier`，无残留
  标签）、从未 `encrypt` 过条目（含已被裁剪释放的密文：nonce 历史仍在即
  拒绝）。字节流不携带任何裁剪回执、认证 / 演进状态、密钥或 nonce
- 字节流以魔数 `b"auditchain/pruned-log/v1\0"` 开头，随后**严格依次**写
  `version`（恒为 `1`，u64）、`B(hash_name 的 UTF-8)`、总条目数 `n`（u64）、
  保留点 `r`（u64）、`B(checkpoint)`（前 `r` 条末条的链摘要，与算法摘要
  等宽）、frontier 子树计数（u64）、按**高度升序**每棵子树一对
  `U(height) || B(digest)`（高度恰为 `r` 的置位，子树覆盖 `[0, r)`）、保留
  条目计数（u64，恰为 `n - r`）与索引 `r..n-1` 的条目；每个条目按
  `dump_log` 格式依次为 `U(index)`、`B(payload)`、`B(previous_hash)`、
  `B(entry_hash)`。随后写 `B(root)`、`B(head)`（完整 size-`n` 快照的
  Merkle 根与链头），末尾追加覆盖此前全部字节的 **64 字节 Ed25519 签名**。
  `U` 为 8 字节无符号大端，`B(x) = U(len(x)) || x`，不允许省略、换序或
  附加字节
- `load_pruned_log` **先验签**（对签名之前的全部字节用公钥校验末尾 64 字节
  签名），通过后才解析并复核上述结构：要求 `0 < r <= n`、frontier 高度恰为
  `r` 的置位、保留条目数恰为 `n - r`、索引恰为 `r..n-1`；随后按 `hash_name`
  从检查点起逐条重算 `entry_digest` 链，链头必须等于 `head`，由 frontier 与
  保留条目重建的 Merkle 根必须等于 `root`，最后经正常 `append` 路径重放
  （`find` 索引、frontier、链头、长度与保留点随之重建）
- `dump_pruned_log` 入参不是 `AuditLog` 或私钥不是 `bytes` 抛 `TypeError`；
  私钥不是 32 字节，或日志未裁剪 / 带认证状态或历史 / 含加密历史抛
  `ValueError`
- `load_pruned_log` 的 `data` 只接受 `bytes`（拒绝 `bytearray` /
  `memoryview`），公钥类型错抛 `TypeError`；公钥非 32 字节，或魔数、版本、
  非法 UTF-8、未知 / 非固定输出算法、截断、尾随、保留点越界、检查点 /
  frontier / 摘要宽度不符、frontier 高度非 `r` 的置位、条目数与 `n - r`
  不符、索引顺序、断链、重算链头 / Merkle 根不符、签名不符均抛
  `ValueError`；恢复为只读校验，不改变入参

### 已裁剪且可含密文日志的签名导出与恢复（Ed25519）

`dump_secure_pruned(log, private_key)` 与
`load_secure_pruned(data, public_key)` 是 `dump_pruned_log` /
`load_pruned_log` 的加密历史版本：把一份 **`retain_from > 0`（已裁剪）、
构造时未传 `key` 且从无认证状态或历史**（但历史中可含 `encrypt` 密文，
包括已被裁剪释放的密文）的日志导出为自证其真的字节流，仅凭预置信任的 32
字节 Ed25519 公钥离线验真后，恢复出一条**独立、可变的无密钥** `AuditLog`
——长度、绝对索引、`retain_from`、Merkle 根、包含证明、检索索引与 nonce
历史都与原日志完全一致。字节流除裁剪检查点与覆盖 `[0, r)` 的 frontier
外，还携带完整 nonce 历史，因此裁剪前用过的 nonce 在恢复后仍不可复用：

```python
log.encrypt("released secret", key, nonce=b"0" * 12)
log.append("plain")
log.encrypt("retained secret", key, nonce=b"1" * 12)
log.prune(2, log.seal(2))                    # 释放前 2 条，retain_from == 2
data = dump_secure_pruned(log, seed)         # bytes，可落盘/跨进程/跨介质传递
restored = load_secure_pruned(data, public_key)
restored.retain_from == 2                    # True：保留点一致
restored.merkle_root() == log.merkle_root()  # True：Merkle 根一致
restored.inclusion_proof(2) == log.inclusion_proof(2)  # True：证明一致
restored.find_encrypted("retained secret", key)        # (2,)：定位索引已恢复
restored.encrypt("again", key, nonce=b"0" * 12)        # ValueError：裁剪前 nonce 历史已恢复
```

- 导出**只读**且确定：不改变日志任何状态；同状态、同种子的两次导出逐字节
  相同（Ed25519 确定性签名），私钥从不保存、不写入字节流
- 仅接受 `retain_from > 0` 的已裁剪日志，且构造时未传 `key`、没有任何认证
  状态或历史（未 `auth` / `auth_batch` / `rotate_key` / `export_verifier`，
  无残留标签）；与 `dump_pruned_log` 不同，**允许** `encrypt` 历史（含已被
  裁剪释放的密文），其 nonce 历史与保留密文的定位索引都会恢复。字节流不
  携带任何裁剪回执、认证 / 演进状态或 AES 密钥
- 字节流以魔数 `b"auditchain/pruned-secure/v1\0"` 开头，头部复用
  `dump_pruned_log` 的字段顺序与 `U`/`B` 规则，仅替换魔数：随后**严格依次**
  写 `version`（恒为 `1`，u64）、`B(hash_name 的 UTF-8)`、总条目数 `n`
  （u64）、保留点 `r`（u64）、`B(checkpoint)`（与算法摘要等宽）、frontier
  子树计数（u64）与按**高度升序**的每对 `U(height) || B(digest)`（高度恰为
  `r` 的置位，子树覆盖 `[0, r)`）
- frontier 之后写 **nonce 历史**：先写计数（u64），再按**字典序**写每项
  `B(nonce)`（`B` 仍为 u64 大端长度前缀，每项内容须恰为 12 字节，严格升序
  即无重复）；集合必须包含每个保留密文的 nonce，并**完整保留裁剪前已用过
  的全部 nonce**（即使对应密文已被释放）
- 随后写保留条目计数（u64，恰为 `n - r`）与索引 `r..n-1` 的条目，每个条目
  复用 `dump_secure_log` 的 `E` 编码：`U(index) || B(payload) ||
  B(previous_hash) || B(entry_hash) || B(locator)`；`locator` 空 blob 为普通
  条目，非空须与摘要同宽且其密文封装必须能恢复 12 字节 nonce。末尾写
  `B(root) || B(head)`（完整 size-`n` 快照的 Merkle 根与链头），并追加覆盖
  此前全部字节的 **64 字节 Ed25519 签名**。`U` 为 8 字节无符号大端，
  `B(x) = U(len(x)) || x`，不允许省略、换序或附加字节
- `load_secure_pruned` **先验签**（对签名之前的全部字节用公钥校验末尾 64
  字节签名），通过后才解析并复核上述结构：要求 `0 < r <= n`、frontier 高度
  恰为 `r` 的置位、nonce 严格字典序且每项 12 字节、保留条目数恰为
  `n - r`、索引恰为 `r..n-1`；非空 locator 须与摘要等宽、密文封装合法且其
  nonce 必须在历史集合中且保留条目间不重复。随后按 `hash_name` 从检查点起
  逐条重算 `entry_digest` 链，链头必须等于 `head`，由 frontier 与保留条目
  重建的 Merkle 根必须等于 `root`，最后经正常 `append` / 加密条目恢复路径
  重放（`find` / `find_encrypted` 索引、nonce 历史、frontier、链头、长度与
  保留点随之重建）
- `dump_secure_pruned` 入参不是 `AuditLog` 或私钥不是 `bytes` 抛
  `TypeError`；私钥不是 32 字节，或日志未裁剪 / 带认证状态或历史抛
  `ValueError`
- `load_secure_pruned` 的 `data` 只接受 `bytes`（拒绝 `bytearray` /
  `memoryview`），两密钥均须为 32 字节 `bytes`；公钥类型错抛 `TypeError`；
  公钥非 32 字节，或魔数、版本、非法 UTF-8、未知 / 非固定输出算法、截断、
  尾随、保留点越界、检查点 / frontier / 摘要宽度不符、frontier 高度非 `r`
  的置位、nonce 宽度 / 顺序不符、保留密文 nonce 缺失或重复、locator 宽度、
  密文封装非法、条目数与 `n - r` 不符、索引顺序、断链、重算链头 / Merkle
  根不符、签名不符均抛 `ValueError`；失败为原子操作，旧接口行为不变

### 前向安全认证

构造日志时传入一个非空 `key` 即可开启前向安全认证；不传 `key` 的无密钥模式
行为与以前完全一致，认证接口禁用。每次 `auth()` 签发标签后立即以单向哈希演进
密钥并丢弃旧密钥，之后即使当前密钥泄露也无法伪造更早条目的标签：

```python
from auditchain import verify_auth

log = AuditLog(key=b"shared-secret")
log.append("agent started")
verifier = log.export_verifier()   # 首次演进前导出一次，交给验证方
tag0 = log.auth(0)                 # AuthTag(stage=0, tag=...)，随后密钥演进到 stage 1
log.append("position claim")
log.rotate_key()                   # 只演进密钥、不签发标签、不追加条目
tag1 = log.auth(1)                 # stage=2 的标签

verify_auth(log.entry(0), tag0, verifier)  # True：无需持有日志即可验证
verify_auth(log.entry(1), tag1, verifier)  # True
```

需要一次为多条保留记录准备认证材料时，用 `auth_batch(indices)` 批量签发：
`indices` 为互异非 `bool` 整数的可迭代对象，按绝对索引升序连续计算标签并一次
提交，返回 `((Entry, AuthTag), ...)`（空选择返回 `()`，不演进密钥）。第 j 项
使用初始 `stage+j`，逐项等于按升序连续调用 `auth`，成功恰演进所选条数次；
离线方用 `verify_auth_batch(items, verifier)` 批量核验，返回同序 `tuple[bool, ...]`：

```python
items = log.auth_batch([4, 1])                    # 升序签发索引 1、4
verify_auth_batch(items, verifier)               # (True, True)，空 tuple 返回 ()
```

- `export_verifier()` 只可在首次演进（`auth` / `rotate_key`）之前调用，且只能
  调用一次；返回的不可变 `Verifier(key, hash_name)` 内含 stage-0 密钥，
  `verify_auth` 会自行把它演进到标签所在 stage
- 标签为 `HMAC(K, b"auditchain/auth/v1" + stage 的 8 字节大端编码 + entry_hash,
  hash_name)`；密钥演进为 `H(b"auditchain/key-evolve/v1" + K)`
- 认证边界只接受 `bytes`：`key`（`AuditLog` / `Verifier`）与 `tag`（`AuthTag`）传入
  `bytearray`、`memoryview` 等均抛 `TypeError`，空 `key` 抛 `ValueError`；`stage`
  须为非 `bool` 整数且小于 `2**64`，类型非法抛 `TypeError`、越界抛 `ValueError`，
  `verify_auth` 在做任何校验之前先检查 `tag.stage`
- `auth` / `rotate_key` / `export_verifier` 失败（参数非法、状态非法等）不改变任何
  认证或日志状态
- 裁剪时同步删除已释放前缀的标签，保留段标签与后续演进不受影响

`auth_batch` 的结果可编码为规范字节形式落盘，跨进程恢复为同一不可变项元组后继续
由 `verify_auth_batch` 凭另行走带外信任通道的 `Verifier`（stage-0 密钥）离线核验；
字节流只含算法名与各项，**不含任何验证材料 / 密钥**，编解码均为只读、确定，旧认证
接口不变：

```python
from auditchain import encode_auth_batch, decode_auth_batch

data = encode_auth_batch(items)             # bytes，可写文件/发网络
hash_name, restored = decode_auth_batch(data)
hash_name                                   # "sha256"
restored == items                           # True：不可变 (Entry, AuthTag) 项元组相等
encode_auth_batch(restored) == data         # True：解码后重编码逐字节相同
verify_auth_batch(restored, verifier)       # (True, ...)：恢复后继续离线逐项核验
decode_auth_batch(encode_auth_batch(()))    # ("sha256", ())：空批次
```

- 签名为 `encode_auth_batch(items, *, hash_name="sha256") -> bytes`，`items` 只收
  既有 `auth_batch` 项元组 `tuple[tuple[Entry, AuthTag], ...]` 并复用其结构约束；
  `hash_name` 必须与签发日志及验证材料一致（默认 `"sha256"`，可任意固定输出长度算法）
- `decode_auth_batch(data) -> tuple[str, tuple[tuple[Entry, AuthTag], ...]]` 只收
  `bytes`（拒绝 `bytearray` / `memoryview`），返回算法名与不可变项元组（空批次为
  `()`），重编码逐字节相同
- 字节流以魔数 `b"auditchain/auth-batch/v1\0"` 开头，随后**严格依次**写 `version`
  （恒为 `1`，u64 大端）、`hash_name` 的 UTF-8 blob、项数（u64）与各项；整数均为
  u64 大端，blob 均为 u64 字节长度前缀加原始字节（零长度也写全零 u64）。各项依次写
  `index`（u64）、`payload` blob、`previous_hash` blob、`entry_hash` blob、
  `stage`（u64）、`tag` blob，不允许省略、换序或附加字节
- 容器或字段类型错抛 `TypeError`；魔数、版本、非法 UTF-8、未知或非固定输出算法、
  截断、尾随字节、blob 长度溢出、计数不符、u64 范围、摘要 / 标签宽度、索引顺序（须
  严格升序、无重复）或 stage 连续性（相邻项 stage 恰差 1，首项可非 0）错误均抛
  `ValueError`；结构合法但标签 / 条目不匹配仍可正常编解码，仅
  `verify_auth_batch` 在对应位置返回 `False`

#### 可信交付 stage-0 验证材料（Ed25519）

`export_verifier()` 给出的 stage-0 `Verifier` 本身不带来源证明：验证方需要另行走
带外信任通道确认它确实来自日志持有者。`export_signed_verifier(private_key)` 用持有
者按次提供的 32 字节 Ed25519 私钥种子为 stage-0 `Verifier` 签发一个不可变
`SignedVerifier`；接收方凭**预先信任**的 32 字节公钥即可离线确认验证材料的来源，
私钥从不落盘：

```python
from auditchain import verify_signed_verifier

log = AuditLog(key=b"shared-secret")
log.append("agent started")
receipt = log.export_signed_verifier(seed)        # 首次演进前、仅可导出一次
receipt.version                                  # 1
receipt.verifier.key == b"shared-secret"         # True：stage-0 验证材料
len(receipt.signature)                           # 64
verify_signed_verifier(receipt, public_key)      # True：来源可信
verify_signed_verifier(receipt, other_key)       # False：未信任的公钥

tag = log.auth(0)
verify_auth(log.entry(0), tag, receipt.verifier)  # True：交付的材料照常验证标签
```

签名**只认证来源、不加密**：`Verifier.key` 在回执中以明文携带，任何拿到回执的人都
能验证该日志此后任意 stage 的标签，调用方仍须像保护裸 `Verifier` 一样保护它。

- 回执为冻结的
  `SignedVerifier(version, verifier, signature)`，支持位置构造、按全部字段相等；
  `version` 恒为 `1`，`verifier` 为嵌套的不可变 `Verifier`（空 `key` 或未知算法
  在构造时即抛 `ValueError`），`signature` 只收恰好 64 字节的 `bytes`
- 签名原文依次为 `D || 0x01 || B(hash_name 的 UTF-8) || B(key)`，其中
  `D = b"auditchain/signed-verifier/v1\0"`，`U` 为 8 字节无符号大端整数，
  `B(x) = U(len(x)) || x`；Ed25519 对该消息确定性签名
- `export_signed_verifier(private_key)` 与 `export_verifier()` 共用同一份一次性
  导出资格：仅限带 `key` 的日志在 `stage == 0` 且尚未导出验证材料时调用，成功即消耗
  资格，此后两个导出接口都不可再用；无密钥模式、已演进或重复导出抛 `ValueError`。
  所有校验（含私钥种子）均在签名与消耗资格之前完成，**失败不消耗资格、不演进密钥、
  不改日志**
- `verify_signed_verifier(receipt, public_key)` 只凭回执与预信任公钥离线验真：
  重建同一签名原文并用公钥校验 64 字节签名。公钥不是对应签发方，或结构合法但
  `verifier` 的 `key` / `hash_name` 或 `signature` 被改，均返回 `False`
- 类型边界只接受 `bytes`：`private_key` / `public_key` 传入 `str` /
  `bytearray` / `memoryview` 等抛 `TypeError`；二者不是 32 字节、`version` 非 `1`、
  嵌套字段类型或宽度非法、空 `key`、未知摘要算法或 `signature` 不是 64 字节抛
  `ValueError`；验签入口为只读
- `encode_signed_verifier(receipt)` / `decode_signed_verifier(data)` 把回执序列化为
  规范二进制并原样还原，使 stage-0 验证材料可落盘、跨进程传输后继续凭预信任公钥
  由 `verify_signed_verifier` 离线验真：

```python
from auditchain import encode_signed_verifier, decode_signed_verifier

data = encode_signed_verifier(receipt)         # bytes，可写文件/发网络
restored = decode_signed_verifier(data)        # SignedVerifier，字段与原回执相等
restored == receipt                            # True
encode_signed_verifier(restored) == data       # True：重编码逐字节相同
verify_signed_verifier(restored, public_key)   # True：无需持有日志
```

  编码以魔数 `b"auditchain/signed-verifier/v1\0"` 开头，依次写 `version`（恒为
  `1`）、`hash_name` 的 UTF-8 blob、`verifier.key` blob、`signature` blob；所有
  整数为 8 字节无符号大端，每个 blob 为 u64 字节长度前缀加原始字节（零长度也是
  全零 u64）。编码只认证来源、**不加密**其中密钥，字节流须像裸 `Verifier` 一样
  保护。`encode_signed_verifier` 只接受 `SignedVerifier`、
  `decode_signed_verifier` 只接受 `bytes`（含拒绝 `bytearray` / `memoryview`），
  非对应类型或绕过构造器写入的字段类型错抛 `TypeError`；魔数、版本、UTF-8、未知
  算法、截断、尾随、blob 长度、空 `key` 或签名宽度非法抛 `ValueError`；结构合法
  但签名与字段不匹配仍可解码，`verify_signed_verifier` 返回 `False`。两个入口
  均为只读

#### 可信认证批次交付包（Ed25519）

`SignedVerifier` 解决"验证材料从哪来"，`auth_batch` 解决"批量签发"，但两者仍要
分别交付、分别核对。`SignedAuthBundle(verifier, hash_name, items)` 把已签名的
stage-0 验证材料与前向安全认证批次合并成**一个**不可变交付包：离线方只凭预置信任
的 32 字节 Ed25519 公钥先确认来源，再逐项核验标签，全程不持有日志、也不新增任何
签名原文（签名仍是 `SignedVerifier` 里那一份）：

```python
from auditchain import (
    SignedAuthBundle,
    decode_signed_auth_bundle,
    encode_signed_auth_bundle,
    verify_signed_auth_bundle,
)

log = AuditLog(key=b"shared-secret")
for record in ("a", "b", "c", "d"):
    log.append(record)
receipt = log.export_signed_verifier(seed)   # 已签名的 stage-0 验证材料
items = log.auth_batch([1, 3])               # 前向安全认证批次
bundle = SignedAuthBundle(receipt, log.hash_name, items)

data = encode_signed_auth_bundle(bundle)     # bytes，可写文件/发网络
restored = decode_signed_auth_bundle(data)   # 冻结 SignedAuthBundle，字段相等
restored == bundle                           # True
encode_signed_auth_bundle(restored) == data  # True：重编码逐字节相同
verify_signed_auth_bundle(restored, public_key)   # (True, True)：逐项核验
verify_signed_auth_bundle(restored, other_key)    # (False, False)：验签失败逐项 False
```

- 交付包为冻结的 `SignedAuthBundle(verifier, hash_name, items)`，支持位置构造、
  按全部三个字段相等；`verifier` 必须是 `SignedVerifier`，`hash_name` 必须是已知
  固定输出算法名，`items` 即 `auth_batch` 的结果元组（必须是 `tuple`）。容器字段
  类型错抛 `TypeError`；项内部的结构契约沿用 `verify_auth_batch`，构造器不重复
  校验
- `verify_signed_auth_bundle(bundle, public_key) -> tuple[bool, ...]` 完全离线：
  先用 `verify_signed_verifier` 以预信任公钥核验嵌套验证材料的签名，**验签失败
  逐项返回 `False`**（结果长度与 `items` 相同，空批次为 `()`）；验签成功且
  `bundle.hash_name` 与签名验证材料的算法一致时，复用 `verify_auth_batch` 以交付的
  `Verifier` 逐项核验标签。算法不一致同样逐项 `False`，绝不抛异常冒充结构错误。
  入参不是 `SignedAuthBundle`（含绕过构造器的容器字段类型错）或公钥不是 `bytes`
  抛 `TypeError`；公钥不是 32 字节或嵌套结构非法沿用 `verify_signed_verifier` /
  `verify_auth_batch` 的既有异常（`TypeError` / `ValueError`）；调用只读
- `encode_signed_auth_bundle(x)` / `decode_signed_auth_bundle(data)` 把交付包
  序列化为规范字节并原样还原，**不新增签名原文**：字节流为
  `D || U(1) || B(S) || B(A)`，其中 `D = b"auditchain/signed-auth-bundle/v1\0"`，
  `U` 为 8 字节无符号大端整数，`B(x) = U(len(x)) || x`（沿用 u64/blob 公开规则）；
  `S`、`A` 依次为既有 `encode_signed_verifier(verifier)` 与
  `encode_auth_batch(items, hash_name=hash_name)` 的完整规范字节，验证材料在前、
  认证批次在后，解码精确消费两个 blob 并禁止尾随字节，分别交给既有解码器
- 类型错抛 `TypeError`（`encode` 只接受 `SignedAuthBundle`，`decode` 只接受
  `bytes`，含拒绝 `bytearray` / `memoryview`）；公钥长度、魔数、版本、UTF-8、
  未知算法、截断、尾随、blob 长度、嵌套格式或**嵌套算法不一致**（批次算法与签名
  验证材料算法不符）抛 `ValueError`；签名或标签不匹配仍可正常解码，核验逐项
  `False`。验证密钥在字节流中明文携带（只认证来源、不加密），须像裸 `Verifier`
  一样保护；两个入口均只读且确定，旧接口不变

`SignedAuthBundle` 也可由日志**原子签发**：`AuditLog.signed_auth_bundle(indices,
private_key) -> SignedAuthBundle` 在一次调用内同时交付已签名的 stage-0 验证材料
与按绝对索引升序的前向安全标签，避免先 `export_signed_verifier` 再 `auth_batch`
分步执行留下"资格已消耗却未发标签"或"密钥已演进却无签名材料"的半提交状态：

```python
log = AuditLog(key=b"shared-secret")
for record in ("a", "b", "c", "d"):
    log.append(record)
bundle = log.signed_auth_bundle([3, 1], seed)   # 一次调用完成签发

# 等价于在同型 stage-0 日志上分步执行 export_signed_verifier + auth_batch
twin = AuditLog(key=b"shared-secret")
for record in ("a", "b", "c", "d"):
    twin.append(record)
stepwise = SignedAuthBundle(
    twin.export_signed_verifier(seed), twin.hash_name, twin.auth_batch([3, 1])
)
bundle == stepwise                             # True：签名与标签逐字节相同
verify_signed_auth_bundle(bundle, public_key)   # (True, True)：逐项核验
```

- `AuditLog.signed_auth_bundle(indices, private_key)` 与
  `export_signed_verifier` 共用同一份一次性导出资格：仅限带 `key` 的日志在
  `stage == 0` 且尚未导出验证材料时调用；成功即消耗资格，此后
  `export_verifier` / `export_signed_verifier` 均不可再用。`indices` 为互异非
  `bool` 整数的可迭代项（含生成器），允许空选择；返回的冻结包与手工组装的
  `SignedAuthBundle` 同型，`verifier` 即本次签发的 stage-0 材料，`hash_name`
  为日志算法，`items` 按绝对索引升序
- **不新增签名原文**：嵌套 `SignedVerifier` 的 Ed25519 签名逐字节复用
  `export_signed_verifier` 的签名原文
  （`D || 0x01 || B(hash_name 的 UTF-8) || B(key)`）；第 j 项（j 从 0 起）使用
  `stage == j`，HMAC、u64 大端 stage 与密钥演进顺序逐字节沿用 `auth_batch`，
  各项等于从初始密钥连续升序调用 `auth` 的结果，成功恰推进所选条数
- **空选择仍交付签名材料**：`items == ()`、验证照常离线验真，但 `stage` 保持
  `0`；导出资格同样被消耗，之后的 `auth_batch` 仍从 stage 0 起
- 所有校验（私钥、索引、重复、保留范围、stage 容量与导出资格）均在签名与任何
  状态变更之前完成：任何失败都**不消耗导出资格、不演进密钥，且不改标签、条目等
  日志状态**。`private_key` 或 `indices` 类型错、索引非整数或为 `bool` 抛
  `TypeError`；种子非 32 字节、索引重复、stage 容量不足、无密钥模式、已演进或
  重复导出抛 `ValueError`；非保留索引沿用 `auth_batch` 的 `IndexError`。成功不
  改哈希链、Merkle 根或搜索索引；既有接口及包编解码不变

#### 认证与批量审计合并交付包（Ed25519）

`SignedAuthBundle` 解决"认证标签 + stage-0 材料从哪来"，`SignedAuditBatch`
解决"选中条目属于哪个签名快照"，但两者仍要分别交付、分别核对。冻结的
`SignedAuthAuditBundle(auth, audit)` 把二者合并成**一个**不可变交付包：离线方
只凭预置信任的 32 字节 Ed25519 公钥，即可在同一凭据上既逐项核验前向安全标签、
又确认这些条目属于同一个已签名快照，全程不持有日志、也不新增任何签名原文：

```python
from auditchain import (
    SignedAuthAuditBundle,
    decode_signed_auth_audit_bundle,
    encode_signed_auth_audit_bundle,
    verify_signed_auth_audit_bundle,
)

log = AuditLog(key=b"shared-secret")
for record in ("a", "b", "c", "d", "e"):
    log.append(record)
bundle = log.signed_auth_audit_bundle([3, 1], seed)   # 一次调用完成签发

data = encode_signed_auth_audit_bundle(bundle)       # bytes，可写文件/发网络
restored = decode_signed_auth_audit_bundle(data)     # 冻结包，字段相等
restored == bundle                                   # True
encode_signed_auth_audit_bundle(restored) == data    # True：重编码逐字节相同
verify_signed_auth_audit_bundle(restored, public_key)  # True：单 bool 结论
```

- 交付包为冻结的 `SignedAuthAuditBundle(auth, audit)`，支持位置构造、按两个
  字段相等；`auth` 必须是 `SignedAuthBundle`，`audit` 必须是
  `SignedAuditBatch`，容器字段类型错抛 `TypeError`；两包内部的结构契约沿用
  各自的既有校验，构造器不重复校验
- `AuditLog.signed_auth_audit_bundle(indices, private_key, size=None)` 在一次
  调用内原子交付两半：`size` 默认当前长度；`indices` 为互异非 `bool` 整数，
  范围 `retain_from <= i < size`。审计半与 `signed_audit_batch` 一致——非空
  快照**自动并入末条**（索引 `size - 1`，即使未选），仅空快照（`size == 0`）
  允许空选择且审计无条目；认证半**只**对调用方选中的索引签标签，末条未选时
  不为其新增签名域。成功时认证半消耗一次性导出资格、stage 恰推进所选条数，
  审计半只读；两包签名逐字节复用既有签名原文
- 类型边界：`private_key` / `indices` / 索引 / `size` 类型错（非整数、为
  `bool`、不可迭代）抛 `TypeError`；索引重复、`size` 越界（不在
  `0..len(log)`）、快照不可重建、stage 容量不足、无密钥模式、已演进或重复
  导出抛 `ValueError`；索引越出保留快照范围抛 `IndexError`。所有校验在认证
  半签名与提交前完成，**失败原子**：不消耗导出资格、不演进密钥、不改标签与
  条目等任何日志状态
- `verify_signed_auth_audit_bundle(bundle, public_key) -> bool` 完全离线，要求
  全部成立才返回 `True`：① 嵌套 `SignedVerifier` 签名验真（空选择也显式
  验签，不会因零项空过），且 `verify_signed_auth_bundle` 逐项全为 `True`；
  ② `verify_signed_audit_batch` 验真（含证明、检查点签名与快照链接）；
  ③ 两包算法一致——认证包算法、其签名验证材料算法与审计批算法三者相同；
  ④ 认证包每个索引上的 `Entry` 与审计包同索引 `Entry` 逐字段相等（审计包
  通常另带末条，认证包无需为其签标签）。任一不成立返回 `False`；入参不是
  `SignedAuthAuditBundle` 抛 `TypeError`，嵌套结构非法与公钥长度错沿用既有
  `TypeError` / `ValueError`；调用只读
- `encode_signed_auth_audit_bundle(x)` / `decode_signed_auth_audit_bundle(data)`
  序列化并原样还原，**不新增签名原文**：字节流为
  `D || U(1) || B(A) || B(M)`，其中 `D = b"auditchain/auth-audit/v1\0"`，
  `U` 为 8 字节无符号大端整数，`B(x) = U(len(x)) || x`；`A`、`M` 依次为既有
  `encode_signed_auth_bundle(auth)` 与 `encode_signed_audit_batch(audit)` 的
  完整规范字节，认证包在前、审计包在后，解码精确消费两个 blob 并禁止尾随
  字节，分别交给既有解码器
- `encode` 只接受 `SignedAuthAuditBundle`，`decode` 只接受 `bytes`（含拒绝
  `bytearray` / `memoryview`），类型错抛 `TypeError`；魔数、版本、截断、
  尾随、blob 长度、嵌套格式或**两包算法冲突**抛 `ValueError`；签名或标签不
  匹配仍可正常解码，`verify_signed_auth_audit_bundle` 返回 `False`。两个入口
  均只读且确定，旧接口不变

#### 跨快照认证审计续接（Ed25519）

`SignedAuthAuditBundle` 证明"选中条目属于某个已签名快照"，
`SignedConsistency` 证明"新快照由旧快照只追加形成"，但两者仍要分别交付、
分别核对。冻结的
`SignedAuthAuditContinuation(bundle, consistency)` 把二者组合成**一个**
不可变续接凭据：离线方只凭预置信任的 32 字节 Ed25519 公钥，即可在同一凭据上
既逐项核验前向安全标签、确认选中条目属于新快照，又确认该新快照由一个更早日签名
快照只追加续接而来，全程不持有日志、也**不新增任何签名域**——一致性凭据的 `new`
检查点就是审计包检查点本身（全字段相等）：

```python
from auditchain import verify_signed_auth_audit_continuation

# old_size=3 的前缀续接到 size=5 的新快照；size 默认 len(log)
cont = log.signed_auth_audit_continuation(3, [4, 1], seed, size=5)
cont.consistency.old == log.sign_root(seed, 3)          # True：旧快照检查点
cont.consistency.new == cont.bundle.audit.checkpoint    # True：新检查点即审计检查点
cont.consistency.proof == log.consistency_proof(3, 5)   # True：逐字节相同
verify_signed_auth_audit_continuation(cont, public_key) # True：无需持有日志
verify_signed_auth_audit_continuation(cont, other_key)  # False：未信任的公钥
```

- 续接凭据为冻结的
  `SignedAuthAuditContinuation(bundle:SignedAuthAuditBundle,
  consistency:SignedConsistency)`，支持位置构造、按两个字段相等；`bundle`
  必须是 `SignedAuthAuditBundle`、`consistency` 必须是
  `SignedConsistency`，容器字段类型错抛 `TypeError`；两包内部的结构契约沿用
  各自的既有校验，构造器不重复校验
- `AuditLog.signed_auth_audit_continuation(old_size, indices, private_key,
  size=None)` 在一次调用内原子组合两半：`size` 默认当前日志长度；尺寸须为非
  `bool` 整数且满足 `0 <= old_size <= size <= len(log)`，两快照均可重建
  （已剪枝的前缀抛 `ValueError`）；`indices` 为互异非 `bool` 整数，范围
  `retain_from <= i < size`，**空选择允许**。审计半与
  `signed_auth_audit_bundle` 一致——非空快照自动并入末条（索引 `size - 1`），
  认证半只对调用方选中索引签标签；一致性半只读，其 `new` 检查点即审计检查点。
  所有校验（尺寸链、两快照可重建、索引、密钥、stage 容量与一次性导出资格）在
  认证半签名与提交前完成，**失败原子**：不消耗导出资格、不演进密钥、不改标签与
  条目等任何日志状态；成功时认证半消耗一次性导出资格、stage 恰推进所选条数
- 尺寸、容器、索引或密钥类型错（非整数、为 `bool`、不可迭代、密钥非 `bytes`）
  抛 `TypeError`；索引重复、密钥非 32 字节、尺寸越界/快照不可重建、stage 容量
  不足或导出资格不满足抛 `ValueError`；索引越出保留快照范围抛 `IndexError`
- `verify_signed_auth_audit_continuation(receipt, public_key) -> bool` 完全
  离线：先用 `verify_signed_auth_audit_bundle` 完整核验认证审计包（签名验证
  材料、逐项标签、批量包含证明、审计检查点签名与同索引 `Entry` 一致），再用
  `verify_signed_consistency` 完整核验一致性包（两个检查点签名与 Merkle 一致性
  证明），最后要求两包算法一致且一致性凭据的 `new` 检查点与审计检查点**全字段
  相等**（含签名本身）。任一不成立返回 `False`（绝不抛异常）；入参不是
  `SignedAuthAuditContinuation`（含绕过冻结构造器写入的容器字段类型错）抛
  `TypeError`，嵌套结构非法与公钥长度错沿用既有 `TypeError` / `ValueError`；
  调用只读，旧接口不变
- `encode_signed_auth_audit_continuation(receipt)` /
  `decode_signed_auth_audit_continuation(data)` 把整个跨快照续接凭据序列化为
  只读、确定的规范二进制并原样还原，使续接凭据可落盘、跨进程恢复后继续凭预置
  信任的 Ed25519 公钥离线验真，且不引入任何新的签名域：

```python
from auditchain import (
    decode_signed_auth_audit_continuation,
    encode_signed_auth_audit_continuation,
)

data = encode_signed_auth_audit_continuation(cont)       # bytes，可写文件/发网络
restored = decode_signed_auth_audit_continuation(data)  # 冻结续接凭据
restored == cont                                        # True：字段相等
encode_signed_auth_audit_continuation(restored) == data # True：重编码逐字节相同
verify_signed_auth_audit_continuation(restored, public_key)  # True：无需持有日志
```

  字节流严格为 `D || U(1) || B(A) || B(C)`，其中
  `D = b"auditchain/auth-audit-continuation/v1\0"`，`U` 为 8 字节无符号大端
  整数，`B(x) = U(len(x)) || x`；`A` 须逐字节等于
  `encode_signed_auth_audit_bundle(bundle)` 的完整输出，`C` 为
  `encode_signed_consistency(consistency)` 的完整输出，顺序固定为认证审计包在
  前、一致性凭据在后，解码精确消费两个 blob 且**禁止尾随字节**，分别原样交给
  `decode_signed_auth_audit_bundle` 与 `decode_signed_consistency`，嵌套异常
  沿用对应既有编解码器。`encode_signed_auth_audit_continuation` 只接受
  `SignedAuthAuditContinuation`（其余类型抛 `TypeError`，含绕过冻结构造器写入
  的字段类型错），`decode_signed_auth_audit_continuation` 只接受 `bytes`
  （含拒绝 `bytearray` / `memoryview`）；魔数、版本、截断、长度、嵌套格式或
  尾随非法均抛 `ValueError`；编解码不校验签名、标签、证明内容及 `new` 检查点
  与审计检查点的关联，结构合法但验真不匹配仍可解码，
  `verify_signed_auth_audit_continuation` 返回 `False`；冻结
  `SignedAuthAuditContinuation(bundle, consistency)` 仍按字段相等，保留位置
  构造及字段顺序，旧接口和签名域不变

#### 连续只追加历史的续接链离线核验（Ed25519）

单个 `SignedAuthAuditContinuation` 只证明"一个旧快照只追加续接到一个新快照"。
顶层 `verify_continuation_chain(receipts, public_key) -> bool` 接收一个**非空
tuple** 的既有冻结续接凭据（保持调用方给定顺序），离线核验它们描述的是同一条
连续只追加历史，全程只读、不持有日志，也**不新增任何签名域**：

```python
from auditchain import verify_continuation_chain

# 三段：size 0 → 2 → 5 → 8；每段由同一日志内容在同一预置密钥下签发
chain = (
    log0.signed_auth_audit_continuation(0, (), seed, size=2),
    log1.signed_auth_audit_continuation(2, (), seed, size=5),
    log2.signed_auth_audit_continuation(5, (), seed, size=8),
)
verify_continuation_chain(chain, public_key)       # True
verify_continuation_chain(chain, other_public_key) # False：未信任的公钥
```

- 首参只收非空 `tuple`：非 `tuple`（含 list、生成器、`None`）抛 `TypeError`，
  空 tuple 抛 `ValueError`；元素必须均为 `SignedAuthAuditContinuation`，否则抛
  `TypeError`。逐项调用 `verify_signed_auth_audit_continuation`，任一项返回
  `False`（或嵌套结构非法按既有规则抛 `TypeError` / `ValueError`，公钥长度错
  抛 `ValueError`、非 `bytes` 抛 `TypeError`）整体即不成立
- 每段还须满足 `consistency.old.size < consistency.new.size`（等长段不描述任何
  追加）；相邻两段要求前段 `consistency.new` 与后段 `consistency.old` **全字段
  相等**（`version`、`hash_name`、`size`、`root`、`head` 及 Ed25519 签名本身）；
  tuple 中出现重复段（含非相邻的重复凭据）返回 `False`。任一关系不符返回
  `False`，调用只读，旧接口不变
- `encode_continuations(receipts) -> bytes` /
  `decode_continuations(data) -> tuple` 把整条续接链序列化为只读、确定的规范
  二进制并按凭据 tuple 的原有顺序原样还原：

```python
from auditchain import decode_continuations, encode_continuations

data = encode_continuations(chain)        # bytes，可写文件/发网络
restored = decode_continuations(data)     # tuple，顺序与逐字段均不变
restored == chain                         # True
encode_continuations(restored) == data    # True：重编码逐字节相同
verify_continuation_chain(restored, public_key)  # True：无需持有日志
```

  字节流严格为 `D || U(1) || U(n) || B(R1) … B(Rn)`，其中
  `D = b"auditchain/cont-chain/v1\0"`，`U` 为 8 字节无符号大端整数，
  `B(x) = U(len(x)) || x`，`n` 为非零凭据计数；每个 `Ri` 须逐字节等于既有
  `encode_signed_auth_audit_continuation(receipt_i)` 的完整输出，按 tuple 顺序
  排列。解码精确消费全部 `Ri` 与所有外层字节、**禁止尾随字节**，每个 blob 原样
  交给 `decode_signed_auth_audit_continuation`，嵌套异常沿用既有解码器。
  `encode_continuations` 只收非空 `SignedAuthAuditContinuation` tuple（非 tuple
  或元素类型错抛 `TypeError`，空 tuple 抛 `ValueError`），`decode_continuations`
  只接受 `bytes`（拒绝 `bytearray` / `memoryview`）；魔数、版本、零计数、截断、
  长度、嵌套格式或尾随非法均抛 `ValueError`；编解码不校验签名、证明及相邻段
  关联，结构合法但验真不匹配仍可解码，由 `verify_continuation_chain` 返回
  `False`；两个入口均只读且确定，旧接口和签名域不变

#### 续接链只读诊断：定位首个失败段或断裂边界（Ed25519）

`verify_continuation_chain` 只回答“整条链是否成立”。顶层
`inspect_continuation_chain(receipts, public_key) -> ContinuationChainReport`
是它的**只读诊断对应物**：同样全程离线、不持有日志、不新增任何 Ed25519 或
HMAC 签名域、不修改凭据，但返回冻结报告以**定位首个失败段或断裂边界**——有效
链返回成功报告，且永远只报告最早出现的那一个问题：

```python
from auditchain import ContinuationChainReport, inspect_continuation_chain

inspect_continuation_chain(chain, public_key)
# ContinuationChainReport(ok=True, index=None, code=None)

inspect_continuation_chain(chain, other_public_key)
# ContinuationChainReport(ok=False, index=0, code='verify')
```

- 冻结报告 `ContinuationChainReport(ok:bool, index:int|None, code:str|None)`
  支持位置构造、按全部三个字段相等（可哈希）；成功报告恒为
  `(True, None, None)`。未知 `code` 抛 `ValueError`；失败报告必须同时携带
  合法的 `index` 与 `code`，成功报告的 `index`、`code` 必须均为 `None`
  （类型/取值不符按既有冻结报告风格抛 `TypeError` / `ValueError`）
- 诊断按 tuple 顺序、分两阶段进行。第一阶段逐段调用既有
  `verify_signed_auth_audit_continuation`：验真失败在该段位置报 `"verify"`
  （签名、标签或证明不匹配是报告而非异常）；该段
  `consistency.old.size >= consistency.new.size`（等长段不描述任何追加）报
  `"growth"`，`index` 即本段位置
- 仅当每一段都单独成立且严格增长后才进入第二阶段，比较段间关系：出现与更早
  凭据完全相等的重复段报 `"duplicate"`；前段 `consistency.new` 与本段
  `consistency.old` 未按全部字段（`version`、`hash_name`、`size`、`root`、
  `head` 及 Ed25519 签名本身）相等则报 `"link"`。二者 `index` 均取**本段**
  位置；`"link"` 只标识两段之间的边界、不归责其中任何一段
- 首参只收非空 `tuple` 的 `SignedAuthAuditContinuation`：非 `tuple`（含
  list、生成器、`None`）抛 `TypeError`，空 tuple 抛 `ValueError`，元素类型
  错抛 `TypeError`；`public_key` 须为恰好 32 字节 `bytes`：非 `bytes`（含
  `bytearray`）抛 `TypeError`，长度不符抛 `ValueError`。结构非法的凭据令
  嵌套核验按既有规则抛出的 `TypeError` / `ValueError` **原样传播**，不会变成
  `"verify"` 报告。调用只读、确定，既有核验与编解码接口、签名域均不变

#### 续接链端点锚定诊断：确认链恰从期望旧快照延伸到期望新快照（Ed25519）

`inspect_continuation_chain` 只回答“链内部是否连续”。顶层
`inspect_anchors(receipts, key, start, end) -> ContinuationChainReport`
是其**端点锚定扩展**：离线方仅凭预置信任公钥与两个期望 `SignedRoot`
检查点，即可确认这条链不仅内部连续，而且**恰好**从期望旧快照延伸到期望新
快照——被截去前缀、截去后缀或整体替换的**有效子链**都会被定位而非被接受。
四个参数均无默认值；调用同样全程离线、只读、不新增任何签名域：

```python
from auditchain import ContinuationChainReport, inspect_anchors

inspect_anchors(chain, key, start, end)
# ContinuationChainReport(ok=True, index=None, code=None)

inspect_anchors(chain[1:], key, start, end)
# ContinuationChainReport(ok=False, index=0, code='start')   # 截去前缀

inspect_anchors(chain[:-1], key, start, end)
# ContinuationChainReport(ok=False, index=len(chain)-2, code='end')  # 截去后缀
```

- 先委托 `inspect_continuation_chain(receipts, key)` 做内部诊断，
  失败报告**原样返回**——`"verify"`、`"growth"`、`"duplicate"`、`"link"`
  四类首错顺序不变，内部不成立的链绝不会被改报为锚点不符
- 仅当内部报告成功才比较锚点，且**起点优先于终点**：首段
  `consistency.old` 不等于 `start` 报 `"start"`（`index` 取 `0`）；末段
  `consistency.new` 不等于 `end` 报 `"end"`（`index` 取末段位置）
- 端点按 `SignedRoot` 全六字段（`version`、`hash_name`、`size`、`root`、
  `head` 及 Ed25519 `signature`）全等比较：尺寸相同但历史或签名者不同的
  检查点不算匹配。两端均锚定的内部连续链返回 `(True, None, None)`
- 报告仍为冻结三字段 `ContinuationChainReport(ok, index, code)`，构造与
  相等规则不变，仅合法码集合新增 `"start"`、`"end"` 两个（仅由
  `inspect_anchors` 报告）
- 调用前校验：非 `tuple` 链、非 `SignedAuthAuditContinuation` 元素、非
  `bytes` 公钥或非 `SignedRoot` 锚点抛 `TypeError`；空链或公钥非 32 字节
  抛 `ValueError`；结构非法凭据的嵌套异常沿用既有规则原样传播。既有核验
  与编解码接口、签名域均不变

#### 锚定续接链持久化：续接凭据与首尾锚点一并保存、跨进程恢复

冻结包 `AnchoredContinuationChain(receipts:tuple, start:SignedRoot,
end:SignedRoot)` 把非空续接凭据 tuple 与其两个端点 `SignedRoot`
（首段 `consistency.old` 应对的 `start`、末段 `consistency.new` 应对的
`end`）绑为一件可持久化制品，支持位置/关键字构造、按全部三个字段相等
（可哈希）；容器或字段类型错抛 `TypeError`，空链抛 `ValueError`，但包
本身不校验链是否内部连续、是否真锚定于两端。顶层
`inspect_anchored_continuations(bundle, key) -> ContinuationChainReport`
是它的只读诊断入口，等价于 `inspect_anchors(bundle.receipts, key,
bundle.start, bundle.end)`：离线、不新增签名域、码集合与首错顺序完全
沿用 `inspect_anchors`，`bundle` 非 `AnchoredContinuationChain` 抛
`TypeError`，其余校验与嵌套异常原样传播。

```python
from auditchain import (
    AnchoredContinuationChain,
    encode_anchored_continuations,
    decode_anchored_continuations,
    inspect_anchored_continuations,
)

bundle = AnchoredContinuationChain(chain, start, end)
data = encode_anchored_continuations(bundle)   # bytes，可写文件/发网络
restored = decode_anchored_continuations(data)  # 另一进程中恢复
restored == bundle                              # True：三字段逐字段相等
encode_anchored_continuations(restored) == data # True：重编码逐字节相同
inspect_anchored_continuations(restored, key)
# ContinuationChainReport(ok=True, index=None, code=None)
```

- 字节流严格为 `D || U(1) || B(C) || B(S) || B(E)`，其中
  `D = b"auditchain/anchor/v1\0"`，`U` 为 8 字节无符号大端整数，
  `B(x) = U(len(x)) || x`；`C` 逐字节等于既有
  `encode_continuations(receipts)` 的完整输出，`S`/`E` 分别逐字节等于
  `encode_signed_root(start)` / `encode_signed_root(end)` 的完整输出，
  按 tuple 顺序排列、**禁止尾随字节**。外层帧不引入任何新签名域
- `encode_anchored_continuations(bundle)` 只接受
  `AnchoredContinuationChain`（否则抛 `TypeError`）；`C`/`S`/`E` 均由既有
  编码器原样产出，嵌套结构问题的 `TypeError` / `ValueError` 原样传播；
  编码只读、确定
- `decode_anchored_continuations(data) -> AnchoredContinuationChain` 只
  接受 `bytes`（拒绝 `bytearray` / `memoryview`，抛 `TypeError`）；魔数、
  版本错、截断、blob 长度越界或尾随字节抛 `ValueError`，链 blob 与两个
  锚点 blob 分别交给 `decode_continuations` / `decode_signed_root`，嵌套
  异常原样传播。解码不校验签名、证明、段间相邻与锚定关系，结构合法但
  验真不匹配仍可解码，由 `inspect_anchored_continuations` 报告而非抛出

#### 多包锚定续接链的按序核验与合并：分批落盘后拼回单一制品

同一条续接链若分多批落盘、每批各自保存为一个
`AnchoredContinuationChain`，离线方可仅凭预置信任公钥，在**不持有日志、
不新增任何签名域**的前提下，按 tuple 顺序把这些包核验为一条链并合并回
单一可持久化制品。顶层
`inspect_anchor_set(items, key) -> ContinuationChainReport`
负责按序诊断，只报最早问题，全部成立返回 `(True, None, None)`：

- **逐包诊断**：按包序对每个包调用
  `inspect_anchored_continuations(item, key)`；失败报告码不变
  （`"verify"`、`"growth"`、`"duplicate"`、`"link"`、`"start"`、
  `"end"`），其 `index` 为**包内位置加此前各包凭据总数**，即该凭据在
  拼接待建链中的全局位置，而非包内位置
- **跨包相邻检查**：仅当每个包自身都成立后，才按包序比较相邻两包——
  前包 `end` 与后包 `start` 须按 `SignedRoot` 全六字段（`version`、
  `hash_name`、`size`、`root`、`head` 及 Ed25519 `signature`）全等；
  不符报新码 `"anchor_link"`，`index` 取**后包首凭据的全局位置**。该码
  同样只标识包间边界、不归责任何一包；仅当每处边界都锚点全等时拼接才
  无缺口、无重叠、无历史切换

```python
from auditchain import inspect_anchor_set, merge_anchor_set

inspect_anchor_set(packages, key)
# ContinuationChainReport(ok=True, index=None, code=None)

merged = merge_anchor_set(packages, key)   # 新的冻结 AnchoredContinuationChain
merged.start == packages[0].start          # 端点取首包 start
merged.end   == packages[-1].end           # 与末包 end
merged.receipts == tuple(                  # 按包序、包内序拼接全部凭据
    r for item in packages for r in item.receipts
)
```

- 顶层 `merge_anchor_set(items, key) -> AnchoredContinuationChain`
  仅在上述诊断**成功**时返回一个**新冻结对象**：receipts 按包序、包内序
  拼接，端点取首包 `start` 与末包 `end`；合并结果沿用既有的
  `encode_anchored_continuations`，**不设新格式、不新增签名域**。诊断
  失败（包内不成立或跨包锚点不符）抛 `ValueError`，绝不返回半成品；
  调用只读，不修改也不重建任何输入包
- 报告仍为冻结三字段 `ContinuationChainReport(ok, index, code)`，构造与
  相等规则不变，仅合法码集合新增 `"anchor_link"`（仅由
  `inspect_anchor_set` 报告）；旧接口与既有各码均不变
- 调用前校验：`items` 须为 `AnchoredContinuationChain` 的非空 tuple，
  非 tuple（含 list、生成器、`None`）或元素类型错抛 `TypeError`，空集
  抛 `ValueError`；`key` 须为恰好 32 字节 `bytes`，非 `bytes`（含
  `bytearray`）抛 `TypeError`，长度不符抛 `ValueError`；诊断中的嵌套
  结构异常按既有规则原样传播（`TypeError` / `ValueError`）

### 认证日志的加密导出与恢复（AES-256-GCM）

`dump_auth(log, key, nonce=None)` 与 `load_auth(data, key)` 为**构造时带
`key` 的前向安全认证日志**提供对称加密的状态导出，使日志进程重启后能从完全
相同的演进点继续前向安全认证。与 Ed25519 签名的各 `dump_*` 不同，导出用按次
传入的 32 字节对称密钥做 AES-256-GCM 密封，字节流不携带明文；仅接受
**未裁剪、无 `encrypt` 历史、构造时带 `key`** 的日志。恢复出的日志独立、可变，
长度、链头、Merkle 根、`find` 索引与 `stage` 均与原日志一致：

```python
import os
from auditchain import AuditLog, dump_auth, load_auth, verify_auth

key = os.urandom(32)                # 密封用对称密钥，必须是 32 字节 bytes
log = AuditLog(key=b"shared-secret")
verifier = log.export_verifier()
log.append("agent started")
tag0 = log.auth(0)                    # stage 推进到 1
data = dump_auth(log, key)            # key 必须是 32 字节 bytes；nonce=None 随机 12 字节
restored = load_auth(data, key)       # 全新、独立、可变的带密钥 AuditLog
restored.head == log.head             # True：链头一致
restored.merkle_root() == log.merkle_root()  # True：Merkle 根一致
restored.find(b"agent started")       # (0,)：find 索引已重建
restored.stage == log.stage           # True：演进 stage 一致
log.append("after restart")
restored.append("after restart")
restored.auth(1) == log.auth(1)       # True：重启后继续演进，标签逐字节相同
verify_auth(restored.entry(0), tag0, verifier)  # True：旧验证材料仍可核验
```

- 字节流为 `D || 0x01 || N || C`，其中 `D = b"auditchain/auth-log/v1\0"`，
  `0x01` 为单字节算法号（AES-256-GCM），`N` 为 12 字节 nonce，`C` 是明文帧
  `P` 的 AESGCM 输出（`ciphertext || 16 字节 tag`）；AEAD 的 AAD 为
  `D || 0x01 || N`，把密文绑定到魔数、算法号与 nonce
- 明文帧为
  `P = B(h) || U(n) || E1…En || B(root) || B(head) || U(stage) ||
  B(K) || U(x)`：`h` 是 `hash_name` 的 UTF-8 编码，`n` 为条目数，`root` /
  `head` 为 size-`n` 快照的 Merkle 根与链头，`stage` 为当前演进 stage，`K`
  为当前演进密钥（stage 0 时即构造密钥，可任意非空长度；演进后为摘要等宽），
  `x` 为验证材料已导出标志（以 u64 编码，值为 `0` 或 `1`；恢复后
  `export_verifier` 的一次性约束随之还原）
- 每个 `E` 按 `Entry(index, payload, previous_hash, entry_hash)` 的字段序
  依次以 `U, B, B, B` 编码；整数为 8 字节无符号大端（`U`），
  `B(x) = U(len(x)) || x`；条目索引须恰为 `0..n-1`
- 加载先做 GCM 解密与认证（错误密钥或任何篡改均失败），再按 `h` 指定的
  算法与摘要宽度从创世零摘要逐条重算 `entry_digest` 链头并重建 Merkle 根，
  二者必须与 `head` / `root` 匹配；最后经正常 `append` 路径重放，并装入
  `K`、`stage` 与标志，失败不产生半成品日志
- `key` 须为 32 字节 `bytes`；`nonce=None` 时用 `os.urandom(12)`，显式
  nonce 须为 12 字节 `bytes`，同 key 复用由调用方避免。`log` 不是
  `AuditLog`、`key` / `nonce` / `data` 类型错（`data` 拒绝 `bytearray` /
  `memoryview`）抛 `TypeError`；密钥长度、nonce 长度、资格不符（已裁剪、
  构造时无 `key`、含 `encrypt` 历史）、魔数 / 算法号、截断、尾随字节、
  非法 UTF-8 / 未知算法、摘要宽度、索引顺序、`stage` / 标志范围、演进密钥
  为空或宽度不符、AEAD 认证失败或重算链 / 根不符均抛 `ValueError`
- 导出只读；恢复对象与调用方缓冲区不共享任何状态，可继续 `append`、
  `auth`、`rotate_key` 等全部既有操作；字节流不含任何标签或验证材料

### 已裁剪认证日志的加密导出与恢复（AES-256-GCM）

`dump_pruned_auth(log, key, nonce=None)` 与
`load_pruned_auth(data, key)` 是 `dump_auth` / `load_auth` 的已裁剪版本：
为**构造时带 `key`、已裁剪（`retain_from > 0`）且无 `encrypt` 历史**的前向
安全认证日志提供对称加密的状态导出，使日志进程在裁剪后重启仍能从完全相同的
演进点继续前向安全认证。同样用按次传入的 32 字节对称密钥做 AES-256-GCM
密封，字节流不携带明文；恢复出的日志独立、可变，长度、绝对索引、
`retain_from`、链头、Merkle 根、包含证明、`find` 索引与 `stage` 均与原日志
一致：

```python
import os
from auditchain import AuditLog, dump_pruned_auth, load_pruned_auth, verify_auth

log = AuditLog(key=b"shared-secret")
verifier = log.export_verifier()
key = os.urandom(32)                   # 密封用对称密钥，必须是 32 字节 bytes
for record in ("a", "b", "c", "d", "e"):
    log.append(record)
log.prune(3, log.seal(3))              # 释放前 3 条，retain_from == 3
tag4 = log.auth(4)                     # 保留段条目仍可签标签，stage 推进到 1
data = dump_pruned_auth(log, key)      # nonce=None 随机 12 字节
restored = load_pruned_auth(data, key)  # 全新、独立、可变的带密钥 AuditLog
restored.retain_from == 3              # True：保留点一致
restored.head == log.head              # True：链头一致
restored.merkle_root() == log.merkle_root()  # True：Merkle 根一致
restored.inclusion_proof(4) == log.inclusion_proof(4)  # True：证明一致
restored.find(b"d")                    # (3,)：find 索引已重建
restored.stage == log.stage            # True：演进 stage 一致
verify_auth(restored.entry(4), tag4, verifier)  # True：旧验证材料仍可核验
restored.append("f")
restored.auth(5)                       # 重启后继续演进
```

- 字节流为 `D || 0x01 || N || C`，其中
  `D = b"auditchain/pruned-auth/v1\0"`，`0x01` 为单字节算法号
  （AES-256-GCM），`N` 为 12 字节 nonce，`C` 是明文帧 `P` 的 AESGCM 输出
  （`ciphertext || 16 字节 tag`）；AEAD 的 AAD 为 `D || 0x01 || N`
- 明文帧严格依次为
  `P = B(hash_name) || U(n) || U(r) || B(checkpoint) || F || E ||
  B(root) || B(head) || U(stage) || B(K) || U(x)`：`n` 为总条目数，`r` 为
  保留点（`0 < r <= n`），`checkpoint` 为前 `r` 条末条的链摘要（与算法
  摘要等宽）；`U` 为 8 字节无符号大端（`U`），`B(x) = U(len(x)) || x`
- `F` 先写 u64 子树计数，再按**高度升序**逐对写 `U(height) || B(digest)`，
  高度恰为 `r` 的置位（子树覆盖 `[0, r)`），与 `dump_pruned_log` 的
  frontier 编码一致
- `E` 先写 u64 保留条目计数（恰为 `n - r`），再按索引 `r..n-1` 顺序写各
  Entry，字段编码沿用 `dump_auth` / `dump_pruned_log`：
  `U(index) || B(payload) || B(previous_hash) || B(entry_hash)`
- `root` / `head` 为完整 size-`n` 快照的 Merkle 根与链头，`stage` 为当前
  演进 stage，`K` 为当前演进密钥（stage 0 时即构造密钥，可任意非空长度；
  演进后为摘要等宽），`x` 为验证材料已导出标志（以 u64 编码，值为 `0`
  或 `1`，恢复后 `export_verifier` 的一次性约束随之还原）
- 加载**先做 GCM 解密与认证**（错误密钥或任何篡改均失败），再按
  `hash_name` 指定的算法与摘要宽度复核：`0 < r <= n`、`checkpoint` 宽度、
  frontier 高度恰为 `r` 的置位、保留条目数恰为 `n - r` 且索引恰为
  `r..n-1`；随后从检查点起逐条重算 `entry_digest` 链头并由 frontier 与保留
  条目重建 Merkle 根，二者必须与 `head` / `root` 匹配；最后经正常
  `append` 路径重放并装入 `K`、`stage` 与标志，失败不产生半成品日志
- `key` 须为 32 字节 `bytes`；`nonce=None` 时用 `os.urandom(12)`，显式
  nonce 须为 12 字节 `bytes`，同 key 复用由调用方避免。`log` 不是
  `AuditLog`、`key` / `nonce` / `data` 类型错（`data` 拒绝 `bytearray` /
  `memoryview`）抛 `TypeError`；密钥长度、nonce 长度、资格不符（未裁剪、
  构造时无 `key`、含 `encrypt` 历史）、魔数 / 算法号、截断、尾随字节、
  非法 UTF-8 / 未知算法、摘要宽度、保留点越界、frontier 结构、条目数 /
  索引顺序、断链、`stage` / 标志范围、演进密钥为空或宽度不符、AEAD 认证
  失败或重算链 / 根不符均抛 `ValueError`
- 导出只读；恢复对象与调用方缓冲区不共享任何状态，可继续 `append`、
  `auth`、`rotate_key`、再次裁剪等全部既有操作；字节流不含任何裁剪回执、
  标签或验证材料；失败原子，旧接口不变

裁剪只释放内容、不改变逻辑：

- `len(log)` 仍是累计条数；索引始终为绝对值（下一条仍接在原末尾之后）；`head`、`append`
  产生的新 `Entry` 与从未裁剪的日志逐字节相同
- `entries()` 与迭代只列出保留段；`entry(i)` / `verify_entry(i)` 访问已裁剪索引抛 `IndexError`，
  `inclusion_proof(i, …)` 对已裁剪索引抛 `ValueError`
- `verify()` 从创世摘要（裁剪后从检查点）开始校验持有的链段；需要定位具体问题时用
  `verify_report()`，它返回不可变 `IntegrityReport`，按期望绝对索引升序列出每条不匹配，
  并在末尾核对链头（重写最后一条也无法蒙混过关）
- 保留点及之后任意快照的 `merkle_root`、`inclusion_proof`、`consistency_proof`
  重建结果与未裁剪日志相同；完全落在已裁剪前缀内的快照无法重建，抛 `ValueError`
  （空快照 `size=0` 是内容无关常量，始终可用）
- 裁剪依据是检查点链摘要与一棵覆盖已封存前缀的 Merkle frontier；不引入任何第三方依赖

### 带认证且含密文日志的混合加密导出与恢复（AES-256-GCM）

`dump_hybrid(log, key, nonce=None)` 与 `load_hybrid(data, key)` 是
`dump_auth` / `load_auth` 与 `dump_secure_log` / `load_secure_log` 的混合：
为**构造时带 `key`、未裁剪且允许 `encrypt` 历史**的前向安全认证日志提供对称
加密的状态导出。导出用按次传入的 32 字节对称密钥做 AES-256-GCM 密封，字节流
不携带明文；明文帧同时携带认证演进状态（演进密钥、`stage`、导出标志）与加密
支持结构（每条密文的 locator HMAC、完整 nonce 历史），恢复出的日志独立、可变，
长度、链头、Merkle 根、`find` / `find_encrypted` 索引、nonce 历史与 `stage`
均与原日志一致，重启后从完全相同的演进点继续前向安全认证：

```python
import os
from auditchain import AuditLog, dump_hybrid, load_hybrid, verify_auth

key = os.urandom(32)                 # 密封用对称密钥，必须是 32 字节 bytes
enc_key = os.urandom(32)             # encrypt 用密钥，按次传入、不落盘
log = AuditLog(key=b"shared-secret")
verifier = log.export_verifier()
log.append("plain event")
log.encrypt("secret event", enc_key)
tag1 = log.auth(1)                    # stage 推进到 1
data = dump_hybrid(log, key)          # nonce=None 随机 12 字节
restored = load_hybrid(data, key)     # 全新、独立、可变的带密钥 AuditLog
restored.head == log.head             # True：链头一致
restored.merkle_root() == log.merkle_root()  # True：Merkle 根一致
restored.find(b"plain event")         # (0,)：find 索引已重建
restored.find_encrypted("secret event", enc_key)  # (1,)：密文定位索引已重建
restored.stage == log.stage           # True：演进 stage 一致
log.append("after restart")
restored.append("after restart")
restored.auth(2) == log.auth(2)       # True：重启后继续演进，标签逐字节相同
verify_auth(restored.entry(1), tag1, verifier)  # True：旧验证材料仍可核验
```

- 字节流为 `D || 0x01 || N || C`，其中 `D = b"auditchain/hybrid/v1\0"`，
  `0x01` 为单字节算法号（AES-256-GCM），`N` 为 12 字节 nonce，`C` 是明文帧
  `P` 的 AESGCM 输出（`ciphertext || 16 字节 tag`）；AEAD 的 AAD 为
  `D || 0x01 || N`，把密文绑定到魔数、算法号与 nonce
- 明文帧严格依次为
  `P = B(h) || U(q) || B(nonce1)…B(nonceq) || U(n) || E1…En ||
  B(root) || B(head) || U(stage) || B(K) || U(x)`：`h` 是 `hash_name` 的
  UTF-8 编码；`q` 为该日志 `encrypt` 历史使用过的 nonce 个数，随后按
  **字典序**逐个写 12 字节的 `B(nonce)`；`n` 为条目数；`root` / `head` 为
  size-`n` 快照的 Merkle 根与链头；`stage` 为当前演进 stage；`K` 为当前演进
  密钥（stage 0 时即构造密钥，可任意非空长度；演进后为摘要等宽）；`x` 为
  验证材料已导出标志（以 u64 编码，值为 `0` 或 `1`）。`U` 为 8 字节无符号
  大端，`B(v) = U(len(v)) || v`
- 每个 `E` 严格复用 `dump_secure_log` 的记录编码与 locator 判型：
  `U(index) || B(payload) || B(previous_hash) || B(entry_hash) ||
  B(locator)`；空 locator blob 表示普通条目，非空 locator 必为摘要等宽的
  密文定位 HMAC，且其 payload 必须能解析为加密条目封装；条目索引须恰为
  `0..n-1`
- 加载**先做 GCM 解密与认证**（错误密钥或任何篡改均失败），再完整复核上述
  规范：nonce 宽度（恰 12 字节）、字典序与互异、nonce 历史与密文封装中恢复
  出的 nonce 集合完全一致、locator / 摘要宽度、索引顺序、`stage` / 标志范围、
  演进密钥非空且宽度合法；随后从创世零摘要逐条重算 `entry_digest` 链头并重建
  Merkle 根，二者必须与 `head` / `root` 匹配；最后原子地重建全部索引与认证
  状态（find 索引、密文定位索引、nonce 历史、`K`、`stage`、导出标志），失败
  不产生半成品日志
- `key` 须为 32 字节 `bytes`；`nonce=None` 时用 `os.urandom(12)`，显式
  nonce 须为 12 字节 `bytes`，同 key 复用由调用方避免。`log` 不是
  `AuditLog`、`key` / `nonce` / `data` 类型错（`data` 拒绝 `bytearray` /
  `memoryview`）抛 `TypeError`；密钥长度、nonce 长度、资格不符（已裁剪或
  构造时无 `key`）、魔数 / 算法号、截断、尾随字节、非法 UTF-8 / 未知算法、
  nonce 宽度 / 顺序 / 与密文不一致、摘要 / locator 宽度、封装不可解析、
  密文 nonce 重复、索引顺序、断链、`stage` / 标志范围、演进密钥为空或宽度
  不符、AEAD 认证失败或重算链 / 根不符均抛 `ValueError`
- 导出只读；恢复对象与调用方缓冲区不共享任何状态，可继续 `append`、
  `encrypt`、`auth`、`rotate_key` 等全部既有操作（已用 nonce 仍被拒绝）；
  字节流不含任何标签或验证材料；旧接口不变

### 带认证且可含密文的已裁剪日志的混合加密导出与恢复（AES-256-GCM）

`dump_pruned_hybrid(log, key, nonce=None)` 与
`load_pruned_hybrid(data, key)` 是 `dump_hybrid` 的裁剪对应物，也是
`dump_pruned_auth` 的密文宽容版本：为**构造时带 `key`、已裁剪
（`retain_from > 0`）且历史可含 `encrypt` 条目**的前向安全认证日志提供对称
加密的状态导出——裁剪掉的前缀中同样可以有密文。导出用按次传入的 32 字节
对称密钥做 AES-256-GCM 密封，字节流不携带明文；明文帧同时携带裁剪检查点与
前缀 frontier、**完整** nonce 历史（含被裁剪释放的密文 nonce）、保留段密文的
locator HMAC 与认证演进状态（演进密钥、`stage`、导出标志），恢复出的日志
独立、可变，长度、`retain_from`、链头、Merkle 根与包含证明、`find` /
`find_encrypted` 索引、nonce 历史与 `stage` 均与原日志一致，重启后从完全相同
的演进点继续前向安全认证：

```python
import os
from auditchain import AuditLog, dump_pruned_hybrid, load_pruned_hybrid, verify_auth

key = os.urandom(32)                 # 密封用对称密钥，必须是 32 字节 bytes
enc_key = os.urandom(32)             # encrypt 用密钥，按次传入、不落盘
log = AuditLog(key=b"shared-secret")
verifier = log.export_verifier()
log.append("plain event")
log.encrypt("released secret", enc_key)   # 该密文随后会被裁剪释放
log.append("kept plain")
log.encrypt("kept secret", enc_key, nonce=b"\x07" * 12)
log.prune(2, log.seal(2))                  # retain_from == 2
data = dump_pruned_hybrid(log, key)        # nonce=None 随机 12 字节
restored = load_pruned_hybrid(data, key)   # 全新、独立、可变的带密钥 AuditLog
restored.retain_from == 2                  # True：保留点一致
restored.head == log.head                  # True：链头一致
restored.merkle_root() == log.merkle_root()  # True：完整快照的 Merkle 根一致
restored.find_encrypted("kept secret", enc_key)  # (3,)：密文索引仅含保留段
restored._used_nonces == log._used_nonces  # True：完整 nonce 历史（含被释放的）
restored.encrypt("again", enc_key, nonce=b"\x07" * 12)  # ValueError：旧 nonce 仍被拒绝
log.append("after restart")
restored.append("after restart")
restored.auth(4) == log.auth(4)            # True：重启后继续演进，标签逐字节相同
```

- 字节流严格复用 `dump_hybrid` 的 `D || 0x01 || N || C` 与 AES-256-GCM 规则，
  仅将 `D` 改为 `b"auditchain/pruned-hybrid/v1\0"`：`0x01` 为单字节算法号
  （AES-256-GCM），`N` 为 12 字节 nonce，`C` 是明文帧 `P` 的 AESGCM 输出
  （`ciphertext || 16 字节 tag`）；AEAD 的 AAD 为 `D || 0x01 || N`
- 明文帧严格依次为
  `P = B(h) || U(n) || U(r) || B(checkpoint) || F || Q || E ||
  B(root) || B(head) || U(stage) || B(K) || U(x)`：`h` 是 `hash_name` 的
  UTF-8 编码；`n` 为累计条目数，`r` 为保留点（`0 < r <= n`），`checkpoint`
  为前 `r` 条末条的链摘要；`U` 为 8 字节无符号大端，`B(v) = U(len(v)) || v`
- `F` 严格沿用 `dump_pruned_auth` 的公开编码：u64 子树计数后按高度升序写每个
  `r` 置位子树的 `U(height) || B(digest)`（高度恰为 `r` 的置位，覆盖
  `[0, r)`）
- `Q` 严格复用 `dump_hybrid` 的**完整** nonce 历史：u64 计数后按字典序逐个写
  12 字节的 `B(nonce)`，覆盖该日志 `encrypt` 用过的全部 nonce——即使对应密文
  已被裁剪释放
- `E` 先写 u64 保留条目计数（恰为 `n - r`），再按索引 `r..n-1` 顺序写各条记录，
  每条严格复用 `dump_secure_log` 的 `U(index) || B(payload) ||
  B(previous_hash) || B(entry_hash) || B(locator)` 编码与 locator 判型：空
  locator 表示普通条目，非空 locator 必为摘要等宽的密文定位 HMAC，且其
  payload 必须能解析为加密条目封装
- `root` / `head` 为完整 size-`n` 快照的 Merkle 根与链头；尾部的 `stage`、
  `K`（当前演进密钥；stage 0 时即构造密钥、可任意非空长度，演进后为摘要等宽）
  与 `x`（验证材料已导出标志，u64 编码、值为 `0` 或 `1`）严格复用
  `dump_hybrid` 的认证状态尾部
- 加载**先做 GCM 解密与认证**（错误密钥或任何篡改均失败），再复核 frontier、
  完整 nonce 历史（宽度、互异、字典序）、locator（保留密文 nonce 须在历史中且
  在保留段不重复，历史可额外含被释放密文的 nonce）、摘要宽度、保留点越界、
  保留条目数与索引顺序；随后从检查点起逐条重算 `entry_digest` 链头并由
  frontier 与保留条目重建完整 Merkle 根，二者必须与 `head` / `root` 匹配；
  最后经正常 `append` / 加密条目恢复路径原子地重建全部索引与认证状态
  （retain_from、检查点、frontier、find 索引、密文定位索引、完整 nonce 历史、
  `K`、`stage`、导出标志），失败不产生半成品日志
- `key` 须为 32 字节 `bytes`；`nonce=None` 时用 `os.urandom(12)`，显式
  nonce 须为 12 字节 `bytes`，同 key 复用由调用方避免。`log` 不是
  `AuditLog`、`key` / `nonce` / `data` 类型错（`data` 拒绝 `bytearray` /
  `memoryview`）抛 `TypeError`；密钥长度、nonce 长度、资格不符（未裁剪或构造
  时无 `key`）、魔数 / 算法号、截断、尾随字节、非法 UTF-8 / 未知算法、
  checkpoint / frontier 结构、保留点越界、nonce 宽度 / 顺序 / 覆盖、摘要 /
  locator 宽度、封装不可解析、保留密文 nonce 重复或缺失、条目数 / 索引顺序、
  断链、`stage` / 标志范围、演进密钥为空或宽度不符、AEAD 认证失败或重算
  链 / 根不符均抛 `ValueError`
- 导出只读；恢复对象与调用方缓冲区不共享任何状态，可继续 `append`、
  `encrypt`、`auth`、`rotate_key`、再次裁剪等全部既有操作（已用 nonce 仍被
  拒绝）；字节流不含任何裁剪回执、标签或验证材料；失败原子，旧接口不变

## 命令行演示

```bash
python3 -m auditchain
```

## 公开接口

- `Entry(index, payload, previous_hash, entry_hash)` — 不可变条目
- `AuthTag(stage, tag)` — 不可变认证标签（演进 stage 与该 stage 下的 HMAC 摘要）；
  `stage` 须为非 `bool` 整数且 `0 <= stage < 2**64`，`tag` 只接受 `bytes`
- `Verifier(key, hash_name)` — 不可变验证材料，由 `export_verifier()` 导出；
  `key` 只接受非空 `bytes`
- `PruneReceipt(hash_name, size, merkle_root, chain_hash)` — 不可变的前缀封存回执
  - `merkle_root` 为该前缀的 Merkle 根，二者均为 `hash_name` 摘要宽度；`chain_hash` 为末条摘要（空前缀为该宽度的零摘要，sha256 下即 `GENESIS_HASH`）
  - `matches(entry)` — 核对某条目是否为裁剪后首条保留记录（绝对索引等于 `size` 且前驱摘要等于 `chain_hash`），
    是返回 `True`，否则 `False`；空前缀回执匹配索引为 0、前驱为该宽度零摘要的创世条目；
    入参不是 `Entry` 抛 `TypeError`
- `AuditReceipt(version, hash_name, size, root, items)` — 不可变的离线审计回执，
  按字段相等、支持位置构造；`version` 恒为 `1`，`root` 为快照 Merkle 根，
  `items` 为按绝对索引升序的 `(Entry, 证明元组)` 元组；**每个 `size > 0` 的回执
  必含 `index == size - 1` 的末条（在 items 末尾）及其包含证明**，`size == 0` 时
  `items` 必须为 `()`；类型非法抛 `TypeError`，版本、范围、未知算法、摘要长度或
  条目结构非法（含非空回执缺失末条、空回执携带条目）抛 `ValueError`
- `SignedRoot(version, hash_name, size, root, head, signature)` — 不可变的 Ed25519
  可信签名快照检查点，按全部字段相等、支持位置构造；`version` 恒为 `1`，`root`
  为前 `size` 条的 Merkle 根，`head` 为该前缀末条摘要（空前缀为该摘要宽度的零
  链头，sha256 下即 `GENESIS_HASH`），`signature` 为 64 字节 Ed25519 签名；
  `root`、`head`、`signature` 只接受精确的 `bytes`（拒绝 `bytearray` 与
  `memoryview`，不做拷贝归一化）；`size` 须满足 `0 <= size < 2**64`。类型非法
  抛 `TypeError`，版本非 1、未知算法、`size` 越界、`root`/`head` 摘要宽度不符
  或 `signature` 不是 64 字节抛 `ValueError`
- `SignedVerifier(version, verifier, signature)` — 不可变的 Ed25519 可信交付
  stage-0 验证材料，按全部字段相等、支持位置构造；`version` 恒为 `1`，
  `verifier` 必须是 `Verifier`（其非空 `bytes` 类型 `key` 与算法名同样被复验），
  `signature` 只接受恰好 64 字节的精确 `bytes`（拒绝 `bytearray` /
  `memoryview`）；签名只认证来源、不加密其中密钥。类型非法抛 `TypeError`，版本非
  1、空 `key`、未知算法或 `signature` 不是 64 字节抛 `ValueError`
- `SignedAuthBundle(verifier, hash_name, items)` — 不可变的可信认证批次交付包，
  按全部三个字段相等、支持位置构造；`verifier` 为已签名的 stage-0 验证材料
  （必须是 `SignedVerifier`），`hash_name` 为认证批次签发所用算法（必须是已知
  固定输出算法名），`items` 即 `auth_batch` 的结果元组（必须是 `tuple`）；容器
  字段类型错抛 `TypeError`，项内部的结构契约由 `verify_auth_batch` 校验
- `SignedAuditBatch(batch, checkpoint)` — 不可变的可信紧凑批量审计包，按两个
  字段相等、支持位置构造；`batch` 为 `audit_batch` 的五元组（必须是 `tuple`），
  `checkpoint` 为同一快照的 `SignedRoot`（必须是 `SignedRoot`）；容器字段类型错
  抛 `TypeError`，批量五元组内部的结构契约由 `verify_audit_batch` 校验
- `SignedPrune(receipt, checkpoint)` — 不可变的可信签名裁剪授权，按两个字段
  相等、支持位置构造；`receipt` 为 `seal` 的前缀裁剪回执（必须是
  `PruneReceipt`），`checkpoint` 为同一前缀的 `SignedRoot`（必须是
  `SignedRoot`）；容器字段类型错抛 `TypeError`，两部分是否描述同一前缀、
  签名是否有效由 `verify_signed_prune` 判定
- `IntegrityIssue(code, index)` — 不可变的单点完整性问题，按字段相等、支持位置构造；
  `code` 为 `"index"`、`"previous_hash"`、`"entry_hash"`（`index` 为问题所在条目的绝对索引）
  或 `"head"`（仅可配 `index=None`，表示重算出的链头与记录的 `head` 不符）；
  `code` 类型/取值、`index` 类型或负值非法抛 `TypeError` / `ValueError`
- `IntegrityReport(ok, issues)` — 不可变的链校验报告，按字段相等、支持位置构造；
  `issues` 仅含 `IntegrityIssue`，`ok` 当且仅当 `issues` 为空。问题按期望绝对索引升序，
  同一位置依次为 `"index"`、`"previous_hash"`、`"entry_hash"`，`("head", None)` 只能在末尾；
  顺序或 `ok`/`issues` 不一致抛 `ValueError`，类型非法抛 `TypeError`
- `GENESIS_HASH` — `bytes(32)` 全零起始前驱摘要（sha256 创世前驱；其他宽度日志用其自身 `digest_size` 个零）
- `AuditLog(*, key=None, hash_name="sha256")` — 传入非空 `bytes` 类型 `key` 开启前向安全认证，
  省略则为无密钥模式；`key` 只接受 `bytes`（`bytearray` / `memoryview` 抛 `TypeError`），
  空 `key` 抛 `ValueError`
  - `append(payload)` — 接受 `bytes` 或 `str`（UTF-8 编码），返回新条目
  - `encrypt(payload, key, nonce=None)` — AES-256-GCM 加密追加：链式规则与
    `append` 相同，但 `Entry.payload` 保存自描述密文封装
    （`b"auditchain/encrypted-entry/v1\0" || 0x01 || 12 字节 nonce ||
    ciphertext || 16 字节 tag`）；AAD 为
    `b"auditchain/aead/v1\0" || 0x01 || index(u64 大端) || previous_hash`，
    封装作为 payload 参与 `entry_digest`。`key` 为 32 字节 `bytes`、按次传入不保存；
    `nonce=None` 时生成 `os.urandom(12)`，显式 nonce 须为 12 字节 `bytes` 且在本日志
    历史中不重复（裁剪后仍记录）。明文编码规则同 `append`；类型错抛 `TypeError`，
    密钥/nonce 长度、nonce 重复抛 `ValueError`，失败不改变日志状态。解密用顶层
    `decrypt_entry`；`find` 只匹配封装本体，不按明文检索
  - `entries()` / `entry(index)` / `__len__()` / `__iter__()` / `head` 属性
  - `find(payload, start=None, stop=None)` — 在保留段内按内容查找，返回匹配条目的绝对索引
    升序元组，无匹配为 `()`；`payload` 只接受 `bytes` 或 `str`（UTF-8 编码），其他类型抛
    `TypeError`；查询范围为半开区间 `[start, stop)`，默认 `[retain_from, len(log))`，
    显式边界须为非 `bool` 整数且满足 `retain_from <= start <= stop <= len(log)`，
    类型非法抛 `TypeError`、越界抛 `ValueError`。索引由 `append` 增量维护、`prune`
    成功时同步删除已释放前缀（失败不变）；定位摘要命中后仍逐条比较原 payload，
    哈希碰撞不会产生误命中；查询为只读，不改变条目、`head`、认证状态、Merkle 根或证明
  - `find_encrypted(payload, key, start=None, stop=None)` — 供持有追加时 AES
    密钥的调用方按原明文定位保留段内的加密条目，返回匹配条目的绝对索引升序元组，
    无命中为 `()`；范围参数的默认值、半开 `[start, stop)` 边界与越界规则与
    `find` 完全相同。`payload` 仅接受 `bytes` 或 `str`（规范化为 `P`，`str`
    按 UTF-8 编码），其他类型抛 `TypeError`；`key` 仅接受 32 字节 `bytes`，
    类型错抛 `TypeError`、长度不符抛 `ValueError`。索引只保存
    `HMAC(key, b"auditchain/encrypted-locate/v1\0" || P, hash_name)` 到绝对索引
    的映射，既不保存明文也不保存密钥，且不改变密文封装、`Entry` 摘要、链与
    Merkle 结果；定位项仅在 `encrypt` 追加成功后提交，`prune` 成功时删除已释放
    前缀的项（失败均不改索引）。候选命中后仍以查询密钥解密并逐字节比较 `P`，
    认证失败或摘要碰撞均不误命中；普通条目或不同密钥的条目不命中，合法但错误的
    密钥返回 `()`，查询为只读
  - `retain_from` 属性 — 当前保留点（首个仍持有条目的绝对索引，未裁剪时为 `0`）
  - `stage` 属性 — 当前密钥演进 stage（首次演进前为 `0`）
  - `verify()` — 从创世摘要（裁剪后从检查点）开始校验持有的链段，等价于
    `verify_report().ok`
  - `verify_report()` — 与 `verify()` 同样从检查点逐条推进，但返回不可变
    `IntegrityReport(ok, issues)` 精确定位不匹配：每条以期望绝对 index、上一步
    重算摘要与当前 payload 重算 `entry_digest`，依次比对记录的 index、
    previous_hash 与 entry_hash，最后要求重算链头等于 `head`（空日志从同宽零摘要
    开始）。问题按绝对索引升序，同位置 code 依次为 `"index"`、`"previous_hash"`、
    `"entry_hash"`，不匹配链头只在末尾追加 `("head", None)`；遍历始终用期望 index
    与重算前驱，故前面的损坏不影响后续定位。结构合法但不匹配只写入 `issues` 并令
    `ok=False`（不抛异常）；非法字段（非 `Entry`、index 非非 bool 非负整数、字段非
    `bytes` 或摘要宽度不符）沿用 `TypeError` / `ValueError`；调用只读
  - `verify_entry(index)` — 只校验某条与前驱的连接
  - `auth(index)` — 为保留段中的条目签发不可变 `AuthTag`，返回后立即以
    `H(b"auditchain/key-evolve/v1" + K)` 替换密钥、stage 加一，不保存旧密钥、不追加条目；
    无密钥模式调用抛 `ValueError`
  - `auth_batch(indices)` — 一次为多条保留记录批量签发：`indices` 为互异非 `bool`
    整数的可迭代对象，先校验全部索引、保留范围与 `stage + 条数 < 2**64`，再按绝对
    索引升序连续计算标签后一次提交，返回 `tuple[tuple[Entry, AuthTag], ...]`（空选择
    返回 `()`）；第 j 项使用初始 `stage+j`，严格沿用 `auth` 的 HMAC 域、stage 的
    8 字节大端编码与 key-evolve 域，逐项等于按升序连续调用 `auth`，成功恰演进所选
    条数次；失败不改密钥、stage、标签或日志；不追加条目，也不改变哈希链、Merkle 根、
    检索索引或既有公开对象；索引类型错抛 `TypeError`，重复或容量不足抛 `ValueError`，
    非保留索引抛 `IndexError`，无密钥模式抛 `ValueError`
  - `rotate_key()` — 只演进密钥一次（stage 加一），不签发标签、不追加条目；无密钥模式抛 `ValueError`
  - `export_verifier()` — 仅可在首次演进前调用一次，返回不可变 `Verifier`；
    演进后或再次调用抛 `ValueError`，无密钥模式抛 `ValueError`
  - `export_signed_verifier(private_key)` — 在与 `export_verifier()` 相同的资格
    条件下（带 key、`stage == 0`、未导出过验证材料），用按次传入的 32 字节
    Ed25519 私钥种子对 stage-0 `Verifier` 确定性签名，返回不可变
    `SignedVerifier(version=1, verifier, signature)`；签名原文为
    `D || 0x01 || B(hash_name 的 UTF-8) || B(key)`
    （`D = b"auditchain/signed-verifier/v1\0"`，`U` 为 8 字节无符号大端，
    `B(x) = U(len(x)) || x`）。成功即消耗与 `export_verifier` 共用的一次导出资格；
    所有校验先于签名和资格消耗，失败不消耗资格、不演进密钥、不改日志。种子类型错
    抛 `TypeError`、长度非 32 抛 `ValueError`；无密钥模式、已演进或重复导出抛
    `ValueError`；离线用 `verify_signed_verifier` 凭预信任公钥验真
  - `merkle_root(size=None)` — 前 `size` 条（默认全部）的前缀 Merkle 根；追加不影响已有前缀根
  - `inclusion_proof(index, size=None)` — 叶到根的兄弟摘要不可变元组
  - `batch_inclusion_proof(indices, size=None)` — 为大量条目合并出的紧凑批量
    包含证明，返回 `(indices, proof)`：`indices` 为去重并按绝对索引升序排列的
    元组，`proof` 为一份覆盖整个 `[0, size)` 快照、合并重复子树摘要的 `bytes`
    元组；`size` 默认当前长度，快照须可重建。`indices` 为可迭代的互异非
    `bool` 整数，须满足 `retain_from <= index < size` 且非空；类型非法抛
    `TypeError`，空选择、重复、越界或快照不可重建抛 `ValueError`；调用只读
  - `consistency_proof(old_size, new_size=None)` — 两个前缀快照之间的一致性证明，不可变元组；
    要求 `0 <= old_size <= new_size <= len(log)`，后续追加不改变同一前缀对的证明
  - `seal(size=None)` — 为前 `size` 条（默认当前长度）生成 `PruneReceipt`，记录前缀根与末条摘要，
    空前缀记录该宽度的零摘要（sha256 下为 `GENESIS_HASH`）
  - `audit_receipt(indices, size=None)` — 为快照中选定条目生成离线 `AuditReceipt`：
    `indices` 为可迭代的互异非 `bool` 整数，须满足 `retain_from <= index < size`；
    `size` 默认当前长度，快照须可重建；**任何 `size > 0` 的快照都自动并入末条
    （`index == size - 1`）及其包含证明，即使 `indices` 为空也不例外**，只有
    `size=0` 的空快照得到 `items == ()`；条目按绝对索引升序携带各自包含证明；
    调用只读，类型非法抛 `TypeError`，越界或重复抛 `ValueError`
  - `audit_batch(indices, size=None)` — 为快照中选定条目签发紧凑离线批量审计回执，
    返回纯五元组 `(hash_name, size, root, entries, proof)`：`entries` 为严格升序的
    `Entry` 元组（`retain_from <= i < size`），`proof` 是多条记录共享的一份
    `batch_inclusion_proof` 紧凑证明（与其逐字节相同）；`size` 默认当前长度，快照须
    可重建。`indices` 为可迭代的互异非 `bool` 整数；非空快照自动并入末条
    （`index == size - 1`，即使选择为空），只有 `size=0` 的空快照接受空选择并返回
    规范空树根、空 `entries` 与空 `proof`。调用只读；类型非法抛 `TypeError`，重复、
    越界或快照不可重建抛 `ValueError`，任何失败都不改变日志状态；离线用
    `verify_audit_batch` 核验
  - `sign_root(private_key, size=None)` — 用按次传入的 32 字节 Ed25519 私钥种子
    为前 `size` 条（默认 `len(log)`）的快照根与链头签发不可变 `SignedRoot`：
    `root` 为该前缀 Merkle 根，`head` 为末条摘要（空前缀为同宽零链头）。签名原文为
    `D || 0x01 || B(hash_name 的 UTF-8) || U(size) || B(root) || B(head)`
    （`D = b"auditchain/signed-root/v1\0"`，`U` 为 8 字节无符号大端，
    `B(x) = U(len(x)) || x`），`signature` 为其 64 字节 Ed25519 签名、
    `version` 恒为 1。私钥种子只用于这一次签名、从不保存或返回；`size` 越界或快照
    已裁剪抛 `ValueError`（空快照 `size=0` 始终可签），种子类型错抛 `TypeError`、
    长度非 32 抛 `ValueError`；调用只读，离线用 `verify_signed_root` 凭预信任公钥验真
  - `rotate_signer(old_seed, new_seed, size=None)` — 只读完成 Ed25519 签名钥轮换，
    返回四元组 `(old, new_key, new, auth)`：在**同一快照**（默认当前长度）上分别用
    旧、新种子各签一个 `SignedRoot`（两者与各自调用 `sign_root(seed, size)` 逐字节相同，
    签名域与接口不变），`new_key` 为新种子的 32 字节原始公钥，`auth` 为旧种子对
    `D || 0x01 || B(old.signature) || B(new_key) || B(new.signature)`
    （`D = b"auditchain/signer-rotation/v1\0"`，`U` 为 8 字节无符号大端、
    `B(x) = U(len(x)) || x`）的确定性 64 字节签名。两粒种子从不保存或返回；种子类型错
    抛 `TypeError`、长度非 32 或 `size` 越界 / 快照已裁剪抛 `ValueError`（`size` 须为
    非 `bool` 整数），任何失败都不改变日志状态；离线用 `verify_rotation` 凭旧公钥验真
  - `signed_audit_batch(indices, private_key, size=None)` — 只读签发可信紧凑批量
    审计包，返回不可变 `SignedAuditBatch`：先调用 `audit_batch(indices, size)`，
    再调用 `sign_root(private_key, size)`（`size` 默认当前长度），据此构造
    `SignedAuditBatch(batch, checkpoint)`，两部分描述同一快照，且不新增签名原文。
    失败（非法选择、种子或 `size`）在构造前抛出，不改变日志状态；异常类型沿用
    `audit_batch` / `sign_root`（`TypeError` / `ValueError`）；离线用
    `verify_signed_audit_batch` 凭预信任公钥验真
  - `sign_prune(private_key, size=None)` — 只读签发可信签名裁剪授权，返回不可变
    `SignedPrune`：先调用 `seal(size)`，再调用 `sign_root(private_key, size)`
    （`size` 默认当前长度），据此构造 `SignedPrune(receipt, checkpoint)`，两部分
    描述同一前缀（同 `hash_name` / `size`，`merkle_root == root`、
    `chain_hash == head`），且不新增签名原文。失败（非法种子或 `size`）在构造前
    抛出，不改变日志状态；异常类型沿用 `seal` / `sign_root`
    （`TypeError` / `ValueError`）；离线用 `verify_signed_prune` 凭预信任公钥验真
  - `prune(retain_from, receipt)` — 在校验通过后释放前 `retain_from` 条的 payload 及其认证标签：
    要求 `retain_from == receipt.size`，且回执的算法、Merkle 根、链摘要与日志一致；
    保留点只可前移（数值增大）且不可越界，类型非法抛 `TypeError`，越界、回退、
    回执不匹配或无有效回执抛 `ValueError`
  - `prune_signed(retain_from, item, public_key)` — 先以
    `verify_signed_prune(item, public_key)` 离线核验签名裁剪授权，通过后等价于
    `prune(retain_from, item.receipt)`（仍自行重算前缀根与链摘要）。
    `retain_from` 必须是非 `bool` 整数（类型错抛 `TypeError`）；授权不匹配
    （未信任公钥、两部分字段不一致、签名被改）返回核验失败并抛 `ValueError`，
    `prune` 的既有越界 / 回退 / 不匹配同样抛 `ValueError`；任何失败都不改变日志、
    认证、索引、nonce 历史与 frontier 检查点状态，其余异常沿用既有入口
  - `apply_retention(value, *, mode="retain_from")` — 按保留策略计算保留点并原子完成封存与裁剪，
    返回 `PruneReceipt`：`mode="retain_from"` 时目标为 `value`（要求
    `retain_from <= value <= len(log)`），`mode="keep_last"` 时目标为
    `max(retain_from, len(log) - value)`（要求 `value >= 0`）；成功等价于
    `seal(target)` 后 `prune(target, receipt)`。`value` 必须是非 `bool` 整数、
    `mode` 必须为上述两个字符串之一，类型非法抛 `TypeError`，未知 `mode` 或越界抛
    `ValueError`，任何失败都不改变日志、认证、索引、nonce 历史及证明状态
- `entry_digest(index, previous_hash, payload, *, hash_name)` — 条目摘要计算
- `decrypt_entry(entry, key, *, hash_name="sha256")` — 解密 `AuditLog.encrypt` 产生的
  条目，无需持有日志：先校验封装格式与 `entry_hash == entry_digest(...)`（封装作为
  payload），再以 `b"auditchain/aead/v1\0" || 0x01 || index(u64 大端) ||
  previous_hash` 为 AAD 校验 AES-256-GCM 标签，全部通过才返回明文 bytes
  （规则同 `append`）。入参不是 `Entry` 或 `key`/字段类型非法抛 `TypeError`；
  `key` 长度非 32、封装魔数不符或截断、算法号未知、摘要长度不符、`entry_hash`
  不符、密钥错误或 AEAD 认证失败抛 `ValueError`；调用只读，不改变条目或日志
- `verify_inclusion(entry_hash, index, size, root, proof, *, hash_name="sha256")` — 只凭条目摘要、快照大小与根摘要验证包含证明，无需持有日志
- `verify_batch_inclusion(indices, entry_hashes, size, root, proof, *, hash_name="sha256")` —
  只凭所选条目摘要、快照大小与根摘要离线验证 `batch_inclusion_proof` 的紧凑批量
  证明，无需持有日志；`indices` 为非空、严格升序的非 `bool` 整数 `tuple`，
  `entry_hashes` 为与之等长的 `bytes` 摘要 `tuple`，`proof` 为 `bytes` 节点的
  `tuple`。类型非法抛 `TypeError`；索引越界/非升序、序列不等长、摘要宽度不符、
  快照大小或证明节点数与 `(indices, size)` 不符抛 `ValueError`；结构合法但摘要、
  证明或根不匹配返回 `False`，否则 `True`
- `verify_consistency(old_size, old_root, new_size, new_root, proof, *, hash_name="sha256")` — 只凭两次快照的大小、根与证明验证后者由前者追加形成，无需日志；
  结构非法抛 `TypeError`/`ValueError`，结构合法但不匹配返回 `False`
- `verify_audit_receipt(receipt)` — 无需持有日志即可验证 `AuditReceipt`：要求非空快照
  回执必携末条（`index == size - 1`）及其包含证明，再重算每个条目的 `entry_digest`
  并核验全部包含证明与快照根，空快照（`size=0`、`items==()`）只接受规范空树根；
  结构合法但条目内容、证明或根不符，或非空回执缺失末条（含绕过构造器的
  `size>0 且 items==()` 零证据回执）返回 `False`；入参不是 `AuditReceipt` 抛
  `TypeError`，字段结构、摘要长度或证明结构非法抛 `ValueError`
- `verify_audit_batch(receipt)` — 无需持有日志即可验证 `AuditLog.audit_batch` 签发的
  紧凑批量回执五元组 `(hash_name, size, root, entries, proof)`：要求非空快照必携末条
  （`index == size - 1`），再对每个 `Entry` 重算 `entry_digest`，并用
  `verify_batch_inclusion` 以那份共享证明重建快照根；空快照
  （`size=0`、`entries==()`）只接受规范空树根。非五元组或字段/条目类型错抛
  `TypeError`；算法、范围（含负 `size`、条目索引越界）、摘要宽度、`entries`
  顺序/重复、缺末条（含 `size>0 且 entries==()`）、空快照携带条目或证明节点数与
  `(indices, size)` 不符抛 `ValueError`；结构合法但条目内容、证明或根不匹配返回
  `False`，匹配返回 `True`
- `verify_signed_verifier(receipt, public_key)` — 凭预先信任的 32 字节 Ed25519
  公钥离线验证 `AuditLog.export_signed_verifier` 签发的 `SignedVerifier`：从嵌套
  `Verifier` 重建同一签名原文
  `D || 0x01 || B(hash_name 的 UTF-8) || B(key)`
  （`D = b"auditchain/signed-verifier/v1\0"`，`U` 为 8 字节无符号大端，
  `B(x) = U(len(x)) || x`）并校验其 64 字节签名，无需持有日志；公钥不是对应
  签发方，或结构合法但 `verifier` 的 `key` / `hash_name` 或 `signature` 被改
  返回 `False`，匹配返回 `True`。签名只认证来源、不加密其中密钥。入参不是
  `SignedVerifier`（含绕过构造器写入错误字段类型）或公钥不是 `bytes` 抛
  `TypeError`；版本非 1、空 `key`、未知算法、签名长度或公钥长度（非 32 字节）
  非法抛 `ValueError`；调用只读
- `verify_signed_root(receipt, public_key)` — 凭预先信任的 32 字节 Ed25519 公钥
  离线验证 `AuditLog.sign_root` 签发的 `SignedRoot`：重建同一签名原文
  `D || 0x01 || B(hash_name 的 UTF-8) || U(size) || B(root) || B(head)`
  （`D = b"auditchain/signed-root/v1\0"`，`U` 为 8 字节无符号大端，
  `B(x) = U(len(x)) || x`）并校验其 64 字节签名，无需持有日志；公钥不是对应
  签发方，或结构合法但 `root`、`head`、`signature` 等被改返回 `False`，匹配
  返回 `True`。入参不是 `SignedRoot` 或公钥不是 `bytes` 抛 `TypeError`；版本、
  未知算法、`size` 范围、摘要宽度、签名长度或公钥长度（非 32 字节）非法抛
  `ValueError`；调用只读
- `verify_rotation(item, key)` — 凭预先信任的旧签名者 32 字节 Ed25519 公钥 `key`，
  完全离线验证 `AuditLog.rotate_signer` 返回的四元组
  `(old, new_key, new, auth)`，无需持有日志：旧公钥 `key` 验证 `old` 的快照签名与
  `auth` 授权签名，`item` 中的 `new_key`（32 字节）验证 `new` 的快照签名——新钥只有经
  旧钥授权后才被信任；并要求 `old` 与 `new` 除 `signature` 外五个字段全等（同一快照）。
  任一签名不符、`new_key` 与授权不匹配或两个检查点描述的不是同一快照，返回 `False`，匹配
  返回 `True`。`item` 不是四元组、`old` / `new` 不是 `SignedRoot`、`new_key` /
  `auth` 不是 `bytes` 抛 `TypeError`；`new_key` 非 32 字节、`auth` 非 64 字节、公钥
  长度非 32 字节或嵌套 `SignedRoot` 结构非法抛 `ValueError`（沿用
  `verify_signed_root` 的既有异常）；调用只读
- `verify_signed_audit_batch(receipt, public_key)` — 凭预先信任的 32 字节
  Ed25519 公钥离线验证 `AuditLog.signed_audit_batch` 签发的 `SignedAuditBatch`，
  无需持有日志：依次调用 `verify_audit_batch`（核验所选条目与共享证明对快照根）
  与 `verify_signed_root`（核验检查点签名），并要求两部分的 `hash_name`、`size`、
  `root` 一致，且非空快照的检查点 `head` 等于批量回执末条（索引 `size - 1`）的
  `entry_hash`，空快照的 `head` 为同宽零摘要。公钥不受信任、两部分不一致，或
  条目/证明/根/链头/签名被改返回 `False`，匹配返回 `True`。入参不是
  `SignedAuditBatch`（含绕过构造器的容器字段类型错）或公钥不是 `bytes` 抛
  `TypeError`；嵌套的批量五元组或检查点结构非法时沿用 `verify_audit_batch` /
  `verify_signed_root` 的既有异常（`TypeError` / `ValueError`），公钥长度非
  32 字节抛 `ValueError`；调用只读
- `verify_signed_prune(item, public_key)` — 凭预先信任的 32 字节 Ed25519 公钥
  离线验证 `AuditLog.sign_prune` 签发的 `SignedPrune` 裁剪授权，无需持有日志：
  先用 `verify_signed_root` 校验检查点签名，再要求回执与检查点描述同一前缀——
  `hash_name` 相等、`size` 相等、`merkle_root == root`、`chain_hash == head`。
  公钥不受信任、两部分不一致或回执 / 根 / 链头 / 签名被改返回 `False`，匹配
  返回 `True`。入参不是 `SignedPrune`（含绕过构造器的容器字段类型错）或公钥
  不是 `bytes` 抛 `TypeError`；嵌套结构非法沿用 `PruneReceipt` /
  `SignedRoot` / `verify_signed_root` 的既有异常（`TypeError` /
  `ValueError`），公钥长度非 32 字节抛 `ValueError`；调用只读
- `verify_signed_auth_bundle(bundle, public_key)` — 凭预先信任的 32 字节
  Ed25519 公钥离线核验 `SignedAuthBundle` 可信认证批次交付包（可由
  `AuditLog.signed_auth_bundle(indices, private_key)` 原子签发，或用
  `export_signed_verifier` 与 `auth_batch` 的结果手工构造），无需持有日志、
  不新增签名原文：先用 `verify_signed_verifier` 核验嵌套的已签名 stage-0 验证
  材料，验签失败逐项返回 `False`（长度与 `items` 相同，空批次为 `()`）；验签
  成功且 `bundle.hash_name` 与签名验证材料的算法一致时，复用
  `verify_auth_batch` 以交付的 `Verifier` 逐项核验标签并返回同序
  `tuple[bool, ...]`；算法不一致同样逐项 `False`。入参不是 `SignedAuthBundle`
  （含绕过构造器的容器字段类型错）或公钥不是 `bytes` 抛 `TypeError`；公钥长度
  非 32 字节抛 `ValueError`，嵌套结构非法沿用 `verify_signed_verifier` /
  `verify_auth_batch` 的既有异常（`TypeError` / `ValueError`）；签名只认证
  来源、不加密其中密钥，调用只读
- `encode_signed_verifier(receipt)` / `decode_signed_verifier(data)` — 可信交付
  stage-0 验证材料的规范二进制编码与解码：魔数
  `b"auditchain/signed-verifier/v1\0"` 开头，后接 version=1（u64）、hash_name 的
  UTF-8 blob、verifier.key blob、signature blob；整数为 8 字节无符号大端，blob 为
  u64 长度前缀加原始字节（零长度也写全零 u64）。解码结果字段与原回执相等、类型为
  `bytes`，重编码逐字节相同，并可继续由 `verify_signed_verifier` 离线验真。编码
  只认证来源、不加密其中密钥。前者只接受 `SignedVerifier`，后者只接受 `bytes`
  （拒绝 `bytearray` / `memoryview`）；非对应类型或字段类型错（含绕过冻结构造器
  的回执）抛 `TypeError`，魔数、版本、UTF-8、未知算法、截断、尾随、blob 长度、
  空 `key` 或签名宽度非法抛 `ValueError`；结构合法但签名不匹配仍可解码，验签
  返回 `False`；两个入口均为只读
- `encode_signed_root(receipt)` / `decode_signed_root(data)` — 可信签名检查点的
  规范二进制编码与解码：魔数 `b"auditchain/signed-root/v1\0"` 开头，后接
  version=1（u64）、hash_name 的 UTF-8 blob、size（u64）、root blob、head
  blob、signature blob；整数为 8 字节无符号大端，blob 为 u64 长度前缀加原始字节
  （零长度也写全零 u64）。解码结果字段与原回执相等、类型为 `bytes`，重编码逐字节
  相同，并可继续由 `verify_signed_root` 离线验真。前者只接受 `SignedRoot`，后者只
  接受 `bytes`（拒绝 `bytearray` / `memoryview`）；非对应类型或字段类型错（含绕过
  冻结构造器的回执）抛 `TypeError`，魔数、版本、UTF-8、未知算法、截断、尾随、blob
  长度、`size` 范围、摘要宽度或签名宽度非法抛 `ValueError`；结构合法但签名不匹配
  仍可解码，验签返回 `False`；两个入口均为只读
- `encode_signed_audit_batch(receipt)` / `decode_signed_audit_batch(data)` —
  可信紧凑批量审计包的规范二进制编码与解码，使 `SignedAuditBatch` 可落盘、跨进程
  传输后继续凭预置信任的 Ed25519 公钥离线验真，且不新增签名原文：魔数
  `b"auditchain/signed-audit-batch/v1\0"` 开头，严格依次写 version=1（u64）、
  batch blob、checkpoint blob（不允许省略、换序或附加字段）；每个 blob 为 u64
  字节长度前缀加原始字节，内容分别是既有 `encode_audit_batch` 与
  `encode_signed_root` 的完整规范字节，解码精确消费两个 blob 并分别交给既有
  解码器。前者只接受 `SignedAuditBatch`（外层类型错抛 `TypeError`，嵌套错误沿用
  既有编码器），后者只接受 `bytes`（拒绝 `bytearray` / `memoryview`）；魔数、
  版本、截断、尾随、blob 长度或嵌套格式非法抛 `ValueError`；解码对象字段相等、
  冻结且重编码逐字节相同，结构合法但验真不匹配仍可解码（验包返回 `False`）；
  两个入口均为只读且确定
- `encode_signed_consistency(receipt)` / `decode_signed_consistency(data)` —
  可信跨快照一致性凭据的规范二进制编码与解码，使 `SignedConsistency` 可落盘、
  跨进程恢复后继续凭预置信任的 Ed25519 公钥离线验真，且不新增签名原文：魔数
  `b"auditchain/signed-consistency/v1\0"` 开头，严格依次写 version=1（u64）、
  old blob、new blob、proof 节点计数（u64）与按元组顺序的节点 blob（不允许
  省略、换序或附加字段）；每个 blob 为 u64 字节长度前缀加原始字节，old 与
  new 的内容分别是既有 `encode_signed_root` 的完整规范字节，解码精确消费后
  分别交给既有 `decode_signed_root`。前者只接受 `SignedConsistency`（外层或
  字段类型错抛 `TypeError`，嵌套检查点错误沿用既有编码器），后者只接受
  `bytes`（拒绝 `bytearray` / `memoryview`）；魔数、版本、截断、尾随、blob
  长度、嵌套格式或 proof 节点宽度（须为 old 检查点算法的摘要宽度）非法抛
  `ValueError`；解码对象字段相等、冻结且重编码逐字节相同；编解码均不校验
  签名、两端关联及证明内容，结构合法但验真不匹配仍可解码（验真返回 `False`）；
  两个入口均为只读且确定
- `encode_signed_prune(item)` / `decode_signed_prune(data)` — 可信签名裁剪
  授权的规范二进制编码与解码，使 `SignedPrune` 可落盘、跨进程恢复后继续凭
  预置信任的 Ed25519 公钥验真并用于 `AuditLog.prune_signed`，且不新增签名
  原文：字节流为 `D || U(1) || B(P) || B(R)`，其中
  `D = b"auditchain/signed-prune/v1\0"`，`U` 为 8 字节无符号大端整数，
  `B(x) = U(len(x)) || x`（沿用 u64 大端与既有 blob 规则）；`P` 与 `R` 分别
  是既有 `encode_prune_receipt(receipt)` 与 `encode_signed_root(checkpoint)`
  的完整规范字节，顺序为回执在前、检查点在后，解码精确消费两个 blob 并禁止
  尾随字节，分别交给既有 `decode_prune_receipt` 与 `decode_signed_root`。
  前者只接受 `SignedPrune`（其余类型抛 `TypeError`，嵌套错误沿用既有编码器
  的 `TypeError` / `ValueError`），后者只接受 `bytes`（拒绝 `bytearray` /
  `memoryview`）；魔数、版本、截断、尾随、blob 长度或任一嵌套格式非法抛
  `ValueError`；解码对象字段相等、冻结且重编码逐字节相同；编解码不校验签名
  及两部分关联，结构合法但两部分不一致或签名不匹配仍可解码（
  `verify_signed_prune` 返回 `False`）；两个入口均为只读且确定
- `encode_signed_auth_bundle(x)` / `decode_signed_auth_bundle(data)` — 可信
  认证批次交付包的规范二进制编码与解码，使 `SignedAuthBundle` 可落盘、跨进程
  恢复后继续凭预置信任的 Ed25519 公钥离线逐项核验，且不新增签名原文：字节流为
  `D || U(1) || B(S) || B(A)`，其中 `D = b"auditchain/signed-auth-bundle/v1\0"`，
  `U` 为 8 字节无符号大端整数，`B(x) = U(len(x)) || x`（沿用 u64 大端与既有
  blob 规则）；`S` 与 `A` 分别是既有 `encode_signed_verifier(verifier)` 与
  `encode_auth_batch(items, hash_name=hash_name)` 的完整规范字节，验证材料在前、
  认证批次在后，解码精确消费两个 blob 并禁止尾随字节，分别交给既有
  `decode_signed_verifier` 与 `decode_auth_batch`，且批次算法必须与签名验证
  材料的算法一致。前者只接受 `SignedAuthBundle`（其余类型抛 `TypeError`，嵌套
  错误沿用既有编码器的 `TypeError` / `ValueError`），后者只接受 `bytes`（拒绝
  `bytearray` / `memoryview`）；魔数、版本、截断、尾随、blob 长度、任一嵌套
  格式或两部分算法不一致抛 `ValueError`；解码对象字段相等、冻结且重编码逐字节
  相同；编解码不校验签名与标签，结构合法但签名或标签不匹配仍可解码
  （`verify_signed_auth_bundle` 逐项返回 `False`）；编码携带明文验证密钥，须像
  裸 `Verifier` 一样保护；两个入口均为只读且确定
- `encode_signed_auth_audit_continuation(receipt)` /
  `decode_signed_auth_audit_continuation(data)` — 跨快照认证审计续接凭据的
  规范二进制编码与解码，使 `SignedAuthAuditContinuation` 可落盘、跨进程恢复后
  继续凭预置信任的 Ed25519 公钥离线验真，且不新增签名域：字节流严格为
  `D || U(1) || B(A) || B(C)`，其中
  `D = b"auditchain/auth-audit-continuation/v1\0"`，`U` 为 8 字节无符号大端
  整数，`B(x) = U(len(x)) || x`；`A` 须逐字节等于
  `encode_signed_auth_audit_bundle(bundle)` 的完整输出，`C` 为
  `encode_signed_consistency(consistency)` 的完整输出，认证审计包在前、一致性
  凭据在后，解码精确消费两个 blob 并禁止尾随字节，分别交给既有
  `decode_signed_auth_audit_bundle` 与 `decode_signed_consistency`，嵌套异常
  沿用对应既有编解码器。前者只接受 `SignedAuthAuditContinuation`（其余类型抛
  `TypeError`，含绕过冻结构造器写入的字段类型错），后者只接受 `bytes`（拒绝
  `bytearray` / `memoryview`）；魔数、版本、截断、blob 长度、尾随或任一嵌套
  格式非法抛 `ValueError`；解码对象字段相等、冻结且重编码逐字节相同；编解码
  不校验签名、标签、证明内容及两部分的快照关联，结构合法但验真不匹配仍可解码
  （`verify_signed_auth_audit_continuation` 返回 `False`）；两个入口均为只读
  且确定，旧接口和签名域不变
- `verify_continuation_chain(receipts, public_key)` — 离线核验一个非空续接
  tuple 描述同一条连续只追加历史，只读且不新增签名域：首参只收非空 `tuple`
  （非 tuple 抛 `TypeError`，空 tuple 抛 `ValueError`），元素均须为既有冻结
  `SignedAuthAuditContinuation`（否则抛 `TypeError`）并保持输入顺序；逐项调用
  `verify_signed_auth_audit_continuation`，任一返回 `False` 整体即 `False`
  （嵌套验真异常与公钥长度/类型错沿用既有规则传播）。每段还须满足
  `consistency.old.size < consistency.new.size`，相邻段要求前段
  `consistency.new` 与后段 `consistency.old` 全字段相等（含签名本身）；重复段
  或任一关系不符返回 `False`
- `inspect_continuation_chain(receipts, public_key)` — `verify_continuation_chain`
  的只读诊断对应物，返回冻结
  `ContinuationChainReport(ok, index, code)` 定位**首个**失败段或断裂边界，
  有效链为 `(True, None, None)`，只报最早问题：逐段
  `verify_signed_auth_audit_continuation` 失败报 `"verify"`，
  `old.size >= new.size` 报 `"growth"`；随后重复凭据报 `"duplicate"`、相邻
  检查点非全字段相等报 `"link"`（`index` 取本段位置，`"link"` 只标识边界不
  归责单段）；未知码抛 `ValueError`。非空 `SignedAuthAuditContinuation`
  tuple 与 32 字节 `bytes` 公钥的类型/长度校验及嵌套异常传播规则与
  `verify_continuation_chain` 一致；不持有日志、不改凭据、不新增签名域，旧
  接口不变
- `inspect_anchors(receipts, key, start, end)` —
  `inspect_continuation_chain` 的端点锚定扩展（四参均无默认值）：先委托内部
  诊断，失败报告原样返回（四类首错顺序不变）；仅当链内部成立才比较锚点，
  首段 `consistency.old` 不等于期望 `start` 报 `"start"`（`index` 取 `0`），
  末段 `consistency.new` 不等于期望 `end` 报 `"end"`（`index` 取末段位置），
  起点不符优先于终点不符；端点按 `SignedRoot` 全六字段全等，故被截去前缀、
  后缀或整体替换的有效子链都会被定位。报告仍为冻结三字段
  `ContinuationChainReport`，仅合法码新增 `"start"`、`"end"`；非
  `SignedRoot` 锚点抛 `TypeError`，其余校验与异常传播规则同
  `inspect_continuation_chain`；只读、不新增签名域，旧接口不变
- `encode_continuations(receipts)` / `decode_continuations(data)` — 续接链的
  规范二进制编码与解码，使非空续接凭据 tuple 可落盘、跨进程恢复后继续凭预置
  信任的 Ed25519 公钥由 `verify_continuation_chain` 离线验真，且不新增签名域：
  字节流严格为 `D || U(1) || U(n) || B(R1) … B(Rn)`，其中
  `D = b"auditchain/cont-chain/v1\0"`，`U` 为 8 字节无符号大端整数，
  `B(x) = U(len(x)) || x`（沿用 u64 大端与既有 blob 规则），`n` 为非零计数，
  `Ri` 为既有 `encode_signed_auth_audit_continuation` 的完整规范输出并按 tuple
  顺序排列；解码精确消费各 `Ri` 及全部外层字节、禁止尾随字节，分别交给既有
  `decode_signed_auth_audit_continuation`，嵌套异常沿用该解码器。前者只收非空
  `SignedAuthAuditContinuation` tuple（非 tuple 或元素类型错抛 `TypeError`，空
  tuple 抛 `ValueError`），后者只接受 `bytes`（拒绝 `bytearray` /
  `memoryview`）；魔数、版本、零计数、截断、blob 长度、嵌套格式或尾随非法抛
  `ValueError`；解码保持凭据 tuple 的原有顺序、字段相等且重编码逐字节相同；
  编解码不校验签名、证明及相邻段关联，结构合法但验真不匹配仍可解码
  （`verify_continuation_chain` 返回 `False`）；两个入口均为只读且确定，旧
  接口和签名域不变
- `AnchoredContinuationChain(receipts, start, end)` — 冻结的锚定续接链包，
  把非空 `SignedAuthAuditContinuation` tuple 与首尾两个 `SignedRoot` 锚点
  绑为一件可持久化制品；支持位置/关键字构造、按全部三字段相等（可哈希）；
  非 tuple 容器、非续接凭据元素或非 `SignedRoot` 锚点抛 `TypeError`，空
  tuple 抛 `ValueError`；包本身不校验链的连续性与锚定关系
- `encode_anchored_continuations(bundle)` /
  `decode_anchored_continuations(data)` — 锚定续接链的规范二进制编码与解码，
  使续接凭据与首尾锚点可一并落盘、跨进程恢复：字节流严格为
  `D || U(1) || B(C) || B(S) || B(E)`，其中
  `D = b"auditchain/anchor/v1\0"`，`U`/`B` 沿用 u64 大端与长度前缀规则，
  `C` 逐字节为既有 `encode_continuations` 输出，`S`/`E` 分别为既有
  `encode_signed_root` 输出，禁止尾随字节；前者只接受
  `AnchoredContinuationChain`（否则抛 `TypeError`），后者只接受 `bytes`
  （拒绝 `bytearray` / `memoryview`）；魔数、版本、截断、blob 长度、嵌套
  格式或尾随非法抛 `ValueError`，嵌套编码器异常原样传播；解码保持三字段
  相等且重编码逐字节相同，不校验签名、证明、段间相邻与锚定关系；两个入口
  均为只读且确定，旧接口和签名域不变
- `inspect_anchored_continuations(bundle, key)` —
  `AnchoredContinuationChain` 的只读诊断入口，等价于
  `inspect_anchors(bundle.receipts, key, bundle.start, bundle.end)`，码集合
  与首错顺序完全沿用 `inspect_anchors`；`bundle` 非
  `AnchoredContinuationChain` 抛 `TypeError`，`key` 及各字段校验与嵌套
  异常原样传播；离线、只读、不新增签名域
- `inspect_anchor_set(items, key)` — 分批落盘的多个
  `AnchoredContinuationChain` 的按序只读核验，两阶段只报最早问题：先按
  包序逐包调用 `inspect_anchored_continuations`，失败码不变且 `index`
  取包内位置加此前各包凭据总数的**全局位置**；仅当各包均成立才比较相邻
  两包，前包 `end` 与后包 `start` 须按 `SignedRoot` 全六字段全等，不符
  报仅由本入口使用的新码 `"anchor_link"`，`index` 取后包首凭据的全局
  位置；全部成立返回 `(True, None, None)`。`items` 非 tuple 或元素非
  `AnchoredContinuationChain` 抛 `TypeError`，空集或 32 字节 `key`
  长度不符抛 `ValueError`，嵌套结构异常原样传播；离线、只读、不持有
  日志、不新增签名域，旧接口与既有码不变
- `merge_anchor_set(items, key)` — 仅当 `inspect_anchor_set` 诊断成功时
  返回**新冻结** `AnchoredContinuationChain`：receipts 按包序、包内序
  拼接，端点取首包 `start` 与末包 `end`，沿用既有
  `encode_anchored_continuations`、不设新格式；诊断失败抛 `ValueError`，
  类型/长度校验与嵌套异常规则同 `inspect_anchor_set`；调用只读，不修改
  任何输入包
- `encode_prune_receipt(receipt)` / `decode_prune_receipt(data)` — 前缀裁剪回执的
  规范二进制编码与解码，使 `PruneReceipt` 可落盘、跨进程恢复后继续用于
  `AuditLog.prune`（编解码只读，旧裁剪行为不变）：字节流为
  `b"auditchain/prune-receipt/v1\0" || version || hash_name || size ||
  merkle_root || chain_hash`；`version` 恒为 `1`，`version` 与 `size` 写 u64，
  `hash_name` 转 UTF-8 后与 `merkle_root`、`chain_hash` 均写 blob
  （`B(x) = U(len(x)) || x`，零长度也是全零 u64）。解码返回字段相等的冻结
  回执，重编码逐字节相同。前者只接受 `PruneReceipt`，后者只接受 `bytes`
  （拒绝 `bytearray` / `memoryview`）；非对应类型或绕过冻结构造器写入的字段
  类型错抛 `TypeError`，魔数、版本、UTF-8、未知或非固定输出算法、截断、尾随、
  blob 长度、u64 范围或摘要宽度（两摘要等宽）非法抛 `ValueError`
- `encode_audit_receipt(receipt)` / `decode_audit_receipt(data)` — 审计回执的规范二进制
  编码与解码：魔数 `b"auditchain/audit-receipt/v1\0"` 开头，整数为 8 字节无符号大端，
  blob 为 u64 长度前缀加原始字节；解码结果字段与原回执相等且重复编码字节相同；
  参数类型错误抛 `TypeError`，编码时整数溢出 u64 或解码时魔数、版本、算法、UTF-8、
  截断、尾随、长度、索引顺序、末条或证明结构非法抛 `ValueError`
- `encode_audit_batch(receipt)` / `decode_audit_batch(data)` — 紧凑批量审计回执五元组
  `(hash_name, size, root, entries, proof)` 的规范二进制编码与解码：魔数
  `b"auditchain/batch/v1\0"` 开头，后接 version=1、hash_name 的 UTF-8 blob、size、
  root blob、entries 计数；整数为 u64 大端，blob 为 u64 长度前缀加原始字节；随后逐个
  Entry 写 index、payload、previous_hash、entry_hash，末尾写共享 proof 的节点计数与
  节点 blob。解码结果与原五元组相等且重复编码字节相同，可继续由
  `verify_audit_batch` 离线核验。前者只接受结构合法的五元组，后者只接受 `bytes`；
  非五元组、非 bytes 或字段类型错抛 `TypeError`，魔数、版本、UTF-8、算法、截断、尾随、
  范围、宽度、顺序、缺末条或节点数不符抛 `ValueError`；内容、根或证明不匹配仍可解码，
  但 `verify_audit_batch` 返回 `False`
- `dump_log(log, private_key)` / `load_log(data, public_key)` — 完整日志状态的
  签名导出与离线恢复，使一份完整、未裁剪、无认证、无加密历史的日志可落盘、跨进程
  恢复为独立、可变的普通无密钥 `AuditLog`：字节流为
  `b"auditchain/log-state/v1\0" || U(1) || B(C) || U(n) || E1…En`，其中
  `C` 是既有 `encode_signed_root(log.sign_root(private_key))` 的完整规范字节，
  `n` 为条目数，每个 `Ei = U(index) || B(payload) || B(previous_hash) ||
  B(entry_hash)`；`U` 为 8 字节无符号大端，`B(x) = U(len(x)) || x`。恢复时以
  公钥验签 `C`，要求索引恰为 `0..n-1`、`C.size == n`，并按 `C.hash_name` 从
  创世零摘要重算 `entry_digest` 链头与 Merkle 根且与 `C` 一致，再以正常
  `append` 路径重放（`find` 索引等随之重建）。导出只读且确定（同状态同种子
  字节相同，私钥不存储、不新增签名原文）；`log` 不是 `AuditLog` 或私钥不是
  `bytes` 抛 `TypeError`，私钥长度非 32 或日志已裁剪 / 带认证状态 / 含加密
  历史抛 `ValueError`。`data` 只接受 `bytes`（拒绝 `bytearray` /
  `memoryview`），公钥类型错抛 `TypeError`；公钥长度非 32、魔数 / 版本 /
  嵌套检查点算法与宽度 / 条目宽度 / 索引顺序 / `C.size` 不符、截断、尾随、
  blob 长度溢出、验签失败或重算链头 / Merkle 根与检查点不一致抛 `ValueError`
- `dump_secure_log(log, private_key)` / `load_secure_log(data, public_key)` —
  含加密历史的完整日志状态的签名导出与离线恢复，使一份完整、未裁剪、无认证
  （但可含 `encrypt` 密文条目）的日志可落盘、跨进程恢复为独立、可变的普通
  无密钥 `AuditLog`：字节流以 `b"auditchain/secure-log/v1\0"` 开头，依次写
  `U(1)`、`B(hash_name 的 UTF-8)`、`U(n)`、`B(root)`、`B(head)` 与 `n` 个
  `E`，末尾追加覆盖此前全部字节的 64 字节 Ed25519 签名；
  `E = U(index) || B(payload) || B(previous_hash) || B(entry_hash) ||
  B(locator)`，`U` 为 8 字节无符号大端、`B(x) = U(len(x)) || x`。`locator`
  空 blob 表示普通条目，否则为与 `hash_name` 同宽的既有加密定位 HMAC。加载
  先验签，再从封装恢复 12 字节 nonce 并拒绝重复，按 `hash_name` 从创世重算
  `entry_digest` 链、`head` 与 Merkle 根并逐项匹配，最后以正常 append / 加密
  恢复路径重放（`find`、`find_encrypted` 定位索引与 nonce 历史随之重建）。
  导出只读且确定（同状态同种子字节相同，私钥不存储）；`log` 不是 `AuditLog`
  或私钥不是 `bytes` 抛 `TypeError`，私钥长度非 32 或日志已裁剪 / 带认证
  状态或历史抛 `ValueError`。`data` 只接受 `bytes`（拒绝 `bytearray` /
  `memoryview`），公钥类型错抛 `TypeError`；公钥非 32 字节，或魔数、版本、
  UTF-8、算法、截断、尾随、索引、摘要 / locator 宽度、密文封装、重复 nonce、
  重算链 / 根、签名不符均抛 `ValueError`
- `dump_pruned_log(log, private_key)` / `load_pruned_log(data, public_key)` —
  已裁剪日志（`retain_from > 0`、无认证、无加密历史）的签名导出与离线恢复，
  使一份已裁剪的普通日志可落盘、跨进程恢复为独立、可变的无密钥 `AuditLog`
  （长度、绝对索引、`retain_from`、Merkle 根与证明均与原日志一致）：字节流为
  `b"auditchain/pruned-log/v1\0" || U(1) || B(hash_name 的 UTF-8) || U(n) ||
  U(r) || B(checkpoint)`，随后是 frontier 计数与按高度升序的
  `U(height) || B(digest)`（高度恰为 `r` 的置位，覆盖 `[0, r)`）、保留条目
  计数与索引 `r..n-1` 的条目（`U(index) || B(payload) || B(previous_hash) ||
  B(entry_hash)`，同 `dump_log`），再写 `B(root)`、`B(head)`，末尾追加覆盖
  此前全部字节的 64 字节 Ed25519 签名；`checkpoint` 为前 `r` 条末条的链摘要，
  与算法摘要等宽。加载先验签，再复核结构、`0 < r <= n`、frontier 高度、条目
  数与索引顺序，从检查点重算链头与 Merkle 根并逐项匹配后重放。导出只读且
  确定（同状态同种子字节相同，私钥不存储）；`log` 不是 `AuditLog` 或私钥
  不是 `bytes` 抛 `TypeError`，私钥长度非 32 或日志未裁剪 / 带认证状态或
  历史 / 含加密历史抛 `ValueError`。`data` 只接受 `bytes`（拒绝
  `bytearray` / `memoryview`），公钥类型错抛 `TypeError`；公钥非 32 字节，
  或魔数、版本、UTF-8、算法、截断、尾随、保留点越界、宽度、frontier 结构、
  条目数、索引顺序、断链、重算链 / 根、签名不符均抛 `ValueError`
- `dump_secure_pruned(log, private_key)` /
  `load_secure_pruned(data, public_key)` — 已裁剪且**可含密文**日志
  （`retain_from > 0`、无认证状态或历史）的签名导出与离线恢复，使一份已
  裁剪、历史中可含 `encrypt` 密文（含已释放密文）的日志可落盘、跨进程恢复
  为独立、可变的无密钥 `AuditLog`（长度、绝对索引、`retain_from`、Merkle
  根、证明、检索索引与 nonce 历史均与原日志一致）：头部复用
  `dump_pruned_log` 的字段顺序与 `U`/`B` 规则，仅将魔数换为
  `b"auditchain/pruned-secure/v1\0"`；frontier 之后写 nonce 计数与按字典序
  的逐项 `B(nonce)`（每项内容须恰为 12 字节，完整保留裁剪前全部已用
  nonce），随后写保留条目计数与索引 `r..n-1` 的 `E` 记录（同
  `dump_secure_log`：`U(index) || B(payload) || B(previous_hash) ||
  B(entry_hash) || B(locator)`，locator 空为普通条目、非空须同摘要宽且密文
  封装须能恢复 12 字节 nonce），末尾 `B(root) || B(head)` 加覆盖此前全部
  字节的 64 字节 Ed25519 签名。加载先验签，再复核结构、nonce 宽度 / 字典序
  / 无重复、保留密文 nonce 在历史集合中、locator 与密文封装，从检查点重算
  链头与 Merkle 根并逐项匹配后经 append / 加密恢复路径重放。导出只读且
  确定（同状态同种子字节相同，私钥不存储）；`log` 不是 `AuditLog` 或私钥
  不是 `bytes` 抛 `TypeError`，私钥长度非 32 或日志未裁剪 / 带认证状态或
  历史抛 `ValueError`。`data` 只接受 `bytes`（拒绝 `bytearray` /
  `memoryview`），两密钥均须为 32 字节 `bytes`，类型错抛 `TypeError`；公钥
  长度、魔数、版本、UTF-8、算法、截断、尾随、保留点、frontier 结构、nonce
  宽度 / 顺序、密文 nonce 缺失或重复、locator / 密文封装、条目数、索引、
  断链、重算链 / 根、签名不符均抛 `ValueError`；失败原子，旧接口不变
- `dump_auth(log, key, nonce=None)` / `load_auth(data, key)` — 构造时带
  `key` 的前向安全认证日志（未裁剪、无 `encrypt` 历史）的加密导出与恢复，
  使日志可落盘、跨进程重启后从同一演进点继续前向安全认证，恢复出独立、可变
  的带密钥 `AuditLog`（长度、链头、Merkle 根、`find` 索引与 `stage` 均与原
  日志一致）：字节流为 `D || 0x01 || N || C`，
  `D = b"auditchain/auth-log/v1\0"`，`0x01` 为 AES-256-GCM 算法号，`N` 为
  12 字节 nonce，`C` 为明文帧 `P` 的 AESGCM 输出（`ciphertext || 16 字节
  tag`），AAD 为 `D || 0x01 || N`；
  `P = B(h) || U(n) || E1…En || B(root) || B(head) || U(stage) ||
  B(K) || U(x)`，`h` 为 `hash_name` 的 UTF-8，`K` 为当前演进密钥，`x` 为
  验证材料已导出标志（以 u64 编码，值为 0/1）；每个 `E` 按
  `Entry(index, payload, previous_hash, entry_hash)` 字段序以 `U, B, B, B`
  编码，索引须恰为 `0..n-1`。加载先通过 GCM 认证，再按 `h` 从创世重算链与
  Merkle 根并与 `head` / `root` 比对，最后以正常 `append` 路径重放并装入
  `K`、`stage` 与标志。`key` 须为 32 字节 `bytes`，`nonce=None` 时随机
  12 字节、显式值同 key 复用由调用方避免；类型错抛 `TypeError`，资格、格式、
  校验或 AEAD 认证失败抛 `ValueError`；导出只读、失败原子，旧接口不变
- `dump_pruned_auth(log, key, nonce=None)` / `load_pruned_auth(data, key)` —
  构造时带 `key` 的前向安全认证日志**已裁剪**（`retain_from > 0`）且无
  `encrypt` 历史时的加密导出与恢复，使日志裁剪后仍可落盘、跨进程重启并从
  同一演进点继续前向安全认证，恢复出独立、可变的带密钥 `AuditLog`（长度、
  绝对索引、`retain_from`、链头、Merkle 根、包含证明、`find` 索引与
  `stage` 均与原日志一致）：字节流为 `D || 0x01 || N || C`，
  `D = b"auditchain/pruned-auth/v1\0"`，`0x01` 为 AES-256-GCM 算法号，
  `N` 为 12 字节 nonce，`C` 为明文帧 `P` 的 AESGCM 输出（`ciphertext ||
  16 字节 tag`），AAD 为 `D || 0x01 || N`；
  `P = B(hash_name) || U(n) || U(r) || B(checkpoint) || F || E ||
  B(root) || B(head) || U(stage) || B(K) || U(x)`；`F` 为 u64 计数后按
  高度升序的 `U(height) || B(digest)`（高度恰为 `r` 的置位，覆盖
  `[0, r)`），`E` 为 u64 计数（恰 `n - r`）后按 `r..n-1` 排列的 Entry，
  字段编码同 `dump_auth`；`x` 以 u64 编码、值为 0/1。加载先通过 GCM 认证，
  再复核 `0 < r <= n`、checkpoint / frontier 结构、条目计数与索引，从检查点
  重算链与 Merkle 根并与 `head` / `root` 比对，最后以正常 `append` 路径
  重放并装入 `K`、`stage` 与标志。`key` 须为 32 字节 `bytes`，显式 nonce
  须为 12 字节 `bytes`，`data` 只收 `bytes`；类型错抛 `TypeError`，资格、
  长度、格式、校验或 AEAD 认证失败抛 `ValueError`；导出只读、失败原子，
  旧接口不变
- `dump_hybrid(log, key, nonce=None)` / `load_hybrid(data, key)` — 构造时带
  `key`、未裁剪且**允许 `encrypt` 历史**的前向安全认证日志的混合加密导出与
  恢复（`dump_auth` 与 `dump_secure_log` 的混合），恢复出独立、可变的带密钥
  `AuditLog`（长度、链头、Merkle 根、`find` / `find_encrypted` 索引、nonce
  历史与 `stage` 均与原日志一致）：字节流为 `D || 0x01 || N || C`，
  `D = b"auditchain/hybrid/v1\0"`，`0x01` 为 AES-256-GCM 算法号，`N` 为
  12 字节 nonce，`C` 为明文帧 `P` 的 AESGCM 输出（`ciphertext || 16 字节
  tag`），AAD 为 `D || 0x01 || N`；
  `P = B(h) || U(q) || B(nonce1)…B(nonceq) || U(n) || E1…En ||
  B(root) || B(head) || U(stage) || B(K) || U(x)`，`h` 为 `hash_name` 的
  UTF-8，`q` 个 nonce 各 12 字节、按字典序排列，`K` 为当前演进密钥，`x` 为
  验证材料已导出标志（以 u64 编码，值为 0/1）；每个 `E` 复用
  `dump_secure_log` 的 `U, B, B, B, B` 编码与 locator 判型，索引须恰为
  `0..n-1`。加载先通过 GCM 认证，再复核 nonce 历史（宽度、字典序、与密文
  封装恢复的 nonce 集合一致）、各宽度与范围，从创世重算链与 Merkle 根并与
  `head` / `root` 比对，最后原子重建全部索引与认证状态。`key` 须为 32 字节
  `bytes`，`nonce=None` 时随机 12 字节、显式值同 key 复用由调用方避免；
  类型错抛 `TypeError`，资格、长度、格式、认证或状态不一致抛
  `ValueError`；导出只读、失败原子，旧接口不变
- `dump_pruned_hybrid(log, key, nonce=None)` /
  `load_pruned_hybrid(data, key)` — 构造时带 `key`、**已裁剪**
  （`retain_from > 0`）且历史可含 `encrypt` 条目（含被裁剪释放的密文）的
  前向安全认证日志的混合加密导出与恢复，恢复出独立、可变的带密钥 `AuditLog`
  （长度、`retain_from`、链头、完整 Merkle 根与包含证明、`find` /
  `find_encrypted` 索引、完整 nonce 历史与 `stage` 均与原日志一致）：字节流
  严格复用 `dump_hybrid` 的 `D || 0x01 || N || C` 与 AES-256-GCM（AAD 为
  `D || 0x01 || N`），仅 `D = b"auditchain/pruned-hybrid/v1\0"`；
  `P = B(h) || U(n) || U(r) || B(checkpoint) || F || Q || E ||
  B(root) || B(head) || U(stage) || B(K) || U(x)`；`F` 沿用
  `dump_pruned_auth` 的 frontier 编码（高度恰为 `r` 的置位，覆盖 `[0, r)`），
  `Q` 复用 `dump_hybrid` 的完整 nonce 历史（12 字节、字典序、含被释放密文的
  nonce），`E` 为 u64 计数（恰 `n - r`）后按 `r..n-1` 排列的
  `dump_secure_log` 记录（`U, B, B, B, B`，locator 判型），尾部为
  `dump_hybrid` 的认证状态。加载先通过 GCM 认证，再复核 frontier、完整
  nonce 历史、locator（保留密文 nonce 须在历史中且不重复）、各宽度与范围，
  从检查点重算链与完整 Merkle 根并与 `head` / `root` 比对，最后原子重建全部
  索引与认证状态。`key` 须为 32 字节 `bytes`，显式 nonce 须为 12 字节
  `bytes`，`data` 只收 `bytes`；类型错抛 `TypeError`，资格、长度、格式、
  认证或状态冲突抛 `ValueError`；导出只读、失败原子，旧接口不变
- `verify_auth(entry, tag, verifier)` — 先校验 `tag.stage`（非 `bool` 整数且 `< 2**64`），
  再用 `entry_digest` 核对 `entry.entry_hash` 与条目内容一致，
  最后把验证方密钥演进到 `tag.stage` 校验 HMAC，无需持有日志；匹配返回 `True`，
  结构合法但内容不符（含篡改条目、错误标签、错误 stage、错误密钥）返回 `False`；
  入参类型错误抛 `TypeError`，负 stage/index、stage 达到 `2**64`、摘要长度不符、
  未知算法等抛 `ValueError`
- `verify_auth_batch(items, verifier)` — 逐项调用 `verify_auth` 核验
  `(Entry, AuthTag)` 对，返回同序 `tuple[bool, ...]`（空 tuple 返回 `()`）。
  `items` 只接受 `tuple`，且 `Entry.index` 严格升序、`AuthTag.stage` 连续；
  容器或元素类型错抛 `TypeError`，重复、范围、顺序、容量（index/stage 达到 `2**64`）
  或摘要结构错抛 `ValueError`；结构合法但不匹配仅令对应位置为 `False`
- `encode_auth_batch(items, *, hash_name="sha256")` /
  `decode_auth_batch(data)` — 前向安全批量认证材料的规范二进制编码与解码，使
  `auth_batch` 结果可落盘、跨进程恢复后继续由 `verify_auth_batch` 离线核验（编解码
  只读、确定，旧接口不变；字节流不含 verifier / 密钥）：魔数
  `b"auditchain/auth-batch/v1\0"` 开头，依次写 version=1（u64）、`hash_name` 的
  UTF-8 blob、项数（u64）与各项；整数为 u64 大端，blob 为 u64 长度前缀加原始字节
  （零长度也写全零 u64）。各项依次写 `index`、`payload`、`previous_hash`、
  `entry_hash`（index 为 u64，其余 blob）、`stage`（u64）、`tag`（blob）。
  `encode_auth_batch` 只收既有批量项元组（容器 / 字段类型错抛 `TypeError`；u64
  范围、算法、摘要 / 标签宽度、索引顺序或 stage 连续性错误抛 `ValueError`），
  `decode_auth_batch` 只接受 `bytes`（其他类型抛 `TypeError`），魔数、版本、UTF-8、
  算法、截断、尾随、计数、宽度、u64 范围、索引顺序或 stage 连续性错误抛
  `ValueError`；返回 `(hash_name, items)`，`items` 为不可变项元组，重编码逐字节
  相同；结构合法但认证不匹配仍可解码，`verify_auth_batch` 逐项返回 `False`

Merkle 树按 `hash_name` 构建：叶为 `H("auditchain/merkle-leaf/v1" + entry_hash)`，父节点为
`H("auditchain/merkle-node/v1" + left + right)`，奇数层末节点原样提升；空树根为
`H("auditchain/merkle-empty/v1")`，单叶根即叶本身。

一致性证明的节点顺序遵循 RFC 6962 §2.1.2 的 SUBPROOF 递归（子树根按同一提升规则计算）。
两个特例：`old_size == new_size` 只接受空证明且要求两根相等；`old_size == 0` 只接受空证明，
旧根须为规范空树根 `H("auditchain/merkle-empty/v1")`，此时新根格式合法即通过（`0 -> 0` 仍须两根相等）。

批量包含证明用一份 `proof` 覆盖快照中的多个所选叶，递归覆盖整个 `[0, size)`：当前子树长度
`n > 1` 时取小于 `n` 的最大二的幂 `k`，按左 `[0, k)` 后右 `[k, n)` 的顺序处理；不含任何
所选索引的子树只追加其 Merkle 根，含所选索引的子树继续递归，所选单叶不追加任何节点。
因此多个所选叶共享的子树摘要只出现一次，比各自独立的包含证明更紧凑；哈希与奇数层末节点
原样提升沿用上面的 Merkle 规则。所选叶的摘要由验证方按升序在 `entry_hashes` 中提供，
空快照（`size=0`）不存在非空选择，故无对应的批量证明。

## 限制

线性哈希链加顺序遍历校验，保留段查询是 `O(n)` 的（证明生成随保留长度增长）。
已封存前缀的 payload 被释放后不可再取回，其前缀快照也无法重建。普通 `append`
的条目内容明文存储；需要保密时用 `encrypt` 追加 AES-256-GCM 密文，密钥从不落盘、
由调用方按次提供，nonce 历史（每条 12 字节）为日志全程保留。认证标签提供前向安全：
stage-0 密钥需在首次演进前通过 `export_verifier()` 另行交给验证方，日志自身演进后
不保留任何旧密钥。

## 测试

```bash
python3 -m unittest discover -s tests
```
