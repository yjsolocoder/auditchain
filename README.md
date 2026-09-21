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

### 前向安全认证

构造日志时传入一个非空 `key` 即可开启前向安全认证；不传 `key` 的无密钥模式
行为与以前完全一致，认证接口禁用。每次 `auth()` 签发标签后立即以单向哈希演进
密钥并丢弃旧密钥，之后即使当前密钥泄露也无法伪造更早条目的标签：

```python
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
- `SignedAuditBatch(batch, checkpoint)` — 不可变的可信紧凑批量审计包，按两个
  字段相等、支持位置构造；`batch` 为 `audit_batch` 的五元组（必须是 `tuple`），
  `checkpoint` 为同一快照的 `SignedRoot`（必须是 `SignedRoot`）；容器字段类型错
  抛 `TypeError`，批量五元组内部的结构契约由 `verify_audit_batch` 校验
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
  - `rotate_key()` — 只演进密钥一次（stage 加一），不签发标签、不追加条目；无密钥模式抛 `ValueError`
  - `export_verifier()` — 仅可在首次演进前调用一次，返回不可变 `Verifier`；
    演进后或再次调用抛 `ValueError`，无密钥模式抛 `ValueError`
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
  - `signed_audit_batch(indices, private_key, size=None)` — 只读签发可信紧凑批量
    审计包，返回不可变 `SignedAuditBatch`：先调用 `audit_batch(indices, size)`，
    再调用 `sign_root(private_key, size)`（`size` 默认当前长度），据此构造
    `SignedAuditBatch(batch, checkpoint)`，两部分描述同一快照，且不新增签名原文。
    失败（非法选择、种子或 `size`）在构造前抛出，不改变日志状态；异常类型沿用
    `audit_batch` / `sign_root`（`TypeError` / `ValueError`）；离线用
    `verify_signed_audit_batch` 凭预信任公钥验真
  - `prune(retain_from, receipt)` — 在校验通过后释放前 `retain_from` 条的 payload 及其认证标签：
    要求 `retain_from == receipt.size`，且回执的算法、Merkle 根、链摘要与日志一致；
    保留点只可前移（数值增大）且不可越界，类型非法抛 `TypeError`，越界、回退、
    回执不匹配或无有效回执抛 `ValueError`
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
- `verify_signed_root(receipt, public_key)` — 凭预先信任的 32 字节 Ed25519 公钥
  离线验证 `AuditLog.sign_root` 签发的 `SignedRoot`：重建同一签名原文
  `D || 0x01 || B(hash_name 的 UTF-8) || U(size) || B(root) || B(head)`
  （`D = b"auditchain/signed-root/v1\0"`，`U` 为 8 字节无符号大端，
  `B(x) = U(len(x)) || x`）并校验其 64 字节签名，无需持有日志；公钥不是对应
  签发方，或结构合法但 `root`、`head`、`signature` 等被改返回 `False`，匹配
  返回 `True`。入参不是 `SignedRoot` 或公钥不是 `bytes` 抛 `TypeError`；版本、
  未知算法、`size` 范围、摘要宽度、签名长度或公钥长度（非 32 字节）非法抛
  `ValueError`；调用只读
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
- `verify_auth(entry, tag, verifier)` — 先校验 `tag.stage`（非 `bool` 整数且 `< 2**64`），
  再用 `entry_digest` 核对 `entry.entry_hash` 与条目内容一致，
  最后把验证方密钥演进到 `tag.stage` 校验 HMAC，无需持有日志；匹配返回 `True`，
  结构合法但内容不符（含篡改条目、错误标签、错误 stage、错误密钥）返回 `False`；
  入参类型错误抛 `TypeError`，负 stage/index、stage 达到 `2**64`、摘要长度不符、
  未知算法等抛 `ValueError`

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
