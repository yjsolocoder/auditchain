# auditchain

只追加的哈希链审计日志。每条条目把自身内容与前一条的摘要绑在一起，任何历史篡改都会让整链校验失败。

## 环境

Python 3.10+。只依赖标准库（`hashlib` / `hmac` / `os`）与
[`cryptography`](https://cryptography.io/)（加密追加使用其中的 `AESGCM`）。

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
- `encode_audit_receipt(receipt)` / `decode_audit_receipt(data)` — 审计回执的规范二进制
  编码与解码：魔数 `b"auditchain/audit-receipt/v1\0"` 开头，整数为 8 字节无符号大端，
  blob 为 u64 长度前缀加原始字节；解码结果字段与原回执相等且重复编码字节相同；
  参数类型错误抛 `TypeError`，编码时整数溢出 u64 或解码时魔数、版本、算法、UTF-8、
  截断、尾随、长度、索引顺序、末条或证明结构非法抛 `ValueError`
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
