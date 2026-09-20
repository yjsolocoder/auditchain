# auditchain

只追加的哈希链审计日志。每条条目把自身内容与前一条的摘要绑在一起，任何历史篡改都会让整链校验失败。

## 环境

Python 3.10+。只依赖标准库（`hashlib` / `hmac` / `os`）与
[`cryptography`](https://cryptography.io/)（加密追加使用其中的 `AESGCM`）。

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

空前缀回执（`seal(0)`，`chain_hash == GENESIS_HASH`）匹配创世条目：
`receipt.matches(entry)` 当且仅当 `entry.index == 0` 且
`entry.previous_hash == GENESIS_HASH`。

### 保留策略（封存 + 裁剪一步原子完成）

`apply_retention(value, *, mode="retain_from")` 先按模式算出保留点，再原子地
封存并裁剪，成功时等价于 `receipt = log.seal(target)` 后
`log.prune(target, receipt)`，返回该 `PruneReceipt`：

```python
receipt = log.apply_retention(2)              # mode="retain_from"：target = value = 2
receipt = log.apply_retention(3, mode="keep_last")  # 只保留最新 3 条
```

- `mode` 只接受 `"retain_from"` 或 `"keep_last"`：
  - `"retain_from"`（默认）令目标保留点等于 `value`，要求
    `retain_from <= value <= len(log)`（保留点只能前移）
  - `"keep_last"` 令目标保留点等于 `max(retain_from, len(log) - value)`，
    要求 `value >= 0`；保留条数超过日志长度时为空操作（已释放前缀不可恢复）
- `value` 须为非 `bool` 整数；`value` 或 `mode` 类型非法抛 `TypeError`，
  未知 `mode` 或违反上述范围抛 `ValueError`
- 任何失败都在修改状态前抛出：条目、认证状态、定位索引、Merkle 状态与
  nonce 使用记录全部保持不变（加密 nonce 跨裁剪仍不可复用）

### 离线审计回执

```python
receipt = log.audit_receipt([1, 3])     # 自动并入末条；size 默认当前长度
receipt.items                           # ((Entry, proof), ...) 按绝对索引升序
verify_audit_receipt(receipt)           # True：无需持有日志即可离线核验
```

回执为冻结的 `AuditReceipt(version=1, hash_name, size, root, items)`，记录快照
Merkle 根与所选条目的包含证明；`verify_audit_receipt` 重算每条 `entry_digest`
并核验全部包含证明、根与末条摘要。空选择（`[]`）得到 `items == ()` 的回执；
`size=0` 的空快照回执只接受规范空树根。签发是只读的，不影响日志任何状态。

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
- `verify()` 从封存检查点（末条摘要）向前校验保留段
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
  - `merkle_root` 为该前缀的 Merkle 根，`chain_hash` 为末条摘要（空前缀为 `GENESIS_HASH`）
  - `matches(entry)` — 核对某条目是否为裁剪后首条保留记录（绝对索引等于 `size` 且前驱摘要等于 `chain_hash`），
    是返回 `True`，否则 `False`；空前缀回执匹配索引为 0、前驱为 `GENESIS_HASH` 的创世条目；
    入参不是 `Entry` 抛 `TypeError`
- `AuditReceipt(version, hash_name, size, root, items)` — 不可变的离线审计回执，
  按字段相等、支持位置构造；`version` 恒为 `1`，`root` 为快照 Merkle 根，
  `items` 为按绝对索引升序的 `(Entry, 证明元组)` 元组，非空回执必含 `index == size - 1`
  的末条；类型非法抛 `TypeError`，版本、范围、未知算法、摘要长度或条目结构非法抛 `ValueError`
- `GENESIS_HASH` — 全零的起始前驱摘要
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
  - `verify()` — 从创世摘要（裁剪后从检查点）开始校验持有的链段
  - `verify_entry(index)` — 只校验某条与前驱的连接
  - `auth(index)` — 为保留段中的条目签发不可变 `AuthTag`，返回后立即以
    `H(b"auditchain/key-evolve/v1" + K)` 替换密钥、stage 加一，不保存旧密钥、不追加条目；
    无密钥模式调用抛 `ValueError`
  - `rotate_key()` — 只演进密钥一次（stage 加一），不签发标签、不追加条目；无密钥模式抛 `ValueError`
  - `export_verifier()` — 仅可在首次演进前调用一次，返回不可变 `Verifier`；
    演进后或再次调用抛 `ValueError`，无密钥模式抛 `ValueError`
  - `merkle_root(size=None)` — 前 `size` 条（默认全部）的前缀 Merkle 根；追加不影响已有前缀根
  - `inclusion_proof(index, size=None)` — 叶到根的兄弟摘要不可变元组
  - `consistency_proof(old_size, new_size=None)` — 两个前缀快照之间的一致性证明，不可变元组；
    要求 `0 <= old_size <= new_size <= len(log)`，后续追加不改变同一前缀对的证明
  - `seal(size=None)` — 为前 `size` 条（默认当前长度）生成 `PruneReceipt`，记录前缀根与末条摘要，
    空前缀记录 `GENESIS_HASH`
  - `audit_receipt(indices, size=None)` — 为快照中选定条目生成离线 `AuditReceipt`：
    `indices` 为可迭代的互异非 `bool` 整数，须满足 `retain_from <= index < size`；
    `size` 默认当前长度，快照须可重建；非空选择自动并入末条（`index == size - 1`），
    空选择及空快照得到 `items == ()`；条目按绝对索引升序携带各自包含证明；
    调用只读，类型非法抛 `TypeError`，越界或重复抛 `ValueError`
  - `prune(retain_from, receipt)` — 在校验通过后释放前 `retain_from` 条的 payload 及其认证标签：
    要求 `retain_from == receipt.size`，且回执的算法、Merkle 根、链摘要与日志一致；
    保留点只可前移（数值增大）且不可越界，类型非法抛 `TypeError`，越界、回退、
    回执不匹配或无有效回执抛 `ValueError`
  - `apply_retention(value, *, mode="retain_from")` — 按保留策略原子完成封存与裁剪，
    返回 `PruneReceipt`，成功等价于 `seal(target)` 后 `prune(target, receipt)`。
    `mode="retain_from"` 令 `target = value`，要求
    `retain_from <= value <= len(log)`；`mode="keep_last"` 令
    `target = max(retain_from, len(log) - value)`，要求 `value >= 0`。
    `value` 须为非 `bool` 整数，`mode` 须为字符串；类型非法抛 `TypeError`，
    未知 `mode` 或越界抛 `ValueError`；任何失败均不改变日志、认证、索引、
    Merkle 与 nonce 状态
- `entry_digest(index, previous_hash, payload, *, hash_name)` — 条目摘要计算
- `decrypt_entry(entry, key, *, hash_name="sha256")` — 解密 `AuditLog.encrypt` 产生的
  条目，无需持有日志：先校验封装格式与 `entry_hash == entry_digest(...)`（封装作为
  payload），再以 `b"auditchain/aead/v1\0" || 0x01 || index(u64 大端) ||
  previous_hash` 为 AAD 校验 AES-256-GCM 标签，全部通过才返回明文 bytes
  （规则同 `append`）。入参不是 `Entry` 或 `key`/字段类型非法抛 `TypeError`；
  `key` 长度非 32、封装魔数不符或截断、算法号未知、摘要长度不符、`entry_hash`
  不符、密钥错误或 AEAD 认证失败抛 `ValueError`；调用只读，不改变条目或日志
- `verify_inclusion(entry_hash, index, size, root, proof, *, hash_name="sha256")` — 只凭条目摘要、快照大小与根摘要验证包含证明，无需持有日志
- `verify_consistency(old_size, old_root, new_size, new_root, proof, *, hash_name="sha256")` — 只凭两次快照的大小、根与证明验证后者由前者追加形成，无需日志；
  结构非法抛 `TypeError`/`ValueError`，结构合法但不匹配返回 `False`
- `verify_audit_receipt(receipt)` — 无需持有日志即可验证 `AuditReceipt`：重算每个条目的
  `entry_digest` 并核验全部包含证明与快照根，空快照只接受规范空树根；结构合法但条目内容、
  证明或根不符返回 `False`；入参不是 `AuditReceipt` 抛 `TypeError`，字段结构、摘要长度或
  证明结构非法抛 `ValueError`
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
