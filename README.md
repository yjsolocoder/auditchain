# auditchain

只追加的哈希链审计日志。每条条目把自身内容与前一条的摘要绑在一起，任何历史篡改都会让整链校验失败。

## 环境

Python 3.10+，只依赖标准库（`hashlib`）。

## 使用

```python
from auditchain import AuditLog

log = AuditLog()
log.append("agent started")
log.append({"event": "position-claim", "lat": -73.9})
print(log.verify())        # True
print(log.head.hex())
```

## 命令行演示

```bash
python3 -m auditchain
```

## 公开接口

- `Entry(index, payload, previous_hash, entry_hash)` — 不可变条目
- `PruneReceipt(hash_name, size, merkle_root, chain_hash)` — 不可变裁剪回执，封存一个前缀的
  Merkle 根与末条链摘要（空前缀的 `chain_hash` 为 `GENESIS_HASH`）
  - `matches(entry)` — 核对条目是否为该前缀之后的首条保留记录（索引等于 `size` 且前驱摘要等于
    `chain_hash`），匹配返回 `True`，否则 `False`；非 `Entry` 抛 `TypeError`
- `GENESIS_HASH` — 全零的起始前驱摘要
- `AuditLog(*, hash_name="sha256")`
  - `append(payload)` — 接受 `bytes` 或 `str`（UTF-8 编码），返回新条目
  - `entries()` / `entry(index)` / `__len__()` / `head()`
  - `verify()` — 从检查点（裁剪保留点，未裁剪时为创世摘要）开始整链校验
  - `verify_entry(index)` — 只校验某条与前驱的连接
  - `merkle_root(size=None)` — 前 `size` 条（默认全部）的前缀 Merkle 根；追加不影响已有前缀根
  - `inclusion_proof(index, size=None)` — 叶到根的兄弟摘要不可变元组
  - `consistency_proof(old_size, new_size=None)` — 两个前缀快照之间的一致性证明，不可变元组；
    要求 `0 <= old_size <= new_size <= len(log)`，后续追加不改变同一前缀对的证明
  - `seal(size=None)` — 为前 `size` 条（默认当前全部）生成 `PruneReceipt`
  - `prune(retain_from, receipt)` — 校验回执后释放保留点之前条目的内容，详见下节
- `entry_digest(index, previous_hash, payload, *, hash_name)` — 条目摘要计算
- `verify_inclusion(entry_hash, index, size, root, proof, *, hash_name="sha256")` — 只凭条目摘要、快照大小与根摘要验证包含证明，无需持有日志
- `verify_consistency(old_size, old_root, new_size, new_root, proof, *, hash_name="sha256")` — 只凭两次快照的大小、根与证明验证后者由前者追加形成，无需持有日志；
  结构非法抛 `TypeError`/`ValueError`，结构合法但不匹配返回 `False`

Merkle 树按 `hash_name` 构建：叶为 `H("auditchain/merkle-leaf/v1" + entry_hash)`，父节点为
`H("auditchain/merkle-node/v1" + left + right)`，奇数层末节点原样提升；空树根为
`H("auditchain/merkle-empty/v1")`，单叶根即叶本身。

一致性证明的节点顺序遵循 RFC 6962 §2.1.2 的 SUBPROOF 递归（子树根按同一提升规则计算）。
两个特例：`old_size == new_size` 只接受空证明且要求两根相等；`old_size == 0` 只接受空证明，
旧根须为规范空树根 `H("auditchain/merkle-empty/v1")`，此时新根格式合法即通过（`0 -> 0` 仍须两根相等）。

## 可验证前缀裁剪

当日志增长后需要释放历史内容时，先 `seal` 封存前缀拿到回执，再凭回执 `prune`：

```python
receipt = log.seal(1000)      # 封存前 1000 条：记录其 Merkle 根与末条链摘要
log.prune(1000, receipt)      # 校验回执与日志一致后，释放这 1000 条的内容
```

`prune` 要求 `retain_from` 等于回执的 `size`，且回执的算法、Merkle 根、链摘要都与日志匹配；
保留点只能前移、不能越界。类型非法抛 `TypeError`，越界、回退或回执不匹配抛 `ValueError`。

裁剪后索引仍是绝对值，行为与未裁剪日志一致：

- `len(log)` 仍是累计条数，`head`、`append` 及新产生的 `Entry` 与未裁剪日志完全相同；
- `verify()` 从保留点检查点继续校验，无需被删内容；
- `entries()` 只列保留段；`entry()` / `verify_entry()` 访问已裁剪索引抛 `IndexError`，
  `inclusion_proof` 对已裁剪索引抛 `ValueError`；
- `merkle_root` 与 `consistency_proof` 对保留点及之后的快照给出与未裁剪日志相同的结果
  （裁剪点之前的快照已丢失，抛 `ValueError`），因此保留点到任意后续前缀的一致性证明始终可用。

实现上，裁剪时把被删前缀折叠成 Merkle 前沿（其二进制分解的子树根集，仅 O(log n) 个摘要），
配合保留点链摘要作为检查点，即可在不保留任何已删内容的情况下重建后续证明。

## 限制

当前是最小可用形态：线性哈希链加顺序遍历校验，查询是 `O(n)` 的；Merkle 包含证明、跨快照
一致性证明与可验证前缀裁剪已支持。条目内容明文存储，没有加密，也没有前向安全的密钥演进。

## 测试

```bash
python3 -m unittest discover -s tests
```
