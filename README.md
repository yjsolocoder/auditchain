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
print(log.head().hex())
```

## 命令行演示

```bash
python3 -m auditchain
```

## 公开接口

- `Entry(index, payload, previous_hash, entry_hash)` — 不可变条目
- `GENESIS_HASH` — 全零的起始前驱摘要
- `AuditLog(*, hash_name="sha256")`
  - `append(payload)` — 接受 `bytes` 或 `str`（UTF-8 编码），返回新条目
  - `entries()` / `entry(index)` / `__len__()` / `head()`
  - `verify()` — 从创世摘要开始整链校验
  - `verify_entry(index)` — 只校验某条与前驱的连接
  - `merkle_root(size=None)` — 前 `size` 条（默认全部）的前缀 Merkle 根；追加不影响已有前缀根
  - `inclusion_proof(index, size=None)` — 叶到根的兄弟摘要不可变元组
  - `consistency_proof(old_size, new_size=None)` — 证明前 `old_size` 条是前 `new_size` 条（默认全部）
    的前缀，返回按 RFC 6962 §2.1.2 SUBPROOF 顺序排列的不可变摘要元组；追加不改变同一前缀对的证明
- `entry_digest(index, previous_hash, payload, *, hash_name)` — 条目摘要计算
- `verify_inclusion(entry_hash, index, size, root, proof, *, hash_name="sha256")` — 只凭条目摘要、快照大小与根摘要验证包含证明，无需持有日志
- `verify_consistency(old_size, old_root, new_size, new_root, proof, *, hash_name="sha256")` —
  只凭两次快照的大小、根与一致性证明确认后者由前者追加形成，无需持有日志。等大快照只接受空证明且
  两根相等；`old_size=0` 只接受空证明和规范空树旧根（`0` 到 `0` 仍须两根相等）；结构合法但不匹配
  返回 `False`，非法输入抛 `TypeError`/`ValueError`

Merkle 树按 `hash_name` 构建：叶为 `H("auditchain/merkle-leaf/v1" + entry_hash)`，父节点为
`H("auditchain/merkle-node/v1" + left + right)`，奇数层末节点原样提升；空树根为
`H("auditchain/merkle-empty/v1")`，单叶根即叶本身。该提升规则等价于按"小于 `n` 的最大 2 的幂"
递归拆分，一致性证明沿用 RFC 6962 §2.1.2 的 SUBPROOF 节点顺序。

## 限制

当前是最小可用形态：线性哈希链加顺序遍历校验，查询是 `O(n)` 的；Merkle 包含证明与跨快照一致性
证明均已支持。条目内容明文存储，没有加密、没有前向安全的密钥演进、也没有保留策略与裁剪能力。

## 测试

```bash
python3 -m unittest discover -s tests
```
