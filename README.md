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
- `entry_digest(index, previous_hash, payload, *, hash_name)` — 条目摘要计算
- `verify_inclusion(entry_hash, index, size, root, proof, *, hash_name="sha256")` — 只凭条目摘要、快照大小与根摘要验证包含证明，无需持有日志

Merkle 树按 `hash_name` 构建：叶为 `H("auditchain/merkle-leaf/v1" + entry_hash)`，父节点为
`H("auditchain/merkle-node/v1" + left + right)`，奇数层末节点原样提升；空树根为
`H("auditchain/merkle-empty/v1")`，单叶根即叶本身。

## 限制

当前是最小可用形态：线性哈希链加顺序遍历校验，查询是 `O(n)` 的；Merkle 包含证明已支持，
但还没有跨快照的一致性证明。条目内容明文存储，没有加密、没有前向安全的密钥演进、也没有保留策略与裁剪能力。

## 测试

```bash
python3 -m unittest discover -s tests
```
