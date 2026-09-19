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
- `entry_digest(index, previous_hash, payload, *, hash_name)` — 条目摘要计算

## 限制

当前是最小可用形态：线性哈希链加顺序遍历校验。查询是 `O(n)` 的，没有 Merkle 树、没有单条包含证明、没有跨快照的一致性证明，因此无法在不交出全量日志的前提下向第三方证明某条存在。条目内容明文存储，没有加密、没有前向安全的密钥演进、也没有保留策略与裁剪能力。

## 测试

```bash
python3 -m unittest discover -s tests
```
