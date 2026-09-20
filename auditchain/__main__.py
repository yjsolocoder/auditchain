"""Self-contained demo: python3 -m auditchain"""

from __future__ import annotations

import os

from . import AuditLog, decrypt_entry, entry_digest, verify_audit_batch, verify_audit_receipt

RECORDS = [
    "agent started",
    "position claim: -73.9857,40.7484",
    "witness counter-signed",
    "position claim: -73.9851,40.7480",
]


def main() -> int:
    log = AuditLog()
    for record in RECORDS:
        entry = log.append(record)
        print(f"  #{entry.index} previous={entry.previous_hash.hex()[:16]}… hash={entry.entry_hash.hex()[:16]}…")
        print(f"       payload={entry.payload.decode('utf-8')!r}")

    print()
    print(f"entries={len(log)}  head={log.head.hex()[:32]}…  verify={log.verify()}")

    print()
    print("every entry links to its predecessor:")
    print(f"  {all(log.verify_entry(index) for index in range(len(log)))}")

    print()
    print("tamper detection:")
    forged = entry_digest(2, log.entry(1).entry_hash, b"witness counter-signed NOW")
    print(f"  recomputing entry #2 with changed payload gives")
    print(f"    {forged.hex()[:32]}…")
    print(f"  which differs from the recorded hash: {forged != log.entry(2).entry_hash}")

    print()
    print("encrypted append (AES-256-GCM):")
    key = os.urandom(32)
    secret = log.encrypt("classified position claim", key)
    print(f"  #{secret.index} payload={secret.payload[:31].decode('ascii', 'replace')!r}…")
    print(f"  decrypts offline to: {decrypt_entry(secret, key).decode('utf-8')!r}")
    print(f"  find never decrypts: plaintext hits={log.find(b'classified position claim')}")

    print()
    print("offline audit receipt:")
    audit = log.audit_receipt([1, 3])
    print(f"  size={audit.size} items={[entry.index for entry, _ in audit.items]}")
    print(f"  verifies without the log: {verify_audit_receipt(audit)}")

    print()
    print("compact offline batch audit receipt:")
    hash_name, size, root, entries, proof = log.audit_batch([1, 3])
    print(f"  hash={hash_name} size={size} items={[entry.index for entry in entries]} proof nodes={len(proof)}")
    print(f"  verifies without the log: {verify_audit_batch((hash_name, size, root, entries, proof))}")

    print()
    print("verifiable prefix pruning:")
    receipt = log.seal(2)
    print(f"  sealed prefix: size={receipt.size} root={receipt.merkle_root.hex()[:16]}…")
    print(f"  receipt matches the first retained entry: {receipt.matches(log.entry(2))}")
    log.prune(2, receipt)
    log.append("post-prune witness")
    print(f"  len={len(log)}  retained_from={log.retain_from}  entries={[e.index for e in log.entries()]}")
    print(f"  verify from checkpoint: {log.verify()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
