"""Self-contained demo: python3 -m auditchain"""

from __future__ import annotations

from . import AuditLog, entry_digest

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
