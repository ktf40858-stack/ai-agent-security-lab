"""Hash-chained, append-only audit log (JSON Lines).

Each entry stores the SHA-256 of the previous one, so editing or deleting a past
entry breaks the chain. Limit: whoever can rewrite the whole file can rebuild a valid
chain. In production, anchor the latest hash somewhere the agent cannot write
(a log service, write-once storage, a separate repository).
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(entry):
    payload = json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self._prev, self._seq = GENESIS, 0

    def append(self, **fields):
        self._seq += 1
        entry = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "prev": self._prev,
            **fields,
        }
        entry["hash"] = self._prev = _digest(entry)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify(self):
        """(True, None) if the chain is intact, else (False, number of the first bad line)."""
        prev = GENESIS
        for n, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, n
            if entry.get("seq") != n or entry.get("prev") != prev or entry.get("hash") != _digest(entry):
                return False, n
            prev = entry["hash"]
        return True, None
