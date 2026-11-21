"""Small SQLite receipt store for the rootless collector."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Mapping


class ReceiptStore:
    """Append-only receipt persistence with a bounded optional history."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS rootless_receipts ("
            "scope_id TEXT PRIMARY KEY, closed_at REAL NOT NULL, "
            "receipt_json TEXT NOT NULL)"
        )
        self._conn.commit()

    def save(self, receipt: Mapping[str, Any]) -> None:
        scope_id = str(receipt.get("scope_id", ""))
        if not scope_id:
            raise ValueError("receipt has no scope_id")
        payload = json.dumps(dict(receipt), sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO rootless_receipts "
                "(scope_id, closed_at, receipt_json) VALUES (?, ?, ?)",
                (scope_id, float(receipt.get("closed_at", 0.0)), payload),
            )
            self._conn.commit()

    def load(self, scope_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT receipt_json FROM rootless_receipts WHERE scope_id = ?",
                (scope_id,),
            ).fetchone()
        if row is None:
            return None
        value = json.loads(row[0])
        return value if isinstance(value, dict) else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
