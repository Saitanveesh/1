from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path

from mon.site_response_models import SiteResponseUpdate


class SQLiteResponseUpdateOutbox:
    """Durable outbox for autonomous site response-state updates."""

    def __init__(self, path: str | Path, *, tenant_id: str, site_id: str) -> None:
        self.path = Path(path)
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS response_update_outbox (
                    update_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _check_scope(self, update: SiteResponseUpdate) -> None:
        if update.tenant_id != self.tenant_id or update.site_id != self.site_id:
            raise ValueError("response update scope does not match this outbox")

    def enqueue(self, update: SiteResponseUpdate) -> bool:
        self._check_scope(update)
        with self._lock:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO response_update_outbox
                    (update_id, tenant_id, site_id, payload, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    update.update_id,
                    update.tenant_id,
                    update.site_id,
                    update.model_dump_json(),
                    dt.datetime.now(dt.UTC).isoformat(),
                ),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def pending(self, limit: int = 100) -> list[SiteResponseUpdate]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload FROM response_update_outbox
                WHERE tenant_id = ? AND site_id = ?
                ORDER BY created_at ASC, update_id ASC
                LIMIT ?
                """,
                (self.tenant_id, self.site_id, limit),
            ).fetchall()
        return [
            SiteResponseUpdate.model_validate_json(row["payload"])
            for row in rows
        ]

    def mark_delivered(self, update_id: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """
                DELETE FROM response_update_outbox
                WHERE update_id = ? AND tenant_id = ? AND site_id = ?
                """,
                (update_id, self.tenant_id, self.site_id),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def mark_failed(self, update_id: str, error: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE response_update_outbox
                SET attempts = attempts + 1, last_error = ?
                WHERE update_id = ? AND tenant_id = ? AND site_id = ?
                """,
                (error[:1000], update_id, self.tenant_id, self.site_id),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def diagnostics(self) -> dict[str, object]:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT
                    COUNT(*) AS queued,
                    COALESCE(MAX(attempts), 0) AS max_attempts,
                    MAX(last_error) AS last_error
                FROM response_update_outbox
                WHERE tenant_id = ? AND site_id = ?
                """,
                (self.tenant_id, self.site_id),
            ).fetchone()
        return {
            "queued": int(row["queued"]) if row else 0,
            "max_attempts": int(row["max_attempts"]) if row else 0,
            "last_error": row["last_error"] if row else None,
        }
