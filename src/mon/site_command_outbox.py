from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path

from mon.site_command_models import SiteCommandResult


class SQLiteCommandResultOutbox:
    """Durable site-side outbox for command results awaiting cloud acknowledgement."""

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
                CREATE TABLE IF NOT EXISTS command_result_outbox (
                    command_id TEXT PRIMARY KEY,
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

    def _check_scope(self, result: SiteCommandResult) -> None:
        if result.tenant_id != self.tenant_id or result.site_id != self.site_id:
            raise ValueError("command result scope does not match this outbox")

    def enqueue(self, result: SiteCommandResult) -> bool:
        self._check_scope(result)
        with self._lock:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO command_result_outbox
                    (command_id, tenant_id, site_id, payload, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    result.command_id,
                    result.tenant_id,
                    result.site_id,
                    result.model_dump_json(),
                    dt.datetime.now(dt.UTC).isoformat(),
                ),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def get(self, command_id: str) -> SiteCommandResult | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT payload FROM command_result_outbox
                WHERE command_id = ? AND tenant_id = ? AND site_id = ?
                """,
                (command_id, self.tenant_id, self.site_id),
            ).fetchone()
        if row is None:
            return None
        return SiteCommandResult.model_validate_json(row["payload"])

    def pending(self, limit: int = 100) -> list[SiteCommandResult]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload FROM command_result_outbox
                WHERE tenant_id = ? AND site_id = ?
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (self.tenant_id, self.site_id, limit),
            ).fetchall()
        return [SiteCommandResult.model_validate_json(row["payload"]) for row in rows]

    def mark_reported(self, command_id: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """
                DELETE FROM command_result_outbox
                WHERE command_id = ? AND tenant_id = ? AND site_id = ?
                """,
                (command_id, self.tenant_id, self.site_id),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def mark_failed(self, command_id: str, error: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE command_result_outbox
                SET attempts = attempts + 1, last_error = ?
                WHERE command_id = ? AND tenant_id = ? AND site_id = ?
                """,
                (error[:1000], command_id, self.tenant_id, self.site_id),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def diagnostics(self) -> dict[str, object]:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT COUNT(*) AS queued,
                       COALESCE(MAX(attempts), 0) AS max_attempts,
                       MAX(last_error) AS last_error
                FROM command_result_outbox
                WHERE tenant_id = ? AND site_id = ?
                """,
                (self.tenant_id, self.site_id),
            ).fetchone()
        return {
            "queued": int(row["queued"]) if row else 0,
            "max_attempts": int(row["max_attempts"]) if row else 0,
            "last_error": row["last_error"] if row else None,
        }
