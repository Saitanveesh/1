from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path

from mon.site_command_models import SiteCommandResult


class SQLiteCommandResultOutbox:
    """Durable result outbox plus command receipt ledger for replay safety."""

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
                    created_at TEXT NOT NULL,
                    reported_at TEXT
                )
                """
            )
            columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(command_result_outbox)").fetchall()}
            if "reported_at" not in columns:
                self._connection.execute("ALTER TABLE command_result_outbox ADD COLUMN reported_at TEXT")
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
                """INSERT OR IGNORE INTO command_result_outbox
                   (command_id, tenant_id, site_id, payload, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (result.command_id, result.tenant_id, result.site_id, result.model_dump_json(), dt.datetime.now(dt.UTC).isoformat()),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def get(self, command_id: str) -> SiteCommandResult | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM command_result_outbox WHERE command_id = ? AND tenant_id = ? AND site_id = ?",
                (command_id, self.tenant_id, self.site_id),
            ).fetchone()
        return None if row is None else SiteCommandResult.model_validate_json(row["payload"])

    def pending(self, limit: int = 100) -> list[SiteCommandResult]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            rows = self._connection.execute(
                """SELECT payload FROM command_result_outbox
                   WHERE tenant_id = ? AND site_id = ? AND reported_at IS NULL
                   ORDER BY created_at ASC LIMIT ?""",
                (self.tenant_id, self.site_id, limit),
            ).fetchall()
        return [SiteCommandResult.model_validate_json(row["payload"]) for row in rows]

    def mark_reported(self, command_id: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """UPDATE command_result_outbox SET reported_at = ?, last_error = NULL
                   WHERE command_id = ? AND tenant_id = ? AND site_id = ? AND reported_at IS NULL""",
                (dt.datetime.now(dt.UTC).isoformat(), command_id, self.tenant_id, self.site_id),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def mark_failed(self, command_id: str, error: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """UPDATE command_result_outbox SET attempts = attempts + 1, last_error = ?
                   WHERE command_id = ? AND tenant_id = ? AND site_id = ? AND reported_at IS NULL""",
                (error[:1000], command_id, self.tenant_id, self.site_id),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def compact_reported(self, *, retain_for: dt.timedelta, now: dt.datetime | None = None) -> int:
        """Delete only acknowledged receipts older than the configured retention window.

        Pending results are never compacted. A positive retention period is mandatory so
        replay protection cannot accidentally be disabled by a zero/negative setting.
        """
        if retain_for <= dt.timedelta(0):
            raise ValueError("retain_for must be positive")
        current = now or dt.datetime.now(dt.UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        cutoff = (current.astimezone(dt.UTC) - retain_for).isoformat()
        with self._lock:
            cursor = self._connection.execute(
                """DELETE FROM command_result_outbox
                   WHERE tenant_id = ? AND site_id = ?
                     AND reported_at IS NOT NULL AND reported_at < ?""",
                (self.tenant_id, self.site_id, cutoff),
            )
            self._connection.commit()
            return cursor.rowcount

    def diagnostics(self) -> dict[str, object]:
        with self._lock:
            row = self._connection.execute(
                """SELECT SUM(CASE WHEN reported_at IS NULL THEN 1 ELSE 0 END) AS queued,
                          COUNT(*) AS receipts, COALESCE(MAX(attempts), 0) AS max_attempts,
                          MAX(last_error) AS last_error
                   FROM command_result_outbox WHERE tenant_id = ? AND site_id = ?""",
                (self.tenant_id, self.site_id),
            ).fetchone()
        return {
            "queued": int(row["queued"] or 0) if row else 0,
            "receipts": int(row["receipts"]) if row else 0,
            "max_attempts": int(row["max_attempts"]) if row else 0,
            "last_error": row["last_error"] if row else None,
        }
