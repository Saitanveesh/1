from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path

from mon.domain import SecurityEvent
from mon.event_fabric import FabricEnvelope, security_event_envelope

_SCHEMA_VERSION = "1"


class DurableFabricOutbox:
    """Scope-bound durable producer outbox for exact fabric-envelope replay."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        site_id: str,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if not tenant_id or not site_id:
            raise ValueError("fabric outbox tenant_id and site_id are required")
        if busy_timeout_seconds <= 0 or busy_timeout_seconds > 60:
            raise ValueError(
                "busy_timeout_seconds must be greater than 0 and at most 60"
            )
        self.path = Path(path)
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            check_same_thread=False,
            timeout=busy_timeout_seconds,
        )
        self._connection.row_factory = sqlite3.Row
        try:
            with self._lock:
                self._connection.execute("PRAGMA journal_mode=WAL")
                self._connection.execute("PRAGMA synchronous=FULL")
                self._connection.execute("PRAGMA foreign_keys=ON")
                self._connection.execute(
                    f"PRAGMA busy_timeout={int(busy_timeout_seconds * 1000)}"
                )
                self._initialize_schema()
        except Exception:
            self._connection.close()
            raise

    def _initialize_schema(self) -> None:
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS fabric_outbox_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS fabric_outbox (
                    event_id TEXT PRIMARY KEY,
                    envelope_sha256 TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    delivered_at TEXT,
                    source_reconciled_at TEXT
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_fabric_outbox_pending
                ON fabric_outbox(delivered_at, created_at, event_id)
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_fabric_outbox_reconciled
                ON fabric_outbox(source_reconciled_at, delivered_at)
                """
            )
            self._bind_metadata("schema_version", _SCHEMA_VERSION)
            self._bind_metadata("tenant_id", self.tenant_id)
            self._bind_metadata("site_id", self.site_id)

    def _bind_metadata(self, key: str, expected: str) -> None:
        row = self._connection.execute(
            "SELECT value FROM fabric_outbox_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO fabric_outbox_metadata(key, value) VALUES (?, ?)",
                (key, expected),
            )
            return
        actual = str(row["value"])
        if actual != expected:
            raise ValueError(
                f"fabric outbox {key} mismatch: expected {expected!r}, "
                f"found {actual!r}"
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _require_scope(self, tenant_id: str, site_id: str) -> None:
        if tenant_id != self.tenant_id or site_id != self.site_id:
            raise ValueError("fabric envelope scope does not match outbox scope")

    @staticmethod
    def _parse_envelope(raw: str) -> FabricEnvelope:
        return FabricEnvelope.model_validate_json(raw)

    def get(self, event_id: str) -> FabricEnvelope | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT envelope_json
                FROM fabric_outbox
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()
        if row is None:
            return None
        envelope = self._parse_envelope(str(row["envelope_json"]))
        self._require_scope(envelope.tenant_id, envelope.site_id)
        return envelope

    def enqueue_security_event(
        self,
        event: SecurityEvent,
        *,
        produced_at: dt.datetime | None = None,
    ) -> FabricEnvelope:
        self._require_scope(event.tenant_id, event.site_id)
        with self._lock:
            existing = self._connection.execute(
                """
                SELECT envelope_json
                FROM fabric_outbox
                WHERE event_id = ?
                """,
                (event.event_id,),
            ).fetchone()
            if existing is not None:
                envelope = self._parse_envelope(str(existing["envelope_json"]))
                if envelope.payload != event.model_dump(mode="json"):
                    raise ValueError(
                        "event_id already exists with different content in fabric outbox"
                    )
                self._require_scope(envelope.tenant_id, envelope.site_id)
                return envelope

            created_at = produced_at or dt.datetime.now(dt.UTC)
            if created_at.tzinfo is None or created_at.utcoffset() is None:
                raise ValueError("fabric outbox produced_at must be timezone-aware")
            envelope = security_event_envelope(
                event,
                produced_at=created_at.astimezone(dt.UTC),
            )
            canonical = envelope.canonical_json()
            self._connection.execute(
                """
                INSERT INTO fabric_outbox(
                    event_id,
                    envelope_sha256,
                    envelope_json,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    envelope.event_id,
                    envelope.canonical_sha256,
                    canonical,
                    created_at.astimezone(dt.UTC).isoformat(),
                ),
            )
            self._connection.commit()
            return envelope

    def pending(self, limit: int = 100) -> list[FabricEnvelope]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT envelope_json
                FROM fabric_outbox
                WHERE delivered_at IS NULL
                ORDER BY created_at ASC, event_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        envelopes = [
            self._parse_envelope(str(row["envelope_json"]))
            for row in rows
        ]
        for envelope in envelopes:
            self._require_scope(envelope.tenant_id, envelope.site_id)
        return envelopes

    def delivered_unreconciled(
        self,
        limit: int = 100,
    ) -> list[FabricEnvelope]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT envelope_json
                FROM fabric_outbox
                WHERE delivered_at IS NOT NULL
                  AND source_reconciled_at IS NULL
                ORDER BY delivered_at ASC, event_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            self._parse_envelope(str(row["envelope_json"]))
            for row in rows
        ]

    def is_delivered(self, event_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT delivered_at
                FROM fabric_outbox
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()
        return row is not None and row["delivered_at"] is not None

    def mark_delivered(
        self,
        event_id: str,
        *,
        now: dt.datetime | None = None,
    ) -> bool:
        delivered_at = now or dt.datetime.now(dt.UTC)
        if delivered_at.tzinfo is None or delivered_at.utcoffset() is None:
            raise ValueError("fabric delivery time must be timezone-aware")
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE fabric_outbox
                SET delivered_at = COALESCE(delivered_at, ?),
                    last_error = NULL
                WHERE event_id = ?
                """,
                (
                    delivered_at.astimezone(dt.UTC).isoformat(),
                    event_id,
                ),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def mark_failed(self, event_id: str, error: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE fabric_outbox
                SET attempts = attempts + 1,
                    last_error = ?
                WHERE event_id = ?
                  AND delivered_at IS NULL
                """,
                (error[:1000], event_id),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def mark_source_reconciled(
        self,
        event_id: str,
        *,
        now: dt.datetime | None = None,
    ) -> bool:
        reconciled_at = now or dt.datetime.now(dt.UTC)
        if reconciled_at.tzinfo is None or reconciled_at.utcoffset() is None:
            raise ValueError("fabric reconciliation time must be timezone-aware")
        with self._lock:
            row = self._connection.execute(
                """
                SELECT delivered_at
                FROM fabric_outbox
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()
            if row is None:
                return False
            if row["delivered_at"] is None:
                raise ValueError(
                    "cannot reconcile fabric source before delivery"
                )
            cursor = self._connection.execute(
                """
                UPDATE fabric_outbox
                SET source_reconciled_at = COALESCE(source_reconciled_at, ?)
                WHERE event_id = ?
                """,
                (
                    reconciled_at.astimezone(dt.UTC).isoformat(),
                    event_id,
                ),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def compact_reconciled(
        self,
        *,
        retain_for: dt.timedelta,
        now: dt.datetime | None = None,
    ) -> int:
        if retain_for <= dt.timedelta(0):
            raise ValueError("retain_for must be positive")
        check_at = now or dt.datetime.now(dt.UTC)
        if check_at.tzinfo is None or check_at.utcoffset() is None:
            raise ValueError("fabric compaction time must be timezone-aware")
        cutoff = (check_at.astimezone(dt.UTC) - retain_for).isoformat()
        with self._lock:
            cursor = self._connection.execute(
                """
                DELETE FROM fabric_outbox
                WHERE delivered_at IS NOT NULL
                  AND source_reconciled_at IS NOT NULL
                  AND source_reconciled_at <= ?
                """,
                (cutoff,),
            )
            self._connection.commit()
            return cursor.rowcount

    def diagnostics(self) -> dict[str, object]:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN delivered_at IS NULL THEN 1 ELSE 0 END)
                        AS pending,
                    SUM(
                        CASE
                            WHEN delivered_at IS NOT NULL
                             AND source_reconciled_at IS NULL
                            THEN 1 ELSE 0
                        END
                    ) AS delivered_unreconciled,
                    SUM(
                        CASE
                            WHEN source_reconciled_at IS NOT NULL
                            THEN 1 ELSE 0
                        END
                    ) AS reconciled,
                    COALESCE(MAX(attempts), 0) AS max_attempts,
                    MAX(last_error) AS last_error
                FROM fabric_outbox
                """
            ).fetchone()
        return {
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "total": int(row["total"] or 0) if row else 0,
            "pending": int(row["pending"] or 0) if row else 0,
            "delivered_unreconciled": (
                int(row["delivered_unreconciled"] or 0) if row else 0
            ),
            "reconciled": int(row["reconciled"] or 0) if row else 0,
            "max_attempts": int(row["max_attempts"] or 0) if row else 0,
            "last_error": row["last_error"] if row else None,
            "durability": "WAL_FULL",
            "delivery_semantics": "AT_LEAST_ONCE_EXACT_ENVELOPE_REPLAY",
        }
