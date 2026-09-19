from __future__ import annotations

import datetime as dt
import random
import re
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from mon.domain import SecurityEvent
from mon.event_fabric import FabricEnvelope, security_event_envelope

_SCHEMA_VERSION = "2"
_MIN_RETRY_DELAY_SECONDS = 0.1
_MAX_RETRY_DELAY_SECONDS = 3600.0
_DEFAULT_BASE_RETRY_DELAY_SECONDS = 1.0
_DEFAULT_MAX_RETRY_DELAY_SECONDS = 300.0
_JITTER_FRACTION = 0.20
_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r"(?i)((?:password|passwd|private[_ -]?key|api[_ -]?key|"
        r"api[_ -]?token|auth[_ -]?token|client[_ -]?secret|"
        r"connector[_ -]?secret)\s*[:=]\s*)[^\s,;]+"
    ),
)


@dataclass(frozen=True, slots=True)
class FabricRetrySchedule:
    attempts: int
    base_delay_seconds: float
    capped_delay_seconds: float
    jitter_seconds: float
    effective_delay_seconds: float
    next_attempt_at: dt.datetime


def sanitize_fabric_error(error: object) -> str:
    text = str(error).strip()
    for pattern in _SENSITIVE_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text[:1000]


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _require_utc(value: dt.datetime, *, field_name: str) -> dt.datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(dt.UTC)


def _parse_utc(value: object, *, field_name: str) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"fabric outbox {field_name} is missing")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"fabric outbox {field_name} is malformed") from exc
    return _require_utc(parsed, field_name=f"fabric outbox {field_name}")


class DurableFabricOutbox:
    """Scope-bound durable producer outbox for exact fabric-envelope replay."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        site_id: str,
        busy_timeout_seconds: float = 5.0,
        base_retry_delay: dt.timedelta | float = _DEFAULT_BASE_RETRY_DELAY_SECONDS,
        max_retry_delay: dt.timedelta | float = _DEFAULT_MAX_RETRY_DELAY_SECONDS,
        now: Callable[[], dt.datetime] | None = None,
        jitter: Callable[[int], float] | None = None,
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
        self.base_retry_delay_seconds = self._delay_seconds(
            base_retry_delay,
            field_name="base_retry_delay",
        )
        self.max_retry_delay_seconds = self._delay_seconds(
            max_retry_delay,
            field_name="max_retry_delay",
        )
        if self.base_retry_delay_seconds > self.max_retry_delay_seconds:
            raise ValueError("base_retry_delay cannot exceed max_retry_delay")
        self._now = now or _utc_now
        self._jitter = jitter or (lambda _attempt: random.uniform(-1.0, 1.0))
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
                self._validate_retry_metadata()
        except Exception:
            self._connection.close()
            raise

    @staticmethod
    def _delay_seconds(value: dt.timedelta | float, *, field_name: str) -> float:
        seconds = value.total_seconds() if isinstance(value, dt.timedelta) else float(value)
        if seconds < _MIN_RETRY_DELAY_SECONDS or seconds > _MAX_RETRY_DELAY_SECONDS:
            raise ValueError(
                f"{field_name} must be between "
                f"{_MIN_RETRY_DELAY_SECONDS} and {_MAX_RETRY_DELAY_SECONDS} seconds"
            )
        return seconds

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
                    source_reconciled_at TEXT,
                    next_attempt_at TEXT,
                    retry_delay_seconds REAL NOT NULL DEFAULT 0,
                    retry_jitter_seconds REAL NOT NULL DEFAULT 0
                )
                """
            )
            columns = {
                str(row["name"])
                for row in self._connection.execute(
                    "PRAGMA table_info(fabric_outbox)"
                ).fetchall()
            }
            additions = {
                "next_attempt_at": "ALTER TABLE fabric_outbox ADD COLUMN next_attempt_at TEXT",
                "retry_delay_seconds": (
                    "ALTER TABLE fabric_outbox ADD COLUMN "
                    "retry_delay_seconds REAL NOT NULL DEFAULT 0"
                ),
                "retry_jitter_seconds": (
                    "ALTER TABLE fabric_outbox ADD COLUMN "
                    "retry_jitter_seconds REAL NOT NULL DEFAULT 0"
                ),
            }
            for column, statement in additions.items():
                if column not in columns:
                    self._connection.execute(statement)
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
            self._bind_schema_version()
            self._bind_metadata("tenant_id", self.tenant_id)
            self._bind_metadata("site_id", self.site_id)

    def _bind_schema_version(self) -> None:
        row = self._connection.execute(
            "SELECT value FROM fabric_outbox_metadata WHERE key = ?",
            ("schema_version",),
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO fabric_outbox_metadata(key, value) VALUES (?, ?)",
                ("schema_version", _SCHEMA_VERSION),
            )
            return
        actual = str(row["value"])
        if actual == "1":
            self._connection.execute(
                """
                UPDATE fabric_outbox_metadata
                SET value = ?
                WHERE key = 'schema_version'
                """,
                (_SCHEMA_VERSION,),
            )
            return
        if actual != _SCHEMA_VERSION:
            raise ValueError(
                f"fabric outbox schema_version mismatch: expected {_SCHEMA_VERSION!r}, "
                f"found {actual!r}"
            )

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

    def _current_time(self) -> dt.datetime:
        return _require_utc(self._now(), field_name="fabric outbox time")

    def _validate_retry_metadata(self) -> None:
        rows = self._connection.execute(
            """
            SELECT event_id, next_attempt_at, retry_delay_seconds, retry_jitter_seconds
            FROM fabric_outbox
            WHERE delivered_at IS NULL
              AND next_attempt_at IS NOT NULL
            """
        ).fetchall()
        for row in rows:
            _parse_utc(row["next_attempt_at"], field_name="next_attempt_at")
            delay = float(row["retry_delay_seconds"] or 0)
            jitter = float(row["retry_jitter_seconds"] or 0)
            if delay < 0:
                raise ValueError(
                    f"fabric outbox retry delay is negative for {row['event_id']}"
                )
            if abs(jitter) > (self.max_retry_delay_seconds * _JITTER_FRACTION):
                raise ValueError(
                    f"fabric outbox retry jitter is outside bounds for {row['event_id']}"
                )

    def retry_schedule(
        self,
        *,
        next_attempt_number: int,
        now: dt.datetime | None = None,
    ) -> FabricRetrySchedule:
        if next_attempt_number < 1:
            raise ValueError("next_attempt_number must be positive")
        scheduled_at = _require_utc(
            now or self._current_time(),
            field_name="fabric retry schedule time",
        )
        exponential = self.base_retry_delay_seconds * (2 ** (next_attempt_number - 1))
        capped = min(exponential, self.max_retry_delay_seconds)
        raw_jitter = max(-1.0, min(1.0, float(self._jitter(next_attempt_number))))
        jitter_seconds = capped * _JITTER_FRACTION * raw_jitter
        effective = max(0.0, min(self.max_retry_delay_seconds, capped + jitter_seconds))
        return FabricRetrySchedule(
            attempts=next_attempt_number,
            base_delay_seconds=self.base_retry_delay_seconds,
            capped_delay_seconds=capped,
            jitter_seconds=jitter_seconds,
            effective_delay_seconds=effective,
            next_attempt_at=scheduled_at + dt.timedelta(seconds=effective),
        )

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

            created_at = produced_at or self._current_time()
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

    def pending(
        self,
        limit: int = 100,
        *,
        eligible_at: dt.datetime | None = None,
    ) -> list[FabricEnvelope]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        check_at = _require_utc(
            eligible_at or self._current_time(),
            field_name="fabric pending check time",
        )
        with self._lock:
            first = self._connection.execute(
                """
                SELECT next_attempt_at
                FROM fabric_outbox
                WHERE delivered_at IS NULL
                ORDER BY created_at ASC, event_id ASC
                LIMIT 1
                """
            ).fetchone()
            if first is None:
                return []
            if first["next_attempt_at"] is not None:
                next_attempt_at = _parse_utc(
                    first["next_attempt_at"],
                    field_name="next_attempt_at",
                )
                if next_attempt_at > check_at:
                    return []

            rows = self._connection.execute(
                """
                SELECT envelope_json
                FROM fabric_outbox
                WHERE delivered_at IS NULL
                  AND (
                    next_attempt_at IS NULL
                    OR next_attempt_at <= ?
                  )
                ORDER BY created_at ASC, event_id ASC
                LIMIT ?
                """,
                (check_at.isoformat(), limit),
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
        delivered_at = _require_utc(
            now or self._current_time(),
            field_name="fabric delivery time",
        )
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE fabric_outbox
                SET delivered_at = COALESCE(delivered_at, ?),
                    last_error = NULL,
                    next_attempt_at = NULL,
                    retry_delay_seconds = 0,
                    retry_jitter_seconds = 0
                WHERE event_id = ?
                """,
                (
                    delivered_at.astimezone(dt.UTC).isoformat(),
                    event_id,
                ),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def mark_failed(
        self,
        event_id: str,
        error: object,
        *,
        now: dt.datetime | None = None,
    ) -> bool:
        failed_at = _require_utc(
            now or self._current_time(),
            field_name="fabric failure time",
        )
        with self._lock:
            row = self._connection.execute(
                """
                SELECT attempts
                FROM fabric_outbox
                WHERE event_id = ?
                  AND delivered_at IS NULL
                """,
                (event_id,),
            ).fetchone()
            if row is None:
                return False
            schedule = self.retry_schedule(
                next_attempt_number=int(row["attempts"] or 0) + 1,
                now=failed_at,
            )
            cursor = self._connection.execute(
                """
                UPDATE fabric_outbox
                SET attempts = attempts + 1,
                    last_error = ?,
                    next_attempt_at = ?,
                    retry_delay_seconds = ?,
                    retry_jitter_seconds = ?
                WHERE event_id = ?
                  AND delivered_at IS NULL
                """,
                (
                    sanitize_fabric_error(error),
                    schedule.next_attempt_at.isoformat(),
                    schedule.effective_delay_seconds,
                    schedule.jitter_seconds,
                    event_id,
                ),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def mark_source_reconciled(
        self,
        event_id: str,
        *,
        now: dt.datetime | None = None,
    ) -> bool:
        reconciled_at = _require_utc(
            now or self._current_time(),
            field_name="fabric reconciliation time",
        )
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
        check_at = _require_utc(
            now or self._current_time(),
            field_name="fabric compaction time",
        )
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
                    MAX(last_error) AS last_error,
                    SUM(
                        CASE
                            WHEN delivered_at IS NULL
                             AND next_attempt_at IS NOT NULL
                            THEN 1 ELSE 0
                        END
                    ) AS backoff_pending,
                    MIN(
                        CASE
                            WHEN delivered_at IS NULL
                             AND next_attempt_at IS NOT NULL
                            THEN next_attempt_at ELSE NULL
                        END
                    ) AS next_attempt_at,
                    MAX(retry_delay_seconds) AS current_retry_delay_seconds
                FROM fabric_outbox
                """
            ).fetchone()
            first = self._connection.execute(
                """
                SELECT next_attempt_at
                FROM fabric_outbox
                WHERE delivered_at IS NULL
                ORDER BY created_at ASC, event_id ASC
                LIMIT 1
                """
            ).fetchone()
        next_attempt_at = row["next_attempt_at"] if row else None
        if next_attempt_at is not None:
            parsed = _parse_utc(next_attempt_at, field_name="next_attempt_at")
            next_attempt_at = parsed.isoformat()
        backoff_active = False
        if first is not None and first["next_attempt_at"] is not None:
            next_due = _parse_utc(first["next_attempt_at"], field_name="next_attempt_at")
            backoff_active = next_due > self._current_time()
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
            "last_error": (
                sanitize_fabric_error(row["last_error"])
                if row and row["last_error"]
                else None
            ),
            "backoff_pending": int(row["backoff_pending"] or 0) if row else 0,
            "backoff_active": backoff_active,
            "next_attempt_at": next_attempt_at,
            "current_retry_delay_seconds": (
                float(row["current_retry_delay_seconds"] or 0) if row else 0.0
            ),
            "base_retry_delay_seconds": self.base_retry_delay_seconds,
            "max_retry_delay_seconds": self.max_retry_delay_seconds,
            "durability": "WAL_FULL",
            "delivery_semantics": "AT_LEAST_ONCE_EXACT_ENVELOPE_REPLAY",
        }
