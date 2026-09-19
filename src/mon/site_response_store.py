from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path

from mon.domain import AuditRecord, ResponseExecution

_SCHEMA_VERSION = "1"


class SQLiteSiteResponseStore:
    """Durable response execution and audit state for exactly one site scope."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        site_id: str,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if not tenant_id or not site_id:
            raise ValueError("tenant_id and site_id are required")
        if busy_timeout_seconds <= 0 or busy_timeout_seconds > 60:
            raise ValueError("busy_timeout_seconds must be greater than 0 and at most 60")

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
                CREATE TABLE IF NOT EXISTS site_response_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS site_response_executions (
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    execution_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, site_id, execution_id)
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS site_response_audit (
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    audit_id TEXT NOT NULL,
                    execution_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, site_id, audit_id)
                )
                """
            )
            self._bind_metadata("schema_version", _SCHEMA_VERSION)
            self._bind_metadata("tenant_id", self.tenant_id)
            self._bind_metadata("site_id", self.site_id)

    def _bind_metadata(self, key: str, expected: str) -> None:
        row = self._connection.execute(
            "SELECT value FROM site_response_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO site_response_metadata (key, value) VALUES (?, ?)",
                (key, expected),
            )
            return
        actual = str(row["value"])
        if actual != expected:
            raise ValueError(
                f"site response store {key} mismatch: expected {expected!r}, found {actual!r}"
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _require_scope(self, tenant_id: str, site_id: str) -> None:
        if tenant_id != self.tenant_id or site_id != self.site_id:
            raise ValueError("response state scope does not match this site store")

    def _validate_execution(self, execution: ResponseExecution) -> None:
        self._require_scope(execution.tenant_id, execution.site_id)
        request = execution.plan.request
        point = execution.plan.enforcement_point
        self._require_scope(request.tenant_id, request.site_id)
        self._require_scope(point.tenant_id, point.site_id)
        if execution.execution_id != request.request_id:
            raise ValueError(
                "response execution_id must match the site response request_id"
            )

        timestamps = {
            "requested_at": execution.requested_at,
            "applied_at": execution.applied_at,
            "expires_at": execution.expires_at,
            "rollback_at": execution.rollback_at,
        }
        if execution.approval is not None:
            timestamps["approval.approved_at"] = execution.approval.approved_at
        for field_name, value in timestamps.items():
            if value is not None:
                self._utc_iso(value, field_name=field_name)

    @staticmethod
    def _utc_iso(value: dt.datetime, *, field_name: str) -> str:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{field_name} must be timezone-aware")
        return value.astimezone(dt.UTC).isoformat()

    def add_response_execution(
        self,
        execution: ResponseExecution,
    ) -> ResponseExecution:
        self._validate_execution(execution)
        updated_at = dt.datetime.now(dt.UTC).isoformat()
        payload = execution.model_dump_json()
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO site_response_executions
                    (tenant_id, site_id, execution_id, status, payload, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, site_id, execution_id) DO UPDATE SET
                    status = excluded.status,
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (
                    execution.tenant_id,
                    execution.site_id,
                    execution.execution_id,
                    execution.status.value,
                    payload,
                    updated_at,
                ),
            )
        return execution

    def get_response_execution(
        self,
        tenant_id: str,
        site_id: str,
        execution_id: str,
    ) -> ResponseExecution | None:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT payload FROM site_response_executions
                WHERE tenant_id = ? AND site_id = ? AND execution_id = ?
                """,
                (tenant_id, site_id, execution_id),
            ).fetchone()
        if row is None:
            return None
        execution = ResponseExecution.model_validate_json(row["payload"])
        self._validate_execution(execution)
        return execution

    def list_response_executions(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[ResponseExecution]:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload FROM site_response_executions
                WHERE tenant_id = ? AND site_id = ?
                ORDER BY execution_id ASC
                """,
                (tenant_id, site_id),
            ).fetchall()
        executions = [
            ResponseExecution.model_validate_json(row["payload"])
            for row in rows
        ]
        for execution in executions:
            self._validate_execution(execution)
        return executions

    def add_audit_record(self, record: AuditRecord) -> AuditRecord:
        self._require_scope(record.tenant_id, record.site_id)
        occurred_at = self._utc_iso(record.occurred_at, field_name="audit occurred_at")
        payload = record.model_dump_json()

        with self._lock, self._connection:
            existing = self._connection.execute(
                """
                SELECT payload FROM site_response_audit
                WHERE tenant_id = ? AND site_id = ? AND audit_id = ?
                """,
                (record.tenant_id, record.site_id, record.audit_id),
            ).fetchone()
            if existing is not None:
                current = AuditRecord.model_validate_json(existing["payload"])
                if current != record:
                    raise ValueError(
                        "audit_id already exists with different content in site response store"
                    )
                return current

            self._connection.execute(
                """
                INSERT INTO site_response_audit
                    (tenant_id, site_id, audit_id, execution_id, occurred_at, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.tenant_id,
                    record.site_id,
                    record.audit_id,
                    record.object_id,
                    occurred_at,
                    payload,
                ),
            )
        return record

    def list_audit_records(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[AuditRecord]:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload FROM site_response_audit
                WHERE tenant_id = ? AND site_id = ?
                ORDER BY occurred_at ASC, audit_id ASC
                """,
                (tenant_id, site_id),
            ).fetchall()
        return [
            AuditRecord.model_validate_json(row["payload"])
            for row in rows
        ]

    def diagnostics(self) -> dict[str, object]:
        with self._lock:
            response_row = self._connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM site_response_executions
                WHERE tenant_id = ? AND site_id = ?
                """,
                (self.tenant_id, self.site_id),
            ).fetchone()
            audit_row = self._connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM site_response_audit
                WHERE tenant_id = ? AND site_id = ?
                """,
                (self.tenant_id, self.site_id),
            ).fetchone()
            status_rows = self._connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM site_response_executions
                WHERE tenant_id = ? AND site_id = ?
                GROUP BY status
                ORDER BY status ASC
                """,
                (self.tenant_id, self.site_id),
            ).fetchall()

        return {
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "responses": int(response_row["count"]) if response_row else 0,
            "audit_records": int(audit_row["count"]) if audit_row else 0,
            "statuses": {
                str(row["status"]): int(row["count"])
                for row in status_rows
            },
        }
