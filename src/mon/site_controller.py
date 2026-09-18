from __future__ import annotations

import datetime as dt
import sqlite3
import ssl
import threading
from pathlib import Path
from typing import Protocol

import httpx

from mon.domain import EventBatch, EventProcessingResult, SecurityEvent
from mon.pipeline import SecurityPipeline
from mon.recovery import RecoveryEngine
from mon.site_command_client import SiteCommandClient
from mon.site_response import SiteResponseExecutor


class SiteScopeViolation(ValueError):
    pass


class EventBatchSender(Protocol):
    async def send_batch(self, events: list[SecurityEvent]) -> set[str]: ...


class SQLiteEventSpool:
    """Durable local outbox for at-least-once site-to-control-plane delivery."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS event_spool (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
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

    def enqueue(self, event: SecurityEvent) -> bool:
        payload = event.model_dump_json()
        created_at = dt.datetime.now(dt.UTC).isoformat()
        with self._lock:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO event_spool
                    (event_id, tenant_id, site_id, observed_at, payload, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.tenant_id,
                    event.site_id,
                    event.observed_at.isoformat(),
                    payload,
                    created_at,
                ),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def pending(self, limit: int = 100) -> list[SecurityEvent]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload
                FROM event_spool
                ORDER BY observed_at ASC, created_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [SecurityEvent.model_validate_json(row["payload"]) for row in rows]

    def mark_delivered(self, event_ids: set[str]) -> int:
        if not event_ids:
            return 0
        placeholders = ",".join("?" for _ in event_ids)
        with self._lock:
            cursor = self._connection.execute(
                f"DELETE FROM event_spool WHERE event_id IN ({placeholders})",
                tuple(sorted(event_ids)),
            )
            self._connection.commit()
            return cursor.rowcount

    def mark_failed(self, event_ids: set[str], error: str) -> int:
        if not event_ids:
            return 0
        placeholders = ",".join("?" for _ in event_ids)
        with self._lock:
            cursor = self._connection.execute(
                f"""
                UPDATE event_spool
                SET attempts = attempts + 1, last_error = ?
                WHERE event_id IN ({placeholders})
                """,
                (error[:1000], *sorted(event_ids)),
            )
            self._connection.commit()
            return cursor.rowcount

    def count(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM event_spool"
            ).fetchone()
        return int(row["count"]) if row else 0

    def diagnostics(self) -> dict[str, object]:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT
                    COUNT(*) AS queued,
                    COALESCE(MAX(attempts), 0) AS max_attempts,
                    MAX(last_error) AS last_error
                FROM event_spool
                """
            ).fetchone()
        return {
            "queued": int(row["queued"]) if row else 0,
            "max_attempts": int(row["max_attempts"]) if row else 0,
            "last_error": row["last_error"] if row else None,
        }


class HttpControlPlaneSender:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 10.0,
        *,
        bearer_token: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.bearer_token = bearer_token
        self.ssl_context = ssl_context

    async def send_batch(self, events: list[SecurityEvent]) -> set[str]:
        batch = EventBatch(events=events)
        headers = {}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            headers=headers,
            verify=self.ssl_context if self.ssl_context is not None else True,
        ) as client:
            response = await client.post(
                "/api/v1/events/batch",
                json=batch.model_dump(mode="json"),
            )
            response.raise_for_status()
            payload = response.json()
        accepted = payload.get("accepted_event_ids", [])
        if not isinstance(accepted, list):
            raise RuntimeError("control plane returned invalid event acknowledgement")
        return {str(value) for value in accepted}


class SiteController:
    """Locally autonomous security pipeline with durable cloud synchronization."""

    def __init__(
        self,
        tenant_id: str,
        site_id: str,
        spool: SQLiteEventSpool,
        sender: EventBatchSender | None = None,
        pipeline: SecurityPipeline | None = None,
        recovery_engine: RecoveryEngine | None = None,
        command_client: SiteCommandClient | None = None,
        response_executor: SiteResponseExecutor | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.spool = spool
        self.sender = sender
        self.pipeline = pipeline or SecurityPipeline()
        self.command_client = command_client
        self.response_executor = response_executor
        self.recovery_engine = recovery_engine or (
            RecoveryEngine(response_executor.orchestrator)
            if response_executor is not None
            else None
        )

    def ingest(self, event: SecurityEvent) -> EventProcessingResult:
        if event.tenant_id != self.tenant_id or event.site_id != self.site_id:
            raise SiteScopeViolation(
                "event tenant/site does not match this site-controller identity"
            )
        self.spool.enqueue(event)
        return self.pipeline.process_event(event)

    async def flush(self, limit: int = 100) -> dict[str, object]:
        events = self.spool.pending(limit=limit)
        if not events:
            return {"state": "SYNCED", "attempted": 0, "delivered": 0, "queued": 0}
        if self.sender is None:
            return {
                "state": "OFFLINE",
                "attempted": 0,
                "delivered": 0,
                "queued": self.spool.count(),
            }

        event_ids = {event.event_id for event in events}
        try:
            accepted = await self.sender.send_batch(events)
        except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
            self.spool.mark_failed(event_ids, str(exc))
            return {
                "state": "DEGRADED",
                "attempted": len(events),
                "delivered": 0,
                "queued": self.spool.count(),
                "error": str(exc)[:1000],
            }

        delivered_ids = event_ids & accepted
        missing_ids = event_ids - delivered_ids
        self.spool.mark_delivered(delivered_ids)
        if missing_ids:
            self.spool.mark_failed(missing_ids, "control plane did not acknowledge event")

        return {
            "state": "SYNCED" if not missing_ids else "DEGRADED",
            "attempted": len(events),
            "delivered": len(delivered_ids),
            "queued": self.spool.count(),
            "unacknowledged": len(missing_ids),
        }

    async def poll_commands(self, limit: int = 20) -> dict[str, object]:
        if self.command_client is None or self.response_executor is None:
            return {
                "state": "DISABLED",
                "attempted": 0,
                "reported": 0,
                "unreported": 0,
            }

        try:
            commands = await self.command_client.pull_commands(limit=limit)
        except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
            return {
                "state": "DEGRADED",
                "attempted": 0,
                "reported": 0,
                "unreported": 0,
                "error": str(exc)[:1000],
            }

        reported = 0
        unreported = 0
        failed = 0
        for command in commands:
            result = await self.response_executor.execute(command)
            if not result.success:
                failed += 1
            try:
                await self.command_client.submit_result(result)
            except (httpx.HTTPError, OSError, RuntimeError, ValueError):
                unreported += 1
                continue
            reported += 1

        return {
            "state": "SYNCED" if unreported == 0 else "DEGRADED",
            "attempted": len(commands),
            "reported": reported,
            "unreported": unreported,
            "failed": failed,
        }

    async def recover_expired_responses(
        self,
        *,
        now: dt.datetime | None = None,
    ) -> dict[str, object]:
        if self.recovery_engine is None:
            return {
                "state": "DISABLED",
                "attempted": 0,
                "rolled_back": 0,
                "failed": 0,
            }

        sweep = await self.recovery_engine.sweep_scope(
            self.tenant_id,
            self.site_id,
            now=now,
        )
        return {
            "state": "RECOVERED" if not sweep.failed else "DEGRADED",
            "attempted": sweep.attempted,
            "rolled_back": len(sweep.rolled_back),
            "failed": len(sweep.failed),
            "rolled_back_execution_ids": list(sweep.rolled_back),
            "failed_execution_ids": list(sweep.failed),
            "errors": sweep.errors,
        }

    def status(self) -> dict[str, object]:
        diagnostics = self.spool.diagnostics()
        return {
            "state": "READY",
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "cloud_sender_configured": self.sender is not None,
            "local_recovery_configured": self.recovery_engine is not None,
            "command_channel_configured": (
                self.command_client is not None and self.response_executor is not None
            ),
            "spool": diagnostics,
            "local_incidents": len(
                self.pipeline.store.list_incidents(self.tenant_id, self.site_id)
            ),
            "local_findings": len(
                self.pipeline.store.list_findings(self.tenant_id, self.site_id)
            ),
        }
