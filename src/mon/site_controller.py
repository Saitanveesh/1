from __future__ import annotations

import datetime as dt
import sqlite3
import ssl
import threading
from pathlib import Path
from typing import Protocol

import httpx

from mon.domain import (
    EventBatch,
    EventProcessingResult,
    ResponseExecutionStatus,
    SecurityEvent,
)
from mon.event_fabric import FabricPublisher
from mon.event_fabric_outbox import DurableFabricOutbox
from mon.pipeline import SecurityPipeline
from mon.recovery import RecoveryEngine
from mon.sensor_fleet_client import SensorFleetClient
from mon.sensor_fleet_models import (
    SensorHeartbeat,
    SensorRenewalRequest,
    SensorRenewalResult,
    SensorTrustIdentity,
)
from mon.site_command_client import SiteCommandClient
from mon.site_response import SiteResponseExecutor
from mon.site_sensor_trust import SQLiteSensorTrustStore


class SiteScopeViolation(ValueError):
    pass


class EventBatchSender(Protocol):
    async def send_batch(self, events: list[SecurityEvent]) -> set[str]: ...


class SQLiteEventSpool:
    """Durable, site-scoped staging queue for analysis and cloud delivery."""

    _SCHEMA_VERSION = "2"

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str | None = None,
        site_id: str | None = None,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if (tenant_id is None) != (site_id is None):
            raise ValueError("tenant_id and site_id must be configured together")
        if busy_timeout_seconds <= 0 or busy_timeout_seconds > 60:
            raise ValueError("busy_timeout_seconds must be between 0 and 60")

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            check_same_thread=False,
            timeout=busy_timeout_seconds,
        )
        self._connection.row_factory = sqlite3.Row
        self.tenant_id: str | None = None
        self.site_id: str | None = None

        try:
            with self._lock:
                self._connection.execute("PRAGMA journal_mode=WAL")
                self._connection.execute("PRAGMA synchronous=FULL")
                self._connection.execute("PRAGMA foreign_keys=ON")
                self._connection.execute(
                    f"PRAGMA busy_timeout={int(busy_timeout_seconds * 1000)}"
                )
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
                        created_at TEXT NOT NULL,
                        analysis_ready INTEGER NOT NULL DEFAULT 0,
                        analysis_attempts INTEGER NOT NULL DEFAULT 0,
                        analysis_last_error TEXT
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS event_spool_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                )
                self._migrate_schema()
                self._connection.commit()
                self._initialize_scope(tenant_id, site_id)
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _migrate_schema(self) -> None:
        columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(event_spool)"
            ).fetchall()
        }
        additions = {
            "analysis_ready": (
                "ALTER TABLE event_spool "
                "ADD COLUMN analysis_ready INTEGER NOT NULL DEFAULT 0"
            ),
            "analysis_attempts": (
                "ALTER TABLE event_spool "
                "ADD COLUMN analysis_attempts INTEGER NOT NULL DEFAULT 0"
            ),
            "analysis_last_error": (
                "ALTER TABLE event_spool ADD COLUMN analysis_last_error TEXT"
            ),
        }
        for name, statement in additions.items():
            if name not in columns:
                self._connection.execute(statement)

        metadata = self._metadata()
        version = metadata.get("schema_version")
        if version == "1":
            self._connection.execute(
                """
                UPDATE event_spool_metadata
                SET value = ?
                WHERE key = 'schema_version'
                """,
                (self._SCHEMA_VERSION,),
            )
        elif version is not None and version != self._SCHEMA_VERSION:
            raise ValueError(
                f"unsupported event spool schema version: {version}"
            )

    def _metadata(self) -> dict[str, str]:
        rows = self._connection.execute(
            "SELECT key, value FROM event_spool_metadata"
        ).fetchall()
        return {str(row["key"]): str(row["value"]) for row in rows}

    def _legacy_scopes(self) -> list[tuple[str, str]]:
        rows = self._connection.execute(
            """
            SELECT DISTINCT tenant_id, site_id
            FROM event_spool
            ORDER BY tenant_id, site_id
            """
        ).fetchall()
        return [(str(row["tenant_id"]), str(row["site_id"])) for row in rows]

    def _write_scope_metadata(self, tenant_id: str, site_id: str) -> None:
        values = {
            "schema_version": self._SCHEMA_VERSION,
            "tenant_id": tenant_id,
            "site_id": site_id,
        }
        with self._connection:
            self._connection.executemany(
                """
                INSERT INTO event_spool_metadata(key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                list(values.items()),
            )
        self.tenant_id = tenant_id
        self.site_id = site_id

    def _initialize_scope(
        self,
        tenant_id: str | None,
        site_id: str | None,
    ) -> None:
        metadata = self._metadata()
        version = metadata.get("schema_version")
        if version is not None and version != self._SCHEMA_VERSION:
            raise ValueError(
                f"unsupported event spool schema version: {version}"
            )

        stored_tenant = metadata.get("tenant_id")
        stored_site = metadata.get("site_id")
        if (stored_tenant is None) != (stored_site is None):
            raise ValueError("event spool metadata contains incomplete site scope")

        if stored_tenant is not None and stored_site is not None:
            if tenant_id is not None and tenant_id != stored_tenant:
                raise ValueError("event spool tenant_id mismatch")
            if site_id is not None and site_id != stored_site:
                raise ValueError("event spool site_id mismatch")
            self.tenant_id = stored_tenant
            self.site_id = stored_site
            return

        legacy_scopes = self._legacy_scopes()
        if tenant_id is not None and site_id is not None:
            if any(scope != (tenant_id, site_id) for scope in legacy_scopes):
                raise ValueError(
                    "existing event spool rows do not match requested site scope"
                )
            self._write_scope_metadata(tenant_id, site_id)
            return

        if len(legacy_scopes) == 1:
            self._write_scope_metadata(*legacy_scopes[0])
        elif len(legacy_scopes) > 1:
            raise ValueError(
                "legacy event spool contains multiple site scopes; explicit migration required"
            )

    def bind_scope(self, tenant_id: str, site_id: str) -> None:
        if not tenant_id or not site_id:
            raise ValueError("event spool tenant_id/site_id cannot be empty")
        with self._lock:
            if self.tenant_id is None and self.site_id is None:
                legacy_scopes = self._legacy_scopes()
                if any(scope != (tenant_id, site_id) for scope in legacy_scopes):
                    raise ValueError(
                        "existing event spool rows do not match requested site scope"
                    )
                self._write_scope_metadata(tenant_id, site_id)
                return
            if self.tenant_id != tenant_id:
                raise ValueError("event spool tenant_id mismatch")
            if self.site_id != site_id:
                raise ValueError("event spool site_id mismatch")

    def _require_scope(self, tenant_id: str, site_id: str) -> None:
        if self.tenant_id is None or self.site_id is None:
            self.bind_scope(tenant_id, site_id)
            return
        if tenant_id != self.tenant_id or site_id != self.site_id:
            raise ValueError("event scope does not match this site spool")

    def enqueue(self, event: SecurityEvent) -> bool:
        self._require_scope(event.tenant_id, event.site_id)
        if event.observed_at.tzinfo is None or event.observed_at.utcoffset() is None:
            raise ValueError("event observed_at must be timezone-aware")
        payload = event.model_dump_json()
        created_at = dt.datetime.now(dt.UTC).isoformat()
        with self._lock:
            existing = self._connection.execute(
                """
                SELECT payload FROM event_spool
                WHERE event_id = ? AND tenant_id = ? AND site_id = ?
                """,
                (event.event_id, event.tenant_id, event.site_id),
            ).fetchone()
            if existing is not None:
                current = SecurityEvent.model_validate_json(existing["payload"])
                if current != event:
                    raise ValueError(
                        "event_id already exists with different content in site spool"
                    )
                return False

            self._connection.execute(
                """
                INSERT INTO event_spool(
                    event_id, tenant_id, site_id, observed_at, payload, created_at,
                    analysis_ready
                )
                VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    event.event_id,
                    event.tenant_id,
                    event.site_id,
                    event.observed_at.astimezone(dt.UTC).isoformat(),
                    payload,
                    created_at,
                ),
            )
            self._connection.commit()
            return True

    def pending(self, limit: int = 100) -> list[SecurityEvent]:
        """Return only events whose local analysis transaction completed."""
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if self.tenant_id is None or self.site_id is None:
            return []
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload
                FROM event_spool
                WHERE tenant_id = ? AND site_id = ? AND analysis_ready = 1
                ORDER BY observed_at ASC, created_at ASC
                LIMIT ?
                """,
                (self.tenant_id, self.site_id, limit),
            ).fetchall()
        events = [SecurityEvent.model_validate_json(row["payload"]) for row in rows]
        for event in events:
            self._require_scope(event.tenant_id, event.site_id)
        return events

    def pending_analysis(self, limit: int = 100) -> list[SecurityEvent]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if self.tenant_id is None or self.site_id is None:
            return []
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload
                FROM event_spool
                WHERE tenant_id = ? AND site_id = ? AND analysis_ready = 0
                ORDER BY observed_at ASC, created_at ASC
                LIMIT ?
                """,
                (self.tenant_id, self.site_id, limit),
            ).fetchall()
        return [
            SecurityEvent.model_validate_json(row["payload"])
            for row in rows
        ]

    def mark_analysis_ready(self, event_id: str) -> bool:
        if self.tenant_id is None or self.site_id is None:
            return False
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE event_spool
                SET analysis_ready = 1, analysis_last_error = NULL
                WHERE event_id = ? AND tenant_id = ? AND site_id = ?
                """,
                (event_id, self.tenant_id, self.site_id),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def mark_analysis_failed(self, event_id: str, error: str) -> bool:
        if self.tenant_id is None or self.site_id is None:
            return False
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE event_spool
                SET analysis_attempts = analysis_attempts + 1,
                    analysis_last_error = ?
                WHERE event_id = ? AND tenant_id = ? AND site_id = ?
                  AND analysis_ready = 0
                """,
                (error[:1000], event_id, self.tenant_id, self.site_id),
            )
            self._connection.commit()
            return cursor.rowcount == 1

    def mark_delivered(self, event_ids: set[str]) -> int:
        if not event_ids or self.tenant_id is None or self.site_id is None:
            return 0
        placeholders = ",".join("?" for _ in event_ids)
        with self._lock:
            cursor = self._connection.execute(
                f"""
                DELETE FROM event_spool
                WHERE tenant_id = ? AND site_id = ? AND analysis_ready = 1
                  AND event_id IN ({placeholders})
                """,
                (self.tenant_id, self.site_id, *sorted(event_ids)),
            )
            self._connection.commit()
            return cursor.rowcount

    def mark_failed(self, event_ids: set[str], error: str) -> int:
        if not event_ids or self.tenant_id is None or self.site_id is None:
            return 0
        placeholders = ",".join("?" for _ in event_ids)
        with self._lock:
            cursor = self._connection.execute(
                f"""
                UPDATE event_spool
                SET attempts = attempts + 1, last_error = ?
                WHERE tenant_id = ? AND site_id = ? AND analysis_ready = 1
                  AND event_id IN ({placeholders})
                """,
                (
                    error[:1000],
                    self.tenant_id,
                    self.site_id,
                    *sorted(event_ids),
                ),
            )
            self._connection.commit()
            return cursor.rowcount

    def has_event(self, event_id: str) -> bool:
        if self.tenant_id is None or self.site_id is None:
            return False
        with self._lock:
            row = self._connection.execute(
                """
                SELECT 1
                FROM event_spool
                WHERE tenant_id = ? AND site_id = ? AND event_id = ?
                """,
                (self.tenant_id, self.site_id, event_id),
            ).fetchone()
        return row is not None

    def count(self) -> int:
        if self.tenant_id is None or self.site_id is None:
            return 0
        with self._lock:
            row = self._connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM event_spool
                WHERE tenant_id = ? AND site_id = ?
                """,
                (self.tenant_id, self.site_id),
            ).fetchone()
        return int(row["count"]) if row else 0

    def diagnostics(self) -> dict[str, object]:
        if self.tenant_id is None or self.site_id is None:
            return {
                "queued": 0,
                "delivery_ready": 0,
                "analysis_pending": 0,
                "max_attempts": 0,
                "last_error": None,
                "analysis_max_attempts": 0,
                "analysis_last_error": None,
                "durability": "WAL_FULL",
                "scope_bound": False,
            }
        with self._lock:
            row = self._connection.execute(
                """
                SELECT
                    COUNT(*) AS queued,
                    SUM(CASE WHEN analysis_ready = 1 THEN 1 ELSE 0 END)
                        AS delivery_ready,
                    SUM(CASE WHEN analysis_ready = 0 THEN 1 ELSE 0 END)
                        AS analysis_pending,
                    COALESCE(MAX(attempts), 0) AS max_attempts,
                    MAX(CASE WHEN analysis_ready = 1 THEN last_error END)
                        AS last_error,
                    COALESCE(MAX(analysis_attempts), 0)
                        AS analysis_max_attempts,
                    MAX(CASE WHEN analysis_ready = 0 THEN analysis_last_error END)
                        AS analysis_last_error
                FROM event_spool
                WHERE tenant_id = ? AND site_id = ?
                """,
                (self.tenant_id, self.site_id),
            ).fetchone()
        return {
            "queued": int(row["queued"]) if row else 0,
            "delivery_ready": int(row["delivery_ready"] or 0) if row else 0,
            "analysis_pending": int(row["analysis_pending"] or 0) if row else 0,
            "max_attempts": int(row["max_attempts"]) if row else 0,
            "last_error": row["last_error"] if row else None,
            "analysis_max_attempts": (
                int(row["analysis_max_attempts"]) if row else 0
            ),
            "analysis_last_error": (
                row["analysis_last_error"] if row else None
            ),
            "durability": "WAL_FULL",
            "scope_bound": True,
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
        sensor_fleet_client: SensorFleetClient | None = None,
        sensor_trust_store: SQLiteSensorTrustStore | None = None,
        fabric_outbox: DurableFabricOutbox | None = None,
        fabric_publisher: FabricPublisher | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.site_id = site_id
        spool.bind_scope(tenant_id, site_id)
        self.spool = spool
        self.sender = sender
        self.pipeline = pipeline or SecurityPipeline()
        self.command_client = command_client
        self.sensor_fleet_client = sensor_fleet_client
        self.sensor_trust_store = sensor_trust_store
        self.fabric_outbox = fabric_outbox
        self.fabric_publisher = fabric_publisher
        if fabric_publisher is not None and fabric_outbox is None:
            raise ValueError(
                "fabric publisher requires a durable fabric outbox"
            )
        if fabric_outbox is not None and (
            fabric_outbox.tenant_id != tenant_id
            or fabric_outbox.site_id != site_id
        ):
            raise ValueError(
                "fabric outbox scope does not match site-controller identity"
            )
        if sensor_trust_store is not None and (
            sensor_trust_store.tenant_id != tenant_id
            or sensor_trust_store.site_id != site_id
        ):
            raise ValueError(
                "sensor trust store scope does not match site-controller identity"
            )
        if response_executor is not None and (
            response_executor.tenant_id != tenant_id
            or response_executor.site_id != site_id
        ):
            raise ValueError(
                "response executor scope does not match site-controller identity"
            )
        self.response_executor = response_executor
        self.recovery_engine = recovery_engine or (
            RecoveryEngine(response_executor.orchestrator)
            if response_executor is not None
            else None
        )

    def authorize_sensor_identity(
        self,
        sensor_id: str,
        fingerprint_sha256: str,
        *,
        now: dt.datetime | None = None,
    ) -> SensorTrustIdentity | None:
        if self.sensor_trust_store is None:
            return None
        return self.sensor_trust_store.authorize(
            sensor_id,
            fingerprint_sha256,
            now=now,
        )

    async def sync_sensor_trust(self) -> dict[str, object]:
        if self.sensor_trust_store is None:
            return {"state": "DISABLED", "accepted_identities": 0}
        if self.sensor_fleet_client is None:
            diagnostics = self.sensor_trust_store.diagnostics()
            return {
                "state": (
                    "OFFLINE"
                    if diagnostics["initialized"]
                    else "DEGRADED"
                ),
                "accepted_identities": diagnostics["accepted_identities"],
                "initialized": diagnostics["initialized"],
            }
        try:
            snapshot = await self.sensor_fleet_client.fetch_trust_snapshot(
                self.tenant_id,
                self.site_id,
            )
            self.sensor_trust_store.replace(snapshot)
        except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
            diagnostics = self.sensor_trust_store.diagnostics()
            return {
                "state": "DEGRADED",
                "accepted_identities": diagnostics["accepted_identities"],
                "initialized": diagnostics["initialized"],
                "error": str(exc)[:1000],
            }
        diagnostics = self.sensor_trust_store.diagnostics()
        return {
            "state": "SYNCED",
            "accepted_identities": diagnostics["accepted_identities"],
            "initialized": True,
            "generated_at": diagnostics["generated_at"],
        }

    async def relay_sensor_heartbeat(
        self,
        heartbeat: SensorHeartbeat,
    ) -> None:
        if (
            heartbeat.tenant_id != self.tenant_id
            or heartbeat.site_id != self.site_id
        ):
            raise SiteScopeViolation(
                "sensor heartbeat scope does not match this site-controller identity"
            )
        if self.authorize_sensor_identity(
            heartbeat.sensor_id,
            heartbeat.fingerprint_sha256,
        ) is None:
            raise SiteScopeViolation(
                "sensor certificate is not accepted by the local trust snapshot"
            )
        if self.sensor_fleet_client is None:
            raise RuntimeError("sensor fleet cloud client is unavailable")
        await self.sensor_fleet_client.submit_heartbeat(heartbeat)

    async def relay_sensor_renewal(
        self,
        request: SensorRenewalRequest,
    ) -> SensorRenewalResult:
        if request.tenant_id != self.tenant_id or request.site_id != self.site_id:
            raise SiteScopeViolation(
                "sensor renewal scope does not match this site-controller identity"
            )
        if self.authorize_sensor_identity(
            request.sensor_id,
            request.current_fingerprint_sha256,
        ) is None:
            raise SiteScopeViolation(
                "sensor certificate is not accepted by the local trust snapshot"
            )
        if self.sensor_fleet_client is None:
            raise RuntimeError("sensor fleet cloud client is unavailable")
        result = await self.sensor_fleet_client.renew_sensor(request)
        if self.sensor_trust_store is not None:
            self.sensor_trust_store.replace(result.trust_snapshot)
        return result

    def ingest(self, event: SecurityEvent) -> EventProcessingResult:
        if event.tenant_id != self.tenant_id or event.site_id != self.site_id:
            raise SiteScopeViolation(
                "event tenant/site does not match this site-controller identity"
            )
        self.spool.enqueue(event)
        try:
            result = self.pipeline.process_event(event)
        except Exception as exc:
            self.spool.mark_analysis_failed(event.event_id, str(exc))
            raise
        self.spool.mark_analysis_ready(event.event_id)
        return result

    def recover_pending_analysis(self, limit: int = 100) -> dict[str, object]:
        pending = self.spool.pending_analysis(limit=limit)
        recovered = 0
        failed = 0
        errors: dict[str, str] = {}
        for event in pending:
            try:
                self.pipeline.process_event(event)
            except Exception as exc:
                error = str(exc)[:1000]
                self.spool.mark_analysis_failed(event.event_id, error)
                errors[event.event_id] = error
                failed += 1
                continue
            self.spool.mark_analysis_ready(event.event_id)
            recovered += 1

        diagnostics = self.spool.diagnostics()
        return {
            "state": "RECOVERED" if failed == 0 else "DEGRADED",
            "attempted": len(pending),
            "recovered": recovered,
            "failed": failed,
            "analysis_pending": diagnostics["analysis_pending"],
            "errors": errors,
        }

    async def _flush_fabric(
        self,
        *,
        limit: int,
        analysis: dict[str, object],
    ) -> dict[str, object]:
        assert self.fabric_outbox is not None

        reconciled = 0
        for envelope in self.fabric_outbox.delivered_unreconciled(limit=limit):
            self.spool.mark_delivered({envelope.event_id})
            self.fabric_outbox.mark_source_reconciled(envelope.event_id)
            reconciled += 1

        staged = 0
        for event in self.spool.pending(limit=limit):
            existing = self.fabric_outbox.get(event.event_id)
            self.fabric_outbox.enqueue_security_event(event)
            if existing is None:
                staged += 1
            if self.fabric_outbox.is_delivered(event.event_id):
                self.spool.mark_delivered({event.event_id})
                self.fabric_outbox.mark_source_reconciled(event.event_id)
                reconciled += 1

        diagnostics = self.fabric_outbox.diagnostics()
        pending = self.fabric_outbox.pending(limit=limit)
        if not pending:
            return {
                "state": (
                    "DEGRADED"
                    if analysis["failed"]
                    else "SYNCED"
                ),
                "attempted": 0,
                "delivered": 0,
                "queued": self.spool.count(),
                "fabric_pending": diagnostics["pending"],
                "fabric_staged": staged,
                "fabric_reconciled": reconciled,
                "analysis": analysis,
            }

        if self.fabric_publisher is None:
            return {
                "state": "OFFLINE",
                "attempted": 0,
                "delivered": 0,
                "queued": self.spool.count(),
                "fabric_pending": diagnostics["pending"],
                "fabric_staged": staged,
                "fabric_reconciled": reconciled,
                "analysis": analysis,
            }

        attempted = 0
        delivered = 0
        error: str | None = None
        for envelope in pending:
            attempted += 1
            try:
                await self.fabric_publisher.publish(envelope)
            except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
                error = str(exc)[:1000]
                self.fabric_outbox.mark_failed(envelope.event_id, error)
                # Preserve one logical ordering domain per tenant/site. Later
                # envelopes are not allowed to overtake a failed predecessor.
                break
            self.fabric_outbox.mark_delivered(envelope.event_id)
            self.spool.mark_delivered({envelope.event_id})
            self.fabric_outbox.mark_source_reconciled(envelope.event_id)
            delivered += 1
            reconciled += 1

        diagnostics = self.fabric_outbox.diagnostics()
        state = (
            "SYNCED"
            if diagnostics["pending"] == 0
            and error is None
            and analysis["failed"] == 0
            else "DEGRADED"
        )
        result: dict[str, object] = {
            "state": state,
            "attempted": attempted,
            "delivered": delivered,
            "queued": self.spool.count(),
            "fabric_pending": diagnostics["pending"],
            "fabric_staged": staged,
            "fabric_reconciled": reconciled,
            "analysis": analysis,
        }
        if error is not None:
            result["error"] = error
        return result

    async def flush(self, limit: int = 100) -> dict[str, object]:
        analysis = self.recover_pending_analysis(limit=limit)
        if self.fabric_outbox is not None:
            return await self._flush_fabric(
                limit=limit,
                analysis=analysis,
            )

        events = self.spool.pending(limit=limit)
        diagnostics = self.spool.diagnostics()
        if not events:
            return {
                "state": (
                    "DEGRADED"
                    if analysis["failed"]
                    else "SYNCED"
                ),
                "attempted": 0,
                "delivered": 0,
                "queued": diagnostics["queued"],
                "analysis": analysis,
            }
        if self.sender is None:
            return {
                "state": "OFFLINE",
                "attempted": 0,
                "delivered": 0,
                "queued": diagnostics["queued"],
                "analysis": analysis,
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
                "analysis": analysis,
                "error": str(exc)[:1000],
            }

        delivered_ids = event_ids & accepted
        missing_ids = event_ids - delivered_ids
        self.spool.mark_delivered(delivered_ids)
        if missing_ids:
            self.spool.mark_failed(missing_ids, "control plane did not acknowledge event")

        return {
            "state": (
                "SYNCED"
                if not missing_ids and analysis["failed"] == 0
                else "DEGRADED"
            ),
            "attempted": len(events),
            "delivered": len(delivered_ids),
            "queued": self.spool.count(),
            "unacknowledged": len(missing_ids),
            "analysis": analysis,
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
        deferred = 0
        for command in commands:
            result = await self.response_executor.execute(command)
            if (
                result.execution is not None
                and result.execution.status is ResponseExecutionStatus.EXECUTING
            ):
                # An interrupted external action is still unverified. Do not
                # turn uncertainty into a terminal command result; leaving the
                # command pending allows safe redelivery and verification.
                deferred += 1
                continue
            if not result.success:
                failed += 1
            try:
                await self.command_client.submit_result(result)
            except (httpx.HTTPError, OSError, RuntimeError, ValueError):
                unreported += 1
                continue
            reported += 1

        return {
            "state": (
                "SYNCED"
                if unreported == 0 and deferred == 0
                else "DEGRADED"
            ),
            "attempted": len(commands),
            "reported": reported,
            "unreported": unreported,
            "deferred": deferred,
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

        reconciliation = {
            "attempted": 0,
            "resolved": 0,
            "present": 0,
            "absent": 0,
            "unresolved": 0,
        }
        if self.response_executor is not None:
            reconciliation = (
                await self.response_executor.reconcile_uncertain_executions()
            )

        sweep = await self.recovery_engine.sweep_scope(
            self.tenant_id,
            self.site_id,
            now=now,
        )
        return {
            "state": (
                "RECOVERED"
                if not sweep.failed and reconciliation["unresolved"] == 0
                else "DEGRADED"
            ),
            "attempted": sweep.attempted,
            "rolled_back": len(sweep.rolled_back),
            "failed": len(sweep.failed),
            "rolled_back_execution_ids": list(sweep.rolled_back),
            "failed_execution_ids": list(sweep.failed),
            "errors": sweep.errors,
            "execution_reconciliation": reconciliation,
        }

    def status(self) -> dict[str, object]:
        diagnostics = self.spool.diagnostics()
        response_state: dict[str, object] | None = None
        if self.response_executor is not None:
            executions = self.response_executor.store.list_response_executions(
                self.tenant_id,
                self.site_id,
            )
            response_state = {
                "executions": len(executions),
                "executing_uncertain": sum(
                    item.status is ResponseExecutionStatus.EXECUTING
                    for item in executions
                ),
            }
        sensor_trust = (
            self.sensor_trust_store.diagnostics()
            if self.sensor_trust_store is not None
            else None
        )
        fabric_state = (
            self.fabric_outbox.diagnostics()
            if self.fabric_outbox is not None
            else None
        )
        degraded = bool(
            diagnostics["last_error"]
            or diagnostics["analysis_last_error"]
            or diagnostics["analysis_pending"]
            or (
                fabric_state is not None
                and fabric_state["last_error"]
            )
        )
        if (
            sensor_trust is not None
            and self.sensor_fleet_client is not None
            and not sensor_trust["initialized"]
        ):
            degraded = True
        if response_state is not None and response_state["executing_uncertain"]:
            degraded = True
        return {
            "state": "DEGRADED" if degraded else "READY",
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "cloud_sender_configured": (
                self.sender is not None or self.fabric_publisher is not None
            ),
            "fabric_outbox": fabric_state,
            "local_recovery_configured": self.recovery_engine is not None,
            "command_channel_configured": (
                self.command_client is not None and self.response_executor is not None
            ),
            "sensor_fleet_configured": self.sensor_fleet_client is not None,
            "sensor_trust": sensor_trust,
            "spool": diagnostics,
            "response_state": response_state,
            "local_pipeline_state_persistence": self.pipeline.persistence_mode.value,
            "local_pipeline_restore": self.pipeline.last_restore,
            "local_incidents": len(
                self.pipeline.store.list_incidents(self.tenant_id, self.site_id)
            ),
            "local_findings": len(
                self.pipeline.store.list_findings(self.tenant_id, self.site_id)
            ),
        }
