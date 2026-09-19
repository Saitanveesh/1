from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from mon.domain import Asset, Finding, Incident, SecurityEvent

_SCHEMA_VERSION = "2"


class SQLiteSiteAnalysisStore:
    """Durable evidence-pipeline state for exactly one tenant/site scope."""

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
        self._transaction_active = False
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
                CREATE TABLE IF NOT EXISTS site_analysis_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            version_row = self._connection.execute(
                """
                SELECT value FROM site_analysis_metadata
                WHERE key = 'schema_version'
                """
            ).fetchone()
            version = str(version_row["value"]) if version_row is not None else None
            if version not in {None, "1", _SCHEMA_VERSION}:
                raise ValueError(
                    f"unsupported site analysis schema version: {version}"
                )

            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS site_analysis_events (
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, site_id, event_id)
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_site_analysis_events_observed
                ON site_analysis_events(tenant_id, site_id, observed_at, event_id)
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS site_analysis_findings (
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, site_id, finding_id)
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS site_analysis_incidents (
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, site_id, incident_id)
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS site_analysis_assets (
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, site_id, asset_id)
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS site_analysis_processing (
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    processed_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, site_id, event_id),
                    FOREIGN KEY (tenant_id, site_id, event_id)
                        REFERENCES site_analysis_events(tenant_id, site_id, event_id)
                        ON DELETE CASCADE
                )
                """
            )

            if version == "1":
                row = self._connection.execute(
                    "SELECT COUNT(*) AS count FROM site_analysis_events"
                ).fetchone()
                if row is not None and int(row["count"]) > 0:
                    raise ValueError(
                        "site analysis schema v1 contains events without atomic "
                        "processing receipts; explicit rebuild is required"
                    )
                self._connection.execute(
                    """
                    UPDATE site_analysis_metadata
                    SET value = ?
                    WHERE key = 'schema_version'
                    """,
                    (_SCHEMA_VERSION,),
                )
            elif version is None:
                self._connection.execute(
                    """
                    INSERT INTO site_analysis_metadata(key, value)
                    VALUES ('schema_version', ?)
                    """,
                    (_SCHEMA_VERSION,),
                )

            self._bind_metadata("tenant_id", self.tenant_id)
            self._bind_metadata("site_id", self.site_id)

    def _bind_metadata(self, key: str, expected: str) -> None:
        row = self._connection.execute(
            "SELECT value FROM site_analysis_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO site_analysis_metadata(key, value) VALUES (?, ?)",
                (key, expected),
            )
            return
        actual = str(row["value"])
        if actual != expected:
            raise ValueError(
                f"site analysis store {key} mismatch: "
                f"expected {expected!r}, found {actual!r}"
            )

    def close(self) -> None:
        with self._lock:
            if self._transaction_active:
                self._connection.rollback()
                self._transaction_active = False
            self._connection.close()

    def _require_scope(self, tenant_id: str, site_id: str) -> None:
        if tenant_id != self.tenant_id or site_id != self.site_id:
            raise ValueError("analysis state scope does not match this site store")

    @staticmethod
    def _utc_iso(value: dt.datetime, *, field_name: str) -> str:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{field_name} must be timezone-aware")
        return value.astimezone(dt.UTC).isoformat()

    def _commit_if_autonomous(self) -> None:
        if not self._transaction_active:
            self._connection.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Commit all local derived state for one event as one SQLite transaction."""
        with self._lock:
            if self._transaction_active:
                raise RuntimeError("nested site analysis transactions are not supported")
            self._connection.execute("BEGIN IMMEDIATE")
            self._transaction_active = True
            try:
                yield
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()
            finally:
                self._transaction_active = False

    def event_exists(self, tenant_id: str, site_id: str, event_id: str) -> bool:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT 1 FROM site_analysis_events
                WHERE tenant_id = ? AND site_id = ? AND event_id = ?
                """,
                (tenant_id, site_id, event_id),
            ).fetchone()
        return row is not None

    def event_processed(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> bool:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT 1 FROM site_analysis_processing
                WHERE tenant_id = ? AND site_id = ? AND event_id = ?
                """,
                (tenant_id, site_id, event_id),
            ).fetchone()
        return row is not None

    def add_event(self, event: SecurityEvent) -> SecurityEvent:
        self._require_scope(event.tenant_id, event.site_id)
        observed_at = self._utc_iso(
            event.observed_at,
            field_name="event observed_at",
        )
        payload = event.model_dump_json()
        with self._lock:
            row = self._connection.execute(
                """
                SELECT payload FROM site_analysis_events
                WHERE tenant_id = ? AND site_id = ? AND event_id = ?
                """,
                (event.tenant_id, event.site_id, event.event_id),
            ).fetchone()
            if row is not None:
                current = SecurityEvent.model_validate_json(row["payload"])
                if current != event:
                    raise ValueError(
                        "event_id already exists with different content "
                        "in site analysis store"
                    )
                return current
            self._connection.execute(
                """
                INSERT INTO site_analysis_events(
                    tenant_id, site_id, event_id, observed_at, payload
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    event.tenant_id,
                    event.site_id,
                    event.event_id,
                    observed_at,
                    payload,
                ),
            )
            self._commit_if_autonomous()
        return event

    def mark_event_processed(self, event: SecurityEvent) -> None:
        self._require_scope(event.tenant_id, event.site_id)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT payload FROM site_analysis_events
                WHERE tenant_id = ? AND site_id = ? AND event_id = ?
                """,
                (event.tenant_id, event.site_id, event.event_id),
            ).fetchone()
            if row is None:
                raise ValueError(
                    "cannot mark an event processed before its durable event record"
                )
            current = SecurityEvent.model_validate_json(row["payload"])
            if current != event:
                raise ValueError(
                    "processed event content does not match durable event record"
                )
            self._connection.execute(
                """
                INSERT OR IGNORE INTO site_analysis_processing(
                    tenant_id, site_id, event_id, processed_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    event.tenant_id,
                    event.site_id,
                    event.event_id,
                    dt.datetime.now(dt.UTC).isoformat(),
                ),
            )
            self._commit_if_autonomous()

    def list_events(
        self,
        tenant_id: str,
        site_id: str,
        *,
        since: dt.datetime | None = None,
    ) -> list[SecurityEvent]:
        self._require_scope(tenant_id, site_id)
        parameters: list[object] = [tenant_id, site_id]
        where = "tenant_id = ? AND site_id = ?"
        if since is not None:
            where += " AND observed_at >= ?"
            parameters.append(
                self._utc_iso(since, field_name="event replay since")
            )
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT payload FROM site_analysis_events
                WHERE {where}
                ORDER BY observed_at ASC, event_id ASC
                """,
                tuple(parameters),
            ).fetchall()
        return [
            SecurityEvent.model_validate_json(row["payload"])
            for row in rows
        ]

    def list_unprocessed_events(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[SecurityEvent]:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT events.payload
                FROM site_analysis_events AS events
                LEFT JOIN site_analysis_processing AS processing
                  ON processing.tenant_id = events.tenant_id
                 AND processing.site_id = events.site_id
                 AND processing.event_id = events.event_id
                WHERE events.tenant_id = ?
                  AND events.site_id = ?
                  AND processing.event_id IS NULL
                ORDER BY events.observed_at ASC, events.event_id ASC
                """,
                (tenant_id, site_id),
            ).fetchall()
        return [
            SecurityEvent.model_validate_json(row["payload"])
            for row in rows
        ]

    def add_finding(self, finding: Finding) -> Finding:
        self._require_scope(finding.tenant_id, finding.site_id)
        last_seen = self._utc_iso(
            finding.last_seen,
            field_name="finding last_seen",
        )
        payload = finding.model_dump_json()
        with self._lock:
            row = self._connection.execute(
                """
                SELECT payload FROM site_analysis_findings
                WHERE tenant_id = ? AND site_id = ? AND finding_id = ?
                """,
                (finding.tenant_id, finding.site_id, finding.finding_id),
            ).fetchone()
            if row is not None:
                current = Finding.model_validate_json(row["payload"])
                if current != finding:
                    raise ValueError(
                        "finding_id already exists with different content "
                        "in site analysis store"
                    )
                return current
            self._connection.execute(
                """
                INSERT INTO site_analysis_findings(
                    tenant_id, site_id, finding_id, last_seen, payload
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    finding.tenant_id,
                    finding.site_id,
                    finding.finding_id,
                    last_seen,
                    payload,
                ),
            )
            self._commit_if_autonomous()
        return finding

    def list_findings(self, tenant_id: str, site_id: str) -> list[Finding]:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload FROM site_analysis_findings
                WHERE tenant_id = ? AND site_id = ?
                ORDER BY last_seen ASC, finding_id ASC
                """,
                (tenant_id, site_id),
            ).fetchall()
        return [Finding.model_validate_json(row["payload"]) for row in rows]

    def add_incident(self, incident: Incident) -> Incident:
        self._require_scope(incident.tenant_id, incident.site_id)
        last_seen = self._utc_iso(
            incident.last_seen,
            field_name="incident last_seen",
        )
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO site_analysis_incidents(
                    tenant_id, site_id, incident_id, last_seen, payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, site_id, incident_id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    payload = excluded.payload
                """,
                (
                    incident.tenant_id,
                    incident.site_id,
                    incident.incident_id,
                    last_seen,
                    incident.model_dump_json(),
                ),
            )
            self._commit_if_autonomous()
        return incident

    def list_incidents(self, tenant_id: str, site_id: str) -> list[Incident]:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload FROM site_analysis_incidents
                WHERE tenant_id = ? AND site_id = ?
                ORDER BY last_seen ASC, incident_id ASC
                """,
                (tenant_id, site_id),
            ).fetchall()
        return [Incident.model_validate_json(row["payload"]) for row in rows]

    def get_incident(
        self,
        tenant_id: str,
        site_id: str,
        incident_id: str,
    ) -> Incident | None:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT payload FROM site_analysis_incidents
                WHERE tenant_id = ? AND site_id = ? AND incident_id = ?
                """,
                (tenant_id, site_id, incident_id),
            ).fetchone()
        return Incident.model_validate_json(row["payload"]) if row else None

    def add_asset(self, asset: Asset) -> Asset:
        self._require_scope(asset.tenant_id, asset.site_id)
        last_seen = self._utc_iso(
            asset.last_seen,
            field_name="asset last_seen",
        )
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO site_analysis_assets(
                    tenant_id, site_id, asset_id, last_seen, payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, site_id, asset_id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    payload = excluded.payload
                """,
                (
                    asset.tenant_id,
                    asset.site_id,
                    asset.asset_id,
                    last_seen,
                    asset.model_dump_json(),
                ),
            )
            self._commit_if_autonomous()
        return asset

    def get_asset(
        self,
        tenant_id: str,
        site_id: str,
        asset_id: str,
    ) -> Asset | None:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT payload FROM site_analysis_assets
                WHERE tenant_id = ? AND site_id = ? AND asset_id = ?
                """,
                (tenant_id, site_id, asset_id),
            ).fetchone()
        return Asset.model_validate_json(row["payload"]) if row else None

    def list_assets(self, tenant_id: str, site_id: str) -> list[Asset]:
        self._require_scope(tenant_id, site_id)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT payload FROM site_analysis_assets
                WHERE tenant_id = ? AND site_id = ?
                ORDER BY last_seen ASC, asset_id ASC
                """,
                (tenant_id, site_id),
            ).fetchall()
        return [Asset.model_validate_json(row["payload"]) for row in rows]

    def diagnostics(self) -> dict[str, object]:
        tables = {
            "events": "site_analysis_events",
            "processed_events": "site_analysis_processing",
            "findings": "site_analysis_findings",
            "incidents": "site_analysis_incidents",
            "assets": "site_analysis_assets",
        }
        counts: dict[str, int] = {}
        with self._lock:
            for name, table in tables.items():
                row = self._connection.execute(
                    f"""
                    SELECT COUNT(*) AS count FROM {table}
                    WHERE tenant_id = ? AND site_id = ?
                    """,
                    (self.tenant_id, self.site_id),
                ).fetchone()
                counts[name] = int(row["count"]) if row else 0
        counts["unprocessed_events"] = (
            counts["events"] - counts["processed_events"]
        )
        return {
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "schema_version": _SCHEMA_VERSION,
            "durability": "WAL_FULL",
            **counts,
        }
