from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path

from mon.domain import Asset, Finding, Incident, SecurityEvent

_SCHEMA_VERSION = "1"


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
            self._bind_metadata("schema_version", _SCHEMA_VERSION)
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
            self._connection.close()

    def _require_scope(self, tenant_id: str, site_id: str) -> None:
        if tenant_id != self.tenant_id or site_id != self.site_id:
            raise ValueError("analysis state scope does not match this site store")

    @staticmethod
    def _utc_iso(value: dt.datetime, *, field_name: str) -> str:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{field_name} must be timezone-aware")
        return value.astimezone(dt.UTC).isoformat()

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

    def add_event(self, event: SecurityEvent) -> SecurityEvent:
        self._require_scope(event.tenant_id, event.site_id)
        observed_at = self._utc_iso(
            event.observed_at,
            field_name="event observed_at",
        )
        payload = event.model_dump_json()
        with self._lock, self._connection:
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
        return event

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

    def add_finding(self, finding: Finding) -> Finding:
        self._require_scope(finding.tenant_id, finding.site_id)
        last_seen = self._utc_iso(
            finding.last_seen,
            field_name="finding last_seen",
        )
        payload = finding.model_dump_json()
        with self._lock, self._connection:
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
        with self._lock, self._connection:
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
        with self._lock, self._connection:
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
        return {
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "durability": "WAL_FULL",
            **counts,
        }
