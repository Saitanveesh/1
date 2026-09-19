from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path

from mon.sensor_fleet_models import (
    SensorIdentityStatus,
    SensorTrustIdentity,
    SensorTrustSnapshot,
)


class SensorTrustStoreError(ValueError):
    pass


class SQLiteSensorTrustStore:
    """Durable site-scoped allow set for sensor certificate fingerprints."""

    _SCHEMA_VERSION = "1"

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        site_id: str,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if not tenant_id or not site_id:
            raise ValueError("sensor trust tenant_id and site_id are required")
        if busy_timeout_seconds <= 0 or busy_timeout_seconds > 60:
            raise ValueError("busy_timeout_seconds must be between 0 and 60")

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
            with self._lock, self._connection:
                self._connection.execute("PRAGMA journal_mode=WAL")
                self._connection.execute("PRAGMA synchronous=FULL")
                self._connection.execute("PRAGMA foreign_keys=ON")
                self._connection.execute(
                    f"PRAGMA busy_timeout={int(busy_timeout_seconds * 1000)}"
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sensor_trust_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sensor_trust_identities (
                        fingerprint_sha256 TEXT PRIMARY KEY,
                        sensor_id TEXT NOT NULL,
                        identity_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        accept_until TEXT,
                        payload TEXT NOT NULL
                    )
                    """
                )
                self._bind_metadata("schema_version", self._SCHEMA_VERSION)
                self._bind_metadata("tenant_id", tenant_id)
                self._bind_metadata("site_id", site_id)
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _bind_metadata(self, key: str, expected: str) -> None:
        row = self._connection.execute(
            "SELECT value FROM sensor_trust_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO sensor_trust_metadata(key, value) VALUES (?, ?)",
                (key, expected),
            )
            return
        if str(row["value"]) != expected:
            raise ValueError(
                f"sensor trust store {key} mismatch: expected {expected!r}, "
                f"found {str(row['value'])!r}"
            )

    def _metadata_value(self, key: str) -> str | None:
        row = self._connection.execute(
            "SELECT value FROM sensor_trust_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        return str(row["value"]) if row is not None else None

    def _set_metadata(self, key: str, value: str) -> None:
        self._connection.execute(
            """
            INSERT INTO sensor_trust_metadata(key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )

    @staticmethod
    def _parse_time(value: str | None) -> dt.datetime | None:
        if value is None:
            return None
        parsed = dt.datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise SensorTrustStoreError(
                "sensor trust metadata time must be timezone-aware"
            )
        return parsed.astimezone(dt.UTC)

    def replace(
        self,
        snapshot: SensorTrustSnapshot,
        *,
        received_at: dt.datetime | None = None,
    ) -> bool:
        if snapshot.tenant_id != self.tenant_id or snapshot.site_id != self.site_id:
            raise SensorTrustStoreError(
                "sensor trust snapshot scope does not match this site"
            )
        if (
            snapshot.generated_at.tzinfo is None
            or snapshot.generated_at.utcoffset() is None
        ):
            raise SensorTrustStoreError(
                "sensor trust snapshot generated_at must be timezone-aware"
            )
        generated_at = snapshot.generated_at.astimezone(dt.UTC)
        receipt_time = (received_at or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)

        fingerprints: set[str] = set()
        for identity in snapshot.identities:
            if identity.fingerprint_sha256 in fingerprints:
                raise SensorTrustStoreError(
                    "sensor trust snapshot contains duplicate certificate fingerprint"
                )
            fingerprints.add(identity.fingerprint_sha256)

        with self._lock, self._connection:
            current = self._parse_time(self._metadata_value("generated_at"))
            if current is not None and generated_at < current:
                raise SensorTrustStoreError(
                    "sensor trust snapshot is older than the durable local snapshot"
                )

            self._connection.execute("DELETE FROM sensor_trust_identities")
            self._connection.executemany(
                """
                INSERT INTO sensor_trust_identities(
                    fingerprint_sha256,
                    sensor_id,
                    identity_id,
                    status,
                    expires_at,
                    accept_until,
                    payload
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        identity.fingerprint_sha256,
                        identity.sensor_id,
                        identity.identity_id,
                        identity.status.value,
                        identity.expires_at.astimezone(dt.UTC).isoformat(),
                        (
                            identity.accept_until.astimezone(dt.UTC).isoformat()
                            if identity.accept_until is not None
                            else None
                        ),
                        identity.model_dump_json(),
                    )
                    for identity in snapshot.identities
                ],
            )
            self._set_metadata("generated_at", generated_at.isoformat())
            self._set_metadata("received_at", receipt_time.isoformat())
        return True

    def authorize(
        self,
        sensor_id: str,
        fingerprint_sha256: str,
        *,
        now: dt.datetime | None = None,
    ) -> SensorTrustIdentity | None:
        check_at = (now or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
        with self._lock:
            if self._metadata_value("generated_at") is None:
                return None
            row = self._connection.execute(
                """
                SELECT payload
                FROM sensor_trust_identities
                WHERE fingerprint_sha256 = ? AND sensor_id = ?
                """,
                (fingerprint_sha256, sensor_id),
            ).fetchone()
        if row is None:
            return None
        identity = SensorTrustIdentity.model_validate_json(str(row["payload"]))
        if identity.expires_at <= check_at:
            return None
        if identity.status is SensorIdentityStatus.ACTIVE:
            return identity
        if (
            identity.status is SensorIdentityStatus.RETIRING
            and identity.accept_until is not None
            and identity.accept_until > check_at
        ):
            return identity
        return None

    def snapshot(self) -> SensorTrustSnapshot | None:
        with self._lock:
            generated_at = self._parse_time(
                self._metadata_value("generated_at")
            )
            if generated_at is None:
                return None
            rows = self._connection.execute(
                """
                SELECT payload
                FROM sensor_trust_identities
                ORDER BY sensor_id, identity_id
                """
            ).fetchall()
        return SensorTrustSnapshot(
            tenant_id=self.tenant_id,
            site_id=self.site_id,
            generated_at=generated_at,
            identities=[
                SensorTrustIdentity.model_validate_json(str(row["payload"]))
                for row in rows
            ],
        )

    def diagnostics(self) -> dict[str, object]:
        with self._lock:
            generated_at = self._metadata_value("generated_at")
            received_at = self._metadata_value("received_at")
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM sensor_trust_identities"
            ).fetchone()
        return {
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "initialized": generated_at is not None,
            "generated_at": generated_at,
            "received_at": received_at,
            "accepted_identities": int(row["count"]) if row else 0,
            "durability": "WAL_FULL",
        }
