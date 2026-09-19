from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import signal
import sqlite3
import ssl
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from mon.sensor_transport import extract_sensor_identity_from_verified_certificate
from mon.site_identity import create_mtls_client_ssl_context

_SUPPORTED_ZEEK_LOGS = ("conn", "dns", "http", "ssl", "notice", "weird")
_SUPPORTED_SURICATA_TYPES = {"alert", "flow", "dns", "http", "tls"}


class SensorCollectorError(RuntimeError):
    pass


class SensorRotationGapError(SensorCollectorError):
    pass


class SensorRecordError(SensorCollectorError):
    pass


class SensorDeliveryError(SensorCollectorError):
    pass


@dataclass(frozen=True, slots=True)
class SensorCursor:
    source_id: str
    configured_path: str
    device: int
    inode: int
    offset: int
    updated_at: dt.datetime


@dataclass(frozen=True, slots=True)
class FileReadBatch:
    records: list[dict[str, Any]]
    checkpoint: SensorCursor | None
    skipped_records: int
    source_missing: bool = False


class SQLiteSensorCursorStore:
    """Durable read checkpoints for one sensor collector identity."""

    _SCHEMA_VERSION = "1"

    def __init__(
        self,
        path: str | Path,
        *,
        sensor_id: str,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if not sensor_id:
            raise ValueError("sensor_id is required")
        if busy_timeout_seconds <= 0 or busy_timeout_seconds > 60:
            raise ValueError("busy_timeout_seconds must be between 0 and 60")

        self.path = Path(path)
        self.sensor_id = sensor_id
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
                    CREATE TABLE IF NOT EXISTS sensor_cursor_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sensor_cursors (
                        source_id TEXT PRIMARY KEY,
                        configured_path TEXT NOT NULL,
                        device INTEGER NOT NULL,
                        inode INTEGER NOT NULL,
                        offset INTEGER NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_error TEXT,
                        failures INTEGER NOT NULL DEFAULT 0,
                        filtered_records INTEGER NOT NULL DEFAULT 0
                    )
                    """
                )
                self._bind_metadata("schema_version", self._SCHEMA_VERSION)
                self._bind_metadata("sensor_id", sensor_id)
        except Exception:
            self._connection.close()
            raise

    def _bind_metadata(self, key: str, expected: str) -> None:
        row = self._connection.execute(
            "SELECT value FROM sensor_cursor_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO sensor_cursor_metadata(key, value) VALUES (?, ?)",
                (key, expected),
            )
            return
        if str(row["value"]) != expected:
            raise ValueError(
                f"sensor cursor store {key} mismatch: expected {expected!r}, "
                f"found {str(row['value'])!r}"
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def get(self, source_id: str) -> SensorCursor | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT source_id, configured_path, device, inode, offset, updated_at
                FROM sensor_cursors
                WHERE source_id = ?
                """,
                (source_id,),
            ).fetchone()
        if row is None:
            return None
        updated_at = dt.datetime.fromisoformat(str(row["updated_at"]))
        if updated_at.tzinfo is None or updated_at.utcoffset() is None:
            raise ValueError("sensor cursor updated_at must be timezone-aware")
        return SensorCursor(
            source_id=str(row["source_id"]),
            configured_path=str(row["configured_path"]),
            device=int(row["device"]),
            inode=int(row["inode"]),
            offset=int(row["offset"]),
            updated_at=updated_at.astimezone(dt.UTC),
        )

    def commit(
        self,
        cursor: SensorCursor,
        *,
        filtered_records: int = 0,
    ) -> None:
        if cursor.offset < 0:
            raise ValueError("sensor cursor offset cannot be negative")
        if filtered_records < 0:
            raise ValueError("filtered_records cannot be negative")
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO sensor_cursors(
                    source_id, configured_path, device, inode, offset,
                    updated_at, last_error, failures, filtered_records
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    configured_path = excluded.configured_path,
                    device = excluded.device,
                    inode = excluded.inode,
                    offset = excluded.offset,
                    updated_at = excluded.updated_at,
                    last_error = NULL,
                    failures = 0,
                    filtered_records = sensor_cursors.filtered_records
                        + excluded.filtered_records
                """,
                (
                    cursor.source_id,
                    cursor.configured_path,
                    cursor.device,
                    cursor.inode,
                    cursor.offset,
                    cursor.updated_at.astimezone(dt.UTC).isoformat(),
                    filtered_records,
                ),
            )

    def record_failure(self, source_id: str, error: str) -> None:
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT source_id FROM sensor_cursors WHERE source_id = ?",
                (source_id,),
            ).fetchone()
            if row is None:
                return
            self._connection.execute(
                """
                UPDATE sensor_cursors
                SET failures = failures + 1, last_error = ?, updated_at = ?
                WHERE source_id = ?
                """,
                (
                    error[:1000],
                    dt.datetime.now(dt.UTC).isoformat(),
                    source_id,
                ),
            )

    def diagnostics(self) -> dict[str, object]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT source_id, configured_path, offset, failures,
                       last_error, filtered_records, updated_at
                FROM sensor_cursors
                ORDER BY source_id
                """
            ).fetchall()
        return {
            "sensor_id": self.sensor_id,
            "durability": "WAL_FULL",
            "sources": [
                {
                    "source_id": str(row["source_id"]),
                    "configured_path": str(row["configured_path"]),
                    "offset": int(row["offset"]),
                    "failures": int(row["failures"]),
                    "last_error": row["last_error"],
                    "filtered_records": int(row["filtered_records"]),
                    "updated_at": str(row["updated_at"]),
                }
                for row in rows
            ],
        }


class JsonLineFileReader:
    """Read complete JSON lines without silently skipping rotation gaps."""

    def __init__(self, cursor_store: SQLiteSensorCursorStore) -> None:
        self.cursor_store = cursor_store

    @staticmethod
    def _matching_inode(
        configured_path: Path,
        device: int,
        inode: int,
    ) -> Path | None:
        candidates: list[Path] = []
        if configured_path.exists():
            candidates.append(configured_path)
        parent = configured_path.parent
        if parent.is_dir():
            try:
                candidates.extend(
                    item
                    for item in parent.iterdir()
                    if item != configured_path and item.is_file()
                )
            except OSError:
                pass

        for candidate in candidates:
            try:
                stat = candidate.stat()
            except OSError:
                continue
            if stat.st_dev == device and stat.st_ino == inode:
                return candidate
        return None

    def _resolve_source(
        self,
        source_id: str,
        configured_path: Path,
    ) -> tuple[Path, int, int, int] | None:
        cursor = self.cursor_store.get(source_id)
        if cursor is None:
            if not configured_path.is_file():
                return None
            stat = configured_path.stat()
            return configured_path, stat.st_dev, stat.st_ino, 0

        if Path(cursor.configured_path) != configured_path:
            raise SensorRotationGapError(
                f"source {source_id} configured path changed from "
                f"{cursor.configured_path} to {configured_path}"
            )

        candidate = self._matching_inode(
            configured_path,
            cursor.device,
            cursor.inode,
        )
        if candidate is None:
            raise SensorRotationGapError(
                f"source {source_id} cannot locate prior inode "
                f"{cursor.device}:{cursor.inode}; unread rotated data may exist"
            )
        stat = candidate.stat()
        if stat.st_size < cursor.offset:
            raise SensorRotationGapError(
                f"source {source_id} was truncated below committed offset "
                f"{cursor.offset}"
            )
        return candidate, cursor.device, cursor.inode, cursor.offset

    def read_batch(
        self,
        source_id: str,
        configured_path: str | Path,
        *,
        limit: int,
        accept: Callable[[Mapping[str, Any]], bool] | None = None,
    ) -> FileReadBatch:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        path = Path(configured_path)
        resolved = self._resolve_source(source_id, path)
        if resolved is None:
            return FileReadBatch(
                records=[],
                checkpoint=None,
                skipped_records=0,
                source_missing=True,
            )

        actual_path, device, inode, offset = resolved
        records: list[dict[str, Any]] = []
        skipped = 0
        checkpoint_offset = offset

        scanned = 0
        with actual_path.open("rb") as handle:
            handle.seek(offset)
            while scanned < limit:
                line_start = handle.tell()
                line = handle.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    # Keep the cursor at the start of an incomplete append.
                    handle.seek(line_start)
                    break
                checkpoint_offset = handle.tell()
                scanned += 1
                try:
                    decoded = line.decode("utf-8")
                    raw = json.loads(decoded)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise SensorRecordError(
                        f"source {source_id} has invalid JSON at byte {line_start}"
                    ) from exc
                if not isinstance(raw, dict):
                    raise SensorRecordError(
                        f"source {source_id} JSON record at byte {line_start} "
                        "must be an object"
                    )
                if accept is not None and not accept(raw):
                    skipped += 1
                    continue
                records.append(raw)

        checkpoint = SensorCursor(
            source_id=source_id,
            configured_path=str(path),
            device=device,
            inode=inode,
            offset=checkpoint_offset,
            updated_at=dt.datetime.now(dt.UTC),
        )

        # If a prior inode was already durably drained, a later empty
        # poll can transition to the replacement path at byte zero. When this
        # poll still contains records from the old inode, keep the old EOF
        # checkpoint until those records have been acknowledged.
        if (
            actual_path != path
            and checkpoint_offset == actual_path.stat().st_size
            and not records
            and skipped == 0
        ):
            current_stat = path.stat() if path.is_file() else None
            if current_stat is not None:
                checkpoint = SensorCursor(
                    source_id=source_id,
                    configured_path=str(path),
                    device=current_stat.st_dev,
                    inode=current_stat.st_ino,
                    offset=0,
                    updated_at=dt.datetime.now(dt.UTC),
                )

        return FileReadBatch(
            records=records,
            checkpoint=checkpoint,
            skipped_records=skipped,
        )


class SensorBatchClient:
    def __init__(
        self,
        base_url: str,
        ssl_context: ssl.SSLContext,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not base_url.lower().startswith("https://"):
            raise ValueError("sensor ingress URL must use https")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("timeout_seconds must be greater than 0 and at most 60")
        self.base_url = base_url.rstrip("/")
        self.ssl_context = ssl_context
        self.timeout_seconds = timeout_seconds

    async def _post(self, path: str, payload: dict[str, object]) -> None:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            verify=self.ssl_context,
            timeout=self.timeout_seconds,
        ) as client:
            try:
                response = await client.post(path, json=payload)
            except httpx.HTTPError as exc:
                raise SensorDeliveryError(
                    "sensor ingress is unavailable"
                ) from exc
        if response.status_code < 200 or response.status_code >= 300:
            detail = response.text.strip()[:500]
            raise SensorDeliveryError(
                f"sensor ingress rejected batch with HTTP "
                f"{response.status_code}: {detail}"
            )

    async def send_zeek(
        self,
        log_type: str,
        records: list[dict[str, Any]],
    ) -> None:
        await self._post(
            "/api/v1/sensors/zeek/batch",
            {
                "records": [
                    {"log_type": log_type, "record": record}
                    for record in records
                ]
            },
        )

    async def send_suricata(
        self,
        records: list[dict[str, Any]],
    ) -> None:
        await self._post(
            "/api/v1/sensors/suricata/batch",
            {"records": [{"record": record} for record in records]},
        )


class ZeekFileCollector:
    def __init__(
        self,
        log_dir: str | Path,
        cursor_store: SQLiteSensorCursorStore,
        client: SensorBatchClient,
        *,
        batch_size: int = 100,
    ) -> None:
        if batch_size < 1 or batch_size > 1000:
            raise ValueError("batch_size must be between 1 and 1000")
        self.log_dir = Path(log_dir)
        self.cursor_store = cursor_store
        self.reader = JsonLineFileReader(cursor_store)
        self.client = client
        self.batch_size = batch_size

    async def poll_once(self) -> dict[str, object]:
        sent = 0
        missing = 0
        errors: dict[str, str] = {}
        for log_type in _SUPPORTED_ZEEK_LOGS:
            source_id = f"zeek:{log_type}"
            path = self.log_dir / f"{log_type}.log"
            try:
                batch = self.reader.read_batch(
                    source_id,
                    path,
                    limit=self.batch_size,
                )
                if batch.source_missing:
                    missing += 1
                    continue
                if batch.records:
                    await self.client.send_zeek(log_type, batch.records)
                    sent += len(batch.records)
                if batch.checkpoint is not None:
                    self.cursor_store.commit(
                        batch.checkpoint,
                        filtered_records=batch.skipped_records,
                    )
            except SensorCollectorError as exc:
                error = str(exc)[:1000]
                self.cursor_store.record_failure(source_id, error)
                errors[source_id] = error
        return {
            "state": "READY" if not errors else "DEGRADED",
            "sent": sent,
            "missing_sources": missing,
            "errors": errors,
        }


class SuricataFileCollector:
    def __init__(
        self,
        eve_path: str | Path,
        cursor_store: SQLiteSensorCursorStore,
        client: SensorBatchClient,
        *,
        batch_size: int = 100,
    ) -> None:
        if batch_size < 1 or batch_size > 1000:
            raise ValueError("batch_size must be between 1 and 1000")
        self.eve_path = Path(eve_path)
        self.cursor_store = cursor_store
        self.reader = JsonLineFileReader(cursor_store)
        self.client = client
        self.batch_size = batch_size

    @staticmethod
    def _supported(record: Mapping[str, Any]) -> bool:
        event_type = record.get("event_type")
        if not isinstance(event_type, str) or not event_type.strip():
            raise SensorRecordError(
                "Suricata EVE record is missing event_type"
            )
        return event_type.casefold() in _SUPPORTED_SURICATA_TYPES

    async def poll_once(self) -> dict[str, object]:
        source_id = "suricata:eve"
        try:
            batch = self.reader.read_batch(
                source_id,
                self.eve_path,
                limit=self.batch_size,
                accept=self._supported,
            )
            if batch.source_missing:
                return {
                    "state": "READY",
                    "sent": 0,
                    "source_missing": True,
                    "filtered": 0,
                }
            if batch.records:
                await self.client.send_suricata(batch.records)
            if batch.checkpoint is not None:
                self.cursor_store.commit(
                    batch.checkpoint,
                    filtered_records=batch.skipped_records,
                )
            return {
                "state": "READY",
                "sent": len(batch.records),
                "source_missing": False,
                "filtered": batch.skipped_records,
            }
        except SensorCollectorError as exc:
            error = str(exc)[:1000]
            self.cursor_store.record_failure(source_id, error)
            return {
                "state": "DEGRADED",
                "sent": 0,
                "source_missing": False,
                "filtered": 0,
                "error": error,
            }


async def run_collector(
    poll: Callable[[], Any],
    *,
    poll_interval_seconds: float,
) -> None:
    if poll_interval_seconds <= 0 or poll_interval_seconds > 3600:
        raise ValueError(
            "poll_interval_seconds must be greater than 0 and at most 3600"
        )
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop_event.set)
        except NotImplementedError:
            pass

    while not stop_event.is_set():
        await poll()
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=poll_interval_seconds,
            )
        except TimeoutError:
            pass


def _collector_client_from_environment() -> tuple[str, SensorBatchClient]:
    tenant_id = os.environ.get("MON_TENANT_ID", "").strip()
    site_id = os.environ.get("MON_SITE_ID", "").strip()
    sensor_id = os.environ.get("MON_SENSOR_ID", "").strip()
    if not tenant_id or not site_id or not sensor_id:
        raise RuntimeError(
            "MON_TENANT_ID, MON_SITE_ID and MON_SENSOR_ID must be configured"
        )
    ingress_url = os.environ.get("MON_SENSOR_INGRESS_URL", "").strip()
    ca_file = os.environ.get("MON_SENSOR_SERVER_CA_CERT_FILE", "").strip()
    cert_file = os.environ.get("MON_SENSOR_CLIENT_CERT_FILE", "").strip()
    key_file = os.environ.get("MON_SENSOR_CLIENT_KEY_FILE", "").strip()
    if not ingress_url or not ca_file or not cert_file or not key_file:
        raise RuntimeError(
            "MON_SENSOR_INGRESS_URL, MON_SENSOR_SERVER_CA_CERT_FILE, "
            "MON_SENSOR_CLIENT_CERT_FILE and MON_SENSOR_CLIENT_KEY_FILE "
            "must be configured"
        )
    for value in (ca_file, cert_file, key_file):
        if not Path(value).is_file():
            raise RuntimeError(
                f"sensor collector certificate file does not exist: {value}"
            )
    try:
        certificate = x509.load_pem_x509_certificate(
            Path(cert_file).read_bytes()
        )
        identity = extract_sensor_identity_from_verified_certificate(
            certificate.public_bytes(serialization.Encoding.DER)
        )
    except (ValueError, OSError) as exc:
        raise RuntimeError(
            "MON_SENSOR_CLIENT_CERT_FILE is not a valid sensor certificate"
        ) from exc
    if (
        identity.tenant_id != tenant_id
        or identity.site_id != site_id
        or identity.sensor_id != sensor_id
    ):
        raise RuntimeError(
            "configured tenant/site/sensor identity does not match "
            "MON_SENSOR_CLIENT_CERT_FILE"
        )

    try:
        timeout = float(os.environ.get("MON_SENSOR_TIMEOUT_SECONDS", "10"))
    except ValueError as exc:
        raise RuntimeError(
            "MON_SENSOR_TIMEOUT_SECONDS must be numeric"
        ) from exc
    context = create_mtls_client_ssl_context(
        ca_file,
        cert_file,
        key_file,
        private_key_password=os.environ.get("MON_SENSOR_CLIENT_KEY_PASSWORD"),
    )
    return sensor_id, SensorBatchClient(
        ingress_url,
        context,
        timeout_seconds=timeout,
    )


def _positive_int_env(name: str, default: str) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < 1 or value > 1000:
        raise RuntimeError(f"{name} must be between 1 and 1000")
    return value


def _positive_float_env(name: str, default: str) -> float:
    try:
        value = float(os.environ.get(name, default))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be numeric") from exc
    if value <= 0 or value > 3600:
        raise RuntimeError(f"{name} must be greater than 0 and at most 3600")
    return value


def zeek_main() -> None:
    sensor_id, client = _collector_client_from_environment()
    log_dir = Path(
        os.environ.get("MON_ZEEK_LOG_DIR", "/opt/zeek/logs/current")
    )
    state_dir = Path(
        os.environ.get("MON_SENSOR_STATE_DIR", "/var/lib/mon-sensor")
    )
    store = SQLiteSensorCursorStore(
        state_dir / "zeek-cursors.db",
        sensor_id=sensor_id,
    )
    collector = ZeekFileCollector(
        log_dir,
        store,
        client,
        batch_size=_positive_int_env("MON_SENSOR_BATCH_SIZE", "100"),
    )
    try:
        asyncio.run(
            run_collector(
                collector.poll_once,
                poll_interval_seconds=_positive_float_env(
                    "MON_SENSOR_POLL_INTERVAL_SECONDS",
                    "1",
                ),
            )
        )
    finally:
        store.close()


def suricata_main() -> None:
    sensor_id, client = _collector_client_from_environment()
    eve_path = Path(
        os.environ.get(
            "MON_SURICATA_EVE_FILE",
            "/var/log/suricata/eve.json",
        )
    )
    state_dir = Path(
        os.environ.get("MON_SENSOR_STATE_DIR", "/var/lib/mon-sensor")
    )
    store = SQLiteSensorCursorStore(
        state_dir / "suricata-cursors.db",
        sensor_id=sensor_id,
    )
    collector = SuricataFileCollector(
        eve_path,
        store,
        client,
        batch_size=_positive_int_env("MON_SENSOR_BATCH_SIZE", "100"),
    )
    try:
        asyncio.run(
            run_collector(
                collector.poll_once,
                poll_interval_seconds=_positive_float_env(
                    "MON_SENSOR_POLL_INTERVAL_SECONDS",
                    "1",
                ),
            )
        )
    finally:
        store.close()
