from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import logging
import os
import signal
import sqlite3
import ssl
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from mon import __version__
from mon.sensor_credentials import (
    SensorCredentialError,
    SensorCredentialStore,
    SensorCredentialTransportError,
    rotate_sensor_credentials_if_due,
)
from mon.sensor_fleet_models import SensorFleetState, SensorRenewalResult
from mon.site_identity import create_mtls_client_ssl_context

_SUPPORTED_ZEEK_LOGS = ("conn", "dns", "http", "ssl", "notice", "weird")
_SUPPORTED_SURICATA_TYPES = {"alert", "flow", "dns", "http", "tls"}


class SensorCollectorError(RuntimeError):
    pass


class SensorRotationGapError(SensorCollectorError):
    pass


class SensorRecordError(SensorCollectorError):
    pass


class SensorDeliveryError(
    SensorCollectorError,
    SensorCredentialTransportError,
):
    pass


@dataclass(frozen=True, slots=True)
class SensorCursor:
    source_id: str
    configured_path: str
    device: int
    inode: int
    offset: int
    anchor_sha256: str
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
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if not tenant_id or not site_id or not sensor_id:
            raise ValueError("tenant_id, site_id and sensor_id are required")
        if busy_timeout_seconds <= 0 or busy_timeout_seconds > 60:
            raise ValueError("busy_timeout_seconds must be between 0 and 60")

        self.path = Path(path)
        self.tenant_id = tenant_id
        self.site_id = site_id
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
                        anchor_sha256 TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_error TEXT,
                        failures INTEGER NOT NULL DEFAULT 0,
                        filtered_records INTEGER NOT NULL DEFAULT 0
                    )
                    """
                )
                self._bind_metadata("schema_version", self._SCHEMA_VERSION)
                self._bind_metadata("tenant_id", tenant_id)
                self._bind_metadata("site_id", site_id)
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
                SELECT source_id, configured_path, device, inode, offset,
                       anchor_sha256, updated_at
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
            anchor_sha256=str(row["anchor_sha256"]),
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
                    anchor_sha256, updated_at, last_error, failures,
                    filtered_records
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    configured_path = excluded.configured_path,
                    device = excluded.device,
                    inode = excluded.inode,
                    offset = excluded.offset,
                    anchor_sha256 = excluded.anchor_sha256,
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
                    cursor.anchor_sha256,
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
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
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

    _ANCHOR_BYTES = 256

    def __init__(self, cursor_store: SQLiteSensorCursorStore) -> None:
        self.cursor_store = cursor_store

    @classmethod
    def _anchor_hash(cls, path: Path, offset: int) -> str:
        if offset < 0:
            raise ValueError("sensor cursor offset cannot be negative")
        length = min(cls._ANCHOR_BYTES, offset)
        start = offset - length
        with path.open("rb") as handle:
            handle.seek(start)
            data = handle.read(length)
        if len(data) != length:
            raise SensorRotationGapError(
                "source file is shorter than the committed checkpoint anchor"
            )
        return hashlib.sha256(data).hexdigest()

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
            with suppress(OSError):
                candidates.extend(
                    item
                    for item in parent.iterdir()
                    if item != configured_path and item.is_file()
                )

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
        if self._anchor_hash(candidate, cursor.offset) != cursor.anchor_sha256:
            raise SensorRotationGapError(
                f"source {source_id} prior inode content no longer matches "
                "the committed checkpoint; inode reuse or rewrite is possible"
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
            anchor_sha256=self._anchor_hash(
                actual_path,
                checkpoint_offset,
            ),
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
                    anchor_sha256=hashlib.sha256(b"").hexdigest(),
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
        credential_fingerprint_sha256: str | None = None,
    ) -> None:
        if not base_url.lower().startswith("https://"):
            raise ValueError("sensor ingress URL must use https")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("timeout_seconds must be greater than 0 and at most 60")
        self.base_url = base_url.rstrip("/")
        self.ssl_context = ssl_context
        self.timeout_seconds = timeout_seconds
        self._credential_fingerprint_sha256 = credential_fingerprint_sha256
        self._client = self._new_client(self.ssl_context)

    def _new_client(self, ssl_context: ssl.SSLContext) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            verify=ssl_context,
            timeout=self.timeout_seconds,
            trust_env=False,
        )

    @property
    def credential_fingerprint_sha256(self) -> str | None:
        return self._credential_fingerprint_sha256

    async def close(self) -> None:
        await self._client.aclose()

    async def _post(self, path: str, payload: dict[str, object]) -> None:
        try:
            response = await self._client.post(path, json=payload)
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

    async def send_heartbeat(
        self,
        *,
        state: SensorFleetState,
        collector_kind: str,
        last_error: str | None,
    ) -> None:
        await self._post(
            "/api/v1/sensors/heartbeat",
            {
                "observed_at": dt.datetime.now(dt.UTC).isoformat(),
                "state": state.value,
                "collector_kind": collector_kind,
                "version": __version__,
                "last_error": last_error,
            },
        )

    async def renew_certificate(
        self,
        csr_pem: str,
    ) -> SensorRenewalResult:
        try:
            response = await self._client.post(
                "/api/v1/sensors/renew",
                json={"csr_pem": csr_pem},
            )
        except httpx.HTTPError as exc:
            raise SensorDeliveryError(
                "sensor credential renewal endpoint is unavailable"
            ) from exc
        if response.status_code < 200 or response.status_code >= 300:
            detail = response.text.strip()[:500]
            raise SensorDeliveryError(
                "sensor credential renewal was rejected with HTTP "
                f"{response.status_code}: {detail}"
            )
        try:
            return SensorRenewalResult.model_validate(response.json())
        except ValueError as exc:
            raise SensorDeliveryError(
                "sensor credential renewal returned invalid data"
            ) from exc

    async def probe_ssl_context(
        self,
        ssl_context: ssl.SSLContext,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
    ) -> None:
        async with self._new_client(ssl_context) as candidate:
            try:
                response = await candidate.get("/health")
            except httpx.HTTPError as exc:
                raise SensorDeliveryError(
                    "renewed sensor credential probe failed"
                ) from exc
        if response.status_code != 200:
            detail = response.text.strip()[:500]
            raise SensorDeliveryError(
                "renewed sensor credential was not accepted by ingress: "
                f"HTTP {response.status_code}: {detail}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise SensorDeliveryError(
                "sensor ingress health returned invalid JSON"
            ) from exc
        if (
            payload.get("tenant_id") != tenant_id
            or payload.get("site_id") != site_id
            or payload.get("sensor_id") != sensor_id
        ):
            raise SensorDeliveryError(
                "renewed sensor credential probe returned the wrong identity"
            )

    async def replace_ssl_context(
        self,
        ssl_context: ssl.SSLContext,
        *,
        fingerprint_sha256: str,
    ) -> None:
        replacement = self._new_client(ssl_context)
        previous = self._client
        self._client = replacement
        self.ssl_context = ssl_context
        self._credential_fingerprint_sha256 = fingerprint_sha256
        await previous.aclose()


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
        required_missing = False
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
                    if log_type == "conn":
                        required_missing = True
                    continue
                if batch.records:
                    await self.client.send_zeek(log_type, batch.records)
                    sent += len(batch.records)
                if batch.checkpoint is not None:
                    self.cursor_store.commit(
                        batch.checkpoint,
                        filtered_records=batch.skipped_records,
                    )
            except (SensorCollectorError, OSError) as exc:
                error = str(exc)[:1000]
                self.cursor_store.record_failure(source_id, error)
                errors[source_id] = error
        return {
            "state": (
                "READY"
                if not errors and not required_missing
                else "DEGRADED"
            ),
            "sent": sent,
            "missing_sources": missing,
            "required_source_missing": required_missing,
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
                    "state": "DEGRADED",
                    "sent": 0,
                    "source_missing": True,
                    "filtered": 0,
                    "error": "Suricata EVE source file is missing",
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
        except (SensorCollectorError, OSError) as exc:
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
        with suppress(NotImplementedError):
            loop.add_signal_handler(signum, stop_event.set)

    logger = logging.getLogger("mon.sensor_collector")
    last_state: str | None = None
    last_log_at = 0.0
    while not stop_event.is_set():
        result = await poll()
        state = str(result.get("state", "UNKNOWN"))
        now = loop.time()
        should_log = state != last_state
        if state == "DEGRADED" and now - last_log_at >= 60:
            should_log = True
        if should_log:
            logger.info(
                "sensor collector state=%s result=%s",
                state,
                json.dumps(result, sort_keys=True, default=str),
            )
            last_log_at = now
        last_state = state
        with suppress(TimeoutError):
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=poll_interval_seconds,
            )


def _collector_client_from_environment() -> tuple[
    str,
    str,
    str,
    SensorBatchClient,
    SensorCredentialStore,
]:
    tenant_id = os.environ.get("MON_TENANT_ID", "").strip()
    site_id = os.environ.get("MON_SITE_ID", "").strip()
    sensor_id = os.environ.get("MON_SENSOR_ID", "").strip()
    if not tenant_id or not site_id or not sensor_id:
        raise RuntimeError(
            "MON_TENANT_ID, MON_SITE_ID and MON_SENSOR_ID must be configured"
        )
    ingress_url = os.environ.get("MON_SENSOR_INGRESS_URL", "").strip()
    ca_file = os.environ.get("MON_SENSOR_SERVER_CA_CERT_FILE", "").strip()
    cert_file = (
        os.environ.get("MON_SENSOR_CLIENT_CERT_FILE", "").strip() or None
    )
    key_file = (
        os.environ.get("MON_SENSOR_CLIENT_KEY_FILE", "").strip() or None
    )
    if not ingress_url or not ca_file:
        raise RuntimeError(
            "MON_SENSOR_INGRESS_URL and MON_SENSOR_SERVER_CA_CERT_FILE "
            "must be configured"
        )
    if not Path(ca_file).is_file():
        raise RuntimeError(
            "sensor ingress server CA certificate file does not exist: "
            f"{ca_file}"
        )

    try:
        timeout = float(os.environ.get("MON_SENSOR_TIMEOUT_SECONDS", "10"))
    except ValueError as exc:
        raise RuntimeError(
            "MON_SENSOR_TIMEOUT_SECONDS must be numeric"
        ) from exc
    state_dir = Path(
        os.environ.get("MON_SENSOR_STATE_DIR", "/var/lib/mon-sensor")
    )
    scope_digest = hashlib.sha256(
        f"{tenant_id}\x1f{site_id}\x1f{sensor_id}".encode()
    ).hexdigest()[:24]
    private_key_password = os.environ.get("MON_SENSOR_CLIENT_KEY_PASSWORD")
    credential_store = SensorCredentialStore(
        state_dir / "credentials" / scope_digest,
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=sensor_id,
        server_ca_certificate_file=ca_file,
        bootstrap_certificate_file=cert_file,
        bootstrap_private_key_file=key_file,
        private_key_password=private_key_password,
    )
    active = credential_store.active_generation()
    context = create_mtls_client_ssl_context(
        ca_file,
        str(active.certificate_file),
        str(active.private_key_file),
        private_key_password=private_key_password,
    )
    client = SensorBatchClient(
        ingress_url,
        context,
        timeout_seconds=timeout,
        credential_fingerprint_sha256=active.fingerprint_sha256,
    )
    return tenant_id, site_id, sensor_id, client, credential_store


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


def _bounded_float_env(
    name: str,
    default: str,
    *,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(os.environ.get(name, default))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be numeric") from exc
    if value < minimum or value > maximum:
        raise RuntimeError(
            f"{name} must be between {minimum:g} and {maximum:g}"
        )
    return value


async def _run_collector_process(
    poll: Callable[[], Any],
    client: SensorBatchClient,
    *,
    credential_store: SensorCredentialStore,
    collector_kind: str,
    poll_interval_seconds: float,
    heartbeat_interval_seconds: float,
    renewal_check_interval_seconds: float,
    renew_before_seconds: float,
) -> None:
    if heartbeat_interval_seconds <= 0 or heartbeat_interval_seconds > 3600:
        raise ValueError(
            "heartbeat_interval_seconds must be greater than 0 and at most 3600"
        )
    if (
        renewal_check_interval_seconds <= 0
        or renewal_check_interval_seconds > 3600
    ):
        raise ValueError(
            "renewal_check_interval_seconds must be greater than 0 and at most 3600"
        )
    if renew_before_seconds < 60 or renew_before_seconds > 7_776_000:
        raise ValueError(
            "renew_before_seconds must be between 60 and 7776000"
        )
    loop = asyncio.get_running_loop()
    next_heartbeat_at = 0.0
    next_renewal_check_at = 0.0
    logger = logging.getLogger("mon.sensor_collector")

    async def managed_poll() -> dict[str, object]:
        nonlocal next_heartbeat_at, next_renewal_check_at
        result = await poll()
        now = loop.time()
        if now >= next_renewal_check_at:
            try:
                rotation = await rotate_sensor_credentials_if_due(
                    credential_store,
                    client,
                    renew_before=dt.timedelta(
                        seconds=renew_before_seconds
                    ),
                )
                if rotation["state"] == "ROTATED":
                    result["credential_rotation"] = rotation
                next_renewal_check_at = now + renewal_check_interval_seconds
            except (
                SensorCredentialError,
                SensorCredentialTransportError,
                OSError,
                ssl.SSLError,
            ) as exc:
                error = str(exc)[:1000]
                result["state"] = "DEGRADED"
                result["credential_rotation_error"] = error
                logger.warning(
                    "sensor credential rotation failed: %s",
                    error,
                )
                next_renewal_check_at = now + min(
                    60.0,
                    renewal_check_interval_seconds,
                )
        if now >= next_heartbeat_at:
            state = (
                SensorFleetState.READY
                if str(result.get("state")) == "READY"
                else SensorFleetState.DEGRADED
            )
            error: str | None = None
            raw_error = result.get("error")
            if raw_error is None:
                raw_error = result.get("credential_rotation_error")
            if raw_error is not None:
                error = str(raw_error)[:1000]
            elif state is SensorFleetState.DEGRADED:
                raw_errors = result.get("errors")
                if raw_errors:
                    error = json.dumps(
                        raw_errors,
                        sort_keys=True,
                        default=str,
                    )[:1000]
                else:
                    error = "collector reported degraded state"
            try:
                await client.send_heartbeat(
                    state=state,
                    collector_kind=collector_kind,
                    last_error=error,
                )
            except SensorDeliveryError as exc:
                logger.warning(
                    "sensor fleet heartbeat delivery failed: %s",
                    str(exc)[:1000],
                )
            next_heartbeat_at = now + heartbeat_interval_seconds
        return result

    try:
        await run_collector(
            managed_poll,
            poll_interval_seconds=poll_interval_seconds,
        )
    finally:
        await client.close()


def zeek_main() -> None:
    logging.basicConfig(level=logging.INFO)
    (
        tenant_id,
        site_id,
        sensor_id,
        client,
        credential_store,
    ) = _collector_client_from_environment()
    log_dir = Path(
        os.environ.get("MON_ZEEK_LOG_DIR", "/opt/zeek/logs/current")
    )
    state_dir = Path(
        os.environ.get("MON_SENSOR_STATE_DIR", "/var/lib/mon-sensor")
    )
    store = SQLiteSensorCursorStore(
        state_dir / "zeek-cursors.db",
        tenant_id=tenant_id,
        site_id=site_id,
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
            _run_collector_process(
                collector.poll_once,
                client,
                credential_store=credential_store,
                collector_kind="ZEEK",
                poll_interval_seconds=_positive_float_env(
                    "MON_SENSOR_POLL_INTERVAL_SECONDS",
                    "1",
                ),
                heartbeat_interval_seconds=_positive_float_env(
                    "MON_SENSOR_HEARTBEAT_INTERVAL_SECONDS",
                    "30",
                ),
                renewal_check_interval_seconds=_positive_float_env(
                    "MON_SENSOR_RENEW_CHECK_INTERVAL_SECONDS",
                    "300",
                ),
                renew_before_seconds=_bounded_float_env(
                    "MON_SENSOR_RENEW_BEFORE_SECONDS",
                    "604800",
                    minimum=60,
                    maximum=7_776_000,
                ),
            )
        )
    finally:
        store.close()


def suricata_main() -> None:
    logging.basicConfig(level=logging.INFO)
    (
        tenant_id,
        site_id,
        sensor_id,
        client,
        credential_store,
    ) = _collector_client_from_environment()
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
        tenant_id=tenant_id,
        site_id=site_id,
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
            _run_collector_process(
                collector.poll_once,
                client,
                credential_store=credential_store,
                collector_kind="SURICATA",
                poll_interval_seconds=_positive_float_env(
                    "MON_SENSOR_POLL_INTERVAL_SECONDS",
                    "1",
                ),
                heartbeat_interval_seconds=_positive_float_env(
                    "MON_SENSOR_HEARTBEAT_INTERVAL_SECONDS",
                    "30",
                ),
                renewal_check_interval_seconds=_positive_float_env(
                    "MON_SENSOR_RENEW_CHECK_INTERVAL_SECONDS",
                    "300",
                ),
                renew_before_seconds=_bounded_float_env(
                    "MON_SENSOR_RENEW_BEFORE_SECONDS",
                    "604800",
                    minimum=60,
                    maximum=7_776_000,
                ),
            )
        )
    finally:
        store.close()
