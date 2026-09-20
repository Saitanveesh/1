from __future__ import annotations

import argparse
import asyncio
import ctypes
import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from xml.etree import ElementTree

import httpx
from pydantic import BaseModel, ConfigDict, Field

from mon.domain import SecurityEvent
from mon.endpoint import (
    EndpointEventKind,
    EndpointTelemetryEvent,
    normalize_endpoint_event,
)

_CHECKPOINT_SCHEMA_VERSION = 1
_BUFFER_SCHEMA_VERSION = "1"
_SUPPORTED_SECURITY_EVENT_IDS = {4624, 4625, 4688}
_SUPPORTED_SYSMON_EVENT_IDS = {1, 3}
_MAX_XML_BYTES = 512_000
_MAX_FIELD_CHARS = 1000
_MIN_SERVICE_POLL_INTERVAL_SECONDS = 0.01
_MAX_SERVICE_POLL_INTERVAL_SECONDS = 3600.0


class WindowsCollectorState(StrEnum):
    DISABLED = "DISABLED"
    SYNCED = "SYNCED"
    BUFFERING = "BUFFERING"
    DEGRADED = "DEGRADED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"


class WindowsCollectorServiceState(StrEnum):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class WindowsEndpointCollectorError(RuntimeError):
    pass


class WindowsEventSourceUnavailable(WindowsEndpointCollectorError):
    pass


class WindowsEventPermissionDenied(WindowsEndpointCollectorError):
    pass


class WindowsCollectorCheckpointError(WindowsEndpointCollectorError):
    pass


class WindowsCollectorServiceError(WindowsEndpointCollectorError):
    pass


class WindowsEventRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    channel: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=256)
    event_id: int = Field(ge=1, le=65535)
    record_id: int = Field(ge=0)
    computer: str | None = Field(default=None, max_length=255)
    observed_at: dt.datetime
    data: dict[str, str] = Field(default_factory=dict)
    raw_xml: str = Field(min_length=1)


class WindowsCollectorHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    state: WindowsCollectorState
    source_available: bool
    permissions_sufficient: bool
    audit_source: str
    buffered_events: int
    last_record_id: int | None = None
    last_error: str | None = None


class WindowsCollectorServiceStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service_state: WindowsCollectorServiceState
    collector_health: WindowsCollectorHealth | None = None
    fatal_error: str | None = None


class WindowsCollectorCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = _CHECKPOINT_SCHEMA_VERSION
    channel: str
    last_record_id: int = Field(ge=0)
    updated_at: dt.datetime


class WindowsEventSource(Protocol):
    def read_after(self, last_record_id: int | None, *, limit: int) -> list[str]: ...


class SecurityEventSender(Protocol):
    async def send(self, event: SecurityEvent) -> None: ...


class CollectorRuntime(Protocol):
    async def collect_once(self) -> WindowsCollectorHealth: ...


class Closable(Protocol):
    def close(self) -> None: ...


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _bounded_text(value: object, limit: int = _MAX_FIELD_CHARS) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(char for char in value.strip() if char.isprintable())
    return cleaned[:limit] if cleaned else None


def _parse_windows_time(value: str | None) -> dt.datetime:
    if not value:
        raise ValueError("Windows event is missing SystemTime")
    normalized = value.replace("Z", "+00:00")
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Windows event timestamp must be timezone-aware")
    return parsed.astimezone(dt.UTC)


def _strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_windows_event_xml(raw_xml: str, *, channel_hint: str | None = None) -> WindowsEventRecord:
    if len(raw_xml.encode("utf-8")) > _MAX_XML_BYTES:
        raise ValueError("Windows event XML exceeds collector bounds")
    root = ElementTree.fromstring(raw_xml)
    system = next((child for child in root if _strip_namespace(child.tag) == "System"), None)
    if system is None:
        raise ValueError("Windows event XML is missing System")

    provider = ""
    event_id: int | None = None
    record_id: int | None = None
    channel = channel_hint or ""
    computer: str | None = None
    observed_at: dt.datetime | None = None
    for child in system:
        name = _strip_namespace(child.tag)
        if name == "Provider":
            provider = _bounded_text(child.attrib.get("Name"), 256) or "unknown"
        elif name == "EventID":
            event_id = int(child.text or "0")
        elif name == "EventRecordID":
            record_id = int(child.text or "0")
        elif name == "Channel":
            channel = _bounded_text(child.text, 128) or channel
        elif name == "Computer":
            computer = _bounded_text(child.text, 255)
        elif name == "TimeCreated":
            observed_at = _parse_windows_time(child.attrib.get("SystemTime"))
    if event_id is None or record_id is None or observed_at is None:
        raise ValueError("Windows event XML is missing required system fields")
    data: dict[str, str] = {}
    for event_data in root.iter():
        if _strip_namespace(event_data.tag) not in {"Data", "EventData"}:
            continue
        if _strip_namespace(event_data.tag) == "Data":
            key = _bounded_text(event_data.attrib.get("Name"), 128)
            value = _bounded_text(event_data.text, _MAX_FIELD_CHARS)
            if key and value is not None:
                data[key] = value
    return WindowsEventRecord(
        channel=channel or "Security",
        provider=provider or "unknown",
        event_id=event_id,
        record_id=record_id,
        computer=computer,
        observed_at=observed_at,
        data=data,
        raw_xml=raw_xml,
    )


def deterministic_event_id(
    *,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    record: WindowsEventRecord,
) -> str:
    material = json.dumps(
        [
            tenant_id,
            site_id,
            sensor_id,
            record.channel,
            record.provider,
            record.event_id,
            record.record_id,
            record.observed_at.isoformat(),
        ],
        separators=(",", ":"),
    )
    return "windows-endpoint:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:48]


def normalize_windows_event(
    record: WindowsEventRecord,
    *,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
) -> EndpointTelemetryEvent | None:
    if tenant_id == "" or site_id == "" or sensor_id == "":
        raise ValueError("tenant_id, site_id, and sensor_id are required")
    source = f"windows-event-log:{record.channel}:{record.provider}:{record.event_id}"
    raw_reference = (
        f"winlog://{record.channel}/{record.provider}/"
        f"{record.event_id}/{record.record_id}"
    )
    data = record.data
    common: dict[str, Any] = {
        "tenant_id": tenant_id,
        "site_id": site_id,
        "sensor_id": sensor_id,
        "event_id": deterministic_event_id(
            tenant_id=tenant_id,
            site_id=site_id,
            sensor_id=sensor_id,
            record=record,
        ),
        "observed_at": record.observed_at,
        "asset_id": f"windows-host:{record.computer.casefold()}" if record.computer else None,
        "hostname": record.computer,
        "source": source,
        "raw_reference": raw_reference,
        "attributes": {
            "windows_event_id": record.event_id,
            "windows_channel": record.channel,
            "windows_provider": record.provider,
            "windows_record_id": record.record_id,
        },
    }
    if record.channel.casefold() == "security" and record.event_id in {4624, 4625}:
        return EndpointTelemetryEvent(
            **common,
            kind=(
                EndpointEventKind.AUTH_SUCCESS
                if record.event_id == 4624
                else EndpointEventKind.AUTH_FAILURE
            ),
            user_name=data.get("TargetUserName"),
            user_domain=data.get("TargetDomainName"),
            user_sid=data.get("TargetUserSid"),
            session_id=data.get("TargetLogonId"),
            src_ip=data.get("IpAddress"),
            outcome="success" if record.event_id == 4624 else "failure",
        )
    if record.channel.casefold() == "security" and record.event_id == 4688:
        return EndpointTelemetryEvent(
            **common,
            kind=EndpointEventKind.PROCESS_START,
            user_name=data.get("SubjectUserName"),
            user_domain=data.get("SubjectDomainName"),
            user_sid=data.get("SubjectUserSid"),
            session_id=data.get("SubjectLogonId"),
            process_pid=_hex_or_int(data.get("NewProcessId")),
            parent_process_pid=_hex_or_int(data.get("CreatorProcessId")),
            image=data.get("NewProcessName"),
            command_line=data.get("CommandLine"),
        )
    if record.provider == "Microsoft-Windows-Sysmon" and record.event_id == 1:
        return EndpointTelemetryEvent(
            **common,
            kind=EndpointEventKind.PROCESS_START,
            user_name=data.get("User"),
            process_guid=data.get("ProcessGuid"),
            process_pid=_hex_or_int(data.get("ProcessId")),
            parent_process_guid=data.get("ParentProcessGuid"),
            parent_process_pid=_hex_or_int(data.get("ParentProcessId")),
            image=data.get("Image"),
            command_line=data.get("CommandLine"),
            process_hashes=_parse_hashes(data.get("Hashes")),
        )
    if record.provider == "Microsoft-Windows-Sysmon" and record.event_id == 3:
        return EndpointTelemetryEvent(
            **common,
            kind=EndpointEventKind.NETWORK_CONNECTION,
            user_name=data.get("User"),
            process_guid=data.get("ProcessGuid"),
            process_pid=_hex_or_int(data.get("ProcessId")),
            image=data.get("Image"),
            src_ip=data.get("SourceIp"),
            dst_ip=data.get("DestinationIp"),
            protocol=data.get("Protocol") or "tcp",
            dst_port=_hex_or_int(data.get("DestinationPort")),
        )
    return None


def _hex_or_int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _parse_hashes(value: str | None) -> dict[str, str]:
    hashes: dict[str, str] = {}
    if not value:
        return hashes
    for item in value.split(","):
        if "=" not in item:
            continue
        key, raw = item.split("=", 1)
        key = key.strip().casefold()
        raw = raw.strip()
        if key in {"md5", "sha1", "sha256", "sha512"} and raw:
            hashes[key] = raw[:256]
    return hashes


class WindowsEventCheckpointStore:
    def __init__(self, path: Path, *, channel: str) -> None:
        self.path = path
        self.channel = channel
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> WindowsCollectorCheckpoint | None:
        if not self.path.exists():
            return None
        try:
            checkpoint = WindowsCollectorCheckpoint.model_validate_json(
                self.path.read_text(encoding="utf-8")
            )
        except ValueError as exc:
            raise WindowsCollectorCheckpointError(
                "Windows collector checkpoint is corrupt"
            ) from exc
        if checkpoint.schema_version != _CHECKPOINT_SCHEMA_VERSION:
            raise WindowsCollectorCheckpointError(
                "Windows collector checkpoint schema is incompatible"
            )
        if checkpoint.channel != self.channel:
            raise WindowsCollectorCheckpointError(
                "Windows collector checkpoint channel mismatch"
            )
        return checkpoint

    def save(self, *, last_record_id: int, now: dt.datetime | None = None) -> None:
        updated_at = now or _utc_now()
        if updated_at.tzinfo is None or updated_at.utcoffset() is None:
            raise ValueError("checkpoint timestamp must be timezone-aware")
        checkpoint = WindowsCollectorCheckpoint(
            channel=self.channel,
            last_record_id=last_record_id,
            updated_at=updated_at.astimezone(dt.UTC),
        )
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.path.parent,
            delete=False,
        ) as handle:
            handle.write(checkpoint.model_dump_json())
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        os.replace(temp_path, self.path)


class SQLiteWindowsEventBuffer:
    def __init__(
        self,
        path: Path,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        max_events: int = 10_000,
    ) -> None:
        if max_events < 1 or max_events > 1_000_000:
            raise ValueError("max_events must be between 1 and 1000000")
        self.path = path
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.sensor_id = sensor_id
        self.max_events = max_events
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path)
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_events(
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            self._bind("schema_version", _BUFFER_SCHEMA_VERSION)
            self._bind("tenant_id", tenant_id)
            self._bind("site_id", site_id)
            self._bind("sensor_id", sensor_id)

    def _bind(self, key: str, expected: str) -> None:
        row = self._connection.execute(
            "SELECT value FROM metadata WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                (key, expected),
            )
            return
        if str(row["value"]) != expected:
            raise ValueError(f"Windows collector buffer {key} mismatch")

    def close(self) -> None:
        self._connection.close()

    def count(self) -> int:
        row = self._connection.execute(
            "SELECT COUNT(*) AS count FROM pending_events"
        ).fetchone()
        return int(row["count"]) if row else 0

    def enqueue(self, event: SecurityEvent) -> bool:
        if (
            event.tenant_id != self.tenant_id
            or event.site_id != self.site_id
            or event.sensor_id != self.sensor_id
        ):
            raise ValueError("Windows collector event scope does not match buffer")
        if self.count() >= self.max_events and not self.has_event(event.event_id):
            raise WindowsEndpointCollectorError("Windows collector buffer is full")
        with self._connection:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO pending_events(event_id, payload, created_at)
                VALUES (?, ?, ?)
                """,
                (event.event_id, event.model_dump_json(), _utc_now().isoformat()),
            )
        return cursor.rowcount == 1

    def has_event(self, event_id: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM pending_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        return row is not None

    def pending(self, limit: int) -> list[SecurityEvent]:
        rows = self._connection.execute(
            """
            SELECT payload
            FROM pending_events
            ORDER BY created_at ASC, event_id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [SecurityEvent.model_validate_json(row["payload"]) for row in rows]

    def mark_sent(self, event_id: str) -> None:
        with self._connection:
            self._connection.execute(
                "DELETE FROM pending_events WHERE event_id = ?",
                (event_id,),
            )


class LocalSiteEventSender:
    def __init__(self, base_url: str, *, timeout_seconds: float = 5.0) -> None:
        if not base_url.startswith(("http://127.0.0.1", "http://localhost")):
            raise ValueError("Windows collector local transport must be loopback")
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def send(self, event: SecurityEvent) -> None:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            trust_env=False,
        ) as client:
            response = await client.post(
                "/api/v1/site/events",
                content=event.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()


class WindowsEndpointCollector:
    def __init__(
        self,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        channel: str,
        source: WindowsEventSource,
        checkpoint_store: WindowsEventCheckpointStore,
        buffer: SQLiteWindowsEventBuffer,
        sender: SecurityEventSender,
        batch_size: int = 100,
    ) -> None:
        if batch_size < 1 or batch_size > 1000:
            raise ValueError("batch_size must be between 1 and 1000")
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.sensor_id = sensor_id
        self.channel = channel
        self.source = source
        self.checkpoint_store = checkpoint_store
        self.buffer = buffer
        self.sender = sender
        self.batch_size = batch_size
        self._last_error: str | None = None
        self._source_available = True
        self._permissions_sufficient = True

    async def collect_once(self) -> WindowsCollectorHealth:
        checkpoint = self.checkpoint_store.load()
        last_record_id = checkpoint.last_record_id if checkpoint else None
        max_record_id = last_record_id or 0
        try:
            records = self.source.read_after(last_record_id, limit=self.batch_size)
        except WindowsEventPermissionDenied as exc:
            self._source_available = True
            self._permissions_sufficient = False
            self._last_error = str(exc)[:1000]
            return self.health(state=WindowsCollectorState.PERMISSION_DENIED)
        except WindowsEventSourceUnavailable as exc:
            self._source_available = False
            self._permissions_sufficient = False
            self._last_error = str(exc)[:1000]
            return self.health(state=WindowsCollectorState.SOURCE_UNAVAILABLE)

        for raw in records:
            record = parse_windows_event_xml(raw, channel_hint=self.channel)
            max_record_id = max(max_record_id, record.record_id)
            if not _supported(record):
                continue
            endpoint = normalize_windows_event(
                record,
                tenant_id=self.tenant_id,
                site_id=self.site_id,
                sensor_id=self.sensor_id,
            )
            if endpoint is None:
                continue
            self.buffer.enqueue(normalize_endpoint_event(endpoint))
        if max_record_id > (last_record_id or 0):
            self.checkpoint_store.save(last_record_id=max_record_id)
        return await self.flush_buffer()

    async def flush_buffer(self) -> WindowsCollectorHealth:
        for event in self.buffer.pending(self.batch_size):
            try:
                await self.sender.send(event)
            except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
                self._last_error = str(exc)[:1000]
                return self.health(state=WindowsCollectorState.TRANSPORT_UNAVAILABLE)
            self.buffer.mark_sent(event.event_id)
        state = (
            WindowsCollectorState.SYNCED
            if self.buffer.count() == 0
            else WindowsCollectorState.BUFFERING
        )
        self._last_error = None if state is WindowsCollectorState.SYNCED else self._last_error
        return self.health(state=state)

    def health(self, *, state: WindowsCollectorState | None = None) -> WindowsCollectorHealth:
        checkpoint = None
        try:
            checkpoint = self.checkpoint_store.load()
        except WindowsCollectorCheckpointError as exc:
            return WindowsCollectorHealth(
                state=WindowsCollectorState.DEGRADED,
                source_available=self._source_available,
                permissions_sufficient=self._permissions_sufficient,
                audit_source=self.channel,
                buffered_events=self.buffer.count(),
                last_error=str(exc)[:1000],
            )
        return WindowsCollectorHealth(
            state=state or WindowsCollectorState.SYNCED,
            source_available=self._source_available,
            permissions_sufficient=self._permissions_sufficient,
            audit_source=self.channel,
            buffered_events=self.buffer.count(),
            last_record_id=checkpoint.last_record_id if checkpoint else None,
            last_error=self._last_error,
        )


def _supported(record: WindowsEventRecord) -> bool:
    if record.channel.casefold() == "security":
        return record.event_id in _SUPPORTED_SECURITY_EVENT_IDS
    if record.provider == "Microsoft-Windows-Sysmon":
        return record.event_id in _SUPPORTED_SYSMON_EVENT_IDS
    return False


def validate_service_poll_interval(value: float) -> float:
    if (
        value < _MIN_SERVICE_POLL_INTERVAL_SECONDS
        or value > _MAX_SERVICE_POLL_INTERVAL_SECONDS
    ):
        raise ValueError("poll interval must be between 0.01 and 3600 seconds")
    return value


class WindowsCollectorServiceRuntime:
    def __init__(
        self,
        *,
        collector: CollectorRuntime,
        poll_interval_seconds: float,
        resources: Iterable[Closable] = (),
    ) -> None:
        self.collector = collector
        self.poll_interval_seconds = validate_service_poll_interval(
            poll_interval_seconds
        )
        self.resources = tuple(resources)
        self._stop_event = asyncio.Event()
        self.status = WindowsCollectorServiceStatus(
            service_state=WindowsCollectorServiceState.STARTING
        )

    def request_stop(self) -> None:
        if self.status.service_state not in {
            WindowsCollectorServiceState.STOPPED,
            WindowsCollectorServiceState.FAILED,
        }:
            self.status = WindowsCollectorServiceStatus(
                service_state=WindowsCollectorServiceState.STOPPING,
                collector_health=self.status.collector_health,
                fatal_error=self.status.fatal_error,
            )
        self._stop_event.set()

    async def run_forever(self) -> WindowsCollectorServiceStatus:
        try:
            health = await self.collector.collect_once()
            self.status = WindowsCollectorServiceStatus(
                service_state=WindowsCollectorServiceState.RUNNING,
                collector_health=health,
            )
            while not self._stop_event.is_set():
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=self.poll_interval_seconds,
                    )
                    break
                except TimeoutError:
                    pass
                health = await self.collector.collect_once()
                self.status = WindowsCollectorServiceStatus(
                    service_state=WindowsCollectorServiceState.RUNNING,
                    collector_health=health,
                )
            if self.status.service_state is not WindowsCollectorServiceState.FAILED:
                self.status = WindowsCollectorServiceStatus(
                    service_state=WindowsCollectorServiceState.STOPPED,
                    collector_health=self.status.collector_health,
                )
            return self.status
        except WindowsCollectorCheckpointError as exc:
            self.status = WindowsCollectorServiceStatus(
                service_state=WindowsCollectorServiceState.FAILED,
                collector_health=self.status.collector_health,
                fatal_error=str(exc)[:1000],
            )
            raise
        finally:
            for resource in reversed(self.resources):
                resource.close()


class NativeWindowsServiceControlBoundary:
    """Thin native SCM boundary without installer/registration behavior."""

    can_accept_stop = 0x00000001
    can_accept_shutdown = 0x00000004

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise WindowsCollectorServiceError(
                "Windows Service Control Manager integration requires Windows"
            )
        self._advapi32 = ctypes.WinDLL("advapi32.dll")


class WindowsEventLogSource:
    """Minimal Windows Event Log source.

    The parser and buffering tests are portable. This source is imported on all
    platforms but can only run on Windows with access to wevtapi.dll.
    """

    def __init__(self, channel: str) -> None:
        self.channel = channel
        if sys.platform != "win32":
            raise WindowsEventSourceUnavailable("Windows Event Log requires Windows")
        self._wevtapi = ctypes.WinDLL("wevtapi.dll")
        self._kernel32 = ctypes.WinDLL("kernel32.dll")

    def read_after(self, last_record_id: int | None, *, limit: int) -> list[str]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        query = "*"
        if last_record_id is not None:
            query = f"*[System[EventRecordID>{last_record_id}]]"
        handle = self._wevtapi.EvtQuery(0, self.channel, query, 1)
        if not handle:
            raise self._error("Windows Event Log query failed")
        try:
            return self._next_xml(handle, limit=limit)
        finally:
            self._wevtapi.EvtClose(handle)

    def _next_xml(self, query_handle: int, *, limit: int) -> list[str]:
        results: list[str] = []
        handles = (ctypes.c_void_p * limit)()
        returned = ctypes.c_ulong(0)
        ok = self._wevtapi.EvtNext(query_handle, limit, handles, 0, 0, ctypes.byref(returned))
        if not ok:
            error = self._kernel32.GetLastError()
            if error == 259:
                return []
            raise self._error("Windows Event Log read failed")
        for index in range(returned.value):
            results.append(self._render_xml(handles[index]))
            self._wevtapi.EvtClose(handles[index])
        return results

    def _render_xml(self, event_handle: int) -> str:
        buffer_used = ctypes.c_ulong(0)
        property_count = ctypes.c_ulong(0)
        self._wevtapi.EvtRender(
            0,
            event_handle,
            1,
            0,
            None,
            ctypes.byref(buffer_used),
            ctypes.byref(property_count),
        )
        if buffer_used.value > _MAX_XML_BYTES:
            raise ValueError("Windows event XML exceeds collector bounds")
        buffer = ctypes.create_unicode_buffer(buffer_used.value // ctypes.sizeof(ctypes.c_wchar))
        ok = self._wevtapi.EvtRender(
            0,
            event_handle,
            1,
            buffer_used,
            buffer,
            ctypes.byref(buffer_used),
            ctypes.byref(property_count),
        )
        if not ok:
            raise self._error("Windows Event Log render failed")
        return buffer.value

    def _error(self, message: str) -> WindowsEndpointCollectorError:
        code = int(self._kernel32.GetLastError())
        if code in {5, 1314}:
            return WindowsEventPermissionDenied(message)
        return WindowsEventSourceUnavailable(f"{message}: win32={code}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect Windows endpoint telemetry for MON")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("foreground", "service-run"),
        help="run continuously instead of performing one collection pass",
    )
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--site-url", default="http://127.0.0.1:8090")
    parser.add_argument("--channel", default="Security")
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--poll-interval-seconds", type=float, default=30.0)
    return parser


def build_collector_from_args(
    args: argparse.Namespace,
) -> tuple[WindowsEndpointCollector, tuple[Closable, ...]]:
    source = WindowsEventLogSource(args.channel)
    checkpoint = WindowsEventCheckpointStore(
        args.state_dir / f"{args.channel.casefold()}-checkpoint.json",
        channel=args.channel,
    )
    buffer = SQLiteWindowsEventBuffer(
        args.state_dir / "windows-endpoint-buffer.db",
        tenant_id=args.tenant_id,
        site_id=args.site_id,
        sensor_id=args.sensor_id,
    )
    collector = WindowsEndpointCollector(
        tenant_id=args.tenant_id,
        site_id=args.site_id,
        sensor_id=args.sensor_id,
        channel=args.channel,
        source=source,
        checkpoint_store=checkpoint,
        buffer=buffer,
        sender=LocalSiteEventSender(args.site_url),
        batch_size=args.batch_size,
    )
    return collector, (buffer,)


async def async_main(argv: Iterable[str] | None = None) -> int:
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    collector, resources = build_collector_from_args(args)
    if args.command in {"foreground", "service-run"}:
        runtime = WindowsCollectorServiceRuntime(
            collector=collector,
            poll_interval_seconds=args.poll_interval_seconds,
            resources=resources,
        )
        status = await runtime.run_forever()
        print(status.model_dump_json())
        return 0 if status.service_state is WindowsCollectorServiceState.STOPPED else 2

    buffer = resources[0]
    try:
        health = await collector.collect_once()
        print(health.model_dump_json())
        return 0 if health.state is WindowsCollectorState.SYNCED else 2
    finally:
        buffer.close()


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
