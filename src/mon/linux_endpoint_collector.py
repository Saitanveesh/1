from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
import re
import signal
import socket
import sqlite3
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field

from mon.domain import SecurityEvent
from mon.endpoint import EndpointEventKind, EndpointTelemetryEvent, normalize_endpoint_event

_CHECKPOINT_SCHEMA_VERSION = 1
_BUFFER_SCHEMA_VERSION = "1"
_MAX_JOURNAL_ENTRY_BYTES = 32_000
_MAX_JOURNAL_MESSAGE_CHARS = 2000
_MAX_AUDIT_LINE_BYTES = 16_000
_MAX_AUDIT_READ_BYTES = 2_000_000
_MAX_FIELD_CHARS = 1000
_AUDIT_UNSET_UID = 4_294_967_295
_MIN_POLL_INTERVAL_SECONDS = 0.01
_MAX_POLL_INTERVAL_SECONDS = 3600.0


class LinuxEndpointCollectorError(RuntimeError):
    pass


class LinuxSourceUnavailable(LinuxEndpointCollectorError):
    pass


class LinuxSourcePermissionDenied(LinuxEndpointCollectorError):
    pass


class LinuxCollectorCheckpointError(LinuxEndpointCollectorError):
    pass


class LinuxSourceKind(StrEnum):
    JOURNAL = "JOURNAL"
    AUDIT = "AUDIT"


class LinuxCollectorState(StrEnum):
    SYNCED = "SYNCED"
    BUFFERING = "BUFFERING"
    DEGRADED = "DEGRADED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"


_STATE_SEVERITY: dict[LinuxCollectorState, int] = {
    LinuxCollectorState.SYNCED: 0,
    LinuxCollectorState.BUFFERING: 1,
    LinuxCollectorState.DEGRADED: 2,
    LinuxCollectorState.TRANSPORT_UNAVAILABLE: 3,
    LinuxCollectorState.SOURCE_UNAVAILABLE: 4,
    LinuxCollectorState.PERMISSION_DENIED: 5,
}


def worst_state(states: Iterable[LinuxCollectorState]) -> LinuxCollectorState:
    ranked = sorted(states, key=lambda item: _STATE_SEVERITY[item])
    return ranked[-1] if ranked else LinuxCollectorState.SYNCED


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _bounded_text(value: object, limit: int = _MAX_FIELD_CHARS) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(char for char in value.strip() if char.isprintable())
    return cleaned[:limit] if cleaned else None


# --------------------------------------------------------------------------
# systemd journal parsing
# --------------------------------------------------------------------------


class JournalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cursor: str = Field(min_length=1, max_length=1000)
    observed_at: dt.datetime
    boot_id: str | None = Field(default=None, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    pid: int | None = Field(default=None, ge=0)
    syslog_identifier: str | None = Field(default=None, max_length=256)
    message: str = Field(max_length=_MAX_JOURNAL_MESSAGE_CHARS)


def parse_journal_entry(raw: Mapping[str, str]) -> JournalRecord:
    total_bytes = sum(
        len(str(key).encode("utf-8")) + len(str(value).encode("utf-8"))
        for key, value in raw.items()
    )
    if total_bytes > _MAX_JOURNAL_ENTRY_BYTES:
        raise ValueError("Linux journal entry exceeds collector bounds")
    cursor = raw.get("__CURSOR")
    realtime = raw.get("__REALTIME_TIMESTAMP")
    message = raw.get("MESSAGE")
    if not cursor or not realtime or message is None:
        raise ValueError("Linux journal entry is missing required fields")
    try:
        observed_at = dt.datetime.fromtimestamp(int(realtime) / 1_000_000, tz=dt.UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError("Linux journal entry has an invalid timestamp") from exc
    pid_raw = raw.get("_PID")
    pid = int(pid_raw) if isinstance(pid_raw, str) and pid_raw.isdigit() else None
    bounded_cursor = _bounded_text(cursor, 1000)
    if not bounded_cursor:
        raise ValueError("Linux journal entry cursor is empty")
    return JournalRecord(
        cursor=bounded_cursor,
        observed_at=observed_at,
        boot_id=_bounded_text(raw.get("_BOOT_ID"), 64),
        hostname=_bounded_text(raw.get("_HOSTNAME"), 255),
        pid=pid,
        syslog_identifier=_bounded_text(raw.get("SYSLOG_IDENTIFIER"), 256),
        message=_bounded_text(message, _MAX_JOURNAL_MESSAGE_CHARS) or "",
    )


_SSH_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_FAILED_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)


def deterministic_journal_event_id(
    *, tenant_id: str, site_id: str, sensor_id: str, cursor: str
) -> str:
    material = json.dumps(
        [tenant_id, site_id, sensor_id, "journal", cursor],
        separators=(",", ":"),
    )
    return "linux-endpoint:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:48]


def normalize_linux_journal_event(
    record: JournalRecord,
    *,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
) -> EndpointTelemetryEvent | None:
    if tenant_id == "" or site_id == "" or sensor_id == "":
        raise ValueError("tenant_id, site_id, and sensor_id are required")
    if (record.syslog_identifier or "").casefold() != "sshd":
        return None
    accepted = _SSH_ACCEPTED_RE.match(record.message)
    failed = None if accepted else _SSH_FAILED_RE.match(record.message)
    if accepted is None and failed is None:
        return None
    match = accepted or failed
    assert match is not None
    event_id = deterministic_journal_event_id(
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=sensor_id,
        cursor=record.cursor,
    )
    return EndpointTelemetryEvent(
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=sensor_id,
        event_id=event_id,
        observed_at=record.observed_at,
        kind=(
            EndpointEventKind.AUTH_SUCCESS
            if accepted is not None
            else EndpointEventKind.AUTH_FAILURE
        ),
        hostname=record.hostname,
        asset_id=f"linux-host:{record.hostname.casefold()}" if record.hostname else None,
        user_name=match.group("user"),
        src_ip=match.group("ip"),
        outcome="success" if accepted is not None else "failure",
        source="linux-journal:sshd",
        raw_reference=f"journal://cursor/{record.cursor}",
    )


# --------------------------------------------------------------------------
# Linux audit (auditd) parsing
# --------------------------------------------------------------------------

_AUDIT_LINE_RE = re.compile(
    r"^type=(?P<type>[A-Z_]+)\s+msg=audit\((?P<timestamp>\d+\.\d+):(?P<serial>\d+)\):\s*(?P<rest>.*)$"
)
_AUDIT_KV_RE = re.compile(r'([a-zA-Z0-9_]+)=("(?:[^"\\]|\\.)*"|\S*)')


@dataclass(frozen=True, slots=True)
class LinuxAuditLine:
    record_type: str
    timestamp: float
    serial: int
    fields: dict[str, str]

    @property
    def audit_id(self) -> str:
        return f"{self.timestamp}:{self.serial}"


def parse_audit_line(raw: str) -> LinuxAuditLine:
    if len(raw.encode("utf-8")) > _MAX_AUDIT_LINE_BYTES:
        raise ValueError("Linux audit record exceeds collector bounds")
    match = _AUDIT_LINE_RE.match(raw.strip())
    if not match:
        raise ValueError("Linux audit record does not match the expected format")
    fields: dict[str, str] = {}
    for key, value in _AUDIT_KV_RE.findall(match.group("rest")):
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        fields[key] = value
    return LinuxAuditLine(
        record_type=match.group("type"),
        timestamp=float(match.group("timestamp")),
        serial=int(match.group("serial")),
        fields=fields,
    )


@dataclass(frozen=True, slots=True)
class LinuxAuditEventGroup:
    audit_id: str
    timestamp: float
    serial: int
    lines_by_type: dict[str, list[dict[str, str]]] = field(default_factory=dict)


def group_audit_lines(
    lines: Iterable[str],
) -> tuple[list[LinuxAuditEventGroup], list[LinuxAuditLine], int]:
    """Group raw audit lines into complete, EOE-terminated events.

    Returns (complete_groups, pending_tail_lines, rejected_count). Lines that
    do not parse are counted as rejected rather than raised, so one malformed
    line cannot take down an entire batch.
    """
    parsed: list[LinuxAuditLine] = []
    rejected = 0
    for raw in lines:
        try:
            parsed.append(parse_audit_line(raw))
        except ValueError:
            rejected += 1

    buckets: dict[str, list[LinuxAuditLine]] = {}
    order: list[str] = []
    for line in parsed:
        bucket = buckets.setdefault(line.audit_id, [])
        if not bucket:
            order.append(line.audit_id)
        bucket.append(line)

    complete: list[LinuxAuditEventGroup] = []
    pending: list[LinuxAuditLine] = []
    for audit_id in order:
        bucket = buckets[audit_id]
        if any(item.record_type == "EOE" for item in bucket):
            lines_by_type: dict[str, list[dict[str, str]]] = {}
            for item in bucket:
                lines_by_type.setdefault(item.record_type, []).append(item.fields)
            complete.append(
                LinuxAuditEventGroup(
                    audit_id=audit_id,
                    timestamp=bucket[0].timestamp,
                    serial=bucket[0].serial,
                    lines_by_type=lines_by_type,
                )
            )
        else:
            pending.extend(bucket)
    return complete, pending, rejected


def _optional_audit_uid(raw: str | None) -> str | None:
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    if value < 0 or value == _AUDIT_UNSET_UID:
        return None
    return str(value)


def _argv_from_execve(fields: Mapping[str, str]) -> str | None:
    try:
        argc = int(fields.get("argc", "0"))
    except ValueError:
        argc = 0
    parts: list[str] = []
    for index in range(argc):
        raw = fields.get(f"a{index}")
        if raw is None:
            break
        parts.append(raw)
    return " ".join(parts) if parts else None


def deterministic_audit_event_id(
    *, tenant_id: str, site_id: str, sensor_id: str, audit_id: str
) -> str:
    material = json.dumps(
        [tenant_id, site_id, sensor_id, "audit", audit_id],
        separators=(",", ":"),
    )
    return "linux-endpoint:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:48]


def normalize_linux_audit_execve(
    group: LinuxAuditEventGroup,
    *,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    hostname: str | None,
) -> EndpointTelemetryEvent | None:
    if tenant_id == "" or site_id == "" or sensor_id == "":
        raise ValueError("tenant_id, site_id, and sensor_id are required")
    syscalls = group.lines_by_type.get("SYSCALL")
    execves = group.lines_by_type.get("EXECVE")
    if not syscalls or not execves:
        # Only classify as process execution when the source explicitly
        # paired a SYSCALL record with an EXECVE record; never guess from a
        # raw syscall number, which is architecture dependent.
        return None
    fields = syscalls[0]
    pid_raw = fields.get("pid")
    if pid_raw is None or not pid_raw.isdigit():
        return None
    ppid_raw = fields.get("ppid")
    ppid = int(ppid_raw) if ppid_raw is not None and ppid_raw.isdigit() else None
    auid = _optional_audit_uid(fields.get("auid"))
    uid = _optional_audit_uid(fields.get("uid"))
    event_id = deterministic_audit_event_id(
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=sensor_id,
        audit_id=group.audit_id,
    )
    return EndpointTelemetryEvent(
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=sensor_id,
        event_id=event_id,
        observed_at=dt.datetime.fromtimestamp(group.timestamp, tz=dt.UTC),
        kind=EndpointEventKind.PROCESS_START,
        hostname=hostname,
        asset_id=f"linux-host:{hostname.casefold()}" if hostname else None,
        user_uid=auid or uid,
        identity_namespace=hostname if (auid or uid) else None,
        process_pid=int(pid_raw),
        parent_process_pid=ppid,
        image=_bounded_text(fields.get("exe"), 1000) or _bounded_text(fields.get("comm"), 256),
        command_line=_bounded_text(_argv_from_execve(execves[0]), 1000),
        outcome="success" if fields.get("success") == "yes" else "failure",
        source="linux-audit:execve",
        raw_reference=f"audit://{group.audit_id}",
    )


# --------------------------------------------------------------------------
# Source protocols and result types
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LinuxSourceReadResult:
    events: list[EndpointTelemetryEvent]
    checkpoint_token: str | None
    records_read: int
    rejected_records: int


class LinuxTelemetrySource(Protocol):
    source_id: str
    source_kind: LinuxSourceKind

    def read_after(self, checkpoint_token: str | None, *, limit: int) -> LinuxSourceReadResult: ...


class JournalReader(Protocol):
    def read_after(self, cursor: str | None, *, limit: int) -> list[Mapping[str, str]]: ...


class AuditLogReader(Protocol):
    """Returns up to `limit` complete audit events, each as its raw lines,
    plus the reader's own opaque resumption token for the position after the
    last returned event.

    Implementations own boundary detection: an event whose EOE record has not
    yet arrived must not be returned, so a caller never observes a partial
    execve group. The resumption token is opaque to callers: an in-memory
    reader may use the audit event id, while a real file-backed reader uses
    a durable byte offset.
    """

    def read_after(
        self, checkpoint_token: str | None, *, limit: int
    ) -> tuple[list[list[str]], str | None]: ...


class SecurityEventSender(Protocol):
    async def send(self, event: SecurityEvent) -> None: ...


class Closable(Protocol):
    def close(self) -> None: ...


class JournalAuthSource:
    source_kind = LinuxSourceKind.JOURNAL

    def __init__(
        self,
        source_id: str,
        reader: JournalReader,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
    ) -> None:
        self.source_id = source_id
        self.reader = reader
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.sensor_id = sensor_id

    def read_after(self, checkpoint_token: str | None, *, limit: int) -> LinuxSourceReadResult:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        raw_entries = self.reader.read_after(checkpoint_token, limit=limit)
        events: list[EndpointTelemetryEvent] = []
        rejected = 0
        last_token = checkpoint_token
        for raw in raw_entries:
            try:
                record = parse_journal_entry(raw)
            except ValueError:
                rejected += 1
                continue
            last_token = record.cursor
            try:
                telemetry = normalize_linux_journal_event(
                    record,
                    tenant_id=self.tenant_id,
                    site_id=self.site_id,
                    sensor_id=self.sensor_id,
                )
            except ValueError:
                rejected += 1
                continue
            if telemetry is not None:
                events.append(telemetry)
        return LinuxSourceReadResult(
            events=events,
            checkpoint_token=last_token,
            records_read=len(raw_entries),
            rejected_records=rejected,
        )


class AuditProcessSource:
    source_kind = LinuxSourceKind.AUDIT

    def __init__(
        self,
        source_id: str,
        reader: AuditLogReader,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        hostname: str | None,
    ) -> None:
        self.source_id = source_id
        self.reader = reader
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.sensor_id = sensor_id
        self.hostname = hostname

    def read_after(self, checkpoint_token: str | None, *, limit: int) -> LinuxSourceReadResult:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        raw_groups, new_token = self.reader.read_after(checkpoint_token, limit=limit)
        events: list[EndpointTelemetryEvent] = []
        rejected = 0
        for lines in raw_groups:
            complete, _pending, group_rejected = group_audit_lines(lines)
            rejected += group_rejected
            for group in complete:
                try:
                    telemetry = normalize_linux_audit_execve(
                        group,
                        tenant_id=self.tenant_id,
                        site_id=self.site_id,
                        sensor_id=self.sensor_id,
                        hostname=self.hostname,
                    )
                except ValueError:
                    rejected += 1
                    continue
                if telemetry is not None:
                    events.append(telemetry)
        return LinuxSourceReadResult(
            events=events,
            checkpoint_token=new_token if new_token is not None else checkpoint_token,
            records_read=len(raw_groups),
            rejected_records=rejected,
        )


class InMemoryJournalReader:
    """Test double for JournalReader; not used against real systems."""

    def __init__(self, entries: Sequence[Mapping[str, str]]) -> None:
        self._entries = list(entries)

    def read_after(self, cursor: str | None, *, limit: int) -> list[Mapping[str, str]]:
        start = 0
        if cursor is not None:
            for index, entry in enumerate(self._entries):
                if entry.get("__CURSOR") == cursor:
                    start = index + 1
                    break
        return self._entries[start : start + limit]


def _first_audit_id(lines: list[str]) -> str | None:
    for raw in lines:
        try:
            return parse_audit_line(raw).audit_id
        except ValueError:
            continue
    return None


class InMemoryAuditLogReader:
    """Test double for AuditLogReader; not used against real systems."""

    def __init__(self, groups: Sequence[list[str]]) -> None:
        self._groups = list(groups)

    def read_after(
        self, checkpoint_token: str | None, *, limit: int
    ) -> tuple[list[list[str]], str | None]:
        start = 0
        if checkpoint_token is not None:
            for index, lines in enumerate(self._groups):
                if _first_audit_id(lines) == checkpoint_token:
                    start = index + 1
                    break
        selected = self._groups[start : start + limit]
        new_token = checkpoint_token
        if selected:
            new_token = _first_audit_id(selected[-1]) or checkpoint_token
        return selected, new_token


class FileAuditLogReader:
    """Reads real auditd-log-formatted lines from a file.

    Checkpointing here is a durable, restart-safe byte offset into the audit
    log: an event whose EOE record has not yet been written is held back and
    re-read on the next call. Rotation-safe inode/anchor tracking (as
    JsonLineFileReader in sensor_collector.py provides for Zeek/Suricata) is
    not implemented for audit logs in this milestone; see docs/adr for the
    documented limitation.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def read_after(
        self, checkpoint_token: str | None, *, limit: int
    ) -> tuple[list[list[str]], str | None]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if not self.path.is_file():
            raise LinuxSourceUnavailable(f"audit log source is missing: {self.path}")
        offset = 0
        if checkpoint_token:
            try:
                offset = int(checkpoint_token)
            except ValueError as exc:
                raise LinuxEndpointCollectorError(
                    "audit log checkpoint token is not a valid byte offset"
                ) from exc
            if offset < 0:
                raise LinuxEndpointCollectorError("audit log checkpoint offset is negative")

        try:
            with self.path.open("r", encoding="utf-8", errors="strict") as handle:
                handle.seek(offset)
                raw_lines = handle.readlines(_MAX_AUDIT_READ_BYTES)
        except PermissionError as exc:
            raise LinuxSourcePermissionDenied(
                f"insufficient permissions to read {self.path}"
            ) from exc
        except OSError as exc:
            raise LinuxSourceUnavailable(f"audit log read failed: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise LinuxSourceUnavailable(f"audit log is not valid UTF-8: {exc}") from exc

        groups: list[list[str]] = []
        pending: list[str] = []
        consumed_bytes = 0
        new_offset = offset
        for raw in raw_lines:
            pending.append(raw)
            consumed_bytes += len(raw.encode("utf-8"))
            if raw.strip().startswith("type=EOE"):
                groups.append(pending)
                pending = []
                new_offset = offset + consumed_bytes
                if len(groups) >= limit:
                    break
        return groups, str(new_offset)


class SystemdJournalReader:
    """Best-effort adapter over the python3-systemd bindings.

    Raises LinuxSourceUnavailable when those bindings (or Linux itself) are
    not present, mirroring how the Windows collector's event-log source
    fails when wevtapi.dll is unavailable.
    """

    def __init__(self, *, unit: str | None = None) -> None:
        if sys.platform != "linux":
            raise LinuxSourceUnavailable("systemd journal access requires Linux")
        try:
            from systemd import journal as _journal
        except ImportError as exc:
            raise LinuxSourceUnavailable("python3-systemd is not installed") from exc
        try:
            self._reader = _journal.Reader()
            if unit:
                self._reader.add_match(_SYSTEMD_UNIT=unit)
        except PermissionError as exc:
            raise LinuxSourcePermissionDenied(
                "insufficient permissions to open the systemd journal"
            ) from exc

    def read_after(self, cursor: str | None, *, limit: int) -> list[Mapping[str, str]]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        try:
            if cursor:
                self._reader.seek_cursor(cursor)
                self._reader.get_next()
            else:
                self._reader.seek_head()
            entries: list[Mapping[str, str]] = []
            for _ in range(limit):
                entry = self._reader.get_next()
                if not entry:
                    break
                entries.append({str(key): str(value) for key, value in entry.items()})
            return entries
        except PermissionError as exc:
            raise LinuxSourcePermissionDenied(
                "insufficient permissions to read the systemd journal"
            ) from exc
        except OSError as exc:
            raise LinuxSourceUnavailable(f"systemd journal read failed: {exc}") from exc


# --------------------------------------------------------------------------
# Durable checkpointing
# --------------------------------------------------------------------------


class LinuxCollectorCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = _CHECKPOINT_SCHEMA_VERSION
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=256)
    source_kind: LinuxSourceKind
    checkpoint_token: str = Field(min_length=1, max_length=1000)
    updated_at: dt.datetime


class LinuxCollectorCheckpointStore:
    def __init__(
        self,
        directory: str | Path,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
    ) -> None:
        if not tenant_id or not site_id or not sensor_id:
            raise ValueError("tenant_id, site_id and sensor_id are required")
        self.directory = Path(directory)
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.sensor_id = sensor_id
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, source_id: str) -> Path:
        digest = hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:32]
        return self.directory / f"{digest}.json"

    def load(
        self, source_id: str, source_kind: LinuxSourceKind
    ) -> LinuxCollectorCheckpoint | None:
        path = self._path(source_id)
        if not path.exists():
            return None
        try:
            checkpoint = LinuxCollectorCheckpoint.model_validate_json(
                path.read_text(encoding="utf-8")
            )
        except ValueError as exc:
            raise LinuxCollectorCheckpointError(
                f"Linux collector checkpoint for {source_id} is corrupt"
            ) from exc
        if checkpoint.schema_version != _CHECKPOINT_SCHEMA_VERSION:
            raise LinuxCollectorCheckpointError(
                f"Linux collector checkpoint for {source_id} schema is incompatible"
            )
        if (
            checkpoint.tenant_id != self.tenant_id
            or checkpoint.site_id != self.site_id
            or checkpoint.sensor_id != self.sensor_id
            or checkpoint.source_id != source_id
            or checkpoint.source_kind != source_kind
        ):
            raise LinuxCollectorCheckpointError(
                f"Linux collector checkpoint for {source_id} scope mismatch"
            )
        return checkpoint

    def save(
        self,
        source_id: str,
        source_kind: LinuxSourceKind,
        checkpoint_token: str,
        *,
        now: dt.datetime | None = None,
    ) -> None:
        updated_at = now or _utc_now()
        if updated_at.tzinfo is None or updated_at.utcoffset() is None:
            raise ValueError("checkpoint timestamp must be timezone-aware")
        checkpoint = LinuxCollectorCheckpoint(
            tenant_id=self.tenant_id,
            site_id=self.site_id,
            sensor_id=self.sensor_id,
            source_id=source_id,
            source_kind=source_kind,
            checkpoint_token=checkpoint_token,
            updated_at=updated_at.astimezone(dt.UTC),
        )
        path = self._path(source_id)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            handle.write(checkpoint.model_dump_json())
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        os.replace(temp_path, path)


# --------------------------------------------------------------------------
# Local buffering
# --------------------------------------------------------------------------


class SQLiteLinuxEventBuffer:
    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        max_events: int = 10_000,
    ) -> None:
        if max_events < 1 or max_events > 1_000_000:
            raise ValueError("max_events must be between 1 and 1000000")
        self.path = Path(path)
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
            raise ValueError(f"Linux collector buffer {key} mismatch")

    def close(self) -> None:
        self._connection.close()

    def count(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) AS count FROM pending_events").fetchone()
        return int(row["count"]) if row else 0

    def enqueue(self, event: SecurityEvent) -> bool:
        if (
            event.tenant_id != self.tenant_id
            or event.site_id != self.site_id
            or event.sensor_id != self.sensor_id
        ):
            raise ValueError("Linux collector event scope does not match buffer")
        if self.count() >= self.max_events and not self.has_event(event.event_id):
            raise LinuxEndpointCollectorError("Linux collector buffer is full")
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
            raise ValueError("Linux collector local transport must be loopback")
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


# --------------------------------------------------------------------------
# Health model
# --------------------------------------------------------------------------


class LinuxSourceHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str
    source_kind: LinuxSourceKind
    state: LinuxCollectorState
    last_checkpoint_token: str | None = None
    last_error: str | None = None


class LinuxCollectorHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    state: LinuxCollectorState
    buffered_events: int
    sources: list[LinuxSourceHealth] = Field(default_factory=list)
    last_error: str | None = None


# --------------------------------------------------------------------------
# Collector orchestration
# --------------------------------------------------------------------------


class LinuxEndpointCollector:
    def __init__(
        self,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        sources: Sequence[LinuxTelemetrySource],
        checkpoint_store: LinuxCollectorCheckpointStore,
        buffer: SQLiteLinuxEventBuffer,
        sender: SecurityEventSender,
        batch_size: int = 100,
    ) -> None:
        if batch_size < 1 or batch_size > 1000:
            raise ValueError("batch_size must be between 1 and 1000")
        if not sources:
            raise ValueError("at least one Linux telemetry source is required")
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.sensor_id = sensor_id
        self.sources = tuple(sources)
        self.checkpoint_store = checkpoint_store
        self.buffer = buffer
        self.sender = sender
        self.batch_size = batch_size
        self._last_error: str | None = None

    async def collect_once(self) -> LinuxCollectorHealth:
        source_healths: list[LinuxSourceHealth] = []
        for source in self.sources:
            checkpoint = self.checkpoint_store.load(source.source_id, source.source_kind)
            token = checkpoint.checkpoint_token if checkpoint else None
            try:
                result = source.read_after(token, limit=self.batch_size)
            except LinuxSourcePermissionDenied as exc:
                source_healths.append(
                    LinuxSourceHealth(
                        source_id=source.source_id,
                        source_kind=source.source_kind,
                        state=LinuxCollectorState.PERMISSION_DENIED,
                        last_checkpoint_token=token,
                        last_error=str(exc)[:1000],
                    )
                )
                continue
            except LinuxSourceUnavailable as exc:
                source_healths.append(
                    LinuxSourceHealth(
                        source_id=source.source_id,
                        source_kind=source.source_kind,
                        state=LinuxCollectorState.SOURCE_UNAVAILABLE,
                        last_checkpoint_token=token,
                        last_error=str(exc)[:1000],
                    )
                )
                continue

            for event in result.events:
                self.buffer.enqueue(normalize_endpoint_event(event))
            if result.checkpoint_token is not None and result.checkpoint_token != token:
                self.checkpoint_store.save(
                    source.source_id, source.source_kind, result.checkpoint_token
                )
            source_healths.append(
                LinuxSourceHealth(
                    source_id=source.source_id,
                    source_kind=source.source_kind,
                    state=(
                        LinuxCollectorState.DEGRADED
                        if result.rejected_records
                        else LinuxCollectorState.SYNCED
                    ),
                    last_checkpoint_token=result.checkpoint_token or token,
                    last_error=(
                        f"{result.rejected_records} record(s) rejected"
                        if result.rejected_records
                        else None
                    ),
                )
            )
        return await self.flush_buffer(source_healths)

    async def flush_buffer(
        self, source_healths: list[LinuxSourceHealth] | None = None
    ) -> LinuxCollectorHealth:
        healths = source_healths if source_healths is not None else []
        for event in self.buffer.pending(self.batch_size):
            try:
                await self.sender.send(event)
            except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
                self._last_error = str(exc)[:1000]
                return self.health(healths, state=LinuxCollectorState.TRANSPORT_UNAVAILABLE)
            self.buffer.mark_sent(event.event_id)

        state = worst_state(item.state for item in healths)
        if state is LinuxCollectorState.SYNCED and self.buffer.count() > 0:
            state = LinuxCollectorState.BUFFERING
        self._last_error = None if state is LinuxCollectorState.SYNCED else self._last_error
        return self.health(healths, state=state)

    def health(
        self, source_healths: list[LinuxSourceHealth], *, state: LinuxCollectorState
    ) -> LinuxCollectorHealth:
        return LinuxCollectorHealth(
            state=state,
            buffered_events=self.buffer.count(),
            sources=source_healths,
            last_error=self._last_error,
        )


# --------------------------------------------------------------------------
# Long-running, cancellation-aware service runtime
# --------------------------------------------------------------------------


class LinuxCollectorServiceState(StrEnum):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class LinuxCollectorServiceStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service_state: LinuxCollectorServiceState
    collector_health: LinuxCollectorHealth | None = None
    fatal_error: str | None = None


class LinuxCollectorRuntime(Protocol):
    async def collect_once(self) -> LinuxCollectorHealth: ...


def validate_poll_interval(value: float) -> float:
    if value < _MIN_POLL_INTERVAL_SECONDS or value > _MAX_POLL_INTERVAL_SECONDS:
        raise ValueError("poll interval must be between 0.01 and 3600 seconds")
    return value


class LinuxCollectorServiceRuntime:
    """A cancellation-aware run loop around LinuxEndpointCollector.collect_once().

    This is a plain asyncio loop suitable for a systemd-managed foreground
    process (systemd supervises the process; there is no SCM-style API to
    integrate with on Linux). It performs one collection pass before
    reporting RUNNING, waits through a stop event rather than busy looping,
    and closes registered resources exactly once on the way out.
    """

    def __init__(
        self,
        *,
        collector: LinuxCollectorRuntime,
        poll_interval_seconds: float,
        resources: Iterable[Closable] = (),
    ) -> None:
        self.collector = collector
        self.poll_interval_seconds = validate_poll_interval(poll_interval_seconds)
        self.resources = tuple(resources)
        self._stop_event = asyncio.Event()
        self.status = LinuxCollectorServiceStatus(
            service_state=LinuxCollectorServiceState.STARTING
        )

    def request_stop(self) -> None:
        if self.status.service_state not in {
            LinuxCollectorServiceState.STOPPED,
            LinuxCollectorServiceState.FAILED,
        }:
            self.status = LinuxCollectorServiceStatus(
                service_state=LinuxCollectorServiceState.STOPPING,
                collector_health=self.status.collector_health,
                fatal_error=self.status.fatal_error,
            )
        self._stop_event.set()

    async def run_forever(self) -> LinuxCollectorServiceStatus:
        try:
            health = await self.collector.collect_once()
            self.status = LinuxCollectorServiceStatus(
                service_state=LinuxCollectorServiceState.RUNNING,
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
                self.status = LinuxCollectorServiceStatus(
                    service_state=LinuxCollectorServiceState.RUNNING,
                    collector_health=health,
                )
            if self.status.service_state is not LinuxCollectorServiceState.FAILED:
                self.status = LinuxCollectorServiceStatus(
                    service_state=LinuxCollectorServiceState.STOPPED,
                    collector_health=self.status.collector_health,
                )
            return self.status
        except LinuxCollectorCheckpointError as exc:
            self.status = LinuxCollectorServiceStatus(
                service_state=LinuxCollectorServiceState.FAILED,
                collector_health=self.status.collector_health,
                fatal_error=str(exc)[:1000],
            )
            raise
        finally:
            for resource in reversed(self.resources):
                resource.close()


# --------------------------------------------------------------------------
# CLI / systemd-managed foreground entry point
# --------------------------------------------------------------------------


class _StaticFailureSource:
    """A source whose read_after always reports the same construction-time
    failure. This keeps the collector able to start (and correctly report
    SOURCE_UNAVAILABLE/PERMISSION_DENIED health) even when a native adapter
    could not be constructed at all, instead of crashing the whole process.
    """

    def __init__(
        self,
        source_id: str,
        source_kind: LinuxSourceKind,
        error: LinuxEndpointCollectorError,
    ) -> None:
        self.source_id = source_id
        self.source_kind = source_kind
        self._error = error

    def read_after(self, checkpoint_token: str | None, *, limit: int) -> LinuxSourceReadResult:
        raise self._error


def _build_journal_source(args: argparse.Namespace) -> LinuxTelemetrySource:
    source_id = f"journal:{args.ssh_unit}"
    try:
        reader = SystemdJournalReader(unit=args.ssh_unit)
    except (LinuxSourceUnavailable, LinuxSourcePermissionDenied) as exc:
        return _StaticFailureSource(source_id, LinuxSourceKind.JOURNAL, exc)
    return JournalAuthSource(
        source_id,
        reader,
        tenant_id=args.tenant_id,
        site_id=args.site_id,
        sensor_id=args.sensor_id,
    )


def _build_audit_source(args: argparse.Namespace, hostname: str | None) -> LinuxTelemetrySource:
    reader = FileAuditLogReader(args.audit_log_file)
    return AuditProcessSource(
        "audit:execve",
        reader,
        tenant_id=args.tenant_id,
        site_id=args.site_id,
        sensor_id=args.sensor_id,
        hostname=hostname,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect Linux endpoint telemetry for MON")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("foreground",),
        help="run continuously instead of performing one collection pass",
    )
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--site-url", default="http://127.0.0.1:8090")
    parser.add_argument(
        "--hostname",
        default=None,
        help="asset/identity-namespace hostname; defaults to the local hostname",
    )
    parser.add_argument(
        "--audit-log-file",
        default=Path("/var/log/audit/audit.log"),
        type=Path,
    )
    parser.add_argument(
        "--ssh-unit",
        default="sshd",
        help="SYSLOG_IDENTIFIER treated as SSH authentication evidence",
    )
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--max-buffered-events", type=int, default=10_000)
    parser.add_argument("--poll-interval-seconds", type=float, default=30.0)
    return parser


def build_collector_from_args(
    args: argparse.Namespace,
) -> tuple[LinuxEndpointCollector, tuple[Closable, ...]]:
    hostname = args.hostname or socket.gethostname()
    checkpoint_store = LinuxCollectorCheckpointStore(
        Path(args.state_dir) / "checkpoints",
        tenant_id=args.tenant_id,
        site_id=args.site_id,
        sensor_id=args.sensor_id,
    )
    buffer = SQLiteLinuxEventBuffer(
        Path(args.state_dir) / "linux-endpoint-buffer.db",
        tenant_id=args.tenant_id,
        site_id=args.site_id,
        sensor_id=args.sensor_id,
        max_events=args.max_buffered_events,
    )
    sources: tuple[LinuxTelemetrySource, ...] = (
        _build_journal_source(args),
        _build_audit_source(args, hostname),
    )
    collector = LinuxEndpointCollector(
        tenant_id=args.tenant_id,
        site_id=args.site_id,
        sensor_id=args.sensor_id,
        sources=sources,
        checkpoint_store=checkpoint_store,
        buffer=buffer,
        sender=LocalSiteEventSender(args.site_url),
        batch_size=args.batch_size,
    )
    return collector, (buffer,)


async def async_main(argv: Iterable[str] | None = None) -> int:
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    collector, resources = build_collector_from_args(args)

    if args.command == "foreground":
        runtime = LinuxCollectorServiceRuntime(
            collector=collector,
            poll_interval_seconds=args.poll_interval_seconds,
            resources=resources,
        )
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            with suppress(NotImplementedError, ValueError):
                loop.add_signal_handler(signum, runtime.request_stop)
        status = await runtime.run_forever()
        print(status.model_dump_json())
        return 0 if status.service_state is LinuxCollectorServiceState.STOPPED else 2

    buffer = resources[0]
    try:
        health = await collector.collect_once()
        print(health.model_dump_json())
        return 0 if health.state is LinuxCollectorState.SYNCED else 2
    finally:
        buffer.close()


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
