from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mon.domain import SecurityEvent

_SECURITY_EVENT_TYPE = "telemetry.normalized.security_event"
_SECURITY_EVENT_SCHEMA_VERSION = 1
_INBOX_SCHEMA_VERSION = "1"


class FabricEnvelope(BaseModel):
    """Versioned, scope-explicit event-fabric message boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=160)
    schema_version: int = Field(ge=1, le=2_147_483_647)
    observed_at: dt.datetime
    produced_at: dt.datetime
    source: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]

    @model_validator(mode="after")
    def validate_times(self) -> FabricEnvelope:
        for name in ("observed_at", "produced_at"):
            value = getattr(self, name)
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{name} must be timezone-aware")
        return self

    @property
    def partition_key(self) -> tuple[str, str]:
        return (self.tenant_id, self.site_id)

    @property
    def partition_key_bytes(self) -> bytes:
        # A canonical JSON tuple avoids ambiguous delimiters in tenant/site IDs.
        return json.dumps(
            [self.tenant_id, self.site_id],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    def canonical_json(self) -> str:
        return _canonical_json(self.model_dump(mode="json"))

    @property
    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


class FabricPublisher(Protocol):
    """Broker-independent publisher boundary.

    A production adapter may use Kafka/Redpanda. Implementations must preserve
    the envelope unchanged across retries.
    """

    async def publish(self, envelope: FabricEnvelope) -> None: ...


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    event_id: str
    processed: bool
    duplicate: bool


def security_event_envelope(
    event: SecurityEvent,
    *,
    produced_at: dt.datetime,
) -> FabricEnvelope:
    """Wrap one normalized SecurityEvent without changing its logical identity.

    Callers that retry delivery must persist/reuse the returned envelope. They
    must not recreate it with a new produced_at for the same event_id.
    """

    return FabricEnvelope(
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        site_id=event.site_id,
        event_type=_SECURITY_EVENT_TYPE,
        schema_version=_SECURITY_EVENT_SCHEMA_VERSION,
        observed_at=event.observed_at,
        produced_at=produced_at,
        source=event.sensor_id,
        payload=event.model_dump(mode="json"),
    )


def security_event_from_envelope(envelope: FabricEnvelope) -> SecurityEvent:
    if (
        envelope.event_type != _SECURITY_EVENT_TYPE
        or envelope.schema_version != _SECURITY_EVENT_SCHEMA_VERSION
    ):
        raise ValueError(
            "fabric envelope is not a supported normalized security event"
        )
    try:
        event = SecurityEvent.model_validate(envelope.payload)
    except ValueError as exc:
        raise ValueError(
            "fabric security-event payload is invalid"
        ) from exc

    if event.event_id != envelope.event_id:
        raise ValueError("fabric event_id does not match security-event payload")
    if (
        event.tenant_id != envelope.tenant_id
        or event.site_id != envelope.site_id
    ):
        raise ValueError(
            "fabric tenant/site does not match security-event payload"
        )
    if event.sensor_id != envelope.source:
        raise ValueError(
            "fabric source does not match security-event sensor identity"
        )
    if event.observed_at != envelope.observed_at:
        raise ValueError(
            "fabric observed_at does not match security-event payload"
        )
    return event


class DurableFabricInbox:
    """Site-scoped SQLite idempotency boundary for at-least-once delivery.

    The handler runs in the same local SQLite transaction as the receipt.
    External effects are not made exactly-once by this class and require their
    own durable idempotency protocol.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        site_id: str,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if not tenant_id or not site_id:
            raise ValueError("fabric inbox tenant_id and site_id are required")
        if busy_timeout_seconds <= 0 or busy_timeout_seconds > 60:
            raise ValueError(
                "busy_timeout_seconds must be greater than 0 and at most 60"
            )

        self.path = Path(path)
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            check_same_thread=False,
            isolation_level=None,
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
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS fabric_inbox_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS fabric_receipts (
                    event_id TEXT PRIMARY KEY,
                    envelope_sha256 TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    processed_at TEXT NOT NULL
                )
                """
            )
            self._bind_metadata("schema_version", _INBOX_SCHEMA_VERSION)
            self._bind_metadata("tenant_id", self.tenant_id)
            self._bind_metadata("site_id", self.site_id)
            self._connection.execute("COMMIT")
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def _bind_metadata(self, key: str, expected: str) -> None:
        row = self._connection.execute(
            "SELECT value FROM fabric_inbox_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO fabric_inbox_metadata(key, value) VALUES (?, ?)",
                (key, expected),
            )
            return
        actual = str(row["value"])
        if actual != expected:
            raise ValueError(
                f"fabric inbox {key} mismatch: expected {expected!r}, "
                f"found {actual!r}"
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def process(
        self,
        envelope: FabricEnvelope,
        handler: Callable[[FabricEnvelope, sqlite3.Connection], None],
    ) -> DeliveryResult:
        self._require_scope(envelope)
        canonical = envelope.canonical_json()
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT envelope_sha256, envelope_json
                    FROM fabric_receipts
                    WHERE event_id = ?
                    """,
                    (envelope.event_id,),
                ).fetchone()
                if row is not None:
                    if (
                        str(row["envelope_sha256"]) != digest
                        or str(row["envelope_json"]) != canonical
                    ):
                        raise ValueError(
                            "event_id collision with different fabric envelope"
                        )
                    self._connection.execute("COMMIT")
                    return DeliveryResult(
                        event_id=envelope.event_id,
                        processed=False,
                        duplicate=True,
                    )

                handler(envelope, self._connection)
                self._connection.execute(
                    """
                    INSERT INTO fabric_receipts(
                        event_id,
                        envelope_sha256,
                        envelope_json,
                        processed_at
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        envelope.event_id,
                        digest,
                        canonical,
                        dt.datetime.now(dt.UTC).isoformat(),
                    ),
                )
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

        return DeliveryResult(
            event_id=envelope.event_id,
            processed=True,
            duplicate=False,
        )

    def _require_scope(self, envelope: FabricEnvelope) -> None:
        if (
            envelope.tenant_id != self.tenant_id
            or envelope.site_id != self.site_id
        ):
            raise ValueError(
                "fabric envelope scope does not match inbox scope"
            )

    def diagnostics(self) -> dict[str, object]:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM fabric_receipts"
            ).fetchone()
        return {
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "receipts": int(row["count"]) if row is not None else 0,
            "durability": "WAL_FULL",
            "delivery_semantics": "AT_LEAST_ONCE_IDEMPOTENT_LOCAL_EFFECT",
        }


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
