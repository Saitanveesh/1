from __future__ import annotations

import datetime as dt
import json
import sqlite3
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FabricEnvelope(BaseModel):
    """Versioned message boundary for cross-process MON events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: uuid.UUID
    tenant_id: uuid.UUID
    site_id: uuid.UUID
    event_type: str = Field(min_length=1, max_length=160)
    schema_version: int = Field(ge=1)
    occurred_at: dt.datetime
    produced_at: dt.datetime
    payload: dict[str, Any]

    @model_validator(mode="after")
    def validate_times(self) -> FabricEnvelope:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        if self.produced_at.tzinfo is None or self.produced_at.utcoffset() is None:
            raise ValueError("produced_at must be timezone-aware")
        return self

    @property
    def partition_key(self) -> str:
        return f"{self.tenant_id}:{self.site_id}"

    def canonical_json(self) -> str:
        return self.model_dump_json()


@dataclass(frozen=True)
class DeliveryResult:
    event_id: uuid.UUID
    processed: bool
    duplicate: bool


class DurableFabricInbox:
    """SQLite-backed idempotency boundary for at-least-once fabric delivery.

    The handler runs inside the same SQLite transaction as the receipt. Handlers
    used here must therefore restrict durable side effects to this transaction or
    implement their own idempotency contract for external effects.
    """

    def __init__(self, path: str | Path, *, tenant_id: uuid.UUID, site_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.site_id = site_id
        self._connection = sqlite3.connect(str(path), isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS fabric_receipts (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                site_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                schema_version INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                processed_at TEXT NOT NULL
            )
            """
        )

    def close(self) -> None:
        self._connection.close()

    def process(
        self,
        envelope: FabricEnvelope,
        handler: Callable[[FabricEnvelope, sqlite3.Connection], None],
    ) -> DeliveryResult:
        self._require_scope(envelope)
        event_id = str(envelope.event_id)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT tenant_id, site_id, event_type, schema_version, payload_json "
                "FROM fabric_receipts WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if row is not None:
                self._verify_duplicate(envelope, row)
                self._connection.execute("COMMIT")
                return DeliveryResult(envelope.event_id, processed=False, duplicate=True)

            handler(envelope, self._connection)
            self._connection.execute(
                "INSERT INTO fabric_receipts "
                "(event_id, tenant_id, site_id, event_type, schema_version, payload_json, processed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    str(envelope.tenant_id),
                    str(envelope.site_id),
                    envelope.event_type,
                    envelope.schema_version,
                    _canonical_payload(envelope.payload),
                    dt.datetime.now(dt.UTC).isoformat(),
                ),
            )
            self._connection.execute("COMMIT")
            return DeliveryResult(envelope.event_id, processed=True, duplicate=False)
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def _require_scope(self, envelope: FabricEnvelope) -> None:
        if envelope.tenant_id != self.tenant_id or envelope.site_id != self.site_id:
            raise ValueError("fabric envelope scope does not match inbox scope")

    @staticmethod
    def _verify_duplicate(envelope: FabricEnvelope, row: tuple[Any, ...]) -> None:
        expected = (
            str(envelope.tenant_id),
            str(envelope.site_id),
            envelope.event_type,
            envelope.schema_version,
            _canonical_payload(envelope.payload),
        )
        if row != expected:
            raise ValueError("event_id collision with different fabric envelope")


def _canonical_payload(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
