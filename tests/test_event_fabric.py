import datetime as dt
import sqlite3
import uuid

import pytest
from pydantic import ValidationError

from mon.event_fabric import DurableFabricInbox, FabricEnvelope


def _envelope(*, event_id=None, tenant_id=None, site_id=None, payload=None):
    now = dt.datetime.now(dt.UTC)
    return FabricEnvelope(
        event_id=event_id or uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        site_id=site_id or uuid.uuid4(),
        event_type="telemetry.normalized",
        schema_version=1,
        occurred_at=now,
        produced_at=now,
        payload=payload or {"source": "sensor", "count": 1},
    )


def test_partition_key_is_tenant_and_site():
    envelope = _envelope()
    assert envelope.partition_key == f"{envelope.tenant_id}:{envelope.site_id}"


def test_rejects_naive_timestamps():
    envelope = _envelope()
    with pytest.raises(ValidationError, match="timezone-aware"):
        FabricEnvelope(**{**envelope.model_dump(), "produced_at": dt.datetime.now()})


def test_duplicate_delivery_runs_handler_once(tmp_path):
    envelope = _envelope()
    inbox = DurableFabricInbox(
        tmp_path / "inbox.sqlite", tenant_id=envelope.tenant_id, site_id=envelope.site_id
    )
    calls = []

    def handler(item, connection):
        calls.append(item.event_id)

    try:
        first = inbox.process(envelope, handler)
        second = inbox.process(envelope, handler)
    finally:
        inbox.close()

    assert first.processed is True
    assert second.duplicate is True
    assert calls == [envelope.event_id]


def test_handler_failure_rolls_back_receipt_and_local_mutation(tmp_path):
    envelope = _envelope()
    inbox = DurableFabricInbox(
        tmp_path / "inbox.sqlite", tenant_id=envelope.tenant_id, site_id=envelope.site_id
    )
    inbox._connection.execute("CREATE TABLE derived (event_id TEXT PRIMARY KEY)")

    def failing_handler(item, connection):
        connection.execute("INSERT INTO derived VALUES (?)", (str(item.event_id),))
        raise RuntimeError("analysis failed")

    try:
        with pytest.raises(RuntimeError, match="analysis failed"):
            inbox.process(envelope, failing_handler)
        count = inbox._connection.execute("SELECT COUNT(*) FROM derived").fetchone()[0]
        receipt_count = inbox._connection.execute("SELECT COUNT(*) FROM fabric_receipts").fetchone()[0]
    finally:
        inbox.close()

    assert count == 0
    assert receipt_count == 0


def test_cross_scope_delivery_fails_closed(tmp_path):
    envelope = _envelope()
    inbox = DurableFabricInbox(
        tmp_path / "inbox.sqlite", tenant_id=uuid.uuid4(), site_id=envelope.site_id
    )
    try:
        with pytest.raises(ValueError, match="scope"):
            inbox.process(envelope, lambda _item, _connection: None)
    finally:
        inbox.close()


def test_event_id_collision_with_changed_payload_fails_closed(tmp_path):
    envelope = _envelope()
    inbox = DurableFabricInbox(
        tmp_path / "inbox.sqlite", tenant_id=envelope.tenant_id, site_id=envelope.site_id
    )
    try:
        inbox.process(envelope, lambda _item, _connection: None)
        changed = envelope.model_copy(update={"payload": {"source": "sensor", "count": 2}})
        with pytest.raises(ValueError, match="collision"):
            inbox.process(changed, lambda _item, _connection: None)
    finally:
        inbox.close()


def test_receipt_survives_inbox_restart(tmp_path):
    envelope = _envelope()
    path = tmp_path / "inbox.sqlite"
    first = DurableFabricInbox(path, tenant_id=envelope.tenant_id, site_id=envelope.site_id)
    first.process(envelope, lambda _item, _connection: None)
    first.close()

    second = DurableFabricInbox(path, tenant_id=envelope.tenant_id, site_id=envelope.site_id)
    calls = []
    try:
        result = second.process(envelope, lambda item, _connection: calls.append(item.event_id))
    finally:
        second.close()

    assert result.duplicate is True
    assert calls == []
