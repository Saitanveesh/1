import datetime as dt
import sqlite3
import threading
import uuid

import pytest
from pydantic import ValidationError

from mon.domain import SecurityEvent
from mon.event_fabric import (
    DurableFabricInbox,
    FabricEnvelope,
    security_event_envelope,
    security_event_from_envelope,
)


def envelope(
    *,
    event_id: str | None = None,
    tenant_id: str = "tenant-a",
    site_id: str = "site-a",
    payload: dict[str, object] | None = None,
    observed_at: dt.datetime | None = None,
    produced_at: dt.datetime | None = None,
) -> FabricEnvelope:
    now = dt.datetime(2026, 9, 19, 6, 0, tzinfo=dt.UTC)
    return FabricEnvelope(
        event_id=event_id or str(uuid.uuid4()),
        tenant_id=tenant_id,
        site_id=site_id,
        event_type="telemetry.normalized.test",
        schema_version=1,
        observed_at=observed_at or now,
        produced_at=produced_at or now + dt.timedelta(milliseconds=1),
        source="sensor-1",
        payload=payload if payload is not None else {"count": 1, "source": "sensor"},
    )


def test_partition_key_is_unambiguous_tenant_site_pair() -> None:
    item = envelope(tenant_id="tenant:one", site_id="site:two")

    assert item.partition_key == ("tenant:one", "site:two")
    assert item.partition_key_bytes == b'["tenant:one","site:two"]'


def test_rejects_naive_fabric_timestamps() -> None:
    item = envelope()
    with pytest.raises(ValidationError, match="timezone-aware"):
        FabricEnvelope(
            **{
                **item.model_dump(),
                "produced_at": dt.datetime(2026, 9, 19, 6, 0),
            }
        )


def test_canonical_digest_is_stable_across_payload_key_order() -> None:
    event_id = "stable-event"
    first = envelope(
        event_id=event_id,
        payload={"a": 1, "b": {"x": 2, "y": 3}},
    )
    second = envelope(
        event_id=event_id,
        payload={"b": {"y": 3, "x": 2}, "a": 1},
    )

    assert first.canonical_json() == second.canonical_json()
    assert first.canonical_sha256 == second.canonical_sha256


def test_duplicate_delivery_runs_handler_once(tmp_path) -> None:
    item = envelope()
    inbox = DurableFabricInbox(
        tmp_path / "inbox.db",
        tenant_id=item.tenant_id,
        site_id=item.site_id,
    )
    calls: list[str] = []

    def handler(
        delivered: FabricEnvelope,
        connection: sqlite3.Connection,
    ) -> None:
        calls.append(delivered.event_id)

    try:
        first = inbox.process(item, handler)
        second = inbox.process(item, handler)
    finally:
        inbox.close()

    assert first.processed is True
    assert first.duplicate is False
    assert second.processed is False
    assert second.duplicate is True
    assert calls == [item.event_id]


def test_handler_failure_rolls_back_receipt_and_local_mutation(tmp_path) -> None:
    item = envelope()
    inbox = DurableFabricInbox(
        tmp_path / "inbox.db",
        tenant_id=item.tenant_id,
        site_id=item.site_id,
    )
    inbox._connection.execute(
        "CREATE TABLE derived(event_id TEXT PRIMARY KEY)"
    )

    def failing_handler(
        delivered: FabricEnvelope,
        connection: sqlite3.Connection,
    ) -> None:
        connection.execute(
            "INSERT INTO derived(event_id) VALUES (?)",
            (delivered.event_id,),
        )
        raise RuntimeError("analysis failed")

    try:
        with pytest.raises(RuntimeError, match="analysis failed"):
            inbox.process(item, failing_handler)

        assert inbox.diagnostics()["receipts"] == 0
        derived = inbox._connection.execute(
            "SELECT COUNT(*) AS count FROM derived"
        ).fetchone()
        assert derived is not None
        assert int(derived["count"]) == 0

        retried = inbox.process(
            item,
            lambda delivered, connection: connection.execute(
                "INSERT INTO derived(event_id) VALUES (?)",
                (delivered.event_id,),
            ),
        )
        assert retried.processed is True
        assert inbox.diagnostics()["receipts"] == 1
    finally:
        inbox.close()


def test_cross_scope_delivery_fails_closed(tmp_path) -> None:
    item = envelope()
    inbox = DurableFabricInbox(
        tmp_path / "inbox.db",
        tenant_id="tenant-b",
        site_id=item.site_id,
    )
    try:
        with pytest.raises(ValueError, match="scope"):
            inbox.process(item, lambda _item, _connection: None)
    finally:
        inbox.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("payload", {"count": 2}),
        ("event_type", "telemetry.other"),
        ("schema_version", 2),
        (
            "observed_at",
            dt.datetime(2026, 9, 19, 6, 0, 1, tzinfo=dt.UTC),
        ),
        (
            "produced_at",
            dt.datetime(2026, 9, 19, 6, 0, 2, tzinfo=dt.UTC),
        ),
        ("source", "sensor-2"),
    ],
)
def test_event_id_collision_with_changed_envelope_fails_closed(
    tmp_path,
    field: str,
    value: object,
) -> None:
    item = envelope(event_id="collision-event")
    inbox = DurableFabricInbox(
        tmp_path / "inbox.db",
        tenant_id=item.tenant_id,
        site_id=item.site_id,
    )
    try:
        inbox.process(item, lambda _item, _connection: None)
        changed = item.model_copy(update={field: value})
        with pytest.raises(ValueError, match="collision"):
            inbox.process(changed, lambda _item, _connection: None)
    finally:
        inbox.close()


def test_receipt_and_scope_binding_survive_restart(tmp_path) -> None:
    item = envelope()
    path = tmp_path / "inbox.db"
    first = DurableFabricInbox(
        path,
        tenant_id=item.tenant_id,
        site_id=item.site_id,
    )
    first.process(item, lambda _item, _connection: None)
    first.close()

    second = DurableFabricInbox(
        path,
        tenant_id=item.tenant_id,
        site_id=item.site_id,
    )
    calls: list[str] = []
    try:
        result = second.process(
            item,
            lambda delivered, _connection: calls.append(delivered.event_id),
        )
        assert result.duplicate is True
        assert calls == []
        assert second.diagnostics()["receipts"] == 1
        assert second.diagnostics()["durability"] == "WAL_FULL"
    finally:
        second.close()

    with pytest.raises(ValueError, match="tenant_id mismatch"):
        DurableFabricInbox(
            path,
            tenant_id="tenant-other",
            site_id=item.site_id,
        )


def test_concurrent_duplicate_delivery_runs_handler_once(tmp_path) -> None:
    item = envelope(event_id="concurrent-event")
    inbox = DurableFabricInbox(
        tmp_path / "inbox.db",
        tenant_id=item.tenant_id,
        site_id=item.site_id,
    )
    barrier = threading.Barrier(3)
    handler_calls: list[str] = []
    results = []
    errors: list[BaseException] = []

    def handler(
        delivered: FabricEnvelope,
        connection: sqlite3.Connection,
    ) -> None:
        handler_calls.append(delivered.event_id)

    def worker() -> None:
        barrier.wait()
        try:
            results.append(inbox.process(item, handler))
        except BaseException as exc:
            errors.append(exc)

    first = threading.Thread(target=worker)
    second = threading.Thread(target=worker)
    first.start()
    second.start()
    barrier.wait()
    first.join(timeout=5)
    second.join(timeout=5)
    try:
        assert not first.is_alive()
        assert not second.is_alive()
        assert errors == []
        assert len(handler_calls) == 1
        assert sorted(result.duplicate for result in results) == [False, True]
    finally:
        inbox.close()


def test_security_event_adapter_round_trip_and_scope_binding() -> None:
    observed = dt.datetime(2026, 9, 19, 6, 0, tzinfo=dt.UTC)
    produced = observed + dt.timedelta(milliseconds=5)
    event = SecurityEvent(
        event_id="security-event-1",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="zeek-edge-1",
        observed_at=observed,
        category="network.connection",
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        protocol="tcp",
        attributes={"dst_port": 443},
    )

    wrapped = security_event_envelope(event, produced_at=produced)

    assert wrapped.event_id == event.event_id
    assert wrapped.partition_key == ("tenant-a", "site-a")
    assert wrapped.source == "zeek-edge-1"
    assert wrapped.produced_at == produced
    assert security_event_from_envelope(wrapped) == event

    with pytest.raises(ValueError, match="tenant/site"):
        security_event_from_envelope(
            wrapped.model_copy(update={"tenant_id": "tenant-b"})
        )


def test_security_event_retry_must_reuse_original_envelope_time() -> None:
    observed = dt.datetime(2026, 9, 19, 6, 0, tzinfo=dt.UTC)
    event = SecurityEvent(
        event_id="security-event-stable",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        observed_at=observed,
        category="network.connection",
    )

    first = security_event_envelope(
        event,
        produced_at=observed + dt.timedelta(seconds=1),
    )
    recreated = security_event_envelope(
        event,
        produced_at=observed + dt.timedelta(seconds=2),
    )

    assert first.event_id == recreated.event_id
    assert first.canonical_sha256 != recreated.canonical_sha256
