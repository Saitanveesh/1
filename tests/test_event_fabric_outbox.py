import datetime as dt

import pytest

from mon.domain import SecurityEvent
from mon.event_fabric_outbox import DurableFabricOutbox


def event(
    event_id: str = "event-1",
    *,
    tenant_id: str = "tenant-a",
    site_id: str = "site-a",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id="sensor-1",
        observed_at=dt.datetime(2026, 9, 19, 7, 0, tzinfo=dt.UTC),
        category="network.connection",
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        protocol="tcp",
        attributes={"dst_port": 443},
    )


def test_outbox_reuses_exact_persisted_envelope_across_restart(tmp_path) -> None:
    path = tmp_path / "fabric-outbox.db"
    produced_at = dt.datetime(2026, 9, 19, 7, 1, tzinfo=dt.UTC)
    first = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    original = first.enqueue_security_event(
        event(),
        produced_at=produced_at,
    )
    first.close()

    reopened = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        replay = reopened.enqueue_security_event(
            event(),
            produced_at=produced_at + dt.timedelta(hours=1),
        )
        assert replay == original
        assert replay.produced_at == produced_at
        assert replay.canonical_sha256 == original.canonical_sha256
        assert reopened.diagnostics()["pending"] == 1
    finally:
        reopened.close()


def test_outbox_rejects_scope_reuse_and_conflicting_event_content(tmp_path) -> None:
    path = tmp_path / "fabric-outbox.db"
    outbox = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        original = event()
        outbox.enqueue_security_event(original)
        with pytest.raises(ValueError, match="different content"):
            outbox.enqueue_security_event(
                original.model_copy(update={"dst_ip": "10.9.9.9"})
            )
        with pytest.raises(ValueError, match="scope"):
            outbox.enqueue_security_event(
                event("foreign", tenant_id="tenant-b")
            )
    finally:
        outbox.close()

    with pytest.raises(ValueError, match="tenant_id mismatch"):
        DurableFabricOutbox(
            path,
            tenant_id="tenant-b",
            site_id="site-a",
        )


def test_failed_delivery_remains_pending_and_records_attempt(tmp_path) -> None:
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        outbox.enqueue_security_event(event())
        assert outbox.mark_failed("event-1", "cloud unavailable")
        diagnostics = outbox.diagnostics()
        assert diagnostics["pending"] == 1
        assert diagnostics["max_attempts"] == 1
        assert diagnostics["last_error"] == "cloud unavailable"
        assert [item.event_id for item in outbox.pending()] == ["event-1"]
    finally:
        outbox.close()


def test_delivered_receipt_survives_until_source_is_reconciled(tmp_path) -> None:
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    delivered_at = dt.datetime(2026, 9, 19, 8, 0, tzinfo=dt.UTC)
    try:
        outbox.enqueue_security_event(event())
        assert outbox.mark_delivered("event-1", now=delivered_at)
        assert outbox.pending() == []
        assert [
            item.event_id
            for item in outbox.delivered_unreconciled()
        ] == ["event-1"]

        assert (
            outbox.compact_reconciled(
                retain_for=dt.timedelta(seconds=1),
                now=delivered_at + dt.timedelta(days=1),
            )
            == 0
        )
        assert outbox.get("event-1") is not None

        assert outbox.mark_source_reconciled(
            "event-1",
            now=delivered_at + dt.timedelta(seconds=1),
        )
        assert (
            outbox.compact_reconciled(
                retain_for=dt.timedelta(hours=1),
                now=delivered_at + dt.timedelta(hours=2),
            )
            == 1
        )
        assert outbox.get("event-1") is None
    finally:
        outbox.close()


def test_source_cannot_be_reconciled_before_delivery(tmp_path) -> None:
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        outbox.enqueue_security_event(event())
        with pytest.raises(ValueError, match="before delivery"):
            outbox.mark_source_reconciled("event-1")
    finally:
        outbox.close()


def test_pending_delivery_preserves_creation_order(tmp_path) -> None:
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    base = dt.datetime(2026, 9, 19, 7, 0, tzinfo=dt.UTC)
    try:
        outbox.enqueue_security_event(
            event("event-2"),
            produced_at=base + dt.timedelta(seconds=2),
        )
        outbox.enqueue_security_event(
            event("event-1"),
            produced_at=base + dt.timedelta(seconds=1),
        )
        assert [
            item.event_id for item in outbox.pending()
        ] == ["event-1", "event-2"]
    finally:
        outbox.close()
