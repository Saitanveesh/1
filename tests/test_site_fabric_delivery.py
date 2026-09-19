import datetime as dt

import pytest

from mon.domain import SecurityEvent
from mon.event_fabric import FabricEnvelope
from mon.event_fabric_outbox import DurableFabricOutbox
from mon.site_controller import SiteController, SQLiteEventSpool


class RecordingPublisher:
    def __init__(self, *, fail_event_id: str | None = None) -> None:
        self.fail_event_id = fail_event_id
        self.published: list[FabricEnvelope] = []

    async def publish(self, envelope: FabricEnvelope) -> None:
        self.published.append(envelope)
        if envelope.event_id == self.fail_event_id:
            raise RuntimeError("fabric unavailable")


def event(index: int) -> SecurityEvent:
    return SecurityEvent(
        event_id=f"event-{index}",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        observed_at=dt.datetime(2026, 9, 19, 8, 0, tzinfo=dt.UTC)
        + dt.timedelta(seconds=index),
        category="network.connection",
        src_ip="10.0.0.10",
        dst_ip=f"10.0.0.{index + 20}",
        protocol="tcp",
        attributes={"dst_port": 443},
    )


@pytest.mark.asyncio
async def test_site_flush_stages_and_delivers_exact_fabric_envelopes(
    tmp_path,
) -> None:
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    publisher = RecordingPublisher()
    controller = SiteController(
        "tenant-a",
        "site-a",
        spool,
        fabric_outbox=outbox,
        fabric_publisher=publisher,
    )
    try:
        controller.ingest(event(1))
        controller.ingest(event(2))

        result = await controller.flush()

        assert result["state"] == "SYNCED"
        assert result["delivered"] == 2
        assert spool.count() == 0
        assert [item.event_id for item in publisher.published] == [
            "event-1",
            "event-2",
        ]
        assert outbox.diagnostics()["pending"] == 0
        assert outbox.diagnostics()["reconciled"] == 2
        assert (
            publisher.published[0].payload
            == event(1).model_dump(mode="json")
        )
    finally:
        outbox.close()
        spool.close()


@pytest.mark.asyncio
async def test_site_fabric_failure_preserves_order_and_exact_retry(
    tmp_path,
) -> None:
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    publisher = RecordingPublisher(fail_event_id="event-1")
    controller = SiteController(
        "tenant-a",
        "site-a",
        spool,
        fabric_outbox=outbox,
        fabric_publisher=publisher,
    )
    try:
        controller.ingest(event(1))
        controller.ingest(event(2))

        failed = await controller.flush()
        assert failed["state"] == "DEGRADED"
        assert [item.event_id for item in publisher.published] == ["event-1"]
        assert spool.count() == 2
        first_envelope = outbox.get("event-1")
        assert first_envelope is not None
        assert outbox.diagnostics()["pending"] == 2

        publisher.fail_event_id = None
        publisher.published.clear()
        retried = await controller.flush()

        assert retried["state"] == "SYNCED"
        assert [item.event_id for item in publisher.published] == [
            "event-1",
            "event-2",
        ]
        assert publisher.published[0] == first_envelope
        assert spool.count() == 0
    finally:
        outbox.close()
        spool.close()


@pytest.mark.asyncio
async def test_site_reconciles_crash_after_publish_ack_before_spool_delete(
    tmp_path,
) -> None:
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    publisher = RecordingPublisher()
    controller = SiteController(
        "tenant-a",
        "site-a",
        spool,
        fabric_outbox=outbox,
        fabric_publisher=publisher,
    )
    try:
        controller.ingest(event(1))
        envelope = outbox.enqueue_security_event(
            event(1),
            produced_at=dt.datetime(2026, 9, 19, 8, 5, tzinfo=dt.UTC),
        )
        outbox.mark_delivered(envelope.event_id)

        assert spool.has_event("event-1")
        result = await controller.flush()

        assert result["state"] == "SYNCED"
        assert publisher.published == []
        assert not spool.has_event("event-1")
        assert outbox.diagnostics()["delivered_unreconciled"] == 0
        assert outbox.diagnostics()["reconciled"] == 1
    finally:
        outbox.close()
        spool.close()


@pytest.mark.asyncio
async def test_site_with_fabric_outbox_and_no_publisher_stays_offline(
    tmp_path,
) -> None:
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    controller = SiteController(
        "tenant-a",
        "site-a",
        spool,
        fabric_outbox=outbox,
    )
    try:
        controller.ingest(event(1))
        result = await controller.flush()

        assert result["state"] == "OFFLINE"
        assert spool.count() == 1
        assert outbox.diagnostics()["pending"] == 1
    finally:
        outbox.close()
        spool.close()


def test_site_requires_outbox_for_fabric_publisher(tmp_path) -> None:
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        with pytest.raises(ValueError, match="requires a durable fabric outbox"):
            SiteController(
                "tenant-a",
                "site-a",
                spool,
                fabric_publisher=RecordingPublisher(),
            )
    finally:
        spool.close()
