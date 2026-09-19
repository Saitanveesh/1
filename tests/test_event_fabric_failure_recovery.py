from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from mon import fabric_load_probe as probe
from mon.database import DatabaseStore
from mon.domain import SecurityEvent
from mon.event_fabric import (
    FabricEnvelope,
    FabricReceipt,
    FabricReceiptStatus,
    security_event_envelope,
)
from mon.event_fabric_outbox import DurableFabricOutbox
from mon.fabric_ingress import FabricProcessingUncertain, ingest_fabric_envelope
from mon.pipeline import PipelinePersistenceMode, SecurityPipeline
from mon.site_controller import SiteController, SQLiteEventSpool


def event(
    index: int,
    *,
    tenant_id: str = "tenant-a",
    site_id: str = "site-a",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=f"{tenant_id}-{site_id}-event-{index}",
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=f"sensor-{site_id}",
        observed_at=dt.datetime(2026, 9, 19, 10, 0, tzinfo=dt.UTC)
        + dt.timedelta(seconds=index),
        category="network.connection",
        asset_id=f"asset-{site_id}-{index}",
        src_ip=f"10.{index}.0.10",
        dst_ip=f"10.{index}.0.20",
        protocol="tcp",
        attributes={"dst_port": 445, "tcp_syn": True},
    )


def build_store(path: Path) -> DatabaseStore:
    return DatabaseStore(f"sqlite+pysqlite:///{path}", create_schema=True)


def build_pipeline(store: DatabaseStore) -> SecurityPipeline:
    return SecurityPipeline(
        store=store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )


class IngressPublisher:
    def __init__(
        self,
        store: DatabaseStore,
        pipeline: SecurityPipeline,
        *,
        fail_event_ids: set[str] | None = None,
        lose_ack_once_for: set[str] | None = None,
    ) -> None:
        self.store = store
        self.pipeline = pipeline
        self.fail_event_ids = fail_event_ids or set()
        self.lose_ack_once_for = lose_ack_once_for or set()
        self.published: list[FabricEnvelope] = []

    async def publish(self, envelope: FabricEnvelope) -> None:
        self.published.append(envelope)
        if envelope.event_id in self.fail_event_ids:
            raise RuntimeError("simulated control-plane outage")
        ingest_fabric_envelope(self.store, self.pipeline, envelope)
        if envelope.event_id in self.lose_ack_once_for:
            self.lose_ack_once_for.remove(envelope.event_id)
            raise RuntimeError("simulated lost acknowledgement")


def controller_for(
    tmp_path: Path,
    *,
    tenant_id: str = "tenant-a",
    site_id: str = "site-a",
    publisher: IngressPublisher | None = None,
) -> tuple[SiteController, SQLiteEventSpool, DurableFabricOutbox]:
    spool = SQLiteEventSpool(
        tmp_path / f"{tenant_id}-{site_id}-spool.db",
        tenant_id=tenant_id,
        site_id=site_id,
    )
    outbox = DurableFabricOutbox(
        tmp_path / f"{tenant_id}-{site_id}-outbox.db",
        tenant_id=tenant_id,
        site_id=site_id,
    )
    controller = SiteController(
        tenant_id,
        site_id,
        spool,
        fabric_outbox=outbox,
        fabric_publisher=publisher,
    )
    return controller, spool, outbox


@pytest.mark.asyncio
async def test_temporary_control_plane_outage_recovers_without_event_loss(
    tmp_path: Path,
) -> None:
    control = build_store(tmp_path / "control.db")
    control_pipeline = build_pipeline(control)
    publisher = IngressPublisher(
        control,
        control_pipeline,
        fail_event_ids={"tenant-a-site-a-event-1"},
    )
    controller, spool, outbox = controller_for(tmp_path, publisher=publisher)
    try:
        controller.ingest(event(1))
        controller.ingest(event(2))
        controller.ingest(event(3))

        failed = await controller.flush()

        assert failed["state"] == "DEGRADED"
        assert failed["delivered"] == 0
        assert [item.event_id for item in publisher.published] == [
            "tenant-a-site-a-event-1"
        ]
        assert spool.count() == 3
        assert outbox.diagnostics()["pending"] == 3
        first_envelope = outbox.get("tenant-a-site-a-event-1")
        assert first_envelope is not None

        publisher.fail_event_ids.clear()
        publisher.published.clear()
        recovered = await controller.flush()

        assert recovered["state"] == "SYNCED"
        assert recovered["queued"] == 0
        assert recovered["fabric_pending"] == 0
        assert [item.event_id for item in publisher.published] == [
            "tenant-a-site-a-event-1",
            "tenant-a-site-a-event-2",
            "tenant-a-site-a-event-3",
        ]
        assert publisher.published[0] == first_envelope
        assert len(control.list_events("tenant-a", "site-a")) == 3
    finally:
        outbox.close()
        spool.close()
        control.close()


@pytest.mark.asyncio
async def test_lost_acknowledgement_replays_exact_envelope_idempotently(
    tmp_path: Path,
) -> None:
    control = build_store(tmp_path / "control.db")
    control_pipeline = build_pipeline(control)
    event_id = "tenant-a-site-a-event-1"
    publisher = IngressPublisher(
        control,
        control_pipeline,
        lose_ack_once_for={event_id},
    )
    controller, spool, outbox = controller_for(tmp_path, publisher=publisher)
    try:
        controller.ingest(event(1))

        uncertain = await controller.flush()
        assert uncertain["state"] == "DEGRADED"
        assert uncertain["delivered"] == 0
        assert spool.count() == 1
        assert outbox.diagnostics()["pending"] == 1
        assert len(control.list_events("tenant-a", "site-a")) == 1
        receipt = control.get_fabric_receipt("tenant-a", "site-a", event_id)
        assert receipt is not None
        assert receipt.status is FabricReceiptStatus.PROCESSED

        retried = await controller.flush()

        assert retried["state"] == "SYNCED"
        assert retried["delivered"] == 1
        assert spool.count() == 0
        assert outbox.diagnostics()["pending"] == 0
        assert [item.event_id for item in publisher.published] == [
            event_id,
            event_id,
        ]
        assert publisher.published[0] == publisher.published[1]
        assert len(control.list_events("tenant-a", "site-a")) == 1
        assert len(control.list_findings("tenant-a", "site-a")) == len(
            {item.finding_id for item in control.list_findings("tenant-a", "site-a")}
        )
    finally:
        outbox.close()
        spool.close()
        control.close()


def test_receiver_restart_recovers_pending_claim_and_refuses_uncertain_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control.db"
    item = event(1)
    envelope = security_event_envelope(
        item,
        produced_at=dt.datetime(2026, 9, 19, 10, 1, tzinfo=dt.UTC),
    )
    first = build_store(path)
    try:
        first.add_fabric_receipt(
            FabricReceipt(
                event_id=envelope.event_id,
                tenant_id=envelope.tenant_id,
                site_id=envelope.site_id,
                envelope_sha256=envelope.canonical_sha256,
                envelope_json=envelope.canonical_json(),
                received_at=dt.datetime(2026, 9, 19, 10, 2, tzinfo=dt.UTC),
            )
        )
    finally:
        first.close()

    second = DatabaseStore(f"sqlite+pysqlite:///{path}")
    try:
        recovered = ingest_fabric_envelope(second, build_pipeline(second), envelope)
        assert recovered.acknowledgement.duplicate is False
        receipt = second.get_fabric_receipt("tenant-a", "site-a", envelope.event_id)
        assert receipt is not None
        assert receipt.status is FabricReceiptStatus.PROCESSED
    finally:
        second.close()

    uncertain_path = tmp_path / "uncertain.db"
    uncertain = build_store(uncertain_path)
    try:
        uncertain.add_event(item)
        with pytest.raises(FabricProcessingUncertain, match="without"):
            ingest_fabric_envelope(uncertain, build_pipeline(uncertain), envelope)
    finally:
        uncertain.close()


def test_database_receipt_write_failure_is_not_reported_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = build_store(tmp_path / "control.db")
    pipeline = build_pipeline(store)
    envelope = security_event_envelope(
        event(1),
        produced_at=dt.datetime(2026, 9, 19, 10, 1, tzinfo=dt.UTC),
    )

    def fail_receipt(_receipt: FabricReceipt) -> FabricReceipt:
        raise RuntimeError("simulated postgres interruption")

    monkeypatch.setattr(store, "add_fabric_receipt", fail_receipt)
    try:
        with pytest.raises(RuntimeError, match="postgres interruption"):
            ingest_fabric_envelope(store, pipeline, envelope)
        assert store.get_event("tenant-a", "site-a", envelope.event_id) is None
        assert store.get_fabric_receipt("tenant-a", "site-a", envelope.event_id) is None
    finally:
        store.close()


@pytest.mark.asyncio
async def test_restart_with_queued_sender_state_delivers_after_reopen(
    tmp_path: Path,
) -> None:
    spool_path = tmp_path / "spool.db"
    outbox_path = tmp_path / "outbox.db"
    first_spool = SQLiteEventSpool(
        spool_path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    first_outbox = DurableFabricOutbox(
        outbox_path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    first = SiteController(
        "tenant-a",
        "site-a",
        first_spool,
        fabric_outbox=first_outbox,
    )
    first.ingest(event(1))
    first.ingest(event(2))
    offline = await first.flush()
    assert offline["state"] == "OFFLINE"
    first_outbox.close()
    first_spool.close()

    control = build_store(tmp_path / "control.db")
    publisher = IngressPublisher(control, build_pipeline(control))
    reopened_spool = SQLiteEventSpool(
        spool_path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    reopened_outbox = DurableFabricOutbox(
        outbox_path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    reopened = SiteController(
        "tenant-a",
        "site-a",
        reopened_spool,
        fabric_outbox=reopened_outbox,
        fabric_publisher=publisher,
    )
    try:
        recovered = await reopened.flush()

        assert recovered["state"] == "SYNCED"
        assert reopened_spool.count() == 0
        assert reopened_outbox.diagnostics()["pending"] == 0
        assert [item.event_id for item in publisher.published] == [
            "tenant-a-site-a-event-1",
            "tenant-a-site-a-event-2",
        ]
        assert len(control.list_events("tenant-a", "site-a")) == 2
    finally:
        reopened_outbox.close()
        reopened_spool.close()
        control.close()


@pytest.mark.asyncio
async def test_retry_attempts_are_bounded_per_flush_and_preserve_order(
    tmp_path: Path,
) -> None:
    control = build_store(tmp_path / "control.db")
    publisher = IngressPublisher(
        control,
        build_pipeline(control),
        fail_event_ids={"tenant-a-site-a-event-1"},
    )
    controller, spool, outbox = controller_for(tmp_path, publisher=publisher)
    try:
        for index in range(1, 4):
            controller.ingest(event(index))

        first = await controller.flush()
        second = await controller.flush()

        assert first["state"] == "DEGRADED"
        assert second["state"] == "DEGRADED"
        assert [item.event_id for item in publisher.published] == [
            "tenant-a-site-a-event-1",
            "tenant-a-site-a-event-1",
        ]
        assert outbox.diagnostics()["max_attempts"] == 2
        assert outbox.diagnostics()["pending"] == 3

        publisher.fail_event_ids.clear()
        publisher.published.clear()
        recovered = await controller.flush()

        assert recovered["state"] == "SYNCED"
        assert [item.event_id for item in publisher.published] == [
            "tenant-a-site-a-event-1",
            "tenant-a-site-a-event-2",
            "tenant-a-site-a-event-3",
        ]
    finally:
        outbox.close()
        spool.close()
        control.close()


@pytest.mark.asyncio
async def test_failed_tenant_queue_does_not_block_other_site_scope(
    tmp_path: Path,
) -> None:
    control = build_store(tmp_path / "control.db")
    tenant_a_publisher = IngressPublisher(
        control,
        build_pipeline(control),
        fail_event_ids={"tenant-a-site-a-event-1"},
    )
    tenant_b_publisher = IngressPublisher(control, build_pipeline(control))
    controller_a, spool_a, outbox_a = controller_for(
        tmp_path,
        tenant_id="tenant-a",
        site_id="site-a",
        publisher=tenant_a_publisher,
    )
    controller_b, spool_b, outbox_b = controller_for(
        tmp_path,
        tenant_id="tenant-b",
        site_id="site-b",
        publisher=tenant_b_publisher,
    )
    try:
        controller_a.ingest(event(1, tenant_id="tenant-a", site_id="site-a"))
        controller_b.ingest(event(1, tenant_id="tenant-b", site_id="site-b"))

        failed = await controller_a.flush()
        succeeded = await controller_b.flush()

        assert failed["state"] == "DEGRADED"
        assert succeeded["state"] == "SYNCED"
        assert spool_a.count() == 1
        assert spool_b.count() == 0
        assert outbox_a.diagnostics()["pending"] == 1
        assert outbox_b.diagnostics()["pending"] == 0
        assert len(control.list_events("tenant-a", "site-a")) == 0
        assert len(control.list_events("tenant-b", "site-b")) == 1
    finally:
        outbox_a.close()
        spool_a.close()
        outbox_b.close()
        spool_b.close()
        control.close()


@pytest.mark.asyncio
async def test_load_probe_failure_interval_keeps_raw_evidence_and_can_recover(
    tmp_path: Path,
) -> None:
    path = tmp_path / "fabric-corpus.ndjson"
    envelopes = [
        security_event_envelope(
            event(index),
            produced_at=dt.datetime(2026, 9, 19, 10, 1, tzinfo=dt.UTC)
            + dt.timedelta(seconds=index),
        )
        for index in range(1, 6)
    ]
    path.write_text(
        "\n".join(envelope.canonical_json() for envelope in envelopes) + "\n",
        encoding="utf-8",
    )
    store = build_store(tmp_path / "control.db")
    pipeline = build_pipeline(store)

    async def interrupted_runner(**kwargs) -> probe.ProbeResult:
        raw_envelopes = kwargs["envelopes"]
        succeeded = 0
        for raw in raw_envelopes[:3]:
            ingest_fabric_envelope(
                store,
                pipeline,
                FabricEnvelope.model_validate_json(raw),
            )
            succeeded += 1
        failed = len(raw_envelopes) - succeeded
        return probe.ProbeResult(
            attempted=len(raw_envelopes),
            succeeded=succeeded,
            failed=failed,
            duration_seconds=0.001,
            requests_per_second=len(raw_envelopes) / 0.001,
            latency_ms_p50=1.0,
            latency_ms_p95=1.0,
            latency_ms_p99=1.0,
            status_counts={"200": succeeded, "transport_error": failed},
        )

    try:
        result = await probe.run_soak(
            url="https://example.test/fabric",
            input_path=path,
            concurrency=2,
            duration_seconds=0.01,
            interval_seconds=0.01,
            deployment_topology="synthetic-failure-injection",
            authorization=None,
            timeout_seconds=1.0,
            verify=True,
            cert=None,
            probe_runner=interrupted_runner,
        )

        assert result.successful is False
        assert result.aggregate.attempted == 5
        assert result.aggregate.succeeded == 3
        assert result.intervals[0].status_counts == {
            "200": 3,
            "transport_error": 2,
        }
        assert len(store.list_events("tenant-a", "site-a")) == 3

        for raw in probe.load_envelopes(path):
            ingest_fabric_envelope(
                store,
                pipeline,
                FabricEnvelope.model_validate_json(raw),
            )

        assert len(store.list_events("tenant-a", "site-a")) == 5
        assert result.corpus_sha256 == probe.corpus_sha256(path)
    finally:
        store.close()


def test_reconciled_outbox_compaction_does_not_delete_forensic_evidence(
    tmp_path: Path,
) -> None:
    store = build_store(tmp_path / "control.db")
    pipeline = build_pipeline(store)
    outbox = DurableFabricOutbox(
        tmp_path / "outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        item = event(1)
        envelope = outbox.enqueue_security_event(
            item,
            produced_at=dt.datetime(2026, 9, 19, 10, 1, tzinfo=dt.UTC),
        )
        ingest_fabric_envelope(store, pipeline, envelope)
        outbox.mark_delivered(envelope.event_id)
        outbox.mark_source_reconciled(
            envelope.event_id,
            now=dt.datetime(2026, 9, 19, 10, 2, tzinfo=dt.UTC),
        )

        removed = outbox.compact_reconciled(
            retain_for=dt.timedelta(minutes=1),
            now=dt.datetime(2026, 9, 19, 10, 4, tzinfo=dt.UTC),
        )

        assert removed == 1
        assert store.get_event("tenant-a", "site-a", item.event_id) == item
        receipt = store.get_fabric_receipt("tenant-a", "site-a", item.event_id)
        assert receipt is not None
        assert receipt.status is FabricReceiptStatus.PROCESSED
    finally:
        outbox.close()
        store.close()
