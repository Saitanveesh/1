import datetime as dt

import pytest

from mon.database import DatabaseStore
from mon.domain import SecurityEvent
from mon.event_fabric import (
    FabricReceipt,
    FabricReceiptStatus,
    security_event_envelope,
)
from mon.fabric_ingress import (
    FabricEnvelopeCollision,
    FabricEnvelopeInvalid,
    FabricProcessingUncertain,
    ingest_fabric_envelope,
)
from mon.pipeline import PipelinePersistenceMode, SecurityPipeline


def event(
    event_id: str = "fabric-event-1",
    *,
    tenant_id: str = "tenant-a",
    site_id: str = "site-a",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id="sensor-1",
        observed_at=dt.datetime(2026, 9, 19, 9, 0, tzinfo=dt.UTC),
        category="network.connection",
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        protocol="tcp",
        attributes={"dst_port": 443},
    )


def build_store(tmp_path) -> DatabaseStore:
    return DatabaseStore(
        f"sqlite+pysqlite:///{tmp_path / 'control.db'}",
        create_schema=True,
    )


def build_pipeline(store: DatabaseStore) -> SecurityPipeline:
    return SecurityPipeline(
        store=store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )


def test_fabric_ingress_processes_once_and_completes_exact_receipt(
    tmp_path,
) -> None:
    store = build_store(tmp_path)
    pipeline = build_pipeline(store)
    envelope = security_event_envelope(
        event(),
        produced_at=dt.datetime(2026, 9, 19, 9, 1, tzinfo=dt.UTC),
    )
    try:
        first = ingest_fabric_envelope(store, pipeline, envelope)
        second = ingest_fabric_envelope(store, pipeline, envelope)

        assert first.acknowledgement.duplicate is False
        assert first.processing_result is not None
        assert second.acknowledgement.duplicate is True
        assert second.processing_result is None
        assert store.event_processed(
            "tenant-a",
            "site-a",
            "fabric-event-1",
        )
        receipt = store.get_fabric_receipt(
            "tenant-a",
            "site-a",
            "fabric-event-1",
        )
        assert receipt is not None
        assert receipt.status is FabricReceiptStatus.PROCESSED
        assert receipt.envelope_sha256 == envelope.canonical_sha256
        assert receipt.envelope_json == envelope.canonical_json()
    finally:
        store.close()


def test_same_event_id_with_changed_producer_time_is_collision(tmp_path) -> None:
    store = build_store(tmp_path)
    pipeline = build_pipeline(store)
    item = event()
    first = security_event_envelope(
        item,
        produced_at=dt.datetime(2026, 9, 19, 9, 1, tzinfo=dt.UTC),
    )
    changed = security_event_envelope(
        item,
        produced_at=dt.datetime(2026, 9, 19, 9, 2, tzinfo=dt.UTC),
    )
    try:
        ingest_fabric_envelope(store, pipeline, first)
        with pytest.raises(FabricEnvelopeCollision, match="different envelope"):
            ingest_fabric_envelope(store, pipeline, changed)
    finally:
        store.close()


def test_outer_inner_identity_mismatch_is_invalid_not_claimed(tmp_path) -> None:
    store = build_store(tmp_path)
    pipeline = build_pipeline(store)
    original = security_event_envelope(
        event(),
        produced_at=dt.datetime(2026, 9, 19, 9, 1, tzinfo=dt.UTC),
    )
    invalid = original.model_copy(update={"source": "sensor-other"})
    try:
        with pytest.raises(FabricEnvelopeInvalid, match="source"):
            ingest_fabric_envelope(store, pipeline, invalid)
        assert (
            store.get_fabric_receipt(
                "tenant-a",
                "site-a",
                "fabric-event-1",
            )
            is None
        )
        assert (
            store.get_event("tenant-a", "site-a", "fabric-event-1")
            is None
        )
    finally:
        store.close()


def test_failed_domain_processing_keeps_pending_claim_and_retries_exactly(
    tmp_path,
    monkeypatch,
) -> None:
    store = build_store(tmp_path)
    pipeline = build_pipeline(store)
    envelope = security_event_envelope(
        event(),
        produced_at=dt.datetime(2026, 9, 19, 9, 1, tzinfo=dt.UTC),
    )
    original_add_asset = store.add_asset

    def fail_add_asset(asset):
        raise RuntimeError("simulated derived-state failure")

    monkeypatch.setattr(store, "add_asset", fail_add_asset)
    try:
        with pytest.raises(RuntimeError, match="derived-state"):
            ingest_fabric_envelope(store, pipeline, envelope)

        assert (
            store.get_event("tenant-a", "site-a", "fabric-event-1")
            is None
        )
        receipt = store.get_fabric_receipt(
            "tenant-a",
            "site-a",
            "fabric-event-1",
        )
        assert receipt is not None
        assert receipt.status is FabricReceiptStatus.PENDING

        monkeypatch.setattr(store, "add_asset", original_add_asset)
        retried = ingest_fabric_envelope(store, pipeline, envelope)

        assert retried.acknowledgement.duplicate is False
        assert store.event_processed(
            "tenant-a",
            "site-a",
            "fabric-event-1",
        )
        completed = store.get_fabric_receipt(
            "tenant-a",
            "site-a",
            "fabric-event-1",
        )
        assert completed is not None
        assert completed.status is FabricReceiptStatus.PROCESSED
    finally:
        store.close()


def test_existing_event_without_processing_receipt_is_uncertain(tmp_path) -> None:
    store = build_store(tmp_path)
    pipeline = build_pipeline(store)
    item = event()
    envelope = security_event_envelope(
        item,
        produced_at=dt.datetime(2026, 9, 19, 9, 1, tzinfo=dt.UTC),
    )
    try:
        # Simulates pre-0006 durable event history where completion cannot be
        # proven and therefore must not be silently backfilled.
        store.add_event(item)

        with pytest.raises(FabricProcessingUncertain, match="without"):
            ingest_fabric_envelope(store, pipeline, envelope)

        receipt = store.get_fabric_receipt(
            "tenant-a",
            "site-a",
            "fabric-event-1",
        )
        assert receipt is not None
        assert receipt.status is FabricReceiptStatus.PENDING
    finally:
        store.close()


def test_processed_event_recovers_pending_fabric_receipt_after_restart(
    tmp_path,
) -> None:
    path = tmp_path / "control.db"
    first = DatabaseStore(
        f"sqlite+pysqlite:///{path}",
        create_schema=True,
    )
    item = event()
    envelope = security_event_envelope(
        item,
        produced_at=dt.datetime(2026, 9, 19, 9, 1, tzinfo=dt.UTC),
    )
    pipeline = build_pipeline(first)
    result = pipeline.process_event(item)
    assert result.duplicate is False
    first.add_fabric_receipt(
        # Simulate crash after event transaction committed but before the
        # fabric receipt was completed.
        FabricReceipt(
            event_id=envelope.event_id,
            tenant_id=envelope.tenant_id,
            site_id=envelope.site_id,
            envelope_sha256=envelope.canonical_sha256,
            envelope_json=envelope.canonical_json(),
            received_at=dt.datetime(2026, 9, 19, 9, 2, tzinfo=dt.UTC),
        )
    )
    first.close()

    second = DatabaseStore(f"sqlite+pysqlite:///{path}")
    second_pipeline = build_pipeline(second)
    try:
        recovered = ingest_fabric_envelope(
            second,
            second_pipeline,
            envelope,
        )
        assert recovered.acknowledgement.duplicate is True
        receipt = second.get_fabric_receipt(
            "tenant-a",
            "site-a",
            "fabric-event-1",
        )
        assert receipt is not None
        assert receipt.status is FabricReceiptStatus.PROCESSED
    finally:
        second.close()
