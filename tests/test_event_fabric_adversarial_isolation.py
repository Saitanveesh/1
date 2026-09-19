from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from mon.database import DatabaseStore
from mon.domain import SecurityEvent
from mon.event_fabric import FabricEnvelope, security_event_envelope
from mon.fabric_ingress import FabricEnvelopeInvalid, ingest_fabric_envelope
from mon.pipeline import PipelinePersistenceMode, SecurityPipeline


def event(*, tenant_id: str, site_id: str, event_id: str = "shared-event") -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=f"sensor-{tenant_id}-{site_id}",
        observed_at=dt.datetime(2026, 9, 19, 12, 0, tzinfo=dt.UTC),
        category="network.connection",
        asset_id=f"asset-{tenant_id}-{site_id}",
        src_ip="10.10.0.10",
        dst_ip="10.10.0.20",
        protocol="tcp",
        attributes={"dst_port": 443, "tcp_syn": True},
    )


def store_and_pipeline(tmp_path: Path) -> tuple[DatabaseStore, SecurityPipeline]:
    store = DatabaseStore(
        f"sqlite+pysqlite:///{tmp_path / 'control.db'}",
        create_schema=True,
    )
    pipeline = SecurityPipeline(
        store=store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    return store, pipeline


def mutate_envelope(envelope: FabricEnvelope, **changes: object) -> FabricEnvelope:
    body = envelope.model_dump(mode="python")
    body.update(changes)
    return FabricEnvelope.model_validate(body)


def test_forged_outer_tenant_cannot_relabel_payload_scope(tmp_path: Path) -> None:
    store, pipeline = store_and_pipeline(tmp_path)
    original = security_event_envelope(
        event(tenant_id="tenant-a", site_id="site-a"),
        produced_at=dt.datetime(2026, 9, 19, 12, 1, tzinfo=dt.UTC),
    )
    forged = mutate_envelope(original, tenant_id="tenant-b")

    with pytest.raises(FabricEnvelopeInvalid, match="tenant/site"):
        ingest_fabric_envelope(store, pipeline, forged)

    assert store.get_event("tenant-a", "site-a", original.event_id) is None
    assert store.get_event("tenant-b", "site-a", original.event_id) is None


def test_forged_outer_site_cannot_relabel_payload_scope(tmp_path: Path) -> None:
    store, pipeline = store_and_pipeline(tmp_path)
    original = security_event_envelope(
        event(tenant_id="tenant-a", site_id="site-a"),
        produced_at=dt.datetime(2026, 9, 19, 12, 1, tzinfo=dt.UTC),
    )
    forged = mutate_envelope(original, site_id="site-b")

    with pytest.raises(FabricEnvelopeInvalid, match="tenant/site"):
        ingest_fabric_envelope(store, pipeline, forged)

    assert store.get_event("tenant-a", "site-a", original.event_id) is None
    assert store.get_event("tenant-a", "site-b", original.event_id) is None


def test_forged_source_identity_is_rejected_before_persistence(tmp_path: Path) -> None:
    store, pipeline = store_and_pipeline(tmp_path)
    original = security_event_envelope(
        event(tenant_id="tenant-a", site_id="site-a"),
        produced_at=dt.datetime(2026, 9, 19, 12, 1, tzinfo=dt.UTC),
    )
    forged = mutate_envelope(original, source="sensor-tenant-b-site-b")

    with pytest.raises(FabricEnvelopeInvalid, match="source"):
        ingest_fabric_envelope(store, pipeline, forged)

    assert store.get_event("tenant-a", "site-a", original.event_id) is None


def test_same_event_id_is_isolated_across_tenant_site_scopes(tmp_path: Path) -> None:
    store, pipeline = store_and_pipeline(tmp_path)
    produced_at = dt.datetime(2026, 9, 19, 12, 1, tzinfo=dt.UTC)
    envelope_a = security_event_envelope(
        event(tenant_id="tenant-a", site_id="site-a"),
        produced_at=produced_at,
    )
    envelope_b = security_event_envelope(
        event(tenant_id="tenant-b", site_id="site-b"),
        produced_at=produced_at,
    )

    outcome_a = ingest_fabric_envelope(store, pipeline, envelope_a)
    outcome_b = ingest_fabric_envelope(store, pipeline, envelope_b)

    assert outcome_a.acknowledgement.duplicate is False
    assert outcome_b.acknowledgement.duplicate is False
    stored_a = store.get_event("tenant-a", "site-a", "shared-event")
    stored_b = store.get_event("tenant-b", "site-b", "shared-event")
    assert stored_a is not None
    assert stored_b is not None
    assert stored_a.tenant_id == "tenant-a"
    assert stored_b.tenant_id == "tenant-b"
