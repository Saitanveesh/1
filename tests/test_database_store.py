import datetime as dt

from mon.database import Base, DatabaseStore
from mon.domain import (
    ActionType,
    Asset,
    EnforcementBinding,
    EnforcementKind,
    EnforcementPoint,
    Finding,
    Incident,
    SecurityEvent,
    Severity,
)


def test_database_store_persists_and_scopes_objects(tmp_path) -> None:
    url = f"sqlite+pysqlite:///{tmp_path / 'mon.db'}"
    first = DatabaseStore(url, create_schema=True)

    event = SecurityEvent(
        event_id="event-1",
        tenant_id="tenant-a",
        site_id="site-1",
        sensor_id="sensor",
        observed_at=dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC),
        category="network.connection",
    )
    first.add_event(event)
    first.add_event(event)

    first.add_finding(
        Finding(
            finding_id="finding-1",
            tenant_id="tenant-a",
            site_id="site-1",
            detector_id="test",
            title="test finding",
            severity=Severity.MEDIUM,
            confidence=0.8,
        )
    )
    first.add_incident(
        Incident(
            incident_id="incident-1",
            tenant_id="tenant-a",
            site_id="site-1",
            title="test incident",
            severity=Severity.HIGH,
            confidence=0.9,
        )
    )
    first.add_asset(
        Asset(
            asset_id="asset-1",
            tenant_id="tenant-a",
            site_id="site-1",
            display_name="Asset 1",
        )
    )
    first.add_enforcement_point(
        EnforcementPoint(
            enforcement_point_id="fw-1",
            tenant_id="tenant-a",
            site_id="site-1",
            kind=EnforcementKind.FIREWALL,
            vendor="generic",
            capabilities={ActionType.BLOCK_IP},
        )
    )
    first.add_enforcement_binding(
        EnforcementBinding(
            binding_id="binding-1",
            tenant_id="tenant-a",
            site_id="site-1",
            asset_id="asset-1",
            enforcement_point_id="fw-1",
        )
    )
    first.close()

    second = DatabaseStore(url)
    assert second.event_exists("tenant-a", "site-1", "event-1")
    assert not second.event_exists("tenant-b", "site-1", "event-1")
    assert [item.finding_id for item in second.list_findings("tenant-a", "site-1")] == [
        "finding-1"
    ]
    assert second.get_incident("tenant-a", "site-1", "incident-1") is not None
    assert second.get_incident("tenant-b", "site-1", "incident-1") is None
    assert second.get_asset("tenant-a", "site-1", "asset-1") is not None
    assert second.get_enforcement_point("tenant-a", "site-1", "fw-1") is not None
    assert [
        item.binding_id
        for item in second.list_enforcement_bindings("tenant-a", "site-1", "asset-1")
    ] == ["binding-1"]
    second.close()


def test_schema_metadata_contains_authoritative_tables() -> None:
    assert {
        "security_events",
        "site_commands",
        "findings",
        "incidents",
        "assets",
        "enforcement_points",
        "enforcement_bindings",
    }.issubset(Base.metadata.tables)
