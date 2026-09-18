from fastapi.testclient import TestClient

from mon.api import app, store
from mon.domain import (
    ActionType,
    Asset,
    EnforcementBinding,
    EnforcementKind,
    EnforcementPoint,
    Incident,
    Severity,
)

client = TestClient(app)


def setup_function() -> None:
    store.__init__()


def test_enforcement_inventory_and_investigation_are_scope_filtered() -> None:
    store.add_asset(
        Asset(
            asset_id="asset-1",
            tenant_id="t1",
            site_id="s1",
            display_name="Asset 1",
        )
    )
    store.add_incident(
        Incident(
            incident_id="inc-1",
            tenant_id="t1",
            site_id="s1",
            title="Incident",
            severity=Severity.HIGH,
            confidence=0.9,
            affected_asset_ids={"asset-1"},
        )
    )
    store.add_enforcement_point(
        EnforcementPoint(
            enforcement_point_id="fw-1",
            tenant_id="t1",
            site_id="s1",
            kind=EnforcementKind.FIREWALL,
            vendor="generic",
            capabilities={ActionType.BLOCK_IP},
        )
    )
    store.add_enforcement_binding(
        EnforcementBinding(
            binding_id="bind-1",
            tenant_id="t1",
            site_id="s1",
            asset_id="asset-1",
            enforcement_point_id="fw-1",
        )
    )

    points = client.get(
        "/api/v1/enforcement-points",
        params={"tenant_id": "t1", "site_id": "s1"},
    )
    other = client.get(
        "/api/v1/enforcement-points",
        params={"tenant_id": "other", "site_id": "s1"},
    )
    investigation = client.get(
        "/api/v1/incidents/inc-1/investigation",
        params={"tenant_id": "t1", "site_id": "s1"},
    )

    assert points.status_code == 200
    assert [item["enforcement_point_id"] for item in points.json()] == ["fw-1"]
    assert other.json() == []
    assert investigation.status_code == 200
    assert investigation.json()["containment_capabilities"][0]["asset_id"] == "asset-1"
