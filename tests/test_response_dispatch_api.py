from fastapi.testclient import TestClient

from mon.api import app, store
from mon.domain import (
    ActionType,
    Asset,
    EnforcementBinding,
    EnforcementKind,
    EnforcementPoint,
    EvidenceClass,
    EvidenceRef,
    Incident,
    Severity,
)


client = TestClient(app)


def test_endpoint_response_api_dispatches_to_site_queue() -> None:
    store.__init__()
    store.add_asset(
        Asset(
            asset_id="endpoint-1",
            tenant_id="t1",
            site_id="s1",
            display_name="Endpoint",
        )
    )
    store.add_incident(
        Incident(
            incident_id="inc-1",
            tenant_id="t1",
            site_id="s1",
            title="Incident",
            severity=Severity.HIGH,
            confidence=0.98,
            evidence=[
                EvidenceRef(
                    evidence_class=EvidenceClass.NETWORK_FLOW,
                    source="network",
                    summary="network",
                    confidence=0.95,
                ),
                EvidenceRef(
                    evidence_class=EvidenceClass.ENDPOINT,
                    source="endpoint",
                    summary="endpoint",
                    confidence=0.95,
                ),
            ],
        )
    )
    store.add_enforcement_point(
        EnforcementPoint(
            enforcement_point_id="host-fw",
            tenant_id="t1",
            site_id="s1",
            kind=EnforcementKind.ENDPOINT,
            vendor="site-only",
            capabilities={ActionType.ISOLATE_ENDPOINT},
        )
    )
    store.add_enforcement_binding(
        EnforcementBinding(
            tenant_id="t1",
            site_id="s1",
            asset_id="endpoint-1",
            enforcement_point_id="host-fw",
            attributes={"blast_radius_estimate": "target endpoint only"},
        )
    )

    payload = {
        "request": {
            "request_id": "dispatch-api-1",
            "tenant_id": "t1",
            "site_id": "s1",
            "incident_id": "inc-1",
            "target": {"asset_id": "endpoint-1"},
            "action": "ISOLATE_ENDPOINT",
            "ttl_seconds": 300,
            "reason": "contain endpoint",
        }
    }
    first = client.post("/api/v1/responses/execute", json=payload)
    second = client.post("/api/v1/responses/execute", json=payload)

    assert first.status_code == 200
    assert first.json()["status"] == "DISPATCH_PENDING"
    assert second.json()["execution_id"] == first.json()["execution_id"]
    commands = store.list_site_commands("t1", "s1")
    assert len(commands) == 1
