from fastapi.testclient import TestClient

from mon.api import (
    app,
    enforcement_registry,
    store,
)
from mon.auth import Permission, Principal, Role, get_principal
from mon.domain import (
    ActionType,
    Asset,
    EnforcementBinding,
    EnforcementKind,
    EnforcementPoint,
    EnforcementResult,
    EvidenceClass,
    EvidenceRef,
    Incident,
    Severity,
)


class ApiTestAdapter:
    async def execute(self, plan, execution_id):
        return EnforcementResult(
            success=True,
            message="applied in API test",
            external_reference=f"test:{execution_id}",
        )

    async def rollback(self, plan, execution_id):
        return EnforcementResult(
            success=True,
            message="rolled back in API test",
            external_reference=f"test:{execution_id}",
        )


client = TestClient(app)


def prepare_response_fixture(vendor: str, *, critical: bool = False) -> None:
    store.__init__()
    store.add_asset(
        Asset(
            asset_id="asset-1",
            tenant_id="t1",
            site_id="s1",
            display_name="Asset 1",
            criticality="CRITICAL" if critical else "NORMAL",
        )
    )
    store.add_incident(
        Incident(
            incident_id="inc-1",
            tenant_id="t1",
            site_id="s1",
            title="Incident",
            severity=Severity.HIGH,
            confidence=0.97,
            evidence=[
                EvidenceRef(
                    evidence_class=EvidenceClass.NETWORK_FLOW,
                    source="network",
                    summary="network evidence",
                    confidence=0.95,
                ),
                EvidenceRef(
                    evidence_class=EvidenceClass.ENDPOINT,
                    source="endpoint",
                    summary="endpoint evidence",
                    confidence=0.95,
                ),
            ],
            affected_asset_ids={"asset-1"},
        )
    )
    store.add_enforcement_point(
        EnforcementPoint(
            enforcement_point_id="endpoint-1",
            tenant_id="t1",
            site_id="s1",
            kind=EnforcementKind.ENDPOINT,
            vendor=vendor,
            capabilities={ActionType.ISOLATE_ENDPOINT},
        )
    )
    store.add_enforcement_binding(
        EnforcementBinding(
            binding_id="binding-1",
            tenant_id="t1",
            site_id="s1",
            asset_id="asset-1",
            enforcement_point_id="endpoint-1",
            attributes={"blast_radius_estimate": "target endpoint only"},
        )
    )
    enforcement_registry.register(
        EnforcementKind.ENDPOINT,
        vendor,
        ApiTestAdapter(),
    )


def command_payload(request_id: str, *, approve: bool = False) -> dict[str, object]:
    payload: dict[str, object] = {
        "request": {
            "request_id": request_id,
            "tenant_id": "t1",
            "site_id": "s1",
            "incident_id": "inc-1",
            "target": {"asset_id": "asset-1"},
            "action": "ISOLATE_ENDPOINT",
            "ttl_seconds": 300,
            "reason": "contain incident",
            "actor_id": "client-supplied-actor-must-be-ignored",
        },
        "approve": approve,
    }
    if approve:
        payload["approval_reason"] = "reviewed evidence"
    return payload


def test_api_uses_authenticated_actor_and_exposes_response_audit() -> None:
    prepare_response_fixture("api-test-normal")
    response = client.post(
        "/api/v1/responses/execute",
        json=command_payload("request-normal"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "APPLIED"
    assert body["plan"]["request"]["actor_id"] == "pytest-platform-admin"

    audit = client.get(
        "/api/v1/audit",
        params={"tenant_id": "t1", "site_id": "s1"},
    )
    assert audit.status_code == 200
    assert all(item["actor_id"] == "pytest-platform-admin" for item in audit.json())


def test_soc_analyst_cannot_approve_critical_response_but_admin_can() -> None:
    prepare_response_fixture("api-test-critical", critical=True)
    analyst = Principal(
        subject="analyst-1",
        tenant_id="t1",
        roles={Role.SOC_ANALYST},
        site_ids={"s1"},
    )
    app.dependency_overrides[get_principal] = lambda: analyst
    try:
        pending = client.post(
            "/api/v1/responses/execute",
            json=command_payload("request-critical"),
        )
        assert pending.status_code == 200
        assert pending.json()["status"] == "PENDING_APPROVAL"

        forbidden = client.post(
            "/api/v1/responses/execute",
            json=command_payload("request-critical", approve=True),
        )
        assert forbidden.status_code == 403
    finally:
        app.dependency_overrides.pop(get_principal, None)

    admin = Principal(
        subject="tenant-admin-1",
        tenant_id="t1",
        roles={Role.TENANT_ADMIN},
        site_ids={"s1"},
    )
    app.dependency_overrides[get_principal] = lambda: admin
    try:
        approved = client.post(
            "/api/v1/responses/execute",
            json=command_payload("request-critical", approve=True),
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "APPLIED"
        assert approved.json()["approval"]["actor_id"] == "tenant-admin-1"
    finally:
        app.dependency_overrides.pop(get_principal, None)


def test_role_permission_contract_separates_respond_and_approve() -> None:
    analyst = Principal(
        subject="analyst",
        tenant_id="t1",
        roles={Role.SOC_ANALYST},
    )
    admin = Principal(
        subject="admin",
        tenant_id="t1",
        roles={Role.TENANT_ADMIN},
    )
    assert Permission.RESPOND in analyst.permissions
    assert Permission.APPROVE_RESPONSE not in analyst.permissions
    assert Permission.APPROVE_RESPONSE in admin.permissions
