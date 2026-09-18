import pytest

from mon.domain import (
    ActionType,
    Asset,
    EnforcementBinding,
    EnforcementKind,
    EnforcementPoint,
    EvidenceClass,
    EvidenceRef,
    Incident,
    ResponseExecutionStatus,
    ResponseRequest,
    ResponseTarget,
    Severity,
)
from mon.enforcement import EnforcementRegistry
from mon.response import ResponseOrchestrator
from mon.store import InMemoryStore


def prepared_orchestrator() -> tuple[ResponseOrchestrator, ResponseRequest]:
    store = InMemoryStore()
    store.add_asset(
        Asset(
            asset_id="host-1",
            tenant_id="t1",
            site_id="s1",
            display_name="Host",
        )
    )
    store.add_incident(
        Incident(
            incident_id="inc-1",
            tenant_id="t1",
            site_id="s1",
            title="Incident",
            severity=Severity.HIGH,
            confidence=0.99,
            evidence=[
                EvidenceRef(
                    evidence_class=EvidenceClass.NETWORK_FLOW,
                    source="n",
                    summary="network",
                    confidence=0.9,
                ),
                EvidenceRef(
                    evidence_class=EvidenceClass.ENDPOINT,
                    source="e",
                    summary="endpoint",
                    confidence=0.9,
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
            vendor="missing",
            capabilities={ActionType.ISOLATE_ENDPOINT},
        )
    )
    store.add_enforcement_binding(
        EnforcementBinding(
            tenant_id="t1",
            site_id="s1",
            asset_id="host-1",
            enforcement_point_id="host-fw",
            attributes={"blast_radius_estimate": "target endpoint only"},
        )
    )
    request = ResponseRequest(
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(asset_id="host-1"),
        action=ActionType.ISOLATE_ENDPOINT,
        ttl_seconds=300,
        reason="test",
    )
    return ResponseOrchestrator(store, EnforcementRegistry()), request


@pytest.mark.asyncio
async def test_missing_adapter_fails_closed() -> None:
    orchestrator, request = prepared_orchestrator()
    result = await orchestrator.execute(request)
    assert result.status is ResponseExecutionStatus.FAILED
    assert result.error is not None
    assert "no enforcement adapter" in result.error
