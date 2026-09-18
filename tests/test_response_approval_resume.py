import pytest

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
    ResponseApproval,
    ResponseExecutionStatus,
    ResponseRequest,
    ResponseTarget,
    Severity,
)
from mon.enforcement import EnforcementRegistry
from mon.response import ResponseOrchestrator
from mon.store import InMemoryStore


class RecordingAdapter:
    def __init__(self) -> None:
        self.actions: list[str] = []

    async def execute(self, plan, execution_id):
        self.actions.append(plan.request.action.value)
        return EnforcementResult(success=True, message="applied")

    async def rollback(self, plan, execution_id):
        return EnforcementResult(success=True, message="rolled back")


@pytest.mark.asyncio
async def test_pending_approval_resumes_stored_plan_not_modified_payload() -> None:
    store = InMemoryStore()
    store.add_asset(
        Asset(
            asset_id="asset-1",
            tenant_id="t1",
            site_id="s1",
            display_name="Critical asset",
            criticality="CRITICAL",
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
                    summary="n",
                    confidence=0.9,
                ),
                EvidenceRef(
                    evidence_class=EvidenceClass.ENDPOINT,
                    source="e",
                    summary="e",
                    confidence=0.9,
                ),
            ],
        )
    )
    point = EnforcementPoint(
        enforcement_point_id="endpoint-1",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.ENDPOINT,
        vendor="test",
        capabilities={ActionType.ISOLATE_ENDPOINT, ActionType.BLOCK_IP},
    )
    store.add_enforcement_point(point)
    store.add_enforcement_binding(
        EnforcementBinding(
            tenant_id="t1",
            site_id="s1",
            asset_id="asset-1",
            enforcement_point_id="endpoint-1",
            attributes={"blast_radius_estimate": "target endpoint only"},
        )
    )
    registry = EnforcementRegistry()
    adapter = RecordingAdapter()
    registry.register(EnforcementKind.ENDPOINT, "test", adapter)
    orchestrator = ResponseOrchestrator(store, registry)

    original = ResponseRequest(
        request_id="request-1",
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(asset_id="asset-1"),
        action=ActionType.ISOLATE_ENDPOINT,
        ttl_seconds=300,
        reason="original",
    )
    pending = await orchestrator.execute(original)
    assert pending.status is ResponseExecutionStatus.PENDING_APPROVAL

    tampered = original.model_copy(
        update={
            "action": ActionType.BLOCK_IP,
            "reason": "modified after pending approval",
        }
    )
    applied = await orchestrator.execute(
        tampered,
        approval=ResponseApproval(
            actor_id="admin",
            reason="approved stored plan",
        ),
    )

    assert applied.status is ResponseExecutionStatus.APPLIED
    assert applied.plan.request.action is ActionType.ISOLATE_ENDPOINT
    assert adapter.actions == ["ISOLATE_ENDPOINT"]
    audit = store.list_audit_records("t1", "s1")
    assert [item.outcome for item in audit] == [
        "PENDING_APPROVAL",
        "APPROVED",
        "STARTED",
        "APPLIED",
    ]
