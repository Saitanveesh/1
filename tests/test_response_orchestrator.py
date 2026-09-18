import datetime as dt

import pytest

from mon.domain import (
    ActionType,
    ActorType,
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
        self.execute_calls = 0
        self.rollback_calls = 0

    async def execute(self, plan, execution_id):
        self.execute_calls += 1
        return EnforcementResult(
            success=True,
            message="temporary isolation applied",
            external_reference=f"rule:{execution_id}",
        )

    async def rollback(self, plan, execution_id):
        self.rollback_calls += 1
        return EnforcementResult(
            success=True,
            message="temporary isolation removed",
            external_reference=f"rule:{execution_id}",
        )


def setup_system(*, critical: bool = False, blast_radius: bool = True):
    store = InMemoryStore()
    asset = Asset(
        asset_id="host-1",
        tenant_id="t1",
        site_id="s1",
        display_name="Host 1",
        criticality="CRITICAL" if critical else "NORMAL",
    )
    store.add_asset(asset)
    store.add_incident(
        Incident(
            incident_id="inc-1",
            tenant_id="t1",
            site_id="s1",
            title="Correlated lateral activity",
            severity=Severity.HIGH,
            confidence=0.97,
            evidence=[
                EvidenceRef(
                    evidence_class=EvidenceClass.NETWORK_FLOW,
                    source="network",
                    summary="east-west fanout",
                    confidence=0.95,
                ),
                EvidenceRef(
                    evidence_class=EvidenceClass.ENDPOINT,
                    source="endpoint",
                    summary="process network evidence",
                    confidence=0.95,
                ),
            ],
            affected_asset_ids={"host-1"},
        )
    )
    point = EnforcementPoint(
        enforcement_point_id="host-fw",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.ENDPOINT,
        vendor="test",
        capabilities={ActionType.ISOLATE_ENDPOINT},
    )
    store.add_enforcement_point(point)
    attributes = {"blast_radius_estimate": "target endpoint only"} if blast_radius else {}
    store.add_enforcement_binding(
        EnforcementBinding(
            tenant_id="t1",
            site_id="s1",
            asset_id="host-1",
            enforcement_point_id="host-fw",
            distance=0,
            attributes=attributes,
        )
    )
    registry = EnforcementRegistry()
    adapter = RecordingAdapter()
    registry.register(EnforcementKind.ENDPOINT, "test", adapter)
    return store, ResponseOrchestrator(store, registry), adapter


def request(request_id: str = "req-1") -> ResponseRequest:
    return ResponseRequest(
        request_id=request_id,
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(asset_id="host-1"),
        action=ActionType.ISOLATE_ENDPOINT,
        actor_type=ActorType.AUTOMATION,
        actor_id="mon-automation",
        ttl_seconds=900,
        reason="contain correlated lateral activity",
    )


@pytest.mark.asyncio
async def test_execution_is_idempotent_and_has_ttl_and_audit() -> None:
    store, orchestrator, adapter = setup_system()
    first = await orchestrator.execute(request())
    second = await orchestrator.execute(request())

    assert first.status is ResponseExecutionStatus.APPLIED
    assert second.execution_id == first.execution_id
    assert adapter.execute_calls == 1
    assert first.expires_at is not None
    assert first.expires_at > first.applied_at
    assert first.plan.blast_radius_estimate == "target endpoint only"
    assert [item.outcome for item in store.list_audit_records("t1", "s1")] == [
        "STARTED",
        "APPLIED",
    ]


@pytest.mark.asyncio
async def test_unknown_blast_radius_requires_approval_and_does_not_execute() -> None:
    _, orchestrator, adapter = setup_system(blast_radius=False)
    result = await orchestrator.execute(request())

    assert result.status is ResponseExecutionStatus.PENDING_APPROVAL
    assert adapter.execute_calls == 0
    assert "blast-radius estimate is unavailable" in result.plan.decision.reasons


@pytest.mark.asyncio
async def test_approved_critical_asset_can_execute_and_rollback() -> None:
    store, orchestrator, adapter = setup_system(critical=True)
    approval = ResponseApproval(
        actor_id="tenant-admin",
        reason="validated incident evidence and maintenance impact",
    )
    applied = await orchestrator.execute(request(), approval=approval)
    assert applied.status is ResponseExecutionStatus.APPLIED
    assert applied.approval == approval

    rolled_back = await orchestrator.rollback(
        "t1",
        "s1",
        applied.execution_id,
        actor_id="tenant-admin",
    )
    duplicate = await orchestrator.rollback(
        "t1",
        "s1",
        applied.execution_id,
        actor_id="tenant-admin",
    )

    assert rolled_back.status is ResponseExecutionStatus.ROLLED_BACK
    assert duplicate.status is ResponseExecutionStatus.ROLLED_BACK
    assert adapter.rollback_calls == 1
    outcomes = [item.outcome for item in store.list_audit_records("t1", "s1")]
    assert outcomes[-2:] == ["STARTED", "ROLLED_BACK"]


@pytest.mark.asyncio
async def test_due_for_rollback_only_returns_expired_applied_actions() -> None:
    _, orchestrator, _ = setup_system()
    applied = await orchestrator.execute(request())
    assert applied.expires_at is not None

    before = orchestrator.due_for_rollback(
        "t1",
        "s1",
        now=applied.expires_at - dt.timedelta(seconds=1),
    )
    after = orchestrator.due_for_rollback(
        "t1",
        "s1",
        now=applied.expires_at + dt.timedelta(seconds=1),
    )

    assert before == []
    assert [item.execution_id for item in after] == [applied.execution_id]
