import datetime as dt

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
from mon.enforcement import (
    EnforcementExecutionPlane,
    EnforcementRegistry,
    execution_plane,
)
from mon.response import ResponseOrchestrator
from mon.response_dispatch import ResponseDispatcher
from mon.site_command_models import SiteCommandKind
from mon.site_command_queue import SiteCommandQueue
from mon.store import InMemoryStore


class RecordingAdapter:
    def __init__(self) -> None:
        self.execute_calls = 0

    async def execute(self, plan, execution_id):
        self.execute_calls += 1
        return EnforcementResult(success=True, message="control-plane applied")

    async def rollback(self, plan, execution_id):
        return EnforcementResult(success=True, message="control-plane rolled back")


def prepare(
    *,
    critical: bool = False,
    kind: EnforcementKind = EnforcementKind.ENDPOINT,
    execution_plane_value: str | None = None,
):
    store = InMemoryStore()
    store.add_asset(
        Asset(
            asset_id="asset-1",
            tenant_id="t1",
            site_id="s1",
            display_name="Asset",
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
        )
    )
    attributes = {}
    if execution_plane_value is not None:
        attributes["execution_plane"] = execution_plane_value
    point = EnforcementPoint(
        enforcement_point_id="point-1",
        tenant_id="t1",
        site_id="s1",
        kind=kind,
        vendor="test",
        capabilities={ActionType.ISOLATE_ENDPOINT},
        attributes=attributes,
    )
    store.add_enforcement_point(point)
    store.add_enforcement_binding(
        EnforcementBinding(
            tenant_id="t1",
            site_id="s1",
            asset_id="asset-1",
            enforcement_point_id="point-1",
            attributes={"blast_radius_estimate": "target only"},
        )
    )
    registry = EnforcementRegistry()
    adapter = RecordingAdapter()
    registry.register(kind, "test", adapter)
    orchestrator = ResponseOrchestrator(store, registry)
    queue = SiteCommandQueue(store)
    return (
        store,
        adapter,
        ResponseDispatcher(store, orchestrator, queue),
        point,
    )


def request(action: ActionType = ActionType.ISOLATE_ENDPOINT) -> ResponseRequest:
    return ResponseRequest(
        request_id="response-1",
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(asset_id="asset-1"),
        action=action,
        ttl_seconds=300,
        reason="contain incident",
    )


@pytest.mark.asyncio
async def test_local_enforcement_is_queued_not_run_in_control_plane() -> None:
    store, adapter, dispatcher, _ = prepare()
    first = await dispatcher.dispatch(request())
    second = await dispatcher.dispatch(request())

    assert first.status is ResponseExecutionStatus.DISPATCH_PENDING
    assert second == first
    assert adapter.execute_calls == 0
    commands = store.list_site_commands("t1", "s1")
    assert len(commands) == 1
    assert commands[0].command.kind is SiteCommandKind.APPLY_RESPONSE
    assert commands[0].command.response_plan is not None
    assert commands[0].command.response_plan.request.actor_id == "mon-automation"


@pytest.mark.asyncio
async def test_pending_approval_dispatches_stored_plan_not_tampered_request() -> None:
    store, adapter, dispatcher, _ = prepare(critical=True)
    original = request()
    pending = await dispatcher.dispatch(original)
    assert pending.status is ResponseExecutionStatus.PENDING_APPROVAL

    tampered = original.model_copy(
        update={
            "action": ActionType.BLOCK_IP,
            "reason": "tampered after approval request",
        }
    )
    dispatched = await dispatcher.dispatch(
        tampered,
        approval=ResponseApproval(
            actor_id="tenant-admin",
            reason="approved original plan",
        ),
    )

    assert dispatched.status is ResponseExecutionStatus.DISPATCH_PENDING
    assert adapter.execute_calls == 0
    commands = store.list_site_commands("t1", "s1")
    assert len(commands) == 1
    plan = commands[0].command.response_plan
    assert plan is not None
    assert plan.request.action is ActionType.ISOLATE_ENDPOINT


@pytest.mark.asyncio
async def test_control_plane_override_executes_registered_adapter() -> None:
    store, adapter, dispatcher, point = prepare(
        execution_plane_value="CONTROL_PLANE"
    )
    assert execution_plane(point) is EnforcementExecutionPlane.CONTROL_PLANE

    result = await dispatcher.dispatch(request())
    assert result.status is ResponseExecutionStatus.APPLIED
    assert adapter.execute_calls == 1
    assert store.list_site_commands("t1", "s1") == []


@pytest.mark.asyncio
async def test_site_rollback_is_queued_once() -> None:
    store, _, dispatcher, _ = prepare()
    dispatched = await dispatcher.dispatch(request())
    applied = dispatched.model_copy(
        update={
            "status": ResponseExecutionStatus.APPLIED,
            "applied_at": dt.datetime.now(dt.UTC),
            "expires_at": dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5),
        }
    )
    store.add_response_execution(applied)

    first = await dispatcher.rollback(
        "t1",
        "s1",
        applied.execution_id,
        actor_id="operator",
        reason="operator rollback",
    )
    second = await dispatcher.rollback(
        "t1",
        "s1",
        applied.execution_id,
        actor_id="operator",
        reason="duplicate request",
    )

    assert first.status is ResponseExecutionStatus.ROLLBACK_PENDING
    assert second.status is ResponseExecutionStatus.ROLLBACK_PENDING
    rollback_commands = [
        record
        for record in store.list_site_commands("t1", "s1")
        if record.command.kind is SiteCommandKind.ROLLBACK_RESPONSE
    ]
    assert len(rollback_commands) == 1


def test_default_execution_planes_and_invalid_override() -> None:
    _, _, _, endpoint = prepare()
    assert execution_plane(endpoint) is EnforcementExecutionPlane.SITE

    cloud = endpoint.model_copy(update={"kind": EnforcementKind.CLOUD})
    assert execution_plane(cloud) is EnforcementExecutionPlane.CONTROL_PLANE
