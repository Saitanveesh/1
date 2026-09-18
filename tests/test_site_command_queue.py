import datetime as dt

from mon.domain import (
    ActionType,
    AuditRecord,
    EnforcementKind,
    EnforcementPoint,
    EnforcementResult,
    PolicyDecision,
    PolicyOutcome,
    ResponseExecution,
    ResponseExecutionStatus,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
)
from mon.site_command_models import (
    SiteCommand,
    SiteCommandKind,
    SiteCommandResult,
    SiteCommandStatus,
)
from mon.site_command_queue import SiteCommandQueue
from mon.store import InMemoryStore

NOW = dt.datetime(2026, 9, 19, 0, 0, tzinfo=dt.UTC)


def response_plan(request_id: str = "response-1") -> ResponsePlan:
    request = ResponseRequest(
        request_id=request_id,
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(ip_address="198.51.100.7"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="fw-1",
        ttl_seconds=300,
        reason="contain source",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw-1",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.FIREWALL,
        vendor="test",
        capabilities={ActionType.BLOCK_IP},
    )
    return ResponsePlan(
        request=request,
        decision=PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["test"]),
        enforcement_point=point,
        blast_radius_estimate="single source rule",
    )


def apply_command(command_id: str = "command-1") -> SiteCommand:
    return SiteCommand(
        command_id=command_id,
        tenant_id="t1",
        site_id="s1",
        kind=SiteCommandKind.APPLY_RESPONSE,
        created_at=NOW,
        not_after=NOW + dt.timedelta(minutes=5),
        response_plan=response_plan(),
    )


def test_pending_delivery_is_at_least_once_and_counted() -> None:
    store = InMemoryStore()
    queue = SiteCommandQueue(store)
    queue.enqueue(apply_command())

    first = queue.pending("t1", "s1", now=NOW + dt.timedelta(seconds=1))
    second = queue.pending("t1", "s1", now=NOW + dt.timedelta(seconds=2))

    assert [item.command_id for item in first] == ["command-1"]
    assert [item.command_id for item in second] == ["command-1"]
    record = store.get_site_command("t1", "s1", "command-1")
    assert record is not None
    assert record.delivery_count == 2


def test_expired_command_is_not_delivered() -> None:
    store = InMemoryStore()
    queue = SiteCommandQueue(store)
    queue.enqueue(apply_command())

    assert queue.pending(
        "t1",
        "s1",
        now=NOW + dt.timedelta(minutes=6),
    ) == []
    record = store.get_site_command("t1", "s1", "command-1")
    assert record is not None
    assert record.status is SiteCommandStatus.EXPIRED


def test_completion_mirrors_execution_and_audit() -> None:
    store = InMemoryStore()
    queue = SiteCommandQueue(store)
    command = apply_command()
    queue.enqueue(command)
    plan = command.response_plan
    assert plan is not None
    execution = ResponseExecution(
        execution_id="response-1",
        tenant_id="t1",
        site_id="s1",
        plan=plan,
        status=ResponseExecutionStatus.APPLIED,
        result=EnforcementResult(success=True, message="applied"),
    )
    audit = AuditRecord(
        audit_id="audit-1",
        tenant_id="t1",
        site_id="s1",
        actor_id="operator",
        category="SITE_RESPONSE",
        object_type="response_execution",
        object_id="response-1",
        action="EXECUTE",
        outcome="APPLIED",
    )
    record = queue.complete(
        SiteCommandResult(
            command_id="command-1",
            tenant_id="t1",
            site_id="s1",
            success=True,
            execution=execution,
            audit_records=[audit],
            completed_at=NOW + dt.timedelta(seconds=2),
        )
    )

    assert record.status is SiteCommandStatus.COMPLETED
    assert store.get_response_execution("t1", "s1", "response-1") == execution
    assert store.list_audit_records("t1", "s1") == [audit]
