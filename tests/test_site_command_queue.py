import datetime as dt

import pytest

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
from mon.site_command_queue import SiteCommandError, SiteCommandQueue
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
        requested_at=NOW,
        applied_at=NOW + dt.timedelta(seconds=1),
        expires_at=NOW + dt.timedelta(seconds=301),
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


def test_expired_command_rejects_late_terminal_result() -> None:
    store = InMemoryStore()
    queue = SiteCommandQueue(store)
    command = apply_command()
    queue.enqueue(command)
    queue.expire_due("t1", "s1", now=NOW + dt.timedelta(minutes=6))
    plan = command.response_plan
    assert plan is not None
    execution = ResponseExecution(
        execution_id="response-1",
        tenant_id="t1",
        site_id="s1",
        plan=plan,
        status=ResponseExecutionStatus.APPLIED,
        requested_at=command.created_at,
        applied_at=NOW + dt.timedelta(seconds=1),
        expires_at=NOW + dt.timedelta(seconds=301),
        result=EnforcementResult(success=True, message="applied"),
    )

    with pytest.raises(SiteCommandError, match="expired"):
        queue.complete(
            SiteCommandResult(
                command_id=command.command_id,
                tenant_id="t1",
                site_id="s1",
                success=True,
                execution=execution,
                completed_at=NOW + dt.timedelta(minutes=6),
            )
        )

    record = store.get_site_command("t1", "s1", command.command_id)
    assert record is not None
    assert record.status is SiteCommandStatus.EXPIRED
    current = store.get_response_execution("t1", "s1", "response-1")
    assert current is None


def test_apply_result_cannot_mutate_dispatched_plan() -> None:
    store = InMemoryStore()
    queue = SiteCommandQueue(store)
    command = apply_command()
    queue.enqueue(command)
    plan = command.response_plan
    assert plan is not None
    tampered_request = plan.request.model_copy(
        update={"reason": "site changed the operator reason"}
    )
    tampered_plan = plan.model_copy(update={"request": tampered_request})
    execution = ResponseExecution(
        execution_id="response-1",
        tenant_id="t1",
        site_id="s1",
        plan=tampered_plan,
        status=ResponseExecutionStatus.APPLIED,
        requested_at=command.created_at,
        applied_at=NOW + dt.timedelta(seconds=1),
        expires_at=NOW + dt.timedelta(seconds=301),
        result=EnforcementResult(success=True, message="applied"),
    )

    with pytest.raises(SiteCommandError, match="cannot mutate"):
        queue.complete(
            SiteCommandResult(
                command_id=command.command_id,
                tenant_id="t1",
                site_id="s1",
                success=True,
                execution=execution,
                completed_at=NOW + dt.timedelta(seconds=2),
            )
        )


def test_apply_result_without_apply_time_requires_verification_evidence() -> None:
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
        requested_at=command.created_at,
        expires_at=command.created_at + dt.timedelta(seconds=300),
        result=EnforcementResult(
            success=True,
            message="verified present",
            details={"reconciled_after_interruption": True},
        ),
    )

    with pytest.raises(SiteCommandError, match="VERIFY/PRESENT"):
        queue.complete(
            SiteCommandResult(
                command_id=command.command_id,
                tenant_id="t1",
                site_id="s1",
                success=True,
                execution=execution,
                completed_at=NOW + dt.timedelta(seconds=2),
            )
        )
