import datetime as dt

from mon.domain import (
    ActionType,
    EnforcementKind,
    EnforcementPoint,
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


def response_plan() -> ResponsePlan:
    request = ResponseRequest(
        request_id="response-1",
        tenant_id="t1",
        site_id="s1",
        incident_id="inc",
        target=ResponseTarget(ip_address="198.51.100.7"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="fw",
        ttl_seconds=60,
        reason="test",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw",
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
    )


def add_execution(
    store: InMemoryStore,
    plan: ResponsePlan,
    status: ResponseExecutionStatus,
) -> ResponseExecution:
    execution = ResponseExecution(
        execution_id="response-1",
        tenant_id="t1",
        site_id="s1",
        plan=plan,
        status=status,
        requested_at=NOW,
    )
    store.add_response_execution(execution)
    return execution


def test_expired_apply_command_fails_dispatch_execution_with_audit() -> None:
    store = InMemoryStore()
    queue = SiteCommandQueue(store)
    plan = response_plan()
    add_execution(store, plan, ResponseExecutionStatus.DISPATCH_PENDING)
    queue.enqueue(
        SiteCommand(
            command_id="cmd-1",
            tenant_id="t1",
            site_id="s1",
            kind=SiteCommandKind.APPLY_RESPONSE,
            created_at=NOW,
            not_after=NOW + dt.timedelta(seconds=30),
            response_plan=plan,
        )
    )

    assert queue.expire_due(
        "t1",
        "s1",
        now=NOW + dt.timedelta(seconds=31),
    ) == 1

    command = store.get_site_command("t1", "s1", "cmd-1")
    assert command is not None
    assert command.status is SiteCommandStatus.EXPIRED

    failed = store.get_response_execution("t1", "s1", "response-1")
    assert failed is not None
    assert failed.status is ResponseExecutionStatus.FAILED
    assert "expired before delivery" in (failed.error or "")

    audit = store.list_audit_records("t1", "s1")
    assert len(audit) == 1
    assert audit[0].outcome == "EXPIRED"
    assert audit[0].details["command_id"] == "cmd-1"


def test_expired_rollback_command_fails_pending_rollback() -> None:
    store = InMemoryStore()
    queue = SiteCommandQueue(store)
    plan = response_plan()
    add_execution(store, plan, ResponseExecutionStatus.ROLLBACK_PENDING)
    queue.enqueue(
        SiteCommand(
            command_id="rollback-1",
            tenant_id="t1",
            site_id="s1",
            kind=SiteCommandKind.ROLLBACK_RESPONSE,
            created_at=NOW,
            not_after=NOW + dt.timedelta(seconds=30),
            rollback_execution_id="response-1",
            reason="operator rollback",
        )
    )

    queue.pending("t1", "s1", now=NOW + dt.timedelta(seconds=31))

    failed = store.get_response_execution("t1", "s1", "response-1")
    assert failed is not None
    assert failed.status is ResponseExecutionStatus.ROLLBACK_FAILED
    assert "rollback command expired" in (failed.error or "")


def test_failed_result_without_execution_reconciles_dispatch_state() -> None:
    store = InMemoryStore()
    queue = SiteCommandQueue(store)
    plan = response_plan()
    add_execution(store, plan, ResponseExecutionStatus.DISPATCH_PENDING)
    queue.enqueue(
        SiteCommand(
            command_id="cmd-1",
            tenant_id="t1",
            site_id="s1",
            kind=SiteCommandKind.APPLY_RESPONSE,
            created_at=NOW,
            not_after=NOW + dt.timedelta(minutes=5),
            response_plan=plan,
        )
    )

    record = queue.complete(
        SiteCommandResult(
            command_id="cmd-1",
            tenant_id="t1",
            site_id="s1",
            success=False,
            error="site command expired before local execution",
            completed_at=NOW + dt.timedelta(seconds=5),
        )
    )

    assert record.status is SiteCommandStatus.FAILED
    failed = store.get_response_execution("t1", "s1", "response-1")
    assert failed is not None
    assert failed.status is ResponseExecutionStatus.FAILED
    assert failed.error == "site command expired before local execution"
    audits = store.list_audit_records("t1", "s1")
    assert len(audits) == 1
    assert audits[0].outcome == "FAILED"
