import datetime as dt

from mon.domain import (
    ActionType,
    AuditRecord,
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
from mon.site_command_models import SiteCommand, SiteCommandKind, SiteCommandRecord
from mon.site_command_queue import SiteCommandQueue
from mon.store import InMemoryStore


def test_expired_apply_command_fails_dispatch_execution_with_audit() -> None:
    store = InMemoryStore()
    queue = SiteCommandQueue(store)
    now = dt.datetime(2026, 9, 19, 0, 0, tzinfo=dt.UTC)
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
    plan = ResponsePlan(
        request=request,
        decision=PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["test"]),
        enforcement_point=point,
    )
    execution = ResponseExecution(
        execution_id="response-1",
        tenant_id="t1",
        site_id="s1",
        plan=plan,
        status=ResponseExecutionStatus.DISPATCH_PENDING,
        requested_at=now,
    )
    store.add_response_execution(execution)
    store.add_site_command(
        SiteCommandRecord(
            command=SiteCommand(
                command_id="cmd-1",
                tenant_id="t1",
                site_id="s1",
                kind=SiteCommandKind.APPLY_RESPONSE,
                created_at=now,
                not_after=now + dt.timedelta(seconds=30),
                response_plan=plan,
            )
        )
    )

    assert queue.expire_due(
        "t1",
        "s1",
        now=now + dt.timedelta(seconds=31),
    ) == 1
    failed = store.get_response_execution("t1", "s1", "response-1")
    assert failed is not None
    assert failed.status is ResponseExecutionStatus.FAILED
    assert "expired before delivery" in (failed.error or "")
    audit = store.list_audit_records("t1", "s1")
    assert isinstance(audit[0], AuditRecord)
    assert audit[0].outcome == "EXPIRED"
