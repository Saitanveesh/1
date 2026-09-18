import datetime as dt

from mon.database import DatabaseStore
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


def test_response_execution_and_audit_persist_across_store_reopen(tmp_path) -> None:
    url = f"sqlite+pysqlite:///{tmp_path / 'response.db'}"
    first = DatabaseStore(url, create_schema=True)
    request = ResponseRequest(
        request_id="request-1",
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(ip_address="203.0.113.9"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="fw-1",
        ttl_seconds=300,
        reason="test",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw-1",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.FIREWALL,
        vendor="test",
        capabilities={ActionType.BLOCK_IP},
    )
    plan = ResponsePlan(
        request=request,
        decision=PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            reasons=["test"],
        ),
        enforcement_point=point,
        blast_radius_estimate="single source IP rule",
    )
    applied_at = dt.datetime.now(dt.UTC)
    execution = ResponseExecution(
        execution_id="request-1",
        tenant_id="t1",
        site_id="s1",
        plan=plan,
        status=ResponseExecutionStatus.APPLIED,
        applied_at=applied_at,
        expires_at=applied_at + dt.timedelta(minutes=5),
        result=EnforcementResult(success=True, message="applied"),
    )
    first.add_response_execution(execution)
    first.add_audit_record(
        AuditRecord(
            tenant_id="t1",
            site_id="s1",
            actor_id="tester",
            category="RESPONSE",
            object_type="response_execution",
            object_id="request-1",
            action="EXECUTE",
            outcome="APPLIED",
        )
    )
    first.close()

    second = DatabaseStore(url)
    restored = second.get_response_execution("t1", "s1", "request-1")
    assert restored is not None
    assert restored.status is ResponseExecutionStatus.APPLIED
    assert second.get_response_execution("other", "s1", "request-1") is None
    audit = second.list_audit_records("t1", "s1")
    assert [item.outcome for item in audit] == ["APPLIED"]
    second.close()
