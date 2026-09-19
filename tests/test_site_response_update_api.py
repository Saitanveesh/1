import datetime as dt

from fastapi.testclient import TestClient

from mon.api import app, store
from mon.domain import (
    ActionType,
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
from mon.site_response_models import SiteResponseUpdate, recovery_update_id

client = TestClient(app)
NOW = dt.datetime(2026, 9, 19, 4, 0, tzinfo=dt.UTC)


def make_execution(status: ResponseExecutionStatus) -> ResponseExecution:
    request = ResponseRequest(
        request_id="api-response-1",
        tenant_id="t1",
        site_id="s1",
        incident_id="incident-1",
        target=ResponseTarget(ip_address="203.0.113.9"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="fw-1",
        ttl_seconds=60,
        reason="temporary containment",
    )
    plan = ResponsePlan(
        request=request,
        decision=PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            reasons=["test"],
            evaluated_at=NOW,
        ),
        enforcement_point=EnforcementPoint(
            enforcement_point_id="fw-1",
            tenant_id="t1",
            site_id="s1",
            kind=EnforcementKind.FIREWALL,
            vendor="test",
            capabilities={ActionType.BLOCK_IP},
        ),
    )
    execution = ResponseExecution(
        execution_id=request.request_id,
        tenant_id="t1",
        site_id="s1",
        plan=plan,
        status=ResponseExecutionStatus.APPLIED,
        requested_at=NOW,
        applied_at=NOW,
        expires_at=NOW + dt.timedelta(seconds=60),
        result=EnforcementResult(success=True, message="applied"),
    )
    if status is ResponseExecutionStatus.ROLLED_BACK:
        return execution.model_copy(
            update={
                "status": status,
                "rollback_at": NOW + dt.timedelta(seconds=61),
                "rollback_result": EnforcementResult(
                    success=True,
                    message="rolled back",
                ),
            }
        )
    return execution


def test_site_response_update_api_reconciles_terminal_recovery() -> None:
    store.__init__()
    applied = make_execution(ResponseExecutionStatus.APPLIED)
    store.add_response_execution(applied)
    rolled_back = make_execution(ResponseExecutionStatus.ROLLED_BACK)
    update = SiteResponseUpdate(
        update_id=recovery_update_id(rolled_back),
        tenant_id="t1",
        site_id="s1",
        execution=rolled_back,
        observed_at=rolled_back.rollback_at,
    )

    response = client.post(
        "/api/v1/site-response-updates",
        json=update.model_dump(mode="json"),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ROLLED_BACK"
    stored = store.get_response_execution("t1", "s1", "api-response-1")
    assert stored is not None
    assert stored.status is ResponseExecutionStatus.ROLLED_BACK
