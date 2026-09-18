import datetime as dt

from fastapi.testclient import TestClient

from mon.api import app, site_command_queue, store
from mon.auth import Principal, Role, get_principal
from mon.domain import (
    ActionType,
    EnforcementKind,
    EnforcementPoint,
    PolicyDecision,
    PolicyOutcome,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
)
from mon.site_command_models import SiteCommand, SiteCommandKind

client = TestClient(app)


def test_site_controller_can_pull_only_its_scoped_commands() -> None:
    store.__init__()
    now_request = ResponseRequest(
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
    now = dt.datetime.now(dt.UTC)
    site_command_queue.enqueue(
        SiteCommand(
            command_id="cmd-1",
            tenant_id="t1",
            site_id="s1",
            kind=SiteCommandKind.APPLY_RESPONSE,
            created_at=now,
            not_after=now + dt.timedelta(minutes=5),
            response_plan=ResponsePlan(
                request=now_request,
                decision=PolicyDecision(
                    outcome=PolicyOutcome.ALLOW,
                    reasons=["test"],
                ),
                enforcement_point=point,
            ),
        )
    )

    principal = Principal(
        subject="site-controller",
        tenant_id="t1",
        roles={Role.SITE_CONTROLLER},
        site_ids={"s1"},
    )
    app.dependency_overrides[get_principal] = lambda: principal
    try:
        response = client.get(
            "/api/v1/site-commands/pending",
            params={"tenant_id": "t1", "site_id": "s1"},
        )
        forbidden = client.get(
            "/api/v1/site-commands/pending",
            params={"tenant_id": "t1", "site_id": "s2"},
        )
    finally:
        app.dependency_overrides.pop(get_principal, None)

    assert response.status_code == 200
    assert [item["command_id"] for item in response.json()] == ["cmd-1"]
    assert forbidden.status_code == 403
