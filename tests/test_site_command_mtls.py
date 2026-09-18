import datetime as dt

import pytest

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
from mon.mtls_ingress import (
    SiteCertificateScopeError,
    VerifiedSiteIdentity,
    require_command_result_matches_site_identity,
)
from mon.site_command_models import SiteCommandResult


def test_command_result_scope_must_match_verified_certificate() -> None:
    identity = VerifiedSiteIdentity(
        tenant_id="t1",
        site_id="s1",
        spiffe_uri="spiffe://mon.local/tenant/t1/site/s1",
        fingerprint_sha256="a" * 64,
        serial_number="1",
    )
    request = ResponseRequest(
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
    execution = ResponseExecution(
        execution_id=request.request_id,
        tenant_id="t1",
        site_id="s1",
        plan=ResponsePlan(
            request=request,
            decision=PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["test"]),
            enforcement_point=point,
        ),
        status=ResponseExecutionStatus.APPLIED,
        applied_at=dt.datetime.now(dt.UTC),
    )
    matching = SiteCommandResult(
        command_id="cmd",
        tenant_id="t1",
        site_id="s1",
        success=True,
        execution=execution,
    )
    require_command_result_matches_site_identity(matching, identity)

    wrong = matching.model_copy(update={"site_id": "s2"})
    with pytest.raises(SiteCertificateScopeError):
        require_command_result_matches_site_identity(wrong, identity)
