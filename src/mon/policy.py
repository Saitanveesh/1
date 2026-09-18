from __future__ import annotations

from mon.domain import (
    ActorType,
    Asset,
    AssetCriticality,
    EnforcementHealth,
    EnforcementPoint,
    Incident,
    PolicyDecision,
    PolicyOutcome,
    ResponseRequest,
)

DISRUPTIVE_ACTIONS = {
    "BLOCK_IP",
    "RATE_LIMIT",
    "ISOLATE_ENDPOINT",
    "QUARANTINE_VLAN",
    "DISABLE_SWITCH_PORT",
    "WAF_BLOCK",
    "CLOUD_DENY",
    "UPSTREAM_MITIGATION",
}


def evaluate_response(
    request: ResponseRequest,
    incident: Incident,
    enforcement_point: EnforcementPoint,
    asset: Asset | None = None,
) -> PolicyDecision:
    reasons: list[str] = []

    if request.tenant_id != incident.tenant_id or request.site_id != incident.site_id:
        return PolicyDecision(
            outcome=PolicyOutcome.DENY,
            reasons=["response request and incident scope do not match"],
        )

    if (
        enforcement_point.tenant_id != request.tenant_id
        or enforcement_point.site_id != request.site_id
    ):
        return PolicyDecision(
            outcome=PolicyOutcome.DENY,
            reasons=["enforcement point is outside the incident tenant/site scope"],
        )

    if enforcement_point.health is EnforcementHealth.UNAVAILABLE:
        return PolicyDecision(
            outcome=PolicyOutcome.DENY,
            reasons=["selected enforcement point is unavailable"],
        )

    if request.action not in enforcement_point.capabilities:
        return PolicyDecision(
            outcome=PolicyOutcome.DENY,
            reasons=["selected enforcement point does not support the requested action"],
        )

    disruptive = request.action.value in DISRUPTIVE_ACTIONS
    if not disruptive:
        return PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["non-disruptive action"])

    if asset is not None:
        if asset.tenant_id != request.tenant_id or asset.site_id != request.site_id:
            return PolicyDecision(
                outcome=PolicyOutcome.DENY,
                reasons=["target asset is outside the incident tenant/site scope"],
            )
        if asset.criticality is AssetCriticality.CRITICAL:
            reasons.append("critical asset containment requires operator approval")

    independent_classes = {item.evidence_class for item in incident.evidence}
    if incident.confidence < 0.90:
        reasons.append("incident confidence is below 0.90")
    if len(independent_classes) < 2:
        reasons.append("fewer than two independent evidence classes support the incident")

    if request.actor_type is ActorType.OPERATOR:
        if reasons:
            return PolicyDecision(
                outcome=PolicyOutcome.REQUIRE_APPROVAL,
                reasons=reasons,
            )
        return PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            reasons=["operator-requested action satisfies response policy"],
        )

    if reasons:
        return PolicyDecision(outcome=PolicyOutcome.REQUIRE_APPROVAL, reasons=reasons)

    return PolicyDecision(
        outcome=PolicyOutcome.ALLOW,
        reasons=[
            "high-confidence incident",
            "multiple independent evidence classes",
            "enforcement capability is healthy and in-scope",
        ],
    )
