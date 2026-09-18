from __future__ import annotations

from dataclasses import dataclass

from mon.domain import (
    ActionType,
    Asset,
    EnforcementBinding,
    EnforcementHealth,
    EnforcementKind,
    EnforcementPoint,
    ResponseRequest,
)


class NoEnforcementPath(ValueError):
    pass


ACTION_KIND_PREFERENCE: dict[ActionType, tuple[EnforcementKind, ...]] = {
    ActionType.ISOLATE_ENDPOINT: (
        EnforcementKind.ENDPOINT,
        EnforcementKind.NAC,
        EnforcementKind.SWITCH,
        EnforcementKind.FIREWALL,
    ),
    ActionType.QUARANTINE_VLAN: (EnforcementKind.NAC, EnforcementKind.SWITCH),
    ActionType.DISABLE_SWITCH_PORT: (EnforcementKind.SWITCH, EnforcementKind.NAC),
    ActionType.BLOCK_IP: (
        EnforcementKind.FIREWALL,
        EnforcementKind.ROUTER,
        EnforcementKind.CLOUD,
        EnforcementKind.WAF,
        EnforcementKind.UPSTREAM,
    ),
    ActionType.RATE_LIMIT: (
        EnforcementKind.ROUTER,
        EnforcementKind.FIREWALL,
        EnforcementKind.CLOUD,
        EnforcementKind.UPSTREAM,
    ),
    ActionType.WAF_BLOCK: (EnforcementKind.WAF, EnforcementKind.CLOUD),
    ActionType.CLOUD_DENY: (EnforcementKind.CLOUD,),
    ActionType.UPSTREAM_MITIGATION: (EnforcementKind.UPSTREAM, EnforcementKind.ROUTER),
    ActionType.RESTORE: (
        EnforcementKind.ENDPOINT,
        EnforcementKind.NAC,
        EnforcementKind.SWITCH,
        EnforcementKind.FIREWALL,
        EnforcementKind.ROUTER,
        EnforcementKind.WAF,
        EnforcementKind.CLOUD,
        EnforcementKind.UPSTREAM,
    ),
}


@dataclass(frozen=True)
class EnforcementSelection:
    point: EnforcementPoint
    reasons: list[str]


def select_enforcement_point(
    request: ResponseRequest,
    points: list[EnforcementPoint],
    bindings: list[EnforcementBinding],
    asset: Asset | None = None,
) -> EnforcementSelection:
    candidates = [
        point
        for point in points
        if point.tenant_id == request.tenant_id
        and point.site_id == request.site_id
        and point.health is not EnforcementHealth.UNAVAILABLE
        and request.action in point.capabilities
    ]

    if request.enforcement_point_id:
        candidates = [
            point
            for point in candidates
            if point.enforcement_point_id == request.enforcement_point_id
        ]
        if not candidates:
            raise NoEnforcementPath("requested enforcement point is unavailable or incapable")

    binding_by_point = {
        binding.enforcement_point_id: binding
        for binding in bindings
        if binding.tenant_id == request.tenant_id
        and binding.site_id == request.site_id
        and (asset is None or binding.asset_id == asset.asset_id)
    }

    if asset is not None and binding_by_point:
        candidates = [
            point for point in candidates if point.enforcement_point_id in binding_by_point
        ]

    if not candidates:
        raise NoEnforcementPath("no healthy in-scope enforcement point supports this action")

    preferences = ACTION_KIND_PREFERENCE.get(request.action, tuple(EnforcementKind))
    preference_index = {kind: index for index, kind in enumerate(preferences)}

    def score(point: EnforcementPoint) -> tuple[int, int, int, str]:
        binding = binding_by_point.get(point.enforcement_point_id)
        kind_rank = preference_index.get(point.kind, 999)
        distance = binding.distance if binding else 50
        bias = binding.priority_bias if binding else 0
        health_penalty = 200 if point.health is EnforcementHealth.DEGRADED else 0
        return (
            kind_rank * 1000 + distance * 10 + point.priority + bias + health_penalty,
            distance,
            point.priority,
            point.enforcement_point_id,
        )

    chosen = min(candidates, key=score)
    binding = binding_by_point.get(chosen.enforcement_point_id)
    reasons = [
        f"selected {chosen.kind.value.lower()} enforcement for {request.action.value.lower()}",
        "healthy/in-scope capability" if chosen.health is EnforcementHealth.HEALTHY else "degraded but usable",
    ]
    if binding:
        reasons.append(f"asset-to-enforcement distance={binding.distance}")
    if request.enforcement_point_id:
        reasons.append("operator/request explicitly selected this enforcement point")
    else:
        reasons.append("selected automatically from the enforcement graph")

    return EnforcementSelection(point=chosen, reasons=reasons)
