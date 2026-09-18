import pytest

from mon.ddos import (
    DDoSImpactScope,
    DDoSObservation,
    DDoSPlanningError,
    plan_ddos_mitigation,
)
from mon.domain import ActionType, EnforcementHealth, EnforcementKind, EnforcementPoint


def point(
    point_id: str,
    kind: EnforcementKind,
    capabilities: set[ActionType],
    *,
    priority: int = 100,
    health: EnforcementHealth = EnforcementHealth.HEALTHY,
) -> EnforcementPoint:
    return EnforcementPoint(
        enforcement_point_id=point_id,
        tenant_id="tenant-a",
        site_id="site-a",
        kind=kind,
        vendor="test",
        capabilities=capabilities,
        priority=priority,
        health=health,
    )


def observation(
    scope: DDoSImpactScope = DDoSImpactScope.LOCAL_SERVICE,
) -> DDoSObservation:
    return DDoSObservation(
        target_ip="203.0.113.10",
        packets_per_second=12_000,
        baseline_packets_per_second=1_000,
        distinct_sources=420,
        window_seconds=30,
        impact_scope=scope,
    )


def test_unconfirmed_traffic_never_proposes_enforcement() -> None:
    firewall = point("fw-1", EnforcementKind.FIREWALL, {ActionType.RATE_LIMIT})
    assert plan_ddos_mitigation(observation(), [firewall], confirmed=False) == []


def test_local_service_pressure_escalates_by_enforcement_location() -> None:
    endpoint = point(
        "endpoint-1",
        EnforcementKind.ENDPOINT,
        {ActionType.RATE_LIMIT},
    )
    switch = point(
        "switch-1",
        EnforcementKind.SWITCH,
        {ActionType.RATE_LIMIT},
    )
    firewall = point(
        "fw-1",
        EnforcementKind.FIREWALL,
        {ActionType.RATE_LIMIT},
    )
    cloud = point(
        "cloud-1",
        EnforcementKind.CLOUD,
        {ActionType.CLOUD_DENY},
    )
    upstream = point(
        "upstream-1",
        EnforcementKind.UPSTREAM,
        {ActionType.UPSTREAM_MITIGATION},
    )

    steps = plan_ddos_mitigation(
        observation(),
        [upstream, cloud, firewall, switch, endpoint],
        confirmed=True,
    )

    assert [step.enforcement_kind for step in steps] == [
        EnforcementKind.ENDPOINT,
        EnforcementKind.SWITCH,
        EnforcementKind.FIREWALL,
        EnforcementKind.CLOUD,
        EnforcementKind.UPSTREAM,
    ]
    assert [step.tier for step in steps] == [1, 2, 3, 4, 5]
    assert all("12000 pps" in step.reason for step in steps)
    assert all("12.00x measured baseline" in step.reason for step in steps)


def test_saturated_upstream_link_skips_local_only_controls() -> None:
    endpoint = point(
        "endpoint-1",
        EnforcementKind.ENDPOINT,
        {ActionType.RATE_LIMIT},
    )
    firewall = point(
        "fw-1",
        EnforcementKind.FIREWALL,
        {ActionType.RATE_LIMIT},
    )
    router = point(
        "router-1",
        EnforcementKind.ROUTER,
        {ActionType.RATE_LIMIT, ActionType.UPSTREAM_MITIGATION},
    )
    cloud = point(
        "cloud-1",
        EnforcementKind.CLOUD,
        {ActionType.CLOUD_DENY},
    )
    upstream = point(
        "upstream-1",
        EnforcementKind.UPSTREAM,
        {ActionType.UPSTREAM_MITIGATION},
    )

    steps = plan_ddos_mitigation(
        observation(DDoSImpactScope.UPSTREAM_LINK),
        [endpoint, firewall, router, cloud, upstream],
        confirmed=True,
    )

    assert [step.enforcement_point_id for step in steps] == [
        "router-1",
        "cloud-1",
        "upstream-1",
    ]
    assert steps[0].action is ActionType.UPSTREAM_MITIGATION
    assert all(
        step.enforcement_kind not in {
            EnforcementKind.ENDPOINT,
            EnforcementKind.FIREWALL,
        }
        for step in steps
    )


def test_unknown_impact_scope_fails_closed() -> None:
    upstream = point(
        "upstream-1",
        EnforcementKind.UPSTREAM,
        {ActionType.UPSTREAM_MITIGATION},
    )
    with pytest.raises(DDoSPlanningError, match="impact scope is unknown"):
        plan_ddos_mitigation(
            observation(DDoSImpactScope.UNKNOWN),
            [upstream],
            confirmed=True,
        )


def test_unavailable_points_are_never_selected_and_healthy_beats_degraded() -> None:
    unavailable = point(
        "rate-limit-down",
        EnforcementKind.FIREWALL,
        {ActionType.RATE_LIMIT},
        priority=1,
        health=EnforcementHealth.UNAVAILABLE,
    )
    degraded = point(
        "rate-limit-degraded",
        EnforcementKind.FIREWALL,
        {ActionType.RATE_LIMIT},
        priority=1,
        health=EnforcementHealth.DEGRADED,
    )
    healthy = point(
        "rate-limit-healthy",
        EnforcementKind.FIREWALL,
        {ActionType.RATE_LIMIT},
        priority=900,
    )

    steps = plan_ddos_mitigation(
        observation(),
        [unavailable, degraded, healthy],
        confirmed=True,
    )
    assert steps[0].enforcement_point_id == "rate-limit-healthy"


def test_confirmed_attack_fails_closed_without_scope_appropriate_capability() -> None:
    endpoint = point(
        "endpoint-1",
        EnforcementKind.ENDPOINT,
        {ActionType.RATE_LIMIT},
    )

    with pytest.raises(DDoSPlanningError, match="established DDoS impact scope"):
        plan_ddos_mitigation(
            observation(DDoSImpactScope.UPSTREAM_LINK),
            [endpoint],
            confirmed=True,
        )
