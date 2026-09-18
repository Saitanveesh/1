import pytest

from mon.ddos import DDoSObservation, DDoSPlanningError, plan_ddos_mitigation
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


def observation() -> DDoSObservation:
    return DDoSObservation(
        target_ip="203.0.113.10",
        packets_per_second=12_000,
        baseline_packets_per_second=1_000,
        distinct_sources=420,
        window_seconds=30,
    )


def test_unconfirmed_traffic_never_proposes_enforcement() -> None:
    firewall = point("fw-1", EnforcementKind.FIREWALL, {ActionType.RATE_LIMIT})

    assert plan_ddos_mitigation(observation(), [firewall], confirmed=False) == []


def test_hierarchy_prefers_reversible_local_controls_before_upstream() -> None:
    firewall = point(
        "fw-1",
        EnforcementKind.FIREWALL,
        {ActionType.RATE_LIMIT, ActionType.BLOCK_IP},
    )
    waf = point("waf-1", EnforcementKind.WAF, {ActionType.WAF_BLOCK})
    upstream = point(
        "upstream-1",
        EnforcementKind.UPSTREAM,
        {ActionType.UPSTREAM_MITIGATION},
    )

    steps = plan_ddos_mitigation(
        observation(), [upstream, firewall, waf], confirmed=True
    )

    assert [step.action for step in steps] == [
        ActionType.RATE_LIMIT,
        ActionType.WAF_BLOCK,
        ActionType.BLOCK_IP,
        ActionType.UPSTREAM_MITIGATION,
    ]
    assert [step.tier for step in steps] == [1, 2, 3, 4]
    assert all("12000 pps" in step.reason for step in steps)
    assert all("12.00x measured baseline" in step.reason for step in steps)


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
        observation(), [unavailable, degraded, healthy], confirmed=True
    )

    assert steps[0].enforcement_point_id == "rate-limit-healthy"


def test_confirmed_attack_fails_closed_without_enforcement_capability() -> None:
    endpoint = point(
        "endpoint-1",
        EnforcementKind.ENDPOINT,
        {ActionType.ISOLATE_ENDPOINT},
    )

    with pytest.raises(DDoSPlanningError, match="no healthy or degraded"):
        plan_ddos_mitigation(observation(), [endpoint], confirmed=True)
