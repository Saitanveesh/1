from __future__ import annotations

from dataclasses import dataclass

from mon.domain import ActionType, EnforcementHealth, EnforcementPoint


class DDoSPlanningError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DDoSObservation:
    """Measured inputs used to decide whether mitigation may be proposed."""

    target_ip: str
    packets_per_second: float
    baseline_packets_per_second: float
    distinct_sources: int
    window_seconds: int

    def __post_init__(self) -> None:
        if not self.target_ip.strip():
            raise ValueError("target_ip is required")
        if self.packets_per_second < 0 or self.baseline_packets_per_second < 0:
            raise ValueError("packet rates cannot be negative")
        if self.distinct_sources < 0 or self.window_seconds <= 0:
            raise ValueError("source count must be non-negative and window positive")

    @property
    def baseline_multiplier(self) -> float | None:
        if self.baseline_packets_per_second <= 0:
            return None
        return self.packets_per_second / self.baseline_packets_per_second


@dataclass(frozen=True, slots=True)
class MitigationStep:
    action: ActionType
    enforcement_point_id: str
    tier: int
    reason: str


# Lowest blast-radius controls come first. Escalation is capability and health driven;
# it never invents traffic thresholds or assumes an upstream service exists.
_DDOS_TIERS: tuple[tuple[ActionType, ...], ...] = (
    (ActionType.RATE_LIMIT,),
    (ActionType.WAF_BLOCK, ActionType.CLOUD_DENY),
    (ActionType.BLOCK_IP,),
    (ActionType.UPSTREAM_MITIGATION,),
)


def plan_ddos_mitigation(
    observation: DDoSObservation,
    enforcement_points: list[EnforcementPoint],
    *,
    confirmed: bool,
) -> list[MitigationStep]:
    """Build a reversible mitigation ladder from measured evidence and live inventory.

    `confirmed` must come from the detection/investigation layer. This planner deliberately
    does not infer an attack from packet rate alone: deployments have different baselines.
    """

    if not confirmed:
        return []
    if observation.packets_per_second <= 0:
        raise DDoSPlanningError("confirmed DDoS observation has no measured traffic")

    usable = [
        point
        for point in enforcement_points
        if point.health is not EnforcementHealth.UNAVAILABLE
    ]
    steps: list[MitigationStep] = []

    for tier_index, actions in enumerate(_DDOS_TIERS, start=1):
        candidates: list[tuple[int, int, EnforcementPoint, ActionType]] = []
        for point in usable:
            for action_index, action in enumerate(actions):
                if action in point.capabilities:
                    health_penalty = (
                        1 if point.health is EnforcementHealth.DEGRADED else 0
                    )
                    candidates.append(
                        (health_penalty, point.priority * 10 + action_index, point, action)
                    )
        if not candidates:
            continue

        _, _, point, action = min(
            candidates,
            key=lambda item: (item[0], item[1], item[2].enforcement_point_id),
        )
        multiplier = observation.baseline_multiplier
        evidence = (
            f"measured {observation.packets_per_second:g} pps over "
            f"{observation.window_seconds}s from {observation.distinct_sources} sources"
        )
        if multiplier is not None:
            evidence += f" ({multiplier:.2f}x measured baseline)"
        steps.append(
            MitigationStep(
                action=action,
                enforcement_point_id=point.enforcement_point_id,
                tier=tier_index,
                reason=evidence,
            )
        )

    if not steps:
        raise DDoSPlanningError("no healthy or degraded DDoS enforcement capability")
    return steps
