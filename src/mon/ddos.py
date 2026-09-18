from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mon.domain import (
    ActionType,
    EnforcementHealth,
    EnforcementKind,
    EnforcementPoint,
)


class DDoSPlanningError(RuntimeError):
    pass


class DDoSImpactScope(StrEnum):
    """Where measured impact is occurring; supplied by investigation evidence."""

    LOCAL_SERVICE = "LOCAL_SERVICE"
    UPSTREAM_LINK = "UPSTREAM_LINK"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class DDoSObservation:
    """Measured inputs used to build a mitigation ladder."""

    target_ip: str
    packets_per_second: float
    baseline_packets_per_second: float
    distinct_sources: int
    window_seconds: int
    impact_scope: DDoSImpactScope

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
    enforcement_kind: EnforcementKind
    tier: int
    reason: str


_KIND_TIERS: tuple[tuple[EnforcementKind, ...], ...] = (
    (EnforcementKind.ENDPOINT,),
    (EnforcementKind.SWITCH, EnforcementKind.NAC),
    (EnforcementKind.FIREWALL, EnforcementKind.ROUTER),
    (EnforcementKind.WAF, EnforcementKind.CLOUD),
    (EnforcementKind.UPSTREAM,),
)

_ACTION_PREFERENCE: dict[EnforcementKind, tuple[ActionType, ...]] = {
    EnforcementKind.ENDPOINT: (ActionType.RATE_LIMIT,),
    EnforcementKind.SWITCH: (ActionType.RATE_LIMIT,),
    EnforcementKind.NAC: (ActionType.RATE_LIMIT,),
    EnforcementKind.FIREWALL: (ActionType.RATE_LIMIT,),
    EnforcementKind.ROUTER: (
        ActionType.RATE_LIMIT,
        ActionType.UPSTREAM_MITIGATION,
    ),
    EnforcementKind.WAF: (
        ActionType.WAF_BLOCK,
        ActionType.RATE_LIMIT,
    ),
    EnforcementKind.CLOUD: (
        ActionType.CLOUD_DENY,
        ActionType.RATE_LIMIT,
    ),
    EnforcementKind.UPSTREAM: (
        ActionType.UPSTREAM_MITIGATION,
        ActionType.RATE_LIMIT,
    ),
}


def _evidence_text(observation: DDoSObservation) -> str:
    evidence = (
        f"measured {observation.packets_per_second:g} pps over "
        f"{observation.window_seconds}s from {observation.distinct_sources} sources; "
        f"impact={observation.impact_scope.value.lower()}"
    )
    multiplier = observation.baseline_multiplier
    if multiplier is not None:
        evidence += f" ({multiplier:.2f}x measured baseline)"
    return evidence


def _allowed_for_scope(
    point: EnforcementPoint,
    action: ActionType,
    scope: DDoSImpactScope,
) -> bool:
    if scope is DDoSImpactScope.LOCAL_SERVICE:
        return True
    if scope is DDoSImpactScope.UPSTREAM_LINK:
        if point.kind in {
            EnforcementKind.WAF,
            EnforcementKind.CLOUD,
            EnforcementKind.UPSTREAM,
        }:
            return True
        return (
            point.kind is EnforcementKind.ROUTER
            and action is ActionType.UPSTREAM_MITIGATION
        )
    return False


def plan_ddos_mitigation(
    observation: DDoSObservation,
    enforcement_points: list[EnforcementPoint],
    *,
    confirmed: bool,
) -> list[MitigationStep]:
    """Build an evidence-gated, location-aware mitigation ladder.

    confirmed and impact_scope come from detection/investigation. This planner does
    not infer an attack or upstream saturation from packet rate alone.
    """

    if not confirmed:
        return []
    if observation.impact_scope is DDoSImpactScope.UNKNOWN:
        raise DDoSPlanningError(
            "DDoS impact scope is unknown; local versus upstream impact must be established"
        )
    if observation.packets_per_second <= 0:
        raise DDoSPlanningError("confirmed DDoS observation has no measured traffic")

    usable = [
        point
        for point in enforcement_points
        if point.health is not EnforcementHealth.UNAVAILABLE
    ]
    steps: list[MitigationStep] = []
    evidence = _evidence_text(observation)

    for tier_index, kinds in enumerate(_KIND_TIERS, start=1):
        candidates: list[
            tuple[int, int, int, str, EnforcementPoint, ActionType]
        ] = []
        for point in usable:
            if point.kind not in kinds:
                continue
            action_preferences = _ACTION_PREFERENCE[point.kind]
            for action_index, action in enumerate(action_preferences):
                if action not in point.capabilities:
                    continue
                if not _allowed_for_scope(
                    point,
                    action,
                    observation.impact_scope,
                ):
                    continue
                health_penalty = (
                    1 if point.health is EnforcementHealth.DEGRADED else 0
                )
                candidates.append(
                    (
                        health_penalty,
                        point.priority,
                        action_index,
                        point.enforcement_point_id,
                        point,
                        action,
                    )
                )

        if not candidates:
            continue

        *_, point, action = min(candidates)
        steps.append(
            MitigationStep(
                action=action,
                enforcement_point_id=point.enforcement_point_id,
                enforcement_kind=point.kind,
                tier=tier_index,
                reason=evidence,
            )
        )

    if not steps:
        raise DDoSPlanningError(
            "no usable enforcement capability for the established DDoS impact scope"
        )
    return steps
