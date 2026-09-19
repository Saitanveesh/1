from __future__ import annotations

import threading
from enum import StrEnum
from typing import Protocol

from mon.domain import EnforcementKind, EnforcementPoint, EnforcementResult, ResponsePlan


class EnforcementError(RuntimeError):
    pass


class EnforcementExecutionPlane(StrEnum):
    SITE = "SITE"
    CONTROL_PLANE = "CONTROL_PLANE"


_CONTROL_PLANE_KINDS = {
    EnforcementKind.WAF,
    EnforcementKind.CLOUD,
    EnforcementKind.UPSTREAM,
}


def execution_plane(point: EnforcementPoint) -> EnforcementExecutionPlane:
    configured = point.attributes.get("execution_plane")
    if configured is not None:
        try:
            return EnforcementExecutionPlane(str(configured).strip().upper())
        except ValueError as exc:
            raise EnforcementError(
                "enforcement point execution_plane must be SITE or CONTROL_PLANE"
            ) from exc
    if point.kind in _CONTROL_PLANE_KINDS:
        return EnforcementExecutionPlane.CONTROL_PLANE
    return EnforcementExecutionPlane.SITE


class EnforcementAdapter(Protocol):
    async def execute(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementResult: ...

    async def rollback(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementResult: ...


class EnforcementRegistry:
    def __init__(self) -> None:
        self._adapters: dict[tuple[EnforcementKind, str], EnforcementAdapter] = {}
        self._lock = threading.RLock()

    def register(
        self,
        kind: EnforcementKind,
        vendor: str,
        adapter: EnforcementAdapter,
    ) -> None:
        with self._lock:
            self._adapters[(kind, vendor.casefold())] = adapter

    def resolve(self, kind: EnforcementKind, vendor: str) -> EnforcementAdapter:
        with self._lock:
            exact = self._adapters.get((kind, vendor.casefold()))
            generic = self._adapters.get((kind, "*"))
            adapter = exact or generic
        if adapter is None:
            raise EnforcementError(f"no enforcement adapter for {kind.value}/{vendor}")
        return adapter
