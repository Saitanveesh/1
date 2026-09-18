from __future__ import annotations

from typing import Protocol

from mon.domain import EnforcementKind, ResponsePlan


class EnforcementError(RuntimeError):
    pass


class EnforcementAdapter(Protocol):
    async def execute(self, plan: ResponsePlan) -> dict[str, object]: ...

    async def rollback(self, plan: ResponsePlan) -> dict[str, object]: ...


class EnforcementRegistry:
    def __init__(self) -> None:
        self._adapters: dict[tuple[EnforcementKind, str], EnforcementAdapter] = {}

    def register(
        self,
        kind: EnforcementKind,
        vendor: str,
        adapter: EnforcementAdapter,
    ) -> None:
        self._adapters[(kind, vendor.casefold())] = adapter

    def resolve(self, kind: EnforcementKind, vendor: str) -> EnforcementAdapter:
        exact = self._adapters.get((kind, vendor.casefold()))
        generic = self._adapters.get((kind, "*"))
        adapter = exact or generic
        if adapter is None:
            raise EnforcementError(f"no enforcement adapter for {kind.value}/{vendor}")
        return adapter
