from __future__ import annotations

import threading
from typing import Protocol

from mon.domain import EnforcementKind, EnforcementResult, ResponsePlan


class EnforcementError(RuntimeError):
    pass


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
