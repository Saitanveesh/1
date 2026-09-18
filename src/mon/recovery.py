from __future__ import annotations

import asyncio
import datetime as dt
from dataclasses import dataclass, field

from mon.domain import ResponseExecutionStatus
from mon.response import ResponseOrchestrator


@dataclass(frozen=True, slots=True)
class RecoverySweep:
    attempted: int = 0
    rolled_back: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    errors: dict[str, str] = field(default_factory=dict)


class RecoveryEngine:
    """Rollback expired temporary responses for one tenant/site scope.

    A process-local lock prevents duplicate rollback attempts from overlapping local
    maintenance ticks. Adapter idempotency remains mandatory because process restarts
    and external retries are normal failure modes.
    """

    def __init__(
        self,
        orchestrator: ResponseOrchestrator,
        *,
        actor_id: str = "mon-site-recovery",
    ) -> None:
        self.orchestrator = orchestrator
        self.actor_id = actor_id
        self._lock = asyncio.Lock()

    async def sweep_scope(
        self,
        tenant_id: str,
        site_id: str,
        *,
        now: dt.datetime | None = None,
    ) -> RecoverySweep:
        async with self._lock:
            due = sorted(
                self.orchestrator.due_for_rollback(
                    tenant_id,
                    site_id,
                    now=now,
                ),
                key=lambda item: (
                    item.expires_at or item.requested_at,
                    item.execution_id,
                ),
            )
            rolled_back: list[str] = []
            failed: list[str] = []
            errors: dict[str, str] = {}

            for execution in due:
                result = await self.orchestrator.rollback(
                    tenant_id,
                    site_id,
                    execution.execution_id,
                    actor_id=self.actor_id,
                    reason="temporary response TTL expired",
                )
                if result.status is ResponseExecutionStatus.ROLLED_BACK:
                    rolled_back.append(result.execution_id)
                else:
                    failed.append(result.execution_id)
                    errors[result.execution_id] = (
                        result.error
                        or (
                            result.rollback_result.message
                            if result.rollback_result is not None
                            else "rollback did not complete"
                        )
                    )

            return RecoverySweep(
                attempted=len(due),
                rolled_back=tuple(rolled_back),
                failed=tuple(failed),
                errors=errors,
            )
