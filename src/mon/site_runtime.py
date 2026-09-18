from __future__ import annotations

import asyncio
import datetime as dt
from dataclasses import dataclass

from mon.site_controller import SiteController


@dataclass(frozen=True, slots=True)
class SiteRuntimeStatus:
    last_flush_at: dt.datetime | None
    last_recovery_at: dt.datetime | None
    last_flush_error: str | None
    last_recovery_error: str | None


class SiteControllerRuntime:
    """Independent local loops for cloud sync and TTL recovery."""

    def __init__(
        self,
        controller: SiteController,
        *,
        flush_interval_seconds: float = 5.0,
        recovery_interval_seconds: float = 5.0,
    ) -> None:
        if flush_interval_seconds <= 0 or recovery_interval_seconds <= 0:
            raise ValueError("runtime intervals must be positive")
        self.controller = controller
        self.flush_interval_seconds = flush_interval_seconds
        self.recovery_interval_seconds = recovery_interval_seconds
        self._last_flush_at: dt.datetime | None = None
        self._last_recovery_at: dt.datetime | None = None
        self._last_flush_error: str | None = None
        self._last_recovery_error: str | None = None

    @staticmethod
    async def _wait_or_stop(stop_event: asyncio.Event, seconds: float) -> bool:
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=seconds)
        except TimeoutError:
            return False
        return True

    async def _flush_loop(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.controller.flush()
                self._last_flush_error = None
            except Exception as exc:
                self._last_flush_error = str(exc)[:1000]
            self._last_flush_at = dt.datetime.now(dt.UTC)
            if await self._wait_or_stop(stop_event, self.flush_interval_seconds):
                return

    async def _recovery_loop(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.controller.recover_expired_responses()
                self._last_recovery_error = None
            except Exception as exc:
                self._last_recovery_error = str(exc)[:1000]
            self._last_recovery_at = dt.datetime.now(dt.UTC)
            if await self._wait_or_stop(stop_event, self.recovery_interval_seconds):
                return

    async def run(self, stop_event: asyncio.Event) -> None:
        async with asyncio.TaskGroup() as group:
            group.create_task(self._flush_loop(stop_event))
            group.create_task(self._recovery_loop(stop_event))

    def status(self) -> SiteRuntimeStatus:
        return SiteRuntimeStatus(
            last_flush_at=self._last_flush_at,
            last_recovery_at=self._last_recovery_at,
            last_flush_error=self._last_flush_error,
            last_recovery_error=self._last_recovery_error,
        )
