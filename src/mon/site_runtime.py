from __future__ import annotations

import asyncio
import datetime as dt
from dataclasses import dataclass

from mon.event_fabric_outbox import sanitize_fabric_error
from mon.site_controller import SiteController


@dataclass(frozen=True, slots=True)
class SiteRuntimeStatus:
    last_flush_at: dt.datetime | None
    last_recovery_at: dt.datetime | None
    last_command_poll_at: dt.datetime | None
    last_sensor_trust_at: dt.datetime | None
    last_flush_state: str | None
    last_recovery_state: str | None
    last_command_state: str | None
    last_sensor_trust_state: str | None
    last_flush_error: str | None
    last_recovery_error: str | None
    last_command_error: str | None
    last_sensor_trust_error: str | None


class SiteControllerRuntime:
    """Independent local loops for cloud sync, command delivery, and TTL recovery."""

    def __init__(
        self,
        controller: SiteController,
        *,
        flush_interval_seconds: float = 5.0,
        recovery_interval_seconds: float = 5.0,
        command_interval_seconds: float = 2.0,
        sensor_trust_interval_seconds: float = 15.0,
    ) -> None:
        if (
            flush_interval_seconds <= 0
            or recovery_interval_seconds <= 0
            or command_interval_seconds <= 0
            or sensor_trust_interval_seconds <= 0
        ):
            raise ValueError("runtime intervals must be positive")
        self.controller = controller
        self.flush_interval_seconds = flush_interval_seconds
        self.recovery_interval_seconds = recovery_interval_seconds
        self.command_interval_seconds = command_interval_seconds
        self.sensor_trust_interval_seconds = sensor_trust_interval_seconds
        self._last_flush_at: dt.datetime | None = None
        self._last_recovery_at: dt.datetime | None = None
        self._last_command_poll_at: dt.datetime | None = None
        self._last_sensor_trust_at: dt.datetime | None = None
        self._last_flush_state: str | None = None
        self._last_recovery_state: str | None = None
        self._last_command_state: str | None = None
        self._last_sensor_trust_state: str | None = None
        self._last_flush_error: str | None = None
        self._last_recovery_error: str | None = None
        self._last_command_error: str | None = None
        self._last_sensor_trust_error: str | None = None

    @staticmethod
    async def _wait_or_stop(stop_event: asyncio.Event, seconds: float) -> bool:
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=seconds)
        except TimeoutError:
            return False
        return True

    @staticmethod
    def _result_state(result: dict[str, object]) -> str:
        state = result.get("state")
        return str(state) if state is not None else "UNKNOWN"

    @staticmethod
    def _result_error(result: dict[str, object]) -> str | None:
        error = result.get("error")
        if error is None:
            return None
        text = sanitize_fabric_error(error)
        return text if text else None

    def _flush_wait_seconds(self, result: dict[str, object]) -> float:
        wait_seconds = self.flush_interval_seconds
        raw_next = result.get("fabric_next_attempt_at")
        if not isinstance(raw_next, str) or not raw_next.strip():
            return wait_seconds
        try:
            next_attempt_at = dt.datetime.fromisoformat(raw_next)
        except ValueError:
            return wait_seconds
        if (
            next_attempt_at.tzinfo is None
            or next_attempt_at.utcoffset() is None
        ):
            return wait_seconds
        now = dt.datetime.now(dt.UTC)
        until_due = (next_attempt_at.astimezone(dt.UTC) - now).total_seconds()
        if until_due <= wait_seconds:
            return wait_seconds
        return min(until_due, 3600.0)

    async def _flush_loop(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                result = await self.controller.flush()
                self._last_flush_state = self._result_state(result)
                self._last_flush_error = self._result_error(result)
            except Exception as exc:
                self._last_flush_state = "ERROR"
                self._last_flush_error = sanitize_fabric_error(exc)
                wait_seconds = self.flush_interval_seconds
            else:
                wait_seconds = self._flush_wait_seconds(result)
            self._last_flush_at = dt.datetime.now(dt.UTC)
            if await self._wait_or_stop(stop_event, wait_seconds):
                return

    async def _recovery_loop(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                result = await self.controller.recover_expired_responses()
                self._last_recovery_state = self._result_state(result)
                self._last_recovery_error = self._result_error(result)
            except Exception as exc:
                self._last_recovery_state = "ERROR"
                self._last_recovery_error = sanitize_fabric_error(exc)
            self._last_recovery_at = dt.datetime.now(dt.UTC)
            if await self._wait_or_stop(stop_event, self.recovery_interval_seconds):
                return

    async def _command_loop(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                result = await self.controller.poll_commands()
                self._last_command_state = self._result_state(result)
                self._last_command_error = self._result_error(result)
            except Exception as exc:
                self._last_command_state = "ERROR"
                self._last_command_error = str(exc)[:1000]
            self._last_command_poll_at = dt.datetime.now(dt.UTC)
            if await self._wait_or_stop(stop_event, self.command_interval_seconds):
                return

    async def _sensor_trust_loop(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            sync = getattr(self.controller, "sync_sensor_trust", None)
            if sync is None:
                self._last_sensor_trust_state = "DISABLED"
                self._last_sensor_trust_error = None
            else:
                try:
                    result = await sync()
                    self._last_sensor_trust_state = self._result_state(result)
                    self._last_sensor_trust_error = self._result_error(result)
                except Exception as exc:
                    self._last_sensor_trust_state = "ERROR"
                    self._last_sensor_trust_error = sanitize_fabric_error(exc)
            self._last_sensor_trust_at = dt.datetime.now(dt.UTC)
            if await self._wait_or_stop(
                stop_event,
                self.sensor_trust_interval_seconds,
            ):
                return

    async def run(self, stop_event: asyncio.Event) -> None:
        async with asyncio.TaskGroup() as group:
            group.create_task(self._flush_loop(stop_event))
            group.create_task(self._recovery_loop(stop_event))
            group.create_task(self._command_loop(stop_event))
            group.create_task(self._sensor_trust_loop(stop_event))

    def status(self) -> SiteRuntimeStatus:
        return SiteRuntimeStatus(
            last_flush_at=self._last_flush_at,
            last_recovery_at=self._last_recovery_at,
            last_command_poll_at=self._last_command_poll_at,
            last_sensor_trust_at=self._last_sensor_trust_at,
            last_flush_state=self._last_flush_state,
            last_recovery_state=self._last_recovery_state,
            last_command_state=self._last_command_state,
            last_sensor_trust_state=self._last_sensor_trust_state,
            last_flush_error=self._last_flush_error,
            last_recovery_error=self._last_recovery_error,
            last_command_error=self._last_command_error,
            last_sensor_trust_error=self._last_sensor_trust_error,
        )
