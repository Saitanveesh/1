import asyncio

import pytest

from mon.site_runtime import SiteControllerRuntime


class FakeController:
    def __init__(self, stop_event: asyncio.Event) -> None:
        self.stop_event = stop_event
        self.flush_calls = 0
        self.recovery_calls = 0
        self.command_calls = 0

    async def flush(self):
        self.flush_calls += 1
        return {"state": "DEGRADED", "error": "cloud unavailable"}

    async def recover_expired_responses(self):
        self.recovery_calls += 1
        self.stop_event.set()
        return {"state": "RECOVERED"}

    async def poll_commands(self):
        self.command_calls += 1
        return {"state": "DISABLED"}


@pytest.mark.asyncio
async def test_site_runtime_runs_recovery_without_waiting_for_cloud_loop() -> None:
    stop_event = asyncio.Event()
    controller = FakeController(stop_event)
    runtime = SiteControllerRuntime(
        controller,
        flush_interval_seconds=0.01,
        recovery_interval_seconds=0.01,
        command_interval_seconds=0.01,
    )

    await asyncio.wait_for(runtime.run(stop_event), timeout=1)

    status = runtime.status()
    assert controller.recovery_calls >= 1
    assert status.last_recovery_at is not None
    assert status.last_recovery_state == "RECOVERED"


@pytest.mark.asyncio
async def test_site_runtime_preserves_degraded_result_state_without_exception() -> None:
    stop_event = asyncio.Event()
    controller = FakeController(stop_event)
    runtime = SiteControllerRuntime(
        controller,
        flush_interval_seconds=0.01,
        recovery_interval_seconds=0.01,
        command_interval_seconds=0.01,
    )

    await asyncio.wait_for(runtime.run(stop_event), timeout=1)

    status = runtime.status()
    assert status.last_flush_state == "DEGRADED"
    assert status.last_flush_error == "cloud unavailable"
    assert status.last_command_state in {"DISABLED", None}
