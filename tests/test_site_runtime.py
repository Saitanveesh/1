import asyncio

import pytest

from mon.site_runtime import SiteControllerRuntime


class FakeController:
    def __init__(self, stop_event: asyncio.Event) -> None:
        self.stop_event = stop_event
        self.flush_calls = 0
        self.recovery_calls = 0

    async def flush(self):
        self.flush_calls += 1
        return {"state": "SYNCED"}

    async def recover_expired_responses(self):
        self.recovery_calls += 1
        self.stop_event.set()
        return {"state": "RECOVERED"}


@pytest.mark.asyncio
async def test_site_runtime_runs_recovery_without_waiting_for_cloud_loop() -> None:
    stop_event = asyncio.Event()
    controller = FakeController(stop_event)
    runtime = SiteControllerRuntime(
        controller,
        flush_interval_seconds=0.01,
        recovery_interval_seconds=0.01,
    )

    await asyncio.wait_for(runtime.run(stop_event), timeout=1)

    assert controller.recovery_calls >= 1
    assert runtime.status().last_recovery_at is not None
