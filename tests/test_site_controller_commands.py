import datetime as dt

import pytest

from mon.domain import (
    ActionType,
    EnforcementKind,
    EnforcementPoint,
    EnforcementResult,
    PolicyDecision,
    PolicyOutcome,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
)
from mon.enforcement import EnforcementRegistry
from mon.site_command_models import SiteCommand, SiteCommandKind
from mon.site_controller import SiteController, SQLiteEventSpool
from mon.site_response import SiteResponseExecutor
from mon.store import InMemoryStore


class RecordingAdapter:
    def __init__(self) -> None:
        self.calls = 0

    async def execute(self, plan, execution_id):
        self.calls += 1
        return EnforcementResult(success=True, message="applied")

    async def rollback(self, plan, execution_id):
        return EnforcementResult(success=True, message="rolled back")


class FlakyCommandClient:
    def __init__(self, item: SiteCommand) -> None:
        self.item = item
        self.submits = 0

    async def pull_commands(self, limit=20):
        return [self.item]

    async def submit_result(self, result):
        self.submits += 1
        if self.submits == 1:
            raise OSError("simulated result upload failure")


def make_command() -> SiteCommand:
    now = dt.datetime.now(dt.UTC)
    request = ResponseRequest(
        request_id="response-1",
        tenant_id="t1",
        site_id="s1",
        incident_id="inc",
        target=ResponseTarget(ip_address="198.51.100.7"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="fw-1",
        ttl_seconds=60,
        reason="test",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw-1",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.FIREWALL,
        vendor="test",
        capabilities={ActionType.BLOCK_IP},
    )
    return SiteCommand(
        command_id="command-1",
        tenant_id="t1",
        site_id="s1",
        kind=SiteCommandKind.APPLY_RESPONSE,
        created_at=now,
        not_after=now + dt.timedelta(minutes=5),
        response_plan=ResponsePlan(
            request=request,
            decision=PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["test"]),
            enforcement_point=point,
            blast_radius_estimate="single source",
        ),
    )


@pytest.mark.asyncio
async def test_result_upload_failure_causes_safe_replay_not_reexecution(tmp_path) -> None:
    store = InMemoryStore()
    registry = EnforcementRegistry()
    adapter = RecordingAdapter()
    registry.register(EnforcementKind.FIREWALL, "test", adapter)
    executor = SiteResponseExecutor("t1", "s1", store, registry)
    command = make_command()
    client = FlakyCommandClient(command)
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController(
        "t1",
        "s1",
        spool,
        command_client=client,
        response_executor=executor,
    )
    try:
        first = await controller.poll_commands()
        second = await controller.poll_commands()
    finally:
        spool.close()

    assert first["state"] == "DEGRADED"
    assert second["state"] == "SYNCED"
    assert adapter.calls == 1
    assert client.submits == 2
