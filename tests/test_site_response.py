import datetime as dt

import pytest

from mon.domain import (
    ActionType,
    EnforcementKind,
    EnforcementPoint,
    EnforcementResult,
    PolicyDecision,
    PolicyOutcome,
    ResponseExecutionStatus,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
)
from mon.enforcement import EnforcementRegistry
from mon.recovery import RecoveryEngine
from mon.site_command_models import SiteCommand, SiteCommandKind
from mon.site_response import SiteResponseExecutor
from mon.store import InMemoryStore


class RecordingAdapter:
    def __init__(self) -> None:
        self.execute_calls = 0
        self.rollback_calls = 0

    async def execute(self, plan, execution_id):
        self.execute_calls += 1
        return EnforcementResult(success=True, message="applied")

    async def rollback(self, plan, execution_id):
        self.rollback_calls += 1
        return EnforcementResult(success=True, message="rolled back")


def command() -> SiteCommand:
    now = dt.datetime.now(dt.UTC)
    request = ResponseRequest(
        request_id="response-1",
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(ip_address="198.51.100.7"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="fw-1",
        ttl_seconds=30,
        reason="contain source",
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
            decision=PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                reasons=["approved by policy"],
            ),
            enforcement_point=point,
            blast_radius_estimate="single source rule",
        ),
    )


@pytest.mark.asyncio
async def test_apply_replay_and_post_rollback_replay_never_reapply() -> None:
    store = InMemoryStore()
    registry = EnforcementRegistry()
    adapter = RecordingAdapter()
    registry.register(EnforcementKind.FIREWALL, "test", adapter)
    executor = SiteResponseExecutor("t1", "s1", store, registry)
    item = command()

    first = await executor.execute(item)
    second = await executor.execute(item)
    assert first.success and second.success
    assert adapter.execute_calls == 1
    assert first.execution is not None
    assert first.execution.expires_at is not None

    recovery = RecoveryEngine(executor.orchestrator)
    await recovery.sweep_scope(
        "t1",
        "s1",
        now=first.execution.expires_at + dt.timedelta(seconds=1),
    )
    replay = await executor.execute(item)

    assert replay.success
    assert replay.execution is not None
    assert replay.execution.status is ResponseExecutionStatus.ROLLED_BACK
    assert adapter.execute_calls == 1
    assert adapter.rollback_calls == 1


@pytest.mark.asyncio
async def test_expired_command_fails_before_adapter() -> None:
    store = InMemoryStore()
    registry = EnforcementRegistry()
    adapter = RecordingAdapter()
    registry.register(EnforcementKind.FIREWALL, "test", adapter)
    executor = SiteResponseExecutor("t1", "s1", store, registry)
    item = command().model_copy(
        update={"not_after": dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)}
    )

    result = await executor.execute(item)
    assert result.success is False
    assert "expired" in (result.error or "")
    assert adapter.execute_calls == 0
