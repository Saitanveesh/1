import datetime as dt

import pytest

from mon.domain import (
    ActionType,
    EnforcementKind,
    EnforcementPoint,
    EnforcementResult,
    EnforcementVerification,
    EnforcementVerificationState,
    PolicyDecision,
    PolicyOutcome,
    ResponseExecution,
    ResponseExecutionStatus,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
)
from mon.enforcement import EnforcementRegistry
from mon.site_command_models import SiteCommand, SiteCommandKind
from mon.site_controller import SiteController, SQLiteEventSpool
from mon.site_response import SiteResponseExecutor
from mon.store import InMemoryStore


class VerifyingAdapter:
    def __init__(self, state: EnforcementVerificationState) -> None:
        self.state = state
        self.execute_calls = 0
        self.verify_calls = 0
        self.rollback_calls = 0

    async def execute(self, plan, execution_id):
        self.execute_calls += 1
        return EnforcementResult(success=True, message="applied")

    async def verify(self, plan, execution_id):
        self.verify_calls += 1
        return EnforcementVerification(
            state=self.state,
            message=f"verified {self.state.value.lower()}",
            external_reference=f"test:{execution_id}",
        )

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
        vendor="verifying",
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


def executor_with_interrupted_state(
    adapter: VerifyingAdapter,
    *,
    requested_at: dt.datetime | None = None,
):
    item = command()
    assert item.response_plan is not None
    store = InMemoryStore()
    interrupted = ResponseExecution(
        execution_id="response-1",
        tenant_id="t1",
        site_id="s1",
        plan=item.response_plan,
        status=ResponseExecutionStatus.EXECUTING,
        requested_at=requested_at or item.created_at,
    )
    store.add_response_execution(interrupted)
    registry = EnforcementRegistry()
    registry.register(EnforcementKind.FIREWALL, "verifying", adapter)
    executor = SiteResponseExecutor("t1", "s1", store, registry)
    return item, store, executor, interrupted


@pytest.mark.asyncio
async def test_present_effect_reconciles_without_reapplying() -> None:
    adapter = VerifyingAdapter(EnforcementVerificationState.PRESENT)
    requested_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=10)
    item, store, executor, interrupted = executor_with_interrupted_state(
        adapter,
        requested_at=requested_at,
    )

    result = await executor.execute(item)

    assert result.success
    assert result.execution is not None
    assert result.execution.status is ResponseExecutionStatus.APPLIED
    assert result.execution.applied_at is None
    assert result.execution.expires_at == requested_at + dt.timedelta(seconds=30)
    assert result.execution.result is not None
    assert result.execution.result.details["reconciled_after_interruption"] is True
    assert adapter.execute_calls == 0
    assert adapter.verify_calls == 1
    restored = store.get_response_execution("t1", "s1", "response-1")
    assert restored == result.execution
    audits = store.list_audit_records("t1", "s1")
    assert any(
        record.action == "VERIFY" and record.outcome == "PRESENT"
        for record in audits
    )
    assert interrupted.applied_at is None


@pytest.mark.asyncio
async def test_absent_effect_resolves_interrupted_execution_as_failed() -> None:
    adapter = VerifyingAdapter(EnforcementVerificationState.ABSENT)
    item, store, executor, _ = executor_with_interrupted_state(adapter)

    result = await executor.execute(item)

    assert result.success is False
    assert result.execution is not None
    assert result.execution.status is ResponseExecutionStatus.FAILED
    assert "confirmed the effect is absent" in (result.error or "")
    assert adapter.execute_calls == 0
    assert adapter.verify_calls == 1
    restored = store.get_response_execution("t1", "s1", "response-1")
    assert restored is not None
    assert restored.status is ResponseExecutionStatus.FAILED


@pytest.mark.asyncio
async def test_unknown_effect_stays_executing_and_is_not_guessed() -> None:
    adapter = VerifyingAdapter(EnforcementVerificationState.UNKNOWN)
    item, store, executor, _ = executor_with_interrupted_state(adapter)

    result = await executor.execute(item)

    assert result.success is False
    assert result.execution is not None
    assert result.execution.status is ResponseExecutionStatus.EXECUTING
    assert result.error == "EXECUTING"
    assert adapter.execute_calls == 0
    assert adapter.verify_calls == 1
    restored = store.get_response_execution("t1", "s1", "response-1")
    assert restored is not None
    assert restored.status is ResponseExecutionStatus.EXECUTING


@pytest.mark.asyncio
async def test_offline_recovery_verifies_then_rolls_back_expired_effect(tmp_path) -> None:
    adapter = VerifyingAdapter(EnforcementVerificationState.PRESENT)
    requested_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=2)
    _, _, executor, _ = executor_with_interrupted_state(
        adapter,
        requested_at=requested_at,
    )
    spool = SQLiteEventSpool(tmp_path / "events.db")
    controller = SiteController(
        "t1",
        "s1",
        spool,
        sender=None,
        response_executor=executor,
    )
    try:
        result = await controller.recover_expired_responses(
            now=dt.datetime.now(dt.UTC)
        )
    finally:
        spool.close()

    assert result["state"] == "RECOVERED"
    assert result["execution_reconciliation"]["present"] == 1
    assert result["execution_reconciliation"]["unresolved"] == 0
    assert result["rolled_back"] == 1
    assert adapter.verify_calls == 1
    assert adapter.execute_calls == 0
    assert adapter.rollback_calls == 1
