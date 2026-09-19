import datetime as dt

import pytest

from mon.domain import (
    ActionType,
    AuditRecord,
    EnforcementKind,
    EnforcementPoint,
    EnforcementResult,
    PolicyDecision,
    PolicyOutcome,
    ResponseExecution,
    ResponseExecutionStatus,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
)
from mon.enforcement import EnforcementRegistry
from mon.recovery import RecoveryEngine
from mon.site_command_models import SiteCommand, SiteCommandKind
from mon.site_response import SiteResponseExecutor
from mon.site_response_store import SQLiteSiteResponseStore


class RecordingAdapter:
    def __init__(self) -> None:
        self.execute_calls = 0
        self.rollback_calls = 0

    async def execute(self, plan, execution_id):
        self.execute_calls += 1
        return EnforcementResult(
            success=True,
            message="applied",
            external_reference=f"rule:{execution_id}",
        )

    async def rollback(self, plan, execution_id):
        self.rollback_calls += 1
        return EnforcementResult(
            success=True,
            message="rolled back",
            external_reference=f"rule:{execution_id}",
        )


def command() -> SiteCommand:
    now = dt.datetime.now(dt.UTC)
    request = ResponseRequest(
        request_id="response-1",
        tenant_id="tenant-a",
        site_id="site-a",
        incident_id="incident-1",
        target=ResponseTarget(ip_address="198.51.100.7"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="fw-1",
        ttl_seconds=30,
        reason="contain source",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw-1",
        tenant_id="tenant-a",
        site_id="site-a",
        kind=EnforcementKind.FIREWALL,
        vendor="test",
        capabilities={ActionType.BLOCK_IP},
    )
    return SiteCommand(
        command_id="command-1",
        tenant_id="tenant-a",
        site_id="site-a",
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


def registry(adapter: RecordingAdapter) -> EnforcementRegistry:
    value = EnforcementRegistry()
    value.register(EnforcementKind.FIREWALL, "test", adapter)
    return value


@pytest.mark.asyncio
async def test_response_state_survives_restart_and_expiry_recovery(tmp_path) -> None:
    path = tmp_path / "responses.db"
    adapter = RecordingAdapter()
    enforcement = registry(adapter)
    item = command()

    first_store = SQLiteSiteResponseStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    first_executor = SiteResponseExecutor(
        "tenant-a",
        "site-a",
        first_store,
        enforcement,
    )
    first = await first_executor.execute(item)
    assert first.success
    assert first.execution is not None
    assert first.execution.status is ResponseExecutionStatus.APPLIED
    assert first.execution.expires_at is not None
    assert adapter.execute_calls == 1
    first_store.close()

    reopened = SQLiteSiteResponseStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        replay_executor = SiteResponseExecutor(
            "tenant-a",
            "site-a",
            reopened,
            enforcement,
        )
        replay = await replay_executor.execute(item)
        assert replay.success
        assert replay.execution is not None
        assert replay.execution.status is ResponseExecutionStatus.APPLIED
        assert adapter.execute_calls == 1

        recovery = RecoveryEngine(replay_executor.orchestrator)
        result = await recovery.sweep_scope(
            "tenant-a",
            "site-a",
            now=first.execution.expires_at + dt.timedelta(seconds=1),
        )
        assert result.rolled_back == ("response-1",)
        assert result.failed == ()
        assert adapter.rollback_calls == 1
    finally:
        reopened.close()

    final_store = SQLiteSiteResponseStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        restored = final_store.get_response_execution(
            "tenant-a",
            "site-a",
            "response-1",
        )
        assert restored is not None
        assert restored.status is ResponseExecutionStatus.ROLLED_BACK
        assert restored.rollback_result is not None
        audits = final_store.list_audit_records("tenant-a", "site-a")
        assert [record.outcome for record in audits] == [
            "STARTED",
            "APPLIED",
            "STARTED",
            "ROLLED_BACK",
        ]
        diagnostics = final_store.diagnostics()
        assert diagnostics["responses"] == 1
        assert diagnostics["audit_records"] == 4
        assert diagnostics["statuses"] == {"ROLLED_BACK": 1}
    finally:
        final_store.close()


@pytest.mark.asyncio
async def test_restart_preserves_executing_uncertainty_without_reapplying(tmp_path) -> None:
    path = tmp_path / "responses.db"
    item = command()
    assert item.response_plan is not None
    uncertain = ResponseExecution(
        execution_id="response-1",
        tenant_id="tenant-a",
        site_id="site-a",
        plan=item.response_plan,
        status=ResponseExecutionStatus.EXECUTING,
        requested_at=item.created_at,
    )
    store = SQLiteSiteResponseStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    store.add_response_execution(uncertain)
    store.close()

    adapter = RecordingAdapter()
    reopened = SQLiteSiteResponseStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        executor = SiteResponseExecutor(
            "tenant-a",
            "site-a",
            reopened,
            registry(adapter),
        )
        replay = await executor.execute(item)

        assert replay.success is False
        assert replay.execution is not None
        assert replay.execution.status is ResponseExecutionStatus.EXECUTING
        assert replay.error == "EXECUTING"
        assert adapter.execute_calls == 0
        assert (
            executor.orchestrator.due_for_rollback(
                "tenant-a",
                "site-a",
                now=dt.datetime.now(dt.UTC) + dt.timedelta(days=1),
            )
            == []
        )
    finally:
        reopened.close()


def test_store_binds_database_to_exact_site_scope(tmp_path) -> None:
    path = tmp_path / "responses.db"
    store = SQLiteSiteResponseStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    store.close()

    with pytest.raises(ValueError, match="tenant_id mismatch"):
        SQLiteSiteResponseStore(
            path,
            tenant_id="tenant-b",
            site_id="site-a",
        )
    with pytest.raises(ValueError, match="site_id mismatch"):
        SQLiteSiteResponseStore(
            path,
            tenant_id="tenant-a",
            site_id="site-b",
        )


def test_store_rejects_foreign_nested_scope_and_naive_timestamps(tmp_path) -> None:
    store = SQLiteSiteResponseStore(
        tmp_path / "responses.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    item = command()
    assert item.response_plan is not None
    try:
        foreign_request = item.response_plan.request.model_copy(
            update={"site_id": "site-b"}
        )
        foreign_plan = item.response_plan.model_copy(
            update={"request": foreign_request}
        )
        foreign = ResponseExecution(
            execution_id="response-1",
            tenant_id="tenant-a",
            site_id="site-a",
            plan=foreign_plan,
            status=ResponseExecutionStatus.EXECUTING,
            requested_at=item.created_at,
        )
        with pytest.raises(ValueError, match="scope"):
            store.add_response_execution(foreign)

        naive = ResponseExecution(
            execution_id="response-1",
            tenant_id="tenant-a",
            site_id="site-a",
            plan=item.response_plan,
            status=ResponseExecutionStatus.EXECUTING,
            requested_at=dt.datetime(2026, 9, 19, 12, 0, 0),
        )
        with pytest.raises(ValueError, match="timezone-aware"):
            store.add_response_execution(naive)
    finally:
        store.close()


def test_audit_receipts_are_idempotent_but_collision_safe(tmp_path) -> None:
    store = SQLiteSiteResponseStore(
        tmp_path / "responses.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    record = AuditRecord(
        audit_id="audit-1",
        tenant_id="tenant-a",
        site_id="site-a",
        actor_id="mon-site",
        category="SITE_RESPONSE",
        object_type="response_execution",
        object_id="response-1",
        action="EXECUTE",
        outcome="STARTED",
    )
    try:
        assert store.add_audit_record(record) == record
        assert store.add_audit_record(record) == record
        conflicting = record.model_copy(update={"outcome": "FAILED"})
        with pytest.raises(ValueError, match="different content"):
            store.add_audit_record(conflicting)
        with pytest.raises(ValueError, match="scope"):
            store.list_audit_records("tenant-b", "site-a")
    finally:
        store.close()
