import datetime as dt

import pytest

from mon.domain import (
    ActionType,
    EnforcementKind,
    EnforcementPoint,
    PolicyDecision,
    PolicyOutcome,
    ResponseExecution,
    ResponseExecutionStatus,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
)
from mon.production_site_controller import ProductionSiteController
from mon.site_command_models import SiteCommand, SiteCommandKind, SiteCommandResult
from mon.site_command_outbox import SQLiteCommandResultOutbox
from mon.site_controller import SQLiteEventSpool
from mon.site_response_outbox import SQLiteResponseUpdateOutbox
from mon.store import InMemoryStore


def apply_command() -> SiteCommand:
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
                reasons=["approved"],
            ),
            enforcement_point=point,
            blast_radius_estimate="single source rule",
        ),
    )


class PendingClient:
    def __init__(self, command: SiteCommand) -> None:
        self.command = command
        self.submits = 0

    async def pull_commands(self, limit: int = 20) -> list[SiteCommand]:
        return [self.command]

    async def submit_result(self, result: SiteCommandResult) -> None:
        self.submits += 1

    async def submit_response_update(self, update) -> None:
        raise AssertionError("no recovery update should be submitted")


class DeferredExecutor:
    def __init__(self, command: SiteCommand) -> None:
        assert command.response_plan is not None
        self.calls = 0
        self.tenant_id = command.tenant_id
        self.site_id = command.site_id
        self.execution = ResponseExecution(
            execution_id=command.response_plan.request.request_id,
            tenant_id=command.tenant_id,
            site_id=command.site_id,
            plan=command.response_plan,
            status=ResponseExecutionStatus.EXECUTING,
            requested_at=command.created_at,
        )
        store = InMemoryStore()
        store.add_response_execution(self.execution)
        self.store = store
        self.orchestrator = type(
            "FakeOrchestrator",
            (),
            {"store": store},
        )()

    async def execute(self, command: SiteCommand) -> SiteCommandResult:
        self.calls += 1
        return SiteCommandResult(
            command_id=command.command_id,
            tenant_id=command.tenant_id,
            site_id=command.site_id,
            success=False,
            execution=self.execution,
            error="EXECUTING",
        )


@pytest.mark.asyncio
async def test_production_controller_does_not_receipt_uncertain_command(tmp_path) -> None:
    command = apply_command()
    client = PendingClient(command)
    executor = DeferredExecutor(command)
    event_spool = SQLiteEventSpool(tmp_path / "events.db")
    result_outbox = SQLiteCommandResultOutbox(
        tmp_path / "command-results.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    response_update_outbox = SQLiteResponseUpdateOutbox(
        tmp_path / "response-updates.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    controller = ProductionSiteController(
        "tenant-a",
        "site-a",
        event_spool,
        command_client=client,
        response_executor=executor,
        result_outbox=result_outbox,
        response_update_outbox=response_update_outbox,
    )
    try:
        result = await controller.poll_commands()
        status = controller.status()
    finally:
        event_spool.close()
        result_outbox.close()
        response_update_outbox.close()

    assert result["state"] == "DEGRADED"
    assert result["deferred"] == 1
    assert result["executed"] == 0
    assert result["reported"] == 0
    assert result["unreported"] == 0
    assert executor.calls == 1
    assert client.submits == 0
    assert status["response_state"]["executing_uncertain"] == 1
