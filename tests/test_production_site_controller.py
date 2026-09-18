import datetime as dt

import pytest

from mon.production_site_controller import ProductionSiteController
from mon.site_command_models import SiteCommand, SiteCommandKind, SiteCommandResult
from mon.site_command_outbox import SQLiteCommandResultOutbox
from mon.site_controller import SQLiteEventSpool


class FakeExecutor:
    def __init__(self) -> None:
        self.calls = 0
        # SiteController derives its local recovery engine from the response
        # executor's orchestrator. Keep the fake aligned with that contract.
        self.orchestrator = object()

    async def execute(self, command: SiteCommand) -> SiteCommandResult:
        self.calls += 1
        return SiteCommandResult(
            command_id=command.command_id,
            tenant_id=command.tenant_id,
            site_id=command.site_id,
            success=False,
            error="sandbox adapter rejected action",
        )


class FlakyClient:
    def __init__(self, command: SiteCommand) -> None:
        self.command = command
        self.submits = 0

    async def pull_commands(self, limit: int = 20) -> list[SiteCommand]:
        return [self.command]

    async def submit_result(self, result: SiteCommandResult) -> None:
        self.submits += 1
        if self.submits == 1:
            raise OSError("control plane unavailable")


def make_rollback_command() -> SiteCommand:
    now = dt.datetime.now(dt.UTC)
    return SiteCommand(
        command_id="cmd-1",
        tenant_id="tenant-a",
        site_id="site-a",
        kind=SiteCommandKind.ROLLBACK_RESPONSE,
        created_at=now,
        not_after=now + dt.timedelta(minutes=5),
        rollback_execution_id="execution-1",
        reason="operator rollback",
    )


def test_result_outbox_persists_and_enforces_scope(tmp_path) -> None:
    path = tmp_path / "results.db"
    result = SiteCommandResult(
        command_id="cmd-1",
        tenant_id="tenant-a",
        site_id="site-a",
        success=False,
        error="test failure",
    )
    outbox = SQLiteCommandResultOutbox(path, tenant_id="tenant-a", site_id="site-a")
    assert outbox.enqueue(result) is True
    outbox.close()

    reopened = SQLiteCommandResultOutbox(path, tenant_id="tenant-a", site_id="site-a")
    try:
        assert reopened.get("cmd-1") == result
        foreign = result.model_copy(update={"tenant_id": "tenant-b"})
        with pytest.raises(ValueError, match="scope"):
            reopened.enqueue(foreign)
    finally:
        reopened.close()


@pytest.mark.asyncio
async def test_command_result_survives_upload_failure_without_reexecution(tmp_path) -> None:
    command = make_rollback_command()
    client = FlakyClient(command)
    executor = FakeExecutor()
    event_spool = SQLiteEventSpool(tmp_path / "events.db")
    result_outbox = SQLiteCommandResultOutbox(
        tmp_path / "results.db",
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
    )
    try:
        first = await controller.poll_commands()
        second = await controller.poll_commands()
    finally:
        event_spool.close()
        result_outbox.close()

    assert first["state"] == "DEGRADED"
    assert first["unreported"] == 1
    assert second["state"] == "SYNCED"
    assert executor.calls == 1
    assert client.submits == 2
