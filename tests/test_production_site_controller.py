import datetime as dt

import pytest

from mon.production_site_controller import ProductionSiteController
from mon.site_command_models import SiteCommand, SiteCommandKind, SiteCommandResult
from mon.site_command_outbox import SQLiteCommandResultOutbox
from mon.site_controller import SQLiteEventSpool
from mon.site_response_outbox import SQLiteResponseUpdateOutbox
from mon.store import InMemoryStore


class FakeExecutor:
    def __init__(self) -> None:
        self.calls = 0
        # SiteController derives its local recovery engine from the response
        # executor's orchestrator. Keep the fake aligned with that contract.
        self.orchestrator = type("FakeOrchestrator", (), {"store": InMemoryStore()})()
        self.store = self.orchestrator.store

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


def test_compaction_removes_only_old_acknowledged_receipts(tmp_path) -> None:
    outbox = SQLiteCommandResultOutbox(
        tmp_path / "results.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    now = dt.datetime(2026, 9, 19, tzinfo=dt.UTC)
    old = SiteCommandResult(
        command_id="old",
        tenant_id="tenant-a",
        site_id="site-a",
        success=False,
        error="historical failed command result",
    )
    pending = SiteCommandResult(
        command_id="pending",
        tenant_id="tenant-a",
        site_id="site-a",
        success=False,
        error="unreported failed command result",
    )
    try:
        outbox.enqueue(old)
        outbox.enqueue(pending)
        assert outbox.mark_reported("old") is True
        # Set a deterministic old acknowledgement without changing production API.
        outbox._connection.execute(
            "UPDATE command_result_outbox SET reported_at = ? WHERE command_id = ?",
            ((now - dt.timedelta(days=31)).isoformat(), "old"),
        )
        outbox._connection.commit()
        assert outbox.compact_reported(retain_for=dt.timedelta(days=30), now=now) == 1
        assert outbox.get("old") is None
        assert outbox.get("pending") == pending
        assert outbox.diagnostics()["queued"] == 1
    finally:
        outbox.close()


def test_compaction_rejects_unsafe_retention(tmp_path) -> None:
    outbox = SQLiteCommandResultOutbox(
        tmp_path / "results.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        with pytest.raises(ValueError, match="positive"):
            outbox.compact_reported(retain_for=dt.timedelta(0))
        with pytest.raises(ValueError, match="timezone-aware"):
            outbox.compact_reported(
                retain_for=dt.timedelta(days=1),
                now=dt.datetime(2026, 9, 19),
            )
    finally:
        outbox.close()


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
        first = await controller.poll_commands()
        second = await controller.poll_commands()
    finally:
        event_spool.close()
        result_outbox.close()
        response_update_outbox.close()

    assert first["state"] == "DEGRADED"
    assert first["unreported"] == 1
    assert second["state"] == "SYNCED"
    assert executor.calls == 1
    assert client.submits == 2


def test_superseded_result_receipt_is_retained_but_not_retried(tmp_path) -> None:
    outbox = SQLiteCommandResultOutbox(
        tmp_path / "results.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    result = SiteCommandResult(
        command_id="cmd-superseded",
        tenant_id="tenant-a",
        site_id="site-a",
        success=False,
        error="late result",
    )
    try:
        assert outbox.enqueue(result)
        assert outbox.pending() == [result]
        assert outbox.mark_superseded(
            result.command_id,
            "state converged through response reconciliation",
        )
        assert outbox.pending() == []
        assert outbox.get(result.command_id) == result
        assert outbox.is_superseded(result.command_id)
        assert outbox.is_reported(result.command_id) is False
        diagnostics = outbox.diagnostics()
        assert diagnostics["queued"] == 0
        assert diagnostics["superseded"] == 1
        assert outbox.mark_failed(result.command_id, "should not retry") is False
    finally:
        outbox.close()
