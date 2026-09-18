from __future__ import annotations

import httpx

from mon.site_command_outbox import SQLiteCommandResultOutbox
from mon.site_controller import SiteController


class ProductionSiteController(SiteController):
    """Site controller with durable, replay-safe command-result delivery."""

    def __init__(self, *args: object, result_outbox: SQLiteCommandResultOutbox, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        if result_outbox.tenant_id != self.tenant_id or result_outbox.site_id != self.site_id:
            raise ValueError("command result outbox scope does not match site controller")
        self.result_outbox = result_outbox

    async def flush_command_results(self, limit: int = 100) -> dict[str, object]:
        pending = self.result_outbox.pending(limit=limit)
        if not pending:
            return {"state": "SYNCED", "attempted": 0, "reported": 0, "queued": 0}
        if self.command_client is None:
            return {
                "state": "OFFLINE",
                "attempted": 0,
                "reported": 0,
                "queued": len(pending),
            }

        reported = 0
        for result in pending:
            try:
                await self.command_client.submit_result(result)
            except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
                self.result_outbox.mark_failed(result.command_id, str(exc))
                continue
            self.result_outbox.mark_reported(result.command_id)
            reported += 1

        queued = int(self.result_outbox.diagnostics()["queued"])
        return {
            "state": "SYNCED" if queued == 0 else "DEGRADED",
            "attempted": len(pending),
            "reported": reported,
            "queued": queued,
        }

    async def poll_commands(self, limit: int = 20) -> dict[str, object]:
        if self.command_client is None or self.response_executor is None:
            return {
                "state": "DISABLED",
                "attempted": 0,
                "reported": 0,
                "unreported": 0,
            }

        # Retry durable results before accepting more work. This bounds local
        # backlog and prevents a transient cloud failure from losing outcomes.
        await self.flush_command_results(limit=max(limit, 20))

        try:
            commands = await self.command_client.pull_commands(limit=limit)
        except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
            return {
                "state": "DEGRADED",
                "attempted": 0,
                "reported": 0,
                "unreported": int(self.result_outbox.diagnostics()["queued"]),
                "error": str(exc)[:1000],
            }

        executed = 0
        replayed = 0
        failed = 0
        for command in commands:
            if command.tenant_id != self.tenant_id or command.site_id != self.site_id:
                raise ValueError("received command outside site-controller scope")

            existing = self.result_outbox.get(command.command_id)
            if existing is not None:
                replayed += 1
                continue

            result = await self.response_executor.execute(command)
            self.result_outbox.enqueue(result)
            executed += 1
            if not result.success:
                failed += 1

        delivery = await self.flush_command_results(limit=max(limit, 20))
        queued = int(self.result_outbox.diagnostics()["queued"])
        return {
            "state": "SYNCED" if queued == 0 else "DEGRADED",
            "attempted": len(commands),
            "executed": executed,
            "replayed": replayed,
            "reported": delivery["reported"],
            "unreported": queued,
            "failed": failed,
        }

    def status(self) -> dict[str, object]:
        status = super().status()
        status["command_result_outbox"] = self.result_outbox.diagnostics()
        return status
