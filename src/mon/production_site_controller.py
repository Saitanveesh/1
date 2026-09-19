from __future__ import annotations

import datetime as dt

import httpx

from mon.site_command_outbox import SQLiteCommandResultOutbox
from mon.site_controller import SiteController
from mon.site_response_models import SiteResponseUpdate
from mon.site_response_outbox import SQLiteResponseUpdateOutbox


class ProductionSiteController(SiteController):
    """Site controller with durable command and autonomous-recovery reporting."""

    def __init__(
        self,
        *args: object,
        result_outbox: SQLiteCommandResultOutbox,
        response_update_outbox: SQLiteResponseUpdateOutbox,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)
        if result_outbox.tenant_id != self.tenant_id or result_outbox.site_id != self.site_id:
            raise ValueError("command result outbox scope does not match site controller")
        if (
            response_update_outbox.tenant_id != self.tenant_id
            or response_update_outbox.site_id != self.site_id
        ):
            raise ValueError("response update outbox scope does not match site controller")
        self.result_outbox = result_outbox
        self.response_update_outbox = response_update_outbox

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

    async def flush_response_updates(self, limit: int = 100) -> dict[str, object]:
        pending = self.response_update_outbox.pending(limit=limit)
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
        for update in pending:
            try:
                await self.command_client.submit_response_update(update)
            except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
                self.response_update_outbox.mark_failed(update.update_id, str(exc))
                continue
            self.response_update_outbox.mark_delivered(update.update_id)
            reported += 1

        queued = int(self.response_update_outbox.diagnostics()["queued"])
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

        # Apply-command results are causal predecessors of autonomous recovery
        # updates. Flush them first so the control plane sees APPLIED before a
        # later site-local ROLLED_BACK state.
        await self.flush_command_results(limit=max(limit, 20))
        await self.flush_response_updates(limit=max(limit, 20))

        try:
            commands = await self.command_client.pull_commands(limit=limit)
        except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
            return {
                "state": "DEGRADED",
                "attempted": 0,
                "reported": 0,
                "unreported": int(self.result_outbox.diagnostics()["queued"]),
                "unreported_response_updates": int(
                    self.response_update_outbox.diagnostics()["queued"]
                ),
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
        response_delivery = await self.flush_response_updates(limit=max(limit, 20))
        queued = int(self.result_outbox.diagnostics()["queued"])
        queued_updates = int(self.response_update_outbox.diagnostics()["queued"])
        return {
            "state": "SYNCED" if queued == 0 and queued_updates == 0 else "DEGRADED",
            "attempted": len(commands),
            "executed": executed,
            "replayed": replayed,
            "reported": delivery["reported"],
            "unreported": queued,
            "response_updates_reported": response_delivery["reported"],
            "unreported_response_updates": queued_updates,
            "failed": failed,
        }

    async def recover_expired_responses(
        self,
        *,
        now: dt.datetime | None = None,
    ) -> dict[str, object]:
        result = await super().recover_expired_responses(now=now)
        if self.recovery_engine is not None:
            execution_ids = [
                *result.get("rolled_back_execution_ids", []),
                *result.get("failed_execution_ids", []),
            ]
            for execution_id in execution_ids:
                execution = self.recovery_engine.orchestrator.store.get_response_execution(
                    self.tenant_id,
                    self.site_id,
                    str(execution_id),
                )
                if execution is None:
                    continue
                audits = [
                    record
                    for record in self.recovery_engine.orchestrator.store.list_audit_records(
                        self.tenant_id,
                        self.site_id,
                    )
                    if record.object_type == "response_execution"
                    and record.object_id == execution.execution_id
                ]
                self.response_update_outbox.enqueue(
                    SiteResponseUpdate(
                        tenant_id=self.tenant_id,
                        site_id=self.site_id,
                        execution=execution,
                        audit_records=audits,
                    )
                )

        delivery = await self.flush_response_updates()
        result["response_update_sync_state"] = delivery["state"]
        result["response_updates_reported"] = delivery["reported"]
        result["unreported_response_updates"] = delivery["queued"]
        return result

    def status(self) -> dict[str, object]:
        status = super().status()
        status["command_result_outbox"] = self.result_outbox.diagnostics()
        status["response_update_outbox"] = self.response_update_outbox.diagnostics()
        return status
