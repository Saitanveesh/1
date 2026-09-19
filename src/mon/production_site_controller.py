from __future__ import annotations

import datetime as dt

import httpx

from mon.domain import AuditRecord, ResponseExecutionStatus
from mon.site_command_outbox import SQLiteCommandResultOutbox
from mon.site_controller import SiteController
from mon.site_response_models import (
    SiteResponseUpdate,
    SiteResponseUpdateKind,
    execution_reconciliation_update_id,
    recovery_update_id,
)
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
            self.response_update_outbox.mark_reported(update.update_id)
            if (
                update.kind is SiteResponseUpdateKind.EXECUTION_RECONCILIATION
                and update.command_id is not None
            ):
                self.result_outbox.mark_superseded(
                    update.command_id,
                    "late execution state reconciled through response update",
                )
            reported += 1

        queued = int(self.response_update_outbox.diagnostics()["queued"])
        return {
            "state": "SYNCED" if queued == 0 else "DEGRADED",
            "attempted": len(pending),
            "reported": reported,
            "queued": queued,
        }

    @staticmethod
    def _parse_command_not_after(record: AuditRecord) -> dt.datetime | None:
        raw = record.details.get("command_not_after")
        if not isinstance(raw, str):
            return None
        try:
            value = dt.datetime.fromisoformat(raw)
        except ValueError:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            return None
        return value.astimezone(dt.UTC)

    def _enqueue_execution_reconciliation_updates(
        self,
        *,
        now: dt.datetime | None = None,
    ) -> int:
        if self.response_executor is None:
            return 0

        check_at = now or dt.datetime.now(dt.UTC)
        if check_at.tzinfo is None or check_at.utcoffset() is None:
            raise ValueError("execution reconciliation time must be timezone-aware")
        check_at = check_at.astimezone(dt.UTC)

        store = self.response_executor.store
        audits = store.list_audit_records(self.tenant_id, self.site_id)
        enqueued = 0
        supported = {
            ResponseExecutionStatus.APPLIED,
            ResponseExecutionStatus.FAILED,
            ResponseExecutionStatus.ROLLED_BACK,
            ResponseExecutionStatus.ROLLBACK_FAILED,
        }
        for execution in store.list_response_executions(self.tenant_id, self.site_id):
            if execution.status not in supported:
                continue
            related = [
                record
                for record in audits
                if record.object_type == "response_execution"
                and record.object_id == execution.execution_id
            ]
            verification = [
                record
                for record in related
                if record.actor_id == "mon-site-reconciliation"
                and record.action == "VERIFY"
                and record.outcome in {"PRESENT", "ABSENT"}
            ]
            if not verification:
                continue

            contexts: set[tuple[str, dt.datetime]] = set()
            for record in related:
                if record.action != "EXECUTE" or record.outcome != "STARTED":
                    continue
                command_id = record.details.get("command_id")
                not_after = self._parse_command_not_after(record)
                if isinstance(command_id, str) and command_id and not_after is not None:
                    contexts.add((command_id, not_after))
            if len(contexts) != 1:
                continue

            command_id, not_after = next(iter(contexts))
            if check_at < not_after:
                continue
            if self.result_outbox.is_reported(command_id):
                continue
            if self.result_outbox.is_superseded(command_id):
                continue

            observed_at = max(record.occurred_at for record in related)
            update = SiteResponseUpdate(
                update_id=execution_reconciliation_update_id(
                    execution,
                    command_id,
                ),
                kind=SiteResponseUpdateKind.EXECUTION_RECONCILIATION,
                command_id=command_id,
                tenant_id=self.tenant_id,
                site_id=self.site_id,
                execution=execution,
                audit_records=related,
                observed_at=observed_at,
            )
            if self.response_update_outbox.enqueue(update):
                enqueued += 1
        return enqueued

    def _enqueue_autonomous_recovery_updates(self) -> int:
        if self.recovery_engine is None:
            return 0

        store = self.recovery_engine.orchestrator.store
        audits = store.list_audit_records(self.tenant_id, self.site_id)
        recovery_audits: dict[str, list[AuditRecord]] = {}
        for record in audits:
            if (
                record.object_type == "response_execution"
                and record.action == "ROLLBACK"
                and record.actor_id == self.recovery_engine.actor_id
            ):
                recovery_audits.setdefault(record.object_id, []).append(record)

        enqueued = 0
        for execution in store.list_response_executions(self.tenant_id, self.site_id):
            related_recovery = recovery_audits.get(execution.execution_id, [])
            if not related_recovery:
                continue
            related_audits = [
                record
                for record in audits
                if record.object_type == "response_execution"
                and record.object_id == execution.execution_id
            ]
            if any(
                record.actor_id == "mon-site-reconciliation"
                and record.action == "VERIFY"
                for record in related_audits
            ):
                # Interrupted executions use the richer reconciliation update,
                # which can carry both verified apply evidence and final rollback.
                continue
            if execution.status not in {
                ResponseExecutionStatus.ROLLED_BACK,
                ResponseExecutionStatus.ROLLBACK_FAILED,
            }:
                continue

            observed_at = max(record.occurred_at for record in related_recovery)
            update = SiteResponseUpdate(
                update_id=recovery_update_id(execution),
                tenant_id=self.tenant_id,
                site_id=self.site_id,
                execution=execution,
                audit_records=related_audits,
                observed_at=observed_at,
            )
            if self.response_update_outbox.enqueue(update):
                enqueued += 1
        return enqueued

    def compact_response_update_receipts(
        self,
        *,
        retain_for: dt.timedelta,
        now: dt.datetime | None = None,
    ) -> int:
        return self.response_update_outbox.compact_reported(
            retain_for=retain_for,
            now=now,
        )

    async def poll_commands(self, limit: int = 20) -> dict[str, object]:
        if self.command_client is None or self.response_executor is None:
            return {
                "state": "DISABLED",
                "attempted": 0,
                "reported": 0,
                "unreported": 0,
            }

        # Normal command results are the preferred causal path. Only after
        # attempting them do we reconstruct late evidence-backed reconciliation
        # for commands whose delivery window has elapsed.
        await self.flush_command_results(limit=max(limit, 20))
        self._enqueue_execution_reconciliation_updates()
        self._enqueue_autonomous_recovery_updates()
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
        deferred = 0
        for command in commands:
            if command.tenant_id != self.tenant_id or command.site_id != self.site_id:
                raise ValueError("received command outside site-controller scope")

            existing = self.result_outbox.get(command.command_id)
            if existing is not None:
                replayed += 1
                continue

            result = await self.response_executor.execute(command)
            if (
                result.execution is not None
                and result.execution.status is ResponseExecutionStatus.EXECUTING
            ):
                # Do not persist or upload a terminal command receipt while an
                # interrupted external action remains unverified. The control
                # plane will redeliver the command and verification can retry.
                deferred += 1
                continue
            self.result_outbox.enqueue(result)
            executed += 1
            if not result.success:
                failed += 1

        delivery = await self.flush_command_results(limit=max(limit, 20))
        self._enqueue_execution_reconciliation_updates()
        response_delivery = await self.flush_response_updates(limit=max(limit, 20))
        queued = int(self.result_outbox.diagnostics()["queued"])
        queued_updates = int(self.response_update_outbox.diagnostics()["queued"])
        return {
            "state": (
                "SYNCED"
                if queued == 0 and queued_updates == 0 and deferred == 0
                else "DEGRADED"
            ),
            "attempted": len(commands),
            "executed": executed,
            "replayed": replayed,
            "deferred": deferred,
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
        await self.flush_command_results()
        result = await super().recover_expired_responses(now=now)
        reconciliation_enqueued = self._enqueue_execution_reconciliation_updates(
            now=now,
        )
        recovery_enqueued = self._enqueue_autonomous_recovery_updates()
        result["execution_reconciliation_updates_enqueued"] = reconciliation_enqueued
        result["response_updates_enqueued"] = (
            reconciliation_enqueued + recovery_enqueued
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
