from __future__ import annotations

import datetime as dt

from mon.domain import AuditRecord, ResponseExecutionStatus
from mon.site_command_models import (
    SiteCommand,
    SiteCommandKind,
    SiteCommandRecord,
    SiteCommandResult,
    SiteCommandStatus,
)
from mon.store import Store


class SiteCommandError(RuntimeError):
    pass


class SiteCommandQueue:
    """Durable at-least-once command queue scoped by tenant and site."""

    def __init__(self, store: Store) -> None:
        self.store = store

    def enqueue(self, command: SiteCommand) -> SiteCommandRecord:
        existing = self.store.get_site_command(
            command.tenant_id,
            command.site_id,
            command.command_id,
        )
        if existing is not None:
            if existing.command != command:
                raise SiteCommandError("command_id already exists with different content")
            return existing

        record = SiteCommandRecord(command=command)
        return self.store.add_site_command(record)

    @staticmethod
    def _execution_id(record: SiteCommandRecord) -> str | None:
        if (
            record.command.kind is SiteCommandKind.APPLY_RESPONSE
            and record.command.response_plan is not None
        ):
            return record.command.response_plan.request.request_id
        return record.command.rollback_execution_id

    def _reconcile_pending_failure(
        self,
        record: SiteCommandRecord,
        *,
        error: str,
        occurred_at: dt.datetime,
        outcome: str,
    ) -> None:
        execution_id = self._execution_id(record)
        if execution_id is None:
            return

        execution = self.store.get_response_execution(
            record.command.tenant_id,
            record.command.site_id,
            execution_id,
        )
        if execution is None:
            return

        status = None
        if (
            record.command.kind is SiteCommandKind.APPLY_RESPONSE
            and execution.status is ResponseExecutionStatus.DISPATCH_PENDING
        ):
            status = ResponseExecutionStatus.FAILED
        elif (
            record.command.kind is SiteCommandKind.ROLLBACK_RESPONSE
            and execution.status is ResponseExecutionStatus.ROLLBACK_PENDING
        ):
            status = ResponseExecutionStatus.ROLLBACK_FAILED

        if status is None:
            return

        updated = execution.model_copy(
            update={
                "status": status,
                "error": error[:2000],
            }
        )
        self.store.add_response_execution(updated)
        self.store.add_audit_record(
            AuditRecord(
                tenant_id=updated.tenant_id,
                site_id=updated.site_id,
                actor_id="mon-site-command",
                category="RESPONSE",
                object_type="response_execution",
                object_id=updated.execution_id,
                action="SITE_COMMAND",
                outcome=outcome,
                occurred_at=occurred_at,
                details={
                    "command_id": record.command.command_id,
                    "command_kind": record.command.kind.value,
                    "error": error[:1000],
                },
            )
        )

    def _expire_record(
        self,
        record: SiteCommandRecord,
        check_at: dt.datetime,
    ) -> SiteCommandRecord:
        expired = record.model_copy(
            update={
                "status": SiteCommandStatus.EXPIRED,
                "updated_at": check_at,
            }
        )
        self.store.add_site_command(expired)

        error = (
            "site response command expired before delivery"
            if record.command.kind is SiteCommandKind.APPLY_RESPONSE
            else "site rollback command expired before delivery"
        )
        self._reconcile_pending_failure(
            record,
            error=error,
            occurred_at=check_at,
            outcome="EXPIRED",
        )
        return expired

    def expire_due(
        self,
        tenant_id: str,
        site_id: str,
        *,
        now: dt.datetime | None = None,
    ) -> int:
        check_at = now or dt.datetime.now(dt.UTC)
        count = 0
        for record in self.store.list_site_commands(tenant_id, site_id):
            if (
                record.status is SiteCommandStatus.PENDING
                and record.command.not_after <= check_at
            ):
                self._expire_record(record, check_at)
                count += 1
        return count

    def pending(
        self,
        tenant_id: str,
        site_id: str,
        *,
        limit: int = 20,
        now: dt.datetime | None = None,
    ) -> list[SiteCommand]:
        if limit < 1 or limit > 100:
            raise ValueError("site command limit must be between 1 and 100")
        check_at = now or dt.datetime.now(dt.UTC)
        records = self.store.list_site_commands(tenant_id, site_id)

        eligible: list[SiteCommandRecord] = []
        for record in records:
            if record.status is not SiteCommandStatus.PENDING:
                continue
            if record.command.not_after <= check_at:
                self._expire_record(record, check_at)
                continue
            eligible.append(record)

        eligible.sort(
            key=lambda item: (item.command.created_at, item.command.command_id)
        )
        commands: list[SiteCommand] = []
        for record in eligible[:limit]:
            delivered = record.model_copy(
                update={
                    "delivery_count": record.delivery_count + 1,
                    "last_delivered_at": check_at,
                    "updated_at": check_at,
                }
            )
            self.store.add_site_command(delivered)
            commands.append(delivered.command)
        return commands

    @staticmethod
    def _has_verified_present_evidence(result: SiteCommandResult) -> bool:
        return any(
            record.actor_id == "mon-site-reconciliation"
            and record.action == "VERIFY"
            and record.outcome == "PRESENT"
            for record in result.audit_records
        )

    def _validate_apply_result(
        self,
        record: SiteCommandRecord,
        result: SiteCommandResult,
    ) -> None:
        execution = result.execution
        if execution is None:
            return
        plan = record.command.response_plan
        assert plan is not None
        if execution.plan != plan:
            raise SiteCommandError(
                "site command result cannot mutate the dispatched response plan"
            )
        if execution.approval != record.command.approval:
            raise SiteCommandError(
                "site command result cannot mutate response approval"
            )
        if execution.requested_at != record.command.created_at:
            raise SiteCommandError(
                "site command result requested_at does not match command creation"
            )

        if result.success:
            if execution.status not in {
                ResponseExecutionStatus.APPLIED,
                ResponseExecutionStatus.ROLLED_BACK,
            }:
                raise SiteCommandError(
                    "successful apply command result has invalid execution status"
                )
            if (
                execution.applied_at is None
                and not self._has_verified_present_evidence(result)
            ):
                raise SiteCommandError(
                    "apply result without applied_at requires VERIFY/PRESENT evidence"
                )
        elif execution.status is not ResponseExecutionStatus.FAILED:
            raise SiteCommandError(
                "failed apply command result has invalid execution status"
            )

    def _validate_rollback_result(
        self,
        record: SiteCommandRecord,
        result: SiteCommandResult,
    ) -> bool:
        execution = result.execution
        if execution is None:
            return False
        current = self.store.get_response_execution(
            record.command.tenant_id,
            record.command.site_id,
            execution.execution_id,
        )
        if current is None:
            raise SiteCommandError(
                "rollback command result references unknown response execution"
            )
        if execution.plan != current.plan:
            raise SiteCommandError(
                "rollback command result cannot mutate the response plan"
            )
        if result.success:
            if execution.status is not ResponseExecutionStatus.ROLLED_BACK:
                raise SiteCommandError(
                    "successful rollback command result must be ROLLED_BACK"
                )
            return True
        if execution.status is ResponseExecutionStatus.ROLLBACK_FAILED:
            return True
        return False

    def complete(self, result: SiteCommandResult) -> SiteCommandRecord:
        record = self.store.get_site_command(
            result.tenant_id,
            result.site_id,
            result.command_id,
        )
        if record is None:
            raise SiteCommandError("site command result references an unknown command")

        if record.status in {SiteCommandStatus.COMPLETED, SiteCommandStatus.FAILED}:
            if record.result == result:
                return record
            raise SiteCommandError("site command already has a different terminal result")
        if record.status is SiteCommandStatus.EXPIRED:
            raise SiteCommandError(
                "expired site command cannot accept a terminal command result"
            )

        expected_execution_id = self._execution_id(record)
        persist_execution = False
        if result.execution is not None:
            if result.execution.execution_id != expected_execution_id:
                raise SiteCommandError(
                    "site command result execution_id does not match command"
                )
            if record.command.kind is SiteCommandKind.APPLY_RESPONSE:
                self._validate_apply_result(record, result)
                persist_execution = True
            else:
                persist_execution = self._validate_rollback_result(record, result)

        if persist_execution and result.execution is not None:
            self.store.add_response_execution(result.execution)
        elif not result.success:
            self._reconcile_pending_failure(
                record,
                error=result.error or "site command failed without execution result",
                occurred_at=result.completed_at,
                outcome="FAILED",
            )

        for audit in result.audit_records:
            if audit.object_type != "response_execution":
                raise SiteCommandError(
                    "site command result contains unsupported audit object type"
                )
            if audit.object_id != expected_execution_id:
                raise SiteCommandError(
                    "site command audit record does not match execution"
                )
            self.store.add_audit_record(audit)

        status = (
            SiteCommandStatus.COMPLETED
            if result.success
            else SiteCommandStatus.FAILED
        )
        completed = record.model_copy(
            update={
                "status": status,
                "completed_at": result.completed_at,
                "result": result,
                "updated_at": result.completed_at,
            }
        )
        return self.store.add_site_command(completed)
