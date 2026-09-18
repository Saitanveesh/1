from __future__ import annotations

import datetime as dt

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
                self.store.add_site_command(
                    record.model_copy(
                        update={
                            "status": SiteCommandStatus.EXPIRED,
                            "updated_at": check_at,
                        }
                    )
                )
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

        expected_execution_id = (
            record.command.response_plan.request.request_id
            if record.command.kind is SiteCommandKind.APPLY_RESPONSE
            and record.command.response_plan is not None
            else record.command.rollback_execution_id
        )
        if result.execution is not None:
            if result.execution.execution_id != expected_execution_id:
                raise SiteCommandError(
                    "site command result execution_id does not match command"
                )
            self.store.add_response_execution(result.execution)

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
