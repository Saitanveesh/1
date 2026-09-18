from __future__ import annotations

import datetime as dt

from mon.domain import (
    AuditRecord,
    EnforcementResult,
    PolicyOutcome,
    ResponseExecution,
    ResponseExecutionStatus,
    utcnow,
)
from mon.enforcement import EnforcementRegistry
from mon.response import ResponseOrchestrator
from mon.site_command_models import SiteCommand, SiteCommandKind, SiteCommandResult
from mon.store import Store


class SiteResponseExecutor:
    """Execute pre-approved response plans locally with durable idempotency."""

    def __init__(
        self,
        tenant_id: str,
        site_id: str,
        store: Store,
        registry: EnforcementRegistry,
    ) -> None:
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.store = store
        self.registry = registry
        self.orchestrator = ResponseOrchestrator(store, registry)

    def _audit(
        self,
        execution: ResponseExecution,
        action: str,
        outcome: str,
        actor_id: str,
        details: dict[str, object] | None = None,
    ) -> None:
        self.store.add_audit_record(
            AuditRecord(
                tenant_id=self.tenant_id,
                site_id=self.site_id,
                actor_id=actor_id,
                category="SITE_RESPONSE",
                object_type="response_execution",
                object_id=execution.execution_id,
                action=action,
                outcome=outcome,
                details=details or {},
            )
        )

    def _result(
        self,
        command: SiteCommand,
        *,
        success: bool,
        execution: ResponseExecution | None,
        error: str | None = None,
    ) -> SiteCommandResult:
        audit_records = []
        if execution is not None:
            audit_records = [
                item
                for item in self.store.list_audit_records(
                    self.tenant_id,
                    self.site_id,
                )
                if item.object_type == "response_execution"
                and item.object_id == execution.execution_id
            ]
        return SiteCommandResult(
            command_id=command.command_id,
            tenant_id=self.tenant_id,
            site_id=self.site_id,
            success=success,
            execution=execution,
            audit_records=audit_records,
            error=error,
        )

    def _validate_scope(self, command: SiteCommand) -> None:
        if command.tenant_id != self.tenant_id or command.site_id != self.site_id:
            raise ValueError("site command scope does not match local site identity")

    async def execute(self, command: SiteCommand) -> SiteCommandResult:
        try:
            self._validate_scope(command)
        except ValueError as exc:
            return SiteCommandResult(
                command_id=command.command_id,
                tenant_id=self.tenant_id,
                site_id=self.site_id,
                success=False,
                error=str(exc),
            )

        if command.not_after <= utcnow():
            return SiteCommandResult(
                command_id=command.command_id,
                tenant_id=self.tenant_id,
                site_id=self.site_id,
                success=False,
                error="site command expired before local execution",
            )

        if command.kind is SiteCommandKind.ROLLBACK_RESPONSE:
            return await self._rollback(command)
        return await self._apply(command)

    async def _apply(self, command: SiteCommand) -> SiteCommandResult:
        plan = command.response_plan
        assert plan is not None
        request = plan.request
        existing = self.store.get_response_execution(
            self.tenant_id,
            self.site_id,
            request.request_id,
        )
        if existing is not None:
            success = existing.status in {
                ResponseExecutionStatus.APPLIED,
                ResponseExecutionStatus.ROLLED_BACK,
            }
            return self._result(
                command,
                success=success,
                execution=existing,
                error=None if success else existing.error or existing.status.value,
            )

        if plan.decision.outcome is PolicyOutcome.DENY:
            return SiteCommandResult(
                command_id=command.command_id,
                tenant_id=self.tenant_id,
                site_id=self.site_id,
                success=False,
                error="site refused a denied response plan",
            )
        if (
            plan.decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
            and command.approval is None
        ):
            return SiteCommandResult(
                command_id=command.command_id,
                tenant_id=self.tenant_id,
                site_id=self.site_id,
                success=False,
                error="site response plan requires missing approval",
            )

        actor_id = (
            command.approval.actor_id
            if command.approval is not None
            else request.actor_id
        )
        execution = ResponseExecution(
            execution_id=request.request_id,
            tenant_id=self.tenant_id,
            site_id=self.site_id,
            plan=plan,
            status=ResponseExecutionStatus.EXECUTING,
            requested_at=command.created_at,
            approval=command.approval,
        )
        self.store.add_response_execution(execution)
        self._audit(
            execution,
            "EXECUTE",
            "STARTED",
            actor_id,
            {
                "command_id": command.command_id,
                "enforcement_point_id": plan.enforcement_point.enforcement_point_id,
            },
        )

        try:
            adapter = self.registry.resolve(
                plan.enforcement_point.kind,
                plan.enforcement_point.vendor,
            )
            adapter_result = await adapter.execute(plan, execution.execution_id)
        except Exception as exc:
            failed = execution.model_copy(
                update={
                    "status": ResponseExecutionStatus.FAILED,
                    "error": str(exc)[:2000],
                }
            )
            self.store.add_response_execution(failed)
            self._audit(
                failed,
                "EXECUTE",
                "FAILED",
                actor_id,
                {"error": str(exc)[:1000]},
            )
            return self._result(
                command,
                success=False,
                execution=failed,
                error=failed.error,
            )

        if not adapter_result.success:
            failed = execution.model_copy(
                update={
                    "status": ResponseExecutionStatus.FAILED,
                    "result": adapter_result,
                    "error": adapter_result.message,
                }
            )
            self.store.add_response_execution(failed)
            self._audit(
                failed,
                "EXECUTE",
                "FAILED",
                actor_id,
                {"adapter_message": adapter_result.message},
            )
            return self._result(
                command,
                success=False,
                execution=failed,
                error=failed.error,
            )

        applied_at = utcnow()
        expires_at = (
            applied_at + dt.timedelta(seconds=request.ttl_seconds)
            if request.ttl_seconds is not None
            else None
        )
        applied = execution.model_copy(
            update={
                "status": ResponseExecutionStatus.APPLIED,
                "applied_at": applied_at,
                "expires_at": expires_at,
                "result": EnforcementResult.model_validate(adapter_result),
            }
        )
        self.store.add_response_execution(applied)
        self._audit(
            applied,
            "EXECUTE",
            "APPLIED",
            actor_id,
            {
                "command_id": command.command_id,
                "external_reference": adapter_result.external_reference,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )
        return self._result(command, success=True, execution=applied)

    async def _rollback(self, command: SiteCommand) -> SiteCommandResult:
        execution_id = command.rollback_execution_id
        assert execution_id is not None
        existing = self.store.get_response_execution(
            self.tenant_id,
            self.site_id,
            execution_id,
        )
        if existing is None:
            return SiteCommandResult(
                command_id=command.command_id,
                tenant_id=self.tenant_id,
                site_id=self.site_id,
                success=False,
                error="rollback command references unknown local execution",
            )

        try:
            result = await self.orchestrator.rollback(
                self.tenant_id,
                self.site_id,
                execution_id,
                actor_id="mon-site-command",
                reason=command.reason,
            )
        except Exception as exc:
            return self._result(
                command,
                success=False,
                execution=existing,
                error=str(exc)[:2000],
            )

        success = result.status is ResponseExecutionStatus.ROLLED_BACK
        return self._result(
            command,
            success=success,
            execution=result,
            error=None if success else result.error or result.status.value,
        )
