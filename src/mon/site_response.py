from __future__ import annotations

import datetime as dt

from mon.domain import (
    AuditRecord,
    EnforcementResult,
    EnforcementVerification,
    EnforcementVerificationState,
    PolicyOutcome,
    ResponseExecution,
    ResponseExecutionStatus,
    utcnow,
)
from mon.enforcement import EnforcementRegistry, VerifiableEnforcementAdapter
from mon.response import ResponseRollbackEngine
from mon.site_command_models import SiteCommand, SiteCommandKind, SiteCommandResult
from mon.store import ResponseStateStore


class SiteResponseExecutor:
    """Execute pre-approved response plans locally with durable idempotency."""

    def __init__(
        self,
        tenant_id: str,
        site_id: str,
        store: ResponseStateStore,
        registry: EnforcementRegistry,
    ) -> None:
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.store = store
        self.registry = registry
        self.orchestrator = ResponseRollbackEngine(store, registry)

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

    async def reconcile_execution(
        self,
        execution: ResponseExecution,
    ) -> ResponseExecution:
        """Resolve a crash-interrupted EXECUTING state using connector evidence."""
        if execution.status is not ResponseExecutionStatus.EXECUTING:
            return execution

        try:
            adapter = self.registry.resolve(
                execution.plan.enforcement_point.kind,
                execution.plan.enforcement_point.vendor,
            )
        except Exception as exc:
            self._audit(
                execution,
                "VERIFY",
                "ERROR",
                "mon-site-reconciliation",
                {"error": str(exc)[:1000]},
            )
            return execution

        if not isinstance(adapter, VerifiableEnforcementAdapter):
            return execution

        try:
            verification = EnforcementVerification.model_validate(
                await adapter.verify(execution.plan, execution.execution_id)
            )
        except Exception as exc:
            self._audit(
                execution,
                "VERIFY",
                "ERROR",
                "mon-site-reconciliation",
                {"error": str(exc)[:1000]},
            )
            return execution

        self._audit(
            execution,
            "VERIFY",
            verification.state.value,
            "mon-site-reconciliation",
            {
                "message": verification.message,
                "external_reference": verification.external_reference,
                "details": verification.details,
            },
        )

        if verification.state is EnforcementVerificationState.UNKNOWN:
            return execution

        if verification.state is EnforcementVerificationState.ABSENT:
            failed = execution.model_copy(
                update={
                    "status": ResponseExecutionStatus.FAILED,
                    "error": (
                        "enforcement verification confirmed the effect is absent "
                        "after an interrupted execution"
                    ),
                }
            )
            self.store.add_response_execution(failed)
            return failed

        ttl_seconds = execution.plan.request.ttl_seconds
        expires_at = (
            execution.requested_at + dt.timedelta(seconds=ttl_seconds)
            if ttl_seconds is not None
            else None
        )
        applied = execution.model_copy(
            update={
                "status": ResponseExecutionStatus.APPLIED,
                # The exact apply instant was lost in the crash window. Do not
                # fabricate applied_at. The conservative expiry bound starts at
                # the durable pre-call requested_at, so containment cannot be
                # extended beyond the configured TTL by reconciliation.
                "applied_at": None,
                "expires_at": expires_at,
                "result": EnforcementResult(
                    success=True,
                    message=(
                        "enforcement effect verified present after interrupted "
                        "execution; original apply result was not persisted"
                    ),
                    external_reference=verification.external_reference,
                    details={
                        "reconciled_after_interruption": True,
                        "verification_message": verification.message,
                        "verification_details": verification.details,
                    },
                ),
                "error": None,
            }
        )
        self.store.add_response_execution(applied)
        return applied

    async def reconcile_uncertain_executions(self) -> dict[str, int]:
        candidates = [
            execution
            for execution in self.store.list_response_executions(
                self.tenant_id,
                self.site_id,
            )
            if execution.status is ResponseExecutionStatus.EXECUTING
        ]
        resolved = 0
        present = 0
        absent = 0
        for execution in candidates:
            updated = await self.reconcile_execution(execution)
            if updated.status is ResponseExecutionStatus.APPLIED:
                resolved += 1
                present += 1
            elif updated.status is ResponseExecutionStatus.FAILED:
                resolved += 1
                absent += 1
        return {
            "attempted": len(candidates),
            "resolved": resolved,
            "present": present,
            "absent": absent,
            "unresolved": len(candidates) - resolved,
        }

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

        if command.kind is SiteCommandKind.ROLLBACK_RESPONSE:
            if command.not_after <= utcnow():
                return SiteCommandResult(
                    command_id=command.command_id,
                    tenant_id=self.tenant_id,
                    site_id=self.site_id,
                    success=False,
                    error="site command expired before local execution",
                )
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
            if existing.status is ResponseExecutionStatus.EXECUTING:
                existing = await self.reconcile_execution(existing)
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

        if command.not_after <= utcnow():
            return SiteCommandResult(
                command_id=command.command_id,
                tenant_id=self.tenant_id,
                site_id=self.site_id,
                success=False,
                error="site command expired before local execution",
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
