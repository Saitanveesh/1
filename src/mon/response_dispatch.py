from __future__ import annotations

import datetime as dt
import uuid

from mon.domain import (
    AuditRecord,
    PolicyOutcome,
    ResponseApproval,
    ResponseExecution,
    ResponseExecutionStatus,
    ResponseRequest,
    utcnow,
)
from mon.enforcement import EnforcementExecutionPlane, execution_plane
from mon.response import ResponseOrchestrator, ResponseStateError
from mon.site_command_models import (
    SiteCommand,
    SiteCommandKind,
    SiteCommandStatus,
)
from mon.site_command_queue import SiteCommandQueue
from mon.store import Store


_COMMAND_NAMESPACE = uuid.UUID("fb2afb63-d8b1-4a68-98d6-a65b131f635f")


class ResponseDispatcher:
    """Route approved responses to the site or a control-plane adapter."""

    def __init__(
        self,
        store: Store,
        orchestrator: ResponseOrchestrator,
        site_commands: SiteCommandQueue,
        *,
        command_ttl_seconds: int = 300,
    ) -> None:
        if command_ttl_seconds < 30 or command_ttl_seconds > 3600:
            raise ValueError("command_ttl_seconds must be between 30 and 3600")
        self.store = store
        self.orchestrator = orchestrator
        self.site_commands = site_commands
        self.command_ttl_seconds = command_ttl_seconds

    def _audit(
        self,
        execution: ResponseExecution,
        *,
        actor_id: str,
        action: str,
        outcome: str,
        details: dict[str, object] | None = None,
    ) -> None:
        self.store.add_audit_record(
            AuditRecord(
                tenant_id=execution.tenant_id,
                site_id=execution.site_id,
                actor_id=actor_id,
                category="RESPONSE",
                object_type="response_execution",
                object_id=execution.execution_id,
                action=action,
                outcome=outcome,
                details=details or {},
            )
        )

    @staticmethod
    def _apply_command_id(execution: ResponseExecution) -> str:
        return str(
            uuid.uuid5(
                _COMMAND_NAMESPACE,
                (
                    f"apply:{execution.tenant_id}:{execution.site_id}:"
                    f"{execution.execution_id}"
                ),
            )
        )

    def _enqueue_apply(self, execution: ResponseExecution) -> None:
        created_at = (
            execution.approval.approved_at
            if execution.approval is not None
            else execution.requested_at
        )
        command = SiteCommand(
            command_id=self._apply_command_id(execution),
            tenant_id=execution.tenant_id,
            site_id=execution.site_id,
            kind=SiteCommandKind.APPLY_RESPONSE,
            created_at=created_at,
            not_after=created_at + dt.timedelta(seconds=self.command_ttl_seconds),
            response_plan=execution.plan,
            approval=execution.approval,
        )
        self.site_commands.enqueue(command)

    def _pending_rollback_command(
        self,
        execution: ResponseExecution,
    ) -> SiteCommand | None:
        for record in self.store.list_site_commands(
            execution.tenant_id,
            execution.site_id,
        ):
            if (
                record.status is SiteCommandStatus.PENDING
                and record.command.kind is SiteCommandKind.ROLLBACK_RESPONSE
                and record.command.rollback_execution_id == execution.execution_id
            ):
                return record.command
        return None

    def _enqueue_rollback(
        self,
        execution: ResponseExecution,
        *,
        reason: str,
    ) -> None:
        if self._pending_rollback_command(execution) is not None:
            return
        matching = [
            record
            for record in self.store.list_site_commands(
                execution.tenant_id,
                execution.site_id,
            )
            if (
                record.command.kind is SiteCommandKind.ROLLBACK_RESPONSE
                and record.command.rollback_execution_id == execution.execution_id
            )
        ]
        attempt = len(matching)
        command_id = str(
            uuid.uuid5(
                _COMMAND_NAMESPACE,
                (
                    f"rollback:{execution.tenant_id}:{execution.site_id}:"
                    f"{execution.execution_id}:{attempt}"
                ),
            )
        )
        created_at = utcnow()
        self.site_commands.enqueue(
            SiteCommand(
                command_id=command_id,
                tenant_id=execution.tenant_id,
                site_id=execution.site_id,
                kind=SiteCommandKind.ROLLBACK_RESPONSE,
                created_at=created_at,
                not_after=created_at
                + dt.timedelta(seconds=self.command_ttl_seconds),
                rollback_execution_id=execution.execution_id,
                reason=reason,
            )
        )

    async def dispatch(
        self,
        request: ResponseRequest,
        *,
        approval: ResponseApproval | None = None,
    ) -> ResponseExecution:
        self.site_commands.expire_due(request.tenant_id, request.site_id)
        existing = self.store.get_response_execution(
            request.tenant_id,
            request.site_id,
            request.request_id,
        )

        if existing is not None:
            if existing.status is ResponseExecutionStatus.DISPATCH_PENDING:
                self._enqueue_apply(existing)
                return existing
            if not (
                existing.status is ResponseExecutionStatus.PENDING_APPROVAL
                and approval is not None
            ):
                return existing
            plan = existing.plan
            request = plan.request
        else:
            plan = self.orchestrator.plan(request)

        if (
            plan.decision.outcome is PolicyOutcome.DENY
            or (
                plan.decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
                and approval is None
            )
        ):
            return await self.orchestrator.execute(
                request,
                approval=approval,
            )

        plane = execution_plane(plan.enforcement_point)
        if plane is EnforcementExecutionPlane.CONTROL_PLANE:
            return await self.orchestrator.execute(
                request,
                approval=approval,
            )

        actor_id = approval.actor_id if approval is not None else request.actor_id
        requested_at = (
            existing.requested_at if existing is not None else utcnow()
        )
        if existing is not None and approval is not None:
            self._audit(
                existing,
                actor_id=approval.actor_id,
                action="APPROVE",
                outcome="APPROVED",
                details={"reason": approval.reason},
            )

        execution = ResponseExecution(
            execution_id=request.request_id,
            tenant_id=request.tenant_id,
            site_id=request.site_id,
            plan=plan,
            status=ResponseExecutionStatus.DISPATCH_PENDING,
            requested_at=requested_at,
            approval=approval,
        )
        self.store.add_response_execution(execution)
        self._audit(
            execution,
            actor_id=actor_id,
            action="DISPATCH",
            outcome="QUEUED",
            details={
                "execution_plane": plane.value,
                "enforcement_point_id": plan.enforcement_point.enforcement_point_id,
                "blast_radius_estimate": plan.blast_radius_estimate,
            },
        )
        self._enqueue_apply(execution)
        return execution

    async def rollback(
        self,
        tenant_id: str,
        site_id: str,
        execution_id: str,
        *,
        actor_id: str,
        reason: str,
    ) -> ResponseExecution:
        self.site_commands.expire_due(tenant_id, site_id)
        execution = self.store.get_response_execution(
            tenant_id,
            site_id,
            execution_id,
        )
        if execution is None:
            raise ResponseStateError("response execution not found")

        plane = execution_plane(execution.plan.enforcement_point)
        if plane is EnforcementExecutionPlane.CONTROL_PLANE:
            return await self.orchestrator.rollback(
                tenant_id,
                site_id,
                execution_id,
                actor_id=actor_id,
                reason=reason,
            )

        if execution.status is ResponseExecutionStatus.ROLLED_BACK:
            return execution
        if execution.status is ResponseExecutionStatus.ROLLBACK_PENDING:
            self._enqueue_rollback(execution, reason=reason)
            return execution
        if execution.status not in {
            ResponseExecutionStatus.APPLIED,
            ResponseExecutionStatus.ROLLBACK_FAILED,
        }:
            raise ResponseStateError(
                f"response execution cannot be rolled back from {execution.status.value}"
            )

        pending = execution.model_copy(
            update={
                "status": ResponseExecutionStatus.ROLLBACK_PENDING,
                "error": None,
            }
        )
        self.store.add_response_execution(pending)
        self._audit(
            pending,
            actor_id=actor_id,
            action="ROLLBACK_DISPATCH",
            outcome="QUEUED",
            details={"reason": reason, "execution_plane": plane.value},
        )
        self._enqueue_rollback(pending, reason=reason)
        return pending
