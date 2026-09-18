from __future__ import annotations

import datetime as dt

from mon.domain import (
    AuditRecord,
    EnforcementBinding,
    PolicyOutcome,
    ResponseApproval,
    ResponseExecution,
    ResponseExecutionStatus,
    ResponsePlan,
    ResponseRequest,
    utcnow,
)
from mon.enforcement import EnforcementRegistry
from mon.enforcement_graph import NoEnforcementPath, select_enforcement_point
from mon.policy import evaluate_response
from mon.store import Store


class ResponseStateError(RuntimeError):
    pass


def _blast_radius(binding: EnforcementBinding | None) -> str | None:
    if binding is None:
        return None
    value = binding.attributes.get("blast_radius_estimate")
    if value is None:
        return None
    text = str(value).strip()
    return text[:500] if text else None


class ResponseOrchestrator:
    """Policy-gated response execution with idempotency, audit, TTL and rollback."""

    def __init__(self, store: Store, registry: EnforcementRegistry) -> None:
        self.store = store
        self.registry = registry

    def plan(self, request: ResponseRequest) -> ResponsePlan:
        incident = self.store.get_incident(
            request.tenant_id,
            request.site_id,
            request.incident_id,
        )
        if incident is None:
            raise ResponseStateError("incident not found in tenant/site scope")

        asset = None
        if request.target.asset_id:
            asset = self.store.get_asset(
                request.tenant_id,
                request.site_id,
                request.target.asset_id,
            )
            if asset is None:
                raise ResponseStateError("asset not found in tenant/site scope")

        points = self.store.list_enforcement_points(
            request.tenant_id,
            request.site_id,
        )
        bindings = self.store.list_enforcement_bindings(
            request.tenant_id,
            request.site_id,
            asset.asset_id if asset else None,
        )
        try:
            selection = select_enforcement_point(
                request,
                points,
                bindings,
                asset,
            )
        except NoEnforcementPath as exc:
            raise ResponseStateError(str(exc)) from exc

        blast_radius = _blast_radius(selection.binding)
        decision = evaluate_response(
            request,
            incident,
            selection.point,
            asset,
            blast_radius_known=blast_radius is not None,
        )
        return ResponsePlan(
            request=request,
            decision=decision,
            enforcement_point=selection.point,
            selection_reasons=selection.reasons,
            blast_radius_estimate=blast_radius,
        )

    def _audit(
        self,
        execution: ResponseExecution,
        action: str,
        outcome: str,
        *,
        actor_id: str,
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

    async def execute(
        self,
        request: ResponseRequest,
        *,
        approval: ResponseApproval | None = None,
    ) -> ResponseExecution:
        existing = self.store.get_response_execution(
            request.tenant_id,
            request.site_id,
            request.request_id,
        )
        if existing is not None:
            if (
                existing.status is ResponseExecutionStatus.PENDING_APPROVAL
                and approval is not None
            ):
                plan = existing.plan
                request = plan.request
                self._audit(
                    existing,
                    "APPROVE",
                    "APPROVED",
                    actor_id=approval.actor_id,
                    details={"reason": approval.reason},
                )
            else:
                return existing
        else:
            plan = self.plan(request)

        now = utcnow()

        if plan.decision.outcome is PolicyOutcome.DENY:
            execution = ResponseExecution(
                execution_id=request.request_id,
                tenant_id=request.tenant_id,
                site_id=request.site_id,
                plan=plan,
                status=ResponseExecutionStatus.DENIED,
                requested_at=now,
                error="; ".join(plan.decision.reasons),
            )
            self.store.add_response_execution(execution)
            self._audit(
                execution,
                "EXECUTE",
                "DENIED",
                actor_id=request.actor_id,
                details={"policy_reasons": plan.decision.reasons},
            )
            return execution

        if (
            plan.decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
            and approval is None
        ):
            execution = ResponseExecution(
                execution_id=request.request_id,
                tenant_id=request.tenant_id,
                site_id=request.site_id,
                plan=plan,
                status=ResponseExecutionStatus.PENDING_APPROVAL,
                requested_at=now,
            )
            self.store.add_response_execution(execution)
            self._audit(
                execution,
                "EXECUTE",
                "PENDING_APPROVAL",
                actor_id=request.actor_id,
                details={"policy_reasons": plan.decision.reasons},
            )
            return execution

        actor_id = approval.actor_id if approval else request.actor_id
        execution = ResponseExecution(
            execution_id=request.request_id,
            tenant_id=request.tenant_id,
            site_id=request.site_id,
            plan=plan,
            status=ResponseExecutionStatus.EXECUTING,
            requested_at=existing.requested_at if existing is not None else now,
            approval=approval,
        )
        self.store.add_response_execution(execution)
        self._audit(
            execution,
            "EXECUTE",
            "STARTED",
            actor_id=actor_id,
            details={
                "action": request.action.value,
                "enforcement_point_id": plan.enforcement_point.enforcement_point_id,
                "blast_radius_estimate": plan.blast_radius_estimate,
            },
        )

        try:
            adapter = self.registry.resolve(
                plan.enforcement_point.kind,
                plan.enforcement_point.vendor,
            )
            result = await adapter.execute(plan, execution.execution_id)
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
                actor_id=actor_id,
                details={"error": str(exc)[:1000]},
            )
            return failed

        if not result.success:
            failed = execution.model_copy(
                update={
                    "status": ResponseExecutionStatus.FAILED,
                    "result": result,
                    "error": result.message,
                }
            )
            self.store.add_response_execution(failed)
            self._audit(
                failed,
                "EXECUTE",
                "FAILED",
                actor_id=actor_id,
                details={"adapter_message": result.message},
            )
            return failed

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
                "result": result,
            }
        )
        self.store.add_response_execution(applied)
        self._audit(
            applied,
            "EXECUTE",
            "APPLIED",
            actor_id=actor_id,
            details={
                "external_reference": result.external_reference,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )
        return applied

    async def rollback(
        self,
        tenant_id: str,
        site_id: str,
        execution_id: str,
        *,
        actor_id: str,
        reason: str | None = None,
    ) -> ResponseExecution:
        execution = self.store.get_response_execution(
            tenant_id,
            site_id,
            execution_id,
        )
        if execution is None:
            raise ResponseStateError("response execution not found")

        if execution.status is ResponseExecutionStatus.ROLLED_BACK:
            return execution
        if execution.status is not ResponseExecutionStatus.APPLIED:
            raise ResponseStateError(
                f"response execution cannot be rolled back from {execution.status.value}"
            )

        pending = execution.model_copy(
            update={"status": ResponseExecutionStatus.ROLLBACK_PENDING}
        )
        self.store.add_response_execution(pending)
        self._audit(
            pending,
            "ROLLBACK",
            "STARTED",
            actor_id=actor_id,
            details={"reason": reason} if reason else None,
        )

        try:
            adapter = self.registry.resolve(
                pending.plan.enforcement_point.kind,
                pending.plan.enforcement_point.vendor,
            )
            result = await adapter.rollback(pending.plan, pending.execution_id)
        except Exception as exc:
            failed = pending.model_copy(
                update={
                    "status": ResponseExecutionStatus.ROLLBACK_FAILED,
                    "error": str(exc)[:2000],
                }
            )
            self.store.add_response_execution(failed)
            self._audit(
                failed,
                "ROLLBACK",
                "FAILED",
                actor_id=actor_id,
                details={"error": str(exc)[:1000]},
            )
            return failed

        status = (
            ResponseExecutionStatus.ROLLED_BACK
            if result.success
            else ResponseExecutionStatus.ROLLBACK_FAILED
        )
        rolled_back = pending.model_copy(
            update={
                "status": status,
                "rollback_at": utcnow() if result.success else None,
                "rollback_result": result,
                "error": None if result.success else result.message,
            }
        )
        self.store.add_response_execution(rolled_back)
        self._audit(
            rolled_back,
            "ROLLBACK",
            "ROLLED_BACK" if result.success else "FAILED",
            actor_id=actor_id,
            details={"adapter_message": result.message},
        )
        return rolled_back

    def due_for_rollback(
        self,
        tenant_id: str,
        site_id: str,
        *,
        now: dt.datetime | None = None,
    ) -> list[ResponseExecution]:
        check_at = now or utcnow()
        return [
            execution
            for execution in self.store.list_response_executions(tenant_id, site_id)
            if execution.status is ResponseExecutionStatus.APPLIED
            and execution.expires_at is not None
            and execution.expires_at <= check_at
        ]
