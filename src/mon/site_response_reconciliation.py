from __future__ import annotations

import datetime as dt

from mon.domain import AuditRecord, ResponseExecution, ResponseExecutionStatus
from mon.site_command_models import SiteCommandKind, SiteCommandRecord, SiteCommandStatus
from mon.site_response_models import SiteResponseUpdate, SiteResponseUpdateKind
from mon.store import Store


class SiteResponseUpdateError(RuntimeError):
    pass


class SiteResponseUpdateReconciler:
    """Accept evidence-backed site response state without allowing plan mutation."""

    def __init__(self, store: Store) -> None:
        self.store = store

    @staticmethod
    def _validate_immutable_recovery_state(
        current: ResponseExecution,
        reported: ResponseExecution,
    ) -> None:
        if reported.execution_id != current.execution_id:
            raise SiteResponseUpdateError("response update execution_id does not match")
        if reported.plan != current.plan:
            raise SiteResponseUpdateError("response update cannot mutate the response plan")
        immutable_fields = (
            "requested_at",
            "approval",
            "applied_at",
            "expires_at",
            "result",
        )
        for field_name in immutable_fields:
            if getattr(reported, field_name) != getattr(current, field_name):
                raise SiteResponseUpdateError(
                    f"response update cannot mutate {field_name}"
                )

    def _validate_audit_records(self, update: SiteResponseUpdate) -> None:
        existing = {
            record.audit_id: record
            for record in self.store.list_audit_records(
                update.tenant_id,
                update.site_id,
            )
        }
        for record in update.audit_records:
            prior = existing.get(record.audit_id)
            if prior is not None and prior != record:
                raise SiteResponseUpdateError(
                    "response update cannot overwrite an existing audit record"
                )

    @staticmethod
    def _recovery_transition_allowed(
        current: ResponseExecutionStatus,
        reported: ResponseExecutionStatus,
    ) -> bool:
        if reported is ResponseExecutionStatus.ROLLED_BACK:
            return current in {
                ResponseExecutionStatus.APPLIED,
                ResponseExecutionStatus.ROLLBACK_PENDING,
                ResponseExecutionStatus.ROLLBACK_FAILED,
            }
        if reported is ResponseExecutionStatus.ROLLBACK_FAILED:
            return current in {
                ResponseExecutionStatus.APPLIED,
                ResponseExecutionStatus.ROLLBACK_PENDING,
            }
        return False

    def _store_site_audits(self, update: SiteResponseUpdate) -> None:
        for record in update.audit_records:
            self.store.add_audit_record(record)

    def _reconcile_recovery(
        self,
        update: SiteResponseUpdate,
        current: ResponseExecution,
    ) -> ResponseExecution:
        reported = update.execution
        self._validate_immutable_recovery_state(current, reported)

        if current == reported:
            self._store_site_audits(update)
            return current

        if not self._recovery_transition_allowed(current.status, reported.status):
            raise SiteResponseUpdateError(
                "response update would cause an invalid or stale state transition "
                f"from {current.status.value} to {reported.status.value}"
            )

        self.store.add_response_execution(reported)
        self._store_site_audits(update)
        self.store.add_audit_record(
            AuditRecord(
                tenant_id=update.tenant_id,
                site_id=update.site_id,
                actor_id="mon-control-plane",
                category="RESPONSE",
                object_type="response_execution",
                object_id=reported.execution_id,
                action="SITE_RECOVERY_REPORT",
                outcome="ACCEPTED",
                details={
                    "update_id": update.update_id,
                    "previous_status": current.status.value,
                    "reported_status": reported.status.value,
                    "site_observed_at": update.observed_at.isoformat(),
                },
            )
        )
        return reported

    def _get_expired_apply_command(
        self,
        update: SiteResponseUpdate,
    ) -> SiteCommandRecord:
        if update.command_id is None:
            raise SiteResponseUpdateError(
                "execution reconciliation update requires command_id"
            )
        record = self.store.get_site_command(
            update.tenant_id,
            update.site_id,
            update.command_id,
        )
        if record is None:
            raise SiteResponseUpdateError(
                "execution reconciliation references an unknown site command"
            )
        if (
            record.command.kind is not SiteCommandKind.APPLY_RESPONSE
            or record.command.response_plan is None
        ):
            raise SiteResponseUpdateError(
                "execution reconciliation must reference an APPLY_RESPONSE command"
            )
        if record.status is not SiteCommandStatus.EXPIRED:
            raise SiteResponseUpdateError(
                "execution reconciliation is accepted only after the apply command expires"
            )
        return record

    def _has_expiry_audit(
        self,
        update: SiteResponseUpdate,
        command_id: str,
    ) -> bool:
        return any(
            record.object_type == "response_execution"
            and record.object_id == update.execution.execution_id
            and record.action == "SITE_COMMAND"
            and record.outcome == "EXPIRED"
            and record.details.get("command_id") == command_id
            for record in self.store.list_audit_records(
                update.tenant_id,
                update.site_id,
            )
        )

    @staticmethod
    def _validate_late_execution_against_command(
        update: SiteResponseUpdate,
        record: SiteCommandRecord,
        current: ResponseExecution,
    ) -> None:
        reported = update.execution
        command = record.command
        plan = command.response_plan
        assert plan is not None

        if reported.execution_id != plan.request.request_id:
            raise SiteResponseUpdateError(
                "execution reconciliation execution_id does not match command"
            )
        if reported.plan != plan or current.plan != plan:
            raise SiteResponseUpdateError(
                "execution reconciliation cannot mutate the dispatched response plan"
            )
        if reported.approval != command.approval or current.approval != command.approval:
            raise SiteResponseUpdateError(
                "execution reconciliation cannot mutate response approval"
            )
        if reported.requested_at != command.created_at:
            raise SiteResponseUpdateError(
                "execution reconciliation requested_at does not match site command"
            )

        ttl_seconds = plan.request.ttl_seconds
        expected_expiry = (
            command.created_at + dt.timedelta(seconds=ttl_seconds)
            if ttl_seconds is not None
            else None
        )
        if reported.status is not ResponseExecutionStatus.FAILED:
            if reported.expires_at != expected_expiry:
                raise SiteResponseUpdateError(
                    "execution reconciliation expiry does not match conservative TTL bound"
                )
            if (
                reported.result is None
                or not reported.result.success
                or reported.result.details.get("reconciled_after_interruption") is not True
            ):
                raise SiteResponseUpdateError(
                    "execution reconciliation lacks verified interrupted-execution result"
                )

    @staticmethod
    def _dynamic_state_matches(
        current: ResponseExecution,
        reported: ResponseExecution,
    ) -> bool:
        fields = (
            "status",
            "applied_at",
            "expires_at",
            "result",
            "rollback_at",
            "rollback_result",
            "error",
        )
        return all(
            getattr(current, field_name) == getattr(reported, field_name)
            for field_name in fields
        )

    @staticmethod
    def _merge_reported_dynamic_state(
        current: ResponseExecution,
        reported: ResponseExecution,
    ) -> ResponseExecution:
        return current.model_copy(
            update={
                "status": reported.status,
                "applied_at": reported.applied_at,
                "expires_at": reported.expires_at,
                "result": reported.result,
                "rollback_at": reported.rollback_at,
                "rollback_result": reported.rollback_result,
                "error": reported.error,
            }
        )

    def _reconcile_interrupted_execution(
        self,
        update: SiteResponseUpdate,
        current: ResponseExecution,
    ) -> ResponseExecution:
        record = self._get_expired_apply_command(update)
        command_id = record.command.command_id
        self._validate_late_execution_against_command(update, record, current)

        if self._dynamic_state_matches(current, update.execution):
            self._store_site_audits(update)
            return current

        if current.status is not ResponseExecutionStatus.FAILED:
            raise SiteResponseUpdateError(
                "late execution reconciliation requires the control-plane response "
                "to be in the command-expiry FAILED state"
            )
        if not self._has_expiry_audit(update, command_id):
            raise SiteResponseUpdateError(
                "late execution reconciliation requires matching command-expiry audit evidence"
            )

        reconciled = self._merge_reported_dynamic_state(current, update.execution)
        self.store.add_response_execution(reconciled)
        self._store_site_audits(update)
        self.store.add_audit_record(
            AuditRecord(
                tenant_id=update.tenant_id,
                site_id=update.site_id,
                actor_id="mon-control-plane",
                category="RESPONSE",
                object_type="response_execution",
                object_id=reconciled.execution_id,
                action="SITE_EXECUTION_RECONCILIATION",
                outcome="ACCEPTED",
                details={
                    "update_id": update.update_id,
                    "command_id": command_id,
                    "previous_status": current.status.value,
                    "reported_status": update.execution.status.value,
                    "site_observed_at": update.observed_at.isoformat(),
                    "site_requested_at": update.execution.requested_at.isoformat(),
                    "control_plane_requested_at": current.requested_at.isoformat(),
                },
            )
        )
        return reconciled

    def reconcile(self, update: SiteResponseUpdate) -> ResponseExecution:
        reported = update.execution
        current = self.store.get_response_execution(
            update.tenant_id,
            update.site_id,
            reported.execution_id,
        )
        if current is None:
            raise SiteResponseUpdateError(
                "response update references an unknown execution"
            )

        self._validate_audit_records(update)
        if update.kind is SiteResponseUpdateKind.RECOVERY:
            return self._reconcile_recovery(update, current)
        return self._reconcile_interrupted_execution(update, current)
