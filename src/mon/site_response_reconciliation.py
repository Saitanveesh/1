from __future__ import annotations

from mon.domain import AuditRecord, ResponseExecution, ResponseExecutionStatus
from mon.site_response_models import SiteResponseUpdate
from mon.store import Store


class SiteResponseUpdateError(RuntimeError):
    pass


class SiteResponseUpdateReconciler:
    """Accept terminal site recovery state without allowing plan mutation or regression."""

    def __init__(self, store: Store) -> None:
        self.store = store

    @staticmethod
    def _validate_immutable_state(
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

    @staticmethod
    def _is_idempotent(
        current: ResponseExecution,
        reported: ResponseExecution,
    ) -> bool:
        return current == reported

    @staticmethod
    def _transition_allowed(
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

    def reconcile(self, update: SiteResponseUpdate) -> ResponseExecution:
        reported = update.execution
        current = self.store.get_response_execution(
            update.tenant_id,
            update.site_id,
            reported.execution_id,
        )
        if current is None:
            raise SiteResponseUpdateError("response update references an unknown execution")

        self._validate_immutable_state(current, reported)

        if self._is_idempotent(current, reported):
            for record in update.audit_records:
                self.store.add_audit_record(record)
            return current

        if not self._transition_allowed(current.status, reported.status):
            raise SiteResponseUpdateError(
                "response update would cause an invalid or stale state transition "
                f"from {current.status.value} to {reported.status.value}"
            )

        self.store.add_response_execution(reported)
        for record in update.audit_records:
            self.store.add_audit_record(record)

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
                occurred_at=update.observed_at,
                details={
                    "update_id": update.update_id,
                    "previous_status": current.status.value,
                    "reported_status": reported.status.value,
                },
            )
        )
        return reported
