from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mon.domain import AuditRecord, ResponseExecution, ResponseExecutionStatus, utcnow

_RECOVERY_UPDATE_NAMESPACE = uuid.UUID("34c6fa1c-3ddc-4ef6-b908-63179508e9a7")


def recovery_update_id(execution: ResponseExecution) -> str:
    rollback_result = (
        execution.rollback_result.model_dump_json()
        if execution.rollback_result is not None
        else ""
    )
    rollback_at = execution.rollback_at.isoformat() if execution.rollback_at is not None else ""
    material = ":".join(
        (
            execution.tenant_id,
            execution.site_id,
            execution.execution_id,
            execution.status.value,
            rollback_at,
            rollback_result,
            execution.error or "",
        )
    )
    return str(uuid.uuid5(_RECOVERY_UPDATE_NAMESPACE, material))


class SiteResponseUpdate(BaseModel):
    """Site-origin response state after autonomous recovery."""

    model_config = ConfigDict(extra="forbid")

    update_id: str = Field(default_factory=lambda: str(uuid.uuid4()), min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    execution: ResponseExecution
    audit_records: list[AuditRecord] = Field(default_factory=list)
    observed_at: dt.datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def validate_update(self) -> SiteResponseUpdate:
        execution = self.execution
        if self.observed_at.utcoffset() is None:
            raise ValueError("response update observed_at must be timezone-aware")
        if execution.tenant_id != self.tenant_id or execution.site_id != self.site_id:
            raise ValueError("response update execution scope does not match report scope")
        if execution.status not in {
            ResponseExecutionStatus.ROLLED_BACK,
            ResponseExecutionStatus.ROLLBACK_FAILED,
        }:
            raise ValueError("site response update must report a terminal rollback state")

        if execution.status is ResponseExecutionStatus.ROLLED_BACK:
            if execution.rollback_at is None:
                raise ValueError("rolled-back response update requires rollback_at")
            if execution.rollback_result is None or not execution.rollback_result.success:
                raise ValueError("rolled-back response update requires successful rollback_result")
            if execution.error is not None:
                raise ValueError("rolled-back response update cannot carry an error")
            if (
                execution.applied_at is not None
                and execution.rollback_at < execution.applied_at
            ):
                raise ValueError("response rollback cannot predate response application")
        else:
            if execution.rollback_result is not None and execution.rollback_result.success:
                raise ValueError("rollback-failed response update cannot carry a successful result")
            if not execution.error:
                raise ValueError("rollback-failed response update requires an error")

        audit_ids: set[str] = set()
        for record in self.audit_records:
            if record.tenant_id != self.tenant_id or record.site_id != self.site_id:
                raise ValueError("response update audit scope does not match report scope")
            if record.object_type != "response_execution":
                raise ValueError("response update audit must target response_execution")
            if record.object_id != execution.execution_id:
                raise ValueError("response update audit does not match execution")
            if record.audit_id in audit_ids:
                raise ValueError("response update contains duplicate audit records")
            audit_ids.add(record.audit_id)
        return self
