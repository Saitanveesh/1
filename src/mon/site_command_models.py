from __future__ import annotations

import datetime as dt
import uuid
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mon.domain import AuditRecord, ResponseApproval, ResponseExecution, ResponsePlan, utcnow


class SiteCommandKind(StrEnum):
    APPLY_RESPONSE = "APPLY_RESPONSE"
    ROLLBACK_RESPONSE = "ROLLBACK_RESPONSE"


class SiteCommandStatus(StrEnum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class SiteCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    kind: SiteCommandKind
    created_at: dt.datetime = Field(default_factory=utcnow)
    not_after: dt.datetime
    response_plan: ResponsePlan | None = None
    approval: ResponseApproval | None = None
    rollback_execution_id: str | None = Field(default=None, max_length=256)
    reason: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def validate_command(self) -> SiteCommand:
        if self.not_after <= self.created_at:
            raise ValueError("site command not_after must be after created_at")

        if self.kind is SiteCommandKind.APPLY_RESPONSE:
            if self.response_plan is None:
                raise ValueError("APPLY_RESPONSE requires response_plan")
            if self.rollback_execution_id is not None:
                raise ValueError("APPLY_RESPONSE cannot set rollback_execution_id")
            request = self.response_plan.request
            point = self.response_plan.enforcement_point
            if request.tenant_id != self.tenant_id or request.site_id != self.site_id:
                raise ValueError("response plan request scope does not match site command")
            if point.tenant_id != self.tenant_id or point.site_id != self.site_id:
                raise ValueError("response plan enforcement scope does not match site command")
            if self.response_plan.decision.outcome.value == "DENY":
                raise ValueError("denied response plans cannot be dispatched to a site")
            if (
                self.response_plan.decision.outcome.value == "REQUIRE_APPROVAL"
                and self.approval is None
            ):
                raise ValueError("response plan requires approval before site dispatch")
        else:
            if not self.rollback_execution_id:
                raise ValueError("ROLLBACK_RESPONSE requires rollback_execution_id")
            if not self.reason:
                raise ValueError("ROLLBACK_RESPONSE requires reason")
            if self.response_plan is not None or self.approval is not None:
                raise ValueError("ROLLBACK_RESPONSE cannot carry a response plan or approval")
        return self


class SiteCommandResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    success: bool
    completed_at: dt.datetime = Field(default_factory=utcnow)
    execution: ResponseExecution | None = None
    audit_records: list[AuditRecord] = Field(default_factory=list)
    error: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def validate_result(self) -> SiteCommandResult:
        if self.success and self.execution is None:
            raise ValueError("successful site command result requires execution")
        if not self.success and not self.error:
            raise ValueError("failed site command result requires error")
        if self.execution is not None:
            if (
                self.execution.tenant_id != self.tenant_id
                or self.execution.site_id != self.site_id
            ):
                raise ValueError("execution scope does not match site command result")
        for record in self.audit_records:
            if record.tenant_id != self.tenant_id or record.site_id != self.site_id:
                raise ValueError("audit record scope does not match site command result")
        return self


class SiteCommandRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: SiteCommand
    status: SiteCommandStatus = SiteCommandStatus.PENDING
    delivery_count: int = Field(default=0, ge=0)
    last_delivered_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None
    result: SiteCommandResult | None = None
    updated_at: dt.datetime = Field(default_factory=utcnow)
