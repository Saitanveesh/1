from __future__ import annotations

import datetime as dt
import threading
from collections import defaultdict
from typing import Protocol

from mon.domain import (
    Asset,
    AuditRecord,
    EnforcementBinding,
    EnforcementPoint,
    Finding,
    Incident,
    ResponseExecution,
    SecurityEvent,
)
from mon.site_command_models import SiteCommandRecord
from mon.site_identity_models import EnrollmentTokenRecord, SiteIdentityRecord


class PipelineStore(Protocol):
    """Persistence contract required by the local evidence pipeline."""

    def event_exists(self, tenant_id: str, site_id: str, event_id: str) -> bool: ...

    def add_event(self, event: SecurityEvent) -> SecurityEvent: ...

    def list_events(
        self,
        tenant_id: str,
        site_id: str,
        *,
        since: dt.datetime | None = None,
    ) -> list[SecurityEvent]: ...

    def add_finding(self, finding: Finding) -> Finding: ...

    def list_findings(self, tenant_id: str, site_id: str) -> list[Finding]: ...

    def add_incident(self, incident: Incident) -> Incident: ...

    def list_incidents(self, tenant_id: str, site_id: str) -> list[Incident]: ...

    def get_incident(
        self, tenant_id: str, site_id: str, incident_id: str
    ) -> Incident | None: ...

    def add_asset(self, asset: Asset) -> Asset: ...

    def get_asset(
        self, tenant_id: str, site_id: str, asset_id: str
    ) -> Asset | None: ...

    def list_assets(self, tenant_id: str, site_id: str) -> list[Asset]: ...


class ResponseStateStore(Protocol):
    """Persistence contract required by local response execution and recovery."""

    def add_response_execution(
        self, execution: ResponseExecution
    ) -> ResponseExecution: ...

    def get_response_execution(
        self, tenant_id: str, site_id: str, execution_id: str
    ) -> ResponseExecution | None: ...

    def list_response_executions(
        self, tenant_id: str, site_id: str
    ) -> list[ResponseExecution]: ...

    def add_audit_record(self, record: AuditRecord) -> AuditRecord: ...

    def list_audit_records(
        self, tenant_id: str, site_id: str
    ) -> list[AuditRecord]: ...


class Store(PipelineStore, ResponseStateStore, Protocol):
    def event_exists(self, tenant_id: str, site_id: str, event_id: str) -> bool: ...

    def add_event(self, event: SecurityEvent) -> SecurityEvent: ...

    def add_finding(self, finding: Finding) -> Finding: ...

    def list_findings(self, tenant_id: str, site_id: str) -> list[Finding]: ...

    def add_incident(self, incident: Incident) -> Incident: ...

    def list_incidents(self, tenant_id: str, site_id: str) -> list[Incident]: ...

    def get_incident(
        self, tenant_id: str, site_id: str, incident_id: str
    ) -> Incident | None: ...

    def add_asset(self, asset: Asset) -> Asset: ...

    def get_asset(self, tenant_id: str, site_id: str, asset_id: str) -> Asset | None: ...

    def list_assets(self, tenant_id: str, site_id: str) -> list[Asset]: ...

    def add_enforcement_point(self, point: EnforcementPoint) -> EnforcementPoint: ...

    def get_enforcement_point(
        self, tenant_id: str, site_id: str, enforcement_point_id: str
    ) -> EnforcementPoint | None: ...

    def list_enforcement_points(
        self, tenant_id: str, site_id: str
    ) -> list[EnforcementPoint]: ...

    def add_enforcement_binding(self, binding: EnforcementBinding) -> EnforcementBinding: ...

    def list_enforcement_bindings(
        self,
        tenant_id: str,
        site_id: str,
        asset_id: str | None = None,
    ) -> list[EnforcementBinding]: ...
    def add_enrollment_token(
        self, record: EnrollmentTokenRecord
    ) -> EnrollmentTokenRecord: ...

    def get_enrollment_token(self, token_hash: str) -> EnrollmentTokenRecord | None: ...

    def consume_enrollment_token(
        self,
        token_hash: str,
        now: dt.datetime,
    ) -> EnrollmentTokenRecord | None: ...

    def add_site_identity(self, record: SiteIdentityRecord) -> SiteIdentityRecord: ...

    def list_site_identities(
        self, tenant_id: str, site_id: str
    ) -> list[SiteIdentityRecord]: ...

    def add_site_command(self, record: SiteCommandRecord) -> SiteCommandRecord: ...

    def get_site_command(
        self, tenant_id: str, site_id: str, command_id: str
    ) -> SiteCommandRecord | None: ...

    def list_site_commands(
        self, tenant_id: str, site_id: str
    ) -> list[SiteCommandRecord]: ...


class InMemoryStore:
    """Development store with strict tenant/site scoping."""

    def __init__(self) -> None:
        self.events: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        self.event_ids: set[tuple[str, str, str]] = set()
        self.incidents: dict[str, Incident] = {}
        self.findings: dict[str, Finding] = {}
        self.assets: dict[tuple[str, str, str], Asset] = {}
        self.enforcement_points: dict[str, EnforcementPoint] = {}
        self.enforcement_bindings: dict[str, EnforcementBinding] = {}
        self.enrollment_tokens: dict[str, EnrollmentTokenRecord] = {}
        self.site_identities: dict[str, SiteIdentityRecord] = {}
        self.response_executions: dict[tuple[str, str, str], ResponseExecution] = {}
        self.audit_records: dict[tuple[str, str, str], AuditRecord] = {}
        self.site_commands: dict[tuple[str, str, str], SiteCommandRecord] = {}
        self._identity_lock = threading.RLock()

    def event_exists(self, tenant_id: str, site_id: str, event_id: str) -> bool:
        return (tenant_id, site_id, event_id) in self.event_ids

    def add_event(self, event: SecurityEvent) -> SecurityEvent:
        key = (event.tenant_id, event.site_id, event.event_id)
        if key in self.event_ids:
            return event
        self.event_ids.add(key)
        self.events[(event.tenant_id, event.site_id)].append(event)
        return event

    def list_events(
        self,
        tenant_id: str,
        site_id: str,
        *,
        since: dt.datetime | None = None,
    ) -> list[SecurityEvent]:
        values = list(self.events[(tenant_id, site_id)])
        if since is not None:
            values = [item for item in values if item.observed_at >= since]
        return sorted(values, key=lambda item: (item.observed_at, item.event_id))

    def add_finding(self, finding: Finding) -> Finding:
        self.findings[finding.finding_id] = finding
        return finding

    def list_findings(self, tenant_id: str, site_id: str) -> list[Finding]:
        return [
            value
            for value in self.findings.values()
            if value.tenant_id == tenant_id and value.site_id == site_id
        ]

    def add_incident(self, incident: Incident) -> Incident:
        self.incidents[incident.incident_id] = incident
        return incident

    def list_incidents(self, tenant_id: str, site_id: str) -> list[Incident]:
        return [
            value
            for value in self.incidents.values()
            if value.tenant_id == tenant_id and value.site_id == site_id
        ]

    def get_incident(self, tenant_id: str, site_id: str, incident_id: str) -> Incident | None:
        value = self.incidents.get(incident_id)
        if value and value.tenant_id == tenant_id and value.site_id == site_id:
            return value
        return None

    def add_asset(self, asset: Asset) -> Asset:
        self.assets[(asset.tenant_id, asset.site_id, asset.asset_id)] = asset
        return asset

    def get_asset(self, tenant_id: str, site_id: str, asset_id: str) -> Asset | None:
        return self.assets.get((tenant_id, site_id, asset_id))

    def list_assets(self, tenant_id: str, site_id: str) -> list[Asset]:
        return [
            value
            for (asset_tenant, asset_site, _), value in self.assets.items()
            if asset_tenant == tenant_id and asset_site == site_id
        ]

    def add_enforcement_point(self, point: EnforcementPoint) -> EnforcementPoint:
        self.enforcement_points[point.enforcement_point_id] = point
        return point

    def get_enforcement_point(
        self,
        tenant_id: str,
        site_id: str,
        enforcement_point_id: str,
    ) -> EnforcementPoint | None:
        value = self.enforcement_points.get(enforcement_point_id)
        if value and value.tenant_id == tenant_id and value.site_id == site_id:
            return value
        return None

    def list_enforcement_points(self, tenant_id: str, site_id: str) -> list[EnforcementPoint]:
        return [
            value
            for value in self.enforcement_points.values()
            if value.tenant_id == tenant_id and value.site_id == site_id
        ]

    def add_enforcement_binding(self, binding: EnforcementBinding) -> EnforcementBinding:
        self.enforcement_bindings[binding.binding_id] = binding
        return binding

    def list_enforcement_bindings(
        self,
        tenant_id: str,
        site_id: str,
        asset_id: str | None = None,
    ) -> list[EnforcementBinding]:
        values = [
            value
            for value in self.enforcement_bindings.values()
            if value.tenant_id == tenant_id and value.site_id == site_id
        ]
        if asset_id is not None:
            values = [value for value in values if value.asset_id == asset_id]
        return values


    def add_enrollment_token(
        self,
        record: EnrollmentTokenRecord,
    ) -> EnrollmentTokenRecord:
        with self._identity_lock:
            self.enrollment_tokens[record.token_hash] = record
        return record

    def get_enrollment_token(self, token_hash: str) -> EnrollmentTokenRecord | None:
        with self._identity_lock:
            return self.enrollment_tokens.get(token_hash)

    def consume_enrollment_token(
        self,
        token_hash: str,
        now: dt.datetime,
    ) -> EnrollmentTokenRecord | None:
        with self._identity_lock:
            record = self.enrollment_tokens.get(token_hash)
            if record is None or record.used_at is not None or record.expires_at <= now:
                return None
            consumed = record.model_copy(update={"used_at": now})
            self.enrollment_tokens[token_hash] = consumed
            return consumed

    def add_site_identity(self, record: SiteIdentityRecord) -> SiteIdentityRecord:
        with self._identity_lock:
            self.site_identities[record.identity_id] = record
        return record

    def list_site_identities(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[SiteIdentityRecord]:
        with self._identity_lock:
            return [
                value
                for value in self.site_identities.values()
                if value.tenant_id == tenant_id and value.site_id == site_id
            ]


    def add_response_execution(
        self,
        execution: ResponseExecution,
    ) -> ResponseExecution:
        key = (execution.tenant_id, execution.site_id, execution.execution_id)
        self.response_executions[key] = execution
        return execution

    def get_response_execution(
        self,
        tenant_id: str,
        site_id: str,
        execution_id: str,
    ) -> ResponseExecution | None:
        return self.response_executions.get((tenant_id, site_id, execution_id))

    def list_response_executions(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[ResponseExecution]:
        return [
            execution
            for (scope_tenant, scope_site, _), execution in self.response_executions.items()
            if scope_tenant == tenant_id and scope_site == site_id
        ]

    def add_audit_record(self, record: AuditRecord) -> AuditRecord:
        key = (record.tenant_id, record.site_id, record.audit_id)
        self.audit_records[key] = record
        return record

    def list_audit_records(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[AuditRecord]:
        return sorted(
            [
                record
                for (scope_tenant, scope_site, _), record in self.audit_records.items()
                if scope_tenant == tenant_id and scope_site == site_id
            ],
            key=lambda item: (item.occurred_at, item.audit_id),
        )


    def add_site_command(self, record: SiteCommandRecord) -> SiteCommandRecord:
        command = record.command
        key = (command.tenant_id, command.site_id, command.command_id)
        self.site_commands[key] = record
        return record

    def get_site_command(
        self,
        tenant_id: str,
        site_id: str,
        command_id: str,
    ) -> SiteCommandRecord | None:
        return self.site_commands.get((tenant_id, site_id, command_id))

    def list_site_commands(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[SiteCommandRecord]:
        return [
            record
            for (scope_tenant, scope_site, _), record in self.site_commands.items()
            if scope_tenant == tenant_id and scope_site == site_id
        ]
