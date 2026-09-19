from __future__ import annotations

import datetime as dt
import threading
from collections import defaultdict
from contextlib import AbstractContextManager
from typing import Protocol, runtime_checkable

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
from mon.event_fabric import FabricReceipt, FabricReceiptStatus
from mon.sensor_fleet_models import (
    SensorEnrollmentTokenRecord,
    SensorHeartbeat,
    SensorIdentityRecord,
    SensorIdentityStatus,
    SensorRecord,
)
from mon.site_command_models import SiteCommandRecord
from mon.site_identity_models import EnrollmentTokenRecord, SiteIdentityRecord


class PipelineStore(Protocol):
    """Persistence contract required by the local evidence pipeline."""

    def event_exists(self, tenant_id: str, site_id: str, event_id: str) -> bool: ...

    def get_event(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> SecurityEvent | None: ...

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


@runtime_checkable
class TransactionalPipelineStore(PipelineStore, Protocol):
    """Optional atomic processing contract for durable local pipeline stores."""

    def transaction(self) -> AbstractContextManager[None]: ...

    def event_processed(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> bool: ...

    def mark_event_processed(self, event: SecurityEvent) -> None: ...

    def list_unprocessed_events(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[SecurityEvent]: ...


class FabricReceiptStore(Protocol):
    def get_fabric_receipt(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> FabricReceipt | None: ...

    def add_fabric_receipt(
        self,
        receipt: FabricReceipt,
    ) -> FabricReceipt: ...

    def complete_fabric_receipt(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
        *,
        processed_at: dt.datetime,
    ) -> FabricReceipt: ...


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


class Store(PipelineStore, ResponseStateStore, FabricReceiptStore, Protocol):
    def event_exists(self, tenant_id: str, site_id: str, event_id: str) -> bool: ...

    def get_event(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> SecurityEvent | None: ...

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

    def add_sensor_enrollment_token(
        self, record: SensorEnrollmentTokenRecord
    ) -> SensorEnrollmentTokenRecord: ...

    def get_sensor_enrollment_token(
        self, token_hash: str
    ) -> SensorEnrollmentTokenRecord | None: ...

    def complete_sensor_enrollment(
        self,
        token_hash: str,
        now: dt.datetime,
        sensor: SensorRecord,
        identity: SensorIdentityRecord,
    ) -> bool: ...

    def get_sensor_record(
        self, tenant_id: str, site_id: str, sensor_id: str
    ) -> SensorRecord | None: ...

    def list_sensor_records(
        self, tenant_id: str, site_id: str
    ) -> list[SensorRecord]: ...

    def get_sensor_identity(
        self,
        tenant_id: str,
        site_id: str,
        identity_id: str,
    ) -> SensorIdentityRecord | None: ...

    def get_sensor_identity_by_fingerprint(
        self,
        tenant_id: str,
        site_id: str,
        fingerprint_sha256: str,
    ) -> SensorIdentityRecord | None: ...

    def list_sensor_identities(
        self,
        tenant_id: str,
        site_id: str,
        sensor_id: str | None = None,
    ) -> list[SensorIdentityRecord]: ...

    def save_sensor_lifecycle(
        self,
        sensor: SensorRecord,
        identities: list[SensorIdentityRecord],
    ) -> None: ...

    def complete_sensor_renewal(
        self,
        previous_identity_id: str,
        sensor: SensorRecord,
        previous: SensorIdentityRecord,
        successor: SensorIdentityRecord,
    ) -> bool: ...

    def revoke_sensor_lifecycle(
        self,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        *,
        actor_id: str,
        reason: str,
        now: dt.datetime,
    ) -> SensorRecord | None: ...

    def record_sensor_heartbeat(
        self,
        heartbeat: SensorHeartbeat,
        received_at: dt.datetime,
    ) -> SensorRecord | None: ...

    def add_site_command(self, record: SiteCommandRecord) -> SiteCommandRecord: ...

    def get_site_command(
        self, tenant_id: str, site_id: str, command_id: str
    ) -> SiteCommandRecord | None: ...

    def list_site_commands(
        self, tenant_id: str, site_id: str
    ) -> list[SiteCommandRecord]: ...

    def get_fabric_receipt(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> FabricReceipt | None: ...

    def add_fabric_receipt(
        self,
        receipt: FabricReceipt,
    ) -> FabricReceipt: ...

    def complete_fabric_receipt(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
        *,
        processed_at: dt.datetime,
    ) -> FabricReceipt: ...


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
        self.sensor_enrollment_tokens: dict[str, SensorEnrollmentTokenRecord] = {}
        self.sensor_records: dict[tuple[str, str, str], SensorRecord] = {}
        self.sensor_identities: dict[str, SensorIdentityRecord] = {}
        self.response_executions: dict[tuple[str, str, str], ResponseExecution] = {}
        self.audit_records: dict[tuple[str, str, str], AuditRecord] = {}
        self.site_commands: dict[tuple[str, str, str], SiteCommandRecord] = {}
        self.fabric_receipts: dict[tuple[str, str, str], FabricReceipt] = {}
        self._identity_lock = threading.RLock()

    def event_exists(self, tenant_id: str, site_id: str, event_id: str) -> bool:
        return (tenant_id, site_id, event_id) in self.event_ids

    def get_event(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> SecurityEvent | None:
        for event in self.events[(tenant_id, site_id)]:
            if event.event_id == event_id:
                return event
        return None

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

    def get_fabric_receipt(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> FabricReceipt | None:
        return self.fabric_receipts.get((tenant_id, site_id, event_id))

    def add_fabric_receipt(
        self,
        receipt: FabricReceipt,
    ) -> FabricReceipt:
        key = (receipt.tenant_id, receipt.site_id, receipt.event_id)
        existing = self.fabric_receipts.get(key)
        if existing is not None:
            if (
                existing.envelope_sha256 != receipt.envelope_sha256
                or existing.envelope_json != receipt.envelope_json
            ):
                raise ValueError(
                    "fabric receipt already exists with different envelope"
                )
            return existing
        self.fabric_receipts[key] = receipt
        return receipt

    def complete_fabric_receipt(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
        *,
        processed_at: dt.datetime,
    ) -> FabricReceipt:
        if processed_at.tzinfo is None or processed_at.utcoffset() is None:
            raise ValueError("fabric receipt processed_at must be timezone-aware")
        key = (tenant_id, site_id, event_id)
        existing = self.fabric_receipts.get(key)
        if existing is None:
            raise ValueError("fabric receipt does not exist")
        if existing.status is FabricReceiptStatus.PROCESSED:
            return existing
        completed = existing.model_copy(
            update={
                "status": FabricReceiptStatus.PROCESSED,
                "processed_at": processed_at.astimezone(dt.UTC),
            }
        )
        self.fabric_receipts[key] = completed
        return completed

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


    def add_sensor_enrollment_token(
        self,
        record: SensorEnrollmentTokenRecord,
    ) -> SensorEnrollmentTokenRecord:
        with self._identity_lock:
            self.sensor_enrollment_tokens[record.token_hash] = record
        return record

    def get_sensor_enrollment_token(
        self,
        token_hash: str,
    ) -> SensorEnrollmentTokenRecord | None:
        with self._identity_lock:
            return self.sensor_enrollment_tokens.get(token_hash)

    def complete_sensor_enrollment(
        self,
        token_hash: str,
        now: dt.datetime,
        sensor: SensorRecord,
        identity: SensorIdentityRecord,
    ) -> bool:
        with self._identity_lock:
            token = self.sensor_enrollment_tokens.get(token_hash)
            if (
                token is None
                or token.used_at is not None
                or token.expires_at <= now
                or token.tenant_id != sensor.tenant_id
                or token.site_id != sensor.site_id
                or token.sensor_id != sensor.sensor_id
                or identity.tenant_id != sensor.tenant_id
                or identity.site_id != sensor.site_id
                or identity.sensor_id != sensor.sensor_id
            ):
                return False
            consumed = token.model_copy(
                update={
                    "used_at": now,
                    "used_identity_id": identity.identity_id,
                }
            )
            self.sensor_enrollment_tokens[token_hash] = consumed
            self.sensor_records[
                (sensor.tenant_id, sensor.site_id, sensor.sensor_id)
            ] = sensor
            self.sensor_identities[identity.identity_id] = identity
            return True

    def get_sensor_record(
        self,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
    ) -> SensorRecord | None:
        with self._identity_lock:
            return self.sensor_records.get((tenant_id, site_id, sensor_id))

    def list_sensor_records(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[SensorRecord]:
        with self._identity_lock:
            return sorted(
                [
                    record
                    for (scope_tenant, scope_site, _), record
                    in self.sensor_records.items()
                    if scope_tenant == tenant_id and scope_site == site_id
                ],
                key=lambda item: item.sensor_id,
            )

    def get_sensor_identity(
        self,
        tenant_id: str,
        site_id: str,
        identity_id: str,
    ) -> SensorIdentityRecord | None:
        with self._identity_lock:
            identity = self.sensor_identities.get(identity_id)
            if (
                identity is not None
                and identity.tenant_id == tenant_id
                and identity.site_id == site_id
            ):
                return identity
            return None

    def get_sensor_identity_by_fingerprint(
        self,
        tenant_id: str,
        site_id: str,
        fingerprint_sha256: str,
    ) -> SensorIdentityRecord | None:
        with self._identity_lock:
            for identity in self.sensor_identities.values():
                if (
                    identity.tenant_id == tenant_id
                    and identity.site_id == site_id
                    and identity.fingerprint_sha256 == fingerprint_sha256
                ):
                    return identity
        return None

    def list_sensor_identities(
        self,
        tenant_id: str,
        site_id: str,
        sensor_id: str | None = None,
    ) -> list[SensorIdentityRecord]:
        with self._identity_lock:
            values = [
                identity
                for identity in self.sensor_identities.values()
                if identity.tenant_id == tenant_id
                and identity.site_id == site_id
                and (sensor_id is None or identity.sensor_id == sensor_id)
            ]
        return sorted(values, key=lambda item: (item.issued_at, item.identity_id))

    def save_sensor_lifecycle(
        self,
        sensor: SensorRecord,
        identities: list[SensorIdentityRecord],
    ) -> None:
        with self._identity_lock:
            for identity in identities:
                if (
                    identity.tenant_id != sensor.tenant_id
                    or identity.site_id != sensor.site_id
                    or identity.sensor_id != sensor.sensor_id
                ):
                    raise ValueError("sensor lifecycle identity scope mismatch")
            self.sensor_records[
                (sensor.tenant_id, sensor.site_id, sensor.sensor_id)
            ] = sensor
            for identity in identities:
                self.sensor_identities[identity.identity_id] = identity

    def complete_sensor_renewal(
        self,
        previous_identity_id: str,
        sensor: SensorRecord,
        previous: SensorIdentityRecord,
        successor: SensorIdentityRecord,
    ) -> bool:
        with self._identity_lock:
            stored = self.sensor_identities.get(previous_identity_id)
            if stored is None or stored.status.value != "ACTIVE":
                return False
            if (
                stored.tenant_id != sensor.tenant_id
                or stored.site_id != sensor.site_id
                or stored.sensor_id != sensor.sensor_id
                or previous.identity_id != stored.identity_id
                or previous.status.value != "RETIRING"
                or successor.tenant_id != sensor.tenant_id
                or successor.site_id != sensor.site_id
                or successor.sensor_id != sensor.sensor_id
            ):
                return False
            current_sensor = self.sensor_records.get(
                (sensor.tenant_id, sensor.site_id, sensor.sensor_id)
            )
            if current_sensor is None or current_sensor.revoked_at is not None:
                return False
            self.sensor_identities[previous.identity_id] = previous
            self.sensor_identities[successor.identity_id] = successor
            self.sensor_records[
                (sensor.tenant_id, sensor.site_id, sensor.sensor_id)
            ] = sensor
            return True

    def revoke_sensor_lifecycle(
        self,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        *,
        actor_id: str,
        reason: str,
        now: dt.datetime,
    ) -> SensorRecord | None:
        with self._identity_lock:
            key = (tenant_id, site_id, sensor_id)
            sensor = self.sensor_records.get(key)
            if sensor is None:
                return None
            if sensor.revoked_at is not None:
                return sensor
            updated = sensor.model_copy(
                update={
                    "updated_at": now,
                    "revoked_at": now,
                    "revoked_by": actor_id,
                    "revocation_reason": reason,
                }
            )
            self.sensor_records[key] = updated
            for identity_id, identity in list(self.sensor_identities.items()):
                if (
                    identity.tenant_id == tenant_id
                    and identity.site_id == site_id
                    and identity.sensor_id == sensor_id
                ):
                    self.sensor_identities[identity_id] = identity.model_copy(
                        update={
                            "status": SensorIdentityStatus.REVOKED,
                            "accept_until": None,
                            "revoked_at": now,
                            "revoked_by": actor_id,
                            "revocation_reason": reason,
                        }
                    )
            return updated

    def record_sensor_heartbeat(
        self,
        heartbeat: SensorHeartbeat,
        received_at: dt.datetime,
    ) -> SensorRecord | None:
        with self._identity_lock:
            key = (heartbeat.tenant_id, heartbeat.site_id, heartbeat.sensor_id)
            sensor = self.sensor_records.get(key)
            if sensor is None or sensor.revoked_at is not None:
                return None
            identity = next(
                (
                    item
                    for item in self.sensor_identities.values()
                    if item.tenant_id == heartbeat.tenant_id
                    and item.site_id == heartbeat.site_id
                    and item.sensor_id == heartbeat.sensor_id
                    and item.fingerprint_sha256
                    == heartbeat.fingerprint_sha256
                ),
                None,
            )
            if identity is None or identity.expires_at <= received_at:
                return None
            accepted = identity.status.value == "ACTIVE" or (
                identity.status.value == "RETIRING"
                and identity.accept_until is not None
                and identity.accept_until > received_at
            )
            if not accepted:
                return None
            updates: dict[str, object] = {
                "updated_at": received_at,
                "last_seen_at": received_at,
            }
            if (
                sensor.last_heartbeat_observed_at is None
                or heartbeat.observed_at >= sensor.last_heartbeat_observed_at
            ):
                updates.update(
                    {
                        "last_heartbeat_observed_at": heartbeat.observed_at,
                        "last_health_state": heartbeat.state,
                        "collector_kind": heartbeat.collector_kind,
                        "version": heartbeat.version,
                        "last_error": heartbeat.last_error,
                    }
                )
            updated = sensor.model_copy(update=updates)
            self.sensor_records[key] = updated
            return updated

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
