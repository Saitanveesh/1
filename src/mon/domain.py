from __future__ import annotations

import datetime as dt
import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RECOVERING = "RECOVERING"
    CLOSED = "CLOSED"


class AssetCriticality(StrEnum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceClass(StrEnum):
    NETWORK_PACKET = "NETWORK_PACKET"
    NETWORK_FLOW = "NETWORK_FLOW"
    IDS_ALERT = "IDS_ALERT"
    ENDPOINT = "ENDPOINT"
    IDENTITY = "IDENTITY"
    THREAT_INTEL = "THREAT_INTEL"
    BEHAVIORAL = "BEHAVIORAL"
    STATISTICAL = "STATISTICAL"
    OPERATOR = "OPERATOR"


class ActionType(StrEnum):
    BLOCK_IP = "BLOCK_IP"
    RATE_LIMIT = "RATE_LIMIT"
    ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
    QUARANTINE_VLAN = "QUARANTINE_VLAN"
    DISABLE_SWITCH_PORT = "DISABLE_SWITCH_PORT"
    WAF_BLOCK = "WAF_BLOCK"
    CLOUD_DENY = "CLOUD_DENY"
    UPSTREAM_MITIGATION = "UPSTREAM_MITIGATION"
    RESTORE = "RESTORE"


class EnforcementKind(StrEnum):
    ENDPOINT = "ENDPOINT"
    NAC = "NAC"
    SWITCH = "SWITCH"
    ROUTER = "ROUTER"
    FIREWALL = "FIREWALL"
    WAF = "WAF"
    CLOUD = "CLOUD"
    UPSTREAM = "UPSTREAM"


class EnforcementHealth(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class ActorType(StrEnum):
    AUTOMATION = "AUTOMATION"
    OPERATOR = "OPERATOR"


class GraphNodeKind(StrEnum):
    ASSET = "ASSET"
    INTERNAL_IP = "INTERNAL_IP"
    EXTERNAL_IP = "EXTERNAL_IP"


class GraphRelation(StrEnum):
    NETWORK_COMMUNICATION = "NETWORK_COMMUNICATION"
    ADMIN_SERVICE = "ADMIN_SERVICE"
    DNS_QUERY = "DNS_QUERY"


class EvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_class: EvidenceClass
    source: str = Field(min_length=1, max_length=128)
    summary: str = Field(min_length=1, max_length=1000)
    confidence: float = Field(ge=0.0, le=1.0)
    observed_at: dt.datetime = Field(default_factory=utcnow)
    raw_reference: str | None = Field(default=None, max_length=1000)


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    observed_at: dt.datetime = Field(default_factory=utcnow)
    category: str = Field(min_length=1, max_length=128)
    asset_id: str | None = Field(default=None, max_length=256)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    protocol: str | None = Field(default=None, max_length=64)
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceRef] = Field(default_factory=list)


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[SecurityEvent] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def require_single_scope(self) -> EventBatch:
        scopes = {(event.tenant_id, event.site_id) for event in self.events}
        if len(scopes) != 1:
            raise ValueError("all events in a batch must belong to one tenant/site scope")
        return self


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=256)
    criticality: AssetCriticality = AssetCriticality.NORMAL
    ip_addresses: set[str] = Field(default_factory=set)
    mac_addresses: set[str] = Field(default_factory=set)
    hostnames: set[str] = Field(default_factory=set)
    vendor: str | None = Field(default=None, max_length=256)
    observed_tcp_services: set[int] = Field(default_factory=set)
    peer_counts: dict[str, int] = Field(default_factory=dict)
    protocol_counts: dict[str, int] = Field(default_factory=dict)
    identity_evidence: set[str] = Field(default_factory=set)
    measured_packets: int | None = Field(default=None, ge=0)
    measured_bytes: int | None = Field(default=None, ge=0)
    first_seen: dt.datetime = Field(default_factory=utcnow)
    last_seen: dt.datetime = Field(default_factory=utcnow)
    tags: set[str] = Field(default_factory=set)
    attributes: dict[str, Any] = Field(default_factory=dict)


class TelemetrySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    window_seconds: int = Field(default=60, ge=1)
    observed_at: dt.datetime = Field(default_factory=utcnow)
    observation_count: int = Field(default=0, ge=0)
    measurement_span_seconds: float | None = Field(default=None, ge=0)
    events_per_second: float | None = Field(default=None, ge=0)
    measured_packets: int | None = Field(default=None, ge=0)
    measured_bytes: int | None = Field(default=None, ge=0)
    measured_packets_per_second: float | None = Field(default=None, ge=0)
    measured_bytes_per_second: float | None = Field(default=None, ge=0)
    unique_src_ips: int = Field(default=0, ge=0)
    unique_dst_ips: int = Field(default=0, ge=0)
    protocol_counts: dict[str, int] = Field(default_factory=dict)
    source_counts: dict[str, int] = Field(default_factory=dict)


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    affected_asset_ids: set[str] = Field(default_factory=set)
    finding_ids: set[str] = Field(default_factory=set)
    detector_ids: set[str] = Field(default_factory=set)
    entities: set[str] = Field(default_factory=set)
    first_seen: dt.datetime = Field(default_factory=utcnow)
    last_seen: dt.datetime = Field(default_factory=utcnow)
    created_at: dt.datetime = Field(default_factory=utcnow)
    updated_at: dt.datetime = Field(default_factory=utcnow)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    detector_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    asset_id: str | None = Field(default=None, max_length=256)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    first_seen: dt.datetime = Field(default_factory=utcnow)
    last_seen: dt.datetime = Field(default_factory=utcnow)
    attributes: dict[str, Any] = Field(default_factory=dict)


class AttackGraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(min_length=1, max_length=512)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    kind: GraphNodeKind
    label: str = Field(min_length=1, max_length=512)
    attributes: dict[str, Any] = Field(default_factory=dict)


class AttackGraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    edge_id: str = Field(min_length=1, max_length=1500)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    src_node_id: str = Field(min_length=1, max_length=512)
    dst_node_id: str = Field(min_length=1, max_length=512)
    relation: GraphRelation
    protocol: str | None = Field(default=None, max_length=64)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    first_seen: dt.datetime
    last_seen: dt.datetime
    event_count: int = Field(default=1, ge=1)
    event_ids: set[str] = Field(default_factory=set)
    finding_ids: set[str] = Field(default_factory=set)
    detector_ids: set[str] = Field(default_factory=set)
    attributes: dict[str, Any] = Field(default_factory=dict)


class AttackGraphSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    site_id: str
    nodes: list[AttackGraphNode] = Field(default_factory=list)
    edges: list[AttackGraphEdge] = Field(default_factory=list)
    generated_at: dt.datetime = Field(default_factory=utcnow)


class EnforcementPoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enforcement_point_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    kind: EnforcementKind
    vendor: str = Field(min_length=1, max_length=128)
    capabilities: set[ActionType]
    health: EnforcementHealth = EnforcementHealth.HEALTHY
    priority: int = Field(default=100, ge=0, le=1000)
    attributes: dict[str, Any] = Field(default_factory=dict)


class EnforcementBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    binding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(min_length=1, max_length=256)
    enforcement_point_id: str = Field(min_length=1, max_length=256)
    distance: int = Field(default=0, ge=0, le=100)
    priority_bias: int = Field(default=0, ge=-500, le=500)
    attributes: dict[str, Any] = Field(default_factory=dict)


class ContainmentCapability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=256)
    binding_id: str = Field(min_length=1, max_length=256)
    enforcement_point_id: str = Field(min_length=1, max_length=256)
    kind: EnforcementKind
    vendor: str = Field(min_length=1, max_length=128)
    health: EnforcementHealth
    capabilities: set[ActionType]
    distance: int = Field(ge=0, le=100)
    blast_radius_estimate: str | None = Field(default=None, max_length=500)
    notes: list[str] = Field(default_factory=list)


class IncidentInvestigation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident: Incident
    findings: list[Finding] = Field(default_factory=list)
    affected_assets: list[Asset] = Field(default_factory=list)
    graph: AttackGraphSnapshot
    containment_capabilities: list[ContainmentCapability] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)


class ResponseTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str | None = Field(default=None, max_length=256)
    ip_address: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def exactly_one_target(self) -> ResponseTarget:
        if bool(self.asset_id) == bool(self.ip_address):
            raise ValueError("response target must specify exactly one of asset_id or ip_address")
        return self


class ResponseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    incident_id: str = Field(min_length=1, max_length=256)
    target: ResponseTarget
    action: ActionType
    enforcement_point_id: str | None = Field(default=None, min_length=1, max_length=256)
    actor_type: ActorType = ActorType.AUTOMATION
    actor_id: str = Field(default="mon-automation", min_length=1, max_length=256)
    ttl_seconds: int | None = Field(default=None, ge=30, le=604800)
    reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def require_ttl_for_disruptive_actions(self) -> ResponseRequest:
        disruptive = {
            ActionType.BLOCK_IP,
            ActionType.RATE_LIMIT,
            ActionType.ISOLATE_ENDPOINT,
            ActionType.QUARANTINE_VLAN,
            ActionType.DISABLE_SWITCH_PORT,
            ActionType.WAF_BLOCK,
            ActionType.CLOUD_DENY,
            ActionType.UPSTREAM_MITIGATION,
        }
        if self.action in disruptive and self.ttl_seconds is None:
            raise ValueError("disruptive response actions require a finite ttl_seconds")
        return self


class PolicyOutcome(StrEnum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class ResponseExecutionStatus(StrEnum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXECUTING = "EXECUTING"
    APPLIED = "APPLIED"
    FAILED = "FAILED"
    DENIED = "DENIED"
    ROLLBACK_PENDING = "ROLLBACK_PENDING"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: PolicyOutcome
    reasons: list[str]
    evaluated_at: dt.datetime = Field(default_factory=utcnow)


class ResponsePlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request: ResponseRequest
    decision: PolicyDecision
    enforcement_point: EnforcementPoint
    rollback_action: ActionType = ActionType.RESTORE
    selection_reasons: list[str] = Field(default_factory=list)
    blast_radius_estimate: str | None = Field(default=None, max_length=500)


class EnforcementResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: bool
    message: str = Field(min_length=1, max_length=1000)
    external_reference: str | None = Field(default=None, max_length=500)
    details: dict[str, Any] = Field(default_factory=dict)


class ResponseApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    actor_id: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1000)
    approved_at: dt.datetime = Field(default_factory=utcnow)


class ResponseExecutionCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request: ResponseRequest
    approve: bool = False
    approval_reason: str | None = Field(default=None, min_length=1, max_length=1000)

    @model_validator(mode="after")
    def require_reason_for_approval(self) -> ResponseExecutionCommand:
        if self.approve and not self.approval_reason:
            raise ValueError("approval_reason is required when approve=true")
        return self


class ResponseRollbackCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=1000)


class ResponseExecution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    plan: ResponsePlan
    status: ResponseExecutionStatus
    requested_at: dt.datetime = Field(default_factory=utcnow)
    approval: ResponseApproval | None = None
    applied_at: dt.datetime | None = None
    expires_at: dt.datetime | None = None
    rollback_at: dt.datetime | None = None
    result: EnforcementResult | None = None
    rollback_result: EnforcementResult | None = None
    error: str | None = Field(default=None, max_length=2000)


class AuditRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=256)
    category: str = Field(min_length=1, max_length=128)
    object_type: str = Field(min_length=1, max_length=128)
    object_id: str = Field(min_length=1, max_length=256)
    action: str = Field(min_length=1, max_length=128)
    outcome: str = Field(min_length=1, max_length=128)
    occurred_at: dt.datetime = Field(default_factory=utcnow)
    details: dict[str, Any] = Field(default_factory=dict)


class EventProcessingResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event: SecurityEvent
    asset_updates: list[Asset] = Field(default_factory=list)
    telemetry: TelemetrySnapshot | None = None
    findings: list[Finding] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)
    duplicate: bool = False


class EventBatchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    results: list[EventProcessingResult] = Field(default_factory=list)
    accepted_event_ids: list[str] = Field(default_factory=list)
