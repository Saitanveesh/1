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


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=256)
    criticality: AssetCriticality = AssetCriticality.NORMAL
    ip_addresses: set[str] = Field(default_factory=set)
    mac_addresses: set[str] = Field(default_factory=set)
    tags: set[str] = Field(default_factory=set)
    attributes: dict[str, Any] = Field(default_factory=dict)


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
    created_at: dt.datetime = Field(default_factory=utcnow)
    updated_at: dt.datetime = Field(default_factory=utcnow)


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
    enforcement_point_id: str = Field(min_length=1, max_length=256)
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
