from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mon.domain import AttackGraphSnapshot

CHECKPOINT_SCHEMA_VERSION = 1


class DetectorObservationCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observed_at: dt.datetime
    dst_ip: str | None = None
    dst_port: int | None = None
    value: str | None = None


class DetectorWindowCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: str
    tenant_id: str
    site_id: str
    source: str
    observations: list[DetectorObservationCheckpoint] = Field(default_factory=list)


class DetectorBeaconCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    site_id: str
    source: str
    destination: str
    protocol: str
    port: int
    observed_at: list[dt.datetime] = Field(default_factory=list)


class DetectorEmitCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: str
    tenant_id: str
    site_id: str
    source: str
    last_emitted_at: dt.datetime


class DetectorStateCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format_version: Literal[1] = 1
    thresholds: dict[str, int]
    windows: list[DetectorWindowCheckpoint] = Field(default_factory=list)
    beacons: list[DetectorBeaconCheckpoint] = Field(default_factory=list)
    last_emit: list[DetectorEmitCheckpoint] = Field(default_factory=list)


class TelemetryObservationCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observed_at: dt.datetime
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    measured_packets: int | None = None
    measured_bytes: int | None = None


class TelemetryStateCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format_version: Literal[1] = 1
    window_seconds: int = Field(ge=1)
    observations: list[TelemetryObservationCheckpoint] = Field(default_factory=list)


class ActiveCorrelationCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    site_id: str
    actor: str
    incident_id: str
    last_seen: dt.datetime


class CorrelationStateCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format_version: Literal[1] = 1
    window_seconds: int = Field(ge=1)
    active: list[ActiveCorrelationCheckpoint] = Field(default_factory=list)


class AnalysisCheckpointPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = CHECKPOINT_SCHEMA_VERSION
    tenant_id: str
    site_id: str
    checkpoint_id: str
    created_at: dt.datetime
    boundary_event_id: str
    boundary_observed_at: dt.datetime
    detector: DetectorStateCheckpoint
    telemetry: TelemetryStateCheckpoint
    correlation: CorrelationStateCheckpoint
    attack_graph: AttackGraphSnapshot
    asset_analysis: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_single_scope(self) -> AnalysisCheckpointPayload:
        if (
            self.attack_graph.tenant_id != self.tenant_id
            or self.attack_graph.site_id != self.site_id
        ):
            raise ValueError("attack graph checkpoint scope mismatch")
        for window in self.detector.windows:
            if window.tenant_id != self.tenant_id or window.site_id != self.site_id:
                raise ValueError("detector window checkpoint scope mismatch")
        for beacon in self.detector.beacons:
            if beacon.tenant_id != self.tenant_id or beacon.site_id != self.site_id:
                raise ValueError("detector beacon checkpoint scope mismatch")
        for item in self.detector.last_emit:
            if item.tenant_id != self.tenant_id or item.site_id != self.site_id:
                raise ValueError("detector emit checkpoint scope mismatch")
        for item in self.correlation.active:
            if item.tenant_id != self.tenant_id or item.site_id != self.site_id:
                raise ValueError("correlation checkpoint scope mismatch")
        return self

