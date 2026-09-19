from __future__ import annotations

import datetime as dt
import uuid
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SensorIdentityStatus(StrEnum):
    ACTIVE = "ACTIVE"
    RETIRING = "RETIRING"
    REVOKED = "REVOKED"


class SensorFleetState(StrEnum):
    READY = "READY"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    REVOKED = "REVOKED"


class SensorEnrollmentTokenRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token_hash: str = Field(min_length=64, max_length=64)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    created_by: str = Field(min_length=1, max_length=256)
    created_at: dt.datetime
    expires_at: dt.datetime
    used_at: dt.datetime | None = None

    @model_validator(mode="after")
    def validate_times(self) -> SensorEnrollmentTokenRecord:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("sensor enrollment created_at must be timezone-aware")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("sensor enrollment expires_at must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("sensor enrollment expires_at must follow created_at")
        if self.used_at is not None and (
            self.used_at.tzinfo is None or self.used_at.utcoffset() is None
        ):
            raise ValueError("sensor enrollment used_at must be timezone-aware")
        return self


class SensorEnrollmentTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    ttl_seconds: int = Field(default=900, ge=60, le=86400)


class SensorEnrollmentTokenIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollment_token: str = Field(min_length=32)
    tenant_id: str
    site_id: str
    sensor_id: str
    expires_at: dt.datetime


class SensorEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollment_token: str = Field(min_length=32, max_length=512)
    csr_pem: str = Field(min_length=64, max_length=32768)


class SensorIdentityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        min_length=1,
        max_length=64,
    )
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    certificate_serial: str = Field(min_length=1, max_length=128)
    fingerprint_sha256: str = Field(min_length=64, max_length=64)
    spiffe_uri: str = Field(min_length=1, max_length=1024)
    certificate_pem: str = Field(min_length=64, max_length=32768)
    issued_at: dt.datetime
    expires_at: dt.datetime
    status: SensorIdentityStatus = SensorIdentityStatus.ACTIVE
    accept_until: dt.datetime | None = None
    superseded_by_identity_id: str | None = Field(default=None, max_length=64)
    revoked_at: dt.datetime | None = None
    revoked_by: str | None = Field(default=None, max_length=256)
    revocation_reason: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> SensorIdentityRecord:
        for name in ("issued_at", "expires_at"):
            value = getattr(self, name)
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"sensor identity {name} must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("sensor identity expires_at must follow issued_at")

        if self.accept_until is not None:
            if (
                self.accept_until.tzinfo is None
                or self.accept_until.utcoffset() is None
            ):
                raise ValueError("sensor identity accept_until must be timezone-aware")
            if self.accept_until > self.expires_at:
                raise ValueError("sensor identity accept_until cannot exceed expires_at")

        if self.status is SensorIdentityStatus.ACTIVE:
            if self.revoked_at is not None:
                raise ValueError("active sensor identity cannot have revoked_at")
        elif self.status is SensorIdentityStatus.RETIRING:
            if self.accept_until is None or not self.superseded_by_identity_id:
                raise ValueError(
                    "retiring sensor identity requires accept_until and successor"
                )
            if self.revoked_at is not None:
                raise ValueError("retiring sensor identity cannot have revoked_at")
        elif self.status is SensorIdentityStatus.REVOKED:
            if self.revoked_at is None or not self.revoked_by or not self.revocation_reason:
                raise ValueError(
                    "revoked sensor identity requires actor, time and reason"
                )
        return self


class SensorEnrollmentResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_id: str
    tenant_id: str
    site_id: str
    sensor_id: str
    certificate_pem: str
    ca_certificate_pem: str
    fingerprint_sha256: str
    spiffe_uri: str
    expires_at: dt.datetime


class SensorRenewalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    current_fingerprint_sha256: str = Field(min_length=64, max_length=64)
    csr_pem: str = Field(min_length=64, max_length=32768)


class SensorRevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=1000)


class SensorHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    fingerprint_sha256: str = Field(min_length=64, max_length=64)
    observed_at: dt.datetime
    state: SensorFleetState
    collector_kind: str = Field(min_length=1, max_length=64)
    version: str | None = Field(default=None, max_length=64)
    last_error: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def validate_heartbeat(self) -> SensorHeartbeat:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("sensor heartbeat observed_at must be timezone-aware")
        if self.state is SensorFleetState.REVOKED:
            raise ValueError("sensor heartbeat state cannot be REVOKED")
        if self.state is SensorFleetState.DEGRADED and not self.last_error:
            raise ValueError("degraded sensor heartbeat requires last_error")
        return self


class SensorRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    created_at: dt.datetime
    updated_at: dt.datetime
    revoked_at: dt.datetime | None = None
    revoked_by: str | None = Field(default=None, max_length=256)
    revocation_reason: str | None = Field(default=None, max_length=1000)
    last_seen_at: dt.datetime | None = None
    last_heartbeat_observed_at: dt.datetime | None = None
    last_health_state: SensorFleetState | None = None
    collector_kind: str | None = Field(default=None, max_length=64)
    version: str | None = Field(default=None, max_length=64)
    last_error: str | None = Field(default=None, max_length=1000)
    current_identity_id: str | None = Field(default=None, max_length=64)


class SensorFleetView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    site_id: str
    sensor_id: str
    state: SensorFleetState
    current_identity_id: str | None = None
    certificate_expires_at: dt.datetime | None = None
    last_seen_at: dt.datetime | None = None
    heartbeat_age_seconds: int | None = Field(default=None, ge=0)
    stale_after_seconds: int = Field(ge=1)
    collector_kind: str | None = None
    version: str | None = None
    last_error: str | None = None


class SensorTrustIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensor_id: str = Field(min_length=1, max_length=128)
    identity_id: str = Field(min_length=1, max_length=64)
    fingerprint_sha256: str = Field(min_length=64, max_length=64)
    status: SensorIdentityStatus
    expires_at: dt.datetime
    accept_until: dt.datetime | None = None


class SensorTrustSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    generated_at: dt.datetime
    identities: list[SensorTrustIdentity] = Field(default_factory=list)
