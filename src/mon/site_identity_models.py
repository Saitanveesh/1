from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SiteIdentityStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class EnrollmentTokenRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token_hash: str = Field(min_length=64, max_length=64)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    created_by: str = Field(min_length=1, max_length=256)
    created_at: dt.datetime
    expires_at: dt.datetime
    used_at: dt.datetime | None = None


class EnrollmentTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    ttl_seconds: int = Field(default=900, ge=60, le=86400)


class EnrollmentTokenIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollment_token: str = Field(min_length=32)
    tenant_id: str
    site_id: str
    expires_at: dt.datetime


class SiteEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollment_token: str = Field(min_length=32, max_length=512)
    csr_pem: str = Field(min_length=64, max_length=32768)


class SiteIdentityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_id: str = Field(min_length=1, max_length=64)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    certificate_serial: str = Field(min_length=1, max_length=128)
    fingerprint_sha256: str = Field(min_length=64, max_length=64)
    spiffe_uri: str = Field(min_length=1, max_length=1024)
    certificate_pem: str = Field(min_length=64, max_length=32768)
    issued_at: dt.datetime
    expires_at: dt.datetime
    status: SiteIdentityStatus = SiteIdentityStatus.ACTIVE


class SiteEnrollmentResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_id: str
    tenant_id: str
    site_id: str
    certificate_pem: str
    ca_certificate_pem: str
    fingerprint_sha256: str
    spiffe_uri: str
    expires_at: dt.datetime


@dataclass(frozen=True)
class GeneratedSiteKeyMaterial:
    private_key_pem: str = field(repr=False)
    csr_pem: str
    spiffe_uri: str
