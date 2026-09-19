from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mon.domain import EvidenceClass, EvidenceRef, SecurityEvent

_SENSITIVE_KEYS = {
    "password",
    "secret",
    "token",
    "ticket",
    "credential",
    "private_key",
    "ntlm",
    "kerberos_ticket",
}


class EndpointEventKind(StrEnum):
    PROCESS_START = "PROCESS_START"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"


class EndpointTelemetryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=256)
    observed_at: dt.datetime
    kind: EndpointEventKind
    asset_id: str | None = Field(default=None, max_length=256)
    hostname: str | None = Field(default=None, max_length=255)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    protocol: str | None = Field(default=None, max_length=64)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    user_name: str | None = Field(default=None, max_length=256)
    user_domain: str | None = Field(default=None, max_length=256)
    user_sid: str | None = Field(default=None, max_length=256)
    user_uid: str | None = Field(default=None, max_length=128)
    identity_namespace: str | None = Field(default=None, max_length=256)
    process_guid: str | None = Field(default=None, max_length=256)
    process_pid: int | None = Field(default=None, ge=0, le=4_294_967_295)
    parent_process_guid: str | None = Field(default=None, max_length=256)
    parent_process_pid: int | None = Field(default=None, ge=0, le=4_294_967_295)
    session_id: str | None = Field(default=None, max_length=256)
    image: str | None = Field(default=None, max_length=1000)
    command_line: str | None = Field(default=None, max_length=1000)
    process_hashes: dict[str, str] = Field(default_factory=dict)
    outcome: str | None = Field(default=None, max_length=64)
    source: str = Field(default="endpoint", min_length=1, max_length=128)
    raw_reference: str | None = Field(default=None, max_length=1000)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_event(self) -> EndpointTelemetryEvent:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("endpoint observed_at must be timezone-aware")
        for key in self.process_hashes:
            normalized = key.casefold()
            if normalized not in {"md5", "sha1", "sha256", "sha512"}:
                raise ValueError("unsupported endpoint process hash algorithm")
        _reject_sensitive(self.attributes)
        return self


def _reject_sensitive(value: object, path: str = "attributes") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).casefold()).strip("_")
            if normalized in _SENSITIVE_KEYS:
                raise ValueError(
                    f"sensitive endpoint telemetry field {path}.{key} is forbidden"
                )
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _text(value: str | None, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(character for character in value.strip() if character.isprintable())
    return cleaned[:limit] if cleaned else None


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def identity_key(event: SecurityEvent) -> tuple[str | None, str, str | None, str | None]:
    source = _text(event.attributes.get("identity_source"), 128)
    principal = _text(event.attributes.get("identity_principal"), 512)
    domain = _text(event.attributes.get("identity_domain"), 256)
    asset_id = _text(event.asset_id, 256)
    if not source or not principal:
        return None, "", None, None
    return source, principal, domain, asset_id


def identity_id_for(
    tenant_id: str,
    site_id: str,
    source: str,
    principal: str,
    domain: str | None,
    asset_id: str | None,
    *,
    weak: bool,
) -> str:
    scope = asset_id if weak else domain
    digest = hashlib.sha256(
        f"{tenant_id}\x1f{site_id}\x1f{source}\x1f{scope or ''}\x1f{principal}".encode()
    ).hexdigest()
    return f"identity:{digest[:48]}"


def process_id_for(event: SecurityEvent) -> str | None:
    asset_id = event.asset_id
    if not asset_id:
        return None
    guid = _text(event.attributes.get("process_guid"), 256)
    if guid:
        digest = hashlib.sha256(
            f"{event.tenant_id}\x1f{event.site_id}\x1f{asset_id}\x1f{guid}".encode()
        ).hexdigest()
        return f"process:{digest[:48]}"
    pid = event.attributes.get("process_pid")
    if not isinstance(pid, int):
        return None
    session = _text(event.attributes.get("session_id"), 256) or "no-session"
    bucket = event.observed_at.astimezone(dt.UTC).isoformat()
    material = (
        f"{event.tenant_id}\x1f{event.site_id}\x1f{asset_id}\x1f"
        f"{session}\x1f{pid}\x1f{bucket}"
    )
    digest = hashlib.sha256(
        material.encode()
    ).hexdigest()
    return f"process:{digest[:48]}"


def normalize_endpoint_event(item: EndpointTelemetryEvent) -> SecurityEvent:
    category = {
        EndpointEventKind.PROCESS_START: "endpoint.process.start",
        EndpointEventKind.AUTH_SUCCESS: "endpoint.auth.success",
        EndpointEventKind.AUTH_FAILURE: "endpoint.auth.failure",
        EndpointEventKind.NETWORK_CONNECTION: "endpoint.network.connection",
    }[item.kind]
    evidence_class = (
        EvidenceClass.IDENTITY
        if item.kind in {EndpointEventKind.AUTH_SUCCESS, EndpointEventKind.AUTH_FAILURE}
        else EvidenceClass.ENDPOINT
    )
    attrs: dict[str, Any] = {
        **item.attributes,
        "endpoint_event_kind": item.kind.value,
        "endpoint_hostname": _text(item.hostname, 255),
        "identity_domain": _text(item.user_domain or item.identity_namespace, 256),
        "session_id": _text(item.session_id, 256),
        "process_guid": _text(item.process_guid, 256),
        "process_pid": item.process_pid,
        "parent_process_guid": _text(item.parent_process_guid, 256),
        "parent_process_pid": item.parent_process_pid,
        "image": _text(item.image, 1000),
        "command_line": _text(item.command_line, 1000),
        "process_hashes": {
            key.casefold(): _text(value, 256)
            for key, value in item.process_hashes.items()
            if _text(value, 256)
        },
        "dst_port": item.dst_port,
        "auth_outcome": _text(item.outcome, 64),
    }
    if item.user_sid:
        attrs.update(
            {
                "identity_source": "windows_sid",
                "identity_principal": _text(item.user_sid, 256),
                "identity_display_name": _text(item.user_name, 256),
                "identity_confidence": "STRONG",
                "identity_evidence_basis": "source provided Windows SID",
            }
        )
    elif item.user_uid:
        namespace = _text(item.identity_namespace or item.user_domain or item.hostname, 256)
        attrs.update(
            {
                "identity_source": "linux_uid",
                "identity_principal": _text(item.user_uid, 128),
                "identity_domain": namespace,
                "identity_display_name": _text(item.user_name, 256),
                "identity_confidence": "STRONG",
                "identity_evidence_basis": "source provided Linux UID with namespace",
            }
        )
    elif item.user_name:
        attrs.update(
            {
                "identity_source": "username",
                "identity_principal": _text(item.user_name, 256),
                "identity_display_name": _text(item.user_name, 256),
                "identity_confidence": "WEAK",
                "identity_evidence_basis": "username-only endpoint observation",
            }
        )
    attrs = {key: value for key, value in attrs.items() if value is not None}
    return SecurityEvent(
        event_id=item.event_id,
        tenant_id=item.tenant_id,
        site_id=item.site_id,
        sensor_id=item.sensor_id,
        observed_at=item.observed_at.astimezone(dt.UTC),
        category=category,
        asset_id=item.asset_id,
        src_ip=_ip(item.src_ip),
        dst_ip=_ip(item.dst_ip),
        protocol=_text(item.protocol, 64),
        attributes=attrs,
        evidence=[
            EvidenceRef(
                evidence_class=evidence_class,
                source=f"endpoint:{item.source}",
                summary=f"Endpoint reported {item.kind.value.lower().replace('_', ' ')}",
                confidence=0.85 if evidence_class is EvidenceClass.ENDPOINT else 0.75,
                observed_at=item.observed_at,
                raw_reference=item.raw_reference or item.event_id,
            )
        ],
    )
