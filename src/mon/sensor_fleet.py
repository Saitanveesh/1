from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from mon.sensor_fleet_models import (
    SensorEnrollmentRequest,
    SensorEnrollmentResult,
    SensorEnrollmentTokenIssue,
    SensorEnrollmentTokenRecord,
    SensorFleetState,
    SensorFleetView,
    SensorHeartbeat,
    SensorIdentityRecord,
    SensorIdentityStatus,
    SensorRecord,
    SensorRenewalRequest,
    SensorTrustIdentity,
    SensorTrustSnapshot,
)
from mon.sensor_identity import (
    SensorEnrollmentDenied,
    issue_sensor_client_certificate,
    sensor_spiffe_uri,
)
from mon.site_identity import CertificateAuthority
from mon.store import Store

DEFAULT_SENSOR_CERTIFICATE_DAYS: Final[int] = 30
DEFAULT_RENEWAL_OVERLAP_SECONDS: Final[int] = 3600
DEFAULT_SENSOR_STALE_AFTER_SECONDS: Final[int] = 90
MAX_HEARTBEAT_FUTURE_SKEW_SECONDS: Final[int] = 300


class SensorFleetError(ValueError):
    pass


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _public_key_bytes(public_key: object) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _result_from_identity(
    identity: SensorIdentityRecord,
    certificate_authority: CertificateAuthority,
) -> SensorEnrollmentResult:
    return SensorEnrollmentResult(
        identity_id=identity.identity_id,
        tenant_id=identity.tenant_id,
        site_id=identity.site_id,
        sensor_id=identity.sensor_id,
        certificate_pem=identity.certificate_pem,
        ca_certificate_pem=certificate_authority.certificate_pem,
        fingerprint_sha256=identity.fingerprint_sha256,
        spiffe_uri=identity.spiffe_uri,
        expires_at=identity.expires_at,
    )


def issue_sensor_enrollment_token(
    store: Store,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    ttl_seconds: int,
    created_by: str,
    *,
    now: dt.datetime | None = None,
) -> SensorEnrollmentTokenIssue:
    if ttl_seconds < 60 or ttl_seconds > 86400:
        raise SensorFleetError(
            "sensor enrollment token TTL must be between 60 and 86400 seconds"
        )
    if store.get_sensor_record(tenant_id, site_id, sensor_id) is not None:
        raise SensorFleetError(
            "sensor_id already exists; use certificate renewal for an enrolled sensor"
        )

    issued_at = (now or _utcnow()).astimezone(dt.UTC)
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = issued_at + dt.timedelta(seconds=ttl_seconds)
    record = SensorEnrollmentTokenRecord(
        token_hash=token_hash,
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=sensor_id,
        created_by=created_by,
        created_at=issued_at,
        expires_at=expires_at,
    )
    store.add_sensor_enrollment_token(record)
    return SensorEnrollmentTokenIssue(
        enrollment_token=raw_token,
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=sensor_id,
        expires_at=expires_at,
    )


def enroll_sensor(
    store: Store,
    certificate_authority: CertificateAuthority,
    request: SensorEnrollmentRequest,
    *,
    now: dt.datetime | None = None,
    validity_days: int = DEFAULT_SENSOR_CERTIFICATE_DAYS,
) -> SensorEnrollmentResult:
    issued_at = (now or _utcnow()).astimezone(dt.UTC)
    token_hash = hashlib.sha256(request.enrollment_token.encode()).hexdigest()
    token = store.get_sensor_enrollment_token(token_hash)
    if token is None or token.used_at is not None or token.expires_at <= issued_at:
        raise SensorEnrollmentDenied(
            "sensor enrollment token is invalid, expired, or already used"
        )
    if store.get_sensor_record(token.tenant_id, token.site_id, token.sensor_id) is not None:
        raise SensorEnrollmentDenied("sensor_id is already enrolled")

    certificate = issue_sensor_client_certificate(
        certificate_authority,
        request.csr_pem,
        token.tenant_id,
        token.site_id,
        token.sensor_id,
        validity_days=validity_days,
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    identity = SensorIdentityRecord(
        tenant_id=token.tenant_id,
        site_id=token.site_id,
        sensor_id=token.sensor_id,
        certificate_serial=str(certificate.serial_number),
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        spiffe_uri=sensor_spiffe_uri(
            token.tenant_id,
            token.site_id,
            token.sensor_id,
        ),
        certificate_pem=certificate_pem,
        issued_at=issued_at,
        expires_at=certificate.not_valid_after_utc,
    )
    sensor = SensorRecord(
        tenant_id=token.tenant_id,
        site_id=token.site_id,
        sensor_id=token.sensor_id,
        created_at=issued_at,
        updated_at=issued_at,
        current_identity_id=identity.identity_id,
    )
    if not store.complete_sensor_enrollment(
        token_hash,
        issued_at,
        sensor,
        identity,
    ):
        raise SensorEnrollmentDenied(
            "sensor enrollment token was concurrently consumed or invalidated"
        )
    return _result_from_identity(identity, certificate_authority)


def _renewal_replay(
    store: Store,
    certificate_authority: CertificateAuthority,
    current: SensorIdentityRecord,
    request: SensorRenewalRequest,
) -> SensorEnrollmentResult | None:
    if (
        current.status is not SensorIdentityStatus.RETIRING
        or not current.superseded_by_identity_id
    ):
        return None
    successor = store.get_sensor_identity(
        request.tenant_id,
        request.site_id,
        current.superseded_by_identity_id,
    )
    if successor is None:
        raise SensorFleetError("retiring sensor identity successor is missing")
    try:
        csr = x509.load_pem_x509_csr(request.csr_pem.encode())
        certificate = x509.load_pem_x509_certificate(
            successor.certificate_pem.encode()
        )
    except ValueError as exc:
        raise SensorFleetError("invalid sensor renewal CSR or stored certificate") from exc
    if not csr.is_signature_valid:
        raise SensorFleetError("sensor renewal CSR signature is invalid")
    if _public_key_bytes(csr.public_key()) != _public_key_bytes(
        certificate.public_key()
    ):
        raise SensorFleetError(
            "sensor renewal was already completed with a different public key"
        )
    return _result_from_identity(successor, certificate_authority)


def renew_sensor(
    store: Store,
    certificate_authority: CertificateAuthority,
    request: SensorRenewalRequest,
    *,
    now: dt.datetime | None = None,
    validity_days: int = DEFAULT_SENSOR_CERTIFICATE_DAYS,
    overlap_seconds: int = DEFAULT_RENEWAL_OVERLAP_SECONDS,
) -> SensorEnrollmentResult:
    if overlap_seconds < 60 or overlap_seconds > 86400:
        raise SensorFleetError(
            "sensor renewal overlap must be between 60 and 86400 seconds"
        )
    renewed_at = (now or _utcnow()).astimezone(dt.UTC)
    sensor = store.get_sensor_record(
        request.tenant_id,
        request.site_id,
        request.sensor_id,
    )
    if sensor is None:
        raise SensorFleetError("sensor is not enrolled")
    if sensor.revoked_at is not None:
        raise SensorFleetError("revoked sensor cannot renew its certificate")

    current = store.get_sensor_identity_by_fingerprint(
        request.tenant_id,
        request.site_id,
        request.current_fingerprint_sha256,
    )
    if current is None or current.sensor_id != request.sensor_id:
        raise SensorFleetError("current sensor certificate is not registered")
    if current.expires_at <= renewed_at:
        raise SensorFleetError("expired sensor certificate cannot be renewed")

    replay = _renewal_replay(
        store,
        certificate_authority,
        current,
        request,
    )
    if replay is not None:
        return replay
    if current.status is not SensorIdentityStatus.ACTIVE:
        raise SensorFleetError("current sensor certificate is not active")

    certificate = issue_sensor_client_certificate(
        certificate_authority,
        request.csr_pem,
        request.tenant_id,
        request.site_id,
        request.sensor_id,
        validity_days=validity_days,
    )
    successor = SensorIdentityRecord(
        tenant_id=request.tenant_id,
        site_id=request.site_id,
        sensor_id=request.sensor_id,
        certificate_serial=str(certificate.serial_number),
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        spiffe_uri=sensor_spiffe_uri(
            request.tenant_id,
            request.site_id,
            request.sensor_id,
        ),
        certificate_pem=certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode(),
        issued_at=renewed_at,
        expires_at=certificate.not_valid_after_utc,
    )
    accept_until = min(
        current.expires_at,
        renewed_at + dt.timedelta(seconds=overlap_seconds),
    )
    retiring = current.model_copy(
        update={
            "status": SensorIdentityStatus.RETIRING,
            "accept_until": accept_until,
            "superseded_by_identity_id": successor.identity_id,
        }
    )
    updated_sensor = sensor.model_copy(
        update={
            "updated_at": renewed_at,
            "current_identity_id": successor.identity_id,
        }
    )
    if not store.complete_sensor_renewal(
        current.identity_id,
        updated_sensor,
        retiring,
        successor,
    ):
        latest = store.get_sensor_identity_by_fingerprint(
            request.tenant_id,
            request.site_id,
            request.current_fingerprint_sha256,
        )
        if latest is not None:
            replay = _renewal_replay(
                store,
                certificate_authority,
                latest,
                request,
            )
            if replay is not None:
                return replay
        raise SensorFleetError("sensor renewal raced with another lifecycle change")
    return _result_from_identity(successor, certificate_authority)


def revoke_sensor(
    store: Store,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    *,
    actor_id: str,
    reason: str,
    now: dt.datetime | None = None,
) -> SensorRecord:
    text = reason.strip()
    if not text:
        raise SensorFleetError("sensor revocation reason is required")
    revoked_at = (now or _utcnow()).astimezone(dt.UTC)
    updated = store.revoke_sensor_lifecycle(
        tenant_id,
        site_id,
        sensor_id,
        actor_id=actor_id,
        reason=text,
        now=revoked_at,
    )
    if updated is None:
        raise SensorFleetError("sensor is not enrolled")
    return updated


def _identity_is_accepted(
    identity: SensorIdentityRecord,
    *,
    now: dt.datetime,
) -> bool:
    if identity.expires_at <= now:
        return False
    if identity.status is SensorIdentityStatus.ACTIVE:
        return True
    return (
        identity.status is SensorIdentityStatus.RETIRING
        and identity.accept_until is not None
        and identity.accept_until > now
    )


def record_sensor_heartbeat(
    store: Store,
    heartbeat: SensorHeartbeat,
    *,
    received_at: dt.datetime | None = None,
) -> SensorRecord:
    server_time = (received_at or _utcnow()).astimezone(dt.UTC)
    if heartbeat.observed_at > server_time + dt.timedelta(
        seconds=MAX_HEARTBEAT_FUTURE_SKEW_SECONDS
    ):
        raise SensorFleetError("sensor heartbeat is too far in the future")

    sensor = store.get_sensor_record(
        heartbeat.tenant_id,
        heartbeat.site_id,
        heartbeat.sensor_id,
    )
    if sensor is None:
        raise SensorFleetError("sensor is not enrolled")
    if sensor.revoked_at is not None:
        raise SensorFleetError("revoked sensor heartbeat is rejected")

    identity = store.get_sensor_identity_by_fingerprint(
        heartbeat.tenant_id,
        heartbeat.site_id,
        heartbeat.fingerprint_sha256,
    )
    if (
        identity is None
        or identity.sensor_id != heartbeat.sensor_id
        or not _identity_is_accepted(identity, now=server_time)
    ):
        raise SensorFleetError("sensor heartbeat certificate is not accepted")

    updates: dict[str, object] = {
        "updated_at": server_time,
        "last_seen_at": server_time,
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
    store.save_sensor_lifecycle(updated, [])
    return updated


def build_sensor_fleet(
    store: Store,
    tenant_id: str,
    site_id: str,
    *,
    now: dt.datetime | None = None,
    stale_after_seconds: int = DEFAULT_SENSOR_STALE_AFTER_SECONDS,
) -> list[SensorFleetView]:
    if stale_after_seconds < 1 or stale_after_seconds > 86400:
        raise SensorFleetError(
            "sensor stale threshold must be between 1 and 86400 seconds"
        )
    check_at = (now or _utcnow()).astimezone(dt.UTC)
    result: list[SensorFleetView] = []
    for sensor in store.list_sensor_records(tenant_id, site_id):
        identity = (
            store.get_sensor_identity(
                tenant_id,
                site_id,
                sensor.current_identity_id,
            )
            if sensor.current_identity_id
            else None
        )
        age_seconds = (
            max(0, int((check_at - sensor.last_seen_at).total_seconds()))
            if sensor.last_seen_at is not None
            else None
        )
        if sensor.revoked_at is not None:
            state = SensorFleetState.REVOKED
        elif age_seconds is None or age_seconds > stale_after_seconds:
            state = SensorFleetState.STALE
        elif sensor.last_health_state is SensorFleetState.DEGRADED:
            state = SensorFleetState.DEGRADED
        else:
            state = SensorFleetState.READY

        result.append(
            SensorFleetView(
                tenant_id=tenant_id,
                site_id=site_id,
                sensor_id=sensor.sensor_id,
                state=state,
                current_identity_id=sensor.current_identity_id,
                certificate_expires_at=(
                    identity.expires_at if identity is not None else None
                ),
                last_seen_at=sensor.last_seen_at,
                heartbeat_age_seconds=age_seconds,
                stale_after_seconds=stale_after_seconds,
                collector_kind=sensor.collector_kind,
                version=sensor.version,
                last_error=sensor.last_error,
            )
        )
    return result


def build_sensor_trust_snapshot(
    store: Store,
    tenant_id: str,
    site_id: str,
    *,
    now: dt.datetime | None = None,
) -> SensorTrustSnapshot:
    generated_at = (now or _utcnow()).astimezone(dt.UTC)
    revoked_sensors = {
        sensor.sensor_id
        for sensor in store.list_sensor_records(tenant_id, site_id)
        if sensor.revoked_at is not None
    }
    identities: list[SensorTrustIdentity] = []
    for identity in store.list_sensor_identities(tenant_id, site_id):
        if identity.sensor_id in revoked_sensors:
            continue
        if not _identity_is_accepted(identity, now=generated_at):
            continue
        identities.append(
            SensorTrustIdentity(
                sensor_id=identity.sensor_id,
                identity_id=identity.identity_id,
                fingerprint_sha256=identity.fingerprint_sha256,
                status=identity.status,
                expires_at=identity.expires_at,
                accept_until=identity.accept_until,
            )
        )
    identities.sort(key=lambda item: (item.sensor_id, item.identity_id))
    return SensorTrustSnapshot(
        tenant_id=tenant_id,
        site_id=site_id,
        generated_at=generated_at,
        identities=identities,
    )
