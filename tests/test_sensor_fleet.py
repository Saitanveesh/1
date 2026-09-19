import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mon.sensor_fleet import (
    SensorFleetError,
    build_sensor_fleet,
    build_sensor_trust_snapshot,
    enroll_sensor,
    issue_sensor_enrollment_token,
    record_sensor_heartbeat,
    renew_sensor,
    revoke_sensor,
)
from mon.sensor_fleet_models import (
    SensorEnrollmentRequest,
    SensorFleetState,
    SensorHeartbeat,
    SensorIdentityStatus,
    SensorRenewalRequest,
)
from mon.sensor_identity import (
    SensorEnrollmentDenied,
    generate_sensor_key_and_csr,
)
from mon.site_identity import CertificateAuthority
from mon.store import InMemoryStore


def make_ca() -> CertificateAuthority:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "MON Sensor Fleet Test CA")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return CertificateAuthority.from_pem(
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def enroll(
    store: InMemoryStore,
    ca: CertificateAuthority,
    *,
    now: dt.datetime,
    sensor_id: str = "zeek-edge-1",
):
    token = issue_sensor_enrollment_token(
        store,
        "tenant-a",
        "site-a",
        sensor_id,
        300,
        "admin",
        now=now,
    )
    private_key_pem, csr_pem, _ = generate_sensor_key_and_csr(
        "tenant-a",
        "site-a",
        sensor_id,
    )
    result = enroll_sensor(
        store,
        ca,
        SensorEnrollmentRequest(
            enrollment_token=token.enrollment_token,
            csr_pem=csr_pem,
        ),
        now=now,
    )
    return token, private_key_pem, result


def test_sensor_enrollment_is_one_time_and_durable_in_fleet_state() -> None:
    store = InMemoryStore()
    ca = make_ca()
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    token, private_key_pem, result = enroll(store, ca, now=now)

    assert "PRIVATE KEY" in private_key_pem
    assert "PRIVATE KEY" not in result.certificate_pem
    sensor = store.get_sensor_record("tenant-a", "site-a", "zeek-edge-1")
    assert sensor is not None
    assert sensor.current_identity_id == result.identity_id
    identity = store.get_sensor_identity(
        "tenant-a",
        "site-a",
        result.identity_id,
    )
    assert identity is not None
    assert identity.status is SensorIdentityStatus.ACTIVE

    token_hash = next(iter(store.sensor_enrollment_tokens))
    consumed = store.get_sensor_enrollment_token(token_hash)
    assert consumed is not None
    assert consumed.used_at == now
    assert consumed.used_identity_id == result.identity_id

    _, replay_csr, _ = generate_sensor_key_and_csr(
        "tenant-a",
        "site-a",
        "zeek-edge-1",
    )
    with pytest.raises(SensorEnrollmentDenied):
        enroll_sensor(
            store,
            ca,
            SensorEnrollmentRequest(
                enrollment_token=token.enrollment_token,
                csr_pem=replay_csr,
            ),
            now=now + dt.timedelta(seconds=1),
        )


def test_existing_sensor_id_cannot_receive_second_enrollment_token() -> None:
    store = InMemoryStore()
    ca = make_ca()
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    enroll(store, ca, now=now)

    with pytest.raises(SensorFleetError, match="already exists"):
        issue_sensor_enrollment_token(
            store,
            "tenant-a",
            "site-a",
            "zeek-edge-1",
            300,
            "admin",
            now=now + dt.timedelta(minutes=1),
        )


def test_sensor_renewal_rotates_key_with_bounded_overlap_and_is_replay_safe() -> None:
    store = InMemoryStore()
    ca = make_ca()
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    _, _, enrolled = enroll(store, ca, now=now)

    new_private_key, csr_pem, _ = generate_sensor_key_and_csr(
        "tenant-a",
        "site-a",
        "zeek-edge-1",
    )
    renewal = SensorRenewalRequest(
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="zeek-edge-1",
        current_fingerprint_sha256=enrolled.fingerprint_sha256,
        csr_pem=csr_pem,
    )
    renewed_at = now + dt.timedelta(days=20)
    renewed = renew_sensor(
        store,
        ca,
        renewal,
        now=renewed_at,
        overlap_seconds=3600,
    )

    assert renewed.identity_id != enrolled.identity_id
    new_certificate = x509.load_pem_x509_certificate(
        renewed.certificate_pem.encode()
    )
    new_key = serialization.load_pem_private_key(
        new_private_key.encode(),
        password=None,
    )
    assert new_certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == new_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    old = store.get_sensor_identity(
        "tenant-a",
        "site-a",
        enrolled.identity_id,
    )
    assert old is not None
    assert old.status is SensorIdentityStatus.RETIRING
    assert old.superseded_by_identity_id == renewed.identity_id
    assert old.accept_until == renewed_at + dt.timedelta(hours=1)

    replay = renew_sensor(
        store,
        ca,
        renewal,
        now=renewed_at + dt.timedelta(seconds=5),
        overlap_seconds=3600,
    )
    assert replay.identity_id == renewed.identity_id
    assert replay.certificate_pem == renewed.certificate_pem

    _, different_csr, _ = generate_sensor_key_and_csr(
        "tenant-a",
        "site-a",
        "zeek-edge-1",
    )
    with pytest.raises(SensorFleetError, match="different public key"):
        renew_sensor(
            store,
            ca,
            renewal.model_copy(update={"csr_pem": different_csr}),
            now=renewed_at + dt.timedelta(seconds=10),
        )


def test_revocation_removes_sensor_from_trust_snapshot_and_blocks_heartbeat() -> None:
    store = InMemoryStore()
    ca = make_ca()
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    _, _, enrolled = enroll(store, ca, now=now)

    before = build_sensor_trust_snapshot(
        store,
        "tenant-a",
        "site-a",
        now=now + dt.timedelta(seconds=1),
    )
    assert [item.fingerprint_sha256 for item in before.identities] == [
        enrolled.fingerprint_sha256
    ]

    revoke_sensor(
        store,
        "tenant-a",
        "site-a",
        "zeek-edge-1",
        actor_id="admin",
        reason="sensor decommissioned",
        now=now + dt.timedelta(minutes=1),
    )
    after = build_sensor_trust_snapshot(
        store,
        "tenant-a",
        "site-a",
        now=now + dt.timedelta(minutes=2),
    )
    assert after.identities == []

    with pytest.raises(SensorFleetError, match="revoked sensor"):
        record_sensor_heartbeat(
            store,
            SensorHeartbeat(
                tenant_id="tenant-a",
                site_id="site-a",
                sensor_id="zeek-edge-1",
                fingerprint_sha256=enrolled.fingerprint_sha256,
                observed_at=now + dt.timedelta(minutes=2),
                state=SensorFleetState.READY,
                collector_kind="ZEEK",
            ),
            received_at=now + dt.timedelta(minutes=2),
        )


def test_heartbeat_uses_server_receipt_time_and_does_not_regress_health() -> None:
    store = InMemoryStore()
    ca = make_ca()
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    _, _, enrolled = enroll(store, ca, now=now)

    record_sensor_heartbeat(
        store,
        SensorHeartbeat(
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="zeek-edge-1",
            fingerprint_sha256=enrolled.fingerprint_sha256,
            observed_at=now + dt.timedelta(seconds=20),
            state=SensorFleetState.DEGRADED,
            collector_kind="ZEEK",
            last_error="conn.log missing",
        ),
        received_at=now + dt.timedelta(seconds=25),
    )
    record_sensor_heartbeat(
        store,
        SensorHeartbeat(
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="zeek-edge-1",
            fingerprint_sha256=enrolled.fingerprint_sha256,
            observed_at=now + dt.timedelta(seconds=10),
            state=SensorFleetState.READY,
            collector_kind="ZEEK",
        ),
        received_at=now + dt.timedelta(seconds=30),
    )

    sensor = store.get_sensor_record("tenant-a", "site-a", "zeek-edge-1")
    assert sensor is not None
    assert sensor.last_seen_at == now + dt.timedelta(seconds=30)
    assert sensor.last_health_state is SensorFleetState.DEGRADED
    assert sensor.last_error == "conn.log missing"


def test_fleet_state_is_stale_from_server_last_seen_threshold() -> None:
    store = InMemoryStore()
    ca = make_ca()
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    _, _, enrolled = enroll(store, ca, now=now)

    initial = build_sensor_fleet(
        store,
        "tenant-a",
        "site-a",
        now=now,
        stale_after_seconds=90,
    )
    assert initial[0].state is SensorFleetState.STALE
    assert initial[0].heartbeat_age_seconds is None

    record_sensor_heartbeat(
        store,
        SensorHeartbeat(
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="zeek-edge-1",
            fingerprint_sha256=enrolled.fingerprint_sha256,
            observed_at=now + dt.timedelta(seconds=5),
            state=SensorFleetState.READY,
            collector_kind="ZEEK",
        ),
        received_at=now + dt.timedelta(seconds=5),
    )
    ready = build_sensor_fleet(
        store,
        "tenant-a",
        "site-a",
        now=now + dt.timedelta(seconds=80),
        stale_after_seconds=90,
    )
    assert ready[0].state is SensorFleetState.READY
    assert ready[0].heartbeat_age_seconds == 75

    stale = build_sensor_fleet(
        store,
        "tenant-a",
        "site-a",
        now=now + dt.timedelta(seconds=100),
        stale_after_seconds=90,
    )
    assert stale[0].state is SensorFleetState.STALE
    assert stale[0].heartbeat_age_seconds == 95


def test_heartbeat_rejects_unregistered_certificate_and_future_clock() -> None:
    store = InMemoryStore()
    ca = make_ca()
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    enroll(store, ca, now=now)

    with pytest.raises(SensorFleetError, match="not accepted"):
        record_sensor_heartbeat(
            store,
            SensorHeartbeat(
                tenant_id="tenant-a",
                site_id="site-a",
                sensor_id="zeek-edge-1",
                fingerprint_sha256="0" * 64,
                observed_at=now,
                state=SensorFleetState.READY,
                collector_kind="ZEEK",
            ),
            received_at=now,
        )

    identity = store.list_sensor_identities(
        "tenant-a",
        "site-a",
        "zeek-edge-1",
    )[0]
    with pytest.raises(SensorFleetError, match="too far in the future"):
        record_sensor_heartbeat(
            store,
            SensorHeartbeat(
                tenant_id="tenant-a",
                site_id="site-a",
                sensor_id="zeek-edge-1",
                fingerprint_sha256=identity.fingerprint_sha256,
                observed_at=now + dt.timedelta(minutes=6),
                state=SensorFleetState.READY,
                collector_kind="ZEEK",
            ),
            received_at=now,
        )
