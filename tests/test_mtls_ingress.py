import datetime as dt
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mon.domain import EventBatch, SecurityEvent
from mon.mtls_ingress import (
    SiteCertificateError,
    SiteCertificateScopeError,
    create_mtls_server_ssl_context,
    extract_site_identity_from_verified_certificate,
    require_batch_matches_site_identity,
    require_sensor_heartbeat_matches_site_identity,
    require_sensor_renewal_matches_site_identity,
)
from mon.sensor_fleet_models import (
    SensorFleetState,
    SensorHeartbeat,
    SensorRenewalRequest,
)
from mon.site_identity import CertificateAuthority, generate_site_key_and_csr


def make_ca() -> tuple[CertificateAuthority, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MON mTLS Test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return CertificateAuthority.from_pem(certificate_pem, private_key_pem), certificate_pem


def make_server_certificate(
    ca: CertificateAuthority,
) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(ca.private_key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return certificate_pem, private_key_pem


def site_certificate_der(
    ca: CertificateAuthority,
    tenant_id: str = "tenant-a",
    site_id: str = "site-1",
) -> bytes:
    material = generate_site_key_and_csr(tenant_id, site_id)
    certificate = ca.issue_client_certificate(
        material.csr_pem,
        tenant_id,
        site_id,
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def test_verified_certificate_identity_is_taken_from_spiffe_san() -> None:
    ca, _ = make_ca()
    identity = extract_site_identity_from_verified_certificate(
        site_certificate_der(ca)
    )

    assert identity.tenant_id == "tenant-a"
    assert identity.site_id == "site-1"
    assert identity.spiffe_uri == "spiffe://mon.local/tenant/tenant-a/site/site-1"
    assert len(identity.fingerprint_sha256) == 64


def test_batch_scope_must_match_verified_certificate() -> None:
    ca, _ = make_ca()
    identity = extract_site_identity_from_verified_certificate(
        site_certificate_der(ca)
    )
    matching = EventBatch(
        events=[
            SecurityEvent(
                tenant_id="tenant-a",
                site_id="site-1",
                sensor_id="sensor",
                category="network.connection",
            )
        ]
    )
    require_batch_matches_site_identity(matching, identity)

    mismatched = EventBatch(
        events=[
            SecurityEvent(
                tenant_id="tenant-a",
                site_id="site-2",
                sensor_id="sensor",
                category="network.connection",
            )
        ]
    )
    with pytest.raises(SiteCertificateScopeError):
        require_batch_matches_site_identity(mismatched, identity)


def test_client_certificate_without_client_auth_is_rejected() -> None:
    ca, _ = make_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bad-client")]))
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        "spiffe://mon.local/tenant/tenant-a/site/site-1"
                    )
                ]
            ),
            critical=False,
        )
        .sign(ca.private_key, hashes.SHA256())
    )

    with pytest.raises(SiteCertificateError):
        extract_site_identity_from_verified_certificate(
            certificate.public_bytes(serialization.Encoding.DER)
        )


def test_server_ssl_context_requires_client_certificate(tmp_path) -> None:
    ca, ca_pem = make_ca()
    server_cert, server_key = make_server_certificate(ca)
    cert_path = tmp_path / "server.pem"
    key_path = tmp_path / "server-key.pem"
    ca_path = tmp_path / "site-ca.pem"
    cert_path.write_text(server_cert, encoding="utf-8")
    key_path.write_text(server_key, encoding="utf-8")
    ca_path.write_text(ca_pem, encoding="utf-8")

    context = create_mtls_server_ssl_context(
        str(cert_path),
        str(key_path),
        str(ca_path),
    )
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_sensor_fleet_messages_must_match_verified_site_scope() -> None:
    ca, _ = make_ca()
    identity = extract_site_identity_from_verified_certificate(
        site_certificate_der(ca)
    )
    renewal = SensorRenewalRequest(
        tenant_id="tenant-a",
        site_id="site-1",
        sensor_id="sensor-1",
        current_fingerprint_sha256="a" * 64,
        csr_pem="-----BEGIN CERTIFICATE REQUEST-----"
        + "x" * 80
        + "-----END CERTIFICATE REQUEST-----",
    )
    require_sensor_renewal_matches_site_identity(renewal, identity)

    heartbeat = SensorHeartbeat(
        tenant_id="tenant-a",
        site_id="site-1",
        sensor_id="sensor-1",
        fingerprint_sha256="a" * 64,
        observed_at=dt.datetime.now(dt.UTC),
        state=SensorFleetState.READY,
        collector_kind="ZEEK",
    )
    require_sensor_heartbeat_matches_site_identity(heartbeat, identity)

    with pytest.raises(SiteCertificateScopeError):
        require_sensor_renewal_matches_site_identity(
            renewal.model_copy(update={"site_id": "site-2"}),
            identity,
        )
    with pytest.raises(SiteCertificateScopeError):
        require_sensor_heartbeat_matches_site_identity(
            heartbeat.model_copy(update={"tenant_id": "tenant-b"}),
            identity,
        )
