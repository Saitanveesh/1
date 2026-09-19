import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mon.sensor_identity import (
    SensorEnrollmentDenied,
    generate_sensor_key_and_csr,
    issue_sensor_client_certificate,
    sensor_spiffe_uri,
)
from mon.sensor_transport import (
    SensorCertificateError,
    SensorCertificateScopeError,
    extract_sensor_identity_from_verified_certificate,
    require_sensor_matches_site,
)
from mon.site_identity import CertificateAuthority


def make_ca() -> CertificateAuthority:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "MON Sensor Test CA")]
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


def sensor_certificate_der(
    ca: CertificateAuthority,
    *,
    tenant_id: str = "tenant-a",
    site_id: str = "site-a",
    sensor_id: str = "zeek-edge-1",
) -> bytes:
    _, csr_pem, _ = generate_sensor_key_and_csr(
        tenant_id,
        site_id,
        sensor_id,
    )
    certificate = issue_sensor_client_certificate(
        ca,
        csr_pem,
        tenant_id,
        site_id,
        sensor_id,
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def test_sensor_certificate_has_scoped_spiffe_identity_and_client_auth() -> None:
    ca = make_ca()
    private_key_pem, csr_pem, expected_uri = generate_sensor_key_and_csr(
        "tenant-a",
        "site-a",
        "zeek-edge-1",
    )
    certificate = issue_sensor_client_certificate(
        ca,
        csr_pem,
        "tenant-a",
        "site-a",
        "zeek-edge-1",
    )

    assert "PRIVATE KEY" in private_key_pem
    assert expected_uri == sensor_spiffe_uri(
        "tenant-a",
        "site-a",
        "zeek-edge-1",
    )
    san = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert expected_uri in san.get_values_for_type(
        x509.UniformResourceIdentifier
    )
    eku = certificate.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku

    identity = extract_sensor_identity_from_verified_certificate(
        certificate.public_bytes(serialization.Encoding.DER)
    )
    assert identity.tenant_id == "tenant-a"
    assert identity.site_id == "site-a"
    assert identity.sensor_id == "zeek-edge-1"
    assert identity.spiffe_uri == expected_uri
    assert len(identity.fingerprint_sha256) == 64


def test_sensor_scope_is_enforced_at_site_boundary() -> None:
    identity = extract_sensor_identity_from_verified_certificate(
        sensor_certificate_der(make_ca())
    )

    require_sensor_matches_site(
        identity,
        tenant_id="tenant-a",
        site_id="site-a",
    )

    with pytest.raises(SensorCertificateScopeError):
        require_sensor_matches_site(
            identity,
            tenant_id="tenant-a",
            site_id="site-b",
        )


def test_sensor_certificate_rejects_site_only_spiffe_identity() -> None:
    ca = make_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong-id")])
        )
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        "spiffe://mon.local/tenant/tenant-a/site/site-a"
                    )
                ]
            ),
            critical=False,
        )
        .sign(ca.private_key, hashes.SHA256())
    )

    with pytest.raises(SensorCertificateError, match="sensor path"):
        extract_sensor_identity_from_verified_certificate(
            certificate.public_bytes(serialization.Encoding.DER)
        )


def test_sensor_certificate_validity_is_bounded() -> None:
    ca = make_ca()
    _, csr_pem, _ = generate_sensor_key_and_csr(
        "tenant-a",
        "site-a",
        "sensor-1",
    )
    with pytest.raises(SensorEnrollmentDenied, match="between 1 and 90"):
        issue_sensor_client_certificate(
            ca,
            csr_pem,
            "tenant-a",
            "site-a",
            "sensor-1",
            validity_days=365,
        )
