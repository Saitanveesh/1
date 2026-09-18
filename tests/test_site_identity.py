import datetime as dt
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mon.site_identity import (
    CertificateAuthority,
    EnrollmentDenied,
    create_mtls_client_ssl_context,
    enroll_site,
    generate_site_key_and_csr,
    issue_enrollment_token,
    site_spiffe_uri,
)
from mon.site_identity_models import SiteEnrollmentRequest
from mon.store import InMemoryStore


def make_ca() -> tuple[CertificateAuthority, str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "MON Test Site CA")]
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
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return (
        CertificateAuthority.from_pem(certificate_pem, private_key_pem),
        certificate_pem,
        private_key_pem,
    )


def test_site_enrollment_keeps_private_key_local_and_token_is_one_time() -> None:
    store = InMemoryStore()
    ca, _, _ = make_ca()
    issued = issue_enrollment_token(
        store,
        "tenant-a",
        "site-1",
        300,
        "admin-1",
    )
    key_material = generate_site_key_and_csr("tenant-a", "site-1")

    result = enroll_site(
        store,
        ca,
        SiteEnrollmentRequest(
            enrollment_token=issued.enrollment_token,
            csr_pem=key_material.csr_pem,
        ),
    )

    certificate = x509.load_pem_x509_certificate(result.certificate_pem.encode())
    csr = x509.load_pem_x509_csr(key_material.csr_pem.encode())
    assert certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == csr.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert "PRIVATE KEY" in key_material.private_key_pem
    assert "PRIVATE KEY" not in result.certificate_pem
    assert result.spiffe_uri == site_spiffe_uri("tenant-a", "site-1")
    san = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert result.spiffe_uri in san.get_values_for_type(
        x509.UniformResourceIdentifier
    )
    eku = certificate.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert len(store.list_site_identities("tenant-a", "site-1")) == 1

    with pytest.raises(EnrollmentDenied):
        enroll_site(
            store,
            ca,
            SiteEnrollmentRequest(
                enrollment_token=issued.enrollment_token,
                csr_pem=key_material.csr_pem,
            ),
        )


def test_expired_enrollment_token_is_rejected() -> None:
    store = InMemoryStore()
    ca, _, _ = make_ca()
    issued = issue_enrollment_token(
        store,
        "tenant-a",
        "site-1",
        60,
        "admin-1",
    )
    token_hash = next(iter(store.enrollment_tokens))
    record = store.enrollment_tokens[token_hash]
    store.enrollment_tokens[token_hash] = record.model_copy(
        update={"expires_at": dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)}
    )

    key_material = generate_site_key_and_csr("tenant-a", "site-1")
    with pytest.raises(EnrollmentDenied):
        enroll_site(
            store,
            ca,
            SiteEnrollmentRequest(
                enrollment_token=issued.enrollment_token,
                csr_pem=key_material.csr_pem,
            ),
        )


def test_mtls_client_context_loads_site_certificate(tmp_path) -> None:
    store = InMemoryStore()
    ca, ca_pem, _ = make_ca()
    issued = issue_enrollment_token(store, "tenant-a", "site-1", 300, "admin")
    key_material = generate_site_key_and_csr("tenant-a", "site-1")
    result = enroll_site(
        store,
        ca,
        SiteEnrollmentRequest(
            enrollment_token=issued.enrollment_token,
            csr_pem=key_material.csr_pem,
        ),
    )

    ca_path = tmp_path / "ca.pem"
    cert_path = tmp_path / "client.pem"
    key_path = tmp_path / "client-key.pem"
    ca_path.write_text(ca_pem, encoding="utf-8")
    cert_path.write_text(result.certificate_pem, encoding="utf-8")
    key_path.write_text(key_material.private_key_pem, encoding="utf-8")

    context = create_mtls_client_ssl_context(
        str(ca_path),
        str(cert_path),
        str(key_path),
    )
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
