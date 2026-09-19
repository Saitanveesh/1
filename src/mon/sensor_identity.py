from __future__ import annotations

import datetime as dt
import hashlib
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mon.site_identity import CertificateAuthority, IdentityConfigurationError


class SensorEnrollmentDenied(ValueError):
    pass


def _validate_identity_component(name: str, value: str) -> str:
    if not value or len(value) > 128:
        raise ValueError(f"{name} must contain between 1 and 128 characters")
    if any(not character.isprintable() for character in value):
        raise ValueError(f"{name} must contain only printable characters")
    return value


def sensor_spiffe_uri(tenant_id: str, site_id: str, sensor_id: str) -> str:
    tenant = quote(_validate_identity_component("tenant_id", tenant_id), safe="")
    site = quote(_validate_identity_component("site_id", site_id), safe="")
    sensor = quote(_validate_identity_component("sensor_id", sensor_id), safe="")
    return (
        f"spiffe://mon.local/tenant/{tenant}/site/{site}/sensor/{sensor}"
    )


def generate_sensor_key_and_csr(
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    *,
    password: str | None = None,
) -> tuple[str, str, str]:
    _validate_identity_component("tenant_id", tenant_id)
    _validate_identity_component("site_id", site_id)
    _validate_identity_component("sensor_id", sensor_id)

    private_key = ec.generate_private_key(ec.SECP256R1())
    encryption: serialization.KeySerializationEncryption
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()

    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    ).decode()

    spiffe_uri = sensor_spiffe_uri(tenant_id, site_id, sensor_id)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME,
                        "MON Network Sensor",
                    ),
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        sensor_id[:64],
                    ),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(spiffe_uri)]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return (
        private_key_pem,
        csr.public_bytes(serialization.Encoding.PEM).decode(),
        spiffe_uri,
    )


def issue_sensor_client_certificate(
    certificate_authority: CertificateAuthority,
    csr_pem: str,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    *,
    validity_days: int = 30,
) -> x509.Certificate:
    try:
        _validate_identity_component("tenant_id", tenant_id)
        _validate_identity_component("site_id", site_id)
        _validate_identity_component("sensor_id", sensor_id)
    except ValueError as exc:
        raise SensorEnrollmentDenied(str(exc)) from exc
    if validity_days < 1 or validity_days > 90:
        raise SensorEnrollmentDenied(
            "sensor certificate validity must be between 1 and 90 days"
        )

    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except ValueError as exc:
        raise SensorEnrollmentDenied(
            "invalid sensor certificate signing request"
        ) from exc
    if not csr.is_signature_valid:
        raise SensorEnrollmentDenied(
            "sensor certificate signing request signature is invalid"
        )

    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            raise SensorEnrollmentDenied(
                "RSA sensor keys must be at least 2048 bits"
            )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, (ec.SECP256R1, ec.SECP384R1)):
            raise SensorEnrollmentDenied(
                "sensor EC key must use P-256 or P-384"
            )
    else:
        raise SensorEnrollmentDenied("unsupported sensor public-key type")

    now = dt.datetime.now(dt.UTC)
    expires_at = min(
        now + dt.timedelta(days=validity_days),
        certificate_authority.certificate.not_valid_after_utc,
    )
    if expires_at <= now + dt.timedelta(minutes=5):
        raise IdentityConfigurationError(
            "sensor CA expires too soon to issue a certificate"
        )

    identity_digest = hashlib.sha256(
        f"{tenant_id}\x1f{site_id}\x1f{sensor_id}".encode()
    ).hexdigest()[:24]
    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "MON Security Fabric",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                f"mon-sensor-{identity_digest}",
            ),
        ]
    )
    spiffe_uri = sensor_spiffe_uri(tenant_id, site_id, sensor_id)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(certificate_authority.certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=2))
        .not_valid_after(expires_at)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(spiffe_uri)]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                certificate_authority.certificate.public_key()
            ),
            critical=False,
        )
    )
    return certificate.sign(
        certificate_authority.private_key,
        hashes.SHA256(),
    )
