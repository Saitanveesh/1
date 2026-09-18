from __future__ import annotations

import datetime as dt
import hashlib
import os
import secrets
import ssl
import uuid
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mon.site_identity_models import (
    EnrollmentTokenIssue,
    EnrollmentTokenRecord,
    GeneratedSiteKeyMaterial,
    SiteEnrollmentRequest,
    SiteEnrollmentResult,
    SiteIdentityRecord,
)
from mon.store import Store


class IdentityConfigurationError(RuntimeError):
    pass


class EnrollmentDenied(ValueError):
    pass


def site_spiffe_uri(tenant_id: str, site_id: str) -> str:
    tenant = quote(tenant_id, safe="")
    site = quote(site_id, safe="")
    return f"spiffe://mon.local/tenant/{tenant}/site/{site}"


def _public_key_bytes(public_key: object) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class CertificateAuthority:
    def __init__(self, certificate: x509.Certificate, private_key: object) -> None:
        self.certificate = certificate
        self.private_key = private_key

        try:
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound as exc:
            raise IdentityConfigurationError("site CA certificate lacks BasicConstraints") from exc
        if not constraints.ca:
            raise IdentityConfigurationError("configured site certificate is not a CA")

        if _public_key_bytes(certificate.public_key()) != _public_key_bytes(
            private_key.public_key()
        ):
            raise IdentityConfigurationError("site CA private key does not match certificate")

        now = dt.datetime.now(dt.UTC)
        if certificate.not_valid_after_utc <= now:
            raise IdentityConfigurationError("site CA certificate is expired")

    @classmethod
    def from_pem(
        cls,
        certificate_pem: str,
        private_key_pem: str,
        password: bytes | None = None,
    ) -> CertificateAuthority:
        try:
            certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=password,
            )
        except (TypeError, ValueError) as exc:
            raise IdentityConfigurationError("invalid site CA certificate or key") from exc
        return cls(certificate, private_key)

    @property
    def certificate_pem(self) -> str:
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode()

    def issue_client_certificate(
        self,
        csr_pem: str,
        tenant_id: str,
        site_id: str,
        *,
        validity_days: int = 30,
    ) -> x509.Certificate:
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except ValueError as exc:
            raise EnrollmentDenied("invalid certificate signing request") from exc

        if not csr.is_signature_valid:
            raise EnrollmentDenied("certificate signing request signature is invalid")

        public_key = csr.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < 2048:
                raise EnrollmentDenied("RSA site keys must be at least 2048 bits")
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if not isinstance(public_key.curve, (ec.SECP256R1, ec.SECP384R1)):
                raise EnrollmentDenied("site EC key must use P-256 or P-384")
        else:
            raise EnrollmentDenied("unsupported site public-key type")

        now = dt.datetime.now(dt.UTC)
        expires_at = min(
            now + dt.timedelta(days=validity_days),
            self.certificate.not_valid_after_utc,
        )
        if expires_at <= now + dt.timedelta(minutes=5):
            raise IdentityConfigurationError("site CA expires too soon to issue a certificate")

        identity_digest = hashlib.sha256(
            f"{tenant_id}\x1f{site_id}".encode()
        ).hexdigest()[:24]
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MON Security Fabric"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"mon-site-{identity_digest}"),
            ]
        )
        spiffe_uri = site_spiffe_uri(tenant_id, site_id)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=2))
            .not_valid_after(expires_at)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
                    self.certificate.public_key()
                ),
                critical=False,
            )
        )
        return builder.sign(self.private_key, hashes.SHA256())


@lru_cache(maxsize=1)
def get_certificate_authority() -> CertificateAuthority:
    certificate_path = os.environ.get("MON_SITE_CA_CERT_FILE", "").strip()
    private_key_path = os.environ.get("MON_SITE_CA_KEY_FILE", "").strip()
    if not certificate_path or not private_key_path:
        raise IdentityConfigurationError(
            "MON_SITE_CA_CERT_FILE and MON_SITE_CA_KEY_FILE must be configured"
        )

    password_value = os.environ.get("MON_SITE_CA_KEY_PASSWORD")
    password = password_value.encode() if password_value else None
    return CertificateAuthority.from_pem(
        Path(certificate_path).read_text(encoding="utf-8"),
        Path(private_key_path).read_text(encoding="utf-8"),
        password=password,
    )


def clear_certificate_authority_cache() -> None:
    get_certificate_authority.cache_clear()


def issue_enrollment_token(
    store: Store,
    tenant_id: str,
    site_id: str,
    ttl_seconds: int,
    created_by: str,
) -> EnrollmentTokenIssue:
    now = dt.datetime.now(dt.UTC)
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = now + dt.timedelta(seconds=ttl_seconds)
    store.add_enrollment_token(
        EnrollmentTokenRecord(
            token_hash=token_hash,
            tenant_id=tenant_id,
            site_id=site_id,
            created_by=created_by,
            created_at=now,
            expires_at=expires_at,
        )
    )
    return EnrollmentTokenIssue(
        enrollment_token=raw_token,
        tenant_id=tenant_id,
        site_id=site_id,
        expires_at=expires_at,
    )


def enroll_site(
    store: Store,
    certificate_authority: CertificateAuthority,
    request: SiteEnrollmentRequest,
) -> SiteEnrollmentResult:
    now = dt.datetime.now(dt.UTC)
    token_hash = hashlib.sha256(request.enrollment_token.encode()).hexdigest()
    token = store.get_enrollment_token(token_hash)
    if token is None or token.used_at is not None or token.expires_at <= now:
        raise EnrollmentDenied("enrollment token is invalid, expired, or already used")

    certificate = certificate_authority.issue_client_certificate(
        request.csr_pem,
        token.tenant_id,
        token.site_id,
    )

    consumed = store.consume_enrollment_token(token_hash, now)
    if consumed is None:
        raise EnrollmentDenied("enrollment token was already consumed")

    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    identity_id = str(uuid.uuid4())
    spiffe_uri = site_spiffe_uri(token.tenant_id, token.site_id)
    identity = SiteIdentityRecord(
        identity_id=identity_id,
        tenant_id=token.tenant_id,
        site_id=token.site_id,
        certificate_serial=str(certificate.serial_number),
        fingerprint_sha256=fingerprint,
        spiffe_uri=spiffe_uri,
        certificate_pem=certificate_pem,
        issued_at=now,
        expires_at=certificate.not_valid_after_utc,
    )
    store.add_site_identity(identity)

    return SiteEnrollmentResult(
        identity_id=identity_id,
        tenant_id=token.tenant_id,
        site_id=token.site_id,
        certificate_pem=certificate_pem,
        ca_certificate_pem=certificate_authority.certificate_pem,
        fingerprint_sha256=fingerprint,
        spiffe_uri=spiffe_uri,
        expires_at=certificate.not_valid_after_utc,
    )


def generate_site_key_and_csr(
    tenant_id: str,
    site_id: str,
    *,
    password: str | None = None,
) -> GeneratedSiteKeyMaterial:
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

    spiffe_uri = site_spiffe_uri(tenant_id, site_id)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MON Site Controller"),
                    x509.NameAttribute(NameOID.COMMON_NAME, site_id[:64]),
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
    return GeneratedSiteKeyMaterial(
        private_key_pem=private_key_pem,
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode(),
        spiffe_uri=spiffe_uri,
    )


def create_mtls_client_ssl_context(
    ca_certificate_file: str,
    client_certificate_file: str,
    client_private_key_file: str,
    *,
    private_key_password: str | None = None,
) -> ssl.SSLContext:
    context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=ca_certificate_file,
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=client_certificate_file,
        keyfile=client_private_key_file,
        password=private_key_password,
    )
    return context
