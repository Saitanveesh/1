import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

import mon.api as api_module
from mon.api import app, pipeline, store
from mon.site_identity import CertificateAuthority, generate_site_key_and_csr

client = TestClient(app)


def make_ca() -> CertificateAuthority:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MON API Test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return CertificateAuthority.from_pem(certificate_pem, private_key_pem)


def setup_function() -> None:
    pipeline.reset()


def test_operator_issues_token_and_site_enrolls(monkeypatch) -> None:
    ca = make_ca()
    monkeypatch.setattr(api_module, "get_certificate_authority", lambda: ca)

    issued = client.post(
        "/api/v1/enrollment-tokens",
        json={
            "tenant_id": "tenant-a",
            "site_id": "site-1",
            "ttl_seconds": 300,
        },
    )
    assert issued.status_code == 201
    raw_token = issued.json()["enrollment_token"]
    assert raw_token
    assert all(record.token_hash != raw_token for record in store.enrollment_tokens.values())

    key_material = generate_site_key_and_csr("tenant-a", "site-1")
    enrolled = client.post(
        "/api/v1/site-enrollment",
        json={
            "enrollment_token": raw_token,
            "csr_pem": key_material.csr_pem,
        },
    )
    assert enrolled.status_code == 201
    body = enrolled.json()
    assert body["tenant_id"] == "tenant-a"
    assert body["site_id"] == "site-1"
    assert body["spiffe_uri"].endswith("/tenant/tenant-a/site/site-1")
    assert "PRIVATE KEY" not in body["certificate_pem"]

    replay = client.post(
        "/api/v1/site-enrollment",
        json={
            "enrollment_token": raw_token,
            "csr_pem": key_material.csr_pem,
        },
    )
    assert replay.status_code == 401

    identities = client.get(
        "/api/v1/site-identities",
        params={"tenant_id": "tenant-a", "site_id": "site-1"},
    )
    assert identities.status_code == 200
    assert len(identities.json()) == 1
