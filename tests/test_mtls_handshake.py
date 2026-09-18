import datetime as dt
import ipaddress
import ssl

import httpx
import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mon.mtls_ingress import create_app, create_mtls_server_ssl_context
from mon.site_identity import (
    CertificateAuthority,
    create_mtls_client_ssl_context,
    generate_site_key_and_csr,
)


def make_ca() -> tuple[CertificateAuthority, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MON TLS Test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return CertificateAuthority.from_pem(certificate_pem, private_key_pem), certificate_pem


def issue_server_certificate(ca: CertificateAuthority) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
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
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca.certificate.public_key()
            ),
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


def write_tls_material(tmp_path):
    ca, ca_pem = make_ca()
    server_cert, server_key = issue_server_certificate(ca)
    site_key = generate_site_key_and_csr("tenant-a", "site-1")
    site_cert = ca.issue_client_certificate(
        site_key.csr_pem,
        "tenant-a",
        "site-1",
    ).public_bytes(serialization.Encoding.PEM).decode()

    paths = {
        "ca": tmp_path / "ca.pem",
        "server_cert": tmp_path / "server.pem",
        "server_key": tmp_path / "server-key.pem",
        "site_cert": tmp_path / "site.pem",
        "site_key": tmp_path / "site-key.pem",
    }
    paths["ca"].write_text(ca_pem, encoding="utf-8")
    paths["server_cert"].write_text(server_cert, encoding="utf-8")
    paths["server_key"].write_text(server_key, encoding="utf-8")
    paths["site_cert"].write_text(site_cert, encoding="utf-8")
    paths["site_key"].write_text(site_key.private_key_pem, encoding="utf-8")
    return paths


async def start_site(app: web.Application, ssl_context: ssl.SSLContext | None = None):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_context)
    await site.start()
    sockets = site._server.sockets
    port = int(sockets[0].getsockname()[1])
    return runner, port


@pytest.mark.asyncio
async def test_real_mtls_handshake_and_forwarding(tmp_path) -> None:
    paths = write_tls_material(tmp_path)
    observed: dict[str, object] = {}

    async def upstream(request: web.Request) -> web.Response:
        observed["authorization"] = request.headers.get("Authorization")
        observed["payload"] = await request.json()
        return web.json_response(
            {"accepted_event_ids": ["event-1"]},
            status=201,
        )

    upstream_app = web.Application()
    upstream_app.router.add_post("/api/v1/events/batch", upstream)
    upstream_runner, upstream_port = await start_site(upstream_app)

    server_context = create_mtls_server_ssl_context(
        str(paths["server_cert"]),
        str(paths["server_key"]),
        str(paths["ca"]),
    )
    ingress_runner, ingress_port = await start_site(
        create_app(f"http://127.0.0.1:{upstream_port}"),
        server_context,
    )

    client_context = create_mtls_client_ssl_context(
        str(paths["ca"]),
        str(paths["site_cert"]),
        str(paths["site_key"]),
    )
    try:
        async with httpx.AsyncClient(verify=client_context) as client:
            response = await client.post(
                f"https://127.0.0.1:{ingress_port}/api/v1/events/batch",
                headers={"Authorization": "Bearer site-service-token"},
                json={
                    "events": [
                        {
                            "event_id": "event-1",
                            "tenant_id": "tenant-a",
                            "site_id": "site-1",
                            "sensor_id": "sensor-1",
                            "category": "network.connection",
                        }
                    ]
                },
            )
        assert response.status_code == 201
        assert response.json()["accepted_event_ids"] == ["event-1"]
        assert observed["authorization"] == "Bearer site-service-token"
    finally:
        await ingress_runner.cleanup()
        await upstream_runner.cleanup()


@pytest.mark.asyncio
async def test_client_without_certificate_cannot_connect(tmp_path) -> None:
    paths = write_tls_material(tmp_path)
    server_context = create_mtls_server_ssl_context(
        str(paths["server_cert"]),
        str(paths["server_key"]),
        str(paths["ca"]),
    )
    ingress_runner, ingress_port = await start_site(
        create_app("http://127.0.0.1:1"),
        server_context,
    )

    client_context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=str(paths["ca"]),
    )
    try:
        async with httpx.AsyncClient(verify=client_context) as client:
            with pytest.raises((httpx.ConnectError, httpx.ReadError)):
                await client.post(
                    f"https://127.0.0.1:{ingress_port}/api/v1/events/batch",
                    json={"events": []},
                )
    finally:
        await ingress_runner.cleanup()


@pytest.mark.asyncio
async def test_certificate_scope_mismatch_is_rejected_before_forwarding(tmp_path) -> None:
    paths = write_tls_material(tmp_path)
    forwarded = False

    async def upstream(request: web.Request) -> web.Response:
        nonlocal forwarded
        forwarded = True
        return web.json_response({"accepted_event_ids": []})

    upstream_app = web.Application()
    upstream_app.router.add_post("/api/v1/events/batch", upstream)
    upstream_runner, upstream_port = await start_site(upstream_app)
    server_context = create_mtls_server_ssl_context(
        str(paths["server_cert"]),
        str(paths["server_key"]),
        str(paths["ca"]),
    )
    ingress_runner, ingress_port = await start_site(
        create_app(f"http://127.0.0.1:{upstream_port}"),
        server_context,
    )
    client_context = create_mtls_client_ssl_context(
        str(paths["ca"]),
        str(paths["site_cert"]),
        str(paths["site_key"]),
    )

    try:
        async with httpx.AsyncClient(verify=client_context) as client:
            response = await client.post(
                f"https://127.0.0.1:{ingress_port}/api/v1/events/batch",
                headers={"Authorization": "Bearer site-service-token"},
                json={
                    "events": [
                        {
                            "event_id": "event-2",
                            "tenant_id": "tenant-a",
                            "site_id": "site-2",
                            "sensor_id": "sensor-1",
                            "category": "network.connection",
                        }
                    ]
                },
            )
        assert response.status_code == 403
        assert forwarded is False
    finally:
        await ingress_runner.cleanup()
        await upstream_runner.cleanup()
