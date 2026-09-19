import datetime as dt
import ssl

import httpx
import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mon.mtls_ingress import create_mtls_server_ssl_context
from mon.sensor_identity import (
    generate_sensor_key_and_csr,
    issue_sensor_client_certificate,
)
from mon.sensor_transport import (
    MtlsSensorIngress,
    SensorTransportConfigurationError,
    require_loopback_site_controller_url,
    require_sensor_matches_site,
)
from mon.site_identity import (
    CertificateAuthority,
    create_mtls_client_ssl_context,
)


def make_ca() -> tuple[CertificateAuthority, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "MON Sensor Transport CA")]
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
        .sign(key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(
        serialization.Encoding.PEM
    ).decode()
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return (
        CertificateAuthority.from_pem(
            certificate_pem,
            private_key_pem,
        ),
        certificate_pem,
    )


def make_server_certificate(
    ca: CertificateAuthority,
) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
            )
        )
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
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
    return (
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def write_sensor_identity(
    tmp_path,
    ca: CertificateAuthority,
    ca_pem: str,
    *,
    site_id: str = "site-a",
    sensor_id: str = "sensor-1",
):
    private_key_pem, csr_pem, _ = generate_sensor_key_and_csr(
        "tenant-a",
        site_id,
        sensor_id,
    )
    certificate = issue_sensor_client_certificate(
        ca,
        csr_pem,
        "tenant-a",
        site_id,
        sensor_id,
    )
    ca_path = tmp_path / f"{sensor_id}-ca.pem"
    cert_path = tmp_path / f"{sensor_id}.pem"
    key_path = tmp_path / f"{sensor_id}-key.pem"
    ca_path.write_text(ca_pem, encoding="utf-8")
    cert_path.write_text(
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        encoding="utf-8",
    )
    key_path.write_text(private_key_pem, encoding="utf-8")
    return ca_path, cert_path, key_path


def install_scope_only_authorizer(ingress: MtlsSensorIngress) -> None:
    async def authorize(request: web.Request):
        identity = ingress._verified_identity(request)
        require_sensor_matches_site(
            identity,
            tenant_id=ingress.tenant_id,
            site_id=ingress.site_id,
        )
        return identity

    ingress._authorize = authorize


async def start_plain_app(app: web.Application):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    assert site._server is not None
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


async def start_ingress(
    app: web.Application,
    ssl_context: ssl.SSLContext,
):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(
        runner,
        host="127.0.0.1",
        port=0,
        ssl_context=ssl_context,
    )
    await site.start()
    assert site._server is not None
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


@pytest.mark.asyncio
async def test_mtls_sensor_health_derives_identity_from_client_certificate(
    tmp_path,
) -> None:
    ca, ca_pem = make_ca()
    server_cert, server_key = make_server_certificate(ca)
    server_cert_path = tmp_path / "server.pem"
    server_key_path = tmp_path / "server-key.pem"
    ca_path = tmp_path / "sensor-ca.pem"
    server_cert_path.write_text(server_cert, encoding="utf-8")
    server_key_path.write_text(server_key, encoding="utf-8")
    ca_path.write_text(ca_pem, encoding="utf-8")

    ingress = MtlsSensorIngress(
        "tenant-a",
        "site-a",
        "http://127.0.0.1:8090",
    )
    install_scope_only_authorizer(ingress)
    app = web.Application()
    app.router.add_get("/health", ingress.health)
    server_context = create_mtls_server_ssl_context(
        str(server_cert_path),
        str(server_key_path),
        str(ca_path),
    )
    runner, port = await start_ingress(app, server_context)

    client_ca, client_cert, client_key = write_sensor_identity(
        tmp_path,
        ca,
        ca_pem,
    )
    client_context = create_mtls_client_ssl_context(
        str(client_ca),
        str(client_cert),
        str(client_key),
    )
    try:
        async with httpx.AsyncClient(
            verify=client_context,
            timeout=5,
            trust_env=False,
        ) as client:
            response = await client.get(
                f"https://localhost:{port}/health"
            )
        assert response.status_code == 200
        assert response.json()["sensor_id"] == "sensor-1"
        assert response.json()["tenant_id"] == "tenant-a"
        assert response.json()["site_id"] == "site-a"
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_valid_certificate_for_other_site_is_forbidden(tmp_path) -> None:
    ca, ca_pem = make_ca()
    server_cert, server_key = make_server_certificate(ca)
    server_cert_path = tmp_path / "server.pem"
    server_key_path = tmp_path / "server-key.pem"
    ca_path = tmp_path / "sensor-ca.pem"
    server_cert_path.write_text(server_cert, encoding="utf-8")
    server_key_path.write_text(server_key, encoding="utf-8")
    ca_path.write_text(ca_pem, encoding="utf-8")

    ingress = MtlsSensorIngress(
        "tenant-a",
        "site-a",
        "http://127.0.0.1:8090",
    )
    install_scope_only_authorizer(ingress)
    app = web.Application()
    app.router.add_get("/health", ingress.health)
    runner, port = await start_ingress(
        app,
        create_mtls_server_ssl_context(
            str(server_cert_path),
            str(server_key_path),
            str(ca_path),
        ),
    )
    client_ca, client_cert, client_key = write_sensor_identity(
        tmp_path,
        ca,
        ca_pem,
        site_id="site-b",
        sensor_id="sensor-other-site",
    )
    client_context = create_mtls_client_ssl_context(
        str(client_ca),
        str(client_cert),
        str(client_key),
    )
    try:
        async with httpx.AsyncClient(
            verify=client_context,
            timeout=5,
            trust_env=False,
        ) as client:
            response = await client.get(
                f"https://localhost:{port}/health"
            )
        assert response.status_code == 403
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_ingress_injects_verified_sensor_id_into_internal_batch(
    tmp_path,
) -> None:
    ca, ca_pem = make_ca()
    server_cert, server_key = make_server_certificate(ca)
    server_cert_path = tmp_path / "server.pem"
    server_key_path = tmp_path / "server-key.pem"
    ca_path = tmp_path / "sensor-ca.pem"
    server_cert_path.write_text(server_cert, encoding="utf-8")
    server_key_path.write_text(server_key, encoding="utf-8")
    ca_path.write_text(ca_pem, encoding="utf-8")

    ingress = MtlsSensorIngress(
        "tenant-a",
        "site-a",
        "http://127.0.0.1:8090",
    )
    install_scope_only_authorizer(ingress)
    captured: dict[str, object] = {}

    async def fake_forward(path: str, payload: dict[str, object]):
        captured["path"] = path
        captured["payload"] = payload
        return web.json_response({"accepted": True}, status=201)

    ingress._forward = fake_forward
    app = web.Application()
    app.router.add_post(
        "/api/v1/sensors/suricata/batch",
        ingress.ingest_suricata,
    )
    runner, port = await start_ingress(
        app,
        create_mtls_server_ssl_context(
            str(server_cert_path),
            str(server_key_path),
            str(ca_path),
        ),
    )
    client_ca, client_cert, client_key = write_sensor_identity(
        tmp_path,
        ca,
        ca_pem,
        sensor_id="suricata-edge-7",
    )
    client_context = create_mtls_client_ssl_context(
        str(client_ca),
        str(client_cert),
        str(client_key),
    )
    try:
        async with httpx.AsyncClient(
            verify=client_context,
            timeout=5,
            trust_env=False,
        ) as client:
            response = await client.post(
                f"https://localhost:{port}/api/v1/sensors/suricata/batch",
                json={
                    "records": [
                        {
                            "record": {
                                "timestamp": "2026-09-19T04:00:00+00:00",
                                "event_type": "flow",
                            }
                        }
                    ]
                },
            )
        assert response.status_code == 201
        assert captured["path"] == "/api/v1/site/sensors/suricata/batch"
        payload = captured["payload"]
        assert isinstance(payload, dict)
        records = payload["records"]
        assert isinstance(records, list)
        assert records[0]["sensor_id"] == "suricata-edge-7"
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_sensor_renewal_injects_verified_current_fingerprint(
    tmp_path,
) -> None:
    ca, ca_pem = make_ca()
    server_cert, server_key = make_server_certificate(ca)
    server_cert_path = tmp_path / "server.pem"
    server_key_path = tmp_path / "server-key.pem"
    ca_path = tmp_path / "sensor-ca.pem"
    server_cert_path.write_text(server_cert, encoding="utf-8")
    server_key_path.write_text(server_key, encoding="utf-8")
    ca_path.write_text(ca_pem, encoding="utf-8")

    ingress = MtlsSensorIngress(
        "tenant-a",
        "site-a",
        "http://127.0.0.1:8090",
    )
    install_scope_only_authorizer(ingress)
    captured: dict[str, object] = {}

    async def fake_forward(path: str, payload: dict[str, object]):
        captured["path"] = path
        captured["payload"] = payload
        return web.json_response({"state": "forwarded"}, status=200)

    ingress._forward = fake_forward
    app = web.Application()
    app.router.add_post(
        "/api/v1/sensors/renew",
        ingress.renew,
    )
    runner, port = await start_ingress(
        app,
        create_mtls_server_ssl_context(
            str(server_cert_path),
            str(server_key_path),
            str(ca_path),
        ),
    )
    client_ca, client_cert, client_key = write_sensor_identity(
        tmp_path,
        ca,
        ca_pem,
        sensor_id="sensor-renew-1",
    )
    certificate = x509.load_pem_x509_certificate(
        client_cert.read_bytes()
    )
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    _, csr_pem, _ = generate_sensor_key_and_csr(
        "tenant-a",
        "site-a",
        "sensor-renew-1",
    )
    client_context = create_mtls_client_ssl_context(
        str(client_ca),
        str(client_cert),
        str(client_key),
    )
    try:
        async with httpx.AsyncClient(
            verify=client_context,
            timeout=5,
            trust_env=False,
        ) as client:
            response = await client.post(
                f"https://localhost:{port}/api/v1/sensors/renew",
                json={"csr_pem": csr_pem},
            )
        assert response.status_code == 200
        assert captured["path"] == "/api/v1/site/sensors/renew"
        payload = captured["payload"]
        assert isinstance(payload, dict)
        assert payload["tenant_id"] == "tenant-a"
        assert payload["site_id"] == "site-a"
        assert payload["sensor_id"] == "sensor-renew-1"
        assert payload["current_fingerprint_sha256"] == fingerprint
        assert payload["csr_pem"] == csr_pem
    finally:
        await runner.cleanup()


def test_sensor_ingress_internal_forwarding_is_loopback_only() -> None:
    assert (
        require_loopback_site_controller_url(
            "http://127.0.0.1:8090"
        )
        == "http://127.0.0.1:8090"
    )
    assert (
        require_loopback_site_controller_url(
            "http://[::1]:8090/"
        )
        == "http://[::1]:8090"
    )

    with pytest.raises(
        SensorTransportConfigurationError,
        match="loopback",
    ):
        require_loopback_site_controller_url(
            "http://10.0.0.10:8090"
        )
    with pytest.raises(
        SensorTransportConfigurationError,
        match="loopback HTTP",
    ):
        require_loopback_site_controller_url(
            "https://127.0.0.1:8090"
        )


@pytest.mark.asyncio
async def test_sensor_ingress_rejects_connection_without_client_certificate(
    tmp_path,
) -> None:
    ca, ca_pem = make_ca()
    server_cert, server_key = make_server_certificate(ca)
    server_cert_path = tmp_path / "server.pem"
    server_key_path = tmp_path / "server-key.pem"
    ca_path = tmp_path / "sensor-ca.pem"
    server_cert_path.write_text(server_cert, encoding="utf-8")
    server_key_path.write_text(server_key, encoding="utf-8")
    ca_path.write_text(ca_pem, encoding="utf-8")

    ingress = MtlsSensorIngress(
        "tenant-a",
        "site-a",
        "http://127.0.0.1:8090",
    )
    install_scope_only_authorizer(ingress)
    app = web.Application()
    app.router.add_get("/health", ingress.health)
    runner, port = await start_ingress(
        app,
        create_mtls_server_ssl_context(
            str(server_cert_path),
            str(server_key_path),
            str(ca_path),
        ),
    )

    client_context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=str(ca_path),
    )
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        async with httpx.AsyncClient(
            verify=client_context,
            timeout=5,
            trust_env=False,
        ) as client:
            with pytest.raises(httpx.TransportError):
                await client.get(f"https://localhost:{port}/health")
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_sensor_ingress_rejects_certificate_missing_from_local_trust(
    tmp_path,
) -> None:
    async def reject_sensor(request: web.Request) -> web.Response:
        return web.json_response({"authorized": False})

    local_app = web.Application()
    local_app.router.add_post(
        "/api/v1/site/sensors/authorize",
        reject_sensor,
    )
    local_runner, local_port = await start_plain_app(local_app)

    ca, ca_pem = make_ca()
    server_cert, server_key = make_server_certificate(ca)
    server_cert_path = tmp_path / "server.pem"
    server_key_path = tmp_path / "server-key.pem"
    ca_path = tmp_path / "sensor-ca.pem"
    server_cert_path.write_text(server_cert, encoding="utf-8")
    server_key_path.write_text(server_key, encoding="utf-8")
    ca_path.write_text(ca_pem, encoding="utf-8")

    ingress = MtlsSensorIngress(
        "tenant-a",
        "site-a",
        f"http://127.0.0.1:{local_port}",
    )
    app = web.Application()
    app.router.add_get("/health", ingress.health)
    runner, port = await start_ingress(
        app,
        create_mtls_server_ssl_context(
            str(server_cert_path),
            str(server_key_path),
            str(ca_path),
        ),
    )
    client_ca, client_cert, client_key = write_sensor_identity(
        tmp_path,
        ca,
        ca_pem,
    )
    client_context = create_mtls_client_ssl_context(
        str(client_ca),
        str(client_cert),
        str(client_key),
    )
    try:
        async with httpx.AsyncClient(
            verify=client_context,
            timeout=5,
            trust_env=False,
        ) as client:
            response = await client.get(
                f"https://localhost:{port}/health"
            )
        assert response.status_code == 403
        assert "not accepted" in response.text
    finally:
        await runner.cleanup()
        await local_runner.cleanup()


@pytest.mark.asyncio
async def test_sensor_ingress_fails_closed_when_local_trust_is_unavailable(
    tmp_path,
) -> None:
    ca, ca_pem = make_ca()
    server_cert, server_key = make_server_certificate(ca)
    server_cert_path = tmp_path / "server.pem"
    server_key_path = tmp_path / "server-key.pem"
    ca_path = tmp_path / "sensor-ca.pem"
    server_cert_path.write_text(server_cert, encoding="utf-8")
    server_key_path.write_text(server_key, encoding="utf-8")
    ca_path.write_text(ca_pem, encoding="utf-8")

    ingress = MtlsSensorIngress(
        "tenant-a",
        "site-a",
        "http://127.0.0.1:1",
        timeout_seconds=0.5,
    )
    app = web.Application()
    app.router.add_get("/health", ingress.health)
    runner, port = await start_ingress(
        app,
        create_mtls_server_ssl_context(
            str(server_cert_path),
            str(server_key_path),
            str(ca_path),
        ),
    )
    client_ca, client_cert, client_key = write_sensor_identity(
        tmp_path,
        ca,
        ca_pem,
    )
    client_context = create_mtls_client_ssl_context(
        str(client_ca),
        str(client_cert),
        str(client_key),
    )
    try:
        async with httpx.AsyncClient(
            verify=client_context,
            timeout=5,
            trust_env=False,
        ) as client:
            response = await client.get(
                f"https://localhost:{port}/health"
            )
        assert response.status_code == 503
    finally:
        await runner.cleanup()
