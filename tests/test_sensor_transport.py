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
