"""Networked mTLS/restart acceptance gate.

This gate covers the boundary ADR 0066 intentionally left open: real loopback
TCP between the Site Controller, mTLS ingress, and Control Plane, plus process
restart and durable replay. It skips outside disposable Linux CI rather than
fabricating a pass.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mon.database import DatabaseStore
from mon.domain import EnforcementVerificationState, ResponseExecutionStatus
from mon.site_identity import CertificateAuthority, generate_site_key_and_csr

pytestmark = pytest.mark.skipif(
    not (
        os.environ.get("MON_TEST_DATABASE_URL")
        and sys.platform == "linux"
        and os.environ.get("MON_TEST_NETNS")
        and os.environ.get("MON_ENABLE_DISPOSABLE_NETNS_ENFORCEMENT") == "1"
    ),
    reason=(
        "networked restart E2E requires PostgreSQL, Linux, a disposable "
        "network namespace, and disposable nftables enforcement"
    ),
)

REPORT_PATH = Path("networked-restart-acceptance-report.json")
ISSUER = "mon-networked-restart-e2e"
AUDIENCE = "mon-control-plane"
SITE_VENDOR = "linux-nftables-e2e"


class Stage:
    def __init__(self, report: dict[str, Any], name: str) -> None:
        self.report = report
        self.name = name

    def __enter__(self) -> Stage:
        self.started = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, _tb) -> bool:
        entry = {
            "status": "PROVEN" if exc_type is None else "NOT_PROVEN",
            "duration_seconds": round(time.monotonic() - self.started, 3),
        }
        if exc_type is not None:
            entry["error"] = f"{exc_type.__name__}: {exc}"[:1000]
        self.report["stages"][self.name] = entry
        REPORT_PATH.write_text(json.dumps(self.report, indent=2, sort_keys=True))
        return False


def stage(report: dict[str, Any], name: str) -> Stage:
    return Stage(report, name)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_http(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    verify: str | bool = True,
    cert: tuple[str, str] | None = None,
    timeout: float = 20.0,
) -> None:
    deadline = time.monotonic() + timeout
    last_error: object = None
    while time.monotonic() < deadline:
        try:
            response = http_get(
                url,
                headers=headers,
                verify=verify,
                cert=cert,
                timeout=2.0,
            )
            if response.status_code < 500:
                return
            last_error = response.text
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.25)
    raise AssertionError(f"{url} did not become ready: {last_error}")


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    verify: str | bool = True,
    cert: tuple[str, str] | None = None,
    timeout: float = 2.0,
) -> httpx.Response:
    with httpx.Client(
        verify=verify,
        cert=cert,
        timeout=timeout,
        trust_env=False,
    ) as client:
        return client.get(url, headers=headers)


def http_post(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: object | None = None,
    content: bytes | None = None,
    verify: str | bool = True,
    cert: tuple[str, str] | None = None,
    timeout: float = 2.0,
) -> httpx.Response:
    with httpx.Client(
        verify=verify,
        cert=cert,
        timeout=timeout,
        trust_env=False,
    ) as client:
        return client.post(url, headers=headers, json=json_body, content=content)


def wait_until(predicate, *, timeout: float = 20.0, interval: float = 0.25):
    deadline = time.monotonic() + timeout
    last_error: object = None
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(interval)
    raise AssertionError(f"condition was not proven before timeout: {last_error}")


def terminate(process: subprocess.Popen[str], *, hard: bool = False) -> int:
    if process.poll() is not None:
        return int(process.returncode)
    if hard:
        process.kill()
    else:
        process.send_signal(signal.SIGTERM)
    try:
        return int(process.wait(timeout=10))
    except subprocess.TimeoutExpired:
        process.kill()
        return int(process.wait(timeout=10))


def make_ca(common_name: str) -> tuple[CertificateAuthority, str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return CertificateAuthority.from_pem(cert_pem, key_pem), cert_pem, key_pem


def server_certificate(ca: CertificateAuthority) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(ca.private_key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def write_site_certificates(
    root: Path,
    ca: CertificateAuthority,
    *,
    tenant_id: str,
    site_id: str,
    prefix: str,
) -> tuple[Path, Path]:
    material = generate_site_key_and_csr(tenant_id, site_id)
    cert = ca.issue_client_certificate(material.csr_pem, tenant_id, site_id)
    cert_path = root / f"{prefix}.cert.pem"
    key_path = root / f"{prefix}.key.pem"
    cert_path.write_text(cert.public_bytes(serialization.Encoding.PEM).decode())
    key_path.write_text(material.private_key_pem)
    return cert_path, key_path


def make_auth_material() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def token(
    private_pem: str,
    *,
    subject: str,
    tenant_id: str,
    roles: list[str],
    site_ids: list[str] | None = None,
) -> str:
    now = dt.datetime.now(dt.UTC)
    return jwt.encode(
        {
            "sub": subject,
            "tenant_id": tenant_id,
            "roles": roles,
            "site_ids": site_ids or [],
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + dt.timedelta(minutes=30),
        },
        private_pem,
        algorithm="RS256",
    )


def start_process(
    args: list[str],
    *,
    env: dict[str, str],
    log_path: Path,
) -> subprocess.Popen[str]:
    log = log_path.open("w", encoding="utf-8")
    return subprocess.Popen(
        args,
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        start_new_session=True,
    )


def count_event(store: DatabaseStore, tenant_id: str, site_id: str, event_id: str) -> int:
    return sum(1 for event in store.list_events(tenant_id, site_id) if event.event_id == event_id)


@pytest.mark.asyncio
async def test_networked_mtls_restart_acceptance(tmp_path: Path) -> None:
    database_url = os.environ["MON_TEST_DATABASE_URL"]
    namespace = os.environ["MON_TEST_NETNS"]
    tenant_id = "networked-tenant-a"
    site_id = "networked-site-a"
    other_site_id = "networked-site-b"
    scenario_id = f"networked-{uuid.uuid4().hex[:10]}"
    report: dict[str, Any] = {
        "scenario_id": scenario_id,
        "tenant_id": tenant_id,
        "site_id": site_id,
        "stages": {},
        "tls": {},
        "fabric": {},
        "outage": {},
        "restart": {},
        "command": {},
        "rollback": {},
        "security": {},
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))

    ca, ca_pem, _ca_key_pem = make_ca("MON networked restart E2E CA")
    wrong_ca, wrong_ca_pem, _wrong_key_pem = make_ca("MON wrong E2E CA")
    server_cert, server_key = server_certificate(ca)
    ca_path = tmp_path / "ca.pem"
    server_cert_path = tmp_path / "server.pem"
    server_key_path = tmp_path / "server.key"
    ca_path.write_text(ca_pem)
    server_cert_path.write_text(server_cert)
    server_key_path.write_text(server_key)
    good_cert, good_key = write_site_certificates(
        tmp_path,
        ca,
        tenant_id=tenant_id,
        site_id=site_id,
        prefix="site-good",
    )
    wrong_scope_cert, wrong_scope_key = write_site_certificates(
        tmp_path,
        ca,
        tenant_id=tenant_id,
        site_id=other_site_id,
        prefix="site-wrong-scope",
    )
    wrong_ca_cert, wrong_ca_key = write_site_certificates(
        tmp_path,
        wrong_ca,
        tenant_id=tenant_id,
        site_id=site_id,
        prefix="site-wrong-ca",
    )
    wrong_ca_path = tmp_path / "wrong-ca.pem"
    wrong_ca_path.write_text(wrong_ca_pem)

    private_pem, public_pem = make_auth_material()
    admin_token = token(
        private_pem,
        subject="tenant-admin",
        tenant_id=tenant_id,
        roles=["tenant_admin"],
    )
    site_token = token(
        private_pem,
        subject="site-controller",
        tenant_id=tenant_id,
        roles=["site_controller"],
        site_ids=[site_id],
    )
    wrong_site_token = token(
        private_pem,
        subject="wrong-site-controller",
        tenant_id=tenant_id,
        roles=["site_controller"],
        site_ids=[other_site_id],
    )
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    site_headers = {"Authorization": f"Bearer {site_token}"}

    control_port = free_port()
    ingress_port = free_port()
    site_port = free_port()
    control_url = f"http://127.0.0.1:{control_port}"
    ingress_url = f"https://localhost:{ingress_port}"
    site_url = f"http://127.0.0.1:{site_port}"
    base_env = os.environ.copy()
    base_env.update(
        {
            "PYTHONUNBUFFERED": "1",
            "MON_DATABASE_URL": database_url,
            "MON_AUTH_PUBLIC_KEY_PEM": public_pem,
            "MON_AUTH_ISSUER": ISSUER,
            "MON_AUTH_AUDIENCE": AUDIENCE,
        }
    )
    processes: list[subprocess.Popen[str]] = []
    store = DatabaseStore(database_url)

    def start_control() -> subprocess.Popen[str]:
        process = start_process(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "mon.api:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(control_port),
                "--log-level",
                "warning",
            ],
            env=base_env,
            log_path=tmp_path / "control-plane.log",
        )
        processes.append(process)
        wait_http(f"{control_url}/health")
        return process

    def start_ingress() -> subprocess.Popen[str]:
        env = base_env.copy()
        env.update(
            {
                "MON_INTERNAL_CONTROL_PLANE_URL": control_url,
                "MON_MTLS_SERVER_CERT_FILE": str(server_cert_path),
                "MON_MTLS_SERVER_KEY_FILE": str(server_key_path),
                "MON_SITE_CA_CERT_FILE": str(ca_path),
                "MON_MTLS_HOST": "127.0.0.1",
                "MON_MTLS_PORT": str(ingress_port),
            }
        )
        process = start_process(
            [sys.executable, "-m", "mon.mtls_ingress"],
            env=env,
            log_path=tmp_path / f"mtls-ingress-{len(processes)}.log",
        )
        processes.append(process)
        wait_http(
            f"{ingress_url}/health",
            verify=str(ca_path),
            cert=(str(good_cert), str(good_key)),
        )
        return process

    def start_site() -> subprocess.Popen[str]:
        env = base_env.copy()
        env.update(
            {
                "MON_TENANT_ID": tenant_id,
                "MON_SITE_ID": site_id,
                "MON_SITE_STATE_DIR": str(tmp_path / "site-state"),
                "MON_SITE_INGRESS_URL": ingress_url,
                "MON_SITE_BEARER_TOKEN": site_token,
                "MON_SITE_CA_CERT_FILE": str(ca_path),
                "MON_SITE_CLIENT_CERT_FILE": str(good_cert),
                "MON_SITE_CLIENT_KEY_FILE": str(good_key),
                "MON_SITE_HOST": "127.0.0.1",
                "MON_SITE_PORT": str(site_port),
                "MON_SITE_FLUSH_INTERVAL_SECONDS": "0.2",
                "MON_SITE_COMMAND_INTERVAL_SECONDS": "0.2",
                "MON_SITE_RECOVERY_INTERVAL_SECONDS": "0.2",
                "MON_SITE_SENSOR_TRUST_INTERVAL_SECONDS": "30",
                "MON_SITE_REQUEST_TIMEOUT_SECONDS": "1",
                "MON_SITE_FABRIC_RETRY_BASE_DELAY_SECONDS": "0.1",
                "MON_SITE_FABRIC_RETRY_MAX_DELAY_SECONDS": "0.2",
                "MON_SITE_DISPOSABLE_NETNS": namespace,
                "MON_SITE_DISPOSABLE_NFTABLES_VENDOR": SITE_VENDOR,
            }
        )
        process = start_process(
            [sys.executable, "-m", "mon.site_service"],
            env=env,
            log_path=tmp_path / f"site-{len(processes)}.log",
        )
        processes.append(process)
        wait_http(f"{site_url}/health")
        return process

    try:
        start_control()
        ingress = start_ingress()

        with stage(report, "tls_and_scope_controls"):
            event_body = {
                "event_id": f"{scenario_id}-scope-check",
                "tenant_id": tenant_id,
                "site_id": site_id,
                "sensor_id": "sensor-1",
                "observed_at": dt.datetime.now(dt.UTC).isoformat(),
                "category": "network.connection",
            }
            with pytest.raises(httpx.TransportError):
                http_post(
                    f"{ingress_url}/api/v1/site/fabric/events",
                    json_body=event_body,
                    verify=str(ca_path),
                    timeout=2,
                )
            with pytest.raises(httpx.TransportError):
                http_get(
                    f"{ingress_url}/health",
                    verify=str(ca_path),
                    cert=(str(wrong_ca_cert), str(wrong_ca_key)),
                    timeout=2,
                )
            missing_bearer = http_get(
                f"{ingress_url}/api/v1/site/commands",
                verify=str(ca_path),
                cert=(str(good_cert), str(good_key)),
                timeout=2,
            )
            assert missing_bearer.status_code == 401
            wrong_scope = http_post(
                f"{ingress_url}/api/v1/site/fabric/events",
                content=json.dumps(
                    {
                        "event_id": f"{scenario_id}-wrong-scope",
                        "tenant_id": tenant_id,
                        "site_id": site_id,
                        "source": "sensor-1",
                        "payload_type": "security_event",
                        "payload": event_body,
                        "produced_at": dt.datetime.now(dt.UTC).isoformat(),
                    }
                ).encode(),
                headers=site_headers | {"Content-Type": "application/json"},
                verify=str(ca_path),
                cert=(str(wrong_scope_cert), str(wrong_scope_key)),
                timeout=2,
            )
            assert wrong_scope.status_code == 403
            wrong_pull = http_get(
                f"{ingress_url}/api/v1/site/commands",
                headers={"Authorization": f"Bearer {wrong_site_token}"},
                verify=str(ca_path),
                cert=(str(wrong_scope_cert), str(wrong_scope_key)),
                timeout=2,
            )
            assert wrong_pull.status_code == 200
            assert wrong_pull.json() == []
            report["tls"] = {
                "trusted_client": "PROVEN",
                "missing_client_certificate": "REJECTED",
                "wrong_ca": "REJECTED",
                "wrong_scope": wrong_scope.status_code,
                "bearer_required": missing_bearer.status_code,
            }

        site = start_site()
        report["restart"]["generation_1_pid"] = site.pid

        with stage(report, "networked_fabric_delivery_exactly_once"):
            event_id = f"{scenario_id}-event-online"
            event = {
                "event_id": event_id,
                "tenant_id": tenant_id,
                "site_id": site_id,
                "sensor_id": "sensor-1",
                "observed_at": dt.datetime.now(dt.UTC).isoformat(),
                "category": "network.connection",
                "asset_id": f"{scenario_id}-asset",
                "src_ip": "203.0.113.10",
                "dst_ip": "10.10.0.10",
                "protocol": "tcp",
            }
            response = httpx.post(f"{site_url}/api/v1/site/events", json=event, timeout=5)
            assert response.status_code == 201
            wait_until(lambda: count_event(store, tenant_id, site_id, event_id) == 1)
            receipt = store.get_fabric_receipt(tenant_id, site_id, event_id)
            assert receipt is not None
            assert receipt.event_id == event_id
            report["fabric"]["online_event_id"] = event_id
            report["fabric"]["ack_digest"] = receipt.envelope_sha256

        with stage(report, "outage_queues_and_reconnect_replays_once"):
            terminate(ingress)
            outage_event_id = f"{scenario_id}-event-outage"
            outage_event = event | {
                "event_id": outage_event_id,
                "observed_at": dt.datetime.now(dt.UTC).isoformat(),
            }
            response = httpx.post(f"{site_url}/api/v1/site/events", json=outage_event, timeout=5)
            assert response.status_code == 201

            def degraded_status() -> dict[str, Any] | None:
                status = httpx.get(f"{site_url}/health", timeout=2).json()
                fabric = status["fabric_outbox"]
                if fabric["pending"] >= 1 and fabric["last_error"]:
                    return status
                return None

            status = wait_until(degraded_status, timeout=15)
            report["outage"]["queued_depth"] = status["fabric_outbox"]["pending"]
            report["outage"]["last_error_recorded"] = bool(status["fabric_outbox"]["last_error"])
            ingress = start_ingress()
            wait_until(lambda: count_event(store, tenant_id, site_id, outage_event_id) == 1)
            wait_until(
                lambda: httpx.get(f"{site_url}/health", timeout=2).json()[
                    "fabric_outbox"
                ]["pending"]
                == 0
            )
            assert count_event(store, tenant_id, site_id, outage_event_id) == 1
            report["outage"]["replay_duplicate_count"] = count_event(
                store,
                tenant_id,
                site_id,
                outage_event_id,
            )

        with stage(report, "graceful_process_restart_preserves_state"):
            generation_1 = site.pid
            exit_code = terminate(site)
            assert exit_code in {0, -signal.SIGTERM}
            site = start_site()
            report["restart"]["generation_1_pid"] = generation_1
            report["restart"]["generation_2_pid"] = site.pid
            assert site.pid != generation_1

        with stage(report, "command_apply_result_survives_hard_restart"):
            asset_id = f"{scenario_id}-asset"
            incident_id = f"{scenario_id}-incident"
            httpx.post(
                f"{control_url}/api/v1/assets",
                headers=admin_headers,
                json={
                    "asset_id": asset_id,
                    "tenant_id": tenant_id,
                    "site_id": site_id,
                    "display_name": "networked restart asset",
                    "ip_addresses": ["10.10.0.10"],
                },
                timeout=5,
            ).raise_for_status()
            httpx.post(
                f"{control_url}/api/v1/incidents",
                headers=admin_headers,
                json={
                    "incident_id": incident_id,
                    "tenant_id": tenant_id,
                    "site_id": site_id,
                    "title": "networked restart containment",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "affected_asset_ids": [asset_id],
                },
                timeout=5,
            ).raise_for_status()
            httpx.post(
                f"{control_url}/api/v1/enforcement-points",
                headers=admin_headers,
                json={
                    "enforcement_point_id": f"{scenario_id}-fw",
                    "tenant_id": tenant_id,
                    "site_id": site_id,
                    "kind": "FIREWALL",
                    "vendor": SITE_VENDOR,
                    "capabilities": ["BLOCK_IP"],
                },
                timeout=5,
            ).raise_for_status()
            httpx.post(
                f"{control_url}/api/v1/enforcement-bindings",
                headers=admin_headers,
                json={
                    "tenant_id": tenant_id,
                    "site_id": site_id,
                    "asset_id": asset_id,
                    "enforcement_point_id": f"{scenario_id}-fw",
                },
                timeout=5,
            ).raise_for_status()
            request = {
                "request_id": f"{scenario_id}-response",
                "tenant_id": tenant_id,
                "site_id": site_id,
                "incident_id": incident_id,
                "target": {"ip_address": "198.51.100.25"},
                "action": "BLOCK_IP",
                "ttl_seconds": 120,
                "reason": "networked restart acceptance containment",
            }
            execution = httpx.post(
                f"{control_url}/api/v1/responses/execute",
                headers=admin_headers,
                json={
                    "request": request,
                    "approve": True,
                    "approval_reason": "networked restart acceptance",
                },
                timeout=5,
            )
            execution.raise_for_status()
            execution_id = execution.json()["execution_id"]
            report["command"]["execution_id"] = execution_id

            def applied_execution() -> bool:
                response = httpx.get(
                    f"{control_url}/api/v1/responses",
                    headers=admin_headers,
                    params={"tenant_id": tenant_id, "site_id": site_id},
                    timeout=5,
                )
                response.raise_for_status()
                return any(
                    item["execution_id"] == execution_id and item["status"] == "APPLIED"
                    for item in response.json()
                )

            wait_until(applied_execution, timeout=30)
            first_status = httpx.get(f"{site_url}/health", timeout=2).json()
            assert first_status["command_result_outbox"]["receipts"] == 1
            report["command"]["result_reported_before_restart"] = True
            terminate(site, hard=True)
            site = start_site()
            assert applied_execution()
            second_status = httpx.get(f"{site_url}/health", timeout=2).json()
            assert second_status["command_result_outbox"]["receipts"] == 1
            report["restart"]["hard_restart_pid"] = site.pid
            report["command"]["receipt_count_after_restart"] = second_status[
                "command_result_outbox"
            ]["receipts"]

            from mon.connectors.nftables_netns import DisposableNftablesAdapter
            from mon.domain import ResponsePlan

            adapter = DisposableNftablesAdapter(namespace)
            plan_response = httpx.post(
                f"{control_url}/api/v1/responses/plan",
                headers=admin_headers,
                json=request,
                timeout=5,
            )
            plan_response.raise_for_status()
            plan = ResponsePlan.model_validate(plan_response.json())
            verification = await adapter.verify(plan, execution_id)
            assert verification.state is EnforcementVerificationState.PRESENT
            report["command"]["nftables_after_restart"] = verification.state.value

            rollback = httpx.post(
                f"{control_url}/api/v1/responses/{execution_id}/rollback",
                headers=admin_headers,
                params={"tenant_id": tenant_id, "site_id": site_id},
                json={"reason": "networked restart rollback proof"},
                timeout=5,
            )
            rollback.raise_for_status()

            def rolled_back() -> bool:
                response = httpx.get(
                    f"{control_url}/api/v1/responses",
                    headers=admin_headers,
                    params={"tenant_id": tenant_id, "site_id": site_id},
                    timeout=5,
                )
                response.raise_for_status()
                return any(
                    item["execution_id"] == execution_id and item["status"] == "ROLLED_BACK"
                    for item in response.json()
                )

            wait_until(rolled_back, timeout=30)
            absent = await adapter.verify(plan, execution_id)
            assert absent.state is EnforcementVerificationState.ABSENT
            audit = httpx.get(
                f"{control_url}/api/v1/audit",
                headers=admin_headers,
                params={"tenant_id": tenant_id, "site_id": site_id},
                timeout=5,
            )
            audit.raise_for_status()
            assert any(
                item["object_id"] == execution_id and item["outcome"] == "ROLLED_BACK"
                for item in audit.json()
            )
            report["rollback"] = {
                "control_plane_state": ResponseExecutionStatus.ROLLED_BACK.value,
                "nftables_after_rollback": absent.state.value,
            }

        for path in tmp_path.glob("*.log"):
            content = path.read_text(encoding="utf-8", errors="replace")
            assert "BEGIN PRIVATE KEY" not in content
            assert site_token not in content
            assert admin_token not in content
        report["security"]["secrets_absent_from_logs"] = True
    finally:
        with contextlib.suppress(Exception):
            store.close()
        for process in reversed(processes):
            terminate(process, hard=True)
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))
