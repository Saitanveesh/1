# ruff: noqa: E501
"""Bounded load / resource / restart gate for the control-plane ingest path (disposable CI).

Reuses tools/fabric_load_probe.py (HTTPS, soak mode, resource sampler). Records measured
facts for the tested scale only; it does not assert any throughput SLO. It fails only on
correctness: dropped/failed requests, lost acknowledged events, or failed recovery.
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
from pathlib import Path

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from mon.database import DatabaseStore
from mon.endpoint import EndpointEventKind, EndpointTelemetryEvent, normalize_endpoint_event
from mon.event_fabric import security_event_envelope

ISSUER, AUDIENCE, KID = "mon-load-gate", "mon-control-plane", "load-key-1"
TENANT, SITE = "load-tenant", "load-site"
CORPUS_SIZE = int(os.environ.get("MON_LOAD_CORPUS", "1500"))
SOAK_SECONDS = float(os.environ.get("MON_LOAD_SOAK_SECONDS", "30"))
INTERVAL_SECONDS = float(os.environ.get("MON_LOAD_INTERVAL_SECONDS", "10"))
CONCURRENCY = int(os.environ.get("MON_LOAD_CONCURRENCY", "8"))


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def make_material(directory: Path) -> tuple[str, Path, Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    jwks = directory / "jwks.json"
    jwks.write_text(json.dumps({"keys": [jwk]}))
    tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(tls_key, hashes.SHA256())
    )
    cert_path, key_path = directory / "server.pem", directory / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        tls_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return private_pem, jwks, cert_path, key_path


def make_corpus(path: Path, count: int) -> None:
    base = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=30)
    with path.open("w") as handle:
        for index in range(count):
            telemetry = EndpointTelemetryEvent(
                tenant_id=TENANT,
                site_id=SITE,
                sensor_id="load-sensor-1",
                event_id=f"load-{index:06d}",
                observed_at=base + dt.timedelta(milliseconds=index),
                kind=EndpointEventKind.AUTH_FAILURE,
                asset_id=f"linux-host:load-{index % 50}",
                hostname=f"load-{index % 50}",
                src_ip=f"198.51.100.{index % 250 + 1}",
                user_name=f"user-{index}",  # distinct identity: never trips the burst detector
                outcome="failure",
                source="sshd",
            )
            envelope = security_event_envelope(
                normalize_endpoint_event(telemetry), produced_at=dt.datetime.now(dt.UTC)
            )
            handle.write(envelope.model_dump_json() + "\n")


def main() -> int:
    work = Path(os.environ.get("MON_LOAD_DIR", "load-run"))
    work.mkdir(parents=True, exist_ok=True)
    db_url = os.environ["MON_DATABASE_URL"]
    private_pem, jwks, cert_path, key_path = make_material(work)
    now = dt.datetime.now(dt.UTC)
    bearer = jwt.encode(
        {
            "sub": "load-site-controller", "tenant_id": TENANT, "roles": ["site_controller"],
            "site_ids": [SITE], "iss": ISSUER, "aud": AUDIENCE, "iat": now,
            "exp": now + dt.timedelta(hours=1),
        },
        private_pem, algorithm="RS256", headers={"kid": KID},
    )  # fmt: skip
    corpus = work / "corpus.jsonl"
    make_corpus(corpus, CORPUS_SIZE)
    port = free_port()
    url = f"https://localhost:{port}/api/v1/fabric/events"
    env = os.environ.copy()
    env.update(
        MON_AUTH_JWKS_FILE=str(jwks), MON_AUTH_ISSUER=ISSUER, MON_AUTH_AUDIENCE=AUDIENCE,
        PYTHONUNBUFFERED="1",
    )
    for key in ("MON_AUTH_PUBLIC_KEY_PEM", "MON_AUTH_PUBLIC_KEY_FILE", "MON_AUTH_JWKS_JSON"):
        env.pop(key, None)
    log = work / "control-plane.log"
    processes: list[subprocess.Popen[str]] = []

    def start() -> subprocess.Popen[str]:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "mon.api:app", "--host", "127.0.0.1", "--port", str(port),
             "--ssl-keyfile", str(key_path), "--ssl-certfile", str(cert_path), "--log-level", "warning"],
            stdout=log.open("a"), stderr=subprocess.STDOUT, text=True, env=env, start_new_session=True,
        )  # fmt: skip
        processes.append(process)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"https://localhost:{port}/health", verify=str(cert_path), timeout=2).status_code == 200:
                    return process
            except httpx.HTTPError:
                time.sleep(0.3)
        raise SystemExit(f"control plane did not start\n{log.read_text()[-2000:]}")

    report: dict = {
        "schema": "mon.load-resource-gate.v1",
        "generated_at": now.isoformat(),
        "scope": "single control-plane instance, TLS, PostgreSQL, one runner; evidence for the tested scale only",
        "tested": {"corpus_unique_events": CORPUS_SIZE, "concurrency": CONCURRENCY,
                   "soak_seconds": SOAK_SECONDS, "interval_seconds": INTERVAL_SECONDS,
                   "runner_cpu_count": os.cpu_count()},  # fmt: skip
        "not_proven": ["throughput beyond the tested scale", "multi-instance load", "TLS termination offload",
                       "long-duration (hours/days) soak", "production hardware sizing"],
        "queue_depth": {"status": "NOT_APPLICABLE", "reason": "control-plane ingest is synchronous; no server-side queue"},
    }  # fmt: skip
    try:
        server = start()
        report["control_plane_pid"] = server.pid
        probe = subprocess.run(
            [sys.executable, "tools/fabric_load_probe.py", "--url", url, "--input", str(corpus),
             "--concurrency", str(CONCURRENCY), "--authorization", f"Bearer {bearer}",
             "--ca-file", str(cert_path), "--soak-duration-seconds", str(SOAK_SECONDS),
             "--soak-interval-seconds", str(INTERVAL_SECONDS),
             "--deployment-topology", "single uvicorn instance + PostgreSQL on one GitHub-hosted runner",
             "--resource-sampler-id", "proc-sample", "--resource-sampler-command",
             sys.executable, "tools/resource_sample.py", str(server.pid)],
            capture_output=True, text=True, timeout=int(SOAK_SECONDS) + 180, check=False,
        )  # fmt: skip
        if probe.returncode != 0 and not probe.stdout.strip():
            raise SystemExit(f"probe failed: {probe.stderr[-1500:]}")
        soak = json.loads(probe.stdout)
        aggregate = soak["aggregate"]
        latencies = [
            {k: i[k] for k in ("interval_index", "attempted", "succeeded", "failed", "requests_per_second",
                               "latency_ms_p50", "latency_ms_p95", "latency_ms_p99")}
            for i in soak["intervals"]
        ]  # fmt: skip
        samples = []
        for item in soak["resource_samples"]:
            try:
                samples.append(json.loads(item["stdout"]))
            except (ValueError, KeyError):
                samples.append({"error": "unparseable sample"})
        store = DatabaseStore(db_url)
        stored = len(store.list_events(TENANT, SITE))
        report["soak"] = {
            "probe_successful": soak["successful"], "failure_reasons": soak["failure_reasons"],
            "attempted": aggregate["attempted"], "succeeded": aggregate["succeeded"],
            "failed": aggregate["failed"], "requests_per_second": aggregate["requests_per_second"],
            "status_counts": aggregate["status_counts"], "intervals": latencies,
            "corpus_sha256": soak["corpus_sha256"],
        }  # fmt: skip
        peak_rss = max((s.get("process_rss_kb", 0) for s in samples), default=0)
        report["resources"] = {
            "samples": samples, "peak_process_rss_kb": peak_rss,
            "cpu_seconds_consumed": (
                samples[-1].get("process_user_cpu_seconds", 0) + samples[-1].get("process_system_cpu_seconds", 0)
                if samples else None
            ),
        }  # fmt: skip
        report["events"] = {"unique_events_offered": CORPUS_SIZE, "unique_events_stored": stored,
                            "dropped_unique_events": CORPUS_SIZE - stored}  # fmt: skip

        # restart / recovery: SIGKILL, restart, acknowledged events must all still exist
        os.killpg(server.pid, signal.SIGKILL)
        server.wait(timeout=10)
        began = time.monotonic()
        restarted = start()
        recovery_seconds = round(time.monotonic() - began, 2)
        after = len(store.list_events(TENANT, SITE))
        # a fresh envelope for a fresh event proves the restarted instance ingests again
        telemetry = EndpointTelemetryEvent(
            tenant_id=TENANT, site_id=SITE, sensor_id="load-sensor-1", event_id="load-post-restart",
            observed_at=dt.datetime.now(dt.UTC), kind=EndpointEventKind.AUTH_FAILURE,
            asset_id="linux-host:load-0", hostname="load-0", src_ip="198.51.100.9",
            user_name="post-restart", outcome="failure", source="sshd",
        )  # fmt: skip
        envelope = security_event_envelope(normalize_endpoint_event(telemetry), produced_at=dt.datetime.now(dt.UTC))
        response = httpx.post(url, json=envelope.model_dump(mode="json"), headers={"Authorization": f"Bearer {bearer}"},
                              verify=str(cert_path), timeout=10)
        report["restart_recovery"] = {
            "killed_pid": server.pid, "restarted_pid": restarted.pid, "recovery_seconds_to_healthy": recovery_seconds,
            "events_before_kill": stored, "events_after_restart": after,
            "acknowledged_events_lost": stored - after, "post_restart_ingest_status": response.status_code,
        }  # fmt: skip
        problems = []
        if aggregate["failed"] != 0 or not soak["successful"]:
            problems.append(f"probe reported failures: {soak['failure_reasons']} failed={aggregate['failed']}")
        if stored != CORPUS_SIZE:
            problems.append(f"stored {stored} of {CORPUS_SIZE} unique events")
        if after != stored:
            problems.append("acknowledged events lost across restart")
        if response.status_code != 201:
            problems.append(f"post-restart ingest returned {response.status_code}")
        report["overall"] = "PASS" if not problems else "FAIL"
        report["problems"] = problems
        return 0 if not problems else 1
    finally:
        for process in processes:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)
        Path("load-resource-gate-report.json").write_text(json.dumps(report, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    raise SystemExit(main())
