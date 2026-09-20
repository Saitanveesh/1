"""Control-plane application-layer HA / multi-instance failover certification.

Topology (real TCP everywhere, disposable Linux CI only):

    client -> nginx (test-only reverse proxy) -> uvicorn mon.api:app  A
                                              -> uvicorn mon.api:app  B
                                                       |
                                                 shared PostgreSQL

This is application-layer HA. PostgreSQL clustering/failover, multi-region,
Kubernetes and consensus are explicitly out of scope and reported NOT_PROVEN.
"""

# ruff: noqa: E501
from __future__ import annotations

import concurrent.futures
import contextlib
import datetime as dt
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, text

from mon.database import DatabaseStore
from mon.endpoint import EndpointEventKind, EndpointTelemetryEvent, normalize_endpoint_event
from mon.event_fabric import security_event_envelope

pytestmark = pytest.mark.skipif(
    not (
        os.environ.get("MON_TEST_DATABASE_URL")
        and sys.platform == "linux"
        and os.environ.get("MON_HA_CERT") == "1"
        and shutil.which("nginx")
    ),
    reason="HA certification requires Linux, PostgreSQL, nginx and MON_HA_CERT=1",
)

REPORT_PATH = Path("control-plane-ha-report.json")
ISSUER, AUDIENCE, KID = "mon-ha-cert", "mon-control-plane", "ha-key-1"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def make_keys(tmp: Path) -> tuple[str, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    path = tmp / "jwks.json"
    path.write_text(json.dumps({"keys": [jwk]}))
    return private_pem, path


def make_token(private_pem: str, *, tenant: str, roles: list[str], sites: list[str]) -> str:
    now = dt.datetime.now(dt.UTC)
    return jwt.encode(
        {
            "sub": f"{tenant}-{roles[0]}",
            "tenant_id": tenant,
            "roles": roles,
            "site_ids": sites,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + dt.timedelta(minutes=30),
        },
        private_pem,
        algorithm="RS256",
        headers={"kid": KID},
    )


def wait_health(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last: object = None
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{url}/health", timeout=2.0, trust_env=False).status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.25)
    raise AssertionError(f"{url} not healthy: {last}")


def spawn(args: list[str], env: dict[str, str], log: Path) -> subprocess.Popen[str]:
    return subprocess.Popen(
        args,
        stdout=log.open("w"),
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        start_new_session=True,
    )


def tail(path: Path) -> str:
    return path.read_text(errors="replace")[-2500:] if path.exists() else "<no log>"


def build_events(
    tenant: str, site: str, prefix: str, src_ip: str, count: int, asset_id: str,
    user: str = "root",
):
    base = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=60)
    out = []
    for index in range(count):
        telemetry = EndpointTelemetryEvent(
            tenant_id=tenant,
            site_id=site,
            sensor_id="ha-sensor-1",
            event_id=f"{prefix}-{index}",
            observed_at=base + dt.timedelta(seconds=3 * index),
            kind=EndpointEventKind.AUTH_FAILURE,
            asset_id=asset_id,
            hostname="ha-host-01",
            src_ip=src_ip,
            user_name=user,
            outcome="failure",
            source="sshd",
        )
        out.append(normalize_endpoint_event(telemetry))
    return out


def envelope_json(event) -> dict[str, Any]:
    return security_event_envelope(event, produced_at=dt.datetime.now(dt.UTC)).model_dump(
        mode="json"
    )


def canon(value):
    """Order-insensitive view: set-derived lists serialize in per-process hash order."""
    if isinstance(value, dict):
        return {k: canon(v) for k, v in value.items()}
    if isinstance(value, list):
        items = [canon(v) for v in value]
        if all(isinstance(v, str) for v in items):
            return sorted(items)
        return items
    return value


class Client:
    """HTTP client with bounded retry, recording every outcome."""

    def __init__(self, base: str, headers: dict[str, str], outcomes: list[dict]) -> None:
        self.base, self.headers, self.outcomes = base, headers, outcomes

    def request(self, method: str, path: str, *, retries: int = 4, **kwargs) -> httpx.Response:
        last: Exception | None = None
        for attempt in range(1, retries + 1):
            started = time.monotonic()
            try:
                response = httpx.request(
                    method,
                    self.base + path,
                    headers=self.headers,
                    timeout=12.0,
                    trust_env=False,
                    **kwargs,
                )
                self.outcomes.append(
                    {
                        "t": time.time(),
                        "path": path,
                        "status": response.status_code,
                        "attempt": attempt,
                        "upstream": response.headers.get("x-upstream"),
                        "ms": round((time.monotonic() - started) * 1000, 1),
                    }
                )
                if response.status_code < 500:
                    return response
                last = RuntimeError(f"HTTP {response.status_code}")
            except httpx.HTTPError as exc:
                last = exc
                self.outcomes.append(
                    {"t": time.time(), "path": path, "status": "error", "attempt": attempt,
                     "error": type(exc).__name__}
                )  # fmt: skip
            time.sleep(0.4)
        raise AssertionError(f"{method} {path} failed after {retries} attempts: {last}")


NGINX_CONF = """
daemon off;
pid {tmp}/nginx.pid;
error_log {tmp}/nginx-error.log warn;
events {{ worker_connections 512; }}
http {{
  access_log {tmp}/nginx-access.log;
  client_body_temp_path {tmp}/body; proxy_temp_path {tmp}/proxy;
  fastcgi_temp_path {tmp}/fcgi; uwsgi_temp_path {tmp}/uwsgi; scgi_temp_path {tmp}/scgi;
  upstream mon {{
    server 127.0.0.1:{a} max_fails=1 fail_timeout=2s;
    server 127.0.0.1:{b} max_fails=1 fail_timeout=2s;
  }}
  server {{
    listen 127.0.0.1:{proxy};
    location / {{
      proxy_pass http://mon;
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_connect_timeout 1s;
      proxy_read_timeout 15s;
      # Bounded failover. Non-idempotent retry is safe here only because the
      # MON fabric/response paths are idempotent by contract (asserted below).
      proxy_next_upstream error timeout http_502 http_503 non_idempotent;
      proxy_next_upstream_tries 2;
      add_header X-Upstream $upstream_addr always;
    }}
  }}
}}
"""


def test_control_plane_ha_failover(tmp_path: Path) -> None:
    db_url = os.environ["MON_TEST_DATABASE_URL"]
    admin_url = os.environ.get("MON_TEST_ADMIN_DATABASE_URL", db_url)
    tenant, site = "ha-tenant-a", "ha-site-a"
    other_tenant, other_site = "ha-tenant-b", "ha-site-b"
    asset_id = "linux-host:ha-host-01"
    scenario = f"ha-{uuid.uuid4().hex[:10]}"

    report: dict[str, Any] = {
        "scenario_id": scenario,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "stages": {},
        "facts": {},
        "not_proven": [
            "PostgreSQL automatic failover",
            "multi-region replication",
            "Kubernetes",
            "distributed consensus",
            "zero-downtime database migration",
        ],
    }
    outcomes: list[dict] = []
    traffic: list[dict] = []
    procs: dict[str, subprocess.Popen[str]] = {}
    ports = {"a": free_port(), "b": free_port(), "proxy": free_port()}
    logs = {name: tmp_path / f"instance-{name}.log" for name in ("a", "b")}

    def record(name: str, ok: bool, status: str | None = None, **facts: Any) -> None:
        report["stages"][name] = {"status": status or ("PROVEN" if ok else "NOT_PROVEN"), **facts}
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
        assert ok, f"{name} not proven: {facts}"

    private_pem, jwks_path = make_keys(tmp_path)
    env = os.environ.copy()
    env.update(
        {
            "PYTHONUNBUFFERED": "1",
            "MON_DATABASE_URL": db_url,
            "MON_AUTH_JWKS_FILE": str(jwks_path),
            "MON_AUTH_ISSUER": ISSUER,
            "MON_AUTH_AUDIENCE": AUDIENCE,
        }
    )
    for key in ("MON_AUTH_PUBLIC_KEY_PEM", "MON_AUTH_PUBLIC_KEY_FILE", "MON_AUTH_JWKS_JSON"):
        env.pop(key, None)

    def start_instance(name: str) -> None:
        procs[name] = spawn(
            [sys.executable, "-m", "uvicorn", "mon.api:app", "--host", "127.0.0.1",
             "--port", str(ports[name]), "--log-level", "warning"],
            env,
            logs[name],
        )  # fmt: skip
        try:
            wait_health(f"http://127.0.0.1:{ports[name]}")
        except AssertionError as exc:
            raise AssertionError(f"{exc}\n{tail(logs[name])}") from exc

    (tmp_path / "nginx.conf").write_text(
        NGINX_CONF.format(tmp=tmp_path, a=ports["a"], b=ports["b"], proxy=ports["proxy"])
    )
    (tmp_path / "body").mkdir()
    proxy = f"http://127.0.0.1:{ports['proxy']}"
    direct = {n: f"http://127.0.0.1:{ports[n]}" for n in ("a", "b")}

    admin = {
        "Authorization": "Bearer "
        + make_token(private_pem, tenant=tenant, roles=["tenant_admin"], sites=[])
    }
    ingest = {
        "Authorization": "Bearer "
        + make_token(private_pem, tenant=tenant, roles=["site_controller"], sites=[site])
    }
    other_admin = {
        "Authorization": "Bearer "
        + make_token(private_pem, tenant=other_tenant, roles=["tenant_admin"], sites=[])
    }
    store = DatabaseStore(db_url)
    scope = {"tenant_id": tenant, "site_id": site}

    try:
        start_instance("a")
        start_instance("b")
        report["facts"]["instance_pids"] = {n: procs[n].pid for n in procs}
        procs["nginx"] = spawn(
            ["nginx", "-c", str(tmp_path / "nginx.conf"), "-e", str(tmp_path / "nginx-boot.log")],
            env,
            tmp_path / "nginx.out",
        )
        wait_health(proxy)

        # ---- shared schema, shared authentication ---------------------------------
        engine = create_engine(admin_url)
        with engine.connect() as conn:
            versions = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
        assert len(versions) == 1
        principals = {
            n: httpx.get(f"{direct[n]}/api/v1/me", headers=admin, timeout=5, trust_env=False)
            for n in ("a", "b")
        }
        assert all(r.status_code == 200 for r in principals.values())
        assert principals["a"].json() == principals["b"].json()
        record("01_shared_schema_and_jwks_auth", True, schema_revision=versions[0][0])

        via_proxy = Client(proxy, admin, outcomes)
        via_a = Client(direct["a"], admin, outcomes)
        via_b = Client(direct["b"], admin, outcomes)
        ingest_a = Client(direct["a"], ingest, outcomes)
        ingest_b = Client(direct["b"], ingest, outcomes)
        ingest_proxy = Client(proxy, ingest, outcomes)

        # ---- ingest via A, read via B, incident consistency ------------------------
        burst = build_events(tenant, site, f"{scenario}-burst", "203.0.113.50", 8, asset_id)
        for event in burst:
            r = ingest_a.request("POST", "/api/v1/fabric/events", json=envelope_json(event))
            assert r.status_code == 201, r.text
        findings_b = via_b.request("GET", "/api/v1/findings", params=scope).json()
        incidents_b = via_b.request("GET", "/api/v1/incidents", params=scope).json()
        incidents_a = via_a.request("GET", "/api/v1/incidents", params=scope).json()
        auth_findings = [f for f in findings_b if f["detector_id"] == "endpoint-auth-failure-pressure"]
        assert len(auth_findings) == 1 and len(incidents_b) == 1
        assert canon(incidents_a) == canon(incidents_b)
        incident_id = incidents_b[0]["incident_id"]
        events_in_db = {e.event_id for e in store.list_events(tenant, site)}
        assert {e.event_id for e in burst} <= events_in_db
        record(
            "02_ingest_via_A_visible_via_B",
            True,
            events=len(burst),
            findings=len(auth_findings),
            incidents=len(incidents_b),
        )

        # ---- duplicate envelope raced through BOTH instances -----------------------
        dup_event = build_events(tenant, site, f"{scenario}-dup", "198.51.100.7", 1, asset_id)[0]
        dup_env = envelope_json(dup_event)
        gate = threading.Barrier(8)

        def fire(client: Client) -> httpx.Response:
            gate.wait(timeout=10)
            return client.request("POST", "/api/v1/fabric/events", json=dup_env, retries=1)

        clients = [ingest_a, ingest_b] * 4
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            results = list(pool.map(fire, clients))
        statuses = [r.status_code for r in results]
        assert all(s == 201 for s in statuses), statuses
        flags = [r.json()["duplicate"] for r in results]
        stored = [e for e in store.list_events(tenant, site) if e.event_id == dup_event.event_id]
        assert len(stored) == 1
        record(
            "03_duplicate_envelope_across_instances_deduplicated",
            True,
            concurrent_requests=len(results),
            statuses=statuses,
            non_duplicate_acks=flags.count(False),
            stored_copies=len(stored),
        )

        # ---- split burst: detection must not depend on which instance saw events ----
        split = build_events(tenant, site, f"{scenario}-split", "203.0.113.99", 8, "linux-host:ha-split-host", user="svc-split")
        for index, event in enumerate(split):
            (ingest_a if index % 2 == 0 else ingest_b).request(
                "POST", "/api/v1/fabric/events", json=envelope_json(event)
            )
        split_findings = [
            f
            for f in via_a.request("GET", "/api/v1/findings", params=scope).json()
            if f["detector_id"] == "endpoint-auth-failure-pressure"
            and any(f"{scenario}-split" in str(e.get("raw_reference")) for e in f["evidence"])
        ]
        split_ids = [f["finding_id"] for f in split_findings]
        # Detector windows live in each instance's memory. Splitting one burst
        # across instances can therefore under-detect; that is measured and
        # reported honestly. What must hold regardless is consistency: no
        # duplicate findings/incidents and identical views from both instances.
        detected = len(split_findings) >= 1
        record(
            "04_detection_consistency_when_events_split_across_instances",
            len(set(split_ids)) == len(split_ids),
            status="PROVEN" if detected else "PARTIALLY_PROVEN",
            split_burst_triggered_detection=detected,
            limitation=None if detected else "detector windows are per-instance memory",
            findings_total=len(split_findings),
        )
        incidents_after = via_b.request("GET", "/api/v1/incidents", params=scope).json()
        assert len({i["incident_id"] for i in incidents_after}) == len(incidents_after)

        # ---- response state across instances, idempotent concurrent execute ---------
        point_id = f"{scenario}-fw"
        via_a.request(
            "POST",
            "/api/v1/enforcement-points",
            json={"enforcement_point_id": point_id, "tenant_id": tenant, "site_id": site,
                  "kind": "FIREWALL", "vendor": "ha-cert-vendor", "capabilities": ["BLOCK_IP"]},
        )  # fmt: skip
        via_b.request(
            "POST",
            "/api/v1/enforcement-bindings",
            json={"tenant_id": tenant, "site_id": site, "asset_id": asset_id,
                  "enforcement_point_id": point_id,
                  "attributes": {"blast_radius_estimate": "single documentation IP"}},
        )  # fmt: skip
        request_body = {
            "request": {
                "request_id": f"{scenario}-response",
                "tenant_id": tenant,
                "site_id": site,
                "incident_id": incident_id,
                "target": {"ip_address": "203.0.113.50"},
                "action": "BLOCK_IP",
                "ttl_seconds": 120,
                "reason": "HA certification containment",
            },
            "approve": True,
            "approval_reason": "HA certification",
        }
        gate2 = threading.Barrier(6)

        def execute(client: Client) -> httpx.Response:
            gate2.wait(timeout=10)
            return client.request("POST", "/api/v1/responses/execute", json=request_body, retries=1)

        with concurrent.futures.ThreadPoolExecutor(6) as pool:
            exec_results = list(pool.map(execute, [via_a, via_b] * 3))
        exec_statuses = [r.status_code for r in exec_results]
        ok_results = [r for r in exec_results if r.status_code == 200]
        assert ok_results, exec_statuses
        execution_ids = {r.json()["execution_id"] for r in ok_results}
        rows = store.list_response_executions(tenant, site)
        commands = [
            c for c in store.list_site_commands(tenant, site) if c.command.kind.value == "APPLY_RESPONSE"
        ]
        record(
            "05_idempotent_response_across_instances_no_duplicate_containment",
            len(execution_ids) == 1 and len(rows) == 1 and len(commands) == 1
            and all(s in (200, 409) for s in exec_statuses),
            statuses=exec_statuses,
            distinct_execution_ids=len(execution_ids),
            stored_executions=len(rows),
            apply_commands=len(commands),
        )
        read_a = via_a.request("GET", "/api/v1/responses", params=scope).json()
        read_b = via_b.request("GET", "/api/v1/responses", params=scope).json()
        assert canon(read_a) == canon(read_b) and len(read_a) == 1
        audit_a = via_a.request("GET", "/api/v1/audit", params=scope)
        audit_b = via_b.request("GET", "/api/v1/audit", params=scope)
        assert audit_a.status_code == audit_b.status_code == 200  # hash verified per record
        assert canon(audit_a.json()) == canon(audit_b.json()) and len(audit_a.json()) > 0
        record(
            "06_response_and_audit_consistent_across_instances",
            True,
            audit_records=len(audit_a.json()),
        )

        # ---- tenant isolation through both instances --------------------------------
        for name in ("a", "b"):
            denied = httpx.get(
                f"{direct[name]}/api/v1/incidents", params=scope, headers=other_admin,
                timeout=5, trust_env=False,
            )  # fmt: skip
            assert denied.status_code == 403, denied.text
            own = httpx.get(
                f"{direct[name]}/api/v1/incidents",
                params={"tenant_id": other_tenant, "site_id": other_site},
                headers=other_admin, timeout=5, trust_env=False,
            )  # fmt: skip
            assert own.status_code == 200 and own.json() == []
        record("07_tenant_isolation_through_both_instances", True)

        # ---- kill A while traffic flows through the proxy ---------------------------
        stop = threading.Event()
        counter = {"n": 0}
        posted: list[str] = []
        lock = threading.Lock()

        def traffic_worker() -> None:
            local = Client(proxy, ingest, traffic)
            while not stop.is_set():
                with lock:
                    counter["n"] += 1
                    n = counter["n"]
                event = build_events(tenant, site, f"{scenario}-flow-{n}", "198.51.100.200", 1, asset_id)[0]
                try:
                    r = local.request("POST", "/api/v1/fabric/events", json=envelope_json(event), retries=5)
                    if r.status_code == 201:
                        with lock:
                            posted.append(event.event_id)
                except AssertionError:
                    pass
                time.sleep(0.05)

        workers = [threading.Thread(target=traffic_worker) for _ in range(3)]
        for worker in workers:
            worker.start()
        time.sleep(3)
        killed_pid = procs["a"].pid
        kill_time = time.time()
        os.killpg(killed_pid, signal.SIGKILL)
        procs["a"].wait(timeout=10)
        time.sleep(6)
        stop.set()
        for worker in workers:
            worker.join(timeout=30)
        after = [o for o in traffic if o["t"] >= kill_time]
        successes_after = [o for o in after if o.get("status") == 201]
        first_success_after = min((o["t"] for o in successes_after), default=None)
        failover_seconds = None if first_success_after is None else round(first_success_after - kill_time, 3)
        errors_after = [o for o in after if o.get("status") != 201]
        served_by_b_after = {o.get("upstream") for o in successes_after}
        db_flow = [e.event_id for e in store.list_events(tenant, site) if "-flow-" in e.event_id]
        duplicates = len(db_flow) - len(set(db_flow))
        acked_missing = [e for e in posted if e not in set(db_flow)]
        record(
            "08_traffic_continues_after_instance_A_killed",
            failover_seconds is not None and failover_seconds < 10 and not acked_missing and duplicates == 0,
            killed_pid=killed_pid,
            failover_seconds=failover_seconds,
            requests_total=len(traffic),
            requests_after_kill=len(after),
            successes_after_kill=len(successes_after),
            non_success_attempts_after_kill=len(errors_after),
            upstreams_after_kill=sorted(str(u) for u in served_by_b_after),
            acknowledged_events=len(posted),
            acknowledged_but_missing=len(acked_missing),
            duplicate_rows=duplicates,
        )

        # ---- restart A, prove it rejoins; then B can be lost instead ----------------
        start_instance("a")
        report["facts"]["restarted_a_pid"] = procs["a"].pid
        time.sleep(3)  # nginx fail_timeout window
        seen: set[str] = set()
        for _ in range(30):
            r = ingest_proxy.request(
                "POST", "/api/v1/fabric/events",
                json=envelope_json(build_events(tenant, site, f"{scenario}-rejoin-{uuid.uuid4().hex[:6]}", "198.51.100.201", 1, asset_id)[0]),
            )  # fmt: skip
            seen.add(str(r.headers.get("x-upstream")))
        a_served = any(str(ports["a"]) in u for u in seen)
        assert (
            canon(httpx.get(f"{direct['a']}/api/v1/incidents", params=scope, headers=admin, timeout=5, trust_env=False).json())
            == canon(via_b.request("GET", "/api/v1/incidents", params=scope).json())
        )
        record("09_restarted_instance_A_rejoins", a_served, upstreams=sorted(seen))

        os.killpg(procs["b"].pid, signal.SIGKILL)
        procs["b"].wait(timeout=10)
        time.sleep(3)
        incidents_from_a = via_proxy.request("GET", "/api/v1/incidents", params=scope)
        responses_from_a = via_proxy.request("GET", "/api/v1/responses", params=scope)
        record(
            "10_no_state_depended_solely_on_a_killed_process",
            incidents_from_a.status_code == 200
            and len(incidents_from_a.json()) >= 1
            and len(responses_from_a.json()) == 1,
            incidents_visible=len(incidents_from_a.json()),
            responses_visible=len(responses_from_a.json()),
        )
        report["overall"] = "PASS"
    except BaseException:
        report["overall"] = "FAIL"
        report["instance_a_log_tail"] = tail(logs["a"])
        report["instance_b_log_tail"] = tail(logs["b"])
        raise
    finally:
        report["request_outcomes_sample"] = outcomes[-60:]
        report["request_status_counts"] = {}
        for item in outcomes + traffic:
            key = str(item.get("status"))
            report["request_status_counts"][key] = report["request_status_counts"].get(key, 0) + 1
        for proc in procs.values():
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
