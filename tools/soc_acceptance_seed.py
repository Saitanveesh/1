# ruff: noqa: E501
"""Deterministic SOC acceptance scenario seeder (disposable CI only).

Drives a *real running* MON control plane over HTTP exactly as a site controller and
operators would: fabric ingest -> detection/correlation -> enforcement registration ->
response planning/approval/dispatch -> real Site Controller executor with the real
nftables adapter in a disposable network namespace -> results posted back -> rollback.
It writes ``seed.json`` for the browser acceptance test. Tokens written there are
short-lived test JWTs for the disposable JWKS created by the ``keys`` subcommand.

    python tools/soc_acceptance_seed.py keys --dir DIR
    python tools/soc_acceptance_seed.py seed --dir DIR --backend URL --namespace NS
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER, AUDIENCE, KID = "mon-soc-acceptance", "mon-control-plane", "soc-key-1"
TENANT_A, SITE_A = "soc-tenant-a", "soc-site-a"
TENANT_B, SITE_B = "soc-tenant-b", "soc-site-b"
ASSET_ID = "linux-host:soc-web-01"
SRC_IP = "203.0.113.50"
VENDOR = "linux-nftables-soc"
TENANT_B_TITLE = "TENANT-B-CONFIDENTIAL-INCIDENT"


def make_keys(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (directory / "private.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    (directory / "jwks.json").write_text(json.dumps({"keys": [jwk]}))


def token(private_pem: str, *, tenant: str, subject: str, roles: list[str], sites: list[str]) -> str:
    now = dt.datetime.now(dt.UTC)
    return jwt.encode(
        {
            "sub": subject,
            "tenant_id": tenant,
            "roles": roles,
            "site_ids": sites,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + dt.timedelta(hours=2),
        },
        private_pem,
        algorithm="RS256",
        headers={"kid": KID},
    )


def must(response: httpx.Response, *ok: int) -> Any:
    if response.status_code not in (ok or (200, 201)):
        raise SystemExit(f"{response.request.method} {response.request.url} -> {response.status_code}: {response.text[:500]}")
    return response.json()


def seed(directory: Path, backend: str, namespace: str) -> None:
    from mon.connectors.nftables_endpoint import LinuxNftablesEndpointAdapter
    from mon.domain import EnforcementKind, EnforcementVerificationState, ResponseExecutionStatus
    from mon.endpoint import EndpointEventKind, EndpointTelemetryEvent, normalize_endpoint_event
    from mon.enforcement import EnforcementRegistry
    from mon.event_fabric import security_event_envelope
    from mon.site_command_models import SiteCommand
    from mon.site_response import SiteResponseExecutor
    from mon.site_response_store import SQLiteSiteResponseStore

    private_pem = (directory / "private.pem").read_text()
    admin = token(private_pem, tenant=TENANT_A, subject="soc-operator-a", roles=["tenant_admin"], sites=[])
    site = token(private_pem, tenant=TENANT_A, subject="soc-site-controller-a", roles=["site_controller"], sites=[SITE_A])
    admin_b = token(private_pem, tenant=TENANT_B, subject="soc-operator-b", roles=["tenant_admin"], sites=[])
    h_admin, h_site, h_admin_b = ({"Authorization": f"Bearer {t}"} for t in (admin, site, admin_b))
    scope = {"tenant_id": TENANT_A, "site_id": SITE_A}
    client = httpx.Client(base_url=backend, timeout=30, trust_env=False)

    # 1. sensor telemetry -> fabric ingest (same path the Site Controller uses)
    base = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=45)
    scenario = f"soc-{uuid.uuid4().hex[:8]}"
    for index in range(8):
        telemetry = EndpointTelemetryEvent(
            tenant_id=TENANT_A,
            site_id=SITE_A,
            sensor_id="soc-endpoint-sensor-1",
            event_id=f"{scenario}-auth-{index}",
            observed_at=base + dt.timedelta(seconds=5 * index),
            kind=EndpointEventKind.AUTH_FAILURE,
            asset_id=ASSET_ID,
            hostname="soc-web-01",
            src_ip=SRC_IP,
            user_name="root",
            outcome="failure",
            source="sshd",
        )
        envelope = security_event_envelope(
            normalize_endpoint_event(telemetry), produced_at=dt.datetime.now(dt.UTC)
        )
        must(client.post("/api/v1/fabric/events", json=envelope.model_dump(mode="json"), headers=h_site), 201)

    incidents = must(client.get("/api/v1/incidents", params=scope, headers=h_admin))
    matching = [i for i in incidents if ASSET_ID in i["affected_asset_ids"]]
    if len(matching) != 1:
        raise SystemExit(f"expected exactly one incident, got {len(matching)}")
    incident = matching[0]

    # 2. enforcement point + binding, plan, approve, dispatch
    point_id = f"{scenario}-fw"
    must(client.post("/api/v1/enforcement-points", headers=h_admin, json={
        "enforcement_point_id": point_id, "tenant_id": TENANT_A, "site_id": SITE_A,
        "kind": "FIREWALL", "vendor": VENDOR, "capabilities": ["BLOCK_IP"],
    }), 201)
    must(client.post("/api/v1/enforcement-bindings", headers=h_admin, json={
        "tenant_id": TENANT_A, "site_id": SITE_A, "asset_id": ASSET_ID,
        "enforcement_point_id": point_id,
        "attributes": {"blast_radius_estimate": "single suspicious source IP"},
    }), 201)
    request = {
        "request_id": f"{scenario}-response", "tenant_id": TENANT_A, "site_id": SITE_A,
        "incident_id": incident["incident_id"], "target": {"ip_address": SRC_IP},
        "action": "BLOCK_IP", "ttl_seconds": 300, "reason": "SOC acceptance containment",
    }
    plan = must(client.post("/api/v1/responses/plan", json=request, headers=h_admin))
    execution = must(client.post("/api/v1/responses/execute", headers=h_admin, json={
        "request": request, "approve": True, "approval_reason": "operator reviewed identity evidence",
    }))
    execution_id = execution["execution_id"]

    # 3. real Site Controller executor + real nftables adapter (disposable netns)
    state_dir = directory / "site-state"
    state_dir.mkdir(exist_ok=True)
    response_store = SQLiteSiteResponseStore(state_dir / "response-state.db", tenant_id=TENANT_A, site_id=SITE_A)
    adapter = LinuxNftablesEndpointAdapter(namespace=namespace)
    registry = EnforcementRegistry()
    registry.register(EnforcementKind.FIREWALL, VENDOR, adapter, capabilities=adapter.capabilities)
    executor = SiteResponseExecutor(TENANT_A, SITE_A, response_store, registry)

    async def site_cycle() -> dict[str, str]:
        states: dict[str, str] = {}

        def pending(kind: str) -> SiteCommand:
            rows = must(client.get("/api/v1/site-commands/pending", params=scope, headers=h_site))
            found = [r for r in rows if r["kind"] == kind]
            if len(found) != 1:
                raise SystemExit(f"expected one pending {kind}, got {len(found)}")
            return SiteCommand.model_validate(found[0])

        apply_cmd = pending("APPLY_RESPONSE")
        result = await executor.execute(apply_cmd)
        assert result.success and result.execution is not None
        assert result.execution.status is ResponseExecutionStatus.APPLIED
        must(client.post("/api/v1/site-commands/results", json=json.loads(result.model_dump_json()), headers=h_site))
        states["after_apply"] = (await adapter.verify(apply_cmd.response_plan, execution_id)).state.value
        assert states["after_apply"] == EnforcementVerificationState.PRESENT.value

        must(client.post(f"/api/v1/responses/{execution_id}/rollback", params=scope, headers=h_admin,
                         json={"reason": "SOC acceptance recovery"}))
        rollback_cmd = pending("ROLLBACK_RESPONSE")
        rolled = await executor.execute(rollback_cmd)
        assert rolled.success and rolled.execution is not None
        assert rolled.execution.status is ResponseExecutionStatus.ROLLED_BACK
        must(client.post("/api/v1/site-commands/results", json=json.loads(rolled.model_dump_json()), headers=h_site))
        states["after_rollback"] = (await adapter.verify(apply_cmd.response_plan, execution_id)).state.value
        assert states["after_rollback"] == EnforcementVerificationState.ABSENT.value
        return states

    verification = asyncio.run(site_cycle())

    # 4. tenant B confidential incident (must never be visible to tenant A operators)
    must(client.post("/api/v1/incidents", headers=h_admin_b, json={
        "tenant_id": TENANT_B, "site_id": SITE_B, "title": TENANT_B_TITLE,
        "severity": "LOW", "confidence": 0.5,
    }), 201)

    final = must(client.get("/api/v1/responses", params=scope, headers=h_admin))
    audit = must(client.get("/api/v1/audit", params=scope, headers=h_admin))
    (directory / "seed.json").write_text(json.dumps({
        "tenant_a": TENANT_A, "site_a": SITE_A, "tenant_b": TENANT_B, "site_b": SITE_B,
        "incident_id": incident["incident_id"], "incident_title": incident["title"],
        "asset_id": ASSET_ID, "src_ip": SRC_IP, "execution_id": execution_id,
        "enforcement_point_id": point_id, "policy_outcome": plan["decision"]["outcome"],
        "final_execution_status": [r["status"] for r in final if r["execution_id"] == execution_id][0],
        "audit_actions": [f"{a['action']}:{a['outcome']}" for a in audit],
        "independent_verification": verification,
        "tenant_b_title": TENANT_B_TITLE,
        "token_operator_a": admin, "token_operator_b": admin_b,
        "seeded_at": time.time(),
    }, indent=2))
    print("seed complete:", json.dumps({k: verification[k] for k in verification}))


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    keys = sub.add_parser("keys")
    keys.add_argument("--dir", type=Path, required=True)
    seed_cmd = sub.add_parser("seed")
    seed_cmd.add_argument("--dir", type=Path, required=True)
    seed_cmd.add_argument("--backend", required=True)
    seed_cmd.add_argument("--namespace", required=True)
    args = parser.parse_args()
    if args.cmd == "keys":
        make_keys(args.dir)
    else:
        seed(args.dir, args.backend, args.namespace)
    return 0


if __name__ == "__main__":
    sys.exit(main())
