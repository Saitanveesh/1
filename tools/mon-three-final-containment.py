#!/usr/bin/env python3
"""Operator-approved three-PC MON BLOCK_IP / rollback acceptance.

Run from PC2 as pc-2. Only target PC6's lab WireGuard source, 10.77.0.60.
This is NOT an autonomous defense daemon or a production deployment recipe.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

BASE = "http://127.0.0.1:8080"
SCOPE = "?tenant_id=mon-lab&site_id=site-a"
INCIDENT = "9398913b-3fb4-4f01-874f-87f6d71ed646"
TARGET = "10.77.0.60"
VICTIM = "10.77.0.50"
ASSET = "linux-host:lab-pc5"
POINT = "pc2-router"
TTL = 120
HOLD_SECONDS = 35
MON_SERVICE = "mon-three-site-router.service"
ACTIVE = {"DISPATCH_PENDING", "EXECUTING", "APPLIED", "ROLLBACK_PENDING", "ROLLBACK_FAILED"}
ROOT = Path.home() / "mon-three"
EXECUTION_ID: str | None = None
REQUEST_ID: str | None = None
COOKIE: str


def output(status: str, message: str) -> None:
    print(f"[{status}] {message}", flush=True)


def api(method: str, path: str, data: dict | None = None) -> object:
    headers = {"Cookie": "mon_session=" + COOKIE}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        BASE + path,
        data=json.dumps(data).encode() if data is not None else None,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"{method} {path} HTTP {exc.code}: {exc.read(400)!r}"
        ) from exc


def get(path: str) -> object:
    return api("GET", path + SCOPE)


def nft_rules() -> str | None:
    result = subprocess.run(
        ["sudo", "-n", "nft", "-a", "list", "chain", "inet", "mon_router", "mon_block_ip"],
        capture_output=True, text=True, timeout=8, check=False,
    )
    if result.returncode:
        # A nonexistent table/chain is normal BEFORE the first block.
        if "No such file or directory" in result.stderr:
            return None
        raise RuntimeError("nft chain inspection failed: " + result.stderr[:350])
    return result.stdout


def matching_rules(rules: str | None, marker: str | None = None) -> list[str]:
    matches = [
        line.strip() for line in (rules or "").splitlines()
        if f"ip saddr {TARGET} drop" in line
    ]
    if marker:
        matches = [line for line in matches if marker in line]
    return matches


def endpoint_up() -> bool:
    try:
        with socket.create_connection((VICTIM, 22), timeout=4):
            return True
    except OSError:
        return False


def state() -> dict | None:
    executions = get("/api/v1/responses")
    match = [
        r for r in executions
        if isinstance(r, dict)
        and (
            r.get("execution_id") in {EXECUTION_ID, REQUEST_ID}
            or (
                isinstance(r.get("plan"), dict)
                and isinstance(r["plan"].get("request"), dict)
                and r["plan"]["request"].get("request_id") == REQUEST_ID
            )
        )
    ]
    return match[-1] if match else None


def wait_status(allowed: set[str], timeout: int) -> dict | None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = state()
        status = last.get("status") if last else None
        if status in allowed:
            return last
        time.sleep(2)
    return last


def ask_approval() -> None:
    print(
        "\nThe MON policy requires an operator approval for this MEDIUM incident.\n"
        "This command will issue a real, temporary source-IP block:\n"
        f"  SOURCE: PC6 {TARGET}\n"
        f"  VICTIM: PC5 {VICTIM}\n"
        f"  ROUTER: PC2 {POINT}, forward traffic only\n"
        f"  TTL: {TTL} seconds; explicit rollback after {HOLD_SECONDS} seconds\n"
        "It does not block PC2, edit WireGuard, or reset the firewall.\n"
    )
    response = input("To authorize, type exactly 'APPROVE PC6 120S': ").strip()
    if response != "APPROVE PC6 120S":
        output("STOP", "Not approved; no response execution was issued")
        raise SystemExit(0)


def rollback() -> bool:
    global EXECUTION_ID
    try:
        ex = state()
        if ex is None:
            output("WARN", "No execution record found; inspect response/audit state")
            return False
        EXECUTION_ID = ex["execution_id"]
        status = ex.get("status")
        if status == "ROLLED_BACK":
            output("PASS", "MON already reports ROLLED_BACK")
            return True
        if status in {"DISPATCH_PENDING", "EXECUTING"}:
            ex = wait_status({"APPLIED", "FAILED", "DENIED", "ROLLED_BACK"}, 22) or ex
            status = ex.get("status")
        if status in {"FAILED", "DENIED"}:
            output("CHECK", f"MON execution ended {status}; inspect owned nft rule")
            return False
        if status not in {"APPLIED", "ROLLBACK_FAILED", "ROLLBACK_PENDING", "ROLLED_BACK"}:
            output("WARN", f"Execution status {status}; automatic TTL recovery is still configured")
            return False
        if status in {"APPLIED", "ROLLBACK_FAILED"}:
            api(
                "POST",
                f"/api/v1/responses/{EXECUTION_ID}/rollback" + SCOPE,
                {"reason": "Operator-approved lab test complete; restore PC6 connectivity"},
            )
            output("CHECK", "Rollback dispatched through MON")
        result = wait_status({"ROLLED_BACK", "ROLLBACK_FAILED", "FAILED"}, 25)
        status = result.get("status") if result else "UNKNOWN"
        output("CHECK", f"MON rollback result: {status}")
        return status == "ROLLED_BACK"
    except Exception as exc:
        output("WARN", f"Rollback request failed: {exc}")
        return False


def main() -> int:
    global COOKIE, EXECUTION_ID, REQUEST_ID
    if os.getuid() == 0 or os.environ.get("USER") != "pc-2":
        raise RuntimeError("Run as pc-2 on PC2, NOT with sudo")
    token = ROOT / "identity/operator.jwt"
    if not token.is_file():
        raise RuntimeError("MON operator token missing")
    COOKIE = token.read_text().strip()
    print("========== PRE-FLIGHT: NO MUTATIONS ==========", flush=True)
    subprocess.run(["sudo", "-v"], check=True, timeout=60)
    subprocess.run(["sudo", "-n", "nft", "list", "tables"], check=True, timeout=8, capture_output=True)
    active = subprocess.run(
        ["systemctl", "is-active", "--quiet", MON_SERVICE], check=False,
    ).returncode == 0
    if not active:
        raise RuntimeError("MON site router systemd service is not active")
    if not endpoint_up():
        raise RuntimeError("PC2 cannot reach PC5:22 before the block; unsafe to proceed")
    baseline = nft_rules()
    if matching_rules(baseline):
        raise RuntimeError("A PC6 source block already exists; cannot safely run a new test")
    incident = next(
        (item for item in get("/api/v1/incidents") if item.get("incident_id") == INCIDENT),
        None,
    )
    if not incident or TARGET not in incident.get("entities", []):
        raise RuntimeError("PC6 incident association was not confirmed")
    if ASSET not in incident.get("affected_asset_ids", []):
        raise RuntimeError("PC6 incident did not contain the PC5 asset")
    points = get("/api/v1/enforcement-points")
    point = next((p for p in points if p.get("enforcement_point_id") == POINT), None)
    if not point or point.get("vendor") != "linux-nftables-router":
        raise RuntimeError("PC2 router enforcement registration is missing or changed")
    bindings = get("/api/v1/enforcement-bindings")
    if not any(
        b.get("asset_id") == ASSET and b.get("enforcement_point_id") == POINT
        for b in bindings
    ):
        raise RuntimeError("PC5 router enforcement binding is absent")
    for ex in get("/api/v1/responses"):
        req = ex.get("plan", {}).get("request", {})
        if req.get("target", {}).get("ip_address") == TARGET and ex.get("status") in ACTIVE:
            raise RuntimeError("Existing PC6 containment execution is active; refusing overlap")
    output("PASS", "PC6 incident, asset binding, service, baseline access, and nftables verified")

    REQUEST_ID = str(uuid.uuid4())
    request = {
        "request_id": REQUEST_ID,
        "tenant_id": "mon-lab",
        "site_id": "site-a",
        "incident_id": INCIDENT,
        "target": {"ip_address": TARGET},
        "action": "BLOCK_IP",
        "enforcement_point_id": POINT,
        "ttl_seconds": TTL,
        "reason": "Controlled three-PC MON source containment and recovery acceptance",
    }
    plan = api("POST", "/api/v1/responses/plan", request)
    if plan.get("decision", {}).get("outcome") != "REQUIRE_APPROVAL":
        raise RuntimeError(f"Unexpected policy result: {plan.get('decision')}")
    if plan.get("enforcement_point", {}).get("enforcement_point_id") != POINT:
        raise RuntimeError("Plan selected a different enforcement point")
    output("PASS", "Response policy: REQUIRE_APPROVAL")
    ask_approval()

    applied = False
    rolled_back = False
    try:
        # Keep REQUEST_ID even on HTTP timeout: reconcile by ID in finally.
        result = api(
            "POST", "/api/v1/responses/execute",
            {
                "request": request,
                "approve": True,
                "approval_reason": "Explicit lab operator approval for PC6-only, 120-second BLOCK_IP",
            },
        )
        EXECUTION_ID = result.get("execution_id")
        if not EXECUTION_ID:
            raise RuntimeError("MON returned no execution ID")
        output("CHECK", f"Execution: {EXECUTION_ID}; awaiting Site Controller")
        ex = wait_status({"APPLIED", "FAILED", "DENIED"}, 35)
        if ex is None or ex.get("status") != "APPLIED":
            raise RuntimeError(f"MON did not apply block: {ex and ex.get('status')}")
        marker = f"mon:v1:mon-lab:site-a:{EXECUTION_ID}"
        rules = nft_rules()
        found = matching_rules(rules, marker=marker)
        if len(found) != 1:
            raise RuntimeError(f"Expected one MON-owned PC6 rule, found {len(found)}")
        applied = True
        output("PASS", f"MON status APPLIED and owned nftables rule PRESENT: {found[0]}")
        if not endpoint_up():
            raise RuntimeError("PC2 management connectivity to PC5 was disrupted")
        output("PASS", "PC2-to-PC5 management path remains reachable")
        print(
            "\nRUN ON PC6 NOW (before rollback):\n"
            "  nc -zv -w3 10.77.0.50 22\n"
            "Expected DURING block: connection timeout/failure.\n"
            f"Rolling back automatically after {HOLD_SECONDS} seconds.\n",
            flush=True,
        )
        time.sleep(HOLD_SECONDS)
    finally:
        # Rollback even after Ctrl-C or most HTTP/verification failures.
        rolled_back = rollback() if REQUEST_ID else False
        if EXECUTION_ID:
            marker = f"mon:v1:mon-lab:site-a:{EXECUTION_ID}"
            try:
                remaining = matching_rules(nft_rules(), marker=marker)
                if remaining:
                    output("FAIL", f"MON-owned block still PRESENT: {remaining}")
                    rolled_back = False
                else:
                    output("PASS", "MON-owned PC6 rule ABSENT after rollback")
            except Exception as exc:
                output("WARN", f"Cannot verify nft state: {exc}")
                rolled_back = False
        if not endpoint_up():
            output("FAIL", "PC2-to-PC5 management path is not reachable after rollback")
            rolled_back = False

    output("CHECK", "PC6 must independently verify restored SSH reachability now:")
    print("  nc -zv -w3 10.77.0.50 22", flush=True)
    ex = state()
    if ex:
        output("CHECK", f"Final MON response status: {ex.get('status')}")
    try:
        audit = get("/api/v1/audit")
        events = [a for a in audit if a.get("object_id") == EXECUTION_ID]
        output("CHECK", f"Audit records for this execution: {len(events)}")
        for e in events:
            print(f"  {e.get('action')}: {e.get('outcome')}")
    except Exception as exc:
        output("WARN", f"Audit inspection failed: {exc}")
    if applied and rolled_back:
        output("PASS", "MON applied AND rolled back the real PC6 source block")
        output("CHECK", "PC6's independent blocked/restored packet tests still require confirmation")
        return 0
    output("FAIL", "Final block/rollback acceptance not fully verified; inspect MON response state")
    return 2


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        output("CHECK", "Interrupted; script's finally block requests rollback if dispatched")
        raise SystemExit(130)
    except Exception as exc:
        output("FAIL", str(exc))
        raise SystemExit(2)
