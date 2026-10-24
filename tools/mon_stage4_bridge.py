"""Non-privileged Stage 4 bridge between operator portal and guarded lab services.

User session and Origin validation are enforced by the existing portal handler.
A recent *actual* EVE signature is required for blocking; release is separately
authorized. This module has no sudo or shell execution capability.
"""
from __future__ import annotations

import hmac
import json
import os
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import build_opener, ProxyHandler

from mon_alert_ack import evidence_key

SOURCES = frozenset({"10.77.0.60", "10.77.0.70"})
TARGET = "10.77.0.50"
PORT = 8085
IDS_RULES = frozenset({42000501, 42000502, 42000503})
SOCKET_PATH = Path(os.environ.get("MON_STAGE4_SOCKET", "/run/mon-stage4/control.sock"))
AUDIT = Path(os.environ.get("MON_STAGE4_AUDIT", "/home/pc-2/mon-three/alerts/stage4_actions.jsonl"))


def verify_source(source: object) -> str:
    if not isinstance(source, str) or source not in SOURCES:
        raise ValueError("Containment is restricted to the enrolled training attackers")
    return source


def evidence_for_block(
    signature_key: object, source: str, snapshot: dict, now: float | None = None
) -> dict:
    if not isinstance(signature_key, str) or len(signature_key) > 600 or not signature_key.startswith("ids:"):
        raise ValueError("Select a genuine IDS alert before blocking")
    if snapshot.get("service_state") != "active" or snapshot.get("status") != "RECENT_EVE":
        raise ValueError("Detection sensor is unavailable; block not authorized")
    stamp = time.time() if now is None else now
    for row in snapshot.get("records", []):
        if not isinstance(row, dict) or row.get("event_type") != "alert":
            continue
        if row.get("src_ip") != source or row.get("dst_ip") != TARGET:
            continue
        if row.get("signature_id") not in IDS_RULES or row.get("dst_port") != PORT:
            continue
        if not hmac.compare_digest(evidence_key(row), signature_key):
            continue
        try:
            at = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            age = stamp - at.timestamp()
        except (ValueError, AttributeError, KeyError, TypeError):
            raise ValueError("Detection timestamp invalid") from None
        if not 0 <= age <= 180:
            raise ValueError("Detection is older than three minutes; run a fresh training test")
        return row
    raise ValueError("No matching recent PC-5 training signature was observed")


def gate_request(action: str, source: str, ttl: int | None = None) -> dict:
    verify_source(source)
    req = {"action": action, "source": source}
    if action == "block":
        if type(ttl) is not int or not 30 <= ttl <= 180:
            raise ValueError("Choose a duration of 30–180 seconds")
        req["ttl"] = ttl
    elif action not in ("status", "release"):
        raise ValueError("Unsupported action")
    raw = (json.dumps(req, separators=(",", ":")) + "\n").encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(4)
        connection.connect(str(SOCKET_PATH))
        connection.sendall(raw)
        data = b""
        while not data.endswith(b"\n") and len(data) < 4096:
            chunk = connection.recv(4096 - len(data))
            if not chunk:
                break
            data += chunk
    if not data.endswith(b"\n"):
        raise OSError("The enforcement helper did not respond")
    result = json.loads(data)
    if not result.get("ok"):
        raise ValueError(str(result.get("error", "Firewall rejected the request"))[:160])
    return result


def audit_action(action: str, source: str, result: dict, signature: str | None = None) -> None:
    AUDIT.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = {
        "at": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "action": action,
        "source": source,
        "destination": TARGET,
        "port": PORT,
        "rule_state": result.get("enforcement"),
        "active": bool(result.get("active")),
        "evidence_key": signature if action == "block" else None,
    }
    payload = (json.dumps(record, separators=(",", ":")) + "\n").encode()
    fd = os.open(AUDIT, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, payload) != len(payload):
            raise OSError("Short audit write")
        os.fsync(fd)
    finally:
        os.close(fd)


def recent_audit(source: str) -> list[dict]:
    verify_source(source)
    if not AUDIT.exists():
        return []
    with AUDIT.open("rb") as stream:
        size = AUDIT.stat().st_size
        stream.seek(max(0, size - 512 * 1024))
        if size > 512 * 1024:
            stream.readline()
        lines = stream.read(512 * 1024).splitlines()[-80:]
    result = []
    for raw in lines:
        try:
            row = json.loads(raw)
            if row.get("source") == source and row.get("action") in {"block", "release"}:
                result.append(row)
        except (ValueError, UnicodeError, TypeError):
            continue
    return result[-20:]


def mitigation_status(source: str) -> dict:
    result = gate_request("status", verify_source(source))
    return {
        "source": source, "destination": TARGET, "port": PORT,
        "active": bool(result["active"]),
        "expires_in_seconds": result.get("expires_in_seconds"),
        "enforcement": result["enforcement"],
        "dropped_packets_total": result.get("dropped_packets_total"),
        "dropped_bytes_total": result.get("dropped_bytes_total"),
        "audit": recent_audit(source),
        "scope": "PC-2 forwarding only; source to PC-5 TCP/8085; no other ports blocked",
    }


def mitigation_action(
    action: str, source: str, signature_key: object = None, ttl: int = 120,
    snapshot: dict | None = None, route_verified: bool = False
) -> dict:
    verify_source(source)
    if action == "block":
        if not route_verified:
            raise ValueError("PC-2 monitored forwarding route not verified")
        evidence_for_block(signature_key, source, snapshot or {})
        result = gate_request("block", source, ttl)
        audit_action("block", source, result, str(signature_key))
    elif action == "release":
        result = gate_request("release", source)
        audit_action("release", source, result)
    else:
        raise ValueError("Unsupported action")
    return mitigation_status(source)


def victim_impact(source: str, since: str | None = None) -> dict:
    source = verify_source(source)
    query = {"source": source}
    if since:
        if not isinstance(since, str) or len(since) > 48:
            raise ValueError("Invalid impact window")
        candidate = datetime.fromisoformat(since.replace("Z", "+00:00"))
        if candidate.utcoffset() is None:
            raise ValueError("Invalid impact window")
        query["since"] = candidate.isoformat()
    opener = build_opener(ProxyHandler({}))
    with opener.open(
        "http://10.77.0.50:8085/api/impact?" + urlencode(query), timeout=4
    ) as response:
        body = json.load(response)
    if body.get("status") != "OBSERVED" or body.get("source") != source:
        raise OSError("PC-5 returned invalid impact evidence")
    return body
