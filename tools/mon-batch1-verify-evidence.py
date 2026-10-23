#!/usr/bin/env python3
"""PC-2 evidence gate: correlate live AF_PACKET frames and real Suricata EVE.

Read-only. No simulated traffic, canned results, firewall action or DB write.
Run within 90 seconds of the three authorized PC-6 requests.
"""
from __future__ import annotations

import json
import pathlib
import sys
import time
import urllib.request
from datetime import datetime

TARGET = "10.77.0.50"
LAB_SOURCE = "10.77.0.60"
WEB_PORT = 8085
RULES = {42000501, 42000502, 42000503}
ROOT = pathlib.Path("/home/pc-2/mon-three")
BASE_URL = "http://127.0.0.1:8088"


def fail(message: str) -> None:
    print("NOT VERIFIED: " + message)
    raise SystemExit(2)


def read(path: str, token: str) -> dict:
    request = urllib.request.Request(BASE_URL + path, headers={
        "Cookie": "mon_session=" + token
    })
    with urllib.request.urlopen(request, timeout=6) as response:
        return json.load(response)


def epoch(text: str) -> float:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def main() -> None:
    try:
        token = (ROOT / "identity/operator.jwt").read_text().strip()
        flows = read("/portal/flows", token)
        ids = read("/portal/ids", token)
    except (OSError, ValueError, KeyError) as error:
        fail("authenticated portal snapshot unavailable: " + type(error).__name__)

    if flows.get("source") != "linux-af_packet" or flows.get("status") != "CAPTURING":
        fail("AF_PACKET collector is not capturing")
    if flows.get("protected_host_ip") != TARGET or \
       flows.get("protected_capture_interface") != "wg0" or \
       flows.get("protected_route_check") != "MATCHES_CAPTURE_INTERFACE":
        fail("PC5 scope or selected kernel route differs from wg0")
    if ids.get("service_state") != "active" or ids.get("capture_interface") != "wg0":
        fail("Suricata passive unit or source interface unverified")
    now = time.time()
    events = [
        frame for frame in flows.get("lab_route_events", [])
        if frame.get("interface") == "wg0" and frame.get("protocol") == "TCP"
        and frame.get("dst_port") == WEB_PORT
        and frame.get("src_ip") == LAB_SOURCE and frame.get("dst_ip") == TARGET
        and 0 <= now - epoch(frame["timestamp"]) <= 90
    ]
    alerts = [
        row for row in ids.get("records", [])
        if row.get("event_type") == "alert" and row.get("signature_id") in RULES
        and row.get("src_ip") == LAB_SOURCE and row.get("dst_ip") == TARGET
        and row.get("dst_port") == WEB_PORT
        and 0 <= now - epoch(row["timestamp"]) <= 180
    ]
    if not events:
        fail("no recent PC6->PC5 TCP/8085 frames observed on PC2 wg0")
    if not alerts:
        fail("no fresh PC6->PC5 rule signature in actual Suricata EVE")
    paired = [
        (row, event) for row in alerts for event in events
        if abs(epoch(row["timestamp"]) - epoch(event["timestamp"])) <= 30
    ]
    if not paired:
        fail("IDS signatures exist but cannot be corroborated by independently observed wg0 frames")
    print("PASS: measured PC6->PC5 packet headers and actual Suricata EVE agree.")
    print("AF_PACKET interface: wg0")
    print("Scope:", LAB_SOURCE, "->", TARGET, "tcp/", WEB_PORT)
    print("Matched packet header records:", len(events))
    print("Unique matched signature IDs:", sorted({row["signature_id"] for row, _ in paired}))
    print("Evidence time:", paired[0][0]["timestamp"])
    print("Limitation: this proves IP-frame and IDS event observations, not host identity, a successful exploit, or IPS enforcement.")


if __name__ == "__main__":
    main()
