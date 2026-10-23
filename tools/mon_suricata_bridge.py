"""Read bounded, untrusted Suricata EVE records for MON's read-only SOC dashboard.

The sensor is a separate passive libpcap service. No packet reinjection,
command execution, external lookups or firewall modifications occur here.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

LOG_PATH = Path(
    os.environ.get(
        "MON_SURICATA_EVE_PATH",
        "/home/pc-2/mon-three/suricata/eve.json",
    )
)
MAX_BYTES = 2097152
MAX_RECORDS = 60
MAX_ALERTS = 30
MAX_OTHER = MAX_RECORDS - MAX_ALERTS
EVENT_TYPES = {"alert", "flow", "dns", "tls", "http"}


def small(value: object, limit: int = 120) -> str:
    if not isinstance(value, (str, int, float)):
        return ""
    return str(value)[:limit]


def safe_port(value: object) -> int | None:
    if type(value) is int and 0 <= value <= 65535:
        return value
    return None


def read_suricata_eve(path: Path = LOG_PATH) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": "suricata-eve",
        "status": "NOT_INSTALLED",
        "observed_events": 0,
        "alerts": 0,
        "last_seen": None,
        "records": [],
        "capture_interface": "wg0",
        "scope": "Passive sensor on PC2; not inline packet enforcement",
    }
    try:
        configured = (path.parent / ".mon-passive-configured").is_file()
        if configured:
            payload["status"] = "CONFIGURED_NO_EVE"
        st = path.stat()
        if not path.is_file():
            return payload
        payload["status"] = "NO_RECENT_EVENTS"
        with path.open("rb") as handle:
            position = max(0, st.st_size - MAX_BYTES)
            handle.seek(position)
            if position:
                handle.readline()  # Drop partial first JSON row.
            data = handle.read(MAX_BYTES)
    except (OSError, PermissionError):
        return payload

    rows = data.splitlines()[-3000:]
    latest_ts: str | None = None
    last_created = st.st_mtime
    recent_alerts: list[dict[str, Any]] = []
    other_records: list[dict[str, Any]] = []
    for raw in reversed(rows):
        if len(recent_alerts) >= MAX_ALERTS and len(other_records) >= MAX_OTHER:
            break
        if len(raw) > 20000:
            continue
        try:
            event = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("event_type")
        if kind not in EVENT_TYPES:
            continue
        source = small(event.get("src_ip"), 48)
        target = small(event.get("dest_ip"), 48)
        if not source or not target:
            continue
        timestamp = small(event.get("timestamp"), 48)
        if latest_ts is None:
            latest_ts = timestamp
        item: dict[str, Any] = {
            "event_type": kind,
            "timestamp": timestamp,
            "src_ip": source,
            "src_port": safe_port(event.get("src_port")),
            "dst_ip": target,
            "dst_port": safe_port(event.get("dest_port")),
            "protocol": small(event.get("proto"), 20),
            "application": small(event.get("app_proto"), 40),
            "community_id": small(event.get("community_id"), 90),
        }
        if kind == "alert":
            alert = event.get("alert")
            if isinstance(alert, dict):
                item["signature"] = small(alert.get("signature"), 180)
                item["signature_id"] = alert.get("signature_id")
                item["severity"] = alert.get("severity")
                item["category"] = small(alert.get("category"), 80)
        if kind == "flow":
            flow = event.get("flow")
            if isinstance(flow, dict):
                item["pkts_toserver"] = flow.get("pkts_toserver")
                item["pkts_toclient"] = flow.get("pkts_toclient")
                item["bytes_toserver"] = flow.get("bytes_toserver")
                item["bytes_toclient"] = flow.get("bytes_toclient")
                item["flow_state"] = small(flow.get("state"), 30)
        # Reserve a bounded, separate window for signature alerts. Otherwise
        # ordinary flow telemetry crowds out high-value detections.
        if kind == "alert" and len(recent_alerts) < MAX_ALERTS:
            recent_alerts.append(item)
        elif kind != "alert" and len(other_records) < MAX_OTHER:
            other_records.append(item)
    payload["records"] = sorted(
        recent_alerts + other_records,
        key=lambda item: item["timestamp"], reverse=True,
    )
    payload["alerts"] = len(recent_alerts)
    payload["observed_events"] = len(payload["records"])
    payload["last_seen"] = latest_ts
    if payload["records"] and time.time() - last_created <= 300:
        payload["status"] = "RECENT_EVE"
    return payload
