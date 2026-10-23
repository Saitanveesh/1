"""Authenticated, evidence-bound acknowledgment journal for MON passive IDS.

Records operator review of a *real observed* Suricata alert. It does not create
a MON incident, acknowledge an unrelated case, or perform traffic enforcement.
"""
from __future__ import annotations

import hmac
import json
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ACK_PATH = Path(os.environ.get(
    "MON_ALERT_ACK_PATH", "/home/pc-2/mon-three/alerts/acknowledged.jsonl"
))
_LOCK = threading.Lock()
MAX_FILE_BYTES = 1024 * 1024
MAX_ENTRIES = 250


def evidence_key(row: dict[str, Any]) -> str:
    """Same deterministic EVE row identity as console/src/suricataThreats.ts."""
    parts = [
        row.get("timestamp"), row.get("signature_id"), row.get("signature"),
        row.get("src_ip"), row.get("src_port"),
        row.get("dst_ip"), row.get("dst_port"),
    ]
    return "ids:" + "|".join("" if part is None else str(part) for part in parts)


def acknowledged_alerts(path: Path = ACK_PATH) -> list[dict[str, str]]:
    """Return bounded, valid journal entries; never trust arbitrary file rows."""
    try:
        if not path.is_file():
            return []
        with path.open("rb") as stream:
            size = path.stat().st_size
            stream.seek(max(0, size - MAX_FILE_BYTES))
            if size > MAX_FILE_BYTES:
                stream.readline()
            rows = stream.read(MAX_FILE_BYTES).splitlines()[-MAX_ENTRIES:]
    except OSError:
        return []
    result: dict[str, dict[str, str]] = {}
    for raw in rows:
        try:
            item = json.loads(raw)
            key, when = item["key"], item["acknowledged_at"]
            if isinstance(key, str) and key.startswith("ids:") and \
               isinstance(when, str) and len(key) <= 600:
                result[key] = {"key": key, "acknowledged_at": when}
        except (KeyError, ValueError, TypeError, UnicodeDecodeError):
            continue
    return list(result.values())[-MAX_ENTRIES:]


def acknowledge_eve_alert(
    key: str,
    snapshot: dict[str, Any],
    target_ip: str | None,
    path: Path = ACK_PATH
) -> dict[str, str]:
    """Accept an ID only when it is in the *currently read* Suricata EVE log."""
    if not isinstance(key, str) or not key.startswith("ids:") or len(key) > 600:
        raise ValueError("invalid IDS alert identity")
    if snapshot.get("service_state") != "active" or not target_ip:
        raise ValueError("active IDS / protected destination not verified")
    matching = [
        row for row in snapshot.get("records", [])
        if row.get("event_type") == "alert" and
        row.get("dst_ip") == target_ip and
        hmac.compare_digest(evidence_key(row), key)
    ]
    if not matching:
        raise ValueError("IDS signature not found in current EVE evidence")
    try:
        event_at = datetime.fromisoformat(matching[0]["timestamp"].replace("Z", "+00:00"))
        age = time.time() - event_at.timestamp()
        if not 0 <= age <= 900:
            raise ValueError("IDS signature outside 15-minute review window")
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("invalid IDS event timestamp") from None
    with _LOCK:
        for existing in acknowledged_alerts(path):
            if hmac.compare_digest(existing["key"], key):
                return existing
        now = datetime.now(UTC).isoformat(timespec="milliseconds")
        item = {"key": key, "acknowledged_at": now}
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            os.chmod(path, 0o600)
            stream.write(json.dumps(item, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return item
