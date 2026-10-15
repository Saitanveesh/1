"""Passive Linux neighbor-table collector for topology bootstrap.

Reads only the current local kernel neighbor cache. Does not scan or probe
hosts. A discovered IP/MAC pair is not a verified physical workstation or port.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import subprocess
import urllib.parse
import urllib.request
from typing import Any

from mon.topology import TopologyBatch, TopologyObservation


def parse_neighbors(
    raw: str,
    *,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    observed_at: dt.datetime,
) -> TopologyBatch | None:
    items = json.loads(raw)
    if not isinstance(items, list):
        raise ValueError("neighbor command did not return a JSON list")
    observations: list[TopologyObservation] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        address = item.get("dst")
        mac = item.get("lladdr")
        interface = item.get("dev")
        state = item.get("state")
        if not isinstance(address, str) or not isinstance(mac, str) or not isinstance(interface, str):
            continue
        if isinstance(state, list):
            state = ",".join(str(part) for part in state)
        if str(state or "").upper() in {"FAILED", "INCOMPLETE", "NOARP"}:
            continue
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        # IP denotes an observation endpoint, not a conclusively identified device.
        source_record: dict[str, Any] = {
            "dst": address,
            "lladdr": mac.lower(),
            "dev": interface,
            "state": state,
        }
        digest = hashlib.sha256(
            json.dumps(source_record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        obs_id = hashlib.sha256(
            f"{tenant_id}/{site_id}/{sensor_id}/{observed_at.isoformat()}/{digest}".encode()
        ).hexdigest()
        try:
            observations.append(
                TopologyObservation(
                    observation_id=obs_id,
                    tenant_id=tenant_id,
                    site_id=site_id,
                    sensor_id=sensor_id,
                    evidence_id=f"linux-neighbor-sha256:{digest}",
                    observed_at=observed_at,
                    ttl_seconds=300,
                    kind="NODE",
                    node_id=f"ip:{address}",
                    node_type="IP_NEIGHBOR",
                    display_name=address,
                    ip_address=address,
                    mac_address=mac.lower(),
                    interface_name=interface,
                )
            )
        except ValueError:
            # Unusual kernel entries are skipped, never silently corrected.
            continue
    if not observations:
        return None
    if len(observations) > 250:
        raise ValueError("neighbor cache exceeds one bounded ingest batch (250)")
    return TopologyBatch(observations=observations)


def main() -> None:
    parser = argparse.ArgumentParser(description="Read Linux IP neighbors without network probing")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument(
        "--ingest-url",
        help="Optional MON control-plane base URL; requires bearer token and HTTPS",
    )
    args = parser.parse_args()

    output = subprocess.run(
        ["ip", "-j", "neigh", "show"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    batch = parse_neighbors(
        output.stdout,
        tenant_id=args.tenant_id,
        site_id=args.site_id,
        sensor_id=args.sensor_id,
        observed_at=dt.datetime.now(dt.UTC),
    )
    if batch is None:
        print('{"observations": []}')
        return
    payload = json.dumps(batch.model_dump(mode="json"))
    if not args.ingest_url:
        print(payload)
        return

    url = args.ingest_url.rstrip("/") + "/api/v1/topology/observations"
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ValueError("topology ingest requires HTTPS outside loopback")
    token = os.environ.get("MON_TOPOLOGY_TOKEN")
    if not token:
        raise ValueError("MON_TOPOLOGY_TOKEN is required for authenticated ingest")
    request = urllib.request.Request(
        url,
        data=payload.encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        print(response.read().decode())


if __name__ == "__main__":
    main()
