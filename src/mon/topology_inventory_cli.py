"""One-shot, read-only topology inventory collector.

The caller schedules polling; this tool does not change switches, create
network traffic probes, or conceal partial collection failures.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from mon.topology import TopologyBatch, TopologyObservation
from mon.topology_inventory import (
    SwitchInventory,
    linux_neighbors_observations,
    switch_inventory_observations,
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _read_bearer(path: Path) -> str:
    details = path.stat()
    if not stat.S_ISREG(details.st_mode):
        raise ValueError("token file must be a regular file")
    if os.name == "posix" and stat.S_IMODE(details.st_mode) & 0o077:
        raise ValueError("token file must not be accessible to group/other users")
    token = path.read_text(encoding="utf-8").strip()
    if not token or "\n" in token or "\r" in token:
        raise ValueError("token file must contain one nonempty bearer token")
    return token


def _check_base_url(url: str, *, allow_local_http: bool) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("API URL may not include credentials, query or fragment")
    if parsed.scheme != "https":
        local = parsed.scheme == "http" and parsed.hostname in {
            "localhost", "127.0.0.1", "::1",
        }
        if not (allow_local_http and local):
            raise ValueError("topology upload requires HTTPS (or explicit loopback development mode)")
    if not parsed.hostname:
        raise ValueError("API URL must contain a host")
    if parsed.path not in {"", "/"}:
        raise ValueError("API URL must be the origin, with no path")
    return url.rstrip("/") + "/api/v1/topology/observations"


def upload(
    records: list[TopologyObservation],
    *,
    api_url: str,
    token_file: Path,
    allow_local_http: bool = False,
) -> tuple[int, int]:
    """Submit bounded authenticated batches; reject redirect token forwarding."""
    endpoint = _check_base_url(api_url, allow_local_http=allow_local_http)
    token = _read_bearer(token_file)
    opener = urllib.request.build_opener(_NoRedirect)
    inserted, duplicate = 0, 0
    for i in range(0, len(records), 250):
        payload = TopologyBatch(observations=records[i:i + 250])
        request = urllib.request.Request(
            endpoint,
            data=payload.model_dump_json().encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with opener.open(request, timeout=10) as response:
            result = json.load(response)
            inserted += int(result["inserted"])
            duplicate += int(result["duplicates"])
    return inserted, duplicate


def collect(
    *,
    source: str,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    switch_file: Path | None = None,
) -> list[TopologyObservation]:
    if source == "linux-neighbors":
        if switch_file is not None:
            raise ValueError("--switch-file is only valid for switch-export")
        outcome = subprocess.run(
            ["ip", "-j", "neigh", "show"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return linux_neighbors_observations(
            outcome.stdout, tenant_id=tenant_id, site_id=site_id,
            sensor_id=sensor_id, collected_at=dt.datetime.now(dt.UTC),
        )
    if source == "switch-export":
        if switch_file is None:
            raise ValueError("--switch-file is required for switch-export")
        # Input is an exported read-only management snapshot, not assumed
        # to be collected by this command or to cover all switches.
        if switch_file.stat().st_size > 8_000_000:
            raise ValueError("switch inventory export exceeds 8 MB")
        inventory = SwitchInventory.model_validate_json(
            switch_file.read_text(encoding="utf-8")
        )
        return switch_inventory_observations(
            inventory, tenant_id=tenant_id, site_id=site_id,
            sensor_id=sensor_id,
        )
    raise ValueError("unsupported inventory source")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only MON topology inventory collector")
    parser.add_argument("--source", choices=("linux-neighbors", "switch-export"), required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--switch-file", type=Path)
    parser.add_argument("--api-url", help="MON API origin; omitted for offline JSON output")
    parser.add_argument("--token-file", type=Path, help="Mode 0600 bearer token file")
    parser.add_argument("--allow-local-http", action="store_true")
    args = parser.parse_args(argv)
    try:
        records = collect(
            source=args.source, tenant_id=args.tenant_id, site_id=args.site_id,
            sensor_id=args.sensor_id, switch_file=args.switch_file,
        )
        if args.api_url:
            if args.token_file is None:
                raise ValueError("--token-file is required for API upload")
            inserted, duplicate = upload(
                records, api_url=args.api_url, token_file=args.token_file,
                allow_local_http=args.allow_local_http,
            )
            print(json.dumps({
                "observations_collected": len(records),
                "inserted": inserted,
                "duplicates": duplicate,
            }))
        else:
            if args.token_file is not None:
                raise ValueError("--token-file requires --api-url")
            print(json.dumps({
                "observations": [item.model_dump(mode="json") for item in records],
            }))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, urllib.error.URLError) as exc:
        print(f"topology collection failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
