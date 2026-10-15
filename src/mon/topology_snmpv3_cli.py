"""One-shot SNMPv3 read-only switch collector. No SNMP SETs or network scans."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import urllib.error
from pathlib import Path

from mon.topology_inventory import switch_inventory_observations
from mon.topology_inventory_cli import upload
from mon.topology_snmpv3 import load_switch_config, poll_switch


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MON authorized read-only SNMPv3 collector")
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--api-url", help="HTTPS MON API; no upload if omitted")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--allow-local-http", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = load_switch_config(args.config_file)
        snapshot = asyncio.run(poll_switch(config))
        records = switch_inventory_observations(
            snapshot,
            tenant_id=args.tenant_id,
            site_id=args.site_id,
            sensor_id=args.sensor_id,
        )
        if args.api_url:
            if args.token_file is None:
                raise ValueError("token file required to upload")
            inserted, duplicates = upload(
                records, api_url=args.api_url, token_file=args.token_file,
                allow_local_http=args.allow_local_http,
            )
            print(json.dumps({
                "observations": len(records), "inserted": inserted,
                "duplicates": duplicates,
                "switch_id": config.switch_id,
            }))
        else:
            if args.token_file is not None:
                raise ValueError("token file supplied without API URL")
            print(json.dumps(snapshot.model_dump(mode="json")))
        return 0
    except (OSError, ValueError, RuntimeError, TimeoutError, urllib.error.URLError) as exc:
        # Do not print exception: exceptions can contain credential-bearing input.
        print(
            f"MON SNMPv3 switch collection failed ({type(exc).__name__}); "
            "see secured collector diagnostics, no values assumed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
