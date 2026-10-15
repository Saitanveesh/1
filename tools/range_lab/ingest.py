"""Opt-in upload of actual isolated lab captures into MON's live event fabric.

This does not manufacture events, assert identity, or grant permission to
observe/attack any ordinary campus device. Capture files are retained locally.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from mon.domain import EventBatch, SecurityEvent
from mon.topology_inventory_cli import _NoRedirect, _read_bearer
from tools.range_lab.analyze_arp import events_from_capture_text
from tools.range_lab.analyze_http import events_from_service_log


def load_captured_events(
    evidence_dir: Path, *,
    target: str,
    tenant_id: str,
    site_id: str,
) -> tuple[list[SecurityEvent], dict[str, str]]:
    if not evidence_dir.is_dir():
        raise ValueError("expected existing lab evidence directory")
    if target not in {"10.253.42.20", "10.253.42.21"}:
        raise ValueError("only an isolated lab victim may be selected")
    files = [
        evidence_dir / "arp-captured-frames.txt",
        evidence_dir / "victim.jsonl",
    ]
    contents: dict[str, str] = {}
    hashes: dict[str, str] = {}
    for path in files:
        if not path.is_file():
            continue
        if path.stat().st_size > 2_000_000:
            raise ValueError(f"bounded evidence file too large: {path.name}")
        raw = path.read_bytes()
        hashes[path.name] = hashlib.sha256(raw).hexdigest()
        contents[path.name] = raw.decode("utf-8")
    if not contents:
        raise ValueError("no real captured evidence files present")
    arp = events_from_capture_text(
        contents.get("arp-captured-frames.txt", ""),
        tenant_id=tenant_id, site_id=site_id,
    )
    http = events_from_service_log(
        contents.get("victim.jsonl", ""),
        target=target, tenant_id=tenant_id, site_id=site_id,
    )
    events = sorted(
        [*arp, *http],
        key=lambda item: (item.observed_at, item.event_id),
    )
    if not events:
        raise ValueError("no actual captured events to ingest")
    return events, hashes


def _url(api_origin: str) -> str:
    parsed = urllib.parse.urlsplit(api_origin)
    if (
        parsed.scheme != "https" or not parsed.hostname
        or parsed.username or parsed.password or parsed.query or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("remote MON ingest requires an HTTPS origin")
    return api_origin.rstrip("/") + "/api/v1/events/batch"


def upload(
    events: list[SecurityEvent], *,
    api_origin: str, token_file: Path,
) -> dict[str, int]:
    endpoint = _url(api_origin)
    token = _read_bearer(token_file)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect,
    )
    batches, accepted = 0, 0
    for start in range(0, len(events), 250):
        batch = EventBatch(events=events[start:start + 250])
        request = urllib.request.Request(
            endpoint,
            data=batch.model_dump_json().encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with opener.open(request, timeout=10) as response:
            result = json.load(response)
            if not isinstance(result, dict):
                raise ValueError("invalid MON ingestion acknowledgement")
        # The API schema may evolve. Do not claim accepted=number sent
        # without reading and validating the actual per-event result.
        batches += 1
        ids = [item.event_id for item in batch.events]
        if (
            not isinstance(result.get("results"), list)
            or result.get("accepted_event_ids") != ids
            or len(result["results"]) != len(ids)
        ):
            raise ValueError("MON did not acknowledge the actual submitted event IDs")
        accepted += len(ids)
    return {"batches_acknowledged": batches, "events_acknowledged": accepted}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MON real isolated-range evidence ingest")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--target", choices=["10.253.42.20", "10.253.42.21"], required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--api-url", help="Approved MON HTTPS origin (omit to preview)")
    parser.add_argument("--token-file", type=Path)
    args = parser.parse_args(argv)
    try:
        events, hashes = load_captured_events(
            args.evidence_dir, target=args.target,
            tenant_id=args.tenant_id, site_id=args.site_id,
        )
        summary: dict[str, object] = {
            "events_from_real_captures": len(events),
            "artifact_sha256": hashes,
            "claim": "packet and victim-side observations only",
            "complete_attack_claim": False,
        }
        if args.api_url:
            if args.token_file is None:
                raise ValueError("protected API token required for upload")
            summary["ingest"] = upload(
                events, api_origin=args.api_url, token_file=args.token_file,
            )
        elif args.token_file is not None:
            raise ValueError("token file provided without API destination")
        print(json.dumps(summary))
        return 0
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f"range evidence ingest refused: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
