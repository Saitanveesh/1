"""Analyze genuine isolated HTTP victim logs with MON's detector."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path

from mon.detection import DetectionEngine
from mon.domain import EvidenceClass, EvidenceRef, SecurityEvent


def events_from_service_log(
    data: str, *, target: str,
    tenant_id: str = "isolated-range",
    site_id: str = "local-veth-lab",
) -> list[SecurityEvent]:
    if target not in {"10.253.42.20", "10.253.42.21"}:
        raise ValueError("victim must be one of the disposable namespaces")
    if len(data) > 2_000_000:
        raise ValueError("log too large")
    events = []
    for line_number, raw in enumerate(data.splitlines(), 1):
        try:
            row = json.loads(raw)
            if not isinstance(row, dict):
                continue
            ip = str(ipaddress.IPv4Address(row["src_ip"]))
            instant = dt.datetime.fromisoformat(row["observed_at"])
            if instant.utcoffset() is None:
                continue
            status = row["status"]
            elapsed = float(row["elapsed_ms"])
            if (not isinstance(status, int)
                or not 100 <= status <= 599
                or not 0 <= elapsed <= 20000):
                continue
        except (ValueError, KeyError, TypeError, OverflowError):
            continue
        evidence = EvidenceRef(
            source="range-victim-http-server",
            evidence_class=EvidenceClass.ENDPOINT,
            summary="Victim recorded actual completed HTTP request",
            confidence=0.93,
            observed_at=instant,
            raw_reference=f"victim.jsonl:line-{line_number}",
        )
        stable_id = hashlib.sha256(
            f"range-http:{line_number}:{raw}".encode()
        ).hexdigest()
        events.append(SecurityEvent(
            event_id=stable_id,
            tenant_id=tenant_id,
            site_id=site_id,
            sensor_id="victim-http-service",
            observed_at=instant,
            category="app.http-request",
            src_ip=ip,
            dst_ip=target,
            protocol="tcp",
            attributes={
                "dst_port": 8081,
                "http_status": status,
                "elapsed_ms": round(elapsed, 3),
            },
            evidence=[evidence],
        ))
    return events


def analyze(data: str, target: str) -> dict[str, object]:
    events = events_from_service_log(data, target=target)
    detector = DetectionEngine()
    findings = []
    for event in events:
        findings.extend(detector.process(event))
    observed = sorted({event.src_ip for event in events if event.src_ip})
    return {
        "source": "VICTIM_SIDE_REAL_HTTP_LOG",
        "requests_recorded": len(events),
        "source_ips_observed": observed,
        "finding_count": len(findings),
        "findings": [item.model_dump(mode="json") for item in findings],
        "claim": (
            "Bounded multi-source service pressure may be present; "
            "not verified upstream volumetric DDoS or confirmed service outage"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.log.read_text(encoding="utf-8"), args.target)
    args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({
        "requests_recorded": result["requests_recorded"],
        "sources": len(result["source_ips_observed"]),
        "finding_count": result["finding_count"],
    }))


if __name__ == "__main__":
    main()
