"""Parse real tcpdump ARP captures into MON's existing detector.

The parser consumes a bounded text transcription of captured packets, not
synthesized events. It never infers a completed MITM from ARP alone.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path

from mon.detection import DetectionEngine
from mon.domain import EvidenceClass, EvidenceRef, SecurityEvent

_ARP_REPLY = re.compile(
    r"ARP,\s+Reply\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+is-at\s+"
    r"(?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
)
_TIMESTAMP = re.compile(r"^\s*(\d{10,12}(?:\.\d+)?)\s+")


def events_from_capture_text(
    text: str, *, tenant_id: str = "isolated-range",
    site_id: str = "local-veth-lab",
) -> list[SecurityEvent]:
    """Preserve source capture timestamps and only literal ARP reply claims."""
    if len(text) > 2_000_000:
        raise ValueError("capture transcription exceeds 2 MB")
    events = []
    for index, line in enumerate(text.splitlines()):
        match = _ARP_REPLY.search(line)
        time_match = _TIMESTAMP.match(line)
        if not match or not time_match:
            continue
        try:
            ip = match.group("ip")
            mac = match.group("mac").lower()
            import ipaddress

            ipaddress.IPv4Address(ip)
            observed_at = dt.datetime.fromtimestamp(
                float(time_match.group(1)), tz=dt.UTC
            )
        except (ValueError, OverflowError, OSError):
            continue
        evidence = EvidenceRef(
            evidence_class=EvidenceClass.NETWORK_PACKET,
            source="isolated-lab-tcpdump",
            summary=f"Captured ARP reply claims {ip} at {mac}",
            confidence=0.90,
            observed_at=observed_at,
            raw_reference="arp-packets.pcap",
        )
        events.append(SecurityEvent(
            event_id=f"range-arp-{index:08d}",
            tenant_id=tenant_id, site_id=site_id,
            sensor_id="range-arp-passive",
            observed_at=observed_at,
            src_ip=ip,
            protocol="arp",
            category="arp.reply",
            evidence=[evidence],
            attributes={
                "arp_opcode": 2,
                "arp_sender_ip": ip,
                "arp_sender_mac": mac,
            },
        ))
        if len(events) >= 10_000:
            break
    return events


def findings_from_capture_text(text: str) -> dict[str, object]:
    events = events_from_capture_text(text)
    detector = DetectionEngine()
    findings = []
    for event in events:
        findings.extend(detector.process(event))
    return {
        "source": "REAL_CAPTURE_TRANSCRIPTION_REQUIRED",
        "arp_replies_observed": len(events),
        "finding_count": len(findings),
        "findings": [finding.model_dump(mode="json") for finding in findings],
        "claim": (
            "ARP mapping conflicts indicate a potential on-path attack or "
            "legitimate mobility/failover; MITM requires separate packet-path proof"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tcpdump-text", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data = args.tcpdump_text.read_text(encoding="utf-8")
    result = findings_from_capture_text(data)
    args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({
        "arp_replies_observed": result["arp_replies_observed"],
        "finding_count": result["finding_count"],
    }))


if __name__ == "__main__":
    main()
