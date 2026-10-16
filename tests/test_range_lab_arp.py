"""No imaginary MITM claims: captured ARP mappings require real evidence."""
import datetime as dt
import struct

import pytest

from mon.detection import DetectionEngine
from tools.range_lab.analyze_arp import events_from_capture_text, findings_from_capture_text
from tools.range_lab.arp_lab import build_arp_reply

TS = dt.datetime(2026, 10, 15, 12, tzinfo=dt.UTC).timestamp()


def test_arp_frame_is_real_ethernet_header_and_arp_reply():
    mac = "02:11:22:33:44:55"
    frame = build_arp_reply(
        mac, "10.253.42.20", "02:aa:bb:cc:dd:ee", "10.253.42.10",
    )
    assert len(frame) == 42
    assert frame[12:14] == struct.pack("!H", 0x0806)
    assert frame[20:22] == struct.pack("!H", 2)
    with pytest.raises(ValueError, match="refusing"):
        build_arp_reply(mac, "10.0.0.20", mac, "10.253.42.10")


def test_capture_conflicting_mapping_triggers_evidence_not_confirmed_mitm():
    # This is a parser unit-test fixture, NOT live captured telemetry.
    transcript = (
        f"{TS:.6f} 00:11:22:33:44:55 > Broadcast, ethertype ARP (0x0806), "
        "length 42: ARP, Reply 10.253.42.20 is-at 02:aa:bb:cc:dd:01, length 28\n"
        f"{TS + 0.5:.6f} 00:11:22:33:44:66 > Broadcast, ethertype ARP (0x0806), "
        "length 42: ARP, Reply 10.253.42.20 is-at 02:aa:bb:cc:dd:02, length 28\n"
    )
    report = findings_from_capture_text(transcript)
    assert report["arp_replies_observed"] == 2
    finding = next(
        item for item in report["findings"]
        if item["detector_id"] == "arp-binding-conflict"
    )
    assert finding["confidence"] == 0.83
    assert "not confirmed MITM" in finding["attributes"]["claim"]
    assert any(
        item["raw_reference"] == "arp-packets.pcap"
        for item in finding["evidence"]
    )


def test_parser_accepts_ethernet_mode_tcpdump_reply():
    # tcpdump -e prints ethertype ARP rather than the short 'ARP, Reply' form.
    text = (
        f"{TS:.6f} 02:11:22:33:44:55 > 02:aa:bb:cc:dd:ee, "
        "ethertype ARP (0x0806), length 42: "
        "Reply 10.253.42.20 is-at 02:11:22:33:44:55, length 28"
    )
    events = events_from_capture_text(text)
    assert len(events) == 1
    assert events[0].attributes["arp_sender_mac"] == "02:11:22:33:44:55"


def test_no_evidence_from_uncaptured_or_invalid_packets():
    assert events_from_capture_text("") == []
    text = f"{TS:.6f} ARP, Request who-has 10.253.42.20"
    assert events_from_capture_text(text) == []
    with pytest.raises(ValueError, match="2 MB"):
        events_from_capture_text("x" * 2_000_001)
    engine = DetectionEngine()
    assert engine.process is not None
