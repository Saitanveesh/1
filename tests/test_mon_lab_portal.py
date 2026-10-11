from __future__ import annotations

import importlib.util
import socket
import struct
from pathlib import Path

PORTAL = Path(__file__).resolve().parents[1] / "tools" / "mon-lab-portal.py"


def load():
    spec = importlib.util.spec_from_file_location("mon_lab_portal_for_test", PORTAL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_lab_password_verifier_is_salted_and_not_plaintext() -> None:
    module = load()
    password_hash = module.hash_password("lab-secret")
    assert password_hash.startswith("scrypt:")
    assert "lab-secret" not in password_hash
    assert module.verify_password("lab-secret", password_hash)
    assert not module.verify_password("incorrect", password_hash)
    assert module.hash_password("lab-secret") != password_hash


def test_capture_ipv4_tcp_header_without_payload_or_fake_counts() -> None:
    module = load()
    header = bytearray(20)
    header[0] = 0x45
    struct.pack_into("!H", header, 2, 40)
    header[9] = 6
    header[12:16] = socket.inet_aton("10.77.0.60")
    header[16:20] = socket.inet_aton("10.77.0.50")
    tcp = struct.pack("!HH", 59000, 22) + b"\x00" * 16
    parsed = module.parse_packet(bytes(header) + tcp, 0)
    assert parsed == ("10.77.0.60", "10.77.0.50", "TCP", 22, 40)
    assert module.parse_packet(bytes(header) + tcp, socket.PACKET_OUTGOING) == parsed


def test_no_packets_means_zero_measurements_not_synthetic_flows() -> None:
    module = load()
    capture = module.FlowCapture()
    capture._flush(capture.current_start + 1)
    snapshot = capture.snapshot()
    assert snapshot["samples"]
    assert snapshot["samples"][0]["packets"] == 0
    assert snapshot["samples"][0]["bytes"] == 0
    assert snapshot["flows"] == []


def test_packet_counters_and_grafana_metrics_expose_real_observations_only() -> None:
    module = load()
    capture = module.FlowCapture()
    assert "mon_capture_up 0" in capture.metrics()
    assert 'mon_capture_packets_total{direction="inbound"} 0' in capture.metrics()
    assert 'mon_capture_packets_total{direction="outbound"} 0' in capture.metrics()
    with capture.lock:
        capture.current[("10.77.0.60", "10.77.0.50", "ICMP", None, "outbound")] = 1
        capture.bytes[("10.77.0.60", "10.77.0.50", "ICMP", None, "outbound")] = 84
        capture.packet_totals["outbound"] = 1
        capture.byte_totals["outbound"] = 84
        capture.raw_frames = 1
    capture._flush(capture.current_start + 1)
    snapshot = capture.snapshot()
    assert snapshot["flows"][0]["direction"] == "outbound"
    assert snapshot["samples"][-1]["packets"] == 1
    assert 'mon_capture_packets_total{direction="outbound"} 1' in capture.metrics()
