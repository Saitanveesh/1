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


def test_real_capture_event_metadata_is_present_and_bounded() -> None:
    module = load()
    capture = module.FlowCapture()
    with capture.lock:
        capture.recent_events.append({
            "timestamp": "2026-10-11T08:00:00.000Z",
            "interface": "wg0",
            "direction": "inbound",
            "src_ip": "10.77.0.60",
            "dst_ip": "10.77.0.50",
            "protocol": "ICMP",
            "dst_port": None,
            "ip_bytes": 84,
        })
        capture.interface_packets["wg0"] += 1
        capture.raw_frames += 1
    result = capture.snapshot()
    assert result["observed_interfaces"] == {"wg0": 1}
    assert len(result["events"]) == 1
    assert result["events"][0]["src_ip"] == "10.77.0.60"
    assert "payload" not in result["events"][0]
    assert capture.recent_events.maxlen == 250


def test_pc6_pc5_route_records_survive_noisy_host_capture() -> None:
    import time

    module = load()
    capture = module.FlowCapture()
    route = {
        "timestamp": "2026-10-11T04:00:00Z", "interface": "wg0",
        "src_ip": "10.77.0.60", "dst_ip": "10.77.0.50",
        "direction": "inbound", "protocol": "ICMP",
        "dst_port": None, "ip_bytes": 84,
    }
    with capture.lock:
        capture.recent_lab_route.append((time.time(), route))
        for i in range(250):
            capture.recent_events.append({
                "timestamp": "2026-10-11T04:00:00Z",
                "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1",
                "direction": "outbound", "protocol": "TCP",
                "dst_port": i, "interface": "lo", "ip_bytes": 84,
            })
    actual = capture.snapshot()
    assert actual["lab_route_events"] == [route]
    assert all(row["src_ip"] == "127.0.0.1" for row in actual["events"])
