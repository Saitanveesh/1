import importlib.util
import json
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1] / "tools" / "mon_suricata_bridge.py"


def bridge():
    spec = importlib.util.spec_from_file_location("mon_suricata_bridge", MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bridge_reports_uninstalled_not_fake_success(tmp_path):
    state = bridge().read_suricata_eve(tmp_path / "not-created.json")
    assert state["status"] == "NOT_INSTALLED"
    assert state["alerts"] == 0
    assert state["records"] == []


def test_bridge_extracts_only_real_flow_and_alert_metadata(tmp_path):
    path = tmp_path / "eve.json"
    rows = [
        {
            "timestamp": "2026-10-11T10:00:00.000000+0000",
            "event_type": "flow",
            "src_ip": "10.77.0.60",
            "src_port": 55001,
            "dest_ip": "10.77.0.50",
            "dest_port": 22,
            "proto": "TCP",
            "flow": {
                "pkts_toserver": 4,
                "pkts_toclient": 3,
                "bytes_toserver": 320,
                "bytes_toclient": 241,
                "state": "closed",
            },
            "payload": "DO NOT INCLUDE PRIVATE PAYLOAD",
        },
        {
            "timestamp": "2026-10-11T10:00:10.000000+0000",
            "event_type": "alert",
            "src_ip": "10.77.0.60",
            "dest_ip": "10.77.0.50",
            "proto": "TCP",
            "alert": {
                "signature": "Example IDS rule",
                "signature_id": 123,
                "severity": 2,
            },
        },
        {
            "timestamp": "2026-10-11T10:00:11.000000+0000",
            "event_type": "stats",
            "stats": {"capture": {"kernel_packets": 800}},
        },
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    result = bridge().read_suricata_eve(path)
    assert result["status"] == "RECENT_EVE"
    assert result["observed_events"] == 2
    assert result["alerts"] == 1
    assert result["records"][0]["signature"] == "Example IDS rule"
    assert result["records"][1]["pkts_toserver"] == 4
    assert "DO NOT INCLUDE PRIVATE PAYLOAD" not in json.dumps(result)
    assert "payload" not in json.dumps(result)


def test_malformed_eve_json_does_not_crash_or_fabricate_events(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text('not json\n{"event_type":"flow","src_ip":"10.77.0.60"}\n')
    data = bridge().read_suricata_eve(path)
    assert data["records"] == []
    assert data["alerts"] == 0


def test_configured_idle_sensor_is_distinct_from_never_installed(tmp_path):
    marker = tmp_path / ".mon-passive-configured"
    marker.write_text("configured")
    result = bridge().read_suricata_eve(tmp_path / "eve.json")
    assert result["status"] == "CONFIGURED_NO_EVE"
    assert result["alerts"] == 0
