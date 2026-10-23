"""Prove Suricata signature records survive unrelated flow-log bursts."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from datetime import UTC, datetime

ROOT = pathlib.Path(__file__).resolve().parents[2]
FILE = ROOT / "tools" / "mon_suricata_bridge.py"
spec = importlib.util.spec_from_file_location("mon_suricata_bridge_under_test", FILE)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class SuricataEvidenceTests(unittest.TestCase):
    def test_high_volume_flows_do_not_hide_web_signature(self):
        now = datetime.now(UTC).isoformat()
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "eve.json"
            flow = {
                "timestamp": now, "event_type": "flow", "src_ip": "10.0.1.4",
                "dest_ip": "10.0.1.5", "proto": "TCP", "app_proto": "http",
                "flow": {"pkts_toserver": 2}
            }
            alert = {
                "timestamp": now, "event_type": "alert", "src_ip": "10.0.1.6",
                "dest_ip": "10.0.1.5", "proto": "TCP", "app_proto": "http",
                "alert": {"signature": "MON LAB web probe", "severity": 2}
            }
            with path.open("w") as out:
                for _ in range(20):
                    out.write(json.dumps(flow) + "\n")
                out.write(json.dumps(alert) + "\n")
                for _ in range(140):
                    out.write(json.dumps(flow) + "\n")
            result = module.read_suricata_eve(path)
            self.assertEqual(result["status"], "RECENT_EVE")
            self.assertGreaterEqual(result["alerts"], 1)
            self.assertTrue(any(
                item.get("signature") == "MON LAB web probe"
                for item in result["records"]
            ))


if __name__ == "__main__":
    unittest.main()
