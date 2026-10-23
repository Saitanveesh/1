"""Acknowledge only records already observed, target-scoped Suricata signatures."""
import importlib.util
import pathlib
import tempfile
import unittest
from datetime import UTC, datetime, timedelta

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("mon_alert_ack_test", ROOT / "tools" / "mon_alert_ack.py")
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class AcknowledgmentJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "ack.jsonl"
        self.row = {
            "event_type": "alert",
            "timestamp": datetime.now(UTC).isoformat(),
            "signature_id": 42000501,
            "signature": "MON LAB possible web directory traversal",
            "src_ip": "10.77.0.60", "src_port": 50500,
            "dst_ip": "10.77.0.50", "dst_port": 8085,
            "severity": 2,
        }
        self.data = {"service_state": "active", "records": [self.row]}

    def tearDown(self):
        self.tmp.cleanup()

    def test_observed_signature_gets_idempotent_persistent_review(self):
        key = module.evidence_key(self.row)
        first = module.acknowledge_eve_alert(key, self.data, "10.77.0.50", self.path)
        again = module.acknowledge_eve_alert(key, self.data, "10.77.0.50", self.path)
        self.assertEqual(first, again)
        self.assertEqual(module.acknowledged_alerts(self.path), [first])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_refuses_unobserved_or_wrong_target(self):
        key = module.evidence_key(self.row)
        for wrong_key, wrong_target in (
            ("ids:unobserved", "10.77.0.50"),
            (key, "10.77.0.99"),
        ):
            with self.assertRaises(ValueError):
                module.acknowledge_eve_alert(wrong_key, self.data, wrong_target, self.path)
        self.assertFalse(self.path.exists())

    def test_offline_sensor_cannot_issue_review(self):
        bad = {**self.data, "service_state": "inactive"}
        with self.assertRaises(ValueError):
            module.acknowledge_eve_alert(
                module.evidence_key(self.row), bad, "10.77.0.50", self.path
            )

    def test_old_eve_alert_cannot_be_newly_acknowledged(self):
        old = {**self.row, "timestamp": (datetime.now(UTC)-timedelta(hours=2)).isoformat()}
        with self.assertRaises(ValueError):
            module.acknowledge_eve_alert(
                module.evidence_key(old),
                {"service_state": "active", "records": [old]},
                "10.77.0.50", self.path
            )


if __name__ == "__main__":
    unittest.main()
