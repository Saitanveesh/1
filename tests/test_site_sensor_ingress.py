from fastapi.testclient import TestClient

from mon.site_api import create_site_app
from mon.site_controller import SiteController, SQLiteEventSpool


def test_zeek_batch_ingress_uses_controller_scope_and_local_pipeline(tmp_path) -> None:
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController("tenant-a", "site-a", spool)
    client = TestClient(create_site_app(controller))
    payload = {
        "records": [
            {
                "sensor_id": "zeek-1",
                "log_type": "conn",
                "record": {
                    "ts": 1774911641.78917,
                    "uid": "uid-1",
                    "id.orig_h": "10.0.0.10",
                    "id.orig_p": 51000,
                    "id.resp_h": "10.0.0.20",
                    "id.resp_p": 445,
                    "proto": "tcp",
                    "orig_pkts": 2,
                    "resp_pkts": 2,
                    "orig_ip_bytes": 200,
                    "resp_ip_bytes": 300,
                },
            }
        ]
    }

    try:
        response = client.post("/api/v1/site/sensors/zeek/batch", json=payload)

        assert response.status_code == 201
        body = response.json()
        assert len(body["accepted_event_ids"]) == 1
        assert body["results"][0]["event"]["tenant_id"] == "tenant-a"
        assert body["results"][0]["event"]["site_id"] == "site-a"
        assert body["results"][0]["event"]["sensor_id"] == "zeek-1"
        assert spool.diagnostics()["analysis_pending"] == 0
        assert spool.diagnostics()["delivery_ready"] == 1
    finally:
        spool.close()


def test_suricata_batch_drives_existing_ids_detection(tmp_path) -> None:
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController("tenant-a", "site-a", spool)
    client = TestClient(create_site_app(controller))
    payload = {
        "records": [
            {
                "sensor_id": "suricata-1",
                "record": {
                    "timestamp": "2026-09-19T04:00:00+00:00",
                    "flow_id": 99,
                    "event_type": "alert",
                    "src_ip": "198.51.100.10",
                    "src_port": 51000,
                    "dest_ip": "10.0.0.20",
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {
                        "signature_id": 12345,
                        "signature": "TEST suspicious traffic",
                        "severity": 2,
                        "action": "allowed",
                    },
                },
            }
        ]
    }

    try:
        response = client.post(
            "/api/v1/site/sensors/suricata/batch",
            json=payload,
        )

        assert response.status_code == 201
        result = response.json()["results"][0]
        assert result["event"]["category"] == "suricata.alert"
        assert len(result["findings"]) == 1
        assert result["findings"][0]["detector_id"] == "network-ids-signature"
        assert controller.status()["local_findings"] == 1
        assert controller.status()["local_incidents"] == 1
    finally:
        spool.close()


def test_raw_sensor_batch_is_prevalidated_before_any_local_mutation(tmp_path) -> None:
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController("tenant-a", "site-a", spool)
    client = TestClient(create_site_app(controller))
    payload = {
        "records": [
            {
                "sensor_id": "suricata-1",
                "record": {
                    "timestamp": "2026-09-19T04:00:00+00:00",
                    "event_type": "flow",
                    "src_ip": "10.0.0.10",
                    "dest_ip": "10.0.0.20",
                    "proto": "TCP",
                    "flow": {
                        "pkts_toserver": 1,
                        "pkts_toclient": 1,
                    },
                },
            },
            {
                "sensor_id": "suricata-1",
                "record": {
                    "timestamp": "2026-09-19T04:00:01+00:00",
                    "event_type": "stats",
                },
            },
        ]
    }

    try:
        response = client.post(
            "/api/v1/site/sensors/suricata/batch",
            json=payload,
        )

        assert response.status_code == 422
        assert "unsupported" in response.json()["detail"]
        assert spool.count() == 0
        assert controller.status()["local_findings"] == 0
        assert controller.status()["local_incidents"] == 0
    finally:
        spool.close()


def test_raw_sensor_replay_is_idempotent(tmp_path) -> None:
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController("tenant-a", "site-a", spool)
    client = TestClient(create_site_app(controller))
    payload = {
        "records": [
            {
                "sensor_id": "zeek-1",
                "log_type": "dns",
                "record": {
                    "ts": 1774911641.78917,
                    "uid": "dns-1",
                    "id.orig_h": "10.0.0.10",
                    "id.orig_p": 53000,
                    "id.resp_h": "1.1.1.1",
                    "id.resp_p": 53,
                    "proto": "udp",
                    "query": "example.com",
                    "qtype_name": "A",
                    "rcode_name": "NOERROR",
                },
            }
        ]
    }

    try:
        first = client.post("/api/v1/site/sensors/zeek/batch", json=payload)
        second = client.post("/api/v1/site/sensors/zeek/batch", json=payload)

        assert first.status_code == 201
        assert second.status_code == 201
        assert first.json()["accepted_event_ids"] == second.json()["accepted_event_ids"]
        assert second.json()["results"][0]["duplicate"] is True
        assert spool.count() == 1
    finally:
        spool.close()
