from fastapi.testclient import TestClient

from mon.api import app, live_hub, pipeline

client = TestClient(app)


def setup_function() -> None:
    pipeline.reset()
    live_hub.reset()


def test_websocket_pushes_processed_event_without_polling() -> None:
    with client.websocket_connect(
        "/ws/v1/live?tenant_id=t1&site_id=s1"
    ) as websocket:
        ready = websocket.receive_json()
        assert ready["kind"] == "stream.ready"
        assert ready["payload"]["mode"] == "push"

        response = client.post(
            "/api/v1/events",
            json={
                "event_id": "live-event-1",
                "tenant_id": "t1",
                "site_id": "s1",
                "sensor_id": "sensor-1",
                "category": "network.connection",
                "src_ip": "10.0.0.10",
                "dst_ip": "10.0.0.20",
                "protocol": "tcp",
                "attributes": {"dst_port": 443},
            },
        )
        assert response.status_code == 201

        pushed = websocket.receive_json()
        assert pushed["kind"] == "event.processed"
        assert pushed["sequence"] == 1
        assert pushed["payload"]["result"]["event"]["event_id"] == "live-event-1"
        assert pushed["payload"]["processing_ms"] >= 0


def test_reconnect_snapshot_exposes_current_sequence_and_state() -> None:
    response = client.post(
        "/api/v1/incidents",
        json={
            "incident_id": "inc-live",
            "tenant_id": "t1",
            "site_id": "s1",
            "title": "Test incident",
            "severity": "HIGH",
            "confidence": 0.95,
        },
    )
    assert response.status_code == 201

    snapshot = client.get(
        "/api/v1/live/snapshot",
        params={"tenant_id": "t1", "site_id": "s1"},
    )
    assert snapshot.status_code == 200
    body = snapshot.json()
    assert body["sequence"] == 1
    assert [item["incident_id"] for item in body["incidents"]] == ["inc-live"]
