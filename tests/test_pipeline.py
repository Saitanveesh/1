import datetime as dt

from fastapi.testclient import TestClient

from mon.api import app, correlator, detector, graph, store

client = TestClient(app)


def setup_function() -> None:
    store.__init__()
    detector.reset()
    graph.reset()
    correlator.reset()


def test_lateral_sweep_becomes_finding_incident_and_graph_trace() -> None:
    base = dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC)
    last_response = None
    for index in range(12):
        payload = {
            "tenant_id": "t1",
            "site_id": "s1",
            "sensor_id": "sensor-1",
            "observed_at": (base + dt.timedelta(milliseconds=index * 100)).isoformat(),
            "category": "network.connection",
            "src_ip": "10.0.0.17",
            "dst_ip": f"10.0.1.{index + 1}",
            "protocol": "tcp",
            "attributes": {
                "direction": "east-west",
                "dst_port": 445,
            },
        }
        last_response = client.post("/api/v1/events", json=payload)
        assert last_response.status_code == 201

    assert last_response is not None
    body = last_response.json()
    assert len(body["findings"]) == 1
    assert len(body["incidents"]) == 1
    incident_id = body["incidents"][0]["incident_id"]

    incidents = client.get(
        "/api/v1/incidents",
        params={"tenant_id": "t1", "site_id": "s1"},
    ).json()
    assert len(incidents) == 1

    trace = client.get(
        f"/api/v1/incidents/{incident_id}/graph",
        params={"tenant_id": "t1", "site_id": "s1"},
    )
    assert trace.status_code == 200
    assert len(trace.json()["edges"]) >= 8
