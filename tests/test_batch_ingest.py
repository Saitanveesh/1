import datetime as dt

from fastapi.testclient import TestClient

from mon.api import app, pipeline


client = TestClient(app)


def setup_function() -> None:
    pipeline.reset()


def payload(event_id: str, dst: str) -> dict[str, object]:
    return {
        "event_id": event_id,
        "tenant_id": "t1",
        "site_id": "s1",
        "sensor_id": "sensor",
        "observed_at": dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC).isoformat(),
        "category": "network.connection",
        "src_ip": "10.0.0.17",
        "dst_ip": dst,
        "protocol": "tcp",
        "attributes": {"direction": "east-west", "dst_port": 445},
    }


def test_replayed_event_is_idempotent() -> None:
    item = payload("event-1", "10.0.0.20")
    first = client.post("/api/v1/events", json=item)
    second = client.post("/api/v1/events", json=item)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["duplicate"] is False
    assert second.json()["duplicate"] is True

    snapshot = client.get(
        "/api/v1/graph",
        params={"tenant_id": "t1", "site_id": "s1"},
    ).json()
    assert snapshot["edges"][0]["event_count"] == 1


def test_batch_acknowledges_duplicates_for_at_least_once_sync() -> None:
    batch = {
        "events": [
            payload("event-1", "10.0.0.20"),
            payload("event-2", "10.0.0.21"),
        ]
    }
    first = client.post("/api/v1/events/batch", json=batch)
    replay = client.post("/api/v1/events/batch", json=batch)

    assert first.status_code == 201
    assert replay.status_code == 201
    assert set(first.json()["accepted_event_ids"]) == {"event-1", "event-2"}
    assert set(replay.json()["accepted_event_ids"]) == {"event-1", "event-2"}
    assert all(item["duplicate"] for item in replay.json()["results"])


def test_batch_rejects_cross_tenant_scope() -> None:
    first = payload("event-1", "10.0.0.20")
    second = payload("event-2", "10.0.0.21")
    second["tenant_id"] = "other"

    response = client.post("/api/v1/events/batch", json={"events": [first, second]})
    assert response.status_code == 422
