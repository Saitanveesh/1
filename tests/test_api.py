from fastapi.testclient import TestClient

from mon.api import app, store

client = TestClient(app)


def setup_function() -> None:
    store.__init__()


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["state"] == "READY"


def test_incident_reads_are_tenant_and_site_scoped() -> None:
    incident = {
        "incident_id": "inc-a",
        "tenant_id": "tenant-a",
        "site_id": "site-1",
        "title": "External scan",
        "severity": "MEDIUM",
        "confidence": 0.91,
    }
    assert client.post("/api/v1/incidents", json=incident).status_code == 201

    own = client.get(
        "/api/v1/incidents",
        params={"tenant_id": "tenant-a", "site_id": "site-1"},
    )
    other = client.get(
        "/api/v1/incidents",
        params={"tenant_id": "tenant-b", "site_id": "site-1"},
    )

    assert [item["incident_id"] for item in own.json()] == ["inc-a"]
    assert other.json() == []
