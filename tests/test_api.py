import datetime as dt

from fastapi.testclient import TestClient

from mon.api import app, correlator, detector, graph, store
from mon.domain import SecurityEvent
from mon.event_fabric import security_event_envelope
from mon.sensor_fleet_models import SensorIdentityRecord, SensorRecord

client = TestClient(app)


def setup_function() -> None:
    store.__init__()
    detector.reset()
    graph.reset()
    correlator.reset()


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


def test_sensor_fleet_api_is_site_scoped_and_revocation_updates_trust() -> None:
    now = dt.datetime.now(dt.UTC)
    identity = SensorIdentityRecord(
        identity_id="sensor-identity-a",
        tenant_id="tenant-a",
        site_id="site-1",
        sensor_id="sensor-1",
        certificate_serial="123",
        fingerprint_sha256="a" * 64,
        spiffe_uri=(
            "spiffe://mon.local/tenant/tenant-a/site/site-1/sensor/sensor-1"
        ),
        certificate_pem=(
            "-----BEGIN CERTIFICATE-----\n"
            + "A" * 80
            + "\n-----END CERTIFICATE-----\n"
        ),
        issued_at=now,
        expires_at=now + dt.timedelta(days=30),
    )
    sensor = SensorRecord(
        tenant_id="tenant-a",
        site_id="site-1",
        sensor_id="sensor-1",
        created_at=now,
        updated_at=now,
        current_identity_id=identity.identity_id,
    )
    store.save_sensor_lifecycle(sensor, [identity])

    own = client.get(
        "/api/v1/sensors",
        params={"tenant_id": "tenant-a", "site_id": "site-1"},
    )
    assert own.status_code == 200
    assert [item["sensor_id"] for item in own.json()] == ["sensor-1"]
    assert own.json()[0]["state"] == "STALE"

    foreign = client.get(
        "/api/v1/sensors",
        params={"tenant_id": "tenant-b", "site_id": "site-1"},
    )
    assert foreign.status_code == 200
    assert foreign.json() == []

    trust = client.get(
        "/api/v1/site/sensors/trust",
        params={"tenant_id": "tenant-a", "site_id": "site-1"},
    )
    assert trust.status_code == 200
    assert len(trust.json()["identities"]) == 1

    revoked = client.post(
        "/api/v1/sensors/sensor-1/revoke",
        params={"tenant_id": "tenant-a", "site_id": "site-1"},
        json={"reason": "decommissioned"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "REVOKED"

    trust_after = client.get(
        "/api/v1/site/sensors/trust",
        params={"tenant_id": "tenant-a", "site_id": "site-1"},
    )
    assert trust_after.status_code == 200
    assert trust_after.json()["identities"] == []

    fleet_after = client.get(
        "/api/v1/sensors",
        params={"tenant_id": "tenant-a", "site_id": "site-1"},
    )
    assert fleet_after.json()[0]["state"] == "REVOKED"


def test_fabric_ingress_is_idempotent_and_pins_exact_envelope() -> None:
    event = SecurityEvent(
        event_id="api-fabric-1",
        tenant_id="tenant-a",
        site_id="site-1",
        sensor_id="sensor-1",
        observed_at=dt.datetime(2026, 9, 19, 10, 0, tzinfo=dt.UTC),
        category="network.connection",
    )
    first_envelope = security_event_envelope(
        event,
        produced_at=dt.datetime(2026, 9, 19, 10, 1, tzinfo=dt.UTC),
    )

    first = client.post(
        "/api/v1/fabric/events",
        json=first_envelope.model_dump(mode="json"),
    )
    assert first.status_code == 201
    assert first.json()["duplicate"] is False
    assert first.json()["envelope_sha256"] == first_envelope.canonical_sha256

    duplicate = client.post(
        "/api/v1/fabric/events",
        json=first_envelope.model_dump(mode="json"),
    )
    assert duplicate.status_code == 201
    assert duplicate.json()["duplicate"] is True

    changed = security_event_envelope(
        event,
        produced_at=dt.datetime(2026, 9, 19, 10, 2, tzinfo=dt.UTC),
    )
    conflict = client.post(
        "/api/v1/fabric/events",
        json=changed.model_dump(mode="json"),
    )
    assert conflict.status_code == 409


def test_fabric_ingress_rejects_outer_inner_identity_mismatch() -> None:
    event = SecurityEvent(
        event_id="api-fabric-invalid",
        tenant_id="tenant-a",
        site_id="site-1",
        sensor_id="sensor-1",
        observed_at=dt.datetime(2026, 9, 19, 10, 0, tzinfo=dt.UTC),
        category="network.connection",
    )
    envelope = security_event_envelope(
        event,
        produced_at=dt.datetime(2026, 9, 19, 10, 1, tzinfo=dt.UTC),
    ).model_copy(update={"source": "sensor-other"})

    response = client.post(
        "/api/v1/fabric/events",
        json=envelope.model_dump(mode="json"),
    )

    assert response.status_code == 422
    assert "source" in response.json()["detail"]
