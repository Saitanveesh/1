import datetime as dt

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from mon import auth
from mon.api import app, live_hub, pipeline
from mon.auth import JWTAuthenticator, get_principal


def make_authenticator() -> tuple[JWTAuthenticator, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return (
        JWTAuthenticator(
            public_pem,
            issuer="https://id.example.test/",
            audience="mon-control-plane",
        ),
        private_pem,
    )


def make_token(
    private_key: str,
    *,
    roles: list[str],
    tenant_id: str,
    site_ids: list[str],
) -> str:
    now = dt.datetime.now(dt.UTC)
    return jwt.encode(
        {
            "sub": "principal-1",
            "tenant_id": tenant_id,
            "roles": roles,
            "site_ids": site_ids,
            "iss": "https://id.example.test/",
            "aud": "mon-control-plane",
            "iat": now,
            "exp": now + dt.timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
    )


@pytest.fixture
def real_auth(monkeypatch):
    app.dependency_overrides.pop(get_principal, None)
    authenticator, private_key = make_authenticator()
    monkeypatch.setattr(auth, "get_authenticator", lambda: authenticator)
    pipeline.reset()
    live_hub.reset()
    return TestClient(app), private_key


def test_viewer_cannot_cross_tenant_boundary(real_auth) -> None:
    client, private_key = real_auth
    bearer = make_token(
        private_key,
        roles=["viewer"],
        tenant_id="tenant-a",
        site_ids=["site-1"],
    )
    headers = {"Authorization": f"Bearer {bearer}"}

    own = client.get(
        "/api/v1/findings",
        params={"tenant_id": "tenant-a", "site_id": "site-1"},
        headers=headers,
    )
    other = client.get(
        "/api/v1/findings",
        params={"tenant_id": "tenant-b", "site_id": "site-1"},
        headers=headers,
    )

    assert own.status_code == 200
    assert other.status_code == 403


def test_site_controller_can_ingest_only_its_site(real_auth) -> None:
    client, private_key = real_auth
    bearer = make_token(
        private_key,
        roles=["site_controller"],
        tenant_id="tenant-a",
        site_ids=["site-1"],
    )
    headers = {"Authorization": f"Bearer {bearer}"}
    base_event = {
        "tenant_id": "tenant-a",
        "sensor_id": "sensor",
        "category": "network.connection",
    }

    allowed = client.post(
        "/api/v1/events",
        json={**base_event, "event_id": "auth-event-1", "site_id": "site-1"},
        headers=headers,
    )
    denied = client.post(
        "/api/v1/events",
        json={**base_event, "event_id": "auth-event-2", "site_id": "site-2"},
        headers=headers,
    )

    assert allowed.status_code == 201
    assert denied.status_code == 403


def test_live_websocket_uses_authenticated_scope(real_auth) -> None:
    client, private_key = real_auth
    bearer = make_token(
        private_key,
        roles=["viewer"],
        tenant_id="tenant-a",
        site_ids=["site-1"],
    )
    headers = {"Authorization": f"Bearer {bearer}"}

    with client.websocket_connect(
        "/ws/v1/live?tenant_id=tenant-a&site_id=site-1",
        headers=headers,
    ) as websocket:
        assert websocket.receive_json()["kind"] == "stream.ready"

    with pytest.raises(WebSocketDisconnect), client.websocket_connect(
        "/ws/v1/live?tenant_id=tenant-a&site_id=site-2",
        headers=headers,
    ) as websocket:
        websocket.receive_json()


def test_topology_ingest_and_read_enforce_same_scoped_permissions(real_auth) -> None:
    client, private_key = real_auth
    ingest_token = make_token(
        private_key, roles=["site_controller"], tenant_id="tenant-a", site_ids=["site-1"]
    )
    viewer_token = make_token(
        private_key, roles=["viewer"], tenant_id="tenant-a", site_ids=["site-1"]
    )
    ingest_headers = {"Authorization": f"Bearer {ingest_token}"}
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    batch = {"observations": [{
        "observation_id": "auth-topology-1",
        "tenant_id": "tenant-a", "site_id": "site-1",
        "sensor_id": "sensor-a", "evidence_id": "reference-a",
        "observed_at": dt.datetime.now(dt.UTC).isoformat(),
        "kind": "NODE", "node_id": "observed-ip",
    }]}
    accepted = client.post(
        "/api/v1/topology/observations", json=batch, headers=ingest_headers,
    )
    assert accepted.status_code == 201, accepted.text
    assert client.post(
        "/api/v1/topology/observations", json=batch, headers=viewer_headers,
    ).status_code == 403
    assert client.post(
        "/api/v1/topology/observations",
        json={"observations": [{**batch["observations"][0], "site_id": "site-2"}]},
        headers=ingest_headers,
    ).status_code == 403
    assert client.get(
        "/api/v1/topology",
        params={"tenant_id": "tenant-a", "site_id": "site-1"},
        headers=viewer_headers,
    ).status_code == 200
    assert client.get(
        "/api/v1/topology",
        params={"tenant_id": "tenant-b", "site_id": "site-1"},
        headers=viewer_headers,
    ).status_code == 403
