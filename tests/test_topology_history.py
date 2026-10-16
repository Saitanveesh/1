"""Historical network reconstruction and sensor coverage regression gates."""

import datetime as dt

import pytest
from fastapi.testclient import TestClient

from mon.api import app, store
from mon.database import DatabaseStore
from mon.store import InMemoryStore
from mon.topology import TopologyBatch, TopologyObservation, build_topology_snapshot

BASE = dt.datetime(2026, 10, 15, 8, tzinfo=dt.UTC)


def observation(
    oid: str, node: str, *,
    seconds: int, ip: str | None = None,
    sensor: str = "switch-a", ttl: int = 60,
) -> TopologyObservation:
    return TopologyObservation(
        observation_id=oid, tenant_id="topology-history",
        site_id="site-a", sensor_id=sensor, evidence_id=f"ev:{oid}",
        observed_at=BASE + dt.timedelta(seconds=seconds),
        ttl_seconds=ttl, kind="NODE", node_id=node, node_type="UNVERIFIED",
        ip_address=ip,
    )


def test_current_addresses_do_not_include_expired_ip_history() -> None:
    old = observation("old", "asset", seconds=0, ip="192.0.2.1", ttl=20)
    recent = observation("new", "asset", seconds=40, ip="192.0.2.2")
    snap = build_topology_snapshot(
        [old, recent], "topology-history", "site-a",
        at=BASE + dt.timedelta(seconds=50),
    )
    node = snap.nodes[0]
    assert node.ip_addresses == ["192.0.2.1", "192.0.2.2"]
    assert node.active_ip_addresses == ["192.0.2.2"]
    assert node.status == "OBSERVED"
    assert snap.coverage_details.active_sensors == 1
    assert snap.coverage_details.sensors_seen == 1
    assert snap.coverage_details.complete_network_visibility is None


def test_historical_snapshot_retains_only_time_eligible_evidence() -> None:
    records = [
        observation("old", "asset", seconds=0, ip="192.0.2.1", ttl=20),
        observation("new", "asset", seconds=40, ip="192.0.2.2"),
        observation("router", "edge", seconds=35, sensor="router-b", ttl=6),
    ]
    earlier = build_topology_snapshot(
        records, "topology-history", "site-a",
        at=BASE + dt.timedelta(seconds=10),
    )
    assert len(earlier.nodes) == 1
    assert earlier.nodes[0].active_ip_addresses == ["192.0.2.1"]
    assert earlier.coverage_details.sensors_seen == 1
    later = build_topology_snapshot(
        records, "topology-history", "site-a",
        at=BASE + dt.timedelta(seconds=55),
    )
    assert later.coverage_details.active_sensors == 1
    assert later.coverage_details.stale_sensors == 1
    assert later.coverage_details.observed_nodes == 1
    assert later.coverage_details.stale_nodes == 1
    assert later.coverage_details.last_observation_at == BASE + dt.timedelta(seconds=40)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_history_store_cutoff_and_scope_before_limit(backend: str, tmp_path) -> None:
    database = (
        InMemoryStore() if backend == "memory" else DatabaseStore(
            f"sqlite+pysqlite:///{tmp_path / 'topology-history.sqlite'}",
            create_schema=True,
        )
    )
    try:
        records = [
            observation("old", "old", seconds=0),
            observation("middle", "middle", seconds=30),
            observation("future", "future", seconds=90),
        ]
        database.add_topology_observations(TopologyBatch(observations=records))
        past, clipped = database.list_topology_observations(
            "topology-history", "site-a",
            before=BASE + dt.timedelta(seconds=35), limit=1,
        )
        assert [item.node_id for item in past] == ["middle"]
        assert clipped is True
        assert database.list_topology_observations(
            "topology-history", "other",
            before=BASE + dt.timedelta(seconds=35),
        )[0] == []
        with pytest.raises(ValueError, match="timezone"):
            database.list_topology_observations(
                "topology-history", "site-a", before=BASE.replace(tzinfo=None)
            )
    finally:
        if backend == "sqlite":
            database.close()


def test_historical_api_filters_future_records_and_invalid_dates() -> None:
    store.__init__()
    client = TestClient(app)
    batch = TopologyBatch(observations=[
        observation("old", "first", seconds=0),
        observation("later", "second", seconds=120),
    ])
    created = client.post(
        "/api/v1/topology/observations", json=batch.model_dump(mode="json"),
    )
    assert created.status_code == 201, created.text
    response = client.get("/api/v1/topology", params={
        "tenant_id": "topology-history", "site_id": "site-a",
        "at": (BASE + dt.timedelta(seconds=30)).isoformat(),
    })
    assert response.status_code == 200, response.text
    assert [n["node_id"] for n in response.json()["nodes"]] == ["first"]
    assert response.json()["coverage_details"]["complete_network_visibility"] is None
    assert client.get("/api/v1/topology", params={
        "tenant_id": "topology-history", "site_id": "site-a",
        "at": "2026-10-15T08:00:00",
    }).status_code == 422
    assert client.get("/api/v1/topology", params={
        "tenant_id": "topology-history", "site_id": "site-a",
        "at": "2099-01-01T00:00:00Z",
    }).status_code == 422
    assert client.get("/api/v1/topology", params={
        "tenant_id": "another-tenant", "site_id": "site-a",
        "at": (BASE + dt.timedelta(seconds=30)).isoformat(),
    }).json()["nodes"] == []
