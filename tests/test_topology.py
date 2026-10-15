import datetime as dt

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from mon.api import app, store
from mon.database import Base, DatabaseStore
from mon.store import InMemoryStore
from mon.topology import TopologyBatch, TopologyObservation, build_topology_snapshot

NOW = dt.datetime(2026, 10, 15, 9, 0, tzinfo=dt.UTC)


def observation(oid: str, node: str, **changes: object) -> TopologyObservation:
    payload = {
        "observation_id": oid,
        "tenant_id": "tenant-a",
        "site_id": "site-1",
        "sensor_id": "trusted-collector",
        "evidence_id": f"evidence-{oid}",
        "observed_at": NOW,
        "ttl_seconds": 300,
        "kind": "NODE",
        "node_id": node,
        "node_type": "SWITCH",
    }
    payload.update(changes)
    return TopologyObservation(**payload)


def test_requires_time_scoped_evidence_and_layer_consistency() -> None:
    with pytest.raises(ValidationError):
        observation("bad", "switch", observed_at=NOW.replace(tzinfo=None))
    with pytest.raises(ValidationError):
        observation("bad", "switch", ip_address="not-an-ip")
    with pytest.raises(ValidationError):
        observation("bad", "switch", mac_address="fake")
    with pytest.raises(ValidationError):
        observation(
            "bad", "switch", kind="LINK", peer_node_id="host",
            relationship="FLOW_OBSERVED", layer="L2",
        )
    with pytest.raises(ValidationError):
        TopologyBatch(
            observations=[
                observation("one", "a"),
                observation("two", "b", tenant_id="tenant-other"),
            ]
        )
    with pytest.raises(ValidationError):
        TopologyBatch(observations=[observation("one", "a"), observation("one", "a")])


def test_lldp_hops_cannot_be_inferred_from_flows_or_mac_learning() -> None:
    data = [
        observation("root", "core"),
        observation("second", "switch-b"),
        observation("neighbor", "core", kind="LINK", peer_node_id="switch-b",
                    relationship="LLDP_NEIGHBOR", layer="L2"),
        observation("flow", "switch-b", kind="LINK", peer_node_id="host-ip",
                    relationship="FLOW_OBSERVED", layer="COMMUNICATION"),
        observation("fdb", "switch-b", kind="LINK", peer_node_id="learned-mac",
                    relationship="FDB_LEARNED", layer="L2"),
    ]
    snap = build_topology_snapshot(
        data, "tenant-a", "site-1", root_node_id="core", at=NOW + dt.timedelta(seconds=10)
    )
    nodes = {n.node_id: n for n in snap.nodes}
    assert nodes["core"].distance_hops == 0
    assert nodes["switch-b"].distance_hops == 1
    assert nodes["host-ip"].distance_hops is None
    assert nodes["learned-mac"].distance_hops is None
    assert nodes["host-ip"].node_type == "UNRESOLVED"
    assert len(snap.links) == 3
    assert snap.coverage == "UNKNOWN"
    assert build_topology_snapshot(
        data, "tenant-other", "site-1", at=NOW
    ).nodes == []


def test_stale_links_do_not_create_valid_hops() -> None:
    data = [observation("stale", "core", kind="LINK", peer_node_id="sw",
                        relationship="LLDP_NEIGHBOR", layer="L2", ttl_seconds=15)]
    snap = build_topology_snapshot(
        data, "tenant-a", "site-1", root_node_id="core",
        at=NOW + dt.timedelta(seconds=30),
    )
    assert snap.links[0].status == "STALE"
    assert {n.node_id: n.distance_hops for n in snap.nodes} == {
        "core": 0, "sw": None,
    }


@pytest.mark.parametrize("factory", [InMemoryStore, "sqlite"])
def test_durable_tenant_scoped_history_and_collision(factory, tmp_path) -> None:
    db = (
        InMemoryStore() if factory is InMemoryStore
        else DatabaseStore(f"sqlite+pysqlite:///{tmp_path / 'topology.db'}", create_schema=True)
    )
    try:
        first = TopologyBatch(observations=[observation("one", "core")])
        assert db.add_topology_observations(first) == 1
        assert db.add_topology_observations(first) == 0
        assert db.list_topology_observations("tenant-other", "site-1")[0] == []
        assert db.list_topology_observations("tenant-a", "site-other")[0] == []
        with pytest.raises(ValueError, match="different content"):
            db.add_topology_observations(TopologyBatch(
                observations=[observation("one", "DIFFERENT")]
            ))
        assert len(db.list_topology_observations("tenant-a", "site-1")[0]) == 1
        if factory == "sqlite":
            db.close()
            db = DatabaseStore(f"sqlite+pysqlite:///{tmp_path / 'topology.db'}")
            assert len(db.list_topology_observations("tenant-a", "site-1")[0]) == 1
    finally:
        if factory == "sqlite":
            db.close()


def test_api_topology_requires_scope_and_publishes_real_observations() -> None:
    # This test uses the project's default development test store and auth settings.
    store.__init__()
    client = TestClient(app)
    payload = TopologyBatch(observations=[observation("api", "switch-42")])
    response = client.post(
        "/api/v1/topology/observations", json=payload.model_dump(mode="json"),
    )
    assert response.status_code == 201, response.text
    assert response.json() == {"inserted": 1, "duplicates": 0}
    assert client.post(
        "/api/v1/topology/observations", json=payload.model_dump(mode="json"),
    ).json()["duplicates"] == 1
    own = client.get(
        "/api/v1/topology", params={"tenant_id": "tenant-a", "site_id": "site-1"}
    )
    assert own.status_code == 200, own.text
    assert [n["node_id"] for n in own.json()["nodes"]] == ["switch-42"]
    other = client.get(
        "/api/v1/topology", params={"tenant_id": "tenant-b", "site_id": "site-1"}
    )
    assert other.json()["nodes"] == []


def test_metadata_declares_topology_rls_table() -> None:
    assert "topology_observations" in Base.metadata.tables
