"""Read-only inventory adapter regression and upload transport safeguards."""
import datetime as dt
import json

import pytest
from pydantic import ValidationError

from mon.topology import TopologyLayer, TopologyRelationship, build_topology_snapshot
from mon.topology_inventory import (
    SwitchInventory,
    linux_neighbors_observations,
    switch_inventory_observations,
)
from mon.topology_inventory_cli import _check_base_url, _read_bearer, upload

NOW = dt.datetime(2026, 10, 15, 12, tzinfo=dt.UTC)


def switch_export(**changes: object) -> SwitchInventory:
    payload = {
        "switch_id": "switch-unknown-location",
        "collected_at": NOW.isoformat(),
        "ttl_seconds": 120,
        "ports": [
            {"name": "ethernet1/17", "learned_macs": [
                {"mac": "02:11:22:33:44:55", "vlan": 101},
                {"mac": "02:11:22:33:44:66", "vlan": 101},
            ]},
        ],
        "lldp_neighbors": [
            {"local_port": "uplink1", "remote_node_id": "distribution-7"},
        ],
    }
    payload.update(changes)
    return SwitchInventory.model_validate(payload)


def test_switch_export_keeps_fdb_separate_from_verified_lldp_hops() -> None:
    inventory = switch_export()
    items = switch_inventory_observations(
        inventory, tenant_id="tenant-a", site_id="site-1", sensor_id="switch-exporter",
    )
    assert len(items) == 6  # switch, 2 learned MAC nodes + 2 FDB links, LLDP
    assert len({item.observation_id for item in items}) == len(items)
    assert switch_inventory_observations(
        inventory, tenant_id="tenant-a", site_id="site-1", sensor_id="switch-exporter",
    ) == items
    assert {item.node_type for item in items if item.kind == "NODE"} == {
        "SWITCH", "UNVERIFIED_LEARNED_MAC",
    }
    assert all(item.mac_address is None for item in items if item.kind == "LINK")
    snap = build_topology_snapshot(
        items, "tenant-a", "site-1", root_node_id="switch-unknown-location",
        at=NOW + dt.timedelta(seconds=1),
    )
    by_id = {item.node_id: item for item in snap.nodes}
    assert by_id["distribution-7"].distance_hops == 1
    for mac in ("02:11:22:33:44:55", "02:11:22:33:44:66"):
        assert by_id[f"mac:{mac}:vlan:101"].distance_hops is None
    assert sum(link.relationship == TopologyRelationship.FDB_LEARNED for link in snap.links) == 2
    assert sum(link.layer == TopologyLayer.L2 for link in snap.links) == 3
    assert snap.coverage == "UNKNOWN"


def test_reobserving_moved_mac_keeps_distinct_evidence() -> None:
    first = switch_export()
    second = switch_export(
        collected_at=(NOW + dt.timedelta(seconds=15)).isoformat(),
        ports=[{"name": "ethernet1/4", "learned_macs": [
            {"mac": "02:11:22:33:44:55", "vlan": 101},
        ]}],
        lldp_neighbors=[],
    )
    original = switch_inventory_observations(
        first, tenant_id="tenant-a", site_id="s", sensor_id="sw",
    )
    moved = switch_inventory_observations(
        second, tenant_id="tenant-a", site_id="s", sensor_id="sw",
    )
    assert set(x.observation_id for x in original).isdisjoint(
        x.observation_id for x in moved
    )


def test_invalid_switch_snapshot_rejected_without_guessing() -> None:
    with pytest.raises(ValidationError):
        switch_export(ports=[{"name": "eth1", "learned_macs": [{"mac": "not-a-mac"}]}])
    with pytest.raises(ValidationError):
        switch_export(collected_at="2026-10-15T12:00:00")
    with pytest.raises(ValidationError):
        switch_export(ports=[{"name": "eth1", "learned_macs": [
            {"mac": "01:11:22:33:44:55"},
        ]}])
    with pytest.raises(ValueError, match="duplicate switch port"):
        switch_inventory_observations(
            switch_export(ports=[{"name": "eth1"}, {"name": "eth1"}]),
            tenant_id="t", site_id="s", sensor_id="sensor",
        )


def test_linux_neighbor_evidence_contains_no_invented_cable() -> None:
    raw = json.dumps([
        {"dst": "192.0.2.30", "dev": "eth0", "lladdr": "02:ab:cd:11:22:33",
         "state": "REACHABLE"},
        {"dst": "192.0.2.31", "dev": "eth0", "lladdr": "02:ab:cd:11:22:44",
         "state": "FAILED"},
        {"dst": "192.0.2.32", "dev": "eth0", "lladdr": "02:ab:cd:11:22:55",
         "state": "STALE"},
    ])
    items = linux_neighbors_observations(
        raw, tenant_id="t", site_id="s", sensor_id="local", collected_at=NOW,
    )
    assert len(items) == 1
    assert items[0].kind == "NODE"
    assert items[0].node_id == "ip:192.0.2.30"
    assert items[0].peer_node_id is None
    assert linux_neighbors_observations(
        raw, tenant_id="t", site_id="s", sensor_id="local", collected_at=NOW,
    ) == items


def test_https_only_and_no_credential_leak(tmp_path) -> None:
    assert _check_base_url("https://soc.example", allow_local_http=False).startswith(
        "https://soc.example/api/v1/"
    )
    for url in ("http://soc.example", "https://a.example/path",
                "https://person:password@a.example", "http://127.0.0.1"):
        with pytest.raises(ValueError):
            _check_base_url(url, allow_local_http=False)
    assert _check_base_url(
        "http://127.0.0.1:8080", allow_local_http=True,
    ).startswith("http://127.0.0.1:8080/")
    credentials = tmp_path / "token"
    credentials.write_text("dummy-test-token\n", encoding="utf-8")
    credentials.chmod(0o600)
    assert _read_bearer(credentials) == "dummy-test-token"
    credentials.chmod(0o644)
    with pytest.raises(ValueError, match="group/other"):
        _read_bearer(credentials)


def test_empty_inventory_does_not_contact_network(tmp_path, monkeypatch) -> None:
    def should_not_upload(*args: object, **kwargs: object) -> None:
        raise AssertionError("No request should be sent for zero observations")

    import urllib.request

    monkeypatch.setattr(urllib.request, "build_opener", should_not_upload)
    token_file = tmp_path / "token"
    token_file.write_text("dummy-test-token\n", encoding="utf-8")
    token_file.chmod(0o600)
    assert upload([], api_url="https://soc.example", token_file=token_file) == (0, 0)
