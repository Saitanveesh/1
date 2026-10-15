import datetime as dt
import json

from mon.topology_neighbor_collector import parse_neighbors


def test_linux_neighbor_cache_is_passive_and_does_not_invent_links() -> None:
    observed = dt.datetime(2026, 10, 15, tzinfo=dt.UTC)
    cache = [
        {
            "dst": "192.0.2.17",
            "dev": "enp1s0",
            "lladdr": "02:42:ac:10:00:04",
            "state": ["REACHABLE"],
        },
        {"dst": "192.0.2.18", "dev": "enp1s0", "state": ["FAILED"]},
        {
            "dst": "2001:db8::3",
            "dev": "enp1s0",
            "lladdr": "02:42:ac:10:00:05",
            "state": ["STALE"],
        },
    ]
    batch = parse_neighbors(
        json.dumps(cache),
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="local-neighbor",
        observed_at=observed,
    )
    assert batch is not None
    assert len(batch.observations) == 2
    first = batch.observations[0]
    assert first.kind == "NODE"
    assert first.node_id == "ip:192.0.2.17"
    assert first.mac_address == "02:42:ac:10:00:04"
    assert first.interface_name == "enp1s0"
    assert first.peer_node_id is None
    assert first.layer is None
    assert first.evidence_id.startswith("linux-neighbor-sha256:")
    assert parse_neighbors(
        json.dumps(cache), tenant_id="tenant-a", site_id="site-a",
        sensor_id="local-neighbor", observed_at=observed,
    ) == batch


def test_empty_neighbor_cache_reports_no_observations() -> None:
    assert parse_neighbors(
        "[]", tenant_id="tenant-a", site_id="site-a",
        sensor_id="local-neighbor", observed_at=dt.datetime.now(dt.UTC),
    ) is None
