"""Regression gates for real topology semantics (no invented campus data)."""
import datetime as dt

import pytest
from pydantic import ValidationError

from mon.network_topology import (
    EvidenceStatus,
    TopologyEngine,
    TopologyLayer,
    TopologyObservation,
)

NOW = dt.datetime(2026, 10, 15, 9, tzinfo=dt.UTC)


def edge(identifier, source, target, *, layer=TopologyLayer.L2,
         tenant="tenant-a", status=EvidenceStatus.OBSERVED, expires=300):
    return TopologyObservation(
        tenant_id=tenant, site_id="site-1", source=source, target=target,
        layer=layer, evidence_id=identifier, sensor_id="switch-readonly",
        observed_at=NOW, valid_until=NOW + dt.timedelta(seconds=expires),
        status=status,
    )


def test_dynamic_graph_paths_without_fixed_devices() -> None:
    graph = TopologyEngine()
    graph.observe(edge("one", "core", "switch"))
    graph.observe(edge("two", "switch", "unknown-new-device"))
    path = graph.shortest_verified_path(
        "tenant-a", "site-1", "core", "unknown-new-device",
        layer=TopologyLayer.L2, at=NOW + dt.timedelta(seconds=1),
    )
    assert path.hop_count == 2
    assert path.nodes == ("core", "switch", "unknown-new-device")
    assert path.evidence_ids == ("one", "two")


def test_expired_links_and_unproven_paths_remain_unknown() -> None:
    graph = TopologyEngine()
    graph.observe(edge("expired", "core", "victim", expires=2))
    graph.observe(edge("inferred", "core", "victim", status=EvidenceStatus.INFERRED))
    path = graph.shortest_verified_path(
        "tenant-a", "site-1", "core", "victim",
        layer=TopologyLayer.L2, at=NOW + dt.timedelta(seconds=5),
    )
    assert path.hop_count is None
    assert path.unknown_reason == "NO_CURRENT_VERIFIED_PATH"


def test_tenant_and_site_isolation_and_evidence_collision() -> None:
    graph = TopologyEngine()
    first = edge("one", "core", "victim")
    graph.observe(first)
    graph.observe(first)  # exact replay idempotent
    with pytest.raises(ValueError, match="collision"):
        graph.observe(edge("one", "core", "other"))
    for tenant, site in [("tenant-b", "site-1"), ("tenant-a", "other")]:
        path = graph.shortest_verified_path(
            tenant, site, "core", "victim", layer=TopologyLayer.L2,
            at=NOW + dt.timedelta(seconds=1),
        )
        assert path.hop_count is None


def test_traffic_and_observer_links_cannot_fake_network_distance() -> None:
    graph = TopologyEngine()
    graph.observe(edge("obs", "MON", "victim", layer=TopologyLayer.OBSERVATION))
    graph.observe(edge("traffic", "MON", "victim", layer=TopologyLayer.COMMUNICATION))
    assert graph.shortest_verified_path(
        "tenant-a", "site-1", "MON", "victim",
        layer=TopologyLayer.L2, at=NOW,
    ).hop_count is None
    with pytest.raises(ValueError, match="requires L2 or L3"):
        graph.shortest_verified_path(
            "tenant-a", "site-1", "MON", "victim",
            layer=TopologyLayer.COMMUNICATION, at=NOW,
        )


def test_directional_routing_does_not_imply_reverse_path() -> None:
    graph = TopologyEngine()
    graph.observe(edge("l3", "router-a", "router-b", layer=TopologyLayer.L3))
    assert graph.shortest_verified_path(
        "tenant-a", "site-1", "router-b", "router-a",
        layer=TopologyLayer.L3, at=NOW,
    ).unknown_reason == "NO_CURRENT_VERIFIED_PATH"


def test_reject_untrusted_time_and_monitor_ports() -> None:
    with pytest.raises(ValidationError):
        edge("bad", "a", "a")
    with pytest.raises(ValidationError):
        TopologyObservation(
            tenant_id="tenant-a", site_id="site-1", source="MON", target="host",
            layer=TopologyLayer.OBSERVATION, evidence_id="bad",
            sensor_id="sensor", observed_at=NOW,
            valid_until=NOW + dt.timedelta(seconds=10), src_port="Gi1/0/1",
        )
