"""Evidence-backed topology observations and bounded network graph reconstruction.

No active scans, no invented host locations, and no physical link is inferred
from an IP flow. Observation ingestion is performed by authenticated collectors.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from collections import deque
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mon.domain import utcnow


class TopologyKind(StrEnum):
    NODE = "NODE"
    LINK = "LINK"


class TopologyLayer(StrEnum):
    L2 = "L2"
    L3 = "L3"
    COMMUNICATION = "COMMUNICATION"


class TopologyRelationship(StrEnum):
    LLDP_NEIGHBOR = "LLDP_NEIGHBOR"
    FDB_LEARNED = "FDB_LEARNED"
    ROUTED_NEXT_HOP = "ROUTED_NEXT_HOP"
    FLOW_OBSERVED = "FLOW_OBSERVED"


_RELATION_LAYER = {
    TopologyRelationship.LLDP_NEIGHBOR: TopologyLayer.L2,
    TopologyRelationship.FDB_LEARNED: TopologyLayer.L2,
    TopologyRelationship.ROUTED_NEXT_HOP: TopologyLayer.L3,
    TopologyRelationship.FLOW_OBSERVED: TopologyLayer.COMMUNICATION,
}


class TopologyObservation(BaseModel):
    """One immutable, provenance-carrying observation from an authorized collector."""

    model_config = ConfigDict(extra="forbid")

    observation_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    evidence_id: str = Field(min_length=1, max_length=256)
    observed_at: dt.datetime
    ttl_seconds: int = Field(default=300, ge=1, le=86400)
    kind: TopologyKind
    node_id: str = Field(min_length=1, max_length=256)
    node_type: str = Field(default="UNKNOWN", min_length=1, max_length=64)
    display_name: str | None = Field(default=None, max_length=256)
    ip_address: str | None = Field(default=None, max_length=45)
    peer_node_id: str | None = Field(default=None, max_length=256)
    relationship: TopologyRelationship | None = None
    layer: TopologyLayer | None = None

    @model_validator(mode="after")
    def validate_observation(self) -> TopologyObservation:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.ip_address is not None:
            try:
                ipaddress.ip_address(self.ip_address)
            except ValueError as exc:
                raise ValueError("ip_address must be valid IPv4/IPv6") from exc
        if self.kind is TopologyKind.NODE:
            if self.peer_node_id is not None or self.relationship or self.layer:
                raise ValueError("NODE must not declare link properties")
        else:
            if not self.peer_node_id or self.peer_node_id == self.node_id:
                raise ValueError("LINK requires a distinct peer_node_id")
            if self.relationship is None or self.layer is None:
                raise ValueError("LINK requires relationship and layer")
            if _RELATION_LAYER[self.relationship] is not self.layer:
                raise ValueError("link relationship is incompatible with layer")
        return self

    @property
    def expires_at(self) -> dt.datetime:
        return self.observed_at + dt.timedelta(seconds=self.ttl_seconds)


class TopologyBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observations: list[TopologyObservation] = Field(min_length=1, max_length=250)

    @model_validator(mode="after")
    def validate_scope(self) -> TopologyBatch:
        if len({(o.tenant_id, o.site_id) for o in self.observations}) != 1:
            raise ValueError("topology observations must share one tenant/site")
        if len({o.observation_id for o in self.observations}) != len(self.observations):
            raise ValueError("duplicate observation_id in batch")
        return self


class TopologyNode(BaseModel):
    node_id: str
    node_type: str
    label: str
    ip_addresses: list[str]
    last_seen: dt.datetime
    status: str
    evidence_ids: list[str]
    distance_hops: int | None = None


class TopologyLink(BaseModel):
    source_id: str
    target_id: str
    layer: TopologyLayer
    relationship: TopologyRelationship
    observed_at: dt.datetime
    status: str
    evidence_id: str
    sensor_id: str


class TopologySnapshot(BaseModel):
    tenant_id: str
    site_id: str
    captured_at: dt.datetime
    root_node_id: str | None
    distance_basis: str
    coverage: str = "UNKNOWN"
    observations_considered: int
    truncated: bool
    nodes: list[TopologyNode]
    links: list[TopologyLink]


def build_topology_snapshot(
    observations: list[TopologyObservation],
    tenant_id: str,
    site_id: str,
    *,
    root_node_id: str | None = None,
    at: dt.datetime | None = None,
    truncated: bool = False,
) -> TopologySnapshot:
    """Collapse immutable observations into current/stale evidence-backed topology.

    Only live LLDP adjacency is eligible for hop counts. MAC/FDB learning, IP
    flows and routing are intentionally excluded from physical/L2 distances.
    """
    when = at or utcnow()
    if when.tzinfo is None or when.utcoffset() is None:
        raise ValueError("snapshot time must be timezone-aware")
    scope = sorted(
        (
            o for o in observations
            if o.tenant_id == tenant_id
            and o.site_id == site_id
            and o.observed_at <= when
        ),
        key=lambda o: (o.observed_at, o.observation_id),
    )
    nodes: dict[str, TopologyNode] = {}
    links: dict[tuple[str, str, TopologyLayer, TopologyRelationship], TopologyLink] = {}
    for o in scope:
        status = "OBSERVED" if o.expires_at > when else "STALE"
        n = nodes.get(o.node_id)
        if n is None:
            nodes[o.node_id] = TopologyNode(
                node_id=o.node_id,
                node_type=o.node_type,
                label=o.display_name or o.node_id,
                ip_addresses=[o.ip_address] if o.ip_address else [],
                last_seen=o.observed_at,
                status=status,
                evidence_ids=[o.evidence_id],
            )
        else:
            # Do not overwrite a later node record with stale or older labels.
            if o.kind is TopologyKind.NODE and o.observed_at >= n.last_seen:
                n.node_type = o.node_type
                n.label = o.display_name or o.node_id
            if o.ip_address and o.ip_address not in n.ip_addresses:
                n.ip_addresses.append(o.ip_address)
            n.last_seen = max(n.last_seen, o.observed_at)
            n.status = "OBSERVED" if n.status == "OBSERVED" or status == "OBSERVED" else "STALE"
            if o.evidence_id not in n.evidence_ids:
                n.evidence_ids.append(o.evidence_id)
        if o.kind is TopologyKind.LINK:
            assert o.peer_node_id is not None
            assert o.layer is not None
            assert o.relationship is not None
            if o.peer_node_id not in nodes:
                nodes[o.peer_node_id] = TopologyNode(
                    node_id=o.peer_node_id,
                    node_type="UNRESOLVED",
                    label=o.peer_node_id,
                    ip_addresses=[],
                    last_seen=o.observed_at,
                    status=status,
                    evidence_ids=[o.evidence_id],
                )
            elif o.observed_at >= nodes[o.peer_node_id].last_seen:
                nodes[o.peer_node_id].last_seen = o.observed_at
                nodes[o.peer_node_id].status = status
            link_key = (o.node_id, o.peer_node_id, o.layer, o.relationship)
            links[link_key] = TopologyLink(
                source_id=o.node_id,
                target_id=o.peer_node_id,
                layer=o.layer,
                relationship=o.relationship,
                observed_at=o.observed_at,
                status=status,
                evidence_id=o.evidence_id,
                sensor_id=o.sensor_id,
            )

    # Reconstruct network depth only from currently valid, observed LLDP links.
    if root_node_id and root_node_id in nodes:
        adjacency: dict[str, set[str]] = {}
        for link in links.values():
            if link.status != "OBSERVED" or link.relationship != TopologyRelationship.LLDP_NEIGHBOR:
                continue
            adjacency.setdefault(link.source_id, set()).add(link.target_id)
            adjacency.setdefault(link.target_id, set()).add(link.source_id)
        queue = deque([(root_node_id, 0)])
        visited: set[str] = set()
        while queue:
            node_id, hops = queue.popleft()
            if node_id in visited:
                continue
            visited.add(node_id)
            nodes[node_id].distance_hops = hops
            for neighbor in sorted(adjacency.get(node_id, set()) - visited):
                queue.append((neighbor, hops + 1))

    return TopologySnapshot(
        tenant_id=tenant_id,
        site_id=site_id,
        captured_at=when,
        root_node_id=root_node_id,
        distance_basis="OBSERVED_LLDP_HOPS" if root_node_id else "NO_ROOT_SELECTED",
        observations_considered=len(scope),
        truncated=truncated,
        nodes=sorted(nodes.values(), key=lambda n: n.node_id),
        links=sorted(
            links.values(),
            key=lambda l: (l.source_id, l.target_id, l.layer, l.relationship),
        ),
    )
