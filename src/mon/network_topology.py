"""Evidence-backed topology graph for MON.

This module deliberately separates observed physical links from communications and
monitoring subscriptions. No network probing or enforcement occurs here.
"""
from __future__ import annotations

import datetime as dt
from collections import deque
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TopologyLayer(StrEnum):
    L2 = "L2"
    L3 = "L3"
    COMMUNICATION = "COMMUNICATION"
    SERVICE = "SERVICE"
    OBSERVATION = "OBSERVATION"


class EvidenceStatus(StrEnum):
    OBSERVED = "OBSERVED"
    CORROBORATED = "CORROBORATED"
    INFERRED = "INFERRED"


class TopologyObservation(BaseModel):
    """A scoped link with an explicit provenance and finite validity window."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=256)
    target: str = Field(min_length=1, max_length=256)
    layer: TopologyLayer
    evidence_id: str = Field(min_length=1, max_length=256)
    sensor_id: str = Field(min_length=1, max_length=256)
    observed_at: dt.datetime
    valid_until: dt.datetime
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    # A known physical connection is not established by traffic observations.
    src_port: str | None = Field(default=None, max_length=128)
    dst_port: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def validate_observation(self) -> TopologyObservation:
        if self.source == self.target:
            raise ValueError("self-links are not valid topology observations")
        if self.observed_at.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        if self.valid_until <= self.observed_at:
            raise ValueError("valid_until must be after observed_at")
        if self.layer == TopologyLayer.OBSERVATION and (
            self.src_port is not None or self.dst_port is not None
        ):
            raise ValueError("monitoring observations are not physical port links")
        return self


class TopologyPath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    site_id: str
    root: str
    target: str
    layer: TopologyLayer
    computed_at: dt.datetime
    hop_count: int | None = None
    nodes: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    unknown_reason: str | None = None


class TopologyEngine:
    """In-memory, scope-safe topology analysis foundation.

    Durable ingestion/snapshots and switch adapters are separate follow-on work.
    Incoming evidence is never construed as authority to modify a switch.
    """

    def __init__(self) -> None:
        self._observations: dict[tuple[str, str, str], TopologyObservation] = {}

    def observe(self, observation: TopologyObservation) -> None:
        key = (observation.tenant_id, observation.site_id, observation.evidence_id)
        previous = self._observations.get(key)
        if previous is not None and previous != observation:
            raise ValueError("evidence ID collision within tenant/site")
        self._observations[key] = observation

    def observations(
        self, tenant_id: str, site_id: str, *, at: dt.datetime
    ) -> tuple[TopologyObservation, ...]:
        self._validate_time(at)
        return tuple(
            sorted(
                (
                    o for (t, s, _), o in self._observations.items()
                    if (t, s) == (tenant_id, site_id)
                    and o.observed_at <= at < o.valid_until
                ),
                key=lambda o: (o.layer.value, o.source, o.target, o.evidence_id),
            )
        )

    @staticmethod
    def _validate_time(at: dt.datetime) -> None:
        if at.tzinfo is None:
            raise ValueError("query timestamp must be timezone-aware")

    def shortest_verified_path(
        self, tenant_id: str, site_id: str, root: str, target: str,
        *, layer: TopologyLayer, at: dt.datetime
    ) -> TopologyPath:
        """Find least-hop path only over current corroborated/observed links.

        Communications, services, and MON observer subscriptions cannot be
        interpreted as network hop distance, even if there is an edge.
        """
        self._validate_time(at)
        if layer not in {TopologyLayer.L2, TopologyLayer.L3}:
            raise ValueError("hop distance requires L2 or L3 topology")
        if not root or not target:
            raise ValueError("root and target must be nonempty")
        relevant = [
            o for o in self.observations(tenant_id, site_id, at=at)
            if o.layer == layer and o.status != EvidenceStatus.INFERRED
        ]
        adjacency: dict[str, list[tuple[str, str]]] = {}
        for observation in relevant:
            adjacency.setdefault(observation.source, []).append(
                (observation.target, observation.evidence_id)
            )
            # L2 physical attachments are bidirectional. L3 next-hop
            # observations may be directional; preserve that direction.
            if layer == TopologyLayer.L2:
                adjacency.setdefault(observation.target, []).append(
                    (observation.source, observation.evidence_id)
                )

        if root == target:
            return TopologyPath(
                tenant_id=tenant_id, site_id=site_id, root=root, target=target,
                layer=layer, computed_at=at, hop_count=0, nodes=(root,),
            )

        queue = deque([(root, (root,), ())])
        visited = {root}
        while queue:
            node, nodes, evidence = queue.popleft()
            for neighbor, evidence_id in sorted(adjacency.get(node, [])):
                if neighbor in visited:
                    continue
                next_nodes = (*nodes, neighbor)
                next_evidence = (*evidence, evidence_id)
                if neighbor == target:
                    return TopologyPath(
                        tenant_id=tenant_id, site_id=site_id,
                        root=root, target=target, layer=layer, computed_at=at,
                        hop_count=len(next_evidence), nodes=next_nodes,
                        evidence_ids=next_evidence,
                    )
                visited.add(neighbor)
                queue.append((neighbor, next_nodes, next_evidence))

        return TopologyPath(
            tenant_id=tenant_id, site_id=site_id,
            root=root, target=target, layer=layer, computed_at=at,
            unknown_reason="NO_CURRENT_VERIFIED_PATH",
        )
