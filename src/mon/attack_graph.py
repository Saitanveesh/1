from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
from collections import defaultdict

from mon.domain import (
    AttackGraphEdge,
    AttackGraphNode,
    AttackGraphSnapshot,
    Finding,
    GraphNodeKind,
    GraphRelation,
    Incident,
    SecurityEvent,
)
from mon.endpoint import identity_id_for, identity_key, process_id_for


def _port(event: SecurityEvent) -> int | None:
    value = event.attributes.get("dst_port")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _ip_kind(value: str) -> GraphNodeKind:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return GraphNodeKind.EXTERNAL_IP
    if address.is_private or address.is_loopback or address.is_link_local:
        return GraphNodeKind.INTERNAL_IP
    return GraphNodeKind.EXTERNAL_IP


class AttackGraphEngine:
    """Build an evidence graph from observed communications and detector findings."""

    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str], dict[str, AttackGraphNode]] = defaultdict(dict)
        self._edges: dict[tuple[str, str], dict[str, AttackGraphEdge]] = defaultdict(dict)

    def reset(self) -> None:
        self._nodes.clear()
        self._edges.clear()

    def restore_checkpoint(self, snapshot: AttackGraphSnapshot) -> None:
        scope = (snapshot.tenant_id, snapshot.site_id)
        self._nodes[scope] = {node.node_id: node for node in snapshot.nodes}
        self._edges[scope] = {edge.edge_id: edge for edge in snapshot.edges}

    @staticmethod
    def _node_for_source(event: SecurityEvent) -> tuple[str, GraphNodeKind, str] | None:
        if event.asset_id:
            return f"asset:{event.asset_id}", GraphNodeKind.ASSET, event.asset_id
        if event.src_ip:
            return f"ip:{event.src_ip}", _ip_kind(event.src_ip), event.src_ip
        return None

    @staticmethod
    def _node_for_destination(event: SecurityEvent) -> tuple[str, GraphNodeKind, str] | None:
        dst_asset = event.attributes.get("dst_asset_id")
        if isinstance(dst_asset, str) and dst_asset:
            return f"asset:{dst_asset}", GraphNodeKind.ASSET, dst_asset
        if event.dst_ip:
            return f"ip:{event.dst_ip}", _ip_kind(event.dst_ip), event.dst_ip
        return None

    @staticmethod
    def _relation(event: SecurityEvent, dst_port: int | None) -> GraphRelation:
        if event.category.casefold() == "dns.query":
            return GraphRelation.DNS_QUERY
        direction = str(event.attributes.get("direction") or "").casefold()
        if direction == "east-west" and dst_port in {22, 445, 3389}:
            return GraphRelation.ADMIN_SERVICE
        return GraphRelation.NETWORK_COMMUNICATION

    def observe_event(self, event: SecurityEvent) -> AttackGraphEdge | None:
        endpoint_edge = self.observe_endpoint_event(event)
        if event.category.casefold().startswith("endpoint.") and not event.dst_ip:
            return endpoint_edge
        source = self._node_for_source(event)
        destination = self._node_for_destination(event)
        if source is None or destination is None:
            return None

        scope = (event.tenant_id, event.site_id)
        for node_id, kind, label in (source, destination):
            current = self._nodes[scope].get(node_id)
            if current is None:
                self._nodes[scope][node_id] = AttackGraphNode(
                    node_id=node_id,
                    tenant_id=event.tenant_id,
                    site_id=event.site_id,
                    kind=kind,
                    label=label,
                )

        dst_port = _port(event)
        relation = self._relation(event, dst_port)
        protocol = event.protocol.casefold() if event.protocol else None
        edge_id = "|".join(
            [
                source[0],
                destination[0],
                relation.value,
                protocol or "",
                str(dst_port or ""),
            ]
        )
        current = self._edges[scope].get(edge_id)
        if current is None:
            current = AttackGraphEdge(
                edge_id=edge_id,
                tenant_id=event.tenant_id,
                site_id=event.site_id,
                src_node_id=source[0],
                dst_node_id=destination[0],
                relation=relation,
                protocol=protocol,
                dst_port=dst_port,
                first_seen=event.observed_at,
                last_seen=event.observed_at,
                event_ids={event.event_id},
                attributes={
                    "direction": event.attributes.get("direction"),
                    "category": event.category,
                },
            )
        else:
            event_ids = set(current.event_ids)
            if len(event_ids) < 200:
                event_ids.add(event.event_id)
            current = current.model_copy(
                update={
                    "last_seen": max(current.last_seen, event.observed_at),
                    "first_seen": min(current.first_seen, event.observed_at),
                    "event_count": current.event_count + 1,
                    "event_ids": event_ids,
                }
            )
        self._edges[scope][edge_id] = current
        return current

    def _upsert_node(
        self,
        scope: tuple[str, str],
        *,
        node_id: str,
        tenant_id: str,
        site_id: str,
        kind: GraphNodeKind,
        label: str,
        attributes: dict[str, object] | None = None,
    ) -> None:
        current = self._nodes[scope].get(node_id)
        if current is None:
            self._nodes[scope][node_id] = AttackGraphNode(
                node_id=node_id,
                tenant_id=tenant_id,
                site_id=site_id,
                kind=kind,
                label=label,
                attributes=attributes or {},
            )

    def _upsert_edge(
        self,
        event: SecurityEvent,
        *,
        src_node_id: str,
        dst_node_id: str,
        relation: GraphRelation,
        attributes: dict[str, object] | None = None,
    ) -> AttackGraphEdge:
        scope = (event.tenant_id, event.site_id)
        edge_id = "|".join([src_node_id, dst_node_id, relation.value])
        current = self._edges[scope].get(edge_id)
        if current is None:
            current = AttackGraphEdge(
                edge_id=edge_id,
                tenant_id=event.tenant_id,
                site_id=event.site_id,
                src_node_id=src_node_id,
                dst_node_id=dst_node_id,
                relation=relation,
                first_seen=event.observed_at,
                last_seen=event.observed_at,
                event_ids={event.event_id},
                attributes={
                    "category": event.category,
                    "evidence": [
                        item.model_dump(mode="json")
                        for item in event.evidence[:5]
                    ],
                    **(attributes or {}),
                },
            )
        else:
            event_ids = set(current.event_ids)
            if len(event_ids) < 200:
                event_ids.add(event.event_id)
            current = current.model_copy(
                update={
                    "event_ids": event_ids,
                    "event_count": current.event_count + 1,
                    "first_seen": min(current.first_seen, event.observed_at),
                    "last_seen": max(current.last_seen, event.observed_at),
                }
            )
        self._edges[scope][edge_id] = current
        return current

    def observe_endpoint_event(self, event: SecurityEvent) -> AttackGraphEdge | None:
        if not event.category.casefold().startswith("endpoint."):
            return None
        scope = (event.tenant_id, event.site_id)
        asset_node = f"asset:{event.asset_id}" if event.asset_id else None
        if asset_node is not None:
            self._upsert_node(
                scope,
                node_id=asset_node,
                tenant_id=event.tenant_id,
                site_id=event.site_id,
                kind=GraphNodeKind.ASSET,
                label=event.asset_id or "asset",
            )
        identity_node = None
        source, principal, domain, asset_id = identity_key(event)
        if source and principal:
            weak = event.attributes.get("identity_confidence") == "WEAK"
            identity_id = identity_id_for(
                event.tenant_id,
                event.site_id,
                source,
                principal,
                domain,
                asset_id,
                weak=weak,
            )
            identity_node = identity_id
            self._upsert_node(
                scope,
                node_id=identity_node,
                tenant_id=event.tenant_id,
                site_id=event.site_id,
                kind=GraphNodeKind.IDENTITY,
                label=str(event.attributes.get("identity_display_name") or principal),
                attributes={"confidence": event.attributes.get("identity_confidence")},
            )
        process_node = process_id_for(event)
        if process_node:
            self._upsert_node(
                scope,
                node_id=process_node,
                tenant_id=event.tenant_id,
                site_id=event.site_id,
                kind=GraphNodeKind.PROCESS,
                label=str(event.attributes.get("image") or event.attributes.get("process_pid")),
                attributes={
                    "pid": event.attributes.get("process_pid"),
                    "basis": (
                        "source process GUID"
                        if event.attributes.get("process_guid")
                        else "PID scoped to endpoint/session/time"
                    ),
                },
            )
        last_edge = None
        category = event.category.casefold()
        if identity_node and asset_node and category == "endpoint.auth.success":
            last_edge = self._upsert_edge(
                event,
                src_node_id=identity_node,
                dst_node_id=asset_node,
                relation=GraphRelation.AUTHENTICATED_TO,
            )
        if identity_node and asset_node and category == "endpoint.auth.failure":
            last_edge = self._upsert_edge(
                event,
                src_node_id=identity_node,
                dst_node_id=asset_node,
                relation=GraphRelation.AUTHENTICATION_FAILED,
            )
        if identity_node and process_node:
            last_edge = self._upsert_edge(
                event,
                src_node_id=identity_node,
                dst_node_id=process_node,
                relation=GraphRelation.EXECUTED_PROCESS,
            )
        if process_node and asset_node:
            last_edge = self._upsert_edge(
                event,
                src_node_id=process_node,
                dst_node_id=asset_node,
                relation=GraphRelation.PROCESS_ON_ASSET,
            )
        parent_guid = event.attributes.get("parent_process_guid")
        if process_node and isinstance(parent_guid, str) and event.asset_id:
            digest = hashlib.sha256(
                f"{event.tenant_id}\x1f{event.site_id}\x1f{event.asset_id}\x1f{parent_guid}".encode()
            ).hexdigest()
            parent_node = f"process:{digest[:48]}"
            self._upsert_node(
                scope,
                node_id=parent_node,
                tenant_id=event.tenant_id,
                site_id=event.site_id,
                kind=GraphNodeKind.PROCESS,
                label=str(event.attributes.get("parent_process_pid") or parent_guid),
            )
            last_edge = self._upsert_edge(
                event,
                src_node_id=parent_node,
                dst_node_id=process_node,
                relation=GraphRelation.PARENT_PROCESS,
            )
        if process_node and event.dst_ip:
            peer_node = f"ip:{event.dst_ip}"
            self._upsert_node(
                scope,
                node_id=peer_node,
                tenant_id=event.tenant_id,
                site_id=event.site_id,
                kind=_ip_kind(event.dst_ip),
                label=event.dst_ip,
            )
            last_edge = self._upsert_edge(
                event,
                src_node_id=process_node,
                dst_node_id=peer_node,
                relation=GraphRelation.PROCESS_NETWORK_CONNECTION,
                attributes={"dst_port": event.attributes.get("dst_port")},
            )
        return last_edge

    def attach_finding(self, finding: Finding) -> int:
        scope = (finding.tenant_id, finding.site_id)
        window_seconds = int(finding.attributes.get("window_seconds") or 60)
        cutoff = finding.last_seen - dt.timedelta(seconds=max(window_seconds, 1))
        source_ids = set()
        if finding.asset_id:
            source_ids.add(f"asset:{finding.asset_id}")
        if finding.src_ip:
            source_ids.add(f"ip:{finding.src_ip}")

        attached = 0
        for edge_id, edge in list(self._edges[scope].items()):
            if source_ids and edge.src_node_id not in source_ids:
                continue
            if edge.last_seen < cutoff or edge.first_seen > finding.last_seen:
                continue
            finding_ids = set(edge.finding_ids)
            detector_ids = set(edge.detector_ids)
            finding_ids.add(finding.finding_id)
            detector_ids.add(finding.detector_id)
            self._edges[scope][edge_id] = edge.model_copy(
                update={
                    "finding_ids": finding_ids,
                    "detector_ids": detector_ids,
                }
            )
            attached += 1
        return attached

    def snapshot(self, tenant_id: str, site_id: str) -> AttackGraphSnapshot:
        scope = (tenant_id, site_id)
        return AttackGraphSnapshot(
            tenant_id=tenant_id,
            site_id=site_id,
            nodes=sorted(self._nodes[scope].values(), key=lambda item: item.node_id),
            edges=sorted(self._edges[scope].values(), key=lambda item: item.edge_id),
        )

    def trace_incident(self, incident: Incident) -> AttackGraphSnapshot:
        snapshot = self.snapshot(incident.tenant_id, incident.site_id)
        entity_nodes = {
            value if value.startswith(("asset:", "ip:")) else f"ip:{value}"
            for value in incident.entities
        }
        entity_nodes |= {f"asset:{asset_id}" for asset_id in incident.affected_asset_ids}

        edges = [
            edge
            for edge in snapshot.edges
            if edge.finding_ids & incident.finding_ids
            or edge.src_node_id in entity_nodes
            or edge.dst_node_id in entity_nodes
        ]
        node_ids = {node_id for edge in edges for node_id in (edge.src_node_id, edge.dst_node_id)}
        nodes = [node for node in snapshot.nodes if node.node_id in node_ids]
        return AttackGraphSnapshot(
            tenant_id=incident.tenant_id,
            site_id=incident.site_id,
            nodes=nodes,
            edges=edges,
        )
