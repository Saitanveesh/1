from __future__ import annotations

from mon.attack_graph import AttackGraphEngine
from mon.domain import (
    Asset,
    ContainmentCapability,
    EvidenceRef,
    Incident,
    IncidentInvestigation,
)
from mon.store import Store


def _dedupe_evidence(items: list[EvidenceRef]) -> list[EvidenceRef]:
    by_id = {item.evidence_id: item for item in items}
    return sorted(
        by_id.values(),
        key=lambda item: (item.observed_at, item.evidence_id),
    )


def build_incident_investigation(
    store: Store,
    graph: AttackGraphEngine,
    incident: Incident,
) -> IncidentInvestigation:
    site_findings = store.list_findings(incident.tenant_id, incident.site_id)
    findings = [
        finding
        for finding in site_findings
        if finding.finding_id in incident.finding_ids
    ]

    asset_ids = set(incident.affected_asset_ids)
    asset_ids.update(
        finding.asset_id
        for finding in findings
        if finding.asset_id is not None
    )
    affected_assets: list[Asset] = []
    for asset_id in sorted(asset_ids):
        asset = store.get_asset(incident.tenant_id, incident.site_id, asset_id)
        if asset is not None:
            affected_assets.append(asset)

    points = {
        point.enforcement_point_id: point
        for point in store.list_enforcement_points(
            incident.tenant_id,
            incident.site_id,
        )
    }

    capabilities: list[ContainmentCapability] = []
    for asset in affected_assets:
        bindings = store.list_enforcement_bindings(
            incident.tenant_id,
            incident.site_id,
            asset.asset_id,
        )
        for binding in bindings:
            point = points.get(binding.enforcement_point_id)
            if point is None:
                continue
            raw_blast_radius = binding.attributes.get("blast_radius_estimate")
            blast_radius = (
                str(raw_blast_radius)[:500]
                if raw_blast_radius is not None
                else None
            )
            notes = [
                f"topology binding distance={binding.distance}",
                "capability inventory only; response policy is evaluated separately",
            ]
            if blast_radius is None:
                notes.append("blast-radius estimate not supplied by connector/topology")

            capabilities.append(
                ContainmentCapability(
                    asset_id=asset.asset_id,
                    binding_id=binding.binding_id,
                    enforcement_point_id=point.enforcement_point_id,
                    kind=point.kind,
                    vendor=point.vendor,
                    health=point.health,
                    capabilities=set(point.capabilities),
                    distance=binding.distance,
                    blast_radius_estimate=blast_radius,
                    notes=notes,
                )
            )

    evidence = list(incident.evidence)
    for finding in findings:
        evidence.extend(finding.evidence)

    return IncidentInvestigation(
        incident=incident,
        findings=findings,
        affected_assets=affected_assets,
        graph=graph.trace_incident(incident),
        containment_capabilities=sorted(
            capabilities,
            key=lambda item: (
                item.asset_id,
                item.distance,
                item.enforcement_point_id,
            ),
        ),
        evidence=_dedupe_evidence(evidence),
    )
