from mon.attack_graph import AttackGraphEngine
from mon.domain import (
    ActionType,
    Asset,
    EnforcementBinding,
    EnforcementHealth,
    EnforcementKind,
    EnforcementPoint,
    EvidenceClass,
    EvidenceRef,
    Finding,
    Incident,
    Severity,
)
from mon.investigation import build_incident_investigation
from mon.store import InMemoryStore


def test_investigation_joins_evidence_assets_graph_and_bound_controls() -> None:
    store = InMemoryStore()
    graph = AttackGraphEngine()

    asset = Asset(
        asset_id="asset-17",
        tenant_id="t1",
        site_id="s1",
        display_name="Workstation 17",
    )
    store.add_asset(asset)

    finding = Finding(
        finding_id="finding-1",
        tenant_id="t1",
        site_id="s1",
        detector_id="internal-lateral-sweep",
        title="Lateral sweep",
        severity=Severity.HIGH,
        confidence=0.88,
        asset_id="asset-17",
        evidence=[
            EvidenceRef(
                evidence_class=EvidenceClass.NETWORK_FLOW,
                source="sensor",
                summary="east-west SMB fanout",
                confidence=0.88,
            )
        ],
    )
    store.add_finding(finding)

    incident = Incident(
        incident_id="incident-1",
        tenant_id="t1",
        site_id="s1",
        title="Correlated suspicious activity",
        severity=Severity.HIGH,
        confidence=0.88,
        finding_ids={"finding-1"},
        affected_asset_ids={"asset-17"},
    )
    store.add_incident(incident)

    point = EnforcementPoint(
        enforcement_point_id="switch-1",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.SWITCH,
        vendor="generic",
        health=EnforcementHealth.HEALTHY,
        capabilities={ActionType.QUARANTINE_VLAN, ActionType.DISABLE_SWITCH_PORT},
    )
    store.add_enforcement_point(point)
    store.add_enforcement_binding(
        EnforcementBinding(
            binding_id="binding-1",
            tenant_id="t1",
            site_id="s1",
            asset_id="asset-17",
            enforcement_point_id="switch-1",
            distance=1,
            attributes={"blast_radius_estimate": "single access port"},
        )
    )

    result = build_incident_investigation(store, graph, incident)

    assert [item.finding_id for item in result.findings] == ["finding-1"]
    assert [item.asset_id for item in result.affected_assets] == ["asset-17"]
    assert len(result.evidence) == 1
    assert len(result.containment_capabilities) == 1
    capability = result.containment_capabilities[0]
    assert capability.enforcement_point_id == "switch-1"
    assert capability.distance == 1
    assert capability.blast_radius_estimate == "single access port"
    assert "policy is evaluated separately" in capability.notes[1]


def test_investigation_never_crosses_tenant_scope() -> None:
    store = InMemoryStore()
    graph = AttackGraphEngine()
    store.add_asset(
        Asset(
            asset_id="shared-id",
            tenant_id="other",
            site_id="s1",
            display_name="Other tenant asset",
        )
    )
    incident = Incident(
        incident_id="incident-1",
        tenant_id="t1",
        site_id="s1",
        title="Scoped incident",
        severity=Severity.MEDIUM,
        confidence=0.7,
        affected_asset_ids={"shared-id"},
    )

    result = build_incident_investigation(store, graph, incident)
    assert result.affected_assets == []
    assert result.containment_capabilities == []
