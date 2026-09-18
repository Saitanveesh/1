from mon.domain import (
    ActionType,
    ActorType,
    Asset,
    AssetCriticality,
    EnforcementKind,
    EnforcementPoint,
    EvidenceClass,
    EvidenceRef,
    Incident,
    PolicyOutcome,
    ResponseRequest,
    ResponseTarget,
    Severity,
)
from mon.policy import evaluate_response


def incident(confidence: float = 0.97) -> Incident:
    return Incident(
        incident_id="inc-1",
        tenant_id="tenant-a",
        site_id="site-1",
        title="Lateral movement",
        severity=Severity.HIGH,
        confidence=confidence,
        evidence=[
            EvidenceRef(
                evidence_class=EvidenceClass.NETWORK_FLOW,
                source="zeek",
                summary="SMB fan-out",
                confidence=0.96,
            ),
            EvidenceRef(
                evidence_class=EvidenceClass.ENDPOINT,
                source="agent",
                summary="suspicious process network activity",
                confidence=0.94,
            ),
        ],
    )


def point() -> EnforcementPoint:
    return EnforcementPoint(
        enforcement_point_id="host-fw",
        tenant_id="tenant-a",
        site_id="site-1",
        kind=EnforcementKind.ENDPOINT,
        vendor="windows",
        capabilities={ActionType.ISOLATE_ENDPOINT},
    )


def request() -> ResponseRequest:
    return ResponseRequest(
        tenant_id="tenant-a",
        site_id="site-1",
        incident_id="inc-1",
        target=ResponseTarget(asset_id="host-1"),
        action=ActionType.ISOLATE_ENDPOINT,
        enforcement_point_id="host-fw",
        actor_type=ActorType.AUTOMATION,
        ttl_seconds=900,
        reason="contain lateral movement",
    )


def test_high_confidence_multi_evidence_automation_can_be_allowed() -> None:
    asset = Asset(
        asset_id="host-1",
        tenant_id="tenant-a",
        site_id="site-1",
        display_name="Workstation 1",
    )
    decision = evaluate_response(request(), incident(), point(), asset)
    assert decision.outcome is PolicyOutcome.ALLOW


def test_critical_asset_requires_approval() -> None:
    asset = Asset(
        asset_id="host-1",
        tenant_id="tenant-a",
        site_id="site-1",
        display_name="Domain Controller",
        criticality=AssetCriticality.CRITICAL,
    )
    decision = evaluate_response(request(), incident(), point(), asset)
    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL


def test_low_confidence_requires_approval() -> None:
    decision = evaluate_response(request(), incident(confidence=0.60), point())
    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
