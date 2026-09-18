import datetime as dt

from mon.correlation import CorrelationEngine
from mon.domain import EvidenceClass, EvidenceRef, Finding, Severity
from mon.store import InMemoryStore


def finding(detector: str, seconds: int, evidence_class: EvidenceClass) -> Finding:
    observed = dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC) + dt.timedelta(seconds=seconds)
    return Finding(
        tenant_id="t1",
        site_id="s1",
        detector_id=detector,
        title=f"{detector} finding",
        severity=Severity.HIGH,
        confidence=0.88,
        src_ip="10.0.0.17",
        dst_ip="10.0.0.20",
        first_seen=observed,
        last_seen=observed,
        evidence=[
            EvidenceRef(
                evidence_class=evidence_class,
                source=detector,
                summary="test evidence",
                confidence=0.88,
                observed_at=observed,
            )
        ],
    )


def test_findings_for_same_actor_correlate_into_one_incident() -> None:
    store = InMemoryStore()
    engine = CorrelationEngine()

    first = engine.process(
        finding("network-rule", 0, EvidenceClass.NETWORK_FLOW),
        store,
    )
    second = engine.process(
        finding("endpoint-rule", 30, EvidenceClass.ENDPOINT),
        store,
    )

    assert first.incident_id == second.incident_id
    assert second.detector_ids == {"network-rule", "endpoint-rule"}
    assert len(second.finding_ids) == 2
    assert second.confidence == 0.88
    assert second.title.startswith("Correlated suspicious activity")


def test_findings_outside_window_create_new_incident() -> None:
    store = InMemoryStore()
    engine = CorrelationEngine(window_seconds=60)

    first = engine.process(
        finding("network-rule", 0, EvidenceClass.NETWORK_FLOW),
        store,
    )
    second = engine.process(
        finding("network-rule", 120, EvidenceClass.NETWORK_FLOW),
        store,
    )

    assert first.incident_id != second.incident_id
