import datetime as dt

from mon.attack_graph import AttackGraphEngine
from mon.domain import (
    EvidenceClass,
    EvidenceRef,
    Finding,
    Incident,
    SecurityEvent,
    Severity,
)


def test_graph_tracks_observed_relationship_and_attaches_finding() -> None:
    engine = AttackGraphEngine()
    base = dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC)

    for index in range(3):
        engine.observe_event(
            SecurityEvent(
                tenant_id="t1",
                site_id="s1",
                sensor_id="sensor",
                observed_at=base + dt.timedelta(seconds=index),
                category="network.connection",
                src_ip="10.0.0.17",
                dst_ip="10.0.0.20",
                protocol="tcp",
                attributes={"direction": "east-west", "dst_port": 445},
            )
        )

    finding = Finding(
        finding_id="finding-1",
        tenant_id="t1",
        site_id="s1",
        detector_id="internal-lateral-sweep",
        title="Internal administrative-service sweep",
        severity=Severity.HIGH,
        confidence=0.88,
        src_ip="10.0.0.17",
        dst_ip="10.0.0.20",
        first_seen=base,
        last_seen=base + dt.timedelta(seconds=2),
        evidence=[
            EvidenceRef(
                evidence_class=EvidenceClass.STATISTICAL,
                source="detector",
                summary="sweep shape",
                confidence=0.88,
                observed_at=base + dt.timedelta(seconds=2),
            )
        ],
        attributes={"window_seconds": 30},
    )

    assert engine.attach_finding(finding) == 1
    snapshot = engine.snapshot("t1", "s1")
    assert len(snapshot.nodes) == 2
    assert len(snapshot.edges) == 1
    edge = snapshot.edges[0]
    assert edge.event_count == 3
    assert edge.finding_ids == {"finding-1"}
    assert edge.detector_ids == {"internal-lateral-sweep"}

    incident = Incident(
        tenant_id="t1",
        site_id="s1",
        title="test",
        severity=Severity.HIGH,
        confidence=0.88,
        finding_ids={"finding-1"},
        entities={"10.0.0.17", "10.0.0.20"},
    )
    trace = engine.trace_incident(incident)
    assert len(trace.edges) == 1
    assert len(trace.nodes) == 2
