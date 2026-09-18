import datetime as dt

from mon.detection import DetectionEngine
from mon.domain import SecurityEvent


def event(
    index: int,
    *,
    category: str = "network.connection",
    src: str = "10.0.0.5",
    dst: str | None = None,
    protocol: str = "tcp",
    attributes: dict[str, object] | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        tenant_id="tenant-a",
        site_id="site-1",
        sensor_id="sensor-1",
        observed_at=dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC)
        + dt.timedelta(milliseconds=index * 100),
        category=category,
        src_ip=src,
        dst_ip=dst or f"10.0.1.{(index % 20) + 1}",
        protocol=protocol,
        attributes=attributes or {},
    )


def test_syn_recon_requires_rate_and_fanout() -> None:
    engine = DetectionEngine()
    findings = []
    for index in range(60):
        findings.extend(
            engine.process(
                event(
                    index,
                    attributes={
                        "tcp_syn": True,
                        "tcp_ack": False,
                        "dst_port": 1000 + (index % 20),
                    },
                )
            )
        )

    assert len(findings) == 1
    assert findings[0].detector_id == "tcp-syn-recon"
    assert findings[0].attributes["unique_destinations"] >= 10
    assert "not proof" in str(findings[0].attributes["claim"])


def test_internal_lateral_sweep_claim_is_evidence_bounded() -> None:
    engine = DetectionEngine()
    findings = []
    for index in range(12):
        findings.extend(
            engine.process(
                event(
                    index,
                    dst=f"10.0.2.{index + 1}",
                    attributes={"direction": "east-west", "dst_port": 445},
                )
            )
        )

    assert len(findings) == 1
    assert findings[0].detector_id == "internal-lateral-sweep"
    assert "not proof" in str(findings[0].attributes["claim"])
