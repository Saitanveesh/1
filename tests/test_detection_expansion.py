import datetime as dt

from mon.detection import DetectionEngine
from mon.domain import SecurityEvent

BASE = dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC)


def event(
    index: int,
    *,
    protocol: str = "tcp",
    dst: str = "10.0.0.20",
    category: str = "network.connection",
    attributes: dict[str, object] | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        tenant_id="tenant-a",
        site_id="site-1",
        sensor_id="sensor",
        observed_at=BASE + dt.timedelta(milliseconds=index * 30),
        category=category,
        src_ip="10.0.0.17",
        dst_ip=dst,
        protocol=protocol,
        attributes=attributes or {},
    )


def test_concentrated_syn_pressure_is_separate_from_recon() -> None:
    engine = DetectionEngine()
    findings = []
    for index in range(200):
        findings.extend(
            engine.process(
                event(
                    index,
                    attributes={
                        "tcp_syn": True,
                        "tcp_ack": False,
                        "dst_port": 443,
                    },
                )
            )
        )

    ids = {item.detector_id for item in findings}
    assert "tcp-syn-flood-shape" in ids
    assert "tcp-syn-recon" not in ids
    flood = next(item for item in findings if item.detector_id == "tcp-syn-flood-shape")
    assert "not proof of service outage" in str(flood.attributes["claim"])


def test_udp_and_icmp_pressure_require_concentration() -> None:
    udp = DetectionEngine()
    udp_findings = []
    for index in range(300):
        udp_findings.extend(udp.process(event(index, protocol="udp")))
    assert any(item.detector_id == "udp-flood-shape" for item in udp_findings)

    icmp = DetectionEngine()
    icmp_findings = []
    for index in range(200):
        icmp_findings.extend(
            icmp.process(
                event(index, protocol="icmp", attributes={"icmp_type": 8})
            )
        )
    assert any(item.detector_id == "icmp-flood-shape" for item in icmp_findings)


def test_admin_service_attempts_do_not_claim_login_failure() -> None:
    engine = DetectionEngine()
    findings = []
    for index in range(25):
        findings.extend(
            engine.process(
                event(
                    index,
                    attributes={
                        "tcp_syn": True,
                        "tcp_ack": False,
                        "dst_port": 22,
                    },
                )
            )
        )

    finding = next(
        item
        for item in findings
        if item.detector_id == "admin-service-attempt-pressure"
    )
    assert "not evidence of authentication failure or success" in str(
        finding.attributes["claim"]
    )


def test_dns_tunnel_shape_requires_many_unique_long_queries() -> None:
    engine = DetectionEngine()
    findings = []
    for index in range(20):
        label = f"{index:02d}" + "abcdefghijklmnopqrstuvwxyz0123456789" + ("x" * 20)
        findings.extend(
            engine.process(
                event(
                    index,
                    protocol="udp",
                    category="dns.query",
                    attributes={"dns_query": f"{label}.example.test"},
                )
            )
        )

    finding = next(item for item in findings if item.detector_id == "dns-tunnel-shape")
    assert finding.attributes["unique_queries"] >= 15
    assert "not proof of data exfiltration" in str(finding.attributes["claim"])


def test_arp_sweep_uses_unique_targets() -> None:
    engine = DetectionEngine()
    findings = []
    for index in range(24):
        findings.extend(
            engine.process(
                event(
                    index,
                    protocol="arp",
                    dst=f"10.0.1.{index + 1}",
                    category="arp.request",
                    attributes={
                        "arp_opcode": 1,
                        "arp_target_ip": f"10.0.1.{index + 1}",
                    },
                )
            )
        )

    finding = next(item for item in findings if item.detector_id == "arp-discovery-sweep")
    assert finding.attributes["unique_targets"] == 24


def test_periodic_beaconing_is_low_confidence_shape_not_c2_claim() -> None:
    engine = DetectionEngine()
    findings = []
    for index in range(8):
        observed = event(
            0,
            dst="198.51.100.7",
            attributes={"dst_port": 443},
        ).model_copy(
            update={"observed_at": BASE + dt.timedelta(seconds=index * 10)}
        )
        findings.extend(engine.process(observed))

    finding = next(
        item for item in findings if item.detector_id == "periodic-beacon-shape"
    )
    assert finding.confidence == 0.68
    assert "not proof of command-and-control" in str(finding.attributes["claim"])


def test_ids_signature_is_preserved_as_ids_evidence() -> None:
    engine = DetectionEngine()
    findings = engine.process(
        event(
            0,
            category="ids.alert",
            attributes={
                "signature": "Example IDS rule",
                "severity": 1,
                "engine": "suricata",
            },
        )
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_id == "network-ids-signature"
    assert finding.severity.value == "HIGH"
    assert finding.evidence[-1].evidence_class.value == "IDS_ALERT"
    assert "not independently proof of compromise" in str(finding.attributes["claim"])
