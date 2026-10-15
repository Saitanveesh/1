"""ARP ambiguity detector: time-bounded, scope-isolated and no false MITM claim."""
import datetime as dt

from mon.detection import DetectionEngine
from mon.domain import SecurityEvent

START = dt.datetime(2026, 10, 15, 9, tzinfo=dt.UTC)


def event(mac, *, ip="10.253.42.20", ms=0, tenant="a", site="s"):
    return SecurityEvent(
        tenant_id=tenant, site_id=site,
        sensor_id="arp-passive", category="arp.reply",
        observed_at=START + dt.timedelta(milliseconds=ms),
        src_ip=ip, protocol="arp",
        attributes={
            "arp_opcode": 2,
            "arp_sender_ip": ip,
            "arp_sender_mac": mac,
        },
    )


def test_conflicting_arp_claims_create_evidence_only():
    engine = DetectionEngine()
    assert engine.process(event("02:aa:bb:cc:dd:01")) == []
    findings = engine.process(event("02:aa:bb:cc:dd:02", ms=250))
    result = next(f for f in findings if f.detector_id == "arp-binding-conflict")
    assert result.severity.value == "HIGH"
    assert result.attributes["claimed_ip"] == "10.253.42.20"
    assert result.attributes["observed_macs"] == [
        "02:aa:bb:cc:dd:01", "02:aa:bb:cc:dd:02"
    ]
    assert "not confirmed MITM" in result.attributes["claim"]
    assert result.evidence[-1].evidence_class.value == "NETWORK_PACKET"


def test_scope_isolated_and_expired_claims_do_not_cross_correlate():
    engine = DetectionEngine()
    engine.process(event("02:aa:bb:cc:dd:01", tenant="tenant-1"))
    assert not engine.process(event(
        "02:aa:bb:cc:dd:02", tenant="tenant-2", ms=500
    ))
    assert not engine.process(event(
        "02:aa:bb:cc:dd:02", tenant="tenant-1", site="other", ms=500
    ))
    assert not engine.process(event(
        "02:aa:bb:cc:dd:02", tenant="tenant-1", ms=46_000
    ))


def test_same_mac_or_invalid_reply_never_becomes_mitm():
    engine = DetectionEngine()
    for i in range(8):
        assert not engine.process(event("02:aa:bb:cc:dd:01", ms=i * 100))
    for mac in ["01:aa:bb:cc:dd:02", "not-a-mac", "00:00:00:00:00:00"]:
        assert not engine.process(event(mac, ms=900))


def test_emission_is_cooldown_bounded():
    engine = DetectionEngine()
    engine.process(event("02:aa:bb:cc:dd:01"))
    assert any(f.detector_id == "arp-binding-conflict" for f in engine.process(
        event("02:aa:bb:cc:dd:02", ms=1000)
    ))
    assert not any(f.detector_id == "arp-binding-conflict" for f in engine.process(
        event("02:aa:bb:cc:dd:03", ms=2000)
    ))
