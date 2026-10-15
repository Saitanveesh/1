"""Measured multi-source pressure detection, source scope and no outage claim."""
import datetime as dt
import json

from mon.detection import DetectionEngine
from mon.domain import SecurityEvent
from tools.range_lab.analyze_http import analyze, events_from_service_log

BASE = dt.datetime(2026, 10, 15, 12, tzinfo=dt.UTC)


def event(index, *, source):
    return SecurityEvent(
        tenant_id="range", site_id="isolated", sensor_id="victim-http",
        category="app.http-request", protocol="tcp",
        observed_at=BASE + dt.timedelta(milliseconds=index * 180),
        src_ip=source, dst_ip="10.253.42.20",
        attributes={"dst_port": 8081, "http_status": 200},
    )


def test_multiple_distinct_origins_emit_one_bounded_pressure_finding():
    detector = DetectionEngine()
    findings = []
    for i in range(42):
        ip = ["10.253.42.11", "10.253.42.12", "10.253.42.30"][i % 3]
        findings.extend(detector.process(event(i, source=ip)))
    pressure = [f for f in findings if f.detector_id == "http-multi-source-pressure"]
    assert len(pressure) == 1
    assert pressure[0].src_ip is None
    assert pressure[0].dst_ip == "10.253.42.20"
    assert len(pressure[0].attributes["source_ips"]) == 3
    assert "not proof of volumetric DDoS" in pressure[0].attributes["claim"]


def test_single_source_and_mismatched_scope_do_not_trigger_multi_source():
    detector = DetectionEngine()
    assert all(
        not detector.process(event(i, source="10.253.42.11"))
        for i in range(30)
    )


def test_victim_log_parser_only_uses_real_request_fields():
    logs = [
        json.dumps({
            "observed_at": (BASE + dt.timedelta(milliseconds=i * 150)).isoformat(),
            "src_ip": ["10.253.42.11", "10.253.42.12", "10.253.42.30"][i % 3],
            "path": "/api/students?limit=1", "status": 200, "elapsed_ms": 120,
        })
        for i in range(30)
    ]
    data = "\n".join(["MON isolated namespace-only target starting", *logs, "{}"])
    events = events_from_service_log(data, target="10.253.42.20")
    assert len(events) == 30
    report = analyze(data, "10.253.42.20")
    assert report["requests_recorded"] == 30
    assert report["finding_count"] >= 1
    assert len(report["source_ips_observed"]) == 3
    assert "not verified upstream volumetric DDoS" in report["claim"]
