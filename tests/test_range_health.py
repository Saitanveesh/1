"""Evidence-backed ERP health: no fabricated healthy readings or cross-tenant metrics."""
import datetime as dt
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from mon.api import app
from mon.range_health import _prometheus_url, _reading, collect_victim_health

NOW = dt.datetime(2026, 10, 15, 10, tzinfo=dt.UTC)


def test_missing_prometheus_is_unconfigured_not_healthy(monkeypatch):
    monkeypatch.delenv("MON_PROMETHEUS_URL", raising=False)
    status = collect_victim_health("tenant-a", "site-a", at=NOW)
    assert status.telemetry_state == "UNCONFIGURED"
    assert status.service_reachable.value is None
    assert status.host_ram_percent.status == "UNKNOWN"
    assert status.host_cpu_percent.status == "UNKNOWN"


def test_prometheus_url_disallows_arbitrary_campus_and_external_targets():
    assert _prometheus_url("http://prometheus:9090").endswith("/api/v1/query")
    for url in (
        "http://8.8.8.8:9090", "https://prometheus.example",
        "http://prometheus:9090/anything", "http://user:password@prometheus:9090",
    ):
        with pytest.raises(ValueError):
            _prometheus_url(url)


def test_readings_do_not_equate_missing_or_stale_with_zero():
    row = {"value": [NOW.timestamp(), "0"]}
    reading = _reading([row], at=NOW)
    assert reading.status == "FRESH"
    assert reading.value == 0
    assert _reading([], at=NOW).status == "UNKNOWN"
    assert _reading([row, row], at=NOW).status == "AMBIGUOUS"
    row["value"] = [(NOW - dt.timedelta(seconds=60)).timestamp(), "1"]
    assert _reading([row], at=NOW).status == "STALE"


def test_actual_prometheus_readings_have_scoped_labels(monkeypatch):
    expressions = []
    class FakeClient:
        def __init__(self, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def get(self, endpoint, params):
            expression = params["query"]
            expressions.append(expression)
            value = "0" if "probe_success" in expression else "1024"
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [{"value": [NOW.timestamp(), value]}],
                    },
                },
                request=httpx.Request("GET", endpoint),
            )

    monkeypatch.setattr("mon.range_health.httpx.Client", FakeClient)
    scope = 'tenant-a"test'
    result = collect_victim_health(
        scope, "site-a", prometheus_url="http://prometheus:9090", at=NOW
    )
    assert len(expressions) == 6
    assert all(f"tenant_id={json.dumps(scope)}" in q for q in expressions)
    assert all('site_id="site-a"' in q for q in expressions)
    assert result.telemetry_state == "AVAILABLE"
    assert result.service_reachable.status == "FRESH"
    assert result.service_reachable.value == 0
    assert result.note == "Independent probe recorded ERP service unavailable"
    assert result.erp_process_rss_bytes.value == 1024
    assert result.host_ram_percent.value == 1024


def test_network_failure_is_visible_as_degraded(monkeypatch):
    class FailingClient:
        def __init__(self, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def get(self, *_args, **_kwargs):
            raise httpx.ConnectError("connection failed")

    monkeypatch.setattr("mon.range_health.httpx.Client", FailingClient)
    result = collect_victim_health(
        "tenant-a", "site-a", prometheus_url="http://prometheus:9090", at=NOW
    )
    assert result.telemetry_state == "DEGRADED"
    assert result.service_reachable.status == "UNKNOWN"


def test_erp_health_api_is_scoped_and_explicitly_unknown_without_source(monkeypatch):
    monkeypatch.delenv("MON_PROMETHEUS_URL", raising=False)
    client = TestClient(app)
    response = client.get("/api/v1/range/erp-health", params={
        "tenant_id": "tenant-a", "site_id": "site-a",
    })
    assert response.status_code == 200, response.text
    assert response.json()["service_reachable"]["status"] == "UNKNOWN"
    assert response.json()["telemetry_state"] == "UNCONFIGURED"
