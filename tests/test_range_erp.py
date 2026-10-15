"""Actual instrumented (not animated) disposable ERP regression tests."""
import pytest
from fastapi.testclient import TestClient

from demo.erp_range.app import main as erp


@pytest.fixture
def client():
    return TestClient(erp.app)


def test_range_banner_and_real_liveness(client):
    result = client.get("/health/live")
    assert result.status_code == 200
    assert result.json()["environment"] == "isolated-range"
    assert "NO REAL STUDENT DATA" in result.json()["service"]


def test_ready_is_fail_closed_when_database_is_missing(client, monkeypatch):
    def failed(*_args, **_kwargs):
        raise RuntimeError("unreachable")

    monkeypatch.setattr(erp, "database_query", failed)
    result = client.get("/health/ready")
    assert result.status_code == 503
    assert result.json()["detail"] == "Synthetic ERP database unavailable"


def test_ready_requires_real_database_response(client, monkeypatch):
    monkeypatch.setattr(erp, "database_query", lambda *_a, **_k: [(250,)])
    result = client.get("/health/ready")
    assert result.status_code == 200
    assert result.json()["database"] == "RESPONDING"
    assert result.json()["synthetic_records"] == "250"


def test_student_api_is_generated_only_and_parameterized(client, monkeypatch):
    observed = []
    def query(sql, params=()):
        observed.append((sql, params))
        return [("DEMO-00001", "Fictional Student 00001", "Engineering Practice")]

    monkeypatch.setattr(erp, "database_query", query)
    result = client.get("/api/students?limit=1")
    assert result.status_code == 200
    assert result.json()["dataset"] == "FICTIONAL / GENERATED TEST RECORDS"
    assert observed[0][1] == (1,)
    assert "%s" in observed[0][0]
    assert client.get("/api/students?limit=10000").status_code == 422
    assert client.get("/api/record/anything-real").status_code == 404
    record = client.get("/api/record/DEMO-00001")
    assert record.status_code == 200
    assert observed[-1][1] == ("DEMO-00001",)


def test_metrics_are_process_observations_not_fake_host_health(client):
    result = client.get("/metrics")
    assert result.status_code == 200
    assert "mon_erp_http_requests_total" in result.text
    assert "mon_erp_process_rss_bytes" in result.text
    assert "mon_erp_process_cpu_seconds" in result.text
    assert "mon_erp_fake_host_cpu" not in result.text
