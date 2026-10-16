"""Bounded live ERP exercise must fail closed and never invent evidence."""
import datetime as dt
import json

import pytest
from pydantic import ValidationError

from mon.range_exercise import (
    ExercisePermit,
    execute_exercise,
    read_permit,
    verify_test_only_target,
)


def permit(**changes):
    obj = {
        "exercise_id": "exercise-001",
        "target_ip": "127.0.0.1",
        "target_port": 8081,
        "tenant_id": "tenant-a",
        "site_id": "site-a",
        "approved_by": "Authorized Operator",
        "expires_at": (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=30)).isoformat(),
        "rps": 2,
        "duration_seconds": 3,
    }
    obj.update(changes)
    return ExercisePermit.model_validate(obj)


def test_permit_is_limited_to_private_literal_ips_approved_fixed_port():
    for address in ("8.8.8.8", "169.254.1.2", "example.com", "224.0.0.1"):
        with pytest.raises(ValidationError):
            permit(target_ip=address)
    with pytest.raises(ValidationError):
        permit(target_port=80)
    with pytest.raises(ValidationError):
        permit(rps=100)
    with pytest.raises(ValidationError):
        permit(duration_seconds=600)
    with pytest.raises(ValidationError):
        permit(expires_at="2026-10-15T12:00:00")


def test_approval_file_must_be_secret_and_unexpired(tmp_path):
    path = tmp_path / "permit.json"
    data = permit()
    path.write_text(data.model_dump_json(), encoding="utf-8")
    path.chmod(0o600)
    assert read_permit(path) == data
    path.chmod(0o644)
    with pytest.raises(ValueError, match="mode 0600"):
        read_permit(path)
    path.chmod(0o600)
    with pytest.raises(ValueError, match="expired"):
        read_permit(path, now=data.expires_at + dt.timedelta(seconds=1))


def test_preflight_requires_real_synthetic_erp_marker(monkeypatch):
    from mon import range_exercise

    def fake_get(*args):
        return 200, 0.01, json.dumps({
            "service": "Ordinary campus ERP", "environment": "production"
        }).encode("utf-8")
    monkeypatch.setattr(range_exercise, "_get", fake_get)
    with pytest.raises(ValueError, match="verified MON"):
        verify_test_only_target(permit())


def test_bounded_request_evidence_counts_only_actual_results():
    clock = [0.0]

    def monotonic():
        return clock[0]

    def sleep(seconds):
        clock[0] += seconds

    calls = []

    def get(ip, port, path):
        calls.append((ip, port, path))
        if len(calls) % 2:
            return 200, 0.01234567, b""
        return 503, 0.1, b""

    verified = []
    result = execute_exercise(
        permit(),
        monotonic=monotonic, sleep=sleep,
        get=get, verify=lambda p: verified.append(p),
    )
    assert len(verified) == 1
    assert result["attempts"] == 6
    assert result["http_200"] == 3
    assert result["other_or_failed"] == 3
    assert all(call[2] == "/api/students?limit=1" for call in calls)
    assert result["attack_claim"] == "NONE"
    assert result["containment_claim"] == "NONE"
    assert len(result["sha256"]) == 64
    assert result["samples"][0]["latency_seconds"] == 0.012346


def test_abort_preflight_without_sending_workload():
    visited = []
    def deny(_):
        raise ValueError("not the isolated ERP")
    with pytest.raises(ValueError, match="not the isolated"):
        execute_exercise(permit(), verify=deny, get=lambda *args: visited.append(args))
    assert visited == []


def test_error_and_timeout_are_recorded_as_failures():
    time_values = [0.0]

    def monotonic():
        return time_values[0]

    def sleep(delta):
        time_values[0] += delta

    def fail(*args):
        raise TimeoutError("lab service timed out")

    summary = execute_exercise(
        permit(duration_seconds=2, rps=1),
        monotonic=monotonic, sleep=sleep,
        get=fail, verify=lambda _: None,
    )
    assert summary["attempts"] == 2
    assert summary["other_or_failed"] == 2
    assert summary["samples"][0]["http_status"] is None
    assert summary["samples"][0]["latency_seconds"] is None
