"""Exercise receipts: canonical hash, immutable storage, SQL and API scope."""
import datetime as dt

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from mon.api import app, store
from mon.database import DatabaseStore
from mon.range_evidence import ExerciseReceipt
from mon.range_exercise import ExercisePermit, execute_exercise
from mon.store import InMemoryStore


def receipt(*, exercise_id="range-1", status=200) -> ExerciseReceipt:
    now = dt.datetime.now(dt.UTC)
    permit = ExercisePermit(
        exercise_id=exercise_id, target_ip="127.0.0.1", target_port=8081,
        tenant_id="tenant-range", site_id="site-1", approved_by="Lab Operator",
        expires_at=now + dt.timedelta(minutes=15), rps=1, duration_seconds=1,
    )
    clock = [0.0]

    def monotonic():
        return clock[0]

    def sleep(seconds):
        clock[0] += seconds

    payload = execute_exercise(
        permit,
        monotonic=monotonic,
        sleep=sleep,
        verify=lambda _: None,
        get=lambda *_: (status, 0.05, b""),
    )
    return ExerciseReceipt.model_validate(payload)


def test_evidence_has_verifiable_hash_and_no_compromise_claim():
    record = receipt()
    assert record.attempts == 1
    assert record.http_200 == 1
    assert record.provenance == "SELF_REPORTED_EXERCISE"
    with pytest.raises(ValidationError, match="sha256 mismatch"):
        ExerciseReceipt.model_validate({
            **record.model_dump(), "other_or_failed": 1,
        })
    with pytest.raises(ValidationError):
        ExerciseReceipt.model_validate({
            **record.model_dump(), "attack_claim": "CONFIRMED_COMPROMISE",
        })


@pytest.mark.parametrize("engine", ["memory", "sqlite"])
def test_store_persists_only_scoped_immutable_evidence(engine, tmp_path):
    records = (
        InMemoryStore() if engine == "memory"
        else DatabaseStore(
            f"sqlite+pysqlite:///{tmp_path / 'range-evidence.sqlite'}",
            create_schema=True,
        )
    )
    try:
        first = receipt()
        assert records.add_exercise_receipt(first) is True
        assert records.add_exercise_receipt(first) is False
        assert records.list_exercise_receipts("tenant-range", "site-1") == [first]
        assert records.list_exercise_receipts("other-tenant", "site-1") == []
        assert records.list_exercise_receipts("tenant-range", "another-site") == []
        with pytest.raises(ValueError, match="different evidence"):
            records.add_exercise_receipt(receipt(status=503))
        with pytest.raises(ValueError, match="limit"):
            records.list_exercise_receipts("tenant-range", "site-1", limit=101)
    finally:
        if engine == "sqlite":
            records.close()


def test_api_refuses_cross_scope_access_and_hash_tampering():
    store.__init__()
    client = TestClient(app)
    record = receipt(exercise_id="api-range-42")
    result = client.post(
        "/api/v1/range/exercises",
        json=record.model_dump(mode="json"),
    )
    assert result.status_code == 201, result.text
    assert result.json()["stored"] is True
    repeat = client.post(
        "/api/v1/range/exercises", json=record.model_dump(mode="json")
    )
    assert repeat.status_code == 201
    assert repeat.json()["stored"] is False
    obtained = client.get(
        "/api/v1/range/exercises",
        params={"tenant_id": "tenant-range", "site_id": "site-1"},
    )
    assert obtained.status_code == 200
    assert len(obtained.json()) == 1
    assert obtained.json()[0]["sha256"] == record.sha256
    assert client.get(
        "/api/v1/range/exercises",
        params={"tenant_id": "tenant-range", "site_id": "other"},
    ).json() == []
    changed = record.model_dump(mode="json")
    changed["http_200"] = 0
    assert client.post("/api/v1/range/exercises", json=changed).status_code == 422
    assert client.post(
        "/api/v1/range/exercises",
        json=receipt(exercise_id="api-range-42", status=503).model_dump(mode="json"),
    ).status_code == 409
