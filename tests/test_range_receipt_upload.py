"""Scope-safe upload of authentic, self-reported, bounded range receipts."""
import datetime as dt
import json

import pytest
from pydantic import ValidationError

from mon.range_exercise import ExercisePermit, execute_exercise
from mon.range_receipt_upload import _api_endpoint, read_receipt, upload_receipt


def sample_receipt(tmp_path):
    permit = ExercisePermit(
        exercise_id="upload-test-001", target_ip="127.0.0.1", target_port=8081,
        tenant_id="tenant", site_id="site", approved_by="Approved Operator",
        expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15),
        duration_seconds=1, rps=1,
    )
    clock = [0.0]
    def monotonic():
        return clock[0]
    def sleep(delta):
        clock[0] += delta
    receipt = execute_exercise(
        permit, monotonic=monotonic, sleep=sleep,
        get=lambda *_: (200, 0.03, b""), verify=lambda _: None,
    )
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return path, receipt


def test_upload_origin_disallows_insecure_untrusted_destination():
    assert _api_endpoint(
        "https://soc.example", allow_local_http=False
    ) == "https://soc.example/api/v1/range/exercises"
    for url in ("http://soc.example", "http://8.8.8.8",
                "https://soc.example/anything",
                "https://operator:password@soc.example"):
        with pytest.raises(ValueError):
            _api_endpoint(url, allow_local_http=False)
    assert _api_endpoint(
        "http://127.0.0.1:8080", allow_local_http=True
    ).startswith("http://127.0.0.1:8080/")


def test_receipt_is_reverified_before_upload(tmp_path):
    path, values = sample_receipt(tmp_path)
    assert read_receipt(path).sha256 == values["sha256"]
    values["attempts"] = 20
    path.write_text(json.dumps(values), encoding="utf-8")
    with pytest.raises(ValidationError, match="sha256 mismatch"):
        read_receipt(path)


def test_upload_uses_scoped_token_file_without_proxy_or_redirect(tmp_path, monkeypatch):
    path, record = sample_receipt(tmp_path)
    token_path = tmp_path / "token"
    token_path.write_text("placeholder-test-token\n", encoding="utf-8")
    token_path.chmod(0o600)
    requests = []

    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def read(self, *_args):
            return json.dumps({
                "exercise_id": record["exercise_id"], "stored": True,
                "provenance": "SELF_REPORTED_EXERCISE",
            }).encode("utf-8")

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            assert timeout == 10
            return Response()

    def build_opener(*handlers):
        assert len(handlers) == 2
        return Opener()

    monkeypatch.setattr("mon.range_receipt_upload.urllib.request.build_opener", build_opener)
    result = upload_receipt(
        path, api_url="https://soc.example", token_file=token_path,
    )
    assert result["stored"] is True
    assert result["sha256"] == record["sha256"]
    assert len(requests) == 1
    assert requests[0].get_header("Authorization") == "Bearer placeholder-test-token"
    assert requests[0].full_url.endswith("/api/v1/range/exercises")
    assert b"SELF_REPORTED_EXERCISE" not in requests[0].data

    token_path.chmod(0o644)
    with pytest.raises(ValueError, match="group/other"):
        upload_receipt(path, api_url="https://soc.example", token_file=token_path)
