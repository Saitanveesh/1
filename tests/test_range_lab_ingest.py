"""Sandbox capture evidence must be real, scoped and acked by MON."""
import datetime as dt
import json
import urllib.request

import pytest

from mon.domain import SecurityEvent
from tools.range_lab.ingest import _url, load_captured_events, upload

NOW = dt.datetime(2026, 10, 15, 10, tzinfo=dt.UTC)


def test_only_present_actual_capture_files_are_accepted(tmp_path):
    (tmp_path / "victim.jsonl").write_text(
        json.dumps({
            "observed_at": NOW.isoformat(), "src_ip": "10.253.42.11",
            "status": 200, "elapsed_ms": 130,
        }) + "\n", encoding="utf-8",
    )
    events, digests = load_captured_events(
        tmp_path, target="10.253.42.20",
        tenant_id="tenant-a", site_id="site-a",
    )
    assert len(events) == 1
    assert events[0].tenant_id == "tenant-a"
    assert events[0].site_id == "site-a"
    assert events[0].src_ip == "10.253.42.11"
    assert len(digests["victim.jsonl"]) == 64
    assert load_captured_events(
        tmp_path, target="10.253.42.20",
        tenant_id="tenant-a", site_id="site-a",
    )[0][0].event_id == events[0].event_id
    with pytest.raises(ValueError, match="isolated"):
        load_captured_events(
            tmp_path, target="192.0.2.50", tenant_id="x", site_id="y",
        )


def test_missing_capture_does_not_generate_fake_events(tmp_path):
    with pytest.raises(ValueError, match="no real"):
        load_captured_events(
            tmp_path, target="10.253.42.20",
            tenant_id="tenant", site_id="site",
        )


def test_cannot_upload_campus_or_insecure_url():
    assert _url("https://mon.example").endswith("/api/v1/events/batch")
    for url in ("http://mon.example", "https://host/path",
                "https://u:p@mon.example", "http://8.8.8.8"):
        with pytest.raises(ValueError):
            _url(url)


def test_authenticated_upload_requires_exact_event_ack(tmp_path, monkeypatch):
    token = tmp_path / "token"
    token.write_text("test-only-ingest-token\n", encoding="utf-8")
    token.chmod(0o600)
    event = SecurityEvent(
        tenant_id="t", site_id="s", sensor_id="capture",
        category="arp.reply", observed_at=NOW,
    )
    collected = []

    class Resp:
        def __init__(self, data):
            self.data = data

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, *args):
            return json.dumps(self.data).encode()

    class Client:
        def open(self, request, timeout):
            collected.append(request)
            assert timeout == 10
            payload = json.loads(request.data)
            assert payload["events"][0]["event_id"] == event.event_id
            return Resp({
                "results": [{"event": payload["events"][0]}],
                "accepted_event_ids": [event.event_id],
            })

    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *handlers: Client()
    )
    result = upload([event], api_origin="https://mon.example", token_file=token)
    assert result == {"batches_acknowledged": 1, "events_acknowledged": 1}
    assert collected[0].get_header("Authorization") == "Bearer test-only-ingest-token"
