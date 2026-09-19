from __future__ import annotations

from pathlib import Path

import pytest

from mon import fabric_load_probe as probe


def test_load_envelopes_preserves_exact_nonempty_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_bytes(b'{"event_id":"a"}\n\n {"event_id":"b"} \n')

    assert probe.load_envelopes(path) == [
        b'{"event_id":"a"}',
        b' {"event_id":"b"} ',
    ]


def test_load_envelopes_rejects_invalid_or_empty_input(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.ndjson"
    invalid.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON on line 1"):
        probe.load_envelopes(invalid)

    empty = tmp_path / "empty.ndjson"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no event-fabric envelopes"):
        probe.load_envelopes(empty)


def test_percentile_uses_nearest_rank() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 100.0]
    assert probe.percentile(values, 0.50) == 3.0
    assert probe.percentile(values, 0.95) == 100.0
    assert probe.percentile([], 0.99) == 0.0


@pytest.mark.asyncio
async def test_probe_rejects_plaintext_target_before_network_io() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        await probe.run_probe(
            url="http://127.0.0.1:8080/api/v1/site/fabric/events",
            envelopes=[b"{}"],
            concurrency=1,
            authorization=None,
            timeout_seconds=1.0,
            verify=True,
            cert=None,
        )


@pytest.mark.asyncio
async def test_probe_rejects_nonpositive_concurrency() -> None:
    with pytest.raises(ValueError, match="concurrency"):
        await probe.run_probe(
            url="https://127.0.0.1/api/v1/site/fabric/events",
            envelopes=[b"{}"],
            concurrency=0,
            authorization=None,
            timeout_seconds=1.0,
            verify=True,
            cert=None,
        )
