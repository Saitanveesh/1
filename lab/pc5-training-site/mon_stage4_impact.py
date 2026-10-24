"""PC-5: bounded application-side record of *fictional* data exposure.

Server-created events only. No attacker-supplied 'impact' values are trusted.
Counts describe responses the socket handler wrote, not proof that a remote
client received them. No real university files, personal data or secrets exist.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
JOURNAL = Path(os.environ.get("MON_TRAINING_IMPACT_JOURNAL", str(ROOT / "impact-events.jsonl")))
MAX_JOURNAL_BYTES = 4 * 1024 * 1024
READ_BYTES = 4 * 1024 * 1024
LOCK = threading.Lock()
CATEGORIES = frozenset({"fictional_canary", "fictional_student", "fictional_internal_notices"})
MAX_EVENTS = 3500


def utc_now() -> datetime:
    return datetime.now(UTC)


def append_event(
    source: str, route: str, status: int, response_bytes: int,
    category: str | None = None, fictional_records: int = 0
) -> None:
    if category not in CATEGORIES:
        category = None
        fictional_records = 0
    item = {
        "at": utc_now().isoformat(timespec="milliseconds"),
        "source": source,
        "route": route,
        "http_status": int(status),
        "response_bytes_written": max(0, int(response_bytes)),
        "fictional_exposure": category if 200 <= status < 300 and response_bytes > 0 else None,
        "fictional_records": fictional_records if 200 <= status < 300 and response_bytes > 0 else 0,
    }
    encoded = (json.dumps(item, separators=(",", ":")) + "\n").encode("utf-8")
    with LOCK:
        JOURNAL.parent.mkdir(parents=True, exist_ok=True)
        if JOURNAL.exists() and JOURNAL.stat().st_size + len(encoded) > MAX_JOURNAL_BYTES:
            previous = JOURNAL.with_suffix(".previous.jsonl")
            os.replace(JOURNAL, previous)
        descriptor = os.open(str(JOURNAL), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            written = os.write(descriptor, encoded)
            if written != len(encoded):
                raise OSError("impact event journal short write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _lines(file: Path):
    if not file.exists():
        return []
    with file.open("rb") as f:
        size = file.stat().st_size
        f.seek(max(0, size - READ_BYTES))
        if size > READ_BYTES:
            f.readline()
        return f.read(READ_BYTES).splitlines()


def impact_summary(source: str, since: str | None = None, now: datetime | None = None) -> dict[str, Any]:
    instant = now or utc_now()
    lower = instant - timedelta(hours=1)
    if since:
        try:
            candidate = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if candidate.utcoffset() is None:
                raise ValueError
        except ValueError:
            raise ValueError("invalid impact window") from None
        lower = max(instant - timedelta(hours=1), candidate.astimezone(UTC))
        if lower > instant + timedelta(seconds=30):
            raise ValueError("impact window is in the future")
    examined: list[dict] = []
    files = (JOURNAL.with_suffix(".previous.jsonl"), JOURNAL)
    with LOCK:
        for path in files:
            for raw in _lines(path):
                try:
                    row = json.loads(raw)
                    at = datetime.fromisoformat(row["at"].replace("Z", "+00:00"))
                    if row.get("source") != source or not lower <= at <= instant + timedelta(seconds=3):
                        continue
                    if row.get("fictional_exposure") not in CATEGORIES | {None}:
                        continue
                    examined.append(row)
                except (UnicodeError, ValueError, KeyError, TypeError, AttributeError):
                    continue
    examined = sorted(examined, key=lambda row: row["at"])[-MAX_EVENTS:]
    exposures = [r for r in examined if r["fictional_exposure"] in CATEGORIES]
    category_counts = {key: sum(r["fictional_exposure"] == key for r in exposures)
                       for key in sorted(CATEGORIES)}
    return {
        "status": "OBSERVED",
        "source": source,
        "window_start": lower.isoformat(),
        "window_end": instant.isoformat(),
        "observed_requests": len(examined),
        "successful_http_responses": sum(200 <= r.get("http_status", 0) < 300 for r in examined),
        "fictional_exposure_responses": len(exposures),
        "fictional_records_in_responses": sum(int(r["fictional_records"]) for r in exposures),
        "fictional_response_bytes_written": sum(int(r["response_bytes_written"]) for r in exposures),
        "exposure_categories": category_counts,
        "last_fictional_exposure_at": exposures[-1]["at"] if exposures else None,
        "recent_events": examined[-30:],
        "truncated": len(examined) >= MAX_EVENTS,
        "scope": "Fictional training fixtures only; bytes written by the server, not verified client receipt",
    }
