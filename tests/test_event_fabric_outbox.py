import datetime as dt
import sqlite3

import pytest

from mon.domain import SecurityEvent
from mon.event_fabric_outbox import DurableFabricOutbox


def event(
    event_id: str = "event-1",
    *,
    tenant_id: str = "tenant-a",
    site_id: str = "site-a",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id="sensor-1",
        observed_at=dt.datetime(2026, 9, 19, 7, 0, tzinfo=dt.UTC),
        category="network.connection",
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        protocol="tcp",
        attributes={"dst_port": 443},
    )


class Clock:
    def __init__(self, now: dt.datetime) -> None:
        self.now = now

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += dt.timedelta(seconds=seconds)


def test_outbox_reuses_exact_persisted_envelope_across_restart(tmp_path) -> None:
    path = tmp_path / "fabric-outbox.db"
    produced_at = dt.datetime(2026, 9, 19, 7, 1, tzinfo=dt.UTC)
    first = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    original = first.enqueue_security_event(
        event(),
        produced_at=produced_at,
    )
    first.close()

    reopened = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        replay = reopened.enqueue_security_event(
            event(),
            produced_at=produced_at + dt.timedelta(hours=1),
        )
        assert replay == original
        assert replay.produced_at == produced_at
        assert replay.canonical_sha256 == original.canonical_sha256
        assert reopened.diagnostics()["pending"] == 1
    finally:
        reopened.close()


def test_outbox_rejects_scope_reuse_and_conflicting_event_content(tmp_path) -> None:
    path = tmp_path / "fabric-outbox.db"
    outbox = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        original = event()
        outbox.enqueue_security_event(original)
        with pytest.raises(ValueError, match="different content"):
            outbox.enqueue_security_event(
                original.model_copy(update={"dst_ip": "10.9.9.9"})
            )
        with pytest.raises(ValueError, match="scope"):
            outbox.enqueue_security_event(
                event("foreign", tenant_id="tenant-b")
            )
    finally:
        outbox.close()

    with pytest.raises(ValueError, match="tenant_id mismatch"):
        DurableFabricOutbox(
            path,
            tenant_id="tenant-b",
            site_id="site-a",
        )


def test_first_failure_schedules_future_retry(tmp_path) -> None:
    clock = Clock(dt.datetime(2026, 9, 19, 7, 0, tzinfo=dt.UTC))
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
        base_retry_delay=10,
        max_retry_delay=60,
        now=clock,
        jitter=lambda _attempt: 0.0,
    )
    try:
        outbox.enqueue_security_event(event())
        assert outbox.mark_failed("event-1", "cloud unavailable")
        diagnostics = outbox.diagnostics()
        assert diagnostics["pending"] == 1
        assert diagnostics["max_attempts"] == 1
        assert diagnostics["last_error"] == "cloud unavailable"
        assert diagnostics["backoff_active"] is True
        assert diagnostics["current_retry_delay_seconds"] == 10.0
        assert diagnostics["next_attempt_at"] == (
            clock.now + dt.timedelta(seconds=10)
        ).isoformat()
        assert outbox.pending() == []

        clock.advance(10)
        assert [item.event_id for item in outbox.pending()] == ["event-1"]
    finally:
        outbox.close()


def test_repeated_failures_increase_delay_until_cap(tmp_path) -> None:
    clock = Clock(dt.datetime(2026, 9, 19, 7, 0, tzinfo=dt.UTC))
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
        base_retry_delay=5,
        max_retry_delay=20,
        now=clock,
        jitter=lambda _attempt: 0.0,
    )
    try:
        outbox.enqueue_security_event(event())
        expected = [5.0, 10.0, 20.0, 20.0]
        for delay in expected:
            assert outbox.mark_failed("event-1", "cloud unavailable")
            diagnostics = outbox.diagnostics()
            assert diagnostics["current_retry_delay_seconds"] == delay
            assert diagnostics["next_attempt_at"] == (
                clock.now + dt.timedelta(seconds=delay)
            ).isoformat()
            clock.advance(delay)
    finally:
        outbox.close()


def test_deterministic_jitter_is_bounded_and_non_negative(tmp_path) -> None:
    now = dt.datetime(2026, 9, 19, 7, 0, tzinfo=dt.UTC)
    positive = DurableFabricOutbox(
        tmp_path / "positive.db",
        tenant_id="tenant-a",
        site_id="site-a",
        base_retry_delay=10,
        max_retry_delay=60,
        jitter=lambda _attempt: 1.0,
    )
    negative = DurableFabricOutbox(
        tmp_path / "negative.db",
        tenant_id="tenant-a",
        site_id="site-a",
        base_retry_delay=10,
        max_retry_delay=60,
        jitter=lambda _attempt: -1.0,
    )
    try:
        high = positive.retry_schedule(next_attempt_number=1, now=now)
        low = negative.retry_schedule(next_attempt_number=1, now=now)
        assert high.effective_delay_seconds == 12.0
        assert high.jitter_seconds == 2.0
        assert low.effective_delay_seconds == 8.0
        assert low.jitter_seconds == -2.0
        capped = positive.retry_schedule(next_attempt_number=20, now=now)
        assert capped.effective_delay_seconds == 60.0
    finally:
        positive.close()
        negative.close()


def test_success_clears_active_retry_state(tmp_path) -> None:
    clock = Clock(dt.datetime(2026, 9, 19, 7, 0, tzinfo=dt.UTC))
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
        now=clock,
        jitter=lambda _attempt: 0.0,
    )
    try:
        outbox.enqueue_security_event(event())
        outbox.mark_failed("event-1", "cloud unavailable")
        assert outbox.diagnostics()["backoff_active"] is True
        assert outbox.mark_delivered("event-1", now=clock.now)
        diagnostics = outbox.diagnostics()
        assert diagnostics["pending"] == 0
        assert diagnostics["backoff_active"] is False
        assert diagnostics["next_attempt_at"] is None
        assert diagnostics["last_error"] is None
    finally:
        outbox.close()


def test_restart_preserves_attempts_and_next_retry_time(tmp_path) -> None:
    path = tmp_path / "fabric-outbox.db"
    start = dt.datetime(2026, 9, 19, 7, 0, tzinfo=dt.UTC)
    clock = Clock(start)
    first = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
        base_retry_delay=10,
        max_retry_delay=60,
        now=clock,
        jitter=lambda _attempt: 0.0,
    )
    first.enqueue_security_event(event())
    first.mark_failed("event-1", "cloud unavailable")
    first.close()

    reopened = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
        base_retry_delay=10,
        max_retry_delay=60,
        now=clock,
        jitter=lambda _attempt: 0.0,
    )
    try:
        diagnostics = reopened.diagnostics()
        assert diagnostics["max_attempts"] == 1
        assert diagnostics["next_attempt_at"] == (
            start + dt.timedelta(seconds=10)
        ).isoformat()
        assert reopened.pending() == []
        clock.advance(10)
        assert [item.event_id for item in reopened.pending()] == ["event-1"]
    finally:
        reopened.close()


def test_legacy_outbox_schema_upgrades_without_queued_event_loss(tmp_path) -> None:
    path = tmp_path / "fabric-outbox.db"
    legacy = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    original = legacy.enqueue_security_event(event())
    legacy.close()
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE fabric_outbox_metadata SET value = '1' WHERE key = 'schema_version'"
        )
        connection.commit()
    finally:
        connection.close()

    upgraded = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        assert upgraded.get("event-1") == original
        assert [item.event_id for item in upgraded.pending()] == ["event-1"]
        assert upgraded.diagnostics()["pending"] == 1
    finally:
        upgraded.close()


def test_corrupted_retry_timestamp_fails_safely(tmp_path) -> None:
    path = tmp_path / "fabric-outbox.db"
    outbox = DurableFabricOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    outbox.enqueue_security_event(event())
    outbox.mark_failed("event-1", "cloud unavailable")
    outbox.close()

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE fabric_outbox SET next_attempt_at = 'not-a-time' WHERE event_id = 'event-1'"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ValueError, match="next_attempt_at"):
        DurableFabricOutbox(
            path,
            tenant_id="tenant-a",
            site_id="site-a",
        )


def test_persisted_last_error_redacts_credentials(tmp_path) -> None:
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
        jitter=lambda _attempt: 0.0,
    )
    try:
        outbox.enqueue_security_event(event())
        outbox.mark_failed(
            "event-1",
            "Authorization: Bearer secret-token password=hunter2 private_key=abc",
        )
        diagnostics = outbox.diagnostics()
        assert "secret-token" not in str(diagnostics)
        assert "hunter2" not in str(diagnostics)
        assert "private_key=abc" not in str(diagnostics)
        assert "[REDACTED]" in str(diagnostics)
    finally:
        outbox.close()


def test_delivered_receipt_survives_until_source_is_reconciled(tmp_path) -> None:
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    delivered_at = dt.datetime(2026, 9, 19, 8, 0, tzinfo=dt.UTC)
    try:
        outbox.enqueue_security_event(event())
        assert outbox.mark_delivered("event-1", now=delivered_at)
        assert outbox.pending() == []
        assert [
            item.event_id
            for item in outbox.delivered_unreconciled()
        ] == ["event-1"]

        assert (
            outbox.compact_reconciled(
                retain_for=dt.timedelta(seconds=1),
                now=delivered_at + dt.timedelta(days=1),
            )
            == 0
        )
        assert outbox.get("event-1") is not None

        assert outbox.mark_source_reconciled(
            "event-1",
            now=delivered_at + dt.timedelta(seconds=1),
        )
        assert (
            outbox.compact_reconciled(
                retain_for=dt.timedelta(hours=1),
                now=delivered_at + dt.timedelta(hours=2),
            )
            == 1
        )
        assert outbox.get("event-1") is None
    finally:
        outbox.close()


def test_source_cannot_be_reconciled_before_delivery(tmp_path) -> None:
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        outbox.enqueue_security_event(event())
        with pytest.raises(ValueError, match="before delivery"):
            outbox.mark_source_reconciled("event-1")
    finally:
        outbox.close()


def test_pending_delivery_preserves_creation_order(tmp_path) -> None:
    outbox = DurableFabricOutbox(
        tmp_path / "fabric-outbox.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    base = dt.datetime(2026, 9, 19, 7, 0, tzinfo=dt.UTC)
    try:
        outbox.enqueue_security_event(
            event("event-2"),
            produced_at=base + dt.timedelta(seconds=2),
        )
        outbox.enqueue_security_event(
            event("event-1"),
            produced_at=base + dt.timedelta(seconds=1),
        )
        assert [
            item.event_id for item in outbox.pending()
        ] == ["event-1", "event-2"]
    finally:
        outbox.close()
