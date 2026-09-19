import datetime as dt
import sqlite3

import pytest

from mon.domain import SecurityEvent
from mon.pipeline import PipelinePersistenceMode, SecurityPipeline
from mon.site_analysis_store import SQLiteSiteAnalysisStore
from mon.site_controller import SiteController, SiteScopeViolation, SQLiteEventSpool


class AcceptingSender:
    async def send_batch(self, events: list[SecurityEvent]) -> set[str]:
        return {event.event_id for event in events}


class FailingSender:
    async def send_batch(self, events: list[SecurityEvent]) -> set[str]:
        raise RuntimeError("cloud unavailable")


def event(index: int, *, tenant: str = "t1", site: str = "s1") -> SecurityEvent:
    return SecurityEvent(
        event_id=f"event-{index}",
        tenant_id=tenant,
        site_id=site,
        sensor_id="sensor-1",
        observed_at=dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC)
        + dt.timedelta(seconds=index),
        category="network.connection",
        src_ip="10.0.0.17",
        dst_ip=f"10.0.1.{index + 1}",
        protocol="tcp",
        attributes={"direction": "east-west", "dst_port": 445},
    )


def test_spool_survives_reopen_and_deduplicates(tmp_path) -> None:
    path = tmp_path / "spool.db"
    spool = SQLiteEventSpool(path)
    assert spool.enqueue(event(1)) is True
    assert spool.enqueue(event(1)) is False
    assert spool.count() == 1
    assert [item.event_id for item in spool.pending_analysis()] == ["event-1"]
    assert spool.pending() == []
    assert spool.mark_analysis_ready("event-1")
    spool.close()

    reopened = SQLiteEventSpool(path)
    assert [item.event_id for item in reopened.pending()] == ["event-1"]
    reopened.close()


def test_site_controller_rejects_wrong_scope(tmp_path) -> None:
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController("t1", "s1", spool)

    with pytest.raises(SiteScopeViolation):
        controller.ingest(event(1, tenant="other"))

    spool.close()


@pytest.mark.asyncio
async def test_failed_sync_retains_events_and_records_attempt(tmp_path) -> None:
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController("t1", "s1", spool, sender=FailingSender())
    controller.ingest(event(1))

    result = await controller.flush()
    assert result["state"] == "DEGRADED"
    assert spool.count() == 1
    assert spool.diagnostics()["max_attempts"] == 1
    spool.close()


@pytest.mark.asyncio
async def test_successful_sync_removes_acknowledged_events(tmp_path) -> None:
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController("t1", "s1", spool, sender=AcceptingSender())
    controller.ingest(event(1))
    controller.ingest(event(2))

    result = await controller.flush()
    assert result["state"] == "SYNCED"
    assert result["delivered"] == 2
    assert spool.count() == 0
    spool.close()


def test_local_detection_continues_without_cloud_sender(tmp_path) -> None:
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController("t1", "s1", spool)

    result = None
    for index in range(12):
        result = controller.ingest(event(index))

    assert result is not None
    assert len(result.findings) == 1
    assert len(result.incidents) == 1
    assert spool.count() == 12
    assert controller.status()["local_incidents"] == 1
    spool.close()


def test_spool_persists_exact_site_scope_across_restart(tmp_path) -> None:
    path = tmp_path / "spool.db"
    spool = SQLiteEventSpool(path, tenant_id="t1", site_id="s1")
    try:
        assert spool.enqueue(event(1))
        assert spool.mark_analysis_ready("event-1")
        diagnostics = spool.diagnostics()
        assert diagnostics["durability"] == "WAL_FULL"
        assert diagnostics["scope_bound"] is True
        assert diagnostics["analysis_pending"] == 0
        assert diagnostics["delivery_ready"] == 1
    finally:
        spool.close()

    reopened = SQLiteEventSpool(path, tenant_id="t1", site_id="s1")
    try:
        assert [item.event_id for item in reopened.pending()] == ["event-1"]
    finally:
        reopened.close()

    with pytest.raises(ValueError, match="tenant_id mismatch"):
        SQLiteEventSpool(path, tenant_id="other", site_id="s1")
    with pytest.raises(ValueError, match="site_id mismatch"):
        SQLiteEventSpool(path, tenant_id="t1", site_id="other")


def test_spool_rejects_foreign_event_after_scope_binding(tmp_path) -> None:
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="t1",
        site_id="s1",
    )
    try:
        with pytest.raises(ValueError, match="scope"):
            spool.enqueue(event(1, tenant="other"))
        assert spool.count() == 0
    finally:
        spool.close()


@pytest.mark.asyncio
async def test_failed_sync_marks_site_health_degraded(tmp_path) -> None:
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="t1",
        site_id="s1",
    )
    controller = SiteController("t1", "s1", spool, sender=FailingSender())
    try:
        controller.ingest(event(1))
        result = await controller.flush()
        assert result["state"] == "DEGRADED"
        status = controller.status()
        assert status["state"] == "DEGRADED"
        assert status["spool"]["last_error"] == "cloud unavailable"
        assert status["local_pipeline_state_persistence"] == "MEMORY_ONLY"
    finally:
        spool.close()


def test_spool_rejects_conflicting_duplicate_event_content(tmp_path) -> None:
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="t1",
        site_id="s1",
    )
    try:
        item = event(1)
        assert spool.enqueue(item)
        conflicting = item.model_copy(update={"dst_ip": "10.9.9.9"})
        with pytest.raises(ValueError, match="different content"):
            spool.enqueue(conflicting)
    finally:
        spool.close()


@pytest.mark.asyncio
async def test_cloud_delivery_waits_for_atomic_local_analysis_recovery(
    tmp_path,
    monkeypatch,
) -> None:
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="t1",
        site_id="s1",
    )
    analysis = SQLiteSiteAnalysisStore(
        tmp_path / "analysis.db",
        tenant_id="t1",
        site_id="s1",
    )
    pipeline = SecurityPipeline(
        store=analysis,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    controller = SiteController(
        "t1",
        "s1",
        spool,
        sender=AcceptingSender(),
        pipeline=pipeline,
    )
    original_add_asset = analysis.add_asset

    def fail_add_asset(asset):
        raise RuntimeError("simulated local analysis write failure")

    monkeypatch.setattr(analysis, "add_asset", fail_add_asset)
    try:
        with pytest.raises(RuntimeError, match="simulated"):
            controller.ingest(event(1))

        diagnostics = spool.diagnostics()
        assert diagnostics["analysis_pending"] == 1
        assert diagnostics["delivery_ready"] == 0
        assert diagnostics["analysis_max_attempts"] == 1
        assert analysis.diagnostics()["events"] == 0
        assert analysis.diagnostics()["processed_events"] == 0

        monkeypatch.setattr(analysis, "add_asset", original_add_asset)
        result = await controller.flush()

        assert result["state"] == "SYNCED"
        assert result["analysis"]["recovered"] == 1
        assert result["delivered"] == 1
        assert spool.count() == 0
        assert analysis.diagnostics()["events"] == 1
        assert analysis.diagnostics()["processed_events"] == 1
    finally:
        analysis.close()
        spool.close()


def test_v1_spool_rows_migrate_to_analysis_pending(tmp_path) -> None:
    path = tmp_path / "legacy-spool.db"
    item = event(1)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE event_spool (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                site_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE event_spool_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO event_spool_metadata(key, value) VALUES (?, ?)",
            [
                ("schema_version", "1"),
                ("tenant_id", "t1"),
                ("site_id", "s1"),
            ],
        )
        connection.execute(
            """
            INSERT INTO event_spool(
                event_id, tenant_id, site_id, observed_at, payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                item.event_id,
                item.tenant_id,
                item.site_id,
                item.observed_at.isoformat(),
                item.model_dump_json(),
                item.observed_at.isoformat(),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    spool = SQLiteEventSpool(path, tenant_id="t1", site_id="s1")
    try:
        assert spool.pending() == []
        assert spool.pending_analysis() == [item]
        diagnostics = spool.diagnostics()
        assert diagnostics["analysis_pending"] == 1
        assert diagnostics["delivery_ready"] == 0
    finally:
        spool.close()
