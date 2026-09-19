import datetime as dt
import sqlite3

import pytest

from mon.domain import SecurityEvent
from mon.pipeline import PipelinePersistenceMode, PipelineStateError, SecurityPipeline
from mon.site_analysis_store import SQLiteSiteAnalysisStore

BASE = dt.datetime(2026, 9, 19, 4, 0, tzinfo=dt.UTC)


def event(index: int, *, offset_seconds: float = 0.0) -> SecurityEvent:
    return SecurityEvent(
        event_id=f"event-{index}-{offset_seconds}",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        observed_at=BASE
        + dt.timedelta(seconds=offset_seconds, milliseconds=index * 100),
        category="network.connection",
        src_ip="10.0.0.17",
        dst_ip=f"10.0.{index // 250 + 1}.{index % 250 + 1}",
        protocol="tcp",
        attributes={"direction": "east-west", "dst_port": 445},
    )


def test_site_analysis_store_persists_objects_and_scope(tmp_path) -> None:
    path = tmp_path / "analysis.db"
    first = SQLiteSiteAnalysisStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        item = event(1)
        assert first.add_event(item) == item
        assert first.add_event(item) == item
        assert first.event_exists("tenant-a", "site-a", item.event_id)
        assert first.diagnostics()["events"] == 1
    finally:
        first.close()

    second = SQLiteSiteAnalysisStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        assert second.list_events("tenant-a", "site-a") == [item]
        with pytest.raises(ValueError, match="scope"):
            second.list_events("tenant-b", "site-a")
    finally:
        second.close()

    with pytest.raises(ValueError, match="tenant_id mismatch"):
        SQLiteSiteAnalysisStore(
            path,
            tenant_id="tenant-b",
            site_id="site-a",
        )


def test_site_analysis_store_rejects_event_id_collision(tmp_path) -> None:
    store = SQLiteSiteAnalysisStore(
        tmp_path / "analysis.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    item = event(1)
    try:
        store.add_event(item)
        conflicting = item.model_copy(update={"dst_ip": "10.9.9.9"})
        with pytest.raises(ValueError, match="different content"):
            store.add_event(conflicting)
    finally:
        store.close()


def test_detection_window_and_graph_restore_across_restart(tmp_path) -> None:
    path = tmp_path / "analysis.db"
    first_store = SQLiteSiteAnalysisStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    first_pipeline = SecurityPipeline(
        store=first_store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    for index in range(11):
        result = first_pipeline.process_event(event(index))
        assert result.findings == []
    graph_before = first_pipeline.graph.snapshot("tenant-a", "site-a")
    assert len(graph_before.edges) == 11
    first_store.close()

    second_store = SQLiteSiteAnalysisStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    second_pipeline = SecurityPipeline(
        store=second_store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    try:
        restored = second_pipeline.restore_scope("tenant-a", "site-a")
        assert restored["events"] == 11
        assert restored["findings"] == 0
        graph_after = second_pipeline.graph.snapshot("tenant-a", "site-a")
        assert len(graph_after.edges) == 11

        result = second_pipeline.process_event(event(11))
        assert len(result.findings) == 1
        assert result.findings[0].detector_id == "internal-lateral-sweep"
        assert len(result.incidents) == 1
        assert second_store.diagnostics()["events"] == 12
        assert second_store.diagnostics()["findings"] == 1
        assert second_store.diagnostics()["incidents"] == 1
    finally:
        second_store.close()


def test_active_incident_correlation_restores_across_restart(tmp_path) -> None:
    path = tmp_path / "analysis.db"
    first_store = SQLiteSiteAnalysisStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    first_pipeline = SecurityPipeline(
        store=first_store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    first_incident_id = None
    for index in range(12):
        result = first_pipeline.process_event(event(index))
        if result.incidents:
            first_incident_id = result.incidents[0].incident_id
    assert first_incident_id is not None
    first_store.close()

    second_store = SQLiteSiteAnalysisStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    second_pipeline = SecurityPipeline(
        store=second_store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    try:
        restored = second_pipeline.restore_scope("tenant-a", "site-a")
        assert restored["correlation_pointers"] >= 1

        latest = None
        for index in range(12, 24):
            latest = second_pipeline.process_event(
                event(index, offset_seconds=31)
            )
        assert latest is not None
        assert len(latest.findings) == 1
        assert len(latest.incidents) == 1
        assert latest.incidents[0].incident_id == first_incident_id

        incidents = second_store.list_incidents("tenant-a", "site-a")
        assert len(incidents) == 1
        assert len(incidents[0].finding_ids) == 2
    finally:
        second_store.close()


def test_restore_refuses_event_without_atomic_processing_receipt(tmp_path) -> None:
    store = SQLiteSiteAnalysisStore(
        tmp_path / "analysis.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    pipeline = SecurityPipeline(
        store=store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    try:
        store.add_event(event(1))
        assert store.event_processed("tenant-a", "site-a", event(1).event_id) is False
        with pytest.raises(PipelineStateError, match="without atomic processing receipts"):
            pipeline.restore_scope("tenant-a", "site-a")
    finally:
        store.close()


def test_pipeline_transaction_rolls_back_all_derived_state_and_restores_memory(
    tmp_path,
    monkeypatch,
) -> None:
    store = SQLiteSiteAnalysisStore(
        tmp_path / "analysis.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    pipeline = SecurityPipeline(
        store=store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    for index in range(11):
        pipeline.process_event(event(index))

    asset_before = store.get_asset("tenant-a", "site-a", "ip:10.0.0.17")
    assert asset_before is not None
    original_add_incident = store.add_incident

    def fail_add_incident(incident):
        raise RuntimeError("simulated incident commit failure")

    monkeypatch.setattr(store, "add_incident", fail_add_incident)
    try:
        with pytest.raises(RuntimeError, match="simulated incident"):
            pipeline.process_event(event(11))

        diagnostics = store.diagnostics()
        assert diagnostics["events"] == 11
        assert diagnostics["processed_events"] == 11
        assert diagnostics["unprocessed_events"] == 0
        assert diagnostics["findings"] == 0
        assert diagnostics["incidents"] == 0
        asset_after_failure = store.get_asset(
            "tenant-a",
            "site-a",
            "ip:10.0.0.17",
        )
        assert asset_after_failure == asset_before

        monkeypatch.setattr(store, "add_incident", original_add_incident)
        retried = pipeline.process_event(event(11))
        assert len(retried.findings) == 1
        assert len(retried.incidents) == 1
        assert store.diagnostics()["events"] == 12
        assert store.diagnostics()["processed_events"] == 12
        assert store.diagnostics()["findings"] == 1
        assert store.diagnostics()["incidents"] == 1
    finally:
        store.close()


def test_v1_analysis_database_with_events_requires_explicit_rebuild(tmp_path) -> None:
    path = tmp_path / "analysis-v1.db"
    item = event(1)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE site_analysis_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO site_analysis_metadata(key, value) VALUES (?, ?)",
            [
                ("schema_version", "1"),
                ("tenant_id", "tenant-a"),
                ("site_id", "site-a"),
            ],
        )
        connection.execute(
            """
            CREATE TABLE site_analysis_events (
                tenant_id TEXT NOT NULL,
                site_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (tenant_id, site_id, event_id)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO site_analysis_events(
                tenant_id, site_id, event_id, observed_at, payload
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                item.tenant_id,
                item.site_id,
                item.event_id,
                item.observed_at.isoformat(),
                item.model_dump_json(),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ValueError, match="explicit rebuild"):
        SQLiteSiteAnalysisStore(
            path,
            tenant_id="tenant-a",
            site_id="site-a",
        )
