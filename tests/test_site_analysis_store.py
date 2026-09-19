import datetime as dt

import pytest

from mon.domain import SecurityEvent
from mon.pipeline import PipelinePersistenceMode, SecurityPipeline
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
