import datetime as dt

import pytest

from mon.domain import EvidenceClass, GraphNodeKind, GraphRelation, SecurityEvent
from mon.endpoint import (
    EndpointEventKind,
    EndpointTelemetryEvent,
    normalize_endpoint_event,
)
from mon.investigation import build_incident_investigation
from mon.pipeline import PipelinePersistenceMode, SecurityPipeline
from mon.site_analysis_store import SQLiteSiteAnalysisStore
from mon.store import InMemoryStore

BASE = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)


def endpoint_event(
    event_id: str,
    kind: EndpointEventKind,
    *,
    tenant_id: str = "tenant-a",
    site_id: str = "site-a",
    asset_id: str = "asset-1",
    observed_at: dt.datetime = BASE,
    user_name: str | None = "alice",
    user_domain: str | None = "MON",
    user_sid: str | None = "S-1-5-21-1000",
    process_guid: str | None = "{process-guid-1}",
    process_pid: int | None = 4242,
    parent_process_guid: str | None = "{parent-guid-1}",
    dst_ip: str | None = None,
    dst_port: int | None = None,
) -> EndpointTelemetryEvent:
    return EndpointTelemetryEvent(
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id="endpoint-sensor-1",
        event_id=event_id,
        observed_at=observed_at,
        kind=kind,
        asset_id=asset_id,
        hostname="workstation-1",
        src_ip="10.0.0.17",
        dst_ip=dst_ip,
        protocol="tcp" if dst_ip else None,
        dst_port=dst_port,
        user_name=user_name,
        user_domain=user_domain,
        user_sid=user_sid,
        process_guid=process_guid,
        process_pid=process_pid,
        parent_process_guid=parent_process_guid,
        parent_process_pid=1000,
        session_id="logon-session-1",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -NoProfile",
        process_hashes={"SHA256": "a" * 64},
        raw_reference=f"endpoint://{event_id}",
    )


def test_normalizes_endpoint_telemetry_without_inline_secrets() -> None:
    event = normalize_endpoint_event(
        endpoint_event("endpoint-1", EndpointEventKind.PROCESS_START)
    )

    assert event.category == "endpoint.process.start"
    assert event.tenant_id == "tenant-a"
    assert event.site_id == "site-a"
    assert event.asset_id == "asset-1"
    assert event.evidence[0].evidence_class is EvidenceClass.ENDPOINT
    assert event.attributes["identity_source"] == "windows_sid"
    assert event.attributes["identity_confidence"] == "STRONG"
    assert event.attributes["process_hashes"]["sha256"] == "a" * 64

    with pytest.raises(ValueError, match="sensitive endpoint telemetry"):
        EndpointTelemetryEvent(
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="endpoint-sensor-1",
            event_id="endpoint-secret",
            observed_at=BASE,
            kind=EndpointEventKind.AUTH_SUCCESS,
            attributes={"password": "do-not-store"},
        )


def test_identity_and_process_graph_relationships_are_tenant_site_scoped() -> None:
    store = InMemoryStore()
    pipeline = SecurityPipeline(store=store)

    auth = pipeline.process_event(
        normalize_endpoint_event(endpoint_event("auth-1", EndpointEventKind.AUTH_SUCCESS))
    )
    process = pipeline.process_event(
        normalize_endpoint_event(endpoint_event("process-1", EndpointEventKind.PROCESS_START))
    )
    network = pipeline.process_event(
        normalize_endpoint_event(
            endpoint_event(
                "network-1",
                EndpointEventKind.NETWORK_CONNECTION,
                dst_ip="10.0.0.99",
                dst_port=445,
            )
        )
    )
    other_tenant = pipeline.process_event(
        normalize_endpoint_event(
            endpoint_event(
                "other-tenant",
                EndpointEventKind.AUTH_SUCCESS,
                tenant_id="tenant-b",
            )
        )
    )

    assert auth.identity_updates[0].tenant_id == "tenant-a"
    assert process.process_updates[0].parent_process_id is not None
    assert network.process_updates[0].asset_id == "asset-1"
    assert other_tenant.identity_updates[0].tenant_id == "tenant-b"

    snapshot = pipeline.graph.snapshot("tenant-a", "site-a")
    node_kinds = {node.kind for node in snapshot.nodes}
    relations = {edge.relation for edge in snapshot.edges}
    assert GraphNodeKind.IDENTITY in node_kinds
    assert GraphNodeKind.PROCESS in node_kinds
    assert GraphRelation.AUTHENTICATED_TO in relations
    assert GraphRelation.EXECUTED_PROCESS in relations
    assert GraphRelation.PARENT_PROCESS in relations
    assert GraphRelation.PROCESS_NETWORK_CONNECTION in relations
    assert pipeline.graph.snapshot("tenant-b", "site-a").nodes


def test_weak_username_identities_and_pid_only_processes_do_not_collapse() -> None:
    store = InMemoryStore()
    pipeline = SecurityPipeline(store=store)

    first = normalize_endpoint_event(
        endpoint_event(
            "weak-1",
            EndpointEventKind.PROCESS_START,
            asset_id="asset-1",
            user_sid=None,
            user_name="operator",
            user_domain=None,
            process_guid=None,
            parent_process_guid=None,
            observed_at=BASE,
        )
    )
    second = normalize_endpoint_event(
        endpoint_event(
            "weak-2",
            EndpointEventKind.PROCESS_START,
            asset_id="asset-2",
            user_sid=None,
            user_name="operator",
            user_domain=None,
            process_guid=None,
            parent_process_guid=None,
            observed_at=BASE + dt.timedelta(seconds=1),
        )
    )

    first_result = pipeline.process_event(first)
    second_result = pipeline.process_event(second)

    assert first_result.identity_updates[0].confidence.value == "WEAK"
    assert first_result.identity_updates[0].identity_id != (
        second_result.identity_updates[0].identity_id
    )
    assert first_result.process_updates[0].process_id != (
        second_result.process_updates[0].process_id
    )


def test_durable_endpoint_identity_process_state_restores_across_restart(tmp_path) -> None:
    path = tmp_path / "analysis.db"
    store = SQLiteSiteAnalysisStore(path, tenant_id="tenant-a", site_id="site-a")
    pipeline = SecurityPipeline(
        store=store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    try:
        pipeline.process_event(
            normalize_endpoint_event(endpoint_event("auth-1", EndpointEventKind.AUTH_SUCCESS))
        )
        pipeline.process_event(
            normalize_endpoint_event(
                endpoint_event("process-1", EndpointEventKind.PROCESS_START)
            )
        )
        assert store.diagnostics()["identities"] == 1
        assert store.diagnostics()["processes"] == 1
    finally:
        store.close()

    reopened = SQLiteSiteAnalysisStore(path, tenant_id="tenant-a", site_id="site-a")
    restored = SecurityPipeline(
        store=reopened,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    try:
        restore = restored.restore_scope("tenant-a", "site-a")
        assert restore["checkpoint_used"] == 1
        assert reopened.diagnostics()["identities"] == 1
        assert reopened.diagnostics()["processes"] == 1
        snapshot = restored.graph.snapshot("tenant-a", "site-a")
        assert {edge.relation for edge in snapshot.edges} >= {
            GraphRelation.AUTHENTICATED_TO,
            GraphRelation.EXECUTED_PROCESS,
            GraphRelation.PROCESS_ON_ASSET,
        }
    finally:
        reopened.close()


def test_endpoint_and_network_findings_correlate_without_claiming_compromise() -> None:
    pipeline = SecurityPipeline()

    for index in range(8):
        result = pipeline.process_event(
            normalize_endpoint_event(
                endpoint_event(
                    f"auth-fail-{index}",
                    EndpointEventKind.AUTH_FAILURE,
                    observed_at=BASE + dt.timedelta(seconds=index),
                    process_guid=f"{{auth-process-{index}}}",
                    parent_process_guid=None,
                )
            )
        )
    assert result.findings
    assert result.findings[0].detector_id == "endpoint-auth-failure-pressure"
    assert result.findings[0].evidence[0].evidence_class is EvidenceClass.IDENTITY
    assert "not proof of compromise" in result.findings[0].attributes["claim"]

    for index in range(12):
        network_result = pipeline.process_event(
            SecurityEvent(
                event_id=f"network-{index}",
                tenant_id="tenant-a",
                site_id="site-a",
                sensor_id="network-sensor-1",
                observed_at=BASE + dt.timedelta(seconds=20 + index),
                category="network.connection",
                asset_id="asset-1",
                src_ip="10.0.0.17",
                dst_ip=f"10.0.1.{index + 10}",
                protocol="tcp",
                attributes={
                    "direction": "east-west",
                    "dst_port": 445,
                    "tcp_syn": True,
                    "tcp_ack": False,
                },
            )
        )

    assert network_result.findings
    assert network_result.incidents
    incident = network_result.incidents[0]
    investigation = build_incident_investigation(
        pipeline.store,
        pipeline.graph,
        incident,
    )
    evidence_classes = {
        evidence.evidence_class for evidence in investigation.evidence
    }
    assert EvidenceClass.IDENTITY in evidence_classes
    assert EvidenceClass.STATISTICAL in evidence_classes
