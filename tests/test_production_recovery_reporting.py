import datetime as dt

import pytest

from mon.domain import (
    ActionType,
    Asset,
    EnforcementBinding,
    EnforcementKind,
    EnforcementPoint,
    EnforcementResult,
    EvidenceClass,
    EvidenceRef,
    Incident,
    ResponseExecutionStatus,
    ResponseRequest,
    ResponseTarget,
    Severity,
)
from mon.enforcement import EnforcementRegistry
from mon.production_site_controller import ProductionSiteController
from mon.recovery import RecoveryEngine
from mon.response import ResponseOrchestrator
from mon.site_command_outbox import SQLiteCommandResultOutbox
from mon.site_controller import SQLiteEventSpool
from mon.site_response_models import SiteResponseUpdate
from mon.site_response_outbox import SQLiteResponseUpdateOutbox
from mon.store import InMemoryStore


class RecordingAdapter:
    def __init__(self) -> None:
        self.rollback_calls = 0

    async def execute(self, plan, execution_id):
        return EnforcementResult(success=True, message="applied")

    async def rollback(self, plan, execution_id):
        self.rollback_calls += 1
        return EnforcementResult(success=True, message="rolled back")


class RecoveryUpdateClient:
    def __init__(self, *, fail_first: bool = False) -> None:
        self.fail_first = fail_first
        self.submits = 0
        self.updates: list[SiteResponseUpdate] = []

    async def submit_response_update(self, update: SiteResponseUpdate) -> None:
        self.submits += 1
        if self.fail_first and self.submits == 1:
            raise OSError("control plane unavailable")
        self.updates.append(update)


async def prepared_execution():
    store = InMemoryStore()
    store.add_asset(
        Asset(
            asset_id="asset-1",
            tenant_id="tenant-a",
            site_id="site-a",
            display_name="Asset",
        )
    )
    store.add_incident(
        Incident(
            incident_id="incident-1",
            tenant_id="tenant-a",
            site_id="site-a",
            title="Incident",
            severity=Severity.HIGH,
            confidence=0.99,
            evidence=[
                EvidenceRef(
                    evidence_class=EvidenceClass.NETWORK_FLOW,
                    source="network",
                    summary="network evidence",
                    confidence=0.95,
                ),
                EvidenceRef(
                    evidence_class=EvidenceClass.ENDPOINT,
                    source="endpoint",
                    summary="endpoint evidence",
                    confidence=0.95,
                ),
            ],
        )
    )
    store.add_enforcement_point(
        EnforcementPoint(
            enforcement_point_id="endpoint-1",
            tenant_id="tenant-a",
            site_id="site-a",
            kind=EnforcementKind.ENDPOINT,
            vendor="test",
            capabilities={ActionType.ISOLATE_ENDPOINT},
        )
    )
    store.add_enforcement_binding(
        EnforcementBinding(
            tenant_id="tenant-a",
            site_id="site-a",
            asset_id="asset-1",
            enforcement_point_id="endpoint-1",
            attributes={"blast_radius_estimate": "target endpoint only"},
        )
    )

    registry = EnforcementRegistry()
    adapter = RecordingAdapter()
    registry.register(EnforcementKind.ENDPOINT, "test", adapter)
    orchestrator = ResponseOrchestrator(store, registry)
    execution = await orchestrator.execute(
        ResponseRequest(
            request_id="response-1",
            tenant_id="tenant-a",
            site_id="site-a",
            incident_id="incident-1",
            target=ResponseTarget(asset_id="asset-1"),
            action=ActionType.ISOLATE_ENDPOINT,
            ttl_seconds=30,
            reason="test autonomous expiry rollback",
        )
    )
    assert execution.status is ResponseExecutionStatus.APPLIED
    assert execution.expires_at is not None
    return store, RecoveryEngine(orchestrator), adapter, execution


def make_controller(tmp_path, recovery, client):
    event_spool = SQLiteEventSpool(tmp_path / "events.db")
    result_outbox = SQLiteCommandResultOutbox(
        tmp_path / "command-results.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    response_update_outbox = SQLiteResponseUpdateOutbox(
        tmp_path / "response-updates.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    controller = ProductionSiteController(
        "tenant-a",
        "site-a",
        event_spool,
        recovery_engine=recovery,
        command_client=client,
        result_outbox=result_outbox,
        response_update_outbox=response_update_outbox,
    )
    return controller, event_spool, result_outbox, response_update_outbox


@pytest.mark.asyncio
async def test_autonomous_recovery_update_survives_cloud_failure(tmp_path) -> None:
    _, recovery, adapter, execution = await prepared_execution()
    client = RecoveryUpdateClient(fail_first=True)
    controller, spool, result_outbox, update_outbox = make_controller(
        tmp_path,
        recovery,
        client,
    )
    try:
        first = await controller.recover_expired_responses(
            now=execution.expires_at + dt.timedelta(seconds=1)
        )
        second = await controller.recover_expired_responses(
            now=execution.expires_at + dt.timedelta(seconds=2)
        )

        assert first["state"] == "RECOVERED"
        assert first["response_update_sync_state"] == "DEGRADED"
        assert first["unreported_response_updates"] == 1
        assert second["attempted"] == 0
        assert second["response_update_sync_state"] == "SYNCED"
        assert second["unreported_response_updates"] == 0
        assert adapter.rollback_calls == 1
        assert client.submits == 2
        assert len(client.updates) == 1
        assert client.updates[0].execution.status is ResponseExecutionStatus.ROLLED_BACK
        diagnostics = update_outbox.diagnostics()
        assert diagnostics["receipts"] == 1
        assert diagnostics["reported"] == 1
    finally:
        spool.close()
        result_outbox.close()
        update_outbox.close()


@pytest.mark.asyncio
async def test_recovery_report_is_reconstructed_after_post_rollback_crash_window(
    tmp_path,
) -> None:
    _, recovery, adapter, execution = await prepared_execution()
    sweep = await recovery.sweep_scope(
        "tenant-a",
        "site-a",
        now=execution.expires_at + dt.timedelta(seconds=1),
    )
    assert sweep.rolled_back == ("response-1",)

    client = RecoveryUpdateClient()
    controller, spool, result_outbox, update_outbox = make_controller(
        tmp_path,
        recovery,
        client,
    )
    try:
        result = await controller.recover_expired_responses(
            now=execution.expires_at + dt.timedelta(seconds=2)
        )

        assert result["attempted"] == 0
        assert result["response_updates_enqueued"] == 1
        assert result["response_updates_reported"] == 1
        assert result["unreported_response_updates"] == 0
        assert adapter.rollback_calls == 1
        assert len(client.updates) == 1
        assert client.updates[0].execution.status is ResponseExecutionStatus.ROLLED_BACK
    finally:
        spool.close()
        result_outbox.close()
        update_outbox.close()
