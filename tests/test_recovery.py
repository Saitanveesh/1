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
from mon.recovery import RecoveryEngine
from mon.response import ResponseOrchestrator
from mon.site_controller import SiteController, SQLiteEventSpool
from mon.store import InMemoryStore


class RecordingAdapter:
    def __init__(self) -> None:
        self.rollback_calls = 0

    async def execute(self, plan, execution_id):
        return EnforcementResult(success=True, message="applied")

    async def rollback(self, plan, execution_id):
        self.rollback_calls += 1
        return EnforcementResult(success=True, message="rolled back")


async def prepared_execution():
    store = InMemoryStore()
    store.add_asset(
        Asset(
            asset_id="asset-1",
            tenant_id="t1",
            site_id="s1",
            display_name="Asset",
        )
    )
    store.add_incident(
        Incident(
            incident_id="inc-1",
            tenant_id="t1",
            site_id="s1",
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
            tenant_id="t1",
            site_id="s1",
            kind=EnforcementKind.ENDPOINT,
            vendor="test",
            capabilities={ActionType.ISOLATE_ENDPOINT},
        )
    )
    store.add_enforcement_binding(
        EnforcementBinding(
            tenant_id="t1",
            site_id="s1",
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
            tenant_id="t1",
            site_id="s1",
            incident_id="inc-1",
            target=ResponseTarget(asset_id="asset-1"),
            action=ActionType.ISOLATE_ENDPOINT,
            ttl_seconds=30,
            reason="test expiry rollback",
        )
    )
    assert execution.status is ResponseExecutionStatus.APPLIED
    assert execution.expires_at is not None
    return store, orchestrator, adapter, execution


@pytest.mark.asyncio
async def test_recovery_engine_rolls_back_expired_response_once() -> None:
    store, orchestrator, adapter, execution = await prepared_execution()
    engine = RecoveryEngine(orchestrator)

    sweep = await engine.sweep_scope(
        "t1",
        "s1",
        now=execution.expires_at + dt.timedelta(seconds=1),
    )
    second = await engine.sweep_scope(
        "t1",
        "s1",
        now=execution.expires_at + dt.timedelta(seconds=2),
    )

    assert sweep.rolled_back == ("response-1",)
    assert sweep.failed == ()
    assert second.attempted == 0
    assert adapter.rollback_calls == 1
    restored = store.get_response_execution("t1", "s1", "response-1")
    assert restored is not None
    assert restored.status is ResponseExecutionStatus.ROLLED_BACK


@pytest.mark.asyncio
async def test_site_controller_recovery_is_independent_of_cloud_sender(tmp_path) -> None:
    _, orchestrator, adapter, execution = await prepared_execution()
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController(
        tenant_id="t1",
        site_id="s1",
        spool=spool,
        sender=None,
        recovery_engine=RecoveryEngine(orchestrator),
    )
    try:
        result = await controller.recover_expired_responses(
            now=execution.expires_at + dt.timedelta(seconds=1)
        )
    finally:
        spool.close()

    assert result["state"] == "RECOVERED"
    assert result["rolled_back"] == 1
    assert adapter.rollback_calls == 1
