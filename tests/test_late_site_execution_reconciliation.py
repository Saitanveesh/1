import datetime as dt

import pytest

from mon.domain import (
    ActionType,
    AuditRecord,
    EnforcementKind,
    EnforcementPoint,
    EnforcementResult,
    PolicyDecision,
    PolicyOutcome,
    ResponseExecution,
    ResponseExecutionStatus,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
)
from mon.enforcement import EnforcementRegistry
from mon.production_site_controller import ProductionSiteController
from mon.site_command_models import (
    SiteCommand,
    SiteCommandKind,
    SiteCommandResult,
    SiteCommandStatus,
)
from mon.site_command_outbox import SQLiteCommandResultOutbox
from mon.site_command_queue import SiteCommandQueue
from mon.site_controller import SQLiteEventSpool
from mon.site_response import SiteResponseExecutor
from mon.site_response_models import (
    SiteResponseUpdate,
    SiteResponseUpdateKind,
    execution_reconciliation_update_id,
)
from mon.site_response_outbox import SQLiteResponseUpdateOutbox
from mon.site_response_reconciliation import (
    SiteResponseUpdateError,
    SiteResponseUpdateReconciler,
)
from mon.store import InMemoryStore

CONTROL_REQUEST = dt.datetime(2026, 9, 19, 4, 0, tzinfo=dt.UTC)
COMMAND_CREATED = CONTROL_REQUEST + dt.timedelta(seconds=30)
COMMAND_NOT_AFTER = COMMAND_CREATED + dt.timedelta(minutes=5)
TTL_SECONDS = 300


def plan() -> ResponsePlan:
    request = ResponseRequest(
        request_id="response-1",
        tenant_id="tenant-a",
        site_id="site-a",
        incident_id="incident-1",
        target=ResponseTarget(ip_address="198.51.100.7"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="fw-1",
        ttl_seconds=TTL_SECONDS,
        reason="contain source",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw-1",
        tenant_id="tenant-a",
        site_id="site-a",
        kind=EnforcementKind.FIREWALL,
        vendor="test",
        capabilities={ActionType.BLOCK_IP},
    )
    return ResponsePlan(
        request=request,
        decision=PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            reasons=["approved by policy"],
            evaluated_at=CONTROL_REQUEST,
        ),
        enforcement_point=point,
        blast_radius_estimate="single source rule",
    )


def command() -> SiteCommand:
    return SiteCommand(
        command_id="command-1",
        tenant_id="tenant-a",
        site_id="site-a",
        kind=SiteCommandKind.APPLY_RESPONSE,
        created_at=COMMAND_CREATED,
        not_after=COMMAND_NOT_AFTER,
        response_plan=plan(),
    )


def dispatch_pending_execution() -> ResponseExecution:
    return ResponseExecution(
        execution_id="response-1",
        tenant_id="tenant-a",
        site_id="site-a",
        plan=plan(),
        status=ResponseExecutionStatus.DISPATCH_PENDING,
        requested_at=CONTROL_REQUEST,
    )


def reconciliation_audits(*, present: bool, rolled_back: bool = False):
    records = [
        AuditRecord(
            audit_id="site-started",
            tenant_id="tenant-a",
            site_id="site-a",
            actor_id="mon-automation",
            category="SITE_RESPONSE",
            object_type="response_execution",
            object_id="response-1",
            action="EXECUTE",
            outcome="STARTED",
            occurred_at=COMMAND_CREATED,
            details={
                "command_id": "command-1",
                "command_not_after": COMMAND_NOT_AFTER.isoformat(),
                "enforcement_point_id": "fw-1",
            },
        ),
        AuditRecord(
            audit_id="site-verify",
            tenant_id="tenant-a",
            site_id="site-a",
            actor_id="mon-site-reconciliation",
            category="SITE_RESPONSE",
            object_type="response_execution",
            object_id="response-1",
            action="VERIFY",
            outcome="PRESENT" if present else "ABSENT",
            occurred_at=COMMAND_NOT_AFTER + dt.timedelta(seconds=1),
            details={"message": "verified external state"},
        ),
    ]
    if rolled_back:
        records.append(
            AuditRecord(
                audit_id="site-rollback",
                tenant_id="tenant-a",
                site_id="site-a",
                actor_id="mon-site-recovery",
                category="RESPONSE",
                object_type="response_execution",
                object_id="response-1",
                action="ROLLBACK",
                outcome="ROLLED_BACK",
                occurred_at=COMMAND_NOT_AFTER + dt.timedelta(seconds=2),
                details={"reason": "temporary response TTL expired"},
            )
        )
    return records


def verified_applied_execution() -> ResponseExecution:
    return ResponseExecution(
        execution_id="response-1",
        tenant_id="tenant-a",
        site_id="site-a",
        plan=plan(),
        status=ResponseExecutionStatus.APPLIED,
        requested_at=COMMAND_CREATED,
        applied_at=None,
        expires_at=COMMAND_CREATED + dt.timedelta(seconds=TTL_SECONDS),
        result=EnforcementResult(
            success=True,
            message="effect verified present after interrupted execution",
            external_reference="test:response-1",
            details={
                "reconciled_after_interruption": True,
                "verification_message": "verified present",
            },
        ),
    )


def verified_rolled_back_execution() -> ResponseExecution:
    applied = verified_applied_execution()
    return applied.model_copy(
        update={
            "status": ResponseExecutionStatus.ROLLED_BACK,
            "rollback_at": COMMAND_NOT_AFTER + dt.timedelta(seconds=2),
            "rollback_result": EnforcementResult(
                success=True,
                message="rolled back after TTL",
            ),
        }
    )


def expired_control_plane():
    store = InMemoryStore()
    store.add_response_execution(dispatch_pending_execution())
    queue = SiteCommandQueue(store)
    queue.enqueue(command())
    assert queue.expire_due(
        "tenant-a",
        "site-a",
        now=COMMAND_NOT_AFTER + dt.timedelta(seconds=1),
    ) == 1
    record = store.get_site_command("tenant-a", "site-a", "command-1")
    assert record is not None
    assert record.status is SiteCommandStatus.EXPIRED
    current = store.get_response_execution("tenant-a", "site-a", "response-1")
    assert current is not None
    assert current.status is ResponseExecutionStatus.FAILED
    return store, queue


def make_update(execution: ResponseExecution, audits) -> SiteResponseUpdate:
    return SiteResponseUpdate(
        update_id=execution_reconciliation_update_id(execution, "command-1"),
        kind=SiteResponseUpdateKind.EXECUTION_RECONCILIATION,
        command_id="command-1",
        tenant_id="tenant-a",
        site_id="site-a",
        execution=execution,
        audit_records=audits,
        observed_at=max(record.occurred_at for record in audits),
    )


def test_expired_command_converges_directly_to_verified_rolled_back_state() -> None:
    store, _ = expired_control_plane()
    reconciler = SiteResponseUpdateReconciler(store)
    reported = verified_rolled_back_execution()
    update = make_update(
        reported,
        reconciliation_audits(present=True, rolled_back=True),
    )

    first = reconciler.reconcile(update)
    second = reconciler.reconcile(update)

    assert first.status is ResponseExecutionStatus.ROLLED_BACK
    assert second == first
    # Preserve the control-plane request time rather than replacing it with the
    # site's command-start timestamp.
    assert first.requested_at == CONTROL_REQUEST
    assert first.applied_at is None
    assert first.expires_at == COMMAND_CREATED + dt.timedelta(seconds=TTL_SECONDS)
    assert first.rollback_result is not None and first.rollback_result.success
    record = store.get_site_command("tenant-a", "site-a", "command-1")
    assert record is not None
    assert record.status is SiteCommandStatus.EXPIRED

    audits = store.list_audit_records("tenant-a", "site-a")
    reconciliation = [
        item for item in audits if item.action == "SITE_EXECUTION_RECONCILIATION"
    ]
    assert len(reconciliation) == 1
    assert reconciliation[0].outcome == "ACCEPTED"
    assert reconciliation[0].details["previous_status"] == "FAILED"
    assert reconciliation[0].details["reported_status"] == "ROLLED_BACK"


def test_verified_absent_replaces_delivery_failure_with_evidence_backed_failure() -> None:
    store, _ = expired_control_plane()
    reconciler = SiteResponseUpdateReconciler(store)
    reported = ResponseExecution(
        execution_id="response-1",
        tenant_id="tenant-a",
        site_id="site-a",
        plan=plan(),
        status=ResponseExecutionStatus.FAILED,
        requested_at=COMMAND_CREATED,
        error=(
            "enforcement verification confirmed the effect is absent "
            "after an interrupted execution"
        ),
    )
    update = make_update(
        reported,
        reconciliation_audits(present=False),
    )

    reconciled = reconciler.reconcile(update)

    assert reconciled.status is ResponseExecutionStatus.FAILED
    assert "effect is absent" in (reconciled.error or "")
    assert reconciled.requested_at == CONTROL_REQUEST
    assert reconciled.result is None
    assert reconciled.expires_at is None


def test_reconciliation_waits_for_command_expiry_and_rejects_tampering() -> None:
    store = InMemoryStore()
    store.add_response_execution(dispatch_pending_execution())
    queue = SiteCommandQueue(store)
    queue.enqueue(command())
    reconciler = SiteResponseUpdateReconciler(store)
    reported = verified_applied_execution()
    update = make_update(
        reported,
        reconciliation_audits(present=True),
    )

    with pytest.raises(SiteResponseUpdateError, match="only after"):
        reconciler.reconcile(update)

    queue.expire_due(
        "tenant-a",
        "site-a",
        now=COMMAND_NOT_AFTER + dt.timedelta(seconds=1),
    )
    wrong_expiry = reported.model_copy(
        update={"expires_at": reported.expires_at + dt.timedelta(seconds=1)}
    )
    with pytest.raises(SiteResponseUpdateError, match="conservative TTL"):
        reconciler.reconcile(
            make_update(
                wrong_expiry,
                reconciliation_audits(present=True),
            )
        )

    tampered_request = reported.plan.request.model_copy(
        update={"reason": "tampered at site"}
    )
    tampered_plan = reported.plan.model_copy(update={"request": tampered_request})
    tampered = reported.model_copy(update={"plan": tampered_plan})
    with pytest.raises(SiteResponseUpdateError, match="cannot mutate"):
        reconciler.reconcile(
            make_update(
                tampered,
                reconciliation_audits(present=True),
            )
        )


class UpdateClient:
    def __init__(self) -> None:
        self.updates: list[SiteResponseUpdate] = []

    async def submit_response_update(self, update: SiteResponseUpdate) -> None:
        self.updates.append(update)


@pytest.mark.asyncio
async def test_production_site_reports_reconciled_terminal_state_and_supersedes_result(
    tmp_path,
) -> None:
    local_store = InMemoryStore()
    execution = verified_rolled_back_execution()
    local_store.add_response_execution(execution)
    for record in reconciliation_audits(present=True, rolled_back=True):
        local_store.add_audit_record(record)

    registry = EnforcementRegistry()
    executor = SiteResponseExecutor(
        "tenant-a",
        "site-a",
        local_store,
        registry,
    )
    event_spool = SQLiteEventSpool(tmp_path / "events.db")
    result_outbox = SQLiteCommandResultOutbox(
        tmp_path / "command-results.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    response_outbox = SQLiteResponseUpdateOutbox(
        tmp_path / "response-updates.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    stale_result = SiteCommandResult(
        command_id="command-1",
        tenant_id="tenant-a",
        site_id="site-a",
        success=True,
        execution=execution,
    )
    assert result_outbox.enqueue(stale_result)
    client = UpdateClient()
    controller = ProductionSiteController(
        "tenant-a",
        "site-a",
        event_spool,
        command_client=client,
        response_executor=executor,
        result_outbox=result_outbox,
        response_update_outbox=response_outbox,
    )
    try:
        assert controller._enqueue_execution_reconciliation_updates(
            now=COMMAND_NOT_AFTER - dt.timedelta(seconds=1)
        ) == 0
        assert controller._enqueue_execution_reconciliation_updates(
            now=COMMAND_NOT_AFTER + dt.timedelta(seconds=1)
        ) == 1
        assert controller._enqueue_autonomous_recovery_updates() == 0

        pending = response_outbox.pending()
        assert len(pending) == 1
        assert pending[0].kind is SiteResponseUpdateKind.EXECUTION_RECONCILIATION
        assert pending[0].command_id == "command-1"

        delivery = await controller.flush_response_updates()
        assert delivery["state"] == "SYNCED"
        assert delivery["reported"] == 1
        assert client.updates == pending
        assert result_outbox.pending() == []
        assert result_outbox.is_superseded("command-1")
        assert result_outbox.diagnostics()["superseded"] == 1
    finally:
        event_spool.close()
        result_outbox.close()
        response_outbox.close()
