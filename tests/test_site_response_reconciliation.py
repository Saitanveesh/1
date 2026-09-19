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
from mon.site_response_models import SiteResponseUpdate, recovery_update_id
from mon.site_response_outbox import SQLiteResponseUpdateOutbox
from mon.site_response_reconciliation import (
    SiteResponseUpdateError,
    SiteResponseUpdateReconciler,
)
from mon.store import InMemoryStore


NOW = dt.datetime(2026, 9, 19, 3, 0, tzinfo=dt.UTC)


def make_applied_execution() -> ResponseExecution:
    request = ResponseRequest(
        request_id="response-1",
        tenant_id="tenant-a",
        site_id="site-a",
        incident_id="incident-1",
        target=ResponseTarget(ip_address="198.51.100.7"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="fw-1",
        ttl_seconds=300,
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
    return ResponseExecution(
        execution_id=request.request_id,
        tenant_id="tenant-a",
        site_id="site-a",
        plan=ResponsePlan(
            request=request,
            decision=PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                reasons=["test policy"],
                evaluated_at=NOW,
            ),
            enforcement_point=point,
            blast_radius_estimate="single source address",
        ),
        status=ResponseExecutionStatus.APPLIED,
        requested_at=NOW,
        applied_at=NOW,
        expires_at=NOW + dt.timedelta(minutes=5),
        result=EnforcementResult(success=True, message="applied"),
    )


def make_rolled_back_update() -> SiteResponseUpdate:
    applied = make_applied_execution()
    rolled_back = applied.model_copy(
        update={
            "status": ResponseExecutionStatus.ROLLED_BACK,
            "rollback_at": NOW + dt.timedelta(minutes=5, seconds=1),
            "rollback_result": EnforcementResult(
                success=True,
                message="rolled back after TTL",
            ),
        }
    )
    audit = AuditRecord(
        audit_id="site-rollback-audit",
        tenant_id="tenant-a",
        site_id="site-a",
        actor_id="mon-site-recovery",
        category="RESPONSE",
        object_type="response_execution",
        object_id="response-1",
        action="ROLLBACK",
        outcome="ROLLED_BACK",
        occurred_at=NOW + dt.timedelta(minutes=5, seconds=1),
        details={"reason": "temporary response TTL expired"},
    )
    return SiteResponseUpdate(
        update_id=recovery_update_id(rolled_back),
        tenant_id="tenant-a",
        site_id="site-a",
        execution=rolled_back,
        audit_records=[audit],
        observed_at=audit.occurred_at,
    )


def test_recovery_update_is_reconciled_idempotently() -> None:
    store = InMemoryStore()
    store.add_response_execution(make_applied_execution())
    reconciler = SiteResponseUpdateReconciler(store)
    update = make_rolled_back_update()

    first = reconciler.reconcile(update)
    audits_after_first = store.list_audit_records("tenant-a", "site-a")
    second = reconciler.reconcile(update)
    audits_after_second = store.list_audit_records("tenant-a", "site-a")

    assert first.status is ResponseExecutionStatus.ROLLED_BACK
    assert second == first
    assert len(audits_after_first) == 2
    assert audits_after_second == audits_after_first
    assert {record.action for record in audits_after_first} == {
        "ROLLBACK",
        "SITE_RECOVERY_REPORT",
    }


def test_recovery_update_cannot_mutate_plan_or_regress_terminal_state() -> None:
    store = InMemoryStore()
    store.add_response_execution(make_applied_execution())
    reconciler = SiteResponseUpdateReconciler(store)
    update = make_rolled_back_update()

    tampered_request = update.execution.plan.request.model_copy(
        update={"reason": "tampered after execution"}
    )
    tampered_plan = update.execution.plan.model_copy(
        update={"request": tampered_request}
    )
    tampered_execution = update.execution.model_copy(
        update={"plan": tampered_plan}
    )
    tampered = update.model_copy(update={"execution": tampered_execution})
    with pytest.raises(SiteResponseUpdateError, match="cannot mutate the response plan"):
        reconciler.reconcile(tampered)

    reconciler.reconcile(update)
    stale_failure = update.execution.model_copy(
        update={
            "status": ResponseExecutionStatus.ROLLBACK_FAILED,
            "rollback_at": None,
            "rollback_result": EnforcementResult(
                success=False,
                message="late stale failure",
            ),
            "error": "late stale failure",
        }
    )
    stale = SiteResponseUpdate(
        tenant_id="tenant-a",
        site_id="site-a",
        execution=stale_failure,
        observed_at=NOW + dt.timedelta(minutes=6),
    )
    with pytest.raises(SiteResponseUpdateError, match="invalid or stale"):
        reconciler.reconcile(stale)

    current = store.get_response_execution("tenant-a", "site-a", "response-1")
    assert current is not None
    assert current.status is ResponseExecutionStatus.ROLLED_BACK


def test_recovery_update_cannot_overwrite_existing_audit_record() -> None:
    store = InMemoryStore()
    store.add_response_execution(make_applied_execution())
    store.add_audit_record(
        AuditRecord(
            audit_id="site-rollback-audit",
            tenant_id="tenant-a",
            site_id="site-a",
            actor_id="control-plane-existing",
            category="RESPONSE",
            object_type="response_execution",
            object_id="response-1",
            action="EXECUTE",
            outcome="APPLIED",
            occurred_at=NOW,
        )
    )
    reconciler = SiteResponseUpdateReconciler(store)

    with pytest.raises(SiteResponseUpdateError, match="cannot overwrite"):
        reconciler.reconcile(make_rolled_back_update())

    current = store.get_response_execution("tenant-a", "site-a", "response-1")
    assert current is not None
    assert current.status is ResponseExecutionStatus.APPLIED


def test_recovery_update_id_is_stable_and_outbox_retains_acknowledged_receipt(
    tmp_path,
) -> None:
    update = make_rolled_back_update()
    assert recovery_update_id(update.execution) == update.update_id

    path = tmp_path / "response-updates.db"
    outbox = SQLiteResponseUpdateOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        assert outbox.enqueue(update) is True
        assert outbox.enqueue(update) is False
        assert outbox.pending() == [update]
    finally:
        outbox.close()

    reopened = SQLiteResponseUpdateOutbox(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        assert reopened.get(update.update_id) == update
        assert reopened.mark_reported(update.update_id, now=NOW + dt.timedelta(days=1))
        assert reopened.pending() == []
        assert reopened.get(update.update_id) == update
        assert reopened.diagnostics()["reported"] == 1

        pending = update.model_copy(update={"update_id": "pending-update"})
        assert reopened.enqueue(pending) is True
        assert reopened.mark_failed("pending-update", "control plane unavailable")
        assert reopened.diagnostics()["queued"] == 1

        removed = reopened.compact_reported(
            retain_for=dt.timedelta(days=30),
            now=NOW + dt.timedelta(days=32),
        )
        assert removed == 1
        assert reopened.get(update.update_id) is None
        assert reopened.get("pending-update") == pending
    finally:
        reopened.close()


def test_response_update_outbox_rejects_unsafe_scope_and_compaction(tmp_path) -> None:
    outbox = SQLiteResponseUpdateOutbox(
        tmp_path / "response-updates.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    update = make_rolled_back_update()
    try:
        foreign = update.model_copy(update={"tenant_id": "tenant-b"})
        with pytest.raises(ValueError, match="scope"):
            outbox.enqueue(foreign)
        with pytest.raises(ValueError, match="positive"):
            outbox.compact_reported(retain_for=dt.timedelta(0))
        with pytest.raises(ValueError, match="timezone-aware"):
            outbox.compact_reported(
                retain_for=dt.timedelta(days=1),
                now=dt.datetime(2026, 9, 19),
            )
    finally:
        outbox.close()
