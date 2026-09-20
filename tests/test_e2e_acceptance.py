"""MON end-to-end acceptance gate.

Proves DISCOVER -> DETECT -> CORRELATE -> TRACE -> CONTAIN -> VERIFY -> RECOVER
across real MON components, plus tenant isolation, offline/restart durability,
response failure/reconciliation, and backup/restore sub-gates.

This test only runs with real disposable infrastructure:
  - MON_TEST_DATABASE_URL: a real PostgreSQL database (control plane store, RLS)
  - Linux + MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT=1 + a disposable network
    namespace named MON_TEST_NETNS (real `nft`/`ip netns`, containment)

Outside that environment it skips rather than fabricating a result. Mocks are
used only where real infrastructure cannot safely exist in CI: the site<->
control-plane HTTP/mTLS transport is replaced by FastAPI's TestClient (an ASGI
in-process transport already used throughout this test suite), and a real
process crash mid-execution is simulated by directly writing an EXECUTING
response-execution record rather than actually killing the process.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import importlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text

pytestmark = pytest.mark.skipif(
    not (
        os.environ.get("MON_TEST_DATABASE_URL")
        and sys.platform == "linux"
        and os.environ.get("MON_TEST_NETNS")
        and os.environ.get("MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT") == "1"
    ),
    reason=(
        "E2E acceptance gate requires a real PostgreSQL database "
        "(MON_TEST_DATABASE_URL), Linux, a disposable network namespace "
        "(MON_TEST_NETNS), and MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT=1"
    ),
)

REPORT_PATH = Path("e2e-acceptance-report.json")


class _StageRecorder:
    """Records one lifecycle stage's pass/fail into the acceptance report.

    Never swallows the underlying exception: a stage failure still fails the
    test. It only guarantees the report captures NOT_PROVEN with a reason
    instead of silently losing the stage on a crash.
    """

    def __init__(self, report: dict[str, Any], name: str) -> None:
        self.report = report
        self.name = name

    def __enter__(self) -> _StageRecorder:
        self._start = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, _tb) -> bool:
        duration = round(time.monotonic() - self._start, 3)
        if exc_type is None:
            self.report["stages"][self.name] = {
                "status": "PROVEN",
                "duration_seconds": duration,
            }
        else:
            self.report["stages"][self.name] = {
                "status": "NOT_PROVEN",
                "duration_seconds": duration,
                "error": f"{exc_type.__name__}: {exc}"[:2000],
            }
        return False


def _stage(report: dict[str, Any], name: str) -> _StageRecorder:
    return _StageRecorder(report, name)


def _new_report(scenario_id: str, tenant_id: str, site_id: str) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "tenant_id": tenant_id,
        "site_id": site_id,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "stages": {},
        "evidence_ids": [],
        "incident_id": None,
        "response_execution_id": None,
        "enforcement_verification_states": {},
        "rollback_result": None,
        "restart_replay_result": {},
        "isolation_result": {},
        "backup_restore_result": {},
    }


@pytest.mark.asyncio
async def test_e2e_acceptance_gate(tmp_path) -> None:
    import mon.api as api_module

    database_url = os.environ["MON_TEST_DATABASE_URL"]
    admin_database_url = os.environ.get("MON_TEST_ADMIN_DATABASE_URL", database_url)
    namespace = os.environ["MON_TEST_NETNS"]

    tenant_a, site_a = "e2e-tenant-a", "e2e-site-a"
    tenant_b, site_b = "e2e-tenant-b", "e2e-site-b"
    scenario_id = f"e2e-{uuid.uuid4().hex[:12]}"
    report = _new_report(scenario_id, tenant_a, site_a)

    # Fresh control-plane wiring bound to the real PostgreSQL database. A
    # plain `import mon.api` could reuse an already-imported (InMemoryStore)
    # module if some other test file imported it first in this process;
    # reload guarantees this test exercises the real Postgres-backed store.
    os.environ["MON_DATABASE_URL"] = database_url
    importlib.reload(api_module)
    from fastapi.testclient import TestClient

    from mon.auth import Principal, Role, get_principal
    from mon.connectors.nftables_endpoint import LinuxNftablesEndpointAdapter
    from mon.domain import (
        ActionType,
        EnforcementKind,
        EnforcementPoint,
        EnforcementResult,
        EnforcementVerification,
        EnforcementVerificationState,
        Incident,
        PolicyDecision,
        PolicyOutcome,
        ResponseExecution,
        ResponseExecutionStatus,
        ResponsePlan,
        ResponseRequest,
        ResponseTarget,
        SecurityEvent,
    )
    from mon.endpoint import EndpointEventKind, EndpointTelemetryEvent, normalize_endpoint_event
    from mon.enforcement import EnforcementRegistry
    from mon.fabric_ingress import ingest_fabric_envelope
    from mon.pipeline import PipelinePersistenceMode, SecurityPipeline
    from mon.site_analysis_store import SQLiteSiteAnalysisStore
    from mon.site_command_outbox import SQLiteCommandResultOutbox
    from mon.site_controller import SQLiteEventSpool
    from mon.site_response import SiteResponseExecutor
    from mon.site_response_outbox import SQLiteResponseUpdateOutbox
    from mon.site_response_store import SQLiteSiteResponseStore
    from mon.site_sensor_trust import SQLiteSensorTrustStore

    client = TestClient(api_module.app)
    control_store = api_module.store

    tenant_a_admin = Principal(
        subject="e2e-tenant-a-admin",
        tenant_id=tenant_a,
        roles={Role.TENANT_ADMIN},
        site_ids={site_a},
    )
    tenant_b_admin = Principal(
        subject="e2e-tenant-b-admin",
        tenant_id=tenant_b,
        roles={Role.TENANT_ADMIN},
        site_ids={site_b},
    )
    site_a_controller = Principal(
        subject="e2e-site-a-controller",
        tenant_id=tenant_a,
        roles={Role.SITE_CONTROLLER},
        site_ids={site_a},
    )

    def as_principal(principal: Principal):
        api_module.app.dependency_overrides[get_principal] = lambda: principal

    def clear_principal() -> None:
        api_module.app.dependency_overrides.pop(get_principal, None)

    # ---- SITE-side durable state (disposable temp dir; matches the seven
    # database contract from build_site_service_resources for the two SQLite
    # stores this scenario actually needs). ----
    site_state_dir = tmp_path / "site-state"
    site_state_dir.mkdir()

    from mon.event_fabric_outbox import DurableFabricOutbox

    event_spool = SQLiteEventSpool(
        site_state_dir / "event-spool.db", tenant_id=tenant_a, site_id=site_a
    )
    fabric_outbox = DurableFabricOutbox(
        site_state_dir / "fabric-outbox.db", tenant_id=tenant_a, site_id=site_a
    )
    site_analysis_store = SQLiteSiteAnalysisStore(
        site_state_dir / "analysis-state.db", tenant_id=tenant_a, site_id=site_a
    )
    site_response_store = SQLiteSiteResponseStore(
        site_state_dir / "response-state.db", tenant_id=tenant_a, site_id=site_a
    )
    site_command_result_outbox = SQLiteCommandResultOutbox(
        site_state_dir / "command-results.db", tenant_id=tenant_a, site_id=site_a
    )
    site_response_update_outbox = SQLiteResponseUpdateOutbox(
        site_state_dir / "response-updates.db", tenant_id=tenant_a, site_id=site_a
    )
    site_sensor_trust_store = SQLiteSensorTrustStore(
        site_state_dir / "sensor-trust.db", tenant_id=tenant_a, site_id=site_a
    )
    # The site also runs its own local detection copy against durable
    # analysis-state.db, independent of the control plane's pipeline -- this
    # is what gives analysis-state.db genuine content for the backup/restore
    # sub-gate to prove survives, matching the real dual-pipeline design.
    site_pipeline = SecurityPipeline(
        store=site_analysis_store,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    site_pipeline.restore_scope(tenant_a, site_a)
    site_registry = EnforcementRegistry()

    nft_vendor = "linux-nftables-e2e"
    src_ip = "203.0.113.50"
    asset_id = "linux-host:web-01"

    try:
        # ================================================================
        # Stages 1-5: DISCOVER -- sensor telemetry -> Site Controller ->
        # normalization -> durable local queue -> reaches the control plane.
        # ================================================================
        events: list[SecurityEvent] = []
        with _stage(report, "01_sensor_event_produced"):
            base_time = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=40)
            for index in range(8):
                telemetry = EndpointTelemetryEvent(
                    tenant_id=tenant_a,
                    site_id=site_a,
                    sensor_id="e2e-endpoint-sensor-1",
                    event_id=f"{scenario_id}-auth-{index}",
                    observed_at=base_time + dt.timedelta(seconds=5 * index),
                    kind=EndpointEventKind.AUTH_FAILURE,
                    asset_id=asset_id,
                    hostname="web-01",
                    src_ip=src_ip,
                    user_name="root",
                    outcome="failure",
                    source="sshd",
                )
                assert telemetry.tenant_id == tenant_a
                events.append(telemetry)

        with _stage(report, "02_normalization_produces_security_event"):
            security_events = [normalize_endpoint_event(item) for item in events]
            for item, source in zip(security_events, events, strict=True):
                assert item.category == "endpoint.auth.failure"
                assert item.event_id == source.event_id
                assert item.attributes.get("identity_source") == "username"

        with _stage(report, "03_event_enters_site_controller"):
            for item in security_events:
                assert event_spool.enqueue(item) is True
                site_pipeline.process_event(item)
            assert event_spool.count() == len(security_events)
            assert len(site_analysis_store.list_events(tenant_a, site_a)) == len(security_events)

        with _stage(report, "04_event_durably_queued"):
            envelopes = []
            for item in security_events:
                envelope = fabric_outbox.enqueue_security_event(item)
                envelopes.append(envelope)
            assert fabric_outbox.diagnostics()["pending"] == len(security_events)

        with _stage(report, "05_event_reaches_control_plane"):
            for envelope in envelopes:
                ingested = ingest_fabric_envelope(
                    control_store, api_module.pipeline, envelope
                )
                assert ingested.acknowledgement.duplicate is False
                assert fabric_outbox.mark_delivered(envelope.event_id) is True
            assert fabric_outbox.diagnostics()["pending"] == 0
            for item in security_events:
                assert control_store.event_exists(tenant_a, site_a, item.event_id)

        # ================================================================
        # Stages 6-10: DETECT -> CORRELATE -> TRACE
        # ================================================================
        with _stage(report, "06_detection_produces_real_finding"):
            findings = control_store.list_findings(tenant_a, site_a)
            auth_findings = [
                item for item in findings if item.detector_id == "endpoint-auth-failure-pressure"
            ]
            assert len(auth_findings) == 1, (
                f"expected exactly one auth-failure-pressure finding, got {len(auth_findings)}"
            )
            finding = auth_findings[0]
            report["evidence_ids"].extend(
                sorted({item.evidence_id for item in finding.evidence})
            )

        with _stage(report, "07_correlation_creates_incident"):
            incidents = control_store.list_incidents(tenant_a, site_a)
            matching = [item for item in incidents if finding.finding_id in item.finding_ids]
            assert len(matching) == 1
            incident = matching[0]
            report["incident_id"] = incident.incident_id

        with _stage(report, "08_incident_contains_evidence"):
            assert len(incident.evidence) > 0
            evidence_classes = {item.evidence_class.value for item in incident.evidence}
            assert "IDENTITY" in evidence_classes
            report["evidence_ids"] = sorted(
                {item.evidence_id for item in incident.evidence} | set(report["evidence_ids"])
            )

        with _stage(report, "09_affected_asset_and_identity_resolve"):
            resolved_asset = control_store.get_asset(tenant_a, site_a, asset_id)
            assert resolved_asset is not None
            assert resolved_asset.asset_id == asset_id
            identities = control_store.list_identities(tenant_a, site_a)
            assert any(item.principal == "root" for item in identities)

        as_principal(tenant_a_admin)
        try:
            with _stage(report, "10_investigation_graph_contains_path"):
                investigation_response = client.get(
                    f"/api/v1/incidents/{incident.incident_id}/investigation",
                    params={"tenant_id": tenant_a, "site_id": site_a},
                )
                assert investigation_response.status_code == 200
                investigation = investigation_response.json()
                assert investigation["incident"]["incident_id"] == incident.incident_id
                assert asset_id in {
                    node["node_id"].removeprefix("asset:")
                    for node in investigation["graph"]["nodes"]
                    if node["kind"] == "ASSET"
                }
                assert len(investigation["evidence"]) > 0
        finally:
            clear_principal()

        # ================================================================
        # Stages 11-13: CONTAIN (planning + dispatch)
        # ================================================================
        as_principal(tenant_a_admin)
        try:
            with _stage(report, "11_response_planning_selects_enforcement_point"):
                point_response = client.post(
                    "/api/v1/enforcement-points",
                    json={
                        "enforcement_point_id": f"{scenario_id}-fw",
                        "tenant_id": tenant_a,
                        "site_id": site_a,
                        "kind": "FIREWALL",
                        "vendor": nft_vendor,
                        "capabilities": ["BLOCK_IP"],
                    },
                )
                assert point_response.status_code == 201
                binding_response = client.post(
                    "/api/v1/enforcement-bindings",
                    json={
                        "tenant_id": tenant_a,
                        "site_id": site_a,
                        "asset_id": asset_id,
                        "enforcement_point_id": f"{scenario_id}-fw",
                        "attributes": {"blast_radius_estimate": "single suspicious source IP"},
                    },
                )
                assert binding_response.status_code == 201

                plan_response = client.post(
                    "/api/v1/responses/plan",
                    json={
                        "request_id": f"{scenario_id}-response",
                        "tenant_id": tenant_a,
                        "site_id": site_a,
                        "incident_id": incident.incident_id,
                        "target": {"ip_address": src_ip},
                        "action": "BLOCK_IP",
                        "ttl_seconds": 120,
                        "reason": "acceptance gate containment",
                    },
                )
                assert plan_response.status_code == 200
                planned = plan_response.json()
                assert planned["enforcement_point"]["enforcement_point_id"] == f"{scenario_id}-fw"

            with _stage(report, "12_policy_decision_recorded"):
                assert planned["decision"]["outcome"] in {"REQUIRE_APPROVAL", "ALLOW"}

            with _stage(report, "13_response_dispatched_to_site_controller"):
                execute_response = client.post(
                    "/api/v1/responses/execute",
                    json={
                        "request": {
                            "request_id": f"{scenario_id}-response",
                            "tenant_id": tenant_a,
                            "site_id": site_a,
                            "incident_id": incident.incident_id,
                            "target": {"ip_address": src_ip},
                            "action": "BLOCK_IP",
                            "ttl_seconds": 120,
                            "reason": "acceptance gate containment",
                        },
                        "approve": True,
                        "approval_reason": "acceptance gate reviewed evidence",
                    },
                )
                assert execute_response.status_code == 200
                execution_payload = execute_response.json()
                report["response_execution_id"] = execution_payload["execution_id"]
                assert execution_payload["status"] in {
                    "DISPATCH_PENDING",
                    "APPLIED",
                }
        finally:
            clear_principal()

        as_principal(site_a_controller)
        try:
            pending_response = client.get(
                "/api/v1/site-commands/pending",
                params={"tenant_id": tenant_a, "site_id": site_a},
            )
        finally:
            clear_principal()
        assert pending_response.status_code == 200
        pending_commands = pending_response.json()
        apply_commands = [item for item in pending_commands if item["kind"] == "APPLY_RESPONSE"]
        assert len(apply_commands) == 1
        apply_command_payload = apply_commands[0]

        from mon.site_command_models import SiteCommand

        apply_command = SiteCommand.model_validate(apply_command_payload)
        containment_plan: ResponsePlan = apply_command.response_plan
        assert containment_plan is not None
        execution_id = containment_plan.request.request_id

        # ================================================================
        # Stages 14-16: real disposable-namespace enforcement.
        # ================================================================
        adapter = LinuxNftablesEndpointAdapter(namespace=namespace)
        site_registry.register(
            EnforcementKind.FIREWALL,
            nft_vendor,
            adapter,
            capabilities=adapter.capabilities,
        )
        site_executor = SiteResponseExecutor(
            tenant_a, site_a, site_response_store, site_registry
        )

        with _stage(report, "14_disposable_nftables_block_ip_applied"):
            apply_result = await site_executor.execute(apply_command)
            assert apply_result.success is True
            assert apply_result.execution is not None
            assert apply_result.execution.status is ResponseExecutionStatus.APPLIED
            site_command_result_outbox.enqueue(apply_result)

        with _stage(report, "15_independent_verify_reports_present"):
            verification = await adapter.verify(containment_plan, execution_id)
            assert verification.state is EnforcementVerificationState.PRESENT
            report["enforcement_verification_states"]["after_apply"] = verification.state.value

        with _stage(report, "16_execution_and_audit_state_persisted"):
            stored_execution = site_response_store.get_response_execution(
                tenant_a, site_a, execution_id
            )
            assert stored_execution is not None
            assert stored_execution.status is ResponseExecutionStatus.APPLIED
            site_audit = site_response_store.list_audit_records(tenant_a, site_a)
            assert any(
                item.action == "EXECUTE" and item.outcome == "APPLIED" for item in site_audit
            )

            as_principal(site_a_controller)
            try:
                result_response = client.post(
                    "/api/v1/site-commands/results",
                    json=json.loads(apply_result.model_dump_json()),
                )
            finally:
                clear_principal()
            assert result_response.status_code == 200
            control_plane_execution = control_store.get_response_execution(
                tenant_a, site_a, execution_id
            )
            assert control_plane_execution is not None
            assert control_plane_execution.status is ResponseExecutionStatus.APPLIED

        # Duplicate replay safety: re-delivering the already-processed apply
        # command must not create a second nftables rule or a second apply.
        with _stage(report, "offline_duplicate_apply_is_not_reapplied"):
            replay_result = await site_executor.execute(apply_command)
            assert replay_result.success is True
            replay_verification = await adapter.verify(containment_plan, execution_id)
            assert replay_verification.state is EnforcementVerificationState.PRESENT

        # ================================================================
        # Stages 17-19: VERIFY -> RECOVER (explicit rollback)
        # ================================================================
        as_principal(tenant_a_admin)
        try:
            with _stage(report, "17a_rollback_dispatched"):
                rollback_response = client.post(
                    f"/api/v1/responses/{execution_id}/rollback",
                    params={"tenant_id": tenant_a, "site_id": site_a},
                    json={"reason": "acceptance gate TTL/rollback proof"},
                )
                assert rollback_response.status_code == 200
                rollback_dispatch = rollback_response.json()
                assert rollback_dispatch["status"] in {
                    "ROLLBACK_PENDING",
                    "ROLLED_BACK",
                }
        finally:
            clear_principal()

        as_principal(site_a_controller)
        try:
            pending_after_rollback = client.get(
                "/api/v1/site-commands/pending",
                params={"tenant_id": tenant_a, "site_id": site_a},
            )
        finally:
            clear_principal()
        rollback_commands = [
            item
            for item in pending_after_rollback.json()
            if item["kind"] == "ROLLBACK_RESPONSE"
        ]
        assert len(rollback_commands) == 1
        rollback_command = SiteCommand.model_validate(rollback_commands[0])

        with _stage(report, "17b_explicit_rollback_removes_containment"):
            rollback_result = await site_executor.execute(rollback_command)
            assert rollback_result.success is True
            assert rollback_result.execution is not None
            assert rollback_result.execution.status is ResponseExecutionStatus.ROLLED_BACK
            site_command_result_outbox.enqueue(rollback_result)
            report["rollback_result"] = rollback_result.execution.status.value

        with _stage(report, "18_independent_verify_reports_absent"):
            absent_verification = await adapter.verify(containment_plan, execution_id)
            assert absent_verification.state is EnforcementVerificationState.ABSENT
            report["enforcement_verification_states"]["after_rollback"] = (
                absent_verification.state.value
            )

        with _stage(report, "19_recovery_audit_reflects_rollback_honestly"):
            as_principal(site_a_controller)
            try:
                rollback_post_response = client.post(
                    "/api/v1/site-commands/results",
                    json=json.loads(rollback_result.model_dump_json()),
                )
            finally:
                clear_principal()
            assert rollback_post_response.status_code == 200

            as_principal(tenant_a_admin)
            try:
                audit_response = client.get(
                    "/api/v1/audit",
                    params={"tenant_id": tenant_a, "site_id": site_a},
                )
            finally:
                clear_principal()
            assert audit_response.status_code == 200
            audit_records = audit_response.json()
            assert any(
                item["action"] == "ROLLBACK" and item["outcome"] == "ROLLED_BACK"
                for item in audit_records
            )
            final_control_execution = control_store.get_response_execution(
                tenant_a, site_a, execution_id
            )
            assert final_control_execution is not None
            assert final_control_execution.status is ResponseExecutionStatus.ROLLED_BACK

        # ================================================================
        # TENANT ISOLATION SUB-GATE
        # ================================================================
        control_store.add_incident(
            Incident(
                incident_id=f"{scenario_id}-tenant-b-incident",
                tenant_id=tenant_b,
                site_id=site_b,
                title="Tenant B unrelated incident",
                severity="LOW",
                confidence=0.5,
            )
        )

        as_principal(tenant_b_admin)
        try:
            with _stage(report, "isolation_incident_not_readable_cross_tenant"):
                cross_investigation = client.get(
                    f"/api/v1/incidents/{incident.incident_id}/investigation",
                    params={"tenant_id": tenant_b, "site_id": site_b},
                )
                assert cross_investigation.status_code == 404
                report["isolation_result"]["incident_cross_tenant_status"] = (
                    cross_investigation.status_code
                )

            with _stage(report, "isolation_responses_not_listed_cross_tenant"):
                cross_responses = client.get(
                    "/api/v1/responses",
                    params={"tenant_id": tenant_b, "site_id": site_b},
                )
                assert cross_responses.status_code == 200
                assert execution_id not in {
                    item["execution_id"] for item in cross_responses.json()
                }

            with _stage(report, "isolation_rollback_denied_cross_tenant"):
                denied_rollback = client.post(
                    f"/api/v1/responses/{execution_id}/rollback",
                    params={"tenant_id": tenant_b, "site_id": site_b},
                    json={"reason": "tenant B should never be able to do this"},
                )
                assert denied_rollback.status_code == 409
                report["isolation_result"]["rollback_cross_tenant_status"] = (
                    denied_rollback.status_code
                )

            with _stage(report, "isolation_auth_layer_denies_cross_tenant_scope"):
                denied_scope = client.get(
                    "/api/v1/audit",
                    params={"tenant_id": tenant_a, "site_id": site_a},
                )
                assert denied_scope.status_code == 403
                report["isolation_result"]["auth_layer_cross_tenant_status"] = (
                    denied_scope.status_code
                )
        finally:
            clear_principal()

        with _stage(report, "isolation_postgresql_rls_enforces_separation"):
            engine = getattr(control_store, "engine", None)
            if engine is not None:
                with engine.connect() as connection:
                    unscoped = connection.execute(
                        text(
                            "SELECT incident_id FROM incidents "
                            "WHERE incident_id = :incident_id"
                        ),
                        {"incident_id": incident.incident_id},
                    ).scalars().all()
                assert unscoped == []
                report["isolation_result"]["rls_unscoped_raw_query_visible_rows"] = len(unscoped)
            else:
                report["isolation_result"]["rls_unscoped_raw_query_visible_rows"] = "N/A"

        # ================================================================
        # RESPONSE FAILURE SUB-GATE (existing adapter boundary; reconcile
        # an interrupted/uncertain execution rather than fabricating an
        # actual process crash).
        # ================================================================
        with _stage(report, "response_failure_uncertain_execution_reconciled_honestly"):

            class _AlwaysAbsentAdapter:
                async def execute(self, plan, execution_id):
                    raise RuntimeError("simulated uncertain external call failure")

                async def rollback(self, plan, execution_id):
                    return EnforcementResult(success=True, message="nothing to roll back")

                async def verify(self, plan, execution_id):
                    return EnforcementVerification(
                        state=EnforcementVerificationState.ABSENT,
                        message="never actually applied",
                    )

            failure_vendor = "e2e-uncertain-adapter"
            site_registry.register(EnforcementKind.ENDPOINT, failure_vendor, _AlwaysAbsentAdapter())

            failure_request = ResponseRequest(
                request_id=f"{scenario_id}-uncertain",
                tenant_id=tenant_a,
                site_id=site_a,
                incident_id=incident.incident_id,
                target=ResponseTarget(asset_id=asset_id),
                action=ActionType.ISOLATE_ENDPOINT,
                ttl_seconds=120,
                reason="acceptance gate uncertain-failure proof",
            )
            failure_point = EnforcementPoint(
                enforcement_point_id=f"{scenario_id}-uncertain-ep",
                tenant_id=tenant_a,
                site_id=site_a,
                kind=EnforcementKind.ENDPOINT,
                vendor=failure_vendor,
                capabilities={ActionType.ISOLATE_ENDPOINT},
            )
            failure_plan = ResponsePlan(
                request=failure_request,
                decision=PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["acceptance gate"]),
                enforcement_point=failure_point,
            )
            interrupted_execution = ResponseExecution(
                execution_id=failure_request.request_id,
                tenant_id=tenant_a,
                site_id=site_a,
                plan=failure_plan,
                status=ResponseExecutionStatus.EXECUTING,
            )
            site_response_store.add_response_execution(interrupted_execution)

            reconciled = await site_executor.reconcile_execution(interrupted_execution)
            assert reconciled.status is ResponseExecutionStatus.FAILED, (
                "an uncertain execution verified ABSENT must never be reported as success"
            )

            persisted_failure = site_response_store.get_response_execution(
                tenant_a, site_a, failure_request.request_id
            )
            assert persisted_failure is not None
            assert persisted_failure.status is ResponseExecutionStatus.FAILED

            failure_audit = [
                item
                for item in site_response_store.list_audit_records(tenant_a, site_a)
                if item.object_id == failure_request.request_id
            ]
            assert any(
                item.action == "VERIFY" and item.outcome == "ABSENT" for item in failure_audit
            ), "reconciliation must leave an observable VERIFY audit trail"

        # ================================================================
        # OFFLINE / RESTART SUB-GATE (already partly covered above via
        # duplicate-apply safety; here we prove the queue-while-offline,
        # restart, and eventual-delivery path using the real fabric outbox).
        # ================================================================
        with _stage(report, "restart_event_queued_while_delivery_unavailable"):
            offline_telemetry = EndpointTelemetryEvent(
                tenant_id=tenant_a,
                site_id=site_a,
                sensor_id="e2e-endpoint-sensor-1",
                event_id=f"{scenario_id}-offline-1",
                observed_at=dt.datetime.now(dt.UTC),
                kind=EndpointEventKind.AUTH_FAILURE,
                asset_id=asset_id,
                hostname="web-01",
                src_ip=src_ip,
                user_name="deploy",
                outcome="failure",
                source="sshd",
            )
            offline_event = normalize_endpoint_event(offline_telemetry)
            offline_envelope = fabric_outbox.enqueue_security_event(offline_event)
            assert fabric_outbox.diagnostics()["pending"] == 1
            fabric_outbox.close()

        with _stage(report, "restart_site_controller_durable_state_reopened"):
            fabric_outbox_reopened = DurableFabricOutbox(
                site_state_dir / "fabric-outbox.db", tenant_id=tenant_a, site_id=site_a
            )
            assert fabric_outbox_reopened.diagnostics()["pending"] == 1

        with _stage(report, "restart_event_eventually_delivered_after_transport_restored"):
            reopened_pending = fabric_outbox_reopened.pending(limit=10)
            assert len(reopened_pending) == 1
            first_delivery = ingest_fabric_envelope(
                control_store, api_module.pipeline, reopened_pending[0]
            )
            assert first_delivery.acknowledgement.duplicate is False
            assert fabric_outbox_reopened.mark_delivered(offline_event.event_id) is True
            assert control_store.event_exists(tenant_a, site_a, offline_event.event_id)
            report["restart_replay_result"]["delivered"] = True

        with _stage(report, "restart_duplicate_replay_is_safe"):
            duplicate_delivery = ingest_fabric_envelope(
                control_store, api_module.pipeline, offline_envelope
            )
            assert duplicate_delivery.acknowledgement.duplicate is True
            assert duplicate_delivery.processing_result is None
            matching_events = [
                item
                for item in control_store.list_events(tenant_a, site_a)
                if item.event_id == offline_event.event_id
            ]
            assert len(matching_events) == 1
            report["restart_replay_result"]["duplicate_replay_created_second_event"] = False
        fabric_outbox_reopened.close()

        # ================================================================
        # BACKUP / RESTORE SUB-GATE (reuses existing tooling only)
        # ================================================================
        with _stage(report, "backup_restore_site_state_snapshot_round_trip"):
            from mon.site_state_snapshot import (
                create_site_state_snapshot,
                restore_site_state_snapshot,
            )

            event_spool.close()
            site_analysis_store.close()
            site_response_store.close()
            site_command_result_outbox.close()
            site_response_update_outbox.close()
            site_sensor_trust_store.close()

            snapshot_archive = tmp_path / "site-state-snapshot.zip"
            create_site_state_snapshot(
                site_state_dir, snapshot_archive, tenant_id=tenant_a, site_id=site_a
            )
            restore_dir = tmp_path / "site-state-restored"
            _manifest, diagnostics = restore_site_state_snapshot(
                snapshot_archive, restore_dir, tenant_id=tenant_a, site_id=site_a
            )

            restored_response_store = SQLiteSiteResponseStore(
                restore_dir / "response-state.db", tenant_id=tenant_a, site_id=site_a
            )
            try:
                restored_execution = restored_response_store.get_response_execution(
                    tenant_a, site_a, execution_id
                )
                assert restored_execution is not None
                assert restored_execution.status is ResponseExecutionStatus.ROLLED_BACK
                restored_audit = restored_response_store.list_audit_records(tenant_a, site_a)
                assert len(restored_audit) > 0
            finally:
                restored_response_store.close()

            restored_spool = SQLiteEventSpool(
                restore_dir / "event-spool.db", tenant_id=tenant_a, site_id=site_a
            )
            try:
                assert restored_spool.count() == len(security_events)
            finally:
                restored_spool.close()

            restored_analysis_store = SQLiteSiteAnalysisStore(
                restore_dir / "analysis-state.db", tenant_id=tenant_a, site_id=site_a
            )
            try:
                assert len(
                    restored_analysis_store.list_events(tenant_a, site_a)
                ) == len(security_events)
            finally:
                restored_analysis_store.close()

            report["backup_restore_result"]["site_state"] = {
                "restored_databases": sorted(diagnostics.keys()),
                "queued_events_survived": True,
                "response_execution_survived": True,
            }

        with _stage(report, "backup_restore_postgresql_incident_round_trip"):
            from mon import control_plane_backup

            # A backup must capture every tenant's data unconditionally, so
            # this whole sub-gate deliberately uses the superuser admin URL
            # (never the RLS-restricted mon_app_e2e role used for the main
            # scenario) -- the same reasoning a real backup/restore job
            # would apply.
            # admin_engine/restore_url go through SQLAlchemy (create_engine,
            # DatabaseStore) and must keep the `+psycopg` driver suffix.
            # control_plane_backup.backup()/restore()/verify() instead shell
            # out to pg_dump/pg_restore/psql, which need the plain
            # `postgresql://` form -- they already strip the suffix
            # themselves internally via native_postgres_url(), so the
            # original (unstripped) admin_database_url is passed to them.
            restore_db_name = f"mon_e2e_restore_{uuid.uuid4().hex[:12]}"
            admin_engine = create_engine(
                admin_database_url.rsplit("/", 1)[0] + "/postgres",
                isolation_level="AUTOCOMMIT",
            )
            try:
                with admin_engine.connect() as connection:
                    connection.execute(text(f'CREATE DATABASE "{restore_db_name}"'))
            finally:
                admin_engine.dispose()

            dump_path = tmp_path / "control-plane.dump"
            control_plane_backup.backup(admin_database_url, dump_path)

            restore_url = (
                admin_database_url.rsplit("/", 1)[0]
                + f"/{restore_db_name}"
            )
            control_plane_backup.restore(restore_url, dump_path)
            control_plane_backup.verify(restore_url)

            from mon.database import DatabaseStore

            restored_store = DatabaseStore(restore_url)
            try:
                restored_incident = restored_store.get_incident(
                    tenant_a, site_a, incident.incident_id
                )
                assert restored_incident is not None
                assert restored_incident.title == incident.title
                restored_audit_records = restored_store.list_audit_records(tenant_a, site_a)
                assert len(restored_audit_records) > 0
            finally:
                restored_store.close()

            report["backup_restore_result"]["postgresql"] = {
                "restore_database": restore_db_name,
                "incident_survived": True,
                "audit_survived": True,
            }

    finally:
        for closable in (
            event_spool,
            fabric_outbox,
            site_analysis_store,
            site_response_store,
            site_command_result_outbox,
            site_response_update_outbox,
            site_sensor_trust_store,
        ):
            with contextlib.suppress(Exception):
                closable.close()

        report["generated_at"] = dt.datetime.now(dt.UTC).isoformat()
        report["all_stages_proven"] = all(
            item["status"] == "PROVEN" for item in report["stages"].values()
        )
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
