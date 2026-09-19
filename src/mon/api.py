from __future__ import annotations

import asyncio
import time

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from mon import __version__
from mon.attack_graph import AttackGraphEngine
from mon.auth import (
    CurrentPrincipal,
    Permission,
    Principal,
    is_scope_authorized,
    require_scope,
)
from mon.correlation import CorrelationEngine
from mon.database import create_control_plane_store
from mon.detection import DetectionEngine
from mon.domain import (
    ActorType,
    Asset,
    AttackGraphSnapshot,
    AuditRecord,
    EnforcementBinding,
    EnforcementPoint,
    EventBatch,
    EventBatchResult,
    EventProcessingResult,
    Finding,
    Incident,
    IncidentInvestigation,
    ResponseApproval,
    ResponseExecution,
    ResponseExecutionCommand,
    ResponsePlan,
    ResponseRequest,
    ResponseRollbackCommand,
    SecurityEvent,
)
from mon.enforcement import EnforcementRegistry
from mon.investigation import build_incident_investigation
from mon.live import LiveEventHub, LiveMessageKind
from mon.pipeline import SecurityPipeline
from mon.response import ResponseOrchestrator, ResponseStateError
from mon.response_dispatch import ResponseDispatcher
from mon.site_command_models import (
    SiteCommand,
    SiteCommandKind,
    SiteCommandRecord,
    SiteCommandResult,
)
from mon.site_command_queue import SiteCommandError, SiteCommandQueue
from mon.site_identity import (
    EnrollmentDenied,
    IdentityConfigurationError,
    enroll_site,
    get_certificate_authority,
    issue_enrollment_token,
)
from mon.site_response_models import SiteResponseUpdate
from mon.site_response_reconciliation import (
    SiteResponseUpdateError,
    SiteResponseUpdateReconciler,
)
from mon.site_identity_models import (
    EnrollmentTokenIssue,
    EnrollmentTokenRequest,
    SiteEnrollmentRequest,
    SiteEnrollmentResult,
    SiteIdentityRecord,
)

app = FastAPI(
    title="MON Security Fabric Control Plane",
    version=__version__,
    description="Control-plane foundation for evidence-backed detection and safe response.",
)
store = create_control_plane_store()
detector = DetectionEngine()
graph = AttackGraphEngine()
correlator = CorrelationEngine()
pipeline = SecurityPipeline(
    store=store,
    detector=detector,
    graph=graph,
    correlator=correlator,
)
live_hub = LiveEventHub()
enforcement_registry = EnforcementRegistry()
response_orchestrator = ResponseOrchestrator(store, enforcement_registry)
site_command_queue = SiteCommandQueue(store)
response_dispatcher = ResponseDispatcher(
    store,
    response_orchestrator,
    site_command_queue,
)
site_response_reconciler = SiteResponseUpdateReconciler(store)


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "state": "READY",
        "service": "mon-control-plane",
        "version": __version__,
        "live_transport": "WEBSOCKET_PUSH",
    }


@app.get("/api/v1/me", response_model=Principal)
def who_am_i(principal: CurrentPrincipal) -> Principal:
    return principal


@app.post(
    "/api/v1/events",
    response_model=EventProcessingResult,
    status_code=201,
)
async def ingest_event(
    event: SecurityEvent,
    principal: CurrentPrincipal,
) -> EventProcessingResult:
    require_scope(
        principal,
        event.tenant_id,
        event.site_id,
        Permission.INGEST,
    )
    started = time.perf_counter()
    result = await run_in_threadpool(pipeline.process_event, event)
    processing_ms = (time.perf_counter() - started) * 1000
    await live_hub.publish_processing_result(result, processing_ms=processing_ms)
    return result


@app.post(
    "/api/v1/events/batch",
    response_model=EventBatchResult,
    status_code=201,
)
async def ingest_event_batch(
    batch: EventBatch,
    principal: CurrentPrincipal,
) -> EventBatchResult:
    first = batch.events[0]
    require_scope(
        principal,
        first.tenant_id,
        first.site_id,
        Permission.INGEST,
    )

    results: list[EventProcessingResult] = []
    for event in batch.events:
        started = time.perf_counter()
        result = await run_in_threadpool(pipeline.process_event, event)
        processing_ms = (time.perf_counter() - started) * 1000
        results.append(result)
        await live_hub.publish_processing_result(result, processing_ms=processing_ms)

    return EventBatchResult(
        results=results,
        accepted_event_ids=[result.event.event_id for result in results],
    )


@app.websocket("/ws/v1/live")
async def live_stream(
    websocket: WebSocket,
    principal: CurrentPrincipal,
) -> None:
    tenant_id = (websocket.query_params.get("tenant_id") or "").strip()
    site_id = (websocket.query_params.get("site_id") or "").strip()
    if not tenant_id or not site_id:
        await websocket.close(code=1008, reason="tenant_id and site_id are required")
        return
    if not is_scope_authorized(principal, tenant_id, site_id, Permission.VIEW):
        await websocket.close(code=1008, reason="tenant/site access denied")
        return

    await websocket.accept()
    subscription = await live_hub.subscribe(tenant_id, site_id)
    try:
        ready = await live_hub.ready_envelope(tenant_id, site_id)
        await websocket.send_json(ready.model_dump(mode="json"))

        while True:
            try:
                envelope = await asyncio.wait_for(
                    subscription.queue.get(),
                    timeout=15.0,
                )
            except TimeoutError:
                envelope = await live_hub.heartbeat_envelope(subscription)

            await websocket.send_json(envelope.model_dump(mode="json"))
    except WebSocketDisconnect:
        pass
    finally:
        await live_hub.unsubscribe(subscription)


@app.get("/api/v1/live/snapshot")
async def live_snapshot(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> dict[str, object]:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    findings = await run_in_threadpool(store.list_findings, tenant_id, site_id)
    incidents = await run_in_threadpool(store.list_incidents, tenant_id, site_id)
    assets = await run_in_threadpool(store.list_assets, tenant_id, site_id)
    snapshot = await run_in_threadpool(graph.snapshot, tenant_id, site_id)
    telemetry = await run_in_threadpool(pipeline.telemetry.snapshot, tenant_id, site_id)
    enforcement_points = await run_in_threadpool(
        store.list_enforcement_points,
        tenant_id,
        site_id,
    )
    enforcement_bindings = await run_in_threadpool(
        store.list_enforcement_bindings,
        tenant_id,
        site_id,
        None,
    )
    response_executions = await run_in_threadpool(
        store.list_response_executions,
        tenant_id,
        site_id,
    )
    audit_records = await run_in_threadpool(
        store.list_audit_records,
        tenant_id,
        site_id,
    )
    sequence = await live_hub.current_sequence(tenant_id, site_id)

    return {
        "tenant_id": tenant_id,
        "site_id": site_id,
        "sequence": sequence,
        "findings": [item.model_dump(mode="json") for item in findings],
        "incidents": [item.model_dump(mode="json") for item in incidents],
        "assets": [item.model_dump(mode="json") for item in assets],
        "telemetry": telemetry.model_dump(mode="json"),
        "enforcement_points": [
            item.model_dump(mode="json") for item in enforcement_points
        ],
        "enforcement_bindings": [
            item.model_dump(mode="json") for item in enforcement_bindings
        ],
        "response_executions": [
            item.model_dump(mode="json") for item in response_executions
        ],
        "audit_records": [
            item.model_dump(mode="json") for item in audit_records
        ],
        "graph": snapshot.model_dump(mode="json"),
    }


@app.get("/api/v1/findings", response_model=list[Finding])
def list_findings(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> list[Finding]:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    return store.list_findings(tenant_id, site_id)


@app.get("/api/v1/graph", response_model=AttackGraphSnapshot)
def get_attack_graph(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> AttackGraphSnapshot:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    return graph.snapshot(tenant_id, site_id)


@app.get(
    "/api/v1/incidents/{incident_id}/investigation",
    response_model=IncidentInvestigation,
)
def get_incident_investigation(
    incident_id: str,
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> IncidentInvestigation:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    incident = store.get_incident(tenant_id, site_id, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found in tenant/site scope")
    return build_incident_investigation(store, graph, incident)


@app.get("/api/v1/incidents/{incident_id}/graph", response_model=AttackGraphSnapshot)
def get_incident_graph(
    incident_id: str,
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> AttackGraphSnapshot:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    incident = store.get_incident(tenant_id, site_id, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found in tenant/site scope")
    return graph.trace_incident(incident)


@app.get("/api/v1/assets", response_model=list[Asset])
def list_assets(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> list[Asset]:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    return store.list_assets(tenant_id, site_id)


@app.post("/api/v1/assets", response_model=Asset, status_code=201)
async def upsert_asset(
    asset: Asset,
    principal: CurrentPrincipal,
) -> Asset:
    require_scope(principal, asset.tenant_id, asset.site_id, Permission.CONFIGURE)
    stored = await run_in_threadpool(store.add_asset, asset)
    await live_hub.publish(
        LiveMessageKind.ASSET_UPDATED,
        asset.tenant_id,
        asset.site_id,
        {"asset": stored.model_dump(mode="json")},
    )
    return stored


@app.post("/api/v1/incidents", response_model=Incident, status_code=201)
async def create_incident(
    incident: Incident,
    principal: CurrentPrincipal,
) -> Incident:
    require_scope(principal, incident.tenant_id, incident.site_id, Permission.RESPOND)
    stored = await run_in_threadpool(store.add_incident, incident)
    await live_hub.publish(
        LiveMessageKind.INCIDENT_UPDATED,
        incident.tenant_id,
        incident.site_id,
        {"incident": stored.model_dump(mode="json")},
    )
    return stored


@app.get("/api/v1/incidents", response_model=list[Incident])
def list_incidents(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> list[Incident]:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    return store.list_incidents(tenant_id, site_id)


@app.get("/api/v1/enforcement-points", response_model=list[EnforcementPoint])
def list_enforcement_points(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> list[EnforcementPoint]:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    return store.list_enforcement_points(tenant_id, site_id)


@app.get("/api/v1/enforcement-bindings", response_model=list[EnforcementBinding])
def list_enforcement_bindings(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
    asset_id: str | None = Query(default=None),
) -> list[EnforcementBinding]:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    return store.list_enforcement_bindings(tenant_id, site_id, asset_id)


@app.post("/api/v1/enforcement-points", response_model=EnforcementPoint, status_code=201)
async def upsert_enforcement_point(
    point: EnforcementPoint,
    principal: CurrentPrincipal,
) -> EnforcementPoint:
    require_scope(principal, point.tenant_id, point.site_id, Permission.CONFIGURE)
    stored = await run_in_threadpool(store.add_enforcement_point, point)
    await live_hub.publish(
        LiveMessageKind.ENFORCEMENT_UPDATED,
        point.tenant_id,
        point.site_id,
        {"enforcement_point": stored.model_dump(mode="json")},
    )
    return stored


@app.post("/api/v1/enforcement-bindings", response_model=EnforcementBinding, status_code=201)
async def upsert_enforcement_binding(
    binding: EnforcementBinding,
    principal: CurrentPrincipal,
) -> EnforcementBinding:
    require_scope(
        principal,
        binding.tenant_id,
        binding.site_id,
        Permission.CONFIGURE,
    )
    stored = await run_in_threadpool(store.add_enforcement_binding, binding)
    await live_hub.publish(
        LiveMessageKind.ENFORCEMENT_UPDATED,
        binding.tenant_id,
        binding.site_id,
        {"enforcement_binding": stored.model_dump(mode="json")},
    )
    return stored


@app.post("/api/v1/responses/plan", response_model=ResponsePlan)
async def plan_response(
    request: ResponseRequest,
    principal: CurrentPrincipal,
) -> ResponsePlan:
    require_scope(
        principal,
        request.tenant_id,
        request.site_id,
        Permission.RESPOND,
    )
    operator_request = request.model_copy(
        update={
            "actor_type": ActorType.OPERATOR,
            "actor_id": principal.subject,
        }
    )
    try:
        plan = await run_in_threadpool(response_orchestrator.plan, operator_request)
    except ResponseStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    await live_hub.publish(
        LiveMessageKind.RESPONSE_PLANNED,
        request.tenant_id,
        request.site_id,
        {"response_plan": plan.model_dump(mode="json")},
    )
    return plan


async def _publish_response_execution(execution: ResponseExecution) -> None:
    audit_records = await run_in_threadpool(
        store.list_audit_records,
        execution.tenant_id,
        execution.site_id,
    )
    related_audit = [
        item
        for item in audit_records
        if item.object_type == "response_execution"
        and item.object_id == execution.execution_id
    ]
    await live_hub.publish(
        LiveMessageKind.RESPONSE_EXECUTION_UPDATED,
        execution.tenant_id,
        execution.site_id,
        {
            "execution": execution.model_dump(mode="json"),
            "audit_records": [
                item.model_dump(mode="json") for item in related_audit
            ],
        },
    )


@app.post("/api/v1/responses/execute", response_model=ResponseExecution)
async def execute_response(
    command: ResponseExecutionCommand,
    principal: CurrentPrincipal,
) -> ResponseExecution:
    request = command.request
    require_scope(
        principal,
        request.tenant_id,
        request.site_id,
        Permission.RESPOND,
    )
    approval = None
    if command.approve:
        require_scope(
            principal,
            request.tenant_id,
            request.site_id,
            Permission.APPROVE_RESPONSE,
        )
        approval = ResponseApproval(
            actor_id=principal.subject,
            reason=command.approval_reason or "approved",
        )

    operator_request = request.model_copy(
        update={
            "actor_type": ActorType.OPERATOR,
            "actor_id": principal.subject,
        }
    )
    try:
        execution = await response_dispatcher.dispatch(
            operator_request,
            approval=approval,
        )
    except ResponseStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    await _publish_response_execution(execution)
    return execution


@app.post(
    "/api/v1/responses/{execution_id}/rollback",
    response_model=ResponseExecution,
)
async def rollback_response(
    execution_id: str,
    command: ResponseRollbackCommand,
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> ResponseExecution:
    require_scope(principal, tenant_id, site_id, Permission.RESPOND)
    try:
        execution = await response_dispatcher.rollback(
            tenant_id,
            site_id,
            execution_id,
            actor_id=principal.subject,
            reason=command.reason,
        )
    except ResponseStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    await _publish_response_execution(execution)
    return execution


@app.get("/api/v1/responses", response_model=list[ResponseExecution])
def list_responses(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> list[ResponseExecution]:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    return store.list_response_executions(tenant_id, site_id)


@app.get("/api/v1/audit", response_model=list[AuditRecord])
def list_audit(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> list[AuditRecord]:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    return store.list_audit_records(tenant_id, site_id)


@app.get("/api/v1/site-commands", response_model=list[SiteCommandRecord])
def list_site_command_records(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> list[SiteCommandRecord]:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    return store.list_site_commands(tenant_id, site_id)


@app.get("/api/v1/site-commands/pending", response_model=list[SiteCommand])
def pull_site_commands(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[SiteCommand]:
    require_scope(principal, tenant_id, site_id, Permission.SITE_COMMAND)
    return site_command_queue.pending(
        tenant_id,
        site_id,
        limit=limit,
    )


@app.post("/api/v1/site-commands/results", response_model=SiteCommandRecord)
async def submit_site_command_result(
    result: SiteCommandResult,
    principal: CurrentPrincipal,
) -> SiteCommandRecord:
    require_scope(
        principal,
        result.tenant_id,
        result.site_id,
        Permission.SITE_COMMAND,
    )
    try:
        record = site_command_queue.complete(result)
    except SiteCommandError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    execution_id = (
        record.command.response_plan.request.request_id
        if record.command.kind is SiteCommandKind.APPLY_RESPONSE
        and record.command.response_plan is not None
        else record.command.rollback_execution_id
    )
    if execution_id is not None:
        execution = store.get_response_execution(
            result.tenant_id,
            result.site_id,
            execution_id,
        )
        if execution is not None:
            await _publish_response_execution(execution)
    return record


@app.post("/api/v1/site-response-updates", response_model=ResponseExecution)
async def submit_site_response_update(
    update: SiteResponseUpdate,
    principal: CurrentPrincipal,
) -> ResponseExecution:
    require_scope(
        principal,
        update.tenant_id,
        update.site_id,
        Permission.SITE_COMMAND,
    )
    try:
        execution = site_response_reconciler.reconcile(update)
    except SiteResponseUpdateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    await _publish_response_execution(execution)
    return execution


@app.post(
    "/api/v1/enrollment-tokens",
    response_model=EnrollmentTokenIssue,
    status_code=201,
)
def create_enrollment_token(
    request: EnrollmentTokenRequest,
    principal: CurrentPrincipal,
) -> EnrollmentTokenIssue:
    require_scope(
        principal,
        request.tenant_id,
        request.site_id,
        Permission.CONFIGURE,
    )
    return issue_enrollment_token(
        store,
        request.tenant_id,
        request.site_id,
        request.ttl_seconds,
        principal.subject,
    )


@app.post(
    "/api/v1/site-enrollment",
    response_model=SiteEnrollmentResult,
    status_code=201,
)
def complete_site_enrollment(
    request: SiteEnrollmentRequest,
) -> SiteEnrollmentResult:
    try:
        certificate_authority = get_certificate_authority()
    except IdentityConfigurationError as exc:
        raise HTTPException(
            status_code=503,
            detail="site certificate authority is unavailable",
        ) from exc

    try:
        return enroll_site(store, certificate_authority, request)
    except EnrollmentDenied as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.get(
    "/api/v1/site-identities",
    response_model=list[SiteIdentityRecord],
)
def list_site_identities(
    principal: CurrentPrincipal,
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> list[SiteIdentityRecord]:
    require_scope(principal, tenant_id, site_id, Permission.VIEW)
    return store.list_site_identities(tenant_id, site_id)
