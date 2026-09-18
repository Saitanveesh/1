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
    Asset,
    AttackGraphSnapshot,
    EnforcementBinding,
    EnforcementPoint,
    EventBatch,
    EventBatchResult,
    EventProcessingResult,
    Finding,
    Incident,
    ResponsePlan,
    ResponseRequest,
    SecurityEvent,
)
from mon.enforcement_graph import NoEnforcementPath, select_enforcement_point
from mon.live import LiveEventHub, LiveMessageKind
from mon.pipeline import SecurityPipeline
from mon.policy import evaluate_response
from mon.site_identity import (
    EnrollmentDenied,
    IdentityConfigurationError,
    enroll_site,
    get_certificate_authority,
    issue_enrollment_token,
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
    snapshot = await run_in_threadpool(graph.snapshot, tenant_id, site_id)
    sequence = await live_hub.current_sequence(tenant_id, site_id)

    return {
        "tenant_id": tenant_id,
        "site_id": site_id,
        "sequence": sequence,
        "findings": [item.model_dump(mode="json") for item in findings],
        "incidents": [item.model_dump(mode="json") for item in incidents],
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
    incident = await run_in_threadpool(
        store.get_incident,
        request.tenant_id,
        request.site_id,
        request.incident_id,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found in tenant/site scope")

    asset = None
    if request.target.asset_id:
        asset = await run_in_threadpool(
            store.get_asset,
            request.tenant_id,
            request.site_id,
            request.target.asset_id,
        )
        if asset is None:
            raise HTTPException(status_code=404, detail="asset not found in tenant/site scope")

    points = await run_in_threadpool(
        store.list_enforcement_points,
        request.tenant_id,
        request.site_id,
    )
    bindings = await run_in_threadpool(
        store.list_enforcement_bindings,
        request.tenant_id,
        request.site_id,
        asset.asset_id if asset else None,
    )
    try:
        selection = select_enforcement_point(request, points, bindings, asset)
    except NoEnforcementPath as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    decision = evaluate_response(request, incident, selection.point, asset)
    plan = ResponsePlan(
        request=request,
        decision=decision,
        enforcement_point=selection.point,
        selection_reasons=selection.reasons,
    )
    await live_hub.publish(
        LiveMessageKind.RESPONSE_PLANNED,
        request.tenant_id,
        request.site_id,
        {"response_plan": plan.model_dump(mode="json")},
    )
    return plan


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
