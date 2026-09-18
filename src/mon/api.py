from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query

from mon import __version__
from mon.domain import (
    Asset,
    EnforcementBinding,
    EnforcementPoint,
    Finding,
    Incident,
    ResponsePlan,
    ResponseRequest,
    SecurityEvent,
)
from mon.detection import DetectionEngine
from mon.enforcement_graph import NoEnforcementPath, select_enforcement_point
from mon.policy import evaluate_response
from mon.store import InMemoryStore

app = FastAPI(
    title="MON Security Fabric Control Plane",
    version=__version__,
    description="Control-plane foundation for evidence-backed detection and safe response.",
)
store = InMemoryStore()
detector = DetectionEngine()


@app.get("/health")
def health() -> dict[str, str]:
    return {"state": "READY", "service": "mon-control-plane", "version": __version__}


@app.post("/api/v1/events", status_code=201)
def ingest_event(event: SecurityEvent) -> dict[str, object]:
    stored = store.add_event(event)
    findings = detector.process(event)
    for finding in findings:
        store.add_finding(finding)
    return {"event": stored, "findings": findings}


@app.get("/api/v1/findings", response_model=list[Finding])
def list_findings(
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> list[Finding]:
    return store.list_findings(tenant_id, site_id)


@app.post("/api/v1/assets", response_model=Asset, status_code=201)
def upsert_asset(asset: Asset) -> Asset:
    return store.add_asset(asset)


@app.post("/api/v1/incidents", response_model=Incident, status_code=201)
def create_incident(incident: Incident) -> Incident:
    return store.add_incident(incident)


@app.get("/api/v1/incidents", response_model=list[Incident])
def list_incidents(
    tenant_id: str = Query(min_length=1),
    site_id: str = Query(min_length=1),
) -> list[Incident]:
    return store.list_incidents(tenant_id, site_id)


@app.post("/api/v1/enforcement-points", response_model=EnforcementPoint, status_code=201)
def upsert_enforcement_point(point: EnforcementPoint) -> EnforcementPoint:
    return store.add_enforcement_point(point)


@app.post("/api/v1/enforcement-bindings", response_model=EnforcementBinding, status_code=201)
def upsert_enforcement_binding(binding: EnforcementBinding) -> EnforcementBinding:
    return store.add_enforcement_binding(binding)


@app.post("/api/v1/responses/plan", response_model=ResponsePlan)
def plan_response(request: ResponseRequest) -> ResponsePlan:
    incident = store.get_incident(request.tenant_id, request.site_id, request.incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found in tenant/site scope")

    asset = None
    if request.target.asset_id:
        asset = store.get_asset(
            request.tenant_id,
            request.site_id,
            request.target.asset_id,
        )
        if asset is None:
            raise HTTPException(status_code=404, detail="asset not found in tenant/site scope")

    points = store.list_enforcement_points(request.tenant_id, request.site_id)
    bindings = store.list_enforcement_bindings(
        request.tenant_id,
        request.site_id,
        asset.asset_id if asset else None,
    )
    try:
        selection = select_enforcement_point(request, points, bindings, asset)
    except NoEnforcementPath as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    decision = evaluate_response(request, incident, selection.point, asset)
    return ResponsePlan(
        request=request,
        decision=decision,
        enforcement_point=selection.point,
        selection_reasons=selection.reasons,
    )
