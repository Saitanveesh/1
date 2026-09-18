from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query

from mon import __version__
from mon.domain import (
    Asset,
    EnforcementPoint,
    Incident,
    ResponsePlan,
    ResponseRequest,
    SecurityEvent,
)
from mon.policy import evaluate_response
from mon.store import InMemoryStore

app = FastAPI(
    title="MON Security Fabric Control Plane",
    version=__version__,
    description="Control-plane foundation for evidence-backed detection and safe response.",
)
store = InMemoryStore()


@app.get("/health")
def health() -> dict[str, str]:
    return {"state": "READY", "service": "mon-control-plane", "version": __version__}


@app.post("/api/v1/events", response_model=SecurityEvent, status_code=201)
def ingest_event(event: SecurityEvent) -> SecurityEvent:
    return store.add_event(event)


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


@app.post("/api/v1/responses/plan", response_model=ResponsePlan)
def plan_response(request: ResponseRequest) -> ResponsePlan:
    incident = store.get_incident(request.tenant_id, request.site_id, request.incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found in tenant/site scope")

    point = store.get_enforcement_point(
        request.tenant_id,
        request.site_id,
        request.enforcement_point_id,
    )
    if point is None:
        raise HTTPException(
            status_code=404,
            detail="enforcement point not found in tenant/site scope",
        )

    asset = None
    if request.target.asset_id:
        asset = store.get_asset(
            request.tenant_id,
            request.site_id,
            request.target.asset_id,
        )
        if asset is None:
            raise HTTPException(status_code=404, detail="asset not found in tenant/site scope")

    decision = evaluate_response(request, incident, point, asset)
    return ResponsePlan(
        request=request,
        decision=decision,
        enforcement_point=point,
    )
