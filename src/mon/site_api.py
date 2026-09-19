from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException

from mon.domain import EventBatchResult, EventProcessingResult, SecurityEvent
from mon.sensor_fleet_models import (
    SensorAuthorizationRequest,
    SensorAuthorizationResult,
    SensorHeartbeat,
    SensorRenewalRequest,
    SensorRenewalResult,
)
from mon.sensors.common import SensorNormalizationError
from mon.sensors.ingest import (
    SiteSensorIngress,
    SuricataSensorBatch,
    ZeekSensorBatch,
)
from mon.site_controller import SiteController, SiteScopeViolation


def create_site_app(
    controller: SiteController,
    *,
    lifespan: Any | None = None,
) -> FastAPI:
    app = FastAPI(
        title="MON Site Controller",
        description="Locally autonomous MON site ingestion and synchronization service.",
        lifespan=lifespan,
    )

    @app.get("/health")
    def health() -> dict[str, object]:
        return controller.status()

    @app.post(
        "/api/v1/site/events",
        response_model=EventProcessingResult,
        status_code=201,
    )
    def ingest(event: SecurityEvent) -> EventProcessingResult:
        try:
            return controller.ingest(event)
        except SiteScopeViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    sensor_ingress = SiteSensorIngress(controller)

    @app.post(
        "/api/v1/site/sensors/zeek/batch",
        response_model=EventBatchResult,
        status_code=201,
    )
    def ingest_zeek(batch: ZeekSensorBatch) -> EventBatchResult:
        try:
            return sensor_ingress.ingest_zeek(batch)
        except SensorNormalizationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except SiteScopeViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post(
        "/api/v1/site/sensors/suricata/batch",
        response_model=EventBatchResult,
        status_code=201,
    )
    def ingest_suricata(batch: SuricataSensorBatch) -> EventBatchResult:
        try:
            return sensor_ingress.ingest_suricata(batch)
        except SensorNormalizationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except SiteScopeViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post(
        "/api/v1/site/sensors/authorize",
        response_model=SensorAuthorizationResult,
    )
    def authorize_sensor(
        request: SensorAuthorizationRequest,
    ) -> SensorAuthorizationResult:
        identity = controller.authorize_sensor_identity(
            request.sensor_id,
            request.fingerprint_sha256,
        )
        if identity is None:
            return SensorAuthorizationResult(authorized=False)
        return SensorAuthorizationResult(
            authorized=True,
            identity_id=identity.identity_id,
            status=identity.status,
            expires_at=identity.expires_at,
            accept_until=identity.accept_until,
        )

    @app.post("/api/v1/site/sensors/heartbeat")
    async def relay_sensor_heartbeat(
        heartbeat: SensorHeartbeat,
    ) -> dict[str, str]:
        try:
            await controller.relay_sensor_heartbeat(heartbeat)
        except SiteScopeViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {"state": "REPORTED"}

    @app.post(
        "/api/v1/site/sensors/renew",
        response_model=SensorRenewalResult,
    )
    async def relay_sensor_renewal(
        request: SensorRenewalRequest,
    ) -> SensorRenewalResult:
        try:
            return await controller.relay_sensor_renewal(request)
        except SiteScopeViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/api/v1/site/sensors/trust/sync")
    async def sync_sensor_trust() -> dict[str, object]:
        return await controller.sync_sensor_trust()

    @app.post("/api/v1/site/flush")
    async def flush() -> dict[str, object]:
        return await controller.flush()

    return app
