from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException

from mon.domain import EventBatchResult, EventProcessingResult, SecurityEvent
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

    @app.post("/api/v1/site/flush")
    async def flush() -> dict[str, object]:
        return await controller.flush()

    return app
