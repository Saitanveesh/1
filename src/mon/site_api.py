from __future__ import annotations

from fastapi import FastAPI, HTTPException

from mon.domain import EventProcessingResult, SecurityEvent
from mon.site_controller import SiteController, SiteScopeViolation


def create_site_app(controller: SiteController) -> FastAPI:
    app = FastAPI(
        title="MON Site Controller",
        description="Locally autonomous MON site ingestion and synchronization service.",
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

    @app.post("/api/v1/site/flush")
    async def flush() -> dict[str, object]:
        return await controller.flush()

    return app
