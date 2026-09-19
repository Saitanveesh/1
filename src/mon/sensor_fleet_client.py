from __future__ import annotations

import ssl
from typing import Protocol

import httpx

from mon.sensor_fleet_models import (
    SensorHeartbeat,
    SensorRenewalRequest,
    SensorRenewalResult,
    SensorTrustSnapshot,
)


class SensorFleetClient(Protocol):
    async def renew_sensor(
        self,
        request: SensorRenewalRequest,
    ) -> SensorRenewalResult: ...

    async def submit_heartbeat(
        self,
        heartbeat: SensorHeartbeat,
    ) -> None: ...

    async def fetch_trust_snapshot(
        self,
        tenant_id: str,
        site_id: str,
    ) -> SensorTrustSnapshot: ...


class HttpSensorFleetClient:
    """Site-scoped cloud client carried over the authenticated site ingress."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str,
        ssl_context: ssl.SSLContext,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not base_url.lower().startswith("https://"):
            raise ValueError("sensor fleet cloud URL must use https")
        if not bearer_token:
            raise ValueError("sensor fleet cloud bearer token is required")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError(
                "sensor fleet timeout must be greater than 0 and at most 60 seconds"
            )
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.ssl_context = ssl_context
        self.timeout_seconds = timeout_seconds

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.bearer_token}"}

    async def renew_sensor(
        self,
        request: SensorRenewalRequest,
    ) -> SensorRenewalResult:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._headers(),
            verify=self.ssl_context,
            timeout=self.timeout_seconds,
            trust_env=False,
        ) as client:
            response = await client.post(
                "/api/v1/site/sensors/renew",
                json=request.model_dump(mode="json"),
            )
            response.raise_for_status()
            return SensorRenewalResult.model_validate(response.json())

    async def submit_heartbeat(
        self,
        heartbeat: SensorHeartbeat,
    ) -> None:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._headers(),
            verify=self.ssl_context,
            timeout=self.timeout_seconds,
            trust_env=False,
        ) as client:
            response = await client.post(
                "/api/v1/site/sensors/heartbeat",
                json=heartbeat.model_dump(mode="json"),
            )
            response.raise_for_status()

    async def fetch_trust_snapshot(
        self,
        tenant_id: str,
        site_id: str,
    ) -> SensorTrustSnapshot:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._headers(),
            verify=self.ssl_context,
            timeout=self.timeout_seconds,
            trust_env=False,
        ) as client:
            response = await client.get(
                "/api/v1/site/sensors/trust",
                params={"tenant_id": tenant_id, "site_id": site_id},
            )
            response.raise_for_status()
            return SensorTrustSnapshot.model_validate(response.json())
