from __future__ import annotations

import ssl

import httpx

from mon.event_fabric import (
    FabricEnvelope,
    FabricIngestResult,
)


class HttpFabricPublisher:
    """Authenticated HTTPS adapter for exact FabricEnvelope delivery."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str,
        ssl_context: ssl.SSLContext,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not base_url.lower().startswith("https://"):
            raise ValueError("fabric ingress URL must use https")
        if not bearer_token.strip():
            raise ValueError("fabric publisher bearer token is required")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError(
                "timeout_seconds must be greater than 0 and at most 60"
            )
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.ssl_context = ssl_context
        self.timeout_seconds = timeout_seconds

    async def publish(self, envelope: FabricEnvelope) -> None:
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            headers=headers,
            verify=self.ssl_context,
            trust_env=False,
        ) as client:
            response = await client.post(
                "/api/v1/fabric/events",
                content=envelope.canonical_json().encode("utf-8"),
            )
            response.raise_for_status()
            try:
                result = FabricIngestResult.model_validate(response.json())
            except ValueError as exc:
                raise RuntimeError(
                    "fabric ingress returned an invalid acknowledgement"
                ) from exc

        if not result.accepted:
            raise RuntimeError("fabric ingress did not accept the envelope")
        if result.event_id != envelope.event_id:
            raise RuntimeError(
                "fabric ingress acknowledged a different event_id"
            )
        if result.envelope_sha256 != envelope.canonical_sha256:
            raise RuntimeError(
                "fabric ingress acknowledgement digest does not match envelope"
            )
