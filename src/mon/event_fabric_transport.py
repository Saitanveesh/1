from __future__ import annotations

import ssl

import httpx

from mon.event_fabric import FabricEnvelope


class HttpFabricPublisher:
    """Publish persisted fabric envelopes through the authenticated site ingress.

    The caller owns retry and ordering. This adapter sends the supplied envelope
    unchanged and never creates a replacement event identity or producer time.
    """

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str,
        ssl_context: ssl.SSLContext | None = None,
        timeout_seconds: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not base_url.lower().startswith("https://") and transport is None:
            raise ValueError("fabric publisher requires HTTPS")
        if not bearer_token:
            raise ValueError("fabric publisher bearer token is required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.ssl_context = ssl_context
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    async def publish(self, envelope: FabricEnvelope) -> None:
        body = envelope.canonical_json().encode("utf-8")
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            headers={"Authorization": f"Bearer {self.bearer_token}"},
            verify=self.ssl_context if self.ssl_context is not None else True,
            transport=self.transport,
            trust_env=False,
        ) as http:
            response = await http.post(
                "/api/v1/site/fabric/events",
                content=body,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
