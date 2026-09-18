from __future__ import annotations

import ssl
from typing import Protocol

import httpx

from mon.site_command_models import SiteCommand, SiteCommandResult


class SiteCommandClient(Protocol):
    async def pull_commands(self, limit: int = 20) -> list[SiteCommand]: ...

    async def submit_result(self, result: SiteCommandResult) -> None: ...


class HttpSiteCommandClient:
    """mTLS-capable site command client using the site ingress endpoint."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str,
        ssl_context: ssl.SSLContext | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.ssl_context = ssl_context
        self.timeout_seconds = timeout_seconds

    async def pull_commands(self, limit: int = 20) -> list[SiteCommand]:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            headers={"Authorization": f"Bearer {self.bearer_token}"},
            verify=self.ssl_context if self.ssl_context is not None else True,
        ) as http:
            response = await http.get(
                "/api/v1/site/commands",
                params={"limit": limit},
            )
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, list):
            raise RuntimeError("site command endpoint returned invalid payload")
        return [SiteCommand.model_validate(item) for item in payload]

    async def submit_result(self, result: SiteCommandResult) -> None:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            headers={"Authorization": f"Bearer {self.bearer_token}"},
            verify=self.ssl_context if self.ssl_context is not None else True,
        ) as http:
            response = await http.post(
                "/api/v1/site/commands/results",
                json=result.model_dump(mode="json"),
            )
            response.raise_for_status()
