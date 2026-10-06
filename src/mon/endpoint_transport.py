from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import httpx

from mon.domain import SecurityEvent
from mon.site_identity import create_mtls_client_ssl_context


class EndpointTransportConfigurationError(ValueError):
    pass


class MtlsSensorEventSender:
    """Send endpoint SecurityEvent objects through the authenticated sensor ingress.

    The client certificate is the sensor identity. The receiver independently
    verifies the certificate scope and rejects any payload whose tenant/site/sensor
    fields do not match that identity.
    """

    def __init__(
        self,
        ingress_url: str,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        ca_certificate_file: str | Path,
        client_certificate_file: str | Path,
        client_private_key_file: str | Path,
        client_private_key_password: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        parsed = urlparse(ingress_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise EndpointTransportConfigurationError(
                "remote endpoint sensor ingress URL must use https"
            )
        if parsed.username is not None or parsed.password is not None:
            raise EndpointTransportConfigurationError(
                "credentials must not be embedded in the sensor ingress URL"
            )
        if not tenant_id or not site_id or not sensor_id:
            raise EndpointTransportConfigurationError(
                "tenant_id, site_id and sensor_id are required"
            )
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise EndpointTransportConfigurationError(
                "endpoint transport timeout must be greater than 0 and at most 60 seconds"
            )

        paths = {
            "server CA certificate": Path(ca_certificate_file),
            "client certificate": Path(client_certificate_file),
            "client private key": Path(client_private_key_file),
        }
        for label, path in paths.items():
            if not path.is_file():
                raise EndpointTransportConfigurationError(
                    f"{label} file does not exist: {path}"
                )

        self.ingress_url = ingress_url.rstrip("/")
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.sensor_id = sensor_id
        self.timeout_seconds = timeout_seconds
        self._ssl_context = create_mtls_client_ssl_context(
            str(paths["server CA certificate"]),
            str(paths["client certificate"]),
            str(paths["client private key"]),
            private_key_password=client_private_key_password,
        )

    async def send(self, event: SecurityEvent) -> None:
        if (
            event.tenant_id != self.tenant_id
            or event.site_id != self.site_id
            or event.sensor_id != self.sensor_id
        ):
            raise ValueError(
                "endpoint event scope does not match configured sensor identity"
            )

        async with httpx.AsyncClient(
            base_url=self.ingress_url,
            verify=self._ssl_context,
            timeout=self.timeout_seconds,
            trust_env=False,
        ) as client:
            response = await client.post(
                "/api/v1/sensors/events",
                content=event.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
