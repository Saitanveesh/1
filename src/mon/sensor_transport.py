from __future__ import annotations

import datetime as dt
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

import httpx
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mon.mtls_ingress import create_mtls_server_ssl_context
from mon.sensor_fleet_models import (
    SensorAuthorizationResult,
    SensorFleetState,
)


class SensorCertificateError(ValueError):
    pass


class SensorCertificateScopeError(ValueError):
    pass


class SensorTransportConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedSensorIdentity:
    tenant_id: str
    site_id: str
    sensor_id: str
    spiffe_uri: str
    fingerprint_sha256: str
    serial_number: str


class ExternalZeekRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    log_type: str = Field(min_length=1, max_length=64)
    record: dict[str, object]


class ExternalSuricataRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record: dict[str, object]


class ExternalZeekBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[ExternalZeekRecord] = Field(min_length=1, max_length=1000)


class ExternalSuricataBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[ExternalSuricataRecord] = Field(min_length=1, max_length=1000)


class ExternalSensorHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observed_at: dt.datetime
    state: SensorFleetState
    collector_kind: str = Field(min_length=1, max_length=64)
    version: str | None = Field(default=None, max_length=64)
    last_error: str | None = Field(default=None, max_length=1000)


class ExternalSensorRenewalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    csr_pem: str = Field(min_length=64, max_length=32768)


def _parse_sensor_spiffe_uri(uri: str) -> tuple[str, str, str]:
    parsed = urlparse(uri)
    if parsed.scheme != "spiffe" or parsed.netloc != "mon.local":
        raise SensorCertificateError(
            "client certificate contains an unsupported SPIFFE URI"
        )

    segments = [segment for segment in parsed.path.split("/") if segment]
    if (
        len(segments) != 6
        or segments[0] != "tenant"
        or segments[2] != "site"
        or segments[4] != "sensor"
    ):
        raise SensorCertificateError(
            "client certificate SPIFFE URI has an invalid sensor path"
        )

    tenant_id = unquote(segments[1])
    site_id = unquote(segments[3])
    sensor_id = unquote(segments[5])
    for name, value in (
        ("tenant", tenant_id),
        ("site", site_id),
        ("sensor", sensor_id),
    ):
        if not value or len(value) > 128:
            raise SensorCertificateError(
                f"client certificate SPIFFE {name} must contain 1-128 characters"
            )
        if any(not character.isprintable() for character in value):
            raise SensorCertificateError(
                f"client certificate SPIFFE {name} contains non-printable characters"
            )
    return tenant_id, site_id, sensor_id


def extract_sensor_identity_from_verified_certificate(
    certificate_der: bytes,
) -> VerifiedSensorIdentity:
    """Extract sensor identity after TLS verifies the certificate chain."""

    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError as exc:
        raise SensorCertificateError("invalid client certificate") from exc

    now = dt.datetime.now(dt.UTC)
    if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc <= now:
        raise SensorCertificateError(
            "client certificate is outside its validity period"
        )

    try:
        eku = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound as exc:
        raise SensorCertificateError(
            "client certificate lacks extended key usage"
        ) from exc
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        raise SensorCertificateError(
            "client certificate is not valid for client authentication"
        )

    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound as exc:
        raise SensorCertificateError(
            "client certificate lacks subject alternative name"
        ) from exc

    sensor_uris = [
        uri
        for uri in san.get_values_for_type(x509.UniformResourceIdentifier)
        if uri.startswith("spiffe://mon.local/")
    ]
    if len(sensor_uris) != 1:
        raise SensorCertificateError(
            "client certificate must contain exactly one MON sensor SPIFFE identity"
        )

    tenant_id, site_id, sensor_id = _parse_sensor_spiffe_uri(sensor_uris[0])
    return VerifiedSensorIdentity(
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=sensor_id,
        spiffe_uri=sensor_uris[0],
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        serial_number=str(certificate.serial_number),
    )


def require_sensor_matches_site(
    identity: VerifiedSensorIdentity,
    *,
    tenant_id: str,
    site_id: str,
) -> None:
    if identity.tenant_id != tenant_id or identity.site_id != site_id:
        raise SensorCertificateScopeError(
            "sensor certificate tenant/site does not match this Site Controller"
        )


def require_loopback_site_controller_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise SensorTransportConfigurationError(
            "sensor ingress internal Site Controller URL must use loopback HTTP"
        )
    host = parsed.hostname
    if host is None:
        raise SensorTransportConfigurationError(
            "sensor ingress internal Site Controller URL requires a host"
        )
    if host == "localhost":
        return url.rstrip("/")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise SensorTransportConfigurationError(
            "sensor ingress internal Site Controller host must be loopback"
        ) from exc
    if not address.is_loopback:
        raise SensorTransportConfigurationError(
            "sensor ingress internal Site Controller host must be loopback"
        )
    return url.rstrip("/")


class MtlsSensorIngress:
    """mTLS boundary that derives sensor identity from the verified certificate."""

    def __init__(
        self,
        tenant_id: str,
        site_id: str,
        internal_site_controller_url: str,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not tenant_id or not site_id:
            raise SensorTransportConfigurationError(
                "sensor ingress tenant_id and site_id are required"
            )
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise SensorTransportConfigurationError(
                "sensor ingress timeout must be greater than 0 and at most 60 seconds"
            )
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.internal_site_controller_url = require_loopback_site_controller_url(
            internal_site_controller_url
        )
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _verified_identity(request: web.Request) -> VerifiedSensorIdentity:
        transport = request.transport
        if transport is None:
            raise SensorCertificateError("TLS transport is unavailable")
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            raise SensorCertificateError("mutual TLS is required")
        certificate_der = ssl_object.getpeercert(binary_form=True)
        if not certificate_der:
            raise SensorCertificateError(
                "verified sensor client certificate is required"
            )
        return extract_sensor_identity_from_verified_certificate(
            certificate_der
        )

    async def _authorize(
        self,
        request: web.Request,
    ) -> VerifiedSensorIdentity:
        identity = self._verified_identity(request)
        require_sensor_matches_site(
            identity,
            tenant_id=self.tenant_id,
            site_id=self.site_id,
        )
        async with httpx.AsyncClient(
            base_url=self.internal_site_controller_url,
            timeout=self.timeout_seconds,
            trust_env=False,
        ) as client:
            try:
                response = await client.post(
                    "/api/v1/site/sensors/authorize",
                    json={
                        "sensor_id": identity.sensor_id,
                        "fingerprint_sha256": identity.fingerprint_sha256,
                    },
                )
            except httpx.HTTPError as exc:
                raise web.HTTPServiceUnavailable(
                    text="local sensor trust service is unavailable"
                ) from exc
        if response.status_code != 200:
            raise web.HTTPServiceUnavailable(
                text="local sensor trust service rejected authorization request"
            )
        try:
            authorization = SensorAuthorizationResult.model_validate(
                response.json()
            )
        except (ValueError, ValidationError) as exc:
            raise web.HTTPServiceUnavailable(
                text="local sensor trust service returned an invalid response"
            ) from exc
        if not authorization.authorized:
            raise SensorCertificateScopeError(
                "sensor certificate is not accepted by the local trust snapshot"
            )
        return identity

    async def health(self, request: web.Request) -> web.Response:
        try:
            identity = await self._authorize(request)
        except SensorCertificateError as exc:
            raise web.HTTPUnauthorized(text=str(exc)) from exc
        except SensorCertificateScopeError as exc:
            raise web.HTTPForbidden(text=str(exc)) from exc
        return web.json_response(
            {
                "state": "READY",
                "service": "mon-mtls-sensor-ingress",
                "tenant_id": self.tenant_id,
                "site_id": self.site_id,
                "sensor_id": identity.sensor_id,
                "client_certificate": "REQUIRED",
            }
        )

    async def _forward(
        self,
        path: str,
        payload: dict[str, object],
    ) -> web.Response:
        async with httpx.AsyncClient(
            base_url=self.internal_site_controller_url,
            timeout=self.timeout_seconds,
            trust_env=False,
        ) as client:
            try:
                response = await client.post(path, json=payload)
            except httpx.HTTPError as exc:
                raise web.HTTPBadGateway(
                    text="local Site Controller is unavailable"
                ) from exc
        return web.Response(
            status=response.status_code,
            body=response.content,
            headers={
                "Content-Type": response.headers.get(
                    "content-type",
                    "application/json",
                )
            },
        )

    async def ingest_zeek(self, request: web.Request) -> web.Response:
        try:
            identity = await self._authorize(request)
        except SensorCertificateError as exc:
            raise web.HTTPUnauthorized(text=str(exc)) from exc
        except SensorCertificateScopeError as exc:
            raise web.HTTPForbidden(text=str(exc)) from exc

        try:
            body = ExternalZeekBatch.model_validate_json(await request.read())
        except ValidationError as exc:
            raise web.HTTPUnprocessableEntity(
                text="invalid Zeek sensor batch"
            ) from exc

        return await self._forward(
            "/api/v1/site/sensors/zeek/batch",
            {
                "records": [
                    {
                        "sensor_id": identity.sensor_id,
                        "log_type": item.log_type,
                        "record": item.record,
                    }
                    for item in body.records
                ]
            },
        )

    async def heartbeat(self, request: web.Request) -> web.Response:
        try:
            identity = await self._authorize(request)
        except SensorCertificateError as exc:
            raise web.HTTPUnauthorized(text=str(exc)) from exc
        except SensorCertificateScopeError as exc:
            raise web.HTTPForbidden(text=str(exc)) from exc

        try:
            body = ExternalSensorHeartbeat.model_validate_json(
                await request.read()
            )
        except ValidationError as exc:
            raise web.HTTPUnprocessableEntity(
                text="invalid sensor heartbeat"
            ) from exc
        if body.state not in {
            SensorFleetState.READY,
            SensorFleetState.DEGRADED,
        }:
            raise web.HTTPUnprocessableEntity(
                text="sensor heartbeat state must be READY or DEGRADED"
            )
        if body.state is SensorFleetState.DEGRADED and not body.last_error:
            raise web.HTTPUnprocessableEntity(
                text="degraded sensor heartbeat requires last_error"
            )

        return await self._forward(
            "/api/v1/site/sensors/heartbeat",
            {
                "tenant_id": identity.tenant_id,
                "site_id": identity.site_id,
                "sensor_id": identity.sensor_id,
                "fingerprint_sha256": identity.fingerprint_sha256,
                "observed_at": body.observed_at.isoformat(),
                "state": body.state.value,
                "collector_kind": body.collector_kind,
                "version": body.version,
                "last_error": body.last_error,
            },
        )

    async def renew(self, request: web.Request) -> web.Response:
        try:
            identity = await self._authorize(request)
        except SensorCertificateError as exc:
            raise web.HTTPUnauthorized(text=str(exc)) from exc
        except SensorCertificateScopeError as exc:
            raise web.HTTPForbidden(text=str(exc)) from exc

        try:
            body = ExternalSensorRenewalRequest.model_validate_json(
                await request.read()
            )
        except ValidationError as exc:
            raise web.HTTPUnprocessableEntity(
                text="invalid sensor renewal request"
            ) from exc

        return await self._forward(
            "/api/v1/site/sensors/renew",
            {
                "tenant_id": identity.tenant_id,
                "site_id": identity.site_id,
                "sensor_id": identity.sensor_id,
                "current_fingerprint_sha256": identity.fingerprint_sha256,
                "csr_pem": body.csr_pem,
            },
        )

    async def ingest_suricata(self, request: web.Request) -> web.Response:
        try:
            identity = await self._authorize(request)
        except SensorCertificateError as exc:
            raise web.HTTPUnauthorized(text=str(exc)) from exc
        except SensorCertificateScopeError as exc:
            raise web.HTTPForbidden(text=str(exc)) from exc

        try:
            body = ExternalSuricataBatch.model_validate_json(
                await request.read()
            )
        except ValidationError as exc:
            raise web.HTTPUnprocessableEntity(
                text="invalid Suricata sensor batch"
            ) from exc

        return await self._forward(
            "/api/v1/site/sensors/suricata/batch",
            {
                "records": [
                    {
                        "sensor_id": identity.sensor_id,
                        "record": item.record,
                    }
                    for item in body.records
                ]
            },
        )


def create_app(
    tenant_id: str,
    site_id: str,
    internal_site_controller_url: str,
    *,
    timeout_seconds: float = 10.0,
) -> web.Application:
    ingress = MtlsSensorIngress(
        tenant_id,
        site_id,
        internal_site_controller_url,
        timeout_seconds=timeout_seconds,
    )
    app = web.Application(client_max_size=8 * 1024 * 1024)
    app.router.add_get("/health", ingress.health)
    app.router.add_post(
        "/api/v1/sensors/zeek/batch",
        ingress.ingest_zeek,
    )
    app.router.add_post(
        "/api/v1/sensors/suricata/batch",
        ingress.ingest_suricata,
    )
    app.router.add_post(
        "/api/v1/sensors/heartbeat",
        ingress.heartbeat,
    )
    app.router.add_post(
        "/api/v1/sensors/renew",
        ingress.renew,
    )
    return app


def main() -> None:
    tenant_id = os.environ.get("MON_TENANT_ID", "").strip()
    site_id = os.environ.get("MON_SITE_ID", "").strip()
    if not tenant_id or not site_id:
        raise RuntimeError("MON_TENANT_ID and MON_SITE_ID must be configured")

    internal_url = os.environ.get(
        "MON_SENSOR_INTERNAL_SITE_URL",
        "http://127.0.0.1:8090",
    )
    certificate_file = os.environ.get(
        "MON_SENSOR_INGRESS_SERVER_CERT_FILE",
        "",
    ).strip()
    private_key_file = os.environ.get(
        "MON_SENSOR_INGRESS_SERVER_KEY_FILE",
        "",
    ).strip()
    sensor_ca_file = os.environ.get(
        "MON_SENSOR_CA_CERT_FILE",
        "",
    ).strip()
    if not certificate_file or not private_key_file or not sensor_ca_file:
        raise RuntimeError(
            "MON_SENSOR_INGRESS_SERVER_CERT_FILE, "
            "MON_SENSOR_INGRESS_SERVER_KEY_FILE and "
            "MON_SENSOR_CA_CERT_FILE must be configured"
        )

    for value in (certificate_file, private_key_file, sensor_ca_file):
        if not Path(value).is_file():
            raise RuntimeError(
                f"sensor ingress certificate file does not exist: {value}"
            )

    try:
        timeout_seconds = float(
            os.environ.get("MON_SENSOR_INGRESS_TIMEOUT_SECONDS", "10")
        )
        port = int(os.environ.get("MON_SENSOR_INGRESS_PORT", "9443"))
    except ValueError as exc:
        raise RuntimeError(
            "sensor ingress timeout/port configuration is invalid"
        ) from exc
    if port < 1 or port > 65535:
        raise RuntimeError(
            "MON_SENSOR_INGRESS_PORT must be between 1 and 65535"
        )

    # Validate loopback forwarding before opening the network listener.
    require_loopback_site_controller_url(internal_url)
    context = create_mtls_server_ssl_context(
        certificate_file,
        private_key_file,
        sensor_ca_file,
        private_key_password=os.environ.get(
            "MON_SENSOR_INGRESS_SERVER_KEY_PASSWORD"
        ),
    )
    web.run_app(
        create_app(
            tenant_id,
            site_id,
            internal_url,
            timeout_seconds=timeout_seconds,
        ),
        host=os.environ.get("MON_SENSOR_INGRESS_HOST", "0.0.0.0"),
        port=port,
        ssl_context=context,
    )


if __name__ == "__main__":
    main()
