from __future__ import annotations

import datetime as dt
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

import httpx
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID
from pydantic import ValidationError

from mon.domain import EventBatch
from mon.site_command_models import SiteCommandResult


class SiteCertificateError(ValueError):
    pass


class SiteCertificateScopeError(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedSiteIdentity:
    tenant_id: str
    site_id: str
    spiffe_uri: str
    fingerprint_sha256: str
    serial_number: str


def _parse_site_spiffe_uri(uri: str) -> tuple[str, str]:
    parsed = urlparse(uri)
    if parsed.scheme != "spiffe" or parsed.netloc != "mon.local":
        raise SiteCertificateError("client certificate contains an unsupported SPIFFE URI")

    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) != 4 or segments[0] != "tenant" or segments[2] != "site":
        raise SiteCertificateError("client certificate SPIFFE URI has an invalid site path")

    tenant_id = unquote(segments[1])
    site_id = unquote(segments[3])
    if not tenant_id or not site_id:
        raise SiteCertificateError("client certificate SPIFFE tenant/site cannot be empty")
    return tenant_id, site_id


def extract_site_identity_from_verified_certificate(
    certificate_der: bytes,
) -> VerifiedSiteIdentity:
    """Extract site identity after the TLS layer has verified the certificate chain."""

    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError as exc:
        raise SiteCertificateError("invalid client certificate") from exc

    now = dt.datetime.now(dt.UTC)
    if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc <= now:
        raise SiteCertificateError("client certificate is outside its validity period")

    try:
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise SiteCertificateError("client certificate lacks extended key usage") from exc
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        raise SiteCertificateError("client certificate is not valid for client authentication")

    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound as exc:
        raise SiteCertificateError("client certificate lacks subject alternative name") from exc

    site_uris = [
        uri
        for uri in san.get_values_for_type(x509.UniformResourceIdentifier)
        if uri.startswith("spiffe://mon.local/")
    ]
    if len(site_uris) != 1:
        raise SiteCertificateError(
            "client certificate must contain exactly one MON site SPIFFE identity"
        )

    tenant_id, site_id = _parse_site_spiffe_uri(site_uris[0])
    return VerifiedSiteIdentity(
        tenant_id=tenant_id,
        site_id=site_id,
        spiffe_uri=site_uris[0],
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        serial_number=str(certificate.serial_number),
    )


def require_batch_matches_site_identity(
    batch: EventBatch,
    identity: VerifiedSiteIdentity,
) -> None:
    for event in batch.events:
        if event.tenant_id != identity.tenant_id or event.site_id != identity.site_id:
            raise SiteCertificateScopeError(
                "event tenant/site does not match the verified client certificate"
            )


def require_command_result_matches_site_identity(
    result: SiteCommandResult,
    identity: VerifiedSiteIdentity,
) -> None:
    if result.tenant_id != identity.tenant_id or result.site_id != identity.site_id:
        raise SiteCertificateScopeError(
            "site command result tenant/site does not match verified client certificate"
        )


def create_mtls_server_ssl_context(
    server_certificate_file: str,
    server_private_key_file: str,
    client_ca_certificate_file: str,
    *,
    private_key_password: str | None = None,
) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=client_ca_certificate_file)
    context.load_cert_chain(
        certfile=server_certificate_file,
        keyfile=server_private_key_file,
        password=private_key_password,
    )
    return context


class MtlsSiteIngress:
    def __init__(
        self,
        internal_control_plane_url: str,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.internal_control_plane_url = internal_control_plane_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _verified_identity(request: web.Request) -> VerifiedSiteIdentity:
        transport = request.transport
        if transport is None:
            raise SiteCertificateError("TLS transport is unavailable")
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            raise SiteCertificateError("mutual TLS is required")
        certificate_der = ssl_object.getpeercert(binary_form=True)
        if not certificate_der:
            raise SiteCertificateError("verified client certificate is required")
        return extract_site_identity_from_verified_certificate(certificate_der)

    async def health(self, request: web.Request) -> web.Response:
        return web.json_response(
            {
                "state": "READY",
                "service": "mon-mtls-site-ingress",
                "client_certificate": "REQUIRED",
            }
        )

    async def ingest_batch(self, request: web.Request) -> web.Response:
        try:
            identity = self._verified_identity(request)
        except SiteCertificateError as exc:
            raise web.HTTPUnauthorized(text=str(exc)) from exc

        try:
            raw_body = await request.read()
            batch = EventBatch.model_validate_json(raw_body)
        except ValidationError as exc:
            raise web.HTTPUnprocessableEntity(text="invalid event batch") from exc

        try:
            require_batch_matches_site_identity(batch, identity)
        except SiteCertificateScopeError as exc:
            raise web.HTTPForbidden(text=str(exc)) from exc

        authorization = request.headers.get("Authorization")
        if not authorization:
            raise web.HTTPUnauthorized(
                text="site service authorization token is required"
            )

        headers = {
            "Authorization": authorization,
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(
            base_url=self.internal_control_plane_url,
            timeout=self.timeout_seconds,
        ) as client:
            try:
                response = await client.post(
                    "/api/v1/events/batch",
                    content=raw_body,
                    headers=headers,
                )
            except httpx.HTTPError as exc:
                raise web.HTTPBadGateway(text="control plane is unavailable") from exc

        response_headers = {}
        content_type = response.headers.get("content-type")
        if content_type:
            response_headers["Content-Type"] = content_type
        return web.Response(
            status=response.status_code,
            body=response.content,
            headers=response_headers,
        )


    @staticmethod
    def _authorization(request: web.Request) -> str:
        authorization = request.headers.get("Authorization")
        if not authorization:
            raise web.HTTPUnauthorized(
                text="site service authorization token is required"
            )
        return authorization

    async def pull_commands(self, request: web.Request) -> web.Response:
        try:
            identity = self._verified_identity(request)
        except SiteCertificateError as exc:
            raise web.HTTPUnauthorized(text=str(exc)) from exc

        authorization = self._authorization(request)
        raw_limit = request.query.get("limit", "20")
        try:
            limit = int(raw_limit)
        except ValueError as exc:
            raise web.HTTPBadRequest(text="limit must be an integer") from exc
        if limit < 1 or limit > 100:
            raise web.HTTPBadRequest(text="limit must be between 1 and 100")

        async with httpx.AsyncClient(
            base_url=self.internal_control_plane_url,
            timeout=self.timeout_seconds,
        ) as client:
            try:
                response = await client.get(
                    "/api/v1/site-commands/pending",
                    params={
                        "tenant_id": identity.tenant_id,
                        "site_id": identity.site_id,
                        "limit": limit,
                    },
                    headers={"Authorization": authorization},
                )
            except httpx.HTTPError as exc:
                raise web.HTTPBadGateway(text="control plane is unavailable") from exc

        return web.Response(
            status=response.status_code,
            body=response.content,
            headers={"Content-Type": response.headers.get(
                "content-type",
                "application/json",
            )},
        )

    async def submit_command_result(self, request: web.Request) -> web.Response:
        try:
            identity = self._verified_identity(request)
        except SiteCertificateError as exc:
            raise web.HTTPUnauthorized(text=str(exc)) from exc

        try:
            raw_body = await request.read()
            result = SiteCommandResult.model_validate_json(raw_body)
        except ValidationError as exc:
            raise web.HTTPUnprocessableEntity(text="invalid site command result") from exc

        try:
            require_command_result_matches_site_identity(result, identity)
        except SiteCertificateScopeError as exc:
            raise web.HTTPForbidden(text=str(exc)) from exc

        authorization = self._authorization(request)
        async with httpx.AsyncClient(
            base_url=self.internal_control_plane_url,
            timeout=self.timeout_seconds,
        ) as client:
            try:
                response = await client.post(
                    "/api/v1/site-commands/results",
                    content=raw_body,
                    headers={
                        "Authorization": authorization,
                        "Content-Type": "application/json",
                    },
                )
            except httpx.HTTPError as exc:
                raise web.HTTPBadGateway(text="control plane is unavailable") from exc

        return web.Response(
            status=response.status_code,
            body=response.content,
            headers={"Content-Type": response.headers.get(
                "content-type",
                "application/json",
            )},
        )

def create_app(
    internal_control_plane_url: str,
    *,
    timeout_seconds: float = 10.0,
) -> web.Application:
    ingress = MtlsSiteIngress(
        internal_control_plane_url,
        timeout_seconds=timeout_seconds,
    )
    app = web.Application(client_max_size=8 * 1024 * 1024)
    app.router.add_get("/health", ingress.health)
    app.router.add_post("/api/v1/events/batch", ingress.ingest_batch)
    app.router.add_get("/api/v1/site/commands", ingress.pull_commands)
    app.router.add_post(
        "/api/v1/site/commands/results",
        ingress.submit_command_result,
    )
    return app


def main() -> None:
    internal_url = os.environ.get(
        "MON_INTERNAL_CONTROL_PLANE_URL",
        "http://control-plane:8080",
    )
    certificate_file = os.environ.get("MON_MTLS_SERVER_CERT_FILE", "").strip()
    private_key_file = os.environ.get("MON_MTLS_SERVER_KEY_FILE", "").strip()
    site_ca_file = os.environ.get("MON_SITE_CA_CERT_FILE", "").strip()
    if not certificate_file or not private_key_file or not site_ca_file:
        raise RuntimeError(
            "MON_MTLS_SERVER_CERT_FILE, MON_MTLS_SERVER_KEY_FILE and "
            "MON_SITE_CA_CERT_FILE must be configured"
        )

    for value in (certificate_file, private_key_file, site_ca_file):
        if not Path(value).is_file():
            raise RuntimeError(f"mTLS ingress certificate file does not exist: {value}")

    context = create_mtls_server_ssl_context(
        certificate_file,
        private_key_file,
        site_ca_file,
        private_key_password=os.environ.get("MON_MTLS_SERVER_KEY_PASSWORD"),
    )
    web.run_app(
        create_app(internal_url),
        host=os.environ.get("MON_MTLS_HOST", "0.0.0.0"),
        port=int(os.environ.get("MON_MTLS_PORT", "8443")),
        ssl_context=context,
    )


if __name__ == "__main__":
    main()
