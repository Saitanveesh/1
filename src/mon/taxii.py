from __future__ import annotations

import asyncio
import base64
import datetime as dt
import ipaddress
import json
import random
import socket
import urllib.parse
import uuid
from collections.abc import Callable, Iterable
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from mon.connector_secrets import ConnectorSecretVault
from mon.domain import AuditRecord
from mon.threat_intel import ThreatIntelImportResult, ingest_stix_bundle

TAXII_MEDIA_TYPE = "application/taxii+json"
TAXII_ACCEPT = "application/taxii+json;version=2.1"
STIX_BUNDLE_MEDIA_TYPE = "application/stix+json"


class TaxiiError(RuntimeError):
    pass


class TaxiiSecurityError(TaxiiError):
    pass


class TaxiiTransportError(TaxiiError):
    pass


class TaxiiAuthenticationError(TaxiiError):
    pass


class TaxiiProtocolError(TaxiiError):
    pass


class TaxiiIngestionError(TaxiiError):
    pass


class TaxiiAuthMode(StrEnum):
    NONE = "NONE"
    BEARER = "BEARER"
    BASIC = "BASIC"


class TaxiiFeedHealth(StrEnum):
    NEVER_SYNCED = "NEVER_SYNCED"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    DISABLED = "DISABLED"


class TaxiiFailureClass(StrEnum):
    NONE = "NONE"
    AUTHENTICATION = "AUTHENTICATION"
    TRANSPORT = "TRANSPORT"
    PROTOCOL = "PROTOCOL"
    PARSING = "PARSING"
    INGESTION = "INGESTION"
    SECURITY = "SECURITY"


class TaxiiFeedConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feed_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=256)
    source_name: str = Field(min_length=1, max_length=256)
    api_root_url: str = Field(min_length=1, max_length=2048)
    collection_id: str = Field(min_length=1, max_length=256)
    credential_ref: str | None = Field(default=None, min_length=1, max_length=256)
    auth_mode: TaxiiAuthMode = TaxiiAuthMode.NONE
    enabled: bool = True
    poll_interval_seconds: int = Field(default=900, ge=60, le=86400)
    discover: bool = False
    validate_collection: bool = True
    allow_http: bool = False
    reject_private_addresses: bool = True
    max_pages_per_sync: int = Field(default=20, ge=1, le=100)
    max_objects_per_sync: int = Field(default=1000, ge=1, le=10000)
    max_response_bytes: int = Field(default=2_000_000, ge=1024, le=10_000_000)
    request_timeout_seconds: float = Field(default=20.0, ge=1.0, le=120.0)
    connect_timeout_seconds: float = Field(default=5.0, ge=0.25, le=60.0)
    read_timeout_seconds: float = Field(default=15.0, ge=1.0, le=120.0)
    max_redirects: int = Field(default=2, ge=0, le=5)
    created_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.UTC))
    updated_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.UTC))

    @model_validator(mode="after")
    def validate_security_boundary(self) -> TaxiiFeedConfig:
        parsed = _parse_url(self.api_root_url, allow_http=self.allow_http)
        if parsed.username or parsed.password:
            raise ValueError("TAXII feed URLs must not contain embedded credentials")
        if self.auth_mode is TaxiiAuthMode.NONE and self.credential_ref is not None:
            raise ValueError("credential_ref requires an authenticated TAXII mode")
        if self.auth_mode is not TaxiiAuthMode.NONE and self.credential_ref is None:
            raise ValueError("authenticated TAXII feeds require credential_ref")
        return self


class TaxiiFeedState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feed_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    last_successful_sync: dt.datetime | None = None
    last_attempted_sync: dt.datetime | None = None
    next_attempt_after: dt.datetime | None = None
    health: TaxiiFeedHealth = TaxiiFeedHealth.NEVER_SYNCED
    failure_class: TaxiiFailureClass = TaxiiFailureClass.NONE
    failure_count: int = Field(default=0, ge=0)
    last_failure: str | None = Field(default=None, max_length=1000)
    last_page_count: int = Field(default=0, ge=0)
    last_object_count: int = Field(default=0, ge=0)
    last_imported: int = Field(default=0, ge=0)
    last_updated: int = Field(default=0, ge=0)
    last_unchanged: int = Field(default=0, ge=0)
    last_revoked: int = Field(default=0, ge=0)
    updated_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.UTC))


class TaxiiFeedRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    config: TaxiiFeedConfig
    state: TaxiiFeedState

    @model_validator(mode="after")
    def require_single_scope(self) -> TaxiiFeedRecord:
        if (
            self.config.feed_id != self.state.feed_id
            or self.config.tenant_id != self.state.tenant_id
            or self.config.site_id != self.state.site_id
        ):
            raise ValueError("TAXII feed config/state scope mismatch")
        return self


class TaxiiSyncResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feed_id: str
    tenant_id: str
    site_id: str
    collection_id: str
    started_at: dt.datetime
    completed_at: dt.datetime
    page_count: int = 0
    object_count: int = 0
    imported: int = 0
    updated: int = 0
    unchanged: int = 0
    revoked: int = 0
    cursor: dt.datetime | None = None
    health: TaxiiFeedHealth
    failure_class: TaxiiFailureClass = TaxiiFailureClass.NONE
    failure: str | None = None


@runtime_checkable
class TaxiiFeedRepository(Protocol):
    def add_taxii_feed(self, record: TaxiiFeedRecord) -> TaxiiFeedRecord: ...

    def get_taxii_feed(
        self,
        tenant_id: str,
        site_id: str,
        feed_id: str,
    ) -> TaxiiFeedRecord | None: ...

    def list_taxii_feeds(
        self,
        tenant_id: str | None = None,
        site_id: str | None = None,
    ) -> list[TaxiiFeedRecord]: ...

    def update_taxii_feed_state(self, state: TaxiiFeedState) -> TaxiiFeedState: ...

    def add_audit_record(self, record: AuditRecord) -> AuditRecord: ...


def _parse_url(raw: str, *, allow_http: bool = False) -> urllib.parse.ParseResult:
    try:
        parsed = urllib.parse.urlparse(raw)
    except ValueError as exc:
        raise TaxiiSecurityError("TAXII URL is malformed") from exc
    allowed = {"https"} | ({"http"} if allow_http else set())
    if parsed.scheme not in allowed:
        raise TaxiiSecurityError("TAXII feed URL must use HTTPS")
    if not parsed.hostname:
        raise TaxiiSecurityError("TAXII feed URL must include a host")
    if parsed.username or parsed.password:
        raise TaxiiSecurityError("TAXII feed URL must not contain credentials")
    return parsed


def _origin(parsed: urllib.parse.ParseResult) -> tuple[str, str, int | None]:
    return (parsed.scheme, parsed.hostname or "", parsed.port)


def _validate_no_private_destination(parsed: urllib.parse.ParseResult) -> None:
    host = parsed.hostname
    if host is None:
        raise TaxiiSecurityError("TAXII feed URL must include a host")
    addresses: list[str] = []
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise TaxiiSecurityError("TAXII feed host could not be resolved") from exc
        addresses = [item[4][0] for item in infos]
    for raw in addresses:
        ip = ipaddress.ip_address(raw)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise TaxiiSecurityError("TAXII feed host resolves to a restricted address")


def _join_url(base: str, *parts: str) -> str:
    normalized = base.rstrip("/") + "/"
    for part in parts:
        normalized = urllib.parse.urljoin(normalized, part.strip("/") + "/")
    return normalized


def _objects_url(api_root_url: str, collection_id: str) -> str:
    return _join_url(api_root_url, "collections", collection_id, "objects")


def _collection_url(api_root_url: str, collection_id: str) -> str:
    return _join_url(api_root_url, "collections", collection_id).rstrip("/")


def _discovery_url(api_root_url: str) -> str:
    parsed = urllib.parse.urlparse(api_root_url)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/taxii2/", "", "", ""))


def _utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise TaxiiProtocolError("TAXII timestamp must be timezone-aware")
    return value.astimezone(dt.UTC)


def _parse_taxii_timestamp(raw: object, *, field_name: str) -> dt.datetime:
    if not isinstance(raw, str):
        raise TaxiiProtocolError(f"{field_name} must be a timestamp string")
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TaxiiProtocolError(f"{field_name} is not a valid timestamp") from exc
    return _utc(parsed)


def _content_type_supported(raw: str | None) -> bool:
    if raw is None:
        return False
    media_type = raw.split(";", 1)[0].strip().casefold()
    return media_type in {TAXII_MEDIA_TYPE, STIX_BUNDLE_MEDIA_TYPE}


def _failure_class(exc: Exception) -> TaxiiFailureClass:
    if isinstance(exc, TaxiiAuthenticationError):
        return TaxiiFailureClass.AUTHENTICATION
    if isinstance(exc, TaxiiSecurityError):
        return TaxiiFailureClass.SECURITY
    if isinstance(exc, TaxiiTransportError):
        return TaxiiFailureClass.TRANSPORT
    if isinstance(exc, TaxiiIngestionError):
        return TaxiiFailureClass.INGESTION
    if isinstance(exc, (json.JSONDecodeError, ValueError)):
        return TaxiiFailureClass.PARSING
    return TaxiiFailureClass.PROTOCOL


def _bounded_failure(exc: Exception) -> str:
    text = str(exc).replace("\r", " ").replace("\n", " ")
    return text[:1000]


def _backoff(
    failure_count: int,
    *,
    base_seconds: int,
    max_seconds: int = 3600,
    jitter: Callable[[], float] | None = None,
) -> dt.timedelta:
    factor = min(2 ** max(failure_count - 1, 0), max_seconds / base_seconds)
    seconds = min(base_seconds * factor, max_seconds)
    jitter_value = (jitter or random.random)()
    return dt.timedelta(seconds=seconds * (1.0 + min(max(jitter_value, 0.0), 1.0) * 0.25))


class TaxiiClient:
    def __init__(
        self,
        *,
        http_client: httpx.Client | None = None,
        secret_vault: ConnectorSecretVault | None = None,
    ) -> None:
        self.http_client = http_client
        self.secret_vault = secret_vault

    def _auth_headers(self, feed: TaxiiFeedConfig) -> dict[str, str]:
        if feed.auth_mode is TaxiiAuthMode.NONE:
            return {}
        if self.secret_vault is None or feed.credential_ref is None:
            raise TaxiiAuthenticationError("TAXII credential vault is unavailable")
        raw = self.secret_vault.resolve(feed.tenant_id, feed.site_id, feed.credential_ref)
        if feed.auth_mode is TaxiiAuthMode.BEARER:
            token = raw.decode("utf-8").strip()
            if not token:
                raise TaxiiAuthenticationError("TAXII bearer credential is empty")
            return {"Authorization": f"Bearer {token}"}
        if feed.auth_mode is TaxiiAuthMode.BASIC:
            try:
                document = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TaxiiAuthenticationError("TAXII basic credential is invalid") from exc
            username = document.get("username")
            password = document.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                raise TaxiiAuthenticationError("TAXII basic credential is invalid")
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
            return {"Authorization": f"Basic {encoded}"}
        raise TaxiiAuthenticationError("unsupported TAXII authentication mode")

    def _request_json(
        self,
        feed: TaxiiFeedConfig,
        url: str,
        *,
        params: dict[str, str] | None = None,
        auth_headers: dict[str, str],
    ) -> dict[str, Any]:
        parsed = _parse_url(url, allow_http=feed.allow_http)
        if feed.reject_private_addresses:
            _validate_no_private_destination(parsed)
        headers = {
            "Accept": TAXII_ACCEPT,
            **auth_headers,
        }
        timeout = httpx.Timeout(
            feed.request_timeout_seconds,
            connect=feed.connect_timeout_seconds,
            read=feed.read_timeout_seconds,
        )
        client = self.http_client or httpx.Client(timeout=timeout, follow_redirects=False)
        close_client = self.http_client is None
        try:
            current_url = url
            for redirect_index in range(feed.max_redirects + 1):
                try:
                    response = client.get(
                        current_url,
                        params=params if redirect_index == 0 else None,
                        headers=headers,
                        timeout=timeout,
                    )
                except httpx.TimeoutException as exc:
                    raise TaxiiTransportError("TAXII request timed out") from exc
                except httpx.HTTPError as exc:
                    raise TaxiiTransportError("TAXII request failed") from exc
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("Location")
                    if not location:
                        raise TaxiiProtocolError("TAXII redirect lacks Location")
                    next_url = urllib.parse.urljoin(str(response.url), location)
                    next_parsed = _parse_url(next_url, allow_http=feed.allow_http)
                    if auth_headers and _origin(next_parsed) != _origin(parsed):
                        raise TaxiiSecurityError(
                            "refusing credential-bearing cross-origin TAXII redirect"
                        )
                    if feed.reject_private_addresses:
                        _validate_no_private_destination(next_parsed)
                    current_url = next_url
                    parsed = next_parsed
                    continue
                if response.status_code in {401, 403}:
                    raise TaxiiAuthenticationError("TAXII authentication failed")
                if response.status_code == 429 or 500 <= response.status_code <= 599:
                    raise TaxiiTransportError(f"TAXII server returned {response.status_code}")
                if response.status_code >= 400:
                    raise TaxiiProtocolError(f"TAXII server returned {response.status_code}")
                if len(response.content) > feed.max_response_bytes:
                    raise TaxiiProtocolError("TAXII response exceeds configured byte limit")
                if not _content_type_supported(response.headers.get("Content-Type")):
                    raise TaxiiProtocolError("unsupported TAXII content type")
                try:
                    document = response.json()
                except json.JSONDecodeError as exc:
                    raise TaxiiProtocolError("TAXII response is not valid JSON") from exc
                if not isinstance(document, dict):
                    raise TaxiiProtocolError("TAXII response must be a JSON object")
                return document
            raise TaxiiSecurityError("TAXII redirect limit exceeded")
        finally:
            if close_client:
                client.close()

    def validate_feed(self, feed: TaxiiFeedConfig) -> None:
        auth_headers = self._auth_headers(feed)
        if feed.discover:
            discovery = self._request_json(
                feed,
                _discovery_url(feed.api_root_url),
                auth_headers=auth_headers,
            )
            api_roots = discovery.get("api_roots")
            if not isinstance(api_roots, list) or feed.api_root_url.rstrip("/") not in {
                str(item).rstrip("/") for item in api_roots if isinstance(item, str)
            }:
                raise TaxiiProtocolError("TAXII discovery did not advertise API root")
        if feed.validate_collection:
            collection = self._request_json(
                feed,
                _collection_url(feed.api_root_url, feed.collection_id),
                auth_headers=auth_headers,
            )
            if collection.get("id") != feed.collection_id:
                raise TaxiiProtocolError("TAXII collection id mismatch")
            can_read = collection.get("can_read")
            if can_read is False:
                raise TaxiiProtocolError("TAXII collection is not readable")

    def iter_collection_pages(
        self,
        feed: TaxiiFeedConfig,
        *,
        added_after: dt.datetime | None,
    ) -> Iterable[dict[str, Any]]:
        auth_headers = self._auth_headers(feed)
        next_token: str | None = None
        for _page_index in range(feed.max_pages_per_sync):
            params: dict[str, str] = {}
            if added_after is not None:
                params["added_after"] = _utc(added_after).isoformat().replace("+00:00", "Z")
            if next_token is not None:
                params["next"] = next_token
            page = self._request_json(
                feed,
                _objects_url(feed.api_root_url, feed.collection_id),
                params=params,
                auth_headers=auth_headers,
            )
            yield page
            more = page.get("more", False)
            token = page.get("next")
            if not isinstance(more, bool):
                raise TaxiiProtocolError("TAXII more flag must be boolean")
            if not more:
                if token is not None:
                    raise TaxiiProtocolError("TAXII next token present when more is false")
                return
            if not isinstance(token, str) or not token:
                raise TaxiiProtocolError("TAXII next token is required when more is true")
            next_token = token
        raise TaxiiProtocolError("TAXII page count exceeded configured limit")


class TaxiiSynchronizer:
    def __init__(
        self,
        repository: TaxiiFeedRepository,
        *,
        client: TaxiiClient,
        jitter: Callable[[], float] | None = None,
    ) -> None:
        self.repository = repository
        self.client = client
        self.jitter = jitter
        self._running: set[tuple[str, str, str]] = set()
        self._lock = asyncio.Lock()

    async def sync_feed(self, feed_id: str, tenant_id: str, site_id: str) -> TaxiiSyncResult:
        key = (tenant_id, site_id, feed_id)
        async with self._lock:
            if key in self._running:
                raise TaxiiProtocolError("TAXII feed synchronization is already running")
            self._running.add(key)
        try:
            return await asyncio.to_thread(self._sync_feed_blocking, feed_id, tenant_id, site_id)
        finally:
            async with self._lock:
                self._running.discard(key)

    def _sync_feed_blocking(
        self,
        feed_id: str,
        tenant_id: str,
        site_id: str,
    ) -> TaxiiSyncResult:
        record = self.repository.get_taxii_feed(tenant_id, site_id, feed_id)
        if record is None:
            raise TaxiiProtocolError("TAXII feed was not found")
        feed = record.config
        state = record.state
        started_at = dt.datetime.now(dt.UTC)
        if not feed.enabled:
            disabled = state.model_copy(
                update={
                    "last_attempted_sync": started_at,
                    "health": TaxiiFeedHealth.DISABLED,
                    "updated_at": started_at,
                }
            )
            self.repository.update_taxii_feed_state(disabled)
            return TaxiiSyncResult(
                feed_id=feed.feed_id,
                tenant_id=feed.tenant_id,
                site_id=feed.site_id,
                collection_id=feed.collection_id,
                started_at=started_at,
                completed_at=started_at,
                health=TaxiiFeedHealth.DISABLED,
            )

        try:
            self.client.validate_feed(feed)
            page_count = 0
            object_count = 0
            imported = updated = unchanged = revoked = 0
            for page in self.client.iter_collection_pages(
                feed,
                added_after=state.last_successful_sync,
            ):
                page_count += 1
                objects = page.get("objects")
                if not isinstance(objects, list):
                    raise TaxiiProtocolError("TAXII objects field must be a list")
                object_count += len(objects)
                if object_count > feed.max_objects_per_sync:
                    raise TaxiiProtocolError("TAXII object count exceeded configured limit")
                bundle = {
                    "type": "bundle",
                    "id": f"bundle--{uuid.uuid4()}",
                    "objects": objects,
                }
                try:
                    result: ThreatIntelImportResult = ingest_stix_bundle(
                        self.repository,  # type: ignore[arg-type]
                        tenant_id=feed.tenant_id,
                        site_id=feed.site_id,
                        source_id=feed.source_id,
                        source_name=feed.source_name,
                        bundle=bundle,
                        imported_at=started_at,
                    )
                except Exception as exc:
                    raise TaxiiIngestionError(str(exc)) from exc
                imported += result.imported
                updated += result.updated
                unchanged += result.unchanged
                revoked += result.revoked

            completed_at = dt.datetime.now(dt.UTC)
            successful = state.model_copy(
                update={
                    "last_successful_sync": started_at,
                    "last_attempted_sync": started_at,
                    "next_attempt_after": completed_at
                    + dt.timedelta(seconds=feed.poll_interval_seconds),
                    "health": TaxiiFeedHealth.HEALTHY,
                    "failure_class": TaxiiFailureClass.NONE,
                    "failure_count": 0,
                    "last_failure": None,
                    "last_page_count": page_count,
                    "last_object_count": object_count,
                    "last_imported": imported,
                    "last_updated": updated,
                    "last_unchanged": unchanged,
                    "last_revoked": revoked,
                    "updated_at": completed_at,
                }
            )
            self.repository.update_taxii_feed_state(successful)
            self._audit(feed, "SYNC", "SUCCESS", successful, completed_at)
            return TaxiiSyncResult(
                feed_id=feed.feed_id,
                tenant_id=feed.tenant_id,
                site_id=feed.site_id,
                collection_id=feed.collection_id,
                started_at=started_at,
                completed_at=completed_at,
                page_count=page_count,
                object_count=object_count,
                imported=imported,
                updated=updated,
                unchanged=unchanged,
                revoked=revoked,
                cursor=started_at,
                health=TaxiiFeedHealth.HEALTHY,
            )
        except Exception as exc:
            completed_at = dt.datetime.now(dt.UTC)
            failure_class = _failure_class(exc)
            failure_count = state.failure_count + 1
            failed = state.model_copy(
                update={
                    "last_attempted_sync": started_at,
                    "next_attempt_after": completed_at
                    + _backoff(
                        failure_count,
                        base_seconds=feed.poll_interval_seconds,
                        jitter=self.jitter,
                    ),
                    "health": TaxiiFeedHealth.DEGRADED,
                    "failure_class": failure_class,
                    "failure_count": failure_count,
                    "last_failure": _bounded_failure(exc),
                    "updated_at": completed_at,
                }
            )
            self.repository.update_taxii_feed_state(failed)
            self._audit(feed, "SYNC", "FAILED", failed, completed_at)
            return TaxiiSyncResult(
                feed_id=feed.feed_id,
                tenant_id=feed.tenant_id,
                site_id=feed.site_id,
                collection_id=feed.collection_id,
                started_at=started_at,
                completed_at=completed_at,
                health=TaxiiFeedHealth.DEGRADED,
                failure_class=failure_class,
                failure=_bounded_failure(exc),
            )

    def _audit(
        self,
        feed: TaxiiFeedConfig,
        action: str,
        outcome: str,
        state: TaxiiFeedState,
        occurred_at: dt.datetime,
    ) -> None:
        self.repository.add_audit_record(
            AuditRecord(
                tenant_id=feed.tenant_id,
                site_id=feed.site_id,
                actor_id="mon-taxii-sync",
                category="THREAT_INTEL",
                object_type="taxii_feed",
                object_id=feed.feed_id,
                action=action,
                outcome=outcome,
                occurred_at=occurred_at,
                details={
                    "source_id": feed.source_id,
                    "collection_id": feed.collection_id,
                    "health": state.health.value,
                    "failure_class": state.failure_class.value,
                    "last_successful_sync": (
                        state.last_successful_sync.isoformat()
                        if state.last_successful_sync is not None
                        else None
                    ),
                    "last_page_count": state.last_page_count,
                    "last_object_count": state.last_object_count,
                    "last_imported": state.last_imported,
                    "last_updated": state.last_updated,
                    "last_unchanged": state.last_unchanged,
                    "last_revoked": state.last_revoked,
                },
            )
        )


class TaxiiFeedScheduler:
    def __init__(
        self,
        repository: TaxiiFeedRepository,
        synchronizer: TaxiiSynchronizer,
        *,
        tick_seconds: float = 5.0,
    ) -> None:
        if tick_seconds <= 0:
            raise ValueError("tick_seconds must be positive")
        self.repository = repository
        self.synchronizer = synchronizer
        self.tick_seconds = tick_seconds
        self._tasks: dict[tuple[str, str, str], asyncio.Task[TaxiiSyncResult]] = {}
        self._stop = asyncio.Event()

    async def run(self) -> None:
        while not self._stop.is_set():
            now = dt.datetime.now(dt.UTC)
            for record in self.repository.list_taxii_feeds():
                key = (
                    record.config.tenant_id,
                    record.config.site_id,
                    record.config.feed_id,
                )
                task = self._tasks.get(key)
                if task is not None and task.done():
                    self._tasks.pop(key, None)
                if not record.config.enabled:
                    continue
                next_attempt = record.state.next_attempt_after
                if next_attempt is not None and _utc(next_attempt) > now:
                    continue
                if key in self._tasks:
                    continue
                self._tasks[key] = asyncio.create_task(
                    self.synchronizer.sync_feed(
                        record.config.feed_id,
                        record.config.tenant_id,
                        record.config.site_id,
                    )
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.tick_seconds)
            except TimeoutError:
                continue

    def stop(self) -> None:
        self._stop.set()

    async def shutdown(self) -> None:
        self.stop()
        for task in self._tasks.values():
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
