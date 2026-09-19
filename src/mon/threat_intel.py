from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import re
from contextlib import suppress
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mon.domain import EvidenceClass, EvidenceRef, Finding, SecurityEvent, Severity

MAX_STIX_BUNDLE_BYTES = 2_000_000
MAX_STIX_OBJECTS = 1000


class ThreatIntelError(ValueError):
    pass


class IndicatorType(StrEnum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    FILE_HASH = "FILE_HASH"


class ThreatIntelSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=1000)
    created_at: dt.datetime
    updated_at: dt.datetime


class ThreatIndicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=256)
    source_name: str = Field(min_length=1, max_length=256)
    stix_id: str = Field(min_length=1, max_length=512)
    stix_created: dt.datetime | None = None
    stix_modified: dt.datetime | None = None
    valid_from: dt.datetime | None = None
    valid_until: dt.datetime | None = None
    revoked: bool = False
    labels: set[str] = Field(default_factory=set)
    stix_confidence: int | None = Field(default=None, ge=0, le=100)
    indicator_type: IndicatorType
    normalized_value: str = Field(min_length=1, max_length=2048)
    pattern: str = Field(min_length=1, max_length=4096)
    name: str | None = Field(default=None, max_length=512)
    description: str | None = Field(default=None, max_length=2000)
    imported_at: dt.datetime

    @model_validator(mode="after")
    def validate_validity_window(self) -> ThreatIndicator:
        if (
            self.valid_from is not None
            and self.valid_until is not None
            and self.valid_until <= self.valid_from
        ):
            raise ValueError("valid_until must be after valid_from")
        return self

    def active_at(self, when: dt.datetime) -> bool:
        if when.tzinfo is None or when.utcoffset() is None:
            raise ValueError("match time must be timezone-aware")
        check_at = when.astimezone(dt.UTC)
        if self.revoked:
            return False
        if self.valid_from is not None and check_at < self.valid_from.astimezone(dt.UTC):
            return False
        return self.valid_until is None or check_at < self.valid_until.astimezone(dt.UTC)


class ThreatIntelImportResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: ThreatIntelSource
    imported: int = 0
    updated: int = 0
    unchanged: int = 0
    revoked: int = 0


@runtime_checkable
class ThreatIntelRepository(Protocol):
    def add_threat_intel_source(self, source: ThreatIntelSource) -> ThreatIntelSource: ...

    def get_threat_indicator(
        self,
        tenant_id: str,
        site_id: str,
        indicator_id: str,
    ) -> ThreatIndicator | None: ...

    def upsert_threat_indicator(self, indicator: ThreatIndicator) -> str: ...

    def list_active_threat_indicators(
        self,
        tenant_id: str,
        site_id: str,
        *,
        indicator_type: IndicatorType | None = None,
        now: dt.datetime | None = None,
    ) -> list[ThreatIndicator]: ...


_SUPPORTED_PATTERN = re.compile(
    r"^\[\s*(?P<object>[a-z0-9-]+)\s*:\s*(?P<path>[^=]+?)\s*=\s*'(?P<value>(?:\\'|[^'])+)'\s*\]$",
    re.IGNORECASE,
)


def _utc(value: object, *, field_name: str) -> dt.datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ThreatIntelError(f"{field_name} must be a STIX timestamp string")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ThreatIntelError(f"{field_name} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ThreatIntelError(f"{field_name} must include a timezone")
    return parsed.astimezone(dt.UTC)


def normalize_domain(value: str) -> str:
    text = value.strip().rstrip(".").casefold()
    if not text or len(text) > 253 or "/" in text or "@" in text:
        raise ThreatIntelError("invalid domain indicator value")
    labels = text.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise ThreatIntelError("invalid domain indicator value")
    try:
        return ".".join(label.encode("idna").decode("ascii") for label in labels)
    except UnicodeError as exc:
        raise ThreatIntelError("invalid domain indicator value") from exc


def normalize_hash(value: str) -> str:
    text = value.strip().casefold()
    if not re.fullmatch(r"[0-9a-f]+", text) or len(text) not in {32, 40, 64, 128}:
        raise ThreatIntelError("unsupported file hash encoding")
    return text


def normalize_url(value: str) -> str:
    text = value.strip()
    if not text or len(text) > 2048 or any(ord(ch) < 32 for ch in text):
        raise ThreatIntelError("invalid URL indicator value")
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", text):
        raise ThreatIntelError("URL indicator must include a scheme")
    return text


def parse_supported_pattern(pattern: str) -> tuple[IndicatorType, str]:
    if len(pattern) > 4096:
        raise ThreatIntelError("STIX pattern is too large")
    match = _SUPPORTED_PATTERN.match(pattern)
    if match is None:
        raise ThreatIntelError("unsupported STIX pattern syntax")
    obj = match.group("object").casefold()
    path = re.sub(r"\s+", "", match.group("path")).casefold()
    value = match.group("value").replace("\\'", "'")
    if obj == "ipv4-addr" and path == "value":
        return IndicatorType.IPV4, str(ipaddress.IPv4Address(value.strip()))
    if obj == "ipv6-addr" and path == "value":
        return IndicatorType.IPV6, str(ipaddress.IPv6Address(value.strip()))
    if obj == "domain-name" and path == "value":
        return IndicatorType.DOMAIN, normalize_domain(value)
    if obj == "url" and path == "value":
        return IndicatorType.URL, normalize_url(value)
    if obj == "file" and path.startswith("hashes."):
        algorithm = path.removeprefix("hashes.").strip("'\"")
        if algorithm in {"md5", "sha-1", "sha-256", "sha-512"}:
            return IndicatorType.FILE_HASH, normalize_hash(value)
    raise ThreatIntelError("unsupported STIX observable pattern")


def indicator_id_for(tenant_id: str, site_id: str, stix_id: str) -> str:
    digest = hashlib.sha256(f"{tenant_id}\x1f{site_id}\x1f{stix_id}".encode()).hexdigest()
    return digest[:48]


def ingest_stix_bundle(
    repository: ThreatIntelRepository,
    *,
    tenant_id: str,
    site_id: str,
    source_id: str,
    source_name: str,
    bundle: dict[str, Any],
    imported_at: dt.datetime | None = None,
) -> ThreatIntelImportResult:
    if imported_at is None:
        imported_at = dt.datetime.now(dt.UTC)
    if imported_at.tzinfo is None or imported_at.utcoffset() is None:
        raise ThreatIntelError("imported_at must be timezone-aware")
    if not tenant_id or not site_id:
        raise ThreatIntelError("tenant_id and site_id are required")
    if bundle.get("type") != "bundle":
        raise ThreatIntelError("STIX document must be a bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ThreatIntelError("STIX bundle objects must be a list")
    if len(objects) > MAX_STIX_OBJECTS:
        raise ThreatIntelError("STIX bundle object count exceeds limit")

    source = ThreatIntelSource(
        source_id=source_id,
        tenant_id=tenant_id,
        site_id=site_id,
        name=source_name,
        created_at=imported_at.astimezone(dt.UTC),
        updated_at=imported_at.astimezone(dt.UTC),
    )

    indicators: list[ThreatIndicator] = []
    for obj in objects:
        if not isinstance(obj, dict):
            raise ThreatIntelError("STIX object must be a JSON object")
        if obj.get("type") != "indicator":
            raise ThreatIntelError(f"unsupported STIX object type: {obj.get('type')!r}")
        stix_id = obj.get("id")
        if not isinstance(stix_id, str) or not stix_id.startswith("indicator--"):
            raise ThreatIntelError("indicator object has invalid STIX id")
        pattern = obj.get("pattern")
        if not isinstance(pattern, str):
            raise ThreatIntelError("indicator pattern is required")
        pattern_type = obj.get("pattern_type")
        if pattern_type != "stix":
            raise ThreatIntelError("only STIX pattern_type is supported")
        indicator_type, normalized = parse_supported_pattern(pattern)
        labels = obj.get("labels", [])
        if not isinstance(labels, list) or not all(isinstance(item, str) for item in labels):
            raise ThreatIntelError("indicator labels must be a list of strings")
        confidence = obj.get("confidence")
        if confidence is not None and (
            not isinstance(confidence, int) or isinstance(confidence, bool)
        ):
            raise ThreatIntelError("indicator confidence must be an integer")

        indicators.append(
            ThreatIndicator(
                indicator_id=indicator_id_for(tenant_id, site_id, stix_id),
                tenant_id=tenant_id,
                site_id=site_id,
                source_id=source_id,
                source_name=source_name,
                stix_id=stix_id,
                stix_created=_utc(obj.get("created"), field_name="created"),
                stix_modified=_utc(obj.get("modified"), field_name="modified"),
                valid_from=_utc(obj.get("valid_from"), field_name="valid_from"),
                valid_until=_utc(obj.get("valid_until"), field_name="valid_until"),
                revoked=bool(obj.get("revoked", False)),
                labels=set(labels),
                stix_confidence=confidence,
                indicator_type=indicator_type,
                normalized_value=normalized,
                pattern=pattern,
                name=obj.get("name") if isinstance(obj.get("name"), str) else None,
                description=(
                    obj.get("description")
                    if isinstance(obj.get("description"), str)
                    else None
                ),
                imported_at=imported_at.astimezone(dt.UTC),
            )
        )

    try:
        with repository.transaction():  # type: ignore[attr-defined]
            repository.add_threat_intel_source(source)
            result = ThreatIntelImportResult(source=source)
            for indicator in indicators:
                status = repository.upsert_threat_indicator(indicator)
                if status == "inserted":
                    result.imported += 1
                elif status == "updated":
                    result.updated += 1
                else:
                    result.unchanged += 1
                if indicator.revoked:
                    result.revoked += 1
            return result
    except AttributeError:
        repository.add_threat_intel_source(source)
        result = ThreatIntelImportResult(source=source)
        for indicator in indicators:
            status = repository.upsert_threat_indicator(indicator)
            if status == "inserted":
                result.imported += 1
            elif status == "updated":
                result.updated += 1
            else:
                result.unchanged += 1
            if indicator.revoked:
                result.revoked += 1
        return result


def _event_observables(event: SecurityEvent) -> dict[IndicatorType, set[str]]:
    values: dict[IndicatorType, set[str]] = {kind: set() for kind in IndicatorType}
    for raw in (event.src_ip, event.dst_ip):
        if raw:
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                continue
            values[IndicatorType.IPV6 if ip.version == 6 else IndicatorType.IPV4].add(str(ip))
    for key in ("dns_query", "query_name", "domain", "hostname"):
        raw = event.attributes.get(key)
        if isinstance(raw, str):
            with suppress(ThreatIntelError):
                values[IndicatorType.DOMAIN].add(normalize_domain(raw))
    for key in ("url", "http_url", "request_url"):
        raw = event.attributes.get(key)
        if isinstance(raw, str):
            with suppress(ThreatIntelError):
                values[IndicatorType.URL].add(normalize_url(raw))
    hashes = event.attributes.get("file_hashes")
    if isinstance(hashes, dict):
        for raw in hashes.values():
            if isinstance(raw, str):
                with suppress(ThreatIntelError):
                    values[IndicatorType.FILE_HASH].add(normalize_hash(raw))
    for key in ("md5", "sha1", "sha256", "sha512", "file_hash"):
        raw = event.attributes.get(key)
        if isinstance(raw, str):
            with suppress(ThreatIntelError):
                values[IndicatorType.FILE_HASH].add(normalize_hash(raw))
    return values


def match_event_indicators(
    repository: ThreatIntelRepository,
    event: SecurityEvent,
    *,
    now: dt.datetime | None = None,
) -> list[Finding]:
    match_at = now or event.observed_at
    observables = _event_observables(event)
    findings: list[Finding] = []
    for indicator_type, seen in observables.items():
        if not seen:
            continue
        for indicator in repository.list_active_threat_indicators(
            event.tenant_id,
            event.site_id,
            indicator_type=indicator_type,
            now=match_at,
        ):
            if indicator.normalized_value not in seen or not indicator.active_at(match_at):
                continue
            confidence = (
                round(indicator.stix_confidence / 100, 2)
                if indicator.stix_confidence is not None
                else 0.6
            )
            summary = (
                f"Event observable matched {indicator.indicator_type.value} "
                f"indicator from {indicator.source_name}"
            )
            findings.append(
                Finding(
                    tenant_id=event.tenant_id,
                    site_id=event.site_id,
                    detector_id="threat-intel-indicator-match",
                    title="Threat intelligence indicator match",
                    severity=Severity.MEDIUM,
                    confidence=min(confidence, 0.95),
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    asset_id=event.asset_id,
                    first_seen=event.observed_at,
                    last_seen=match_at.astimezone(dt.UTC),
                    evidence=[
                        *event.evidence,
                        EvidenceRef(
                            evidence_class=EvidenceClass.THREAT_INTEL,
                            source=f"mon:threat-intel:{indicator.source_id}",
                            summary=summary,
                            confidence=min(confidence, 0.95),
                            observed_at=match_at,
                            raw_reference=event.event_id,
                        ),
                    ],
                    attributes={
                        "claim": (
                            "indicator match only; not proof of compromise "
                            "or successful malicious activity"
                        ),
                        "indicator_id": indicator.indicator_id,
                        "stix_id": indicator.stix_id,
                        "indicator_type": indicator.indicator_type.value,
                        "indicator_value": indicator.normalized_value,
                        "source_id": indicator.source_id,
                        "source_name": indicator.source_name,
                        "matched_at": match_at.astimezone(dt.UTC).isoformat(),
                        "valid_from": (
                            indicator.valid_from.isoformat()
                            if indicator.valid_from is not None
                            else None
                        ),
                        "valid_until": (
                            indicator.valid_until.isoformat()
                            if indicator.valid_until is not None
                            else None
                        ),
                        "stix_confidence": indicator.stix_confidence,
                    },
                )
            )
    return findings
