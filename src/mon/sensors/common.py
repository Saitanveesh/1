from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import math
import uuid
from collections.abc import Mapping
from typing import Any

from mon.domain import EvidenceClass, EvidenceRef

_EVENT_NAMESPACE = uuid.UUID("0dc3cc11-77e8-4ea2-a28e-c5f76752b9f6")
_EVIDENCE_NAMESPACE = uuid.UUID("ea7e6bce-d3cc-43cc-90b5-68ffd5d2c5d8")


class SensorNormalizationError(ValueError):
    pass


def canonical_record(record: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            dict(record),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise SensorNormalizationError(
            "sensor record must contain JSON-compatible finite values"
        ) from exc


def deterministic_event_id(
    *,
    engine: str,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    record_type: str,
    record: Mapping[str, Any],
) -> str:
    digest = hashlib.sha256(canonical_record(record).encode()).hexdigest()
    material = ":".join(
        (engine, tenant_id, site_id, sensor_id, record_type, digest)
    )
    return str(uuid.uuid5(_EVENT_NAMESPACE, material))


def deterministic_evidence_id(
    event_id: str,
    source: str,
    raw_reference: str | None,
) -> str:
    material = ":".join((event_id, source, raw_reference or ""))
    return str(uuid.uuid5(_EVIDENCE_NAMESPACE, material))


def evidence(
    *,
    event_id: str,
    evidence_class: EvidenceClass,
    source: str,
    summary: str,
    confidence: float,
    observed_at: dt.datetime,
    raw_reference: str | None,
) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=deterministic_evidence_id(event_id, source, raw_reference),
        evidence_class=evidence_class,
        source=source,
        summary=summary[:1000],
        confidence=confidence,
        observed_at=observed_at,
        raw_reference=raw_reference[:1000] if raw_reference else None,
    )


def parse_epoch_timestamp(value: object, *, field_name: str) -> dt.datetime:
    if isinstance(value, bool):
        raise SensorNormalizationError(f"{field_name} must be a numeric epoch timestamp")
    try:
        seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise SensorNormalizationError(
            f"{field_name} must be a numeric epoch timestamp"
        ) from exc
    if not math.isfinite(seconds):
        raise SensorNormalizationError(f"{field_name} must be finite")
    try:
        return dt.datetime.fromtimestamp(seconds, tz=dt.UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise SensorNormalizationError(f"{field_name} is outside supported range") from exc


def parse_iso_timestamp(value: object, *, field_name: str) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise SensorNormalizationError(f"{field_name} must be an ISO-8601 timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise SensorNormalizationError(
            f"{field_name} must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SensorNormalizationError(f"{field_name} must include a timezone offset")
    return parsed.astimezone(dt.UTC)


def text(value: object, *, limit: int = 512) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(character for character in value.strip() if character.isprintable())
    return cleaned[:limit] if cleaned else None


def integer(
    value: object,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    if result < minimum or (maximum is not None and result > maximum):
        return None
    return result


def floating(value: object, *, minimum: float = 0.0) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(result) or result < minimum:
        return None
    return result


def ip(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    candidate = text(value, limit=128)
    if candidate is None:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise SensorNormalizationError(f"{field_name} is not a valid IP address") from exc


def port(value: object) -> int | None:
    return integer(value, minimum=0, maximum=65535)


def bool_value(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def add_if_present(target: dict[str, Any], key: str, value: object) -> None:
    if value is not None:
        target[key] = value


def complete_sum(left: object, right: object) -> int | None:
    first = integer(left)
    second = integer(right)
    if first is None or second is None:
        return None
    return first + second
