"""Scope-aware victim-health summary from real Prometheus observations.

This module never returns synthetic readings. It has no user-supplied URL or
arbitrary PromQL route, and distinguishes missing/stale/disconnected evidence.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import os
import urllib.parse
from typing import Literal

import httpx
from pydantic import BaseModel, Field

from mon.domain import utcnow


class MetricReading(BaseModel):
    status: Literal["FRESH", "STALE", "UNKNOWN", "AMBIGUOUS"] = "UNKNOWN"
    value: float | None = None
    observed_at: dt.datetime | None = None
    source: str = "PROMETHEUS_OBSERVATION"


class VictimHealthView(BaseModel):
    tenant_id: str
    site_id: str
    collected_at: dt.datetime = Field(default_factory=utcnow)
    telemetry_state: Literal["AVAILABLE", "DEGRADED", "UNCONFIGURED"] = "UNCONFIGURED"
    service_reachable: MetricReading = Field(default_factory=MetricReading)
    probe_duration_seconds: MetricReading = Field(default_factory=MetricReading)
    erp_process_rss_bytes: MetricReading = Field(default_factory=MetricReading)
    erp_process_cpu_seconds: MetricReading = Field(default_factory=MetricReading)
    host_cpu_percent: MetricReading = Field(default_factory=MetricReading)
    host_ram_percent: MetricReading = Field(default_factory=MetricReading)
    note: str = "No verified ERP metrics"


_QUERIES = {
    "service_reachable": ('probe_success', 'erp-independent-availability'),
    "probe_duration_seconds": ('probe_duration_seconds', 'erp-independent-availability'),
    "erp_process_rss_bytes": ('mon_erp_process_rss_bytes', 'erp-process'),
    "erp_process_cpu_seconds": ('mon_erp_process_cpu_seconds', 'erp-process'),
}


def _prometheus_url(url: str) -> str:
    """Only a configured internal service endpoint, never user-controlled HTTP targets."""
    parts = urllib.parse.urlsplit(url)
    if (
        parts.scheme != "http" or
        parts.hostname not in {"prometheus", "127.0.0.1", "localhost"} or
        parts.username or parts.password or parts.query or parts.fragment or
        parts.path not in {"", "/"} or parts.port not in {9090, None}
    ):
        raise ValueError("Prometheus URL must be the preconfigured local monitoring service")
    return url.rstrip("/") + "/api/v1/query"


def _reading(items: object, *, at: dt.datetime) -> MetricReading:
    if not isinstance(items, list) or len(items) == 0:
        return MetricReading()
    if len(items) != 1:
        return MetricReading(status="AMBIGUOUS")
    row = items[0]
    try:
        epoch, string_value = row["value"]
        value = float(string_value)
        observed_at = dt.datetime.fromtimestamp(float(epoch), tz=dt.UTC)
        if not math.isfinite(value) or observed_at > at + dt.timedelta(seconds=30):
            return MetricReading()
    except (ValueError, OverflowError, TypeError, KeyError, IndexError, OSError):
        return MetricReading()
    freshness = (at - observed_at).total_seconds()
    return MetricReading(
        status="FRESH" if freshness <= 20 and freshness >= -30 else "STALE",
        value=value, observed_at=observed_at,
    )


def collect_victim_health(
    tenant_id: str,
    site_id: str,
    *,
    prometheus_url: str | None = None,
    at: dt.datetime | None = None,
) -> VictimHealthView:
    """Read fixed, tenant/site-labelled range metrics; never guess missing values."""
    now = at or utcnow()
    view = VictimHealthView(tenant_id=tenant_id, site_id=site_id, collected_at=now)
    configured = (
        prometheus_url
        if prometheus_url is not None
        else os.getenv("MON_PROMETHEUS_URL", "")
    )
    if not configured:
        return view
    try:
        endpoint = _prometheus_url(configured)
    except ValueError:
        view.telemetry_state = "DEGRADED"
        view.note = "Metrics endpoint misconfigured; no values assumed"
        return view

    view.telemetry_state = "AVAILABLE"
    # json.dumps produces escaped quoted-string PromQL selectors, avoiding
    # unescaped user-supplied expressions. Only fixed query names are allowed.
    labels = (
        f'tenant_id={json.dumps(tenant_id)},site_id={json.dumps(site_id)}'
    )
    try:
        with httpx.Client(timeout=3.0, trust_env=False) as client:
            for field, (name, job) in _QUERIES.items():
                expression = f'{name}{{job={json.dumps(job)},{labels}}}'
                response = client.get(endpoint, params={"query": expression})
                response.raise_for_status()
                payload = response.json()
                if payload.get("status") != "success" or (
                    payload.get("data", {}).get("resultType") != "vector"
                ):
                    raise ValueError("unavailable Prometheus vector")
                setattr(
                    view, field,
                    _reading(payload["data"].get("result"), at=now),
                )
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        # Partial responses may have arrived. Mark whole provider degraded;
        # individual measurements retain provenance/age rather than zeros.
        view.telemetry_state = "DEGRADED"
        view.note = "Metrics source unreachable or incomplete"
        return view

    readings = [
        view.service_reachable, view.probe_duration_seconds,
        view.erp_process_rss_bytes, view.erp_process_cpu_seconds,
    ]
    if all(item.status == "UNKNOWN" for item in readings):
        view.note = "No instrumented ERP target configured or observed"
    elif any(item.status in {"STALE", "AMBIGUOUS"} for item in readings):
        view.note = "Partial, stale or multiply matched telemetry"
    elif view.service_reachable.status == "FRESH" and view.service_reachable.value == 0:
        view.note = "Independent probe recorded ERP service unavailable"
    else:
        view.note = "Measurements from configured Prometheus collectors"
    # Host readings intentionally remain UNKNOWN until a separately certified
    # host-level collector is connected. Process RSS is not host RAM.
    return view
