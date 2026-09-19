from __future__ import annotations

import datetime as dt
import threading
from collections import Counter, defaultdict, deque
from dataclasses import dataclass

from mon.analysis_checkpoint import (
    TelemetryObservationCheckpoint,
    TelemetryStateCheckpoint,
)
from mon.domain import SecurityEvent, TelemetrySnapshot


@dataclass(frozen=True)
class _Observation:
    observed_at: dt.datetime
    src_ip: str | None
    dst_ip: str | None
    protocol: str | None
    measured_packets: int | None
    measured_bytes: int | None


def _measurement(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


class TelemetryEngine:
    """Short-window operational telemetry from observed events.

    Packet and byte counters remain None unless the sensor actually supplied those
    measurements. Observation count is an event count, not a packet count.
    """

    def __init__(self, window_seconds: int = 60) -> None:
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self._windows: dict[
            tuple[str, str], deque[_Observation]
        ] = defaultdict(deque)
        self._lock = threading.RLock()

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()

    def export_checkpoint(self, tenant_id: str, site_id: str) -> TelemetryStateCheckpoint:
        with self._lock:
            return TelemetryStateCheckpoint(
                window_seconds=self.window_seconds,
                observations=[
                    TelemetryObservationCheckpoint(
                        observed_at=item.observed_at,
                        src_ip=item.src_ip,
                        dst_ip=item.dst_ip,
                        protocol=item.protocol,
                        measured_packets=item.measured_packets,
                        measured_bytes=item.measured_bytes,
                    )
                    for item in self._windows[(tenant_id, site_id)]
                ],
            )

    def restore_checkpoint(
        self,
        tenant_id: str,
        site_id: str,
        state: TelemetryStateCheckpoint,
    ) -> None:
        with self._lock:
            self.window_seconds = state.window_seconds
            self._windows[(tenant_id, site_id)] = deque(
                _Observation(
                    observed_at=item.observed_at,
                    src_ip=item.src_ip,
                    dst_ip=item.dst_ip,
                    protocol=item.protocol,
                    measured_packets=item.measured_packets,
                    measured_bytes=item.measured_bytes,
                )
                for item in state.observations
            )

    def observe(self, event: SecurityEvent) -> TelemetrySnapshot:
        observation = _Observation(
            observed_at=event.observed_at,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            protocol=event.protocol.casefold() if event.protocol else None,
            measured_packets=_measurement(event.attributes.get("packets")),
            measured_bytes=_measurement(event.attributes.get("bytes")),
        )
        scope = (event.tenant_id, event.site_id)
        with self._lock:
            window = self._windows[scope]
            window.append(observation)
            return self._snapshot_locked(
                event.tenant_id,
                event.site_id,
                event.observed_at,
            )

    def snapshot(self, tenant_id: str, site_id: str) -> TelemetrySnapshot:
        with self._lock:
            window = self._windows[(tenant_id, site_id)]
            as_of = max(
                (item.observed_at for item in window),
                default=dt.datetime.now(dt.UTC),
            )
            return self._snapshot_locked(tenant_id, site_id, as_of)

    def _snapshot_locked(
        self,
        tenant_id: str,
        site_id: str,
        as_of: dt.datetime,
    ) -> TelemetrySnapshot:
        window = self._windows[(tenant_id, site_id)]
        cutoff = as_of - dt.timedelta(seconds=self.window_seconds)
        while window and window[0].observed_at < cutoff:
            window.popleft()

        observations = list(window)
        if observations:
            earliest = min(item.observed_at for item in observations)
            latest = max(item.observed_at for item in observations)
            span = max(0.0, (latest - earliest).total_seconds())
        else:
            span = 0.0

        rate_span = span if span >= 1.0 and len(observations) >= 2 else None
        packets = [
            item.measured_packets
            for item in observations
            if item.measured_packets is not None
        ]
        bytes_measured = [
            item.measured_bytes
            for item in observations
            if item.measured_bytes is not None
        ]
        packet_total = sum(packets) if packets else None
        byte_total = sum(bytes_measured) if bytes_measured else None

        protocols = Counter(
            item.protocol for item in observations if item.protocol is not None
        )
        sources = Counter(item.src_ip for item in observations if item.src_ip)

        return TelemetrySnapshot(
            tenant_id=tenant_id,
            site_id=site_id,
            window_seconds=self.window_seconds,
            observed_at=as_of,
            observation_count=len(observations),
            measurement_span_seconds=round(span, 3) if observations else None,
            events_per_second=(
                round(len(observations) / rate_span, 3)
                if rate_span is not None
                else None
            ),
            measured_packets=packet_total,
            measured_bytes=byte_total,
            measured_packets_per_second=(
                round(packet_total / rate_span, 3)
                if packet_total is not None and rate_span is not None
                else None
            ),
            measured_bytes_per_second=(
                round(byte_total / rate_span, 3)
                if byte_total is not None and rate_span is not None
                else None
            ),
            unique_src_ips=len({item.src_ip for item in observations if item.src_ip}),
            unique_dst_ips=len({item.dst_ip for item in observations if item.dst_ip}),
            protocol_counts=dict(protocols.most_common(32)),
            source_counts=dict(sources.most_common(32)),
        )
