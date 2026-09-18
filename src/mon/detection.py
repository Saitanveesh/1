from __future__ import annotations

import datetime as dt
from collections import defaultdict, deque
from dataclasses import dataclass

from mon.domain import EvidenceClass, EvidenceRef, Finding, SecurityEvent, Severity


@dataclass(frozen=True)
class _Observation:
    observed_at: dt.datetime
    dst_ip: str | None
    dst_port: int | None


class DetectionEngine:
    """Small streaming detector core with evidence-bounded claims.

    These rules identify traffic shapes, not confirmed compromise. Mature signature,
    behavioral and endpoint engines can later publish into the same Finding contract.
    """

    def __init__(self) -> None:
        self._windows: dict[tuple[str, str, str, str], deque[_Observation]] = defaultdict(deque)
        self._last_emit: dict[tuple[str, str, str, str], dt.datetime] = {}

    def reset(self) -> None:
        self._windows.clear()
        self._last_emit.clear()

    @staticmethod
    def _port(event: SecurityEvent) -> int | None:
        value = event.attributes.get("dst_port")
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _record(
        self,
        rule: str,
        event: SecurityEvent,
        source: str,
        window_seconds: int,
    ) -> deque[_Observation]:
        key = (rule, event.tenant_id, event.site_id, source)
        window = self._windows[key]
        window.append(_Observation(event.observed_at, event.dst_ip, self._port(event)))
        cutoff = event.observed_at - dt.timedelta(seconds=window_seconds)
        while window and window[0].observed_at < cutoff:
            window.popleft()
        return window

    def _may_emit(
        self,
        rule: str,
        event: SecurityEvent,
        source: str,
        cooldown_seconds: int,
    ) -> bool:
        key = (rule, event.tenant_id, event.site_id, source)
        previous = self._last_emit.get(key)
        if previous and (event.observed_at - previous).total_seconds() < cooldown_seconds:
            return False
        self._last_emit[key] = event.observed_at
        return True

    @staticmethod
    def _finding(
        event: SecurityEvent,
        detector_id: str,
        title: str,
        severity: Severity,
        confidence: float,
        summary: str,
        attributes: dict[str, object],
    ) -> Finding:
        evidence = [
            *event.evidence,
            EvidenceRef(
                evidence_class=EvidenceClass.STATISTICAL,
                source=f"mon:{detector_id}",
                summary=summary,
                confidence=confidence,
                observed_at=event.observed_at,
                raw_reference=event.event_id,
            ),
        ]
        return Finding(
            tenant_id=event.tenant_id,
            site_id=event.site_id,
            detector_id=detector_id,
            title=title,
            severity=severity,
            confidence=confidence,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            asset_id=event.asset_id,
            evidence=evidence,
            first_seen=min(item.observed_at for item in evidence),
            last_seen=event.observed_at,
            attributes=attributes,
        )

    def process(self, event: SecurityEvent) -> list[Finding]:
        findings: list[Finding] = []
        source = event.src_ip or event.asset_id or "unknown"

        tcp_syn = bool(event.attributes.get("tcp_syn"))
        tcp_ack = bool(event.attributes.get("tcp_ack"))
        if tcp_syn and not tcp_ack and source != "unknown":
            window = self._record("tcp-syn-recon", event, source, 10)
            destinations = {item.dst_ip for item in window if item.dst_ip}
            ports = {item.dst_port for item in window if item.dst_port is not None}
            if (
                len(window) >= 60
                and (len(destinations) >= 10 or len(ports) >= 18)
                and self._may_emit("tcp-syn-recon", event, source, 10)
            ):
                findings.append(
                    self._finding(
                        event,
                        "tcp-syn-recon",
                        "TCP SYN reconnaissance/flood shape",
                        Severity.HIGH,
                        0.82,
                        (
                            f"{len(window)} SYN attempts in 10s across "
                            f"{len(destinations)} destinations and {len(ports)} ports"
                        ),
                        {
                            "window_seconds": 10,
                            "attempts": len(window),
                            "unique_destinations": len(destinations),
                            "unique_ports": len(ports),
                            "claim": "traffic shape only; not proof of compromise",
                        },
                    )
                )

        icmp_type = str(event.attributes.get("icmp_type") or "").casefold()
        if event.protocol and event.protocol.casefold() == "icmp" and icmp_type in {
            "8",
            "echo-request",
            "echo_request",
        }:
            window = self._record("icmp-host-discovery", event, source, 15)
            destinations = {item.dst_ip for item in window if item.dst_ip}
            if (
                len(window) >= 14
                and len(destinations) >= 12
                and self._may_emit("icmp-host-discovery", event, source, 15)
            ):
                findings.append(
                    self._finding(
                        event,
                        "icmp-host-discovery",
                        "ICMP host-discovery pattern",
                        Severity.MEDIUM,
                        0.78,
                        f"{len(window)} ICMP echo requests reached {len(destinations)} hosts in 15s",
                        {
                            "window_seconds": 15,
                            "requests": len(window),
                            "unique_destinations": len(destinations),
                        },
                    )
                )

        if event.category.casefold() == "dns.query":
            window = self._record("dns-query-rate", event, source, 10)
            if len(window) >= 120 and self._may_emit("dns-query-rate", event, source, 10):
                findings.append(
                    self._finding(
                        event,
                        "dns-query-rate",
                        "Abnormal DNS query-rate pattern",
                        Severity.MEDIUM,
                        0.75,
                        f"{len(window)} DNS queries observed from the source in 10s",
                        {"window_seconds": 10, "queries": len(window)},
                    )
                )

        direction = str(event.attributes.get("direction") or "").casefold()
        port = self._port(event)
        if direction == "east-west" and port in {22, 445, 3389} and source != "unknown":
            window = self._record("internal-lateral-sweep", event, source, 30)
            destinations = {item.dst_ip for item in window if item.dst_ip}
            if (
                len(window) >= 12
                and len(destinations) >= 8
                and self._may_emit("internal-lateral-sweep", event, source, 30)
            ):
                findings.append(
                    self._finding(
                        event,
                        "internal-lateral-sweep",
                        "Internal administrative-service sweep",
                        Severity.HIGH,
                        0.88,
                        (
                            f"{len(window)} east-west attempts to administrative services "
                            f"across {len(destinations)} internal targets in 30s"
                        ),
                        {
                            "window_seconds": 30,
                            "attempts": len(window),
                            "unique_destinations": len(destinations),
                            "ports": sorted(
                                {item.dst_port for item in window if item.dst_port is not None}
                            ),
                            "claim": "lateral-movement indicator; not proof of successful access",
                        },
                    )
                )

        return findings
