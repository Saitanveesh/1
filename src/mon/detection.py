from __future__ import annotations

import datetime as dt
import statistics
import threading
from collections import defaultdict, deque
from dataclasses import dataclass

from mon.analysis_checkpoint import (
    DetectorBeaconCheckpoint,
    DetectorEmitCheckpoint,
    DetectorObservationCheckpoint,
    DetectorStateCheckpoint,
    DetectorWindowCheckpoint,
)
from mon.domain import EvidenceClass, EvidenceRef, Finding, SecurityEvent, Severity


@dataclass(frozen=True)
class DetectionThresholds:
    syn_recon_attempts: int = 60
    syn_flood_attempts: int = 200
    udp_flood_events: int = 300
    icmp_flood_events: int = 200
    dns_rate_queries: int = 120
    dns_tunnel_queries: int = 20
    arp_sweep_requests: int = 24
    admin_service_attempts: int = 25
    beacon_observations: int = 8
    endpoint_auth_failures: int = 8


@dataclass(frozen=True)
class _Observation:
    observed_at: dt.datetime
    dst_ip: str | None
    dst_port: int | None
    value: str | None = None


class DetectionEngine:
    """Streaming, evidence-bounded network detection.

    Rules describe observable traffic shapes. They do not claim successful compromise,
    credential theft, exfiltration, or command-and-control unless a stronger evidence
    source explicitly provides that conclusion.
    """

    ADMIN_PORTS = {21, 22, 23, 445, 3389, 5900}

    def __init__(self, thresholds: DetectionThresholds | None = None) -> None:
        self.thresholds = thresholds or DetectionThresholds()
        self._windows: dict[
            tuple[str, str, str, str], deque[_Observation]
        ] = defaultdict(deque)
        self._beacons: dict[
            tuple[str, str, str, str, str, int], deque[dt.datetime]
        ] = defaultdict(deque)
        self._last_emit: dict[tuple[str, str, str, str], dt.datetime] = {}
        self._lock = threading.RLock()

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
            self._beacons.clear()
            self._last_emit.clear()

    def export_checkpoint(self, tenant_id: str, site_id: str) -> DetectorStateCheckpoint:
        with self._lock:
            return DetectorStateCheckpoint(
                thresholds={
                    field: int(getattr(self.thresholds, field))
                    for field in self.thresholds.__dataclass_fields__
                },
                windows=[
                    DetectorWindowCheckpoint(
                        rule=rule,
                        tenant_id=scope_tenant,
                        site_id=scope_site,
                        source=source,
                        observations=[
                            DetectorObservationCheckpoint(
                                observed_at=item.observed_at,
                                dst_ip=item.dst_ip,
                                dst_port=item.dst_port,
                                value=item.value,
                            )
                            for item in window
                        ],
                    )
                    for (
                        rule,
                        scope_tenant,
                        scope_site,
                        source,
                    ), window in sorted(self._windows.items())
                    if scope_tenant == tenant_id and scope_site == site_id
                ],
                beacons=[
                    DetectorBeaconCheckpoint(
                        tenant_id=scope_tenant,
                        site_id=scope_site,
                        source=source,
                        destination=destination,
                        protocol=protocol,
                        port=port,
                        observed_at=list(samples),
                    )
                    for (
                        scope_tenant,
                        scope_site,
                        source,
                        destination,
                        protocol,
                        port,
                    ), samples in sorted(self._beacons.items())
                    if scope_tenant == tenant_id and scope_site == site_id
                ],
                last_emit=[
                    DetectorEmitCheckpoint(
                        rule=rule,
                        tenant_id=scope_tenant,
                        site_id=scope_site,
                        source=source,
                        last_emitted_at=last_emitted_at,
                    )
                    for (
                        rule,
                        scope_tenant,
                        scope_site,
                        source,
                    ), last_emitted_at in sorted(self._last_emit.items())
                    if scope_tenant == tenant_id and scope_site == site_id
                ],
            )

    def restore_checkpoint(
        self,
        tenant_id: str,
        site_id: str,
        state: DetectorStateCheckpoint,
    ) -> None:
        thresholds = DetectionThresholds(**state.thresholds)
        with self._lock:
            self.thresholds = thresholds
            for key in [
                key
                for key in self._windows
                if key[1] == tenant_id and key[2] == site_id
            ]:
                del self._windows[key]
            for key in [
                key
                for key in self._beacons
                if key[0] == tenant_id and key[1] == site_id
            ]:
                del self._beacons[key]
            for key in [
                key
                for key in self._last_emit
                if key[1] == tenant_id and key[2] == site_id
            ]:
                del self._last_emit[key]

            for window in state.windows:
                if window.tenant_id != tenant_id or window.site_id != site_id:
                    raise ValueError("detector checkpoint scope mismatch")
                self._windows[
                    (window.rule, window.tenant_id, window.site_id, window.source)
                ] = deque(
                    _Observation(
                        observed_at=item.observed_at,
                        dst_ip=item.dst_ip,
                        dst_port=item.dst_port,
                        value=item.value,
                    )
                    for item in window.observations
                )
            for beacon in state.beacons:
                if beacon.tenant_id != tenant_id or beacon.site_id != site_id:
                    raise ValueError("detector checkpoint scope mismatch")
                self._beacons[
                    (
                        beacon.tenant_id,
                        beacon.site_id,
                        beacon.source,
                        beacon.destination,
                        beacon.protocol,
                        beacon.port,
                    )
                ] = deque(beacon.observed_at)
            for item in state.last_emit:
                if item.tenant_id != tenant_id or item.site_id != site_id:
                    raise ValueError("detector checkpoint scope mismatch")
                self._last_emit[
                    (item.rule, item.tenant_id, item.site_id, item.source)
                ] = item.last_emitted_at

    @staticmethod
    def _port(event: SecurityEvent, key: str = "dst_port") -> int | None:
        value = event.attributes.get(key)
        if isinstance(value, bool):
            return None
        try:
            result = int(value) if value is not None else None
        except (TypeError, ValueError):
            return None
        if result is None or result < 0 or result > 65535:
            return None
        return result

    @staticmethod
    def _text(value: object, limit: int = 512) -> str | None:
        if not isinstance(value, str):
            return None
        text = "".join(character for character in value.strip() if character.isprintable())
        return text[:limit] if text else None

    def _record(
        self,
        rule: str,
        event: SecurityEvent,
        source: str,
        window_seconds: int,
        *,
        value: str | None = None,
        dst_ip: str | None = None,
        dst_port: int | None = None,
    ) -> deque[_Observation]:
        key = (rule, event.tenant_id, event.site_id, source)
        window = self._windows[key]
        window.append(
            _Observation(
                observed_at=event.observed_at,
                dst_ip=event.dst_ip if dst_ip is None else dst_ip,
                dst_port=self._port(event) if dst_port is None else dst_port,
                value=value,
            )
        )
        if len(window) > 1 and window[-2].observed_at > window[-1].observed_at:
            window = deque(sorted(window, key=lambda item: item.observed_at))
            self._windows[key] = window

        as_of = max(item.observed_at for item in window)
        cutoff = as_of - dt.timedelta(seconds=window_seconds)
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
        *,
        evidence_class: EvidenceClass = EvidenceClass.STATISTICAL,
    ) -> Finding:
        evidence = [
            *event.evidence,
            EvidenceRef(
                evidence_class=evidence_class,
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

    @staticmethod
    def _dns_tunnel_shaped(query: str) -> bool:
        normalized = query.rstrip(".").casefold()
        if len(normalized) < 60:
            return False
        labels = [label for label in normalized.split(".") if label]
        if not labels:
            return False
        longest = max(labels, key=len)
        if len(longest) < 45:
            return False
        diversity = len(set(longest))
        return diversity >= 12

    @staticmethod
    def _ids_severity(value: object) -> Severity:
        if isinstance(value, str):
            normalized = value.strip().upper()
            if normalized in Severity.__members__:
                return Severity[normalized]
            try:
                value = int(normalized)
            except ValueError:
                return Severity.MEDIUM
        if isinstance(value, int) and not isinstance(value, bool):
            return {
                1: Severity.HIGH,
                2: Severity.MEDIUM,
                3: Severity.LOW,
            }.get(value, Severity.MEDIUM)
        return Severity.MEDIUM

    def _beacon_finding(
        self,
        event: SecurityEvent,
        source: str,
        protocol: str,
        port: int | None,
    ) -> Finding | None:
        destination = event.dst_ip
        if not destination:
            return None
        key = (
            event.tenant_id,
            event.site_id,
            source,
            destination,
            protocol,
            port or 0,
        )
        samples = self._beacons[key]
        samples.append(event.observed_at)
        cutoff = event.observed_at - dt.timedelta(minutes=10)
        while samples and samples[0] < cutoff:
            samples.popleft()
        if len(samples) < self.thresholds.beacon_observations:
            return None

        intervals = [
            (right - left).total_seconds()
            for left, right in zip(samples, list(samples)[1:], strict=False)
            if right >= left
        ]
        if len(intervals) < self.thresholds.beacon_observations - 1:
            return None
        mean = statistics.fmean(intervals)
        if mean < 5 or mean > 120:
            return None
        jitter = statistics.pstdev(intervals) / mean if mean else 1.0
        detector_source = f"{source}->{destination}:{port or 0}/{protocol}"
        if jitter > 0.15 or not self._may_emit(
            "periodic-beacon-shape",
            event,
            detector_source,
            300,
        ):
            return None

        return self._finding(
            event,
            "periodic-beacon-shape",
            "Periodic outbound communication pattern",
            Severity.MEDIUM,
            0.68,
            (
                f"{len(samples)} observations to the same endpoint with "
                f"mean interval {mean:.1f}s and relative jitter {jitter:.2f}"
            ),
            {
                "observations": len(samples),
                "mean_interval_seconds": round(mean, 3),
                "relative_jitter": round(jitter, 3),
                "destination": destination,
                "dst_port": port,
                "protocol": protocol,
                "claim": "periodicity indicator only; not proof of command-and-control",
            },
        )

    def process(self, event: SecurityEvent) -> list[Finding]:
        with self._lock:
            return self._process_locked(event)

    def _process_locked(self, event: SecurityEvent) -> list[Finding]:
        findings: list[Finding] = []
        source = event.src_ip or event.asset_id or "unknown"
        protocol = event.protocol.casefold() if event.protocol else ""
        port = self._port(event)
        tcp_syn = bool(event.attributes.get("tcp_syn"))
        tcp_ack = bool(event.attributes.get("tcp_ack"))

        if event.category.casefold() in {"ids.alert", "suricata.alert"}:
            signature = self._text(
                event.attributes.get("signature")
                or event.attributes.get("signature_name")
                or event.attributes.get("rule_id"),
                300,
            )
            if signature:
                findings.append(
                    self._finding(
                        event,
                        "network-ids-signature",
                        f"IDS signature match: {signature}",
                        self._ids_severity(event.attributes.get("severity")),
                        0.95,
                        f"Network IDS reported signature match {signature}",
                        {
                            "signature": signature,
                            "engine": self._text(event.attributes.get("engine"), 64),
                            "claim": (
                                "signature match from IDS telemetry; "
                                "not independently proof of compromise"
                            ),
                        },
                        evidence_class=EvidenceClass.IDS_ALERT,
                    )
                )

        if event.category.casefold() == "endpoint.auth.failure" and source != "unknown":
            identity = self._text(
                event.attributes.get("identity_principal")
                or event.attributes.get("identity_display_name"),
                512,
            )
            auth_failures = self._record(
                "endpoint-auth-failure-pressure",
                event,
                f"{source}:{identity or 'unknown'}",
                300,
                value=identity,
                dst_ip=event.asset_id,
            )
            if (
                len(auth_failures) >= self.thresholds.endpoint_auth_failures
                and self._may_emit(
                    "endpoint-auth-failure-pressure",
                    event,
                    f"{source}:{identity or 'unknown'}",
                    300,
                )
            ):
                findings.append(
                    self._finding(
                        event,
                        "endpoint-auth-failure-pressure",
                        "Repeated endpoint authentication failures",
                        Severity.MEDIUM,
                        0.72,
                        (
                            f"{len(auth_failures)} endpoint authentication failures "
                            "observed in 300s"
                        ),
                        {
                            "window_seconds": 300,
                            "failures": len(auth_failures),
                            "identity_observed": identity,
                            "claim": (
                                "authentication-failure pressure only; "
                                "not proof of compromise or successful access"
                            ),
                        },
                        evidence_class=EvidenceClass.IDENTITY,
                    )
                )

        if tcp_syn and not tcp_ack and source != "unknown":
            recon = self._record("tcp-syn-recon", event, source, 10)
            destinations = {item.dst_ip for item in recon if item.dst_ip}
            ports = {item.dst_port for item in recon if item.dst_port is not None}
            if (
                len(recon) >= self.thresholds.syn_recon_attempts
                and (len(destinations) >= 10 or len(ports) >= 18)
                and self._may_emit("tcp-syn-recon", event, source, 10)
            ):
                findings.append(
                    self._finding(
                        event,
                        "tcp-syn-recon",
                        "TCP SYN reconnaissance shape",
                        Severity.HIGH,
                        0.82,
                        (
                            f"{len(recon)} SYN attempts in 10s across "
                            f"{len(destinations)} destinations and {len(ports)} ports"
                        ),
                        {
                            "window_seconds": 10,
                            "attempts": len(recon),
                            "unique_destinations": len(destinations),
                            "unique_ports": len(ports),
                            "claim": "reconnaissance shape; not proof of compromise",
                        },
                    )
                )

            pressure = self._record("tcp-syn-flood-shape", event, source, 10)
            pressure_destinations = {
                item.dst_ip for item in pressure if item.dst_ip is not None
            }
            pressure_ports = {
                item.dst_port for item in pressure if item.dst_port is not None
            }
            if (
                len(pressure) >= self.thresholds.syn_flood_attempts
                and len(pressure_destinations) <= 3
                and len(pressure_ports) <= 6
                and self._may_emit("tcp-syn-flood-shape", event, source, 10)
            ):
                findings.append(
                    self._finding(
                        event,
                        "tcp-syn-flood-shape",
                        "TCP SYN flood-pressure shape",
                        Severity.HIGH,
                        0.84,
                        (
                            f"{len(pressure)} SYN attempts concentrated on "
                            f"{len(pressure_destinations)} destination(s) in 10s"
                        ),
                        {
                            "window_seconds": 10,
                            "attempts": len(pressure),
                            "unique_destinations": len(pressure_destinations),
                            "unique_ports": len(pressure_ports),
                            "claim": (
                                "transport-layer pressure indicator; "
                                "not proof of service outage"
                            ),
                        },
                    )
                )

            if port in self.ADMIN_PORTS:
                admin = self._record("admin-service-attempt-pressure", event, source, 30)
                if (
                    len(admin) >= self.thresholds.admin_service_attempts
                    and self._may_emit(
                        "admin-service-attempt-pressure",
                        event,
                        source,
                        30,
                    )
                ):
                    admin_destinations = {
                        item.dst_ip for item in admin if item.dst_ip is not None
                    }
                    findings.append(
                        self._finding(
                            event,
                            "admin-service-attempt-pressure",
                            "High-rate administrative-service connection attempts",
                            Severity.MEDIUM,
                            0.76,
                            (
                                f"{len(admin)} connection attempts to administrative "
                                f"services across {len(admin_destinations)} targets in 30s"
                            ),
                            {
                                "window_seconds": 30,
                                "attempts": len(admin),
                                "unique_destinations": len(admin_destinations),
                                "ports": sorted(
                                    {
                                        item.dst_port
                                        for item in admin
                                        if item.dst_port is not None
                                    }
                                ),
                                "claim": (
                                    "connection-attempt pressure only; "
                                    "not evidence of authentication failure or success"
                                ),
                            },
                        )
                    )

        if protocol == "udp" and source != "unknown":
            udp = self._record("udp-flood-shape", event, source, 10)
            destinations = {item.dst_ip for item in udp if item.dst_ip}
            if (
                len(udp) >= self.thresholds.udp_flood_events
                and len(destinations) <= 3
                and self._may_emit("udp-flood-shape", event, source, 10)
            ):
                findings.append(
                    self._finding(
                        event,
                        "udp-flood-shape",
                        "UDP flood-pressure shape",
                        Severity.HIGH,
                        0.81,
                        (
                            f"{len(udp)} UDP observations concentrated on "
                            f"{len(destinations)} destination(s) in 10s"
                        ),
                        {
                            "window_seconds": 10,
                            "observations": len(udp),
                            "unique_destinations": len(destinations),
                            "claim": (
                                "traffic-pressure indicator; "
                                "not proof of application or link exhaustion"
                            ),
                        },
                    )
                )

        icmp_type = str(event.attributes.get("icmp_type") or "").casefold()
        if protocol == "icmp":
            icmp_pressure = self._record("icmp-flood-shape", event, source, 10)
            pressure_destinations = {
                item.dst_ip for item in icmp_pressure if item.dst_ip
            }
            if (
                len(icmp_pressure) >= self.thresholds.icmp_flood_events
                and len(pressure_destinations) <= 3
                and self._may_emit("icmp-flood-shape", event, source, 10)
            ):
                findings.append(
                    self._finding(
                        event,
                        "icmp-flood-shape",
                        "ICMP flood-pressure shape",
                        Severity.HIGH,
                        0.80,
                        (
                            f"{len(icmp_pressure)} ICMP observations concentrated on "
                            f"{len(pressure_destinations)} destination(s) in 10s"
                        ),
                        {
                            "window_seconds": 10,
                            "observations": len(icmp_pressure),
                            "unique_destinations": len(pressure_destinations),
                            "claim": (
                                "traffic-pressure indicator; "
                                "not proof of host or link exhaustion"
                            ),
                        },
                    )
                )

        if protocol == "icmp" and icmp_type in {"8", "echo-request", "echo_request"}:
            discovery = self._record("icmp-host-discovery", event, source, 15)
            destinations = {item.dst_ip for item in discovery if item.dst_ip}
            if (
                len(discovery) >= 14
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
                        (
                            f"{len(discovery)} ICMP echo requests reached "
                            f"{len(destinations)} hosts in 15s"
                        ),
                        {
                            "window_seconds": 15,
                            "requests": len(discovery),
                            "unique_destinations": len(destinations),
                            "claim": "host-discovery shape; intent is not established",
                        },
                    )
                )

        if event.category.casefold() == "dns.query":
            dns_rate = self._record("dns-query-rate", event, source, 10)
            if (
                len(dns_rate) >= self.thresholds.dns_rate_queries
                and self._may_emit("dns-query-rate", event, source, 10)
            ):
                findings.append(
                    self._finding(
                        event,
                        "dns-query-rate",
                        "Abnormal DNS query-rate pattern",
                        Severity.MEDIUM,
                        0.75,
                        f"{len(dns_rate)} DNS queries observed from the source in 10s",
                        {
                            "window_seconds": 10,
                            "queries": len(dns_rate),
                            "claim": "query-rate anomaly; intent is not established",
                        },
                    )
                )

            query = self._text(
                event.attributes.get("dns_query")
                or event.attributes.get("query_name"),
                1024,
            )
            if query and self._dns_tunnel_shaped(query):
                shaped = self._record(
                    "dns-tunnel-shape",
                    event,
                    source,
                    30,
                    value=query.casefold(),
                )
                unique_queries = {item.value for item in shaped if item.value}
                if (
                    len(shaped) >= self.thresholds.dns_tunnel_queries
                    and len(unique_queries) >= 15
                    and self._may_emit("dns-tunnel-shape", event, source, 30)
                ):
                    findings.append(
                        self._finding(
                            event,
                            "dns-tunnel-shape",
                            "DNS tunneling-shaped query pattern",
                            Severity.HIGH,
                            0.83,
                            (
                                f"{len(shaped)} long/high-diversity DNS queries with "
                                f"{len(unique_queries)} unique names in 30s"
                            ),
                            {
                                "window_seconds": 30,
                                "suspicious_queries": len(shaped),
                                "unique_queries": len(unique_queries),
                                "claim": (
                                    "tunneling-shaped DNS behavior; "
                                    "not proof of data exfiltration"
                                ),
                            },
                        )
                    )

        arp_opcode = str(event.attributes.get("arp_opcode") or "").casefold()
        if (
            event.category.casefold() == "arp.request"
            or protocol == "arp" and arp_opcode in {"1", "request"}
        ):
            arp_target = self._text(
                event.attributes.get("arp_target_ip") or event.dst_ip,
                64,
            )
            arp = self._record(
                "arp-discovery-sweep",
                event,
                source,
                10,
                dst_ip=arp_target,
            )
            targets = {item.dst_ip for item in arp if item.dst_ip}
            if (
                len(arp) >= self.thresholds.arp_sweep_requests
                and len(targets) >= 20
                and self._may_emit("arp-discovery-sweep", event, source, 10)
            ):
                findings.append(
                    self._finding(
                        event,
                        "arp-discovery-sweep",
                        "ARP discovery sweep pattern",
                        Severity.MEDIUM,
                        0.79,
                        (
                            f"{len(arp)} ARP requests addressed "
                            f"{len(targets)} unique targets in 10s"
                        ),
                        {
                            "window_seconds": 10,
                            "requests": len(arp),
                            "unique_targets": len(targets),
                            "claim": "local discovery shape; intent is not established",
                        },
                    )
                )

        direction = str(event.attributes.get("direction") or "").casefold()
        if direction == "east-west" and port in {22, 445, 3389} and source != "unknown":
            lateral = self._record("internal-lateral-sweep", event, source, 30)
            destinations = {item.dst_ip for item in lateral if item.dst_ip}
            if (
                len(lateral) >= 12
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
                            f"{len(lateral)} east-west attempts to administrative "
                            f"services across {len(destinations)} internal targets in 30s"
                        ),
                        {
                            "window_seconds": 30,
                            "attempts": len(lateral),
                            "unique_destinations": len(destinations),
                            "ports": sorted(
                                {
                                    item.dst_port
                                    for item in lateral
                                    if item.dst_port is not None
                                }
                            ),
                            "claim": (
                                "lateral-movement indicator; "
                                "not proof of successful access"
                            ),
                        },
                    )
                )

        if source != "unknown" and protocol in {"tcp", "udp"} and event.dst_ip:
            beacon = self._beacon_finding(event, source, protocol, port)
            if beacon is not None:
                findings.append(beacon)

        return findings
