from __future__ import annotations

import threading
from enum import StrEnum

from mon.asset_engine import AssetEngine
from mon.attack_graph import AttackGraphEngine
from mon.correlation import CorrelationEngine
from mon.detection import DetectionEngine
from mon.domain import EventProcessingResult, SecurityEvent
from mon.store import InMemoryStore, PipelineStore
from mon.telemetry import TelemetryEngine


class PipelinePersistenceMode(StrEnum):
    MEMORY_ONLY = "MEMORY_ONLY"
    DURABLE_RESTORED = "DURABLE_RESTORED"


class SecurityPipeline:
    """Shared evidence pipeline used by the SaaS control plane and local site controller."""

    def __init__(
        self,
        store: PipelineStore | None = None,
        detector: DetectionEngine | None = None,
        graph: AttackGraphEngine | None = None,
        correlator: CorrelationEngine | None = None,
        telemetry: TelemetryEngine | None = None,
        *,
        persistence_mode: PipelinePersistenceMode = PipelinePersistenceMode.MEMORY_ONLY,
    ) -> None:
        self.store = store or InMemoryStore()
        self.detector = detector or DetectionEngine()
        self.graph = graph or AttackGraphEngine()
        self.correlator = correlator or CorrelationEngine()
        self.asset_engine = AssetEngine(self.store)
        self.telemetry = telemetry or TelemetryEngine()
        self.persistence_mode = persistence_mode
        self.last_restore: dict[str, int] | None = None
        self._lock = threading.RLock()

    def reset(self) -> None:
        with self._lock:
            if isinstance(self.store, InMemoryStore):
                self.store.__init__()
            self.detector.reset()
            self.graph.reset()
            self.correlator.reset()
            self.telemetry.reset()
            self.last_restore = None

    def restore_scope(self, tenant_id: str, site_id: str) -> dict[str, int]:
        """Rebuild bounded in-memory engines from durable local evidence state."""
        with self._lock:
            self.detector.reset()
            self.graph.reset()
            self.correlator.reset()
            self.telemetry.reset()

            events = self.store.list_events(tenant_id, site_id)
            for event in events:
                self.telemetry.observe(event)
                self.graph.observe_event(event)
                # Detector replay intentionally discards generated findings. Its
                # purpose is to rebuild windows/cooldowns; persisted findings remain
                # authoritative and are attached below.
                self.detector.process(event)

            findings = self.store.list_findings(tenant_id, site_id)
            attached = 0
            for finding in findings:
                attached += self.graph.attach_finding(finding)

            incidents = self.store.list_incidents(tenant_id, site_id)
            correlation_pointers = self.correlator.restore(findings, incidents)
            restored = {
                "events": len(events),
                "findings": len(findings),
                "incidents": len(incidents),
                "graph_finding_attachments": attached,
                "correlation_pointers": correlation_pointers,
            }
            self.last_restore = restored
            return restored

    def process_event(self, event: SecurityEvent) -> EventProcessingResult:
        with self._lock:
            if self.store.event_exists(event.tenant_id, event.site_id, event.event_id):
                return EventProcessingResult(event=event, duplicate=True)

            stored = self.store.add_event(event)
            asset = self.asset_engine.observe(event)
            telemetry = self.telemetry.observe(event)
            self.graph.observe_event(event)
            findings = self.detector.process(event)
            incidents = []
            for finding in findings:
                self.store.add_finding(finding)
                self.graph.attach_finding(finding)
                incidents.append(self.correlator.process(finding, self.store))

            return EventProcessingResult(
                event=stored,
                asset_updates=[asset] if asset is not None else [],
                telemetry=telemetry,
                findings=findings,
                incidents=incidents,
                duplicate=False,
            )
