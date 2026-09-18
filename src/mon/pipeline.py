from __future__ import annotations

from mon.attack_graph import AttackGraphEngine
from mon.correlation import CorrelationEngine
from mon.detection import DetectionEngine
from mon.domain import EventProcessingResult, SecurityEvent
from mon.store import InMemoryStore


class SecurityPipeline:
    """Shared evidence pipeline used by the SaaS control plane and local site controller."""

    def __init__(
        self,
        store: InMemoryStore | None = None,
        detector: DetectionEngine | None = None,
        graph: AttackGraphEngine | None = None,
        correlator: CorrelationEngine | None = None,
    ) -> None:
        self.store = store or InMemoryStore()
        self.detector = detector or DetectionEngine()
        self.graph = graph or AttackGraphEngine()
        self.correlator = correlator or CorrelationEngine()

    def reset(self) -> None:
        self.store.__init__()
        self.detector.reset()
        self.graph.reset()
        self.correlator.reset()

    def process_event(self, event: SecurityEvent) -> EventProcessingResult:
        if self.store.event_exists(event.tenant_id, event.site_id, event.event_id):
            return EventProcessingResult(event=event, duplicate=True)

        stored = self.store.add_event(event)
        self.graph.observe_event(event)
        findings = self.detector.process(event)
        incidents = []
        for finding in findings:
            self.store.add_finding(finding)
            self.graph.attach_finding(finding)
            incidents.append(self.correlator.process(finding, self.store))

        return EventProcessingResult(
            event=stored,
            findings=findings,
            incidents=incidents,
            duplicate=False,
        )
