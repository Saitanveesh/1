from __future__ import annotations

import datetime as dt
import threading
import uuid
from enum import StrEnum

from mon.analysis_checkpoint import AnalysisCheckpointPayload
from mon.asset_engine import AssetEngine
from mon.attack_graph import AttackGraphEngine
from mon.correlation import CorrelationEngine
from mon.detection import DetectionEngine
from mon.domain import EventProcessingResult, SecurityEvent
from mon.identity_engine import IdentityProcessEngine
from mon.store import (
    AnalysisCheckpointStore,
    InMemoryStore,
    PipelineStore,
    TransactionalPipelineStore,
)
from mon.telemetry import TelemetryEngine
from mon.threat_intel import ThreatIntelRepository, match_event_indicators


class PipelinePersistenceMode(StrEnum):
    MEMORY_ONLY = "MEMORY_ONLY"
    DURABLE_RESTORED = "DURABLE_RESTORED"
    DURABLE_CHECKPOINT_RESTORED = "DURABLE_CHECKPOINT_RESTORED"


class PipelineStateError(RuntimeError):
    pass


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
        self.identity_engine = IdentityProcessEngine(self.store)  # type: ignore[arg-type]
        self.telemetry = telemetry or TelemetryEngine()
        self.persistence_mode = persistence_mode
        self.last_restore: dict[str, object] | None = None
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

    def restore_scope(self, tenant_id: str, site_id: str) -> dict[str, object]:
        """Rebuild bounded in-memory engines from durable local evidence state."""
        with self._lock:
            if isinstance(self.store, TransactionalPipelineStore):
                unprocessed = self.store.list_unprocessed_events(tenant_id, site_id)
                if unprocessed:
                    raise PipelineStateError(
                        "durable local analysis contains events without atomic "
                        "processing receipts"
                    )

            checkpoint = None
            if isinstance(self.store, AnalysisCheckpointStore):
                checkpoints = self.store.iter_analysis_checkpoints(tenant_id, site_id)
                checkpoint = checkpoints[0] if checkpoints else None

            self.detector.reset()
            self.graph.reset()
            self.correlator.reset()
            self.telemetry.reset()

            if checkpoint is not None:
                self.detector.restore_checkpoint(tenant_id, site_id, checkpoint.detector)
                self.telemetry.restore_checkpoint(tenant_id, site_id, checkpoint.telemetry)
                self.graph.restore_checkpoint(checkpoint.attack_graph)
                self.correlator.restore_checkpoint(
                    tenant_id,
                    site_id,
                    checkpoint.correlation,
                )
                replay_source = self.store.list_events(
                    tenant_id,
                    site_id,
                    since=checkpoint.boundary_observed_at,
                )
                events = [
                    event
                    for event in replay_source
                    if (
                        event.observed_at,
                        event.event_id,
                    )
                    > (
                        checkpoint.boundary_observed_at,
                        checkpoint.boundary_event_id,
                    )
                ]
            else:
                events = self.store.list_events(tenant_id, site_id)

            for event in events:
                self.identity_engine.observe(event)
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
                "checkpoint_used": 1 if checkpoint is not None else 0,
            }
            if checkpoint is not None:
                restored["checkpoint_boundary_replayed_events"] = len(events)
                restored["checkpoint_boundary_event"] = checkpoint.boundary_event_id
                self.persistence_mode = (
                    PipelinePersistenceMode.DURABLE_CHECKPOINT_RESTORED
                )
            self.last_restore = restored
            return restored

    def create_analysis_checkpoint(
        self,
        tenant_id: str,
        site_id: str,
    ) -> AnalysisCheckpointPayload | None:
        if not isinstance(self.store, AnalysisCheckpointStore):
            return None
        with self._lock:
            events = self.store.list_events(tenant_id, site_id)
            if not events:
                return None
            boundary = events[-1]
            checkpoint = AnalysisCheckpointPayload(
                tenant_id=tenant_id,
                site_id=site_id,
                checkpoint_id=str(uuid.uuid4()),
                created_at=dt.datetime.now(dt.UTC),
                boundary_event_id=boundary.event_id,
                boundary_observed_at=boundary.observed_at,
                detector=self.detector.export_checkpoint(tenant_id, site_id),
                telemetry=self.telemetry.export_checkpoint(tenant_id, site_id),
                correlation=self.correlator.export_checkpoint(tenant_id, site_id),
                attack_graph=self.graph.snapshot(tenant_id, site_id),
                asset_analysis={"source": "durable-assets-authoritative"},
            )
            self.store.save_analysis_checkpoint(checkpoint)
            self.store.compact_analysis_checkpoints(retain=3)
            return checkpoint

    def _process_new_event(self, event: SecurityEvent) -> EventProcessingResult:
        stored = self.store.add_event(event)
        asset = self.asset_engine.observe(event)
        identity, process = self.identity_engine.observe(event)
        telemetry = self.telemetry.observe(event)
        self.graph.observe_event(event)
        findings = self.detector.process(event)
        if isinstance(self.store, ThreatIntelRepository):
            findings.extend(match_event_indicators(self.store, event))
        incidents = []
        for finding in findings:
            self.store.add_finding(finding)
            self.graph.attach_finding(finding)
            incidents.append(self.correlator.process(finding, self.store))

        return EventProcessingResult(
            event=stored,
            asset_updates=[
                item for item in (asset,) if item is not None
            ],
            telemetry=telemetry,
            findings=findings,
            incidents=incidents,
            duplicate=False,
            identity_updates=[identity] if identity is not None else [],
            process_updates=[process] if process is not None else [],
        )

    def process_event(self, event: SecurityEvent) -> EventProcessingResult:
        # Stores shared by several control-plane instances expose a per-scope
        # cross-process lock; without it two instances can both pass the
        # duplicate check and one fails on the primary-key insert.
        scope_lock = getattr(self.store, "scope_lock", None)
        if scope_lock is None:
            return self._process_event_serialized(event)
        try:
            with scope_lock(event.tenant_id, event.site_id):
                return self._process_event_serialized(event)
        except TimeoutError as exc:
            raise PipelineStateError(str(exc)) from exc

    def _process_event_serialized(self, event: SecurityEvent) -> EventProcessingResult:
        with self._lock:
            if self.store.event_exists(event.tenant_id, event.site_id, event.event_id):
                if (
                    isinstance(self.store, TransactionalPipelineStore)
                    and not self.store.event_processed(
                        event.tenant_id,
                        event.site_id,
                        event.event_id,
                    )
                ):
                    raise PipelineStateError(
                        "durable event exists without a completed processing receipt"
                    )
                return EventProcessingResult(event=event, duplicate=True)

            if not isinstance(self.store, TransactionalPipelineStore):
                return self._process_new_event(event)

            try:
                with self.store.transaction():
                    result = self._process_new_event(event)
                    self.store.mark_event_processed(event)
                self.create_analysis_checkpoint(event.tenant_id, event.site_id)
                return result
            except Exception:
                # Engine memory may have advanced before the durable transaction
                # failed. Rebuild it from the last committed evidence boundary.
                self.restore_scope(event.tenant_id, event.site_id)
                raise
