from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Protocol

from mon.domain import Finding, Incident, IncidentStatus, Severity, utcnow


class IncidentRepository(Protocol):
    def add_incident(self, incident: Incident) -> Incident: ...

    def get_incident(
        self,
        tenant_id: str,
        site_id: str,
        incident_id: str,
    ) -> Incident | None: ...


@dataclass
class _ActiveIncident:
    incident_id: str
    last_seen: dt.datetime


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class CorrelationEngine:
    """Correlate findings by observed actor without inventing causal certainty."""

    def __init__(self, window_seconds: int = 300) -> None:
        self.window_seconds = window_seconds
        self._active: dict[tuple[str, str, str], _ActiveIncident] = {}

    def reset(self) -> None:
        self._active.clear()

    @staticmethod
    def _actor(finding: Finding) -> str:
        return finding.asset_id or finding.src_ip or finding.dst_ip or finding.finding_id

    @staticmethod
    def _severity(left: Severity, right: Severity) -> Severity:
        return left if _SEVERITY_RANK[left] >= _SEVERITY_RANK[right] else right

    def process(self, finding: Finding, repository: IncidentRepository) -> Incident:
        actor = self._actor(finding)
        key = (finding.tenant_id, finding.site_id, actor)
        active = self._active.get(key)

        incident: Incident | None = None
        if active is not None:
            age = (finding.last_seen - active.last_seen).total_seconds()
            if 0 <= age <= self.window_seconds:
                candidate = repository.get_incident(
                    finding.tenant_id,
                    finding.site_id,
                    active.incident_id,
                )
                if candidate and candidate.status in {
                    IncidentStatus.OPEN,
                    IncidentStatus.INVESTIGATING,
                }:
                    incident = candidate

        entities = {value for value in (finding.asset_id, finding.src_ip, finding.dst_ip) if value}
        affected = {finding.asset_id} if finding.asset_id else set()

        if incident is None:
            incident = Incident(
                tenant_id=finding.tenant_id,
                site_id=finding.site_id,
                title=finding.title,
                severity=finding.severity,
                confidence=finding.confidence,
                evidence=list(finding.evidence),
                affected_asset_ids=affected,
                finding_ids={finding.finding_id},
                detector_ids={finding.detector_id},
                entities=entities,
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
            )
        else:
            evidence_by_id = {item.evidence_id: item for item in incident.evidence}
            evidence_by_id.update({item.evidence_id: item for item in finding.evidence})
            detector_ids = incident.detector_ids | {finding.detector_id}
            title = incident.title
            if len(detector_ids) > 1:
                title = f"Correlated suspicious activity involving {actor}"

            incident = incident.model_copy(
                update={
                    "title": title,
                    "severity": self._severity(incident.severity, finding.severity),
                    "confidence": max(incident.confidence, finding.confidence),
                    "evidence": list(evidence_by_id.values()),
                    "affected_asset_ids": incident.affected_asset_ids | affected,
                    "finding_ids": incident.finding_ids | {finding.finding_id},
                    "detector_ids": detector_ids,
                    "entities": incident.entities | entities,
                    "first_seen": min(incident.first_seen, finding.first_seen),
                    "last_seen": max(incident.last_seen, finding.last_seen),
                    "updated_at": utcnow(),
                }
            )

        repository.add_incident(incident)
        self._active[key] = _ActiveIncident(
            incident_id=incident.incident_id,
            last_seen=finding.last_seen,
        )
        return incident
