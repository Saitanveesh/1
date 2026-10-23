import type { Finding, Incident, LiveEnvelope, Severity } from "./types";

export interface SecurityThreatAlert {
  key: string;
  incidentId?: string;
  signatureId?: number;
  title: string;
  severity: Severity;
  source: string;
  target: string;
  attackClass: string;
  observedAt: string;
  detector: string;
}

const rank: Record<Severity, number> = {
  INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4
};

function qualifies(severity: Severity): boolean {
  return rank[severity] >= rank.MEDIUM;
}

function linkedFinding(incident: Incident, findings: Finding[]): Finding | undefined {
  return findings.find(finding => incident.detector_ids.includes(finding.detector_id)) ??
    findings.find(finding => incident.entities.includes(finding.src_ip ?? ""));
}

function fromIncident(incident: Incident, finding: Finding | undefined, key: string): SecurityThreatAlert {
  return {
    key,
    incidentId: incident.incident_id,
    title: incident.title,
    severity: incident.severity,
    source: finding?.src_ip || "Unknown Source",
    target: finding?.dst_ip || finding?.asset_id || incident.affected_asset_ids[0] || "Unresolved target",
    attackClass: finding?.detector_id || incident.detector_ids[0] || "Security anomaly",
    observedAt: incident.last_seen,
    detector: finding?.detector_id || incident.detector_ids[0] || "MON detection"
  };
}

function fromFinding(finding: Finding): SecurityThreatAlert {
  return {
    key: "finding:" + finding.finding_id,
    title: finding.title,
    severity: finding.severity,
    source: finding.src_ip || "Unknown Source",
    target: finding.dst_ip || finding.asset_id || "Unresolved target",
    attackClass: finding.detector_id,
    observedAt: finding.last_seen,
    detector: finding.detector_id
  };
}

/**
 * Alert only for new, evidence-backed events received over the live stream.
 * Snapshot hydration, heartbeats, repeated incident updates, and response
 * execution messages must never trigger the intrusion overlay.
 */
export function selectSecurityAlert(
  envelope: LiveEnvelope,
  previous: { incidents: Incident[]; findings: Finding[] }
): SecurityThreatAlert | null {
  if (envelope.kind === "event.processed") {
    const result = envelope.payload.result as
      | { incidents?: Incident[]; findings?: Finding[] }
      | undefined;
    if (!result) return null;
    const newIncidents = (result.incidents ?? []).filter(incident =>
      incident.status !== "CLOSED" &&
      qualifies(incident.severity) &&
      !previous.incidents.some(old => old.incident_id === incident.incident_id)
    );
    const incident = newIncidents.sort((a, b) =>
      rank[b.severity] - rank[a.severity]
    )[0];
    if (incident) {
      const finding = linkedFinding(incident, result.findings ?? previous.findings);
      return fromIncident(incident, finding, "incident:" + incident.incident_id);
    }
    const finding = (result.findings ?? []).filter(item =>
      qualifies(item.severity) &&
      !previous.findings.some(old => old.finding_id === item.finding_id)
    ).sort((a, b) => rank[b.severity] - rank[a.severity])[0];
    return finding ? fromFinding(finding) : null;
  }

  if (envelope.kind === "incident.updated") {
    const incident = envelope.payload.incident as Incident | undefined;
    if (!incident || incident.status === "CLOSED" || !qualifies(incident.severity)) {
      return null;
    }
    const prior = previous.incidents.find(item => item.incident_id === incident.incident_id);
    // New case or actual severity escalation; repeated refreshes are not alerts.
    if (prior && rank[incident.severity] <= rank[prior.severity]) return null;
    return fromIncident(
      incident,
      linkedFinding(incident, previous.findings),
      "incident:" + incident.incident_id + ":" + incident.severity
    );
  }

  return null;
}
