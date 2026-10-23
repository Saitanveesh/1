import "./IncidentWorkspace.css";
import type { Finding, Incident } from "./types";

function incidentSource(incident: Incident, findings: Finding[]): string {
  // Incident.entities can contain the victim. A generic IP is NOT evidence
  // of an attacker/source address; require a corresponding finding.src_ip.
  const source = findings.find(finding =>
    Boolean(finding.src_ip) &&
    incident.detector_ids.includes(finding.detector_id) &&
    incident.entities.includes(finding.src_ip!)
  );
  return source?.src_ip || "Unknown Source";
}

export default function IncidentQueue({
  incidents, findings = [], selectedId, onSelect
}: {
  incidents: Incident[];
  findings?: Finding[];
  selectedId: string | null;
  onSelect: (incident: Incident) => void;
}) {
  const rows = [...incidents].sort((a, b) => b.last_seen.localeCompare(a.last_seen));
  return <aside className="mon-case-queue" data-testid="incident-case-queue">
    <header className="mon-case-queue-head">
      
      <h2>Security cases <b>{rows.length}</b></h2>
      <p>Cases can remain open after activity stops. Select one to review the evidence.</p>
    </header>
    <div className="mon-case-queue-list">
      {rows.map(incident =>
        <article key={incident.incident_id}
          data-testid="incident-row"
          className={"mon-case-queue-row" +
            (selectedId === incident.incident_id ? " is-selected" : "")}>
          <button type="button" aria-pressed={selectedId === incident.incident_id}
            onClick={() => onSelect(incident)}
            title={incident.title}>
            <span className="mon-case-queue-overline">
              <span className={"severity " + incident.severity.toLowerCase()}>{incident.severity}</span>
              <span>{incident.status}</span>
              <span>{Math.round(incident.confidence * 100)}% confidence</span>
            </span>
            <strong>{incident.title}</strong>
            <span className="mon-case-queue-source">{incidentSource(incident, findings)}</span>
            <time dateTime={incident.last_seen}>Updated {new Date(incident.last_seen).toLocaleString()}</time>
          </button>
        </article>
      )}
      {!rows.length && <p className="mon-case-queue-empty">No incidents recorded at this site.</p>}
    </div>
  </aside>;
}
