import "./IncidentWorkspace.css";
import type { Incident } from "./types";

function incidentSource(incident: Incident): string {
  return incident.entities.find(value =>
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)
  ) ?? incident.entities.find(value => value.startsWith("linux-host:")) ??
    "Unknown Source";
}

export default function IncidentQueue({
  incidents, selectedId, onSelect
}: {
  incidents: Incident[];
  selectedId: string | null;
  onSelect: (incident: Incident) => void;
}) {
  const rows = [...incidents].sort((a, b) => b.last_seen.localeCompare(a.last_seen));
  return <aside className="mon-case-queue" data-testid="incident-case-queue">
    <header className="mon-case-queue-head">
      <span>CASE QUEUE</span>
      <h2>Incidents <b>{rows.length}</b></h2>
      <p>Select a case to inspect its evidence and response history.</p>
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
            <span className="mon-case-queue-source">{incidentSource(incident)}</span>
            <time dateTime={incident.last_seen}>Last seen {new Date(incident.last_seen).toLocaleString()}</time>
          </button>
        </article>
      )}
      {!rows.length && <p className="mon-case-queue-empty">No incidents recorded at this site.</p>}
    </div>
  </aside>;
}
