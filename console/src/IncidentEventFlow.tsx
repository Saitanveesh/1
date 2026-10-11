import type { IncidentInvestigation, ResponseExecution } from "./types";

interface FlowStep {
  stage: string;
  name: string;
  detail: string;
  timestamp: string | null;
  state: "observed" | "derived" | "recorded";
}

export function buildIncidentSteps(investigation: IncidentInvestigation, responses: ResponseExecution[]): FlowStep[] {
  const incident = investigation.incident;
  const finding = investigation.findings.find(item => item.src_ip) ?? investigation.findings[0];
  const source = finding?.src_ip ??
    incident.entities.find(item => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(item));
  const target = investigation.affected_assets[0];
  const evidence = investigation.evidence.find(item => item.source.includes("journal")) ??
    investigation.evidence[0];
  const response = responses
    .filter(item => item.plan.request.incident_id === incident.incident_id)
    .sort((a, b) => (b.requested_at ?? "").localeCompare(a.requested_at ?? ""))[0];
  const steps: FlowStep[] = [
    {
      stage: "01 / SOURCE",
      name: source ?? "Source unconfirmed",
      detail: source ? "Source IP recorded in an incident finding" : "No source address attached to this case",
      timestamp: null,
      state: "recorded"
    },
    {
      stage: "02 / TARGET + EVIDENCE",
      name: target?.display_name ?? "Target unresolved",
      detail: evidence ? evidence.summary + " · " + evidence.source :
        "MON has not attached endpoint evidence",
      timestamp: evidence?.observed_at ?? null,
      state: "observed"
    },
    {
      stage: "03 / DETECTION",
      name: finding?.detector_id ?? "No detector record",
      detail: finding ? finding.title :
        "No detector finding available for the selected case",
      timestamp: finding?.last_seen ?? incident.last_seen,
      state: "derived"
    },
    {
      stage: "04 / RESPONSE",
      name: response ? response.plan.request.action + " · " + response.status : "No response recorded",
      detail: response ?
        "MON response state; see Response tab for approvals, actions and rollback" :
        "No containment action is recorded for this incident",
      timestamp: response?.applied_at ?? response?.requested_at ?? null,
      state: "recorded"
    }
  ];
  return steps;
}

export default function IncidentEventFlow({
  investigation, responses, compact = false
}: {
  investigation: IncidentInvestigation;
  responses: ResponseExecution[];
  compact?: boolean;
}) {
  const steps = buildIncidentSteps(investigation, responses);
  return <section className={"mon-event-chain" + (compact ? " is-compact" : "")}
    data-testid="incident-event-chain" aria-label="Recorded incident sequence">
    <header>
      <div><small>INCIDENT EXPLAINER / EVIDENCE-BASED</small>
        <h3>How this incident unfolded</h3></div>
      <span>Recorded case sequence, not a verified packet-hop trace</span>
    </header>
    <div className="mon-event-chain-steps">
      {steps.map((step, index) =>
        <div className="mon-event-chain-step" key={step.stage}>
          <span className="mon-event-chain-stage">{step.stage}</span>
          <strong>{step.name}</strong>
          <p>{step.detail}</p>
          <time>{step.timestamp
            ? new Date(step.timestamp).toLocaleString() : "Time not recorded"}</time>
          {index < steps.length - 1 && <b className="mon-event-chain-arrow"
            aria-hidden="true">→</b>}
        </div>
      )}
    </div>
  </section>;
}
