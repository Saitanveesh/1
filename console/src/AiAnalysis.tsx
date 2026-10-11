import { useEffect, useMemo, useRef, useState } from "react";
import { analyzeIncidentWithLocalAi, ApiError, fetchInvestigation } from "./api";
import type {
  AiIncidentAnalysis,
  AuditRecord,
  EvidenceRef,
  Finding,
  Incident,
  IncidentInvestigation,
  ResponseExecution
} from "./types";
import "./AiAnalysis.css";

type MomentKind = "EVIDENCE" | "FINDING" | "INCIDENT" | "RESPONSE" | "AUDIT";
export interface CaseMoment {
  id: string;
  kind: MomentKind;
  timestamp: string | null;
  headline: string;
  description: string;
  reference: string;
  confidence?: number;
}

function validTime(value: string | undefined | null): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

function matchesAudit(record: AuditRecord, incidentId: string, executionIds: Set<string>): boolean {
  // Never merge unrelated activity from the same site into the incident.
  return record.object_id === incidentId
    || executionIds.has(record.object_id)
    || record.details?.incident_id === incidentId;
}

export function buildCaseTimeline(
  investigation: IncidentInvestigation,
  executions: ResponseExecution[],
  audits: AuditRecord[]
): CaseMoment[] {
  const incidentId = investigation.incident.incident_id;
  const responses = executions.filter(row => row.plan?.request?.incident_id === incidentId);
  const responseIds = new Set(responses.map(row => row.execution_id));
  const rows: CaseMoment[] = [];

  investigation.evidence.forEach((e: EvidenceRef) => {
    rows.push({
      id: "evidence:" + e.evidence_id,
      kind: "EVIDENCE",
      timestamp: validTime(e.observed_at),
      headline: e.summary || "Evidence observed",
      description: e.source + " · " + e.evidence_class,
      reference: e.evidence_id,
      confidence: e.confidence
    });
  });

  investigation.findings.forEach((f: Finding) => {
    rows.push({
      id: "finding:" + f.finding_id,
      kind: "FINDING",
      timestamp: validTime(f.last_seen),
      headline: f.title || f.detector_id,
      description: [f.src_ip, f.dst_ip].filter(Boolean).join(" → ") || f.detector_id,
      reference: f.finding_id,
      confidence: f.confidence
    });
  });

  if (investigation.incident.last_seen) {
    rows.push({
      id: "incident:" + incidentId,
      kind: "INCIDENT",
      timestamp: validTime(investigation.incident.last_seen),
      headline: investigation.incident.title,
      description: "Incident record · " + investigation.incident.status,
      reference: incidentId,
      confidence: investigation.incident.confidence
    });
  }

  responses.forEach(response => {
    const stages: { timestamp: string | undefined; label: string; note: string }[] = [
      { timestamp: response.requested_at, label: "Response requested",
        note: response.plan.request.action + " · " + response.status },
      { timestamp: response.applied_at, label: "Response applied",
        note: response.plan.request.action + " · " + response.status },
      { timestamp: response.rollback_at, label: "Response rolled back",
        note: response.plan.request.action + " · " + response.status }
    ];
    stages.forEach(({ timestamp, label, note }, index) => {
      if (timestamp) rows.push({
        id: "response:" + response.execution_id + ":" + index,
        kind: "RESPONSE",
        timestamp: validTime(timestamp),
        headline: label, description: note, reference: response.execution_id
      });
    });
  });

  audits.filter(record => matchesAudit(record, incidentId, responseIds))
    .forEach(record => {
      rows.push({
        id: "audit:" + record.audit_id,
        kind: "AUDIT",
        timestamp: validTime(record.occurred_at),
        headline: record.action + " · " + record.outcome,
        description: "Audit by " + record.actor_id,
        reference: record.audit_id
      });
    });

  // The input can be incomplete. Null timestamps remain undated, rather
  // than being assigned the present time or an inferred event time.
  return rows.sort((a, b) => {
    if (!a.timestamp) return 1;
    if (!b.timestamp) return -1;
    return a.timestamp.localeCompare(b.timestamp) || a.id.localeCompare(b.id);
  });
}

function isoLabel(value: string | null): string {
  return value ? value.replace("T", " ").replace("Z", " UTC") : "TIME UNAVAILABLE";
}

function percent(value: number): string {
  return Number.isFinite(value) ? Math.round(value * 100) + "%" : "—";
}

function compactRef(value: string): string {
  return value.length > 39 ? value.slice(0, 20) + "…" + value.slice(-12) : value;
}

function graphLabels(investigation: IncidentInvestigation) {
  const findingWithSource = investigation.findings.find(row => row.src_ip);
  const incidentIp = investigation.incident.entities.find(value =>
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)
  );
  const source = findingWithSource?.src_ip ?? incidentIp ?? "SOURCE UNKNOWN";
  const firstAsset = investigation.affected_assets[0];
  const target = firstAsset?.display_name
    ?? investigation.incident.affected_asset_ids[0]
    ?? "TARGET UNKNOWN";
  const targetIp = firstAsset?.ip_addresses?.[0] ?? "";
  return { source, target, targetIp };
}

function TimelineStrip({
  moments,
  currentId,
  onPick
}: {
  moments: CaseMoment[];
  currentId: string | null;
  onPick: (id: string) => void;
}) {
  const dated = moments.filter(row => !!row.timestamp);
  const times = dated.map(row => Date.parse(row.timestamp!));
  const min = times.length ? Math.min(...times) : 0;
  const max = times.length ? Math.max(...times) : 0;
  return (
    <section className="aiwb-panel aiwb-timeline" data-testid="ai-timeline">
      <div className="aiwb-section-top">
        <div><span className="aiwb-kicker">01 / SEQUENCE</span><h3>Evidence timeline</h3></div>
        <span className="aiwb-dim">{dated.length} timestamped · {moments.length - dated.length} undated</span>
      </div>
      {dated.length > 0 ? (
        <>
          <div className="aiwb-rail" role="group" aria-label="Timestamped incident events">
            <div className="aiwb-rail-line" />
            {dated.map((moment, index) => {
              const x = max === min
                ? 50 : 4 + 92 * ((Date.parse(moment.timestamp!) - min) / (max - min));
              return (
                <button
                  type="button"
                  key={moment.id}
                  className={"aiwb-rail-point" + (currentId === moment.id ? " is-selected" : "")}
                  style={{ left: x + "%", transform: "translateX(-50%) translateY(" + ((index % 3) * 3) + "px)" }}
                  title={isoLabel(moment.timestamp) + " · " + moment.headline}
                  aria-label={moment.kind + ": " + moment.headline + " at " + isoLabel(moment.timestamp)}
                  onClick={() => onPick(moment.id)}
                />
              );
            })}
          </div>
          <div className="aiwb-rail-times">
            <span>{isoLabel(dated[0].timestamp)}</span>
            <span>{isoLabel(dated[dated.length - 1].timestamp)}</span>
          </div>
        </>
      ) : <p className="aiwb-placeholder">No dated evidence is available for this incident.</p>}
      <div className="aiwb-events">
        {moments.map((moment, index) =>
          <button
            type="button"
            key={moment.id}
            data-testid="ai-timeline-event"
            className={"aiwb-event" + (currentId === moment.id ? " is-selected" : "")}
            onClick={() => onPick(moment.id)}
          >
            <span className="aiwb-event-index">{String(index + 1).padStart(2, "0")}</span>
            <span className="aiwb-event-copy">
              <small>{moment.kind} / {isoLabel(moment.timestamp)}</small>
              <strong>{moment.headline}</strong>
              <span>{moment.description}</span>
            </span>
            <span className="aiwb-event-arrow" aria-hidden="true">↗</span>
          </button>
        )}
        {!moments.length && <div className="aiwb-placeholder">MON returned no incident events. No sequence can be reconstructed.</div>}
      </div>
    </section>
  );
}

export default function AiAnalysis({
  incidents,
  tenantId,
  siteId,
  executions,
  auditRecords,
  onOpenIncident
}: {
  incidents: Incident[];
  tenantId: string;
  siteId: string;
  executions: ResponseExecution[];
  auditRecords: AuditRecord[];
  onOpenIncident: (incident: Incident) => void;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [investigation, setInvestigation] = useState<IncidentInvestigation | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [ai, setAi] = useState<AiIncidentAnalysis | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [activeMoment, setActiveMoment] = useState<string | null>(null);
  const [refreshCount, setRefreshCount] = useState(0);
  const requestId = useRef(0);

  const ordered = useMemo(
    () => [...incidents].sort((a, b) => b.last_seen.localeCompare(a.last_seen)),
    [incidents]
  );
  const chosenId = selectedId && ordered.some(row => row.incident_id === selectedId)
    ? selectedId : ordered[0]?.incident_id ?? null;
  const chosen = ordered.find(row => row.incident_id === chosenId);

  useEffect(() => {
    if (!chosenId) {
      setInvestigation(null);
      setLoadError(null);
      return;
    }
    const current = ++requestId.current;
    setInvestigation(null);
    setAi(null);
    setAiError(null);
    setAiLoading(false);
    setActiveMoment(null);
    setLoading(true);
    setLoadError(null);
    fetchInvestigation(chosenId, tenantId, siteId)
      .then(value => {
        if (current !== requestId.current) return;
        if (value.incident.incident_id !== chosenId) {
          setLoadError("Investigation response does not match selected incident");
          return;
        }
        setInvestigation(value);
      })
      .catch((error: unknown) => {
        if (current === requestId.current) {
          setLoadError(error instanceof ApiError ? "Investigation API: HTTP " + error.status
            : "Incident evidence unavailable");
        }
      })
      .finally(() => {
        if (current === requestId.current) setLoading(false);
      });
    return () => { requestId.current += 1; };
  }, [chosenId, tenantId, siteId, refreshCount]);

  const moments = useMemo(
    () => investigation ? buildCaseTimeline(investigation, executions, auditRecords) : [],
    [investigation, executions, auditRecords]
  );
  const selectedMoment = moments.find(row => row.id === activeMoment) ?? moments[0] ?? null;
  const correlated = investigation ? graphLabels(investigation) : null;
  const caseResponses = chosenId
    ? executions.filter(row => row.plan?.request?.incident_id === chosenId) : [];

  async function askLocalModel() {
    if (!chosenId || !investigation || aiLoading) return;
    const active = ++requestId.current;
    setAiLoading(true);
    setAiError(null);
    try {
      const result = await analyzeIncidentWithLocalAi(chosenId, tenantId, siteId);
      if (active === requestId.current && result.incident_id === chosenId) setAi(result);
    } catch (error: unknown) {
      if (active === requestId.current) setAiError(
        error instanceof ApiError ? "Local AI unavailable (HTTP " + error.status + ")"
          : "Local AI analysis failed"
      );
    } finally {
      if (active === requestId.current) setAiLoading(false);
    }
  }

  return (
    <div className="aiwb" data-testid="ai-analysis-workspace">
      <section className="aiwb-intro">
        <div className="aiwb-intro-main">
          <span className="aiwb-kicker">MON / EVIDENCE INTELLIGENCE / LOCAL INFERENCE</span>
          <h2>Incident Reconstruction</h2>
          <p>Evidence first. A timestamped investigation of what MON observed, correlated with local AI advice.</p>
        </div>
        <div className="aiwb-intro-status">
          <span className="aiwb-live-dot" />
          <strong>READ-ONLY ANALYSIS</strong>
          <small>QWEN3 4B · PC2 LOCAL</small>
        </div>
      </section>

      <section className="aiwb-case-selector">
        <label htmlFor="aiwb-case">CASE FILE</label>
        <select
          id="aiwb-case" data-testid="ai-case-select"
          value={chosenId ?? ""}
          onChange={event => setSelectedId(event.target.value)}
          disabled={!ordered.length}
        >
          {!ordered.length && <option value="">No available incidents</option>}
          {ordered.map(row =>
            <option key={row.incident_id} value={row.incident_id}>
              {row.title} · {row.incident_id.slice(0, 8)} · {row.severity}
            </option>
          )}
        </select>
        <button type="button" className="aiwb-secondary" disabled={!chosenId}
          onClick={() => setRefreshCount(count => count + 1)}>
          REFRESH EVIDENCE
        </button>
        {chosen && <button type="button" className="aiwb-secondary"
          onClick={() => onOpenIncident(chosen)}>OPEN CASE ↗</button>}
      </section>

      {!chosen && <div className="aiwb-placeholder aiwb-no-case">
        No incident records exist for this site. The reconstruction view will populate when MON detects an incident.
      </div>}
      {chosen && loading && <div className="aiwb-loading" role="status">Retrieving case evidence from MON…</div>}
      {chosen && loadError && <div className="aiwb-load-error" role="alert">{loadError}</div>}
      {chosen && investigation && (
        <>
          <section className="aiwb-metrics">
            <div><small>SEVERITY</small><strong>{chosen.severity}</strong></div>
            <div><small>CONFIDENCE</small><strong>{percent(chosen.confidence)}</strong></div>
            <div><small>MON EVIDENCE</small><strong>{investigation.evidence.length}</strong></div>
            <div><small>DETECTORS</small><strong>{investigation.findings.length}</strong></div>
            <div><small>RESPONSES</small><strong>{caseResponses.length}</strong></div>
          </section>

          <section className="aiwb-panel aiwb-correlation" data-testid="ai-case-correlation">
            <div className="aiwb-section-top">
              <div><span className="aiwb-kicker">CORRELATED ENTITIES</span><h3>Who contacted whom?</h3></div>
              <span className="aiwb-dim">EVIDENCE RELATIONSHIP · NOT A PACKET HOP TRACE</span>
            </div>
            <div className="aiwb-correlation-map">
              <div className="aiwb-map-node">
                <small>OBSERVED SOURCE</small>
                <strong>{correlated?.source}</strong>
                <span>From finding / incident entity</span>
              </div>
              <div className="aiwb-map-connector">
                <span className="aiwb-map-link" />
                <span>{investigation.evidence.length} EVIDENCE</span>
              </div>
              <div className="aiwb-map-node aiwb-map-target">
                <small>AFFECTED ASSET</small>
                <strong>{correlated?.target}</strong>
                <span>{correlated?.targetIp || "IP NOT RESOLVED"}</span>
              </div>
            </div>
            <p className="aiwb-honesty">This diagram shows MON's correlated source, evidence and affected asset. It does not assert intermediate routers, packet timing, or actions without records.</p>
          </section>

          <div className="aiwb-columns">
            <TimelineStrip moments={moments} currentId={selectedMoment?.id ?? null}
              onPick={setActiveMoment} />
            <div className="aiwb-inspector">
              <section className="aiwb-panel">
                <div className="aiwb-section-top">
                  <div><span className="aiwb-kicker">02 / EVIDENCE INSPECTOR</span><h3>Selected observation</h3></div>
                </div>
                {selectedMoment ? (
                  <div className="aiwb-selected-detail" data-testid="ai-selected-evidence">
                    <span className="aiwb-detail-kind">{selectedMoment.kind}</span>
                    <h4>{selectedMoment.headline}</h4>
                    <div className="aiwb-detail-pair"><span>TIME (UTC)</span><strong>{isoLabel(selectedMoment.timestamp)}</strong></div>
                    <div className="aiwb-detail-pair"><span>SOURCE / NOTE</span><strong>{selectedMoment.description}</strong></div>
                    <div className="aiwb-detail-pair"><span>RECORD ID</span><code title={selectedMoment.reference}>{compactRef(selectedMoment.reference)}</code></div>
                    {selectedMoment.confidence !== undefined &&
                      <div className="aiwb-detail-pair"><span>CONFIDENCE</span><strong>{percent(selectedMoment.confidence)}</strong></div>}
                  </div>
                ) : <p className="aiwb-placeholder">No evidence selected.</p>}
              </section>

              <section className="aiwb-panel aiwb-ai-box" data-testid="ai-model-investigation">
                <div className="aiwb-section-top">
                  <div><span className="aiwb-kicker">03 / LOCAL QWEN3 4B</span><h3>AI Analyst Brief</h3></div>
                  <span className="aiwb-ai-local">ON DEVICE</span>
                </div>
                <div className="aiwb-ai-inner">
                  {!ai && <p className="aiwb-ai-empty">Ask the local model to evaluate this case. The timeline and facts above come directly from MON, regardless of model availability.</p>}
                  {ai && <div className="aiwb-ai-results">
                    <div><small>WHAT HAPPENED</small><strong>{ai.headline}</strong></div>
                    <div><small>ASSESSMENT · AI GENERATED</small><p>{ai.assessment}</p></div>
                    <div><small>WHAT TO CHECK NEXT</small><p>{ai.next_check}</p></div>
                    <span>{ai.evidence_count} MON references · {ai.model} · no enforcement</span>
                  </div>}
                  {aiError && <p className="aiwb-ai-failure" role="alert">{aiError}</p>}
                  <button type="button" className="aiwb-action" data-testid="ai-generate-brief"
                    disabled={aiLoading} onClick={() => void askLocalModel()}>
                    {aiLoading ? "ANALYZING ON PC2…" : ai ? "REGENERATE ANALYST BRIEF ↗" : "GENERATE ANALYST BRIEF ↗"}
                  </button>
                </div>
              </section>

              <section className="aiwb-panel aiwb-response-summary">
                <div className="aiwb-section-top">
                  <div><span className="aiwb-kicker">04 / RESPONSE HISTORY</span><h3>What MON did</h3></div>
                </div>
                <div className="aiwb-history">
                  {caseResponses.map(row => <div key={row.execution_id}>
                    <span>{row.plan.request.action}</span><strong>{row.status}</strong>
                    <small>{isoLabel(validTime(row.requested_at))}</small>
                  </div>)}
                  {!caseResponses.length && <p className="aiwb-placeholder">
                    No response execution is directly linked to this incident in the current snapshot.
                  </p>}
                </div>
              </section>
            </div>
          </div>
          <footer className="aiwb-footer">
            <span>Evidence timestamps are shown in UTC. Different sensors may have clock differences.</span>
            <span>Only retained MON evidence is shown · AI is advisory · no response action in this view.</span>
          </footer>
        </>
      )}
    </div>
  );
}
