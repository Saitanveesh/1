import { useEffect, useMemo, useState } from "react";
import { LiveClient, type LiveState } from "./live";
import type { Finding, Incident, Severity } from "./types";
import "./styles.css";

type View =
  | "Overview"
  | "Incidents"
  | "Attack Graph"
  | "Assets"
  | "Enforcement"
  | "Sites"
  | "System";

const views: View[] = [
  "Overview",
  "Incidents",
  "Attack Graph",
  "Assets",
  "Enforcement",
  "Sites",
  "System"
];

const rank: Record<Severity, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
};

function severityBand(severity: Severity): string {
  return severity.toLowerCase();
}

function latest<T extends { last_seen: string }>(items: T[]): T[] {
  return [...items].sort((a, b) => b.last_seen.localeCompare(a.last_seen));
}

function Metric({
  label,
  value,
  note,
  progress
}: {
  label: string;
  value: string;
  note: string;
  progress?: number;
}) {
  return (
    <article className="metric">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {typeof progress === "number" && (
        <div className="bar" aria-label={`${label} ${progress}%`}>
          <span style={{ width: `${Math.max(0, Math.min(progress, 100))}%` }} />
        </div>
      )}
      <div className="metric-note">{note}</div>
    </article>
  );
}

function IncidentTable({ incidents }: { incidents: Incident[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>SEV</th><th>INCIDENT</th><th>STATUS</th><th>CONF</th><th>ENTITIES</th><th>LAST</th>
          </tr>
        </thead>
        <tbody>
          {latest(incidents).map((incident) => (
            <tr key={incident.incident_id}>
              <td><span className={`severity ${severityBand(incident.severity)}`}>{incident.severity}</span></td>
              <td>{incident.title}</td>
              <td>{incident.status}</td>
              <td>{Math.round(incident.confidence * 100)}%</td>
              <td>{incident.entities?.slice(0, 3).join(", ") || "—"}</td>
              <td>{new Date(incident.last_seen).toLocaleTimeString()}</td>
            </tr>
          ))}
          {!incidents.length && <tr><td colSpan={6} className="empty">No active incidents in the current snapshot.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function FindingTable({ findings }: { findings: Finding[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>SEV</th><th>DETECTOR</th><th>SOURCE</th><th>TARGET</th><th>CONF</th></tr></thead>
        <tbody>
          {latest(findings).slice(0, 12).map((item) => (
            <tr key={item.finding_id}>
              <td><span className={`severity ${severityBand(item.severity)}`}>{item.severity}</span></td>
              <td>{item.detector_id}</td>
              <td>{item.asset_id ?? item.src_ip ?? "—"}</td>
              <td>{item.dst_ip ?? "—"}</td>
              <td>{Math.round(item.confidence * 100)}%</td>
            </tr>
          ))}
          {!findings.length && <tr><td colSpan={5} className="empty">No findings.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function AttackGraph({ state }: { state: LiveState }) {
  const nodes = state.graph.nodes.slice(0, 18);
  const edges = state.graph.edges.slice(0, 30);
  return (
    <section className="panel graph-panel">
      <div className="panel-head">
        <div><span className="eyebrow">EVIDENCE GRAPH</span><h2>Observed communication relationships</h2></div>
        <span className="mono">{nodes.length} nodes / {edges.length} edges shown</span>
      </div>
      <div className="graph-list">
        {edges.map((edge) => (
          <div className="graph-edge" key={edge.edge_id}>
            <span>{edge.src_node_id.replace(/^.+:/, "")}</span>
            <i>→ {edge.relation} / {edge.protocol ?? "?"}{edge.dst_port ? `:${edge.dst_port}` : ""} →</i>
            <span>{edge.dst_node_id.replace(/^.+:/, "")}</span>
            <b>{edge.event_count} evt</b>
          </div>
        ))}
        {!edges.length && <div className="empty large">No observed graph edges yet.</div>}
      </div>
    </section>
  );
}

export default function App() {
  const params = new URLSearchParams(window.location.search);
  const tenantId = params.get("tenant") || "default";
  const siteId = params.get("site") || "default";
  const [view, setView] = useState<View>("Overview");
  const [state, setState] = useState<LiveState>({
    tenant_id: tenantId,
    site_id: siteId,
    sequence: 0,
    findings: [],
    incidents: [],
    graph: { tenant_id: tenantId, site_id: siteId, nodes: [], edges: [] },
    connection: "CONNECTING",
    droppedMessages: 0
  });

  useEffect(() => {
    const client = new LiveClient(tenantId, siteId);
    const unsubscribe = client.subscribe(setState);
    void client.start();
    return () => {
      unsubscribe();
      client.stop();
    };
  }, [tenantId, siteId]);

  const metrics = useMemo(() => {
    const active = state.incidents.filter((item) => item.status !== "CLOSED");
    const highest = active.reduce<Severity>(
      (current, item) => rank[item.severity] > rank[current] ? item.severity : current,
      "INFO"
    );
    const attackPressure = Math.min(
      100,
      active.reduce((sum, item) => sum + (rank[item.severity] + 1) * item.confidence * 8, 0)
    );
    const critical = active.filter((item) => item.severity === "CRITICAL").length;
    return { active, highest, attackPressure, critical };
  }, [state.incidents]);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="mark">M</span>
          <div><strong>MON</strong><small>SECURITY FABRIC</small></div>
        </div>
        <nav>
          {views.map((item) => (
            <button key={item} className={view === item ? "active" : ""} onClick={() => setView(item)}>
              <span>{item}</span><small>{item === "Incidents" ? metrics.active.length : ""}</small>
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className={`connection ${state.connection.toLowerCase()}`}><span />{state.connection}</div>
          <small>{tenantId} / {siteId}</small>
          <small>SEQ {state.sequence}</small>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div><span className="eyebrow">COMMAND CENTER</span><h1>{view}</h1></div>
          <div className="top-status">
            <span>LIVE TRANSPORT</span><strong>{state.connection}</strong>
            <span>LAST EVENT</span><strong>{state.lastMessageAt ? new Date(state.lastMessageAt).toLocaleTimeString() : "—"}</strong>
          </div>
        </header>

        {view === "Overview" && (
          <>
            <section className="metric-grid">
              <Metric label="NETWORK HEALTH" value={state.connection === "LIVE" ? "ONLINE" : state.connection} note="control-plane live channel" progress={state.connection === "LIVE" ? 100 : 25} />
              <Metric label="ATTACK PRESSURE" value={String(Math.round(metrics.attackPressure))} note="derived from active incident severity × confidence" progress={metrics.attackPressure} />
              <Metric label="HIGHEST SEVERITY" value={metrics.highest} note={`${metrics.active.length} active incidents`} />
              <Metric label="CRITICAL INCIDENTS" value={String(metrics.critical)} note="requires operator attention" />
              <Metric label="GRAPH COVERAGE" value={String(state.graph.nodes.length)} note={`${state.graph.edges.length} observed relationships`} />
              <Metric label="DROPPED LIVE MSG" value={String(state.droppedMessages)} note="slow-client backpressure counter" />
            </section>
            <section className="split">
              <article className="panel">
                <div className="panel-head"><div><span className="eyebrow">ACTIVE</span><h2>Incidents</h2></div></div>
                <IncidentTable incidents={metrics.active.slice(0, 8)} />
              </article>
              <article className="panel">
                <div className="panel-head"><div><span className="eyebrow">DETECTION</span><h2>Latest findings</h2></div></div>
                <FindingTable findings={state.findings} />
              </article>
            </section>
          </>
        )}

        {view === "Incidents" && <section className="panel full"><div className="panel-head"><div><span className="eyebrow">CASE QUEUE</span><h2>Incident lifecycle</h2></div></div><IncidentTable incidents={state.incidents} /></section>}
        {view === "Attack Graph" && <AttackGraph state={state} />}
        {["Assets","Enforcement","Sites","System"].includes(view) && (
          <section className="panel full placeholder">
            <span className="eyebrow">MODULE FOUNDATION</span>
            <h2>{view}</h2>
            <p>This module is wired into the command-center navigation. Its durable API and operational controls are being implemented next; no synthetic values are displayed.</p>
          </section>
        )}
      </main>
    </div>
  );
}
