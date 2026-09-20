import { useEffect, useMemo, useState } from "react";
import { ApiError, fetchOperator, fetchSensorFleet, fetchSnapshot } from "./api";
import IncidentDetail from "./IncidentDetail";
import { LiveClient, type LiveState } from "./live";
import type {
  Asset,
  AuditRecord,
  EnforcementBinding,
  EnforcementPoint,
  Finding,
  Incident,
  OperatorPrincipal,
  ResponseExecution,
  SensorFleetView,
  Severity
} from "./types";
import "./styles.css";

type View =
  | "Overview"
  | "Incidents"
  | "Attack Graph"
  | "Telemetry"
  | "Assets"
  | "Enforcement"
  | "Response"
  | "Audit"
  | "Fleet"
  | "Sites"
  | "System";

const views: View[] = [
  "Overview",
  "Incidents",
  "Attack Graph",
  "Telemetry",
  "Assets",
  "Enforcement",
  "Response",
  "Audit",
  "Fleet",
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

function IncidentTable({
  incidents,
  selectedId,
  onSelect
}: {
  incidents: Incident[];
  selectedId?: string;
  onSelect?: (incident: Incident) => void;
}) {
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
            <tr
              key={incident.incident_id}
              data-testid="incident-row"
              className={selectedId === incident.incident_id ? "selected" : ""}
              onClick={onSelect ? () => onSelect(incident) : undefined}
              style={onSelect ? { cursor: "pointer" } : undefined}
            >
              <td><span className={`severity ${severityBand(incident.severity)}`}>{incident.severity}</span></td>
              <td>{onSelect ? <button className="link" onClick={() => onSelect(incident)}>{incident.title}</button> : incident.title}</td>
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

function AssetTable({ assets }: { assets: Asset[] }) {
  const sorted = [...assets].sort((a, b) => b.last_seen.localeCompare(a.last_seen));
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ASSET</th><th>IP</th><th>MAC</th><th>VENDOR</th><th>SERVICES</th><th>EVIDENCE</th><th>LAST</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((asset) => (
            <tr key={asset.asset_id}>
              <td><strong>{asset.display_name}</strong><br /><span className="subtle">{asset.asset_id}</span></td>
              <td>{asset.ip_addresses.join(", ") || "—"}</td>
              <td>{asset.mac_addresses.join(", ") || "—"}</td>
              <td>{asset.vendor ?? "—"}</td>
              <td>{asset.observed_tcp_services.join(", ") || "—"}</td>
              <td>{asset.identity_evidence.slice(0, 3).join(", ") || "—"}</td>
              <td>{new Date(asset.last_seen).toLocaleTimeString()}</td>
            </tr>
          ))}
          {!assets.length && <tr><td colSpan={7} className="empty">No evidence-backed assets observed yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function TelemetryPanel({ state }: { state: LiveState }) {
  const telemetry = state.telemetry;
  const protocols = Object.entries(telemetry.protocol_counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12);
  return (
    <section className="panel full">
      <div className="panel-head">
        <div><span className="eyebrow">60 SECOND WINDOW</span><h2>Observed telemetry</h2></div>
        <span className="mono">MEASURED VALUES ONLY</span>
      </div>
      <div className="telemetry-grid">
        <Metric label="OBSERVATIONS" value={String(telemetry.observation_count)} note="security events, not packet count" />
        <Metric label="EVENT RATE" value={telemetry.events_per_second == null ? "—" : `${telemetry.events_per_second}/s`} note="shown after ≥1s measurement span" />
        <Metric label="MEASURED PACKETS" value={telemetry.measured_packets == null ? "—" : String(telemetry.measured_packets)} note="null when sensor did not provide packet counts" />
        <Metric label="MEASURED BYTES/S" value={telemetry.measured_bytes_per_second == null ? "—" : String(Math.round(telemetry.measured_bytes_per_second))} note="sum of supplied byte measurements / span" />
      </div>
      <div className="protocol-list">
        {protocols.map(([protocol, count]) => <div key={protocol}><span>{protocol}</span><b>{count}</b></div>)}
        {!protocols.length && <div className="empty">No protocol observations yet.</div>}
      </div>
    </section>
  );
}

function EnforcementTable({
  points,
  bindings
}: {
  points: EnforcementPoint[];
  bindings: EnforcementBinding[];
}) {
  const bindingCounts = new Map<string, number>();
  for (const binding of bindings) {
    bindingCounts.set(
      binding.enforcement_point_id,
      (bindingCounts.get(binding.enforcement_point_id) ?? 0) + 1
    );
  }
  const sorted = [...points].sort((a, b) =>
    a.enforcement_point_id.localeCompare(b.enforcement_point_id)
  );
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>POINT</th><th>KIND</th><th>VENDOR</th><th>HEALTH</th><th>CAPABILITIES</th><th>BOUND ASSETS</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((point) => (
            <tr key={point.enforcement_point_id}>
              <td><strong>{point.enforcement_point_id}</strong></td>
              <td>{point.kind}</td>
              <td>{point.vendor}</td>
              <td>{point.health}</td>
              <td>{point.capabilities.join(", ") || "—"}</td>
              <td>{bindingCounts.get(point.enforcement_point_id) ?? 0}</td>
            </tr>
          ))}
          {!points.length && <tr><td colSpan={6} className="empty">No enforcement points registered for this site.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function ResponseTable({ executions }: { executions: ResponseExecution[] }) {
  const sorted = [...executions].sort((a, b) =>
    b.requested_at.localeCompare(a.requested_at)
  );
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>STATUS</th><th>ACTION</th><th>TARGET</th><th>ENFORCEMENT</th><th>POLICY</th><th>TTL</th><th>BLAST RADIUS</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((item) => (
            <tr key={item.execution_id}>
              <td><strong>{item.status}</strong></td>
              <td>{item.plan.request.action}</td>
              <td>{item.plan.request.target.asset_id ?? item.plan.request.target.ip_address ?? "—"}</td>
              <td>{item.plan.enforcement_point.enforcement_point_id}</td>
              <td>{item.plan.decision.outcome}</td>
              <td>{item.plan.request.ttl_seconds == null ? "—" : `${item.plan.request.ttl_seconds}s`}</td>
              <td>{item.plan.blast_radius_estimate ?? "UNKNOWN"}</td>
            </tr>
          ))}
          {!executions.length && <tr><td colSpan={7} className="empty">No response executions recorded for this site.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function AuditTable({ records }: { records: AuditRecord[] }) {
  const sorted = [...records].sort((a, b) => b.occurred_at.localeCompare(a.occurred_at));
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>TIME</th><th>ACTOR</th><th>ACTION</th><th>OUTCOME</th><th>OBJECT</th></tr>
        </thead>
        <tbody>
          {sorted.map((item) => (
            <tr key={item.audit_id}>
              <td>{new Date(item.occurred_at).toLocaleString()}</td>
              <td>{item.actor_id}</td>
              <td>{item.action}</td>
              <td>{item.outcome}</td>
              <td>{item.object_id}</td>
            </tr>
          ))}
          {!records.length && <tr><td colSpan={5} className="empty">No audit records for this site.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function FleetPanel({ tenantId, siteId }: { tenantId: string; siteId: string }) {
  const [sensors, setSensors] = useState<SensorFleetView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    fetchSensorFleet(tenantId, siteId)
      .then((value) => !cancelled && setSensors(value))
      .catch((reason: unknown) => {
        if (!cancelled) setError(reason instanceof ApiError ? `HTTP ${reason.status}` : "unavailable");
      });
    return () => {
      cancelled = true;
    };
  }, [tenantId, siteId]);
  return (
    <section className="panel full" data-testid="fleet-panel">
      <div className="panel-head">
        <div><span className="eyebrow">SENSOR FLEET</span><h2>Enrolled sensors</h2></div>
        <span className="mono">HEARTBEAT-DERIVED STATE ONLY</span>
      </div>
      {error && <div className="empty" role="alert">Fleet unavailable: {error}</div>}
      <div className="table-wrap">
        <table>
          <thead><tr><th>SENSOR</th><th>STATE</th><th>LAST SEEN</th><th>KIND</th><th>VERSION</th><th>ERROR</th></tr></thead>
          <tbody>
            {(sensors ?? []).map((sensor) => (
              <tr key={sensor.sensor_id} data-testid="fleet-row">
                <td>{sensor.sensor_id}</td>
                <td>{sensor.state}</td>
                <td>{sensor.last_seen_at ? new Date(sensor.last_seen_at).toLocaleString() : "never"}</td>
                <td>{sensor.collector_kind ?? "—"}</td>
                <td>{sensor.version ?? "—"}</td>
                <td>{sensor.last_error ?? "—"}</td>
              </tr>
            ))}
            {sensors && !sensors.length && <tr><td colSpan={6} className="empty">No sensors enrolled for this site.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
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
  const [operator, setOperator] = useState<OperatorPrincipal | null>(null);
  const [authState, setAuthState] = useState<"CHECKING" | "OK" | "UNAUTHENTICATED" | "DENIED">("CHECKING");
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [state, setState] = useState<LiveState>({
    tenant_id: tenantId,
    site_id: siteId,
    sequence: 0,
    findings: [],
    incidents: [],
    assets: [],
    enforcement_points: [],
    enforcement_bindings: [],
    response_executions: [],
    audit_records: [],
    telemetry: {
      tenant_id: tenantId,
      site_id: siteId,
      window_seconds: 60,
      observed_at: new Date(0).toISOString(),
      observation_count: 0,
      unique_src_ips: 0,
      unique_dst_ips: 0,
      protocol_counts: {},
      source_counts: {}
    },
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

  useEffect(() => {
    let cancelled = false;
    setAuthState("CHECKING");
    fetchOperator()
      .then(async (principal) => {
        if (cancelled) return;
        setOperator(principal);
        try {
          await fetchSnapshot(tenantId, siteId);
          if (!cancelled) setAuthState("OK");
        } catch (reason: unknown) {
          if (!cancelled) {
            setAuthState(reason instanceof ApiError && reason.status === 403 ? "DENIED" : "UNAUTHENTICATED");
          }
        }
      })
      .catch(() => {
        if (!cancelled) {
          setOperator(null);
          setAuthState("UNAUTHENTICATED");
        }
      });
    return () => {
      cancelled = true;
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
          <small data-testid="operator-context">
            {operator ? `${operator.subject} · ${operator.roles.join(", ")}` : "not authenticated"}
          </small>
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

        {authState === "DENIED" && (
          <section className="panel full" role="alert" data-testid="access-denied">
            <h2>ACCESS DENIED</h2>
            <p>Your credentials do not grant access to tenant {tenantId} / site {siteId}. No data is shown.</p>
          </section>
        )}
        {authState === "UNAUTHENTICATED" && (
          <section className="panel full" role="alert" data-testid="unauthenticated">
            <h2>AUTHENTICATION REQUIRED</h2>
            <p>No valid operator session was found. Sign in through your identity provider and reload.</p>
          </section>
        )}
        {view === "Overview" && (
          <>
            <section className="metric-grid">
              <Metric label="CONTROL PLANE LINK" value={state.connection === "LIVE" ? "ONLINE" : state.connection} note="authenticated WebSocket transport" progress={state.connection === "LIVE" ? 100 : 25} />
              <Metric label="ATTACK PRESSURE" value={String(Math.round(metrics.attackPressure))} note="derived from active incident severity × confidence" progress={metrics.attackPressure} />
              <Metric label="HIGHEST SEVERITY" value={metrics.highest} note={`${metrics.active.length} active incidents`} />
              <Metric label="CRITICAL INCIDENTS" value={String(metrics.critical)} note="requires operator attention" />
              <Metric label="ASSETS OBSERVED" value={String(state.assets.length)} note="evidence-backed identities in current site" />
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

        {view === "Incidents" && (
          <>
            <section className="panel full"><div className="panel-head"><div><span className="eyebrow">CASE QUEUE</span><h2>Incident lifecycle</h2></div></div><IncidentTable incidents={state.incidents} selectedId={selectedIncident?.incident_id} onSelect={setSelectedIncident} /></section>
            {selectedIncident && (
              <IncidentDetail
                incident={selectedIncident}
                tenantId={tenantId}
                siteId={siteId}
                executions={state.response_executions}
                auditRecords={state.audit_records}
              />
            )}
          </>
        )}
        {view === "Fleet" && <FleetPanel tenantId={tenantId} siteId={siteId} />}
        {view === "Attack Graph" && <AttackGraph state={state} />}
        {view === "Telemetry" && <TelemetryPanel state={state} />}
        {view === "Assets" && <section className="panel full"><div className="panel-head"><div><span className="eyebrow">IDENTITY</span><h2>Observed assets</h2></div><span className="mono">{state.assets.length} assets</span></div><AssetTable assets={state.assets} /></section>}
        {view === "Enforcement" && <section className="panel full"><div className="panel-head"><div><span className="eyebrow">CONTROL SURFACES</span><h2>Enforcement inventory</h2></div><span className="mono">{state.enforcement_points.length} points / {state.enforcement_bindings.length} bindings</span></div><EnforcementTable points={state.enforcement_points} bindings={state.enforcement_bindings} /></section>}
        {view === "Response" && <section className="panel full"><div className="panel-head"><div><span className="eyebrow">POLICY-GATED</span><h2>Response executions</h2></div><span className="mono">{state.response_executions.length} records</span></div><ResponseTable executions={state.response_executions} /></section>}
        {view === "Audit" && <section className="panel full"><div className="panel-head"><div><span className="eyebrow">AUDIT TRAIL</span><h2>Recorded actions</h2></div><span className="mono">{state.audit_records.length} records</span></div><AuditTable records={state.audit_records} /></section>}
        {["Sites","System"].includes(view) && (
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
