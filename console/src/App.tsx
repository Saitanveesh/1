import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import SecurityAlert from "./SecurityAlert";
import AlertInvestigation from "./AlertInvestigation";
import AlertCenter, { collectAlerts } from "./AlertCenter";
import type { SecurityThreatAlert } from "./securityAlerts";
import { useSuricataThreatAlerts } from "./suricataThreats";
import {
  currentProtectedFindings, currentProtectedIncidents, idsStatus,
  isProtectedCaptureReady, isRecentObservation
} from "./operationalTruth";
import { ApiError, fetchOperator, fetchSensorFleet, fetchSnapshot } from "./api";
import IncidentDetail from "./IncidentDetail";
import IncidentQueue from "./IncidentQueue";
import Investigation3D from "./Incident3D";
import SocGauges from "./SocGauges";
import SuricataPanel from "./SuricataPanel";
import LoginPage from "./LoginPage";
import { NetworkPath, PacketHistory, ProtectedRouteStrip, usePacketCapture } from "./PacketObservability";
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

type View = "Overview" | "Alerts" | "Incidents" | "Investigation";

const views: View[] = ["Overview", "Alerts", "Incidents", "Investigation"];
const viewLabels: Record<View, string> = {
  Overview: "Dashboard", Alerts: "Alerts", Incidents: "Cases", Investigation: "Investigation"
};

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
            <th>Severity</th><th>What happened</th><th>Status</th><th>Confidence</th><th>Related addresses</th><th>Last seen</th>
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
              <td>{new Date(incident.last_seen).toLocaleString()}</td>
            </tr>
          ))}
          {!incidents.length && <tr><td colSpan={6} className="empty">No new cases in the last five minutes. Earlier cases are still available.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function FindingTable({ findings }: { findings: Finding[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Severity</th><th>Detection</th><th>Source</th><th>Destination</th><th>Confidence</th></tr></thead>
        <tbody>
          {latest(findings).slice(0, 12).map((item) => (
            <tr key={item.finding_id}>
              <td><span className={`severity ${severityBand(item.severity)}`}>{item.severity}</span></td>
              <td>{item.detector_id}</td>
              <td>{item.src_ip ?? "Unknown Source"}</td>
              <td>{item.dst_ip ?? "Not recorded"}</td>
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
  const [pendingAlerts, setPendingAlerts] = useState<SecurityThreatAlert[]>([]);
  const [focusedAlert, setFocusedAlert] = useState<SecurityThreatAlert | null>(null);
  const [sessionAlerts, setSessionAlerts] = useState<SecurityThreatAlert[]>([]);
  const [acknowledgedAlerts, setAcknowledgedAlerts] = useState<Record<string, string>>({});
  const [ackBusy, setAckBusy] = useState(false);
  const [ackError, setAckError] = useState<string | null>(null);
  const seenAlertKeys = useRef(new Set<string>());
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
    if (authState !== "OK") return;
    const client = new LiveClient(tenantId, siteId);
    const unsubscribe = client.subscribe(setState);
    void client.start();
    return () => {
      unsubscribe();
      client.stop();
    };
  }, [tenantId, siteId, authState]);

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

  const enqueueThreat = useCallback((incoming: SecurityThreatAlert) => {
    if (seenAlertKeys.current.has(incoming.key)) return;
    seenAlertKeys.current.add(incoming.key);
    setSessionAlerts(current => [incoming, ...current.filter(item => item.key !== incoming.key)].slice(0, 200));
    setPendingAlerts(current => current.some(item => item.key === incoming.key)
      ? current
      : [...current, incoming].slice(-10));
  }, []);

  const packetCapture = usePacketCapture(authState === "OK");
  const targetIp = packetCapture?.protected_host_ip || null;

  useEffect(() => {
    const incoming = state.threatAlert;
    // A new WS event is not necessarily recent or intended for this victim.
    // Do not flash a central "live attack" for historical or unscoped events.
    if (authState === "OK" && state.connection === "LIVE" &&
        incoming && targetIp && incoming.target === targetIp &&
        isRecentObservation(incoming.observedAt, Date.now(), 120_000)) {
      enqueueThreat(incoming);
    }
  }, [authState, state.connection, state.threatAlert, enqueueThreat, targetIp]);

  const ids = useSuricataThreatAlerts(authState === "OK", enqueueThreat, targetIp);
  const alerts = useMemo(
    () => collectAlerts(ids.snapshot, targetIp, sessionAlerts),
    [ids.snapshot, targetIp, sessionAlerts]
  );
  const unreviewedAlerts = alerts.filter(item => !acknowledgedAlerts[item.key]);

  useEffect(() => {
    if (authState !== "OK") return;
    let cancelled = false;
    fetch("/portal/alerts/acknowledged", { credentials: "same-origin" })
      .then(response => response.ok ? response.json() : Promise.reject(new Error("Review state unavailable")))
      .then((data: { records?: Array<{ key: string; acknowledged_at: string }> }) => {
        if (cancelled) return;
        const next: Record<string, string> = {};
        for (const row of data.records ?? []) {
          if (row.key.startsWith("ids:")) next[row.key] = row.acknowledged_at;
        }
        setAcknowledgedAlerts(next);
      })
      .catch(() => { /* Review state is optional; a failed write is never silently accepted. */ });
    return () => { cancelled = true; };
  }, [authState]);

  function openAlert(alert: SecurityThreatAlert): void {
    setFocusedAlert(alert);
    setAckError(null);
    const caseMatch = alert.incidentId
      ? state.incidents.find(item => item.incident_id === alert.incidentId)
      : undefined;
    if (caseMatch) setSelectedIncident(caseMatch);
    setView("Investigation");
    setPendingAlerts(queue => queue.filter(item => item.key !== alert.key));
  }

  async function acknowledgeAlert(alert: SecurityThreatAlert): Promise<void> {
    if (ackBusy) return;
    if (acknowledgedAlerts[alert.key]) {
      openAlert(alert);
      return;
    }
    setAckBusy(true);
    setAckError(null);
    try {
      let stamp = new Date().toISOString();
      if (alert.key.startsWith("ids:")) {
        const response = await fetch("/portal/alerts/acknowledge", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key: alert.key })
        });
        if (!response.ok) {
          const errorBody = await response.json().catch(() => ({})) as { error?: string };
          throw new Error(errorBody.error ?? ("Review not saved: HTTP " + response.status));
        }
        const body = await response.json() as { acknowledged_at?: string };
        if (!body.acknowledged_at) throw new Error("Review timestamp missing");
        stamp = body.acknowledged_at;
      }
      // Stream-only alerts stay browser-session-only. Acknowledgment does not
      // change the MON case database, case status or network enforcement.
      setAcknowledgedAlerts(old => ({ ...old, [alert.key]: stamp }));
      openAlert(alert);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Acknowledgment unavailable";
      setAckError(message);
      // Keep failed modal visible; no success state or suppressed alert.
      setFocusedAlert(current => current?.key === alert.key ? current : alert);
    } finally {
      setAckBusy(false);
    }
  }

  const metrics = useMemo(() => {
    const active = currentProtectedIncidents(
      state.incidents, state.findings, state.assets, targetIp
    );
    const recentFindings = currentProtectedFindings(state.findings, targetIp);
    const highest = active.reduce<Severity>(
      (current, item) => rank[item.severity] > rank[current] ? item.severity : current,
      "INFO"
    );
    const recordedOpen = state.incidents.filter(item => item.status !== "CLOSED");
    return { active, recentFindings, highest, recordedOpen };
  }, [state.incidents, state.findings, state.assets, targetIp]);

  const protectedReady = isProtectedCaptureReady(packetCapture);
  const idsState = idsStatus(ids.snapshot, ids.availability);

  const displayedIncident = state.incidents.find(item =>
    item.incident_id === selectedIncident?.incident_id
  ) ?? state.incidents[0] ?? null;

  if (authState === "UNAUTHENTICATED") {
    return <LoginPage loading={false} onAuthenticated={() => window.location.reload()} />;
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="mark">M</span>
          <div><strong>MON</strong><small>Security monitoring</small></div>
        </div>
        <nav>
          {views.map((item) => (
            <button key={item} type="button" className={view === item ? "active" : ""} aria-current={view === item ? "page" : undefined}
              onClick={() => { setView(item); if (item !== "Investigation") setFocusedAlert(null); setAckError(null); }}>
              <span>{viewLabels[item]}</span><small>{item === "Alerts" ? unreviewedAlerts.length || "" : item === "Incidents" ? metrics.recordedOpen.length || "" : ""}</small>
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          {authState === "OK" && (
            <button className="mon-logout" onClick={async () => {
              try {
                await fetch("/portal/logout", { method: "POST", credentials: "same-origin" });
              } finally {
                window.location.reload();
              }
            }}>Sign out</button>
          )}
          <div className={`connection ${state.connection.toLowerCase()}`} role="status"><span />
            {state.connection === "LIVE" ? "Connected" : "Connection: " + state.connection.toLowerCase()}</div>

        </div>
      </aside>

      <main>
        <header className="topbar">
          <div><h1>{viewLabels[view]}</h1><p className="mon-topbar-description">{
              view === "Overview" ? "Live activity and security monitoring" :
              view === "Alerts" ? "Review detections and keep track of your decisions" :
              view === "Incidents" ? "Recorded security cases and response history" :
              "Inspect the evidence behind an alert or case"
            }</p></div>
          <div className="top-status" role="status">
            <span className={state.connection === "LIVE" ? "mon-online-dot" : "mon-offline-dot"} />
            <strong>{state.connection === "LIVE" ? "Live" : "Reconnecting"}</strong>
            <small>{state.lastMessageAt ? "Updated " + new Date(state.lastMessageAt).toLocaleTimeString() : "Awaiting connection"}</small>
          </div>
        </header>

        {authState === "DENIED" && (
          <section className="panel full" role="alert" data-testid="access-denied">
            <h2>ACCESS DENIED</h2>
            <p>Your credentials do not grant access to tenant {tenantId} / site {siteId}. No data is shown.</p>
          </section>
        )}
        {view === "Overview" && (
          <div className="mon-command-desk" data-testid="mon-single-console">
            {(!protectedReady || ids.snapshot?.service_state !== "active" || packetCapture?.protected_route_check !== "MATCHES_CAPTURE_INTERFACE") && (
              <section className="mon-evidence-notice" role="status" data-testid="sensor-coverage-warning">
                <strong>Some monitoring data is unavailable</strong>
                <span>
                  {protectedReady
                    ? "Traffic monitoring is active."
                    : "Live traffic cannot be confirmed right now. Packet counts are hidden until the sensor is ready."}
                  {" "}
                  {packetCapture?.protected_route_check === "DIFFERENT_INTERFACE"
                    ? "Traffic is using a different route than the one being monitored. "
                    : packetCapture?.protected_route_check !== "MATCHES_CAPTURE_INTERFACE"
                      ? "The network route has not been verified. "
                      : ""}
                  {idsState === "SERVICE OFFLINE"
                    ? "The detection sensor is offline."
                    : idsState === "SERVICE UNVERIFIED" || idsState === "API UNAVAILABLE"
                      ? "The detection sensor could not be checked."
                      : idsState === "CHECKING"
                        ? "Checking the detection sensor..."
                        : "Detection data: " + idsState.toLowerCase() + "."}
                </span>
              </section>
            )}
            <section className="mon-overview-strip" data-testid="overview-status-strip">
              <button type="button" onClick={() => setView("Alerts")}>
                <small>Alerts to review</small><strong>{unreviewedAlerts.length}</strong><span>View alerts →</span>
              </button>
              <button type="button" onClick={() => setView("Incidents")}>
                <small>Open cases</small><strong>{metrics.recordedOpen.length}</strong><span>View cases →</span>
              </button>
              <div><small>Network capture</small><strong>{protectedReady ? "Online" : "Unavailable"}</strong></div>
              <div><small>Threat detection</small><strong>{ids.snapshot?.service_state === "active" ? "Online" : "Unavailable"}</strong></div>
            </section>
            <SocGauges state={state} capture={packetCapture} ids={ids} />
            <details className="mon-technical-details">
              <summary>Network details</summary>
              <ProtectedRouteStrip capture={packetCapture} />
            </details>
            <div className="mon-command-desk-grid">
              <div className="mon-desk-traffic">
                <PacketHistory capture={packetCapture} compact protectedOnly />
              </div>
              <div className="mon-desk-incidents">
                <section className="panel">
                  <div className="panel-head">
                    <div><h2>Recent cases</h2></div>
                    <button type="button" className="mon-desk-action" onClick={() => setView("Incidents")}>View cases →</button>
                  </div>
                  <IncidentTable incidents={metrics.active.slice(0, 6)} />
                </section>
                <section className="panel">
                  <div className="panel-head">
                    <div><h2>Recent findings</h2></div>
                    <button type="button" className="mon-desk-action" onClick={() => setView("Alerts")}>View alerts →</button>
                  </div>
                  <FindingTable findings={metrics.recentFindings.slice(0, 5)} />
                </section>
              </div>
            </div>
          </div>
        )}

        {view === "Alerts" && (
          <AlertCenter
            alerts={alerts}
            acknowledged={acknowledgedAlerts}
            sensorReady={ids.availability === "AVAILABLE" && ids.snapshot?.service_state === "active"}
            onOpen={openAlert}
            onAcknowledge={item => void acknowledgeAlert(item)}
          />
        )}

        {view === "Incidents" && (
          <div className="mon-incidents-workspace" data-testid="incident-workspace">
            <IncidentQueue incidents={state.incidents} findings={state.findings}
              selectedId={displayedIncident?.incident_id ?? null}
              onSelect={setSelectedIncident} />
            <div className="mon-incidents-main">
              {displayedIncident ? (
                <IncidentDetail
                  incident={displayedIncident}
                  tenantId={tenantId}
                  siteId={siteId}
                  executions={state.response_executions}
                  auditRecords={state.audit_records}
                  onOpen3D={(incident) => {
                    setSelectedIncident(incident);
                    setView("Investigation");
                  }}
                />
              ) : (
                <section className="mon-case-waiting">
                  <h2>No incidents recorded</h2>
                  <p>When MON detects an incident, its evidence will appear here.</p>
                </section>
              )}
            </div>
          </div>
        )}
        {view === "Investigation" && (
          <>
          {focusedAlert && <AlertInvestigation
            alert={focusedAlert}
            snapshot={ids.snapshot}
            capture={packetCapture}
            acknowledgedAt={acknowledgedAlerts[focusedAlert.key] ?? null}
            acknowledging={ackBusy}
            error={ackError}
            onAcknowledge={() => { if (focusedAlert) void acknowledgeAlert(focusedAlert); }}
            onClose={() => { setFocusedAlert(null); setView("Alerts"); }}
            onOpenCase={focusedAlert.incidentId &&
              state.incidents.some(item => item.incident_id === focusedAlert.incidentId)
              ? () => {
                const caseItem = state.incidents.find(item => item.incident_id === focusedAlert.incidentId);
                if (caseItem) { setSelectedIncident(caseItem); setFocusedAlert(null); setView("Incidents"); }
              } : undefined}
          />}
          {(!focusedAlert || (focusedAlert.incidentId && state.incidents.some(
            item => item.incident_id === focusedAlert.incidentId
          ))) && <Investigation3D
            incidents={state.incidents}
            executions={state.response_executions}
            audits={state.audit_records}
            capture={packetCapture}
            tenantId={tenantId}
            siteId={siteId}
            initialIncidentId={selectedIncident?.incident_id}
            onOpen={(incident) => {
              setSelectedIncident(incident);
              setView("Incidents");
            }}
          />}
          <details className="mon-technical-details mon-investigation-details">
            <summary>Network traffic and sensor records</summary>
            <NetworkPath capture={packetCapture} />
            <SuricataPanel protectedIp={targetIp} />
          </details>
          </>
        )}

      </main>
      {authState === "OK" && pendingAlerts.length > 0 && (
        <SecurityAlert
          alert={pendingAlerts[0]}
          queued={pendingAlerts.length}
          onInvestigate={() => { if (pendingAlerts[0]) openAlert(pendingAlerts[0]); }}
          onAcknowledge={() => { if (pendingAlerts[0]) void acknowledgeAlert(pendingAlerts[0]); }}
          acknowledging={ackBusy}
          acknowledgeError={ackError}
        />
      )}
    </div>
  );
}
