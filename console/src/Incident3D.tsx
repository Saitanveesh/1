import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, fetchInvestigation } from "./api";
import { buildCaseTimeline, type CaseMoment } from "./AiAnalysis";
import type { Incident, IncidentInvestigation, ResponseExecution, AuditRecord, PacketCaptureSnapshot } from "./types";
import "./Incident3D.css";

export type SceneKind = "authentication" | "reconnaissance" | "lateral" | "beacon" | "containment" | "generic";
export interface SceneNode {
  id: string;
  label: string;
  detail: string;
  kind: "source" | "asset" | "response" | "evidence";
  x: number;
  y: number;
  z: number;
  ref: string;
}
export interface SceneLink {
  id: string;
  from: string;
  to: string;
  relation: string;
  recorded: boolean;
}
export interface SceneModel {
  kind: SceneKind;
  label: string;
  nodes: SceneNode[];
  links: SceneLink[];
  timeline: CaseMoment[];
  source: string | null;
  targets: string[];
  packets: number;
  lastPacketAt: string | null;
}

export function classifyIncident(incident: Incident): SceneKind {
  const haystack = [incident.title, ...incident.detector_ids].join(" ").toLowerCase();
  if (/scan|recon|port.?sweep|enumerat/.test(haystack)) return "reconnaissance";
  if (/lateral|pivot|remote.?exec|east.?west|credential.?reuse/.test(haystack)) return "lateral";
  if (/beacon|c2|command.?and.?control|dns.?tunnel|callback/.test(haystack)) return "beacon";
  if (/auth|login|ssh|password|credential.?guess/.test(haystack)) return "authentication";
  if (/block|response|contain|isolation/.test(haystack)) return "containment";
  return "generic";
}
const titleFor: Record<SceneKind, string> = {
  authentication: "Authentication pressure",
  reconnaissance: "Reconnaissance and fan-out",
  lateral: "Host-to-host relationships",
  beacon: "Outbound communications",
  containment: "Response lifecycle",
  generic: "Evidence relationships"
};

export function buildIncidentScene(
  investigation: IncidentInvestigation,
  executions: ResponseExecution[],
  audits: AuditRecord[],
  capture: PacketCaptureSnapshot | null
): SceneModel {
  const incident = investigation.incident;
  const kind = classifyIncident(incident);
  const related = executions.filter(r => r.plan.request.incident_id === incident.incident_id);
  const source = investigation.findings.find(f => f.src_ip)?.src_ip ??
    incident.entities.find(value => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) ?? null;
  const assets = investigation.affected_assets.slice(0, 8);
  const targets = assets.flatMap(a => a.ip_addresses);
  const nodes: SceneNode[] = [];
  const links: SceneLink[] = [];
  if (source) nodes.push({
    id: "source:" + source, label: source, detail: "Source from recorded finding or case",
    kind: "source", x: kind === "beacon" ? -.9 : -3.3,
    y: kind === "beacon" ? -1.65 : .7, z: kind === "beacon" ? 1.3 : 0,
    ref: source
  });
  assets.forEach((asset, i) => {
    const offset = i - (assets.length - 1) / 2;
    const spread = Math.min(1.35, 4 / Math.max(1, assets.length));
    const theta = i * Math.PI * 2 / Math.max(1, assets.length);
    const x = kind === "lateral" ? -1 + (i + 1) * .85 :
      kind === "beacon" ? Math.cos(theta) * 2.55 + .8 :
      kind === "containment" ? .7 : kind === "reconnaissance" ? 3 : 2.45;
    const y = kind === "beacon" ? Math.sin(theta) * 1.9 + .7 :
      kind === "lateral" ? (i % 2 ? 1.6 : -.2) :
      kind === "containment" ? 1.35 : offset * spread;
    const z = kind === "lateral" ? Math.sin(i * 1.2) * 1.25 :
      kind === "beacon" ? Math.cos(theta) * 1.1 :
      kind === "containment" ? -.75 :
      assets.length < 2 ? 0 : Math.sin(i * 1.2) * 1.1;
    nodes.push({
      id: "asset:" + asset.asset_id, label: asset.display_name,
      detail: asset.ip_addresses.join(", ") || asset.asset_id,
      kind: "asset", x, y, z, ref: asset.asset_id
    });
    if (source) links.push({
      id: "case:" + i, from: "source:" + source, to: "asset:" + asset.asset_id,
      relation: "Case association; not a packet-level hop", recorded: false
    });
  });
  // Central evidence markers stay separate from the source and protected asset.
  // Avoid overlapping full-size cards and crossing response edges.
  const evidence = investigation.evidence.slice(0, 6);
  evidence.forEach((e, i) => {
    const x = -.9 + (i % 3) * 1.15;
    const y = 1.8 + Math.floor(i / 3) * .72;
    nodes.push({
      id: "evidence:" + e.evidence_id, label: e.evidence_class,
      detail: e.summary, kind: "evidence", x, y,
      z: -.65 + (i % 3) * .25, ref: e.evidence_id
    });
  });
  related.slice(0, 4).forEach((r, i) => {
    nodes.push({
      id: "response:" + r.execution_id,
      label: r.plan.request.action + " · " + r.status,
      detail: r.execution_id,
      kind: "response", x: -1.2 + (i % 3) * 1.2,
      y: -1.7 - Math.floor(i / 3) * .7, z: .55, ref: r.execution_id
    });
  });
  if (!nodes.length) nodes.push({
    id: "unresolved:" + incident.incident_id, label: "Incident record",
    detail: "No source or asset resolved", kind: "evidence",
    x: 0, y: 0, z: 0, ref: incident.incident_id
  });
  const eventSource = capture?.lab_route_events ?? capture?.events ?? [];
  const matches = eventSource.filter(e => source && (
    (e.src_ip === source && targets.includes(e.dst_ip)) ||
    (e.dst_ip === source && targets.includes(e.src_ip))
  ));
  return {
    kind, label: titleFor[kind], nodes, links,
    timeline: buildCaseTimeline(investigation, executions, audits),
    source, targets, packets: matches.length,
    lastPacketAt: matches[0]?.timestamp ?? null
  };
}

function SceneEdge({ a, b, recorded }: { a: SceneNode; b: SceneNode; recorded: boolean }) {
  const dx = b.x - a.x, dy = b.y - a.y, dz = b.z - a.z;
  const length = Math.hypot(dx, dy, dz);
  const yaw = Math.atan2(-dz, dx) * 180 / Math.PI;
  const pitch = Math.atan2(dy, Math.hypot(dx, dz)) * 180 / Math.PI;
  const transform = "translate3d(0, 0, " + (a.z * 82) + "px) rotateY(" +
    yaw + "deg) rotateZ(" + (-pitch) + "deg)";
  return <div className={"mon3d-edge " + (recorded ? "recorded" : "inferred")}
    style={{ left: "calc(50% + " + (a.x * 82) + "px)",
      top: "calc(50% - " + (a.y * 82) + "px)", width: length * 82, transform }}
    aria-hidden="true" />;
}

export function Incident3DScene({ model }: { model: SceneModel }) {
  const [projection, setProjection] = useState<"3d" | "2d">("3d");
  const [camera, setCamera] = useState({ x: -23, y: -19, zoom: 1 });
  const [selected, setSelected] = useState<string | null>(null);
  const [momentIndex, setMomentIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const dragging = useRef<{ x: number; y: number } | null>(null);
  const sceneElement = useRef<HTMLDivElement | null>(null);
  const [viewportWidth, setViewportWidth] = useState(980);
  useEffect(() => {
    const element = sceneElement.current;
    if (!element) return;
    const update = () => setViewportWidth(element.getBoundingClientRect().width || 980);
    update();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(update);
    observer.observe(element);
    return () => observer.disconnect();
  }, [projection]);
  useEffect(() => {
    if (!playing || model.timeline.length < 2) return;
    const clock = window.setInterval(() => setMomentIndex(i => {
      if (i >= model.timeline.length - 1) {
        setPlaying(false);
        return i;
      }
      return i + 1;
    }), 1000);
    return () => window.clearInterval(clock);
  }, [playing, model.timeline.length]);
  const current = model.timeline[momentIndex];
  const picked = model.nodes.find(node => node.id === selected);
  const coreLinks = model.links.filter(l => !verifiedOnly || l.recorded);
  // Fixed world scale at full width; fit the actual stage when the analyst resizes MON.
  const fitScale = Math.min(1, Math.max(.5, (viewportWidth - 125) / 670));
  return (
    <article className="mon3d-workspace mon3d-studio" data-testid="incident-3d-scene">
      <div className="mon3d-studio-top">
        <div className="mon3d-scene-title">
          <small>INVESTIGATION / {model.kind.toUpperCase()}</small>
          <h3>{model.label}</h3>
          <p>Recorded entities · evidence-first reconstruction</p>
        </div>
        <div className="mon3d-switch">
          <button type="button" aria-pressed={projection === "3d"} onClick={() => setProjection("3d")}>3D</button>
          <button type="button" aria-pressed={projection === "2d"} onClick={() => setProjection("2d")}>2D</button>
          <button type="button" onClick={() => setCamera({ x: -23, y: -19, zoom: 1 })}>FIT VIEW</button>
        </div>
      </div>
      <div className="mon3d-studio-bar">
        <span><strong>{model.nodes.length}</strong> entities</span>
        <span><strong>{model.timeline.length}</strong> recorded events</span>
        <span><strong>{model.packets}</strong> matching live IP headers</span>
        <label><input type="checkbox" checked={verifiedOnly}
          onChange={event => setVerifiedOnly(event.target.checked)} />
          Verified links only</label>
      </div>
      <div className="mon3d-studio-grid">
        <div className="mon3d-stage-panel">
          {projection === "3d" ? (
            <div className="mon3d-stage" ref={sceneElement} data-testid="incident-3d-viewport"
              role="region" tabIndex={0} aria-label="Interactive 3D evidence topology; drag to orbit"
              onPointerDown={event => {
                if ((event.target as HTMLElement).closest("button")) return;
                dragging.current = { x: event.clientX, y: event.clientY };
                event.currentTarget.setPointerCapture(event.pointerId);
              }}
              onPointerMove={event => {
                if (!dragging.current) return;
                const dx = event.clientX - dragging.current.x;
                const dy = event.clientY - dragging.current.y;
                dragging.current = { x: event.clientX, y: event.clientY };
                setCamera(v => ({
                  ...v, y: v.y + dx * .24,
                  x: Math.max(-55, Math.min(55, v.x - dy * .24))
                }));
              }}
              onPointerUp={() => { dragging.current = null; }}
              onPointerCancel={() => { dragging.current = null; }}
              onWheel={event => setCamera(v => ({
                ...v, zoom: Math.min(1.6, Math.max(.62, v.zoom - event.deltaY * .0007))
              }))}
              onKeyDown={event => {
                if (event.key === "ArrowLeft") setCamera(v => ({ ...v, y: v.y - 9 }));
                if (event.key === "ArrowRight") setCamera(v => ({ ...v, y: v.y + 9 }));
                if (event.key === "+") setCamera(v => ({ ...v, zoom: Math.min(1.6, v.zoom + .1) }));
                if (event.key === "-") setCamera(v => ({ ...v, zoom: Math.max(.62, v.zoom - .1) }));
              }}>
              <div className="mon3d-grid" aria-hidden="true" />
              <div className="mon3d-universe" style={{
                transform: "rotateX(" + camera.x + "deg) rotateY(" + camera.y +
                  "deg) scale(" + (camera.zoom * fitScale) + ")"
              }}>
                {coreLinks.map(link => {
                  const a = model.nodes.find(node => node.id === link.from);
                  const b = model.nodes.find(node => node.id === link.to);
                  return a && b ? <SceneEdge key={link.id} a={a} b={b} recorded={link.recorded} /> : null;
                })}
                {model.nodes.map(node =>
                  <button type="button" key={node.id}
                    data-testid={"mon3d-node-" + node.kind}
                    className={"mon3d-node " + node.kind +
                      (selected === node.id ? " selected" : "") +
                      (current?.reference === node.ref ? " timeline-active" : "")}
                    title={node.detail}
                    style={{ left: "calc(50% + " + node.x * 82 + "px)",
                      top: "calc(50% - " + node.y * 82 + "px)",
                      transform: "translate3d(-50%, -50%, " + node.z * 82 + "px)" }}
                    onClick={() => setSelected(node.id)}>
                    <small>{node.kind.toUpperCase()}</small>
                    <strong>{node.label}</strong>
                  </button>
                )}
              </div>
              <div className="mon3d-help">DRAG TO ROTATE · SCROLL TO ZOOM</div>
            </div>
          ) : (
            <div className="mon3d-list" data-testid="incident-2d-view">
              {model.nodes.map(node =>
                <button type="button" key={node.id} onClick={() => setSelected(node.id)}>
                  <small>{node.kind.toUpperCase()}</small><strong>{node.label}</strong>
                  <span>{node.detail}</span>
                </button>
              )}
            </div>
          )}
          <div className="mon3d-legend">
            <span><i className="mon3d-legend-source" /> Observed source</span>
            <span><i className="mon3d-legend-asset" /> Asset</span>
            <span><i className="mon3d-legend-evidence" /> Evidence</span>
            <span><i className="mon3d-legend-response" /> Response</span>
          </div>
        </div>
        <aside className="mon3d-rail">
          <section className="mon3d-rail-card" data-testid="scene-inspector">
            <small>01 / EVIDENCE INSPECTOR</small>
            <h4>{picked?.label ?? "Select an evidence node"}</h4>
            <p>{picked?.detail ?? "Select a node to inspect its recorded identity or response."}</p>
            <div className="mon3d-rail-stat">
              <span>Current event</span><strong>{current?.headline ?? "No event selected"}</strong>
            </div>
            <div className="mon3d-rail-stat">
              <span>Last matched IP header</span>
              <strong>{model.lastPacketAt ?? "None retained"}</strong>
            </div>
          </section>
          <section className="mon3d-rail-card mon3d-rail-playback">
            <small>02 / RECORDED TIMELINE</small>
            <div className="mon3d-player" aria-label="Recorded event playback">
              <button type="button" data-testid="incident-play"
                disabled={model.timeline.length < 2}
                onClick={() => setPlaying(value => !value)}>
                {playing ? "PAUSE Ⅱ" : "PLAY ▶"}
              </button>
              <span>{model.timeline.length ? momentIndex + 1 + " / " + model.timeline.length : "NO EVENTS"}</span>
            </div>
            <input type="range" min={0} max={Math.max(0, model.timeline.length - 1)}
              value={momentIndex} disabled={!model.timeline.length}
              aria-label="Select timeline event" onChange={event => {
                setPlaying(false);
                setMomentIndex(Number(event.target.value));
              }} />
            <time>{current?.timestamp ?? "Timestamp not recorded"}</time>
            <p>{current?.description ?? "Recorded events will appear when MON creates an incident."}</p>
          </section>
          <div className="mon3d-rail-note">
            Only recorded MON entities are drawn. Lines denote case associations,
            not verified network hops. Playback cannot execute containment.
          </div>
        </aside>
      </div>
      <p className="mon3d-disclaimer">
        Playback is a sequence of recorded evidence, not reconstructed packet timing.
        The scene is read-only and never authorizes response execution.
      </p>
    </article>
  );
}

export default function Investigation3D({
  incidents, executions, audits, capture, tenantId, siteId, initialIncidentId, onOpen
}: {
  incidents: Incident[];
  executions: ResponseExecution[];
  audits: AuditRecord[];
  capture: PacketCaptureSnapshot | null;
  tenantId: string;
  siteId: string;
  initialIncidentId?: string;
  onOpen: (incident: Incident) => void;
}) {
  const [choice, setChoice] = useState("");
  const [investigation, setInvestigation] = useState<IncidentInvestigation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const cases = useMemo(() => [...incidents].sort((a, b) =>
    b.last_seen.localeCompare(a.last_seen)), [incidents]);
  const id = cases.some(c => c.incident_id === choice) ? choice :
    cases.some(c => c.incident_id === initialIncidentId) ? initialIncidentId! :
      cases[0]?.incident_id ?? "";
  useEffect(() => {
    if (!id) { setInvestigation(null); return; }
    let cancelled = false;
    setInvestigation(null); setError(null);
    fetchInvestigation(id, tenantId, siteId).then(value => {
      if (!cancelled) {
        if (value.incident.incident_id !== id) setError("Case mismatch from investigation API");
        else setInvestigation(value);
      }
    }).catch((cause: unknown) => {
      if (!cancelled) setError(cause instanceof ApiError ?
        "Investigation HTTP " + cause.status : "Investigation unavailable");
    });
    return () => { cancelled = true; };
  }, [id, tenantId, siteId]);
  const model = useMemo(() => investigation ?
    buildIncidentScene(investigation, executions, audits, capture) : null,
    [investigation, executions, audits, capture]);
  return <section className="mon3d-page" data-testid="investigation-3d">
    <header className="mon3d-casebar">
      <div><span>MON / INVESTIGATION STUDIO</span><h2>Incident Reconstruction</h2></div>
      <label>SELECT CASE
        <select aria-label="Choose incident reconstruction" value={id}
          onChange={e => setChoice(e.target.value)}>
          {!cases.length && <option value="">No incidents</option>}
          {cases.map(c => <option value={c.incident_id} key={c.incident_id}>
            {c.title} · {c.incident_id.slice(0, 8)}</option>)}
        </select>
      </label>
      {id && <button type="button" onClick={() => {
        const item = cases.find(c => c.incident_id === id);
        if (item) onOpen(item);
      }}>OPEN CASE ↗</button>}
    </header>
    {!cases.length && <p className="mon3d-empty">No incident records are available to reconstruct.</p>}
    {error && <p role="alert" className="mon3d-empty">{error}</p>}
    {id && !error && !model && <p className="mon3d-empty" role="status">Loading MON evidence…</p>}
    {model && <Incident3DScene key={id} model={model} />}
  </section>;
}
