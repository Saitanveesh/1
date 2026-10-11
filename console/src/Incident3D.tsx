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
    kind: "source", x: -3.3, y: .7, z: 0, ref: source
  });
  assets.forEach((asset, i) => {
    const offset = i - (assets.length - 1) / 2;
    nodes.push({
      id: "asset:" + asset.asset_id, label: asset.display_name,
      detail: asset.ip_addresses.join(", ") || asset.asset_id,
      kind: "asset", x: kind === "reconnaissance" ? 3 : 2.45,
      y: offset * 1.8, z: assets.length < 2 ? 0 : Math.sin(i * 1.2) * 1.1,
      ref: asset.asset_id
    });
    if (source) links.push({
      id: "case:" + i, from: "source:" + source, to: "asset:" + asset.asset_id,
      relation: "Case association; not a packet-level hop", recorded: false
    });
  });
  investigation.evidence.slice(0, 6).forEach((e, i) => {
    const angle = i * Math.PI * 2 / Math.max(1, Math.min(investigation.evidence.length, 6));
    nodes.push({
      id: "evidence:" + e.evidence_id, label: e.evidence_class,
      detail: e.summary, kind: "evidence",
      x: Math.cos(angle) * 1.15, y: Math.sin(angle) * 1.25,
      z: -1.4, ref: e.evidence_id
    });
    const target = assets[i % Math.max(assets.length, 1)];
    if (target) links.push({
      id: "evidence:" + i, from: "evidence:" + e.evidence_id,
      to: "asset:" + target.asset_id, relation: "Attached MON evidence",
      recorded: true
    });
  });
  related.slice(0, 4).forEach((r, i) => {
    nodes.push({
      id: "response:" + r.execution_id,
      label: r.plan.request.action + " · " + r.status,
      detail: r.execution_id, kind: "response",
      x: -1.15 + i * 1.12, y: -2.3, z: 1.1, ref: r.execution_id
    });
    if (assets[0]) links.push({
      id: "response:" + i, from: "response:" + r.execution_id,
      to: "asset:" + assets[0].asset_id, relation: "Recorded response",
      recorded: true
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
  const [verifiedOnly, setVerifiedOnly] = useState(true);
  const dragging = useRef<{ x: number; y: number } | null>(null);
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
  return (
    <article className="mon3d-workspace" data-testid="incident-3d-scene">
      <div className="mon3d-scene-head">
        <div><small>CASE-BASED SPATIAL RECONSTRUCTION / {model.kind.toUpperCase()}</small>
          <h3>{model.label}</h3>
          <p>Only recorded entities are placed. Spatial distance is a layout aid, not a network hop count.</p>
        </div>
        <div className="mon3d-switch">
          <button type="button" aria-pressed={projection === "3d"} onClick={() => setProjection("3d")}>3D</button>
          <button type="button" aria-pressed={projection === "2d"} onClick={() => setProjection("2d")}>2D</button>
          <button type="button" onClick={() => setCamera({ x: -23, y: -19, zoom: 1 })}>RESET</button>
        </div>
      </div>
      <div className="mon3d-scene-meta">
        <span>{model.nodes.length} EVIDENCE / ENTITY NODES</span>
        <span>{model.packets} MATCHED RECENT IP HEADERS</span>
        <label><input type="checkbox" checked={verifiedOnly}
          onChange={e => setVerifiedOnly(e.target.checked)} /> VERIFIED LINKS ONLY</label>
      </div>
      {projection === "3d" ? (
        <div className="mon3d-stage" data-testid="incident-3d-viewport"
          role="region" tabIndex={0} aria-label="Interactive 3D evidence topology; drag to orbit"
          onPointerDown={e => {
            if ((e.target as HTMLElement).closest("button")) return;
            dragging.current = { x: e.clientX, y: e.clientY };
            e.currentTarget.setPointerCapture(e.pointerId);
          }}
          onPointerMove={e => {
            if (!dragging.current) return;
            const dx = e.clientX - dragging.current.x;
            const dy = e.clientY - dragging.current.y;
            dragging.current = { x: e.clientX, y: e.clientY };
            setCamera(v => ({ ...v, y: v.y + dx * .3,
              x: Math.max(-65, Math.min(65, v.x - dy * .3)) }));
          }}
          onPointerUp={() => { dragging.current = null; }}
          onPointerCancel={() => { dragging.current = null; }}
          onWheel={e => setCamera(v => ({ ...v, zoom: Math.max(.6, Math.min(1.6, v.zoom - e.deltaY * .0008)) }))}
          onKeyDown={e => {
            if (e.key === "ArrowLeft") setCamera(v => ({ ...v, y: v.y - 9 }));
            if (e.key === "ArrowRight") setCamera(v => ({ ...v, y: v.y + 9 }));
            if (e.key === "+") setCamera(v => ({ ...v, zoom: Math.min(1.6, v.zoom + .1) }));
            if (e.key === "-") setCamera(v => ({ ...v, zoom: Math.max(.6, v.zoom - .1) }));
          }}>
          <div className="mon3d-grid" />
          <div className="mon3d-universe" style={{
            transform: "rotateX(" + camera.x + "deg) rotateY(" + camera.y +
              "deg) scale(" + camera.zoom + ")"
          }}>
            {model.links.filter(l => !verifiedOnly || l.recorded).map(link => {
              const a = model.nodes.find(n => n.id === link.from);
              const b = model.nodes.find(n => n.id === link.to);
              return a && b ? <SceneEdge key={link.id} a={a} b={b} recorded={link.recorded} /> : null;
            })}
            {model.nodes.map(node => <button type="button" key={node.id}
              data-testid={"mon3d-node-" + node.kind}
              className={"mon3d-node " + node.kind + (selected === node.id ? " selected" : "")}
              title={node.detail}
              style={{ left: "calc(50% + " + (node.x * 82) + "px)",
                top: "calc(50% - " + (node.y * 82) + "px)",
                transform: "translate3d(-50%, -50%, " + (node.z * 82) + "px)" }}
              onClick={() => setSelected(node.id)}>
              <small>{node.kind.toUpperCase()}</small><strong>{node.label}</strong>
            </button>)}
          </div>
          <span className="mon3d-help">DRAG TO ORBIT · SCROLL TO ZOOM · ARROWS TO ROTATE</span>
        </div>
      ) : <div className="mon3d-list" data-testid="incident-2d-view">
        {model.nodes.map(node => <button type="button" key={node.id}
          onClick={() => setSelected(node.id)}><small>{node.kind.toUpperCase()}</small>
          <strong>{node.label}</strong><span>{node.detail}</span></button>)}
      </div>}
      <div className="mon3d-inspect" data-testid="scene-inspector">
        <div><small>ENTITY</small><strong>{picked?.label ?? "Select a node"}</strong></div>
        <div><small>RECORD</small><strong>{picked?.detail ?? "MON case evidence"}</strong></div>
        <div><small>CURRENT EVENT</small><strong>{current?.headline ?? "No timestamped records"}</strong></div>
        <div><small>LAST PACKET OBSERVATION</small><strong>{model.lastPacketAt ?? "None retained"}</strong></div>
      </div>
      <div className="mon3d-player" aria-label="Recorded event playback">
        <button type="button" data-testid="incident-play" disabled={model.timeline.length < 2}
          onClick={() => setPlaying(v => !v)}>{playing ? "PAUSE" : "PLAY"} {playing ? "Ⅱ" : "▶"}</button>
        <input type="range" min={0} max={Math.max(0, model.timeline.length - 1)}
          value={momentIndex} disabled={!model.timeline.length}
          aria-label="Select timeline event" onChange={e => {
            setPlaying(false);
            setMomentIndex(Number(e.target.value));
          }} />
        <span>{model.timeline.length ? (momentIndex + 1) + " / " + model.timeline.length : "NO EVENTS"}</span>
        <time>{current?.timestamp ?? "Time not retained"}</time>
      </div>
      <p className="mon3d-disclaimer">
        Playback is a sequence of recorded evidence, not reconstructed packet timing.
        The scene is read-only and never authorizes response execution.
      </p>
    </article>
  );
}

export default function Investigation3D({
  incidents, executions, audits, capture, tenantId, siteId, onOpen
}: {
  incidents: Incident[];
  executions: ResponseExecution[];
  audits: AuditRecord[];
  capture: PacketCaptureSnapshot | null;
  tenantId: string;
  siteId: string;
  onOpen: (incident: Incident) => void;
}) {
  const [choice, setChoice] = useState("");
  const [investigation, setInvestigation] = useState<IncidentInvestigation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const cases = useMemo(() => [...incidents].sort((a, b) =>
    b.last_seen.localeCompare(a.last_seen)), [incidents]);
  const id = cases.some(c => c.incident_id === choice) ? choice : cases[0]?.incident_id ?? "";
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
