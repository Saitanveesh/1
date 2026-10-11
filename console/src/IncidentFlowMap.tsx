import { useMemo, useState } from "react";
import type { PacketCaptureSnapshot } from "./types";
import type { SceneModel } from "./Incident3D";
import "./IncidentFlowMap.css";

interface Props {
  model: SceneModel;
  capture: PacketCaptureSnapshot | null;
}

function safeDate(value: string | null | undefined): number | null {
  const parsed = value ? Date.parse(value) : NaN;
  return Number.isFinite(parsed) ? parsed : null;
}

export function grafanaCaseUrl(model: SceneModel, hostname: string): string {
  const times = model.timeline.map(event => safeDate(event.timestamp))
    .filter((value): value is number => value !== null);
  const start = times.length ? new Date(Math.min(...times) - 5 * 60_000).toISOString() : "now-1h";
  const end = times.length ? new Date(Math.max(...times) + 5 * 60_000).toISOString() : "now";
  const params = new URLSearchParams({ orgId: "1", from: start, to: end, refresh: "5s" });
  return "http://" + hostname + ":3000/d/mon-network?" + params.toString();
}

export function observedForTarget(
  source: string | null, targetIps: string[], capture: PacketCaptureSnapshot | null
) {
  if (!source || !targetIps.length || capture?.status !== "CAPTURING") return [];
  // Lab-route events are a subset of the general capture buffer. Merge rather than
  // prefer them, so an unrelated new incident still gets its own packet matches.
  const packets = [...(capture.events ?? []), ...(capture.lab_route_events ?? [])];
  const matches = packets.filter(event =>
    (event.src_ip === source && targetIps.includes(event.dst_ip)) ||
    (event.dst_ip === source && targetIps.includes(event.src_ip))
  );
  const unique = new Map(matches.map(event => [
    [event.timestamp, event.interface, event.direction, event.src_ip, event.dst_ip,
      event.protocol, event.dst_port, event.ip_bytes].join("|"), event
  ]));
  return [...unique.values()];
}

function TrafficTrace({ capture }: { capture: PacketCaptureSnapshot | null }) {
  const samples = (capture?.samples ?? []).slice(-90);
  const values = samples.map(sample => Math.max(0, sample.packets));
  const peak = Math.max(1, ...values);
  const points = values.map((value, index) =>
    (values.length < 2 ? 50 : (index / (values.length - 1)) * 100).toFixed(2) +
    "," + (34 - value / peak * 30).toFixed(2)
  ).join(" ");
  const latest = values.slice(-5);
  const rate = latest.length ? (latest.reduce((sum, value) => sum + value, 0) / latest.length).toFixed(1) : "—";
  return <section className="mon-flow-signal" data-testid="mon-normal-traffic">
    <div className="mon-flow-signal-heading">
      <div><small>PC2 NETWORK SENSOR · CONTINUOUS</small><h4>Measured traffic</h4></div>
      <span className={capture?.status === "CAPTURING" ? "mon-flow-online" : "mon-flow-offline"}>
        {capture?.status ?? "CONNECTING"}
      </span>
    </div>
    {capture?.status === "CAPTURING" && values.length ?
      <svg viewBox="0 0 100 36" preserveAspectRatio="none"
        role="img" aria-label="Measured incoming and outgoing network packet samples; rolling capture window">
        <path d="M0 35 H100" stroke="#d5d5d5" fill="none" vectorEffect="non-scaling-stroke" />
        <polyline points={points} stroke="#171717" strokeWidth="1.15" fill="none"
          vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
      </svg> :
      <div className="mon-flow-no-signal">{capture?.error ??
        "Waiting for the PC2 packet sensor. No samples will be invented."}</div>}
    <div className="mon-flow-signal-footer">
      <span>{rate} packets/s (latest available samples)</span>
      <span>{capture?.capture_scope ?? capture?.interface ?? "No capture interface"}</span>
    </div>
    <p>Traffic continues to be measured when no attack is active. This graph shows PC2-visible traffic,
      not a historical recording of this case or a full-network tap.</p>
  </section>;
}

/** The only network edges shown as observed are supported by actual captured IP headers. */
export default function IncidentFlowMap({ model, capture }: Props) {
  const [view, setView] = useState<"3d" | "2d">("3d");
  const [focus, setFocus] = useState<string | null>(null);
  const assets = model.nodes.filter(node => node.kind === "asset");
  const evidence = model.nodes.filter(node => node.kind === "evidence");
  const responses = model.nodes.filter(node => node.kind === "response");
  const selected = model.nodes.find(node => node.id === focus);
  const packets = capture?.status === "CAPTURING" ? observedForTarget(model.source, model.targets, capture) : [];
  const last = packets.map(row => row.timestamp).sort().at(-1) ?? null;
  const protocols = [...new Set(packets.map(event =>
    event.protocol + (event.dst_port ? ":" + event.dst_port : "")
  ))].slice(0, 5);
  const hostname = typeof window !== "undefined" ? window.location.hostname : "100.75.116.62";
  const grafana = useMemo(() => grafanaCaseUrl(model, hostname), [model, hostname]);

  return <article className="mon-flow-workspace" data-testid="incident-3d-scene">
    <header className="mon-flow-head">
      <div>
        <small>CASE NETWORK VIEW / {model.kind.toUpperCase()}</small>
        <h3>{model.label}</h3>
        <p>Follow the source, affected device, evidence, and response without confusing them for network hops.</p>
      </div>
      <div className="mon3d-switch" aria-label="Network diagram perspective">
        <button type="button" aria-pressed={view === "3d"} onClick={() => setView("3d")}>3D</button>
        <button type="button" aria-pressed={view === "2d"} onClick={() => setView("2d")}>2D</button>
      </div>
    </header>
    <div className="mon-flow-summary">
      <span><b>{assets.length}</b> affected {assets.length === 1 ? "device" : "devices"}</span>
      <span><b>{evidence.length}</b> evidence records</span>
      <span><b>{model.timeline.length}</b> case events</span>
      <span><b>{packets.length}</b> captured matching IP headers (recent window)</span>
    </div>
    <div className="mon-flow-grid">
      <section className="mon-flow-network">
        <div className="mon-flow-network-title">
          <div><small>01 / NETWORK RELATIONSHIP</small><h4>Source to affected device</h4></div>
          <span>{packets.length ? "RECENT IP HEADERS OBSERVED" : "CASE RELATIONSHIP ONLY"}</span>
        </div>
        <div className={"mon-flow-diagram" + (view === "3d" ? " is-depth" : "")}
          data-testid={view === "3d" ? "incident-3d-viewport" : "incident-2d-view"}>
          <button type="button" className="mon-flow-node mon-flow-source"
            data-testid="mon3d-node-source"
            onClick={() => setFocus("source:" + model.source)}
            title="Recorded finding source. Does not establish a physical ingress path.">
            <small>ORIGIN / SOURCE IP</small>
            <strong>{model.source ?? "Source not identified"}</strong>
            <span>{model.source ? "Found in case evidence" : "Not provided by the investigation"}</span>
          </button>
          <div className="mon-flow-links">
            <svg viewBox="0 0 150 56" role="img" aria-label="Source to target relationship">
              <path d="M 7 28 H 135" fill="none" stroke="#222" strokeWidth="2.5"
                strokeDasharray={packets.length ? undefined : "6 6"} />
              <path d="M 133 19 L 144 28 L 133 37" fill="none" stroke="#222"
                strokeWidth="2.5" strokeLinejoin="round" />
            </svg>
            <strong>{packets.length ? packets.length + " recent packet headers" : "Not packet-verified"}</strong>
            <small>{protocols.length ? protocols.join(" · ") : "Association from the case record"}</small>
          </div>
          <div className="mon-flow-destinations">
            {assets.map(node => {
              const ips = node.detail.split(",").map(ip => ip.trim())
                .filter(ip => model.targets.includes(ip));
              const targetPackets = observedForTarget(model.source, ips, capture);
              return <button type="button" className="mon-flow-node mon-flow-target"
                data-testid="mon3d-node-asset" key={node.id}
                onClick={() => setFocus(node.id)}>
                <small>PROTECTED ASSET</small>
                <strong>{node.label}</strong>
                <span>{node.detail}</span>
                <em>{targetPackets.length ? targetPackets.length + " matching headers" :
                  "No matching recent headers"}</em>
              </button>;
            })}
            {!assets.length && <div className="mon-flow-node mon-flow-target">
              <small>PROTECTED ASSET</small><strong>Not resolved</strong>
              <span>No device mapped to this case</span>
            </div>}
          </div>
        </div>
        <div className="mon-flow-verification">
          <strong>{packets.length ? "Packet observation available" : "Packet path not established"}</strong>
          <p>{packets.length ?
            "IP headers for this source and target were seen by the current PC2 capture window. They do not prove intermediate routing hops." :
            "The source and device are associated by the investigation. No matching headers were retained in the current capture window; historical traffic is not reconstructed."}</p>
          <span>Last matching header: {last ? new Date(last).toLocaleString() : "None in retained window"}</span>
        </div>
        <TrafficTrace capture={capture} />
      </section>
      <aside className="mon-flow-case">
        <section className="mon-flow-case-card">
          <small>02 / WHY MON FLAGGED THIS CASE</small>
          <h4>Evidence and detection</h4>
          <p>These are case records, not devices in the traffic path. Select an entry to inspect it.</p>
          {evidence.map(node => <button type="button" key={node.id}
            className={focus === node.id ? "is-selected" : ""}
            data-testid="mon3d-node-evidence" onClick={() => setFocus(node.id)}>
            <span>EVIDENCE</span><strong>{node.label}</strong>
          </button>)}
          {!evidence.length && <p>No evidence records supplied.</p>}
        </section>
        <section className="mon-flow-case-card">
          <small>03 / WHAT HAPPENED NEXT</small>
          <h4>Detection and response</h4>
          <p>{model.timeline.filter(moment => moment.kind === "FINDING").length} findings in the recorded case sequence.</p>
          {responses.map(node => <button type="button" key={node.id}
            className={focus === node.id ? "is-selected" : ""}
            data-testid="mon3d-node-response" onClick={() => setFocus(node.id)}>
            <span>RESPONSE</span><strong>{node.label}</strong>
          </button>)}
          {!responses.length && <p>No response recorded.</p>}
        </section>
        <section className="mon-flow-inspector" data-testid="scene-inspector">
          <small>SELECTED RECORD</small>
          <h4>{selected?.label ?? "Inspect a device or record"}</h4>
          <p>{selected?.detail ?? "Select a source, device, evidence record, or response above."}</p>
          <div><span>Last matched IP header</span>
            <strong>{last ? new Date(last).toLocaleString() : "None retained"}</strong></div>
        </section>
        <section className="mon-flow-grafana">
          <small>04 / MEASURED TRAFFIC CONTEXT</small>
          <h4>Review in Grafana</h4>
          <p>Opens the case's recorded time window. Grafana graphs PC2 aggregate traffic,
            so spikes are not automatically attributable to this incident.</p>
          <a href={grafana} target="_blank" rel="noopener noreferrer">OPEN CASE WINDOW IN GRAFANA ↗</a>
        </section>
      </aside>
    </div>
    <footer className="mon-flow-footer">
      Each selected incident builds its own view from its investigation record. This is a read-only diagram;
      containment actions remain in the incident Response tab.
    </footer>
  </article>;
}
