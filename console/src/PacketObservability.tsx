import { useEffect, useMemo, useState } from "react";
import type { PacketCaptureSnapshot, PacketFlow } from "./types";

const COUNT = 90;
const WIDTH = 1000;
const HEIGHT = 260;

export function usePacketCapture(authenticated: boolean): PacketCaptureSnapshot | null {
  const [capture, setCapture] = useState<PacketCaptureSnapshot | null>(null);
  useEffect(() => {
    if (!authenticated) return;
    let cancelled = false;
    async function poll() {
      try {
        const response = await fetch("/portal/flows", { credentials: "same-origin" });
        if (!response.ok) throw new Error("capture unavailable");
        const next = await response.json() as PacketCaptureSnapshot;
        if (!cancelled) setCapture(next);
      } catch {
        if (!cancelled) setCapture({
          source: "linux-af_packet", interface: "wg0", capture_scope: "wg0", status: "UNAVAILABLE",
          error: "Packet sensor unavailable", observed_at: new Date().toISOString(),
          sample_interval_seconds: 1, capture_window_seconds: COUNT,
          direction: "inbound and outbound", packet_layer: "IP", samples: [], flows: []
        });
      }
    }
    void poll();
    const timer = window.setInterval(() => void poll(), 1000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [authenticated]);
  return authenticated ? capture : null;
}

function human(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + "G";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
  return n.toString();
}

function graphPath(values: number[], maximum: number): string {
  const x0 = 45, dx = (WIDTH - 65) / (COUNT - 1), bottom = HEIGHT - 40;
  return values.map((value, index) =>
    (index ? "L" : "M") +
    (x0 + dx * index).toFixed(2) + " " +
    (bottom - (value / maximum) * (bottom - 22)).toFixed(2)
  ).join(" ");
}

/**
 * A trailing arithmetic mean of REAL recorded one-second packet counts.
 * Never interpolates missing traffic or modifies the captured measurements.
 */
export function trailingPacketRate(samples: number[], seconds = 5): number[] {
  return samples.map((_, index) => {
    let sum = 0;
    const from = Math.max(0, index - seconds + 1);
    for (let i = from; i <= index; i += 1) sum += samples[i];
    return sum / (index - from + 1);
  });
}

export function PacketHistory({ capture, compact = false }: { capture: PacketCaptureSnapshot | null; compact?: boolean }) {
  const [display, setDisplay] = useState<"average" | "raw">("average");
  const { raw, smoothed, ceiling, total } = useMemo(() => {
    const samples = capture?.samples ?? [];
    const bySecond = new Map(samples.map(row => [row.second, row.packets]));
    const end = samples.at(-1)?.second ?? 0;
    const raw = Array.from({ length: COUNT }, (_, index) =>
      bySecond.get(end - (COUNT - index - 1)) ?? 0
    );
    const smoothed = trailingPacketRate(raw, 5);
    return {
      raw,
      smoothed,
      ceiling: Math.max(1, ...raw, ...smoothed),
      total: raw.reduce((sum, current) => sum + current, 0)
    };
  }, [capture]);
  const capturing = capture?.status === "CAPTURING";
  const lastFive = capture?.samples.slice(-5) ?? [];
  const recentPackets = lastFive.reduce((sum, row) => sum + row.packets, 0);
  const recentBytes = lastFive.reduce((sum, row) => sum + row.bytes, 0);
  const pps = recentPackets / Math.max(1, lastFive.length);
  const series = display === "average" ? smoothed : raw;
  const displayPath = graphPath(series, ceiling);
  const rawPath = graphPath(raw, ceiling);
  const interfaces = Object.entries(capture?.observed_interfaces ?? {})
    .sort((a, b) => b[1] - a[1]).map(([name]) => name);
  const scope = capture?.capture_scope ?? "wg0";
  const events = capture?.events ?? [];
  const lastPacket = capture?.last_packet_at
    ? new Date(capture.last_packet_at * 1000).toLocaleTimeString()
    : "none recorded";
  return (
    <section className={"mon-panel mon-traffic-panel" + (compact ? " mon-traffic-compact" : "")} data-testid="live-packet-history">
      <div className="mon-panel-heading">
        <div>
          <span className="mon-eyebrow">NETWORK / MEASURED IP HEADERS</span>
          <h2>Live network traffic</h2>
          <p>Scope: {scope === "any" ? "PC2 host interfaces" : scope} · one-second measurements · 90-second window</p>
        </div>
        <span className={"mon-tag " + (capturing ? "mon-tag-active" : "")}>
          <span className="mon-dot" />{capture?.status ?? "CONNECTING"}
        </span>
      </div>
      <div className="mon-flow-metrics">
        <div><span>PACKETS / LAST 5S</span><strong>{capturing ? human(recentPackets) : "—"}</strong></div>
        <div><span>MEASURED PACKETS / S (5S AVG)</span><strong>{capturing ? pps.toFixed(2) : "—"}</strong></div>
        <div><span>BYTES / LAST 5S</span><strong>{capturing ? human(recentBytes) : "—"}</strong></div>
        <div><span>90-SECOND PACKETS</span><strong>{capturing ? human(total) : "—"}</strong></div>
      </div>
      <div className="mon-chart-control">
        <span>{display === "average" ? "BLACK: 5-second trailing average · GRAY: raw 1-second counts" : "BLACK: raw captured packets per second"}</span>
        <div className="mon-graph-switch" aria-label="Packet chart calculation">
          <button type="button" aria-pressed={display === "average"} onClick={() => setDisplay("average")}>5S RATE</button>
          <button type="button" aria-pressed={display === "raw"} onClick={() => setDisplay("raw")}>RAW 1S</button>
        </div>
      </div>
      <div className="mon-chart-frame">
        <svg viewBox={"0 0 " + WIDTH + " " + HEIGHT} preserveAspectRatio="xMidYMid meet"
          role="img" aria-label="Measured packet rate, with a selectable five-second trailing average or raw one-second data">
          {Array.from({ length: 5 }, (_, i) => {
            const y = 22 + i * ((HEIGHT - 62) / 4);
            return <g key={i}>
              <line className="mon-grid-line" x1="45" x2={WIDTH - 20} y1={y} y2={y} />
              <text className="mon-svg-label" x="37" y={y + 4} textAnchor="end">
                {(ceiling * (1 - i / 4)).toFixed(1)}
              </text>
            </g>;
          })}
          {capturing && <>
            {display === "average" && <path className="mon-packet-raw" d={rawPath} />}
            <path className="mon-packet-line" d={displayPath} data-testid="measured-rate-path" />
          </>}
          {[0, 30, 60, 89].map(index => <text key={index}
            className="mon-svg-label" textAnchor="middle"
            x={45 + index * ((WIDTH - 65) / 89)} y={HEIGHT - 11}>
            {index === 89 ? "NOW" : "-" + (89 - index) + "s"}
          </text>)}
          {!capturing && <text x={WIDTH / 2} y="125" textAnchor="middle"
            className="mon-chart-empty">{capture?.error ?? "NO MEASURED PACKETS"}</text>}
        </svg>
      </div>
      <div className="mon-chart-footer">
        <span>RAW FRAMES {capture?.raw_frames ?? "—"} · DECODED IP {capture?.decoded_packets ?? "—"} · LAST PACKET {lastPacket}</span>
        <span>Observed interfaces: {interfaces.join(", ") || scope}</span>
      </div>
      {!compact && <div className="mon-flow-section" data-testid="real-network-event-log">
        <div className="mon-panel-heading mon-panel-heading-small">
          <h3>Recent network observations <span>REAL IP METADATA · NOT SIMULATED</span></h3>
          <span>{events.length} recent records · volatile buffer</span>
        </div>
        <div className="mon-flow-table-wrapper">
          <table className="mon-flow-table">
            <thead>
              <tr><th>TIME</th><th>INTERFACE</th><th>DIRECTION</th><th>SOURCE</th><th>DESTINATION</th><th>PROTO / PORT</th><th>IP BYTES</th></tr>
            </thead>
            <tbody>
              {events.slice(0, 24).map((event, index) => <tr key={event.timestamp + ":" + index}>
                <td>{new Date(event.timestamp).toLocaleTimeString()}</td>
                <td>{event.interface}</td>
                <td>{event.direction}</td>
                <td>{event.src_ip}</td>
                <td>{event.dst_ip}</td>
                <td>{event.protocol}{event.dst_port == null ? "" : ":" + event.dst_port}</td>
                <td>{event.ip_bytes}</td>
              </tr>)}
              {!events.length && <tr><td colSpan={7} className="mon-flow-empty">
                No IP header observations recorded yet. Check capture scope, capabilities and actual interface traffic.
              </td></tr>}
            </tbody>
          </table>
        </div>
      </div>}
      {compact && <p className="mon-compact-network-hint">Full packet log and protocol analysis are available in Network.</p>}
      <p className="mon-packet-caveat">5S RATE is a calculated average of measured one-second samples, never a packet generator. PC2 cannot observe traffic that bypasses PC2. Forwarded packets seen on multiple interfaces may appear more than once.</p>
    </section>
  );
}

function protocol(flow: PacketFlow): string {
  return flow.protocol + (flow.dst_port == null ? "" : ":" + flow.dst_port);
}

export function NetworkPath({
  capture, attackerIps
}: {
  capture: PacketCaptureSnapshot | null;
  attackerIps: string[];
}) {
  const measured = capture?.status === "CAPTURING";
  const source = attackerIps.includes("10.77.0.60") ? "10.77.0.60" :
    (attackerIps.find(ip => ip !== "10.77.0.1") ?? "10.77.0.60");
  const flows = capture?.flows ?? [];
  const target = "10.77.0.50";
  const now = Date.parse(capture?.observed_at ?? "");
  const recent = (capture?.lab_route_events ?? capture?.events ?? []).filter(event =>
    ((event.src_ip === source && event.dst_ip === target) ||
     (event.src_ip === target && event.dst_ip === source)) &&
    Number.isFinite(Date.parse(event.timestamp)) &&
    now - Date.parse(event.timestamp) >= 0 &&
    now - Date.parse(event.timestamp) <= 90000
  );
  const active = measured && recent.some(event =>
    now - Date.parse(event.timestamp) <= 5000
  );
  const recentBytes = recent.reduce((sum, event) => sum + event.ip_bytes, 0);
  const lastMatch = recent.length ? new Date(recent[0].timestamp).toLocaleTimeString() : null;
  const observedIfaces = Object.keys(capture?.observed_interfaces ?? {});

  return (
    <section className="mon-panel mon-topology-panel" data-testid="network-path">
      <div className="mon-panel-heading">
        <div>
          <span className="mon-eyebrow">EVIDENCE-BACKED ROUTE RECONSTRUCTION</span>
          <h2>Attacker / Router / Protected endpoint</h2>
          <p>The verified lab forwarding path is drawn separately from live packet observations.</p>
        </div>
        <span className="mon-tag">{active ? "TRAFFIC OBSERVED NOW" : recent.length ? "RECENT MATCH" : "NO MATCHING RECENT PACKETS"}</span>
      </div>
      <div className="mon-topology-canvas">
        <svg viewBox="0 0 1040 265" role="img"
          aria-label="Three computer lab topology: PC6, via PC2 gateway, to PC5">
          <defs>
            <marker id="mon-arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
              <path d="M0 0 L0 6 L9 3 Z" fill="currentColor" />
            </marker>
          </defs>
          <path className={"mon-route" + (active ? " mon-route-active" : "")}
            d="M260 167 H403" markerEnd="url(#mon-arrow)" />
          <path className={"mon-route" + (active ? " mon-route-active" : "")}
            d="M637 167 H782" markerEnd="url(#mon-arrow)" />
          {active && <>
            <circle cx="260" cy="167" r="5" className="mon-traffic-pulse mon-pulse-leg1" />
            <circle cx="637" cy="167" r="5" className="mon-traffic-pulse mon-pulse-leg2" />
          </>}
          <rect className="mon-node mon-node-attacker" x="26" y="93" width="234" height="152" rx="4" />
          <text className="mon-node-label mon-inverse" x="45" y="122">01 / OBSERVED SOURCE</text>
          <text className="mon-node-title mon-inverse" x="45" y="165">PC6 · Lab source</text>
          <text className="mon-node-ip mon-inverse" x="45" y="196">{source}</text>
          <text className="mon-node-info mon-inverse" x="45" y="223">Test source · normal or attack traffic</text>

          <rect className="mon-node" x="404" y="93" width="233" height="152" rx="4" />
          <text className="mon-node-label" x="423" y="122">02 / ROUTE + RESPONSE</text>
          <text className="mon-node-title" x="423" y="165">PC2 · MON Router</text>
          <text className="mon-node-ip" x="423" y="196">10.77.0.1</text>
          <text className="mon-node-info" x="423" y="223">WireGuard · nftables</text>

          <rect className="mon-node" x="783" y="93" width="231" height="152" rx="4" />
          <text className="mon-node-label" x="802" y="122">03 / PROTECTED SYSTEM</text>
          <text className="mon-node-title" x="802" y="165">PC5 · Linux Host</text>
          <text className="mon-node-ip" x="802" y="196">10.77.0.50</text>
          <text className="mon-node-info" x="802" y="223">SSH · endpoint collector</text>

          <text className="mon-link-label" x="332" y="140" textAnchor="middle">TUNNEL</text>
          <text className="mon-link-label" x="710" y="140" textAnchor="middle">FORWARDED</text>

        </svg>
      </div>
      <div className="mon-route-observations" data-testid="route-observation-summary">
        <span>CAPTURE: {capture?.status ?? "CONNECTING"}</span>
        <span data-testid="route-count">PC6 ↔ PC5: {recent.length} observed IP packets · {human(recentBytes)} IP bytes (90s)</span>
        <span>LAST SEEN: {lastMatch ?? "NOT OBSERVED"}</span>
        <span>INTERFACES: {observedIfaces.join(", ") || capture?.capture_scope || "UNKNOWN"}</span>
      </div>
      <div className="mon-flow-section">
        <div className="mon-panel-heading mon-panel-heading-small">
          <h3>Active network conversations <span>10-SECOND WINDOW</span></h3>
          <span>{flows.length} measured flows</span>
        </div>
        <div className="mon-flow-table-wrapper">
          <table className="mon-flow-table">
            <thead><tr><th>SOURCE</th><th>DESTINATION</th><th>TRANSPORT</th><th>PACKETS</th><th>BYTES</th></tr></thead>
            <tbody>
              {flows.slice(0, 15).map((flow, index) => <tr key={index}>
                <td>{flow.src_ip}</td><td>{flow.dst_ip}</td>
                <td>{protocol(flow)}{flow.src_ip === "10.77.0.60" && flow.dst_ip === "10.77.0.50" &&
                  flow.protocol === "ICMP" ? " · EXPECTED-BASELINE" : ""}</td>
                <td>{human(flow.packets)}</td><td>{human(flow.bytes)}</td>
              </tr>)}
              {!flows.length && <tr>
                <td colSpan={5} className="mon-flow-empty">
                  {measured ? "No IP conversations observed during this aggregation window" :
                    "Capture unavailable · no invented network conversations"}
                </td>
              </tr>}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
