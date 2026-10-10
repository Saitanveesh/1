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
          source: "linux-af_packet", interface: "wg0", status: "UNAVAILABLE",
          error: "Packet sensor unavailable", observed_at: new Date().toISOString(),
          sample_interval_seconds: 1, capture_window_seconds: COUNT,
          direction: "Incoming only", packet_layer: "IP", samples: [], flows: []
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

export function PacketHistory({ capture }: { capture: PacketCaptureSnapshot | null }) {
  const { packets, ceiling, total } = useMemo(() => {
    const source = capture?.samples ?? [];
    const bySecond = new Map(source.map(s => [s.second, s.packets]));
    const end = source.at(-1)?.second ?? 0;
    const values = Array.from({ length: COUNT }, (_, index) =>
      bySecond.get(end - (COUNT - index - 1)) ?? 0
    );
    return {
      packets: values,
      ceiling: Math.max(1, ...values),
      total: values.reduce((a, b) => a + b, 0)
    };
  }, [capture]);
  const capturing = capture?.status === "CAPTURING";
  const now = capture?.samples.at(-1);
  const path = graphPath(packets, ceiling);
  return (
    <section className="mon-panel mon-traffic-panel" data-testid="live-packet-history">
      <div className="mon-panel-heading">
        <div>
          <span className="mon-eyebrow">NETWORK / WIREGUARD INGEST</span>
          <h2>Live packet flow</h2>
          <p>Real IP packet headers · wg0 ingress · 1-second buckets · rolling 90s window</p>
        </div>
        <span className={"mon-tag " + (capturing ? "mon-tag-active" : "")}>
          <span className="mon-dot" />{capture?.status ?? "CONNECTING"}
        </span>
      </div>
      <div className="mon-flow-metrics">
        <div><span>PACKETS / SECOND</span><strong>{capturing ? human(now?.packets ?? 0) : "—"}</strong></div>
        <div><span>BYTES / SECOND</span><strong>{capturing ? human(now?.bytes ?? 0) : "—"}</strong></div>
        <div><span>90-SECOND PACKETS</span><strong>{capturing ? human(total) : "—"}</strong></div>
        <div><span>SOURCE</span><strong className="mon-smaller">{capturing ? "AF_PACKET · wg0" : "NOT CONNECTED"}</strong></div>
      </div>
      <div className="mon-chart-frame">
        <svg viewBox={"0 0 " + WIDTH + " " + HEIGHT} preserveAspectRatio="xMidYMid meet"
          role="img" aria-label="Measured packets per second for the last 90 seconds">
          {Array.from({ length: 5 }, (_, i) => {
            const y = 22 + i * ((HEIGHT - 62) / 4);
            return <g key={i}>
              <line className="mon-grid-line" x1="45" x2={WIDTH - 20} y1={y} y2={y} />
              <text className="mon-svg-label" x="37" y={y + 4} textAnchor="end">
                {human(Math.round(ceiling * (1 - i / 4)))}
              </text>
            </g>;
          })}
          {capturing && <>
            <path className="mon-packet-area" d={path + " L 980 220 L 45 220 Z"} />
            <path className="mon-packet-line" d={path} />
          </>}
          {[0, 30, 60, 89].map(index => <text key={index}
            className="mon-svg-label" textAnchor="middle"
            x={45 + index * ((WIDTH - 65) / 89)} y={HEIGHT - 11}>
            {index === 89 ? "NOW" : "-" + (89 - index) + "s"}
          </text>)}
          {!capturing && <text x={WIDTH / 2} y="125" textAnchor="middle"
            className="mon-chart-empty">{capture?.error ?? "AWAITING MEASURED PACKET DATA"}</text>}
        </svg>
      </div>
      <div className="mon-chart-footer">
        <span>BLACK TRACE = CAPTURED PACKETS / SECOND</span>
        <span>{capturing ? new Date(capture.observed_at).toLocaleTimeString() : "NO GENERATED OR ESTIMATED PACKETS"}</span>
      </div>
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
  const traffic = flows.filter(f => f.src_ip === source && f.dst_ip === "10.77.0.50");
  const packets = traffic.reduce((n, flow) => n + flow.packets, 0);
  const bytes = traffic.reduce((n, flow) => n + flow.bytes, 0);

  return (
    <section className="mon-panel mon-topology-panel" data-testid="network-path">
      <div className="mon-panel-heading">
        <div>
          <span className="mon-eyebrow">EVIDENCE-BACKED ROUTE RECONSTRUCTION</span>
          <h2>Attacker / Router / Protected endpoint</h2>
          <p>The verified lab forwarding path is drawn separately from live packet observations.</p>
        </div>
        <span className="mon-tag">{packets ? "PACKETS OBSERVED" : "NO CURRENT PACKETS"}</span>
      </div>
      <div className="mon-topology-canvas">
        <svg viewBox="0 0 1040 330" role="img"
          aria-label="Three computer lab topology: PC6, via PC2 gateway, to PC5">
          <defs>
            <marker id="mon-arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
              <path d="M0 0 L0 6 L9 3 Z" fill="currentColor" />
            </marker>
          </defs>
          <path className={"mon-route" + (packets ? " mon-route-active" : "")}
            d="M260 167 H403" markerEnd="url(#mon-arrow)" />
          <path className={"mon-route" + (packets ? " mon-route-active" : "")}
            d="M637 167 H782" markerEnd="url(#mon-arrow)" />
          {packets > 0 && <>
            <circle r="5" className="mon-traffic-pulse">
              <animateMotion path="M260 167 H403" dur="1.7s" repeatCount="indefinite" />
            </circle>
            <circle r="5" className="mon-traffic-pulse">
              <animateMotion path="M637 167 H782" dur="1.7s" repeatCount="indefinite" />
            </circle>
          </>}
          <rect className="mon-node mon-node-attacker" x="26" y="93" width="234" height="152" rx="4" />
          <text className="mon-node-label" x="45" y="122">01 / ATTACK SOURCE</text>
          <text className="mon-node-title" x="45" y="165">PC6 · Attacker</text>
          <text className="mon-node-ip" x="45" y="196">{source}</text>
          <text className="mon-node-info" x="45" y="223">Observed in auth evidence</text>

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
          <text className="mon-route-note" x="520" y="289" textAnchor="middle">
            {packets ? human(packets) + " packets · " + human(bytes) + " bytes · 10-second window" :
              "No packet observation for this route in the latest window"}
          </text>
          <text className="mon-svg-label" x="520" y="313" textAnchor="middle">
            {measured ? "Measured on PC2 wg0; no payload capture" :
              "Packet capture offline; incident source is independently supported by PC5 auth logs"}
          </text>
        </svg>
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
                <td>{flow.src_ip}</td><td>{flow.dst_ip}</td><td>{protocol(flow)}</td>
                <td>{human(flow.packets)}</td><td>{human(flow.bytes)}</td>
              </tr>)}
              {!flows.length && <tr>
                <td colSpan={5} className="mon-flow-empty">
                  {measured ? "No incoming IP packets observed in the latest window" :
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
