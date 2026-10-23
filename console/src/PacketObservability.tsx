import { useEffect, useMemo, useState } from "react";
import type { PacketCaptureSnapshot } from "./types";
import { selectProtectedRoute } from "./routeEvidence";

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

export function PacketHistory({ capture, compact = false, protectedOnly = false }: {
  capture: PacketCaptureSnapshot | null;
  compact?: boolean;
  protectedOnly?: boolean;
}) {
  const [display, setDisplay] = useState<"average" | "raw">("average");
  const samples = protectedOnly ? (capture?.protected_route_samples ?? []) : (capture?.samples ?? []);
  const { raw, smoothed, ceiling, total } = useMemo(() => {
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
  }, [samples]);
  const capturing = capture?.status === "CAPTURING" &&
    (!protectedOnly || (Boolean(capture.protected_host_ip) &&
      Array.isArray(capture.protected_route_samples)));
  const lastFive = samples.slice(-5);
  const recentPackets = lastFive.reduce((sum, row) => sum + row.packets, 0);
  const recentBytes = lastFive.reduce((sum, row) => sum + row.bytes, 0);
  const pps = recentPackets / Math.max(1, lastFive.length);
  const series = display === "average" ? smoothed : raw;
  const displayPath = graphPath(series, ceiling);
  const rawPath = graphPath(raw, ceiling);
  const interfaces = Object.entries(capture?.observed_interfaces ?? {})
    .sort((a, b) => b[1] - a[1]).map(([name]) => name);
  const scope = capture?.capture_scope ?? "wg0";
  const protectedRoute = selectProtectedRoute(capture);
  const events = capture?.events ?? [];
  const lastPacket = protectedOnly
    ? protectedRoute.lastSeen ? new Date(protectedRoute.lastSeen).toLocaleTimeString() : "none recorded"
    : capture?.last_packet_at
      ? new Date(capture.last_packet_at * 1000).toLocaleTimeString()
      : "none recorded";
  return (
    <section className={"mon-panel mon-traffic-panel" + (compact ? " mon-traffic-compact" : "")} data-testid="live-packet-history">
      <div className="mon-panel-heading">
        <div>
          <span className="mon-eyebrow">NETWORK / MEASURED IP HEADERS</span>
          <h2>{protectedOnly ? "Live PC-5 gateway traffic" : "Live network traffic"}</h2>
          <p>{protectedOnly
            ? "Filtered: " + (capture?.protected_host_ip || "PC-5 address not configured") +
              " on " + protectedRoute.captureInterface + " · observed IP frames per second"
            : "Scope: " + (scope === "any" ? "ALL PC2 host interfaces (background included)" : scope) +
              " · one-second measurements · 90-second window"}</p>
        </div>
        <span className={"mon-tag " + (capturing ? "mon-tag-active" : "")}>
          <span className="mon-dot" />{capture?.status ?? "CONNECTING"}
        </span>
      </div>
      <div className="mon-flow-metrics">
        <div><span>{protectedOnly ? "IP FRAMES / LAST 5S" : "PACKETS / LAST 5S"}</span><strong>{capturing ? human(recentPackets) : "—"}</strong></div>
        <div><span>MEASURED PACKETS / S (5S AVG)</span><strong>{capturing ? pps.toFixed(2) : "—"}</strong></div>
        <div><span>BYTES / LAST 5S</span><strong>{capturing ? human(recentBytes) : "—"}</strong></div>
        <div><span>{protectedOnly ? "90-SECOND IP FRAMES" : "90-SECOND PACKETS"}</span><strong>{capturing ? human(total) : "—"}</strong></div>
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
            className="mon-chart-empty">{protectedOnly && !capture?.protected_host_ip
              ? "PC-5 ADDRESS NOT CONFIGURED"
              : protectedOnly && !capture?.protected_route_samples
                ? "TARGET-SCOPED SENSOR COUNTERS UNAVAILABLE"
                : capture?.error ?? "NO MEASURED PACKETS"}</text>}
        </svg>
      </div>
      <div className="mon-chart-footer">
        <span>{protectedOnly
          ? "PC-5 MATCHING FRAMES " + protectedRoute.observedFrames + " · ICMP " +
            protectedRoute.icmpFrames + " · LAST MATCH " + lastPacket
          : "RAW FRAMES " + (capture?.raw_frames ?? "—") + " · DECODED IP " +
            (capture?.decoded_packets ?? "—") + " · LAST PACKET " + lastPacket}</span>
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
      {compact && <p className="mon-compact-network-hint">{protectedOnly
        ? "Only packets matching the configured protected IP on the selected tunnel are charted. ICMP/ping is included; no synthetic traffic."
        : "PC2 aggregate traffic includes unrelated hosts. Protected PC5 traffic is reported separately below."}</p>}
      <p className="mon-packet-caveat">5S RATE averages measured one-second frames, not generated traffic. PC-2 cannot inspect traffic that bypasses its interfaces; forwarded packets can appear on both RX and TX. An IP frame is not a verified end-to-end packet.</p>
    </section>
  );
}


export function ProtectedRouteStrip({ capture }: { capture: PacketCaptureSnapshot | null }) {
  const route = selectProtectedRoute(capture);
  return (
    <section className="mon-protected-strip" data-testid="pc5-protected-strip">
      <div>
        <small>PROTECTED SITE · TUNNEL CAPTURE</small>
        <strong>{route.configured ? "PC-5 gateway traffic" : "Victim IP not configured"}</strong>
      </div>
      <div><small>TARGET IP</small><strong>{route.target ?? "UNCONFIGURED"}</strong></div>
      <div><small>OBSERVED PEER</small><strong>{route.peer ?? "Unknown Source"}</strong></div>
      <div><small>IP FRAMES · 90S</small><strong>{route.observedFrames}</strong></div>
      <div><small>ICMP FRAMES · 90S</small><strong>{route.icmpFrames}</strong></div>
      <div><small>CAPTURE PATH</small><strong>{route.captureInterface}</strong></div>
      <p>
        {route.configured
          ? "Only observed packets involving the configured PC-5 address on the selected tunnel. IP frame counts are not unique end-to-end packets."
          : "Set MON_PROTECTED_HOST_IP on the PC-2 portal service to enable evidence-based route monitoring."}
      </p>
    </section>
  );
}

export function NetworkPath({ capture }: { capture: PacketCaptureSnapshot | null }) {
  const route = selectProtectedRoute(capture);
  const observedIfaces = Object.keys(capture?.observed_interfaces ?? {});
  const status = !route.configured ? "TARGET UNCONFIGURED"
    : !route.events.length ? "NO MATCHING TUNNEL FRAMES"
    : route.active && route.observedBothDirections ? "RECENT RX/TX OBSERVED"
    : route.active ? "RECENT CAPTURE OBSERVED"
    : "RECENT FRAME HISTORY";
  const peerLabel = route.peer ?? "Unknown Source";
  return (
    <section className="mon-panel mon-topology-panel" data-testid="network-path">
      <div className="mon-panel-heading">
        <div>
          <span className="mon-eyebrow">PROTECTED WEB SERVER / CAPTURED IP FRAMES</span>
          <h2>Observed traffic toward PC-5</h2>
          <p>PC-2 is the intended gateway. Interface capture alone does not prove the forwarding rule or successful IPS enforcement.</p>
        </div>
        <span className="mon-tag">{status}</span>
      </div>
      <div className="mon-topology-canvas">
        <svg viewBox="0 0 1040 265" role="img"
          aria-label="Observed peer and configured PC-5 endpoint through intended PC-2 gateway">
          <defs>
            <marker id="mon-arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
              <path d="M0 0 L0 6 L9 3 Z" fill="currentColor" />
            </marker>
          </defs>
          <path className={"mon-route" + (route.active ? " mon-route-active" : "")}
            d="M260 167 H403" markerEnd="url(#mon-arrow)" />
          <path className={"mon-route" + (route.active ? " mon-route-active" : "")}
            d="M637 167 H782" markerEnd="url(#mon-arrow)" />
          {route.active && <circle cx="260" cy="167" r="5"
            className="mon-traffic-pulse mon-pulse-leg1" />}
          <rect className="mon-node mon-node-attacker" x="26" y="93" width="234" height="152" rx="4" />
          <text className="mon-node-label mon-inverse" x="45" y="122">01 / OBSERVED PEER</text>
          <text className="mon-node-title mon-inverse" x="45" y="165">Unverified identity</text>
          <text className="mon-node-ip mon-inverse" x="45" y="196">{peerLabel}</text>
          <text className="mon-node-info mon-inverse" x="45" y="223">Observed IP · not assumed PC-6</text>

          <rect className="mon-node" x="404" y="93" width="233" height="152" rx="4" />
          <text className="mon-node-label" x="423" y="122">02 / CAPTURE GATEWAY</text>
          <text className="mon-node-title" x="423" y="165">PC-2 · MON gateway</text>
          <text className="mon-node-ip" x="423" y="196">{route.captureInterface}</text>
          <text className="mon-node-info" x="423" y="223">Inline forwarding not yet proven</text>

          <rect className="mon-node" x="783" y="93" width="231" height="152" rx="4" />
          <text className="mon-node-label" x="802" y="122">03 / PROTECTED TARGET</text>
          <text className="mon-node-title" x="802" y="165">PC-5 · Web server</text>
          <text className="mon-node-ip" x="802" y="196">{route.target ?? "Not configured"}</text>
          <text className="mon-node-info" x="802" y="223">Actual address from portal config</text>

          <text className="mon-link-label" x="332" y="140" textAnchor="middle">OBSERVED</text>
          <text className="mon-link-label" x="710" y="140" textAnchor="middle">INTENDED ROUTE</text>
        </svg>
      </div>
      <div className="mon-route-observations" data-testid="route-observation-summary">
        <span>CAPTURE: {capture?.status ?? "CONNECTING"}</span>
        <span data-testid="route-count">PC-5: {route.observedFrames} matching frame observations · {human(route.observedBytes)} IP bytes (90s)</span>
        <span>ICMP: {route.icmpFrames} observed frames</span>
        <span>RX/TX ON CAPTURE IFACE: {route.observedBothDirections ? "BOTH" : "NOT BOTH"}</span>
        <span>LAST SEEN: {route.lastSeen ? new Date(route.lastSeen).toLocaleTimeString() : "NOT OBSERVED"}</span>
        <span>INTERFACES ON PC2: {observedIfaces.join(", ") || capture?.capture_scope || "UNKNOWN"}</span>
      </div>
      <div className="mon-flow-section">
        <div className="mon-panel-heading mon-panel-heading-small">
          <h3>Recorded PC-5 conversations <span>90-SECOND WINDOW · SENSOR FRAMES</span></h3>
          <span>{route.events.length} captured frames</span>
        </div>
        <div className="mon-flow-table-wrapper">
          <table className="mon-flow-table">
            <thead><tr><th>TIME</th><th>INTERFACE</th><th>DIRECTION</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOL</th><th>IP BYTES</th></tr></thead>
            <tbody>
              {route.events.slice(0, 50).map((event, index) => (
                <tr key={event.timestamp + ":" + index}>
                  <td>{new Date(event.timestamp).toLocaleTimeString()}</td>
                  <td>{event.interface}</td>
                  <td>{event.direction.toUpperCase()}</td>
                  <td>{event.src_ip}</td>
                  <td>{event.dst_ip}</td>
                  <td>{event.protocol}{event.dst_port == null ? "" : ":" + event.dst_port}</td>
                  <td>{event.ip_bytes}</td>
                </tr>
              ))}
              {!route.events.length && <tr>
                <td colSpan={7} className="mon-flow-empty">
                  {!route.configured
                    ? "No protected IP configured. MON will not invent a victim or attacker address."
                    : capture?.status !== "CAPTURING"
                      ? "Sensor is unavailable: inspect portal capture permissions and interface."
                      : "No matching traffic reached this capture interface in the last 90 seconds. Verify the network route to PC-5."}
                </td>
              </tr>}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
