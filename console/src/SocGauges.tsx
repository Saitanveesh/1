import type { LiveState } from "./live";
import type { PacketCaptureSnapshot } from "./types";
import "./SocGauges.css";

interface GaugeProps { name: string; display: string; percent: number | null; foot: string; }
function Gauge({ name, display, percent, foot }: GaugeProps) {
  const bounded = percent === null ? 0 : Math.min(100, Math.max(0, percent));
  return <article className="mon-gauge">
    <div className="mon-gauge-name">{name}</div>
    <div className="mon-gauge-ring" style={{
      background: "conic-gradient(#101010 0 " + (bounded * .75) +
        "turn, #dedede " + (bounded * .75) + "turn .75turn, transparent .75turn 1turn)"
    }}>
      <div className="mon-gauge-center"><strong>{display}</strong></div>
    </div>
    <small>{foot}</small>
  </article>;
}

export default function SocGauges({
  state, capture
}: { state: LiveState; capture: PacketCaptureSnapshot | null }) {
  const samples = capture?.samples.slice(-5) ?? [];
  const packets = samples.reduce((n, s) => n + s.packets, 0);
  const bytes = samples.reduce((n, s) => n + s.bytes, 0);
  const count = samples.length || 1;
  const pps = packets / count;
  const bps = bytes / count;
  const incidents = state.incidents.filter(r => r.status !== "CLOSED");
  const verifiedCapture = capture?.status === "CAPTURING";
  const alerts = state.findings.length;
  return <section className="mon-gauges" data-testid="soc-gauges">
    <div className="mon-gauges-header">
      <div><span>OBSERVABILITY / MEASURED VALUES</span><h2>Security operations telemetry</h2></div>
      <a href="http://100.75.116.62:3000/d/mon-network" target="_blank"
        rel="noopener noreferrer">OPEN GRAFANA ↗</a>
    </div>
    <div className="mon-gauge-grid">
      <Gauge name="PACKET RATE" display={verifiedCapture ? pps.toFixed(1) + "/s" : "—"}
        percent={verifiedCapture ? Math.min(100, 100 * pps / 100) : null}
        foot="Observed 5s average · 100 pps reference" />
      <Gauge name="BANDWIDTH" display={verifiedCapture ? Math.round(bps) + " B/s" : "—"}
        percent={verifiedCapture ? Math.min(100, 100 * bps / 50000) : null}
        foot="Observed 5s average · 50 kB/s reference" />
      <Gauge name="OPEN INCIDENTS" display={String(incidents.length)}
        percent={Math.min(100, incidents.length * 10)}
        foot="Recorded MON cases · 10 incident reference" />
      <Gauge name="DETECTION FINDINGS" display={String(alerts)}
        percent={Math.min(100, alerts * 10)}
        foot="MON findings · not Suricata rule count" />
    </div>
    <p className="mon-gauges-note">
      Gauges show measured values and explicitly labeled reference scales, not network utilization
      against a measured link capacity. Grafana requires its own running service and login.
    </p>
  </section>;
}
