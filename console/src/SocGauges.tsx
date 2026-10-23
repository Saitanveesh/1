import type { LiveState } from "./live";
import type { PacketCaptureSnapshot } from "./types";
import type { IdsObservation } from "./suricataThreats";
import { isProtectedCaptureReady, isRecentObservation } from "./operationalTruth";
import "./SocGauges.css";

function Metric({
  name, display, foot
}: { name: string; display: string; foot: string }) {
  return <article className="mon-truth-metric">
    <div className="mon-gauge-name">{name}</div>
    <strong className="mon-truth-value">{display}</strong>
    <small>{foot}</small>
  </article>;
}

export default function SocGauges({
  state, capture, ids
}: {
  state: LiveState;
  capture: PacketCaptureSnapshot | null;
  ids: IdsObservation;
}) {
  const verified = isProtectedCaptureReady(capture);
  const samples = verified ? (capture?.protected_route_samples ?? []) : [];
  const lastFive = samples.slice(-5);
  const pps = lastFive.reduce((sum, item) => sum + item.packets, 0) / 5;
  const bps = lastFive.reduce((sum, item) => sum + item.bytes, 0) / 5;
  const icmp = samples.reduce((sum, item) => sum + item.icmp_packets, 0);
  const idsReady = ids.availability === "AVAILABLE" &&
    ids.snapshot?.service_state === "active";
  const currentAlerts = idsReady
    ? (ids.snapshot?.records ?? []).filter(row =>
        row.event_type === "alert" &&
        row.dst_ip === capture?.protected_host_ip &&
        isRecentObservation(row.timestamp, Date.now(), 120_000)).length
    : null;
  const scope = capture?.protected_host_ip || "UNCONFIGURED";
  return <section className="mon-gauges" data-testid="soc-gauges">
    <div className="mon-gauges-header">
      <div>
        <span>PROTECTED ENDPOINT / SOURCE-VERIFIED MEASUREMENTS</span>
        <h2>PC-5 security telemetry</h2>
      </div>
      <a href="http://100.75.116.62:3000/d/mon-network" target="_blank"
        rel="noopener noreferrer">OPEN GRAFANA ↗</a>
    </div>
    <div className="mon-gauge-grid">
      <Metric name="PC-5 CAPTURED FRAMES / S"
        display={verified ? pps.toFixed(1) : "NO DATA"}
        foot="Actual IP frames · last 5 seconds" />
      <Metric name="PC-5 CAPTURED IP BYTES / S"
        display={verified ? bps.toFixed(0) + " B/s" : "NO DATA"}
        foot="Actual header-based bytes · last 5 seconds" />
      <Metric name="PC-5 ICMP FRAMES"
        display={verified ? String(icmp) : "NO DATA"}
        foot="ICMP / ICMPv6 frames · rolling 90 seconds" />
      <Metric name="PC-5 IDS RULE MATCHES"
        display={currentAlerts === null ? "UNVERIFIED" : String(currentAlerts)}
        foot="Suricata EVE signature records · last 2 minutes" />
    </div>
    <p className="mon-gauges-note">
      Target: {scope} · Interface: {capture?.protected_capture_interface || "UNVERIFIED"} ·
      {state.connection === "LIVE" ? " MON API connected" : " MON API not connected"}.
      Data is withheld when the targeted sensor is missing or stale.
      Frame observations can include RX/TX duplicates; IDS alerts do not prove IPS blocking.
    </p>
  </section>;
}
