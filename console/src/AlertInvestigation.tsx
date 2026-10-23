import type { SecurityThreatAlert } from "./securityAlerts";
import type { PacketCaptureSnapshot, SuricataRecord, SuricataSnapshot } from "./types";
import { recordKey } from "./suricataThreats";
import "./AlertInvestigation.css";

export function evidenceForAlert(
  alert: SecurityThreatAlert,
  snapshot: SuricataSnapshot | null,
  capture: PacketCaptureSnapshot | null
) {
  const isIds = alert.key.startsWith("ids:");
  const signature = isIds
    ? snapshot?.records.find(row =>
        row.event_type === "alert" && ("ids:" + recordKey(row)) === alert.key
      ) ?? null
    : null;
  const at = Date.parse(alert.observedAt);
  const frames = (capture?.lab_route_events ?? [])
    .filter(frame => {
      const stamped = Date.parse(frame.timestamp);
      return Number.isFinite(at) && Number.isFinite(stamped) &&
        Math.abs(stamped - at) <= 30_000 &&
        frame.interface === capture?.protected_capture_interface &&
        ((frame.src_ip === alert.source && frame.dst_ip === alert.target) ||
         (frame.src_ip === alert.target && frame.dst_ip === alert.source));
    })
    .slice(0, 25);
  return { signature, frames, isIds };
}

export default function AlertInvestigation({
  alert, snapshot, capture, acknowledgedAt, acknowledging, error,
  onAcknowledge, onClose, onOpenCase
}: {
  alert: SecurityThreatAlert;
  snapshot: SuricataSnapshot | null;
  capture: PacketCaptureSnapshot | null;
  acknowledgedAt: string | null;
  acknowledging: boolean;
  error: string | null;
  onAcknowledge: () => void;
  onClose: () => void;
  onOpenCase?: () => void;
}) {
  const { signature, frames, isIds } = evidenceForAlert(alert, snapshot, capture);
  return <section className="mon-alert-investigation panel full" data-testid="alert-evidence-investigation">
    <div className="mon-alert-investigation-head">
      <div>
        <span className="eyebrow">DETECTION EVIDENCE / {isIds ? "SURICATA EVE" : "MON EVENT"}</span>
        <h2>{alert.title}</h2>
        <p>Detection does not establish compromise. This is observed alert metadata, not a reconstructed attack or an automatically blocked request.</p>
      </div>
      <span className={"severity " + alert.severity.toLowerCase()}>{alert.severity}</span>
    </div>
    <div className="mon-alert-investigation-stats">
      <div><small>SOURCE FROM DETECTOR</small><strong>{alert.source}</strong></div>
      <div><small>PROTECTED DESTINATION</small><strong>{alert.target}</strong></div>
      <div><small>DETECTION TIME</small><strong>{new Date(alert.observedAt).toLocaleString()}</strong></div>
      <div><small>PROVENANCE</small><strong>{alert.detector}</strong></div>
      <div><small>SIGNATURE ID</small><strong>{signature?.signature_id ?? alert.signatureId ?? "NOT PROVIDED"}</strong></div>
      <div><small>OPERATOR REVIEW</small><strong>{acknowledgedAt ? "ACKNOWLEDGED" : "NOT ACKNOWLEDGED"}</strong></div>
    </div>
    <div className="mon-alert-investigation-actions">
      <button type="button" onClick={onAcknowledge} disabled={acknowledging || !!acknowledgedAt}>
        {acknowledging ? "SAVING REVIEW…" : acknowledgedAt ? "ACKNOWLEDGED" : "ACKNOWLEDGE DETECTION"}
      </button>
      {onOpenCase && <button type="button" onClick={onOpenCase}>OPEN RECORDED CASE ↗</button>}
      <button type="button" onClick={onClose}>RETURN TO OVERVIEW ↗</button>
    </div>
    {error && <p role="alert" className="mon-alert-investigation-error">{error}</p>}
    {acknowledgedAt && <p className="mon-alert-investigation-confirmation" role="status">
      Acknowledged {new Date(acknowledgedAt).toLocaleString()}. This records operator review only; it does not close a MON incident, suppress a sensor or block traffic.
    </p>}
    <div className="mon-alert-investigation-subsections">
      <div>
        <h3>IDS signature record</h3>
        {signature ? <dl className="mon-alert-facts">
          <dt>Signature</dt><dd>{signature.signature}</dd>
          <dt>Category</dt><dd>{signature.category ?? "Not reported"}</dd>
          <dt>Protocol</dt><dd>{signature.protocol} / {signature.application || "unknown"}</dd>
          <dt>Source port</dt><dd>{signature.src_port ?? "—"}</dd>
          <dt>Destination port</dt><dd>{signature.dst_port ?? "—"}</dd>
          <dt>Suricata event time</dt><dd>{signature.timestamp}</dd>
        </dl> : <p className="mon-alert-evidence-empty">
          {isIds
            ? "The exact EVE signature is no longer in the sensor's bounded recent records. The original alert details remain above."
            : "This notification came from MON's case or finding stream, not a Suricata signature."}
        </p>}
      </div>
      <div>
        <h3>Independent packet-header observations</h3>
        <p>Matching source/destination pairs on the configured capture interface, within ±30 seconds of the alert. Each row is an observed IP frame; forwarded traffic may be counted twice.</p>
        <div className="mon-alert-frame-scroll">
          <table className="mon-flow-table">
            <thead><tr><th>TIME</th><th>DIRECTION</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOL</th><th>IP BYTES</th></tr></thead>
            <tbody>
              {frames.map(frame => <tr key={frame.frame_id ?? frame.timestamp}>
                <td>{new Date(frame.timestamp).toLocaleTimeString()}</td>
                <td>{frame.direction}</td><td>{frame.src_ip}</td><td>{frame.dst_ip}</td>
                <td>{frame.protocol}{frame.dst_port == null ? "" : ":" + frame.dst_port}</td>
                <td>{frame.ip_bytes}</td>
              </tr>)}
              {frames.length === 0 && <tr><td colSpan={6}>
                No matching independent packet headers retained for this alert. This does not invalidate the IDS signature, but packet-level corroboration is unavailable.
              </td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </section>;
}
