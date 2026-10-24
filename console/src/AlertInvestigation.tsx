import { useState } from "react";
import type { SecurityThreatAlert } from "./securityAlerts";
import type { PacketCaptureSnapshot, SuricataSnapshot } from "./types";
import { recordKey } from "./suricataThreats";
import Stage4ResponsePanel from "./Stage4ResponsePanel";
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

export function alertReport(alert: SecurityThreatAlert, acknowledgedAt: string | null,
  sensorRecordFound: boolean, matchedFrames: number): string {
  return [
    "Security detection", "",
    "What was detected: " + alert.title,
    "Severity: " + alert.severity,
    "Observed at: " + alert.observedAt,
    "Source address: " + alert.source,
    "Destination address: " + alert.target,
    "Detection: " + alert.detector,
    "Rule: " + (alert.signatureId ?? "Not available"),
    "Exact sensor record retained: " + (sensorRecordFound ? "Yes" : "Not currently available"),
    "Corroborating packet headers retained: " + matchedFrames,
    "Review status: " + (acknowledgedAt ? "Acknowledged at " + acknowledgedAt : "Not acknowledged"),
    "",
    "Scope: Detection of a network pattern; does not establish a successful attack or that traffic was blocked."
  ].join("\n");
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
  const [detail, setDetail] = useState<"summary" | "evidence">("summary");
  const [copyState, setCopyState] = useState<string | null>(null);
  const report = alertReport(alert, acknowledgedAt, Boolean(signature), frames.length);
  async function copyReport(): Promise<void> {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard access unavailable");
      await navigator.clipboard.writeText(report);
      setCopyState("Report copied");
    } catch {
      setCopyState("Clipboard unavailable. Select the evidence text to copy it.");
    }
  }
  return <section className="mon-alert-investigation panel full" data-testid="alert-evidence-investigation">
    <div className="mon-alert-investigation-head">
      <div>
        <button type="button" className="mon-alert-back" onClick={onClose}>← Back to alerts</button>
        <h2>{alert.title}</h2>
        <p>Here is what the monitoring system actually recorded.</p>
      </div>
      <div className="mon-alert-investigation-status">
        <span className={"severity " + alert.severity.toLowerCase()}>{alert.severity}</span>
        <span className={acknowledgedAt ? "mon-review-ok" : "mon-review-pending"}>
          {acknowledgedAt ? "Acknowledged" : "Needs review"}
        </span>
      </div>
    </div>
    <div className="mon-alert-flow" aria-label="Detection route">
      <div><small>Traffic from</small><strong>{alert.source}</strong><span>Address reported by the sensor</span></div>
      <span className="mon-alert-flow-arrow" aria-hidden="true">→</span>
      <div><small>Traffic to</small><strong>{alert.target}</strong><span>Monitored destination</span></div>
    </div>
    <div className="mon-alert-investigation-actions">
      <button type="button" onClick={onAcknowledge}
        disabled={acknowledging || !!acknowledgedAt}>
        {acknowledging ? "SAVING REVIEW…" : acknowledgedAt ? "ACKNOWLEDGED" : "ACKNOWLEDGE DETECTION"}
      </button>
      <button type="button" onClick={() => void copyReport()}>Copy report</button>
      {onOpenCase && <button type="button" onClick={onOpenCase}>Open related case →</button>}
      <button type="button" onClick={onClose}>BACK TO ALERTS</button>
    </div>
    {copyState && <p className="mon-alert-copy-state" role="status">{copyState}</p>}
    {error && <p role="alert" className="mon-alert-investigation-error">{error}</p>}
    {acknowledgedAt && <p className="mon-alert-investigation-confirmation" role="status">
      Reviewed on {new Date(acknowledgedAt).toLocaleString()}.
      {isIds ? " This review is saved on the monitoring gateway." :
        " This review is saved for this browser session only."}
      {" "}Acknowledging an alert does not stop traffic or close a case.
    </p>}
    <div className="mon-alert-section-tabs" role="tablist" aria-label="Investigation sections">
      <button type="button" role="tab" aria-selected={detail === "summary"}
        onClick={() => setDetail("summary")}>Overview</button>
      <button type="button" role="tab" aria-selected={detail === "evidence"}
        onClick={() => setDetail("evidence")}>Captured evidence</button>
    </div>
    {detail === "summary" && <>
      <div className="mon-alert-explanation">
        <div className="mon-alert-conclusion">
          <span className="mon-alert-step">1</span>
          <div><h3>What happened?</h3>
            <p>A monitoring rule matched network activity from <strong>{alert.source}</strong> to <strong>{alert.target}</strong>.</p>
            <p>{alert.title} was reported at <strong>{new Date(alert.observedAt).toLocaleString()}</strong>.</p>
          </div>
        </div>
        <div className="mon-alert-conclusion">
          <span className="mon-alert-step">2</span>
          <div><h3>What supports this alert?</h3>
            <p>{signature
              ? "The exact detection record is available from the sensor."
              : isIds ? "The original notification was received, but the sensor's recent record has expired or is unavailable." :
                "This alert came from a recorded MON finding or case."}</p>
            <p>{frames.length
              ? frames.length + " matching network frame observations are retained in the current capture window."
              : "There are no independently captured matching packet headers retained for this time."}</p>
          </div>
        </div>
        <div className="mon-alert-conclusion">
          <span className="mon-alert-step">3</span>
          <div><h3>What should happen next?</h3>
            <p>Check the evidence before deciding whether the activity needs further investigation.
              A detection alone does not prove that an attack succeeded.</p>
            <p>{acknowledgedAt
              ? "The alert has been acknowledged. You can still reopen and inspect it."
              : "When you have reviewed the details, acknowledge the alert to record that you checked it."}</p>
          </div>
        </div>
      </div>
      <div className="mon-alert-clear-note">Detection and acknowledgment do not stop traffic. The optional containment controls below apply only to the fictional training lab.</div>
    </>}
    {detail === "evidence" && <div className="mon-alert-investigation-subsections">
      <div>
        <h3>Detection record</h3>
        {signature ? <dl className="mon-alert-facts">
          <dt>Signature</dt><dd>{signature.signature}</dd>
          <dt>Category</dt><dd>{signature.category ?? "Not reported"}</dd>
          <dt>Protocol</dt><dd>{signature.protocol} / {signature.application || "unknown"}</dd>
          <dt>Source port</dt><dd>{signature.src_port ?? "—"}</dd>
          <dt>Destination port</dt><dd>{signature.dst_port ?? "—"}</dd>
          <dt>Suricata event time</dt><dd>{signature.timestamp}</dd>
          <dt>Rule ID</dt><dd>{signature.signature_id ?? "Not recorded"}</dd>
        </dl> : <p className="mon-alert-evidence-empty">
          {isIds
            ? "The exact EVE signature is no longer in the sensor's bounded recent records. The original alert details remain above."
            : "This notification came from MON's case or finding stream, not a Suricata signature."}
        </p>}
      </div>
      <div>
        <h3>Observed network frames</h3>
        <p>Frames with matching addresses within 30 seconds of this detection, from the monitored interface. These are real recorded packet headers, not reconstructed traffic; the same forwarded packet may appear more than once.</p>
        <div className="mon-alert-frame-scroll">
          <table className="mon-flow-table">
            <thead><tr><th>Time</th><th>Direction</th><th>Source</th><th>Destination</th><th>Protocol</th><th>IP bytes</th></tr></thead>
            <tbody>
              {frames.map((frame, index) => <tr key={frame.frame_id ?? frame.timestamp + ":" + index}>
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
    </div>}
    <Stage4ResponsePanel alert={alert} />
  </section>;
}
