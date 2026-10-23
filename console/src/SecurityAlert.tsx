import { useEffect, useRef } from "react";
import type { SecurityThreatAlert } from "./securityAlerts";
import "./SecurityAlert.css";

interface Props {
  alert: SecurityThreatAlert;
  queued: number;
  onInvestigate: () => void;
  onAcknowledge: () => void;
  acknowledging?: boolean;
  acknowledgeError?: string | null;
}

export default function SecurityAlert({
  alert, queued, onInvestigate, onAcknowledge,
  acknowledging = false, acknowledgeError = null
}: Props) {
  const actionRef = useRef<HTMLButtonElement>(null);
  useEffect(() => { actionRef.current?.focus(); }, [alert.key]);
  return <div className="mon-threat-overlay" data-testid="live-threat-overlay">
    <section className="mon-threat-window" role="alertdialog" aria-modal="true"
      aria-labelledby="mon-threat-heading" aria-describedby="mon-threat-summary">
      <header className="mon-threat-header">
        <span className="mon-threat-brand"><span className="mon-threat-mark">!</span> Security alert</span>
        <span className="mon-threat-live">New detection</span>
      </header>
      <div className="mon-threat-card">
        <div className="mon-threat-titlebar">
          <h2 id="mon-threat-heading">Suspicious activity detected</h2>
          <span className={"severity " + alert.severity.toLowerCase()}>{alert.severity}</span>
        </div>
        <p className="mon-threat-evidence-title" id="mon-threat-summary">{alert.title}</p>
        <div className="mon-threat-grid">
          <div><span>Source address</span><strong>{alert.source}</strong></div>
          <div><span>Destination address</span><strong>{alert.target}</strong></div>
          <div><span>Detected by</span><strong>{alert.detector}</strong></div>
          <div><span>When</span><strong>{new Date(alert.observedAt).toLocaleString()}</strong></div>
        </div>
        <p className="mon-threat-proof">This alert is based on recorded detection evidence. It does not mean that an attack succeeded.</p>
        {acknowledgeError && <p role="alert" className="mon-threat-error">
          Review could not be saved: {acknowledgeError}</p>}
        <div className="mon-threat-actions">
          <button ref={actionRef} className="mon-threat-investigate"
            onClick={onInvestigate} disabled={acknowledging} type="button">INVESTIGATE</button>
          <button className="mon-threat-acknowledge"
            onClick={onAcknowledge} disabled={acknowledging} type="button">
            {acknowledging ? "SAVING REVIEW…" : "ACKNOWLEDGE"}
          </button>
        </div>
        <div className="mon-threat-meta">
          <span>Investigate to see the evidence.</span>
          <span>{queued > 1 ? queued - 1 + " other alerts waiting" : "Acknowledge to record your review"}</span>
        </div>
      </div>
    </section>
  </div>;
}
