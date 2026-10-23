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

export default function SecurityAlert({ alert, queued, onInvestigate, onAcknowledge, acknowledging = false, acknowledgeError = null }: Props) {
  const actionRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    actionRef.current?.focus();
  }, [alert.key]);
  return (
    <div className="mon-threat-overlay" data-testid="live-threat-overlay">
      <section className="mon-threat-window" role="alertdialog"
        aria-modal="true" aria-labelledby="mon-threat-heading"
        aria-describedby="mon-threat-summary">
        <header className="mon-threat-header">
          <div className="mon-threat-brand">
            <span className="mon-threat-mark">M</span>
            <strong>MON / COMMAND CENTER</strong>
          </div>
          <span className="mon-threat-live">LIVE SECURITY ALERT</span>
        </header>
        <div className="mon-threat-card">
          <div className="mon-threat-titlebar">
            <span className="mon-threat-shield" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                <path d="M12 2 4 5.5V12c0 5 3 8.4 8 10 5-1.6 8-5 8-10V5.5L12 2Z"/>
                <path d="M12 7.4v5.2M12 16.5h.01"/>
              </svg>
            </span>
            <div>
              <div className="mon-threat-overline">LIVE SECURITY ALERT</div>
              <h2 id="mon-threat-heading">Suspicious Traffic Detected</h2>
            </div>
            <span className="mon-threat-siren" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                <path d="M6 17V11a6 6 0 0 1 12 0v6M4 20h16M12 1v2M3 6 1.5 4.5M21 6l1.5-1.5"/>
              </svg>
            </span>
          </div>
          <p className="mon-threat-evidence-title" id="mon-threat-summary">{alert.title}</p>
          <div className="mon-threat-grid">
            <div><span>SOURCE</span><strong>{alert.source}</strong></div>
            <div><span>TARGET</span><strong>{alert.target}</strong></div>
            <div><span>ATTACK CLASS</span><strong>{alert.attackClass}</strong></div>
            <div><span>SEVERITY</span><strong>{alert.severity}</strong></div>
          </div>
          <div className="mon-threat-proof">
            <span className="mon-threat-radiowave" aria-hidden="true">◉</span>
            <span>{alert.detector === "Suricata IDS" ? "MON IDS — Detection evidence received" : "MON Detection — Security evidence received"}</span>
          </div>
          <div className="mon-threat-meta">
            <span>Observed {new Date(alert.observedAt).toLocaleString()}</span>
            <span>{queued > 1 ? queued - 1 + " more alerts queued" : "Evidence-backed event"}</span>
          </div>
          {acknowledgeError && <p role="alert" className="mon-alert-investigation-error">Review not saved: {acknowledgeError}</p>}
          <div className="mon-threat-actions">
            <button ref={actionRef} className="mon-threat-investigate"
              onClick={onInvestigate} disabled={acknowledging} type="button">INVESTIGATE</button>
            <button className="mon-threat-acknowledge"
              onClick={onAcknowledge} disabled={acknowledging} type="button">{acknowledging ? "SAVING REVIEW…" : "ACKNOWLEDGE"}</button>
          </div>
        </div>
      </section>
    </div>
  );
}
