import { useEffect, useRef } from "react";
import type { SecurityThreatAlert } from "./securityAlerts";
import "./SecurityAlert.css";

interface Props {
  alert: SecurityThreatAlert;
  queued: number;
  onInvestigate: () => void;
  onAcknowledge: () => void;
}

export default function SecurityAlert({ alert, queued, onInvestigate, onAcknowledge }: Props) {
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
            <span className="mon-threat-shield" aria-hidden="true">♢</span>
            <div>
              <div className="mon-threat-overline">LIVE SECURITY ALERT</div>
              <h2 id="mon-threat-heading">Suspicious Traffic Detected</h2>
            </div>
            <span className="mon-threat-siren" aria-hidden="true">♧</span>
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
            <span>MON IDS — Detection evidence received</span>
          </div>
          <div className="mon-threat-meta">
            <span>Observed {new Date(alert.observedAt).toLocaleString()}</span>
            <span>{queued > 1 ? queued - 1 + " more alerts queued" : "Evidence-backed event"}</span>
          </div>
          <div className="mon-threat-actions">
            <button ref={actionRef} className="mon-threat-investigate"
              onClick={onInvestigate} type="button">INVESTIGATE</button>
            <button className="mon-threat-acknowledge"
              onClick={onAcknowledge} type="button">ACKNOWLEDGE</button>
          </div>
        </div>
      </section>
    </div>
  );
}
