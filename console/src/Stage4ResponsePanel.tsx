import { useCallback, useEffect, useMemo, useState } from "react";
import type { SecurityThreatAlert } from "./securityAlerts";
import "./Stage4ResponsePanel.css";

export interface MitigationAudit {
  at: string;
  action: "block" | "release";
  source: string;
  destination: string;
  port: number;
  active: boolean;
  rule_state: string;
}
export interface MitigationStatus {
  source: string;
  destination: string;
  port: number;
  active: boolean;
  expires_in_seconds: number | null;
  enforcement: string;
  audit: MitigationAudit[];
  scope: string;
}
export interface VictimImpactEvent {
  at: string;
  source: string;
  route: string;
  http_status: number;
  response_bytes_written: number;
  fictional_exposure: string | null;
  fictional_records: number;
}
export interface VictimImpact {
  status: "OBSERVED";
  source: string;
  window_start: string;
  window_end: string;
  observed_requests: number;
  successful_http_responses: number;
  fictional_exposure_responses: number;
  fictional_records_in_responses: number;
  fictional_response_bytes_written: number;
  exposure_categories: Record<string, number>;
  last_fictional_exposure_at: string | null;
  recent_events: VictimImpactEvent[];
  truncated: boolean;
  scope: string;
}

export function eligibleForManualContainment(alert: SecurityThreatAlert): boolean {
  return alert.key.startsWith("ids:") &&
    ["10.77.0.60", "10.77.0.70"].includes(alert.source) &&
    alert.target === "10.77.0.50" &&
    [42000501, 42000502, 42000503].includes(alert.signatureId ?? -1);
}

async function readJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { credentials: "same-origin", cache: "no-store" });
  const payload = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(payload.error || "Monitoring service unavailable");
  return payload;
}

async function changeBlock(action: "block" | "release", alert: SecurityThreatAlert,
  duration: number): Promise<MitigationStatus> {
  const response = await fetch("/portal/stage4/" + action, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      source: alert.source,
      alert_key: alert.key,
      duration_seconds: duration
    })
  });
  const payload = await response.json() as MitigationStatus & { error?: string };
  if (!response.ok) throw new Error(payload.error || "The firewall did not accept the action");
  return payload;
}

export function impactAfterBlock(impact: VictimImpact | null,
  audit: MitigationAudit[] | undefined): { requests: number; exposures: number } | null {
  if (!impact || !audit) return null;
  const last = [...audit].reverse().find(row => row.action === "block");
  if (!last) return null;
  const at = Date.parse(last.at);
  if (!Number.isFinite(at)) return null;
  const after = impact.recent_events.filter(row => Date.parse(row.at) >= at);
  return {
    requests: after.length,
    exposures: after.filter(row => Boolean(row.fictional_exposure)).length
  };
}

function phrase(category: string): string {
  switch (category) {
    case "fictional_canary": return "Training document exposed";
    case "fictional_student": return "Fictional student record returned";
    case "fictional_internal_notices": return "Fictional internal notices returned";
    default: return category.replaceAll("_", " ");
  }
}

export default function Stage4ResponsePanel({ alert }: { alert: SecurityThreatAlert }) {
  const eligible = eligibleForManualContainment(alert);
  const knownSource = ["10.77.0.60", "10.77.0.70"].includes(alert.source) &&
    alert.target === "10.77.0.50";
  const [mitigation, setMitigation] = useState<MitigationStatus | null>(null);
  const [impact, setImpact] = useState<VictimImpact | null>(null);
  const [mitigationError, setMitigationError] = useState<string | null>(null);
  const [impactError, setImpactError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmAction, setConfirmAction] = useState<"block" | "release" | null>(null);
  const [duration, setDuration] = useState(120);
  const [agreed, setAgreed] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [lastRead, setLastRead] = useState<string | null>(null);
  const [trialStart, setTrialStart] = useState<string | null>(null);
  const since = trialStart ?? alert.observedAt;

  const refresh = useCallback(async (cancelled: () => boolean = () => false) => {
    if (!knownSource) return;
    const source = encodeURIComponent(alert.source);
    const [m, i] = await Promise.allSettled([
      readJson<MitigationStatus>("/portal/stage4/mitigation?source=" + source),
      readJson<VictimImpact>("/portal/stage4/impact?source=" + source +
        "&since=" + encodeURIComponent(since))
    ]);
    if (cancelled()) return;
    if (m.status === "fulfilled") { setMitigation(m.value); setMitigationError(null); }
    else { setMitigation(null); setMitigationError(m.reason instanceof Error ? m.reason.message : "Unavailable"); }
    if (i.status === "fulfilled") { setImpact(i.value); setImpactError(null); }
    else { setImpact(null); setImpactError(i.reason instanceof Error ? i.reason.message : "Unavailable"); }
    setLastRead(new Date().toISOString());
  }, [alert.source, knownSource, since]);

  useEffect(() => {
    let stopped = false;
    setMitigation(null);
    setImpact(null);
    setResult(null);
    setConfirmAction(null);
    setAgreed(false);
    void refresh(() => stopped);
    const timer = window.setInterval(() => void refresh(() => stopped), 5000);
    return () => { stopped = true; window.clearInterval(timer); };
  }, [refresh, alert.key]);

  async function submit(): Promise<void> {
    if (!confirmAction || !agreed || busy) return;
    setBusy(true);
    setResult(null);
    setMitigationError(null);
    try {
      const action = confirmAction;
      const response = await changeBlock(action, alert, duration);
      setMitigation(response);
      setResult(action === "block"
        ? "A temporary kernel firewall rule was installed. Test from the attacker computer to verify its effect."
        : "The kernel no longer reports a block for this source. Test connectivity to verify recovery.");
      setConfirmAction(null);
      setAgreed(false);
      await refresh();
    } catch (cause) {
      setMitigationError(cause instanceof Error ? cause.message : "Action failed");
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  const after = useMemo(() => impactAfterBlock(impact, mitigation?.audit),
    [impact, mitigation]);
  const latestBlock = mitigation?.audit?.slice().reverse().find(item => item.action === "block");
  const sinceBlock = latestBlock && impact?.recent_events.filter(
    item => Date.parse(item.at) >= Date.parse(latestBlock.at));
  const observedAfterBlock = sinceBlock?.filter(item => Boolean(item.fictional_exposure)).length ?? 0;

  return <section className="mon-stage4" data-testid="stage4-response-panel">
    <header className="mon-stage4-heading">
      <div><h3>Protect the application</h3>
        <p>See what the website returned, then decide whether to stop further requests from this source.</p>
      </div>
      <button type="button" onClick={() => void refresh()} disabled={busy || !knownSource}>Refresh evidence</button>
    </header>

    {!knownSource ? <p className="mon-stage4-boundary">
      This containment view is limited to verified activity directed at the protected training website from its enrolled test attackers. No firewall action is available for this alert.
    </p> : <div className="mon-stage4-cols">
      <article className="mon-stage4-card">
        <div className="mon-stage4-card-title">
          <span className="mon-stage4-circle">A</span>
          <div><h4>Without intervention</h4>
            <p>What the victim application has actually returned.</p></div>
        </div>
        <div className="mon-stage4-reading" role="status">
          {impactError ? <p className="mon-stage4-error">Victim evidence unavailable: {impactError}</p> :
           !impact ? <p>Checking the application’s response ledger…</p> :
           <>
             <div className="mon-stage4-big-number">
               <strong>{impact.fictional_exposure_responses}</strong>
               <span>fictional exposure responses</span>
             </div>
             <div className="mon-stage4-totals">
               <div><strong>{impact.observed_requests}</strong><span>Requests seen by victim</span></div>
               <div><strong>{impact.fictional_records_in_responses}</strong><span>Fictional records returned</span></div>
               <div><strong>{impact.fictional_response_bytes_written.toLocaleString()}</strong><span>Response bytes written</span></div>
             </div>
             <p className="mon-stage4-window">Since {new Date(impact.window_start).toLocaleString()} · Updates every 5 seconds</p>
             {impact.fictional_exposure_responses > 0
               ? <p className="mon-stage4-attention">The app logged successful HTTP responses containing fictional, deliberately vulnerable lab data.</p>
               : <p>No fictional exposure response was recorded in this observation window. This does not prove the application has no vulnerabilities.</p>}
             <ul className="mon-stage4-categories">
               {Object.entries(impact.exposure_categories).filter(([, count]) => count > 0).map(([key, count]) =>
                 <li key={key}><span>{phrase(key)}</span><strong>{count}</strong></li>)}
             </ul>
             {impact.truncated && <p className="mon-stage4-attention">The record window was truncated; totals are incomplete.</p>}
           </>}
        </div>
        <button type="button" className="mon-stage4-secondary" disabled={busy}
          onClick={() => { setTrialStart(new Date().toISOString()); setResult("Started a new observation window. No firewall change was made."); }}>
          Start new observation
        </button>
      </article>

      <article className="mon-stage4-card">
        <div className="mon-stage4-card-title">
          <span className="mon-stage4-circle">B</span>
          <div><h4>Operator response</h4>
            <p>Temporary block for {alert.source} → {alert.target}:8085.</p></div>
        </div>
        {mitigationError && <p className="mon-stage4-error" role="alert">{mitigationError}</p>}
        <div className="mon-stage4-state" role="status">
          <span className={"mon-stage4-indicator " + (mitigation?.active ? "blocked" : "clear")} />
          <strong>{mitigation?.active ? "Temporary firewall block active" :
            mitigation ? "No active training-web block" : "Firewall state unavailable"}</strong>
        </div>
        {mitigation?.active && <p className="mon-stage4-window">
          {mitigation.expires_in_seconds == null ? "Kernel timeout enabled" :
            "Approximately " + mitigation.expires_in_seconds + " seconds remaining"}
        </p>}
        {eligible ? <>
          {!confirmAction && <>
            <div className="mon-stage4-controls">
              {mitigation?.active
                ? <button type="button" onClick={() => { setConfirmAction("release"); setAgreed(false); }} disabled={busy}>
                    Restore this source’s website access
                  </button>
                : <button type="button" onClick={() => { setConfirmAction("block"); setAgreed(false); }}
                    disabled={busy || !mitigation}>
                    Block this source temporarily
                  </button>}
            </div>
          </>}
          {confirmAction && <div className="mon-stage4-confirm">
            <strong>{confirmAction === "block" ? "Confirm temporary containment" : "Confirm access restoration"}</strong>
            <p>{confirmAction === "block"
              ? "Only forwarded TCP connections from this source to the victim website on port 8085 will be dropped. Other machines, SSH and WireGuard remain untouched."
              : "Remove only this source’s temporary training-web rule. The existing monitoring system stays online."}</p>
            {confirmAction === "block" && <label>Block duration
              <select value={duration} onChange={event => setDuration(Number(event.target.value))}>
                <option value={30}>30 seconds</option><option value={60}>1 minute</option>
                <option value={120}>2 minutes</option><option value={180}>3 minutes</option>
              </select>
            </label>}
            <label className="mon-stage4-checkbox">
              <input type="checkbox" checked={agreed} onChange={event => setAgreed(event.target.checked)} />
              I approve this change to the training network.
            </label>
            <div className="mon-stage4-confirm-actions">
              <button type="button" disabled={!agreed || busy} onClick={() => void submit()}>
                {busy ? "Checking…" : confirmAction === "block" ? "Apply timed block" : "Restore access"}
              </button>
              <button type="button" className="mon-stage4-secondary"
                disabled={busy} onClick={() => { setConfirmAction(null); setAgreed(false); }}>Cancel</button>
            </div>
          </div>}
        </> : <p className="mon-stage4-boundary">
          Containment is available only for a fresh, matching training-web Suricata signature. Review a newly detected lab request to enable this action.
        </p>}
        {result && <p role="status" className="mon-stage4-result">{result}</p>}
        {after && <div className="mon-stage4-outcome">
          <h5>After the most recent block</h5>
          <p>{after.requests} requests recorded by the victim, {observedAfterBlock} fictional exposure responses in the retained recent event sample.</p>
          {observedAfterBlock > 0 && <p className="mon-stage4-attention">
            The app still recorded exposure after the block timestamp. Check in-flight traffic, routing and firewall placement before claiming mitigation worked.</p>}
        </div>}
        <p className="mon-stage4-guard">A kernel rule proves the block was installed, not that the attacker failed. Verify with a new request from PC-6 or PC-7. The rule expires automatically.</p>
      </article>
    </div>}
    <details className="mon-stage4-details">
      <summary>Evidence and response history</summary>
      <div className="mon-stage4-details-content">
        <p>{impact?.scope ?? "Victim-side observations are not available."}</p>
        <p>Actual host file or personal-data loss: <strong>not applicable to the fictional training fixtures</strong>. This display cannot measure real-world financial impact or independently prove what a remote client received.</p>
        <h5>Recent application responses</h5>
        <div className="mon-stage4-table-wrap">
          <table><thead><tr><th>Time</th><th>Route</th><th>HTTP</th><th>Fictional exposure</th></tr></thead>
            <tbody>{(impact?.recent_events ?? []).slice(-20).reverse().map((row, i) => <tr key={row.at + ":" + i}>
              <td>{new Date(row.at).toLocaleTimeString()}</td>
              <td>{row.route}</td><td>{row.http_status}</td><td>{row.fictional_exposure ? phrase(row.fictional_exposure) : "None recorded"}</td>
            </tr>)}
              {!impact?.recent_events?.length && <tr><td colSpan={4}>No application events available in this window.</td></tr>}
            </tbody></table>
        </div>
        <h5>Operator decisions</h5>
        {(mitigation?.audit ?? []).slice().reverse().map((entry,i) =>
          <p key={entry.at + ":" + i}>{new Date(entry.at).toLocaleString()} — {entry.action === "block" ? "Temporary block installed" : "Access restored"} ({entry.source})</p>)}
        {!mitigation?.audit?.length && <p>No containment decisions have been recorded.</p>}
        {lastRead && <p className="mon-stage4-window">Last checked: {new Date(lastRead).toLocaleTimeString()}</p>}
      </div>
    </details>
  </section>;
}
