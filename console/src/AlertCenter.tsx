import { useMemo, useState } from "react";
import type { SecurityThreatAlert } from "./securityAlerts";
import type { SuricataSnapshot } from "./types";
import { alertFromSuricata } from "./suricataThreats";
import "./AlertCenter.css";

/** Session alerts plus the exact, bounded records still held by Suricata.
 * A historical EVE record is reviewable but never presented as a new popup.
 * The caller must supply an actual configured victim address.
 */
export function collectAlerts(
  snapshot: SuricataSnapshot | null,
  protectedIp: string | null,
  session: SecurityThreatAlert[]
): SecurityThreatAlert[] {
  const unique = new Map<string, SecurityThreatAlert>();
  if (protectedIp && snapshot) for (const row of snapshot.records) {
    if (row.dst_ip !== protectedIp) continue;
    const alert = alertFromSuricata(row);
    if (alert) unique.set(alert.key, alert);
  }
  for (const alert of session) {
    if (protectedIp && alert.target === protectedIp) unique.set(alert.key, alert);
  }
  return [...unique.values()]
    .filter(item => Number.isFinite(Date.parse(item.observedAt)))
    .sort((a, b) => Date.parse(b.observedAt) - Date.parse(a.observedAt))
    .slice(0, 200);
}

type Filter = "all" | "new" | "reviewed";
export default function AlertCenter({
  alerts, acknowledged, sensorReady, onOpen, onAcknowledge
}: {
  alerts: SecurityThreatAlert[];
  acknowledged: Record<string, string>;
  sensorReady: boolean;
  onOpen: (alert: SecurityThreatAlert) => void;
  onAcknowledge: (alert: SecurityThreatAlert) => void;
}) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [order, setOrder] = useState<"recent" | "severity">("recent");
  const reviewed = alerts.filter(a => Boolean(acknowledged[a.key])).length;
  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    const ranks = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    return alerts.filter(item => {
      const isReviewed = Boolean(acknowledged[item.key]);
      if (filter === "reviewed" && !isReviewed) return false;
      if (filter === "new" && isReviewed) return false;
      return !term || [item.title, item.source, item.target, item.attackClass,
        item.detector, item.signatureId?.toString() || ""]
        .some(value => value.toLowerCase().includes(term));
    }).sort((a, b) => order === "severity"
      ? ranks[b.severity] - ranks[a.severity] ||
        Date.parse(b.observedAt) - Date.parse(a.observedAt)
      : Date.parse(b.observedAt) - Date.parse(a.observedAt));
  }, [alerts, acknowledged, filter, search, order]);

  return <section className="mon-alerts-page" data-testid="alerts-workspace">
    <div className="mon-alerts-intro">
      <div><h2>Security alerts</h2>
        <p>Review detected activity, inspect the evidence and record what you have checked.</p></div>
      <div className="mon-alerts-totals" aria-label="Alert totals">
        <div><strong>{alerts.length - reviewed}</strong><span>Needs review</span></div>
        <div><strong>{reviewed}</strong><span>Acknowledged</span></div>
      </div>
    </div>
    {!sensorReady && <div className="mon-alerts-warning" role="status">
      The detection sensor is unavailable or has not been verified. Previously received alerts remain visible; new detections cannot be confirmed here.
    </div>}
    <div className="mon-alerts-toolbar">
      <label className="mon-alerts-search">Search alerts
        <input aria-label="Search alerts" value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search description or source address…" />
      </label>
      <div className="mon-alerts-filters" role="group" aria-label="Review status">
        {(["all","new","reviewed"] as const).map(item =>
          <button type="button" key={item} aria-pressed={filter === item}
            onClick={() => setFilter(item)}>
            {item === "all" ? "All" : item === "new" ? "Needs review" : "Acknowledged"}
          </button>)}
      </div>
      <label className="mon-alerts-order">Sort by
        <select aria-label="Sort alerts" value={order}
          onChange={e => setOrder(e.target.value as "recent" | "severity")}>
          <option value="recent">Newest first</option>
          <option value="severity">Severity</option>
        </select>
      </label>
    </div>
    <div className="mon-alerts-list" aria-live="polite">
      {filtered.map(alert => {
        const ack = acknowledged[alert.key];
        const age = Date.now() - Date.parse(alert.observedAt);
        const mayReview = !alert.key.startsWith("ids:") ||
          (sensorReady && age >= 0 && age <= 900_000);
        return <article className="mon-alert-row" key={alert.key}>
          <div className="mon-alert-row-main">
            <span className={"severity " + alert.severity.toLowerCase()}>{alert.severity}</span>
            <div className="mon-alert-row-body">
              <h3>{alert.title}</h3>
              <p>{alert.source} <span aria-hidden="true">→</span> {alert.target}</p>
              <small>{new Date(alert.observedAt).toLocaleString()} · {alert.detector}</small>
            </div>
            <span className={"mon-alert-row-state" + (ack ? " is-reviewed" : "")}>
              {ack ? "Acknowledged" : "Needs review"}
            </span>
          </div>
          <div className="mon-alert-row-actions">
            <button type="button" className="mon-alert-open"
              onClick={() => onOpen(alert)} aria-label={"Investigate " + alert.title}>
              Investigate <span aria-hidden="true">→</span>
            </button>
            {!ack && (mayReview
              ? <button type="button" className="mon-alert-review"
                  onClick={() => onAcknowledge(alert)}
                  aria-label={"Acknowledge " + alert.title}>Acknowledge</button>
              : <span className="mon-alert-row-unavailable">
                  {sensorReady ? "Review window ended" : "Review unavailable while sensor is offline"}
                </span>)}
          </div>
        </article>;
      })}
      {!filtered.length && <div className="mon-alerts-empty">
        <strong>{alerts.length ? "No alerts match your filters" : "No detections recorded"}</strong>
        <p>{alerts.length
          ? "Change the search or review status to see other alerts."
          : "This list shows actual detections from the sensor and alerts received during this session. It will not generate sample incidents."}</p>
        {alerts.length > 0 && <button type="button" onClick={() => { setFilter("all"); setSearch(""); }}>
          Clear filters</button>}
      </div>}
    </div>
    <p className="mon-alerts-footnote">
      This list contains currently retained sensor records and alerts seen in this browser session. Acknowledgment means an operator reviewed the alert; it does not close a case or block any traffic.
    </p>
  </section>;
}
