import { useEffect, useMemo, useState } from "react";
import type { SuricataRecord, SuricataSnapshot } from "./types";

const idle: SuricataSnapshot = {
  source: "suricata-eve", status: "NOT_INSTALLED", observed_events: 0,
  alerts: 0, last_seen: null, records: []
};

export default function SuricataPanel() {
  const [snapshot, setSnapshot] = useState<SuricataSnapshot>(idle);
  const [networkError, setNetworkError] = useState(false);
  const [filter, setFilter] = useState<"all" | "alert" | "flow">("all");

  useEffect(() => {
    let closed = false;
    async function refresh() {
      try {
        const response = await fetch("/portal/ids", { credentials: "same-origin" });
        if (!response.ok) throw new Error("IDS endpoint unavailable");
        const data = await response.json() as SuricataSnapshot;
        if (!closed) { setSnapshot(data); setNetworkError(false); }
      } catch {
        if (!closed) setNetworkError(true);
      }
    }
    void refresh();
    const interval = window.setInterval(() => void refresh(), 5000);
    return () => { closed = true; window.clearInterval(interval); };
  }, []);

  const rows = useMemo(() => snapshot.records.filter(
    record => filter === "all" || record.event_type === filter
  ), [snapshot.records, filter]);
  return (
    <section className="mon-panel mon-ids-panel" data-testid="suricata-ids-panel">
      <div className="mon-panel-heading">
        <div>
          <span className="mon-eyebrow">PASSIVE NETWORK IDS / SURICATA EVE</span>
          <h2>Protocol analysis and detections</h2>
          <p>PC-2 Suricata EVE evidence. Sensor service and actual capture interface must be checked separately; this is not proof of blocking.</p>
        </div>
        <span className="mon-tag" data-testid="suricata-status">
          {networkError ? "API UNREACHABLE"
            : snapshot.service_state !== "active"
              ? "SERVICE " + (snapshot.service_state || "UNVERIFIED").toUpperCase()
              : snapshot.status.replaceAll("_", " ")}
        </span>
      </div>
      <div className="mon-ids-summary">
        <div><small>RECENT EVE RECORDS</small><strong>{snapshot.observed_events}</strong></div>
        <div><small>RULE ALERTS</small><strong>{snapshot.alerts}</strong></div>
        <div><small>LAST EVENT</small><strong>{snapshot.last_seen || "NONE"}</strong></div>
        <div><small>CAPTURE INTERFACE</small><strong>{snapshot.capture_interface || "UNVERIFIED"}</strong></div>
      </div>
      <div className="mon-ids-actions" role="group" aria-label="IDS event filters">
        <button type="button" aria-pressed={filter === "all"} onClick={() => setFilter("all")}>ALL</button>
        <button type="button" aria-pressed={filter === "alert"} onClick={() => setFilter("alert")}>ALERTS</button>
        <button type="button" aria-pressed={filter === "flow"} onClick={() => setFilter("flow")}>FLOWS</button>
      </div>
      <div className="mon-flow-table-wrapper">
        <table className="mon-flow-table">
          <thead><tr><th>TIME</th><th>TYPE</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOL</th><th>EVIDENCE</th></tr></thead>
          <tbody>
            {rows.map((row: SuricataRecord, i) => (
              <tr key={row.timestamp + ":" + i}>
                <td>{row.timestamp}</td>
                <td>{row.event_type.toUpperCase()}</td>
                <td>{row.src_ip}{row.src_port === null ? "" : ":" + row.src_port}</td>
                <td>{row.dst_ip}{row.dst_port === null ? "" : ":" + row.dst_port}</td>
                <td>{row.application || row.protocol}</td>
                <td>{row.event_type === "alert" ? row.signature || "Alert without signature" :
                  row.event_type === "flow" ?
                  [(row.pkts_toserver ?? 0) + (row.pkts_toclient ?? 0), "packets"].join(" ") :
                  row.community_id || "Protocol metadata"}</td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={6} className="mon-flow-empty">
              {snapshot.status === "NOT_INSTALLED"
                ? "Suricata IDS not yet installed. Run the separately authorized PC2 sensor installer."
                : "No matching EVE network records retained; live capture alone is not an alert."}
            </td></tr>}
          </tbody>
        </table>
      </div>
      <p className="mon-packet-caveat">
        EVE provides protocol/flow metadata and signature alerts. It does not prove malicious intent
        without corroboration. Traffic outside PC2 is not visible.
      </p>
    </section>
  );
}
