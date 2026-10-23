import { useEffect, useState } from "react";
import { isRecentObservation } from "./operationalTruth";
import type { SuricataRecord, SuricataSnapshot } from "./types";
import type { SecurityThreatAlert } from "./securityAlerts";

export function recordKey(item: SuricataRecord): string {
  return [
    item.timestamp, item.signature_id ?? "", item.signature ?? "",
    item.src_ip, item.src_port ?? "", item.dst_ip, item.dst_port ?? ""
  ].join("|");
}

/** Convert an actual Suricata signature into a reviewable alert.
 * This does not announce historical rows as new live attacks.
 */
export function alertFromSuricata(row: SuricataRecord): SecurityThreatAlert | null {
  if (row.event_type !== "alert" ||
      (row.severity !== 1 && row.severity !== 2 && row.severity !== 3) ||
      !row.src_ip || !row.dst_ip || !row.timestamp) return null;
  return {
    key: "ids:" + recordKey(row),
    title: row.signature || "Security rule matched",
    severity: row.severity === 1 ? "CRITICAL" : row.severity === 2 ? "HIGH" : "MEDIUM",
    source: row.src_ip,
    target: row.dst_ip,
    attackClass: row.category || row.signature || "Network detection",
    observedAt: row.timestamp,
    signatureId: row.signature_id,
    detector: "Suricata IDS"
  };
}

export function newSuricataThreats(
  snapshot: SuricataSnapshot,
  seen: Set<string>,
  baseline: boolean,
  protectedIp: string | null = null,
  now = Date.now()
): SecurityThreatAlert[] {
  const alerts = snapshot.records.filter(item => item.event_type === "alert");
  const result: SecurityThreatAlert[] = [];
  for (const row of alerts) {
    const key = recordKey(row);
    if (seen.has(key)) continue;
    seen.add(key);
    if (!baseline ||
        snapshot.service_state !== "active" ||
        snapshot.status !== "RECENT_EVE" ||
        !protectedIp ||
        row.dst_ip !== protectedIp ||
        !isRecentObservation(row.timestamp, now, 120_000)) continue;
    const item = alertFromSuricata(row);
    if (item) result.push(item);
  }
  return result;
}

export interface IdsObservation {
  availability: "CHECKING" | "AVAILABLE" | "UNAVAILABLE";
  snapshot: SuricataSnapshot | null;
}

/**
 * New real PC5-targeted EVE matches can raise the overlay. A disconnected,
 * failed or unconfigured Suricata sensor must never create a fake attack.
 * The initial successful read is history only, even if it contains alerts.
 */
export function useSuricataThreatAlerts(
  authenticated: boolean,
  onThreat: (item: SecurityThreatAlert) => void,
  protectedIp: string | null
): IdsObservation {
  const [observation, setObservation] = useState<IdsObservation>({
    availability: "CHECKING", snapshot: null
  });
  useEffect(() => {
    if (!authenticated) return;
    let stopped = false;
    let baseline = false;
    const seen = new Set<string>();
    async function poll() {
      try {
        const response = await fetch("/portal/ids", { credentials: "same-origin" });
        if (!response.ok) throw new Error("IDS endpoint not available");
        const snapshot = await response.json() as SuricataSnapshot;
        if (stopped) return;
        setObservation({ availability: "AVAILABLE", snapshot });
        const items = newSuricataThreats(snapshot, seen, baseline, protectedIp);
        baseline = true;
        for (const item of items) onThreat(item);
      } catch {
        if (!stopped) {
          setObservation(previous => ({
            availability: "UNAVAILABLE", snapshot: previous.snapshot
          }));
        }
      }
    }
    void poll();
    const timer = window.setInterval(() => void poll(), 3000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [authenticated, protectedIp, onThreat]);
  return observation;
}
