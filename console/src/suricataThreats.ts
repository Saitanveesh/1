import { useEffect, useState } from "react";
import type { SuricataRecord, SuricataSnapshot } from "./types";
import type { SecurityThreatAlert } from "./securityAlerts";

function recordKey(item: SuricataRecord): string {
  return [
    item.timestamp, item.signature_id ?? "", item.signature ?? "",
    item.src_ip, item.src_port ?? "", item.dst_ip, item.dst_port ?? ""
  ].join("|");
}

export function newSuricataThreats(
  snapshot: SuricataSnapshot,
  seen: Set<string>,
  baseline: boolean
): SecurityThreatAlert[] {
  const alerts = snapshot.records.filter(item => item.event_type === "alert");
  const result: SecurityThreatAlert[] = [];
  for (const row of alerts) {
    const key = recordKey(row);
    if (seen.has(key)) continue;
    seen.add(key);
    if (!baseline || snapshot.status !== "RECENT_EVE") continue;
    // Suricata signature priority: 1 most severe, 2 high, 3 medium.
    // No fabricated severity for absent/invalid priority values.
    if (row.severity !== 1 && row.severity !== 2 && row.severity !== 3) continue;
    result.push({
      key: "ids:" + key,
      title: row.signature || "Suricata signature match",
      severity: row.severity === 1 ? "CRITICAL" : row.severity === 2 ? "HIGH" : "MEDIUM",
      source: row.src_ip || "Unknown Source",
      target: row.dst_ip || "Unresolved target",
      attackClass: row.category || row.signature || "Suricata signature",
      observedAt: row.timestamp,
      detector: "Suricata IDS"
    });
  }
  return result;
}

/**
 * Polls the existing PC-2 Suricata evidence endpoint. The first successful
 * response establishes a baseline and cannot produce a user-visible attack.
 */
export function useSuricataThreatAlerts(
  authenticated: boolean,
  onThreat: (item: SecurityThreatAlert) => void
): void {
  useEffect(() => {
    if (!authenticated) return;
    let stopped = false;
    let baseline = false;
    const seen = new Set<string>();
    async function poll() {
      try {
        const response = await fetch("/portal/ids", { credentials: "same-origin" });
        if (!response.ok) return;
        const snapshot = await response.json() as SuricataSnapshot;
        if (stopped) return;
        const items = newSuricataThreats(snapshot, seen, baseline);
        baseline = true;
        for (const item of items) onThreat(item);
      } catch {
        // A disconnected sensor must never generate a synthetic alert.
      }
    }
    void poll();
    const timer = window.setInterval(() => void poll(), 3000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [authenticated, onThreat]);
}
