import type {
  Asset, Finding, Incident, PacketCaptureSnapshot, SuricataSnapshot
} from "./types";

/** No wall-clock freshness => no "live" classification. */
export function isRecentObservation(
  timestamp: string | null | undefined,
  now = Date.now(),
  maxAgeMs = 300_000
): boolean {
  if (!timestamp) return false;
  const at = Date.parse(timestamp);
  if (!Number.isFinite(at)) return false;
  const age = now - at;
  return age >= -30_000 && age <= maxAgeMs;
}

/**
 * A real AF_PACKET reading must be specifically scoped to the configured
 * victim address and arrive from a fresh working sensor. The presence of an
 * active websocket or packets on other PC-2 interfaces is insufficient.
 */
export function isProtectedCaptureReady(
  capture: PacketCaptureSnapshot | null,
  now = Date.now()
): boolean {
  return Boolean(
    capture?.status === "CAPTURING" &&
    capture.protected_host_ip &&
    capture.protected_capture_interface &&
    capture.protected_route_samples?.length &&
    isRecentObservation(capture.observed_at, now, 12_000)
  );
}

export function currentProtectedFindings(
  findings: Finding[],
  target: string | null | undefined,
  now = Date.now()
): Finding[] {
  if (!target) return [];
  return findings.filter(item =>
    item.dst_ip === target &&
    isRecentObservation(item.last_seen, now)
  );
}

/**
 * An incident must be both recent and linked to the actual protected endpoint.
 * Historical OPEN incidents remain accessible in Incidents, not the live desk.
 */
export function currentProtectedIncidents(
  incidents: Incident[],
  findings: Finding[],
  assets: Asset[],
  target: string | null | undefined,
  now = Date.now()
): Incident[] {
  if (!target) return [];
  const targetAssets = new Set(assets.filter(asset =>
    asset.ip_addresses.includes(target)
  ).map(asset => asset.asset_id));
  return incidents.filter(incident => {
    if (incident.status === "CLOSED" ||
        !isRecentObservation(incident.last_seen, now)) return false;
    const hasTargetAsset = incident.affected_asset_ids.some(id =>
      targetAssets.has(id)
    );
    const hasTargetFinding = findings.some(finding =>
      incident.detector_ids.includes(finding.detector_id) &&
      finding.dst_ip === target &&
      isRecentObservation(finding.last_seen, now)
    );
    return hasTargetAsset || hasTargetFinding;
  });
}

export type IdsStatus =
  "CHECKING" | "API UNAVAILABLE" | "SERVICE OFFLINE" |
  "NO RECENT EVE" | "EVE OBSERVED";

export function idsStatus(
  snapshot: SuricataSnapshot | null,
  accessible: boolean
): IdsStatus {
  if (!accessible) return snapshot ? "API UNAVAILABLE" : "CHECKING";
  if (!snapshot || snapshot.service_state !== "active") {
    return "SERVICE OFFLINE";
  }
  return snapshot.status === "RECENT_EVE"
    ? "EVE OBSERVED" : "NO RECENT EVE";
}
