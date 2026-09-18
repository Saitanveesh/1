import type { LiveSnapshot } from "./types";

const jsonHeaders = { Accept: "application/json" };

function query(scope: { tenantId: string; siteId: string }): string {
  return new URLSearchParams({
    tenant_id: scope.tenantId,
    site_id: scope.siteId
  }).toString();
}

export async function fetchSnapshot(
  tenantId: string,
  siteId: string
): Promise<LiveSnapshot> {
  const response = await fetch(
    `/api/v1/live/snapshot?${query({ tenantId, siteId })}`,
    { credentials: "include", headers: jsonHeaders }
  );
  if (!response.ok) {
    throw new Error(`snapshot failed: HTTP ${response.status}`);
  }
  return response.json() as Promise<LiveSnapshot>;
}

export function liveWebSocketUrl(tenantId: string, siteId: string): string {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const params = query({ tenantId, siteId });
  return `${scheme}://${window.location.host}/ws/v1/live?${params}`;
}
