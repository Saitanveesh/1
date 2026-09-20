import type { IncidentInvestigation, LiveSnapshot, OperatorPrincipal, SensorFleetView } from "./types";

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

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
    throw new ApiError(response.status, `snapshot failed: HTTP ${response.status}`);
  }
  return response.json() as Promise<LiveSnapshot>;
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { credentials: "include", headers: jsonHeaders });
  if (!response.ok) {
    throw new ApiError(response.status, `${path} failed: HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export function fetchOperator(): Promise<OperatorPrincipal> {
  return getJson<OperatorPrincipal>("/api/v1/me");
}

export function fetchInvestigation(
  incidentId: string,
  tenantId: string,
  siteId: string
): Promise<IncidentInvestigation> {
  return getJson<IncidentInvestigation>(
    `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation?${query({ tenantId, siteId })}`
  );
}

export function fetchSensorFleet(tenantId: string, siteId: string): Promise<SensorFleetView[]> {
  return getJson<SensorFleetView[]>(`/api/v1/sensors?${query({ tenantId, siteId })}`);
}

export function liveWebSocketUrl(tenantId: string, siteId: string): string {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const params = query({ tenantId, siteId });
  return `${scheme}://${window.location.host}/ws/v1/live?${params}`;
}
