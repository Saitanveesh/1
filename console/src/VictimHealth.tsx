import { useEffect, useState } from "react";
import { fetchVictimHealth } from "./api";
import type { Asset, VictimHealthView, VictimMetric } from "./types";

function measured(
  item: VictimMetric | undefined,
  format: (value: number) => string
): string {
  if (!item || item.status !== "FRESH" || item.value === null) return "UNKNOWN";
  return format(item.value);
}

function Measurement({
  title,
  reading,
  formatter
}: {
  title: string;
  reading: VictimMetric | undefined;
  formatter: (value: number) => string;
}) {
  return (
    <article className="metric">
      <div className="metric-label">{title}</div>
      <div className="metric-value">{measured(reading, formatter)}</div>
      <div className="metric-note">
        Source: {reading?.source ?? "unavailable"}
        {" · "}State: {reading?.status ?? "UNKNOWN"}
        {" · "}Observed: {reading?.observed_at
          ? new Date(reading.observed_at).toLocaleTimeString() : "Never"}
      </div>
    </article>
  );
}

export default function VictimHealth({
  tenantId,
  siteId,
  assets
}: {
  tenantId: string;
  siteId: string;
  assets: Asset[];
}) {
  const [selectedAsset, setSelectedAsset] = useState("");
  const [health, setHealth] = useState<VictimHealthView | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const value = await fetchVictimHealth(tenantId, siteId, selectedAsset || undefined);
        if (!cancelled) {
          setHealth(value);
          setError("");
        }
      } catch (cause) {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : "Health source failed");
          setHealth(null);
        }
      }
    };
    void load();
    const interval = window.setInterval(() => void load(), 5000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [tenantId, siteId, selectedAsset]);

  const response = health?.service_reachable;
  const availability =
    response?.status !== "FRESH" || response.value === null
      ? "UNKNOWN"
      : response.value === 1 ? "REACHABLE" : response.value === 0 ? "UNAVAILABLE" : "UNKNOWN";

  return (
    <section className="panel full" data-testid="victim-health">
      <div className="panel-head">
        <div>
          <span className="eyebrow">INDEPENDENT VICTIM EVIDENCE</span>
          <h2>Runtime-selected victim health</h2>
        </div>
        <span className="mono">{health?.telemetry_state ?? "NOT CONNECTED"}</span>
      </div>
      <p className="network-explain">
        This view measures only actual authorized, instrumented selected assets.
        No metric is inferred for unrelated devices. No PC is a fixed victim. Missing or stale observations
        remain UNKNOWN; process RSS is not host RAM.
      </p>
      <label className="network-footnote">
        Selected observed device (not automatically enrolled for host monitoring)
        <select value={selectedAsset} onChange={(event) => setSelectedAsset(event.target.value)}>
          <option value="">Unassigned / legacy single-target view</option>
          {assets.map((asset) => (
            <option key={asset.asset_id} value={asset.asset_id}>
              {asset.display_name} · {asset.asset_id}
            </option>
          ))}
        </select>
      </label>
      {selectedAsset && (
        <p className="network-footnote">
          Device selected at runtime: {selectedAsset}. If no matching exporter, show UNKNOWN.
        </p>
      )}
      {error && <p className="network-warning" role="alert">Telemetry unavailable: {error}</p>}
      <div className="metrics-grid">
        <Measurement title="Independent service reachability"
          reading={health?.service_reachable}
          formatter={() => availability} />
        <Measurement title="HTTP probe duration"
          reading={health?.probe_duration_seconds}
          formatter={(value) => `${(value * 1000).toFixed(1)} ms`} />
        <Measurement title="ERP process memory"
          reading={health?.erp_process_rss_bytes}
          formatter={(value) => `${(value / (1024 * 1024)).toFixed(1)} MiB`} />
        <Measurement title="ERP process CPU time"
          reading={health?.erp_process_cpu_seconds}
          formatter={(value) => `${value.toFixed(1)} s`} />
        <Measurement title="Victim host CPU" reading={health?.host_cpu_percent}
          formatter={(value) => `${value.toFixed(1)}%`} />
        <Measurement title="Victim host RAM" reading={health?.host_ram_percent}
          formatter={(value) => `${value.toFixed(1)}%`} />
      </div>
      <p className="network-footnote">
        {health?.note ?? "No health snapshot received"}.
        {" "}Last check: {health?.collected_at
          ? new Date(health.collected_at).toLocaleTimeString() : "Never"}.
      </p>
    </section>
  );
}
