import { useEffect, useMemo, useState } from "react";
import { fetchRangeExercises } from "./api";
import type { ExerciseReceipt } from "./types";

export default function ExerciseTimeline({
  tenantId, siteId
}: {
  tenantId: string;
  siteId: string;
}) {
  const [exercises, setExercises] = useState<ExerciseReceipt[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    let stopped = false;
    const load = async () => {
      try {
        const items = await fetchRangeExercises(tenantId, siteId);
        if (!stopped) {
          setExercises(items);
          setError("");
        }
      } catch (cause) {
        if (!stopped) {
          setError(cause instanceof Error ? cause.message : "Unreachable");
          setExercises([]);
        }
      }
    };
    void load();
    const interval = window.setInterval(() => void load(), 10000);
    return () => {
      stopped = true;
      window.clearInterval(interval);
    };
  }, [tenantId, siteId]);

  const selected = useMemo(
    () => exercises.find((item) => item.exercise_id === selectedId) ?? exercises[0],
    [selectedId, exercises]
  );

  return (
    <section className="panel full" data-testid="exercise-timeline">
      <div className="panel-head">
        <div>
          <span className="eyebrow">BOUNDED ISOLATED RANGE</span>
          <h2>Exercise evidence timeline</h2>
        </div>
        <span className="mono">{exercises.length} retained exercises</span>
      </div>
      <p className="network-explain">
        These records are operator-submitted, hashed observations of real HTTP
        requests. They are not authenticated packet captures and do not prove
        compromise, DDoS, MITM, source location, containment or recovery.
        Cross-correlate with sensor and response audit evidence before drawing conclusions.
      </p>
      {error && <p className="network-warning" role="alert">History unavailable: {error}</p>}
      {!error && exercises.length === 0 && (
        <p className="network-footnote">
          No authenticated exercise receipts received for this tenant/site.
          No simulated history will be substituted.
        </p>
      )}
      {exercises.length > 0 && (
        <>
          <label className="network-footnote">
            Select exercise
            <select value={selected?.exercise_id ?? ""}
              onChange={(event) => setSelectedId(event.target.value)}>
              {exercises.map((item) => (
                <option key={item.exercise_id} value={item.exercise_id}>
                  {item.exercise_id} · {new Date(item.started_at).toLocaleString()}
                </option>
              ))}
            </select>
          </label>
          {selected && (
            <>
              <div className="metrics-grid">
                <article className="metric">
                  <div className="metric-label">Recorded requests</div>
                  <div className="metric-value">{selected.attempts}</div>
                  <div className="metric-note">Bounded single source · self-reported</div>
                </article>
                <article className="metric">
                  <div className="metric-label">HTTP 200 responses</div>
                  <div className="metric-value">{selected.http_200}</div>
                  <div className="metric-note">Actual client-observed statuses</div>
                </article>
                <article className="metric">
                  <div className="metric-label">Other / failed</div>
                  <div className="metric-value">{selected.other_or_failed}</div>
                  <div className="metric-note">Not automatically an attack or compromise</div>
                </article>
              </div>
              <p className="network-footnote">
                Target IP: {selected.target_ip} · Approved by: {selected.approved_by}
                {" · "}Started: {new Date(selected.started_at).toLocaleString()}
                {" · "}Finished: {new Date(selected.finished_at).toLocaleString()}
                {" · "}Attack conclusion: {selected.attack_claim}
                {" · "}Containment conclusion: {selected.containment_claim}
              </p>
              <p className="network-footnote">
                SHA-256 receipt: <code>{selected.sha256}</code>
              </p>
              <div style={{ maxHeight: 320, overflowY: "auto" }}>
                <table>
                  <thead><tr>
                    <th>Observed at</th><th>HTTP status</th><th>Latency</th>
                  </tr></thead>
                  <tbody>
                    {selected.samples.map((sample, index) => (
                      <tr key={`${sample.observed_at}-${index}`}>
                        <td>{new Date(sample.observed_at).toLocaleTimeString()}</td>
                        <td>{sample.http_status ?? "NO RESPONSE"}</td>
                        <td>{sample.latency_seconds === null ? "UNKNOWN" :
                          `${(sample.latency_seconds * 1000).toFixed(1)} ms`}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </section>
  );
}
