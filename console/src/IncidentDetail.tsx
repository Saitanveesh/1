import { useEffect, useState } from "react";
import { ApiError, executeResponse, fetchInvestigation, planResponse, rollbackResponse } from "./api";
import type {
  AuditRecord,
  Incident,
  IncidentInvestigation,
  ResponseExecution,
  ResponsePlan,
  ResponseRequestPayload
} from "./types";

interface Props {
  incident: Incident;
  tenantId: string;
  siteId: string;
  executions: ResponseExecution[];
  auditRecords: AuditRecord[];
}

function nodeLabel(id: string): string {
  return id.replace(/^[A-Za-z]+:/, "");
}

export default function IncidentDetail({
  incident,
  tenantId,
  siteId,
  executions,
  auditRecords
}: Props) {
  const [investigation, setInvestigation] = useState<IncidentInvestigation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [targetIp, setTargetIp] = useState("");
  const [ttlSeconds, setTtlSeconds] = useState(120);
  const [enforcementPointId, setEnforcementPointId] = useState("");
  const [planned, setPlanned] = useState<ResponsePlan | null>(null);
  const [approvalReason, setApprovalReason] = useState("operator reviewed evidence and blast radius");
  const [responseBusy, setResponseBusy] = useState(false);
  const [responseMessage, setResponseMessage] = useState<string | null>(null);
  const [responseError, setResponseError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setInvestigation(null);
    setError(null);
    fetchInvestigation(incident.incident_id, tenantId, siteId)
      .then((value) => {
        if (cancelled) return;
        setInvestigation(value);
        const candidate = value.containment_capabilities.find(
          (item) => item.health !== "UNAVAILABLE" && item.capabilities.includes("BLOCK_IP")
        );
        setEnforcementPointId(candidate?.enforcement_point_id ?? "");
        const observedSource =
          value.findings.find(
            (item) =>
              item.detector_id === "endpoint-auth-failure-pressure" &&
              Boolean(item.src_ip)
          )?.src_ip ??
          value.findings.find((item) => Boolean(item.src_ip))?.src_ip;
        const external = value.graph.nodes.find((item) => item.kind === "EXTERNAL_IP");
        setTargetIp(observedSource ?? external?.label ?? "");
        setPlanned(null);
        setResponseMessage(null);
        setResponseError(null);
      })
      .catch((reason: unknown) => {
        if (cancelled) return;
        setError(
          reason instanceof ApiError
            ? `investigation unavailable (HTTP ${reason.status})`
            : "investigation unavailable"
        );
      });
    return () => {
      cancelled = true;
    };
  }, [incident.incident_id, tenantId, siteId]);

  const related = executions.filter(
    (item) => item.plan.request.incident_id === incident.incident_id
  );
  const relatedIds = new Set(related.map((item) => item.execution_id));
  const audit = auditRecords
    .filter((item) => relatedIds.has(item.object_id))
    .sort((a, b) => a.occurred_at.localeCompare(b.occurred_at));
  const identities = (investigation?.evidence ?? []).filter(
    (item) => item.evidence_class === "IDENTITY"
  );

  function buildRequest(): ResponseRequestPayload {
    const ip = targetIp.trim();
    if (!ip) throw new Error("target source IP is required");
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 604800) {
      throw new Error("TTL must be an integer between 30 and 604800 seconds");
    }
    if (!enforcementPointId) throw new Error("select an enforcement point");
    return {
      request_id: `console-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      tenant_id: tenantId,
      site_id: siteId,
      incident_id: incident.incident_id,
      target: { ip_address: ip },
      action: "BLOCK_IP",
      enforcement_point_id: enforcementPointId,
      ttl_seconds: ttlSeconds,
      reason: "operator containment from incident investigation"
    };
  }

  async function handlePlan(): Promise<void> {
    setResponseBusy(true);
    setResponseError(null);
    setResponseMessage(null);
    try {
      const request = buildRequest();
      const plan = await planResponse(request);
      setPlanned(plan);
      setResponseMessage(
        `Plan ${plan.decision.outcome}: ${plan.enforcement_point.enforcement_point_id}`
      );
    } catch (reason: unknown) {
      setPlanned(null);
      setResponseError(
        reason instanceof Error ? reason.message : "response planning failed"
      );
    } finally {
      setResponseBusy(false);
    }
  }

  async function handleExecute(): Promise<void> {
    if (!planned) return;
    setResponseBusy(true);
    setResponseError(null);
    setResponseMessage(null);
    try {
      const approvalRequired = planned.decision.outcome === "REQUIRE_APPROVAL";
      if (approvalRequired && !approvalReason.trim()) {
        throw new Error("approval reason is required by policy");
      }
      const execution = await executeResponse(
        planned.request,
        approvalRequired,
        approvalRequired ? approvalReason.trim() : undefined
      );
      setResponseMessage(`Execution ${execution.status}: ${execution.execution_id}`);
      setPlanned(null);
    } catch (reason: unknown) {
      setResponseError(
        reason instanceof Error ? reason.message : "response execution failed"
      );
    } finally {
      setResponseBusy(false);
    }
  }

  async function handleRollback(executionId: string): Promise<void> {
    setResponseBusy(true);
    setResponseError(null);
    setResponseMessage(null);
    try {
      const execution = await rollbackResponse(
        executionId,
        tenantId,
        siteId,
        "operator requested recovery from incident investigation"
      );
      setResponseMessage(`Rollback ${execution.status}: ${execution.execution_id}`);
    } catch (reason: unknown) {
      setResponseError(
        reason instanceof Error ? reason.message : "rollback failed"
      );
    } finally {
      setResponseBusy(false);
    }
  }

  return (
    <section className="panel full" data-testid="incident-detail">
      <div className="panel-head">
        <div>
          <span className="eyebrow">INCIDENT INVESTIGATION</span>
          <h2 data-testid="incident-detail-title">{incident.title}</h2>
        </div>
        <span className="mono">
          {incident.severity} / {incident.status} / {Math.round(incident.confidence * 100)}%
        </span>
      </div>
      {error && <div className="empty" role="alert">{error}</div>}
      {!error && !investigation && <div className="empty">Loading investigation…</div>}
      {investigation && (
        <div className="detail-grid">
          <article>
            <h3>Evidence ({investigation.evidence.length})</h3>
            <ul data-testid="evidence-list">
              {investigation.evidence.map((item) => (
                <li key={item.evidence_id} data-testid="evidence-item">
                  <b>{item.evidence_class}</b> · {item.source} · {Math.round(item.confidence * 100)}%
                  <br />
                  <span className="subtle">{item.summary}</span>
                </li>
              ))}
              {!investigation.evidence.length && <li className="empty">No evidence attached.</li>}
            </ul>
          </article>
          <article>
            <h3>Affected assets</h3>
            <ul data-testid="affected-assets">
              {investigation.affected_assets.map((asset) => (
                <li key={asset.asset_id} data-testid="affected-asset">
                  <strong>{asset.display_name}</strong> <span className="subtle">{asset.asset_id}</span>
                  <br />
                  <span className="subtle">{asset.ip_addresses.join(", ") || "no observed IP"}</span>
                </li>
              ))}
              {!investigation.affected_assets.length && <li className="empty">No resolved assets.</li>}
            </ul>
            <h3>Affected identities (identity evidence)</h3>
            <ul data-testid="affected-identities">
              {identities.map((item) => (
                <li key={item.evidence_id} data-testid="affected-identity">{item.summary}</li>
              ))}
              {!identities.length && <li className="empty">No identity evidence.</li>}
            </ul>
          </article>
          <article>
            <h3>Investigation graph</h3>
            <div data-testid="investigation-graph">
              {investigation.graph.edges.map((edge) => (
                <div className="graph-edge" key={edge.edge_id} data-testid="graph-edge">
                  <span>{nodeLabel(edge.src_node_id)}</span>
                  <i>→ {edge.relation} →</i>
                  <span>{nodeLabel(edge.dst_node_id)}</span>
                  <b>{edge.event_count} evt</b>
                </div>
              ))}
              {!investigation.graph.edges.length && <div className="empty">No observed path edges.</div>}
            </div>
          </article>
          <article>
            <h3>Containment capability</h3>
            <ul data-testid="containment-capabilities">
              {investigation.containment_capabilities.map((item) => (
                <li key={item.binding_id} data-testid="containment-capability">
                  <strong>{item.enforcement_point_id}</strong> · {item.kind} · {item.vendor} · {item.health}
                  <br />
                  <span className="subtle">
                    {item.capabilities.join(", ")} · blast radius: {item.blast_radius_estimate ?? "UNKNOWN"}
                  </span>
                </li>
              ))}
              {!investigation.containment_capabilities.length && (
                <li className="empty">No enforcement point is bound to the affected assets.</li>
              )}
            </ul>
            <div className="response-controls" data-testid="response-controls">
              <label>
                TARGET SOURCE IP
                <input
                  value={targetIp}
                  onChange={(event) => {
                    setTargetIp(event.target.value);
                    setPlanned(null);
                  }}
                  placeholder="IPv4 or IPv6 source address"
                  autoComplete="off"
                />
              </label>
              <label>
                ENFORCEMENT POINT
                <select
                  value={enforcementPointId}
                  onChange={(event) => {
                    setEnforcementPointId(event.target.value);
                    setPlanned(null);
                  }}
                >
                  <option value="">Select</option>
                  {investigation.containment_capabilities
                    .filter((item) => item.capabilities.includes("BLOCK_IP"))
                    .map((item) => (
                      <option key={item.binding_id} value={item.enforcement_point_id}>
                        {item.enforcement_point_id} · {item.kind} · {item.health}
                      </option>
                    ))}
                </select>
              </label>
              <label>
                TTL SECONDS
                <input
                  type="number"
                  min={30}
                  max={604800}
                  value={ttlSeconds}
                  onChange={(event) => {
                    setTtlSeconds(Number(event.target.value));
                    setPlanned(null);
                  }}
                />
              </label>
              <button
                type="button"
                className="control-button"
                onClick={() => void handlePlan()}
                disabled={responseBusy || !investigation.containment_capabilities.length}
              >
                PLAN BLOCK
              </button>
              {planned && (
                <div className="planned-response" data-testid="planned-response">
                  <strong>{planned.decision.outcome}</strong>
                  <span>
                    {planned.decision.reasons.join(" · ") || "policy returned no reasons"}
                  </span>
                  <span>
                    blast radius: {planned.blast_radius_estimate ?? "UNKNOWN"}
                  </span>
                  <span>
                    selected: {planned.enforcement_point.enforcement_point_id}
                  </span>
                  {planned.decision.outcome === "REQUIRE_APPROVAL" && (
                    <label>
                      APPROVAL REASON
                      <input
                        value={approvalReason}
                        onChange={(event) => setApprovalReason(event.target.value)}
                        maxLength={1000}
                      />
                    </label>
                  )}
                  <button
                    type="button"
                    className="control-button primary"
                    onClick={() => void handleExecute()}
                    disabled={responseBusy || planned.decision.outcome === "DENY"}
                  >
                    {planned.decision.outcome === "DENY" ? "POLICY DENIED" : "EXECUTE BLOCK"}
                  </button>
                </div>
              )}
              {responseMessage && <div className="action-state">{responseMessage}</div>}
              {responseError && <div className="action-state error" role="alert">{responseError}</div>}
            </div>
          </article>
        </div>
      )}
      <div className="detail-grid">
        <article>
          <h3>Response, policy and recovery</h3>
          <ul data-testid="response-list">
            {related.map((item) => (
              <li key={item.execution_id} data-testid="response-row">
                <strong data-testid="response-status">{item.status}</strong> · {item.plan.request.action} →{" "}
                {item.plan.request.target.ip_address ?? item.plan.request.target.asset_id} via{" "}
                {item.plan.enforcement_point.enforcement_point_id}
                <br />
                <span className="subtle">
                  policy {item.plan.decision.outcome}
                  {item.approval ? ` · approved by ${item.approval.actor_id}` : ""}
                  {item.applied_at ? ` · applied ${new Date(item.applied_at).toLocaleTimeString()}` : ""}
                  {item.rollback_at ? ` · rolled back ${new Date(item.rollback_at).toLocaleTimeString()}` : ""}
                </span>
                {item.rollback_result && (
                  <div className="subtle" data-testid="rollback-result">rollback: {item.rollback_result.message}</div>
                )}
                {["APPLIED", "ROLLBACK_FAILED"].includes(item.status) && (
                  <button
                    type="button"
                    className="control-button compact"
                    disabled={responseBusy}
                    onClick={() => void handleRollback(item.execution_id)}
                  >
                    ROLLBACK
                  </button>
                )}
              </li>
            ))}
            {!related.length && <li className="empty">No response recorded for this incident.</li>}
          </ul>
        </article>
        <article>
          <h3>Audit history</h3>
          <ul data-testid="audit-list">
            {audit.map((item) => (
              <li key={item.audit_id} data-testid="audit-row">
                {new Date(item.occurred_at).toLocaleTimeString()} · {item.actor_id} ·{" "}
                <b>{item.action}</b> → {item.outcome}
              </li>
            ))}
            {!audit.length && <li className="empty">No audit records for this incident's responses.</li>}
          </ul>
        </article>
      </div>
    </section>
  );
}
