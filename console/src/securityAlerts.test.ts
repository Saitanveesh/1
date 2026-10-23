import { describe, expect, it } from "vitest";
import { selectSecurityAlert } from "./securityAlerts";
import type { Finding, Incident, LiveEnvelope } from "./types";

const incident: Incident = {
  incident_id: "case-1", tenant_id: "mon-lab", site_id: "site-a",
  title: "Web probe detected", severity: "HIGH", status: "OPEN", confidence: 0.91,
  affected_asset_ids: ["web-server"], detector_ids: ["suricata-web"],
  entities: [], last_seen: "2026-10-23T10:00:00Z"
};
const finding: Finding = {
  finding_id: "finding-1", detector_id: "suricata-web", title: "Web probe",
  severity: "HIGH", confidence: 0.91, src_ip: "10.77.0.6",
  dst_ip: "10.77.0.5", last_seen: "2026-10-23T10:00:00Z"
};
const envelope = (kind: string, payload: Record<string, unknown>): LiveEnvelope => ({
  kind, payload, tenant_id: "mon-lab", site_id: "site-a", sequence: 10,
  emitted_at: "2026-10-23T10:00:00Z"
});

describe("MON live threat alerts", () => {
  it("shows a newly detected case with grounded source and target", () => {
    const item = selectSecurityAlert(envelope("event.processed", {
      result: { incidents: [incident], findings: [finding] }
    }), { incidents: [], findings: [] });
    expect(item).toMatchObject({
      incidentId: "case-1", source: "10.77.0.6", target: "10.77.0.5",
      severity: "HIGH", attackClass: "suricata-web"
    });
  });
  it("does not alert on historical repeat or heartbeat", () => {
    expect(selectSecurityAlert(envelope("event.processed", {
      result: { incidents: [incident], findings: [finding] }
    }), { incidents: [incident], findings: [finding] })).toBeNull();
    expect(selectSecurityAlert(envelope("stream.heartbeat", {}),
      { incidents: [], findings: [] })).toBeNull();
  });
  it("alerts on new medium finding, but never invents an attacker", () => {
    const alert = selectSecurityAlert(envelope("event.processed", {
      result: { findings: [{ ...finding, src_ip: undefined, severity: "MEDIUM" }] }
    }), { incidents: [], findings: [] });
    expect(alert?.source).toBe("Unknown Source");
    expect(alert?.severity).toBe("MEDIUM");
  });
  it("does not alert on low-confidence-independent low-severity findings", () => {
    expect(selectSecurityAlert(envelope("event.processed", {
      result: { findings: [{ ...finding, severity: "LOW" }] }
    }), { incidents: [], findings: [] })).toBeNull();
  });
  it("alerts for newly escalated cases, not repeated updates", () => {
    expect(selectSecurityAlert(envelope("incident.updated", {
      incident: { ...incident, severity: "CRITICAL" }
    }), { incidents: [incident], findings: [finding] })?.severity).toBe("CRITICAL");
    expect(selectSecurityAlert(envelope("incident.updated", {
      incident
    }), { incidents: [incident], findings: [finding] })).toBeNull();
  });
});
