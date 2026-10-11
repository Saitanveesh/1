import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import AiAnalysis, { buildCaseTimeline } from "./AiAnalysis";
import type { AuditRecord, Incident, IncidentInvestigation, ResponseExecution } from "./types";

const incident: Incident = {
  incident_id: "9398913b-3fb4-4f01-874f-87f6d71ed646",
  tenant_id: "mon-lab",
  site_id: "site-a",
  title: "Repeated endpoint authentication failures",
  severity: "MEDIUM",
  status: "OPEN",
  confidence: 0.72,
  affected_asset_ids: ["linux-host:lab-pc5"],
  detector_ids: ["endpoint-auth-failure-pressure"],
  entities: ["linux-host:lab-pc5", "10.77.0.60"],
  last_seen: "2026-10-10T17:17:32Z"
};
const caseFile: IncidentInvestigation = {
  incident,
  findings: [{
    finding_id: "finding-pc6",
    detector_id: "endpoint-auth-failure-pressure",
    title: "Repeated endpoint authentication failures",
    severity: "MEDIUM",
    confidence: .72,
    src_ip: "10.77.0.60",
    last_seen: "2026-10-10T17:17:30Z"
  }],
  affected_assets: [{
    asset_id: "linux-host:lab-pc5", tenant_id: "mon-lab", site_id: "site-a",
    display_name: "lab-pc5", criticality: "MEDIUM",
    ip_addresses: ["10.77.0.50"], mac_addresses: [], hostnames: [],
    observed_tcp_services: [22], peer_counts: {}, protocol_counts: {},
    identity_evidence: [], first_seen: "2026-10-10T17:00:00Z",
    last_seen: "2026-10-10T17:17:30Z"
  }],
  evidence: [
    {
      evidence_id: "later", evidence_class: "IDENTITY",
      source: "endpoint:linux-journal:sshd-session",
      summary: "8 endpoint authentication failures observed in 300s",
      confidence: .72, observed_at: "2026-10-10T17:17:16Z"
    },
    {
      evidence_id: "first", evidence_class: "IDENTITY",
      source: "endpoint:linux-journal:sshd-session",
      summary: "Endpoint reported authentication failure",
      confidence: .75, observed_at: "2026-10-10T17:16:16Z"
    }
  ],
  graph: { tenant_id: "mon-lab", site_id: "site-a", nodes: [], edges: [] },
  containment_capabilities: []
};

const relevantResponse = {
  execution_id: "resp-1",
  requested_at: "2026-10-10T17:18:00Z",
  applied_at: "2026-10-10T17:18:05Z",
  rollback_at: "2026-10-10T17:19:20Z",
  status: "ROLLED_BACK",
  plan: {
    request: {
      incident_id: incident.incident_id,
      action: "BLOCK_IP"
    }
  }
} as unknown as ResponseExecution;

function audit(id: string, objectId: string, time: string): AuditRecord {
  return {
    audit_id: id, actor_id: "operator", category: "RESPONSE",
    object_type: "response", object_id: objectId,
    action: "ROLLBACK", outcome: "ROLLED_BACK", occurred_at: time, details: {}
  };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("AI Analysis / real incident reconstruction", () => {
  it("sorts actual evidence timestamps and correlates only case-linked response/audit", () => {
    const unrelated = { ...relevantResponse, execution_id: "unrelated",
      plan: { request: { incident_id: "other", action: "BLOCK_IP" } } } as unknown as ResponseExecution;
    const events = buildCaseTimeline(
      caseFile,
      [relevantResponse, unrelated],
      [
        audit("audit-related", "resp-1", "2026-10-10T17:19:25Z"),
        audit("audit-other", "resp-other", "2026-10-10T17:19:30Z")
      ]
    );
    expect(events[0].reference).toBe("first");
    expect(events[1].reference).toBe("later");
    expect(events.map(x => x.headline)).toContain("Response applied");
    expect(events.map(x => x.headline)).toContain("Response rolled back");
    expect(events.map(x => x.reference)).toContain("audit-related");
    expect(events.map(x => x.reference)).not.toContain("audit-other");
    expect(events.map(x => x.reference)).not.toContain("unrelated");
    expect(events.every(x => x.timestamp?.endsWith("Z"))).toBe(true);
  });

  it("retains undated evidence as undated instead of inventing a clock time", () => {
    const records = buildCaseTimeline({
      ...caseFile, evidence: [{
        ...caseFile.evidence[0], evidence_id: "clock-missing", observed_at: ""
      }]
    }, [], []);
    expect(records.at(-1)?.reference).toBe("clock-missing");
    expect(records.at(-1)?.timestamp).toBeNull();
  });

  it("loads real investigation on tab, renders correlation/timestamps, then requests local AI on demand", async () => {
    const ai = {
      incident_id: incident.incident_id,
      model: "qwen3:4b",
      headline: "10.77.0.60 → lab-pc5: 8 authentication failures in 300s",
      assessment: "Repeated failures indicate possible credential guessing.",
      next_check: "Confirm authorized test activity.",
      analysis: "Repeated failures indicate possible credential guessing.",
      evidence_ids: ["first", "later"],
      evidence_count: 2, read_only: true, advisory: "Read-only."
    };
    const mockedFetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => caseFile })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ai });
    vi.stubGlobal("fetch", mockedFetch);
    render(<AiAnalysis incidents={[incident]} tenantId="mon-lab" siteId="site-a"
      executions={[relevantResponse]}
      auditRecords={[audit("audit-related", "resp-1", "2026-10-10T17:19:25Z")]}
      onOpenIncident={vi.fn()} />);
    await waitFor(() => expect(screen.getByTestId("ai-timeline")).toBeTruthy());
    expect(screen.getAllByTestId("ai-timeline-event").length).toBeGreaterThanOrEqual(5);
    expect(screen.getByText("10.77.0.60")).toBeTruthy();
    expect(screen.getByText("lab-pc5")).toBeTruthy();
    expect(screen.getByText(/NOT A PACKET HOP TRACE/)).toBeTruthy();
    expect(mockedFetch).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByTestId("ai-generate-brief"));
    await waitFor(() => expect(screen.getByText("Repeated failures indicate possible credential guessing.")).toBeTruthy());
    expect(mockedFetch.mock.calls[1][0]).toBe("/portal/ai/investigate");
    const sent = JSON.parse(mockedFetch.mock.calls[1][1].body as string);
    expect(sent).toEqual({
      incident_id: incident.incident_id, tenant_id: "mon-lab", site_id: "site-a"
    });
    expect(mockedFetch).toHaveBeenCalledTimes(2);
  });

  it("provides a clear empty state when MON has no incident to reconstruct", () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    render(<AiAnalysis incidents={[]} tenantId="mon-lab" siteId="site-a"
      executions={[]} auditRecords={[]} onOpenIncident={vi.fn()} />);
    expect(screen.getByText(/No incident records exist for this site/)).toBeTruthy();
    expect(fetch).not.toHaveBeenCalled();
  });
});
