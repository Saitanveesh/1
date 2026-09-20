import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import IncidentDetail from "./IncidentDetail";
import type { Incident, IncidentInvestigation } from "./types";

const incident: Incident = {
  incident_id: "inc-1",
  tenant_id: "t",
  site_id: "s",
  title: "Repeated endpoint authentication failures",
  severity: "MEDIUM",
  status: "OPEN",
  confidence: 0.72,
  affected_asset_ids: ["linux-host:web-01"],
  detector_ids: ["endpoint-auth-failure-pressure"],
  entities: ["203.0.113.50"],
  last_seen: "2026-09-20T00:00:00Z"
};

const investigation: IncidentInvestigation = {
  incident,
  findings: [],
  affected_assets: [],
  graph: { tenant_id: "t", site_id: "s", nodes: [], edges: [] },
  containment_capabilities: [],
  evidence: [
    {
      evidence_id: "e1",
      evidence_class: "IDENTITY",
      source: "endpoint:sshd",
      summary: "8 failed logons for root",
      confidence: 0.75,
      observed_at: "2026-09-20T00:00:00Z"
    }
  ]
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("IncidentDetail", () => {
  it("renders only what the investigation API returned, with honest empty states", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => investigation })
    );
    render(
      <IncidentDetail incident={incident} tenantId="t" siteId="s" executions={[]} auditRecords={[]} />
    );
    await waitFor(() => expect(screen.getAllByTestId("evidence-item")).toHaveLength(1));
    expect(screen.getByTestId("affected-identity").textContent).toContain("8 failed logons for root");
    expect(screen.getByText("No resolved assets.")).toBeTruthy();
    expect(screen.getByText("No enforcement point is bound to the affected assets.")).toBeTruthy();
    expect(screen.getByText("No response recorded for this incident.")).toBeTruthy();
  });

  it("surfaces an authorization failure instead of showing data", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 403, json: async () => ({}) }));
    render(
      <IncidentDetail incident={incident} tenantId="t" siteId="s" executions={[]} auditRecords={[]} />
    );
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("HTTP 403"));
    expect(screen.queryAllByTestId("evidence-item")).toHaveLength(0);
  });
});
