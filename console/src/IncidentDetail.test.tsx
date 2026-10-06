import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

  it("plans a policy-gated block from evidence-backed containment capability", async () => {
    const actionable: IncidentInvestigation = {
      ...investigation,
      graph: {
        tenant_id: "t",
        site_id: "s",
        nodes: [{ node_id: "ip:203.0.113.50", kind: "EXTERNAL_IP", label: "203.0.113.50" }],
        edges: []
      },
      containment_capabilities: [
        {
          asset_id: "linux-host:web-01",
          binding_id: "bind-1",
          enforcement_point_id: "router-1",
          kind: "ROUTER",
          vendor: "linux-nftables-router",
          health: "HEALTHY",
          capabilities: ["BLOCK_IP"],
          distance: 1,
          blast_radius_estimate: "single hostile source IP on lab overlay",
          notes: []
        }
      ]
    };
    const plan = {
      request: {
        request_id: "req-1",
        tenant_id: "t",
        site_id: "s",
        incident_id: "inc-1",
        target: { ip_address: "203.0.113.50" },
        action: "BLOCK_IP",
        enforcement_point_id: "router-1",
        ttl_seconds: 120,
        reason: "operator containment from incident investigation"
      },
      decision: { outcome: "REQUIRE_APPROVAL", reasons: ["incident confidence is below 0.90"] },
      enforcement_point: {
        enforcement_point_id: "router-1",
        kind: "ROUTER",
        vendor: "linux-nftables-router"
      },
      rollback_action: "RESTORE",
      selection_reasons: ["operator/request explicitly selected this enforcement point"],
      blast_radius_estimate: "single hostile source IP on lab overlay"
    };
    const mockedFetch = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => actionable })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => plan });
    vi.stubGlobal("fetch", mockedFetch);

    render(
      <IncidentDetail incident={incident} tenantId="t" siteId="s" executions={[]} auditRecords={[]} />
    );
    await waitFor(() => expect(screen.getByDisplayValue("203.0.113.50")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "PLAN BLOCK" }));
    await waitFor(() => expect(screen.getByTestId("planned-response").textContent).toContain("REQUIRE_APPROVAL"));
    expect(screen.getByTestId("planned-response").textContent).toContain("single hostile source IP");
    const secondCall = mockedFetch.mock.calls[1];
    expect(secondCall[0]).toBe("/api/v1/responses/plan");
    expect(JSON.parse(secondCall[1].body as string).enforcement_point_id).toBe("router-1");
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
