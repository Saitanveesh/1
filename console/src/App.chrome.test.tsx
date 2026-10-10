import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App, { formatActivityAge } from "./App";

vi.mock("./api", () => ({
  fetchOperator: vi.fn().mockResolvedValue({
    subject: "sensitive-lab-operator",
    tenant_id: "mon-lab",
    site_ids: ["site-a"],
    roles: ["tenant_admin"]
  }),
  fetchSnapshot: vi.fn().mockResolvedValue({
    tenant_id: "mon-lab",
    site_id: "site-a",
    sequence: 0,
    findings: [],
    incidents: [],
    assets: [],
    enforcement_points: [],
    enforcement_bindings: [],
    response_executions: [],
    audit_records: [],
    telemetry: {
      tenant_id: "mon-lab",
      site_id: "site-a",
      window_seconds: 60,
      observed_at: "1970-01-01T00:00:00Z",
      observation_count: 0,
      unique_src_ips: 0,
      unique_dst_ips: 0,
      protocol_counts: {},
      source_counts: {}
    },
    graph: { tenant_id: "mon-lab", site_id: "site-a", nodes: [], edges: [] }
  })
}));

vi.mock("./live", () => ({
  LiveClient: class {
    subscribe(handler: (state: unknown) => void) {
      handler({
        tenant_id: "mon-lab",
        site_id: "site-a",
        sequence: 0,
        findings: [],
        incidents: [],
        assets: [],
        enforcement_points: [],
        enforcement_bindings: [],
        response_executions: [],
        audit_records: [],
        telemetry: {
          tenant_id: "mon-lab",
          site_id: "site-a",
          window_seconds: 60,
          observed_at: "1970-01-01T00:00:00Z",
          observation_count: 0,
          unique_src_ips: 0,
          unique_dst_ips: 0,
          protocol_counts: {},
          source_counts: {}
        },
        graph: { tenant_id: "mon-lab", site_id: "site-a", nodes: [], edges: [] },
        connection: "LIVE",
        lastMessageAt: new Date(Date.now() - 3000).toISOString(),
        droppedMessages: 0
      });
      return () => {};
    }

    async start() {}
    stop() {}
  }
}));

afterEach(() => {
  cleanup();
  // Keep the module-level async API mock implementations across test cases.
  vi.clearAllMocks();
});

describe("SOC operator chrome", () => {
  it("shows transport age and honestly distinguishes missing security events", async () => {
    render(<App />);
    expect(screen.getByText("STREAM ACTIVITY")).toBeTruthy();
    expect(screen.getByTestId("stream-age").textContent).toMatch(/^\ds ago$/);
    expect(screen.getByTestId("last-security-event").textContent).toBe("NONE OBSERVED");
    await waitFor(() => expect(screen.queryByTestId("unauthenticated")).toBeNull());
    expect(screen.getByText("LIVE TRANSPORT")).toBeTruthy();
  });

  it("does not put operator role, site IDs, sequence, or a boxed initial in sidebar", async () => {
    render(<App />);
    await waitFor(() => expect(screen.queryByText("AUTHENTICATION REQUIRED")).toBeNull());
    expect(document.querySelector(".mark")).toBeNull();
    expect(document.querySelector(".brand")?.textContent).toContain("MON");
    expect(document.querySelector(".sidebar-foot")?.textContent).toBe("LIVE");
    expect(document.querySelector(".sidebar")?.textContent).not.toContain("sensitive-lab-operator");
    expect(document.querySelector(".sidebar")?.textContent).not.toContain("mon-lab");
    expect(document.querySelector(".sidebar")?.textContent).not.toContain("tenant_admin");
    expect(document.querySelector(".sidebar")?.textContent).not.toContain("SEQ");
  });
});

describe("observed stream age formatting", () => {
  const now = Date.parse("2026-10-10T10:00:00.000Z");
  it("changes every second without generating a fake event", () => {
    const event = "2026-10-10T09:59:58.000Z";
    expect(formatActivityAge(event, now)).toBe("2s ago");
    expect(formatActivityAge(event, now + 1000)).toBe("3s ago");
    expect(formatActivityAge(event, now + 60_000)).toBe("1m 2s ago");
  });

  it("does not invent a last timestamp", () => {
    expect(formatActivityAge(undefined, now)).toBe("WAITING");
    expect(formatActivityAge("invalid", now)).toBe("UNKNOWN");
  });
});
