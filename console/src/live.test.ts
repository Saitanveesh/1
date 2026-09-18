import { describe, expect, it } from "vitest";
import type { LiveSnapshot } from "./types";

describe("live snapshot contract", () => {
  it("keeps tenant/site scope explicit", () => {
    const snapshot: LiveSnapshot = {
      tenant_id: "tenant-a",
      site_id: "site-1",
      sequence: 42,
      findings: [],
      incidents: [],
      assets: [],
      enforcement_points: [],
      enforcement_bindings: [],
      telemetry: {
        tenant_id: "tenant-a",
        site_id: "site-1",
        window_seconds: 60,
        observed_at: new Date(0).toISOString(),
        observation_count: 0,
        unique_src_ips: 0,
        unique_dst_ips: 0,
        protocol_counts: {},
        source_counts: {}
      },
      graph: {
        tenant_id: "tenant-a",
        site_id: "site-1",
        nodes: [],
        edges: []
      }
    };
    expect(snapshot.sequence).toBe(42);
    expect(snapshot.graph.site_id).toBe("site-1");
  });
});
