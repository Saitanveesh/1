import { describe, expect, it } from "vitest";
import type { Finding, TopologySnapshot } from "./types";
import { matchTopologyFindings } from "./topology-highlights";

const clock = Date.parse("2026-10-15T12:00:00Z");

function graph(addresses: string[][]): TopologySnapshot {
  return {
    tenant_id: "tenant-a", site_id: "site-1",
    captured_at: new Date(clock).toISOString(),
    root_node_id: null, distance_basis: "NO_ROOT_SELECTED",
    coverage: "UNKNOWN", observations_considered: addresses.length,
    truncated: false, links: [],
    nodes: addresses.map((ips, i) => ({
      node_id: `node-${i}`, node_type: "UNVERIFIED",
      label: `Observed ${i}`, ip_addresses: ips, mac_addresses: [],
      status: "OBSERVED", last_seen: new Date(clock).toISOString(),
      evidence_ids: [`ev-${i}`], distance_hops: null
    }))
  };
}

function finding(src: string, dst: string, when = clock): Finding {
  return {
    finding_id: "f-1", detector_id: "test", title: "Observed traffic",
    severity: "MEDIUM", confidence: 0.7, src_ip: src, dst_ip: dst,
    last_seen: new Date(when).toISOString()
  };
}

describe("observed network finding overlay", () => {
  it("marks only unique, recent IP matches without asserting physical source", () => {
    const results = matchTopologyFindings(
      graph([["192.0.2.1"], ["192.0.2.2"]]),
      [finding("192.0.2.1", "192.0.2.2")], clock
    );
    expect(results.recentFindings).toBe(1);
    expect(results.roles.get("node-0")?.has("SOURCE")).toBe(true);
    expect(results.roles.get("node-1")?.has("TARGET")).toBe(true);
    expect(results.matchedEndpoints).toBe(2);
    expect(results.unresolvedEndpoints).toBe(0);
  });

  it("refuses ambiguous IP assignments across observed nodes", () => {
    const results = matchTopologyFindings(
      graph([["192.0.2.1"], ["192.0.2.1"]]),
      [finding("192.0.2.1", "198.51.100.8")], clock
    );
    expect(results.roles.size).toBe(0);
    expect(results.unresolvedEndpoints).toBe(2);
  });

  it("omits stale findings rather than implying an active attack", () => {
    const result = matchTopologyFindings(
      graph([["192.0.2.1"]]),
      [finding("192.0.2.1", "192.0.2.2", clock - 11 * 60_000)], clock
    );
    expect(result.recentFindings).toBe(0);
    expect(result.roles.size).toBe(0);
  });
});
