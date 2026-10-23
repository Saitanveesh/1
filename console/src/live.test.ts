import { describe, expect, it } from "vitest";
import { LiveClient, type LiveState } from "./live";
import type { LiveEnvelope } from "./types";
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
      response_executions: [],
      audit_records: [],
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


describe("real WebSocket activity vs actual security events", () => {
  it("never reports a heartbeat or stream readiness as a security event", () => {
    const client = new LiveClient("tenant-a", "site-1");
    let latest: LiveState | undefined;
    const unsubscribe = client.subscribe((state) => { latest = state; });
    const receive = (envelope: LiveEnvelope) => {
      (client as unknown as { apply: (message: LiveEnvelope) => void }).apply(envelope);
    };

    receive({
      kind: "stream.ready", tenant_id: "tenant-a", site_id: "site-1",
      sequence: 0, emitted_at: "2026-10-10T09:00:00Z", payload: {}
    });
    expect(latest?.lastMessageAt).toBeDefined();
    expect(latest?.lastEventAt).toBeUndefined();

    receive({
      kind: "stream.heartbeat", tenant_id: "tenant-a", site_id: "site-1",
      sequence: 0, emitted_at: "2026-10-10T09:00:15Z",
      payload: { dropped_messages: 0 }
    });
    expect(latest?.lastEventAt).toBeUndefined();
    expect(latest?.connection).toBe("LIVE");

    receive({
      kind: "event.processed", tenant_id: "tenant-a", site_id: "site-1",
      sequence: 1, emitted_at: "2026-10-10T09:00:20Z", payload: {}
    });
    expect(latest?.lastEventAt).toBe("2026-10-10T09:00:20Z");
    receive({
      kind: "stream.heartbeat", tenant_id: "tenant-a", site_id: "site-1",
      sequence: 1, emitted_at: "2026-10-10T09:00:35Z",
      payload: { dropped_messages: 0 }
    });
    expect(latest?.lastEventAt).toBe("2026-10-10T09:00:20Z");
    unsubscribe();
    client.stop();
  });
});
