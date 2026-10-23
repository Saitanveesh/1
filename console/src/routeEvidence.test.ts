import { describe, expect, it } from "vitest";
import { selectProtectedRoute } from "./routeEvidence";
import type { PacketCaptureSnapshot } from "./types";

const stamp = "2026-10-23T10:00:00.000Z";
const snapshot: PacketCaptureSnapshot = {
  source: "linux-af_packet", interface: "any", capture_scope: "any",
  observed_at: stamp, status: "CAPTURING", error: null,
  sample_interval_seconds: 1, capture_window_seconds: 90,
  direction: "inbound and outbound", packet_layer: "IP", samples: [],
  flows: [], protected_host_ip: "10.77.0.50",
  protected_capture_interface: "wg0",
  events: [
    { timestamp: stamp, interface: "wg0", direction: "inbound", src_ip:"10.77.0.60", dst_ip:"10.77.0.50", protocol:"ICMP", dst_port:null, ip_bytes:84 },
    { timestamp: stamp, interface: "wg0", direction: "outbound", src_ip:"10.77.0.60", dst_ip:"10.77.0.50", protocol:"ICMP", dst_port:null, ip_bytes:84 },
    { timestamp: stamp, interface: "docker0", direction: "inbound", src_ip:"172.17.0.2", dst_ip:"10.77.0.50", protocol:"TCP", dst_port:80, ip_bytes:50 },
    { timestamp: stamp, interface: "wg0", direction: "inbound", src_ip:"8.8.8.8", dst_ip:"1.1.1.1", protocol:"UDP", dst_port:53, ip_bytes:65 },
  ]
};

describe("protected gateway evidence", () => {
  it("shows exactly captured PC5 tunnel traffic, including ICMP", () => {
    const route = selectProtectedRoute(snapshot);
    expect(route.observedFrames).toBe(2);
    expect(route.observedBytes).toBe(168);
    expect(route.icmpFrames).toBe(2);
    expect(route.peer).toBe("10.77.0.60");
    expect(route.observedBothDirections).toBe(true);
  });
  it("never assumes a target or attack source", () => {
    const route = selectProtectedRoute({
      ...snapshot, protected_host_ip: null
    });
    expect(route.configured).toBe(false);
    expect(route.peer).toBeNull();
    expect(route.observedFrames).toBe(0);
  });
  it("does not count old or off-interface packets", () => {
    const route = selectProtectedRoute({
      ...snapshot,
      events: [{ ...snapshot.events![0], timestamp: "2026-10-22T09:00:00Z" },
               { ...snapshot.events![0], interface: "eth0" }]
    });
    expect(route.active).toBe(false);
    expect(route.observedFrames).toBe(0);
  });
});
