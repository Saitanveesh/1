import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import {
  NetworkPath, PacketHistory, ProtectedRouteStrip, trailingPacketRate
} from "./PacketObservability";
import type { PacketCaptureSnapshot } from "./types";

const observedAt = new Date().toISOString();
const routeEvent = {
  timestamp: new Date(Date.now() - 2000).toISOString(), interface: "wg0",
  direction: "inbound" as const, src_ip: "10.77.0.60",
  dst_ip: "10.77.0.50", protocol: "ICMP", dst_port: null, ip_bytes: 84
};
const capture: PacketCaptureSnapshot = {
  source: "linux-af_packet", interface: "any", capture_scope: "any", status: "CAPTURING",
  error: null, observed_at: observedAt,
  sample_interval_seconds: 1, capture_window_seconds: 90,
  direction: "inbound and outbound", packet_layer: "IP",
  protected_host_ip: "10.77.0.50", protected_capture_interface: "wg0",
  samples: [
    { second: 10, packets: 1, bytes: 84 },
    { second: 11, packets: 0, bytes: 0 },
    { second: 12, packets: 2, bytes: 168 }
  ],
  protected_route_samples: [
    { second: 10, packets: 0, bytes: 0, icmp_packets: 0 },
    { second: 11, packets: 1, bytes: 84, icmp_packets: 1 },
    { second: 12, packets: 1, bytes: 84, icmp_packets: 1 }
  ],
  events: [
    routeEvent,
    { ...routeEvent, interface: "docker0", src_ip: "172.17.0.1" },
    { ...routeEvent, src_ip: "8.8.8.8", dst_ip: "1.1.1.1" }
  ],
  flows: [{
    src_ip: "10.77.0.60", dst_ip: "10.77.0.50", protocol: "ICMP",
    dst_port: null, packets: 3, bytes: 252
  }]
};

describe("Real packet visualization", () => {
  it("still labels global host counters as unfiltered PC2 traffic", () => {
    render(<PacketHistory capture={capture} />);
    const panel = screen.getByTestId("live-packet-history");
    expect(within(panel).getByText("PACKETS / LAST 5S")).toBeTruthy();
    expect(within(panel).getByText("252")).toBeTruthy();
    expect(within(panel).getByText(/ALL PC2 host interfaces/)).toBeTruthy();
  });

  it("shows PC5-only per-second samples on the overview chart", () => {
    render(<PacketHistory capture={capture} compact protectedOnly />);
    const panel = screen.getByTestId("live-packet-history");
    expect(panel.className).toContain("mon-traffic-compact");
    expect(within(panel).getByText("Live PC-5 gateway traffic")).toBeTruthy();
    expect(within(panel).getByText("IP FRAMES / LAST 5S")).toBeTruthy();
    expect(within(panel).getByText("168")).toBeTruthy();
    expect(screen.queryByTestId("real-network-event-log")).toBeNull();
  });

  it("does not invent a protected target when unconfigured", () => {
    const unconfigured = { ...capture, protected_host_ip: null };
    render(<ProtectedRouteStrip capture={unconfigured} />);
    expect(screen.getByText("Victim IP not configured")).toBeTruthy();
    expect(screen.getAllByText("UNVERIFIED").length).toBeGreaterThan(0);
  });

  it("only highlights actual recent PC5 tunnel evidence", () => {
    const { container, rerender } = render(<NetworkPath capture={capture} />);
    expect(container.querySelectorAll(".mon-traffic-pulse")).toHaveLength(1);
    expect(screen.getByText("RECENT CAPTURE OBSERVED")).toBeTruthy();
    expect(screen.getByTestId("route-count").textContent).toContain(
      "2 matching frame observations"
    );
    rerender(<NetworkPath capture={{
      ...capture, events: [], lab_route_events: [], protected_route_samples: []
    }} />);
    expect(container.querySelectorAll(".mon-traffic-pulse")).toHaveLength(0);
    expect(screen.getByText("NO MATCHING TUNNEL FRAMES")).toBeTruthy();
  });

  it("shows captured ping as ICMP, not a fictional intrusion", () => {
    render(<NetworkPath capture={capture} />);
    expect(screen.getByTestId("route-observation-summary").textContent).toContain("ICMP: 2");
    expect(screen.getAllByText("ICMP").length).toBeGreaterThan(0);
    expect(screen.queryByText(/PC6 · Lab source/)).toBeNull();
  });
});

describe("Honest chart aggregation and event data", () => {
  it("computes true 5-second arithmetic means", () => {
    expect(trailingPacketRate([2, 0, 2, 0, 2, 0, 2], 5))
      .toEqual([2, 1, 4 / 3, 1, 1.2, 0.8, 1.2]);
  });
  it("shows observed packet metadata, without manufactured entries", () => {
    render(<PacketHistory capture={capture} />);
    const panel = screen.getByTestId("real-network-event-log");
    expect(within(panel).getAllByText("wg0").length).toBeGreaterThan(0);
    expect(within(panel).getAllByText("inbound").length).toBeGreaterThan(0);
    expect(within(panel).getAllByText("10.77.0.60").length).toBeGreaterThan(0);
    expect(within(panel).getAllByText("10.77.0.50").length).toBeGreaterThan(0);
  });
});
