import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { NetworkPath, PacketHistory, trailingPacketRate } from "./PacketObservability";
import type { PacketCaptureSnapshot } from "./types";

const capture: PacketCaptureSnapshot = {
  source: "linux-af_packet",
  interface: "wg0",
  status: "CAPTURING",
  error: null,
  observed_at: "2026-10-11T00:00:00Z",
  sample_interval_seconds: 1,
  capture_window_seconds: 90,
  direction: "incoming only",
  packet_layer: "IP",
  samples: [
    { second: 10, packets: 1, bytes: 84 },
    { second: 11, packets: 0, bytes: 0 },
    { second: 12, packets: 2, bytes: 168 }
  ],
  flows: [
    {
      src_ip: "10.77.0.60",
      dst_ip: "10.77.0.50",
      protocol: "ICMP",
      dst_port: null,
      packets: 3,
      bytes: 252
    }
  ]
};

describe("Real packet visualization", () => {
  it("shows measured 5s counters rather than zeroed last-second averages", () => {
    render(<PacketHistory capture={capture} />);
    const panel = screen.getByTestId("live-packet-history");
    expect(within(panel).getByText("PACKETS / LAST 5S")).toBeTruthy();
    expect(within(panel).getByText("BYTES / LAST 5S")).toBeTruthy();
    expect(within(panel).getByText("252")).toBeTruthy();
    expect(within(panel).getByText("MEASURED PACKETS / S (5S AVG)")).toBeTruthy();
    expect(within(panel).getByText("RAW 1S")).toBeTruthy();
  });

  it("animates only while matching RECENT packet-header evidence exists", () => {
    const recent: PacketCaptureSnapshot = {
      ...capture,
      events: [{
        timestamp: "2026-10-10T23:59:58Z", interface: "wg0",
        direction: "inbound", src_ip: "10.77.0.60",
        dst_ip: "10.77.0.50", protocol: "ICMP", dst_port: null, ip_bytes: 84
      }]
    };
    const { container, rerender } = render(
      <NetworkPath capture={recent} attackerIps={["10.77.0.60"]} />
    );
    expect(container.querySelectorAll(".mon-traffic-pulse")).toHaveLength(2);
    expect(screen.getByText("TRAFFIC OBSERVED NOW")).toBeTruthy();
    rerender(<NetworkPath capture={{ ...recent, events: [] }} attackerIps={["10.77.0.60"]} />);
    expect(container.querySelectorAll(".mon-traffic-pulse")).toHaveLength(0);
    expect(screen.getByText("NO MATCHING RECENT PACKETS")).toBeTruthy();
  });

  it("describes ICMP from the lab source as expected baseline, not attack", () => {
    render(<NetworkPath capture={capture} attackerIps={["10.77.0.60"]} />);
    expect(screen.getByText(/EXPECTED-BASELINE/)).toBeTruthy();
    expect(screen.getByText(/Animation is enabled only by recent matching IP headers/)).toBeTruthy();
  });
});

describe("Honest chart aggregation and event data", () => {
  it("computes a true trailing five-second average from real sample counts", () => {
    expect(trailingPacketRate([2, 0, 2, 0, 2, 0, 2], 5))
      .toEqual([2, 1, 4 / 3, 1, 1.2, 0.8, 1.2]);
  });

  it("shows actual observed packet log fields without fabricated entries", () => {
    const withEvents: PacketCaptureSnapshot = {
      ...capture,
      capture_scope: "any",
      raw_frames: 3,
      decoded_packets: 3,
      observed_interfaces: { wg0: 3 },
      events: [
        {
          timestamp: "2026-10-11T00:00:01Z",
          interface: "wg0", direction: "inbound",
          src_ip: "10.77.0.60", dst_ip: "10.77.0.50",
          protocol: "ICMP", dst_port: null, ip_bytes: 84
        }
      ]
    };
    render(<PacketHistory capture={withEvents} />);
    const panel = screen.getByTestId("real-network-event-log");
    expect(within(panel).getByText("wg0")).toBeTruthy();
    expect(within(panel).getByText("inbound")).toBeTruthy();
    expect(within(panel).getByText("10.77.0.60")).toBeTruthy();
    expect(within(panel).getByText("10.77.0.50")).toBeTruthy();
    expect(within(panel).getByText("84")).toBeTruthy();
  });
});
