import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { NetworkPath, PacketHistory } from "./PacketObservability";
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
  });

  it("animates only while a corresponding observed flow exists", () => {
    const { container, rerender } = render(
      <NetworkPath capture={capture} attackerIps={["10.77.0.60"]} />
    );
    expect(container.querySelectorAll(".mon-traffic-pulse")).toHaveLength(2);
    expect(screen.getByText("PACKETS OBSERVED")).toBeTruthy();
    rerender(<NetworkPath capture={{ ...capture, flows: [] }} attackerIps={["10.77.0.60"]} />);
    expect(container.querySelectorAll(".mon-traffic-pulse")).toHaveLength(0);
    expect(screen.getByText("NO CURRENT PACKETS")).toBeTruthy();
  });

  it("describes ICMP from the lab source as expected baseline, not attack", () => {
    render(<NetworkPath capture={capture} attackerIps={["10.77.0.60"]} />);
    expect(screen.getByText(/EXPECTED-BASELINE/)).toBeTruthy();
    expect(screen.getByText(/Animation indicates RECENT OBSERVED activity/)).toBeTruthy();
  });
});
