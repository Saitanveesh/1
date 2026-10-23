import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import SuricataPanel from "./SuricataPanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("presents only actual Suricata EVE metadata and rule alerts", async () => {
  const request = vi.fn().mockResolvedValue({
    ok: true, json: async () => ({
      source: "suricata-eve", status: "RECENT_EVE", service_state: "active", observed_events: 2,
      alerts: 1, last_seen: "2026-10-11T12:00:00Z",
      records: [
        { event_type: "alert", timestamp: "2026-10-11T12:00:00Z",
          src_ip: "10.77.0.60", src_port: 50100,
          dst_ip: "10.77.0.50", dst_port: 22,
          protocol: "TCP", application: "ssh", community_id: "1:abc",
          signature: "Example test IDS signature", severity: 2 },
        { event_type: "flow", timestamp: "2026-10-11T12:00:01Z",
          src_ip: "10.77.0.60", src_port: 50100,
          dst_ip: "10.77.0.50", dst_port: 22,
          protocol: "TCP", application: "ssh", community_id: "1:abc",
          pkts_toserver: 4, pkts_toclient: 3 }
      ]
    })
  });
  vi.stubGlobal("fetch", request);
  render(<SuricataPanel />);
  await waitFor(() => expect(screen.getByTestId("suricata-status").textContent)
    .toContain("RECENT EVE"));
  const panel = screen.getByTestId("suricata-ids-panel");
  expect(within(panel).getByText("Example test IDS signature")).toBeTruthy();
  expect(within(panel).getByText("7 packets")).toBeTruthy();
  expect(request.mock.calls[0][0]).toBe("/portal/ids");
});

it("does not fabricate IDS alerts before a real sensor has been installed", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
    ok: true, json: async () => ({
      source: "suricata-eve", status: "NOT_INSTALLED",
      observed_events: 0, alerts: 0, last_seen: null, records: []
    })
  }));
  render(<SuricataPanel />);
  await waitFor(() => expect(screen.getByText(/Suricata IDS not yet installed/))
    .toBeTruthy());
});

it("does not mix unrelated PC2 EVE traffic into the protected PC5 IDS panel", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({
      source: "suricata-eve", status: "RECENT_EVE", service_state: "active",
      observed_events: 2, alerts: 2, last_seen: new Date().toISOString(),
      records: [
        { event_type: "alert", timestamp: new Date().toISOString(),
          src_ip: "10.77.0.60", dst_ip: "10.77.0.50", src_port: 50000,
          dst_port: 8085, signature: "MON LAB PC5 signature", protocol: "TCP", application: "http" },
        { event_type: "alert", timestamp: new Date().toISOString(),
          src_ip: "172.17.0.3", dst_ip: "10.5.112.136", src_port: 50001,
          dst_port: 8080, signature: "Unrelated host event", protocol: "TCP", application: "http" }
      ]
    })
  }));
  render(<SuricataPanel protectedIp="10.77.0.50" />);
  await waitFor(() => expect(screen.getByText("MON LAB PC5 signature")).toBeTruthy());
  expect(screen.queryByText("Unrelated host event")).toBeNull();
  const panel = screen.getByTestId("suricata-ids-panel");
  expect(within(panel).getAllByText("1").length).toBeGreaterThanOrEqual(2);
  expect(within(panel).getByText("PROTECTED-HOST EVE ROWS")).toBeTruthy();
});
