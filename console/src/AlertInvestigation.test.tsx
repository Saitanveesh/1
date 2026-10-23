import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import AlertInvestigation, { evidenceForAlert } from "./AlertInvestigation";
import SecurityAlert from "./SecurityAlert";
import type { SecurityThreatAlert } from "./securityAlerts";
import type { PacketCaptureSnapshot, SuricataSnapshot } from "./types";

const stamp = new Date().toISOString();
const idsRow = {
  event_type: "alert" as const, timestamp: stamp,
  signature_id: 42000501,
  signature: "MON LAB possible web directory traversal", severity: 2,
  src_ip: "10.77.0.60", src_port: 50000,
  dst_ip: "10.77.0.50", dst_port: 8085,
  category: "Web Application Attack", protocol: "TCP",
  application: "http", community_id: "1:abc"
};
const alert: SecurityThreatAlert = {
  key: ["ids:",stamp,"|42000501|MON LAB possible web directory traversal|10.77.0.60|50000|10.77.0.50|8085"].join(""),
  title: idsRow.signature, signatureId: idsRow.signature_id,
  severity: "HIGH", source: idsRow.src_ip, target: idsRow.dst_ip,
  observedAt: stamp, detector: "Suricata IDS", attackClass: idsRow.category
};
const snapshot: SuricataSnapshot = {
  source: "suricata-eve", status: "RECENT_EVE", service_state: "active",
  observed_events: 1, alerts: 1, last_seen: stamp, records: [idsRow]
};
const frame = {
  timestamp: stamp, interface: "wg0", direction: "inbound" as const,
  src_ip: "10.77.0.60", dst_ip: "10.77.0.50", protocol: "TCP",
  dst_port: 8085, ip_bytes: 128, frame_id: 5
};
const capture = {
  protected_capture_interface: "wg0",
  lab_route_events: [frame, {...frame, frame_id:6, interface:"docker0"},
    {...frame, frame_id:7, src_ip:"8.8.8.8"}]
} as PacketCaptureSnapshot;

describe("live IDS investigation actions", () => {
  it("matches the exact EVE signature and only truly matching wg0 headers", () => {
    const evidence = evidenceForAlert(alert, snapshot, capture);
    expect(evidence.signature?.signature_id).toBe(42000501);
    expect(evidence.frames).toHaveLength(1);
    expect(evidence.frames[0].frame_id).toBe(5);
  });
  it("shows the actual signature, scoped packets and a wired acknowledge button", () => {
    const ack = vi.fn();
    const back = vi.fn();
    render(<AlertInvestigation alert={alert} snapshot={snapshot} capture={capture}
      acknowledgedAt={null} acknowledging={false} error={null}
      onAcknowledge={ack} onClose={back} />);
    const panel = screen.getByTestId("alert-evidence-investigation");
    expect(within(panel).getByText(/What happened\?/)).toBeTruthy();
    fireEvent.click(within(panel).getByRole("tab", {name:"Captured evidence"}));
    expect(within(panel).getByText(idsRow.signature, {selector:"dd"})).toBeTruthy();
    expect(within(panel).getByText("128")).toBeTruthy();
    fireEvent.click(within(panel).getByRole("button", {name:"ACKNOWLEDGE DETECTION"}));
    expect(ack).toHaveBeenCalledTimes(1);
    fireEvent.click(within(panel).getByRole("button", {name:"BACK TO ALERTS"}));
    expect(back).toHaveBeenCalledTimes(1);
  });
  it("does not conjure corroboration for missing capture", () => {
    render(<AlertInvestigation alert={alert} snapshot={snapshot} capture={null}
      acknowledgedAt={stamp} acknowledging={false} error={null}
      onAcknowledge={vi.fn()} onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("tab", {name:"Captured evidence"}));
    expect(screen.getByText(/No matching independent packet headers/)).toBeTruthy();
    expect(screen.getByRole("button", {name:"ACKNOWLEDGED"}).hasAttribute("disabled")).toBe(true);
  });
  it("modal keeps a failed acknowledgment visible for retry", () => {
    const acknowledge = vi.fn();
    const investigate = vi.fn();
    render(<SecurityAlert alert={alert} queued={1}
      onInvestigate={investigate} onAcknowledge={acknowledge}
      acknowledgeError="journal unavailable" />);
    fireEvent.click(screen.getByRole("button", {name:"ACKNOWLEDGE"}));
    expect(acknowledge).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("alert").textContent).toContain("journal unavailable");
    fireEvent.click(screen.getByRole("button", {name:"INVESTIGATE"}));
    expect(investigate).toHaveBeenCalledTimes(1);
  });
});
