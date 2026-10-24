import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import DemoGuide, { describeDemo, preferredGuideAlert } from "./DemoGuide";
import type { SecurityThreatAlert } from "./securityAlerts";
import type { MitigationStatus, VictimImpact } from "./Stage4ResponsePanel";
import type { PacketCaptureSnapshot, SuricataSnapshot } from "./types";

const NOW = Date.parse("2026-10-24T06:00:00.000Z");
const timestamp = new Date(NOW).toISOString();

const alert: SecurityThreatAlert = {
  key: "ids:example",
  title: "Training web rule matched",
  severity: "HIGH",
  source: "10.77.0.70",
  target: "10.77.0.50",
  attackClass: "Training web request",
  observedAt: timestamp,
  detector: "Suricata IDS",
  signatureId: 42000503
};

const capture = {
  source: "linux-af_packet",
  interface: "wg0",
  protected_host_ip: "10.77.0.50",
  protected_capture_interface: "wg0",
  protected_route_check: "MATCHES_CAPTURE_INTERFACE",
  status: "CAPTURING",
  observed_at: timestamp,
  sample_interval_seconds: 1,
  protected_route_samples: [
    { second: Math.floor(NOW / 1000) - 2, packets: 0, bytes: 0, icmp_packets: 0 },
    { second: Math.floor(NOW / 1000) - 1, packets: 5, bytes: 200, icmp_packets: 0 },
    { second: Math.floor(NOW / 1000), packets: 0, bytes: 0, icmp_packets: 0 }
  ]
} as PacketCaptureSnapshot;

const sensor = {
  source: "suricata-eve",
  service_state: "active",
  status: "RECENT_EVE",
  records: [],
  alerts: 1,
  observed_events: 1,
  last_seen: timestamp
} as SuricataSnapshot;

const mitigation: MitigationStatus = {
  source: "10.77.0.70",
  destination: "10.77.0.50",
  port: 8085,
  active: true,
  enforcement: "KERNEL_RULE_PRESENT",
  expires_in_seconds: 90,
  dropped_packets_total: 4,
  audit: [],
  scope: "training only"
};

const impact: VictimImpact = {
  status: "OBSERVED",
  source: "10.77.0.70",
  window_start: timestamp,
  window_end: timestamp,
  observed_requests: 4,
  successful_http_responses: 3,
  fictional_exposure_responses: 2,
  fictional_records_in_responses: 2,
  fictional_response_bytes_written: 250,
  exposure_categories: { fictional_canary: 1, fictional_student: 1 },
  last_fictional_exposure_at: timestamp,
  recent_events: [],
  truncated: false,
  scope: "fictional training only"
};

type Input = Parameters<typeof describeDemo>[0];

function example(overrides: Partial<Input> = {}): Input {
  return {
    view: "Overview",
    connected: true,
    capture,
    sensor,
    sensorAvailable: true,
    alerts: [],
    acknowledged: {},
    focusedAlert: null,
    cases: [],
    mitigation: null,
    impact: null,
    now: NOW,
    ...overrides
  };
}

describe("Batch 5: truthful plain-language narration", () => {
  it("never fabricates a detection when the feeds are unavailable", () => {
    const story = describeDemo(example({
      connected: false, capture: null, sensor: null, sensorAvailable: false
    }));
    expect(story.heading).toBe("Monitoring information is unavailable");
    expect(story.steps[0].status).toBe("unavailable");
    expect(story.steps[1].status).toBe("unavailable");
    expect(story.steps[3].status).toBe("waiting");
    expect(story.source).toBeNull();
  });

  it("reports packets but never labels ordinary network traffic an attack", () => {
    const story = describeDemo(example());
    expect(story.heading).toContain("Traffic is passing");
    expect(story.explanation).toContain("not automatically an attack");
    expect(story.steps[0].status).toBe("seen");
    expect(story.steps[1].status).toBe("waiting");
  });

  it("only labels a fresh matching alert as a detection", () => {
    const story = describeDemo(example({ alerts: [alert] }));
    expect(story.heading).toBe("Suspicious activity was reported");
    expect(story.steps[1].status).toBe("seen");
    expect(story.steps[3].status).toBe("waiting");
  });

  it("does not describe a stale alert as a live attack", () => {
    const stale = { ...alert, observedAt: new Date(NOW - 500_000).toISOString() };
    const story = describeDemo(example({ alerts: [stale] }));
    expect(story.heading).toContain("Traffic is passing");
    expect(story.steps[1].status).toBe("waiting");
  });

  it("opening Investigation and acknowledging it are separate from enforcement", () => {
    const inspecting = describeDemo(example({
      view: "Investigation", focusedAlert: alert, alerts: [alert]
    }));
    expect(inspecting.heading).toContain("Blue Team is checking");
    expect(inspecting.steps[2].status).toBe("in-progress");
    expect(inspecting.steps[3].status).toBe("waiting");
    const reviewed = describeDemo(example({
      view: "Investigation", focusedAlert: alert,
      acknowledged: { [alert.key]: timestamp }
    }));
    expect(reviewed.steps[2].status).toBe("seen");
    expect(reviewed.steps[3].status).toBe("waiting");
  });

  it("requires a kernel-reported rule for a present-tense block claim", () => {
    const active = describeDemo(example({
      alerts: [alert], mitigation
    }));
    expect(active.heading).toBe("A temporary website block is installed");
    expect(active.explanation).toContain("must still be tried");
    expect(active.steps[3].status).toBe("seen");
    const pending = describeDemo(example({
      alerts: [alert],
      mitigation: { ...mitigation, active: true, enforcement: "UNAVAILABLE" }
    }));
    expect(pending.heading).not.toContain("block is installed");
    expect(pending.steps[3].status).toBe("waiting");
  });

  it("does not attribute a different source's block to the selected alert", () => {
    const story = describeDemo(example({
      alerts: [alert],
      mitigation: { ...mitigation, source: "10.77.0.60" }
    }));
    expect(story.steps[3].status).toBe("waiting");
    expect(story.heading).toBe("Suspicious activity was reported");
  });

  it("reports only recorded fictional victim responses, without asserting client receipt", () => {
    const story = describeDemo(example({
      alerts: [alert], impact,
      sensorAvailable: false, sensor: null, capture: null
    }));
    expect(story.steps[4].status).toBe("seen");
    expect(story.steps[4].detail).toContain("4 responses recorded");
    expect(story.steps[4].detail).toContain("2 contained fictional training data");
    expect(story.coverage).toContain("fictional test data");
    expect(story.explanation).not.toContain("attacker was stopped");
  });

  it("does not misattribute another source's victim responses", () => {
    const story = describeDemo(example({
      alerts: [alert], impact: { ...impact, source: "10.77.0.60" }
    }));
    expect(story.steps[4].status).toBe("unavailable");
  });

  it("reports completed history without calling an expired rule active", () => {
    const history = {
      ...mitigation, active: false, enforcement: "NO_RULE",
      audit: [{
        at: timestamp, action: "block" as const,
        source: "10.77.0.70", destination: "10.77.0.50",
        port: 8085, active: false, rule_state: "NO_RULE"
      }]
    };
    const story = describeDemo(example({ alerts: [alert], mitigation: history }));
    expect(story.steps[3].detail).toContain("no active block is verified");
    expect(story.heading).not.toContain("block is installed");
  });

  it("prefers the exact investigated alert, but excludes a wrong victim", () => {
    expect(preferredGuideAlert(example({
      focusedAlert: alert,
      alerts: [{ ...alert, source: "10.77.0.60" }]
    }))?.source).toBe("10.77.0.70");
    expect(preferredGuideAlert(example({
      focusedAlert: { ...alert, target: "192.0.2.1" }, alerts: []
    }))).toBeNull();
  });

  it("renders a collapsible contextual guide without synthetic values", () => {
    const onClose = vi.fn();
    render(<DemoGuide view="Alerts" connected={false} capture={null}
      sensor={null} sensorAvailable={false} alerts={[]} acknowledged={{}}
      focusedAlert={null} cases={[]} authenticated={false}
      onClose={onClose} />);
    expect(screen.getByRole("complementary", {
      name: "What is happening in this demonstration"
    })).toBeTruthy();
    expect(screen.getByText("What's happening?")).toBeTruthy();
    expect(screen.getByText(/does not prove an attack succeeded/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Hide explanation panel" }));
    expect(onClose).toHaveBeenCalledOnce();
  });
});
