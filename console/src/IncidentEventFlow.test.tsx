import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { buildIncidentSteps } from "./IncidentEventFlow";
import IncidentEventFlow from "./IncidentEventFlow";
import type { IncidentInvestigation, ResponseExecution } from "./types";

const investigation = {
  incident: {
    incident_id: "case-pc6", tenant_id: "mon-lab", site_id: "site-a",
    title: "Repeated endpoint authentication failures", severity: "MEDIUM",
    status: "OPEN", confidence: .72,
    affected_asset_ids: ["linux-host:lab-pc5"], detector_ids: ["endpoint-auth-failure-pressure"],
    entities: ["10.77.0.60", "linux-host:lab-pc5"], last_seen: "2026-10-11T10:00:00Z"
  },
  findings: [{
    finding_id: "finding-1", src_ip: "10.77.0.60", detector_id: "endpoint-auth-failure-pressure",
    title: "8 authentication failures in 300 seconds", last_seen: "2026-10-11T10:00:00Z"
  }],
  evidence: [{
    evidence_id: "evidence-1", source: "endpoint:linux-journal:sshd-session",
    summary: "Endpoint reported SSH authentication failure",
    evidence_class: "IDENTITY", observed_at: "2026-10-11T09:59:00Z"
  }],
  affected_assets: [{
    asset_id: "linux-host:lab-pc5", display_name: "lab-pc5", ip_addresses: ["10.77.0.50"]
  }],
  graph: { nodes: [], edges: [] },
  containment_capabilities: []
} as unknown as IncidentInvestigation;

const response = {
  execution_id: "response-1", status: "ROLLED_BACK",
  requested_at: "2026-10-11T10:00:30Z",
  plan: { request: { incident_id: "case-pc6", action: "BLOCK_IP" } }
} as ResponseExecution;

afterEach(cleanup);

it("exposes observed case source, endpoint evidence, detector and actual rollback", () => {
  const steps = buildIncidentSteps(investigation, [response]);
  expect(steps).toHaveLength(4);
  expect(steps[0].name).toBe("10.77.0.60");
  expect(steps[1].name).toBe("lab-pc5");
  expect(steps[1].detail).toContain("sshd-session");
  expect(steps[2].name).toBe("endpoint-auth-failure-pressure");
  expect(steps[3].name).toBe("BLOCK_IP · ROLLED_BACK");
  expect(steps.some(step => step.name.includes("PC2"))).toBe(false);
});

it("shows unknown observations honestly instead of inventing a network hop", () => {
  render(<IncidentEventFlow investigation={{
    ...investigation, evidence: [], findings: []
  }} responses={[]} />);
  expect(screen.getByTestId("incident-event-chain")).toBeTruthy();
  expect(screen.getByText("No detector record")).toBeTruthy();
  expect(screen.getByText("No response recorded")).toBeTruthy();
  expect(screen.getByText(/not a verified packet-hop trace/)).toBeTruthy();
});
