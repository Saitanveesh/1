import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import IncidentFlowMap, { grafanaCaseUrl, observedForTarget } from "./IncidentFlowMap";
import { buildIncidentScene } from "./Incident3D";
import type { IncidentInvestigation, PacketCaptureSnapshot } from "./types";

const caseData = {
  incident: {
    incident_id: "case-1", tenant_id: "mon-lab", site_id: "site-a",
    title: "SSH authentication pressure", severity: "MEDIUM", status: "OPEN", confidence: .88,
    detector_ids: ["endpoint-auth-failure-pressure"],
    affected_asset_ids: ["linux-host:pc5"], entities: ["10.77.0.60"],
    last_seen: "2026-10-11T09:00:00Z"
  },
  findings: [{
    finding_id: "finding-1", src_ip: "10.77.0.60", dst_ip: "10.77.0.50",
    title: "Failed SSH logins", detector_id: "endpoint-auth-failure-pressure",
    last_seen: "2026-10-11T09:00:00Z"
  }],
  affected_assets: [{
    asset_id: "linux-host:pc5", display_name: "lab-pc5", ip_addresses: ["10.77.0.50"]
  }],
  evidence: [{
    evidence_id: "ev-1", evidence_class: "IDENTITY", source: "journal:sshd-session",
    summary: "Failed authentication", confidence: 1, observed_at: "2026-10-11T08:59:00Z"
  }],
  graph: { nodes: [], edges: [] }, containment_capabilities: []
} as unknown as IncidentInvestigation;

const capture = {
  status: "CAPTURING", capture_scope: "wg0", interface: "wg0",
  samples: [
    { second: 1, packets: 2, bytes: 140 },
    { second: 2, packets: 4, bytes: 260 }
  ],
  lab_route_events: [
    { timestamp: "2026-10-11T09:00:00Z", interface: "wg0",
      direction: "inbound", src_ip: "10.77.0.60", dst_ip: "10.77.0.50",
      protocol: "TCP", dst_port: 22, ip_bytes: 80 },
    { timestamp: "2026-10-11T09:00:01Z", interface: "lo",
      direction: "outbound", src_ip: "127.0.0.1", dst_ip: "127.0.0.1",
      protocol: "TCP", dst_port: 8088, ip_bytes: 60 }
  ]
} as unknown as PacketCaptureSnapshot;

afterEach(cleanup);

describe("MON V5.3 case flow", () => {
  it("draws only source-to-target traffic, keeps evidence outside network path, removes playback", () => {
    const model = buildIncidentScene(caseData, [], [], capture);
    render(<IncidentFlowMap model={model} capture={capture} />);
    expect(screen.getByTestId("incident-3d-viewport")).toBeTruthy();
    expect(screen.getByTestId("mon3d-node-source")).toBeTruthy();
    expect(screen.getByTestId("mon3d-node-asset")).toBeTruthy();
    expect(screen.getByTestId("mon3d-node-evidence")).toBeTruthy();
    expect(screen.getByText("1 recent packet headers")).toBeTruthy();
    expect(screen.queryByTestId("incident-play")).toBeNull();
    expect(screen.queryByRole("slider")).toBeNull();
    expect(screen.getByTestId("mon-normal-traffic")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "2D" }));
    expect(within(screen.getByTestId("incident-2d-view")).getByText("lab-pc5")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "3D" }));
    expect(screen.getByTestId("incident-3d-viewport")).toBeTruthy();
  });

  it("does not claim historical packet evidence when live headers are absent", () => {
    const model = buildIncidentScene(caseData, [], [], null);
    render(<IncidentFlowMap model={model} capture={null} />);
    expect(screen.getByText("Packet path not established")).toBeTruthy();
    expect(screen.getByText(/No matching headers were retained/)).toBeTruthy();
    expect(screen.getByText("CONNECTING")).toBeTruthy();
    expect(screen.queryByText("1 recent packet headers")).toBeNull();
  });

  it("scopes matches to recorded source and target addresses, not unrelated traffic", () => {
    expect(observedForTarget("10.77.0.60", ["10.77.0.50"], capture)).toHaveLength(1);
    expect(observedForTarget("10.77.0.61", ["10.77.0.50"], capture)).toHaveLength(0);
    expect(observedForTarget(null, ["10.77.0.50"], capture)).toHaveLength(0);
  });

  it("opens the true case window in Grafana and does not imply per-flow Prometheus metrics", () => {
    const model = buildIncidentScene(caseData, [], [], capture);
    const url = new URL(grafanaCaseUrl(model, "100.75.116.62"));
    expect(url.pathname).toBe("/d/mon-network");
    expect(url.searchParams.get("from")).toBe("2026-10-11T08:54:00.000Z");
    expect(url.searchParams.get("to")).toBe("2026-10-11T09:05:00.000Z");
  });

  it("reconstructs a different case from its own findings, never from the previous case", () => {
    const other = { ...caseData,
      incident: { ...caseData.incident, incident_id: "case-2", title: "Port scan" },
      findings: [{ ...caseData.findings[0], src_ip: "10.77.0.90" }]
    } as unknown as IncidentInvestigation;
    const model = buildIncidentScene(other, [], [], capture);
    expect(model.source).toBe("10.77.0.90");
    expect(model.kind).toBe("reconnaissance");
    render(<IncidentFlowMap model={model} capture={capture} />);
    expect(screen.getByText("10.77.0.90")).toBeTruthy();
    expect(screen.queryByText("10.77.0.60")).toBeNull();
  });
});
