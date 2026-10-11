import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { buildIncidentScene, classifyIncident, Incident3DScene } from "./Incident3D";
import type { Incident, IncidentInvestigation, ResponseExecution } from "./types";

const incident: Incident = {
  incident_id: "incident-1", tenant_id: "mon-lab", site_id: "site-a",
  title: "Repeated endpoint authentication failures", severity: "MEDIUM",
  status: "OPEN", confidence: .72,
  affected_asset_ids: ["linux-host:lab-pc5"],
  detector_ids: ["endpoint-auth-failure-pressure"],
  entities: ["10.77.0.60", "linux-host:lab-pc5"],
  last_seen: "2026-10-11T03:12:00Z"
};
const investigation = {
  incident,
  affected_assets: [{
    asset_id: "linux-host:lab-pc5", display_name: "lab-pc5",
    ip_addresses: ["10.77.0.50"]
  }],
  findings: [{
    finding_id: "finding-1", detector_id: "endpoint-auth-failure-pressure",
    title: incident.title, src_ip: "10.77.0.60",
    last_seen: "2026-10-11T03:12:00Z"
  }],
  evidence: [
    { evidence_id: "evt-1", evidence_class: "IDENTITY",
      summary: "SSH authentication failure", source: "journal:sshd-session",
      confidence: .75, observed_at: "2026-10-11T03:11:00Z" }
  ],
  graph: { tenant_id: "mon-lab", site_id: "site-a", nodes: [], edges: [] },
  containment_capabilities: []
} as unknown as IncidentInvestigation;
const response = {
  execution_id: "response-1", requested_at: "2026-10-11T03:13:00Z",
  status: "ROLLED_BACK", plan: {
    request: { incident_id: "incident-1", action: "BLOCK_IP" }
  }
} as ResponseExecution;

afterEach(cleanup);

describe("3D scene is rebuilt from recorded MON incident evidence", () => {
  it("uses distinct scene layouts for distinct detector categories", () => {
    const kinds = [
      ["SSH authentication failures", "authentication"],
      ["TCP port scan across the subnet", "reconnaissance"],
      ["Lateral movement after remote exec", "lateral"],
      ["Periodic malware beacon callbacks", "beacon"],
      ["Containment blocked suspicious source", "containment"],
      ["Generic incident with observations", "generic"]
    ] as const;
    for (const [title, expected] of kinds) {
      expect(classifyIncident({ ...incident, title, detector_ids: [] })).toBe(expected);
    }
    expect(classifyIncident(incident)).toBe("authentication");
    const auth = buildIncidentScene(investigation, [], [], null);
    const beaconIncident = { ...incident, title: "Periodic C2 beacon",
      detector_ids: ["dns-beacon-pressure"] };
    const beacon = buildIncidentScene({
      ...investigation, incident: beaconIncident
    }, [], [], null);
    expect(auth.nodes.find(n => n.kind === "asset")?.y)
      .not.toEqual(beacon.nodes.find(n => n.kind === "asset")?.y);
  });

  it("does not manufacture intermediate network devices or attacker hops", () => {
    const model = buildIncidentScene(investigation, [response], [], null);
    expect(model.source).toBe("10.77.0.60");
    expect(model.nodes.some(n => n.kind === "asset" && n.label === "lab-pc5")).toBe(true);
    expect(model.nodes.some(n => n.label.includes("PC2"))).toBe(false);
    expect(model.links.find(l => l.id.startsWith("case:"))?.recorded).toBe(false);
    expect(model.links.find(l => l.id.startsWith("response:"))?.recorded).toBe(true);
    expect(model.packets).toBe(0);
    expect(model.lastPacketAt).toBeNull();
  });

  it("counts only matching source-target packet headers", () => {
    const model = buildIncidentScene(investigation, [], [], {
      lab_route_events: [
        { timestamp: "2026-10-11T03:12:00Z", interface: "wg0",
          direction: "inbound", src_ip: "10.77.0.60", dst_ip: "10.77.0.50",
          protocol: "ICMP", dst_port: null, ip_bytes: 84 },
        { timestamp: "2026-10-11T03:12:02Z", interface: "lo",
          direction: "outbound", src_ip: "127.0.0.1", dst_ip: "127.0.0.1",
          protocol: "TCP", dst_port: 8088, ip_bytes: 500 }
      ]
    } as never);
    expect(model.packets).toBe(1);
    expect(model.lastPacketAt).toBe("2026-10-11T03:12:00Z");
  });

  it("supports orbit, accessible 2D fallback and time scrubbing without executing responses", () => {
    const model = buildIncidentScene(investigation, [response], [], null);
    render(<Incident3DScene model={model} />);
    expect(screen.getByTestId("incident-3d-viewport")).toBeTruthy();
    expect(screen.getByTestId("scene-inspector")).toBeTruthy();
    expect(screen.getByText(/Recorded entities/)).toBeTruthy();
    expect(screen.getByText(/Last matched IP header/)).toBeTruthy();
    expect(screen.getByTestId("mon3d-node-source")).toBeTruthy();
    expect(screen.getByTestId("mon3d-node-asset")).toBeTruthy();
    expect(screen.getAllByTestId("mon3d-node-response")).toHaveLength(1);
    expect(screen.getAllByTestId("mon3d-node-evidence")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "2D" }));
    const flat = screen.getByTestId("incident-2d-view");
    expect(within(flat).getByText("lab-pc5")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "3D" }));
    expect(screen.getByTestId("incident-3d-viewport")).toBeTruthy();
    expect(screen.getByTestId("incident-play")).toBeTruthy();
    expect(screen.getByText(/read-only and never authorizes response execution/)).toBeTruthy();
  });
});
