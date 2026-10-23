import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import AlertCenter, { collectAlerts } from "./AlertCenter";
import { alertFromSuricata } from "./suricataThreats";
import { alertReport } from "./AlertInvestigation";
import type { SecurityThreatAlert } from "./securityAlerts";
import type { SuricataRecord, SuricataSnapshot } from "./types";

const at = new Date(Date.now()-15_000).toISOString();
const row: SuricataRecord = {
  event_type: "alert", timestamp: at, src_ip:"10.77.0.70",
  dst_ip:"10.77.0.50", src_port:45321,dst_port:8085,
  signature:"MON LAB test traversal", signature_id:42000501,
  category:"Web Application Attack",severity:2,protocol:"TCP",
  application:"http", community_id:"test"
};
const snapshot: SuricataSnapshot = {
  source:"suricata-eve",service_state:"active",status:"RECENT_EVE",
  observed_events:2,alerts:2,last_seen:at,
  records:[row,{...row,src_ip:"10.5.112.33",dst_ip:"10.77.0.99",signature_id:77}]
};
const alert:SecurityThreatAlert = alertFromSuricata(row)!;
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("final alert review", () => {
  it("builds only observed, target-scoped IDS alerts without synthetic peers", () => {
    const result = collectAlerts(snapshot,"10.77.0.50",[]);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      source:"10.77.0.70",target:"10.77.0.50",signatureId:42000501
    });
    expect(collectAlerts(snapshot,null,[])).toHaveLength(0);
  });
  it("never replays a duplicate detection as two separate inbox records", () => {
    expect(collectAlerts(snapshot,"10.77.0.50",[alert,alert])).toHaveLength(1);
  });
  it("offers an active alert's specific investigation and review actions", () => {
    const open=vi.fn(), ack=vi.fn();
    render(<AlertCenter alerts={[alert]} acknowledged={{}}
      sensorReady onOpen={open} onAcknowledge={ack} />);
    const panel=screen.getByTestId("alerts-workspace");
    expect(within(panel).getByText("10.77.0.70", {exact:false})).toBeTruthy();
    fireEvent.click(within(panel).getByRole("button",{name:/Investigate MON LAB test traversal/}));
    expect(open).toHaveBeenCalledExactlyOnceWith(alert);
    fireEvent.click(within(panel).getByRole("button",{name:/Acknowledge MON LAB test traversal/}));
    expect(ack).toHaveBeenCalledExactlyOnceWith(alert);
  });
  it("shows acknowledged status and removes duplicate review action", () => {
    render(<AlertCenter alerts={[alert]} acknowledged={{[alert.key]:at}}
      sensorReady onOpen={vi.fn()} onAcknowledge={vi.fn()} />);
    expect(screen.getAllByText("Acknowledged").length).toBeGreaterThan(0);
    expect(screen.queryByRole("button",{name:/Acknowledge MON LAB/})).toBeNull();
  });
  it("does not offer a server write for stale or unavailable EVE evidence", () => {
    const old={...alert,observedAt:new Date(Date.now()-1_000_000).toISOString()};
    const ack=vi.fn();
    const {rerender}=render(<AlertCenter alerts={[old]} acknowledged={{}}
      sensorReady onOpen={vi.fn()} onAcknowledge={ack} />);
    expect(screen.getByText("Review window ended")).toBeTruthy();
    expect(screen.queryByRole("button",{name:/Acknowledge MON LAB/})).toBeNull();
    rerender(<AlertCenter alerts={[alert]} acknowledged={{}}
      sensorReady={false} onOpen={vi.fn()} onAcknowledge={ack} />);
    expect(screen.getByText("Review unavailable while sensor is offline")).toBeTruthy();
    expect(ack).not.toHaveBeenCalled();
  });
  it("searches by source and filters by review state without changing evidence", () => {
    const other={...alert,key:"finding:2",title:"MON case finding",source:"10.77.0.60"};
    const {rerender}=render(<AlertCenter alerts={[alert,other]} acknowledged={{}}
      sensorReady onOpen={vi.fn()} onAcknowledge={vi.fn()} />);
    fireEvent.change(screen.getByRole("textbox",{name:"Search alerts"}),{target:{value:"10.77.0.60"}});
    expect(screen.getByText("MON case finding")).toBeTruthy();
    expect(screen.queryByText("MON LAB test traversal")).toBeNull();
    rerender(<AlertCenter alerts={[alert,other]} acknowledged={{[alert.key]:at}}
      sensorReady onOpen={vi.fn()} onAcknowledge={vi.fn()} />);
    fireEvent.change(screen.getByRole("textbox",{name:"Search alerts"}),{target:{value:""}});
    fireEvent.click(screen.getByRole("button",{name:"Acknowledged"}));
    expect(screen.getByText("MON LAB test traversal")).toBeTruthy();
    expect(screen.queryByText("MON case finding")).toBeNull();
  });
  it("prints an honest offline report without claiming attack success or blocking", () => {
    const report = alertReport(alert,null,false,0);
    expect(report).toContain("10.77.0.70");
    expect(report).toContain("Not currently available");
    expect(report).toContain("does not establish a successful attack");
  });
});
