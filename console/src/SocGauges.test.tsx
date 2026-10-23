import { render, screen, within } from "@testing-library/react";
import { expect, it } from "vitest";
import SocGauges from "./SocGauges";
import type { LiveState } from "./live";
import type { PacketCaptureSnapshot } from "./types";
import type { IdsObservation } from "./suricataThreats";

const now = new Date().toISOString();
const epoch = Math.floor(Date.parse(now) / 1000);
const state = {
  connection: "LIVE", findings: [{ finding_id:"historical",last_seen:"2026-10-11T00:00:00Z" }],
  incidents: [{ incident_id:"old",severity:"HIGH",status:"OPEN",
    last_seen:"2026-10-11T00:00:00Z" }]
} as unknown as LiveState;
const observed: PacketCaptureSnapshot = {
  source:"linux-af_packet", interface:"any", status:"CAPTURING",
  observed_at:now, error:null, sample_interval_seconds:1,
  capture_window_seconds:90, direction:"inbound and outbound",packet_layer:"IP",
  protected_host_ip:"10.77.0.50",protected_capture_interface:"wg0",
  protected_route_check:"MATCHES_CAPTURE_INTERFACE",
  samples:[{second:epoch,packets:5000,bytes:500000}],
  protected_route_samples:[{second:epoch,packets:2,bytes:168,icmp_packets:2}],
  flows:[]
};
const idsOffline: IdsObservation = {
  availability:"AVAILABLE",
  snapshot:{source:"suricata-eve",status:"RECENT_EVE",
    service_state:"failed",observed_events:1,alerts:1,last_seen:now,
    records:[{event_type:"alert",timestamp:now,src_ip:"10.77.0.60",
      src_port:1234,dst_ip:"10.77.0.50",dst_port:8085,protocol:"TCP",
      application:"http",community_id:"c",severity:2}]
  }
};

it("withholds PC5 numbers without a recent targeted capture", () => {
  render(<SocGauges state={state} capture={{
    ...observed,protected_host_ip:null
  }} ids={idsOffline} />);
  const box = screen.getByTestId("soc-gauges");
  expect(within(box).getAllByText("NO DATA").length).toBe(3);
  expect(within(box).getByText("UNVERIFIED")).toBeTruthy();
  expect(within(box).queryByText(/5000/)).toBeNull();
  expect(within(box).queryByText(/100 pps reference/)).toBeNull();
});

it("uses scoped PC5 measured frames, not unrelated PC2 packet totals", () => {
  render(<SocGauges state={state} capture={observed} ids={idsOffline} />);
  const box = screen.getByTestId("soc-gauges");
  expect(within(box).getByText("0.4")).toBeTruthy();
  expect(within(box).getByText("34 B/s")).toBeTruthy();
  expect(within(box).getByText("2")).toBeTruthy();
  expect(within(box).getByText("UNVERIFIED")).toBeTruthy();
  expect(within(box).queryByText(/5000/)).toBeNull();
});

it("counts only fresh real rule signatures from active Suricata aimed at PC5", () => {
  render(<SocGauges state={state} capture={observed} ids={{
    ...idsOffline,
    snapshot:{...idsOffline.snapshot!,service_state:"active"}
  }} />);
  expect(screen.getByText("1")).toBeTruthy();
});
