import { describe, expect, it } from "vitest";
import {
  currentProtectedFindings, currentProtectedIncidents,
  idsStatus, isProtectedCaptureReady, isRecentObservation
} from "./operationalTruth";
import type {
  Asset, Finding, Incident, PacketCaptureSnapshot, SuricataSnapshot
} from "./types";

const now = Date.parse("2026-10-23T10:00:00Z");
const recent = "2026-10-23T09:59:30Z";
const old = "2026-10-11T10:00:00Z";
const finding: Finding = {
  finding_id:"new", detector_id:"suricata-web", title:"Observed signature",
  severity:"HIGH", confidence:.98, src_ip:"10.77.0.60",
  dst_ip:"10.77.0.50", last_seen:recent
};
const incident: Incident = {
  incident_id:"i", tenant_id:"t", site_id:"s", severity:"HIGH",
  title:"Web attempt", status:"OPEN", confidence:.98,
  affected_asset_ids:["asset-pc5"], detector_ids:["suricata-web"],
  entities:["10.77.0.60"], last_seen:recent
};
const asset: Asset = {
  asset_id:"asset-pc5", tenant_id:"t", site_id:"s", display_name:"PC5",
  criticality:"HIGH", ip_addresses:["10.77.0.50"],
  mac_addresses:[], hostnames:[], observed_tcp_services:[],
  peer_counts:{}, protocol_counts:{}, identity_evidence:[],
  first_seen:recent, last_seen:recent
};

describe("truthful live metrics", () => {
  it("rejects old, future and invalid observations", () => {
    expect(isRecentObservation(recent,now)).toBe(true);
    expect(isRecentObservation(old,now)).toBe(false);
    expect(isRecentObservation("invalid",now)).toBe(false);
    expect(isRecentObservation("2026-10-23T10:03:00Z",now)).toBe(false);
  });
  it("rejects host-wide packet readings without a protected route", () => {
    const capture = {
      status:"CAPTURING", observed_at:recent,
      protected_host_ip:null, protected_capture_interface:"wg0",
      protected_route_samples:[{ second:1, packets:25, bytes:2000, icmp_packets:0 }]
    } as PacketCaptureSnapshot;
    expect(isProtectedCaptureReady(capture,now)).toBe(false);
    expect(isProtectedCaptureReady({ ...capture,protected_host_ip:"10.77.0.50" },now))
      .toBe(false); // stale > 12s
    expect(isProtectedCaptureReady({
      ...capture,protected_host_ip:"10.77.0.50",
      observed_at:"2026-10-23T09:59:59Z"
    },now)).toBe(true);
  });
  it("does not classify historical OPEN cases as live attacks", () => {
    const historical = { ...incident,last_seen:old };
    expect(currentProtectedIncidents([historical],[finding],[asset],"10.77.0.50",now))
      .toEqual([]);
    expect(currentProtectedIncidents([incident],[finding],[asset],"10.77.0.50",now))
      .toEqual([incident]);
  });
  it("does not infer a target from a generic incident entity IP", () => {
    expect(currentProtectedIncidents([
      { ...incident,affected_asset_ids:[],detector_ids:["other"] }
    ],[],[], "10.77.0.50",now)).toEqual([]);
    expect(currentProtectedFindings([finding],"10.77.0.99",now)).toEqual([]);
  });
  it("does not call an old detector log a running IDS", () => {
    const snapshot = {
      status:"RECENT_EVE",service_state:"failed"
    } as SuricataSnapshot;
    expect(idsStatus(snapshot,true)).toBe("SERVICE OFFLINE");
    expect(idsStatus({ ...snapshot,service_state:"active" },true))
      .toBe("EVE OBSERVED");
    expect(idsStatus(snapshot,false)).toBe("API UNAVAILABLE");
  });
});
