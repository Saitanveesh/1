import { describe, expect, it } from "vitest";
import { newSuricataThreats } from "./suricataThreats";
import type { SuricataSnapshot } from "./types";

const snapshot: SuricataSnapshot = {
  source: "suricata-eve", status: "RECENT_EVE", observed_events: 1,
  alerts: 1, last_seen: "2026-10-23T10:00:00Z",
  records: [{
    event_type: "alert", timestamp: "2026-10-23T10:00:00Z",
    src_ip: "10.77.0.6", src_port: 45678,
    dst_ip: "10.77.0.5", dst_port: 80, protocol: "TCP",
    application: "http", community_id: "1:test",
    signature: "LAB HTTP probe", severity: 2, category: "Web attack"
  }]
};

describe("suricata threat polling", () => {
  it("does not show old events on initial connection", () => {
    const seen = new Set<string>();
    expect(newSuricataThreats(snapshot, seen, false)).toHaveLength(0);
    expect(newSuricataThreats(snapshot, seen, true)).toHaveLength(0);
  });
  it("alerts on a new observed signature once only", () => {
    const seen = new Set<string>();
    const events = newSuricataThreats(snapshot, seen, true);
    expect(events[0]).toMatchObject({
      severity: "HIGH", source: "10.77.0.6", target: "10.77.0.5",
      attackClass: "Web attack"
    });
    expect(newSuricataThreats(snapshot, seen, true)).toHaveLength(0);
  });
  it("does not treat packet flows as IDS alerts", () => {
    const seen = new Set<string>();
    const flow: SuricataSnapshot = { ...snapshot,
      records: [{ ...snapshot.records[0], event_type: "flow" }]
    };
    expect(newSuricataThreats(flow, seen, true)).toHaveLength(0);
  });
  it("requires explicit Suricata priority and sensor evidence", () => {
    const seen = new Set<string>();
    const missing = { ...snapshot, records: [{ ...snapshot.records[0], severity: undefined }] };
    expect(newSuricataThreats(missing, seen, true)).toHaveLength(0);
    const inactive = { ...snapshot, status: "NO_RECENT_EVENTS" as const };
    expect(newSuricataThreats(inactive, new Set(), true)).toHaveLength(0);
  });
});
