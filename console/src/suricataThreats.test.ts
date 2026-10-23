import { describe, expect, it } from "vitest";
import { newSuricataThreats } from "./suricataThreats";
import type { SuricataSnapshot } from "./types";

const now = Date.parse("2026-10-23T10:00:30Z");
const target = "10.77.0.50";
const snapshot: SuricataSnapshot = {
  source: "suricata-eve", status: "RECENT_EVE", service_state: "active",
  observed_events: 1, alerts: 1, last_seen: "2026-10-23T10:00:00Z",
  records: [{
    event_type: "alert", timestamp: "2026-10-23T10:00:00Z",
    src_ip: "10.77.0.60", src_port: 45678,
    dst_ip: target, dst_port: 8085, protocol: "TCP",
    application: "http", community_id: "1:test",
    signature: "MON LAB HTTP probe", severity: 2, category: "Web attack"
  }]
};
const pick = (
  next: SuricataSnapshot,
  seen = new Set<string>(),
  baseline = true,
  ip: string | null = target
) => newSuricataThreats(next, seen, baseline, ip, now);

describe("Suricata popup evidence gating", () => {
  it("does not replay historical alerts when a new session connects", () => {
    const seen = new Set<string>();
    expect(pick(snapshot, seen, false)).toHaveLength(0);
    expect(pick(snapshot, seen)).toHaveLength(0);
  });
  it("detects a new real signature for PC5, once only", () => {
    const seen = new Set<string>();
    expect(pick(snapshot, seen)).toMatchObject([{
      severity: "HIGH", source: "10.77.0.60", target,
      attackClass: "Web attack"
    }]);
    expect(pick(snapshot, seen)).toHaveLength(0);
  });
  it("rejects the wrong target and unconfigured capture", () => {
    expect(pick(snapshot, new Set(), true, "10.77.0.49")).toHaveLength(0);
    expect(pick(snapshot, new Set(), true, null)).toHaveLength(0);
  });
  it("rejects stopped Suricata regardless of EVE contents", () => {
    expect(pick({ ...snapshot, service_state: "failed" })).toHaveLength(0);
    expect(pick({ ...snapshot, service_state: "unknown" })).toHaveLength(0);
  });
  it("rejects stale timestamp and ambient flow traffic", () => {
    expect(pick({ ...snapshot, records: [{
      ...snapshot.records[0], timestamp: "2026-10-11T10:00:00Z"
    }] })).toHaveLength(0);
    expect(pick({ ...snapshot, records: [{
      ...snapshot.records[0], event_type: "flow"
    }] })).toHaveLength(0);
  });
  it("requires explicit rule priority and recent EVE status", () => {
    expect(pick({ ...snapshot, records: [{
      ...snapshot.records[0], severity: undefined
    }] })).toHaveLength(0);
    expect(pick({ ...snapshot, status: "NO_RECENT_EVENTS" })).toHaveLength(0);
  });
});
