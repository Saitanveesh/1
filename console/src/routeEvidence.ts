import type { PacketCaptureSnapshot, PacketEvent, PacketFlow } from "./types";
import { isRecentObservation } from "./operationalTruth";

export interface ProtectedRouteEvidence {
  configured: boolean;
  target: string | null;
  captureInterface: string;
  peer: string | null;
  events: PacketEvent[];
  flows: PacketFlow[];
  observedFrames: number;
  observedBytes: number;
  icmpFrames: number;
  observedBothDirections: boolean;
  active: boolean;
  lastSeen: string | null;
}

/**
 * A protected-site view is scoped by a configured PC-5 address and the actual
 * routed/tunnel capture interface. We do not infer PC-6, fabricate a target,
 * or consider ambient PC-2 traffic evidence of a routed attack.
 */
export function selectProtectedRoute(
  capture: PacketCaptureSnapshot | null,
  windowSeconds = 90
): ProtectedRouteEvidence {
  const target = capture?.protected_host_ip || null;
  const iface = capture?.protected_capture_interface || "wg0";
  const configured = Boolean(target);
  const now = Date.parse(capture?.observed_at ?? "");
  const events = !configured || !Number.isFinite(now) ? [] :
    // Target-specific events are bounded on the backend independently of the
    // general event log, which can be crowded out by unrelated PC-2 traffic.
    (capture?.lab_route_events ?? capture?.events ?? [])
      .filter(event => event.interface === iface &&
        (event.src_ip === target || event.dst_ip === target) &&
        Number.isFinite(Date.parse(event.timestamp)) &&
        now >= Date.parse(event.timestamp) &&
        now - Date.parse(event.timestamp) <= windowSeconds * 1000)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  const flows = !configured ? [] : (capture?.flows ?? []).filter(flow =>
    flow.src_ip === target || flow.dst_ip === target);
  const firstPeer = events.find(event =>
    event.src_ip !== target || event.dst_ip !== target);
  const peer = firstPeer ?
    (firstPeer.src_ip === target ? firstPeer.dst_ip : firstPeer.src_ip) :
    null;
  const directions = new Set(events.map(event => event.direction));
  const lastSeen = events[0]?.timestamp ?? null;
  const observedBothDirections =
    directions.has("inbound") && directions.has("outbound");
  const samples = configured ? (capture?.protected_route_samples ?? []) : [];
  const observedFrames = samples.length
    ? samples.reduce((sum, item) => sum + item.packets, 0)
    : events.length;
  const observedBytes = samples.length
    ? samples.reduce((sum, item) => sum + item.bytes, 0)
    : events.reduce((sum, item) => sum + item.ip_bytes, 0);
  const icmpFrames = samples.length
    ? samples.reduce((sum, item) => sum + item.icmp_packets, 0)
    : events.filter(event =>
      event.protocol === "ICMP" || event.protocol === "ICMPv6").length;
  return {
    configured, target, captureInterface: iface, peer, events, flows,
    // AF_PACKET may see forwarded packets twice; counts are frame
    // observations, not deduplicated end-to-end packets. Use the full
    // per-second counters instead of the bounded event-table sample.
    observedFrames, observedBytes, icmpFrames,
    observedBothDirections,
    active: capture?.status === "CAPTURING" &&
      capture.protected_route_check === "MATCHES_CAPTURE_INTERFACE" &&
      isRecentObservation(capture.observed_at, Date.now(), 12_000) &&
      (samples.length
        ? samples.slice(-5).some(item => item.packets > 0)
        : events.some(event => now - Date.parse(event.timestamp) <= 5000)),
    lastSeen
  };
}
