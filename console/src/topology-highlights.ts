import type { Finding, TopologySnapshot } from "./types";

export type FindingRole = "SOURCE" | "TARGET";

export interface TopologyFindingHighlights {
  roles: Map<string, Set<FindingRole>>;
  recentFindings: number;
  matchedEndpoints: number;
  unresolvedEndpoints: number;
}

/**
 * Highlight only recently observed addresses uniquely mapped to a graph node.
 * An IP is not a verified workstation or human identity. Never invent a route.
 */
export function matchTopologyFindings(
  snapshot: TopologySnapshot | null,
  findings: Finding[],
  nowMs: number = Date.now()
): TopologyFindingHighlights {
  const result: TopologyFindingHighlights = {
    roles: new Map(),
    recentFindings: 0,
    matchedEndpoints: 0,
    unresolvedEndpoints: 0
  };
  if (!snapshot) return result;

  const ipToNode = new Map<string, string | null>();
  for (const node of snapshot.nodes) {
    for (const ip of node.ip_addresses) {
      if (ipToNode.has(ip) && ipToNode.get(ip) !== node.node_id) {
        ipToNode.set(ip, null);
      } else if (!ipToNode.has(ip)) {
        ipToNode.set(ip, node.node_id);
      }
    }
  }

  for (const finding of findings) {
    const age = nowMs - Date.parse(finding.last_seen);
    if (!Number.isFinite(age) || age < -60_000 || age > 5 * 60_000) continue;
    result.recentFindings++;
    for (const [role, ip] of [
      ["SOURCE", finding.src_ip],
      ["TARGET", finding.dst_ip]
    ] as const) {
      if (!ip) continue;
      const nodeId = ipToNode.get(ip);
      if (!nodeId) {
        result.unresolvedEndpoints++;
        continue;
      }
      if (!result.roles.has(nodeId)) result.roles.set(nodeId, new Set());
      result.roles.get(nodeId)?.add(role);
      result.matchedEndpoints++;
    }
  }
  return result;
}
