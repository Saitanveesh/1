import { useEffect, useMemo, useState } from "react";
import { fetchTopology } from "./api";
import type { TopologyLayer, TopologyNode, TopologySnapshot } from "./types";
import "./network-map.css";

const MAX_DRAWN_NODES = 160;
type Coordinate = { x: number; y: number };

function positionsFor(nodes: TopologyNode[], rootId: string): Map<string, Coordinate> {
  const result = new Map<string, Coordinate>();
  if (!rootId) {
    // Presentation layout only. Grid placement does NOT imply cable distance.
    nodes.forEach((node, i) => {
      result.set(node.node_id, { x: 60 + (i % 15) * 62, y: 55 + Math.floor(i / 15) * 43 });
    });
    return result;
  }

  const known = nodes.filter((n) => n.distance_hops !== null);
  const unknown = nodes.filter((n) => n.distance_hops === null);
  const byDepth = new Map<number, TopologyNode[]>();
  for (const node of known) {
    const depth = node.distance_hops ?? 0;
    byDepth.set(depth, [...(byDepth.get(depth) ?? []), node]);
  }
  for (const [depth, peers] of byDepth) {
    peers.forEach((node, i) => {
      if (depth === 0) {
        result.set(node.node_id, { x: 385, y: 265 });
        return;
      }
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / peers.length;
      const radius = Math.min(215, 60 + depth * 45);
      result.set(node.node_id, {
        x: 385 + Math.cos(angle) * radius,
        y: 265 + Math.sin(angle) * radius
      });
    });
  }
  // Unknown depth is segregated from the rooted subgraph, never assigned a hop.
  unknown.forEach((node, i) => {
    result.set(node.node_id, { x: 705 + (i % 5) * 51, y: 42 + Math.floor(i / 5) * 42 });
  });
  return result;
}

export default function NetworkMap({
  tenantId,
  siteId,
  sequence
}: {
  tenantId: string;
  siteId: string;
  sequence: number;
}) {
  const [snapshot, setSnapshot] = useState<TopologySnapshot | null>(null);
  const [root, setRoot] = useState("");
  const [layer, setLayer] = useState<TopologyLayer>("L2");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");
  const [lastLoad, setLastLoad] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const graph = await fetchTopology(tenantId, siteId, root || undefined);
        if (cancelled) return;
        setSnapshot(graph);
        setLastLoad(new Date().toISOString());
        setError("");
      } catch (cause) {
        if (!cancelled) setError(cause instanceof Error ? cause.message : "Topology unavailable");
      }
    };
    void load();
    const interval = window.setInterval(() => void load(), 10000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [tenantId, siteId, root, sequence]);

  const visibleNodes = useMemo(() => {
    if (!snapshot) return [];
    const needle = search.trim().toLowerCase();
    const matching = snapshot.nodes.filter(
      (n) => !needle ||
      [n.node_id, n.label, n.node_type, ...n.ip_addresses, ...n.mac_addresses]
        .some((value) => value.toLowerCase().includes(needle))
    );
    return matching.slice(0, MAX_DRAWN_NODES);
  }, [snapshot, search]);
  const coords = useMemo(() => positionsFor(visibleNodes, root), [visibleNodes, root]);
  const selectedNode = snapshot?.nodes.find((n) => n.node_id === selected);
  const ids = new Set(visibleNodes.map((n) => n.node_id));
  const visibleLinks = (snapshot?.links ?? []).filter(
    (link) => link.layer === layer &&
      ids.has(link.source_id) && ids.has(link.target_id)
  );
  const matchingCount = snapshot?.nodes.filter(
    (n) => !search.trim() ||
      [n.node_id, n.label, n.node_type, ...n.ip_addresses, ...n.mac_addresses]
        .some((value) => value.toLowerCase().includes(search.trim().toLowerCase()))
  ).length ?? 0;

  return (
    <section className="network-map panel full" data-testid="network-map">
      <div className="panel-head">
        <div>
          <span className="eyebrow">OBSERVED / NOT INVENTED</span>
          <h2>Discovered network graph</h2>
        </div>
        <div className="mono">
          {snapshot ? `${snapshot.nodes.length} observed IDs / ${snapshot.links.length} links` : "No snapshot"}
        </div>
      </div>
      <div className="network-toolbar">
        <label>
          Find device
          <input value={search} onChange={(event) => setSearch(event.target.value)}
            placeholder="IP, MAC, name or asset ID" aria-label="Find device" />
        </label>
        <label>
          Graph layer
          <select value={layer} onChange={(event) => setLayer(event.target.value as TopologyLayer)}>
            <option value="L2">Switch / neighbor</option>
            <option value="L3">Routed next hop</option>
            <option value="COMMUNICATION">Observed traffic</option>
          </select>
        </label>
        <label>
          Distance root
          <select value={root} onChange={(event) => setRoot(event.target.value)}>
            <option value="">None — distance unknown</option>
            {(snapshot?.nodes ?? []).map((n) => (
              <option key={n.node_id} value={n.node_id}>{n.label} ({n.node_id})</option>
            ))}
          </select>
        </label>
      </div>
      {error && <p className="network-warning" role="alert">Topology cannot refresh: {error}. Last result may be stale.</p>}
      {snapshot?.truncated && (
        <p className="network-warning">History query reached its 10,000-observation limit. Graph may be incomplete.</p>
      )}
      <p className="network-explain">
        Nodes are observations from authenticated ingest, not a complete census. Visual spacing is schematic.
        {root
          ? " Hop depth uses only current LLDP neighbor observations. Missing hops stay unknown."
          : " Select a verified network device as root to calculate observed LLDP hop depth."}
        {" "}Physical location is unknown unless separately verified.
      </p>
      {!snapshot || snapshot.nodes.length === 0 ? (
        <div className="empty large">
          No topology evidence ingested. MON will not invent devices or connections.
        </div>
      ) : (
        <div className="network-layout">
          <div className="network-stage">
            <svg viewBox="0 0 1000 530" role="img" aria-label="Observed network topology">
              {visibleLinks.map((link) => {
                const from = coords.get(link.source_id);
                const to = coords.get(link.target_id);
                if (!from || !to) return null;
                return (
                  <line key={`${link.source_id}:${link.target_id}:${link.relationship}`}
                    x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                    stroke={link.status === "OBSERVED" ? "#555" : "#bbb"}
                    strokeWidth={link.relationship === "LLDP_NEIGHBOR" ? 2 : 1}
                    strokeDasharray={link.relationship === "LLDP_NEIGHBOR" ? undefined : "4 4"}
                  >
                    <title>{link.relationship} · {link.status} · {link.evidence_id}</title>
                  </line>
                );
              })}
              {visibleNodes.map((node) => {
                const position = coords.get(node.node_id);
                if (!position) return null;
                const active = selected === node.node_id;
                return (
                  <g key={node.node_id} className="network-node"
                    onClick={() => setSelected(node.node_id)}
                    role="button" tabIndex={0}
                    onKeyDown={(event) => { if (event.key === "Enter") setSelected(node.node_id); }}
                    aria-label={`Inspect ${node.label}`}>
                    <circle cx={position.x} cy={position.y} r={active ? 13 : 9}
                      fill={node.status === "STALE" ? "#fff" : "#333"}
                      stroke={active ? "#000" : "#777"} strokeWidth={active ? 3 : 1.5} />
                    <text x={position.x} y={position.y + 22} textAnchor="middle" fontSize="10" fill="#333">
                      {node.label.length > 18 ? node.label.slice(0, 16) + "…" : node.label}
                    </text>
                  </g>
                );
              })}
            </svg>
            <p className="network-footnote">
              Displaying {visibleNodes.length} of {matchingCount} matching nodes.
              {" "}A partial view is not full network visibility.
            </p>
          </div>
          <aside className="network-inspector">
            <span className="eyebrow">DEVICE EVIDENCE</span>
            {selectedNode ? (
              <>
                <h2>{selectedNode.label}</h2>
                <dl>
                  <dt>ID</dt><dd>{selectedNode.node_id}</dd>
                  <dt>Type</dt><dd>{selectedNode.node_type}</dd>
                  <dt>Status</dt><dd>{selectedNode.status}</dd>
                  <dt>IP</dt><dd>{selectedNode.ip_addresses.join(", ") || "Not observed"}</dd>
                  <dt>MAC</dt><dd>{selectedNode.mac_addresses.join(", ") || "Not observed"}</dd>
                  <dt>Observed hops</dt>
                  <dd>{root && selectedNode.distance_hops !== null
                    ? selectedNode.distance_hops : "Unknown"}</dd>
                  <dt>Last seen</dt><dd>{new Date(selectedNode.last_seen).toLocaleString()}</dd>
                  <dt>Evidence IDs</dt><dd>{selectedNode.evidence_ids.join(", ")}</dd>
                  <dt>Physical location</dt><dd>Unknown / not independently verified</dd>
                </dl>
              </>
            ) : <p>Select an observed device to inspect its evidence.</p>}
            <p className="network-footnote">
              Coverage: {snapshot.coverage}. Collector placement and unobserved network segments
              must be assessed independently.
            </p>
          </aside>
        </div>
      )}
      <p className="network-footnote">Last successful refresh: {lastLoad ? new Date(lastLoad).toLocaleTimeString() : "Never"}</p>
    </section>
  );
}
