export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface EvidenceRef {
  evidence_id: string;
  evidence_class: string;
  source: string;
  summary: string;
  confidence: number;
  observed_at: string;
}

export interface Asset {
  asset_id: string;
  tenant_id: string;
  site_id: string;
  display_name: string;
  criticality: string;
  ip_addresses: string[];
  mac_addresses: string[];
  hostnames: string[];
  vendor?: string;
  observed_tcp_services: number[];
  peer_counts: Record<string, number>;
  protocol_counts: Record<string, number>;
  identity_evidence: string[];
  measured_packets?: number;
  measured_bytes?: number;
  first_seen: string;
  last_seen: string;
}

export interface TelemetrySnapshot {
  tenant_id: string;
  site_id: string;
  window_seconds: number;
  observed_at: string;
  observation_count: number;
  measurement_span_seconds?: number;
  events_per_second?: number;
  measured_packets?: number;
  measured_bytes?: number;
  measured_packets_per_second?: number;
  measured_bytes_per_second?: number;
  unique_src_ips: number;
  unique_dst_ips: number;
  protocol_counts: Record<string, number>;
  source_counts: Record<string, number>;
}

export interface Incident {
  incident_id: string;
  tenant_id: string;
  site_id: string;
  title: string;
  severity: Severity;
  status: string;
  confidence: number;
  affected_asset_ids: string[];
  detector_ids: string[];
  entities: string[];
  last_seen: string;
}

export interface Finding {
  finding_id: string;
  detector_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  src_ip?: string;
  dst_ip?: string;
  asset_id?: string;
  last_seen: string;
}

export interface GraphNode {
  node_id: string;
  kind: string;
  label: string;
}

export interface GraphEdge {
  edge_id: string;
  src_node_id: string;
  dst_node_id: string;
  relation: string;
  protocol?: string;
  dst_port?: number;
  event_count: number;
  detector_ids: string[];
}

export interface GraphSnapshot {
  tenant_id: string;
  site_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface LiveSnapshot {
  tenant_id: string;
  site_id: string;
  sequence: number;
  findings: Finding[];
  incidents: Incident[];
  assets: Asset[];
  telemetry: TelemetrySnapshot;
  graph: GraphSnapshot;
}

export interface LiveEnvelope {
  kind: string;
  tenant_id: string;
  site_id: string;
  sequence: number;
  emitted_at: string;
  payload: Record<string, unknown>;
}
