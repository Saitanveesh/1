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

export interface EnforcementPoint {
  enforcement_point_id: string;
  tenant_id: string;
  site_id: string;
  kind: string;
  vendor: string;
  capabilities: string[];
  health: string;
  priority: number;
  attributes: Record<string, unknown>;
}

export interface EnforcementBinding {
  binding_id: string;
  tenant_id: string;
  site_id: string;
  asset_id: string;
  enforcement_point_id: string;
  distance: number;
  priority_bias: number;
  attributes: Record<string, unknown>;
}

export interface ResponseExecution {
  execution_id: string;
  tenant_id: string;
  site_id: string;
  status: string;
  requested_at: string;
  applied_at?: string;
  expires_at?: string;
  rollback_at?: string;
  error?: string;
  plan: {
    request: {
      incident_id: string;
      action: string;
      ttl_seconds?: number;
      target: { asset_id?: string; ip_address?: string };
    };
    decision: { outcome: string; reasons: string[] };
    enforcement_point: {
      enforcement_point_id: string;
      kind: string;
      vendor: string;
    };
    blast_radius_estimate?: string;
  };
}

export interface AuditRecord {
  audit_id: string;
  actor_id: string;
  category: string;
  object_type: string;
  object_id: string;
  action: string;
  outcome: string;
  occurred_at: string;
  details: Record<string, unknown>;
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
  enforcement_points: EnforcementPoint[];
  enforcement_bindings: EnforcementBinding[];
  response_executions: ResponseExecution[];
  audit_records: AuditRecord[];
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
