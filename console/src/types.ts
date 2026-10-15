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

export interface ResponseRequestPayload {
  request_id: string;
  tenant_id: string;
  site_id: string;
  incident_id: string;
  target: { asset_id?: string; ip_address?: string };
  action: string;
  enforcement_point_id?: string;
  ttl_seconds?: number;
  reason: string;
}

export interface ResponsePlan {
  request: ResponseRequestPayload;
  decision: { outcome: string; reasons: string[] };
  enforcement_point: {
    enforcement_point_id: string;
    kind: string;
    vendor: string;
  };
  rollback_action: string;
  selection_reasons: string[];
  blast_radius_estimate?: string;
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
  approval?: { actor_id: string; reason: string };
  result?: { success: boolean; message: string };
  rollback_result?: { success: boolean; message: string };
  plan: ResponsePlan;
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

export interface OperatorPrincipal {
  subject: string;
  tenant_id: string;
  roles: string[];
  site_ids: string[];
}

export interface ContainmentCapability {
  asset_id: string;
  binding_id: string;
  enforcement_point_id: string;
  kind: string;
  vendor: string;
  health: string;
  capabilities: string[];
  distance: number;
  blast_radius_estimate?: string;
  notes: string[];
}

export interface IncidentInvestigation {
  incident: Incident;
  findings: Finding[];
  affected_assets: Asset[];
  graph: GraphSnapshot;
  containment_capabilities: ContainmentCapability[];
  evidence: EvidenceRef[];
}

export interface SensorFleetView {
  tenant_id: string;
  site_id: string;
  sensor_id: string;
  state: string;
  last_seen_at?: string;
  heartbeat_age_seconds?: number;
  stale_after_seconds: number;
  collector_kind?: string;
  version?: string;
  last_error?: string;
}

export type TopologyLayer = "L2" | "L3" | "COMMUNICATION";

export interface TopologyNode {
  node_id: string;
  node_type: string;
  label: string;
  ip_addresses: string[];
  mac_addresses: string[];
  active_ip_addresses: string[];
  active_mac_addresses: string[];
  last_seen: string;
  status: "OBSERVED" | "STALE";
  evidence_ids: string[];
  distance_hops: number | null;
}

export interface TopologyLink {
  source_id: string;
  target_id: string;
  layer: TopologyLayer;
  relationship: string;
  observed_at: string;
  status: "OBSERVED" | "STALE";
  evidence_id: string;
  sensor_id: string;
}

export interface TopologyCoverage {
  sensors_seen: number;
  active_sensors: number;
  stale_sensors: number;
  observed_nodes: number;
  stale_nodes: number;
  observed_links: number;
  stale_links: number;
  unresolved_nodes: number;
  last_observation_at: string | null;
  complete_network_visibility: boolean | null;
}

export interface TopologySnapshot {
  tenant_id: string;
  site_id: string;
  captured_at: string;
  root_node_id: string | null;
  distance_basis: string;
  coverage: string;
  coverage_details: TopologyCoverage;
  observations_considered: number;
  truncated: boolean;
  nodes: TopologyNode[];
  links: TopologyLink[];
}

export interface VictimMetric {
  status: "FRESH" | "STALE" | "UNKNOWN" | "AMBIGUOUS";
  value: number | null;
  observed_at: string | null;
  source: string;
}

export interface VictimHealthView {
  tenant_id: string;
  site_id: string;
  collected_at: string;
  telemetry_state: "AVAILABLE" | "DEGRADED" | "UNCONFIGURED";
  service_reachable: VictimMetric;
  probe_duration_seconds: VictimMetric;
  erp_process_rss_bytes: VictimMetric;
  erp_process_cpu_seconds: VictimMetric;
  host_cpu_percent: VictimMetric;
  host_ram_percent: VictimMetric;
  note: string;
}
