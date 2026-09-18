import { fetchSnapshot, liveWebSocketUrl } from "./api";
import type {
  Asset,
  Finding,
  Incident,
  LiveEnvelope,
  LiveSnapshot,
  TelemetrySnapshot
} from "./types";

export type ConnectionState = "CONNECTING" | "LIVE" | "RECOVERING" | "OFFLINE";

export interface LiveState extends LiveSnapshot {
  connection: ConnectionState;
  lastMessageAt?: string;
  droppedMessages: number;
}

export class LiveClient {
  private socket?: WebSocket;
  private stopped = false;
  private reconnectAttempt = 0;
  private state: LiveState;
  private readonly listeners = new Set<(state: LiveState) => void>();

  constructor(
    private readonly tenantId: string,
    private readonly siteId: string
  ) {
    this.state = {
      tenant_id: tenantId,
      site_id: siteId,
      sequence: 0,
      findings: [],
      incidents: [],
      assets: [],
      telemetry: {
        tenant_id: tenantId,
        site_id: siteId,
        window_seconds: 60,
        observed_at: new Date(0).toISOString(),
        observation_count: 0,
        unique_src_ips: 0,
        unique_dst_ips: 0,
        protocol_counts: {},
        source_counts: {}
      },
      graph: { tenant_id: tenantId, site_id: siteId, nodes: [], edges: [] },
      connection: "CONNECTING",
      droppedMessages: 0
    };
  }

  subscribe(listener: (state: LiveState) => void): () => void {
    this.listeners.add(listener);
    listener(this.state);
    return () => this.listeners.delete(listener);
  }

  async start(): Promise<void> {
    this.stopped = false;
    await this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.socket?.close();
    this.socket = undefined;
  }

  private emit(patch: Partial<LiveState>): void {
    this.state = { ...this.state, ...patch };
    for (const listener of this.listeners) listener(this.state);
  }

  private async connect(): Promise<void> {
    if (this.stopped) return;
    this.emit({ connection: this.reconnectAttempt ? "RECOVERING" : "CONNECTING" });
    const socket = new WebSocket(liveWebSocketUrl(this.tenantId, this.siteId));
    this.socket = socket;

    socket.onmessage = (event) => {
      const envelope = JSON.parse(event.data) as LiveEnvelope;
      this.apply(envelope);
    };

    socket.onopen = async () => {
      try {
        const snapshot = await fetchSnapshot(this.tenantId, this.siteId);
        this.emit({
          ...snapshot,
          connection: "LIVE",
          lastMessageAt: new Date().toISOString()
        });
        this.reconnectAttempt = 0;
      } catch {
        socket.close();
      }
    };

    socket.onclose = () => {
      if (this.stopped) return;
      this.emit({ connection: "OFFLINE" });
      this.reconnectAttempt += 1;
      const delay = Math.min(1000 * 2 ** (this.reconnectAttempt - 1), 15000);
      window.setTimeout(() => void this.connect(), delay);
    };
  }

  private apply(envelope: LiveEnvelope): void {
    if (envelope.sequence <= this.state.sequence && envelope.kind !== "stream.heartbeat") {
      return;
    }

    const common = {
      sequence: Math.max(this.state.sequence, envelope.sequence),
      lastMessageAt: envelope.emitted_at,
      connection: "LIVE" as const
    };

    if (envelope.kind === "stream.heartbeat") {
      const dropped = Number(envelope.payload.dropped_messages ?? 0);
      this.emit({ ...common, droppedMessages: dropped });
      return;
    }

    if (envelope.kind === "event.processed") {
      const result = envelope.payload.result as
        | {
            findings?: Finding[];
            incidents?: Incident[];
            asset_updates?: Asset[];
            telemetry?: TelemetrySnapshot;
          }
        | undefined;
      if (!result) {
        this.emit(common);
        return;
      }
      const findingMap = new Map(this.state.findings.map((item) => [item.finding_id, item]));
      for (const item of result.findings ?? []) findingMap.set(item.finding_id, item);
      const incidentMap = new Map(
        this.state.incidents.map((item) => [item.incident_id, item])
      );
      for (const item of result.incidents ?? []) incidentMap.set(item.incident_id, item);
      const assetMap = new Map(
        this.state.assets.map((item) => [item.asset_id, item])
      );
      for (const item of result.asset_updates ?? []) assetMap.set(item.asset_id, item);
      this.emit({
        ...common,
        findings: [...findingMap.values()],
        incidents: [...incidentMap.values()],
        assets: [...assetMap.values()],
        telemetry: result.telemetry ?? this.state.telemetry
      });
      return;
    }

    if (envelope.kind === "asset.updated") {
      const asset = envelope.payload.asset as Asset | undefined;
      if (asset) {
        const assetMap = new Map(
          this.state.assets.map((item) => [item.asset_id, item])
        );
        assetMap.set(asset.asset_id, asset);
        this.emit({ ...common, assets: [...assetMap.values()] });
        return;
      }
    }

    if (envelope.kind === "incident.updated") {
      const incident = envelope.payload.incident as Incident | undefined;
      if (incident) {
        const incidentMap = new Map(
          this.state.incidents.map((item) => [item.incident_id, item])
        );
        incidentMap.set(incident.incident_id, incident);
        this.emit({ ...common, incidents: [...incidentMap.values()] });
        return;
      }
    }

    this.emit(common);
  }
}
