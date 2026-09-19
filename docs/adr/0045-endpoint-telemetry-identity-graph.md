# ADR 0045: Endpoint telemetry and asset/identity graph foundation

## Status

Accepted.

## Context

MON already normalizes network and IDS telemetry into tenant/site-scoped
`SecurityEvent` records, persists forensic evidence, detects traffic shapes, correlates
findings into incidents, and builds an attack graph. The next foundation needs endpoint
process/authentication/process-network evidence without pretending MON has a production
Windows or Linux endpoint agent.

Endpoint telemetry carries identity and process semantics that are different from network
flows:

- a username alone is not a globally stable identity;
- a SID or UID with namespace is stronger evidence than a display name;
- a PID is reusable and cannot identify a process by itself;
- parent/child process and process-to-peer edges are derived analysis state, while the
  original endpoint event remains the forensic record.

## Decision

Introduce typed endpoint telemetry normalization for four event kinds:

- process start;
- authentication success;
- authentication failure;
- process network connection.

These events normalize into the existing `SecurityEvent` pipeline under endpoint-specific
categories. They carry evidence references using `ENDPOINT` or `IDENTITY` evidence
classes and reject inline credential-bearing attributes.

Add tenant/site-scoped derived records:

- `IdentityRecord`, with strong identities for source-provided Windows SIDs and Linux
  UIDs with namespace, and weak identities for username-only observations scoped to the
  asset;
- `ProcessRecord`, with strong identity when a source process GUID is present and
  observational identity when MON only has a PID scoped to asset, session, and event time.

Persist identity and process records in:

- the in-memory store used by unit tests and local development;
- the local SQLite site-analysis store used by the autonomous site controller;
- the PostgreSQL control-plane store with tenant/site row-level security.

Extend the attack graph with identity and process nodes and these relations:

- identity authenticated to asset;
- identity authentication failed to asset;
- identity executed process;
- parent process to child process;
- process on asset;
- process network connection to peer.

Add an endpoint authentication-failure pressure detector. The detector explicitly reports
authentication failure pressure only; it does not claim compromise or successful access.
Existing correlation and investigation paths then combine endpoint-derived findings with
network findings when they share the same scoped entity.

## Failure and integrity semantics

Endpoint-derived identity/process state is replayable derived analysis state. The original
`SecurityEvent` and its evidence references remain the forensic source of truth and are
not pruned by identity/process maintenance.

For the local SQLite site-analysis store, identity and process updates participate in the
same per-event transaction as the event, assets, findings, incidents, graph windows, and
processing receipt. A crash before commit leaves no processing receipt and restore refuses
to report healthy processing. A replay rebuilds identity/process state idempotently from
durable events and compatible checkpoints.

PostgreSQL identity and process tables use explicit tenant/site keys and forced RLS
policies under the existing runtime role. Unscoped raw reads see no rows, and cross-scope
writes are rejected.

## Consequences

This establishes endpoint evidence semantics and graph relationships without shipping a
production endpoint collector. Future Windows/Linux agents can emit this typed telemetry
or be adapted through source-specific normalizers.

The process and identity records are intentionally conservative. Username-only identities
remain weak and asset-scoped. PID-only processes remain observational and are not merged
across process lifetimes. Stronger merge behavior requires stronger source evidence.

The attack graph now spans network, asset, identity, process, and endpoint process-network
relationships. Investigation evidence remains evidence-backed: endpoint and identity
evidence is carried from source events and findings, while graph edges retain bounded raw
evidence references for trace reconstruction.
