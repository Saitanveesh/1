# MON Security Fabric

MON is a critical-network detection, investigation, containment, recovery, and multi-tenant
security platform.

It is built as a distributed security fabric rather than a single-host or single-firewall
monitor. Detection, investigation, policy, enforcement, rollback, and recovery are separate
concerns connected by typed, tenant/site-scoped state.

## Product direction

MON combines:

- distributed network and endpoint telemetry;
- asset and identity graphing;
- signature, behavioral, statistical, and correlation detection;
- attack-path reconstruction;
- policy-driven response decisions;
- multi-point enforcement;
- containment rollback and recovery;
- a multi-tenant SaaS control plane with locally autonomous site controllers.

There is no single perimeter device that defines trust. Enforcement may occur at an endpoint,
switch/NAC, network firewall/router, cloud control, WAF, or upstream mitigation point,
depending on evidence and the enforcement graph.

## Current implementation status

MON is an active production-foundation implementation, not a finished production release.

Implemented foundations include:

- typed tenant/site-scoped domain models and APIs;
- PostgreSQL control-plane persistence and migrations;
- forced PostgreSQL tenant/site row-level security under a non-bypass runtime role;
- AES-256-GCM connector-secret vault with external keyring and reference-only credentials;
- RBAC/authentication boundaries and site enrollment identities;
- rotatable RS256 JWKS trust sets with fail-closed hot reload;
- mTLS site ingress;
- durable at-least-once site command delivery and result receipts;
- durable site response state, audit, TTL recovery, and autonomous recovery reporting;
- append-only SHA-256-sealed audit records with PostgreSQL mutation guards;
- execution-plane dispatch between site-local and control-plane enforcement;
- evidence-based reconciliation of crash-interrupted enforcement;
- late response-state convergence after site command expiry;
- disposable Linux network-namespace/nftables enforcement validation;
- a typed enforcement-adapter capability/certification contract (declared capabilities,
  verify/rollback/reconcile support, idempotency, credential requirement, execution plane)
  integrated into response planning, plus a reusable adapter certification harness;
- a Linux endpoint nftables BLOCK_IP enforcement adapter candidate, MON-table-owned and
  certified only in disposable network namespaces so far;
- local event buffering and a production site-controller service composition;
- Zeek JSON and Suricata EVE normalization into scoped, deterministic MON evidence;
- mTLS-authenticated sensor ingress plus durable Zeek/Suricata file collectors;
- managed sensor enrollment, renewal/revocation, durable site trust, and fleet heartbeats;
- crash-safe managed sensor credential generations with proactive certificate rotation;
- typed tenant/site event-fabric envelopes with durable local consumer idempotency;
- durable exact-envelope producer outbox with ordered retry and crash reconciliation;
- verified site-mTLS fabric ingress with durable control-plane processing receipts;
- tenant/site-scoped durable local analysis checkpoints for bounded warm restore without
  deleting forensic evidence;
- STIX 2.1 indicator-bundle ingestion with tenant/site-scoped persistence and
  evidence-backed exact indicator matching for IPs, domains, URLs, and file hashes;
- TAXII 2.1 read-only feed synchronization with vault-backed credentials, bounded HTTP
  behavior, pagination, added_after cursors, retry/backoff state, and tenant/site RLS;
- typed endpoint process/auth/process-network telemetry normalization with durable
  tenant/site-scoped identity and process analysis state;
- first Windows Event Log endpoint collector adapter with deterministic event IDs,
  durable cursoring, bounded local buffering into the existing endpoint pipeline, and a
  service-oriented foreground/runtime loop boundary;
- a Linux endpoint collector adapter (systemd journal sshd auth evidence, Linux audit
  execve process-execution evidence) into the same endpoint pipeline, with deterministic
  event IDs, durable per-source cursoring, bounded local buffering, a cancellation-aware
  systemd-managed foreground runtime, and a repository-owned example systemd unit;
- identity/process attack-graph relationships for authentication, execution,
  parent/child process, and process-network evidence;
- opt-in event-fabric load/soak evidence CLI for caller-supplied canonical envelope
  corpora and disposable performance environments;
- deterministic event-fabric failure-injection and recovery regression coverage for
  the current durable outbox, idempotent ingress, and exact-envelope replay path;
- durable event-fabric exponential retry/backoff with persisted next retry times,
  bounded jitter, restart-stable attempts, and sanitized delivery errors;
- deterministic release manifests plus a controlled release-candidate workflow that builds
  current Python/console artifacts and the unsigned Windows collector executable, generates
  validated CycloneDX SBOM evidence, gates that evidence, verifies the final manifest,
  creates keyless GitHub provenance attestations for final candidate artifacts, and verifies
  those attestations before artifact upload;
- network detection, correlation, asset enrichment, attack/investigation graph foundations;
- push/live operator updates and a React operator console foundation;
- PostgreSQL, Python, container, console, and disposable Linux enforcement CI gates.

Known boundaries are reported explicitly rather than hidden. Local evidence objects
(events, assets, findings, and incidents) are durable; detector/correlation/graph windows are
warm-restored after restart from integrity-checked analysis checkpoints plus post-boundary
event replay; and one event plus its derived durable state is committed as an atomic local
analysis unit before the event becomes cloud-deliverable. Local forensic history is not
silently pruned by checkpoint maintenance. The nftables adapter in this repository remains
disposable-sandbox-only rather than a production host firewall connector. The newer Linux
endpoint nftables adapter (`LinuxNftablesEndpointAdapter`, BLOCK_IP only) is a separate,
MON-table-owned candidate that is likewise certified only in disposable network namespaces so
far; it is not yet certified on arbitrary production hosts, does not integrate with or certify
against firewalld/ufw/vendor firewall tooling, and no network appliance/NAC/cloud connector is
production-certified yet. Disposable-namespace success does not prove every Linux distribution
or kernel behaves identically. Threat-intelligence
support currently covers direct STIX bundle ingestion and exact indicator matching; TAXII
feed synchronization is read-only and client-side. MON does not yet implement a TAXII server,
TAXII write/publish APIs, or complex STIX pattern evaluation. Endpoint support currently
normalizes typed endpoint telemetry into the pipeline and graph and includes a narrow Windows
Event Log collector adapter for Security 4624/4625/4688 plus optional Sysmon
process/process-network records when present. The Windows collector now has a bounded
foreground/service runtime loop and a real SCM service-host lifecycle validated on
`windows-latest` with temporary service registration/start/query/stop/delete. A repository-owned
PowerShell wrapper now provides deterministic install/start/status/stop/uninstall commands for
an already-built `MONWindows.exe`. A separate Linux endpoint collector (`mon-linux-endpoint-collector`)
now normalizes systemd journal sshd authentication evidence and Linux audit execve process
evidence into the same endpoint pipeline, with a bounded systemd-managed foreground runtime,
graceful SIGINT/SIGTERM shutdown, and a repository-owned example systemd unit; it does not yet
implement rotation-safe audit log tracking, an eBPF/kernel collector, or DEB/RPM packaging, and
does not guarantee process-network association unless a native source explicitly supplies it.
Neither collector is yet a production-complete Windows or Linux EDR agent, and neither provides
Authenticode/package signing, MSI/DEB/RPM packaging, install/uninstall certification,
upgrade/rollback certification, privileged service-registration certification outside disposable
CI, or tamper protection. Load/soak
measurements are deployment-specific evidence, not universal performance, resilience, or
tenant-isolation proof. Event-fabric recovery validation currently covers deterministic local
outage, crash/restart, duplicate replay, and scope-isolation scenarios; it is not yet a
broker-backed HA, arbitrary network partition, multi-region failover, or disaster-recovery
proof. Release-candidate packaging now emits SBOM, manifest, and GitHub
provenance-attestation evidence for candidate bytes, but provenance does not prove
vulnerability-free software, runtime safety, correct deployment configuration, or production
readiness.

See:

- `PROJECT_INSTRUCTIONS.md` for the product and engineering charter;
- `docs/ARCHITECTURE.md` for the architecture baseline;
- `docs/adr/` for accepted architecture decisions;
- `docs/site-controller.md` for Site Controller runtime configuration.
- `docs/connector-secrets.md` for connector credential provisioning and key rotation.

No binary or deployment is considered production-ready merely because it compiles or starts.
Release claims require the repository release gates and appropriate disposable/VM validation.
