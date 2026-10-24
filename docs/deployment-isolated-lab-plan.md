# MON deployment planning and isolated-lab certification plan

## Status

Planned deployment phase. This phase is intentionally **not a feature-development phase**.

Baseline source commit:

`5c7ae457393bf1f69beb885113634867436688c8`

The lab must consume release-candidate artifacts produced from that exact source commit and must preserve the existing manifest/SBOM/provenance verification chain.

## Objective

Move MON from repository-controlled CI evidence into disposable, production-shaped infrastructure without making production claims that the evidence does not support.

The phase has five goals:

1. verify the exact release artifacts outside GitHub-hosted CI;
2. exercise MON across real VM network boundaries rather than loopback-only test boundaries;
3. close the highest-value PARTIALLY_PROVEN gaps with isolated lab evidence;
4. establish deployment, rollback, backup, recovery, and evidence-collection runbooks;
5. define evidence-based gates for a later internal pilot.

No customer network, production endpoint, user workstation, or critical asset is an acceptable first target.

## Hard rules

- No feature work is planned in this phase.
- If lab testing exposes a product defect, stop the affected stage, preserve evidence, open a defect, fix it on a separate branch/PR, rerun repository gates, then rerun the failed lab stage from a clean VM snapshot.
- Never weaken a release gate to make a lab test pass.
- Never fabricate telemetry, health, packet-drop evidence, recovery state, or confidence.
- Every destructive or containment test must have a defined rollback and a bounded target.
- Critical-system automatic isolation is out of scope.
- Unsigned Windows MSI and Linux .deb artifacts are acceptable only in the isolated lab. They are not a production trust claim.
- Lab attack traffic must remain inside the isolated virtual network.

## Lab topology

Use three virtual networks.

### 1. Management network

Host-only administrative network for SSH/RDP and artifact transfer.

It may have temporary outbound NAT while base operating systems and packages are installed. Disable or disconnect that egress during security scenarios.

MON application traffic must not rely on this network.

### 2. SaaS-side network

Example: `10.70.0.0/24`.

Hosts:

- `cp-1`: MON control plane plus PostgreSQL for the first pass.
- `cp-2`: optional second control-plane instance for the HA stage.
- optional reverse proxy for the HA stage.

### 3. Site-side network

Example: `10.80.0.0/24`.

Hosts:

- `site-1`: MON Site Controller and sensor ingress.
- `sensor-1`: Zeek and Suricata source/collector host.
- `linux-1`: disposable Ubuntu endpoint.
- `win-1`: disposable Windows endpoint.
- `traffic-1`: bounded test-traffic and fault-generation host.

Place a disposable Linux router VM between the SaaS and site networks. Do not configure internet forwarding. Use this VM only to create controlled WAN-like outage, latency, loss, and reconnect conditions.

The Site Controller loopback API remains loopback-only. Remote sensors use `mon-sensor-ingress` with mTLS.

## First-pass operating systems

Prefer environments already represented in repository evidence before broadening the matrix:

- Ubuntu 24.04-class Linux for control plane, Site Controller, sensor, router, traffic generator, and Linux endpoint.
- Windows Server 2025 for the first Windows endpoint pass because that matches the current GitHub runner certification environment.

Later matrix expansion can add Windows client versions, other Ubuntu kernels, Debian-family variants, firewalld, ufw, and other firewall-management combinations.

## Suggested lab capacity

Preferred single-host capacity:

- 8-12 logical CPU cores;
- 32 GB RAM;
- approximately 180 GB free SSD storage.

A smaller host can run the same plan sequentially by powering off nodes not needed for the current stage. Do not collapse security boundaries merely to make the topology appear complete.

## Immutable release input

The lab starts from the release-candidate evidence bundle generated from the baseline source SHA.

Before installation:

1. verify the release manifest;
2. verify the expected source SHA;
3. verify GitHub provenance attestations;
4. verify required artifact hashes and exact artifact set;
5. retain the SBOMs;
6. record the artifact verification output in the lab evidence bundle.

Expected packaged endpoint artifacts currently include:

- `windows/MONWindows-0.1.0.msi`;
- `linux/mon-linux-endpoint-collector_0.1.0_amd64.deb`.

The packages are currently unsigned. Record that fact explicitly.

## Certification stages

### L0 — VM and network isolation proof

Prove:

- lab networks have no route to production networks;
- attack/test traffic cannot leave the isolated data networks;
- management/NAT egress can be disconnected without breaking the lab topology;
- snapshots exist before destructive tests.

Evidence:

- virtual-network configuration;
- routing tables;
- connectivity matrix;
- clean snapshots.

Exit criterion: no unintended external path exists.

### L1 — Release-chain verification

Verify exact release-candidate bytes, manifest, SBOMs, provenance, and source SHA before installation.

Exit criterion: all verification succeeds with no substituted or rebuilt artifact.

### L2 — Package installation and service lifecycle

Install the exact MSI and .deb on disposable endpoints.

Exercise:

- install;
- start/status/stop;
- restart;
- state-directory creation and permissions;
- upgrade;
- rollback using the documented package procedure;
- uninstall/remove;
- state preservation where promised.

Exit criterion: lifecycle behavior matches repository claims and no secret is embedded in package configuration.

### L3 — Identity, PKI, and enrollment

Create disposable lab CAs and scoped identities.

Exercise:

- control-plane JWT/JWKS validation;
- Site Controller mTLS;
- correct tenant/site certificate scope;
- wrong CA rejection;
- wrong scope rejection;
- missing client certificate rejection;
- sensor one-time enrollment;
- sensor heartbeat;
- sensor certificate renewal;
- sensor revocation and trust-snapshot synchronization.

Exit criterion: valid identities work, invalid identities fail closed, and revocation behavior matches the documented offline trust model.

### L4 — Normal telemetry path

Feed real lab-generated telemetry through:

- Zeek JSON collector;
- Suricata EVE collector;
- Windows Event Log collector;
- Linux endpoint collector.

Prove the path:

sensor/endpoint -> Site Controller -> local evidence pipeline -> durable fabric outbox -> mTLS ingress -> Control Plane -> incident/evidence/operator views.

Do not seed a healthy state that bypasses the real collection path.

Exit criterion: telemetry is attributable to the correct tenant/site/sensor/asset and evidence survives restart.

### L5 — Detection and correlation

Use bounded, controlled scenarios such as:

- repeated failed authentication;
- small reconnaissance scan inside the lab;
- known Suricata test signature traffic;
- process execution plus related network activity;
- east-west connection changes.

For each finding/incident record:

- source evidence;
- confidence;
- involved asset/identity;
- timestamps;
- attack/investigation graph relationships;
- tenant/site scope.

Exit criterion: conclusions never exceed the evidence.

### L6 — Real packet-flow containment and rollback

This is a priority gap because current repository certification proves rule state more strongly than packet flow.

Linux endpoint:

- enable the host nftables adapter only on the disposable endpoint;
- establish a known-good connection;
- apply `BLOCK_IP` against a lab-only peer;
- independently verify packet flow is blocked;
- verify unrelated nftables state is unchanged;
- rollback;
- independently verify reachability returns;
- repeat apply/rollback to verify idempotency;
- reboot/restart tests must record the documented non-persistence behavior rather than hiding it.

Windows endpoint:

- repeat the same pattern with Windows Defender Firewall;
- verify the MON-owned rule group;
- independently test packet flow before/after apply and rollback;
- verify unrelated rules and profiles are unchanged;
- test service restart/reboot behavior and record actual persistence.

Exit criterion: containment blocks only the intended lab flow, rollback restores it, and unrelated firewall state is preserved.

### L7 — Firewall coexistence matrix

Run separate clean-snapshot cases for:

- native nftables only;
- nftables with iptables-nft coexistence;
- ufw present;
- firewalld present;
- Windows Defender Firewall without Group Policy;
- where feasible, a controlled Group Policy-managed Windows lab case.

A failure here does not justify mutating foreign firewall rules. Record incompatibility and stop.

Exit criterion: supported combinations are based on observed evidence, not assumption.

### L8 — SaaS outage and local autonomy

Disconnect the Site Controller from the SaaS-side network while keeping the site network alive.

Prove:

- local telemetry ingestion continues;
- local evidence processing continues;
- fabric outbox grows durably;
- health reports degraded/offline cloud delivery rather than healthy;
- already-authorized local response state can perform documented TTL recovery;
- the last synchronized sensor trust snapshot remains effective;
- a revocation created while disconnected does not falsely appear active locally;
- reconnection replays queued telemetry without duplicate logical events.

Exit criterion: local protection degrades honestly and recovers without data corruption.

### L9 — Crash, restart, and reconciliation

Inject process failures into:

- Site Controller;
- control plane;
- endpoint collector;
- sensor collector.

Verify durable queues, cursors, response receipts, response updates, and analysis state.

For Windows, explicitly record that automatic collector service crash recovery is not currently configured.

Exit criterion: restart behavior matches documented guarantees and limitations.

### L10 — Backup and restore

Control plane:

- create a PostgreSQL logical backup;
- restore into a fresh database;
- run the repository verification tool;
- start a fresh control-plane instance against the restored database and perform functional reads.

Site Controller:

- quiesce the service;
- create a seven-database snapshot;
- verify the archive;
- restore into a fresh state directory;
- restart against restored state;
- prove queued delivery/reconciliation continues.

Exit criterion: restored services work, not merely that files can be unpacked.

### L11 — Tenant/site isolation in a deployed topology

Create at least two tenants and two sites.

Attempt:

- cross-tenant reads;
- wrong-site certificate use;
- cross-scope event relabeling;
- response reuse across scopes;
- sensor-state reuse under a different identity.

Exit criterion: every cross-scope attempt fails closed and no record appears under the wrong tenant/site.

### L12 — Control-plane HA and WAN impairment

Add `cp-2` and a reverse proxy.

Exercise:

- one control-plane process loss;
- rejoin;
- duplicate/raced ingest;
- duplicate/raced response request;
- bounded WAN latency;
- bounded packet loss;
- temporary ingress outage;
- reconnect.

Record the existing known limitation: detector/correlation windows are per-process memory and burst detection can under-detect when traffic is split between instances.

Exit criterion: state remains consistent and any detector limitation is visible in the evidence.

### L13 — Load/resource baseline

Run bounded load tests in the VM lab.

Measure:

- ingest throughput;
- latency percentiles;
- CPU;
- RAM;
- disk growth;
- outbox growth under outage;
- restart/warm-restore duration.

This stage establishes a lab baseline only. It does not create a production SLO or capacity claim.

Exit criterion: no unbounded growth, crash loop, silent loss, or false healthy state under the tested envelope.

### L14 — Operator workflow

From the operator console, complete one full case:

DISCOVER -> DETECT -> CORRELATE -> TRACE -> CONTAIN -> VERIFY -> RECOVER.

The operator must be able to trace each conclusion to evidence and each response to policy/audit/rollback state.

Exit criterion: no step relies on a hidden test shortcut.

### L15 — Teardown and residue check

Rollback all active containment.

Verify:

- no MON test firewall rules remain;
- no test certificates or tokens remain on reusable hosts;
- test tenants/sites can be removed or archived as intended;
- evidence artifacts are retained separately;
- VM snapshots are either reset or destroyed.

Exit criterion: the environment returns to a known clean state.

## Evidence bundle

Each lab run should produce a timestamped evidence bundle containing:

- source SHA and release artifact hashes;
- release verification output;
- VM/OS/kernel/firewall versions;
- network topology and routing proof;
- test-case result matrix;
- MON audit records;
- relevant MON runtime diagnostics;
- packet-flow verification results;
- resource measurements;
- backup/restore verification output;
- containment and rollback evidence;
- known limitations and deviations;
- final residue/cleanup report.

Do not place private keys, bearer tokens, connector secrets, or raw secret material in this bundle.

## Severity and stop conditions

Immediately stop the affected stage for:

- tenant/site data crossover;
- containment affecting an unintended host or address;
- rollback failure;
- silent event loss;
- false healthy state during a known outage;
- secret disclosure;
- corrupted durable state;
- an unbounded process/resource failure;
- artifact/provenance mismatch.

A CRITICAL or HIGH defect blocks progression beyond the failed stage.

## Lab completion gate

The isolated-lab phase is complete only when:

- release artifacts verify from the immutable source SHA;
- package lifecycle succeeds on disposable VMs;
- real telemetry reaches incidents/evidence without seeded shortcuts;
- Linux and Windows containment are verified by packet flow, not only rule state;
- rollback restores connectivity and preserves unrelated firewall state;
- SaaS outage/reconnect and local autonomy are proven;
- restart/reconciliation succeeds;
- backup/restore produces functioning services;
- tenant/site isolation passes in the deployed topology;
- no unresolved CRITICAL/HIGH defect remains;
- all limitations are documented honestly.

## Deployment progression after the lab

Passing the lab does **not** imply general production readiness.

Recommended progression:

### D0 — Lab only

Current phase.

### D1 — Internal observe-only pilot

One non-critical internal site.

- detection and telemetry enabled;
- response planning visible;
- automatic containment disabled;
- operator validates incident/evidence quality.

### D2 — Internal manual-containment pilot

Allow endpoint containment only on explicitly designated disposable/non-critical endpoints.

Requirements:

- human approval;
- short TTL;
- verified rollback;
- blast-radius estimate;
- evidence and audit record;
- emergency disable procedure.

### D3 — Limited production pilot

Only after operational blockers such as package signing, identity-provider integration, support runbooks, monitored backups, and the relevant OS/firewall combinations are proven.

Start with one site and a narrow asset allowlist. Critical assets stay manual/observe-only until sufficient site-specific evidence exists.

### D4 — Broader rollout

Expand only by an explicit compatibility matrix, measured capacity envelope, rollback rehearsal, and connector-specific certification.

Enterprise firewall/NAC/cloud/upstream DDoS enforcement remains unavailable until those adapters and their real infrastructure are independently validated.

## Current production blockers that the lab does not magically remove

The current readiness ledger still identifies important non-proven areas, including:

- production code signing;
- broad Linux distro/kernel coverage;
- broad Windows version coverage;
- PostgreSQL automatic failover;
- multi-region disaster recovery;
- enterprise firewall/NAC appliances;
- cloud-provider enforcement;
- upstream ISP/DDoS mitigation;
- real customer production-network operation.

These are separate deployment workstreams, not reasons to weaken the isolated-lab gate.
