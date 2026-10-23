# Three-host MON: resilience and evidence acceptance

**Status:** Implemented in PR #90; disposable-VM and physical-site acceptance are still outstanding. Passing unit/CI checks alone is not operational proof.

## Why this demonstrates engineering rather than a simulation

The standard MON Linux endpoint collector handles Linux event and authentication telemetry, not CPU/RAM/disk exhaustion findings. MON's real security demonstration must use observed Suricata network events, endpoint evidence, incident correlation, an operator-approved TTL-bound containment, packet-level validation and rollback. The separate local resource-pressure harness measures a host's physical-resource response inside a disposable VM. It does **not** fabricate MON findings or claim RAM/disk pressure is an attack detected by MON.

## Automation implemented in the repo

The orchestrator tools/lab_three_host.py supports one independently verified stage at a time. On PC2 (operator machine, reached through Tailscale):

```bash
cd ~/mon-three-operator
git fetch origin feat/three-host-tailscale-lab
git checkout --detach FETCH_HEAD
python3 tools/lab_three_host.py --inventory ~/lab-three.json doctor
```

The read-only doctor prints actual running package-manager processes and lock holders, WireGuard peer endpoints (not private keys), interfaces/routes, memory and filesystem capacity. **PC5 and PC6 have an active legacy wg0 to 10.5.115.5:51820.** This must be reconciled through a supervised, backed-up cutover before invoking the overlay stage; the implementation refuses to overwrite active wg0.

After completing the legitimate MON services and collecting real observations, run the read-only API evidence export on PC2:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --evidence-out ~/mon-three-evidence/before.json evidence
# Following the separately approved incident and rollback test, choose a NEW filename:
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --evidence-out ~/mon-three-evidence/after.json evidence
```

These reports use tenant mon-lab and site site-a, preserve observed API response bodies and UTC times, redact credential-bearing field names, and mark missing endpoints INCOMPLETE. They do not manufacture absent telemetry, incident state or recovery metrics. Do not commit these real reports to GitHub.

## Safe resource-pressure demonstration — disposable VM only

Do **not** use the entire RAM or fill the 1 TB disk of PC5's physical Ubuntu host. That may crash the host, terminate remote access, damage data or affect the college environment. A professional test instead uses a dedicated Ubuntu VM on PC5 with its own 2–4 GiB RAM, 1–2 vCPUs and a disposable 10+ GiB virtual disk, with NAT or host-only networking, a snapshot, and a local recovery console. Do not bridge the pressure-test VM to the shared campus LAN.

Inside that **VM**, obtain this PR branch, make local scratch and evidence directories, and use the unprivileged Python runner:

```bash
mkdir -p ~/mon-pressure-scratch ~/mon-pressure-evidence
git clone https://github.com/Saitanveesh/1.git ~/mon-pressure-code
cd ~/mon-pressure-code
git fetch origin feat/three-host-tailscale-lab
git checkout --detach FETCH_HEAD

python3 tools/lab_three_pressure.py --ack-disposable-vm \
  --mode cpu --workers 2 --duration-seconds 15 \
  --scratch-dir ~/mon-pressure-scratch \
  --report ~/mon-pressure-evidence/cpu.json

python3 tools/lab_three_pressure.py --ack-disposable-vm \
  --mode memory --memory-mib 128 --duration-seconds 15 \
  --scratch-dir ~/mon-pressure-scratch \
  --report ~/mon-pressure-evidence/memory.json

python3 tools/lab_three_pressure.py --ack-disposable-vm \
  --mode disk --disk-mib 128 --duration-seconds 15 \
  --scratch-dir ~/mon-pressure-scratch \
  --report ~/mon-pressure-evidence/disk.json
```

Safety gates are enforced in source: positive systemd-detect-virt --vm result, non-root account, explicit operator acknowledgement, 5–60 second bounded runtime, maximum two CPU workers, memory capped to the smaller of 512 MiB, 50% of available VM RAM, or 25% of VM total RAM; disk writes capped to the smaller of 512 MiB or 20% of free VM space. Workload workers are automatically stopped, and only the unique scratch file is removed. The runner samples genuine Linux /proc/stat, /proc/meminfo and filesystem usage, then records a post-run observation in a mode-0600 JSON report.

The CPU workload may saturate one or two **allocated VM vCPUs**. It cannot guarantee 100% total CPU on a multi-vCPU host; report actual observed peak instead. The RAM/disk workloads deliberately stop far short of full capacity. To demonstrate greater pressure, use a smaller VM or resource-constrained test service, not an unbounded bare-metal load.

## Pass/fail rubric for a credible live demonstration

| Gate | Evidence to retain | Explicit fail state |
| --- | --- | --- |
| Identity and route | Verified SSH identities; WireGuard peer, endpoint, recent handshake; MON sensor vantage | Unknown host, old hub, bypass route |
| Network telemetry | Real Suricata EVE flows and mTLS sensor heartbeat with UTC timestamps | Missing/stale records, synthetic data |
| Endpoint telemetry | Real Linux SSH/journald evidence and authenticated collector health | Wrong source, missing heartbeat |
| Correlation | Incident ID connecting independent observed evidence; asset/source identifiers | Empty/synthetic incident, unsupported conclusions |
| Containment | Authorization actor; TTL, blast radius, policy, enforcement point and MON-owned firewall rule | Unapproved action, off-target rule, absent rollback |
| Verification | Packet check fails during block, succeeds after rollback, management connectivity persists | No restored service or collateral damage |
| Audit | Real API response, sensor/host timestamps, execution/rollback actor and outcomes | Partial data labelled healthy |
| VM pressure | Baseline, measured peak, explicit limits, recovery sample, cleanup, report integrity | Bare-metal run, unbounded pressure, missing recovery |

For engineering rigor, compare detection latency and missed event counts under bounded test load, check service availability, and disclose unknowns and failures. The three-system lab does not establish production high availability, Windows runtime support, multi-site failover or upstream volumetric DDoS mitigation. Release qualification remains governed by the repository's CI/security/load/sandbox gates.

## Operator ownership

The operator must perform real SSH/package operations, approve any WireGuard change or test, and verify the resulting data. Scripts cannot run autonomously from this chat. Never run isolation or test traffic automatically against the college LAN; no wide scans or network floods are part of this harness.
