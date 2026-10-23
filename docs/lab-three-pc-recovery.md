# MON Three-PC Recovery — PC-2 Unavailable

Date: 2026-10-23. This is a **proposed new lab topology**, not a claim that it is already deployed.

## Current PCs
| Host | Wired IPv4 | Initial role |
|---|---|---|
| lab-pc7 | 10.5.115.130/20 | MON control plane, PostgreSQL, operator console |
| lab-pc6 | 10.5.113.245/20 | Site Controller, Suricata sensor, isolated victim |
| lab-pc5 | 10.5.114.47/20 | Red Team / controlled client |
| lab-pc2 | unavailable | administrative/evidence functions moved to PC-7 |

## Critical topology delta
The old seven-PC runbook used PC-3 as a WireGuard forwarding hub and PC-2 as an admin/evidence station, with PC-4 and PC-5 victims and PC-6 attacker. Its old 10.77.0.x assignments, certificates, host routing and nftables rules MUST NOT be applied verbatim on these newly assigned machines. The user has reported wg0 on PC-5 and PC-6; these preexisting interfaces might belong to a previous experiment. Do not overwrite or delete them blindly.

For an eight-hour MVP: run MON control plane on PC-7, use PC-6 for the site sensor and isolated training service, and PC-5 only as the controlled lab client. Establish an explicitly authorized virtual networking boundary before any attack workload. Moving router enforcement from old PC-3 to new PC-6 needs separate verification. Until then, report passive detection plus app-level containment rather than claiming production inline IPS.

## Git-only Phase 1: inventory and launch prerequisites

On **PC-7**, use a separate directory:
```bash
cd ~/Desktop
git clone -b lab/three-pc-recovery-20261023 https://github.com/Saitanveesh/1.git mon-3pc
cd mon-3pc
git status --short
docker --version
docker compose version
python3 --version
node --version
npm --version
ss -lnt | grep -E ':8080|:5173|:5432' || true
ip -br addr
```

On **PC-6** and **PC-5**, inspect the current network state without making changes:
```bash
hostname
ip -br addr
ip route
sudo wg show 2>/dev/null || true
docker --version
python3 --version
```

## Phase 2: initial PC-7 control-plane service
Requires working Docker Compose. The repository's `compose.yaml` contains a PostgreSQL container and a MON API control-plane container; the console is a separate React/Vite process. The default compose binds API port 8080 to all host interfaces and includes a development database password, so DO NOT start it unmodified on the shared campus LAN. Before running, revise bindings to localhost, set up non-default credentials, inspect `compose.yaml` and use a local protected console proxy. Keep the demo's synthetic presentation server (`demo/mon_cinematic`) separate; it is not real event telemetry.

## Acceptance gates
1. PC-7: PostgreSQL and MON API health endpoint reports READY.
2. PC-7: React console serves real API data, not demo JSON.
3. PC-6: isolated sensor logs produce actual normalized Suricata evidence with proper tenant/site identity.
4. PC-5: authorized bounded client traffic reaches only PC-6's designated test endpoint through verified isolation.
5. PC-7: incident references genuine sensor observations and updates live.
6. PC-6: a tested sandbox containment control demonstrably interrupts only the authorized test path; rollback restores it.
7. PC-7: action, audit trail and recovery status are observable.

Do not execute attack traffic until the isolation boundary is verified. Do not claim a passed gate without direct lab evidence.
