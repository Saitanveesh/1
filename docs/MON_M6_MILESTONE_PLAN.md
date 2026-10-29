# MON M6 — Reproducible Three-PC Lab and Bounded Many-to-Many Testing

**Status:** Implementation plan; NOT deployed to the lab.
**Baseline date:** 2026-10-28
**Owner:** MON Security Fabric engineering
**Milestone objective:** Start, verify, upgrade and recover the existing MON Security Fabric laboratory across PC-2, PC-5 and PC-7 without manual repair of the database, console, network peer configuration or application dependencies. Safely add multiple distinct synthetic attackers/victims while preserving valid MON source/target evidence.

## 0. Baseline, evidence and version integration gate

Verified from user-operated terminals:
- PC-2: WG `10.77.0.1`; existing `mon-three-postgres` running and `pg_isready` succeeding; `mon-three-lab-portal`, `mon-three-console-v2`, `mon-suricata-passive` and `mon-stage4-gate` active; local HTTP health checks pass on API/portal/console and PC-5 website.
- PC-5: independently verified from `pc-5@lab-pc5` on 2026-10-28: `systemctl is-active wg-quick@wg0 mon-training-site.service` returned `active` for both; local `curl http://10.77.0.50:8085/health` returned `{"status":"READY","training":true,"version":4}`. Stored journal durability and reboot persistence are **not yet verified**.
- PC-7: independently verified from `pc-7@lab-pc7` on 2026-10-28: `systemctl is-active wg-quick@wg0 mon-batch2-attack-console.service` returned `active` for both; local `curl http://127.0.0.1:8766/` returned **HTTP 200**. Peer-to-gateway ping also passed during recovery. Reboot persistence and cross-host remote SSH verification are **not yet verified**.
- The existing PC-2 control-plane process listens on port 8080 and passes its health endpoint. **Boot owner was resolved by a subsequent direct operator check:** PID 5787 (`uvicorn`, PPID 1), cgroup `/system.slice/mon-three-control-plane.service`. Enabled-at-boot state remains to be checked. Manual JWT token renewal was needed; authentication and readiness must be tested separately. PC-5 had a stale physical LAN WireGuard endpoint and was repaired without rekey.
- **Repository integration risk:** `main` is at `0ee941ba`; Stage-4 release is `release/mon-batch4-rc1` at `10eb488`; Batch-5 UI remains draft PR #97 (`feature/mon-batch5-plain-language-20261024`, `d65309f`) on Stage-4. The M6 documentation/helper is draft PR #99 based on `main`. There is no single verified integrated source ref containing all installed lab pieces, including PC-7's locally located `~/mon-batch2/lab/pc6-console/`.
- **Before producing images**, reconcile an integration branch with the exact tested Stage-4/Batch-5 code and import/audit PC-7's local console; do not silently build from old `main` or replace the working app with it. Record a source manifest with commit SHA, image digest, schema revision, runtime owner, expected ports and health route.

## 1. Sequenced implementation work packages

| ID | Deliverable and key decisions | Acceptance evidence | Scope/exclusions |
| --- | --- | --- | --- |
| M6.0 Inventory + recoverable backups | Capture `docker inspect` mounts/images/restart policies; verify `mon-three-control-plane.service` enablement and identify actual `mon-three-console` container role; record secrets as **paths/permissions only**; inspect PC-5/PC-7 host units, WG peer endpoints and persistent evidence paths; back up PostgreSQL, victim journal, EVE, audit and signing keys with offline restoration test. | Signed-off machine inventory; checksum/restore logs on a disposable host; recorded baseline `GET /health`, authenticated `/api/v1/me` and `/api/v1/live/snapshot`; independent PC-5 and PC-7 health. | **No** `docker rm`, `down -v`, database initialization, secret copying to repository, or firewall changes. |
| M6.1 Reliable startup on existing hosts | Introduce audited host units for the API and deterministic existing Docker container autostart; establish stable LAN endpoint discovery or reservation with a fail-closed peer health check; add the fleet coordinator (SSH with pinned host keys, narrow sudo, bounded timeouts) to `mon lab up/status`; use separate readiness states `READY`, `DEGRADED`, `UNAVAILABLE`. | From a deliberate clean reboot in disposable environments, all three powered-on PCs become healthy without ad-hoc shell repair; a missing/offline PC returns a nonzero exit and explicitly identifies it. | Does not power on computers or bypass auth; no claims about cloud/offline features without tests. |
| M6.2 Compose-based core, **staging first** | Versioned image/builds and host-specific Compose profiles/projects for PC-2 API, frontend and DB. Health checks use `depends_on: {condition: service_healthy}` but application retries and reconnect logic remain mandatory. Preserve existing PostgreSQL data/roles/RLS and secrets through a rehearsed side-by-side migration. Keep real wg0, passive Suricata, privileged scoped nftables helper **host-managed**. | CI build and disposable-VM Compose API tests, live staged port health, authenticated snapshot 200, retained row counts/checksums, continuous packet evidence and successful rollback of application image. | Do not run root `compose.yaml` with development password `mon-dev` in the physical lab. Do not expose DB on LAN. Do not bind Docker socket or add host network to untrusted workloads. |
| M6.3 Containerized victim and attack-console workloads | PC-5 synthetic version-4 sites and durable impact journal in one Compose project with unique ports; PC-7 recovered console source imported, reviewed and built as another project. Both first run alongside the original services at nonconflicting ports. Explicit health, no-new-privileges, nonroot UID, drop caps, read-only root, tmpfs scratch, bounded CPU/RAM/PIDs, read-only code/data fixtures and writable evidence volume only where needed. | Compare old/new health and synthetic responses; ledger persists across restart; console UI and bounded actor invocation work; safe revert to original host services; no real university files visible/mounted. | No automatic attacks on boot; no production targets. |
| M6.4 **True** many-to-many traceability | Start with 2 synthetic actors × 2 synthetic victims, then optionally 3×3. Design explicit *non-overlapping* routed sandbox source/destination subnets (or separate registered peers) so MON sees real originating addresses and traffic passes through an observed enforcement path; preserve actor-to-container identity map. Restrict egress to synthetic victim network, reject shared-LAN/public targets, cap to <=1 HTTP request/second/actor and low global concurrency. Validate IP attribution before enabling multi-actor UI. | For each source→victim pair: routed packet observed, real IDS evidence (where matching signatures exist), tenant/site tagging, source identity, target, timestamps, and non-fabricated incident link. One approved short-TTL block affects only the selected source/target path; other allowed pairs still reach their target; rollback verified. | Current Stage-4 gate supports only 10.77.0.60/.70 to 10.77.0.50:8085, so general enforcement is **new implementation with policy/test gates**. No SYN/UDP floods or volumetric DDoS on shared college LAN. |
| M6.5 Safe upgrades, observability and documentation | `mon lab test/backup/upgrade/rollback` with pinned image digests, signed/recorded release manifest, preflight + maintenance window + consistent backups, dry-run before mutable operations, staged test and atomic/app-specific rollback. Separate schema/data migration procedures; do not promise automatic down-migration. Implement fleet views for actual CPU/RAM, container/service health, data freshness, routing and IDS state. | CI release gates and live acceptance below; console never paints unknown/stale as healthy; operator can reproduce results from a fresh workstation. | No broad `docker compose down` without explicit scope; never delete audit/evidence on rollback. |

## 2. Proposed machine-owned interfaces

| Host | Host-managed boundaries | Compose workloads (after staged cutover) | Observed targets |
| --- | --- | --- | --- |
| PC-2 — 10.77.0.1 | `wg-quick@wg0`, verified nftables helper and passive network sensor, least-privileged SSH coordinator | PostgreSQL; API; MON console; optional scoped observability | API loopback:8080; portal loopback:8088; UI :5174; real packet capture + stage4 audit |
| PC-5 — 10.77.0.50 | WireGuard, optional endpoint sensor and host firewall guard | Fictional college site v4, additional synthetic targets, isolated evidence volume | Health at legacy :8085 and nonconflicting staging ports |
| PC-7 — 10.77.0.70 | WireGuard and host egress guard | Recovered existing attacker console (legacy loopback :8766), isolated **bounded** actor services | Explicit synthetic destinations only |

**IMPORTANT:** Docker default bridge egress typically source-NATs to the host, so `10.77.0.70` may mask all actor containers. Two services on the same Docker host may exchange traffic without crossing PC-2's WireGuard capture. Do not count containers as independent traceable attackers until packet/route/enforcement tests pass. A routed sandbox subnet requires careful host routes, WireGuard `AllowedIPs`, forwarding policy, Docker firewall integration and a disposable namespace/VM proof before a live change.

## 3. End-to-end acceptance / stop-the-line checklist

All are mandatory before replacing the current laboratory:
1. Three-machine fleet status checks units/services, health endpoints, EVE freshness, DB read/write transaction, authenticated API and credential-expiry behavior; offline peers are reported `UNAVAILABLE`, never `READY`.
2. Restart PC-2 while PC-5/PC-7 remain on; restart PC-5; restart PC-7; and restart Docker daemon in a disposable replica. Each has documented recovery without overwriting an existing volume.
3. PostgreSQL recovery is verified by original records/tenant-scoped queries and a reversible *test* transaction; backup restore completed in a disposable replica. Evidence journal and audit trail survive restart and app image rollback.
4. During an unobserved training request, available disk evidence retains timestamp/source/target. Open the UI later and **distinguish** disk history from the UI's bounded live window. No evidence inference if buffers expired or sensor was offline.
5. Two-actor × two-victim topology yields unique attributable real packet paths. All target IPs are training-only. Enforcement has evidence, actor/approval, TTL, blast radius, audit, rollback and independent connectivity verification.
6. Block a fresh authorized source to only a selected victim application, check kernel presence/drop counter, confirm other path unaffected, release or expire, and independently confirm recovery. Critical assets cannot be isolated based on a weak detector.
7. Simulate API/DB failure, sensor downtime and WireGuard peer loss: fail closed on control actions, preserve local collection when possible, show gaps/unknown state, and recover after reconnect without false events.
8. Lint/type checks, unit/API/integration tests, container image scan, SBOM/image digests, CPU/RAM/PID caps, long-lived retry/crash behavior, cross-tenant isolation, security-configuration checks and disposable Linux netns/VM packet-path tests are green.
9. Every lab machine has a rollback instruction: old systemd unit / pinned image and preserved volume, with pre/post health and evidence checks. Never erase evidence to make a rollback appear successful.
10. Runbook with literal machine-specific commands, troubleshooting, live demonstration story and limitations is versioned in repository. Do not label production-ready based on this campus sandbox.

## 4. Suggested execution order by lab session (dependencies, not delivery promise)

- **Session A — zero migration risk:** finish M6.0 and M6.1, import local console source, pin consolidated release ref and boot mechanism. Final output is a green, independently verified three-PC baseline and recoverable backups. Stop if backups cannot be restored.
- **Session B — build and disposable tests:** implement Compose projects, dev/test images, health and retry semantics and staging network (M6.2–M6.3). Run automated CI and disposable VMs/netns. No physical cutover.
- **Session C — controlled cutover:** after rehearsal, migrate one role at a time, compare old/new evidence, run restart/rollback tests. Preserve host WG/IDS/nftables until real packet-path parity.
- **Session D — multi-actor network:** implement and approve M6.4 after proving routing/source identity, and then complete M6.5 with quantified resource ceilings, upgrade/rollback and one-command orchestration.

Plan is deliberately phased because **Compose on three hosts is not a single Compose deployment**. A `mon lab` wrapper should orchestrate independent host Compose projects using authenticated management links; every host still needs power and operating network connectivity.

## 5. Immediate next-start command and output to collect

On PC-2, with branch helper installed:
```bash
bash ~/mon-three-lab-operator.sh status
```

On PC-5:
```bash
hostname; systemctl is-active wg-quick@wg0 mon-training-site.service
curl --noproxy '*' --max-time 5 http://10.77.0.50:8085/health
```

On PC-7:
```bash
hostname; systemctl is-active wg-quick@wg0 mon-batch2-attack-console.service
curl --noproxy '*' --max-time 5 -o /dev/null -w 'console HTTP %{http_code}\n' http://127.0.0.1:8766/
```

Record **exit status/health only**; do not paste tokens, credentials, raw DB backup, private keys or Docker inspect output containing secrets into public tickets.

## 6. References

- ADR 0076: `docs/adr/0076-three-pc-docker-sandbox-migration.md`.
- Interim operation: `docs/MON_THREE_PC_CONTAINERIZATION_RUNBOOK.md`.
- Existing release: `release/mon-batch4-rc1`; UI PR #97; migration PR #99.
- Docker Compose startup order: https://docs.docker.com/compose/how-tos/startup-order/
- Docker Engine isolation limits: https://docs.docker.com/engine/security/
- Docker networking and source NAT: https://docs.docker.com/engine/network/port-publishing/

## 7. 2026-10-28 live baseline: all three machines independently healthy

The operator's subsequent machine-local checks add independent confirmation to the original recovery log:

| Host | Source of evidence | Verified state | Not yet proven |
| --- | --- | --- | --- |
| PC-2 | `bash ~/mon-three-lab-operator.sh status` | WG 10.77.0.1 present; `mon-three-postgres` running and accepting connections; portal, console, IDS and Stage-4 gate services active; API/portal/console and remote PC-5 website HTTP probes passed | Automatic reboot recovery of port 8080; successful DB restore; expiry handling; sustained telemetry freshness |
| PC-5 | Direct terminal `systemctl is-active` and `curl` | `wg-quick@wg0` active, `mon-training-site.service` active, version-4 `/health` READY | Application evidence backup/restore; startup after reboot |
| PC-7 | Direct terminal `systemctl is-active` and `curl` | `wg-quick@wg0` active, `mon-batch2-attack-console.service` active, local `:8766/` HTTP 200 | Source present in canonical repo; safe actor sandboxing; startup after reboot |

The PC-2 helper reports remote PC-5/PC-7 systemd state **UNVERIFIED** by design, because it does not run SSH by default. This is not a failed remote host; direct terminal verification establishes current service health, not centralized authenticated control.

**Next Phase A2 action:** inventory the exact mounts and boot owners (without dumping environment variables or tokens), create an access-restricted logical PostgreSQL backup, run `pg_restore --list` against the archive, preserve Suricata and Stage-4 audit/PC-5 impact artifacts separately, then validate a full restore in a disposable database before any live Compose cutover. Never confuse `pg_restore --list` with a proven restoration.

## 8. 2026-10-28 Phase A2 evidence: existing PostgreSQL volume and verified backup format

Directly observed on PC-2 (not inferred from GitHub):
- Existing container `mon-three-postgres` has Docker restart policy `unless-stopped`.
- Docker named volume is **`mon-three-pgdata`**, physically mounted as `/var/lib/docker/volumes/mon-three-pgdata/_data` to `/var/lib/postgresql/data`. Never modify/remove this volume in staging.
- Control plane PID 5787 (`uvicorn`) is supervised by **`mon-three-control-plane.service`**, cgroup `/system.slice/mon-three-control-plane.service`. Service enabled-on-boot state and restart dependencies have not yet been confirmed.
- Filesystem `/dev/nvme0n1p5` has ~39 GB free as observed.
- Logical `pg_dump -Fc` created a **175 KB** archive `~/mon-three/backups/mon-control-20261028T113211Z.dump` with mode `0600`, produced at 2026-10-28T11:32:11Z. User-verified `pg_restore --list` succeeded. The observed artifact digest is `65b7b025596abdfd5924e16c5101a80d2c4dc2eec32bb8487e7f186d306cea64`.
- **Unproven:** restoring the backup and booting a recovered MON API; `pg_restore --list` alone only proves archive readability. No conclusion yet about data integrity or offsite disaster recovery.

**Next gate — disposable restore rehearsal:** `tools/mon-m6-restore-rehearsal.sh` uses the verified archive/digest, the *already locally present* PostgreSQL image and a temporary `--network none` container with bounded CPU/RAM/PIDs, tmpfs PostgreSQL storage and no published ports or host mounts. It refuses unexpected images, missing databases and checksum failures, and automatically removes its temporary container. It runs actual `pg_restore --exit-on-error`, then compares public-table count, Alembic revision, RLS-enabled table count and RLS policy count against the live source. This is **not** a cross-tenant data recovery test or a durable off-host backup; a complete MON restore validation remains a release gate.

PC-2 execution (from a clean checkout of the migration branch, or fetch the exact file with `git show FETCH_HEAD:tools/mon-m6-restore-rehearsal.sh`):

```bash
bash tools/mon-m6-restore-rehearsal.sh \
  "$HOME/mon-three/backups/mon-control-20261028T113211Z.dump" \
  65b7b025596abdfd5924e16c5101a80d2c4dc2eec32bb8487e7f186d306cea64
```

**Do not mark Phase A2 complete** until the disposable restore logs show `[PASS] Disposable database restore rehearsal completed` and an additional full MON tenant/evidence recovery test is performed.

## 9. Alternative sandbox technology decision gate (2026-10-29)

Research is recorded in `docs/MON_M6_SANDBOX_TECHNOLOGY_ASSESSMENT.md` (official Incus, Linux netns/Mininet, gVisor, KVM, Hyper-V, Firecracker/Kata and GNS3 sources). **Candidate recommendation:** replace *attack/victim* Docker application sandboxes with unprivileged Incus Linux system containers plus an explicitly routed Linux namespace/Mininet network test layer **if** capability and packet-path tests succeed. Retain existing PC-2 PostgreSQL Docker volume/control API/IDS and host WireGuard/nftables. This modifies the M6.3/M6.4 implementation candidates, not the M6.0 backup gate or M6.1 readiness work. Do not interpret Incus as a VM-grade boundary for untrusted malware; stronger scenarios require a dedicated VM or remain out of scope. No live migration is authorized by this research note. Before changing an accepted architecture, publish a decision ADR and regression gates; ensure every observed actor IP is preserved across PC-2 `wg0`, no campus-LAN egress exists, and per-source containment is honestly verified rather than assumed from a launched service.
