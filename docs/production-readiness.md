# MON production-readiness ledger

<!-- Generated from docs/production-readiness.json by tools/final_readiness_report.py --render-md. Do not edit by hand. -->

Evidence-based ledger. PROVEN means exercised by the cited automated gate in the stated environment, for the stated scope only. It is not a production certification.

Status values: `PROVEN`, `PARTIALLY_PROVEN`, `NOT_PROVEN`.

## Repository-controllable subsystems

| Subsystem | Capability | Evidence | Last validated environment | Status | Limitation |
|---|---|---|---|---|---|
| `detection-correlation-investigation` | Endpoint telemetry to finding, incident, evidence, asset/identity resolution and investigation graph | `tests/test_e2e_acceptance.py`<br>`.github/workflows/e2e-acceptance.yml`<br>`docs/adr/0066-end-to-end-acceptance-gate.md` | GitHub-hosted ubuntu-latest, PostgreSQL 17, Python 3.12 | **PROVEN** | One detector scenario (repeated authentication failures). Detector, graph and correlator windows are per-process memory. |
| `tenant-isolation-rls` | Tenant/site isolation in API, fabric ingest and PostgreSQL row-level security | `tests/test_e2e_acceptance.py`<br>`tests/test_event_fabric_adversarial_isolation.py`<br>`tests/test_control_plane_ha.py`<br>`.github/workflows/e2e-acceptance.yml`<br>`.github/workflows/ci.yml` | ubuntu-latest, PostgreSQL 17 with a NOSUPERUSER NOBYPASSRLS application role | **PROVEN** | RLS provides no backstop for a superuser connection; production must connect as a non-bypass role. |
| `authentication-jwks` | JWKS/JWT bearer authentication and cookie session, identical across control-plane instances | `tests/test_control_plane_ha.py`<br>`e2e/soc/tests/soc.spec.ts`<br>`docs/authentication.md` | ubuntu-latest, disposable RSA JWKS | **PARTIALLY_PROVEN** | No real external identity provider, key rotation in production, or SSO flow was exercised. |
| `site-to-control-plane-mtls-restart` | Site Controller to control plane over real mTLS, outage, restart and durable replay | `tests/test_networked_restart_e2e.py`<br>`.github/workflows/networked-restart-e2e.yml`<br>`docs/adr/0067-networked-mtls-restart-acceptance.md` | ubuntu-latest, PostgreSQL 17, loopback | **PROVEN** | Loopback network; no WAN latency, packet loss or real certificate authority operations. |
| `event-fabric-failure-recovery` | Durable outbox, duplicate safety and failure/recovery of the event fabric | `tests/test_event_fabric_failure_recovery.py`<br>`tests/test_event_fabric_outbox.py`<br>`tests/test_fabric_ingress.py`<br>`.github/workflows/ci.yml` | ubuntu-latest, Python 3.12 and 3.13 | **PROVEN** | Failure injection is in-process; no chaos testing of real networks. |
| `control-plane-application-ha` | Two control-plane instances behind a reverse proxy on shared PostgreSQL; failover, rejoin, concurrent-duplicate safety | `tests/test_control_plane_ha.py`<br>`.github/workflows/control-plane-ha.yml`<br>`docs/adr/0070-control-plane-ha-failover-certification.md` | ubuntu-latest, nginx, uvicorn x2, PostgreSQL 17 | **PARTIALLY_PROVEN** | Detector windows are per-instance memory, so a burst split across instances can under-detect. Two instances only. |
| `postgresql-backup-restore` | PostgreSQL logical backup, restore into a fresh database and integrity verification | `tests/test_control_plane_backup.py`<br>`.github/workflows/backup-restore.yml`<br>`docs/adr/0064-postgresql-backup-restore.md` | ubuntu-latest, PostgreSQL 16 | **PROVEN** | Logical dump only; no point-in-time recovery or encrypted off-site storage. |
| `site-controller-state-snapshot` | Site Controller durable-state snapshot, verify and restore | `tests/test_site_state_snapshot.py`<br>`docs/adr/0065-site-controller-state-snapshot.md` | ubuntu-latest and windows-latest unit environments | **PROVEN** | Snapshots are files; no automated scheduling, retention or off-host copy. |
| `linux-nftables-enforcement` | BLOCK_IP apply, verify, rollback, reconcile with nftables in a disposable namespace and on a disposable privileged host, IPv4 and IPv6 | `tests/test_nftables_netns_integration.py`<br>`tests/test_nftables_privileged_host.py`<br>`.github/workflows/nftables-host-certification.yml`<br>`.github/workflows/ci.yml`<br>`docs/adr/0068-linux-privileged-host-nftables-certification.md` | ubuntu-latest (Ubuntu 24.04, kernel 6.17 azure, nftables 1.0.9) | **PARTIALLY_PROVEN** | Rule state is verified, not packet flow. firewalld and ufw were not exercised. Only the runner Ubuntu image and iptables-nft coexistence were tested. |
| `windows-defender-firewall-enforcement` | BLOCK_IP apply, verify, rollback, reconcile with Windows Defender Firewall, IPv4 and IPv6 | `src/mon/connectors/windows_firewall_endpoint.py`<br>`tests/test_windows_firewall_endpoint_adapter.py`<br>`tests/test_windows_firewall_certification.py`<br>`.github/workflows/windows-firewall-certification.yml`<br>`docs/adr/0071-windows-defender-firewall-enforcement.md` | windows-latest (Windows Server 2025, 10.0.26100) | **PARTIALLY_PROVEN** | Rule state is verified through Get-NetFirewallRule, not packet flow. No Group Policy or third-party firewall coexistence. |
| `windows-collector-service-lifecycle` | Windows collector as an SCM service: install, start, stop, restart, crash observation, uninstall, state preservation, upgrade/rollback | `tests/test_windows_service_certification.py`<br>`.github/workflows/windows-service-certification.yml`<br>`docs/adr/0069-windows-service-lifecycle-certification.md` | windows-latest (Windows Server 2025, 10.0.26100) | **PROVEN** | No automatic crash recovery is configured. Security-log reading was observed on the runner but volume and event coverage are not certified. |
| `linux-collector-service` | Linux endpoint collector under a hardened systemd unit | `tests/test_linux_endpoint_collector.py`<br>`tests/test_package_lifecycle_linux.py`<br>`.github/workflows/package-lifecycle.yml`<br>`tools/systemd/mon-linux-endpoint-collector.service` | ubuntu-latest with systemd | **PARTIALLY_PROVEN** | auditd process-execution evidence under the packaged unit was not exercised end to end. |
| `deployable-packages` | Windows MSI and Linux .deb install, start, stop, upgrade, rollback, uninstall, state preservation | `tests/test_package_lifecycle_windows.py`<br>`tests/test_package_lifecycle_linux.py`<br>`.github/workflows/package-lifecycle.yml`<br>`.github/workflows/release-candidate.yml`<br>`docs/adr/0072-deployable-packages-release-chain.md` | windows-latest and ubuntu-latest | **PROVEN** | Unsigned. No apt repository, RPM, GPO/SCCM/Intune tooling, or in-place downgrade. |
| `release-manifest-sbom-provenance` | Deterministic manifest, CycloneDX SBOMs, GitHub attestations and independent verification of the exact artifact set | `src/mon/release_candidate.py`<br>`tests/test_release_candidate_gate.py`<br>`.github/workflows/release-candidate.yml`<br>`.github/workflows/verify-release-candidate.yml`<br>`docs/adr/0059-windows-collector-release-chain.md` | GitHub Actions, GitHub artifact attestations | **PROVEN** | Attestations prove build provenance, not code-signing trust. PyInstaller output is not bit-reproducible. |
| `soc-operator-console` | Operator console: authenticated context, incident, evidence, asset/identity, investigation path, containment capability, response/policy/recovery state, audit history, tenant-scoped navigation | `e2e/soc/tests/soc.spec.ts`<br>`tools/soc_acceptance_seed.py`<br>`.github/workflows/soc-browser-acceptance.yml`<br>`console/src/IncidentDetail.tsx` | ubuntu-latest, Chromium (Playwright), real backend, real nftables in a namespace | **PARTIALLY_PROVEN** | The scenario enrolls no sensor, so the fleet view is proven only for its honest empty state. There is no Network Health metric with a documented source, and independent verification state is not displayed in the console. |
| `load-resource-restart` | Bounded ingest load, latency percentiles, process CPU/RAM samples, restart recovery | `tools/load_resource_gate.py`<br>`tools/fabric_load_probe.py`<br>`.github/workflows/load-resource-gate.yml` | ubuntu-latest, one uvicorn instance over TLS, PostgreSQL 17 | **PARTIALLY_PROVEN** | Evidence for the tested event count, concurrency and 30 s duration on one runner only; no SLO or capacity claim. |

## External / not exercised by this repository

| Subsystem | Capability | Evidence | Last validated environment | Status | Limitation |
|---|---|---|---|---|---|
| `postgresql-ha-failover` | Automatic PostgreSQL failover and replication | `docs/adr/0070-control-plane-ha-failover-certification.md` | not exercised | **NOT_PROVEN** | No PostgreSQL cluster, replica promotion or connection failover was tested. |
| `multi-region-disaster-recovery` | Multi-region replication and disaster recovery | `docs/backup-recovery.md` | not exercised | **NOT_PROVEN** | Only single-site logical backup/restore is exercised; no cross-region infrastructure exists. |
| `enterprise-firewall-nac-appliances` | Real enterprise firewall / NAC appliance enforcement | `docs/adr/0063-enforcement-adapter-capability-contract.md` | not exercised | **NOT_PROVEN** | No vendor appliance, appliance API credential or lab was available. |
| `cloud-provider-enforcement` | Cloud security-group / firewall enforcement | `docs/adr/0063-enforcement-adapter-capability-contract.md` | not exercised | **NOT_PROVEN** | No cloud account, credentials or environment were used. |
| `upstream-isp-ddos-mitigation` | Upstream ISP or DDoS-provider mitigation integration | `docs/adr/0063-enforcement-adapter-capability-contract.md` | not exercised | **NOT_PROVEN** | No provider integration exists or was tested. |
| `production-code-signing` | Production Authenticode and package signing | `tools/package/sign_msi.ps1`<br>`docs/adr/0072-deployable-packages-release-chain.md` | not exercised | **NOT_PROVEN** | No production signing certificate or GPG key exists; every artifact is unsigned and CI asserts NotSigned. |
| `linux-distro-kernel-matrix` | Broad Linux distribution and kernel coverage | `.github/workflows/nftables-host-certification.yml` | only the runner Ubuntu image was tested | **NOT_PROVEN** | No other distribution, kernel, or firewall manager combination was exercised. |
| `windows-version-matrix` | Broad Windows version coverage | `.github/workflows/windows-service-certification.yml` | only Windows Server 2025 (10.0.26100) was tested | **NOT_PROVEN** | No Windows client or older server version was exercised. |
| `customer-production-networks` | Operation on real customer production networks | `docs/production-readiness.md` | not exercised | **NOT_PROVEN** | No customer pilot or production deployment exists. |

## Required release gates

| Gate | Workflow |
|---|---|
| python 3.12/3.13 | `.github/workflows/ci.yml` |
| console build/tests | `.github/workflows/ci.yml` |
| PostgreSQL integration / RLS | `.github/workflows/ci.yml` |
| adversarial tenant isolation | `.github/workflows/ci.yml` |
| mTLS | `.github/workflows/networked-restart-e2e.yml` |
| E2E lifecycle | `.github/workflows/e2e-acceptance.yml` |
| networked restart E2E | `.github/workflows/networked-restart-e2e.yml` |
| Linux privileged nftables certification | `.github/workflows/nftables-host-certification.yml` |
| Windows service certification | `.github/workflows/windows-service-certification.yml` |
| Windows Firewall certification | `.github/workflows/windows-firewall-certification.yml` |
| backup/restore | `.github/workflows/backup-restore.yml` |
| site-state snapshot/restore | `.github/workflows/ci.yml` |
| event-fabric failure/recovery | `.github/workflows/ci.yml` |
| control-plane HA | `.github/workflows/control-plane-ha.yml` |
| load/resource gate | `.github/workflows/load-resource-gate.yml` |
| release manifest, SBOM, provenance | `.github/workflows/release-candidate.yml` |
| independent artifact verification | `.github/workflows/verify-release-candidate.yml` |
| Windows/Linux package lifecycle | `.github/workflows/package-lifecycle.yml` |
| SOC browser acceptance | `.github/workflows/soc-browser-acceptance.yml` |
