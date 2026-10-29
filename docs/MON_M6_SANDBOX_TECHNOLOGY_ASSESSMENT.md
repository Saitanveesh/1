# MON M6 sandbox-technology assessment — 2026-10-29

**Status:** Candidate decision / evaluation gate; no host deployment or network change performed.
**Context:** PC-2 MON control-plane + Suricata + existing nftables scoped enforcement; PC-5 synthetic training website v4; PC-7 recovered attack console. Three existing Ubuntu instances run on Windows lab systems, use WireGuard overlays (PC-2 10.77.0.1, PC-5 10.77.0.50, PC-7 10.77.0.70) and share a physical institutional LAN. Docker persists PostgreSQL successfully but **does not** itself provide VM-grade isolation or distinct attacker IP identities. Hypervisor edition, nested-virt, actual Incus compatibility and spare per-PC resources remain **unverified**.

## Security objective and threat model

1. Reproducible, controlled and bounded synthetic training behavior from multiple independent sources to multiple synthetic victim applications.
2. Forensic integrity: source/destination addresses, real IDS events, victim server-written metadata and nftables rule state are *observed*, not simulated or inferred.
3. Enforcement visibility: every relevant flow crosses an explicitly verified observation/enforcement point (currently PC-2 `wg0` for host-to-host training), with source identity preserved.
4. Egress containment: no training workload has access to unrelated college LAN IPs, public networks, real personal files, host Docker/Incus control sockets, or administrative services; no uncontrolled or high-volume attacks.
5. Safe user experience: deterministic `up/status/test/backup/upgrade/rollback` that never deletes volumes or audit history or changes host WireGuard routes without explicit reviewed deployment.
6. Stronger isolation is required for *untrusted* malicious executables or kernel exploits. A shared-kernel technology is **not approved** for that workload class even if it passes connectivity tests.

## Official-source comparison

| Candidate | Type, dependency | Benefits for MON | Limitations / judgement |
| --- | --- | --- | --- |
| **Incus with unprivileged Linux system containers** | Linux namespaces+cgroups; **no KVM required for containers** | Individual long-running synthetic Linux hosts, service ownership, snapshots, CPU/RAM constraints, routed NIC/veth, repeatable provisioning | Shares kernel; verify user namespaces/AppArmor/Incus daemon restrictions. Avoid privileged mode. **Recommended default for trusted actor/victim applications**, if compatible with existing Ubuntu guest. |
| **Linux network namespaces + veth + Mininet** | Host-kernel network isolation; no KVM | Linux-real routing/switching, source identity, repeatable 2×2/3×3 topologies, packet-path and per-path block/rollback assertions | Mininet virtual hosts are processes sharing kernel; network namespace by itself does not isolate filesystem/pids. Use for **network test topology**, not hostile code. |
| **gVisor Systrap (`runsc`)** | Userspace application kernel; default Systrap without KVM; OCI runtime, Docker optional | Stronger user-space syscall boundary than ordinary containers, good if application can work within syscall restrictions | OCI packaging still required; compatibility/performance/capture fidelity to be checked; do not run kernel sensors/host nftables inside gVisor. Optional narrow sandbox for trusted-in-scope HTTP actors. |
| **KVM/QEMU+libvirt / Incus virtual machines** | Hardware virtualization (`/dev/kvm`) | Strongest traditional isolation of candidate Linux guests, separate kernels; good for arbitrary OS and higher-risk controlled experiments | Inside existing Windows-hosted Ubuntu VM may lack exposed nested virtualization; costs memory and CPU. Use only after capability test and disposable VM benchmark. |
| **Microsoft Hyper-V directly on Windows** | Host hypervisor, requires supported edition (Windows 10/11 Pro or Enterprise), CPU/BIOS support | Replace VirtualBox **host** dependency with Windows-native Ubuntu VM, then Incus/netns inside that Linux VM without nested KVM | Requires institutional permission, edition checks and careful migration/rollback; enabling Hyper-V may affect existing VM stack. Not an in-place magic fix. |
| **Firecracker / Kata Containers** | MicroVM hardware KVM (in this context requires nested KVM) | Strong VM kernel boundary and fast instance lifecycle | KVM dependency, disk/image/init/network TAP integration and nested virtualization complexity; not an M6 first step. |
| **GNS3** | GUI network emulation, compute often uses a VM/QEMU/Docker | Complex visual topology and router/switch demonstrations | Extra control plane and virtualization dependencies, not a strong isolation boundary on its own; optional education/demo layer, not MON's operational sandbox. |
| **Proxmox VE** | Bare-metal hypervisor OS on dedicated hardware | Great when dedicated servers and strong virtualization management available | Installation replaces host OS; not acceptable on existing shared Windows PCs without explicit dedicated-hardware authorization. |
| **NsJail / system-level process sandbox tools** | Namespaces, seccomp, cgroups, rlimits | Lightweight bounded single-process exercises | Does not alone provide persistent networked Linux host lifecycle and observability; optional actor-level defense-in-depth. |

References (official):
- Incus containers vs VMs: https://linuxcontainers.org/incus/docs/main/explanation/containers_and_vms/
- Incus security and privileged-container caveat: https://linuxcontainers.org/incus/docs/main/explanation/security/
- Incus routed NICs and host routing: https://linuxcontainers.org/incus/docs/main/reference/devices_nic/
- Linux network namespaces: https://man7.org/linux/man-pages/man7/network_namespaces.7.html
- Mininet overview: https://mininet.org/overview/
- gVisor architecture: https://gvisor.dev/docs/architecture_guide/intro/
- gVisor Systrap: https://gvisor.dev/docs/architecture_guide/platforms/
- Hyper-V requirements: https://learn.microsoft.com/virtualization/hyper-v-on-windows/reference/hyper-v-requirements
- Hyper-V nested virtualization: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization
- Firecracker KVM requirement: https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md
- Kata VM boundary: https://kata-containers.github.io/kata-containers/
- GNS3 architecture: https://docs.gns3.com/docs/using-gns3/design/architecture
- Proxmox bare-metal: https://proxmox.com/en/products/proxmox-virtual-environment/get-started
- NsJail: https://github.com/google/nsjail

## Proposed architecture, conditional on the hardware and compatibility preflight

- PC-2 **unchanged baseline**: PostgreSQL persists in existing named Docker volume `mon-three-pgdata`; host `mon-three-control-plane.service`, portal, Suricata `wg0` capture and tightly scoped nftables helper remain as-is. Do **not** require Docker removal merely because Docker is unsuitable as an *attack sandbox*. Keep detection separate from enforcement.
- PC-5: use unprivileged Incus *system containers* for multiple **fictional** victim applications, with read-only code+training fixtures and separate durable, bounded server-owned impact journals. Stage alongside `:8085`; maintain original service until parity and rollback proven.
- PC-7: use unprivileged Incus system containers for multiple bounded **synthetic** traffic actors; preserve existing local `:8766` console until recovered source is audited and port parity validated.
- Mininet or direct `ip netns` + veth only for network-path experiments, in disposable hosts/namespaces first. Keep a single known traversal path through PC-2 rather than assuming same-host traffic goes across WireGuard.
- For **strong isolation of untrusted code**, require an explicitly dedicated VM/physical execution boundary (KVM/QEMU or direct Hyper-V Ubuntu) and an independent offline or tightly isolated network. If unavailable, that workload is out of scope on this institutional network.
- Routing: no default NAT for actor identities; use distinct unallocated overlay-only CIDRs approved for the site, explicitly scoped WireGuard `AllowedIPs`, return routes, host forwarding rules and anti-spoof checks **only after** a disposable network test. No bridged NIC to shared campus LAN and no host-network attack workload.
- Current Stage-4 rule supports only narrow named legacy WireGuard addresses to PC-5 TCP/8085; new container subnet-aware policy/adapter must be designed, formally approved and tested before generalized containment is claimed.
- Identity: store `actor_id`, `sandbox_id`, `src_ip`, `victim_id`, `dst_ip`, `tenant_id`, `site_id`, timestamp and confidence with real IDS/flow evidence. False historical evidence is prohibited.

## Read-only compatibility gate before changing technology

Run **on each Ubuntu instance**, without installation:
```bash
hostname
systemd-detect-virt || true
uname -r
test -e /dev/kvm && ls -l /dev/kvm || echo '/dev/kvm unavailable (nested KVM not verified)'
findmnt -no FSTYPE /sys/fs/cgroup
for f in /boot/config-$(uname -r) /proc/config.gz; do
  if [ -r "$f" ]; then
    case "$f" in *.gz) zgrep -E '^CONFIG_(NET_NS|USER_NS|CGROUPS|SECCOMP|VETH)=' "$f" ;; *) grep -E '^CONFIG_(NET_NS|USER_NS|CGROUPS|SECCOMP|VETH)=' "$f" ;; esac
    break
  fi
done
command -v incus || true
command -v ip
```
No `systemd-detect-virt` or /dev/kvm result alone certifies safety; perform a disposable unprivileged container create/delete and a no-egress topology test in a **test VM** before live installation.

## Decision gate (M6.1 -> M6.2 / M6.3 / M6.4)

1. Preserve the current working deployment and complete restore drill plus evidence backups.
2. If unprivileged Incus works inside the existing Ubuntu guest, **prefer it** over Docker for sandbox host lifecycle; build a small 2×2 synthetic test and snapshot/rollback.
3. If Incus cannot run safely (kernel/permission/institutional constraint), keep the existing hosts, use a minimal Mininet or netns path topology for **trusted** traffic only, with an independent process sandbox where needed; do not weaken host security to make Incus work.
4. If stronger VM isolation is needed and Windows host licensing/permissions permit, consider Hyper-V as **outer Ubuntu hypervisor**. Do not attempt Firecracker/Kata nested in unsupported guests.
5. Do not mark M6 sandboxing complete until every actor-to-victim flow is attributable from PC-2 `wg0`, cannot escape to college LAN, survives start/stop/reset/rebuild, and timed containment affects exactly the selected path with independent rollback verification.
6. Do not migrate the MON database or sensor to a new sandbox runtime for this purpose. Their lifecycle is separate.

**Relationship to ADR 0076:** ADR 0076's Compose-first choice remains *proposed*, not live. This assessment introduces a **technology selection gate**: Incus+netns is the preferred non-Docker alternative for simulated workload sandboxing, pending actual capability and packet-path tests. An accepted replacement ADR is required before any disruptive migration.
