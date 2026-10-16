#!/usr/bin/env bash
# Read-only safety preflight. MUST run in a disposable, network-disconnected VM.
# Refuses bare-metal dual-boot Ubuntu and VMs with any external virtual NIC.
set -Eeuo pipefail

die() { printf 'MON LAB PREFLIGHT: BLOCKED — %s\n' "$*" >&2; exit 2; }

if [ "$(id -u)" -ne 0 ]; then
  die "run with sudo inside an isolated disposable Ubuntu VM"
fi
command -v systemd-detect-virt >/dev/null || die "systemd-detect-virt missing"
command -v ip >/dev/null || die "iproute2 missing"
if ! vm_kind="$(systemd-detect-virt --vm 2>/dev/null)"; then
  die "not a detected virtual machine: dual-boot Ubuntu alone is NOT a sandbox"
fi

# An offline VM should have only lo. This rejects NAT, host-only and bridged
# NICs rather than relying on the operator's description of the network.
# Do not run this check after veth namespaces have been created.
interfaces="$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)"
if [ "$interfaces" != "lo" ]; then
  printf 'Current network interfaces:\n%s\n' "$interfaces" >&2
  die "VM has a network interface; remove ALL VM NICs (including NAT/host-only) before exercise"
fi
if [ -n "$(ip -4 route show)" ] || [ -n "$(ip -6 route show)" ]; then
  die "VM has IP routes; exercise must have no networking outside disposable veth"
fi

if [ "${MON_DISPOSABLE_VM_CONFIRMED:-}" != "YES" ]; then
  die "explicit authorization and disposable VM confirmation missing"
fi

for cmd in ip curl tcpdump timeout nft sysctl sha256sum grep mktemp ping; do
  command -v "$cmd" >/dev/null || die "missing prerequisite: $cmd"
done

printf 'MON LAB PREFLIGHT: PASS — hypervisor=%s; interfaces=lo only; no IP routes.\n' "$vm_kind"
printf 'Scope: ephemeral veth namespaces in a disconnected VM, NOT shared campus LAN.\n'
