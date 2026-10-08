#!/usr/bin/env bash
# Read-only preparation for PC2. Does not scan the LAN or configure remote hosts.
set -Eeuo pipefail
echo "MON PC2 READ-ONLY INVENTORY | $(date -Is)"
echo "hostname=$(hostname)"
echo "login=$(id -un)"
echo "os=$(source /etc/os-release; echo "$PRETTY_NAME")"
echo "tailscale=$(command -v tailscale >/dev/null && tailscale ip -4 2>/dev/null || echo unavailable)"
echo "Interfaces:"
ip -br -4 addr
echo "Default route:"
ip -4 route show default
echo
echo "Hostnames (DNS/mDNS lookup only, no subnet scanning):"
for pc in 1 3 4 5 6 7; do
  echo "PC$pc:"
  found=0
  for name in "lab-pc$pc.local" "lab-pc$pc"; do
    answer=$(getent ahostsv4 "$name" 2>/dev/null | awk '$2=="STREAM" {print $1; exit}') || true
    if [[ -n "$answer" ]]; then
      echo "  $name -> $answer (verify on that PC before using)"
      found=1
      break
    fi
  done
  if [[ $found == 0 ]]; then
    echo "  unresolved: ask the operator on PC$pc to run: ip -br -4 addr"
  fi
done
echo
echo "SSH tools:"
for bin in ssh scp git tmux python3; do
  command -v "$bin" || echo "MISSING: $bin"
done
echo
echo "No remote connection attempted. No packages, users, interfaces or firewall settings changed."
