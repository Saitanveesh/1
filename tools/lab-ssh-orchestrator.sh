#!/usr/bin/env bash
# MON lab: run from PC2 (Ubuntu) only. No agent/secret distribution.
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage: bash tools/lab-ssh-orchestrator.sh INVENTORY preflight|install|wireguard-keys|wireguard-config|verify|isolate-attacker
Run from PC2. Inventory is a trusted local shell file; do not use untrusted input.
Order: preflight -> install -> wireguard-keys -> wireguard-config -> verify.
isolate-attacker is an explicit LAST STEP; it will terminate PC2 SSH access to PC6.
USAGE
}
[[ $# == 2 ]] || { usage; exit 2; }
inventory=$1 action=$2
[[ -f "$inventory" ]] || { echo "Missing inventory: $inventory" >&2; exit 2; }
# shellcheck source=/dev/null
source "$inventory"
: "${LAB_USER:?set LAB_USER}"
: "${PC1_IP:?set PC1_IP}" "${PC2_IP:?set PC2_IP}" "${PC3_IP:?set PC3_IP}"
: "${PC4_IP:?set PC4_IP}" "${PC5_IP:?set PC5_IP}" "${PC6_IP:?set PC6_IP}" "${PC7_IP:?set PC7_IP}"
MON_REF=${MON_REF:-8f66baa9f8d287b8c05da379259b289c661c5828}
[[ "$LAB_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "Invalid username" >&2; exit 2; }
[[ "$MON_REF" =~ ^[a-fA-F0-9]{40}$ ]] || { echo "MON_REF must be a 40-character SHA" >&2; exit 2; }
for n in 1 2 3 4 5 6 7; do
  x=PC${n}_IP
  [[ "${!x}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "Invalid $x" >&2; exit 2; }
done
hosts=("$PC1_IP" "$PC3_IP" "$PC4_IP" "$PC5_IP" "$PC6_IP" "$PC7_IP")
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes)
remote() { local host=$1; shift; ssh "${ssh_opts[@]}" "$LAB_USER@$host" "$@"; }
# A command file on disk avoids sudo consuming script stdin.
root_script() {
  local host=$1 file=$2 name
  name=$(basename "$file")
  scp -q "${ssh_opts[@]}" "$file" "$LAB_USER@$host:/tmp/$name"
  echo "[$host] One interactive sudo prompt may appear."
  ssh -tt -o ConnectTimeout=10 -o StrictHostKeyChecking=yes "$LAB_USER@$host" "sudo bash /tmp/$name; rc=\$?; rm -f /tmp/$name; exit \$rc"
}
command -v ssh >/dev/null
command -v scp >/dev/null
command -v python3 >/dev/null
case "$action" in
preflight)
  for h in "${hosts[@]}"; do
    echo "====== $h ======"
    remote "$h" 'hostname; id -un; ip -4 route get 1.1.1.1 | head -1; command -v sudo; command -v apt-get' || exit 1
  done
  echo "SSH and basic tooling OK. Ensure PCs are dedicated/disposable test hosts."
  ;;
install)
  tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
  cat >"$tmp" <<'SCRIPT'
#!/bin/bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3 python3-venv python3-pip curl jq tmux openssh-server openssl wireguard nftables
systemctl enable --now ssh
SCRIPT
  for h in "${hosts[@]}"; do root_script "$h" "$tmp"; done
  echo "Base dependencies installed. MON services and credentials NOT deployed yet."
  ;;
wireguard-keys)
  for h in "$PC3_IP" "$PC4_IP" "$PC5_IP" "$PC6_IP"; do
    remote "$h" 'umask 077; if [ ! -s "$HOME/wg-private.key" ]; then wg genkey | tee "$HOME/wg-private.key" | wg pubkey > "$HOME/wg-public.key"; fi; test -s "$HOME/wg-public.key" && cat "$HOME/wg-public.key"' || exit 1
  done
  echo "Keypairs generated on their owners. Private keys stayed on each PC."
  ;;
wireguard-config)
  declare -A keys=()
  for n in 3 4 5 6; do
    hvar=PC${n}_IP
    key=$(remote "${!hvar}" 'cat "$HOME/wg-public.key"') || exit 1
    [[ "$key" =~ ^[a-zA-Z0-9+/]{43}=$ ]] || { echo "Invalid key on PC$n" >&2; exit 1; }
    keys[$n]=$key
  done
  [[ $PC3_IP != "$PC6_IP" ]] || exit 1
  for n in 3 4 5 6; do
    hvar=PC${n}_IP
    host=${!hvar}
    localfile=$(mktemp)
    if [[ $n == 3 ]]; then
      cat >"$localfile" <<CONF
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
[Peer]
PublicKey = ${keys[4]}
AllowedIPs = 10.77.0.40/32
[Peer]
PublicKey = ${keys[5]}
AllowedIPs = 10.77.0.50/32
[Peer]
PublicKey = ${keys[6]}
AllowedIPs = 10.77.0.60/32
CONF
    else
      ip=10.77.0.$((n * 10))
      [[ $n == 4 ]] && ip=10.77.0.40
      [[ $n == 5 ]] && ip=10.77.0.50
      [[ $n == 6 ]] && ip=10.77.0.60
      cat >"$localfile" <<CONF
[Interface]
Address = $ip/32
[Peer]
PublicKey = ${keys[3]}
Endpoint = $PC3_IP:51820
AllowedIPs = 10.77.0.0/24
PersistentKeepalive = 15
CONF
    fi
    scp -q "${ssh_opts[@]}" "$localfile" "$LAB_USER@$host:/tmp/mon-wg-public.conf"
    rm -f "$localfile"
    setup=$(mktemp)
    cat >"$setup" <<'SCRIPT'
#!/bin/bash
set -Eeuo pipefail
umask 077
owner=$(stat -c '%U' /tmp/mon-wg-public.conf)
userhome=$(getent passwd "$owner" | cut -d: -f6)
[[ -n "$userhome" && -s "$userhome/wg-private.key" ]] || exit 1
test ! -f /etc/wireguard/wg0.conf || cp -a /etc/wireguard/wg0.conf "/etc/wireguard/wg0.conf.mon-backup-$(date +%s)"
{
  sed -n '1,/^\\[Peer\\]/{ /^\\[Peer\\]/!p; }' /tmp/mon-wg-public.conf
  printf 'PrivateKey = %s\\n' "$(cat "$userhome/wg-private.key")"
  sed -n '/^\\[Peer\\]/,$p' /tmp/mon-wg-public.conf
} > /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf
wg-quick down wg0 2>/dev/null || true
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0
rm -f /tmp/mon-wg-public.conf
SCRIPT
    root_script "$host" "$setup"
    rm -f "$setup"
  done
  setup=$(mktemp)
  cat >"$setup" <<'SCRIPT'
#!/bin/bash
set -Eeuo pipefail
printf 'net.ipv4.ip_forward=1\\n' > /etc/sysctl.d/99-mon-lab.conf
sysctl -w net.ipv4.ip_forward=1
SCRIPT
  root_script "$PC3_IP" "$setup"
  rm -f "$setup"
  echo "WireGuard configured. Check handshakes; isolation has NOT been enabled."
  ;;
verify)
  echo "Checking WireGuard hub:"
  remote "$PC3_IP" 'sudo -n wg show wg0 || wg show wg0' || exit 1
  for n in 4 5 6; do
    hvar=PC${n}_IP
    echo "Testing PC$n -> hub"
    remote "${!hvar}" 'ping -c 1 -W 2 10.77.0.1' || exit 1
  done
  echo "Overlay-to-hub connectivity OK. This does not prove end-to-end MON telemetry."
  ;;
isolate-attacker)
  echo "WARNING: this cuts PC2 SSH to PC6. Must be at physical PC6 console to undo."
  read -r -p "Type ISOLATE to proceed: " confirmation
  [[ "$confirmation" == ISOLATE ]] || exit 1
  guard=$(mktemp)
  cat >"$guard" <<'SCRIPT'
#!/bin/bash
set -Eeuo pipefail
nft list table inet mon_lab_guard >/dev/null 2>&1 && { echo "Existing guard; inspect manually"; exit 1; }
nft add table inet mon_lab_guard
nft 'add chain inet mon_lab_guard input { type filter hook input priority -100; policy accept; }'
nft 'add chain inet mon_lab_guard forward { type filter hook forward priority -100; policy accept; }'
nft 'add rule inet mon_lab_guard input iifname "wg0" ip saddr 10.77.0.60 drop'
nft 'add rule inet mon_lab_guard forward iifname "wg0" ip saddr 10.77.0.60 ip daddr { 10.77.0.40, 10.77.0.50 } accept'
nft 'add rule inet mon_lab_guard forward iifname "wg0" ip saddr 10.77.0.60 drop'
nft 'add rule inet mon_lab_guard forward iifname "wg0" oifname != "wg0" drop'
nft list table inet mon_lab_guard
SCRIPT
  root_script "$PC3_IP" "$guard"
  rm -f "$guard"
  tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
  cat >"$tmp" <<SCRIPT
#!/bin/bash
set -Eeuo pipefail
MGMT_IF=\$(ip -4 route show default | awk 'NR==1{print \$5}')
[[ -n "\$MGMT_IF" ]] || exit 1
nft list table inet mon_lab_egress >/dev/null 2>&1 && { echo "Already isolated; refusing overwrite"; exit 1; }
nft add table inet mon_lab_egress
nft 'add chain inet mon_lab_egress output { type filter hook output priority -100; policy accept; }'
nft add rule inet mon_lab_egress output oifname "\$MGMT_IF" ip daddr "$PC3_IP" udp dport 51820 accept
nft add rule inet mon_lab_egress output oifname "\$MGMT_IF" drop
echo 'PC6 isolated. LOCAL ROLLBACK: sudo nft delete table inet mon_lab_egress'
SCRIPT
  root_script "$PC6_IP" "$tmp" || echo "SSH may have dropped by design. Verify directly on PC6."
  ;;
*)
  usage; exit 2
  ;;
esac
