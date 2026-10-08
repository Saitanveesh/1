#!/usr/bin/env bash
# MON seven-host Ubuntu lab: SSH controller. Run on PC2 only.
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${MON_LAB_CONFIG:-$SCRIPT_DIR/lab.env}"
REMOTE_DIR='.local/share/mon-lab'
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes)

usage() {
  cat <<'HELP'
Usage: MON_LAB_CONFIG=/path/to/lab.env bash controller.sh COMMAND
Commands:
  preflight    Check SSH, host keys, Ubuntu, management IP and sudo on all PCs
  install      Install prerequisites and pinned MON code on required PCs
  keys         Generate/reuse WireGuard keys; save public keys locally
  network      Configure WireGuard hub and three spokes, verify connectivity
  control      Start persistent PostgreSQL + MON control plane + console on PC1
  site         Enroll and start PC3 Site Controller + sensor mTLS ingress
  sensors      Enroll and start PC3 Suricata + PC4/PC5 Linux collectors
  register     Register PC3 ROUTER enforcement point in MON
  status       Check all node/overlay/services; never reports fake healthy values
  lockdown     Explicitly restrict PC6 egress (keeps PC2 SSH replies and WG UDP)
  teardown     Stop MON lab services and remove only MON lab firewall tables
  all          install, keys, network, control, site, sensors, register, status

Must be launched from PC2 after SSH public-key authentication and confirmed
host fingerprints are set up for PC1, PC3, PC4, PC5, PC6 and PC7.
Each remote stage prompts once for sudo as needed; no blanket NOPASSWD sudo.
No test attacks are launched by this script.
HELP
}

[[ $# -eq 1 ]] || { usage; exit 2; }
CMD="$1"
case "$CMD" in preflight|install|keys|network|control|site|sensors|register|status|lockdown|teardown|all) ;; *) usage; exit 2 ;; esac
[[ -f "$CONFIG" ]] || { echo "Missing $CONFIG (copy lab.env.example and edit it)" >&2; exit 2; }
# Configuration is a user-owned trusted shell file. Do not load downloaded configs.
# shellcheck disable=SC1090
source "$CONFIG"
: "${LAB_USER:?LAB_USER is required}"
: "${MON_REF:?MON_REF is required}"
for i in 1 2 3 4 5 6 7; do var="PC${i}_MGMT_IP"; [[ -n "${!var:-}" ]] || { echo "Missing $var" >&2; exit 2; }; done
[[ "$LAB_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "Invalid LAB_USER" >&2; exit 2; }
[[ "$MON_REF" =~ ^[0-9a-f]{40}$ ]] || { echo 'MON_REF must be a complete immutable 40-char Git SHA' >&2; exit 2; }
for i in 1 2 3 4 5 6 7; do
  var="PC${i}_MGMT_IP"; value="${!var}"
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Invalid $var: $value" >&2; exit 2; }
  IFS=. read -r a b c d <<<"$value"
  for oct in "$a" "$b" "$c" "$d"; do ((10#$oct <= 255)) || { echo "Invalid $var" >&2; exit 2; }; done
  for j in $(seq 1 $((i-1))); do other="PC${j}_MGMT_IP"; [[ "${!other}" != "$value" ]] || { echo "$var duplicates $other" >&2; exit 2; }; done
done
[[ "${PC2_MGMT_IP}" != 10.77.* && "${PC3_MGMT_IP}" != 10.77.* ]] || { echo 'Management LAN must not overlap 10.77.0.0/24' >&2; exit 2; }
if command -v ip >/dev/null 2>&1; then
  ip -4 -o addr show | grep -Fq " $PC2_MGMT_IP/" || { echo "Run this from PC2 ($PC2_MGMT_IP), not another PC" >&2; exit 2; }
fi

ip_of() { local v="${1^^}_MGMT_IP"; printf '%s' "${!v}"; }
ssh_host() { local pc="$1"; shift; ssh "${SSH_OPTS[@]}" "${LAB_USER}@$(ip_of "$pc")" "$@"; }
copy_to() { local pc="$1" from="$2" to="$3"; scp -q "${SSH_OPTS[@]}" "$from" "${LAB_USER}@$(ip_of "$pc"):$to"; }
copy_from() { local pc="$1" from="$2" to="$3"; scp -q "${SSH_OPTS[@]}" "${LAB_USER}@$(ip_of "$pc"):$from" "$to"; }
msg() { echo; echo "===== $* ====="; }
remote_dir() { printf '/home/%s/%s' "$LAB_USER" "$REMOTE_DIR"; }

push_node() {
  local pc="$1" keyfile="$SCRIPT_DIR/wireguard-public.env" config_tmp
  ssh_host "$pc" "mkdir -p ~/$REMOTE_DIR/incoming ~/$REMOTE_DIR/outgoing && chmod 700 ~/$REMOTE_DIR ~/$REMOTE_DIR/incoming ~/$REMOTE_DIR/outgoing"
  config_tmp="$(mktemp)"
  # Compose explicit values, never copy secret JWT/CA/private WireGuard keys to PC2.
  {
    printf 'LAB_USER=%q\nMON_REF=%q\n' "$LAB_USER" "$MON_REF"
    for i in 1 2 3 4 5 6 7; do var="PC${i}_MGMT_IP"; printf '%s=%q\n' "$var" "${!var}"; done
    printf '%s\n' 'TENANT=mon-lab' 'SITE=site-a'
    [[ ! -e "$keyfile" ]] || cat "$keyfile"
  } > "$config_tmp"
  chmod 600 "$config_tmp"
  copy_to "$pc" "$config_tmp" "$REMOTE_DIR/config.env"
  rm -f "$config_tmp"
  copy_to "$pc" "$SCRIPT_DIR/node.sh" "$REMOTE_DIR/node.sh"
}

run_node() {
  local pc="$1" stage="$2" root="$(remote_dir)"
  msg "$pc :: $stage"
  push_node "$pc" || return 1
  # -tt lets remote sudo prompt interactively, unlike SSH-stdin heredocs.
  ssh -tt "${SSH_OPTS[@]}" "${LAB_USER}@$(ip_of "$pc")" \
    "sudo bash '$root/node.sh' '$pc' '$stage'"
}

check_ssh() {
  local pc="$1" expect ip
  ip="$(ip_of "$pc")"
  msg "$pc :: SSH $ip"
  ssh_host "$pc" 'printf "hostname="; hostname; printf "os="; . /etc/os-release; echo "$ID $VERSION_ID"; printf "user="; whoami; command -v sudo >/dev/null'
}

preflight() {
  ip -4 -o addr show | grep -Fq " $PC2_MGMT_IP/" || { echo "This machine is not PC2 ($PC2_MGMT_IP)" >&2; exit 2; }
  for p in PC1 PC3 PC4 PC5 PC6 PC7; do check_ssh "$p"; done
  msg 'Check PC2 controller address'
  ip -4 -br addr
  echo 'Verify this machine is PC2. Confirm SSH host fingerprints before first use.'
  for p in PC1 PC3 PC4 PC5 PC6; do run_node "$p" preflight; done
}
install_all() {
  for p in PC1 PC3 PC4 PC5 PC6; do run_node "$p" install; done
}
keys() {
  for p in PC3 PC4 PC5 PC6; do run_node "$p" wg-key; done
  local keyfile="$SCRIPT_DIR/wireguard-public.env" pc k
  : > "$keyfile"; chmod 600 "$keyfile"
  for pc in PC3 PC4 PC5 PC6; do
    k="$(ssh_host "$pc" "cat ~/$REMOTE_DIR/outgoing/wg-public.key")"
    [[ "$k" =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "Invalid WireGuard public key from $pc" >&2; exit 1; }
    printf '%s_PUB=%q\n' "$pc" "$k" >> "$keyfile"
  done
  msg 'WireGuard public keys recorded (private keys remain on their own PCs)'
}
network() {
  [[ -f "$SCRIPT_DIR/wireguard-public.env" ]] || { echo 'Run keys first' >&2; exit 2; }
  run_node PC3 wg-hub
  for p in PC4 PC5 PC6; do run_node "$p" wg-spoke; done
  for p in PC4 PC5 PC6; do run_node "$p" wg-check; done
  run_node PC3 wg-guard
  msg 'WireGuard peers and PC3 guard configured. PC6 egress is NOT locked yet.'
}

TMP_WORK=''
cleanup() { [[ -z "$TMP_WORK" ]] || rm -rf "$TMP_WORK"; }
trap cleanup EXIT
prepare_transfer() { TMP_WORK="$(mktemp -d)"; chmod 700 "$TMP_WORK"; }
transfer() {
  local from="$1" source_file="$2" to="$3" dest_file="$4"
  mkdir -p "$TMP_WORK/transfer"
  copy_from "$from" "$REMOTE_DIR/outgoing/$source_file" "$TMP_WORK/transfer/$source_file"
  copy_to "$to" "$TMP_WORK/transfer/$source_file" "$REMOTE_DIR/incoming/$dest_file"
  rm -f "$TMP_WORK/transfer/$source_file"
}
control() { run_node PC1 control; }
site() {
  prepare_transfer
  run_node PC3 site-csr
  transfer PC3 site-client.csr.pem PC1 site-client.csr.pem
  run_node PC1 enroll-site
  for f in site-client-cert.pem site-ca.pem site-controller.jwt sensor-ca.pem sensor-ingress-server.pem sensor-ingress-server-key.pem; do
    transfer PC1 "$f" PC3 "$f"
  done
  run_node PC3 site-start
  run_node PC1 cleanup-exchange
  run_node PC3 cleanup-exchange
  cleanup; TMP_WORK=''
}
sensors() {
  prepare_transfer
  # Enroll all three sensors before starting collectors.
  for p in PC3 PC5 PC4; do
    run_node "$p" sensor-csr
    transfer "$p" sensor-client.csr.pem PC1 "$p-sensor-client.csr.pem"
    run_node PC1 "enroll-$p"
    transfer PC1 "$p-sensor-client-cert.pem" "$p" sensor-client-cert.pem
    transfer PC1 sensor-ca.pem "$p" sensor-ca.pem
    run_node "$p" sensor-install
  done
  run_node PC3 sensor-start
  run_node PC5 victim-start
  run_node PC4 victim-start
  msg 'Waiting for sensor trust reconciliation...'
  sleep 25
  run_node PC5 collector-start
  run_node PC4 collector-start
  for p in PC1 PC3 PC4 PC5; do run_node "$p" cleanup-exchange; done
  cleanup; TMP_WORK=''
}
register() { run_node PC1 register-router; }
status() {
  local failure=0
  for p in PC1 PC3 PC4 PC5 PC6; do
    if ! run_node "$p" status; then failure=1; echo "FAIL: $p status" >&2; fi
  done
  [[ "$failure" -eq 0 ]] || { echo 'Some status checks failed.' >&2; return 1; }
}
lockdown() {
  ip -4 -o addr show | grep -Fq " $PC2_MGMT_IP/" || { echo 'Lockdown can only be launched from PC2' >&2; exit 2; }
  echo 'PC6 loses ordinary management-LAN egress. PC2 management SSH responses and WireGuard transport remain allowed.'
  echo 'WARNING: physical console access to PC6 is necessary for emergency recovery.'
  [[ "${MON_LAB_CONFIRM_PC6_LOCKDOWN:-}" == 'YES' ]] || { echo 'Set MON_LAB_CONFIRM_PC6_LOCKDOWN=YES to proceed' >&2; exit 2; }
  run_node PC6 lockdown
}
teardown() {
  [[ "${MON_LAB_CONFIRM_TEARDOWN:-}" == 'YES' ]] || { echo 'Set MON_LAB_CONFIRM_TEARDOWN=YES to proceed' >&2; exit 2; }
  for p in PC6 PC4 PC5 PC3 PC1; do run_node "$p" teardown; done
}
case "$CMD" in
  preflight) preflight ;;
  install) install_all ;;
  keys) keys ;;
  network) network ;;
  control) control ;;
  site) site ;;
  sensors) sensors ;;
  register) register ;;
  status) status ;;
  lockdown) lockdown ;;
  teardown) teardown ;;
  all) install_all; keys; network; control; site; sensors; register; status ;;
esac
