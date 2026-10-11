#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
bash -n "$HERE/controller.sh"
bash -n "$HERE/node.sh"
bash -n "$HERE/lab.env.example"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# Deliberately invalid configuration must fail before contacting any hosts.
cat > "$tmp/lab.env" <<'CFG'
LAB_USER=lab
MON_REF=not-a-commit
PC1_MGMT_IP=192.168.99.11
PC2_MGMT_IP=192.168.99.12
PC3_MGMT_IP=192.168.99.13
PC4_MGMT_IP=192.168.99.14
PC5_MGMT_IP=192.168.99.15
PC6_MGMT_IP=192.168.99.16
PC7_MGMT_IP=192.168.99.17
CFG
if MON_LAB_CONFIG="$tmp/lab.env" bash "$HERE/controller.sh" preflight >"$tmp/out" 2>&1; then
  echo 'FAIL: invalid SHA accepted' >&2; exit 1
fi
grep -q '40-char Git SHA' "$tmp/out"
sed -i 's/MON_REF=not-a-commit/MON_REF=8f66baa9f8d287b8c05da379259b289c661c5828/' "$tmp/lab.env"
sed -i 's/PC3_MGMT_IP=192.168.99.13/PC3_MGMT_IP=192.168.99.12/' "$tmp/lab.env"
if MON_LAB_CONFIG="$tmp/lab.env" bash "$HERE/controller.sh" install >"$tmp/out" 2>&1; then
  echo 'FAIL: duplicate addresses accepted' >&2; exit 1
fi
grep -q 'duplicates' "$tmp/out"
sed -i 's/PC3_MGMT_IP=192.168.99.12/PC3_MGMT_IP=192.168.99.300/' "$tmp/lab.env"
if MON_LAB_CONFIG="$tmp/lab.env" bash "$HERE/controller.sh" install >"$tmp/out" 2>&1; then
  echo 'FAIL: invalid IPv4 accepted' >&2; exit 1
fi
grep -q 'Invalid PC3_MGMT_IP' "$tmp/out"
# A failed validation must never touch a remote host.
echo 'PASS: scripts parse and malformed config is rejected before SSH'

