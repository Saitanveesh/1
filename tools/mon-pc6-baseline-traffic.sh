#!/usr/bin/env bash
# Controlled three-PC MON lab: low-rate benign baseline traffic from PC6 to PC5.
# This intentionally never runs SSH authentication attempts or attack tooling.
set -euo pipefail
UNIT=mon-pc6-baseline-icmp.service
FILE="/etc/systemd/system/$UNIT"
SRC=10.77.0.60
DST=10.77.0.50

[[ "$(id -un)" != root ]] || { echo '[FAIL] Run as ordinary PC6 user, not root'; exit 1; }
command -v ping >/dev/null || { echo '[FAIL] ping is required on PC6'; exit 1; }
command -v systemctl >/dev/null || { echo '[FAIL] systemd required'; exit 1; }
route=$(ip -4 route get "$DST") || { echo '[FAIL] No route to PC5'; exit 1; }
[[ "$route" == *"src $SRC"* ]] || {
  echo "[FAIL] PC6 should use source $SRC to reach PC5; actual route is: $route"
  exit 1
}
if systemctl is-active --quiet "$UNIT"; then
  echo "[PASS] $UNIT already active, no duplicate generator started"
  echo "Stop: sudo systemctl disable --now $UNIT"
  exit 0
fi
if sudo test -e "$FILE"; then
  echo "[FAIL] $FILE already exists but service is not active. Inspect it before replacing."
  exit 1
fi

sudo tee "$FILE" >/dev/null <<EOF
[Unit]
Description=MON lab baseline ICMP traffic PC6 to PC5 (benign)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/sys/class/net/wg0

[Service]
Type=simple
User=$(id -un)
Group=$(id -gn)
ExecStart=$(command -v ping) -n -I $SRC -i 2 -W 1 -s 32 $DST
Restart=always
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StandardOutput=null
StandardError=journal
SyslogIdentifier=mon-baseline-icmp

[Install]
WantedBy=multi-user.target
EOF
sudo chmod 0644 "$FILE"
sudo systemctl daemon-reload
sudo systemctl enable --now "$UNIT"
if ! sudo systemctl is-active --quiet "$UNIT"; then
  echo '[FAIL] Baseline traffic service did not start; view journalctl -u mon-pc6-baseline-icmp'
  exit 1
fi
echo "[PASS] PC6 sends one benign ICMP echo toward PC5 every 2 seconds"
echo "[CHECK] This is a SYNTHETIC BASELINE TRAFFIC GENERATOR, not attacker activity"
echo "[CHECK] If PC2 capture still reports zero, inspect wg0 AF_PACKET capture path; don't invent packets"
echo "Stop: sudo systemctl disable --now $UNIT"
echo "Status: systemctl status $UNIT --no-pager"
