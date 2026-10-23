#!/usr/bin/env bash
# PC-5 lab-only fictional campus site. Back up service unit before installation.
set -Eeuo pipefail
umask 077
SITE=/home/pc-5/mon-training-site
UNIT=/etc/systemd/system/mon-training-site.service
BACKUP="$HOME/mon-training-site-backup-$(date +%Y%m%d-%H%M%S)"
[[ "$(id -un)" == pc-5 ]] || { echo 'Run as pc-5 on PC-5'; exit 1; }
[[ -f "$SITE/server.py" && -f "$SITE/public/index.html" ]] || {
  echo "Extract the PC5 training-site archive into $SITE first"; exit 1;
}
ip -4 -o address show wg0 | grep -Fq '10.77.0.50/32' || {
  echo 'PC-5 wg0 is not 10.77.0.50/32; refusing wrong-machine deployment'; exit 1;
}
python3 -m unittest discover -s "$SITE" -p 'test_site.py' || exit 1
sudo -v
mkdir -p "$BACKUP"
if [[ -f "$UNIT" ]]; then sudo cp -a "$UNIT" "$BACKUP/previous.service"; fi
sudo tee "$UNIT" >/dev/null <<'EOF'
[Unit]
Description=MON fictional campus lab website, PC-5 wg0 only
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=pc-5
Group=pc-5
WorkingDirectory=/home/pc-5/mon-training-site
Environment=MON_TRAINING_BIND=10.77.0.50
Environment=MON_TRAINING_PORT=8085
ExecStart=/usr/bin/python3 /home/pc-5/mon-training-site/server.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=full
PrivateTmp=yes
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable mon-training-site.service
sudo systemctl restart mon-training-site.service
for i in 1 2 3 4 5; do
  if curl --noproxy '*' -fsS --max-time 2 http://10.77.0.50:8085/health >/dev/null; then
    echo 'PC-5 fictional website READY at http://10.77.0.50:8085/'
    echo "Previous unit backup: $BACKUP"
    exit 0
  fi
  sleep 1
done
if [[ -f "$BACKUP/previous.service" ]]; then
  sudo cp -a "$BACKUP/previous.service" "$UNIT"
else
  sudo systemctl disable --now mon-training-site.service || true
  sudo rm -f "$UNIT"
fi
sudo systemctl daemon-reload
sudo journalctl -u mon-training-site.service --no-pager -n 20
echo 'PC-5 site startup failed; previous unit restored.'
exit 1
