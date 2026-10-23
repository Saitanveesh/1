#!/usr/bin/env bash
# PC-5: update the already-running fictional training site (not host services).
# No WireGuard, firewall, database, or other application changes.
set -Eeuo pipefail
umask 077
ARCHIVE="${1:-$HOME/mon-batch1-pc5-site-v2.tar.gz}"
SITE=/home/pc-5/mon-training-site
SERVICE=mon-training-site.service
STAGE=""
BACKUP=""
TOUCHED=0
SUCCESS=0
log(){ echo "[PC5 TRAINING] $*"; }
fail(){ log "STOP: $*"; exit 1; }
restore(){
  code=$?
  trap - EXIT
  if [[ "$TOUCHED" == 1 && "$SUCCESS" != 1 ]]; then
    log "Upgrade failed, restoring previous website."
    sudo systemctl stop "$SERVICE" || true
    tar -xzf "$BACKUP/site.tar.gz" -C /home/pc-5 || true
    sudo systemctl start "$SERVICE" || true
    log "Old site restored from $BACKUP"
  fi
  [[ -z "$STAGE" ]] || rm -rf "$STAGE"
  exit "$code"
}
trap restore EXIT
[[ "$(id -un)" == "pc-5" ]] || fail "Run as pc-5 on PC-5"
[[ -f "$ARCHIVE" && -f "$SITE/server.py" && -f "$SITE/public/index.html" ]] ||
  fail "Existing website or V2 archive is missing"
ip -4 -o address show wg0 | grep -Fq '10.77.0.50/32' ||
  fail "This host is not the expected PC-5 overlay endpoint"
sudo -v
sudo systemctl is-active --quiet "$SERVICE" || fail "Old training website is down; not replacing"
curl --noproxy '*' -fsS --max-time 5 http://10.77.0.50:8085/health >/dev/null ||
  fail "Old website health check failed"
STAGE="$(mktemp -d "$HOME/mon-training-v2-stage.XXXXXXXX")"
tar -xzf "$ARCHIVE" -C "$STAGE" --strip-components=1
[[ -f "$STAGE/server.py" && -f "$STAGE/public/app.js" &&
   -f "$STAGE/public/app.css" ]] || fail "Archive missing expected components"
python3 -m py_compile "$STAGE/server.py"
python3 -m unittest discover -s "$STAGE" -p 'test_site.py'
BACKUP="$(mktemp -d "$HOME/mon-training-v2-rollback.XXXXXXXX")"
tar -czf "$BACKUP/site.tar.gz" -C /home/pc-5 mon-training-site
sha256sum "$BACKUP/site.tar.gz" > "$BACKUP/checksums.sha256"
log "Existing PC5 website restore point: $BACKUP"
TOUCHED=1
cp -a "$STAGE/." "$SITE/"
sudo systemctl restart "$SERVICE"
READY=0
for i in 1 2 3 4 5 6 7 8; do
  if curl --noproxy '*' -fsS --max-time 3 http://10.77.0.50:8085/health |
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["status"]=="READY" and d["version"]==2' >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || fail "New PC5 site failed readiness check"
curl --noproxy '*' -fsS --max-time 5 http://10.77.0.50:8085/app.js |
  grep -Fq "notice-form" || fail "Frontend script not served"
curl --noproxy '*' -fsS --max-time 5 http://10.77.0.50:8085/api/notices?q=timetable |
  python3 -c 'import json,sys; assert json.load(sys.stdin)["count"]==1' ||
  fail "Expected real HTTP notice endpoint not working"
log "PC5 training website V2 READY: http://10.77.0.50:8085/"
log "Only fake in-memory and fixture records are exposed. Backup: $BACKUP"
SUCCESS=1
