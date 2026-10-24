#!/usr/bin/env bash
# PC-5: guarded extension of the running fictional campus lab site.
# No WireGuard, router, SSH, Suricata or non-training application is changed.
set -Eeuo pipefail
umask 077
MODE="${1:---check}"
ARCHIVE="${2:-$HOME/mon-stage4-pc5.tar.gz}"
[[ "$MODE" == --check || "$MODE" == --apply ]] || {
  echo "Usage: bash stage4-upgrade-pc5.sh --check|--apply [archive]" >&2; exit 2;
}
[[ "$(id -un)" == "pc-5" ]] || { echo "Run on the PC-5 Ubuntu computer as pc-5" >&2; exit 1; }
SITE="$HOME/mon-training-site"
SERVICE=mon-training-site.service
STAGE=""
BACKUP=""
CHANGED=0
DONE=0
log(){ printf '[PC5 IMPACT] %s\n' "$*"; }
fail(){ log "STOP: $*" >&2; exit 1; }
restore(){
  code=$?
  trap - EXIT
  if [[ "$CHANGED" == 1 && "$DONE" != 1 ]]; then
    log "Restoring the previous working training site."
    tar -xzf "$BACKUP/site.tar.gz" -C "$HOME" || true
    sudo systemctl restart "$SERVICE" || true
    log "Restore point: $BACKUP"
  fi
  [[ -z "$STAGE" ]] || rm -rf "$STAGE"
  exit "$code"
}
trap restore EXIT
for x in python3 curl tar ip; do command -v "$x" >/dev/null || fail "Missing $x"; done
[[ -s "$ARCHIVE" && -s "$SITE/server.py" && -f "$SITE/public/index.html" ]] ||
  fail "Training site/archive missing; install Stage 1 first"
ip -4 -o address show wg0 | grep -Fq '10.77.0.50/32' ||
  fail "PC-5 WireGuard IP does not match the expected training victim"
sudo systemctl is-active --quiet "$SERVICE" ||
  fail "The existing site is not running. Do not replace a failed installation."
curl --noproxy '*' -fsS --max-time 5 http://10.77.0.50:8085/health >/dev/null ||
  fail "Current victim portal is unavailable; refusing deployment"
STAGE="$(mktemp -d "$HOME/mon-stage4-site-stage.XXXXXXXX")"
tar -xzf "$ARCHIVE" -C "$STAGE" --strip-components=1
[[ -s "$STAGE/server.py" && -s "$STAGE/mon_stage4_impact.py" &&
   -s "$STAGE/public/index.html" && -s "$STAGE/test_impact.py" ]] ||
  fail "Stage 4 archive incomplete"
python3 -m py_compile "$STAGE/server.py" "$STAGE/mon_stage4_impact.py"
python3 -m unittest discover -s "$STAGE" -p 'test_site.py' ||
  fail "PC-5 website tests failed; original site untouched"
python3 -m unittest discover -s "$STAGE" -p 'test_impact.py' ||
  fail "PC-5 impact tests failed; original site untouched"
[[ "$MODE" == --apply ]] || { log "CHECK PASSED; no service modified."; DONE=1; exit 0; }
BACKUP="$(mktemp -d "$HOME/mon-stage4-pc5-rollback.XXXXXXXX")"
tar -czf "$BACKUP/site.tar.gz" -C "$HOME" mon-training-site
sha256sum "$BACKUP/site.tar.gz" > "$BACKUP/SHA256SUMS"
log "Original PC-5 website archived to $BACKUP"
CHANGED=1
cp -a "$STAGE/." "$SITE/"
sudo systemctl restart "$SERVICE"
READY=0
for attempt in 1 2 3 4 5 6 7 8 9; do
  if sudo systemctl is-active --quiet "$SERVICE" &&
    curl --noproxy '*' -fsS --max-time 3 http://10.77.0.50:8085/health |
      python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["training"] and x["version"]==4' >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || fail "New training site did not report version 4"
log "PC-5 fictional website ready, with real response-side impact ledger."
log "Impact API is restricted to PC-2 and local loopback; lab attackers cannot query it."
log "Only fake documents/student records/notices are in scope."
DONE=1
