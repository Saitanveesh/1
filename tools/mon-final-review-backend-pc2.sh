#!/usr/bin/env bash
# MON final-stage compatibility check for the existing PC-2 alert-review API.
# No WireGuard, Suricata, case DB, PC5, PC6 or PC7 modifications.
set -Eeuo pipefail
umask 077
MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--apply" ]] || { echo "Usage: $0 --check|--apply" >&2; exit 2; }
[[ "$(id -un)" == pc-2 ]] || { echo "Run as pc-2 on PC-2" >&2; exit 1; }

ROOT="$HOME/mon-three"
CODE="$HOME/mon-three-code"
TOOLS="$ROOT/tools"
UNIT=mon-three-lab-portal.service
PORTAL="$TOOLS/mon-lab-portal.py"
JOURNAL_MODULE="$TOOLS/mon_alert_ack.py"
ALERT_DIR="$ROOT/alerts"
DROPIN=/etc/systemd/system/mon-three-lab-portal.service.d/mon-final-review.conf
REMOTE=https://github.com/Saitanveesh/1.git
BRANCH=feature/mon-final-console-20261023
STAGE=""
BACKUP=""
CHANGED=0
GOOD=0
log(){ printf '[MON REVIEW] %s\n' "$*"; }
fail(){ log "STOP: $*" >&2; exit 1; }
rollback(){
  status=$?
  trap - EXIT
  if [[ "$CHANGED" == 1 && "$GOOD" != 1 ]]; then
    log "Review endpoint upgrade failed; restoring the old portal files."
    [[ ! -f "$BACKUP/portal.py" ]] || cp -a "$BACKUP/portal.py" "$PORTAL"
    if [[ -f "$BACKUP/ack.py" ]]; then cp -a "$BACKUP/ack.py" "$JOURNAL_MODULE"; else rm -f "$JOURNAL_MODULE"; fi
    if [[ -f "$BACKUP/dropin.conf" ]]; then sudo cp -a "$BACKUP/dropin.conf" "$DROPIN"; else sudo rm -f "$DROPIN"; fi
    sudo systemctl daemon-reload || true
    sudo systemctl restart "$UNIT" || true
    log "Existing portal restored from $BACKUP"
  fi
  [[ -z "$STAGE" ]] || rm -rf "$STAGE"
  exit "$status"
}
trap rollback EXIT

[[ -f "$PORTAL" && -d "$CODE/.git" && -s "$ROOT/identity/operator.jwt" ]] ||
  fail "MON portal installation or identity is missing."
for cmd in git python3 sudo curl; do command -v "$cmd" >/dev/null || fail "Missing $cmd"; done
sudo -v
sudo systemctl is-active --quiet "$UNIT" || fail "Existing portal is not running; no upgrade attempted."
curl -fsS --max-time 6 http://127.0.0.1:8088/portal/health >/dev/null ||
  fail "Existing portal health check failed."

# Avoid printing credentials. This is a read-only check against the real portal.
check_review(){
  ROOT_DIR="$ROOT" python3 - <<'PY'
import json,os,pathlib,urllib.request
root=pathlib.Path(os.environ["ROOT_DIR"])
token=(root/"identity/operator.jwt").read_text().strip()
request=urllib.request.Request(
    "http://127.0.0.1:8088/portal/alerts/acknowledged",
    headers={"Cookie":"mon_session="+token})
try:
    with urllib.request.urlopen(request,timeout=5) as response:
        data=json.load(response)
    assert isinstance(data.get("records"),list)
except Exception:
    raise SystemExit(1)
PY
}

if check_review; then
  log "Alert-review API already working. No backend changes necessary."
  GOOD=1
  exit 0
fi
log "Alert-review endpoint is missing or unverified. A compatibility update is required."
if [[ "$MODE" == "--check" ]]; then
  log "No changes made. Run --apply to add the reviewed endpoint with a rollback checkpoint."
  GOOD=1
  exit 0
fi

# Verify that the service really executes this portal path before replacing code.
sudo systemctl cat "$UNIT" | grep -Fq "mon-lab-portal.py" ||
  fail "Unknown portal service layout; refusing to replace it."
git -C "$CODE" fetch --no-tags "$REMOTE" "refs/heads/$BRANCH"
REV="$(git -C "$CODE" rev-parse FETCH_HEAD)"
STAGE="$(mktemp -d "$ROOT/mon-review-stage.XXXXXXXX")"
git -C "$CODE" archive "$REV" tools/mon-lab-portal.py tools/mon_alert_ack.py |
  tar -xf - -C "$STAGE"
python3 -m py_compile "$STAGE/tools/mon-lab-portal.py" "$STAGE/tools/mon_alert_ack.py" ||
  fail "Staged portal syntax invalid."
grep -Fq '/portal/alerts/acknowledge' "$STAGE/tools/mon-lab-portal.py" ||
  fail "The staged portal lacks the review route."
grep -Fq 'acknowledge_eve_alert' "$STAGE/tools/mon_alert_ack.py" ||
  fail "The staged review journal is not evidence-bound."

BACKUP="$(mktemp -d "$ROOT/mon-review-rollback.XXXXXXXX")"
cp -a "$PORTAL" "$BACKUP/portal.py"
[[ ! -f "$JOURNAL_MODULE" ]] || cp -a "$JOURNAL_MODULE" "$BACKUP/ack.py"
[[ ! -f "$DROPIN" ]] || sudo cp -a "$DROPIN" "$BACKUP/dropin.conf"
log "Old portal backed up to $BACKUP"

CHANGED=1
sudo install -d -o pc-2 -g pc-2 -m 0700 "$ALERT_DIR"
cp -a "$STAGE/tools/mon-lab-portal.py" "$PORTAL"
cp -a "$STAGE/tools/mon_alert_ack.py" "$JOURNAL_MODULE"
sudo install -d -m 0755 /etc/systemd/system/mon-three-lab-portal.service.d
sudo tee "$DROPIN" >/dev/null <<EOF
[Service]
ReadWritePaths=$ALERT_DIR
Environment=MON_ALERT_ACK_PATH=$ALERT_DIR/acknowledged.jsonl
Environment=MON_PORTAL_ALLOWED_ORIGINS=http://100.75.116.62:5174,http://100.75.116.62:5173
EOF
sudo systemctl daemon-reload
sudo systemctl restart "$UNIT"
for i in 1 2 3 4 5 6 7 8; do
  if sudo systemctl is-active --quiet "$UNIT" &&
    curl -fsS --max-time 3 http://127.0.0.1:8088/portal/health >/dev/null 2>&1 &&
    check_review; then
    log "Review endpoint working. Operator review journal is private."
    log "No MON data or WireGuard/Suricata changes were made."
    log "Backup: $BACKUP"
    GOOD=1
    exit 0
  fi
  sleep 2
done
fail "Review endpoint failed post-install verification."
