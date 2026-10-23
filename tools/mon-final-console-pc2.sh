#!/usr/bin/env bash
# MON final interface rollout for the existing PC-2 operator portal.
# Only ~/mon-three/console-v2 and mon-three-console-v2.service are changed.
# This never updates WireGuard, nftables, Suricata, PC5, PC6, PC7 or MON's DB.
set -Eeuo pipefail
umask 077

MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--apply" ]] || {
  printf 'Usage: bash mon-final-console-pc2.sh --check | --apply\n' >&2
  exit 2
}
[[ "$(id -un)" == "pc-2" ]] || { echo "Run as pc-2 on PC-2" >&2; exit 1; }

REPOSITORY=https://github.com/Saitanveesh/1.git
BRANCH=feature/mon-final-console-20261023
ROOT="$HOME/mon-three"
CODE="$HOME/mon-three-code"
WEB="$ROOT/console-v2"
SERVICE=mon-three-console-v2.service
STAGE=""
BACKUP=""
UPDATED=0
DONE=0

say(){ printf '[MON FINAL] %s\n' "$*"; }
fail(){ say "ERROR: $*" >&2; exit 1; }
rollback(){
  code=$?
  trap - EXIT
  if [[ "$UPDATED" == 1 && "$DONE" != 1 ]]; then
    say "Frontend update failed. Restoring the saved working interface."
    if [[ -s "$BACKUP/console-v2.tar.gz" ]]; then
      tar -xzf "$BACKUP/console-v2.tar.gz" -C "$ROOT" || true
      sudo systemctl restart "$SERVICE" || true
    fi
    say "Previous interface restore point: $BACKUP"
  fi
  [[ -z "$STAGE" ]] || rm -rf "$STAGE"
  exit "$code"
}
trap rollback EXIT

for tool in git tar node npm python3 curl sudo; do
  command -v "$tool" >/dev/null || fail "Missing $tool"
done
[[ -d "$CODE/.git" && -f "$WEB/src/App.tsx" && -f "$WEB/package.json" ]] ||
  fail "Expected existing MON frontend is missing."
[[ -d "$WEB/node_modules" ]] || fail "Frontend dependencies are missing. Do not overwrite the running UI."
sudo -v
sudo systemctl is-active --quiet "$SERVICE" || fail "Existing MON console service is not active."
curl -fsS --max-time 6 http://127.0.0.1:5174/ >/dev/null ||
  fail "Existing MON console health check failed; refusing upgrade."
say "Existing operator console is active and reachable."
say "This script does not change WireGuard, Suricata, any other MON service, or stored cases."

git -C "$CODE" fetch --no-tags "$REPOSITORY" "refs/heads/$BRANCH" ||
  fail "Cannot fetch the final console branch"
REV="$(git -C "$CODE" rev-parse FETCH_HEAD)"
STAGE="$(mktemp -d "$ROOT/mon-final-stage.XXXXXXXX")"
git -C "$CODE" archive "$REV" console | tar -xf - -C "$STAGE"
[[ -s "$STAGE/console/src/AlertCenter.tsx" &&
   -s "$STAGE/console/src/AlertInvestigation.tsx" &&
   -s "$STAGE/console/src/FinalConsole.css" ]] ||
  fail "Staged revision does not contain the expected operator workflow."

ln -s "$WEB/node_modules" "$STAGE/console/node_modules"
say "Validating code from GitHub commit $REV"
(
  cd "$STAGE/console"
  npm run build
  npm test -- --run
) || fail "Frontend build or regression tests failed. Existing console unchanged."

if [[ "$MODE" == "--check" ]]; then
  say "PRECHECK PASSED. Existing console was not modified."
  say "To install: bash mon-final-console-pc2.sh --apply"
  DONE=1
  exit 0
fi

BACKUP="$(mktemp -d "$ROOT/mon-final-rollback.XXXXXXXX")"
tar -czf "$BACKUP/console-v2.tar.gz" \
  --exclude='console-v2/node_modules' \
  -C "$ROOT" console-v2
sha256sum "$BACKUP/console-v2.tar.gz" > "$BACKUP/SHA256SUMS"
say "Current working interface backed up to $BACKUP"

UPDATED=1
# Retain existing private config, npm dependencies and service definitions.
tar -C "$STAGE/console" --exclude=node_modules --exclude=dist -cf - . |
  tar -C "$WEB" -xf -
(
  cd "$WEB"
  npm run build
)
sudo systemctl restart "$SERVICE"
READY=0
for i in 1 2 3 4 5 6 7 8; do
  if sudo systemctl is-active --quiet "$SERVICE" &&
    curl -fsS --max-time 5 http://127.0.0.1:5174/ >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 2
done
[[ "$READY" == 1 ]] || fail "New interface did not become available. Attempting restore."
# No case or sensor data fabricated as part of deployment.
say "MON final operator console READY"
say "Visit: http://100.75.116.62:5174/?tenant=mon-lab&site=site-a"
say "Verify Dashboard, Alerts, Cases, Investigation, and alert review from live PC5 events."
say "Saved recovery checkpoint: $BACKUP"
say "No VPN, IDS, database, PC5, PC6 or PC7 changes."
DONE=1
