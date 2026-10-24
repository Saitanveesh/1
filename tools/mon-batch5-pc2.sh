#!/usr/bin/env bash
# Batch 5 PC-2: only change the operator console's explanatory user interface.
# Never mutate the portal, WireGuard peers, IDS, control plane or firewall.
set -Eeuo pipefail
umask 077

MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--apply" ]] || {
  echo "Usage: bash mon-batch5-pc2.sh --check|--apply" >&2
  exit 2
}
[[ "$(id -un)" == "pc-2" ]] || {
  echo "Run as the pc-2 user on PC-2" >&2
  exit 1
}

ROOT="$HOME/mon-three"
WEB="$ROOT/console-v2"
CODE="$HOME/mon-three-code"
BRANCH="feature/mon-batch5-plain-language-20261024"
REPO="https://github.com/Saitanveesh/1.git"
FRONTEND="mon-three-console-v2.service"
PORTAL="mon-three-lab-portal.service"
GATE="mon-stage4-gate.service"
FILES=(App.tsx DemoGuide.tsx DemoGuide.css DemoGuide.test.tsx)
STAGE=""
BACKUP=""
TOUCHED=0
COMPLETE=0

log() { printf '[BATCH5 UI] %s\n' "$*"; }
fail() { log "STOP: $*" >&2; exit 1; }

restore() {
  local status=$?
  trap - EXIT
  if [[ "$TOUCHED" == 1 && "$COMPLETE" != 1 ]]; then
    log "Patch did not finish. Restoring the previous frontend."
    for name in "${FILES[@]}"; do
      if [[ -f "$BACKUP/$name" ]]; then
        cp -a "$BACKUP/$name" "$WEB/src/$name" || true
      else
        rm -f "$WEB/src/$name" || true
      fi
    done
    ( cd "$WEB" && npm run build ) || true
    sudo systemctl restart "$FRONTEND" || true
    log "Frontend restore point: $BACKUP"
  fi
  [[ -z "$STAGE" ]] || rm -rf "$STAGE"
  exit "$status"
}
trap restore EXIT

for item in git node npm python3 curl tar sudo; do
  command -v "$item" >/dev/null || fail "Required program missing: $item"
done
[[ -d "$CODE/.git" && -f "$WEB/src/App.tsx" &&
  -x "$WEB/node_modules/.bin/tsc" ]] ||
  fail "Existing Stage 4 operator console not found"
sudo -v
for service in "$FRONTEND" "$PORTAL" "$GATE"; do
  sudo systemctl is-active --quiet "$service" ||
    fail "Prerequisite service is not active: $service"
done
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/ >/dev/null ||
  fail "Existing frontend unavailable; refusing to replace it"
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8088/portal/health >/dev/null ||
  fail "Existing portal unavailable; refusing to change console"

git -C "$CODE" fetch --no-tags "$REPO" "refs/heads/$BRANCH" ||
  fail "Could not fetch the Batch 5 release branch"
REV="$(git -C "$CODE" rev-parse FETCH_HEAD)"
STAGE="$(mktemp -d "$ROOT/mon-batch5-stage.XXXXXXXX")"
git -C "$CODE" archive "$REV" console | tar -xf - -C "$STAGE"
for name in "${FILES[@]}"; do
  [[ -s "$STAGE/console/src/$name" ]] ||
    fail "Required Batch 5 file missing from staged revision: $name"
done
ln -s "$WEB/node_modules" "$STAGE/console/node_modules"
(
  cd "$STAGE/console" || exit 1
  npm run build || exit 1
  npm test -- --run || exit 1
) || fail "Batch 5 frontend did not pass build/tests. Existing console unchanged."
log "Staged revision $REV: production build and browser component tests passed."
if [[ "$MODE" == "--check" ]]; then
  log "CHECK PASSED: no running service or network policy modified."
  COMPLETE=1
  exit 0
fi

BACKUP="$(mktemp -d "$ROOT/mon-batch5-backup.XXXXXXXX")"
for name in "${FILES[@]}"; do
  if [[ -f "$WEB/src/$name" ]]; then
    cp -a "$WEB/src/$name" "$BACKUP/$name"
  fi
done
log "Previous frontend source saved: $BACKUP"
TOUCHED=1
for name in "${FILES[@]}"; do
  cp -a "$STAGE/console/src/$name" "$WEB/src/$name"
done
( cd "$WEB" && npm run build ) || fail "Installed frontend build failed"
sudo systemctl restart "$FRONTEND"

READY=0
for attempt in 1 2 3 4 5 6 7 8; do
  if sudo systemctl is-active --quiet "$FRONTEND" &&
    curl --noproxy '*' -fsS --max-time 4 http://127.0.0.1:5174/ >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || fail "New frontend did not pass health check"

sudo systemctl is-active --quiet "$PORTAL" ||
  fail "Existing portal became unavailable"
sudo systemctl is-active --quiet "$GATE" ||
  fail "Existing Stage 4 firewall helper became unavailable"
log "APPLY PASSED: explanatory rail installed on Dashboard, Alerts, Cases, Investigation."
log "Portal, firewall, IDS and WireGuard unchanged."
log "Open http://100.75.116.62:5174/?tenant=mon-lab&site=site-a"
log "Restore point: $BACKUP"
COMPLETE=1
