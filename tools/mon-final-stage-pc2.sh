#!/usr/bin/env bash
# One guarded final-stage rollout for existing PC-2 MON.
# Runs backend compatibility only when review endpoint is missing, then UI.
set -Eeuo pipefail
umask 077
MODE="${1:---apply}"
[[ "$MODE" == "--check" || "$MODE" == "--apply" ]] || { echo "Usage: $0 --check|--apply"; exit 2; }
[[ "$(id -un)" == pc-2 ]] || { echo "Run as pc-2 on PC-2"; exit 1; }
ROOT="$HOME/mon-three"
CODE="$HOME/mon-three-code"
REPO=https://github.com/Saitanveesh/1.git
BRANCH=feature/mon-final-console-20261023
[[ -d "$CODE/.git" && -d "$ROOT" ]] || { echo "MON installation not found"; exit 1; }
STAGE="$(mktemp -d "$ROOT/mon-final-run.XXXXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
git -C "$CODE" fetch --no-tags "$REPO" "refs/heads/$BRANCH"
REV="$(git -C "$CODE" rev-parse FETCH_HEAD)"
git -C "$CODE" show "$REV:tools/mon-final-review-backend-pc2.sh" > "$STAGE/review.sh"
git -C "$CODE" show "$REV:tools/mon-final-console-pc2.sh" > "$STAGE/console.sh"
bash -n "$STAGE/review.sh" "$STAGE/console.sh"
echo "[MON FINAL] Staged $REV"
if [[ "$MODE" == "--check" ]]; then
  bash "$STAGE/review.sh" --check
  echo "[MON FINAL] If review backend is missing, frontend --check will require the compatibility step first."
  # This may intentionally fail when the server is still missing the endpoint.
  bash "$STAGE/console.sh" --check
else
  bash "$STAGE/review.sh" --apply
  bash "$STAGE/console.sh" --check
  bash "$STAGE/console.sh" --apply
  echo "[MON FINAL] Final stage installed: Dashboard, Alerts, Cases and Investigation."
  echo "[MON FINAL] Hard refresh http://100.75.116.62:5174/?tenant=mon-lab\&site=site-a"
fi
