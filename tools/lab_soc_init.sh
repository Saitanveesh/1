#!/usr/bin/env bash
# Lab-only bootstrap for MON control plane + database, no auth bypass.
# Creates disposable RS256 trust and scoped tokens on the chosen SOC host.
# It does not start network attacks, expose MON to the campus, or contact switches.
set -Eeuo pipefail
umask 077
fail() { printf 'MON SOC LAB SETUP: %s\n' "$*" >&2; exit 2; }

[ "${MON_LOCAL_SOC_CONFIRMED:-}" = "YES" ] ||
  fail "set MON_LOCAL_SOC_CONFIRMED=YES only on an authorized lab management host"
[ "$(id -u)" -ne 0 ] ||
  fail "run as ordinary Ubuntu user; use sudo only for docker compose"
for tool in openssl git python3; do
  command -v "$tool" >/dev/null || fail "install $tool first"
done

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
[ -x "$PYTHON" ] || fail "first create .venv and run .venv/bin/pip install -e ."
DEPLOY="$ROOT/deploy/four-pc"
TENANT="${MON_LAB_TENANT:-mon-lab}"
SITE="${MON_LAB_SITE:-isolated-range}"
SECRETS="${MON_LAB_SECRETS_DIR:-$HOME/.local/share/mon-soc-lab-identity}"
[[ "$TENANT" =~ ^[a-z0-9][a-z0-9_-]{1,63}$ ]] ||
  fail "invalid tenant scope"
[[ "$SITE" =~ ^[a-z0-9][a-z0-9_-]{1,63}$ ]] ||
  fail "invalid site scope"
[ ! -e "$DEPLOY/.env" ] || fail "existing deployment .env: refusing overwrite"
[ ! -e "$DEPLOY/auth/public.pem" ] || fail "existing auth key: refusing overwrite"
[ ! -e "$SECRETS" ] || fail "identity directory already exists; refusing overwrite"

mkdir -p "$(dirname "$SECRETS")"
# Tokens and the private signing key remain *outside* the Git repository.
"$PYTHON" "$ROOT/tools/lab_identity.py" init \
  --out-dir "$SECRETS" --tenant-id "$TENANT" --site-id "$SITE" \
  --site-ingress-host 127.0.0.1 \
  --sensor-ingress-host 127.0.0.1 \
  --issuer mon-lab-local-only \
  --audience mon-lab-control-plane \
  --token-hours 8

# Public verifier may be readable in a non-root container; private key cannot.
mkdir -p "$DEPLOY/auth"
openssl pkey -in "$SECRETS/auth-private.pem" -pubout \
  -out "$DEPLOY/auth/public.pem" >/dev/null
chmod 755 "$DEPLOY/auth"
chmod 644 "$DEPLOY/auth/public.pem"
chmod 700 "$SECRETS"
chmod 600 "$SECRETS"/auth-private.pem "$SECRETS"/operator.jwt \
  "$SECRETS"/site-controller.jwt

DB_SECRET="$(openssl rand -hex 24)"
cat > "$DEPLOY/.env" <<EOF
MON_DB_PASSWORD=$DB_SECRET
MON_DATABASE_URL=postgresql+psycopg://mon:$DB_SECRET@postgres:5432/mon
MON_AUTH_ISSUER=mon-lab-local-only
MON_AUTH_AUDIENCE=mon-lab-control-plane
EOF
chmod 600 "$DEPLOY/.env"

printf 'MON LOCAL SOC BOOTSTRAP: credentials prepared (no services started)\n'
printf 'Tenant/site: %s / %s\n' "$TENANT" "$SITE"
printf 'Secrets: %s (never commit or transmit raw files)\n' "$SECRETS"
printf 'Compose file: %s/compose.soc.yml\n' "$DEPLOY"
printf 'Next: cd %s && sudo docker compose -f compose.soc.yml config -q\n' "$DEPLOY"
printf 'Then: sudo docker compose -f compose.soc.yml up -d --build\n'
printf 'Operator token: %s/operator.jwt (expires in 8h).\n' "$SECRETS"
printf 'Ingest-only token: %s/site-controller.jwt (expires in 8h).\n' "$SECRETS"
printf 'The console still requires an authenticated session; no login bypass was installed.\n'
