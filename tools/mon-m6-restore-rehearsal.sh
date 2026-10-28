#!/usr/bin/env bash
# PC-2 only. Restore a pg_dump custom archive into disposable network-isolated PostgreSQL.
# Existing MON PostgreSQL, named volume, containers, network and services are read-only.
set -Eeuo pipefail
umask 077

usage() {
  printf 'Usage: bash %s /path/to/backup.dump 64_CHARACTER_SHA256\n' "$0" >&2
}
if [[ $# -ne 2 ]]; then usage; exit 2; fi
if [[ $(id -un) != pc-2 ]]; then
  echo '[FAIL] Run as pc-2 on PC-2, not with sudo bash.' >&2
  exit 1
fi
BACKUP=$(realpath -e -- "$1") || { echo '[FAIL] Backup not found.' >&2; exit 1; }
EXPECTED_SHA=$2
if [[ ! $EXPECTED_SHA =~ ^[0-9a-f]{64}$ ]]; then
  echo '[FAIL] Expected SHA-256 must be 64 lowercase hexadecimal characters.' >&2
  exit 2
fi
if [[ ! -f $BACKUP || ! -s $BACKUP ]]; then
  echo '[FAIL] Backup is empty or not a regular file.' >&2
  exit 1
fi
printf '%s  %s\n' "$EXPECTED_SHA" "$BACKUP" | sha256sum --check --status || {
  echo '[FAIL] Backup checksum mismatch. Nothing started.' >&2
  exit 1
}

SOURCE=mon-three-postgres
if ! sudo docker container inspect "$SOURCE" >/dev/null 2>&1; then
  echo '[FAIL] Existing MON database container missing; refusing replacement.' >&2
  exit 1
fi
if [[ $(sudo docker inspect -f '{{.State.Running}}' "$SOURCE") != true ]]; then
  echo '[FAIL] Existing MON database is not running; no changes made.' >&2
  exit 1
fi
IMAGE=$(sudo docker inspect -f '{{.Config.Image}}' "$SOURCE")
case "$IMAGE" in
  postgres:* | postgres@sha256:*) ;;
  *) echo '[FAIL] Unrecognized PostgreSQL image; inspect it before restore.' >&2; exit 1 ;;
esac
if ! sudo docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo '[FAIL] Exact local PostgreSQL image unavailable; refusing image download.' >&2
  exit 1
fi
sudo docker exec -i "$SOURCE" pg_restore --list < "$BACKUP" > /dev/null

echo '[PASS] Backup checksum and archive format verified'
echo "[INFO] Using the already-present PostgreSQL image: $IMAGE"

TEST="mon-m6-restore-$(date -u +%Y%m%d%H%M%S)-$$"
CREATED=0
cleanup() {
  if [[ "$CREATED" == 1 ]]; then
    if sudo docker container inspect "$TEST" >/dev/null 2>&1; then
      sudo docker rm -f "$TEST" >/dev/null || {
        echo "[WARNING] Cannot remove temporary test container $TEST; remove it manually." >&2
      }
    fi
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# No published ports, no network, no host mounts, bounded RAM/CPU/PIDs;
# all PostgreSQL files are in tmpfs and vanish at container removal.
sudo docker run --detach --rm \
  --name "$TEST" \
  --network none \
  --cpus=1 \
  --memory=768m --memory-swap=768m --pids-limit=128 \
  --security-opt no-new-privileges:true \
  --tmpfs /var/lib/postgresql/data:rw,nosuid,size=512m \
  --tmpfs /var/run/postgresql:rw,nosuid,size=8m \
  --tmpfs /tmp:rw,nosuid,size=32m \
  -e PGDATA=/var/lib/postgresql/data/pgdata \
  -e POSTGRES_DB=mon \
  -e POSTGRES_USER=mon \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  "$IMAGE" >/dev/null
CREATED=1

READY=0
for _ in $(seq 1 30); do
  if sudo docker exec "$TEST" pg_isready -q -U mon -d mon >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [[ $READY != 1 ]]; then
  echo '[FAIL] Disposable PostgreSQL did not become ready.' >&2
  sudo docker logs --tail 20 "$TEST" >&2 || true
  exit 1
fi

echo '[PASS] Disposable isolated PostgreSQL ready'
sudo docker cp -- "$BACKUP" "$TEST:/tmp/mon-backup.dump" >/dev/null
# Database is freshly initialized and empty; never target the live database.
sudo docker exec "$TEST" pg_restore \
  --exit-on-error --single-transaction --no-owner --no-privileges \
  -U mon -d mon /tmp/mon-backup.dump

echo '[PASS] Full pg_restore finished successfully'

sql() {
  local container=$1 statement=$2
  sudo docker exec "$container" sh -ec \
    'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$1"' \
    _ "$statement"
}
TABLE_QUERY="SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname = 'public'"
REV_QUERY='SELECT version_num FROM public.alembic_version ORDER BY version_num'
RLS_QUERY="SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relrowsecurity"
POLICY_QUERY="SELECT count(*) FROM pg_catalog.pg_policies WHERE schemaname='public'"

SOURCE_TABLES=$(sql "$SOURCE" "$TABLE_QUERY")
RESTORED_TABLES=$(sql "$TEST" "$TABLE_QUERY")
SOURCE_REV=$(sql "$SOURCE" "$REV_QUERY")
RESTORED_REV=$(sql "$TEST" "$REV_QUERY")
SOURCE_RLS=$(sql "$SOURCE" "$RLS_QUERY")
RESTORED_RLS=$(sql "$TEST" "$RLS_QUERY")
SOURCE_POLICIES=$(sql "$SOURCE" "$POLICY_QUERY")
RESTORED_POLICIES=$(sql "$TEST" "$POLICY_QUERY")

if [[ $SOURCE_TABLES -lt 1 || "$SOURCE_TABLES" != "$RESTORED_TABLES" || \
      -z "$RESTORED_REV" || "$SOURCE_REV" != "$RESTORED_REV" || \
      "$SOURCE_RLS" != "$RESTORED_RLS" || \
      "$SOURCE_POLICIES" != "$RESTORED_POLICIES" ]]; then
  echo '[FAIL] Recovered schema differs from current live schema.' >&2
  echo "[DETAIL] table_count: live=$SOURCE_TABLES restored=$RESTORED_TABLES" >&2
  echo "[DETAIL] rls_tables: live=$SOURCE_RLS restored=$RESTORED_RLS" >&2
  echo "[DETAIL] rls_policies: live=$SOURCE_POLICIES restored=$RESTORED_POLICIES" >&2
  exit 1
fi
printf '[PASS] Schema: %s tables, %s RLS tables, %s RLS policies\n' \
  "$RESTORED_TABLES" "$RESTORED_RLS" "$RESTORED_POLICIES"
printf '[PASS] Alembic revision: %s\n' "$RESTORED_REV"

# Only synthetic metadata counts; never print actual tenant or alert contents.
for table in security_events incidents audit_records; do
  count=$(sql "$TEST" "SELECT count(*) FROM public.$table")
  printf '[RESTORED] %s count=%s\n' "$table" "$count"
done

echo '[PASS] Disposable database restore rehearsal completed'
echo '[NOTE] Full service/data-isolation verification and a second storage location are still required.'
echo '[NOTE] Temporary test container will be removed automatically.'
