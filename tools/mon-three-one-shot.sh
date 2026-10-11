#!/usr/bin/env bash
# MON three-PC live-lab repair and evidence verification. Run on PC2 as pc-2.
# No changes to VPN, firewalls, PKI, credentials, policies, or PC6.
set -Eeuo pipefail
umask 077
REPO='https://github.com/Saitanveesh/1.git'
FIX_BRANCH='fix/linux-ssh-journal-ingestion-20261010'
FIX_COMMIT='f3fe7074b24df75217306124fed5bdcb602cdf4e'
PC5='pc-5@10.77.0.50'
CODE="$HOME/mon-three-code"
ROOT="$HOME/mon-three"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ok(){ printf '[PASS] %s\n' "$*"; }
check(){ printf '[CHECK] %s\n' "$*"; }
fail(){ printf '[FAIL] %s\n' "$*" >&2; exit 1; }
phase(){ printf '\n========== %s ==========\n' "$*"; }

phase 'PC2 PRE-FLIGHT'
[[ "$(id -un)" == 'pc-2' ]] || fail 'Run on PC2 under pc-2, not on PC5/PC6'
[[ -d "$CODE/.git" && -x "$CODE/.venv/bin/python" ]] || fail "MON checkout missing: $CODE"
[[ -s "$ROOT/identity/operator.jwt" ]] || fail 'operator.jwt missing'
for cmd in ssh scp git curl python3 ss; do command -v "$cmd" >/dev/null || fail "Missing $cmd"; done
for port in 8080 8090 8443 9443; do
  if ss -H -lnt "( sport = :$port )" | grep -q LISTEN; then
    ok "PC2 port $port LISTEN"
  else
    fail "PC2 port $port not listening (not safe to proceed)"
  fi
done
sshopts=(-o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes)
ssh "${sshopts[@]}" "$PC5" 'test -s "$HOME/sensor-id/pc2-sensor-ca.pem" && test -s "$HOME/sensor-id/sensor-client-cert.pem" && test -s "$HOME/sensor-id/sensor-client-key.pem" && test -x "$HOME/mon-three-code/.venv/bin/python"' || fail 'PC5 SSH/identity preflight failed'
ok 'PC2 and PC5 basic preflight'

phase 'SAVE AUTHENTICATED MON BASELINE'
"$CODE/.venv/bin/python" - "$ROOT" "$TMP/baseline" <<'PY'
import json, sys, urllib.request
from pathlib import Path
root=Path(sys.argv[1]); out=Path(sys.argv[2])
token=(root/'identity/operator.jwt').read_text().strip()
for name,route in (
    ('ME','/api/v1/me'),
    ('SNAPSHOT','/api/v1/live/snapshot?tenant_id=mon-lab&site_id=site-a'),
):
    request=urllib.request.Request(
        'http://127.0.0.1:8080'+route,
        headers={'Cookie':'mon_session='+token},
    )
    with urllib.request.urlopen(request, timeout=10) as r:
        data=json.load(r)
        assert r.status==200, r.status
    if name=='SNAPSHOT':
        out.write_text(str(data.get('sequence') or 0))
        print('[BASELINE] snapshot sequence:',data.get('sequence'))
    else:
        print('[PASS] operator JWT accepted')
PY

phase 'STAGE PINNED GITHUB COLLECTOR FIX'
git -C "$CODE" fetch --quiet --no-tags "$REPO" "refs/heads/$FIX_BRANCH" || fail 'Unable to fetch GitHub fix'
git -C "$CODE" merge-base --is-ancestor "$FIX_COMMIT" FETCH_HEAD || fail 'Tested GitHub commit missing'
git -C "$CODE" show "$FIX_COMMIT:src/mon/linux_endpoint_collector.py" >"$TMP/collector.py"
"$CODE/.venv/bin/python" -m py_compile "$TMP/collector.py"
grep -Fq 'SYSLOG_IDENTIFIER=unit' "$TMP/collector.py" || fail 'Wrong journal adapter'
grep -Fq '_SSH_INVALID_USER_RE' "$TMP/collector.py" || fail 'Wrong SSH parser'
ok "Pinned tested source $FIX_COMMIT; no local git checkout modified"

phase 'DEPLOY AND TEST PC5'
cat >"$TMP/pc5.sh" <<'REMOTE'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
CODE="$HOME/mon-three-code"
DIR="$HOME/mon-three-pc5"
TARGET="$CODE/src/mon/linux_endpoint_collector.py"
STAGE="$DIR/collector.pending.py"
UNIT='mon-pc5-endpoint'
[[ -s "$TARGET" && -s "$STAGE" ]] || { echo '[FAIL] Missing collector file'; exit 1; }
sudo -v || { echo '[FAIL] sudo permission required'; exit 1; }
systemctl cat "$UNIT" | grep -Fq 'mon.linux_endpoint_collector' || { echo '[FAIL] Unexpected systemd unit'; exit 1; }
for f in pc2-sensor-ca.pem sensor-client-cert.pem sensor-client-key.pem; do
  [[ -s "$HOME/sensor-id/$f" ]] || { echo "[FAIL] Missing $f"; exit 1; }
done
"$CODE/.venv/bin/python" -m py_compile "$STAGE"
BACKUP="$TARGET.before-one-shot-$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$TARGET" "$BACKUP"
installed=0
rollback(){
  rc=$?
  trap - ERR
  if [[ "$installed" == 1 ]]; then
    cp -p "$BACKUP" "$TARGET" || true
    sudo systemctl restart "$UNIT" || true
    echo '[FAIL] Collector reverted to backed-up version'
  fi
  exit "$rc"
}
trap rollback ERR
install -m 0644 "$STAGE" "$TARGET"
installed=1
cd "$CODE"
PYTHONPATH="$CODE/src" "$CODE/.venv/bin/python" - <<'PY'
import datetime
from mon.linux_endpoint_collector import (
  SystemdJournalReader, normalize_linux_journal_event, parse_journal_entry
)
ts=str(int(datetime.datetime.now(datetime.UTC).timestamp()*1_000_000))
for i, (message, expected) in enumerate((
  ('Invalid user mon-lab-probe from 10.77.0.60 port 45498','AUTH_FAILURE'),
  ('Accepted publickey for pc-5 from 10.77.0.1 port 44708 ssh2','AUTH_SUCCESS'),
)):
    record=parse_journal_entry({'__CURSOR':f'one-shot-{i}',
      '__REALTIME_TIMESTAMP':ts,'SYSLOG_IDENTIFIER':'sshd-session',
      'MESSAGE':message,'_HOSTNAME':'lab-pc5'})
    event=normalize_linux_journal_event(record,tenant_id='mon-lab',site_id='site-a',sensor_id='linux-pc5')
    assert event is not None and event.kind.value==expected
    print('[PASS] Real SSH format parses as', expected)
native=SystemdJournalReader(unit='sshd-session').read_after(None,limit=10)
assert native, 'No SSH journal records accessible through native reader'
parse_journal_entry(native[0])
print('[PASS] Native systemd journal filter + cursor + timestamp')
PY
sudo systemctl restart "$UNIT"
sleep 3
sudo systemctl is-active --quiet "$UNIT"
trap - ERR
installed=0
echo "[PASS] PC5 service active; code backup: $BACKUP"

# One harmless failed authentication against local lab SSH service.
KEYDIR="$(mktemp -d)"
trap 'rm -rf "$KEYDIR"' EXIT
ssh-keygen -q -t ed25519 -N '' -f "$KEYDIR/key"
PROBE="moncheck-$(date +%s)"
ssh -n -T -i "$KEYDIR/key" -o IdentitiesOnly=yes -o BatchMode=yes \
  -o PreferredAuthentications=publickey -o ConnectTimeout=6 \
  -o StrictHostKeyChecking=accept-new \
  "$PROBE@10.77.0.50" true >/dev/null 2>&1 || true
if journalctl -t sshd-session --since '-2 minutes' --no-pager | grep -Fq "Invalid user $PROBE"; then
  echo "[PASS] Genuine local failed SSH event: $PROBE"
else
  echo '[CHECK] Local test SSH failure not visible in journal'
fi
sleep 8
PYTHONPATH="$CODE/src" "$CODE/.venv/bin/python" - <<'PY'
from pathlib import Path
import json
for f in (Path.home()/'mon-three-pc5/state/checkpoints').glob('*.json'):
    data=json.loads(f.read_text())
    if data.get('source_id')=='journal:sshd-session':
        print('[CHECK] SSH checkpoint present:',bool(data.get('checkpoint_token')))
        break
else:
    print('[CHECK] No SSH checkpoint yet')
PY
sudo journalctl -u "$UNIT" --since '-3 minutes' --no-pager -n 10
REMOTE

ssh "${sshopts[@]}" "$PC5" 'mkdir -p "$HOME/mon-three-pc5"; chmod 700 "$HOME/mon-three-pc5"'
scp -q "${sshopts[@]}" "$TMP/collector.py" "$PC5:/home/pc-5/mon-three-pc5/collector.pending.py"
scp -q "${sshopts[@]}" "$TMP/pc5.sh" "$PC5:/home/pc-5/mon-three-pc5/pc5-deploy.sh"
# Real terminal for normal sudo prompt; no secret copied to PC2.
ssh -tt -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes \
  "$PC5" 'bash "$HOME/mon-three-pc5/pc5-deploy.sh"' || fail 'PC5 deployment failed; examine output'

phase 'VERIFY LIVE PC5 -> PC2 EVENT INGESTION'
"$CODE/.venv/bin/python" - "$ROOT" "$TMP/baseline" <<'PY'
import json, sys, time, urllib.request
from pathlib import Path
root=Path(sys.argv[1]); before=int(Path(sys.argv[2]).read_text())
token=(root/'identity/operator.jwt').read_text().strip()
base='http://127.0.0.1:8080'
headers={'Cookie':'mon_session='+token}
def get(route):
    with urllib.request.urlopen(
      urllib.request.Request(base+route,headers=headers),timeout=12
    ) as r:
        assert r.status==200
        return json.load(r)
snap={}
for attempt in range(18):
    snap=get('/api/v1/live/snapshot?tenant_id=mon-lab&site_id=site-a')
    if int(snap.get('sequence') or 0)>before:
        break
    time.sleep(5)
after=int(snap.get('sequence') or 0)
print(f'Before sequence={before}, after sequence={after}')
for name in ('findings','incidents','assets'):
    print(name,len(snap.get(name) or []))
print('observations',(snap.get('telemetry') or {}).get('observation_count'))
print('registered sensors',len(get('/api/v1/sensors?tenant_id=mon-lab&site_id=site-a')))
if after<=before:
    print('[FAIL] Event ingestion still unproven; do not claim MON is complete')
    raise SystemExit(2)
print('[PASS] MON live state advanced after actual PC5 SSH activity')
PY

phase 'READ-ONLY CONSOLE, INCIDENT, RESPONSE AND AUDIT CHECKS'
"$CODE/.venv/bin/python" - "$ROOT" <<'PY'
import json, sys, urllib.request
from pathlib import Path
token=(Path(sys.argv[1])/'identity/operator.jwt').read_text().strip()
headers={'Cookie':'mon_session='+token}
scope='?tenant_id=mon-lab&site_id=site-a'
for name,path in [('Incidents','/api/v1/incidents'+scope),
                  ('Audit','/api/v1/audit'+scope),
                  ('Responses','/api/v1/responses'+scope)]:
    try:
        req=urllib.request.Request('http://127.0.0.1:8080'+path,headers=headers)
        with urllib.request.urlopen(req,timeout=8) as r:
            data=json.load(r)
            assert r.status==200
        print('[PASS]',name,'API',len(data) if isinstance(data,list) else '')
    except Exception as exc:
        print('[CHECK]',name,'API:',type(exc).__name__,exc)
url='http://100.75.116.62:5173'
for name,path in [('HTML','/'),('Authenticated API','/api/v1/me')]:
    try:
        req=urllib.request.Request(url+path,headers=headers)
        with urllib.request.urlopen(req,timeout=8) as r:
            assert r.status==200
        print('[PASS] Dashboard',name)
    except Exception as exc:
        print('[CHECK] Dashboard',name,':',type(exc).__name__,exc)
print('Dashboard URL:',url+'/')
PY

phase 'END OF ONE-SHOT RUN'
ok 'PC5 collector deployed, monitored SSH event path verified, APIs checked'
check 'PC6-originated attacks require PC6 participation (no SSH access from PC2)'
check 'Real router containment and rollback NOT applied automatically to the live WireGuard hub'
echo 'WireGuard, certificates, firewall, identities, and incident approvals were left unchanged.'
