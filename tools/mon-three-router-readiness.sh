#!/usr/bin/env bash
# Run on PC2 as pc-2. Convert the existing MON Site Controller to a
# dedicated systemd service with CAP_NET_ADMIN (not root), preserving config.
# Prepares the MON response plan only. Never applies an nftables block.
set -Eeuo pipefail
umask 077
UNIT=mon-three-site-router.service
SERVICE=/etc/systemd/system/$UNIT
ENVFILE=/etc/mon-three/site-router.env
CODE="$HOME/mon-three-code"
ROOT="$HOME/mon-three"
RESTORE="$ROOT/restore-site-tmux.sh"
POINT=pc2-router
INCIDENT=9398913b-3fb4-4f01-874f-87f6d71ed646
ASSET=linux-host:lab-pc5
TARGET=10.77.0.60
swapped=0
info(){ printf '\n========== %s ==========\n' "$*"; }
fail(){ echo "[FAIL] $*" >&2; return 1; }
good(){ echo "[PASS] $*"; }
rollback(){
  rc=$?
  trap - ERR
  echo "[ROLLBACK] Site transition failed (status $rc)" >&2
  if [[ $swapped == 1 ]]; then
    sudo systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
    tmux kill-session -t mon-three-site >/dev/null 2>&1 || true
    tmux new-session -d -s mon-three-site "$RESTORE" || true
    sleep 4
    if curl -fsS --max-time 6 http://127.0.0.1:8090/health >/dev/null; then
      good 'Original tmux Site Controller restored'
    else
      echo '[FAIL] Original controller did not recover; inspect tmux mon-three-site' >&2
    fi
  fi
  exit "$rc"
}
trap rollback ERR

info 'PREFLIGHT (NO CHANGES)'
[[ "$(id -un)" == pc-2 ]] || fail 'Run as pc-2 on PC2'
[[ -x "$CODE/.venv/bin/python" && -f "$CODE/src/mon/site_service.py" ]] || fail 'MON code not found'
grep -Fq 'MON_ENABLE_ROUTER_NFTABLES_ENFORCEMENT' "$CODE/src/mon/site_service.py" || fail 'This MON checkout lacks the router adapter'
tmux has-session -t mon-three-site 2>/dev/null || fail 'Expected tmux session mon-three-site not found'
sudo -v
command -v nft >/dev/null || fail 'nft command missing'
sudo nft list tables >/dev/null || fail 'root cannot access nftables on this host'
ip -4 route get 10.77.0.50 | grep -Fq 'dev wg0' || fail 'Victim is not reached through wg0'
curl -fsS --max-time 8 http://127.0.0.1:8090/health >/dev/null || fail 'Existing Site Controller unhealthy'
if systemctl is-active --quiet "$UNIT"; then
  fail "Systemd unit $UNIT already active; refusing to replace it"
fi
if sudo nft list table inet mon_router >/dev/null 2>&1; then
  fail 'MON router nftables table already exists; refusing to assume its ownership'
fi
sudo install -d -m 0700 /etc/mon-three
mkdir -p "$ROOT"
chmod 700 "$ROOT"

info 'CAPTURE EXISTING SITE SERVICE LAUNCH SAFELY'
python3 - "$RESTORE" <<'PY' | sudo tee /etc/mon-three/site-router.env >/dev/null
import os, re, shlex, subprocess, sys
from pathlib import Path
restore=Path(sys.argv[1])
output=subprocess.check_output(
    ['ss','-H','-lntp','( sport = :8090 )'],text=True
)
m=re.search(r'pid=(\d+)', output)
if not m: raise SystemExit('cannot identify Site Controller PID')
pid=m.group(1)
proc=Path('/proc')/pid
argv=[x.decode('utf-8','strict') for x in (proc/'cmdline').read_bytes().split(b'\0') if x]
if not any('mon.site_service' in a or a.endswith('/mon-site') for a in argv):
    raise SystemExit('unexpected 8090 process; refusing migration')
cwd=os.readlink(proc/'cwd')
raw=(proc/'environ').read_bytes().split(b'\0')
env={}
for item in raw:
    if not item or b'=' not in item: continue
    key,value=item.split(b'=',1)
    key=key.decode('ascii','strict')
    if key.startswith('MON_') or key in ('PYTHONPATH','PYTHONUNBUFFERED','PATH'):
        env[key]=value.decode('utf-8','strict')
if env.get('MON_TENANT_ID')!='mon-lab' or env.get('MON_SITE_ID')!='site-a':
    raise SystemExit('unexpected tenant/site identity; refusing migration')
if cwd != str(Path.home()/'mon-three-code') and not Path(cwd).is_dir():
    raise SystemExit('Site Controller working directory is invalid')
env['MON_ENABLE_ROUTER_NFTABLES_ENFORCEMENT']='1'
env['MON_SITE_ROUTER_NFTABLES_VENDOR']='linux-nftables-router'
original_env={k:v for k,v in env.items() if k not in (
  'MON_ENABLE_ROUTER_NFTABLES_ENFORCEMENT','MON_SITE_ROUTER_NFTABLES_VENDOR'
)}
if len(argv) < 1:
    raise SystemExit('empty original command')
lines=['#!/usr/bin/env bash','set -Eeuo pipefail',
       'cd '+shlex.quote(cwd)]
for k,v in original_env.items():
    if '\n' in v: raise SystemExit('unsafe newline in environment')
    lines.append('export '+k+'='+shlex.quote(v))
lines.append('exec '+' '.join(shlex.quote(a) for a in argv))
restore.write_text('\n'.join(lines)+'\n')
restore.chmod(0o700)
print('[CHECK] Current Site Controller PID '+pid,file=sys.stderr)
print('[CHECK] Original launch saved privately to '+str(restore),file=sys.stderr)
for k,v in sorted(env.items()):
    if '\n' in v: raise SystemExit('unsafe newline in environment')
    print(k+'='+shlex.quote(v))
PY
sudo chmod 0600 "$ENVFILE"
[[ -s "$RESTORE" ]] || fail 'Rollback launcher missing'

info 'CONFIGURE LEAST-PRIVILEGED SITE SERVICE'
# EnvironmentFile is root-readable only. Site process runs as pc-2.
sudo tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=MON Three-PC Site Controller with lab router enforcement
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pc-2
Group=pc-2
WorkingDirectory=$CODE
EnvironmentFile=$ENVFILE
ExecStart=$CODE/.venv/bin/python -m mon.site_service
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
UMask=0077
Restart=on-failure
RestartSec=5
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
sudo chmod 0644 "$SERVICE"
sudo systemctl daemon-reload

info 'SWITCH SITE CONTROLLER; AUTO-RESTORE ON FAILURE'
# This interrupts only the loopback Site Controller for a few seconds.
tmux kill-session -t mon-three-site
swapped=1
for _ in $(seq 1 12); do
  if ! ss -H -lnt '( sport = :8090 )' | grep -q LISTEN; then break; fi
  sleep 1
done
if ss -H -lnt '( sport = :8090 )' | grep -q LISTEN; then
  fail 'Old Site Controller did not release port 8090'
fi
sudo systemctl enable --now "$UNIT"
healthy=0
for _ in $(seq 1 20); do
  if curl -fsS --max-time 3 http://127.0.0.1:8090/health >/dev/null 2>&1; then
    healthy=1; break
  fi
  sleep 1
done
[[ "$healthy" == 1 ]] || {
  sudo journalctl -u "$UNIT" -n 30 --no-pager >&2
  fail 'New Site Controller did not become healthy'
}
pid=$(systemctl show --value -p MainPID "$UNIT")
[[ "$pid" =~ ^[1-9][0-9]*$ ]] || fail 'New Site Controller PID unavailable'
sudo /usr/bin/python3 - "$pid" <<'PY'
import sys
from pathlib import Path
pid=sys.argv[1]
p=Path('/proc')/pid
status=(p/'status').read_text()
line=next(x for x in status.splitlines() if x.startswith('CapEff:'))
cap=int(line.split(':',1)[1].strip(),16)
if not (cap & (1<<12)):
    raise SystemExit('[FAIL] CAP_NET_ADMIN still not effective')
env=(p/'environ').read_bytes()
if b'MON_ENABLE_ROUTER_NFTABLES_ENFORCEMENT=1' not in env.split(b'\0'):
    raise SystemExit('[FAIL] router adapter still disabled')
print('[PASS] Router adapter enabled, CAP_NET_ADMIN granted to unprivileged site service')
PY
good "Site Controller ready; state, identity and WireGuard preserved"

info 'REGISTER CAPABILITY AND BIND THE REAL PC5 ASSET'
"$CODE/.venv/bin/python" - "$ROOT/identity/operator.jwt" <<'PY'
import json,sys,uuid,urllib.error,urllib.request
from pathlib import Path
token=Path(sys.argv[1]).read_text().strip()
headers={'Cookie':'mon_session='+token}
base='http://127.0.0.1:8080'
scope='?tenant_id=mon-lab&site_id=site-a'
def api(method,path,obj=None):
    h=dict(headers); body=None
    if obj is not None:
        h['Content-Type']='application/json'
        body=json.dumps(obj).encode()
    req=urllib.request.Request(base+path,headers=h,data=body,method=method)
    try:
        with urllib.request.urlopen(req,timeout=12) as r:return json.load(r)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f'{method} {path} -> HTTP {exc.code}: {exc.read()[:300]!r}') from exc
incident='9398913b-3fb4-4f01-874f-87f6d71ed646'
pc6='10.77.0.60'
asset='linux-host:lab-pc5'
point='pc2-router'
incidents=api('GET','/api/v1/incidents'+scope)
i=next((x for x in incidents if x.get('incident_id')==incident),None)
if not i or pc6 not in i.get('entities',[]) or asset not in i.get('affected_asset_ids',[]):
    raise RuntimeError('PC6 incident association does not match; refusing response planning')
points=api('GET','/api/v1/enforcement-points'+scope)
known=next((x for x in points if x.get('enforcement_point_id')==point),None)
if known:
    if (known.get('vendor')!='linux-nftables-router' or
        known.get('kind')!='ROUTER' or
        'BLOCK_IP' not in known.get('capabilities',[])):
        raise RuntimeError('Existing enforcement point has incompatible configuration')
else:
    api('POST','/api/v1/enforcement-points',{
        'enforcement_point_id':point,'tenant_id':'mon-lab',
        'site_id':'site-a','kind':'ROUTER',
        'vendor':'linux-nftables-router',
        'capabilities':['BLOCK_IP'],'priority':100})
bindings=api('GET','/api/v1/enforcement-bindings'+scope)
if not any(x.get('asset_id')==asset and x.get('enforcement_point_id')==point for x in bindings):
    api('POST','/api/v1/enforcement-bindings',{
        'tenant_id':'mon-lab','site_id':'site-a',
        'asset_id':asset,'enforcement_point_id':point,
        'distance':0,
        'attributes':{'blast_radius_estimate':'All forwarded traffic from PC6 on the lab overlay'}})
request={
  'request_id':str(uuid.uuid4()),'tenant_id':'mon-lab',
  'site_id':'site-a','incident_id':incident,
  'target':{'ip_address':pc6},'action':'BLOCK_IP',
  'enforcement_point_id':point,'ttl_seconds':120,
  'reason':'Lab PC6 source containment validation'
}
plan=api('POST','/api/v1/responses/plan',request)
print('[PASS] PC6 enforcement point and PC5 binding registered')
print('[PASS] PC6 response plan produced; policy:',plan.get('decision',{}).get('outcome'))
print('POLICY REASONS:',plan.get('decision',{}).get('reasons'))
print('TARGET:',pc6,'ENFORCEMENT POINT:',point,'TTL: 120 seconds')
print('NO FIREWALL BLOCK EXECUTED. Operator approval is still required.')
PY

info 'FINAL STATE'
curl -fsS --max-time 8 http://127.0.0.1:8090/health >/dev/null
sudo systemctl is-active "$UNIT"
sudo nft list tables | grep -F 'table inet mon_router' || true
good 'MON router service and response planning ready'
echo '[CHECK] Actual PC6 block/rollback still requires explicitly approved execution and independent PC6 connectivity checks.'
