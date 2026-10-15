# MON four-computer cyber-range profile

Status: **software manifests + synthetic ERP service implemented**. Not certified against
the institution's actual switches, endpoint population, campus LAN, or PC hardware.
No network is scanned or attacked when these files are added to Git.

## Allocation: four physical computers, not seven

- **PC1 — MON SOC and monitoring**: PostgreSQL control-plane data, MON API,
  React console, Prometheus metrics archive and independent Blackbox probes.
  A real passive packet sensor still needs an authorized TAP/SPAN/flow export
  or a local interface that genuinely observes the path. The base container
  does NOT automatically receive all switched traffic.
- **PC2 — blue team**: browser plus SSH tunnel to PC1 console. Uses issuer
  authentication/RBAC and an authorized `mon_session` browser cookie. The
  current MON codebase does not contain a complete identity-provider login
  portal; provisioning the actual issuer/session is a deployment prerequisite.
- **PC3 — red team**: authorized exercise station with verified isolation.
  No MON daemon or artificial fixed-source attacker address is required.
  Attack tooling is not included in the management network deployment.
- **PC4 — disposable victim**: isolated synthetic university ERP API and
  PostgreSQL with **only fabricated records**. PC4 does not represent the
  institution's production ERP. It can be replaced by any separately
  authorized, instrumented disposable victim without editing detector code.

## Required isolation and resource preparation

1. Obtain written campus/IT authorization for monitoring and an approved
   exercise subnet/VLAN with designated switch ports or physically isolated
   virtual switch. Verify the exercise fabric has **no routing or bridging**
   into ordinary campus systems before PC3 can send scenario traffic.
2. Survey managed-switch vendor/model, firmware, SNMPv3 read-only support,
   LLDP, BRIDGE-MIB, Q-BRIDGE-MIB, SPAN/flow export, VLANs, trunk ports and
   expected device count. Do not infer 100% visibility from one port.
3. Install Docker Engine + Compose on PC1 and PC4 in disposable OS/VMs.
   PC1 storage needs separate persistent quotas, backups and disk alerts;
   size CPU/RAM only after realistic measured load. Do not deploy on the
   operator's main laptop for first tests.
4. Prepare institution-approved identity-provider signing keys and issue
   correctly scoped MON browser sessions; no hard-coded developer bypass.
   Secure PC1 management access, and use a dedicated non-root Docker account.
5. Confirm PC1 can reach PC4's **approved probe/metrics interface**, while
   the red-team attack interface is restricted to the approved exercise
   workload and cannot reach campus production networks.

## PC1 preparation and SOC startup

All commands are for the checked-out branch in a disposable test host.

```bash
git checkout design/dynamic-multilab-cyber-range
cd deploy/four-pc
umask 077
cp example.env .env
# Edit .env. Set real unique passwords, URL-encode reserved URL chars, and
# set MON_AUTH_ISSUER and MON_AUTH_AUDIENCE to your real configured issuer.
# Do NOT leave sample values or commit .env.
mkdir -p auth
# Provision your approved identity-provider public key into auth/public.pem,
# with read-only permissions. Never put the private signing key here.
chmod 600 .env auth/public.pem
docker compose --env-file .env -f compose.soc.yml config -q
docker compose --env-file .env -f compose.soc.yml up -d --build
docker compose --env-file .env -f compose.soc.yml ps
```

The SOC API is bound **only to PC1 loopback :8080**; the operator console is
bound to **PC1 loopback :8088**; Prometheus is **PC1 loopback :9090**.
PostgreSQL is internal to Docker and uses a named persistent volume.
MON's existing container entrypoint applies Alembic migrations.
All production JWT/mTLS identity enrollment and audit controls are still
required, not replaced by Docker Compose.

## PC4 preparation and isolated ERP startup

Copy the same repository checkout to disposable PC4. Prepare a **separate**
private `.env` there, with `ERP_DB_PASSWORD`, `ERP_DATABASE_URL` and
`ERP_BIND_IP`. That bind IP must be an address actually configured on PC4's
isolated, authorized exercise interface; it must **not** be a campus
management interface. The example's RFC 5737 documentation address must
never be treated as a real interface.

```bash
git checkout design/dynamic-multilab-cyber-range
cd deploy/four-pc
umask 077
cp example.env .env
# Set PC4 values and verify isolated interface ownership before proceeding.
docker compose --env-file .env -f compose.erp.yml config -q
docker compose --env-file .env -f compose.erp.yml up -d --build
docker compose --env-file .env -f compose.erp.yml ps
```

From an explicitly permitted monitoring station that can reach PC4's
approved interface:

```bash
curl --fail --max-time 5 http://YOUR_ISOLATED_ERP_IP:8081/health/live
curl --fail --max-time 5 http://YOUR_ISOLATED_ERP_IP:8081/health/ready
curl --fail --max-time 5 http://YOUR_ISOLATED_ERP_IP:8081/api/students?limit=3
curl --fail --max-time 5 http://YOUR_ISOLATED_ERP_IP:8081/metrics
```

These endpoints measure actual request timing, process RSS/CPU time and
database readiness. `/health/ready` fails with HTTP 503 if DB reads fail.
PC4 host CPU and RAM now have a separate Node Exporter, listening only on the
operator-approved `ERP_MONITOR_BIND_IP:9100` interface. This sensitive metrics
endpoint must be accessible only to PC1 and denied to PC3 and campus clients
by independent firewall/routing rules. Keep it unconfigured until isolation
is verified. Process memory is not host memory.

## Independent PC1 Prometheus/Blackbox observation of PC4

Initially all three `targets/*.json` files contain `[]`: **zero configured targets**
is intentional and must show no service metrics, never a manufactured healthy
ERP value. After confirming the private probe route and authorization,
edit the files **only on PC1**.

Illustrative format (substitute the actual private, routed target):

```json
[
  {
    "targets": ["10.77.0.50:8081"],
    "labels": {"tenant_id": "YOUR_TENANT", "site_id": "YOUR_SITE"}
  }
]
```

Put the above in `targets/erp-metrics.json` with only the host:port.
For `targets/erp-host.json`, configure the actual PC4 `HOST:9100` address
with the same tenant/site labels after confirming the monitoring VLAN and
firewall scope. MON's measured CPU percentage uses idle CPU-time rate; memory
percentage comes from available/total host memory. Missing or ambiguous
host data stays UNKNOWN.

For `targets/erp-probe.json` use an **actual** URL including the health path,
such as `http://YOUR_APPROVED_ERP_IP:8081/health/ready`.
These represent two distinct measurements: self-reported application/process
metrics and an independently performed HTTP readiness probe. Prometheus
retains seven days of measurements in a named volume for this pilot.
Restrict PC1-to-PC4 access to the intended route and do not trust operator
labels as an isolation boundary.

## PC2 blue-team browser and PC3 red-team station

On PC2, after verifying the PC1 SSH host key and authenticating as an
authorized operator:

```bash
ssh -N -L 8088:127.0.0.1:8088 YOUR_PC1_OPERATOR@YOUR_PC1_MANAGEMENT_ADDRESS
```

Open `http://127.0.0.1:8088` on PC2. A properly provisioned `mon_session`
cookie from the institution's trusted MON issuer is necessary to use API and
live WebSocket features. An unconfigured identity provider should produce
an authentication error, not a demo bypass.

PC3 is a role, not a hard-coded attacker identity in MON. Exercise traffic
may originate from another preauthorized range participant if scope controls
and exercise isolation are independently validated. No attack targets on
the campus LAN and no actual college ERP accounts/data.

## One-switch SNMPv3 read-only collection

Install the optional collector on an authorized Linux collector station:

```bash
python -m pip install -e '.[switch]'
mon-switch-snmpv3 --help
```

Use an administrator-provisioned mode-0600 **single-line JSON** config file
outside the repo with `switch_id`, `address` (literal authorized RFC1918
management IP), `username`, `auth_passphrase`, `priv_passphrase`,
optional `port` and `ttl_seconds`. SNMPv3 requires SHA-256 authentication
plus AES128 privacy. No SNMP SET operation exists. Do not pass secrets as
command arguments or store them in this repository.

```bash
mon-switch-snmpv3 --config-file /etc/mon/switch-auth.json \
  --tenant-id YOUR_TENANT --site-id YOUR_SITE \
  --sensor-id managed-switch-sensor
```

This first performs an **offline JSON export only**, showing actual LLDP
neighbor labels and default-bridge FDB MAC-to-port data with unknown VLAN.
After validating identities and establishing a scoped `INGEST` token:

```bash
mon-switch-snmpv3 --config-file /etc/mon/switch-auth.json \
  --tenant-id YOUR_TENANT --site-id YOUR_SITE \
  --sensor-id managed-switch-sensor \
  --api-url https://YOUR_APPROVED_MON_API \
  --token-file /etc/mon/topology.token
```

A default BRIDGE-MIB table does NOT expose every VLAN on all switches.
LLDP sysName is untrusted peer-supplied input, not attestation. Poll failure
aborts the whole observation batch rather than asserting an empty, healthy
switch. Test on one certified switch/model using temporary, least-privilege
management credentials before expanding to other devices. Record actual
firmware/OID/port mapping mismatches and blind spots. The four-PC Compose
profile does not itself deploy this SNMP poller automatically.

## Rollback and release gates

- Stop demo PC4 services using
  `docker compose --env-file .env -f compose.erp.yml down`; this preserves
  the named test database volume. To **discard only fictional test records**,
  separately remove the isolated test volume after verifying its name.
- Stop PC1 services using `docker compose --env-file .env -f compose.soc.yml down`
  without `-v`; durable MON evidence and metrics must not be deleted
  as a side effect of routine shutdown.
- Mandatory gates: unit/CI success, Compose config/build, disposable VM
  integration, restart/crash/retention verification, live sensor packet path,
  true PC4 health under load, management-network isolation, and approved
  enforcement with TTL+verification+rollback.
- **Not yet certified:** SNMP management hardware, four physical PC resources,
  network isolation, PC2 issuer/browser login, all-endpoint coverage, full
  host-health exporter, red-team exercise and automatic containment.

Do not claim that a successful Docker build means these physical gates passed.
