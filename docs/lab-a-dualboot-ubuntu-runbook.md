# Lab A Ubuntu checklist — Friday 16 October 2026

Status: pre-lab executable instructions, NOT a certification that the college
switches, network coverage, login service or local hardware have been tested.

**The lab computers are all dual-boot Windows/Ubuntu. Ubuntu boot is not an
isolation boundary. The destructive/ARP/mitigation scenario must run only
inside a disconnected disposable Linux VM, not on dual-boot bare metal.**

## Physical allocations — selected at runtime

Choose any eligible Ubuntu lab station for each operational task. These are
**roles**, not permanent host or attacker/victim IDs:

| Role | Physical allocation | What runs there |
| --- | --- | --- |
| Exercise host | ONE available Ubuntu lab computer | Hypervisor + a disposable, fully disconnected Ubuntu VM |
| Monitoring/SOC host | Any other authorized Ubuntu computer, optional for initial self-contained test | MON API/React UI/PostgreSQL/Prometheus, once genuine auth and credentials are provisioned |
| Blue-team operator | Any browser-capable Ubuntu station, optional initially | Verified SSH tunnel to SOC console and investigation |
| Switch telemetry collector | Optional authorized Ubuntu station | Read-only SNMPv3 collection only after hardware survey and signed approval |

For the **first verification**, ONE physical Ubuntu host suffices because the
disconnected VM contains six separate kernel network namespaces. The attacker
and victim are dynamically selected *virtual participants inside that VM*,
not physical machines. On a later approved, segregated exercise network,
authorized physical systems can change roles; that requires separate
visibility and containment checks.

Do not connect a red-team attack network to the shared classroom LAN or
try to ARP-poison, overload, or isolate an uninvolved campus station.

## Phase 0 — check selected host (normal dual-boot Ubuntu)

Run on the selected **Ubuntu host OS** (not the exercise VM):

```bash
cat /etc/os-release | grep PRETTY_NAME
hostnamectl
lscpu | grep -Ei 'Virtualization|Architecture'
ip -br link
sudo apt update
sudo apt install -y git qemu-kvm libvirt-daemon-system libvirt-clients virt-manager
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt,kvm "$USER"
```

Re-login for group changes. If hardware virtualization is not enabled in
BIOS/UEFI, request authorization from the lab administrator; **do not
install privileged attack tools directly on the host** as a workaround.

Open `virt-manager`. Create a new Ubuntu 24.04 **disposable** VM from an
approved Ubuntu ISO, e.g. 2 vCPU, 4 GiB RAM, 25 GiB disk when resources allow.
For initial OS setup and dependency download, VM NAT may be temporarily
enabled; it is **never permitted during the scenario**.

## Phase 1 — prepare packages while disposable VM still has internet

Inside the **guest Ubuntu VM** terminal, before detaching its NIC:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip \
  iproute2 iputils-ping curl tcpdump nftables jq
git clone https://github.com/Saitanveesh/1.git MON
cd MON
git fetch origin design/dynamic-multilab-cyber-range
git checkout design/dynamic-multilab-cyber-range
python3 -m venv .venv
.venv/bin/python -m pip install -e .
bash -n tools/range_lab/run.sh tools/range_lab/preflight.sh
.venv/bin/python -m pytest --version || true
```

The final `pytest --version` is informational; it is not needed for the
exercise and a missing `pytest` does not affect runner dependencies.

**Shut down the VM completely.** In `virt-manager`, open VM hardware
Details, select the virtual **NIC**, and **Remove hardware**. If there is
more than one NIC, remove all of them. No NAT, host-only network, physical
bridge, Wi-Fi bridge or USB network device may remain. Restart the VM.

In the disconnected guest:

```bash
ip -br link
ip -4 route show
ip -6 route show
systemd-detect-virt --vm
cd ~/MON
sudo env MON_DISPOSABLE_VM_CONFIRMED=YES \
  bash tools/range_lab/preflight.sh
```

**Proceed only when preflight prints PASS.** It requires a detected VM,
`lo` as the *only* network interface, and no IPv4/IPv6 routes. If it
refuses, fix the VM configuration instead of bypassing the check.

## Phase 2 — isolated MITM exercise in the guest VM

The following creates a **new**, unplugged virtual bridge and six network
namespaces entirely inside the VM. No host or classroom NIC is involved.

```bash
cd ~/MON
sudo env MON_DISPOSABLE_VM_CONFIRMED=YES \
  MON_PYTHON="$PWD/.venv/bin/python" \
  bash tools/range_lab/run.sh --scenario mitm --victim alpha
```

The operator can select `--victim beta` on another run; these are only
disposable virtual workloads. Do not interpret them as physical seat IDs.

Expected sequence (each stage uses real kernel observations):
- create disconnected veth/bridge namespace topology;
- start a disposable **fictional** service and verify availability;
- record real ARP MAC binding before and during forged local ARP frames;
- capture packets passing through the relay on its virtual interface;
- correct neighbor MACs and disable forwarding in the isolated test;
- independently confirm the service is reachable again and clean up.

**The script may fail on different Ubuntu kernel configurations.**
ARP spoofing is not considered verified without the neighbor-binding change,
on-path TCP capture and recovery check. Review the evidence folder printed
by the script; do not report a success if a verification gate fails.

## Phase 3 — bounded multi-origin pressure / DDoS-shaped exercise

Perform a separate new run in the *same disconnected disposable VM*:

```bash
cd ~/MON
sudo env MON_DISPOSABLE_VM_CONFIRMED=YES \
  MON_PYTHON="$PWD/.venv/bin/python" \
  bash tools/range_lab/run.sh --scenario multi-origin --victim beta
```

This produces real independent virtual sender addresses (three
namespaces), measured requests/response logs from the disposable victim,
and a finding from MON's HTTP multi-source pressure detector. The victim
namespace applies temporary `nftables` rules against only the three test
sources. An unaffected independent client is checked; the rule is removed;
a formerly blocked source is checked again.

Traffic is bounded to **15 scheduled HTTP requests/second for six seconds**
spread across three senders. This is a real multi-origin pressure-shaped
exercise, **not proof of link-saturating Internet-scale DDoS**.

Choose `--scenario all` only after both standalone exercises work in
the current VM. When `mitm` fails closed, `all` stops before the next
scenario; separate runs make troubleshooting easier.

## Phase 4 — collect actual evidence and inspect

The runner prints `Evidence directory: /tmp/mon-isolated-range.XXXXXXXX/`.
Replace the placeholder below with the directory from **your run**.

```bash
EVIDENCE_DIR=/tmp/mon-isolated-range.REPLACE_WITH_ACTUAL_RUN
sudo ls -lah "$EVIDENCE_DIR"
sudo cat "$EVIDENCE_DIR"/arp-mon-findings.json   # MITM run only
sudo cat "$EVIDENCE_DIR"/multi-source-mon-findings.json # pressure run only
```

For a **read-only preview** using MON's normal typed security-event models:

```bash
# For --victim alpha only:
sudo "$HOME/MON/.venv/bin/python" -m tools.range_lab.ingest \
  --evidence-dir "$EVIDENCE_DIR" --target 10.253.42.20 \
  --tenant-id authorized-range --site-id lab-a-disconnected-vm
```

For `--victim beta` use `--target 10.253.42.21`. Use the Python
interpreter and current working directory from the guest installation,
and remember a default `sudo` environment can change `HOME`; an absolute
interpreter path from `$PWD` before sudo is safer:

```bash
cd ~/MON
sudo "$PWD/.venv/bin/python" -m tools.range_lab.ingest \
  --evidence-dir "$EVIDENCE_DIR" --target 10.253.42.21 \
  --tenant-id authorized-range --site-id lab-a-disconnected-vm
```

No `--api-url` is supplied, so this only reads the actual evidence.
It does not send traffic or invent an incident. MITM evidence includes
ARP capture and packet-path proof; pressure evidence includes observed
source IPs, logs, independent-client checks and rollback.

The evidence is inside the disposable VM; **leave its NIC disconnected**.
Export only approved/redacted evidence through an offline removable medium
or an administrator-approved transfer method. Raw packet captures and host
identifiers require handling as sensitive lab evidence.

## Phase 5 — optional actual MON server and PostgreSQL (different Ubuntu host)

A consolidated MON server can run on any chosen authorized Ubuntu host.
This is independent of the isolated exercise. The repo has Compose manifests
at `deploy/four-pc/compose.soc.yml` for MON API, PostgreSQL, React console,
Prometheus and independent Blackbox availability probing; see
[the deployment runbook](../deploy/four-pc/README.md).

Unlike the disconnected demo VM, the SOC server is a **management-plane
application**, not a bridge into the attack network. The production-style
SOC profile **requires actual JWT issuer, signing public key, tenant/site
principals, strong PostgreSQL password, and optional sensor enrollment**;
these are not available just because the software was cloned.
Do not guess a JWT, hard-code sample credentials or disable RBAC.

For a disposable **local-only** SOC demo on the chosen MON Ubuntu host,
the repo can generate signed, 8-hour lab credentials without weakening RBAC:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip openssl \
  docker.io docker-compose-v2
git clone https://github.com/Saitanveesh/1.git MON
cd MON
git fetch origin design/dynamic-multilab-cyber-range
git checkout design/dynamic-multilab-cyber-range
python3 -m venv .venv
.venv/bin/python -m pip install -e .
MON_LOCAL_SOC_CONFIRMED=YES bash tools/lab_soc_init.sh
cd deploy/four-pc
sudo docker compose -f compose.soc.yml config -q
sudo docker compose -f compose.soc.yml up -d --build
sudo docker compose -f compose.soc.yml ps
curl -fsS http://127.0.0.1:8080/health
```

The script places secrets at
`~/.local/share/mon-soc-lab-identity/`, creates a randomly generated
PostgreSQL password in an ignored mode-0600 deployment `.env`, and
mounts only the *public* JWT verification key into MON. **No sample
administrator bypass or fake attack events are enabled.** These
credentials are disposable lab credentials, not an institution-approved
production identity provider; do not deploy this local issuer on a
public interface.

For the browser, return to the MON checkout root:

```bash
cd ~/MON
.venv/bin/python tools/lab_soc_session.py \
  --token-file "$HOME/.local/share/mon-soc-lab-identity/operator.jwt" \
  --public-key-file deploy/four-pc/auth/public.pem
```

The command prints a **one-time loopback-only URL**. Open it in the
selected operator's browser within three minutes. It validates the signed
token and sets an HttpOnly cookie, then redirects to the actual MON
React console at `http://127.0.0.1:8088/?tenant=mon-lab&site=isolated-range`.
The browser session expires within an hour; repeat the helper if needed
while the JWT is valid. It does not publish secrets on the shared LAN.

For an operator browser on a **different authorized Ubuntu PC**, first
establish an SSH tunnel with **both** loopback ports from that PC:

```bash
ssh -N -L 8088:127.0.0.1:8088 \
  -L 9876:127.0.0.1:9876 USER_ON_MON_HOST@MON_HOST_MANAGEMENT_IP
```

Only then launch the one-time session helper on the MON host. Open its
printed `127.0.0.1:9876` URL in the tunneled browser; the signed token
never needs copying to the blue-team computer.

If the Ubuntu repositories do not contain `docker-compose-v2`, use the
institution-approved Docker Compose v2 installation method; confirm
`sudo docker compose version` before proceeding. Initial Docker image
pulls require network access **only on the SOC management host**, not
the attack VM. PostgreSQL and time-series metrics are persistent Docker
volumes; use `down` without `-v` for routine shutdown.

No synthetic students or attack records are inserted into MON's
live security database. The disconnected exercise can be inspected locally
and transferred later to the authenticated MON ingestion endpoint.

The first isolated MITM/pressure exercise will **run without MON login**.
Later, the administrator can transfer validated real observations to the
management-side INGEST station and upload to MON over authenticated HTTPS,
then view findings in the real SOC console. A disconnected VM should
not be given an uplink to make that transfer more convenient.

## Phase 6 — optional passive college-network observation (not red-team)

On an *authorized* Ubuntu management station:

```bash
git clone https://github.com/Saitanveesh/1.git MON
cd MON
git fetch origin design/dynamic-multilab-cyber-range
git checkout design/dynamic-multilab-cyber-range
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[switch]'
.venv/bin/mon-topology-collect --source linux-neighbors \
  --tenant-id YOUR_APPROVED_TENANT --site-id YOUR_APPROVED_SITE \
  --sensor-id local-neighbors
```

The local Linux neighbor table is **not a campus census**. Read-only
SNMPv3 switch collection (`mon-switch-snmpv3`) needs switch
vendor/model/firmware, read-only SNMPv3 credentials and IT approval.
No arbitrary host is attacked because it appears in this observation.

## Team demonstration script

Explain what the professor is actually shown:

1. **DISCOVER**: MON observes active test participants/switch information
   only where real telemetry exists; the disconnected VM is a separate range.
2. **DETECT**: actual ARP replies or victim-side HTTP logs enter detectors.
3. **CORRELATE**: source/target identities are time- and evidence-scoped;
   ARP conflicts alone are not proof of MITM.
4. **TRACE**: packet capture in the relay namespace demonstrates the MITM
   path; unknown campus links are NOT drawn as facts.
5. **CONTAIN**: temporary neighbor correction or test-only `nftables`
   is performed on the disposable VM, not the college switch.
6. **VERIFY**: test sources are blocked only where intended while an
   independent client can still reach the victim.
7. **RECOVER**: remove the temporary block, confirm service restoration
   and erase the ephemeral virtual network.

The separate real MON console and hosted PostgreSQL system are part of
the application deployment and require authentication and site integration;
the isolated demo by itself is NOT proof of seamless campus-wide enforcement.

## Quick troubleshooting

- `PRECHECK BLOCKED: VM has a network interface`: shut down the guest and
  remove every virtual NIC; do not remove the physical host's NIC.
- `Not a detected virtual machine`: do not run on bare-metal dual-boot Ubuntu.
- `Permission denied`: verify that you are using `sudo` **inside the VM**.
- `tcpdump captured 0` / ARP binding did not change: test did not prove
  MITM. Save the failure logs; inspect VM kernel/network-namespace support.
- `MON SOC authentication unavailable`: the issuer/public key/session has
  not been provisioned; use the isolated CLI tests first.
- `Discovered devices = 0`: a collector without observable segments
  legitimately reports no information. Never backfill demonstration nodes
  into the actual inventory.

## Links

- [Self-contained MITM and pressure test kit](../tools/range_lab/README.md)
- [Full MON four-PC optional deployment](../deploy/four-pc/README.md)
- [Dynamic network graph ADR](adr/0078-evidence-backed-topology-and-network-distance.md)
- [Range safety ADR](adr/0080-four-pc-range-host-health-and-evidence.md)
